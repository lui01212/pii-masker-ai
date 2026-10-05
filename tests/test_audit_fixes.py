"""
Regression tests for the audit fixes (token continuity, LangChain wrapper isolation, CLI batch
and scan hardening, hash mode keying, detection and overlap fixes, synthetic values).
Uses standard library unittest and synthetic data only.
"""

import contextlib
import hashlib
import hmac
import io
import json
import os
import stat
import tempfile
import time
import unittest
import warnings
from unittest import mock

from pii_masker.cli import main
from pii_masker.core import PIIMasker, MaskMode, SYNTHETIC_TEMPLATES, _synthetic_builtin
from pii_masker.integrations import PIIChatWrapper, PIILangChainCallback
from pii_masker.patterns.financial import luhn_checksum


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class EchoLLM:
    """Stand-in chat model: records what it received and echoes text back."""

    def __init__(self):
        self.seen = None

    def invoke(self, value):
        self.seen = value
        return "echo: " + (value if isinstance(value, str) else repr(value))


class TestTokenContinuity(unittest.TestCase):
    """Finding 1 and 20: tokens continue across calls and repeat for repeated values."""

    def setUp(self):
        self.masker = PIIMasker()

    def test_same_value_gets_one_token(self):
        res = self.masker.mask("alice@example.com wrote to alice@example.com")
        self.assertEqual(res.masked_text, "<EMAIL_1> wrote to <EMAIL_1>")
        self.assertEqual(res.mapping, {"<EMAIL_1>": "alice@example.com"})
        self.assertEqual(res.entity_count, 2)

    def test_mapping_continues_numbering_and_reuses_tokens(self):
        first = self.masker.mask("call 0912345678")
        before = dict(first.mapping)
        second = self.masker.mask("call 0987654321 or 0912345678", mapping=first.mapping)
        self.assertEqual(second.masked_text, "call <PHONE_2> or <PHONE_1>")
        self.assertEqual(first.mapping, before)  # the passed mapping is not modified
        merged = dict(first.mapping)
        merged.update(second.mapping)
        self.assertEqual(merged, {"<PHONE_1>": "0912345678", "<PHONE_2>": "0987654321"})
        self.assertEqual(PIIMasker.unmask(first.masked_text, merged), "call 0912345678")

    def test_synthetic_mapping_continues_across_records(self):
        first = self.masker.synthetic_mask("mail alice@example.com")
        second = self.masker.mask("mail bob@example.com", mode=MaskMode.SYNTHETIC, mapping=first.mapping)
        self.assertEqual(first.masked_text, "mail user1@example.com")
        self.assertEqual(second.masked_text, "mail user2@example.com")

    def test_literal_token_in_input_is_not_reused(self):
        res = self.masker.mask("Template <EMAIL_1>; contact bob@example.com")
        self.assertEqual(res.masked_text, "Template <EMAIL_1>; contact <EMAIL_2>")
        self.assertEqual(
            PIIMasker.unmask(res.masked_text, res.mapping), "Template <EMAIL_1>; contact bob@example.com"
        )

    def test_cli_batch_keeps_one_mapping_for_the_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "a.jsonl")
            out = os.path.join(tmpdir, "a.out.jsonl")
            map_path = os.path.join(tmpdir, "map.json")
            with open(src, "w", encoding="utf-8") as f:
                f.write('{"prompt": "call 0912345678"}\n{"prompt": "call 0987654321"}\n')
            code, _, _ = run_cli(["batch", "-i", src, "-o", out, "--save-mapping", map_path])
            self.assertEqual(code, 0)
            with open(out, encoding="utf-8") as f:
                records = [json.loads(line) for line in f]
            with open(map_path, encoding="utf-8") as f:
                mapping = json.load(f)
            self.assertEqual(records[0]["prompt"], "call <PHONE_1>")
            self.assertEqual(records[1]["prompt"], "call <PHONE_2>")
            self.assertEqual(PIIMasker.unmask(records[0]["prompt"], mapping), "call 0912345678")
            self.assertEqual(PIIMasker.unmask(records[1]["prompt"], mapping), "call 0987654321")

    def test_cli_batch_synthetic_values_unique_across_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "ips.txt")
            out = os.path.join(tmpdir, "ips.out.txt")
            map_path = os.path.join(tmpdir, "map.json")
            lines = [f"host 203.0.113.{i}\n" for i in range(1, 13)]
            with open(src, "w", encoding="utf-8") as f:
                f.writelines(lines)
            code, _, _ = run_cli(["batch", "-i", src, "-o", out, "--mode", "synthetic", "--save-mapping", map_path])
            self.assertEqual(code, 0)
            with open(out, encoding="utf-8") as f:
                masked = f.read()
            with open(map_path, encoding="utf-8") as f:
                mapping = json.load(f)
            self.assertEqual(len(mapping), 12)
            self.assertEqual(PIIMasker.unmask(masked, mapping), "".join(lines))


class TestChatWrapper(unittest.TestCase):
    """Findings 2, 3 and 22: per-call mappings, every input shape masked, no caller mutation."""

    def test_mapping_is_local_to_each_invoke(self):
        wrapper = PIIChatWrapper(EchoLLM())
        self.assertEqual(wrapper.invoke("my email alice@example.com"), "echo: my email alice@example.com")
        # A second user quoting the token must not receive the first user's address
        self.assertEqual(wrapper.invoke("what is <EMAIL_1>?"), "echo: what is <EMAIL_1>?")
        self.assertEqual(wrapper.last_mapping, {})

    def test_last_mapping_is_replaced_not_merged(self):
        wrapper = PIIChatWrapper(EchoLLM())
        for i in range(3):
            wrapper.invoke(f"user{i} mail person{i}@example.com")
        self.assertEqual(wrapper.last_mapping, {"<EMAIL_1>": "person2@example.com"})

    def test_tuple_messages_are_masked(self):
        llm = EchoLLM()
        PIIChatWrapper(llm).invoke([("human", "my mail is alice@example.com")])
        self.assertEqual(llm.seen, [("human", "my mail is <EMAIL_1>")])

    def test_content_blocks_are_masked(self):
        class Msg:
            def __init__(self, content):
                self.content = content

        llm = EchoLLM()
        original = Msg([{"type": "text", "text": "card 4111111111111111"}])
        PIIChatWrapper(llm).invoke([original])
        self.assertEqual(llm.seen[0].content, [{"type": "text", "text": "card <CREDIT_CARD_1>"}])
        self.assertEqual(original.content, [{"type": "text", "text": "card 4111111111111111"}])

    def test_dict_input_values_are_masked_recursively(self):
        llm = EchoLLM()
        PIIChatWrapper(llm).invoke({"question": "mail bob@example.com", "context": {"ip": "192.0.2.10"}, "k": 3})
        self.assertEqual(llm.seen, {"question": "mail <EMAIL_1>", "context": {"ip": "<IP_ADDRESS_1>"}, "k": 3})

    def test_prompt_value_is_masked(self):
        class Msg:
            def __init__(self, content):
                self.content = content

        class FakePromptValue:
            def to_messages(self):
                return [Msg("mail carol@example.com")]

        llm = EchoLLM()
        PIIChatWrapper(llm).invoke(FakePromptValue())
        self.assertEqual(llm.seen[0].content, "mail <EMAIL_1>")

    def test_unsupported_input_raises(self):
        llm = EchoLLM()
        with self.assertRaises(TypeError):
            PIIChatWrapper(llm).invoke(object())
        self.assertIsNone(llm.seen)

    def test_message_copy_keeps_fields_and_does_not_mutate(self):
        class ToolMessage:
            def __init__(self, content, tool_call_id):
                self.content = content
                self.tool_call_id = tool_call_id

        original = ToolMessage("lookup result alice@example.com", "call_1")
        llm = EchoLLM()
        PIIChatWrapper(llm).invoke([original])
        self.assertEqual(original.content, "lookup result alice@example.com")
        self.assertEqual(llm.seen[0].content, "lookup result <EMAIL_1>")
        self.assertEqual(llm.seen[0].tool_call_id, "call_1")

    def test_message_copy_prefers_model_copy(self):
        class PydanticLikeMessage:
            def __init__(self, content, name):
                self.content = content
                self.name = name
                self.via_model_copy = False

            def model_copy(self, update=None):
                clone = PydanticLikeMessage(self.content, self.name)
                clone.via_model_copy = True
                for key, value in (update or {}).items():
                    setattr(clone, key, value)
                return clone

        original = PydanticLikeMessage("mail dave@example.com", "dave")
        llm = EchoLLM()
        PIIChatWrapper(llm).invoke([original])
        self.assertTrue(llm.seen[0].via_model_copy)
        self.assertEqual(llm.seen[0].content, "mail <EMAIL_1>")
        self.assertEqual(original.content, "mail dave@example.com")


class TestCallback(unittest.TestCase):
    """Finding 7: raise_on_pii must make LangChain propagate the handler's exception."""

    def test_raise_error_follows_raise_on_pii(self):
        self.assertTrue(PIILangChainCallback(raise_on_pii=True).raise_error)
        self.assertFalse(PIILangChainCallback(raise_on_pii=False).raise_error)

    def test_chat_model_start_inspects_content_blocks(self):
        class Msg:
            def __init__(self, content):
                self.content = content

        cb = PIILangChainCallback(raise_on_pii=True)
        with self.assertRaises(ValueError):
            cb.on_chat_model_start({}, [[Msg([{"type": "text", "text": "mail erin@example.com"}])]])


class TestBatchFormats(unittest.TestCase):
    """Findings 4, 5, 16, 17 and 19: JSONL, TXT and CSV handling in `batch`."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def write(self, name, content):
        with open(self.path(name), "w", encoding="utf-8", newline="") as f:
            f.write(content)
        return self.path(name)

    def read(self, name):
        with open(self.path(name), encoding="utf-8", newline="") as f:
            return f.read()

    def test_jsonl_nested_values_numbers_and_invalid_lines(self):
        src = self.write(
            "b.jsonl",
            '{"messages": [{"role": "user", "content": "mail alice@example.com"}]}\n'
            '{"user": {"email": "bob@example.com"}, "id": 7}\n'
            '{"card": 4111111111111111}\n'
            '{"prompt": "mail carol@example.com",}\n'
            '["dave@example.com"]\n',
        )
        code, _, err = run_cli(["batch", "-i", src, "-o", self.path("b.out.jsonl"), "--mode", "redact"])
        self.assertEqual(code, 1)
        self.assertIn("line 4", err)
        output = self.read("b.out.jsonl")
        self.assertNotIn("carol@example.com", output)
        records = [json.loads(line) for line in output.splitlines()]
        self.assertEqual(records, [
            {"messages": [{"role": "user", "content": "mail [EMAIL]"}]},
            {"user": {"email": "[EMAIL]"}, "id": 7},
            {"card": "[CREDIT_CARD]"},
            ["[EMAIL]"],
        ])

    def test_jsonl_fields_mask_nested_values_of_selected_keys(self):
        src = self.write("f.jsonl", '{"chat": {"text": "mail erin@example.com"}, "meta": "frank@example.com"}\n')
        code, _, _ = run_cli(["batch", "-i", src, "-o", self.path("f.out.jsonl"), "--fields", "chat", "--mode", "redact"])
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(self.read("f.out.jsonl")), {"chat": {"text": "mail [EMAIL]"}, "meta": "frank@example.com"}
        )

    def test_txt_multiline_private_key_is_masked(self):
        src = self.write(
            "k.txt",
            "before alice@example.com\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
            "-----END PRIVATE KEY-----\n"
            "after\n",
        )
        code, _, _ = run_cli(["batch", "-i", src, "-o", self.path("k.out.txt"), "--mode", "redact"])
        self.assertEqual(code, 0)
        self.assertEqual(self.read("k.out.txt"), "before [EMAIL]\n[PRIVATE_KEY]\nafter\n")

    def test_same_input_and_output_is_refused(self):
        src = self.write("c.csv", "id,email\n1,alice@example.com\n")
        code, _, err = run_cli(["batch", "-i", src, "-o", src, "--mode", "redact"])
        self.assertEqual(code, 1)
        self.assertIn("differ", err)
        self.assertEqual(self.read("c.csv"), "id,email\n1,alice@example.com\n")

    def test_csv_extra_cells_are_masked_and_kept(self):
        src = self.write("x.csv", "id,email\n1,alice@example.com\n2,bob@example.com,extra@example.com\n")
        code, _, _ = run_cli(["batch", "-i", src, "-o", self.path("x.out.csv"), "--fields", "email", "--mode", "redact"])
        self.assertEqual(code, 0)
        self.assertEqual(self.read("x.out.csv"), "id,email\r\n1,[EMAIL]\r\n2,[EMAIL],[EMAIL]\r\n")

    def test_csv_unknown_field_is_an_error(self):
        src = self.write("f.csv", "id,Email\n1,alice@example.com\n")
        code, _, err = run_cli(["batch", "-i", src, "-o", self.path("f.out.csv"), "--fields", "email"])
        self.assertEqual(code, 1)
        self.assertIn("email", err)
        self.assertIn("Available columns: id, Email", err)
        self.assertFalse(os.path.exists(self.path("f.out.csv")))

    def test_csv_quoted_multiline_cell(self):
        src = self.write("m.csv", 'id,note\r\n1,"line one\r\nmail alice@example.com"\r\n')
        code, _, _ = run_cli(["batch", "-i", src, "-o", self.path("m.out.csv"), "--mode", "redact"])
        self.assertEqual(code, 0)
        self.assertEqual(self.read("m.out.csv"), 'id,note\r\n1,"line one\r\nmail [EMAIL]"\r\n')

    def test_mapping_file_is_private_and_always_rewritten(self):
        map_path = self.path("s.json")
        run_cli(["mask", "mail alice@example.com", "--save-mapping", map_path])
        self.assertEqual(json.loads(self.read("s.json")), {"<EMAIL_1>": "alice@example.com"})
        if os.name != "nt":
            os.chmod(map_path, 0o644)
        run_cli(["mask", "no pii here", "--save-mapping", map_path])
        self.assertEqual(json.loads(self.read("s.json")), {})
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(map_path).st_mode), 0o600)

    def test_batch_mapping_file_is_private(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions")
        src = self.write("p.txt", "mail alice@example.com\n")
        map_path = self.path("p.json")
        run_cli(["batch", "-i", src, "-o", self.path("p.out.txt"), "--save-mapping", map_path])
        self.assertEqual(stat.S_IMODE(os.stat(map_path).st_mode), 0o600)


class TestHashMode(unittest.TestCase):
    """Finding 6: keyed HMAC-SHA256 with an explicit, environment or random salt."""

    def test_hmac_token_with_explicit_salt(self):
        res = PIIMasker(salt="test-salt").mask("call 0912345678", mode=MaskMode.HASH)
        digest = hmac.new(b"test-salt", b"0912345678", hashlib.sha256).hexdigest()[:16]
        self.assertEqual(res.masked_text, f"call <PHONE_{digest}>")

    def test_environment_salt(self):
        with mock.patch.dict(os.environ, {"PII_MASKER_SALT": "env-salt"}):
            a = PIIMasker().mask("call 0912345678", mode=MaskMode.HASH).masked_text
            b = PIIMasker().mask("call 0912345678", mode=MaskMode.HASH).masked_text
        self.assertEqual(a, b)
        self.assertEqual(a, PIIMasker(salt="env-salt").mask("call 0912345678", mode=MaskMode.HASH).masked_text)

    def test_random_salt_warns_and_differs_per_instance(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PII_MASKER_SALT", None)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                a = PIIMasker().mask("call 0912345678", mode=MaskMode.HASH).masked_text
                b = PIIMasker().mask("call 0912345678", mode=MaskMode.HASH).masked_text
        self.assertNotEqual(a, b)
        self.assertTrue(any("salt" in str(w.message) for w in caught))

    def test_cli_salt_option(self):
        _, out1, _ = run_cli(["mask", "call 0912345678", "--mode", "hash", "--salt", "cli-salt"])
        _, out2, _ = run_cli(["mask", "call 0912345678", "--mode", "hash", "--salt", "cli-salt"])
        expected = PIIMasker(salt="cli-salt").mask("call 0912345678", mode=MaskMode.HASH).masked_text
        self.assertEqual(out1.strip(), expected)
        self.assertEqual(out1, out2)


class TestScan(unittest.TestCase):
    """Finding 8: no secrets in scan output, every text file scanned, read errors reported."""

    def test_scan_output_hides_values_and_covers_dotfiles(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret = "sk-" + "Q" * 40
            with open(os.path.join(tmpdir, ".env"), "w", encoding="utf-8") as f:
                f.write(f"TOKEN={secret}\n")
            with open(os.path.join(tmpdir, "notes.cfg"), "w", encoding="utf-8") as f:
                f.write("owner\nalice@example.com\n")
            with open(os.path.join(tmpdir, "blob.bin"), "wb") as f:
                f.write(b"\x00\x01 alice@example.com")
            code, out, _ = run_cli(["scan", tmpdir, "--strict"])
            self.assertEqual(code, 1)
            self.assertNotIn(secret, out)
            self.assertNotIn("alice@example.com", out)
            self.assertIn(".env:1", out)
            self.assertIn("notes.cfg:2", out)
            self.assertIn("(43 chars)", out)
            self.assertNotIn("blob.bin", out)

    def test_scan_reports_unreadable_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                os.symlink(os.path.join(tmpdir, "missing.txt"), os.path.join(tmpdir, "dangling.txt"))
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not available")
            code, _, err = run_cli(["scan", tmpdir])
            self.assertEqual(code, 0)
            self.assertIn("dangling.txt", err)


class TestDetection(unittest.TestCase):
    """Findings 9-13, 18 and 23: patterns, overlap resolution and the allowlist."""

    def setUp(self):
        self.masker = PIIMasker()

    def assertMasked(self, text, category, value):
        res = self.masker.mask(text)
        self.assertNotIn(value, res.masked_text)
        self.assertIn((category, value), [(e.category, e.original) for e in res.entities])

    def test_ipv6_whole_address(self):
        for addr in ["2001:db8:85a3::8a2e:370:7334", "fe80::1ff:fe23:4567:890a", "::ffff:c000:280",
                     "2001:db8::", "::ffff:192.0.2.128"]:
            self.assertMasked(f"addr {addr} ok", "IPV6_ADDRESS", addr)
        res = self.masker.mask("addr 2001:db8::1.")
        self.assertEqual(res.masked_text, "addr <IPV6_ADDRESS_1>.")

    def test_ipv6_false_positives(self):
        for text in ["call Add::add(x)", "std::vector<int> v;", "x = items[::2]", "at 10:30:45", "MAC 00:1A:2B:3C:4D:5E"]:
            self.assertNotIn("IPV6_ADDRESS", self.masker.mask(text).categories, text)

    def test_api_key_formats(self):
        keys = [
            "sk-proj-" + "A1b2C3d4E5" * 4 + "_" + "x9Y8z7W6v5" * 4,
            "sk-" + "a" * 70,
            "sk_" + "live_51" + "Ab3" * 33,  # split so secret scanners do not flag the test
            "rk_" + "test_" + "Zz9" * 8,
            "sk-ant-api03-" + "abcdefghij" * 3,
        ]
        for key in keys:
            self.assertMasked(f"key {key} end", "API_KEY", key)

    def test_connection_strings(self):
        cases = [
            "mongodb+srv://admin:p4ss!w$rd@cluster0.example.com",
            "postgresql+psycopg2://admin:S3cret@db.example.com",
            "amqp://guest:guest@mq.example.com",
            "rediss://:s3cret@cache.example.com",
            "mssql://sa:Pa55@word@sql.example.com",
            "sftp://deploy:hunter2@files.example.com",
        ]
        for url in cases:
            res = self.masker.mask(f"uri {url}/db")
            self.assertEqual(res.masked_text, "uri <CREDENTIALS_1>/db", url)
            self.assertEqual(res.mapping["<CREDENTIALS_1>"], url)

    def test_card_after_year_is_not_leaked(self):
        res = self.masker.mask("Order 2024 4111 1111 1111 1111 ok")
        self.assertEqual([e.category for e in res.entities], ["CREDIT_CARD"])
        self.assertNotIn("1111", res.masked_text)

    def test_grouped_iban(self):
        res = self.masker.mask("IBAN DE89 3704 0044 0532 0130 00 ok")
        self.assertEqual(res.masked_text, "IBAN <IBAN_1> ok")
        self.assertNotIn("IBAN", self.masker.mask("IBAN DE89 3704 0044 0532 0130 01 ok").categories)

    def test_allowlist_is_exact_and_ignores_blank_entries(self):
        masker = PIIMasker(allowlist=["bob@example.com", "192.0.2.1", "", "  "])
        res = masker.mask("jimbob@example.com, BOB@example.com, 192.0.2.10, 192.0.2.1")
        self.assertEqual(res.masked_text, "<EMAIL_1>, BOB@example.com, <IP_ADDRESS_1>, 192.0.2.1")
        self.assertTrue(masker.is_allowlisted(" Bob@Example.com "))
        self.assertFalse(masker.is_allowlisted("jimbob@example.com"))
        self.assertFalse(PIIMasker(allowlist=[""]).is_allowlisted("alice@example.com"))

    def test_allowlisted_value_stays_intact_when_overlapped(self):
        masker = PIIMasker(allowlist=["0912345678@example.com"])
        self.assertEqual(masker.mask("mail 0912345678@example.com").masked_text, "mail 0912345678@example.com")

    def test_empty_countries_loads_no_country_rules(self):
        self.assertFalse([p for p in PIIMasker(countries=[]).patterns if p.country == "VN"])
        self.assertTrue([p for p in PIIMasker().patterns if p.country == "VN"])

    def test_vn_phone_needs_leading_boundary(self):
        self.assertNotIn("PHONE", self.masker.mask("ref 1230912345678").categories)

    def test_bearer_requires_a_token(self):
        self.assertFalse(self.masker.mask("The bearer of bad news").has_pii)
        self.assertFalse(self.masker.mask("Bearer responsibilities").has_pii)
        token = "Bearer abcDEF123456ghiJKL789"
        self.assertMasked(f"Authorization: {token}", "API_KEY", token)

    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self.masker.mask("mail bob@example.com", mode="redacted")
        self.assertIn("redact", str(ctx.exception))
        with self.assertRaises(ValueError):
            self.masker.mask("", mode="nope")

    def test_adversarial_inputs_run_in_linear_time(self):
        inputs = {
            "email dots": "1." * 50000,
            "email dashes": "a-" * 50000,
            "pem headers": "-----BEGIN PRIVATE KEY-----\n" * 3600,
            "ipv6 colons": "1:" * 50000,
            "key prefixes": "sk-" * 33000,
        }
        for label, text in inputs.items():
            start = time.perf_counter()
            self.masker.mask(text)
            self.assertLess(time.perf_counter() - start, 2.0, label)


class TestSyntheticAndUnmask(unittest.TestCase):
    """Finding 14: synthetic values are unique, reserved and never prefixes; unmask is single-pass."""

    def test_values_unique_and_prefix_free(self):
        for category in SYNTHETIC_TEMPLATES:
            values = [_synthetic_builtin(category, n, "postgres://u:p@h") for n in range(1, 600)]
            self.assertEqual(len(set(values)), len(values), category)
            ordered = sorted(values)
            for a, b in zip(ordered, ordered[1:]):
                self.assertFalse(b.startswith(a), (category, a, b))

    def test_shipped_templates_describe_first_value(self):
        for category, template in SYNTHETIC_TEMPLATES.items():
            self.assertEqual(template.format(n=1), _synthetic_builtin(category, 1, "postgres://u:p@h"), category)

    def test_values_come_from_reserved_ranges(self):
        import ipaddress

        for n in (1, 10, 155, 466, 79000):
            ip = ipaddress.ip_address(_synthetic_builtin("IP_ADDRESS", n, ""))
            self.assertTrue(
                any(ip in ipaddress.ip_network(net) for net in
                    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15")), ip)
        for n in (1, 70000):
            self.assertIn(ipaddress.ip_address(_synthetic_builtin("IPV6_ADDRESS", n, "")),
                          ipaddress.ip_network("2001:db8::/32"))
            self.assertRegex(_synthetic_builtin("PHONE", n, ""), r"^\+1-\d{3}-555-01\d\d$")
            self.assertFalse(luhn_checksum(_synthetic_builtin("CREDIT_CARD", n, "")))

    def test_many_entities_round_trip(self):
        masker = PIIMasker()
        text = " ".join(f"203.0.113.{i}" for i in range(1, 30)) + " alice@example.com user2@example.com"
        res = masker.synthetic_mask(text)
        self.assertEqual(len(set(res.mapping)), 31)
        self.assertEqual(masker.unmask(res.masked_text, res.mapping), text)

    def test_cards_and_ibans_do_not_collide(self):
        masker = PIIMasker()
        text = "a 4111111111111111 b 5555555555554444"
        res = masker.synthetic_mask(text)
        self.assertEqual(len(res.mapping), 2)
        self.assertEqual(masker.unmask(res.masked_text, res.mapping), text)

    def test_custom_template_is_used(self):
        with mock.patch.dict(SYNTHETIC_TEMPLATES, {"EMAIL": "person{n}@example.org"}):
            res = PIIMasker().synthetic_mask("mail alice@example.com")
        self.assertEqual(res.masked_text, "mail person1@example.org")

    def test_unmask_is_single_pass(self):
        self.assertEqual(PIIMasker.unmask("<A> <B>", {"<A>": "<B>", "<B>": "x"}), "<B> x")
        self.assertEqual(PIIMasker.unmask("<EMAIL_10> <EMAIL_1>", {"<EMAIL_1>": "a", "<EMAIL_10>": "b"}), "b a")


class TestUnmaskCli(unittest.TestCase):
    """Finding 24: a malformed mapping file is a clean error."""

    def test_non_dict_mapping(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = os.path.join(tmpdir, "bad.json")
            with open(bad, "w", encoding="utf-8") as f:
                f.write("[1, 2]")
            code, _, err = run_cli(["unmask", "x", "-m", bad])
            self.assertEqual(code, 1)
            self.assertIn("must be a JSON object", err)
            with open(bad, "w", encoding="utf-8") as f:
                f.write("{not json")
            code, _, err = run_cli(["unmask", "x", "-m", bad])
            self.assertEqual(code, 1)
            self.assertIn("Cannot read mapping", err)


if __name__ == "__main__":
    unittest.main()
