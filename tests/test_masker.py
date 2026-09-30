"""
Comprehensive unit tests for pii_masker.
Uses standard library unittest (zero external dependencies).
"""

import unittest
from pii_masker.core import PIIMasker, mask_text, unmask_text, redact_text
from pii_masker.patterns.base import PIIPattern
from pii_masker.patterns.financial import luhn_checksum, iban_validator
import re


class TestPIIMasker(unittest.TestCase):
    def setUp(self):
        self.masker = PIIMasker()

    def test_email_mask_and_unmask(self):
        text = "Contact Alice at alice.smith@company.com or bob@gmail.com for help."
        res = self.masker.mask(text, reversible=True)

        self.assertTrue(res.has_pii)
        self.assertEqual(res.entity_count, 2)
        self.assertIn("<EMAIL_1>", res.masked_text)
        self.assertIn("<EMAIL_2>", res.masked_text)
        self.assertNotIn("alice.smith@company.com", res.masked_text)

        # Test unmasking
        restored = self.masker.unmask(res.masked_text, res.mapping)
        self.assertEqual(restored, text)

    def test_vietnam_phone_and_cccd(self):
        text = "Khách hàng Nguyễn Văn A, SĐT: 0912345678, CCCD: 001201012345."
        res = self.masker.mask(text, reversible=True)

        self.assertTrue(res.has_pii)
        self.assertIn("<PHONE_1>", res.masked_text)
        self.assertIn("<GOV_ID_1>", res.masked_text)
        self.assertNotIn("0912345678", res.masked_text)
        self.assertNotIn("001201012345", res.masked_text)

        # Unmask test
        restored = self.masker.unmask(res.masked_text, res.mapping)
        self.assertEqual(restored, text)

    def test_vietnam_phone_variations(self):
        text = "Call +84987654321 or 84381234567 or 0791234567."
        res = self.masker.mask(text)
        self.assertEqual(res.entity_count, 3)
        self.assertTrue(all(e.category == "PHONE" for e in res.entities))

    def test_vietnam_invalid_cccd_rejected(self):
        # Province code 999 is invalid in Vietnam (valid is 001-096)
        text = "CCCD giả: 999201012345."
        res = self.masker.mask(text)
        # Should not match as CCCD
        self.assertNotIn("GOV_ID", res.categories)

    def test_vietnam_tax_id(self):
        text = "Mã số thuế doanh nghiệp: 0101234567 hoặc chi nhánh 0101234567-001."
        res = self.masker.mask(text)
        self.assertTrue(res.has_pii)
        self.assertIn("TAX_ID", res.categories)

    def test_vietnam_passport(self):
        text = "Hộ chiếu số B1234567 hoặc C7654321."
        res = self.masker.mask(text)
        self.assertTrue(res.has_pii)
        self.assertIn("PASSPORT", res.categories)

    def test_api_keys_openai_and_anthropic(self):
        text = (
            "OpenAI: sk-abcdefghijklmnopqrstuvwx123456, "
            "Anthropic: sk-ant-api03-abcdefghijklmnop123456789"
        )
        res = self.masker.mask(text, reversible=False)
        self.assertTrue(res.has_pii)
        self.assertIn("[API_KEY]", res.masked_text)
        self.assertNotIn("sk-abcdef", res.masked_text)
        self.assertNotIn("sk-ant-api03", res.masked_text)

    def test_api_keys_github_and_aws(self):
        text = "GitHub: ghp_1234567890abcdefghijklmnopqrstuvwxyz, AWS: AKIAIOSFODNN7EXAMPLE"
        res = self.masker.mask(text, reversible=False)
        self.assertTrue(res.has_pii)
        self.assertNotIn("ghp_1234", res.masked_text)
        self.assertNotIn("AKIAIOSF", res.masked_text)

    def test_api_keys_jwt(self):
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        text = f"Token is {jwt_token}."
        res = self.masker.mask(text, reversible=True)
        self.assertTrue(res.has_pii)
        self.assertIn("<JWT_TOKEN_1>", res.masked_text)
        self.assertNotIn("eyJhbGci", res.masked_text)

        restored = self.masker.unmask(res.masked_text, res.mapping)
        self.assertEqual(restored, text)

    def test_private_key_masking(self):
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1+rNqXyZ8p...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        text = f"Config key:\n{pem}"
        res = self.masker.mask(text, reversible=True)
        self.assertIn("<PRIVATE_KEY_1>", res.masked_text)
        self.assertNotIn("MIIEow", res.masked_text)

        restored = self.masker.unmask(res.masked_text, res.mapping)
        self.assertEqual(restored, text)

    def test_api_keys_slack_google_stripe(self):
        google_key = "AIzaSy" + ("B" * 33)
        fake_stripe_key = "sk_" + "test_" + ("z" * 24)
        text = (
            "Slack: xoxb-123456789012-1234567890123-456789abcdef,\n"
            f"Google: {google_key},\n"
            f"Stripe: {fake_stripe_key}"
        )
        res = self.masker.mask(text, reversible=False)
        self.assertTrue(res.has_pii)
        self.assertNotIn("xoxb-", res.masked_text)
        self.assertNotIn("AIzaSy", res.masked_text)
        self.assertNotIn("sk_test_", res.masked_text)

    def test_luhn_checksum_helper(self):
        # Valid test card (Visa)
        self.assertTrue(luhn_checksum("4532015112830366"))
        self.assertTrue(luhn_checksum("4532-0151-1283-0366"))
        # Invalid test card (corrupted digit)
        self.assertFalse(luhn_checksum("4532015112830367"))
        # Short string
        self.assertFalse(luhn_checksum("12345"))

    def test_credit_card_valid_luhn(self):
        text = "Payment card: 4532-0151-1283-0366."
        res = self.masker.mask(text, reversible=True)
        self.assertTrue(res.has_pii)
        self.assertIn("<CREDIT_CARD_1>", res.masked_text)
        self.assertNotIn("4532", res.masked_text)

    def test_credit_card_invalid_luhn_ignored(self):
        # Invalid checksum should NOT be flagged as CREDIT_CARD
        text = "Random number: 4532-0151-1283-0367."
        res = self.masker.mask(text)
        self.assertNotIn("CREDIT_CARD", res.categories)

    def test_iban_validation(self):
        # Valid German test IBAN
        valid_iban = "DE89370400440532013000"
        self.assertTrue(iban_validator(valid_iban))
        res = self.masker.mask(f"IBAN: {valid_iban}")
        self.assertIn("IBAN", res.categories)

    def test_ipv4_masking(self):
        text = "Server connection from 198.51.100.42 and 203.0.113.195"
        res = self.masker.mask(text, reversible=True)
        self.assertTrue(res.has_pii)
        self.assertIn("<IP_ADDRESS_1>", res.masked_text)
        self.assertIn("<IP_ADDRESS_2>", res.masked_text)
        self.assertNotIn("198.51.100.42", res.masked_text)

    def test_ipv6_masking(self):
        text = "Connected over 2001:0db8:85a3:0000:0000:8a2e:0370:7334 or 2001:db8::1"
        res = self.masker.mask(text, reversible=True)
        self.assertTrue(res.has_pii)
        self.assertIn("IPV6_ADDRESS", res.categories)

    def test_mac_address_masking(self):
        text = "Device MAC is 00:1A:2B:3C:4D:5E."
        res = self.masker.mask(text, reversible=True)
        self.assertTrue(res.has_pii)
        self.assertIn("<MAC_ADDRESS_1>", res.masked_text)
        self.assertNotIn("00:1A:2B:3C:4D:5E", res.masked_text)

    def test_us_ssn_masking(self):
        text = "Taxpayer SSN is 123-45-6789."
        res = self.masker.mask(text, reversible=True)
        self.assertTrue(res.has_pii)
        self.assertIn("<SSN_1>", res.masked_text)
        self.assertNotIn("123-45-6789", res.masked_text)

    def test_empty_and_clean_text(self):
        res_empty = self.masker.mask("")
        self.assertFalse(res_empty.has_pii)
        self.assertEqual(res_empty.masked_text, "")

        clean_text = "The weather today is sunny and pleasant."
        res_clean = self.masker.mask(clean_text)
        self.assertFalse(res_clean.has_pii)
        self.assertEqual(res_clean.masked_text, clean_text)

    def test_redact_convenience_function(self):
        text = "User email is test@domain.com."
        redacted = redact_text(text)
        self.assertEqual(redacted, "User email is [EMAIL].")

    def test_convenience_functions(self):
        prompt = "Send report to support@anthropic.com please."
        res = mask_text(prompt)
        self.assertIn("<EMAIL_1>", res.masked_text)
        restored = unmask_text(res.masked_text, res.mapping)
        self.assertEqual(restored, prompt)

    def test_selective_masker_options(self):
        # Disable API keys
        masker_no_keys = PIIMasker(include_api_keys=False)
        text = "Key: sk-1234567890abcdef123456, Email: user@test.com"
        res = masker_no_keys.mask(text)
        self.assertNotIn("API_KEY", res.categories)
        self.assertIn("EMAIL", res.categories)

    def test_custom_pattern(self):
        custom = PIIPattern(
            category="ORDER_ID",
            regex=re.compile(r"\bORD-[0-9]{5}\b"),
            description="Internal order code",
        )
        custom_masker = PIIMasker(custom_patterns=[custom])
        text = "Order processed: ORD-99123."
        res = custom_masker.mask(text)
        self.assertIn("<ORDER_ID_1>", res.masked_text)
        self.assertEqual(res.mapping["<ORDER_ID_1>"], "ORD-99123")

    def test_multiple_entities_in_same_prompt(self):
        prompt = (
            "User: alice@example.com (Phone: 0912345678, IP: 198.51.100.1)\n"
            "Report: Paid with Visa 4532-0151-1283-0366."
        )
        res = self.masker.mask(prompt, reversible=True)
        self.assertEqual(res.entity_count, 4)
        expected_categories = {"EMAIL", "PHONE", "IP_ADDRESS", "CREDIT_CARD"}
        self.assertEqual(res.categories, expected_categories)

    def test_cli_mask_command(self):
        from pii_masker.cli import main
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["mask", "My email is test@domain.com.", "--redact"])
        self.assertEqual(exit_code, 0)
        self.assertIn("My email is [EMAIL].", buf.getvalue())

    def test_cli_help(self):
        from pii_masker.cli import main
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main([])
        self.assertEqual(exit_code, 0)
        self.assertIn("pii-masker", buf.getvalue())

    def test_hash_masking_mode(self):
        from pii_masker.core import MaskMode
        text = "Contact alice@example.com or alice@example.com again."
        res = self.masker.mask(text, mode=MaskMode.HASH)
        self.assertTrue(res.has_pii)
        # Should be formatted as <EMAIL_xxxxxxxx>
        self.assertRegex(res.masked_text, r"<EMAIL_[a-f0-9]{8}>")
        # Check mapping
        self.assertIn("alice@example.com", res.mapping.values())
        # Restoring should recover original
        restored = self.masker.unmask(res.masked_text, res.mapping)
        self.assertEqual(restored, text)

    def test_hash_masking_custom_salt(self):
        from pii_masker.core import PIIMasker, MaskMode
        m1 = PIIMasker(salt="salt-alpha")
        m2 = PIIMasker(salt="salt-beta")
        text = "Secret email: dev@corp.io"
        r1 = m1.mask(text, mode=MaskMode.HASH)
        r2 = m2.mask(text, mode=MaskMode.HASH)
        self.assertNotEqual(r1.masked_text, r2.masked_text)

    def test_synthetic_masking_mode(self):
        from pii_masker.core import MaskMode
        text = "Reach me at customer@gmail.com or 0901234567."
        res = self.masker.synthetic_mask(text)
        self.assertTrue(res.has_pii)
        self.assertNotIn("customer@gmail.com", res.masked_text)
        self.assertNotIn("0901234567", res.masked_text)
        self.assertIn("user1@example.com", res.masked_text)
        # Restoring
        restored = self.masker.unmask(res.masked_text, res.mapping)
        self.assertEqual(restored, text)

    def test_allowlist_exemption(self):
        from pii_masker.core import PIIMasker
        # Whitelist public company support email and internal domain
        masker = PIIMasker(allowlist=["support@mycompany.com", "127.0.0.1"])
        text = (
            "Contact public support@mycompany.com or private admin@gmail.com "
            "at localhost 127.0.0.1 vs server 198.51.100.4."
        )
        res = masker.mask(text)
        # support@mycompany.com and 127.0.0.1 should NOT be masked
        self.assertIn("support@mycompany.com", res.masked_text)
        self.assertIn("127.0.0.1", res.masked_text)
        # admin@gmail.com and 198.51.100.4 MUST be masked
        self.assertNotIn("admin@gmail.com", res.masked_text)
        self.assertNotIn("198.51.100.4", res.masked_text)

    def test_langchain_chat_wrapper_round_trip(self):
        from pii_masker.integrations import PIIChatWrapper

        # Mock LLM that echoes prompt back with an answer
        class MockLLM:
            def invoke(self, prompt: str) -> str:
                # LLM sees <EMAIL_1> and references it
                return f"Confirmed. Sending notification to {prompt.split()[-1]} now."

        mock_llm = MockLLM()
        shielded = PIIChatWrapper(mock_llm)

        user_prompt = "Please send invoice to john.doe@acme.corp"
        output = shielded.invoke(user_prompt)

        # Output must be unmasked back to original email!
        self.assertIn("john.doe@acme.corp", output)
        self.assertNotIn("<EMAIL_1>", output)

    def test_langchain_callback_raise_on_pii(self):
        from pii_masker.integrations import PIILangChainCallback
        cb = PIILangChainCallback(raise_on_pii=True)

        with self.assertRaises(ValueError) as ctx:
            cb.on_llm_start({}, ["Here is my key: AKIAIOSFODNN7EXAMPLE"])
        self.assertIn("PIISecurityException", str(ctx.exception))

    def test_cli_batch_jsonl(self):
        import tempfile
        import json
        from pii_masker.cli import main

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = f"{tmpdir}/dataset.jsonl"
            output_file = f"{tmpdir}/sanitized.jsonl"
            mapping_file = f"{tmpdir}/map.json"

            sample = [
                {"id": 1, "prompt": "My phone is 0912345678", "tag": "test"},
                {"id": 2, "prompt": "Email me at dev@corp.vn", "tag": "test2"},
            ]
            with open(input_file, "w", encoding="utf-8") as f:
                for row in sample:
                    f.write(json.dumps(row) + "\n")

            exit_code = main([
                "batch",
                "-i", input_file,
                "-o", output_file,
                "--fields", "prompt",
                "--mode", "redact",
                "--save-mapping", mapping_file
            ])
            self.assertEqual(exit_code, 0)

            with open(output_file, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f]
            self.assertEqual(lines[0]["prompt"], "My phone is [PHONE]")
            self.assertEqual(lines[1]["prompt"], "Email me at [EMAIL]")
            self.assertEqual(lines[0]["tag"], "test")

    def test_cli_batch_csv(self):
        import tempfile
        import csv
        from pii_masker.cli import main

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = f"{tmpdir}/dataset.csv"
            output_file = f"{tmpdir}/sanitized.csv"

            with open(input_file, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["id", "contact", "status"])
                writer.writeheader()
                writer.writerow({"id": "1", "contact": "0987654321", "status": "active"})

            exit_code = main([
                "batch",
                "-i", input_file,
                "-o", output_file,
                "--fields", "contact",
                "--mode", "reversible"
            ])
            self.assertEqual(exit_code, 0)

            with open(output_file, "r", encoding="utf-8", newline="") as f:
                reader = list(csv.DictReader(f))
            self.assertIn("<PHONE_1>", reader[0]["contact"])
            self.assertEqual(reader[0]["status"], "active")


    def test_cli_batch_plain_text(self):
        import tempfile
        from pii_masker.cli import main

        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = f"{tmpdir}/notes.txt"
            output_file = f"{tmpdir}/sanitized.txt"
            with open(input_file, "w", encoding="utf-8") as f:
                f.write("Note: Email alice@example.com for login.\n")

            exit_code = main(["batch", "-i", input_file, "-o", output_file, "--mode", "redact"])
            self.assertEqual(exit_code, 0)
            with open(output_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Email [EMAIL] for login.", content)

    def test_batch_file_not_found_handled(self):
        from pii_masker.cli import main
        exit_code = main(["batch", "-i", "nonexistent_file_xyz_123.jsonl"])
        self.assertEqual(exit_code, 1)

    def test_allowlist_from_file(self):
        import tempfile
        from pii_masker.cli import _load_allowlist
        with tempfile.TemporaryDirectory() as tmpdir:
            allow_path = f"{tmpdir}/whitelist.txt"
            with open(allow_path, "w", encoding="utf-8") as f:
                f.write("# comments are ignored\ncorp.internal\nadmin@safe.com\n")
            loaded = _load_allowlist(allow_path)
            self.assertEqual(loaded, {"corp.internal", "admin@safe.com"})

    def test_mask_empty_and_none_text(self):
        res = self.masker.mask("")
        self.assertEqual(res.masked_text, "")
        self.assertEqual(res.entity_count, 0)

    def test_unmask_empty_mapping(self):
        text = "Hello world"
        restored = self.masker.unmask(text, {})
        self.assertEqual(restored, text)

    def test_mac_address_and_ipv6_masking(self):
        text = "Host 2001:db8::1 with MAC 00:1A:2B:3C:4D:5E connected."
        res = self.masker.mask(text, reversible=True)
        self.assertTrue(res.has_pii)
        self.assertIn("IPV6_ADDRESS", res.categories)
        self.assertIn("MAC_ADDRESS", res.categories)
        restored = self.masker.unmask(res.masked_text, res.mapping)
        self.assertEqual(restored, text)

    def test_langchain_chat_wrapper_dict_messages(self):
        from pii_masker.integrations import PIIChatWrapper

        class MockLLM:
            def invoke(self, messages: list) -> dict:
                return {"role": "assistant", "content": f"Echo: {messages[0]['content']}"}

        wrapper = PIIChatWrapper(MockLLM())
        input_messages = [{"role": "user", "content": "My phone is 0912345678"}]
        resp = wrapper.invoke(input_messages)
        self.assertIn("0912345678", resp["content"])

    def test_langchain_callback_chat_model_start(self):
        from pii_masker.integrations import PIILangChainCallback

        class MockMsg:
            def __init__(self, content):
                self.content = content

        cb = PIILangChainCallback(raise_on_pii=False)
        cb.on_chat_model_start({}, [[MockMsg("Key is sk-abcdefghijklmnopqrstuvwx123456")]])
        self.assertEqual(len(cb.detected_entities), 1)
        self.assertEqual(cb.detected_entities[0]["category"], "API_KEY")

    def test_synthetic_masking_all_templates(self):
        from pii_masker.core import PIIMasker, MaskMode
        m = PIIMasker()
        text = "IP: 198.51.100.2, Card: 4532-0151-1283-0366, Key: sk-abcdefghijklmnopqrstuvwx123456"
        res = m.synthetic_mask(text)
        self.assertIn("198.51.100.1", res.masked_text)
        self.assertIn("4532-0151-1283-0366", res.masked_text)  # card template
        self.assertIn("sk-synthetic-api-key-1", res.masked_text)
        restored = m.unmask(res.masked_text, res.mapping)
        self.assertEqual(restored, text)

    def test_cli_mask_with_json_and_mode_synthetic(self):
        import io
        import json
        from contextlib import redirect_stdout
        from pii_masker.cli import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            exit_code = main(["mask", "Contact 0912345678", "--mode", "synthetic", "--json"])
        self.assertEqual(exit_code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["mode"], "synthetic")
        self.assertEqual(data["entities_count"], 1)


if __name__ == "__main__":
    unittest.main()


