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


if __name__ == "__main__":
    unittest.main()
