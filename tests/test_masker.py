"""
Unit tests for pii_masker.
Uses standard library unittest (zero external dependencies).
"""

import unittest
from pii_masker.core import PIIMasker, mask_text, unmask_text


class TestPIIMasker(unittest.TestCase):
    def setUp(self):
        self.masker = PIIMasker()

    def test_email_mask_and_unmask(self):
        text = "Contact Alice at alice.smith@company.com or bob@gmail.com for help."
        res = self.masker.mask(text, reversible=True)
        
        self.assertTrue(res.has_pii)
        self.assertEqual(len(res.entities), 2)
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

    def test_api_keys_masking(self):
        text = (
            "OpenAI: sk-abcdefghijklmnopqrstuvwx123456, "
            "Anthropic: sk-ant-api03-abcdefghijklmnop123456789, "
            "GitHub: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        )
        res = self.masker.mask(text, reversible=False)
        self.assertTrue(res.has_pii)
        self.assertIn("[API_KEY]", res.masked_text)
        self.assertNotIn("sk-abcdef", res.masked_text)
        self.assertNotIn("ghp_1234", res.masked_text)

    def test_credit_card_masking(self):
        text = "Card number is 4532-1234-5678-9012."
        res = self.masker.mask(text, reversible=False)
        self.assertTrue(res.has_pii)
        self.assertIn("[CREDIT_CARD]", res.masked_text)
        self.assertNotIn("4532", res.masked_text)

    def test_empty_and_clean_text(self):
        res_empty = self.masker.mask("")
        self.assertFalse(res_empty.has_pii)
        self.assertEqual(res_empty.masked_text, "")

        clean_text = "The weather today is sunny and pleasant."
        res_clean = self.masker.mask(clean_text)
        self.assertFalse(res_clean.has_pii)
        self.assertEqual(res_clean.masked_text, clean_text)

    def test_convenience_functions(self):
        prompt = "Send report to support@anthropic.com please."
        res = mask_text(prompt)
        self.assertIn("<EMAIL_1>", res.masked_text)
        restored = unmask_text(res.masked_text, res.mapping)
        self.assertEqual(restored, prompt)


if __name__ == "__main__":
    unittest.main()
