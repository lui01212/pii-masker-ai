"""
Vietnam-specific PII detection patterns (CCCD, CMND, Phone numbers, Tax IDs).
"""

import re
from typing import List
from pii_masker.patterns.base import PIIPattern

# Vietnam Phone Numbers: +84, 84, or 0 followed by 3, 5, 7, 8, 9 and 8 digits
VN_PHONE_REGEX = re.compile(
    r"(?:\+84|84|0)(?:3[2-9]|5[25689]|7[06-9]|8[1-9]|9[0-9])[0-9]{7}\b"
)

# Vietnam CCCD (12 digits) and CMND (9 digits)
# Example: 001201012345 (12 digits) or 012345678 (9 digits)
VN_CITIZEN_ID_REGEX = re.compile(
    r"\b(?:0\d{11}|\d{9})\b"
)

# Vietnam Tax Identification Number (Mã số thuế: 10 digits or 10 digits - 3 digits)
VN_TAX_ID_REGEX = re.compile(
    r"\b\d{10}(?:-\d{3})?\b"
)

VIETNAM_PATTERNS: List[PIIPattern] = [
    PIIPattern(category="PHONE", regex=VN_PHONE_REGEX, description="Vietnam Phone Number", country="VN"),
    PIIPattern(category="GOV_ID", regex=VN_CITIZEN_ID_REGEX, description="Vietnam Citizen ID (CCCD/CMND)", country="VN"),
    PIIPattern(category="TAX_ID", regex=VN_TAX_ID_REGEX, description="Vietnam Tax ID (MST)", country="VN"),
]
