"""
Vietnam-specific PII detection patterns (CCCD, CMND, Phone numbers, Tax IDs, Passport).
"""

import re
from typing import List
from pii_masker.patterns.base import PIIPattern


def validate_vietnam_cccd(cccd_str: str) -> bool:
    """
    Validate 12-digit Vietnam Citizen Identification Card (CCCD):
    - Digits 1-3: Province code (001 - 096)
    - Digit 4: Gender and Century code (0-9)
    - Digits 5-6: Birth year (last 2 digits)
    - Digits 7-12: Random 6 digits
    """
    if len(cccd_str) != 12 or not cccd_str.isdigit():
        return False
    province_code = int(cccd_str[:3])
    if province_code < 1 or province_code > 96:
        return False
    return True


# Vietnam Phone Numbers: +84, 84, or 0 followed by 3, 5, 7, 8, 9 and 8 digits
VN_PHONE_REGEX = re.compile(
    r"(?:\+84|84|0)(?:3[2-9]|5[25689]|7[06-9]|8[1-9]|9[0-9])[0-9]{7}\b"
)

# Vietnam CCCD (12 digits starting with 0)
VN_CCCD_REGEX = re.compile(
    r"\b0\d{11}\b"
)

# Vietnam CMND (legacy 9 digits)
VN_CMND_REGEX = re.compile(
    r"\b\d{9}\b"
)

# Vietnam Tax Identification Number (Mã số thuế: 10 digits or 10 digits - 3 digits)
VN_TAX_ID_REGEX = re.compile(
    r"\b\d{10}(?:-\d{3})?\b"
)

# Vietnam Passport (B or C followed by 7 digits)
VN_PASSPORT_REGEX = re.compile(
    r"\b[BC]\d{7}\b"
)

VIETNAM_PATTERNS: List[PIIPattern] = [
    PIIPattern(category="PHONE", regex=VN_PHONE_REGEX, description="Vietnam Phone Number", country="VN"),
    PIIPattern(category="GOV_ID", regex=VN_CCCD_REGEX, description="Vietnam CCCD (12 digits)", country="VN", validator=validate_vietnam_cccd),
    PIIPattern(category="GOV_ID", regex=VN_CMND_REGEX, description="Vietnam CMND (9 digits)", country="VN"),
    PIIPattern(category="TAX_ID", regex=VN_TAX_ID_REGEX, description="Vietnam Tax ID (MST)", country="VN"),
    PIIPattern(category="PASSPORT", regex=VN_PASSPORT_REGEX, description="Vietnam Passport Number", country="VN"),
]
