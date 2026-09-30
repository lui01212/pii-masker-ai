"""
Global PII detection patterns (Email, US SSN, Generic Phone, Passwords in URLs).
"""

import re
from typing import List
from pii_masker.patterns.base import PIIPattern

# Email regex
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# US Social Security Number (SSN: 3 digits - 2 digits - 4 digits, excluding invalid area numbers)
US_SSN_REGEX = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)

# Generic international phone numbers:
# 1) E.164 with + prefix (e.g. +14155552671, +44 20 7183 8750)
# 2) Formatted phone numbers with separators (e.g. (123) 456-7890, 123-456-7890)
GENERIC_PHONE_REGEX = re.compile(
    r"\+\d{1,4}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{3,4}\b|"
    r"\b\(\d{2,4}\)[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b|"
    r"\b\d{3,4}[-.\s]\d{3,4}[-.\s]\d{3,4}\b"
)

# Password embedded in URLs (e.g., postgresql://user:password@host:5432/db)
URL_CREDENTIALS_REGEX = re.compile(
    r"\b(?:https?|ftp|postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9_\-\.%]+:([a-zA-Z0-9_\-\.%!$&'()*+,;=]+)@"
)

GLOBAL_PATTERNS: List[PIIPattern] = [
    PIIPattern(category="EMAIL", regex=EMAIL_REGEX, description="Standard Email address"),
    PIIPattern(category="SSN", regex=US_SSN_REGEX, description="US Social Security Number (SSN)", country="US"),
    PIIPattern(category="PHONE", regex=GENERIC_PHONE_REGEX, description="International Formatted Phone Number"),
    PIIPattern(category="CREDENTIALS", regex=URL_CREDENTIALS_REGEX, description="Credentials in Connection URL"),
]
