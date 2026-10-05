"""
Global PII detection patterns (Email, US SSN, Generic Phone, Passwords in URLs).
"""

import re
from typing import List
from pii_masker.patterns.base import PIIPattern

# Email regex. The local part starts only where a run of local-part characters starts
# (a lookbehind instead of \b), so inputs like "1.1.1.1..." are scanned once, not quadratically.
EMAIL_REGEX = re.compile(
    r"(?<![A-Za-z0-9_.%+\-])[A-Za-z0-9_.%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
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

# Password embedded in URLs of any scheme (e.g. postgresql+psycopg2://user:password@host:5432/db,
# mongodb+srv://..., amqp://..., rediss://...). The match is scheme://user:password@host: the
# password runs to the last "@" before the host, so a password containing "@" is masked whole.
URL_CREDENTIALS_REGEX = re.compile(
    r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]*://[^\s/?#@:]*:[^\s/?#]*@"
    r"(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._~%\-]+)"
)

GLOBAL_PATTERNS: List[PIIPattern] = [
    PIIPattern(category="EMAIL", regex=EMAIL_REGEX, description="Standard Email address"),
    PIIPattern(category="SSN", regex=US_SSN_REGEX, description="US Social Security Number (SSN)", country="US"),
    PIIPattern(category="PHONE", regex=GENERIC_PHONE_REGEX, description="International Formatted Phone Number"),
    PIIPattern(category="CREDENTIALS", regex=URL_CREDENTIALS_REGEX, description="Credentials in Connection URL", priority=1),
]
