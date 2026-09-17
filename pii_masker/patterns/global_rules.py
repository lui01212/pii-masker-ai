"""
Global PII detection patterns (Email, IPv4, Credit Cards, URLs, etc.).
"""

import re
from typing import List
from pii_masker.patterns.base import PIIPattern

# Email regex
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# IPv4 regex (excluding local localhost / 127.0.0.1 if needed, but flagging public IPs)
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Credit Card regex (Visa, MasterCard, Amex, Discover)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
)

# Generic international phone numbers (E.164-like)
GENERIC_PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
)

GLOBAL_PATTERNS: List[PIIPattern] = [
    PIIPattern(category="EMAIL", regex=EMAIL_REGEX, description="Standard Email address"),
    PIIPattern(category="CREDIT_CARD", regex=CREDIT_CARD_REGEX, description="Major credit card numbers"),
    PIIPattern(category="IP_ADDRESS", regex=IPV4_REGEX, description="IPv4 Address"),
]
