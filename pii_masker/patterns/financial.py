"""
Financial PII detection patterns (Credit cards, IBAN, bank account numbers).
Includes Luhn algorithm validation for credit card numbers.
"""

import re
from typing import List
from pii_masker.patterns.base import PIIPattern


def luhn_checksum(card_number: str) -> bool:
    """
    Validate credit card number using the Luhn checksum algorithm (Mod 10).
    Ignores spaces and dashes.
    """
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    # Process from right to left
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d

    return checksum % 10 == 0


def iban_validator(iban: str) -> bool:
    """
    Validate International Bank Account Number (IBAN) mod-97 check.
    """
    clean_iban = re.sub(r"\s+", "", iban).upper()
    if len(clean_iban) < 15 or len(clean_iban) > 34:
        return False
    # Rearrange: move first 4 characters to end
    rearranged = clean_iban[4:] + clean_iban[:4]
    # Replace letters with digits: A=10, B=11, ..., Z=35
    digits = []
    for ch in rearranged:
        if ch.isdigit():
            digits.append(ch)
        elif "A" <= ch <= "Z":
            digits.append(str(ord(ch) - 55))
        else:
            return False
    num_str = "".join(digits)
    # Python handles arbitrary precision integers
    try:
        return int(num_str) % 97 == 1
    except ValueError:
        return False


# Regex for major credit card formats:
# Visa (4xxx), Mastercard (51-55, 22-27), Amex (34, 37), Discover (6011, 65), JCB (35)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"           # Visa
    r"5[1-5][0-9]{14}|2(?:2[2-9][0-9]{2}|[3-6][0-9]{3}|7[01][0-9]{2}|720[0-9])[0-9]{10}|"  # MasterCard
    r"3[47][0-9]{13}|"                         # American Express
    r"6(?:011|5[0-9]{2})[0-9]{12}|"            # Discover
    r"(?:2131|1800|35\d{3})\d{11}|"            # JCB
    r"(?:\d{4}[-\s]){3}\d{4}\b|"               # Formatted 16 digits
    r"\b\d{4}[-\s]\d{6}[-\s]\d{5}\b)"          # Formatted 15 digits (Amex)
)

# IBAN pattern: 2 letter country code, 2 digits, up to 30 alphanumeric characters,
# either unspaced or printed in space-separated groups of four (DE89 3704 0044 ...)
IBAN_REGEX = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[A-Za-z0-9]{11,30}|(?: [A-Za-z0-9]{4}){2,7}(?: [A-Za-z0-9]{1,4})?)\b"
)


def _iban_match_validator(candidate: str) -> bool:
    """Require some digits in the account part (as real BBANs have), then the mod-97 check."""
    return sum(c.isdigit() for c in candidate[4:]) >= 7 and iban_validator(candidate)


FINANCIAL_PATTERNS: List[PIIPattern] = [
    PIIPattern(
        category="CREDIT_CARD",
        regex=CREDIT_CARD_REGEX,
        description="Major credit card number (Visa, MC, Amex, Discover, JCB) with Luhn validation",
        validator=luhn_checksum,
        priority=1,
    ),
    PIIPattern(
        category="IBAN",
        regex=IBAN_REGEX,
        description="International Bank Account Number (IBAN)",
        validator=_iban_match_validator,
        priority=1,
    ),
]
