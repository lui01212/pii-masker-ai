"""
Network PII detection patterns (IPv4, IPv6, MAC Address).
Zero external dependencies, leverages standard library `ipaddress`.
"""

import ipaddress
import re
from typing import List
from pii_masker.patterns.base import PIIPattern


def is_valid_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return not ip.is_loopback  # Still detect or flag as requested
    except Exception:
        return False


def is_valid_ipv6(ip_str: str) -> bool:
    # Code such as "Add::add" or "x[10::2]" is also valid IPv6 syntax: require a decimal
    # digit and at least two non-empty groups before asking ipaddress.
    if not any(c.isdigit() for c in ip_str):
        return False
    if sum(1 for group in ip_str.split(":") if group) < 2:
        return False
    try:
        ip = ipaddress.IPv6Address(ip_str)
        return not ip.is_loopback
    except Exception:
        return False


# IPv4 regex
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# IPv6 candidate regex: a whole run of hex digits, colons and dots (for embedded IPv4) with at
# least two colons, not glued to surrounding word characters. The validator decides; matching
# the whole run avoids masking only part of an address (2001:db8:85a3::8a2e:370:7334, ::ffff:c000:280).
IPV6_REGEX = re.compile(
    r"(?<![0-9A-Za-z_:.])"
    r"(?=[0-9A-Fa-f.]*:[0-9A-Fa-f.]*:)"
    r"(?:[0-9A-Fa-f:.]*[0-9A-Fa-f]|[0-9A-Fa-f:]*::)"
    r"(?![0-9A-Za-z_:])"
)

# MAC Address regex: 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E
MAC_ADDRESS_REGEX = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
)

NETWORK_PATTERNS: List[PIIPattern] = [
    PIIPattern(
        category="IP_ADDRESS",
        regex=IPV4_REGEX,
        description="IPv4 Address",
        validator=is_valid_ipv4,
    ),
    PIIPattern(
        category="IPV6_ADDRESS",
        regex=IPV6_REGEX,
        description="IPv6 Address",
        validator=is_valid_ipv6,
    ),
    PIIPattern(
        category="MAC_ADDRESS",
        regex=MAC_ADDRESS_REGEX,
        description="Hardware MAC Address",
    ),
]
