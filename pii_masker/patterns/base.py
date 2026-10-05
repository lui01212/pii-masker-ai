"""
Base dataclass for PII regex patterns.
"""

from dataclasses import dataclass
from typing import Callable, Optional, Pattern


@dataclass(frozen=True)
class PIIPattern:
    category: str      # e.g. "EMAIL", "PHONE", "API_KEY", "CREDIT_CARD", "GOV_ID", "IP_ADDRESS", "PRIVATE_KEY"
    regex: Pattern[str]
    description: str
    country: str = "GLOBAL"  # "GLOBAL", "VN", "US", etc.
    validator: Optional[Callable[[str], bool]] = None
    # Overlapping matches are merged into one span labelled with the highest-priority category.
    # Validated, specific detectors (cards, IBANs, keys, credentials) use 1; generic ones keep 0.
    priority: int = 0
