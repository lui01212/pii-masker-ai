"""
Core PII masking and unmasking engine.
Supports reversible masking (for LLM context preservation) and redaction (permanent masking).
Zero external dependencies.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
import re

from pii_masker.patterns.base import PIIPattern
from pii_masker.patterns.global_rules import GLOBAL_PATTERNS
from pii_masker.patterns.api_keys import API_KEY_PATTERNS
from pii_masker.patterns.financial import FINANCIAL_PATTERNS
from pii_masker.patterns.network import NETWORK_PATTERNS
from pii_masker.patterns.vietnam import VIETNAM_PATTERNS


@dataclass
class DetectedEntity:
    category: str
    original: str
    placeholder: str
    start: int
    end: int


@dataclass
class MaskResult:
    masked_text: str
    mapping: Dict[str, str] = field(default_factory=dict)  # placeholder -> original
    entities: List[DetectedEntity] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return len(self.entities) > 0

    @property
    def entity_count(self) -> int:
        return len(self.entities)

    @property
    def categories(self) -> Set[str]:
        return {e.category for e in self.entities}


class PIIMasker:
    """
    Main PII Masker class for sanitizing text before sending to LLMs.
    Zero external dependencies.
    """

    def __init__(
        self,
        include_global: bool = True,
        include_api_keys: bool = True,
        include_financial: bool = True,
        include_network: bool = True,
        countries: Optional[List[str]] = None,
        custom_patterns: Optional[List[PIIPattern]] = None,
    ):
        self.patterns: List[PIIPattern] = []

        if include_global:
            self.patterns.extend(GLOBAL_PATTERNS)

        if include_api_keys:
            self.patterns.extend(API_KEY_PATTERNS)

        if include_financial:
            self.patterns.extend(FINANCIAL_PATTERNS)

        if include_network:
            self.patterns.extend(NETWORK_PATTERNS)

        country_set = {c.upper() for c in countries} if countries else {"VN"}
        if "VN" in country_set:
            self.patterns.extend(VIETNAM_PATTERNS)

        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def mask(self, text: str, reversible: bool = True) -> MaskResult:
        """
        Detect and mask PII in text.
        If reversible=True, generates numbered placeholders like `<EMAIL_1>`, `<PHONE_1>`.
        If reversible=False, permanently redacts with `[EMAIL]`, `[PHONE]`.
        """
        if not text:
            return MaskResult(masked_text="", mapping={}, entities=[])

        # Step 1: Find all matches across all patterns
        matches: List[Tuple[int, int, str, str]] = []  # (start, end, category, original_text)

        for pattern in self.patterns:
            for m in pattern.regex.finditer(text):
                start, end = m.span()
                matched_str = text[start:end]
                # Validate match if validator is provided
                if pattern.validator and not pattern.validator(matched_str):
                    continue
                matches.append((start, end, pattern.category, matched_str))

        # Sort matches by start position, then by length descending (longest match wins on overlap)
        matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))

        # Step 2: Remove overlapping intervals (greedy longest non-overlapping)
        non_overlapping: List[Tuple[int, int, str, str]] = []
        last_end = -1
        for start, end, category, matched_str in matches:
            if start >= last_end:
                non_overlapping.append((start, end, category, matched_str))
                last_end = end

        # Step 3: Assign placeholders and build mapping
        category_counters: Dict[str, int] = {}
        mapping: Dict[str, str] = {}
        entities: List[DetectedEntity] = []

        for start, end, category, matched_str in non_overlapping:
            if reversible:
                category_counters[category] = category_counters.get(category, 0) + 1
                placeholder = f"<{category}_{category_counters[category]}>"
                mapping[placeholder] = matched_str
            else:
                placeholder = f"[{category}]"

            entities.append(
                DetectedEntity(
                    category=category,
                    original=matched_str,
                    placeholder=placeholder,
                    start=start,
                    end=end,
                )
            )

        # Reconstruct the text
        result_chars = []
        cursor = 0
        for entity in entities:
            result_chars.append(text[cursor:entity.start])
            result_chars.append(entity.placeholder)
            cursor = entity.end
        result_chars.append(text[cursor:])

        masked_text = "".join(result_chars)
        return MaskResult(masked_text=masked_text, mapping=mapping, entities=entities)

    def redact(self, text: str) -> str:
        """Convenience method for permanent non-reversible redaction."""
        return self.mask(text, reversible=False).masked_text

    @staticmethod
    def unmask(text: str, mapping: Dict[str, str]) -> str:
        """
        Restore original PII data into LLM response using the provided mapping.
        """
        if not text or not mapping:
            return text

        result = text
        for placeholder, original in mapping.items():
            result = result.replace(placeholder, original)
        return result


# Module-level convenience functions
_default_masker = PIIMasker()


def mask_text(text: str, reversible: bool = True) -> MaskResult:
    """Mask text using default settings."""
    return _default_masker.mask(text, reversible=reversible)


def redact_text(text: str) -> str:
    """Permanently redact PII from text."""
    return _default_masker.redact(text)


def unmask_text(text: str, mapping: Dict[str, str]) -> str:
    """Unmask text using the mapping returned from mask_text."""
    return PIIMasker.unmask(text, mapping)
