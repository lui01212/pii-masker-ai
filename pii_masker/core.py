"""
Core PII masking and unmasking engine.
Supports reversible masking (for LLM context preservation), permanent redaction,
SHA-256 pseudonym hashing, and realistic synthetic data replacement.
Inspired by Microsoft Presidio and Tonic Textual.
Zero external dependencies.
"""

from dataclasses import dataclass, field
import hashlib
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from pii_masker.patterns.base import PIIPattern
from pii_masker.patterns.global_rules import GLOBAL_PATTERNS
from pii_masker.patterns.api_keys import API_KEY_PATTERNS
from pii_masker.patterns.financial import FINANCIAL_PATTERNS
from pii_masker.patterns.network import NETWORK_PATTERNS
from pii_masker.patterns.vietnam import VIETNAM_PATTERNS


class MaskMode:
    """Supported anonymization / masking strategies."""
    REVERSIBLE = "reversible"  # <EMAIL_1>, <PHONE_1> (best for LLM chat round-trip)
    REDACT = "redact"          # [EMAIL], [PHONE] (best for logs & public audits)
    HASH = "hash"              # <EMAIL_a1b2c3d4> (salted SHA-256 for consistent agent memory)
    SYNTHETIC = "synthetic"    # user1@example.com, +15550101 (realistic dummy data)


SYNTHETIC_TEMPLATES: Dict[str, str] = {
    "EMAIL": "user{n}@example.com",
    "PHONE": "+8490123456{n}",
    "CREDIT_CARD": "4532-0151-1283-0366",
    "IBAN": "DE89370400440532013000",
    "IP_ADDRESS": "198.51.100.{n}",
    "IPV6_ADDRESS": "2001:db8::{n}",
    "MAC_ADDRESS": "00:1A:2B:3C:4D:0{n}",
    "GOV_ID": "00120100000{n}",
    "TAX_ID": "010123456{n}",
    "PASSPORT": "B123456{n}",
    "SSN": "123-45-678{n}",
    "API_KEY": "sk-synthetic-api-key-{n}",
    "JWT_TOKEN": "eyJhbGciOiJIUzI1NiJ9.synthetic.token{n}",
    "PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_KEY_{n}\n-----END PRIVATE KEY-----",
    "CREDENTIALS": "https://synthetic_user:synthetic_pass@internal.db",
}


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
    Production-grade PII Masker & De-identifier for AI Prompts and Agent Pipelines.
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
        allowlist: Optional[Sequence[str]] = None,
        salt: str = "pii-masker-salt",
    ):
        self.patterns: List[PIIPattern] = []
        self.allowlist: Set[str] = set(allowlist) if allowlist else set()
        self.salt: str = salt

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

    def is_allowlisted(self, text: str) -> bool:
        """Check if an entity match is exempted by the allowlist."""
        if not self.allowlist:
            return False
        clean = text.strip().lower()
        for item in self.allowlist:
            item_lower = item.strip().lower()
            if clean == item_lower or item_lower in clean:
                return True
        return False

    def mask(
        self,
        text: str,
        reversible: bool = True,
        mode: Optional[str] = None,
        allowlist: Optional[Sequence[str]] = None,
    ) -> MaskResult:
        """
        Detect and mask PII in text using the configured mode.
        
        Args:
            text: Input string (e.g. user prompt, chat history)
            reversible: If True and mode is None, uses MaskMode.REVERSIBLE.
            mode: Explicit MaskMode: 'reversible', 'redact', 'hash', or 'synthetic'.
            allowlist: Optional per-call allowlist overrides/additions.
        """
        if not text:
            return MaskResult(masked_text="", mapping={}, entities=[])

        # Resolve mode
        if mode is None:
            active_mode = MaskMode.REVERSIBLE if reversible else MaskMode.REDACT
        else:
            active_mode = mode.lower()

        active_allowlist = self.allowlist.copy()
        if allowlist:
            active_allowlist.update(allowlist)

        # Step 1: Find all matches across all patterns
        matches: List[Tuple[int, int, str, str]] = []  # (start, end, category, original_text)

        for pattern in self.patterns:
            for m in pattern.regex.finditer(text):
                start, end = m.span()
                matched_str = text[start:end]

                # Check allowlist
                if active_allowlist:
                    clean = matched_str.strip().lower()
                    if any(item.strip().lower() in clean for item in active_allowlist):
                        continue

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

        # Step 3: Assign placeholders and build mapping according to active_mode
        category_counters: Dict[str, int] = {}
        mapping: Dict[str, str] = {}
        entities: List[DetectedEntity] = []

        for start, end, category, matched_str in non_overlapping:
            category_counters[category] = category_counters.get(category, 0) + 1
            count = category_counters[category]

            if active_mode == MaskMode.REVERSIBLE:
                placeholder = f"<{category}_{count}>"
                mapping[placeholder] = matched_str

            elif active_mode == MaskMode.REDACT:
                placeholder = f"[{category}]"

            elif active_mode == MaskMode.HASH:
                # Salted SHA-256 8-char digest
                h = hashlib.sha256(f"{self.salt}:{matched_str}".encode("utf-8")).hexdigest()[:8]
                placeholder = f"<{category}_{h}>"
                mapping[placeholder] = matched_str

            elif active_mode == MaskMode.SYNTHETIC:
                template = SYNTHETIC_TEMPLATES.get(category, f"synthetic_{category.lower()}_{{n}}")
                placeholder = template.format(n=count)
                mapping[placeholder] = matched_str

            else:
                placeholder = f"<{category}_{count}>"
                mapping[placeholder] = matched_str

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
        """Permanently redact PII with fixed [CATEGORY] tags."""
        return self.mask(text, mode=MaskMode.REDACT).masked_text

    def hash_mask(self, text: str) -> MaskResult:
        """Mask PII with salted SHA-256 hashes for consistent pseudonymization."""
        return self.mask(text, mode=MaskMode.HASH)

    def synthetic_mask(self, text: str) -> MaskResult:
        """Replace PII with realistic synthetic data."""
        return self.mask(text, mode=MaskMode.SYNTHETIC)

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


def mask_text(
    text: str,
    reversible: bool = True,
    mode: Optional[str] = None,
    allowlist: Optional[Sequence[str]] = None,
) -> MaskResult:
    """Mask text using default settings."""
    return _default_masker.mask(text, reversible=reversible, mode=mode, allowlist=allowlist)


def redact_text(text: str) -> str:
    """Permanently redact PII from text."""
    return _default_masker.redact(text)


def unmask_text(text: str, mapping: Dict[str, str]) -> str:
    """Unmask text using the mapping returned from mask_text."""
    return PIIMasker.unmask(text, mapping)
