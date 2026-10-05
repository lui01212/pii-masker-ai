"""
Core PII masking and unmasking engine.
Supports reversible masking (for LLM context preservation), permanent redaction,
keyed HMAC-SHA256 pseudonym hashing, and realistic synthetic data replacement.
Inspired by Microsoft Presidio and Tonic Textual.
Zero external dependencies.
"""

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import re
import secrets
import warnings
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pii_masker.patterns.base import PIIPattern
from pii_masker.patterns.global_rules import GLOBAL_PATTERNS
from pii_masker.patterns.api_keys import API_KEY_PATTERNS
from pii_masker.patterns.financial import FINANCIAL_PATTERNS
from pii_masker.patterns.network import NETWORK_PATTERNS
from pii_masker.patterns.vietnam import VIETNAM_PATTERNS


# Environment variable read for the hash-mode salt when PIIMasker(salt=...) is not given.
SALT_ENV_VAR = "PII_MASKER_SALT"


class MaskMode:
    """Supported anonymization / masking strategies."""
    REVERSIBLE = "reversible"  # <EMAIL_1>, <PHONE_1> (best for LLM chat round-trip)
    REDACT = "redact"          # [EMAIL], [PHONE] (best for logs & public audits)
    HASH = "hash"              # <EMAIL_a1b2c3d4e5f60718> (HMAC-SHA256 keyed by your salt, for consistent agent memory)
    SYNTHETIC = "synthetic"    # user1@example.com, +1-201-555-0100 (realistic dummy data)


_VALID_MODES = (MaskMode.REVERSIBLE, MaskMode.REDACT, MaskMode.HASH, MaskMode.SYNTHETIC)


# Synthetic value for the first entity of each built-in category. Built-in values come from
# reserved or test ranges, are unique for every counter value and never a prefix of each other.
# To use your own format, replace an entry (or add one for a custom category) with a template
# containing "{n}"; mask() then uses template.format(n=n).
SYNTHETIC_TEMPLATES: Dict[str, str] = {
    "EMAIL": "user{n}@example.com",
    "PHONE": "+1-201-555-0100",
    "CREDIT_CARD": "4111-1100-0000-0014",
    "IBAN": "XX00TEST000000000001",
    "IP_ADDRESS": "198.51.100.100",
    "IPV6_ADDRESS": "2001:db8::0:0001",
    "MAC_ADDRESS": "00:00:5E:00:53:00",
    "GOV_ID": "000000000001",
    "TAX_ID": "0000000001",
    "PASSPORT": "X0000001",
    "SSN": "900-00-0001",
    "API_KEY": "sk-synthetic-000000000001",
    "JWT_TOKEN": "eyJhbGciOiJub25lIn0.eyJzdWIiOiAic3ludGhldGljLTEifQ.c3ludGhldGlj",
    "PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_KEY_1\n-----END PRIVATE KEY-----",
    "CREDENTIALS": "postgres://user1:synthetic-password@db1.example.com",
}
_SHIPPED_SYNTHETIC_TEMPLATES: Dict[str, str] = dict(SYNTHETIC_TEMPLATES)

_IPV4_DOC_BLOCKS = ("198.51.100", "203.0.113", "192.0.2")  # RFC 5737 documentation ranges


def _luhn_check_digit(body: str) -> int:
    total = 0
    for i, ch in enumerate(reversed(body)):
        digit = int(ch)
        if i % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (10 - total % 10) % 10


def _synthetic_builtin(category: str, n: int, original: str) -> Optional[str]:
    """Reserved/test-range value for counter n, or None once the category's range is used up."""
    i = n - 1
    if category == "EMAIL":
        return f"user{n}@example.com"
    if category == "PHONE" and i < 799 * 100:
        # NANP lines 555-0100..555-0199 are reserved for fictional use in every area code
        return f"+1-{201 + i // 100}-555-01{i % 100:02d}"
    if category == "CREDIT_CARD" and n < 10 ** 9:
        body = "411111" + f"{n:09d}"
        digits = body + str((_luhn_check_digit(body) + 1) % 10)  # deliberately fails Luhn: never a real card
        return "-".join(digits[k:k + 4] for k in range(0, 16, 4))
    if category == "IBAN" and n < 10 ** 12:
        return f"XX00TEST{n:012d}"  # "XX" is not an ISO country code
    if category == "IP_ADDRESS":
        # The last octet always has three digits, so no address is a prefix of another
        if i < 3 * 155:
            return f"{_IPV4_DOC_BLOCKS[i // 155]}.{100 + i % 155}"
        j = i - 3 * 155
        if j < 512 * 155:  # then 198.18.0.0/15, reserved for benchmarking (RFC 2544)
            block = j // 155
            return f"198.{18 + block // 256}.{block % 256}.{100 + j % 155}"
        return None
    if category == "IPV6_ADDRESS" and n < 2 ** 32:
        return f"2001:db8::{n >> 16:x}:{n & 0xFFFF:04x}"  # RFC 3849 documentation prefix
    if category == "MAC_ADDRESS":
        if i < 256:
            return f"00:00:5E:00:53:{i:02X}"  # RFC 7042 documentation range
        j = i - 256
        if j < 2 ** 24:  # then locally administered unicast addresses
            return f"02:00:00:{j >> 16:02X}:{(j >> 8) & 0xFF:02X}:{j & 0xFF:02X}"
        return None
    if category == "GOV_ID" and n < 10 ** 9:
        return f"000{n:09d}"  # province code 000 is never issued
    if category == "TAX_ID" and n < 10 ** 8:
        return f"00{n:08d}"
    if category == "PASSPORT" and n < 10 ** 7:
        return f"X{n:07d}"
    if category == "SSN" and i < 100 * 9999:
        return f"{900 + i // 9999}-00-{i % 9999 + 1:04d}"  # group 00 is never issued
    if category == "API_KEY" and n < 10 ** 12:
        return f"sk-synthetic-{n:012d}"
    if category == "JWT_TOKEN":
        payload = base64.urlsafe_b64encode(json.dumps({"sub": f"synthetic-{n}"}).encode("utf-8"))
        return f"eyJhbGciOiJub25lIn0.{payload.decode('ascii').rstrip('=')}.c3ludGhldGlj"
    if category == "PRIVATE_KEY":
        return f"-----BEGIN PRIVATE KEY-----\nSYNTHETIC_KEY_{n}\n-----END PRIVATE KEY-----"
    if category == "CREDENTIALS":
        scheme = original.split("://", 1)[0] if "://" in original else "https"
        return f"{scheme}://user{n}:synthetic-password@db{n}.example.com"
    return None


def _synthetic_value(category: str, n: int, original: str) -> str:
    template = SYNTHETIC_TEMPLATES.get(category)
    if template is not None and template != _SHIPPED_SYNTHETIC_TEMPLATES.get(category) and "{n}" in template:
        return template.format(n=n)
    value = _synthetic_builtin(category, n, original)
    if value is None:
        value = f"<SYNTHETIC_{category}_{n}>"
    return value


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


class _MappingState:
    """Token bookkeeping shared by consecutive mask() calls (one conversation, one dataset)."""

    def __init__(self, mapping: Optional[Dict[str, str]] = None):
        self.mapping: Dict[str, str] = {}   # token -> original, everything issued so far
        self.by_value: Dict[str, str] = {}  # original -> token, so a repeated value keeps its token
        self.next_n: Dict[Tuple[str, str], int] = {}
        if mapping:
            for token, original in mapping.items():
                self.add(token, original)

    def add(self, token: str, original: str) -> None:
        self.mapping[token] = original
        self.by_value.setdefault(original, token)

    def new_token(self, mode: str, category: str, original: str, text: str) -> str:
        if mode == MaskMode.SYNTHETIC:
            def make(n: int) -> str:
                return _synthetic_value(category, n, original)
        else:
            def make(n: int) -> str:
                return f"<{category}_{n}>"

        key = (mode, category)
        n = self.next_n.get(key)
        if n is None:
            n = self._first_free(make)
        token = make(n)
        # Never reuse a token already issued, nor one that appears literally in the input
        while token in self.mapping or token in text:
            n += 1
            token = make(n)
        self.next_n[key] = n + 1
        return token

    def _first_free(self, make: Callable[[int], str]) -> int:
        """First unused counter, assuming earlier calls numbered the category 1, 2, 3, ..."""
        if make(1) not in self.mapping:
            return 1
        high = 2
        while make(high) in self.mapping:
            high *= 2
        low = high // 2
        while high - low > 1:
            mid = (low + high) // 2
            if make(mid) in self.mapping:
                low = mid
            else:
                high = mid
        return high


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
        salt: Optional[str] = None,
    ):
        """
        Args:
            countries: Country rule sets to load. Default (None) is ["VN"]; [] loads none.
            allowlist: Values never masked (exact, case-insensitive match on the detected value).
            salt: Key for hash mode. Falls back to the PII_MASKER_SALT environment variable,
                then to a random per-instance salt (hash tokens then differ between processes).
        """
        self.patterns: List[PIIPattern] = []
        self.allowlist: Set[str] = {item for item in allowlist if item and item.strip()} if allowlist else set()
        self.salt: Optional[str] = salt
        self._random_salt: str = secrets.token_hex(16)
        self._warned_random_salt = False

        if include_global:
            self.patterns.extend(GLOBAL_PATTERNS)

        if include_api_keys:
            self.patterns.extend(API_KEY_PATTERNS)

        if include_financial:
            self.patterns.extend(FINANCIAL_PATTERNS)

        if include_network:
            self.patterns.extend(NETWORK_PATTERNS)

        country_set = {c.upper() for c in countries} if countries is not None else {"VN"}
        if "VN" in country_set:
            self.patterns.extend(VIETNAM_PATTERNS)

        if custom_patterns:
            self.patterns.extend(custom_patterns)

    @staticmethod
    def _normalize_allowlist(items: Iterable[str]) -> Set[str]:
        return {item.strip().lower() for item in items if item and item.strip()}

    def is_allowlisted(self, text: str) -> bool:
        """Check if a detected value is exempted (exact, case-insensitive match on the allowlist)."""
        return text.strip().lower() in self._normalize_allowlist(self.allowlist)

    def _hash_salt(self) -> str:
        if self.salt:
            return self.salt
        env_salt = os.environ.get(SALT_ENV_VAR)
        if env_salt:
            return env_salt
        if not self._warned_random_salt:
            self._warned_random_salt = True
            warnings.warn(
                "PIIMasker has no salt: hash mode uses a random per-instance salt, so hash tokens "
                f"will not be stable across processes. Pass salt=... or set {SALT_ENV_VAR}.",
                UserWarning,
                stacklevel=4,
            )
        return self._random_salt

    @staticmethod
    def _resolve_mode(reversible: bool, mode: Optional[str]) -> str:
        if mode is None:
            return MaskMode.REVERSIBLE if reversible else MaskMode.REDACT
        active_mode = mode.lower() if isinstance(mode, str) else mode
        if active_mode not in _VALID_MODES:
            raise ValueError(f"Unknown mask mode {mode!r}; expected one of: {', '.join(_VALID_MODES)}")
        return active_mode

    def _detect(self, text: str) -> List[Tuple[int, int, str]]:
        """Find PII spans: (start, end, category), sorted and non-overlapping."""
        candidates: List[Tuple[int, int, int, int, str]] = []  # (start, end, priority, order, category)
        for order, pattern in enumerate(self.patterns):
            priority = getattr(pattern, "priority", 0)
            pos = 0
            while pos <= len(text):
                m = pattern.regex.search(text, pos)
                if m is None:
                    break
                start, end = m.span()
                if start == end:
                    pos = end + 1
                    continue
                if pattern.validator and not pattern.validator(m.group()):
                    # An overlapping later match may still validate (a card number right after a year)
                    pos = start + 1
                    continue
                candidates.append((start, end, priority, order, pattern.category))
                pos = end

        # Overlapping matches become one span, so no part of a detected value is left visible.
        # The span takes the category of the best match: higher priority (validated, specific
        # detectors), then longer, then earlier, then pattern order.
        def rank(cand: Tuple[int, int, int, int, str]) -> Tuple[int, int, int, int]:
            return (-cand[2], cand[0] - cand[1], cand[0], cand[3])

        candidates.sort(key=lambda c: (c[0], -c[1]))
        spans: List[Tuple[int, int, str]] = []
        best: Optional[Tuple[int, int, int, int, str]] = None
        span_start = span_end = 0
        for cand in candidates:
            if best is not None and cand[0] < span_end:
                span_end = max(span_end, cand[1])
                if rank(cand) < rank(best):
                    best = cand
                continue
            if best is not None:
                spans.append((span_start, span_end, best[4]))
            best = cand
            span_start, span_end = cand[0], cand[1]
        if best is not None:
            spans.append((span_start, span_end, best[4]))
        return spans

    def mask(
        self,
        text: str,
        reversible: bool = True,
        mode: Optional[str] = None,
        allowlist: Optional[Sequence[str]] = None,
        mapping: Optional[Dict[str, str]] = None,
    ) -> MaskResult:
        """
        Detect and mask PII in text using the configured mode.

        Args:
            text: Input string (e.g. user prompt, chat history)
            reversible: If True and mode is None, uses MaskMode.REVERSIBLE.
            mode: Explicit MaskMode: 'reversible', 'redact', 'hash', or 'synthetic'.
            allowlist: Optional per-call allowlist additions (exact, case-insensitive values).
            mapping: Optional token -> original mapping from earlier calls that share one context
                (turns of one conversation, records of one dataset). Numbering continues after its
                tokens and a value already in it keeps its token, so the returned mapping can be
                merged into it with dict.update() without overwriting entries. It is not modified.
        """
        return self._mask(text, reversible, mode, allowlist, _MappingState(mapping))

    def _mask(
        self,
        text: str,
        reversible: bool,
        mode: Optional[str],
        allowlist: Optional[Sequence[str]],
        state: _MappingState,
    ) -> MaskResult:
        active_mode = self._resolve_mode(reversible, mode)
        if not text:
            return MaskResult(masked_text="", mapping={}, entities=[])

        exempt = self._normalize_allowlist(self.allowlist)
        if allowlist:
            exempt |= self._normalize_allowlist(allowlist)

        mapping: Dict[str, str] = {}
        entities: List[DetectedEntity] = []
        for start, end, category in self._detect(text):
            matched_str = text[start:end]
            # The allowlist is checked after overlaps are resolved, so an exempt value stays intact
            if exempt and matched_str.strip().lower() in exempt:
                continue

            if active_mode == MaskMode.REDACT:
                placeholder = f"[{category}]"
            elif active_mode == MaskMode.HASH:
                # Keyed HMAC-SHA256, 64-bit digest: guessing a value requires the salt
                digest = hmac.new(
                    self._hash_salt().encode("utf-8"), matched_str.encode("utf-8"), hashlib.sha256
                ).hexdigest()[:16]
                placeholder = f"<{category}_{digest}>"
                state.add(placeholder, matched_str)
            else:
                # Reversible and synthetic: the same value always gets the same token
                placeholder = state.by_value.get(matched_str)
                if placeholder is None:
                    placeholder = state.new_token(active_mode, category, matched_str, text)
                    state.add(placeholder, matched_str)

            if active_mode != MaskMode.REDACT:
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
        """Mask PII with keyed HMAC-SHA256 digests for consistent pseudonymization."""
        return self.mask(text, mode=MaskMode.HASH)

    def synthetic_mask(self, text: str) -> MaskResult:
        """Replace PII with realistic synthetic data."""
        return self.mask(text, mode=MaskMode.SYNTHETIC)

    @staticmethod
    def unmask(text: str, mapping: Dict[str, str]) -> str:
        """
        Restore original PII data into LLM response using the provided mapping.
        All placeholders are replaced in one pass (longest first), so a restored value is
        never rewritten again by another placeholder.
        """
        if not text or not mapping:
            return text

        present = [placeholder for placeholder in mapping if placeholder and placeholder in text]
        if not present:
            return text
        present.sort(key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(placeholder) for placeholder in present))
        return pattern.sub(lambda m: mapping[m.group(0)], text)


# Module-level convenience functions
_default_masker = PIIMasker()


def mask_text(
    text: str,
    reversible: bool = True,
    mode: Optional[str] = None,
    allowlist: Optional[Sequence[str]] = None,
    mapping: Optional[Dict[str, str]] = None,
) -> MaskResult:
    """Mask text using default settings."""
    return _default_masker.mask(text, reversible=reversible, mode=mode, allowlist=allowlist, mapping=mapping)


def redact_text(text: str) -> str:
    """Permanently redact PII from text."""
    return _default_masker.redact(text)


def unmask_text(text: str, mapping: Dict[str, str]) -> str:
    """Unmask text using the mapping returned from mask_text."""
    return PIIMasker.unmask(text, mapping)
