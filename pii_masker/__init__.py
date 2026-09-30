"""
pii-masker-ai: Ultra-fast, zero-dependency PII masking and redaction for AI prompts and agents.
"""

from pii_masker.core import (
    PIIMasker,
    MaskResult,
    DetectedEntity,
    mask_text,
    unmask_text,
    redact_text,
)
from pii_masker.patterns.base import PIIPattern

__version__ = "0.2.0"
__all__ = [
    "PIIMasker",
    "MaskResult",
    "DetectedEntity",
    "PIIPattern",
    "mask_text",
    "unmask_text",
    "redact_text",
]
