"""
pii-masker-ai: Ultra-fast, zero-dependency PII masking and redaction for AI prompts and agents.
"""

from pii_masker.core import (
    PIIMasker,
    MaskResult,
    MaskMode,
    SYNTHETIC_TEMPLATES,
    DetectedEntity,
    mask_text,
    unmask_text,
    redact_text,
)
from pii_masker.patterns.base import PIIPattern
from pii_masker.integrations.langchain import PIIChatWrapper, PIILangChainCallback

__version__ = "0.4.0"
__all__ = [
    "PIIMasker",
    "MaskResult",
    "MaskMode",
    "SYNTHETIC_TEMPLATES",
    "DetectedEntity",
    "PIIPattern",
    "PIIChatWrapper",
    "PIILangChainCallback",
    "mask_text",
    "unmask_text",
    "redact_text",
]
