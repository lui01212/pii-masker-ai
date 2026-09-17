"""
pii-masker-ai: Ultra-fast, zero-dependency PII masking and redaction for AI prompts and agents.
"""

from pii_masker.core import PIIMasker, MaskResult, mask_text, unmask_text

__version__ = "0.1.0"
__all__ = ["PIIMasker", "MaskResult", "mask_text", "unmask_text"]
