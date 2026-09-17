"""
Secret & API Key detection patterns (OpenAI, Anthropic, GitHub, AWS, etc.).
"""

import re
from typing import List
from pii_masker.patterns.base import PIIPattern

# OpenAI API Key: sk-...
OPENAI_KEY_REGEX = re.compile(
    r"\bsk-[a-zA-Z0-9]{10,64}\b"
)

# Anthropic API Key: sk-ant-...
ANTHROPIC_KEY_REGEX = re.compile(
    r"\bsk-ant-[a-zA-Z0-9_\-]{10,128}\b"
)

# GitHub Personal Access Token: ghp_..., gho_..., github_pat_...
GITHUB_TOKEN_REGEX = re.compile(
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"
)

# AWS Access Key ID: AKIA...
AWS_KEY_REGEX = re.compile(
    r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"
)

# Generic Bearer Token in authorization headers
BEARER_TOKEN_REGEX = re.compile(
    r"(?i)\bBearer\s+[a-zA-Z0-9\-._~+/]+=*"
)

API_KEY_PATTERNS: List[PIIPattern] = [
    PIIPattern(category="API_KEY", regex=OPENAI_KEY_REGEX, description="OpenAI API Key"),
    PIIPattern(category="API_KEY", regex=ANTHROPIC_KEY_REGEX, description="Anthropic API Key"),
    PIIPattern(category="API_KEY", regex=GITHUB_TOKEN_REGEX, description="GitHub Token"),
    PIIPattern(category="API_KEY", regex=AWS_KEY_REGEX, description="AWS Access Key"),
    PIIPattern(category="API_KEY", regex=BEARER_TOKEN_REGEX, description="Generic Bearer Token"),
]
