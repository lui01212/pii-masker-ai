"""
Secret & API Key detection patterns (OpenAI, Anthropic, GitHub, AWS, JWT, Private Keys, Slack, Stripe, Google).
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

# JSON Web Token (JWT): 3 base64url segments separated by dots, starting with eyJ
JWT_TOKEN_REGEX = re.compile(
    r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+\b"
)

# PEM Private Keys (RSA, EC, DSA, OPENSSH, etc.)
PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"
)

# Slack API Tokens (Bot, User, App) with hyphenated sections: xoxb-1234-5678-abcd
SLACK_TOKEN_REGEX = re.compile(
    r"\bxox[baprs](?:-[0-9a-zA-Z]{5,48})+\b"
)

# Google Cloud / Firebase API Key: AIza followed by 35 characters
GOOGLE_API_KEY_REGEX = re.compile(
    r"\bAIza[0-9A-Za-z\-_]{35}\b"
)

# Stripe API Keys (secret / publishable, test or live)
STRIPE_KEY_REGEX = re.compile(
    r"\b(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,34}\b"
)

API_KEY_PATTERNS: List[PIIPattern] = [
    PIIPattern(category="API_KEY", regex=OPENAI_KEY_REGEX, description="OpenAI API Key"),
    PIIPattern(category="API_KEY", regex=ANTHROPIC_KEY_REGEX, description="Anthropic API Key"),
    PIIPattern(category="API_KEY", regex=GITHUB_TOKEN_REGEX, description="GitHub Token"),
    PIIPattern(category="API_KEY", regex=AWS_KEY_REGEX, description="AWS Access Key"),
    PIIPattern(category="API_KEY", regex=BEARER_TOKEN_REGEX, description="Generic Bearer Token"),
    PIIPattern(category="JWT_TOKEN", regex=JWT_TOKEN_REGEX, description="JSON Web Token (JWT)"),
    PIIPattern(category="PRIVATE_KEY", regex=PRIVATE_KEY_REGEX, description="PEM Formatted Private Key"),
    PIIPattern(category="API_KEY", regex=SLACK_TOKEN_REGEX, description="Slack API Token"),
    PIIPattern(category="API_KEY", regex=GOOGLE_API_KEY_REGEX, description="Google Cloud API Key"),
    PIIPattern(category="API_KEY", regex=STRIPE_KEY_REGEX, description="Stripe API Key"),
]
