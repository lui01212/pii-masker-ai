# pii-masker-ai 🔒🤖

[![PyPI version](https://img.shields.io/pypi/v/pii-masker-ai.svg)](https://pypi.org/project/pii-masker-ai/)
[![Python versions](https://img.shields.io/pypi/pyversions/pii-masker-ai.svg)](https://pypi.org/project/pii-masker-ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://github.com/lui01212/pii-masker-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/lui01212/pii-masker-ai/actions)
[![good first issues](https://img.shields.io/github/issues/lui01212/pii-masker-ai/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/lui01212/pii-masker-ai/issues?q=is%3Aissue+state%3Aopen+label%3A%22good+first+issue%22)
[![Hacktoberfest](https://img.shields.io/badge/Hacktoberfest-2024-ff7a59?logo=hacktoberfest)](https://hacktoberfest.com/)

**Ultra-fast, zero-dependency PII masking and reversible unmasking for AI prompts, LLM agents, and vector databases.**

Prevent sensitive customer data (Emails, Phone Numbers, Credit Cards, Citizen IDs, API Keys, Private Keys, IP Addresses) from leaking into external AI models (Claude, OpenAI, Gemini).

---

## ⚡ The AI Privacy Problem & Solution

```mermaid
sequenceDiagram
    participant User
    participant PII_Masker as pii-masker-ai
    participant LLM as Claude / OpenAI / Gemini
    
    User->>PII_Masker: "Contact John at john@company.com with phone 0912345678"
    Note over PII_Masker: Reversible Masking
    PII_Masker->>LLM: "Contact John at <EMAIL_1> with phone <PHONE_1>"
    LLM->>PII_Masker: "Scheduled an appointment for <EMAIL_1> via <PHONE_1>."
    Note over PII_Masker: Automatic Unmasking
    PII_Masker->>User: "Scheduled an appointment for john@company.com via 0912345678."
```

---

## 🌟 Key Features

- **Zero dependencies:** Written in 100% pure Python standard library. Instant install, zero attack surface.
- **Bi-directional Reversible Masking:** Masks with sequential placeholders (`<EMAIL_1>`, `<PHONE_1>`) so the LLM retains conversational context, then restores original data upon return.
- **Permanent Redaction:** Supports redacting with fixed tags (`[EMAIL]`, `[API_KEY]`, `[CREDIT_CARD]`) for logging and training datasets.
- **Comprehensive Pattern Suite (v0.2.0):**
  - **Financial:** Credit cards (Visa, MasterCard, Amex, Discover, JCB) with **Luhn algorithm verification**, IBAN bank codes.
  - **Network:** Public IPv4, IPv6 addresses, MAC addresses.
  - **Secrets & API Keys:** JWT tokens, PEM Private Keys (`RSA`, `EC`), OpenAI, Anthropic, GitHub, AWS, Slack, Stripe, Google Cloud.
  - **Global & Regional:** Email, US SSN, International phone (E.164), Vietnam Citizen ID (CCCD/CMND), Tax ID, Passports.
- **CLI & CI Scanner:** Built-in scanner to detect PII leaks in text/code files during pre-commit or CI/CD pipelines.

---

## 📦 Installation

```bash
pip install pii-masker-ai
```

---

## 🚀 Quickstart (Python API)

### 1. Reversible Masking with LLMs

```python
from pii_masker import mask_text, unmask_text

# 1. Mask prompt before calling Claude / OpenAI
prompt = "Please send invoice #123 to customer alice@example.com, phone 0912345678."
result = mask_text(prompt, reversible=True)

print(result.masked_text)
# Output: "Please send invoice #123 to customer <EMAIL_1>, phone <PHONE_1>."

# 2. Call your LLM with masked_text...
llm_response = "I have drafted the invoice for <EMAIL_1> and notified <PHONE_1>."

# 3. Restore original customer PII in the response
final_output = unmask_text(llm_response, result.mapping)
print(final_output)
# Output: "I have drafted the invoice for alice@example.com and notified 0912345678."
```

### 2. Permanent Redaction (Logging / Storage)

```python
from pii_masker import mask_text

log_entry = "User key was sk-ant-api03-abcdef123456789 on IP 192.168.1.50"
result = mask_text(log_entry, reversible=False)

print(result.masked_text)
# Output: "User key was [API_KEY] on IP [IP_ADDRESS]"
```

---

## 💻 CLI Usage

### Masking text
```bash
pii-masker mask "My email is support@anthropic.com and phone is 0987654321"
```

### Scanning files for PII leaks (CI/CD friendly)
```bash
# Returns exit code 1 if any PII leak is found
pii-masker scan ./data/ --strict
```

---

## 🌍 Supported PII Categories

| Category | Description | Examples |
| :--- | :--- | :--- |
| `EMAIL` | Standard RFC email addresses | `user@example.com` |
| `PHONE` | International & Vietnamese numbers | `+84912345678`, `0901234567` |
| `CREDIT_CARD` | Major credit card formats | `4532-xxxx-xxxx-9012` |
| `IP_ADDRESS` | IPv4 addresses | `192.168.1.1` |
| `API_KEY` | OpenAI, Anthropic, GitHub, AWS keys | `sk-...`, `sk-ant-...`, `ghp_...`, `AKIA...` |
| `GOV_ID` | National IDs (e.g. VN CCCD 12-digit / CMND 9-digit) | `001201012345` |
| `TAX_ID` | Tax identification numbers | `0123456789-001` |

---

## 🤝 Community: Add Your Country's PII Rules!

We are actively expanding localized PII regex rules for more countries!
Beginner contributors can easily add new rules in under 15 minutes:
- 🇫🇷 France (NIR / Carte Vitale)
- 🇯🇵 Japan (My Number)
- 🇺🇸 US (SSN, Driver License)
- 🇩🇪 Germany (Steuer-ID)
- 🇬🇧 UK (National Insurance Number)

Check out [CONTRIBUTING.md](CONTRIBUTING.md) to claim a country module!

---

## 📄 License

[MIT License](LICENSE) © 2026 lui01212
