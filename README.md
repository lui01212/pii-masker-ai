# pii-masker-ai 🔒🤖

[![PyPI version](https://img.shields.io/pypi/v/pii-masker-ai.svg)](https://pypi.org/project/pii-masker-ai/)
[![Python versions](https://img.shields.io/pypi/pyversions/pii-masker-ai.svg)](https://pypi.org/project/pii-masker-ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://github.com/lui01212/pii-masker-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/lui01212/pii-masker-ai/actions)
[![good first issues](https://img.shields.io/github/issues/lui01212/pii-masker-ai/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/lui01212/pii-masker-ai/issues?q=is%3Aissue+state%3Aopen+label%3A%22good+first+issue%22)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-7057ff)](CONTRIBUTING.md)

**Ultra-fast, zero-dependency PII masking, redaction, and de-identification for AI prompts, LLM agents, and datasets.**

Detect and mask supported patterns before sending text to an external model. Review the output: pattern matching cannot guarantee that all sensitive data has been removed.

## Start here: your first contribution

**[Featured beginner issue #11](https://github.com/lui01212/pii-masker-ai/issues/11)**: Write a first redaction walkthrough using synthetic data.
Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, claiming an issue, and opening a draft PR.

Repository: `pii-masker-ai`; PyPI distribution: `pii-masker-ai`; Python import: `pii_masker`.
The installed CLI is pii-masker.

Try this from a reviewed source checkout, in the repository root, with Python 3.8+.
It uses synthetic inputs and needs no API key or network access:

```python
from pii_masker import redact_text
print(redact_text("Contact demo@example.com"))
```

Expected output:

```text
Contact [EMAIL]
```

Pattern detection can miss personal data. Review results before sharing them, and keep
reversible mappings private because they contain original values.

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

- **Zero dependencies:** Written in 100% pure Python standard library. No third-party runtime dependencies; this does not eliminate security risks.
- **4 De-identification Modes:**
  1. `reversible`: Sequential numbered tokens (`<EMAIL_1>`, `<PHONE_1>`) for LLM chat round-trips.
  2. `redact`: Fixed redaction tags (`[EMAIL]`, `[API_KEY]`) for audit logs and security reporting.
  3. `hash`: Salted SHA-256 pseudonym digests (`<EMAIL_a1b2c3d4>`) for persistent agent memory & cross-session consistency.
  4. `synthetic`: Realistic fake dummy data (`user1@example.com`, `+84901234561`) for realistic model reasoning.
- **Allowlist & Safe Exemption:** Safely exempt public support emails, internal company domains, or localhost IPs.
- **LangChain & LLM Chat Wrapper:** Wrap any LLM or ChatModel in 1 line of code with automatic prompt masking and response unmasking.
- **Batch Dataset Sanitizer:** High-speed CLI to sanitize `.jsonl`, `.csv`, and `.txt` datasets with column/field targeting.
- **Comprehensive Pattern Suite (v0.3.0):**
  - **Financial:** Credit cards (Visa, MasterCard, Amex, Discover, JCB) with **Luhn algorithm verification**, IBAN bank codes.
  - **Network:** IPv4, IPv6 addresses, MAC addresses.
  - **Secrets & API Keys:** JWT tokens, PEM Private Keys (`RSA`, `EC`), OpenAI, Anthropic, GitHub, AWS, Slack, Stripe, Google Cloud.
  - **Global & Regional:** Email, US SSN, International phone (E.164), Vietnam Citizen ID (CCCD/CMND), Tax ID, Passports.

---

## 📦 Installation

```bash
pip install pii-masker-ai
```

---

## 🚀 Quickstart (Python API)

### 1. Reversible Masking for LLMs

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

### 2. LangChain & Claude Chat Wrapper

```python
from pii_masker.integrations import PIIChatWrapper
from langchain_anthropic import ChatAnthropic

base_model = ChatAnthropic(model="claude-3-5-sonnet-20241022")

# Shield your LLM: automatically sanitizes prompts & unmasks responses
shielded_model = PIIChatWrapper(base_model)

response = shielded_model.invoke("Send email to alice@company.com with bill $500")
print(response.content)
```

### 3. Pseudonymization (Hash Mode) & Synthetic Data

```python
from pii_masker import PIIMasker, MaskMode

masker = PIIMasker(salt="company-secret-salt", allowlist=["support@mycompany.com"])

# Hash mode for persistent agent memory
res_hash = masker.mask("User dev@corp.io reported an issue", mode=MaskMode.HASH)
print(res_hash.masked_text)
# Output: "User <EMAIL_8f2b3e41> reported an issue"

# Synthetic replacement
res_synth = masker.synthetic_mask("Customer phone is 0912345678")
print(res_synth.masked_text)
# Output: "Customer phone is +84901234561"
```

---

## 💻 CLI Usage

### Masking text
```bash
# Reversible masking
pii-masker mask "My email is alice@company.com"

# Redact mode
pii-masker mask "Contact support@example.com" --mode redact

# Output JSON with mapping
pii-masker mask "User 0912345678" --json --save-mapping map.json

# Restore text
pii-masker unmask "Hello <PHONE_1>" -m map.json
```

### Batch Dataset Sanitization (JSONL & CSV)
```bash
# Sanitize fine-tuning or training datasets
pii-masker batch -i raw_dataset.jsonl -o clean_dataset.jsonl --fields prompt,response --mode redact

# Sanitize CSV customer data
pii-masker batch -i users.csv -o safe_users.csv --fields email,phone --mode synthetic
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
| `CREDIT_CARD` | Major credit cards with Luhn verification | `4532-xxxx-xxxx-9012` |
| `IBAN` | International Bank Account Numbers | `DE89370400440532013000` |
| `IP_ADDRESS` | IPv4 & IPv6 addresses | `198.51.100.1`, `2001:db8::1` |
| `MAC_ADDRESS` | Network hardware MAC addresses | `00:1A:2B:3C:4D:5E` |
| `API_KEY` | OpenAI, Anthropic, GitHub, AWS, Stripe keys | `sk-...`, `sk-ant-...`, `ghp_...`, `AKIA...` |
| `JWT_TOKEN` | JSON Web Tokens | `eyJhbGci...` |
| `PRIVATE_KEY` | RSA / EC PEM private keys | `-----BEGIN PRIVATE KEY-----` |
| `GOV_ID` | National IDs (e.g. VN CCCD 12-digit / US SSN) | `001201012345`, `123-45-6789` |
| `TAX_ID` | Business tax identification numbers | `0123456789-001` |
| `PASSPORT` | Passport identification numbers | `B1234567` |

---

## 🤝 Community: Add Your Country's PII Rules!

We are actively expanding localized PII regex rules for more countries!
Country-specific rules need format references, synthetic test cases, and validation:
- 🇫🇷 France (NIR / Carte Vitale)
- 🇯🇵 Japan (My Number)
- 🇩🇪 Germany (Steuer-ID)
- 🇬🇧 UK (National Insurance Number)

Check out [CONTRIBUTING.md](CONTRIBUTING.md) to claim a country module!

---

## 📄 License

[MIT License](LICENSE) © 2026 lui01212
