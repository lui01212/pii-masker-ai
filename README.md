# pii-masker-ai 🔒🤖

[![PyPI version](https://img.shields.io/pypi/v/pii-masker-ai.svg)](https://pypi.org/project/pii-masker-ai/)
[![Python versions](https://img.shields.io/pypi/pyversions/pii-masker-ai.svg)](https://pypi.org/project/pii-masker-ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/lui01212/pii-masker-ai/blob/main/LICENSE)
[![Tests](https://github.com/lui01212/pii-masker-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/lui01212/pii-masker-ai/actions)
[![good first issues](https://img.shields.io/github/issues/lui01212/pii-masker-ai/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/lui01212/pii-masker-ai/issues?q=is%3Aissue+state%3Aopen+label%3A%22good+first+issue%22)
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-7057ff)](https://github.com/lui01212/pii-masker-ai/blob/main/CONTRIBUTING.md)

**Ultra-fast, zero-dependency PII masking, redaction, and de-identification for AI prompts, LLM agents, and datasets.**

Detect and mask supported patterns before sending text to an external model. Review the output: pattern matching cannot guarantee that all sensitive data has been removed.

## Start here: your first contribution

**[Featured beginner issue #11](https://github.com/lui01212/pii-masker-ai/issues/11)**: Write a first redaction walkthrough using synthetic data.
Read [CONTRIBUTING.md](https://github.com/lui01212/pii-masker-ai/blob/main/CONTRIBUTING.md) for setup, claiming an issue, and opening a draft PR.

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
  3. `hash`: Keyed HMAC-SHA256 pseudonyms (`<EMAIL_26d609702036a71b>`) for persistent agent memory; consistent across sessions when you set a salt.
  4. `synthetic`: Realistic dummy data from reserved and test ranges (`user1@example.com`, `+1-201-555-0100`) for realistic model reasoning.
- **Allowlist & Safe Exemption:** Exempt exact values, such as a public support email or a known gateway IP (case-insensitive exact match on the detected value).
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

A repeated value always gets the same token. To mask several texts that share one context
(turns of a conversation, records of a dataset), pass the mapping you have so far: numbering
continues and known values keep their token, so `mapping.update(result.mapping)` never
overwrites an entry.

```python
from pii_masker import mask_text

mapping = {}
for turn in ["Mail alice@example.com", "Now mail bob@example.com"]:
    result = mask_text(turn, mapping=mapping)
    mapping.update(result.mapping)
# mapping == {"<EMAIL_1>": "alice@example.com", "<EMAIL_2>": "bob@example.com"}
```

`PIIMasker()` loads the Vietnam rules by default (`countries=["VN"]`); pass `countries=[]`
to load no country-specific rules.

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

The wrapper masks strings, message objects (text content or content blocks), `(role, text)`
tuples, dict inputs (values, recursively), lists of these, and prompt values; any other input
raises `TypeError` rather than being sent unmasked. Each `invoke()` uses its own mapping, so
one wrapper can serve several users. `last_mapping` only shows the most recent call and is not
thread-safe.

### 3. Pseudonymization (Hash Mode) & Synthetic Data

```python
from pii_masker import PIIMasker, MaskMode

masker = PIIMasker(salt="company-secret-salt", allowlist=["support@mycompany.com"])

# Hash mode for persistent agent memory
res_hash = masker.mask("User dev@corp.io reported an issue", mode=MaskMode.HASH)
print(res_hash.masked_text)
# Output (with salt "company-secret-salt"): "User <EMAIL_26d609702036a71b> reported an issue"

# Synthetic replacement
res_synth = masker.synthetic_mask("Customer phone is 0912345678")
print(res_synth.masked_text)
# Output: "Customer phone is +1-201-555-0100"
```

Hash mode is **pseudonymisation, not anonymisation**. Tokens are HMAC-SHA256 digests keyed by
your salt, so keep the salt secret: anyone who holds it can guess low-entropy values such as
phone numbers or IDs by hashing candidates. The salt comes from `salt=...`, else the
`PII_MASKER_SALT` environment variable, else a random per-instance salt (a warning is shown,
and tokens then differ between processes).

Synthetic values come from reserved or test ranges (`example.com` emails, `555-01xx` phone
numbers, documentation IP ranges, card numbers that deliberately fail the Luhn check) and are
unique for each entity, so unmasking restores every value.

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

# Hash mode with a stable salt (or set PII_MASKER_SALT)
pii-masker mask "User 0912345678" --mode hash --salt "$MY_SECRET_SALT"
```

Mapping files contain the original values: they are written readable by the owner only and
should never be committed.

### Batch Dataset Sanitization (JSONL & CSV)
```bash
# Sanitize fine-tuning or training datasets
pii-masker batch -i raw_dataset.jsonl -o clean_dataset.jsonl --fields prompt,response --mode redact

# Sanitize CSV customer data
pii-masker batch -i users.csv -o safe_users.csv --fields email,phone --mode synthetic
```

One mapping covers the whole run, so tokens never collide between records. JSONL values are
masked at any depth (numbers too, when they look like PII); lines that are not valid JSON are
left out of the output, reported on stderr, and make the command exit with code 1. An unknown
CSV column in `--fields` is an error. The output file must differ from the input file.

### Scanning files for PII leaks (CI/CD friendly)
```bash
# Returns exit code 1 if any PII leak is found
pii-masker scan ./data/ --strict
```

`scan` checks every non-binary file (including dotfiles such as `.env`) and prints the
category, `file:line`, and only a short preview of each finding, never the full value.

---

## 🌍 Supported PII Categories

| Category | Description | Examples |
| :--- | :--- | :--- |
| `EMAIL` | Standard RFC email addresses | `user@example.com` |
| `PHONE` | International & Vietnamese numbers | `+84912345678`, `0901234567` |
| `CREDIT_CARD` | Major credit cards with Luhn verification | `4532-xxxx-xxxx-9012` |
| `IBAN` | International Bank Account Numbers | `DE89370400440532013000` |
| `IP_ADDRESS` | IPv4 addresses (loopback is not reported) | `198.51.100.1` |
| `IPV6_ADDRESS` | IPv6 addresses | `2001:db8::1`, `fe80::1ff:fe23:4567:890a` |
| `MAC_ADDRESS` | Network hardware MAC addresses | `00:1A:2B:3C:4D:5E` |
| `API_KEY` | OpenAI, Anthropic, GitHub, AWS, Slack, Stripe, Google keys, Bearer tokens | `sk-...`, `sk-proj-...`, `sk-ant-...`, `ghp_...`, `AKIA...` |
| `JWT_TOKEN` | JSON Web Tokens | `eyJhbGci...` |
| `PRIVATE_KEY` | RSA / EC PEM private keys | `-----BEGIN PRIVATE KEY-----` |
| `CREDENTIALS` | `user:password@host` in URLs of any scheme | `postgresql://user:pass@db.example.com` |
| `SSN` | US Social Security Numbers | `123-45-6789` |
| `GOV_ID` | National IDs (VN CCCD 12-digit / CMND 9-digit) | `001201012345` |
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

See [CONTRIBUTING.md](https://github.com/lui01212/pii-masker-ai/blob/main/CONTRIBUTING.md) to get started.

---

## 📄 License

[MIT License](https://github.com/lui01212/pii-masker-ai/blob/main/LICENSE) © 2026 lui01212
