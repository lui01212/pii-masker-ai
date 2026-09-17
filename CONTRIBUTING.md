# Contributing to pii-masker-ai

Thank you for contributing to **pii-masker-ai**! We welcome bug fixes, documentation improvements, and especially **localized country PII patterns** from developers around the world.

---

## 🌟 How to Add a New Country Pattern (Easy First Contribution!)

Adding a new country's PII pattern is modular and straightforward:

1. Look in `pii_masker/patterns/` (e.g. `vietnam.py`).
2. Create a new file for your country, e.g. `pii_masker/patterns/france.py` or `japan.py`.
3. Define your `PIIPattern` with a regex and category (`PHONE`, `GOV_ID`, `TAX_ID`).
4. Register it in `PIIMasker.__init__` in `pii_masker/core.py`.
5. Add a test in `tests/test_masker.py`.
6. Submit your Pull Request!

---

## 🛠️ Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/pii-masker-ai.git
   cd pii-masker-ai
   ```

2. **Zero external dependencies:**
   No external packages needed! Uses Python 3.8+ standard library.

3. **Running tests:**
   ```bash
   python -m unittest discover tests
   ```

4. **Commit format:**
   Please use Conventional Commits (e.g. `feat(patterns): add French NIR social security regex`).
