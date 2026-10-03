# Contributing to pii-masker-ai

Thanks for taking a look! Small, focused contributions are welcome.

## Start with one small issue

[Our featured beginner issue](https://github.com/lui01212/pii-masker-ai/issues/11): Write a first redaction walkthrough using synthetic data.
It lists the exact files, expected output or test cases, and completion criteria.

Comment if you would like to work on it and wait for assignment before starting.
Respect existing assignments. Ask questions before expanding the scope; a draft PR
is welcome for early feedback. Assignment and passing tests do not guarantee a merge.

## Local setup

Use Python 3.8 or newer. Fork the repository, then clone your fork:

```sh
git clone https://github.com/YOUR-USERNAME/pii-masker-ai.git
cd pii-masker-ai
git switch -c docs/your-change
python -m unittest discover -s tests -v
```

The runtime uses the Python standard library. Tests can run from the source checkout
without installing the package. Packaging, lint, and CI tools have their own dependencies.
For installed CLI commands, use a virtual environment and `python -m pip install -e .`;
review the packaging configuration before installing.

Repository: `pii-masker-ai`; PyPI distribution: `pii-masker-ai`; Python import: `pii_masker`.
The installed CLI is pii-masker.

Review code before running it. Use synthetic data in examples. Avoid credentials,
private files, hook installation, or AI client configuration changes unless required
by the task.

## Submit a focused PR

- Link the issue and explain the change.
- Keep unrelated cleanup out of the diff.
- Add or update tests when behavior changes; include commands and outcomes.
- For documentation, run the snippets and check the links.
- Use a Conventional Commit message, for example `docs: clarify first local example`.
- Push your branch to your fork and open a PR, or a draft PR for early feedback.

Maintainers review scope, correctness, validation, and privacy before merging.
Respond to review comments in the PR; there is no guaranteed review time.
Contributions are credited through GitHub PR authorship, commit history, and the
[contributors page](https://github.com/lui01212/pii-masker-ai/graphs/contributors).

## Larger contributions

Issues labelled `help wanted` can need design discussion and more testing.
Country-specific identity patterns require authoritative format references, positive
and negative synthetic cases, and any applicable checksum validation.
Discuss the scope before starting; documentation and test-only issues are the
recommended starting point.

For a country pattern, start with `pii_masker/patterns/vietnam.py` and the
`PIIPattern` definition in `pii_masker/patterns/base.py`. Add a country module,
wire it into the country selection in `pii_masker/core.py`, and add focused tests
under `tests/`. Keep all examples synthetic and include false-positive cases.
