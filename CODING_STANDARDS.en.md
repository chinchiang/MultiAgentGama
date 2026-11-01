# Coding standards

English ｜ [正體中文（臺灣）](CODING_STANDARDS.md)

Apply every rule below to a diff under review. Only rules that need judgement live here; the mechanical ones are caught by tests and CI, listed in the last section, and need no re-check in review. Terms follow `GLOSSARY.md`.

## 1. Every fix has a regression test that is red before the fix

- The new test reaches the changed branch: take the fix out and it fails. A test that only checks "does not crash" or that a structure exists does not count.
- The suite runs offline: mock Execution mode plus the fake litellm in `tests/conftest.py`, with no API key and no network.
- Agent calls run concurrently on threads through `vibeharness/core/fanout.py`, so a fake responder in a test that keeps shared state needs a lock.
- A violation looks like: a fix with no test; a new test that also passes on `master`; a test that needs a real model or the network.

## 2. Only Executed evidence decides the Verdict

- Check how Hypotheses, Simulated output and Shape errors may affect the Verdict against their definitions in `GLOSSARY.md`.
- Anything that makes the Verdict untrustworthy is recorded as an Evidence gap (with a stable code) for the Quality Gate, never skipped silently.
- A violation looks like: a model answer changing the Verdict directly; an `except` that swallows an error and carries on without an Evidence gap; an empty list taken as "no findings".

## 3. Target code and model output are untrusted input

- Untrusted content enters a prompt only as `Untrusted(Content.X, text)` passed to `ask` / `ask_text` in `vibeharness/core/agent_call.py`, which wraps it in the provenance-labeled channel for its kind and adds that channel's policy.
- Model-written text goes through `markdown_safe` (`vibeharness/core/sanitize.py`) or the report generator's `_cell` / `_code_span` / `_cell_code` before it reaches a report.
- A violation looks like: an f-string splicing file content or a model answer into a prompt; calling `untrusted_block` directly instead of going through `ask`; model text written raw into Markdown or SARIF.

## 4. Configuration errors fail loudly at start-up

- A new config key is validated for type and range when `load_settings` in `vibeharness/core/settings.py` loads it (`_validate_endpoints`, `_validate_models_and_agents`, `_sandbox_settings`, `_mutation_settings`, `_pattern_list`, ...); the error is `ConfigError` / `ValueError` (exit 5).
- Consumers read the validated, typed settings values and never parse the raw config themselves.
- A violation looks like: a new key read with `.get(key, default)` where it is used; a type error that surfaces only at call time; null treated as 0 or an empty string.

## 5. What generated tests may do only ever narrows

- The pre-run check in `vibeharness/core/codecheck.py` only gets stricter; nothing is installed into the user's environment.
- Check Heal calls against the "Heal call" definition in `GLOSSARY.md`.
- A violation looks like: allowing more imports or system calls; `pip install`, or writes outside the target; an invalid test replaced with `assert True`.

## 6. Fixed output strings are bilingual and their English half stays

- Fixed strings in reports, the console, logs, failure reasons and SARIF text all go through `bi("中文", "English")` from `vibeharness/core/i18n.py`.
- The English half of an existing string does not change: CI and fingerprint matching rely on it.
- Prompts sent to a model stay English; a bilingual reason goes through `en_only()` before it enters a prompt.
- A violation looks like: a new fixed string in one language only; a changed English half of an existing `bi()`; Chinese or bilingual text in a prompt.

## 7. Documentation changes with the behaviour

- When behaviour changes, the same PR updates `README.md` / `README.en.md`, `docs/configuration*.md`, and the same section of `[Unreleased]` in both CHANGELOGs; a design-level change updates `docs/design*.md`.
- Comments and descriptions in config files, workflows, `action.yml`, Dockerfiles and packaging files, and the CLI `--help`, put Traditional Chinese (Taiwan) first and English second.
- A violation looks like: a new config key or CLI flag the docs do not mention; only one CHANGELOG updated, or the two in different sections; zh and en documents that disagree.

## Checked by tests and CI (no re-check in review)

| Rule | Checked by |
| :--- | :--- |
| Bilingual `.py` docstrings and comments (Chinese line(s) first inside a docstring, a Chinese `#` line above each English comment, `# 中文 ／ English` for trailing comments) | `tests/test_i18n.py` |
| Chinese wording passes the injection self-scan (avoid phrasings like 「忽略…指令」「不要回報…」「視為…安全」) | `tests/test_ai_security.py` |
| Hashed lock and sandbox lock agree, sdist contents | `tests/test_review_build.py` |
| Third-party actions pinned to a commit SHA with a version comment | `tests/test_review_build.py`, the repo's Actions settings |
| zh / en document pairs have the same line count, version numbers agree | `tests/test_r2_packaging.py` |
| `path:line` references in the design documents | `tests/test_design_refs.py` |
| A behaviour-changing PR links an issue (`Closes #N`, `Refs #N` in a commit) | `.github/workflows/pr-issue-link.yml` |
| Lint, types, coverage ≥ 93% | CI's `ruff check .`, `mypy`, `pytest --cov-fail-under=93` |
