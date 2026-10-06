# Changelog

[正體中文（臺灣）](CHANGELOG.md) | English (US)

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Packaging, model-output robustness, execution correctness and SARIF fixes from a deep review.

### Fixed
- **Installed package could not run**: the wheel did not ship `config/agents_config.yaml` / `threat_rules.yaml`, so a `pip install`ed `vibeharness` always failed with "Agent config not found" (exit 5); they are now installed with the package. Missing or broken threat rules now log a warning instead of being skipped silently
- **A `null` model field crashed the whole pipeline**: the test generator and attack synthesizer raised `ValidationError` on `"title": null` and other non-string fields; they now fall back to defaults. Reviewer fields are coerced the same way; only findings with neither a usable title nor description are dropped
- **Generated tests with `from __future__` imports always ERRORed**: the harness header is now inserted after the docstring / `__future__` imports
- **Threats were not deduplicated across batches**: the same threat (STRIDE category + title + attack vector, normalized) is kept once with its highest severity, instead of being synthesized and executed again for every batch
- **Offline probes called argument-less functions**: functions such as `main()` or `run_server()` are no longer invoked by probes (which used to trigger real side effects or hang until the timeout)
- **Black-box testing no longer probes `localhost:8000` implicitly**: `--base-url` now defaults to none; Live HTTP mode only runs against an explicitly given URL, so attack scripts cannot hit an unrelated local service
- **White-box false positives**: a generated test calling the target with the wrong signature (a `TypeError` raised in the test module itself) is now an ERROR, not a target defect that yields NEEDS_FIXES
- **SARIF**: never emits `"locations": null`; unattributed findings (`unknown`) no longer get a fake URI; URIs are relative to the git repository root; rule ids are stable and fingerprints ignore casing/punctuation; black-box breaches are located at the attacked symbol when possible
- **Docker sandbox**: the in-container `timeout` backstop uses the run's own budget (the per-test budget on reruns, not the whole batch budget)
- **Cross-verification**: quoted indices (`"0"`) are accepted and booleans rejected (`True` used to count as index 1)

### Infrastructure
- New CI `package` job, and the `publish` smoke test now builds the wheel, installs it outside the checkout and runs a real mock-mode audit
- `pyproject.toml` dependency caps match `requirements.txt` (`pydantic<3`, `litellm<2`)
- New `tests/test_quality_fixes.py` (a regression test per fix, each verified to fail before the fix)

## [0.1.2] - 2026-10-03

Correctness, honesty and infrastructure sweep from a deep review (PRs #13, #14, #15, #16).

### Fixed
- **Sandbox stability**: after a timeout kill, the pipe drain is bounded, so a grandchild that daemonized into a new session can no longer hang the whole run forever; the timeout sentinel is now 124 (execution failure 125), decoupled from SIGHUP/SIGINT signal deaths
- **Exit-code semantics**: a new usage code 5 covers a missing `--target`, a missing or invalid-YAML config, an unavailable sandbox, CLI misuse, and unexpected crashes; exit 1 is now exclusive to NEEDS_FIXES (CI can no longer misread a harness error as a defect verdict); unknown verdict strings fail closed with exit 3
- **Quality-gate honesty**: black-box attack tests that FAILED without matching the exploit predicate are now counted (`blackbox_tests_failed`) and listed as an evidence gap — previously they vanished, letting a run pass as READY_TO_SHIP; the vacuous-test gate can no longer be fooled by assert-prefixed calls such as `mock.assert_called_once()`
- **Injection hardening**: LLM-controlled metadata in generated-test headers is newline-sanitized so unvalidated code cannot bypass `check_test_code`; fence stripping accepts `python3`/`Python` language tags without leaking the tag into the code
- **Threat-modeling coverage**: target symbols are now batched (same token-budgeted scheme as the white-box reviewers) so large targets are no longer silently truncated to a partial view; threats from all batches merge with deterministic renumbering of colliding ids
- **Cross-verification counts**: confirmed statistics subtract undecided tie findings, matching the consensus summary text
- **Docker sandbox hardening**: a root harness runs the container as `nobody`; `noexec,nosuid` on the `/tmp` tmpfs; an in-container `timeout` backstop so the container dies even if host-side cleanup fails; `custom_env` filters credential keys and interpreter-injection vectors (`BASH_ENV`, `LD_PRELOAD`, ...); only the target's own paths are rewritten for the container
- **Executor**: the JUnit module regex supports ≥1000 modules; malformed container-emitted `time` attributes cannot crash parsing; single-module batch timeouts are reported honestly; batch-timeout reruns are capped by the sandbox budget; partially skipped modules are flagged
- **Misc**: a crashed reviewer batch no longer discards other batches' results (live mode still fails loudly); unknown severity/STRIDE values are logged; the server-health probe retries; non-UTF-8 targets degrade gracefully; PoC fences widen when the code contains backticks; AST extraction reports `*args/**kwargs` and class decorators

### Engineering
- **Dependency locking**: new `requirements.lock` (`uv pip compile --universal --python-version 3.10`, marker-aware across 3.10–3.13); upper bounds on `litellm`/`pydantic`; CI and the sandbox image install pinned versions matching the lock
- **Static typing**: mypy in CI (all 28 findings fixed); mypy added to `requirements-dev.txt`
- **CI hygiene**: `push` fires only for `master` (PR branches no longer run twice); `permissions: contents: read`; `timeout-minutes` on every job; matrix extended to 3.11/3.12 (2 OS × 4 versions); pip cache keyed on the lock
- Test suite grown to 123 tests (including real Docker container sandbox tests)

## [0.1.1] - 2026-10-03

### Added
- `--sarif <path>`: emit a SARIF 2.1.0 report for GitHub Code Scanning — confirmed white-box findings carry file/line locations (resolved from `line_number` or the symbol table), and confirmed black-box breaches are reported as error-level results
- Bilingual documentation and README overhaul: Mermaid pipeline architecture diagram, agent responsibility matrix, and a full configuration reference (`docs/configuration.md`); Traditional Chinese is primary with English mirrors (README.en.md, CHANGELOG.en.md, docs/configuration.en.md)

## [0.1.0] - 2026-10-03

Initial release.

### Added
- Dual-engine testing pipeline: heterogeneous multi-model white-box cross-review (Claude / Nemotron / ChatGPT / Gemini) with debate-style cross-verification (votes from non-author models, agreement-ratio computation, arbitration)
- Black-box testing: STRIDE / OWASP threat-model-driven dynamic attack tests (BOLA, Mass Assignment, Injection, etc.)
- Sandboxed execution: local subprocess and Docker containers (read-only mounts, no network by default, secret isolation via env-var allowlist, per-test re-runs after a batch timeout)
- Audit reports: Markdown and JSON (`--format md|json`) with execution provenance, `[SIMULATED]` disclosure, and evidence-gap reporting
- CLI: `--version`, `--format`, `live` / `hybrid` / `mock` modes, and quality-gate exit codes (0 / 1 / 2 / 3 / 4)
- Model fault tolerance: `fallback_model` support, graceful degradation on malformed model output (never fabricated), untested threats listed as "Threats Not Tested"
- Packaging and installation: `pip install .` registers the `vibeharness` command; version has a single source of truth in `core/__init__.py`

### Engineering
- 98 unit tests (including Docker container sandbox tests, run on CI Linux runners), ~93% code coverage
- ruff static checks with pre-commit integration
- CI matrix: ubuntu / windows × Python 3.10 / 3.13, with lint and coverage reporting
- MIT license
