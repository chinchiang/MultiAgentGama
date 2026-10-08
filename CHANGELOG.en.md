# Changelog

[正體中文（臺灣）](CHANGELOG.md) | English (US)

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

Design corrections against the OWASP Top 10 for LLM Applications 2026 and MITRE ATLAS: the white-box ensemble becomes Claude / DeepSeek / GLM / Gemini, with deterministic AI-security rules and trust-boundary controls.

### Changed (design corrections per OWASP LLM Top 10 2026 / MITRE ATLAS)
- **White-box ensemble is now Claude / DeepSeek / GLM / Gemini**: Nemotron and ChatGPT were removed (the `nemotron` / `chatgpt` model aliases and `NVIDIA_API_KEY` / `OPENAI_API_KEY` are no longer used). DeepSeek takes over defensive & resource review, white-box test generation and black-box attack synthesis, GLM takes over specification & contract review (in a live run GLM-5.3 spent its whole 16k output budget thinking on 8 of 12 attack scripts and answered empty, so attack synthesis moved to DeepSeek), and the new **Gemini "AI Integration & Supply-Chain Reviewer"** audits model-calling code against OWASP LLM01–LLM10:2026. The verifiers follow (four of them). Default models use versioned ids (`claude-sonnet-5-5`, `zai/glm-5.3`, `deepseek/deepseek-v4-pro`) so a provider-side swap shows up in reports
- **Reviewers are config-driven**: every `whitebox_reviewer_*` entry is used, and its name, model and `focus` actually reach the prompt (the roster used to be hard-coded at three and the config `focus` was ignored); no configured reviewer is an evidence gap. Fewer than two model families triggers a warning that cross-verification cannot run (LLM07:2026)
- **Unconfigured agents are no longer silently routed to `gpt-4o`**: they resolve to an `unconfigured` alias; hybrid simulates, live fails loudly
- **Quality gate**: a HIGH+ hit of a deterministic AI-security rule makes the verdict `NEEDS_FIXES` (exit 1)

### Added (security design)
- **Deterministic AI-security rules `VH-AI-001`–`009`** (`agents/whitebox/ai_static_scanner.py`, no model involved): `trust_remote_code=True`, `torch.load` without `weights_only=True`, pickle-style deserialization, hub models without a pinned `revision`, LLM calls without an output cap, model output flowing into `eval`/`exec`/shell/SQL, hard-coded credentials, invisible/bidi control characters, and comments addressing AI reviewers. Each rule carries its OWASP LLM 2026 entry, MITRE ATLAS technique and CWE, and appears in Markdown / JSON / SARIF (`vibeharness/VH-AI-00x`)
- **Untrusted-code channel (LLM01:2026, AML.T0051.001)**: code shown to any model has invisible characters stripped and secrets redacted (LLM02:2026, AML.T0055), is wrapped in `<untrusted_target_code>` (a forged closing tag is neutralized), and every code-reading agent's system prompt carries a security policy; planted reviewer instructions or invisible characters are an evidence gap, so such a run can never be `READY_TO_SHIP`
- **OWASP LLM Top 10 2026 threat modeling**: `threat_rules.yaml` gains `owasp_llm_top10_2026` (ATLAS tactic/technique and CWE mappings); it is applied automatically when the target imports an AI SDK, threats gain an `atlas_mapping` field, and the report's threat table a MITRE ATLAS column
- **Report output sanitization (LLM10:2026, AML.T0077)**: model text is rendered into Markdown with images and raw HTML defanged and ANSI/OSC sequences removed; console output escapes rich markup; SARIF messages drop control characters
- **Generated tests may not install packages** (slopsquatting, LLM04:2026, AML.T0060): `pip install`, `import pip` and the like are refused by the static gate
- **Model endpoints must be https** (plain http only for loopback); a bad `api_base` fails at startup with `ConfigError`. Every model call records a `prompt_sha256` for audit traceability
- Reviewers may report an optional `owasp_mapping`; reports list the reviewer models and the detected AI components
- **Per-model output limit** (found in a live run): `models.<alias>.max_output_tokens` overrides the global value; the global default rises from 4096 to `16384`: thinking tokens count against the limit, and 4096 left Gemini 3 test-generation answers empty or cut off and truncated Claude's threat-model JSON (the limit is a cap; `max_model_calls` still bounds cost). The per-request `timeout_seconds` likewise rises from 60 to 180, since Opus took longer than 60s to write a long threat-model JSON. Truncated answers are now recorded as "output truncated at the max_output_tokens limit" instead of a generic "not valid JSON"
- **Unsupported sampling parameters are dropped instead of failing** (found in a live run): Claude Opus 5.5 on Bedrock accepts only `temperature=1`, so every call used to fail over to the fallback model; `drop_params` is now passed. Models that authenticate with AWS credentials (Bedrock) can set `aws_profile_name` / `aws_region_name` instead of `api_key_env`, and empty answers record their `finish_reason` (e.g. a safety filter's `content_filter`)
- **Reports keep the generated test code** (audit trail): the Markdown report gains a "Generated Test Code" appendix listing each white-box / black-box test's code, its source finding / threat and its outcome in collapsible blocks; the JSON report gains `generated_tests` / `blackbox_generated_tests` with the code verbatim. A live run showed some "passing" tests were asserting the defect itself, which cannot be audited without the code. Code fences grow past the longest backtick run in the content (the PoC block could previously be broken out of with four backticks)

## [0.2.0] - 2026-10-07

Packaging, model-output robustness, execution correctness and SARIF fixes from a deep review, plus parallel test synthesis and a cost guard; a second verification round adds execution-attribution honesty, gate decoy protection and engineering convergence; a third hardening round covers stricter mypy, CI supply-chain protection and a higher coverage floor.

### Added
- **Parallel white-box test generation and black-box attack synthesis**: model calls fan out on a thread pool like the review/verification phases, with deterministic output order (test ids, reports); one failing finding/threat no longer takes down the others (live mode still fails loudly)
- **Parallel threat modeling across symbol batches**: `AutomatedThreatModeler` batches fan out concurrently on a thread pool, eliminating the Phase 4 serial bottleneck on large targets while preserving deterministic output
- **`max_model_calls` cost guard** (CLI `--max-model-calls`): caps real model invocations per run, exact under concurrency; when exhausted, hybrid falls back to simulation and lists an evidence gap (never `READY_TO_SHIP`), live fails
- **Tunable limits**: `max_concurrent_calls` (parallelism) and `max_files` (CLI `--max-files`, previously hard-coded to 50)

### Fixed
- **`pytest.fail` security exploit misclassification**: `_is_assertion` now recognizes `Failed:` messages emitted by `pytest.fail()`, correctly confirming security exploits instead of demoting them to `INCONCLUSIVE`
- **Multi-tier LLM JSON parsing fault tolerance**: `_clean_and_parse_json` now handles conversational text wrapping, case-insensitive and unclosed code fences, and multi-block candidate recovery, avoiding spurious `invalid` calls
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
- **`.gitignore` cleanup**: ignored `.venv/`, `*.sarif`, `report.json`, and cache folders

### Fixed (verification round 2)
- **Honest executor attribution**: a corrupted / unparseable sandbox junit report is reported as "report could not be parsed" instead of "no tests collected"; per-test rerun parse failures are flagged the same way. A target module that crashes on import (syntax error, missing dependency) is now attributed to the target ("Target code is broken and was never exercised by this test", with the real exception text) instead of blaming the test; the test's own import errors still blame the test; generic failure reasons prefer the pytest traceback `E` line
- **Parent-directory module shadowing**: the sandbox sys.path puts the target directory first, so a same-named module in a parent directory no longer shadows the module under test
- **Per-batch verifier isolation**: a non-gateway exception in one cross-verification batch is logged and treated as "no consensus" for that batch instead of aborting arbitration; gateway errors still fail loudly in live mode
- **Threat-rules degradation**: structurally wrong `stride_categories` / `owasp_api_top10` (nulls, non-strings, non-dict entries) degrade safely to no guidance with a warning instead of raising `AttributeError`
- **SARIF home-directory guard**: when the user's home directory is itself a git repo (dotfiles), `sarif_root` no longer treats it as the repo root (comparison via `os.path.samefile` + case normalization), so findings are no longer attached to the dotfiles repo
- **Any-of key validation for LLM responses**: `generate()` accepts `required_keys_any`; the test generator requires `tests` or `code`, so a refusal can no longer silently produce zero tests
- **URL guard resolves IPv6 and userinfo**: `scenario_builder` now uses `urlsplit().hostname` (`[::1]` and credentials no longer mask the host); unparseable URLs fail closed
- **Full traceback on crashes**: unexpected CLI exceptions no longer print a bare `type: message` line
- **Fallback threat ids have no gaps**: model-supplied ids no longer consume the fallback counter, so THREAT-XX numbering stays contiguous
- **Vacuous-test gate decoys**: an `assert` inside a nested, never-called helper no longer satisfies the gate (only helpers actually invoked count); removed the unused `top_level_test_functions`
- **Non-Python targets disclosed and guided**: detected JS/TS is listed as an evidence gap (the sandbox only executes Python, so there is no dynamic verification); `import_instructions` for non-.py files state that the file cannot be imported or executed instead of handing out an importlib recipe that cannot work
- **Misc**: the detected-language list in reports is sorted (deterministic); test-generator self-heal logs identify the finding id instead of an unrelated integer index; the evidence-gap message for clean targets is clearer about which boundaries remain unverified

### Infrastructure
- New CI `package` job, and the `publish` smoke test now builds the wheel, installs it outside the checkout and runs a real mock-mode audit
- `pyproject.toml` dependency caps match `requirements.txt` (`pydantic<3`, `litellm<2`)
- New `tests/test_quality_fixes.py` (a regression test per fix, each verified to fail before the fix)

### Infrastructure (verification round 2)
- **Pinned lint tools**: the CI lint job installs from `requirements-dev.txt` (ruff==0.16.10, mypy==2.4.0); the pre-commit ruff hook was aligned and upgraded (v0.6.9 → v0.16.9)
- **requirements-dev.txt completed**: adds `build` and `pytest-cov` (matching CI)
- **threat_rules.yaml comments**: documents which fields are functional (fed into prompts) and which are documentation only
- The CI test job enforces a total coverage floor (`--cov-fail-under`)

### Infrastructure (hardening round 3)
- **Stricter mypy**: `check_untyped_defs = true` (type-checks bodies of unannotated functions); `core/sandbox.py` now branches on `sys.platform` so mypy can narrow types — full suite reports 0 errors
- **CI Actions pinned to commit SHAs**: checkout / setup-python / pypa publish actions all pin the full SHA (tag kept as a comment), so rewritten tags can no longer tamper with CI
- **Dependency vulnerability audit**: new `audit` job runs pip-audit against the fully resolved `requirements.lock` (on every PR; a dependency bump with a known CVE fails before merge)
- **Optional PyPI publishing**: the publish workflow gains a `pypi-publish` job that publishes the wheel/sdist via Trusted Publishing (OIDC); it runs only when the repo variable `ENABLE_PYPI_PUBLISH=true` is set, otherwise it is skipped
- **Coverage floor raised to 93%**: regression tests added for reviewer-ensemble fault tolerance, threat-modeler rules degradation and coverage-table parsing (CI: 209 passed, 93.48% total coverage)

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
