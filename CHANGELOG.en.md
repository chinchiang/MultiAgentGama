# Changelog

[正體中文（臺灣）](CHANGELOG.md) | English (US)

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **`--estimate`**: runs Phase 1 only (no model call) and prints the expected calls per agent / per model (reviewers = reviewers × white-box batches and threat modeling = batches are exact; verification, test generation and attack synthesis are scenario figures from the assumptions "3 findings per batch, 4 threats per batch, 70% confirmed, 30% need a heal", with a maximum that includes `retry_invalid_output` re-asks and up to 2 heals per test), estimated prompt / output tokens and a warning when `max_model_calls` is below the typical count; with `models.<alias>.price_per_million_input` / `_output` (new optional fields, validated at start-up) an estimated cost. `--format json` writes it to `--output`; exit 0. `VibeHarnessCommander` gains `select_symbols()` / `work_dir_for()`, shared by the estimate and the real run
- **`--baseline <report.json>`**: with a previous JSON report, the confirmed findings, black-box breaches, probe failures and HIGH+ rule hits it already contains are still reported (new "Known from baseline (not counted)" section and a recommendation) but no longer count toward the verdict or the exit code, so CI fails on new problems only. Keys are independent of run numbering: a finding = target-relative path + symbol + normalized title, a breach = the threat's STRIDE category + title + attack vector, a rule hit = rule + file + evidence (no line number), a probe = its symbol. The JSON report's static hits, confirmed findings, failed white-box tests and breaches gain a `fingerprint` field (schema version unchanged); 0.3.0 reports without it are recomputed; a crash's `.partial.json` or a foreign JSON file is refused (exit 5). `VibeHarnessSummary` gains `baseline_path` / `baseline_suppressed`
- **Composite GitHub Action (`action.yml`)**: a target repository runs the audit with one `uses: chinchiang/MultiAgentGama@vX.Y.Z` line; inputs `target`, `mode`, `max-model-calls`, `max-files`, `changed-since`, `baseline`, `output` / `format`, `sarif`, `extra-args`, `python-version` and `fail-on` (`blocked` / `needs-fixes` / `inconclusive` / `never`); outputs `verdict`, `exit-code`, `report`, `sarif`; the report, SARIF and `.partial.json` are uploaded as an artifact. The package is installed from the same action ref via git (switchable to PyPI once published); actions are SHA-pinned
- **JS/TS dynamic test execution**: for `.js` / `.jsx` / `.mjs` / `.cjs` / `.ts` / `.tsx` / `.mts` / `.cts` targets (`.mjs` / `.cjs` / `.mts` / `.cts` are now extracted too), white-box tests and in-process black-box attack tests are generated as `node:test` + `node:assert` ES modules and run with Node's built-in runner (new `GeneratedTest.language` / `TestExecutionResult.language` fields; `RunMetadata.node_runtime` records the Node version used). New `NodeSubprocessSandbox` / `NodeDockerSandbox` (`docker/sandbox-node.Dockerfile`), a static JS code gate `check_js_test_code` (balanced delimiters, at least one `test()` / `it()`, an assertion in every test, `npm` / `pnpm` / `yarn` / `bun` / `npx` installs refused), `js_module_kind` / `js_exported_names` / `js_import_instructions` (ESM / CommonJS detection and the `file://` import form) and Node JUnit classification (only `ERR_ASSERTION` is a confirmed breach; a `TypeError` inside the target is a defect, not an exploit; a test-side `ReferenceError`, `ERR_MODULE_NOT_FOUND` or `SyntaxError` is a harness error; load errors are recovered from the runner output). Each JS module runs in its own `node --test` process (Node's junit reporter does not name the file a test came from). New settings `node_bin`, `sandbox_node_provider`, `docker_node_image`; the Node sandbox sets no `RLIMIT_AS` and caps the heap with `--max-old-space-size` instead; `NODE_OPTIONS` / `NODE_REPL_EXTERNAL_MODULE` join the environment deny list. The evidence gap for JS/TS targets now has three forms: no JS test generated (always the case in mock mode), generated but no usable Node, TypeScript tests not run because Node < 22.6; other languages keep "reviewed statically only". Limits: no JS coverage, TypeScript by type stripping only, bare ESM specifiers do not resolve inside Docker. CI installs Node 22 (`VIBEHARNESS_REQUIRE_NODE=1` forces the real runs; Linux also builds the Node image and forces container runs with `VIBEHARNESS_REQUIRE_DOCKER_NODE=1`)

### Changed
- Code fences for PoCs and the "Generated Test Code" appendix carry the test's language (`python` / `javascript` / `typescript`); the console coverage line reads "Line Coverage (Python)". `import_instructions` gives JS/TS files their `file://` URL and import form; other non-Python files keep the "cannot be imported" note

## [0.3.0] - 2026-10-09

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

### Changed (breaking: packaging namespace)
- **Everything moved under the single top-level package `vibeharness/`**: `core`, `agents`, `runners`, `reports`, `config` and `main` used to be separate top-level packages / modules that landed directly in site-packages, colliding with other packages of the same generic names (`core` and `config` are common) and shadowing a user project's own `config`. Only the `vibeharness/` directory is installed now: imports become `vibeharness.core.…` / `vibeharness.agents.…`, the CLI entry point is `vibeharness.cli:main`, the default config lives in `vibeharness/config/` and the version in `vibeharness/__init__.py`; the repository root keeps a `main.py` launcher, so `python main.py …` and the `vibeharness` command behave as before. Library users must update their import paths; a new test asserts the wheel installs no generic top-level package

### Added (follow-up items)
- **Response cache**: with `global.cache_dir` / CLI `--cache-dir`, usable live answers are stored as JSON keyed by model, settings (including `max_output_tokens` and `extra_params`) and prompt; an identical prompt is served from the cache with no provider call and no `max_model_calls` spend, shown as "live (response cache)" in the call log and reports (`AgentCallRecord.cached`). Unusable answers are never cached and a corrupt entry counts as a miss; writes go through a temp file and an atomic replace so concurrent agents never read a torn file
- **Partial report on a crash or interrupt**: any exception or Ctrl-C in the six phases first writes the completed phases (call log, static rule hits, findings, verification, white-box tests and results, threats, black-box tests and results) and the error to `<output>.partial.json` (`partial: true`, `phase_reached`) before propagating; paid-for model results are no longer lost
- **`local_subprocess` resource caps**: `global.sandbox_memory_mb` (default 2048, `0` disables) caps the pytest process tree's address space with `RLIMIT_AS` on POSIX and adds a CPU-time cap (batch budget + 10 s); a generated test allocating 1 GiB ends in `MemoryError` instead of eating the host. Not applied by the `docker` provider (the container has `--memory` / `--cpus`; the docker CLI itself stays unlimited)
- **SARIF rule `help`**: every rule carries `help.text` / `help.markdown` (deterministic rules: the remediation and OWASP / ATLAS / CWE mappings; white-box and black-box rules: how to verify with the generated test and PoC in the report), so GitHub Code Scanning alerts show guidance
- **Chinese injection markers**: `VH-AI-009` gains Traditional and Simplified Chinese phrasings: ignore / disregard (previous | above | system) instructions or rules, do not report / flag … this issue / function, report zero / no findings, a note to the AI / reviewer, "AI 審查者：", treat / mark this code as safe / passing. Everyday phrases ("忽略大小寫", "回報錯誤給呼叫端", "寄給審查者") do not match and the harness self-scan stays at zero
- **Manual live smoke workflow** (`.github/workflows/live-smoke.yml`): `workflow_dispatch` runs the target once in live / hybrid mode with the provider keys stored as repository secrets (with a call cap), re-runs for the JSON report from the response cache at no cost, and uploads the reports, SARIF and partial report as an artifact; exit 4 / 5 fail the job, 0–3 are verdicts about the target

### Added (feature improvements)
- **Unusable answers are re-asked**: a live answer that is not JSON, lacks a key or is empty used to be booked `invalid` and turned the whole run INCONCLUSIVE; it is now re-asked `global.retry_invalid_output` times (default 1) with a prompt naming the problem and demanding JSON only. The first attempt is booked `retried` (shown as "unusable, re-asked" in the Execution Provenance table, not an evidence gap) and only a still-unusable answer is booked `invalid`; every re-ask is a real call against `max_model_calls`, none happens once the budget is spent, and `json_output=False` repair calls are never re-asked
- **`models.<alias>.extra_params`**: parameters passed verbatim to litellm (e.g. `thinking: {type: disabled}`, `reasoning_effort: low`) so a reasoning model does not spend the whole `max_output_tokens` thinking (the main GLM failure in live runs); validated as a mapping at start-up
- **File selection**: CLI `--include GLOB` / `--exclude GLOB` (repeatable, replacing the config's `global.include` / `exclude`) and `--changed-since <git ref>` (only files that changed relative to that ref, staged, unstaged and untracked included; an unresolvable ref or a target outside a git repository is exit 5); filtered-out files are not evidence gaps. `site-packages` joins the skipped directories
- **`global.max_file_bytes`** (default 1 MB): larger files (minified bundles, generated code) are not analyzed and are listed as an evidence gap; the character-by-character JS/TS lexer used to take minutes on them
- **Run metadata in reports**: `summary.run` carries `generated_at` (UTC), `harness_version`, `execution_mode`, `config_path`, `sandbox_provider`, `target_path`, `target_git_commit` / `target_git_dirty` and `file_filters`; shown in the Markdown header, the JSON report and the SARIF run `properties`; JSON gains `schema_version` (`"1"`)
- **Fail early, interrupt cleanly**: a missing or unwritable `--output` / `--sarif` directory exits 5 before any model call (the run used to crash while writing the report, after every model call had been paid for); Ctrl-C exits 130 with a note that no report was written instead of a traceback

### Engineering (governance and supply chain)
- Added `SECURITY.md` (private reporting, the vulnerability classes that matter here, supported versions), `CONTRIBUTING.md` (setup, pre-push checks, principles, release steps), `.github/CODEOWNERS`, and PR / issue templates
- Added `.github/dependabot.yml`: weekly proposals for the SHA-pinned Actions and `requirements.lock` (major bumps of `litellm` / `pydantic` excluded); until now a CVE in a locked version failed the `audit` job on every PR and the lock could only be regenerated by hand
- `requirements-dev.txt` is fully pinned (`pip-audit==2.10.1` and `build==1.6.1` added, `pytest-cov` pinned to the lock's 7.1.0); the CI `audit` / `package` / `publish` jobs read those pins instead of installing unpinned latest versions
- `tests.yml` gains `concurrency` (a new push to the same PR cancels the superseded run); `publish.yml`'s `build-and-upload` gains `timeout-minutes`, and `pypi-publish` downloads the same build artifacts (`actions/upload-artifact` / `download-artifact`, SHA-pinned) instead of rebuilding, so the Release and PyPI files are bit-identical
- pre-commit gains a mypy hook (run from the project environment, the same pins as CI's lint job)

### Fixed (deep review, 2026-10-09)
- **Import guidance for package targets**: when `--target` is a directory that is itself a package (has `__init__.py`, modules use relative imports), prompts and offline probes said `from app import f`, the target raised `attempted relative import with no known parent package` on execution, and the executor blamed it on "the target is broken"; `module_import_name` now detects the package and anchors at the parent directory (`from shop.app import f`; the parent is on the sandbox's sys.path already), and probes load the target with `importlib.import_module`
- **`--base-url` accepts http(s) only**: `urllib` opens `file:` / `ftp:` / `data:` URLs too, so `--base-url file:///etc/hostname` once counted as a live server and switched into Live HTTP mode; the CLI and `ThreatScenarioBuilder` now check scheme and host with `validate_base_url`, and an invalid URL is a usage error (exit 5)
- **`VH-AI-009` no longer treats a bare `READY_TO_SHIP` as injection**: the rule fired 27 times on this repository's own code (all verdict constants), and any target that reads the JSON report and compares `overall_status` would be an evidence gap forever; it now matches only sentences that ask the reviewer to produce that verdict, and a dogfooding test scans the harness's own sources for zero hits
- **Provider error text is redacted before it is recorded**: the raw `live invocation failed: …` text went into the `call_log` reason, the Markdown Execution Provenance table, the JSON report and live-mode stderr, while an HTTP client exception can echo a URL or header carrying the API key; every reason and `LLMGatewayError` message now passes through `redact_secrets` and control-character stripping
- **Numeric settings are validated at start-up**: `timeout_seconds`, `max_retries`, `max_output_tokens` (global and per model) and each agent's `temperature` were read only when a call was made, so a typo (e.g. a string) made litellm fail and hybrid mode quietly fell back to the simulation engine, leaving just an INCONCLUSIVE verdict; they are now `ConfigError` (exit 5)
- Docs: report section headings use the same six-phase numbering as the README / harness (Phases 2–3, 4, 5); the design document's test count is updated

### Fixed (gaps listed by the design document)
- **Crashed reviewer / verifier batches are evidence gaps**: when a batch raised outside the gateway, it was only logged and treated as an empty result, with no `call_log` entry, so the gate could not see the missing review; `LLMGateway.record_failure` now books it as an `invalid` call (reason includes the exception), and the evidence-gap message lists each agent with its reason
- **A single reviewer model is an evidence gap**: with every `whitebox_reviewer_*` on the same model the console only warned; the run now also records it in `inconclusive_reasons` (never `READY_TO_SHIP`; OWASP LLM07:2026)
- **Report sanitization completed**: the Markdown evidence-gap list and the "Threats Not Tested" list bypassed `markdown_safe` / `_code_span`, so a model-chosen threat id or failure text could inject images, HTML or break out of a code span
- **Agents without `model_alias` show as `unconfigured`**: reviewers and verifiers used the agent-id suffix as the alias (the report named a model that was never called, and the debater's self-review exclusion compared the wrong alias); they now resolve like the gateway routes them, with finding ids `WB-UNC-NN`
- **`max_files` validation in the config**: a negative, boolean or non-integer value is now a `ConfigError` (exit 5), like `max_model_calls` / `max_concurrent_calls`; a negative value used to be taken as a slice and a string was silently converted by `int()`
- **Two Docker tests failed when the suite ran as root**: the tests now create the run dir first (the real path always `mkdtemp`s it), and a new test with a faked uid covers the root branch that opens the run dir to `nobody`

### Documentation
- New design document `docs/design.md` (Traditional Chinese): architecture and component responsibilities, the six-phase data flow, data models, LLM gateway mode decisions, white-box / black-box subsystems, deterministic rules, the sandbox security model, the quality gate's 15 evidence gaps and verdict order, report formats, trust boundaries, configuration extension points, concurrency and cost model, test strategy, known limitations and a design-decision record (file:line references at commit `f087dfb`)
- Fixed documentation that disagreed with the code: the single-key example in `docs/configuration.md` labelled `blackbox_test_synthesizer`'s original value as `glm` (it is `deepseek`); the `threat_rules.yaml` header and `docs/configuration.md` claimed `stride_categories.<key>.description` is sent in the prompt, while only `name` and `common_vibe_bugs` are read

## [0.2.0] - 2026-10-07

Packaging, model-output robustness, execution correctness and SARIF fixes from a deep review, plus parallel test synthesis and a cost guard; a second verification round adds execution-attribution honesty, gate decoy protection and engineering convergence; a third hardening round covers stricter mypy, CI supply-chain protection and a higher coverage floor.

### Added
- **JS/TS extractor rewrite** (PR #19): a dependency-free lexer with real brace/parenthesis matching — strings, template literals (including nested `${}`), comments and regex literals are masked first, so their contents can no longer create phantom declarations; functions, arrow functions and routes get accurate line spans (the old fixed 15/25-line windows truncated long functions and duplicated neighbours); generators, async, multi-line signatures, bare-parameter arrows and class methods (constructor/static/async; `if`/`while` are no longer mistaken for methods) are supported; routes accept any receiver (app/router/server/fastify…) with string or template-literal paths, and Next.js App Router handlers named after HTTP verbs are marked as routes
- **Parallel white-box test generation and black-box attack synthesis**: model calls fan out on a thread pool like the review/verification phases, with deterministic output order (test ids, reports); one failing finding/threat no longer takes down the others (live mode still fails loudly)
- **Parallel threat modeling across symbol batches**: `AutomatedThreatModeler` batches fan out concurrently on a thread pool, eliminating the Phase 4 serial bottleneck on large targets while preserving deterministic output
- **`max_model_calls` cost guard** (CLI `--max-model-calls`): caps real model invocations per run, exact under concurrency; when exhausted, hybrid falls back to simulation and lists an evidence gap (never `READY_TO_SHIP`), live fails
- **Tunable limits**: `max_concurrent_calls` (parallelism) and `max_files` (CLI `--max-files`, previously hard-coded to 50)

### Fixed
- **Determinism and precision of review, dedup and black-box synthesis** (PR #18): dedup uses transitive union-find, sorted corroborator lists and finding_id tie-breaks at equal severity, and plural stemming no longer mangles `classes`/`address`; symbol matching prefers an exact name before a suffix, and a finding that names no symbol stays unresolved instead of being pinned to the batch's first symbol; finding ids are numbered per reviewer agent and de-duplicated, so two agents sharing a model alias cannot collide; black-box symbol relevance uses whole-word matching (`username` no longer pulls in `get_user`), and in live mode attack code targeting a host other than the base URL is rejected statically; `render_symbols` truncates over-budget blocks instead of dropping them; the report shows an UNKNOWN badge for an unrecognized `overall_status` and renders a list field mistakenly returned as a string as one item instead of character by character
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
