# 🛡️ VibeHarness-MAS: Multi-Agent Testing Harness for Vibe Coding

[正體中文（臺灣）](README.md) | English (US)

[![tests](https://github.com/chinchiang/MultiAgentGama/actions/workflows/tests.yml/badge.svg)](https://github.com/chinchiang/MultiAgentGama/actions/workflows/tests.yml)

> **An AI software quality-assurance toolkit that runs white-box first (heterogeneous model cross-review + executable test verification), then black-box (STRIDE/OWASP threat-model-driven attack testing).**

Designed for the failure modes of today's **Vibe Coding (natural-language-prompt-driven programming)**: code that looks fine on the surface (the happy path passes) but lacks defensive boundaries and ships BOLA/IDOR holes and uncaught exceptions.

---

## 🏛️ Architecture & Pipeline Overview

`vibeharness/core/harness.py` drives the sub-agents through six linear phases (no state-machine branching or rollback). Every model call goes through `vibeharness/core/llm_gateway.py`, and every agent that reads target code first passes it through the untrusted-code channel in `vibeharness/core/sanitize.py`.

```mermaid
flowchart TD
    CLI["main.py CLI<br/>--target / --mode / --desc / --base-url<br/>--format / --sarif / --max-files / --max-model-calls"] --> CMD["🧠 Commander<br/>vibeharness/core/harness.py (six linear phases)"]
    CMD --> AST["Phase 1 · Symbol extraction<br/>ast_extractor.py (AST for Python; lexer for JS/TS)"]
    AST --> SAST["Phase 1 · Deterministic AI-security rules<br/>ai_static_scanner.py (VH-AI-001..009)<br/>also detects ai_components"]

    GW["LLM gateway llm_gateway.py<br/>LiteLLM routing, fallback_model, simulation fallback<br/>max_model_calls, max_concurrent_calls, call_log"]
    SAN["Untrusted-code channel sanitize.py<br/>strip invisible chars / redact secrets / &lt;untrusted_target_code&gt;<br/>every agent that reads target code goes through it"]

    subgraph WB ["Phases 2–3 · White-box: multi-model review → cross-verification → sandboxed execution (model calls in parallel)"]
        R1["Logic & State Reviewer<br/>Claude"]
        R2["Safety & Defensive Reviewer<br/>DeepSeek"]
        R3["Specification & Contract Reviewer<br/>GLM"]
        R4["AI Integration & Supply-Chain Reviewer<br/>Gemini (OWASP LLM Top 10 2026)"]
        DEDUP["Deduplication<br/>deduplicator.py"]
        DEB["Cross-verification: votes from non-author models<br/>confirm / reject / unsure"]
        GEN["White-box test generation test_generator.py<br/>invalid tests repaired up to 2 times;<br/>WB-PROBE probes when no usable test"]
        SBX["Sandboxed execution (with line coverage)<br/>test_executor.py → local_subprocess / docker"]
        R1 --> DEDUP
        R2 --> DEDUP
        R3 --> DEDUP
        R4 --> DEDUP
        DEDUP --> DEB
        DEB -- "confirmed + ties" --> GEN --> SBX
    end

    AST --> SAN
    SAN --> R1
    SAN --> R2
    SAN --> R3
    SAN --> R4
    SAN --> DEB
    SAN --> GEN

    subgraph BB ["Phases 4–5 · Black-box: threat-model-driven attack testing (model calls in parallel)"]
        TM["STRIDE / OWASP API/LLM threat modeling<br/>(+ MITRE ATLAS mapping) threat_modeler.py<br/>symbols sent in batches, cross-batch dedup"]
        ATK["Attack script generation<br/>scenario_builder.py"]
        BEX["Black-box test execution<br/>test_executor.py → same sandbox; HTTP / in-process"]
        TM --> ATK --> BEX
    end

    AST -- "routes & symbols" --> TM
    SAST -- "ai_components" --> TM
    CLI -- "--desc" --> TM
    SAN --> TM
    SAN --> ATK

    GATE["Phase 6 · Quality gate<br/>READY_TO_SHIP / NEEDS_FIXES /<br/>INCONCLUSIVE / BLOCKED_CRITICAL_RISK"]
    SAST --> GATE
    SBX --> GATE
    BEX --> GATE
    GW -- "call_log: simulated, invalid, budget exhausted" --> GATE
    GATE --> OUT["Audit report report_generator.py<br/>md / json / SARIF"]

    WB -. "all model calls" .-> GW
    BB -. "all model calls" .-> GW
```

### 🤖 Agent Responsibilities

Every agent's model and prompt live in [`vibeharness/config/agents_config.yaml`](vibeharness/config/agents_config.yaml) and can be reassigned freely. The reviewer roster is config-driven: every `whitebox_reviewer_*` entry is used with its own `name`, `model_alias`, `temperature`, and `focus` (the focus text goes into its prompt), so adding or removing an entry changes the ensemble (field details in [docs/configuration.en.md](docs/configuration.en.md)):

| Sub-agent (agent_id) | Default model | Responsibility | temperature |
| :--- | :--- | :--- | :--- |
| Logic & State Reviewer (`whitebox_reviewer_claude`) | claude | Deep logical edge cases, unhandled exceptions, state inconsistencies, null-pointer/type bugs | 0.2 |
| Safety & Defensive Reviewer (`whitebox_reviewer_deepseek`) | deepseek | Input sanitization, injection (SQL/command/path), defensive guards, resource exhaustion, unsafe concurrency | 0.1 |
| Specification & Contract Reviewer (`whitebox_reviewer_glm`) | glm | API signature compliance, business-spec adherence, contract violations, authorization checks (BOLA/BFLA) | 0.2 |
| AI Integration & Supply-Chain Reviewer (`whitebox_reviewer_gemini`) | gemini | OWASP Top 10 for LLM Applications 2026 (LLM01–LLM08, LLM10) in code that calls models: prompt injection, secrets in prompts/logs, unchecked tool agency, model and package supply chain, unbounded consumption, unvalidated model output; also hard-coded credentials and unpinned third-party dependencies | 0.2 |
| Cross-verification votes (`whitebox_verifier_*` ×4) | claude / deepseek / glm / gemini | Vote only on findings reported by *other* models: confirm / reject / unsure; one vote per model alias (a second verifier on the same alias is skipped) | 0.0 |
| White-box test generator (`whitebox_test_generator`) | deepseek | Generates executable pytest tests targeting confirmed defects | 0.3 |
| STRIDE threat modeler (`blackbox_threat_modeler`) | claude | Extracts trust boundaries and assets; builds the STRIDE + OWASP API (and, for AI-integrated targets, OWASP LLM Top 10 2026) attack matrix and tags MITRE ATLAS techniques | 0.2 |
| Attack scenario synthesizer (`blackbox_test_synthesizer`) | deepseek | Turns threat scenarios into black-box attack scripts (BOLA, injection, rate limiting, prompt injection) | 0.2 |

---

## 🚀 Key Features

1. **AI Harness Commander**: schedules the white-box and black-box sub-agents through six linear phases and arbitrates the final Quality Gate.
2. **Heterogeneous multi-model de-biasing**: the white-box review stage fans out to four LLM families with different training lineages, so their blind spots do not overlap:
   - **Claude**: complex boundary conditions, non-null-pointer assumptions, and state-machine flaws.
   - **DeepSeek**: input sanitization, injection, defensive guards, resource-exhaustion limits (DoS defense), and unsafe concurrency.
   - **GLM**: API contract compliance, specification consistency, and authorization checks (BOLA/BFLA).
   - **Gemini**: AI-integration and supply-chain security per OWASP Top 10 for LLM Applications 2026 — untrusted input concatenated into prompts (LLM01), secrets in prompts and logs (LLM02/LLM08), tools or agents acting without allowlists (LLM03), unpinned or unsafely loaded models and packages (LLM04/LLM05), uncapped tokens and spend (LLM06), model output trusted unvalidated (LLM07) or reaching `eval`/`exec`/shell/SQL/HTML (LLM10); LLM09 (vector weaknesses) is not in its focus. Reviewers may tag findings with an `owasp_mapping` such as `LLM01:2026`.
   - Fewer than two distinct reviewer model families is an evidence gap (the verdict can never be `READY_TO_SHIP`; "consensus" from one model is consistency, not corroboration; OWASP LLM07:2026). Verifiers never rule on findings from their own model, so with a single family there are no votes at all, no findings are filtered, and the report shows N/A for both the agreement ratio and the confirmed count (the findings are listed as unverified hypotheses).
   - **Cross-model verification**: no single arbiter model. Each finding is ruled on independently by every model that did *not* report it. Each model alias votes once, however many verifier entries point at it. If another model also reported the same defect (recorded when duplicates are merged; the merge is complete-linkage, so a generic finding cannot chain two distinct defects together), that counts as one confirm vote, but corroborations alone never count as verification: without at least one real confirm / reject from a verifier the findings stay unverified hypotheses. More confirms than rejects → confirmed; more rejects → disputed (no test is generated); a tie → kept and left to the test to decide. The agreement ratio is computed from the actual votes.
3. **Mandatory threat-modeling first**: no blind brute-force testing. A STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) and OWASP API Security Top 10 attack matrix is built first, then attack tests are generated against it. The threat modeler's inputs are `--desc` (or a default description), the routes and symbols from Phase 1, and the `ai_components` detected by the deterministic rules — it does not depend on white-box results. Like the white-box reviewers, target symbols are sent in batches (split by token budget) so every symbol is visible to the threat model; threats from all batches are merged and deduplicated.
4. **An execution-based quality gate**: model findings and threats are only hypotheses; only tests that actually ran (or the deterministic rules below) can fail or block the gate. A black-box test counts as a confirmed breach only when it fails with `AssertionError`, a bare `assert`, or `pytest.fail`. Assertion-free empty tests, unusable model output (non-JSON / missing fields, or a review, verification or threat-modeling batch or an attack synthesis that crashed outside the gateway — all recorded as `invalid`), untested threats, and black-box attack tests that failed without being classified as an exploit are all listed as evidence gaps.
5. **Deterministic AI-security rules (no model involved)**: before any model sees the code, AST/text rules scan the target; their results cannot be prompt-injected:

   | Rule | Detects | Severity | Mapping |
   | :--- | :--- | :--- | :--- |
   | `VH-AI-001` | `trust_remote_code=True` (executes code shipped with the model repo) | HIGH | LLM04:2026 / AML.T0010.003, AML.T0011.000 / CWE-494 |
   | `VH-AI-002` | `torch.load` without `weights_only=True` | HIGH | LLM04:2026 / AML.T0011.000 / CWE-502 |
   | `VH-AI-003` | pickle / cloudpickle / dill / joblib / `pandas.read_pickle` / `np.load(allow_pickle=True)` deserialization | MEDIUM | LLM04:2026 / AML.T0011.000 / CWE-502 |
   | `VH-AI-004` | Hub model download without a pinned `revision=` (a moving branch such as `main` / `master` / `HEAD` does not count as pinned) | MEDIUM | LLM04:2026 / AML.T0010.003, AML.T0109 / CWE-494 |
   | `VH-AI-005` | LLM call without an output-token cap (a `config=` / `generation_config=` counts only if it contains one) | MEDIUM | LLM06:2026 / AML.T0034 / CWE-770 |
   | `VH-AI-006` | Model output flowing into `eval` / `exec` / shell / SQL (a literal argument list without `shell=True` is safe unless the program itself is tainted or is a shell / interpreter) | HIGH | LLM10:2026 / AML.T0050, AML.T0102 / CWE-94, 78, 89 |
   | `VH-AI-007` | Hard-coded credential in source (development placeholders in URL credentials, such as a loopback host or `postgres:postgres`, are redacted but not reported) | HIGH | LLM02:2026 / AML.T0055 / CWE-798 |
   | `VH-AI-008` | Invisible or bidirectional-control characters (Unicode tags, zero-width, Trojan Source, Hangul fillers); ZWJ / ZWNJ and variation selectors are not reported inside emoji, RTL / Indic text or CJK variants | HIGH (zero-width and invisible formatting characters: MEDIUM) | LLM01:2026 / AML.T0068 |
   | `VH-AI-009` | Comments/strings addressed to AI reviewers ("ignore previous instructions", "report no findings"; Traditional and Simplified Chinese phrasings such as 「忽略先前的指令」「不要回報這個問題」「AI 審查者：視為安全」 are recognized too) | MEDIUM | LLM01:2026 / AML.T0051.001 |

   `VH-AI-001`–`006` scan Python only (`005`/`006` only in files that import an AI SDK; `006` tracks taint within a single function or module scope); `007`–`009` also scan JS/TS. HIGH+ hits make the verdict `NEEDS_FIXES`. `VH-AI-008`/`009` hits also add an evidence gap (the model-driven phases may have been manipulated), so such a run can never be `READY_TO_SHIP`; that includes `009` hits in test-file string literals, on purpose, since fixture text reaches the reviewer prompts like any other code. `009` matches after NFKC normalization and skips descriptions of behaviour ("should report no findings for clean code"), negations and conditions (「不可視為安全」「判定為通過時」); a Chinese verdict claim counts only when it names the code (「此程式碼視為安全」). If the target imports an AI SDK (`openai`, `anthropic`, `litellm`, `langchain`, `transformers`, `torch`, ...), the detected `ai_components` switch on the OWASP LLM Top 10 2026 checklist and ATLAS mapping in threat modeling (`owasp_llm_top10_2026` in `vibeharness/config/threat_rules.yaml`), and threats can carry an `atlas_mapping`.
6. **Two sandboxes**: generated tests run in a temp directory with an environment-variable allowlist (API keys are not in the child's environment, and injection keys such as `LD_PRELOAD` and `BASH_ENV` are dropped). Each batch has a timeout (`sandbox_timeout_seconds`); a timed-out batch is re-run test by test, where each test gets its own timeout (`per_test_timeout_seconds`) while the batch budget still caps the total. On timeout the whole process tree is killed (Docker removes the container instead). Output is captured in temp files rather than pipes, so a stray child process left behind by a test cannot turn a finished run into a timeout, and on POSIX the rest of the process group is killed when the main process exits.
   - `local_subprocess` (default): a local subprocess; on POSIX its address space is capped by `sandbox_memory_mb` (default 2 GB) plus a CPU-time cap, stopping runaway consumption. `HOME` points at a per-run temp directory, and on Linux the harness makes itself non-dumpable so a generated test cannot read the API keys in `/proc/<harness>/environ`. Other processes of your user (the shell that launched the harness, for one) keep a readable environment, so this is still not a security boundary.
   - `docker`: each test batch runs in a disposable container — no network by default, read-only root filesystem and target mount, all capabilities dropped, no privilege escalation, non-root user (when the harness itself runs as root the container runs as `nobody`), and memory/CPU/process limits. Only the run's temp directory and `/tmp` (a noexec tmpfs) are writable.
7. **JS/TS dynamic test execution**: for `.js` / `.jsx` / `.mjs` / `.cjs` / `.ts` / `.tsx` / `.mts` / `.cts` targets, white-box tests and in-process black-box attack tests are generated as `node:test` + `node:assert` ES modules (`node_bin` is detected the first time one is needed; Node >= 20, and >= 22.6 for `.ts` through type stripping). Each test module runs in its own `node --test` process, on what is left of the batch budget (after a batch timeout the rest are re-run on `per_test_timeout_seconds`), and is judged from the JUnit report: only an `AssertionError` / `ERR_ASSERTION` failure is a confirmed breach, a `TypeError` thrown inside the target is a defect but not an exploit, and a test-side `ReferenceError` or an unresolvable import is a harness error. Tests import the target through its `file://` URL (the prompt states the ESM / CommonJS import form and the detected exports); bare specifiers resolve from the target's `node_modules` (linked into the run directory); the static gate refuses package installs (`npm` / `pnpm` / `yarn` / `bun` / `npx`) as it does for Python. The Node sandbox sets no `RLIMIT_AS` (V8 reserves a large address space at start-up) and caps the heap with `--max-old-space-size` instead, keeping the CPU cap; `NODE_OPTIONS` / `NODE_PATH` are never forwarded from the host. Black-box HTTP attacks against a running server are still written in Python (urllib). Without a usable Node runtime the JS/TS tests are reported as ERROR and as an evidence gap ("no usable Node runtime"), never as a start-up failure; the mock mode's simulation engine generates no JS test, so the gap reads "no JS/TS test was generated". Under Docker, Node tests use a separate image, `docker_node_image` (`docker/sandbox-node.Dockerfile`).
8. **Mutation testing (optional, `--mutation`)**: coverage only measures which lines ran, not whether the tests would notice a behaviour change. When on, deterministic single-token changes (`+`↔`-`, `<`↔`<=`, `and`↔`or`, removing `not`, `True`↔`False`, `0`↔`1`, …) are made to the functions covered by passing Python white-box tests and the tests are re-run on a copy: any failing test "kills" the mutant, all passing means it "survived"; score = killed ÷ (killed + survived), a lower bound (equivalent mutants cannot be decided). Fully offline, no model calls, **off by default**; it only adds evidence gaps (score below `mutation_min_score`, mutants truncated by `mutation_max_mutants`, or no conclusion), never causes `NEEDS_FIXES`, and never writes into your target directory. Limits: Python only, no JS/TS, not in SARIF or the baseline.

> ⚠️ **`local_subprocess` is not a security boundary.** It executes model-generated code with your user's permissions, with file and network access. API keys are kept out of the child's environment and, on Linux, out of reach through `/proc/<harness>/environ`, but other same-user processes (your shell, for one) still expose theirs. For untrusted targets or live mode, use `sandbox_provider: docker`.

### 🔐 Security design basis (OWASP LLM Top 10 2026 / MITRE ATLAS)

VibeHarness-MAS is itself an LLM application: the target's code is untrusted input to every review, verification, and generation prompt, and model output is untrusted input to its reports. The design follows the [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/) (v1.0, with the Appendix A mapping to ATLAS v2026.06 / CWE 4.20), [MITRE ATLAS](https://atlas.mitre.org/) (content release 2026.07), and AI supply-chain practice, placing a deterministic control at every trust boundary instead of relying on "a model supervising a model":

| Risk | Harness control |
| :--- | :--- |
| LLM01 Prompt Injection (AML.T0051.001, AML.T0068) | Invisible Unicode (tag block, variation selectors, zero-width, bidi controls) is stripped before code reaches a model; code is passed in a provenance-labeled `<untrusted_target_code>` channel, and model-written text handed to another model (a threat-model item, a reviewer's finding) in `<untrusted_model_output>` or the same untrusted channel (second-order injection); forged tags of either channel are neutralized in both; every agent that reads target code has a security policy appended to its system prompt (instructions inside code are data, and a defect in themselves); `VH-AI-008`/`009` detect planted reviewer-directed instructions and list them as an evidence gap |
| LLM02 / LLM08 Sensitive Information (AML.T0055) | Hard-coded secrets (OpenAI / Anthropic / AWS access and secret / GitHub / Google / Slack / HF / NVIDIA / Stripe keys, JWTs, Azure storage keys, passwords in URL userinfo, private keys) are replaced with `<REDACTED:…>` before any code reaches an external model, and reports never echo their values; the sandbox environment allowlist never passes API keys, and `extra_params` cannot redirect a model to another endpoint |
| LLM04 Supply Chain (AML.T0010, AML.T0060) | Default models use versioned ids (not moving aliases like `deepseek-chat` that a provider can swap); `api_base` must be https (http only for loopback); generated tests that install packages (`pip`/`uv`/`poetry`/`npm install`, `import pip`, ...) are refused, so hallucinated package names cannot be slopsquatted; this repo's CI and sandbox images install hash-locked dependencies (`--require-hashes`) on digest-pinned base images |
| LLM06 Unbounded Consumption (AML.T0034) | `max_model_calls` (a hard cap: live calls stop when it is spent), `max_output_tokens` (global and per model), request and sandbox timeouts, the `max_concurrent_calls` parallelism cap, and per-batch token budgets; a live failure or Ctrl-C cancels the calls still queued |
| LLM07 Misinformation | Model findings and threats are hypotheses only; only executed tests or deterministic rules can fail the gate; models never judge their own findings; fewer than two distinct reviewer model families is an evidence gap |
| LLM10 Improper Output Handling (AML.T0077) | Model text has images and raw HTML disabled before it enters Markdown (no image-URL exfiltration), ANSI/OSC control sequences removed and line breaks collapsed (so it cannot open a spoofed heading or table); model-chosen ids go into code spans with pipes escaped; console output escapes rich markup; SARIF messages have control characters stripped |
| Audit trail | Every successfully sent model call records a `prompt_sha256`, so a verdict can be traced back to its actual input without the report having to store (possibly sensitive) code; a batch that crashes outside the gateway (review, verification, threat modeling, attack synthesis) is booked through `record_failure` as `invalid` (with the exception, no hash) |

### 🧭 Not yet implemented (planned)

| Feature | Status |
| :--- | :--- |
| Mutation testing extensions | v1 is Python only (core feature 8); JS/TS mutants, baseline and SARIF integration and per-operator statistics are not implemented |
| Dynamic DAST / fuzzing agent | Not implemented; black-box tests are generated per threat as pytest attack scripts |
| Hypothesis property-based testing | Not built in; models may generate it, but the target environment needs `hypothesis` installed |
| `e2b` sandbox | Not implemented; `sandbox_provider` supports `local_subprocess` and `docker`, anything else fails fast |
| JS/TS coverage and third-party packages | JS/TS tests are generated and run with Node (see "JS/TS dynamic test execution" below), but JS coverage is not collected; TypeScript is type-stripped only (enums, namespaces, parameter properties, decorators and tsconfig path aliases are unsupported); inside the Docker sandbox bare ESM specifiers do not resolve (only CommonJS honours `NODE_PATH`) |
| Scope of JSX lexing | The lexer treats `<` as JSX only in expression position in `.js` / `.jsx` / `.mjs` / `.cjs` / `.tsx` files (in `.ts`, `<T>x` is a type assertion); a `<` that is not valid JSX (e.g. a TS generic) falls back to plain lexing, and so does an element nested deeper than 120 levels; a file may have at most 32 failed attempts, after which every remaining `<` is lexed as plain code |

---

## 📦 Repository Layout

```text
MultiAgentGama/
├── .github/
│   ├── CODEOWNERS               # default reviewers
│   ├── dependabot.yml           # weekly update proposals for Actions, requirements*.txt / requirements.lock, the sandbox base images and docker/sandbox-requirements.*
│   ├── ISSUE_TEMPLATE/          # bug report / feature request templates
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       ├── tests.yml            # CI: lint (ruff / mypy), audit (pip-audit), package (sdist + wheel: wheel smoke test, suite run from the sdist), test (Ubuntu / Windows × Python 3.10–3.14 plus macOS × 3.12, 93% coverage floor)
│       ├── publish.yml          # Release: on tag push, run tests.yml first, verify the version matches, build sdist / wheel, smoke-test the wheel in a clean venv, upload to the GitHub Release (PyPI needs ENABLE_PYPI_PUBLISH)
│       └── live-smoke.yml       # Manual: one live / hybrid run of examples with the repo's provider secrets, reports uploaded
├── docker/
│   ├── sandbox.Dockerfile       # Base image for the docker sandbox (digest-pinned python:3.12-slim, USER 65534; pytest / pytest-cov / requests)
│   ├── sandbox-node.Dockerfile  # Base image for the docker Node sandbox (digest-pinned node:22-slim, USER 65534; runs JS/TS tests)
│   ├── sandbox-requirements.in  # Direct inputs of the sandbox image's lock (constrained by requirements.lock)
│   └── sandbox-requirements.txt # Hash-locked sandbox dependencies (installed with --require-hashes)
├── vibeharness/                 # the only top-level package (the sole directory a pip install adds to site-packages)
│   ├── __init__.py              # package version (__version__, pyproject's single source)
│   ├── cli.py                   # CLI entry point (the vibeharness command)
│   ├── config/
│   │   ├── agents_config.yaml       # Global settings (execution mode, sandbox, limits), multi-model routing (Claude, GLM, DeepSeek, Gemini), per-agent prompts
│   │   └── threat_rules.yaml        # STRIDE, OWASP API Top 10 and OWASP LLM Top 10 2026 (with ATLAS / CWE mapping)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── harness.py               # Commander: six linear phases and the quality gate
│   │   ├── llm_gateway.py           # Unified LiteLLM gateway: routing, fallback, simulation fallback, call budget and call_log
│   │   ├── models.py                # Pydantic data models
│   │   ├── baseline.py              # --baseline: run-independent fingerprints, known problems not counted
│   │   ├── codecheck.py             # Static checks on generated tests (every test_ function / method asserts; refuses package installs)
│   │   ├── codecontext.py           # Source code and import guidance handed to the models (through the untrusted-code channel)
│   │   ├── estimate.py              # --estimate: calls, tokens and cost without calling a model
│   │   ├── i18n.py                  # bilingual "中文 ／ English" output helpers (bi / en_only)
│   │   ├── mutation.py              # Optional mutation testing (Python)
│   │   ├── sanitize.py              # Trust-boundary hygiene: invisible chars, secret redaction, untrusted-code / model-output channels, output sanitizing
│   │   └── sandbox.py               # Sandboxes: local subprocess (not a security boundary) and Docker containers; a Node flavour of each (node --test)
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── whitebox/
│   │   │   ├── __init__.py
│   │   │   ├── ast_extractor.py     # Symbol parsing and route extraction (AST for Python; dependency-free lexer for JS/TS)
│   │   │   ├── ai_static_scanner.py # Deterministic AI-security rules VH-AI-001..009 (no model involved)
│   │   │   ├── common.py            # Shared helper: cancels queued model calls on a live failure or Ctrl-C
│   │   │   ├── multi_reviewer.py    # Heterogeneous model ensemble review (built from the whitebox_reviewer_* entries)
│   │   │   ├── deduplicator.py      # Merges the same defect reported by multiple models (complete-linkage)
│   │   │   ├── debater.py           # Cross-verification: ruled on by non-author models
│   │   │   └── test_generator.py    # Automatic unit/boundary test generation (self-repair, WB-PROBE probes)
│   │   └── blackbox/
│   │       ├── __init__.py
│   │       ├── threat_modeler.py    # STRIDE / OWASP API / LLM threat-modeling engine (with ATLAS mapping)
│   │       └── scenario_builder.py  # Turns threats into executable attack scripts
│   ├── runners/
│   │   ├── __init__.py
│   │   └── test_executor.py         # Sandboxed pytest executor with PoC capture (shared by white-box and black-box)
│   ├── reports/
│   │   ├── __init__.py
│   │   └── report_generator.py      # Markdown / JSON / SARIF audit report generator
├── examples/
│   └── vibe_sample_app.py       # A representative sample of typical Vibe-Coding defects
├── docs/
│   ├── sample_report.md         # Sample report produced in mock mode
│   ├── configuration.md         # Configuration reference (Traditional Chinese)
│   ├── configuration.en.md      # Configuration reference (English)
│   ├── design.md                # Design document: architecture, data flow, gate verdicts, sandbox security model (Traditional Chinese)
│   └── design.en.md             # Design document (English)
├── tests/                       # The toolkit's own tests (offline, no API keys needed)
│   ├── conftest.py              # Shared fixtures: a fake litellm so the live paths run offline
│   ├── test_ai_security.py      # OWASP LLM Top 10 2026 / ATLAS controls and the deterministic AI-security rules
│   ├── test_baseline.py                # --baseline: run-independent keys, known problems not counted, action.yml structure
│   ├── test_cross_verification.py      # Cross-verification: models never judge their own findings, vote tallies
│   ├── test_dedup_and_budget.py        # Duplicate-finding merge and prompt context within the token budget
│   ├── test_docker_sandbox.py          # Docker sandbox: path mapping, hardening flags, real execution (when Docker is present)
│   ├── test_estimate.py                # --estimate: exact and scenario figures, prices, no model call
│   ├── test_harness_components.py      # Component integration tests in mock mode
│   ├── test_i18n.py                    # Bilingual helpers, report / console / CLI strings, bilingual docstrings and comments
│   ├── test_i18n_output.py             # Prompts stay English, bilingual rule titles, executor reasons and PoCs
│   ├── test_js_execution.py            # JS/TS execution: code gate, ESM/CJS detection, Node JUnit classification, Node sandboxes (real runs when node exists), end to end
│   ├── test_js_ts_extractor.py         # JS/TS extractor: brace matching, literal/comment masking, arrow functions, routes
│   ├── test_mutation.py                # Mutation testing: sites and splicing, determinism and cap, isolation and path rewriting, strong vs weak tests end to end, gate semantics, switch precedence, CLI / Action
│   ├── test_model_output_robustness.py # Graceful degradation on malformed model output, probe-fallback disclosure
│   ├── test_p0_regressions.py          # Executor correctness, self-repair and result-provenance honesty regressions
│   ├── test_parallel_and_budgets.py    # Parallel test generation, model-call budget, file / worker caps
│   ├── test_prompt_context.py          # Live mode: prompts carry real code and import paths, gateway call robustness
│   ├── test_quality_fixes.py           # Packaging, model-output robustness, execution and SARIF fix regressions
│   ├── test_review_blackbox.py         # Threat ids, STRIDE spellings, crashed black-box batches booked
│   ├── test_review_build.py            # Pinned actions, workflow inputs via env, image digests, hashed locks, sdist contents
│   ├── test_review_cache_only.py       # --cache-only: hits never call litellm, a miss is an evidence gap (hybrid) or exit 4 (live), no re-ask, exit 5 without a cache
│   ├── test_review_cli_config.py       # Crash exit codes, config validation, re-ask / cache key, unverified count
│   ├── test_review_dedup_votes.py      # Complete-linkage dedup, one vote per verifier model
│   ├── test_review_extractor_scanner.py # JSX / TS lexing, route detection, VH-AI-004/005/006 precision
│   ├── test_review_known_limits.py     # JSX text, hapi array and regex routes, nested Flask routes reviewed once, named argv lists
│   ├── test_review_reports.py          # Code spans, newline spoofing, SARIF paths, threat symbols, unverified hypotheses
│   ├── test_review_sandbox_executor.py # Fake home, non-dumpable harness, stray children, NameError attribution, JS budgets
│   ├── test_review_sanitize.py         # Credential formats, invisible characters, injection markers, channel tags
│   ├── test_review_sanitize_blackbox_fixes.py # Placeholder credentials, VH-AI-008/009 precision, port check, aborting calls
│   └── test_review_whitebox_fixes.py   # Routes, nested Python definitions, scanner rules, severity, untrusted finding text
├── .pre-commit-config.yaml      # pre-commit: ruff and mypy before every commit
├── CHANGELOG.md                 # Changelog (Traditional Chinese); CHANGELOG.en.md is the English version
├── CONTRIBUTING.md              # Contributing guide: setup, pre-push checks, principles, release steps
├── LICENSE                      # MIT license
├── SECURITY.md                  # Security policy: private vulnerability reporting
├── MANIFEST.in                  # sdist contents: docs, config, tests, examples, main.py, action.yml, requirements and locks, docker/, policy files
├── action.yml                   # composite GitHub Action: one `uses: chinchiang/MultiAgentGama@vX.Y.Z` line runs the audit in a target repo
├── pyproject.toml               # Package metadata, the vibeharness entry point, pytest / ruff / mypy settings
├── requirements.txt             # Runtime dependencies
├── requirements-dev.txt         # Development dependencies (ruff, mypy, pytest-cov, build, pip-audit; pinned)
├── requirements.lock            # Fully locked, hashed versions (CI installs with --require-hashes; pip-audit)
├── README.md                    # Documentation (Traditional Chinese); README.en.md is the English version
└── main.py                      # thin launcher: `python main.py …` calls vibeharness.cli
```

---

## 🛠️ Getting Started

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

For exactly the dependency set CI tests with (hash-verified): `pip install --require-hashes -r requirements.lock`.

Or install as a package (this also registers the `vibeharness` command):

```bash
pip install .
vibeharness --version
```

### 2. Configure API keys (optional)

The toolkit supports real API calls and an offline simulation mode (Hybrid Mode):

> For a complete reference to every field in `vibeharness/config/agents_config.yaml` — defaults, model reassignment, and Docker sandbox examples — see **[docs/configuration.en.md](docs/configuration.en.md)** ([正體中文](docs/configuration.md)).
>
> For why each component is designed the way it is, how data flows between phases, and how the gate and evidence gaps are decided, see **[docs/design.en.md](docs/design.en.md)** (design document; [正體中文](docs/design.md)).

```bash
# To use live models:
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude
export ZAI_API_KEY="..."                 # GLM (Zhipu Z.AI)
export DEEPSEEK_API_KEY="sk-..."         # DeepSeek
export GEMINI_API_KEY="AIza..."          # Gemini
```

Default models are in `vibeharness/config/agents_config.yaml` (Claude `claude-sonnet-5-5`, GLM `zai/glm-5.3`, DeepSeek `deepseek/deepseek-v4-pro`, Gemini `gemini/gemini-3.8-flash`). Each model can set a `fallback_model` (defaults: `claude-haiku-4-5-20251001`, `zai/glm-5.3-flash`, `deepseek/deepseek-v4-flash`, `gemini/gemini-3.5-flash`); after the primary model fails `max_retries` times the fallback is tried, and the report records which model was actually used. Each model's key is read from the environment variable named in `api_key_env`; providers that authenticate with AWS credentials (e.g. Bedrock) can set `aws_profile_name` / `aws_region_name` instead. Target code is sent to every configured provider (with hard-coded credentials redacted first), so only configure providers whose data-retention terms you accept.

Other limits in the `global` section (effective unless overridden from the CLI): `execution_mode` (overridden by `--mode`), `timeout_seconds` (per model request, default 180 s), `max_retries` (2), `max_output_tokens` (16384, reasoning tokens count against it; `models.<alias>.max_output_tokens` overrides it per model), `max_concurrent_calls` (parallel model calls per phase, 6), `max_model_calls`, `max_files`, `max_file_bytes`, `include` / `exclude`, `retry_invalid_output`, `sandbox_timeout_seconds` (120) and `per_test_timeout_seconds` (30). `null` for `timeout_seconds`, `max_retries`, `max_output_tokens` or `retry_invalid_output` means the same as leaving it out (the default; a per-model `max_output_tokens: null` keeps the global value).

Any agent can point at any defined model via `model_alias`; an agent without a `model_alias` resolves to `unconfigured` (simulated in hybrid mode, a hard failure in live mode). A single API key is enough to run live mode — for example, with only a Gemini key, change every `model_alias` in the `agents` section to `gemini` (note: `gemini-2.5-flash` is no longer available to newly issued Google API keys; use a 3.x version). With a single model family, though, verifiers never rule on their own model's findings, so there are no verification votes, no findings are filtered, and fewer than two reviewer families is an evidence gap: the best possible verdict is `INCONCLUSIVE` (exit code 3), so treat the result as indicative only.

*Note: without API keys, `hybrid` mode falls back to the simulation engine so you can experience the workflow offline. The simulation returns **fixed templates unrelated to the target code**; the report marks them with `[SIMULATED]` and an "執行來源 ／ Execution Provenance" section, and the quality gate will never yield `READY_TO_SHIP` because of them.*

| `--mode` | Behavior |
| :--- | :--- |
| `live` | Real models only; a missing key or failed call aborts (exit code 4). Unusable model responses are recorded as `invalid` and the verdict becomes INCONCLUSIVE |
| `hybrid` (default) | Calls live models when possible; otherwise falls back to simulation, disclosed in the report |
| `mock` | Simulation engine only |

In simulation mode, white-box tests use deterministic None-input robustness probes derived automatically from the target functions (`WB-PROBE-*`); in any mode, a confirmed finding that ends up without a usable model-generated test also gets a probe and is listed as an evidence gap. Black-box threats without an executable test are listed under "Threats Not Tested" instead of fabricating results.

### 3. Use the Docker sandbox (recommended for untrusted targets)

```bash
docker build -t vibeharness-sandbox:latest -f docker/sandbox.Dockerfile .
docker build -t vibeharness-sandbox-node:latest -f docker/sandbox-node.Dockerfile .   # when the target has JS/TS
```

Set `sandbox_provider: "docker"` in `vibeharness/config/agents_config.yaml`. Tunables: `docker_image`, `docker_network`, `docker_memory`, `docker_cpus`, `docker_pids_limit`. JS/TS tests use the Node container `docker_node_image` (`sandbox_node_provider` follows `sandbox_provider` by default and can be set to `local_subprocess` alone to run JS tests with the local Node).

- The target directory is mounted read-only into the container at `/work/<dir name>`; host absolute paths inside generated tests are rewritten to container paths automatically.
- Containers have **no network** by default, so packages cannot be installed at run time. Pre-install the target's dependencies into a project-specific image and point `docker_image` at it. The base image runs as `nobody` (`USER 65534`), so switch to root for the install and back afterwards:

  ```dockerfile
  FROM vibeharness-sandbox:latest
  USER root
  COPY requirements.txt /tmp/requirements.txt
  RUN pip install --no-cache-dir -r /tmp/requirements.txt
  USER 65534:65534
  ```

- Both base images are pinned by digest, and the Python image installs its test tools from the hash-locked `docker/sandbox-requirements.txt`.
- Black-box tests that hit a running service need network access (e.g. `docker_network: "host"` on Linux), which reduces isolation.
- A missing docker command or image fails loudly with the build command — it never silently falls back to the local subprocess.

### 4. Run the full pipeline against a target project

```bash
python main.py --target examples --output vibe_harness_report.md
```

`--target` (`-t`, default `examples`) accepts a directory or a single file; `--output` (`-o`) defaults to `vibe_harness_report.md`. `--desc` (`-d`) gives the threat modeler a high-level description of the system; `--config` (`-c`) points at another config file; `--verbose` (`-v`) enables debug logging. Black-box tests import the target in-process by default; they send real HTTP requests only when you pass `--base-url` (`-u`, e.g. `--base-url http://localhost:8000`; only `http://`/`https://` URLs with a host name are accepted, any other scheme is a usage error) explicitly and a service answers there. No default address is ever probed, so attack scripts cannot hit an unrelated local service, and in live HTTP mode attack code aimed at any host other than `--base-url`, or at another port of that host, is rejected statically. See [`docs/sample_report.md`](docs/sample_report.md) for example output.

Before a run, `--estimate` shows its size: it runs Phase 1 only (symbol extraction and the deterministic rules, no model call) and prints the expected calls per agent and per model (reviewer and threat-modeling counts are exact; verification, test generation and attack synthesis are scenario figures from stated assumptions such as findings per batch, with a maximum that includes re-asks and heals), the estimated prompt / output tokens and, for models with `price_per_million_*` configured, the estimated cost; with `--format json` it is written to `--output`; the exit code is 0 (5 when a `--changed-since` ref cannot be resolved or `--output` cannot be written). Scale and cost limits can be overridden from the CLI: `--max-files` (number of source files analyzed per run, default 50, must be ≥ 1; the rest are reported as skipped and listed as an evidence gap) and `--max-model-calls` (cap on model invocations per run, unlimited by default; `0` also means unlimited and a negative value is a usage error; retries and the fallback are not counted separately; when exhausted, hybrid falls back to simulation and lists an evidence gap, live fails). File selection: `--include GLOB` / `--exclude GLOB` (repeatable; matched against the path relative to `--target` or the file name, e.g. `--exclude 'tests/*' --exclude '*.min.js'`; they replace the config's `include` / `exclude`), and `--changed-since <git ref>` (only files that changed relative to that ref, including unstaged and untracked ones; made for PR checks: `--changed-since origin/main`). Files above `max_file_bytes` (default 1 MB) are not analyzed and are listed as an evidence gap. An unusable model answer is re-asked once (`retry_invalid_output`) before it is booked `invalid`. An unwritable `--output` / `--sarif` location exits 5 before any model call; when a run crashes or is interrupted, the completed phases (call log, findings, test results, threats) are written to `<output>.partial.json`. `--cache-dir DIR` enables the response cache: usable live answers are stored in DIR and an identical prompt later is served from it without a provider call or budget spend (handy for re-runs or switching the report format); an answer that only became usable after a re-ask is also stored under the original prompt's key, so a re-run hits on the first attempt. `--cache-only` serves every call from the response cache only (needs `--cache-dir` or `global.cache_dir`, else exit 5): no provider call, no budget spend and no re-ask; a call the cache cannot answer is an evidence gap, simulated in hybrid (the verdict cannot be `READY_TO_SHIP`) and exit 4 in live. `--estimate` with `--cache-only` still lists the calls and notes that no provider is called and nothing is spent. See [`docs/configuration.en.md`](docs/configuration.en.md).

Report formats: `--format md` (default) or `--format json` (machine-readable, with the complete findings, threat model, and test results — suited to CI/CD). Both keep every generated test's code: the Markdown appendix "產生的測試程式碼（稽核軌跡） ／ Generated Test Code (audit trail)" lists each test's code next to its outcome in collapsible blocks (control characters removed), and the JSON `generated_tests` / `blackbox_generated_tests` keep it verbatim for audits or re-runs. Model-written tests are hypotheses too — a "passing" test may be asserting the defect itself (e.g. `pytest.raises(KeyError)`), so check that the assertions describe the correct behaviour:

```bash
python main.py --target examples --output report.json --format json
```

You can also pass `--sarif <path>` to emit a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) report alongside: confirmed white-box findings carry file/line locations (resolved from `line_number` or the symbol table; when cross-verification was not applied they are marked `properties.verified: false` and their message starts with "Unverified hypothesis"), confirmed black-box breaches are error-level results (located at the attacked symbol when the attack vector names it as a whole identifier or route, the longest match winning), and deterministic AI-security rule hits use their own rules `vibeharness/VH-AI-001` … `vibeharness/VH-AI-009`, tagged with their OWASP, MITRE ATLAS, and CWE ids. Rule ids are stable (`vibeharness/whitebox-finding` / `vibeharness/blackbox-breach` / `vibeharness/VH-AI-00x`) and the run-specific finding/test ids live in `properties`, so renumbering between runs does not close and reopen Code Scanning alerts. Upload the SARIF to GitHub Code Scanning to surface defects in the repo's **Security** tab:

```yaml
# Example .github/workflows/security.yml for the target project: this repo ships a composite GitHub Action (action.yml)
- uses: chinchiang/MultiAgentGama@v0.5.1      # installs the package from the action's own checkout (hash-verified dependencies) and runs the audit
  with:
    target: src
    mode: hybrid
    max-model-calls: "80"
    changed-since: origin/main                 # PR checks: only files that changed (optional)
    baseline: .vibeharness/baseline.json       # optional: only problems that are new fail the job
    mutation: "true"                            # optional: true / false switches mutation testing for this run, empty follows the config
    fail-on: needs-fixes                       # blocked | needs-fixes | inconclusive | never
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    ZAI_API_KEY: ${{ secrets.ZAI_API_KEY }}
    DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
    GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
- uses: github/codeql-action/upload-sarif@9f759ee644a3e7c15c1390abf49868036c00067b # v3.38.3
  if: always()
  with:
    sarif_file: vibeharness.sarif
```

The action's outputs are `verdict` (`READY_TO_SHIP` / `NEEDS_FIXES` / `BLOCKED_CRITICAL_RISK` / `INCONCLUSIVE`, or `ERROR` when the harness itself failed) and `exit-code`; the report, the SARIF and a crash's `.partial.json` are uploaded as the `vibeharness-report` artifact. Without the action, `pip install "git+https://github.com/chinchiang/MultiAgentGama@v0.5.1"` and call `vibeharness` directly.

**Mutation testing switch**: `--mutation` turns it on, `--no-mutation` off; precedence is CLI flag > config `global.mutation_testing` > off, so a config that enables it can be switched off for one run with `--no-mutation`, and a config that disables it can be switched on with `--mutation`. `--mutation-max-mutants N` (≥ 1) overrides the mutant cap (default 20); each mutant costs one sandbox batch and no model call, and `--estimate` lists the ceiling when it is on. The report has a Mutation Score row in the metrics table and lists surviving mutants; the other keys are in [`docs/configuration.md`](docs/configuration.md).

**Gating on new problems only (`--baseline`)**: keep one `--format json` report (for example committed as `.vibeharness/baseline.json`) and pass it with `--baseline`: failed white-box tests (keyed by their source finding), probe failures, black-box breaches and HIGH+ rule hits it already contains are still listed in the report's "基準中的已知問題（不計入） ／ Known from baseline (not counted)" section and in the recommendations, but no longer count toward the verdict or the exit code, so CI fails only on problems that are new. The keys do not depend on run numbering (a finding is keyed by target-relative path + symbol + normalized title, a breach by the threat's STRIDE category + title + attack vector, a rule hit by rule + file + evidence without the line number, a probe by its symbol), so re-numbered model output or unrelated line shifts never turn an old problem into a new one. Every item in the JSON report carries a `fingerprint` field; reports from before 0.3.0 without it are recomputed. A crash's `.partial.json` cannot serve as a baseline.

> Note: file paths in the SARIF are relativized against the root of the git repository containing `--target` (falling back to the `--target` directory outside a repository), so `--target src` still yields Code-Scanning-aligned paths such as `src/app.py`. A file outside that root gets an absolute `file://` URI (no `uriBaseId`), and a model-reported relative path that would escape it with `..` gets no location; `..` is never emitted.

Exit codes (evaluated in order):

| Code | Meaning | Condition |
| :--- | :--- | :--- |
| `2` | BLOCKED_CRITICAL_RISK | At least one black-box attack test confirmed a defense was breached |
| `1` | NEEDS_FIXES | At least one white-box test failed (exposed a defect), or a HIGH+ deterministic AI-security rule hit; this code is exclusive to that verdict — harness errors never use it |
| `3` | INCONCLUSIVE | No failures, but evidence gaps exist: simulation engine used, unusable model output or a crashed batch, `max_model_calls` exhausted, no reviewers or fewer than two reviewer model families, files skipped by `max_files`, files above `max_file_bytes`, non-Python code reviewed statically only, test errors / not run, confirmed findings without a model-generated test, untested threats, black-box tests that failed without being classified as an exploit, file parse failures, planted reviewer-directed instructions or invisible characters (`VH-AI-008`/`009`), etc.; an unknown verdict string also fails closed with this code |
| `0` | READY_TO_SHIP | None of the above |
| `4` | — | Live-mode model invocation failed, or the response cache had no answer for a live-mode `--cache-only` run |
| `5` | — | Harness configuration or usage error: `--target` missing, config file absent, invalid YAML, a directory, unreadable or binary, or with a top level / section / entry that is not a mapping, an invalid `max_files` / `max_model_calls` / `max_concurrent_calls` / timeout or similar value, a reserved `extra_params` key (output-token caps `max_tokens` / `max_completion_tokens` / `max_output_tokens` included), `--cache-only` without a response cache (neither `--cache-dir` nor `global.cache_dir`), sandbox unavailable, unwritable `--output` / `--sarif`, an unresolvable `--changed-since` ref, CLI usage error, or any unexpected internal error, whether while starting up, during `--estimate` or during the run (a crash is never misreported as a verdict) |
| `130` | — | Interrupted with Ctrl-C; no full report written (completed phases are in `<output>.partial.json`) |

### 5. Run the toolkit's own tests and linters

```bash
pip install -r requirements-dev.txt
python -m pytest
python -m ruff check .
python -m mypy vibeharness/ main.py
```

A manual `live-smoke.yml` (Actions tab → live-smoke → Run workflow) runs the target once against real models with the provider keys stored as repository secrets (live or hybrid, with a call cap), then re-runs for the JSON report with `--cache-only --mode hybrid` from the same response cache (no provider call, so the whole workflow makes at most the cap in real calls; calls the first run could not cache are simulated and listed as an evidence gap), and uploads the reports and SARIF as an artifact; it is the only check that reaches the providers and does not run on PRs. CI (`.github/workflows/tests.yml`) has four jobs: `lint` (ruff and mypy), `audit` (pip-audit), `package` (builds the wheel and runs it once in mock mode outside the checkout) and `test` (Ubuntu / Windows × Python 3.10–3.14 plus one macOS cell on Python 3.12, installed with `--require-hashes` from `requirements.lock`; the Linux job also builds the Docker sandbox images and runs the real-container tests). `package` builds the sdist and the wheel, runs the wheel once in mock mode outside the checkout and runs the full suite from the extracted sdist; `publish.yml` runs this whole workflow on the tagged commit before it builds a release. The `test` job enforces a coverage floor; to run the same check locally:

```bash
python -m pytest --cov=vibeharness --cov-fail-under=93
```

Supply-chain check (the CI `audit` job runs the same command against the locked set; a dependency with a known CVE fails before merge):

```bash
pip install "$(grep '^pip-audit==' requirements-dev.txt)"
python -m pip_audit -r requirements.lock --disable-pip --require-hashes
```

Optional: install [pre-commit](https://pre-commit.com/) to run ruff and mypy automatically before every `git commit` (see [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow and [SECURITY.md](SECURITY.md) for vulnerability reporting):

```bash
pip install pre-commit
pre-commit install
```
