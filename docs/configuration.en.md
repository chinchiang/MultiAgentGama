# Configuration Reference (agents_config.yaml)

English (US) ｜ [正體中文（臺灣）](configuration.md)

This document covers every field in `vibeharness/config/agents_config.yaml`: semantics, defaults, and what actually takes effect (as implemented).

The file has three top-level sections: **`global`** (execution and sandbox parameters), **`models`** (provider definitions), and **`agents`** (per-agent model routing). A missing or invalid-YAML config file fails loudly (`ConfigError`; the CLI exits with code 5); the harness never runs on an empty configuration.

From the CLI, use `--config <path>` to point at a different file and `--mode` to override `execution_mode` (precedence: CLI `--mode` > `global.execution_mode` > default `hybrid`); `--max-files` and `--max-model-calls` override their `global` fields the same way.

---

## The `global` section

| Field | Default | Description |
| :--- | :--- | :--- |
| `execution_mode` | `"hybrid"` | One of `live` / `hybrid` / `mock` (see table below); anything else fails at startup |
| `timeout_seconds` | `180` | Per-LLM-request timeout in seconds, passed to litellm; must be a number ≥ 1 (validated at start-up, else `ConfigError`) |
| `max_retries` | `2` | Retry count at the litellm level (retries the same primary model; the `fallback_model` is tried once only after all retries fail); must be an integer ≥ 0 |
| `max_output_tokens` | `16384` | Token cap per model response; `models.<alias>.max_output_tokens` overrides it per model; must be an integer ≥ 1 |
| `max_model_calls` | `null` (unlimited) | Cost guard: real model invocations per run (litellm retries and the `fallback_model` of one invocation are not counted separately). Once exhausted, `hybrid` falls back to the simulation engine and it is listed as an evidence gap (the verdict cannot be `READY_TO_SHIP`); `live` raises `LLMGatewayError` (exit 4). Must be a non-negative integer; `0` means unlimited |
| `max_concurrent_calls` | `6` | Concurrent model calls per agent phase (review, verification, white-box test generation, black-box attack synthesis); `1` makes everything sequential |
| `max_file_bytes` | `1000000` | Size cap (bytes) for a single source file; larger files are not analyzed and are listed as an evidence gap (minified bundles, generated code). Non-negative integer; `0` / `null` keep the default |
| `include` | `[]` | Glob list: only files whose path relative to `--target` (or file name) matches one of them are analyzed (e.g. `["src/*"]`); empty = everything. CLI `--include` replaces the list |
| `exclude` | `[]` | Glob list: matching files are not analyzed (e.g. `["tests/*", "vendor/*", "*.min.js"]`; `vendor` also matches the whole directory); excluded files are not an evidence gap. CLI `--exclude` replaces the list |
| `cache_dir` | `null` (off) | Response cache directory (created if missing): usable live answers are stored as JSON keyed by model, settings and prompt, and an identical prompt later is served from it with no provider call and no `max_model_calls` spend; the "執行來源 ／ Execution Provenance" table shows it as "真實（回應快取） ／ live (response cache)". CLI `--cache-dir` overrides. The directory holds raw model answers (which may quote the audited code), so treat it like the reports |
| `retry_invalid_output` | `1` | How many times an unusable answer (not JSON, missing keys, empty) is re-asked, naming the problem, before it is booked `invalid`; every re-ask is a real call against `max_model_calls` and shows as "無法使用，已重問 ／ unusable, re-asked" in the "執行來源 ／ Execution Provenance" table. `0` disables; integer 0–5 |
| `max_files` | `50` | Source files analyzed per run; files beyond the cap are listed as an evidence gap (the verdict cannot be `READY_TO_SHIP`). Must be a non-negative integer; `0` / `null` keep the default, a negative or non-integer value fails at startup with `ConfigError` (exit 5) |
| `sandbox_provider` | `"local_subprocess"` | `local_subprocess` (local subprocess, **not a security boundary**) or `docker` (disposable isolated container); anything else fails at startup |
| `docker_image` | `"vibeharness-sandbox:latest"` | Docker sandbox image; must ship `pytest`, `pytest-cov`, and the target's dependencies |
| `docker_network` | `"none"` | Container network mode; `none` blocks all network. Black-box tests against a running service need network access (e.g. `host` on Linux), which reduces isolation |
| `docker_memory` | `"1g"` | Container memory limit |
| `docker_cpus` | `"2"` | Container CPU limit |
| `docker_pids_limit` | `256` | Container process limit |
| `sandbox_memory_mb` | `2048` | `local_subprocess` only: caps the pytest process tree's address space with `RLIMIT_AS` (POSIX; no effect on Windows) and adds a CPU-time cap of the batch budget + 10 s. `0` disables. The Node sandbox sets no `RLIMIT_AS` (V8 would fail to start) and caps the heap with `--max-old-space-size=<value>` instead, keeping the CPU cap. Not a security boundary, just a stop on runaway memory / CPU use; the `docker` provider uses `docker_memory` / `docker_cpus` instead |
| `node_bin` | `"node"` | Node executable (name or path) that runs JS/TS tests; detected the first time one is needed, needs >= 20 (>= 22.6 for `.ts`, type stripping). When it is missing or too old, JS/TS tests are reported as ERROR and as an evidence gap, never as a start-up failure |
| `sandbox_node_provider` | `null` | Sandbox for JS/TS tests: `null` follows `sandbox_provider`; set `local_subprocess` (local Node) or `docker` (Node container, which uses the image's own Node, so the host needs none) on its own. Any other value fails at start-up (exit 5) |
| `docker_node_image` | `"vibeharness-sandbox-node:latest"` | Node container image (`docker/sandbox-node.Dockerfile`, node:22-slim); the container sets `NODE_PATH=/work/<target>/node_modules`, which only CommonJS honours |
| `sandbox_timeout_seconds` | `120` | Total timeout for one batched pytest run; on timeout the whole process tree is killed / the container removed |
| `per_test_timeout_seconds` | `30` | Per-test timeout used when a timed-out batch is re-run test by test |
| `mutation_testing` | `false` | Master switch for mutation testing (off by default); CLI `--mutation` / `--no-mutation` wins over it. Python only, fully offline, no model calls |
| `mutation_max_mutants` | `20` | Mutant cap per run (≥ 1); beyond it the list is truncated and flagged as an evidence gap. CLI `--mutation-max-mutants` overrides |
| `mutation_timeout_seconds` | same as `per_test_timeout_seconds` | Timeout (seconds) of the sandbox batch for one mutant; a timeout counts as killed |
| `mutation_min_score` | `70` | A score (percent, 0–100) below this is an evidence gap; it never causes `NEEDS_FIXES` |

### `execution_mode` behavior

| Value | Behavior |
| :--- | :--- |
| `live` | Real models only. A missing key, a model definition without `api_key_env`, or a failed call raises `LLMGatewayError` immediately (the CLI aborts with exit code 4) |
| `hybrid` (default) | Calls real APIs when keys are present; falls back to the simulation engine on missing keys or failures, disclosed in the report's "執行來源 ／ Execution Provenance" table |
| `mock` | Simulation engine only (offline workflow preview; simulated output is unrelated to the target code, so the quality gate never yields `READY_TO_SHIP`) |

---

## The `models` section

Each **key** is a `model_alias` (referenced by the `agents` section's `model_alias`). Each alias supports:

| Field | Required | Description |
| :--- | :--- | :--- |
| `model` | ✅ | A [litellm model string](https://docs.litellm.ai/docs/providers), e.g. `"claude-sonnet-5-5"`, `"zai/glm-5.3"`, `"gemini/gemini-3.8-flash"`. Prefer versioned ids over moving aliases (e.g. `deepseek/deepseek-v4-pro` rather than `deepseek-chat`) so a provider-side model swap shows up in the report |
| `api_key_env` | Required for live mode | Name of the environment variable holding the API key. The key is passed explicitly to litellm, so providers whose litellm default env var differs from `api_key_env` still authenticate. Without this field, live calls raise `LLMGatewayError` |
| `fallback_model` | Optional | Litellm model string tried **once** after the primary model still fails after `max_retries`; the report records which model was actually used |
| `api_base` | Optional | Custom API endpoint (e.g. a self-hosted OpenAI-compatible gateway at `https://llm-gateway.example.com/v1`, or a local Ollama at `http://localhost:11434`). **Must be `https://`**; plain `http://` is accepted only for loopback hosts (`localhost` / `127.0.0.1` / `::1`); anything else fails at startup with `ConfigError` (exit 5). Target source code is sent to these endpoints, so only allow-listed endpoints are accepted (OWASP LLM04:2026 Supply Chain) |
| `aws_profile_name` / `aws_region_name` | Optional | For models that authenticate through the AWS credential chain (e.g. `bedrock/...`), use these instead of `api_key_env`: the named AWS profile (SSO included) and region; a configured profile counts as live credentials |
| `price_per_million_input` / `price_per_million_output` | Optional | Price per million tokens (USD, non-negative); with both set, `--estimate` prints the model's estimated cost, otherwise tokens only. Never used to control spend (use `max_model_calls`) |
| `extra_params` | Optional | Extra parameters passed verbatim to litellm (a mapping), e.g. `{thinking: {type: disabled}}` or `{reasoning_effort: low}`, so a reasoning model does not spend the whole output budget thinking; anything but a mapping is a `ConfigError` at start-up |
| `max_output_tokens` | Optional | Overrides `global.max_output_tokens`. Reasoning models (GLM, DeepSeek, Gemini 3) count thinking tokens against this limit; too small a value yields empty or cut-off answers, reported as "output truncated at the max_output_tokens limit" |
| `provider` | Optional | **Label only — not read by the code** (routing is determined entirely by the litellm model string) |

Built-in aliases and defaults:

| Alias | model | api_key_env | fallback_model |
| :--- | :--- | :--- | :--- |
| `claude` | `claude-sonnet-5-5` | `ANTHROPIC_API_KEY` | `claude-haiku-4-5-20251001` |
| `glm` | `zai/glm-5.3` (Zhipu AI / Z.AI, litellm `zai/` provider) | `ZAI_API_KEY` | `zai/glm-5.3-flash` |
| `deepseek` | `deepseek/deepseek-v4-pro` | `DEEPSEEK_API_KEY` | `deepseek/deepseek-v4-flash` |
| `gemini` | `gemini/gemini-3.8-flash` | `GEMINI_API_KEY` | `gemini/gemini-3.5-flash` |

> Note: `gemini-2.5-flash` is no longer available to newly issued Google API keys; use a 3.x version.
>
> Data handling: target source code is sent to every provider an agent points at (after invisible Unicode is stripped and hard-coded secrets are redacted to `<REDACTED:kind>`), so only configure providers whose data-retention terms you accept. Each call record in the report carries a `prompt_sha256` (SHA-256 of the system + user prompt), so an audit can tie a verdict to its exact inputs without the report storing the code.

---

## The `agents` section

Each **key** is an `agent_id` and supports:

| Field | Default | Description |
| :--- | :--- | :--- |
| `model_alias` | none (resolves to `unconfigured`) | Points at a `models` alias; **this is the field that actually routes the model**. A missing or unknown alias has no model and no key: `hybrid` simulates that agent, `live` fails with `LLMGatewayError` |
| `temperature` | `0.2` | Sampling temperature (`0.0` recommended for verification/voting agents); must be a number between 0 and 2 (validated at start-up) |
| `name` | — | For `whitebox_reviewer_*`: the reviewer name used in its prompt and in the report ("Identified by ..."); descriptive only for other agents |
| `focus` | — | For `whitebox_reviewer_*`: the review focus, **inserted into the reviewer's prompt** (default "General correctness and security defects") |
| `role` | — | Descriptive only; not read by the code |

### What actually takes effect (important)

- **White-box reviewers are config-driven**: every entry prefixed with `whitebox_reviewer_` is a reviewer, each with its own `name`, `model_alias`, `temperature`, and `focus`; **adding or removing entries changes the ensemble**. Finding ids are prefixed with the first three letters of the model alias (`WB-CLA-01`, `WB-DEE-01`, `WB-GLM-01`, `WB-GEM-01`). Reviewers may return an optional `owasp_mapping` (e.g. `LLM01:2026`, `API1:2023`), shown next to the finding in the report. With no `whitebox_reviewer_*` entries the white-box review is skipped and listed as an evidence gap (the verdict cannot be `READY_TO_SHIP`).
- **Cross-verification is dynamic**: every entry prefixed with `whitebox_verifier_` participates in voting; **adding or removing entries adds/removes that model's vote**. Each finding is voted on only by models that did *not* report it (models never judge their own findings); a defect also reported by another model (recorded during deduplication) counts as one confirm vote.
- The remaining agents (test generator, threat modeler, scenario synthesizer) are invoked with fixed `agent_id`s; the config controls their model and temperature.

### Current agents

| agent_id | Default `model_alias` | `temperature` | Responsibility |
| :--- | :--- | :--- | :--- |
| `whitebox_reviewer_claude` | claude | 0.2 | Logic & State: deep logical edge cases, unhandled exceptions, state inconsistencies, hidden null/type bugs |
| `whitebox_reviewer_deepseek` | deepseek | 0.1 | Safety & Defensive: input sanitization, injection (SQL/command/path), defensive guards, resource exhaustion, unsafe concurrency |
| `whitebox_reviewer_glm` | glm | 0.2 | Specification & Contract: API signature compliance, business-spec adherence, contract violations, authorization checks (BOLA/BFLA) |
| `whitebox_reviewer_gemini` | gemini | 0.2 | AI Integration & Supply Chain: OWASP Top 10 for LLM Applications 2026 (LLM01–LLM10) in code that calls models, plus hard-coded credentials and unpinned dependencies |
| `whitebox_verifier_claude` / `_deepseek` / `_glm` / `_gemini` | their matching models | 0.0 | Vote confirm / reject / unsure on findings reported by other models |
| `whitebox_test_generator` | deepseek | 0.3 | Generates executable pytest tests targeting confirmed defects |
| `blackbox_threat_modeler` | claude | 0.2 | STRIDE, OWASP API and (for AI-integrated targets) OWASP LLM threat modeling |
| `blackbox_test_synthesizer` | deepseek | 0.2 | Turns threat scenarios into black-box attack scripts (BOLA, injection, rate limiting, prompt injection) |

---

## Common configuration examples

### Only one API key (point everything at a single model)

With only a Gemini key, change every `model_alias` in the `agents` section to `gemini` to run live mode:

```yaml
agents:
  whitebox_reviewer_claude:
    model_alias: "gemini"      # was claude
  whitebox_reviewer_deepseek:
    model_alias: "gemini"      # was deepseek
  whitebox_reviewer_glm:
    model_alias: "gemini"      # was deepseek
  whitebox_reviewer_gemini:
    model_alias: "gemini"      # already gemini
  whitebox_verifier_claude:
    model_alias: "gemini"
  whitebox_verifier_deepseek:
    model_alias: "gemini"
  whitebox_verifier_glm:
    model_alias: "gemini"
  whitebox_verifier_gemini:
    model_alias: "gemini"
  whitebox_test_generator:
    model_alias: "gemini"      # was deepseek
  blackbox_threat_modeler:
    model_alias: "gemini"      # was claude
  blackbox_test_synthesizer:
    model_alias: "gemini"      # was deepseek
```

> Note: with a single model family, **cross-model verification cannot run**: every finding comes from `gemini`, and verifiers never rule on their own model's findings, so no finding gets a vote (none are filtered, and the agreement ratio shows N/A). The console warns "Fewer than two distinct reviewer models" and the run records an evidence gap (the verdict cannot be `READY_TO_SHIP`). The four reviewers still contribute their different `focus` areas, but agreement among copies of one model is consistency, not corroboration (OWASP LLM07:2026).

### Switch to the Docker sandbox

```yaml
global:
  sandbox_provider: "docker"
  docker_image: "vibeharness-sandbox:latest"   # requires docker build -t ... -f docker/sandbox.Dockerfile . first
  docker_node_image: "vibeharness-sandbox-node:latest"   # when the target has JS/TS: docker build -t ... -f docker/sandbox-node.Dockerfile .
  docker_network: "none"                        # use "host" (Linux) for black-box tests against a running service
  docker_memory: "1g"
  docker_cpus: "2"
  docker_pids_limit: 256
```

### Add a custom model and assign it to an agent

```yaml
models:
  my_model:
    model: "openai/qwen2.5-72b-instruct"   # any litellm-supported string (here: an OpenAI-compatible endpoint)
    api_key_env: "MY_API_KEY"
    api_base: "https://llm-gateway.example.com/v1"   # must be https (http only for localhost)
    fallback_model: "openai/qwen2.5-32b-instruct"   # uses the same api_key_env and api_base

agents:
  whitebox_reviewer_claude:
    model_alias: "my_model"
```

### Add a fifth reviewer

Any new `whitebox_reviewer_*` entry joins the ensemble; its `focus` goes straight into its prompt. Add a matching `whitebox_verifier_*` entry if that model should also vote on the other reviewers' findings:

```yaml
agents:
  whitebox_reviewer_local:
    name: "Concurrency Reviewer (local Qwen)"
    model_alias: "my_model"
    temperature: 0.1
    focus: "Race conditions, lock ordering, async cancellation and shared mutable state"
  whitebox_verifier_local:
    model_alias: "my_model"
    temperature: 0.0
```

An agent without `model_alias`, or whose `model_alias` names an alias missing from `models`, resolves to `unconfigured` (no model, no key): `hybrid` runs it on the simulation engine and discloses that in the report, `live` fails loudly with `LLMGatewayError` (exit 4). It is never silently routed to some other provider — double-check alias spelling.

---

## Related: `vibeharness/config/threat_rules.yaml`

The threat modeler reads a few fields of `vibeharness/config/threat_rules.yaml` as prompt guidance; everything else in that file (`code`, `target_components`, `cwe`, `atlas_tactics`, ...) is documentation and has no runtime effect.

| Section | Fields the code reads | When it is used |
| :--- | :--- | :--- |
| `stride_categories.<key>` | `name` / `common_vibe_bugs` | Always (`description` is documentation only; it is not sent in the prompt) |
| `owasp_api_top10[*]` | `id` / `name` | Always; ids are suggested for `owasp_mapping` |
| `owasp_llm_top10_2026[*]` | `id` / `name` / `common_vibe_bugs` / `atlas_techniques` | Only when the target imports an AI/LLM SDK (`openai`, `anthropic`, `litellm`, `langchain`, `transformers`, `@ai-sdk/*`, ...), detected deterministically and listed as `ai_components` in the report |

`owasp_llm_top10_2026` lists LLM01:2026 to LLM10:2026 of the OWASP Top 10 for LLM Applications 2026. The threat modeler is told to use those ids for `owasp_mapping` and the listed MITRE ATLAS technique ids for `atlas_mapping` (shown in the report's MITRE ATLAS column). `cwe` and `atlas_tactics` follow the 2026 document's Appendix A mapping tables (ATLAS content v2026.06, tactic level); `atlas_techniques` is the harness's own technique-level mapping, checked against ATLAS content release 2026.07.
