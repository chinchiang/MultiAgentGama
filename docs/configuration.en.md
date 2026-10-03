# Configuration Reference (agents_config.yaml)

English (US) ｜ [正體中文（臺灣）](configuration.md)

This document covers every field in `config/agents_config.yaml`: semantics, defaults, and what actually takes effect (as implemented).

The file has three top-level sections: **`global`** (execution and sandbox parameters), **`models`** (provider definitions), and **`agents`** (per-agent model routing). A missing config file fails loudly (`FileNotFoundError`); the harness never runs on an empty configuration.

From the CLI, use `--config <path>` to point at a different file and `--mode` to override `execution_mode` (precedence: CLI `--mode` > `global.execution_mode` > default `hybrid`).

---

## The `global` section

| Field | Default | Description |
| :--- | :--- | :--- |
| `execution_mode` | `"hybrid"` | One of `live` / `hybrid` / `mock` (see table below); anything else fails at startup |
| `timeout_seconds` | `60` | Per-LLM-request timeout in seconds, passed to litellm |
| `max_retries` | `2` | Retry count at the litellm level (retries the same primary model; the `fallback_model` is tried once only after all retries fail) |
| `max_output_tokens` | `4096` | Token cap per model response |
| `sandbox_provider` | `"local_subprocess"` | `local_subprocess` (local subprocess, **not a security boundary**) or `docker` (disposable isolated container); anything else fails at startup |
| `docker_image` | `"vibeharness-sandbox:latest"` | Docker sandbox image; must ship `pytest`, `pytest-cov`, and the target's dependencies |
| `docker_network` | `"none"` | Container network mode; `none` blocks all network. Black-box tests against a running service need network access (e.g. `host` on Linux), which reduces isolation |
| `docker_memory` | `"1g"` | Container memory limit |
| `docker_cpus` | `"2"` | Container CPU limit |
| `docker_pids_limit` | `256` | Container process limit |
| `sandbox_timeout_seconds` | `120` | Total timeout for one batched pytest run; on timeout the whole process tree is killed / the container removed |
| `per_test_timeout_seconds` | `30` | Per-test timeout used when a timed-out batch is re-run test by test |

### `execution_mode` behavior

| Value | Behavior |
| :--- | :--- |
| `live` | Real models only. A missing key, a model definition without `api_key_env`, or a failed call raises `LLMGatewayError` immediately (the CLI aborts with exit code 4) |
| `hybrid` (default) | Calls real APIs when keys are present; falls back to the simulation engine on missing keys or failures, disclosed in the report's Execution Provenance |
| `mock` | Simulation engine only (offline workflow preview; simulated output is unrelated to the target code, so the quality gate never yields `READY_TO_SHIP`) |

---

## The `models` section

Each **key** is a `model_alias` (referenced by the `agents` section's `model_alias`). Each alias supports:

| Field | Required | Description |
| :--- | :--- | :--- |
| `model` | ✅ | A [litellm model string](https://docs.litellm.ai/docs/providers), e.g. `"claude-sonnet-5"`, `"nvidia_nim/nvidia/nemotron-4-340b-instruct"`, `"gemini/gemini-3.8-flash"` |
| `api_key_env` | Required for live mode | Name of the environment variable holding the API key. The key is passed explicitly to litellm, so providers whose litellm default env var differs (e.g. NVIDIA NIM) still authenticate. Without this field, live calls raise `LLMGatewayError` |
| `fallback_model` | Optional | Litellm model string tried **once** after the primary model still fails after `max_retries`; the report records which model was actually used |
| `api_base` | Optional | Custom API endpoint (e.g. NVIDIA NIM's `https://integrate.api.nvidia.com/v1`) |
| `provider` | Optional | **Label only — not read by the code** (routing is determined entirely by the litellm model string) |

Built-in aliases and defaults:

| Alias | model | api_key_env | fallback_model |
| :--- | :--- | :--- | :--- |
| `claude` | `claude-sonnet-5` | `ANTHROPIC_API_KEY` | `claude-haiku-4-5-20251001` |
| `nemotron` | `nvidia_nim/nvidia/nemotron-4-340b-instruct` | `NVIDIA_API_KEY` | `nvidia_nim/meta/llama-3.3-70b-instruct` |
| `chatgpt` | `gpt-4o` | `OPENAI_API_KEY` | `gpt-4o-mini` |
| `gemini` | `gemini/gemini-3.8-flash` | `GEMINI_API_KEY` | `gemini/gemini-3.5-flash` |

> Note: `gemini-2.5-flash` is no longer available to newly issued Google API keys; use a 3.x version.

---

## The `agents` section

Each **key** is an `agent_id` and supports:

| Field | Default | Description |
| :--- | :--- | :--- |
| `model_alias` | `"chatgpt"` | Points at a `models` alias; **this is the field that actually routes the model** |
| `temperature` | `0.2` | Sampling temperature (`0.0` recommended for verification/voting agents) |
| `name` | — | Descriptive only; not read by the code (agent names inside prompts are hardcoded) |
| `role` / `focus` | — | Descriptive only; not read by the code (reviewer focus areas are hardcoded) |

### What actually takes effect (important)

- **The white-box reviewer roster is fixed at three** (`whitebox_reviewer_claude`, `whitebox_reviewer_nemotron`, `whitebox_reviewer_chatgpt`): the config can reassign their `model_alias` and `temperature`, but reviewers cannot be added or removed via config.
- **Cross-verification is dynamic**: every entry prefixed with `whitebox_verifier_` participates in voting; **adding or removing entries adds/removes that model's vote**. Each finding is voted on only by models that did *not* report it (models never judge their own findings); a defect also reported by another model (recorded during deduplication) counts as one confirm vote.
- The remaining agents (test generator, threat modeler, scenario synthesizer) are invoked with fixed `agent_id`s; the config controls their model and temperature.

### Current agents

| agent_id | Default `model_alias` | `temperature` | Responsibility |
| :--- | :--- | :--- | :--- |
| `whitebox_reviewer_claude` | claude | 0.2 | Deep logical edge cases, unhandled exceptions, state inconsistencies |
| `whitebox_reviewer_nemotron` | nemotron | 0.1 | Input sanitization, resource limits, memory-safety guardrails |
| `whitebox_reviewer_chatgpt` | chatgpt | 0.2 | API contract adherence, specification consistency, test-case synthesis |
| `whitebox_verifier_claude` / `_nemotron` / `_chatgpt` | their matching models | 0.0 | Vote confirm / reject / unsure on findings reported by other models |
| `whitebox_test_generator` | chatgpt | 0.3 | Generates executable pytest tests targeting confirmed defects |
| `blackbox_threat_modeler` | claude | 0.2 | STRIDE and OWASP threat modeling |
| `blackbox_test_synthesizer` | chatgpt | 0.2 | Turns threat scenarios into black-box attack scripts (BOLA, injection, rate limiting) |

---

## Common configuration examples

### Only one API key (point everything at a single model)

With only a Gemini key, change every `model_alias` in the `agents` section to `gemini` to run live mode:

```yaml
agents:
  whitebox_reviewer_claude:
    model_alias: "gemini"      # was claude
  whitebox_reviewer_nemotron:
    model_alias: "gemini"      # was nemotron
  whitebox_reviewer_chatgpt:
    model_alias: "gemini"      # was chatgpt -> change to gemini
  whitebox_verifier_claude:
    model_alias: "gemini"
  whitebox_verifier_nemotron:
    model_alias: "gemini"
  whitebox_verifier_chatgpt:
    model_alias: "gemini"
  whitebox_test_generator:
    model_alias: "gemini"
  blackbox_threat_modeler:
    model_alias: "gemini"
  blackbox_test_synthesizer:
    model_alias: "gemini"
```

> Note: when every agent points at the same model, "multi-model de-biasing" and "cross-model verification" lose their independence (the same model reviews and verifies its own findings); interpret the report's agreement ratio accordingly.

### Switch to the Docker sandbox

```yaml
global:
  sandbox_provider: "docker"
  docker_image: "vibeharness-sandbox:latest"   # requires docker build -t ... -f docker/sandbox.Dockerfile . first
  docker_network: "none"                        # use "host" (Linux) for black-box tests against a running service
  docker_memory: "1g"
  docker_cpus: "2"
  docker_pids_limit: 256
```

### Add a custom model and assign it to an agent

```yaml
models:
  my_model:
    model: "openai/qwen2.5-72b-instruct"   # any litellm-supported string
    api_key_env: "MY_API_KEY"
    api_base: "https://my-endpoint.example.com/v1"
    fallback_model: "openai/gpt-4o-mini"

agents:
  whitebox_reviewer_claude:
    model_alias: "my_model"
```

If a `model_alias` points at an unknown alias, that agent silently falls back to the default model (`gpt-4o`) and default temperature (`0.2`), and live mode then fails on the missing key — double-check alias spelling.
