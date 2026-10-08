import hashlib
import os
import json
import logging
import re
import threading
import urllib.parse
from typing import Dict, Any, Optional, List
import yaml

from core.models import AgentCallRecord
from core.sanitize import clean_model_text, redact_secrets

try:
    import litellm
except ImportError:  # pragma: no cover - litellm is an optional runtime dependency
    litellm = None  # type: ignore[assignment]

logger = logging.getLogger("VibeHarness.LLMGateway")

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "agents_config.yaml"
)

# Key added to every response so callers can tell simulated output from real model output
PROVENANCE_KEY = "_provenance"

DEFAULT_MAX_CONCURRENT_CALLS = 6
# A cap, not a spend: threat-model JSON and reasoning models' thinking tokens both overflowed 4096 in live runs
DEFAULT_MAX_OUTPUT_TOKENS = 16384


BUDGET_EXHAUSTED_REASON = "max_model_calls budget exhausted"

# Agents missing from the config resolve to this alias, which has no model and no key: hybrid mode
# simulates them and live mode fails loudly, instead of silently routing them to some real provider
UNCONFIGURED_ALIAS = "unconfigured"

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class LLMGatewayError(RuntimeError):
    """Raised in strict 'live' mode when a real model invocation is impossible or fails."""


class ConfigError(ValueError):
    """Raised when the agent configuration file is missing or unparseable.

    Subclasses ValueError so code (and tests) that guard against bad config values keeps working.
    main.py maps this to a dedicated 'harness misconfigured' exit code so it can never be
    mistaken for a NEEDS_FIXES verdict about the audited target.
    """


class LLMGateway:
    """
    Unified gateway for orchestrating calls to heterogeneous LLMs (by default Claude, GLM, DeepSeek and Gemini).
    Execution modes:
    - live:   real API calls only; any missing key or failure raises LLMGatewayError.
    - hybrid: real API calls when possible, otherwise the offline simulation engine (recorded as simulated).
    - mock:   simulation engine only.
    Every call is recorded in `call_log` so reports can disclose which results are simulated.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH, execution_mode: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.execution_mode = execution_mode or self.config.get("global", {}).get("execution_mode", "hybrid")
        if self.execution_mode not in ("live", "hybrid", "mock"):
            raise ValueError(f"Unknown execution_mode '{self.execution_mode}' (expected live, hybrid or mock)")
        self.models_config = self.config.get("models") or {}
        self.agents_config = self.config.get("agents") or {}
        self.call_log: List[AgentCallRecord] = []
        global_cfg = self.config.get("global") or {}
        # Cost guard: live model invocations allowed per run (litellm retries / fallback_model of one
        # invocation are not counted separately). None or 0 means unlimited.
        self.max_model_calls = self._positive_int(global_cfg.get("max_model_calls"), "max_model_calls")
        # Agents fan their calls out on a thread pool of at most this many workers
        self.max_concurrent_calls = self._positive_int(
            global_cfg.get("max_concurrent_calls", DEFAULT_MAX_CONCURRENT_CALLS), "max_concurrent_calls"
        ) or DEFAULT_MAX_CONCURRENT_CALLS
        self.live_calls_attempted = 0
        self._budget_lock = threading.Lock()
        self._validate_endpoints()
        self._validate_settings()

    def _validate_endpoints(self) -> None:
        """Every custom api_base must be https (plain http only to loopback): target source code and
        prompts travel to these endpoints, so a typo or a hostile config must not send them in clear
        text to an arbitrary host (OWASP LLM04:2026; allow-listed model endpoints)."""
        for alias, info in self.models_config.items():
            base = info.get("api_base") if isinstance(info, dict) else None
            if not base:
                continue
            try:
                parts = urllib.parse.urlsplit(str(base))
                host = (parts.hostname or "").lower()
            except ValueError as e:
                raise ConfigError(f"models.{alias}.api_base is not a valid URL: {base!r}") from e
            if parts.scheme == "https" and host:
                continue
            if parts.scheme == "http" and host in _LOOPBACK_HOSTS:
                continue
            raise ConfigError(
                f"models.{alias}.api_base must be an https:// URL (http:// only for loopback hosts), got {base!r}"
            )

    def _validate_settings(self) -> None:
        """Numeric settings are checked once at start-up. They used to be read only when a call was
        made, so a typo such as `timeout_seconds: "abc"` reached litellm, failed there, and in hybrid
        mode was booked as "live invocation failed" and silently replaced by the simulation engine."""
        global_cfg = self.config.get("global") or {}
        self._number(global_cfg.get("timeout_seconds", 180), "global.timeout_seconds", minimum=1)
        self._number(global_cfg.get("max_retries", 2), "global.max_retries", minimum=0, integer=True)
        self._number(global_cfg.get("max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS), "global.max_output_tokens",
                     minimum=1, integer=True)
        for alias, info in self.models_config.items():
            if isinstance(info, dict) and info.get("max_output_tokens") is not None:
                self._number(info["max_output_tokens"], f"models.{alias}.max_output_tokens", minimum=1, integer=True)
        for agent_id, meta in self.agents_config.items():
            if isinstance(meta, dict) and meta.get("temperature") is not None:
                self._number(meta["temperature"], f"agents.{agent_id}.temperature", minimum=0, maximum=2)

    @staticmethod
    def _number(value: Any, key: str, minimum: float, maximum: Optional[float] = None, integer: bool = False) -> None:
        ok = isinstance(value, (int, float)) and not isinstance(value, bool) and (not integer or isinstance(value, int))
        if not ok or value < minimum or (maximum is not None and value > maximum):
            kind = "an integer" if integer else "a number"
            bounds = f">= {minimum}" if maximum is None else f"between {minimum} and {maximum}"
            raise ConfigError(f"{key} must be {kind} {bounds}, got {value!r}")

    @staticmethod
    def _safe_reason(text: str) -> str:
        """Provider error text as it may be logged or reported: credentials redacted (an HTTP client
        can echo a request URL or header carrying the API key), control characters removed."""
        return clean_model_text(redact_secrets(str(text)))

    @staticmethod
    def _positive_int(value: Any, key: str) -> Optional[int]:
        """An optional positive integer setting; None/0 mean "not set"."""
        if value is None or value == 0:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ConfigError(f"global.{key} must be a non-negative integer, got {value!r}")
        return value

    def _reserve_live_call(self) -> bool:
        """Claims one live invocation from the budget (thread-safe); False when it is exhausted."""
        with self._budget_lock:
            if self.max_model_calls is not None and self.live_calls_attempted >= self.max_model_calls:
                return False
            self.live_calls_attempted += 1
            return True

    @property
    def budget_exhausted_calls(self) -> List[AgentCallRecord]:
        return [rec for rec in self.call_log if rec.reason == BUDGET_EXHAUSTED_REASON]

    @property
    def used_simulation(self) -> bool:
        return any(rec.mode == "simulated" for rec in self.call_log)

    @property
    def invalid_calls(self) -> List[AgentCallRecord]:
        return [rec for rec in self.call_log if rec.mode == "invalid"]

    @staticmethod
    def is_simulated(resp: Dict[str, Any]) -> bool:
        return resp.get(PROVENANCE_KEY, {}).get("mode") == "simulated"

    @staticmethod
    def is_usable(resp: Dict[str, Any]) -> bool:
        """False when the model answered but its output could not be used."""
        return resp.get(PROVENANCE_KEY, {}).get("mode") != "invalid"

    def _load_config(self, path: str) -> Dict[str, Any]:
        # A missing or unparseable config would silently drop every model/agent mapping, so
        # fail loudly with ConfigError instead of leaking raw FileNotFoundError/YAMLError
        if not os.path.exists(path):
            raise ConfigError(f"Agent config not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Agent config is not valid YAML ({path}): {e}") from e

    def is_live_configured(self, model_alias: str) -> bool:
        """Checks whether the requested model has credentials: its API key, or an AWS profile
        (Bedrock authenticates through the AWS credential chain, not an API key)."""
        model_info = self.models_config.get(model_alias, {})
        if model_info.get("aws_profile_name"):
            return True
        env_var = model_info.get("api_key_env")
        return bool(env_var and os.getenv(env_var))

    def generate(
        self,
        agent_id: str,
        system_prompt: str,
        user_prompt: str,
        json_output: bool = True,
        required_keys: Optional[List[str]] = None,
        required_keys_any: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes a prompt targeting the designated agent's configured LLM.
        A live response that is not valid JSON or lacks any of `required_keys` (all must be
        present) or `required_keys_any` (at least one must be present) is recorded with
        mode "invalid" (and returned as {}), so callers and the quality gate never mistake an
        unusable answer for a genuine empty result.
        """
        agent_meta = self.agents_config.get(agent_id) or {}
        model_alias = agent_meta.get("model_alias") or UNCONFIGURED_ALIAS
        temperature = agent_meta.get("temperature", 0.2)
        model_info = self.models_config.get(model_alias) or {}
        model_name = model_info.get("model") or f"(no model configured for alias '{model_alias}')"
        prompt_hash = hashlib.sha256(f"{system_prompt}\x00{user_prompt}".encode("utf-8")).hexdigest()

        # Decide whether to invoke live API or mock engine
        fallback_reason: Optional[str] = None
        if self.execution_mode == "mock":
            fallback_reason = "execution_mode is 'mock'"
        elif litellm is None:
            fallback_reason = "litellm is not installed"
        elif not self.is_live_configured(model_alias):
            env_var = model_info.get("api_key_env") or "<no api_key_env configured>"
            fallback_reason = f"API key env var {env_var} is not set"
        elif not self._reserve_live_call():
            fallback_reason = BUDGET_EXHAUSTED_REASON

        if fallback_reason is None:
            logger.info(f"Dispatching [{agent_id}] to Live LLM: {model_name} (Alias: {model_alias})")
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
            try:
                raw_text, model_name, finish_reason = self._complete(model_info, model_name, messages, temperature)
            except Exception as e:
                fallback_reason = f"live invocation failed: {self._safe_reason(str(e))}"
                if self.execution_mode == "live":
                    raise LLMGatewayError(f"[{agent_id}] {model_name}: {fallback_reason}") from e
                logger.warning(f"Live invocation failed for {agent_id} ({model_name}): {fallback_reason}. Falling back to simulation logic.")
            else:
                # Only the network call is guarded above: a bug in parsing/validation/booking
                # must fail loudly instead of being masked as a fallback to simulation.
                result = self._clean_and_parse_json(raw_text) if json_output else {"raw": raw_text}
                problem = self._validate_output(result, json_output, required_keys, required_keys_any)
                if problem is None and result is not None:
                    self._record(agent_id, model_alias, model_name, "live", prompt_sha256=prompt_hash)
                    result[PROVENANCE_KEY] = {"mode": "live", "model": model_name}
                    return result
                reason = problem or "response is not valid JSON"
                if not raw_text.strip():
                    # e.g. a provider safety filter blocking attack-test code; the finish reason says which
                    reason = f"model returned an empty response (finish_reason: {finish_reason or 'unknown'})"
                if finish_reason == "length":
                    # Reasoning models spend part of the budget thinking; say so instead of blaming the format
                    reason = (
                        f"output truncated at the max_output_tokens limit ({self._max_output_tokens(model_info)}); "
                        f"{reason}. Raise max_output_tokens for this model (reasoning tokens count against it)"
                    )
                logger.error(f"[{agent_id}] {model_name} returned unusable output: {reason}")
                self._record(agent_id, model_alias, model_name, "invalid", reason, prompt_sha256=prompt_hash)
                return {PROVENANCE_KEY: {"mode": "invalid", "model": model_name, "reason": reason}}
        elif self.execution_mode == "live":
            raise LLMGatewayError(f"[{agent_id}] cannot run live with {model_name}: {fallback_reason}")

        # Offline / Mock Fallback
        logger.info(f"Dispatching [{agent_id}] to Simulation Engine (Model Alias: {model_alias}; reason: {fallback_reason})")
        self._record(agent_id, model_alias, model_name, "simulated", fallback_reason, prompt_sha256=prompt_hash)
        result = self._generate_simulated_response(agent_id, model_alias, user_prompt)
        result[PROVENANCE_KEY] = {"mode": "simulated", "model": model_name, "reason": fallback_reason}
        return result

    def _complete(self, model_info: Dict[str, Any], model_name: str, messages: List[Dict[str, str]], temperature: float):
        """
        Calls the primary model (with litellm's own retries), then `fallback_model` once if the primary fails.
        The API key is passed explicitly, so providers whose litellm default env var differs from
        `api_key_env` (e.g. Z.AI for GLM) still authenticate.
        Returns (text, model_actually_used, finish_reason); finish_reason "length" means the token limit cut it off.
        """
        global_cfg = self.config.get("global") or {}
        env_var = model_info.get("api_key_env")
        aws_profile = model_info.get("aws_profile_name")
        if not env_var and not aws_profile:
            # Fail with an actionable message instead of a KeyError from the config lookup below
            raise LLMGatewayError(
                f"Model '{model_name}' has no 'api_key_env' (or 'aws_profile_name' for Bedrock) configured; "
                "set it in the models section of the agents config to make live calls."
            )
        kwargs: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            # Newer models reject sampling knobs (Claude Opus 5.5 on Bedrock accepts only temperature=1;
            # Gemini 3 is deprecating them): drop what a model does not support rather than failing the call
            "drop_params": True,
            "timeout": global_cfg.get("timeout_seconds", 180),
            "num_retries": global_cfg.get("max_retries", 2),
            "max_tokens": self._max_output_tokens(model_info),
        }
        if env_var:
            kwargs["api_key"] = os.getenv(env_var)
        if aws_profile:
            kwargs["aws_profile_name"] = aws_profile
            if model_info.get("aws_region_name"):
                kwargs["aws_region_name"] = model_info["aws_region_name"]
        if model_info.get("api_base"):
            kwargs["api_base"] = model_info["api_base"]

        candidates = [model_name] + ([model_info["fallback_model"]] if model_info.get("fallback_model") else [])
        last_error: Optional[Exception] = None
        for candidate in candidates:
            try:
                response = litellm.completion(model=candidate, **kwargs)
                choice = response.choices[0]
                finish_reason = getattr(choice, "finish_reason", None)
                return choice.message.content or "", candidate, finish_reason if isinstance(finish_reason, str) else None
            except Exception as e:
                last_error = e
                logger.warning(f"Model {candidate} failed: {self._safe_reason(str(e))}")
        if last_error is None:
            # Unreachable in practice: candidates is never empty, but never raise an Optional
            raise LLMGatewayError(f"Model {model_name}: no candidate model could be attempted")
        raise last_error

    def _max_output_tokens(self, model_info: Dict[str, Any]) -> int:
        """Per-model `max_output_tokens` overrides the global one: reasoning models (GLM, DeepSeek,
        Gemini 3) count thinking tokens against this limit and need a larger budget."""
        value = model_info.get("max_output_tokens") or (self.config.get("global") or {}).get(
            "max_output_tokens", DEFAULT_MAX_OUTPUT_TOKENS
        )
        return int(value)

    @staticmethod
    def _validate_output(
        result: Any, json_output: bool,
        required_keys: Optional[List[str]], required_keys_any: Optional[List[str]] = None
    ) -> Optional[str]:
        if not json_output:
            return None
        if result is None:
            return "response is not valid JSON"
        if not isinstance(result, dict):
            return f"expected a JSON object, got {type(result).__name__}"
        missing = [k for k in (required_keys or []) if k not in result]
        if missing:
            return f"response is missing required key(s): {', '.join(missing)}"
        if required_keys_any and not any(k in result for k in required_keys_any):
            return f"response has none of the expected key(s): {', '.join(required_keys_any)}"
        return None

    def record_failure(self, agent_id: str, reason: str) -> None:
        """Books an agent call that crashed before the gateway could answer (e.g. an exception in
        the caller's thread-pool batch). Recorded as an `invalid` call so the quality gate sees the
        missing result as an evidence gap instead of mistaking silence for "nothing found"."""
        agent_meta = self.agents_config.get(agent_id) or {}
        model_alias = agent_meta.get("model_alias") or UNCONFIGURED_ALIAS
        model_info = self.models_config.get(model_alias) or {}
        model_name = model_info.get("model") or f"(no model configured for alias '{model_alias}')"
        self._record(agent_id, model_alias, model_name, "invalid", f"agent call crashed before producing output: {reason}")

    def _record(
        self, agent_id: str, model_alias: str, model_name: str, mode: str,
        reason: Optional[str] = None, prompt_sha256: Optional[str] = None
    ):
        self.call_log.append(AgentCallRecord(
            agent_id=agent_id, model_alias=model_alias, model_name=model_name, mode=mode,
            reason=self._safe_reason(reason) if reason is not None else None,
            prompt_sha256=prompt_sha256
        ))

    def _clean_and_parse_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Strips markdown code fences and parses JSON safely, with conversational fallback."""
        text = text.strip()
        # 1. Closed markdown code fence (```json ... ``` or ```JSON / ```)
        match = re.search(r"```[\w-]*\s*([\s\S]*?)\s*```", text)
        if match:
            candidate = match.group(1).strip()
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        # 2. Direct JSON string
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        # 3. Unclosed code fence (starts with ```tag but missing closing ```)
        unclosed_match = re.match(r"^\s*```[\w-]*\s*([\s\S]*)$", text)
        if unclosed_match:
            candidate = re.sub(r"```+\s*$", "", unclosed_match.group(1)).strip()
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        # 4. Conversational wrapping fallback: extract substring between first '{' and last '}'
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            candidate = text[first_brace:last_brace + 1]
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                # If first-to-last failed (e.g. earlier unclosed non-JSON brace), search each '{' to last '}'
                for m in re.finditer(r"\{", text):
                    start = m.start()
                    if start == first_brace or start >= last_brace:
                        continue
                    try:
                        parsed = json.loads(text[start:last_brace + 1])
                        if isinstance(parsed, dict):
                            return parsed
                    except json.JSONDecodeError:
                        continue

        logger.error(f"JSON parsing error: could not extract valid JSON. Raw content: {text[:200]}")
        # None (not a sentinel dict): a model could legitimately echo such a dict, which would
        # have been indistinguishable from a parse failure.
        return None

    def _generate_simulated_response(self, agent_id: str, model_alias: str, prompt: str) -> Dict[str, Any]:
        """
        High-fidelity domain-specific fallback logic reflecting each reviewer's focus:
        - Claude: state transitions, missing null checks, edge-case logic.
        - DeepSeek: boundary limits, input sanitization, defensive guards.
        - GLM: contract specifications, API compliance, parameter validation.
        - Gemini: AI/LLM integration (OWASP Top 10 for LLM Applications 2026).
        Reviewer templates are chosen by model alias, falling back to the agent id's suffix.
        NOTE: responses are fixed templates independent of the target code; they exist so the
        pipeline can be exercised offline and are always flagged as simulated in reports.
        """
        if "reviewer_" in agent_id:
            template = _SIMULATED_REVIEWS.get(model_alias) or _SIMULATED_REVIEWS.get(agent_id.rsplit("_", 1)[-1])
            return {"findings": [dict(template)] if template else []}

        if "verifier" in agent_id:
            # A template cannot judge target-specific findings; the debater ignores simulated verdicts
            return {"verdicts": []}

        elif "threat_modeler" in agent_id:
            return {
                "system_description": "Vibe-coded web application and API service.",
                "entrypoints": ["REST API routes", "Auth headers", "User registration / management endpoints"],
                "trust_boundaries": ["Client / Internet to Public Gateway", "Public Gateway to Internal DB"],
                "assets": ["User credentials", "Customer data records", "Database connection strings"],
                "threats": [
                    {
                        "threat_id": "THREAT-01",
                        "stride_category": "Elevation of Privilege",
                        "owasp_mapping": "API1:2023 - Broken Object Level Authorization (BOLA)",
                        "title": "BOLA / IDOR on Resource Updates",
                        "description": "An authenticated user can modify other users' objects by simply tampering with the object ID in the URL path or payload.",
                        "asset_at_risk": "User accounts & private records",
                        "attack_vector": "HTTP PUT/PATCH /api/users/{foreign_id}",
                        "trust_boundary_crossed": "User A boundary into User B data domain",
                        "severity": "CRITICAL",
                        "attack_scenario": "Login as User A, issue a PUT request targeting User B's resource ID.",
                        "test_verification_goal": "Ensure status code is 403 Forbidden or 404 Not Found, never 200 OK."
                    },
                    {
                        "threat_id": "THREAT-02",
                        "stride_category": "Tampering",
                        "owasp_mapping": "API3:2023 - Broken Object Property Level Authorization",
                        "title": "Mass Assignment of Admin / Sensitive Fields",
                        "description": "The update endpoint accepts raw JSON body and applies it to the DB model without a strict whitelist, allowing users to inject is_admin=true.",
                        "asset_at_risk": "System authorization integrity",
                        "attack_vector": "HTTP POST/PUT with extra 'is_admin': true in payload",
                        "trust_boundary_crossed": "Unprivileged client to privileged role",
                        "severity": "HIGH",
                        "attack_scenario": "Send payload {'name': 'test', 'is_admin': true} during profile update.",
                        "test_verification_goal": "Ensure is_admin remains false and cannot be altered through public endpoint."
                    },
                    {
                        "threat_id": "THREAT-03",
                        "stride_category": "Information Disclosure",
                        "owasp_mapping": "API8:2023 - Security Misconfiguration",
                        "title": "Stack Trace & Database Error Leakage on Malformed Input",
                        "description": "Sending invalid JSON or syntax characters causes unhandled 500 error leaking internal database details and file paths.",
                        "asset_at_risk": "Internal system architecture details",
                        "attack_vector": "HTTP POST with malformed syntax / SQL injection characters",
                        "trust_boundary_crossed": "Internal error logs to external HTTP response",
                        "severity": "MEDIUM",
                        "attack_scenario": "Send malformed payload and inspect HTTP response body for tracebacks.",
                        "test_verification_goal": "Ensure response contains generic error message without file paths or SQL keywords."
                    }
                ]
            }

        elif "test_synthesizer" in agent_id or "test_generator" in agent_id:
            # The simulation engine cannot write target-specific tests; callers fall back to
            # deterministic, target-derived probes (whitebox) or mark the threat as untested (blackbox).
            return {"tests": []}

        return {"status": "ok", "message": f"Simulated output for {agent_id}"}


# Fixed offline review templates per model alias (see LLMGateway._generate_simulated_response)
_SIMULATED_REVIEWS: Dict[str, Dict[str, str]] = {
    "claude": {
        "severity": "HIGH",
        "title": "Unchecked Null / Implicit State Assumption in Handler",
        "description": "The vibe-coded logic assumes entities exist and state transitions are valid without verifying database fetch outcomes, leading to unhandled NoneType / NullPointer exceptions.",
        "root_cause": "Absence of defensive null-check before property traversal.",
        "suspected_vibe_flaw": "Vibe coding commonly assumes the 'happy path' where records are always found.",
        "suggested_test_scenario": "Invoke the endpoint/function with a non-existent ID or empty payload and assert proper error status (404/400) instead of a 500 crash.",
    },
    "deepseek": {
        "severity": "CRITICAL",
        "title": "Missing Input Sanitization & Unbounded Resource Allocation",
        "description": "The logic lacks input length and numerical range clamping on queries or data arrays, allowing memory exhaustion and ReDoS or unvalidated bulk payloads.",
        "root_cause": "Directly feeding untrusted input into downstream iteration and memory structures.",
        "suspected_vibe_flaw": "AI coding assistants frequently skip explicit size checks and pagination limits.",
        "suggested_test_scenario": "Supply a 10MB payload or integer values exceeding 1,000,000 and verify graceful rejection with HTTP 413 or 422.",
    },
    "glm": {
        "severity": "MEDIUM",
        "title": "API Contract Specification Drift & Schema Inconsistency",
        "description": "Missing parameter type enforcement and inconsistency between expected response schema and actual serialized dictionary fields.",
        "root_cause": "Implicit schema casting without strict Pydantic/dataclass schema validation.",
        "suspected_vibe_flaw": "Quick prototyping in vibe coding often changes response structures on the fly without updating contract definitions.",
        "suggested_test_scenario": "Assert response schema matches the expected OpenAPI/JSON contract exactly across all field types.",
    },
    "gemini": {
        "severity": "HIGH",
        "title": "Untrusted Input Reaches the Prompt and Model Output Is Used Unvalidated",
        "description": "User-controlled or retrieved text is concatenated into model prompts, and model output drives decisions or downstream calls without a strict schema check.",
        "root_cause": "No trust boundary between instructions and data, and no deterministic validation of model output (OWASP LLM01:2026 / LLM10:2026).",
        "suspected_vibe_flaw": "Vibe-coded AI features wire the model straight into business logic because the demo prompt behaved.",
        "suggested_test_scenario": "Feed input containing an instruction override and invisible Unicode, and assert the output is schema-validated and never reaches eval/SQL/HTML or a privileged action.",
        "owasp_mapping": "LLM01:2026",
    },
}
