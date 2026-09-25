import os
import json
import logging
import re
from typing import Dict, Any, Optional, List
import yaml

from core.models import AgentCallRecord

try:
    import litellm
except ImportError:
    litellm = None

logger = logging.getLogger("VibeHarness.LLMGateway")

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "agents_config.yaml"
)

# Key added to every response so callers can tell simulated output from real model output
PROVENANCE_KEY = "_provenance"


class LLMGatewayError(RuntimeError):
    """Raised in strict 'live' mode when a real model invocation is impossible or fails."""


class LLMGateway:
    """
    Unified gateway for orchestrating calls to heterogeneous LLMs (Claude, Nemotron, ChatGPT).
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
        self.models_config = self.config.get("models", {})
        self.agents_config = self.config.get("agents", {})
        self.call_log: List[AgentCallRecord] = []

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
        # A missing config would silently drop every model/agent mapping, so fail loudly instead
        if not os.path.exists(path):
            raise FileNotFoundError(f"Agent config not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def is_live_configured(self, model_alias: str) -> bool:
        """Checks whether the requested model has its API key configured."""
        model_info = self.models_config.get(model_alias, {})
        env_var = model_info.get("api_key_env")
        return bool(env_var and os.getenv(env_var))

    def generate(
        self,
        agent_id: str,
        system_prompt: str,
        user_prompt: str,
        json_output: bool = True,
        required_keys: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes a prompt targeting the designated agent's configured LLM.
        A live response that is not valid JSON or lacks any of `required_keys` is recorded with
        mode "invalid" (and returned as {}), so callers and the quality gate never mistake an
        unusable answer for a genuine empty result.
        """
        agent_meta = self.agents_config.get(agent_id, {})
        model_alias = agent_meta.get("model_alias", "chatgpt")
        temperature = agent_meta.get("temperature", 0.2)
        model_info = self.models_config.get(model_alias, {})
        model_name = model_info.get("model", "gpt-4o")

        # Decide whether to invoke live API or mock engine
        fallback_reason: Optional[str] = None
        if self.execution_mode == "mock":
            fallback_reason = "execution_mode is 'mock'"
        elif litellm is None:
            fallback_reason = "litellm is not installed"
        elif not self.is_live_configured(model_alias):
            env_var = model_info.get("api_key_env") or "<no api_key_env configured>"
            fallback_reason = f"API key env var {env_var} is not set"

        if fallback_reason is None:
            try:
                logger.info(f"Dispatching [{agent_id}] to Live LLM: {model_name} (Alias: {model_alias})")
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
                raw_text, model_name = self._complete(model_info, model_name, messages, temperature)
                result = self._clean_and_parse_json(raw_text) if json_output else {"raw": raw_text}
                problem = self._validate_output(result, json_output, required_keys)
                if problem:
                    logger.error(f"[{agent_id}] {model_name} returned unusable output: {problem}")
                    self._record(agent_id, model_alias, model_name, "invalid", problem)
                    return {PROVENANCE_KEY: {"mode": "invalid", "model": model_name, "reason": problem}}
                self._record(agent_id, model_alias, model_name, "live")
                result[PROVENANCE_KEY] = {"mode": "live", "model": model_name}
                return result
            except Exception as e:
                fallback_reason = f"live invocation failed: {e}"
                if self.execution_mode == "live":
                    raise LLMGatewayError(f"[{agent_id}] {model_name}: {fallback_reason}") from e
                logger.warning(f"Live invocation failed for {agent_id} ({model_name}): {e}. Falling back to simulation logic.")
        elif self.execution_mode == "live":
            raise LLMGatewayError(f"[{agent_id}] cannot run live with {model_name}: {fallback_reason}")

        # Offline / Mock Fallback
        logger.info(f"Dispatching [{agent_id}] to Simulation Engine (Model Alias: {model_alias}; reason: {fallback_reason})")
        self._record(agent_id, model_alias, model_name, "simulated", fallback_reason)
        result = self._generate_simulated_response(agent_id, model_alias, user_prompt)
        result[PROVENANCE_KEY] = {"mode": "simulated", "model": model_name, "reason": fallback_reason}
        return result

    def _complete(self, model_info: Dict[str, Any], model_name: str, messages: List[Dict[str, str]], temperature: float):
        """
        Calls the primary model (with litellm's own retries), then `fallback_model` once if the primary fails.
        The API key is passed explicitly, so providers whose litellm default env var differs from
        `api_key_env` (e.g. NVIDIA NIM) still authenticate. Returns (text, model_actually_used).
        """
        global_cfg = self.config.get("global", {})
        kwargs: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "api_key": os.getenv(model_info["api_key_env"]),
            "timeout": global_cfg.get("timeout_seconds", 60),
            "num_retries": global_cfg.get("max_retries", 2),
            "max_tokens": global_cfg.get("max_output_tokens", 4096),
        }
        if model_info.get("api_base"):
            kwargs["api_base"] = model_info["api_base"]

        candidates = [model_name] + ([model_info["fallback_model"]] if model_info.get("fallback_model") else [])
        last_error: Optional[Exception] = None
        for candidate in candidates:
            try:
                response = litellm.completion(model=candidate, **kwargs)
                return response.choices[0].message.content or "", candidate
            except Exception as e:
                last_error = e
                logger.warning(f"Model {candidate} failed: {e}")
        raise last_error

    @staticmethod
    def _validate_output(result: Any, json_output: bool, required_keys: Optional[List[str]]) -> Optional[str]:
        if not json_output:
            return None
        if not isinstance(result, dict):
            return f"expected a JSON object, got {type(result).__name__}"
        if result.get("error") == "JSONDecodeError":
            return "response is not valid JSON"
        missing = [k for k in (required_keys or []) if k not in result]
        if missing:
            return f"response is missing required key(s): {', '.join(missing)}"
        return None

    def _record(self, agent_id: str, model_alias: str, model_name: str, mode: str, reason: Optional[str] = None):
        self.call_log.append(AgentCallRecord(
            agent_id=agent_id, model_alias=model_alias, model_name=model_name, mode=mode, reason=reason
        ))

    def _clean_and_parse_json(self, text: str) -> Dict[str, Any]:
        """Strips markdown code fences and parses JSON safely."""
        text = text.strip()
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            text = match.group(1).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError as err:
            logger.error(f"JSON parsing error: {err}. Raw content: {text[:200]}")
            return {"error": "JSONDecodeError", "raw_content": text}

    def _generate_simulated_response(self, agent_id: str, model_alias: str, prompt: str) -> Dict[str, Any]:
        """
        High-fidelity domain-specific fallback logic reflecting distinctive model traits:
        - Claude: Excels at state transitions, missing null checks, edge-case logic.
        - Nemotron: Focuses on boundary limits, buffer/memory safety, defensive guards.
        - ChatGPT: Focuses on contract specifications, API compliance, parameter validation.
        NOTE: responses are fixed templates independent of the target code; they exist so the
        pipeline can be exercised offline and are always flagged as simulated in reports.
        """
        if "reviewer_claude" in agent_id:
            return {
                "findings": [
                    {
                        "severity": "HIGH",
                        "title": "Unchecked Null / Implicit State Assumption in Handler",
                        "description": "The vibe-coded logic assumes entities exist and state transitions are valid without verifying database fetch outcomes, leading to unhandled NoneType / NullPointer exceptions.",
                        "root_cause": "Absence of defensive null-check before property traversal.",
                        "suspected_vibe_flaw": "Vibe coding commonly assumes the 'happy path' where records are always found.",
                        "suggested_test_scenario": "Invoke the endpoint/function with a non-existent ID or empty payload and assert proper error status (404/400) instead of a 500 crash."
                    }
                ]
            }

        elif "reviewer_nemotron" in agent_id:
            return {
                "findings": [
                    {
                        "severity": "CRITICAL",
                        "title": "Missing Input Sanitization & Unbounded Resource Allocation",
                        "description": "The logic lacks input length and numerical range clamping on queries or data arrays, allowing memory exhaustion and ReDoS or unvalidated bulk payloads.",
                        "root_cause": "Directly feeding untrusted input into downstream iteration and memory structures.",
                        "suspected_vibe_flaw": "AI coding assistants frequently skip explicit size checks and pagination limits.",
                        "suggested_test_scenario": "Supply a 10MB payload or integer values exceeding 1,000,000 and verify graceful rejection with HTTP 413 or 422."
                    }
                ]
            }

        elif "reviewer_chatgpt" in agent_id:
            return {
                "findings": [
                    {
                        "severity": "MEDIUM",
                        "title": "API Contract Specification Drift & Schema Inconsistency",
                        "description": "Missing parameter type enforcement and inconsistency between expected response schema and actual serialized dictionary fields.",
                        "root_cause": "Implicit schema casting without strict Pydantic/dataclass schema validation.",
                        "suspected_vibe_flaw": "Quick prototyping in vibe coding often changes response structures on the fly without updating contract definitions.",
                        "suggested_test_scenario": "Assert response schema matches the expected OpenAPI/JSON contract exactly across all field types."
                    }
                ]
            }

        elif "debater" in agent_id:
            return {
                "consensus_summary": "All three heterogeneous models identified that the codebase prioritizes superficial functionality over defensive bounds, resource limits, and error handling.",
                "model_agreement_ratio": 0.88,
                "confirmed_findings_indices": [0, 1, 2],
                "disputed_findings_indices": []
            }

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
