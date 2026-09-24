import os
import json
import logging
import re
from typing import Dict, Any, Optional, List
import yaml

try:
    import litellm
except ImportError:
    litellm = None

logger = logging.getLogger("VibeHarness.LLMGateway")


class LLMGateway:
    """
    Unified gateway for orchestrating calls to heterogeneous LLMs (Claude, Nemotron, ChatGPT).
    Provides automatic fallback to offline mock responses when API keys are absent or when in mock mode.
    """

    def __init__(self, config_path: str = "config/agents_config.yaml"):
        self.config = self._load_config(config_path)
        self.execution_mode = self.config.get("global", {}).get("execution_mode", "hybrid")
        self.models_config = self.config.get("models", {})
        self.agents_config = self.config.get("agents", {})

    def _load_config(self, path: str) -> Dict[str, Any]:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

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
        json_output: bool = True
    ) -> Dict[str, Any]:
        """
        Executes a prompt targeting the designated agent's configured LLM.
        """
        agent_meta = self.agents_config.get(agent_id, {})
        model_alias = agent_meta.get("model_alias", "chatgpt")
        temperature = agent_meta.get("temperature", 0.2)
        model_info = self.models_config.get(model_alias, {})
        model_name = model_info.get("model", "gpt-4o")

        # Decide whether to invoke live API or mock engine
        can_run_live = self.is_live_configured(model_alias) and self.execution_mode in ["live", "hybrid"]

        if can_run_live and litellm is not None:
            try:
                logger.info(f"Dispatching [{agent_id}] to Live LLM: {model_name} (Alias: {model_alias})")
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
                api_base = model_info.get("api_base")
                kwargs = {
                    "model": model_name,
                    "messages": messages,
                    "temperature": temperature,
                }
                if api_base:
                    kwargs["api_base"] = api_base

                response = litellm.completion(**kwargs)
                raw_text = response.choices[0].message.content
                if json_output:
                    return self._clean_and_parse_json(raw_text)
                return {"raw": raw_text}
            except Exception as e:
                logger.warning(f"Live invocation failed for {agent_id} ({model_name}): {e}. Falling back to simulation logic.")

        # Offline / Mock Fallback
        logger.info(f"Dispatching [{agent_id}] to Simulation Engine (Model Alias: {model_alias})")
        return self._generate_simulated_response(agent_id, model_alias, user_prompt)

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
            return {
                "tests": [
                    {
                        "test_id": "WB-TEST-01",
                        "test_type": "whitebox_unit",
                        "title": "Test null entity traversal defensively",
                        "rationale": "Verifies that handlers defensively check for None before accessing nested properties.",
                        "expected_outcome": "Graceful handling without raising unhandled TypeError.",
                        "code": (
                            "def test_null_profile_edge_case():\n"
                            "    try:\n"
                            "        from vibe_sample_app import get_user_profile\n"
                            "    except ImportError:\n"
                            "        from examples.vibe_sample_app import get_user_profile\n"
                            "    try:\n"
                            "        res = get_user_profile('usr_002')\n"
                            "        assert res is not None\n"
                            "    except (TypeError, KeyError):\n"
                            "        raise AssertionError('Exposed vibe-coding flaw: unhandled NoneType access in get_user_profile')\n"
                        )
                    }
                ]
            }

        return {"status": "ok", "message": f"Simulated output for {agent_id}"}
