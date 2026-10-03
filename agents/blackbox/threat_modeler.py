import logging
import os
import yaml
from pydantic import ValidationError
from typing import List, Dict, Any, Optional
from core.models import ThreatItem, ThreatModelReport, STRIDECategory, FindingSeverity, CodeSymbol
from core.llm_gateway import LLMGateway
from core.codecontext import render_symbols

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "config", "threat_rules.yaml")

logger = logging.getLogger("VibeHarness.ThreatModeler")

# Estimated-token budget for the target code shown to the threat modeler (entry points first)
CODE_CONTEXT_TOKENS = 8000

DEFAULT_TRUST_BOUNDARIES = ["Internet to Public Gateway", "Gateway to Database"]
DEFAULT_ASSETS = ["User Credentials", "Business Records"]


def _text(value: Any, default: str) -> str:
    """A string field from the model; anything else (None, number, object) falls back to the default."""
    return value if isinstance(value, str) else default


def _string_list(value: Any, fallback: List[str]) -> List[str]:
    """A list-of-strings field from the model; anything else falls back to the harness's own value."""
    if isinstance(value, list):
        cleaned = [v for v in value if isinstance(v, str) and v.strip()]
        if cleaned:
            return cleaned
    return fallback


class AutomatedThreatModeler:
    """
    Automated Threat Modeling Agent using STRIDE and OWASP Top 10 frameworks.
    Analyzes architectural boundaries, endpoints, and assets, then synthesizes
    a rigorous Threat Matrix before any black-box test cases are designed.
    """

    def __init__(self, gateway: LLMGateway, rules_path: str = DEFAULT_RULES_PATH):
        self.gateway = gateway
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: str) -> Dict[str, Any]:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def _rules_guidance(self) -> str:
        """STRIDE vibe-bug checklist and OWASP API Top 10 from config/threat_rules.yaml."""
        lines = []
        for cat in (self.rules.get("stride_categories") or {}).values():
            bugs = "; ".join(cat.get("common_vibe_bugs") or [])
            lines.append(f"- {cat.get('name')}: {bugs}")
        owasp = [f"{o.get('id')} {o.get('name')}" for o in self.rules.get("owasp_api_top10") or []]
        text = ""
        if lines:
            text += "Common vibe-coding flaws to check per STRIDE category:\n" + "\n".join(lines) + "\n\n"
        if owasp:
            text += "Use these OWASP API Top 10 ids for owasp_mapping: " + ", ".join(owasp) + "\n\n"
        return text

    @staticmethod
    def _code_guidance(symbols: Optional[List[CodeSymbol]], root_dir: Optional[str]) -> str:
        if not symbols:
            return ""
        root = root_dir or os.path.dirname(os.path.abspath(symbols[0].file_path))
        # Entry points first: they are where untrusted input crosses the trust boundary
        ordered = sorted(symbols, key=lambda s: s.symbol_type != "route")
        return f"Target source code:\n{render_symbols(ordered, root, max_tokens=CODE_CONTEXT_TOKENS)}\n\n"

    def model_system(
        self,
        system_description: str,
        entrypoints: List[str],
        detected_routes: Optional[List[str]] = None,
        symbols: Optional[List[CodeSymbol]] = None,
        root_dir: Optional[str] = None
    ) -> ThreatModelReport:
        """
        Executes STRIDE threat modeling against the target system.
        """
        routes_summary = ", ".join(detected_routes) if detected_routes else "General RESTful APIs"
        entrypoints_summary = ", ".join(entrypoints) if entrypoints else "HTTP/REST Endpoints"

        system_prompt = (
            "You are a Senior Principal Security Architect and Threat Modeling Specialist.\n"
            "Your mission: Perform rigorous STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, "
            "Denial of Service, Elevation of Privilege) and OWASP API Top 10 threat modeling on a vibe-coded system.\n\n"
            "Output JSON format matching this exact schema:\n"
            "{\n"
            '  "system_description": "summary",\n'
            '  "entrypoints": ["list of entry points"],\n'
            '  "trust_boundaries": ["list of trust boundaries"],\n'
            '  "assets": ["critical assets requiring defense"],\n'
            '  "threats": [\n'
            "    {\n"
            '      "threat_id": "THREAT-01",\n'
            '      "stride_category": "Elevation of Privilege",\n'
            '      "owasp_mapping": "API1:2023 - BOLA",\n'
            '      "title": "Clear threat title",\n'
            '      "description": "Mechanics of the threat",\n'
            '      "asset_at_risk": "Target data/asset",\n'
            '      "attack_vector": "HTTP endpoint or payload",\n'
            '      "trust_boundary_crossed": "Boundary traversed",\n'
            '      "severity": "CRITICAL" | "HIGH" | "MEDIUM",\n'
            '      "attack_scenario": "Concrete steps an adversary would take",\n'
            '      "test_verification_goal": "Expected verifiable defensive condition"\n'
            "    }\n"
            "  ]\n"
            "}"
        )

        user_prompt = (
            f"System Description: {system_description}\n"
            f"Entrypoints: {entrypoints_summary}\n"
            f"Detected Routes: {routes_summary}\n\n"
            f"{self._rules_guidance()}"
            f"{self._code_guidance(symbols, root_dir)}"
            f"Perform comprehensive threat modeling identifying vibe-coding vulnerabilities. "
            f"Only include threats that are plausible for the code shown, and name the concrete function/route in attack_vector."
        )

        logger.info("Initiating STRIDE & OWASP threat modeling...")
        resp = self.gateway.generate(
            "blackbox_threat_modeler", system_prompt, user_prompt, json_output=True, required_keys=["threats"]
        )

        raw_threats = resp.get("threats")
        if not isinstance(raw_threats, list):
            logger.warning(f"Ignoring unusable threat list from model (got {type(raw_threats).__name__})")
            raw_threats = []

        threat_items: List[ThreatItem] = []
        for position, item in enumerate(raw_threats, start=1):
            if not isinstance(item, dict):
                logger.warning(f"Skipping malformed threat entry #{position} (not a JSON object)")
                continue

            try:
                category = STRIDECategory(str(item.get("stride_category") or "Tampering"))
            except ValueError:
                category = STRIDECategory.TAMPERING

            try:
                severity = FindingSeverity(str(item.get("severity") or "HIGH").upper())
            except ValueError:
                severity = FindingSeverity.HIGH

            threat_id = item.get("threat_id")
            if not isinstance(threat_id, str) or not threat_id.strip():
                threat_id = f"THREAT-{position:02d}"

            owasp_mapping = item.get("owasp_mapping")
            try:
                threat_items.append(ThreatItem(
                    threat_id=threat_id,
                    stride_category=category,
                    owasp_mapping=owasp_mapping if isinstance(owasp_mapping, str) and owasp_mapping.strip() else None,
                    title=_text(item.get("title"), "Unclassified Threat"),
                    description=_text(item.get("description"), ""),
                    asset_at_risk=_text(item.get("asset_at_risk"), "Application Data"),
                    attack_vector=_text(item.get("attack_vector"), "REST API"),
                    trust_boundary_crossed=_text(item.get("trust_boundary_crossed"), "Internet to Server"),
                    severity=severity,
                    attack_scenario=_text(item.get("attack_scenario"), ""),
                    test_verification_goal=_text(item.get("test_verification_goal"), ""),
                ))
            except ValidationError as e:
                logger.warning(f"Skipping unusable threat entry #{position}: {e}")

        return ThreatModelReport(
            system_description=_text(resp.get("system_description"), system_description) or system_description,
            entrypoints=_string_list(resp.get("entrypoints"), entrypoints),
            trust_boundaries=_string_list(resp.get("trust_boundaries"), DEFAULT_TRUST_BOUNDARIES),
            assets=_string_list(resp.get("assets"), DEFAULT_ASSETS),
            threats=threat_items,
            is_simulated=self.gateway.is_simulated(resp)
        )
