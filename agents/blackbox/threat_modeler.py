import logging
import os
import yaml
from typing import List, Dict, Any, Optional
from core.models import ThreatItem, ThreatModelReport, STRIDECategory, FindingSeverity
from core.llm_gateway import LLMGateway

logger = logging.getLogger("VibeHarness.ThreatModeler")


class AutomatedThreatModeler:
    """
    Automated Threat Modeling Agent using STRIDE and OWASP Top 10 frameworks.
    Analyzes architectural boundaries, endpoints, and assets, then synthesizes
    a rigorous Threat Matrix before any black-box test cases are designed.
    """

    def __init__(self, gateway: LLMGateway, rules_path: str = "config/threat_rules.yaml"):
        self.gateway = gateway
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: str) -> Dict[str, Any]:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def model_system(
        self,
        system_description: str,
        entrypoints: List[str],
        detected_routes: Optional[List[str]] = None
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
            f"Perform comprehensive threat modeling identifying vibe-coding vulnerabilities."
        )

        logger.info("Initiating STRIDE & OWASP threat modeling...")
        resp = self.gateway.generate("blackbox_threat_modeler", system_prompt, user_prompt, json_output=True)

        raw_threats = resp.get("threats", [])
        threat_items: List[ThreatItem] = []

        for item in raw_threats:
            category_str = item.get("stride_category", "Tampering")
            severity_str = item.get("severity", "HIGH").upper()

            try:
                category = STRIDECategory(category_str)
            except ValueError:
                category = STRIDECategory.TAMPERING

            try:
                severity = FindingSeverity(severity_str)
            except ValueError:
                severity = FindingSeverity.HIGH

            threat_items.append(ThreatItem(
                threat_id=item.get("threat_id", f"THREAT-{len(threat_items)+1:02d}"),
                stride_category=category,
                owasp_mapping=item.get("owasp_mapping"),
                title=item.get("title", "Unclassified Threat"),
                description=item.get("description", ""),
                asset_at_risk=item.get("asset_at_risk", "Application Data"),
                attack_vector=item.get("attack_vector", "REST API"),
                trust_boundary_crossed=item.get("trust_boundary_crossed", "Internet to Server"),
                severity=severity,
                attack_scenario=item.get("attack_scenario", ""),
                test_verification_goal=item.get("test_verification_goal", "")
            ))

        return ThreatModelReport(
            system_description=resp.get("system_description", system_description),
            entrypoints=resp.get("entrypoints", entrypoints),
            trust_boundaries=resp.get("trust_boundaries", ["Internet to Public Gateway", "Gateway to Database"]),
            assets=resp.get("assets", ["User Credentials", "Business Records"]),
            threats=threat_items,
            is_simulated=self.gateway.is_simulated(resp)
        )
