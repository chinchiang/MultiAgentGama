import logging
import os
import re
import yaml
from concurrent.futures import ThreadPoolExecutor
from pydantic import ValidationError
from typing import List, Dict, Any, Optional
from vibeharness.core.models import ThreatItem, ThreatModelReport, STRIDECategory, FindingSeverity, CodeSymbol
from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError
from vibeharness.core.i18n import bi
from vibeharness.core.codecontext import render_symbols, batch_symbols
from vibeharness.core.sanitize import UNTRUSTED_CODE_POLICY, untrusted_block

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "config", "threat_rules.yaml")

logger = logging.getLogger("VibeHarness.ThreatModeler")

# The threat model drives all black-box testing, so every symbol must be visible to it: like the
# white-box reviewers, symbols are split into batches whose code listing fits the token budget,
# instead of rendering everything into one prompt and silently dropping the overflow.
BATCH_MAX_TOKENS = 8000
BATCH_MAX_SYMBOLS = 15

_SEVERITY_RANK = {
    FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1, FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3, FindingSeverity.INFO: 4,
}

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
        # The rules only enrich the prompt, so a missing or broken file degrades with a warning
        # instead of failing the run (but never silently: it once went missing from the wheel)
        if not os.path.exists(path):
            logger.warning(bi(f"在 {path} 找不到威脅規則；威脅建模將在沒有 STRIDE/OWASP 檢查清單的情況下執行。",
                              f"Threat rules not found at {path}; threat modeling runs without the STRIDE/OWASP checklist."))
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                rules = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as e:
            logger.warning(bi(f"無法從 {path} 載入威脅規則：{e}；在沒有規則的情況下繼續執行。",
                              f"Could not load threat rules from {path}: {e}; continuing without them."))
            return {}
        return rules if isinstance(rules, dict) else {}

    def _rules_guidance(self) -> str:
        """STRIDE vibe-bug checklist and OWASP API Top 10 from config/threat_rules.yaml.

        The file is user-editable, so every level is type-checked: a structurally wrong file
        (e.g. a list where a mapping is expected) skips the checklist instead of crashing
        every modeling batch with an AttributeError.
        """
        lines = []
        stride = self.rules.get("stride_categories")
        if isinstance(stride, dict):
            for cat in stride.values():
                if not isinstance(cat, dict):
                    continue
                bugs = cat.get("common_vibe_bugs")
                bug_list = "; ".join(b for b in bugs if isinstance(b, str)) if isinstance(bugs, list) else ""
                name = cat.get("name") if isinstance(cat.get("name"), str) else "Unnamed category"
                lines.append(f"- {name}: {bug_list}")
        owasp = self.rules.get("owasp_api_top10")
        owasp_entries = [
            f"{o.get('id')} {o.get('name')}" for o in owasp
            if isinstance(o, dict) and isinstance(o.get("id"), str)
        ] if isinstance(owasp, list) else []
        text = ""
        if lines:
            text += "Common vibe-coding flaws to check per STRIDE category:\n" + "\n".join(lines) + "\n\n"
        if owasp_entries:
            text += "Use these OWASP API Top 10 ids for owasp_mapping: " + ", ".join(owasp_entries) + "\n\n"
        return text

    def _llm_rules_guidance(self, ai_components: Optional[List[str]]) -> str:
        """OWASP Top 10 for LLM Applications 2026 checklist, only for targets that import an AI SDK
        (a plain CRUD service would otherwise get LLM threats invented for it)."""
        entries = self.rules.get("owasp_llm_top10_2026")
        if not ai_components or not isinstance(entries, list):
            return ""
        lines = []
        for e in entries:
            if not isinstance(e, dict) or not isinstance(e.get("id"), str):
                continue
            bugs = e.get("common_vibe_bugs")
            bug_list = "; ".join(b for b in bugs if isinstance(b, str)) if isinstance(bugs, list) else ""
            techniques = e.get("atlas_techniques")
            atlas = ", ".join(t for t in techniques if isinstance(t, str)) if isinstance(techniques, list) else ""
            lines.append(f"- {e['id']} {e.get('name', '')}: {bug_list}" + (f" [ATLAS: {atlas}]" if atlas else ""))
        if not lines:
            return ""
        return (
            f"The target integrates AI/LLM components ({', '.join(ai_components)}). Also model threats from the "
            "OWASP Top 10 for LLM Applications 2026; use its ids for owasp_mapping and the listed MITRE ATLAS "
            "technique ids for atlas_mapping:\n" + "\n".join(lines) + "\n\n"
        )

    @staticmethod
    def _code_guidance(symbols: Optional[List[CodeSymbol]], root_dir: Optional[str]) -> str:
        if not symbols:
            return ""
        root = root_dir or os.path.dirname(os.path.abspath(symbols[0].file_path))
        return f"Target source code:\n{untrusted_block(render_symbols(symbols, root, max_tokens=BATCH_MAX_TOKENS))}\n\n"

    def _model_batch(
        self,
        batch: List[CodeSymbol],
        system_prompt: str,
        system_description: str,
        entrypoints_summary: str,
        routes_summary: str,
        root_dir: Optional[str],
        ai_components: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        user_prompt = (
            f"System Description: {system_description}\n"
            f"Entrypoints: {entrypoints_summary}\n"
            f"Detected Routes: {routes_summary}\n\n"
            f"{self._rules_guidance()}"
            f"{self._llm_rules_guidance(ai_components)}"
            f"{self._code_guidance(batch, root_dir)}"
            f"Perform comprehensive threat modeling identifying vibe-coding vulnerabilities. "
            f"Only include threats that are plausible for the code shown, and name the concrete function/route in attack_vector."
        )
        return self.gateway.generate(
            "blackbox_threat_modeler", system_prompt, user_prompt, json_output=True, required_keys=["threats"]
        )

    def model_system(
        self,
        system_description: str,
        entrypoints: List[str],
        detected_routes: Optional[List[str]] = None,
        symbols: Optional[List[CodeSymbol]] = None,
        root_dir: Optional[str] = None,
        ai_components: Optional[List[str]] = None
    ) -> ThreatModelReport:
        """
        Executes STRIDE threat modeling against the target system.
        Symbols are verified in batches so the model sees all of them; the threats of every
        batch are merged into one report (duplicate threat_ids are renumbered).
        `ai_components` (AI SDKs the target imports) adds the OWASP LLM Top 10 2026 checklist.
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
            '      "atlas_mapping": "MITRE ATLAS technique id(s) for AI-specific threats, else empty",\n'
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
            f"{UNTRUSTED_CODE_POLICY}"
        )

        ordered = sorted(symbols or [], key=lambda s: s.symbol_type != "route")
        # An empty symbol list keeps one (code-less) batch so a report-level response is still produced
        batches = batch_symbols(ordered, root_dir or os.getcwd(), BATCH_MAX_TOKENS, BATCH_MAX_SYMBOLS) or [[]]

        logger.info(bi("開始 STRIDE 與 OWASP 威脅建模...", "Initiating STRIDE & OWASP threat modeling..."))
        with ThreadPoolExecutor(max_workers=min(self.gateway.max_concurrent_calls, len(batches))) as pool:
            futures = [
                pool.submit(
                    self._model_batch,
                    batch,
                    system_prompt,
                    system_description,
                    entrypoints_summary,
                    routes_summary,
                    root_dir,
                    ai_components
                )
                for batch in batches
            ]
            responses: List[Dict[str, Any]] = []
            for _batch, future in zip(batches, futures, strict=True):
                try:
                    responses.append(future.result())
                except LLMGatewayError:
                    raise
                except Exception as e:
                    logger.error(bi(f"威脅建模批次失敗：{type(e).__name__}: {e}",
                                    f"Threat modeler batch failed: {type(e).__name__}: {e}"))
                    responses.append({})

        report_fields: Optional[Dict[str, Any]] = None
        threats: List[ThreatItem] = []
        used_ids: set = set()
        any_simulated = False

        for resp in responses:
            any_simulated = any_simulated or self.gateway.is_simulated(resp)
            if report_fields is None and self.gateway.is_usable(resp):
                # Report-level fields come from the first batch that produced a usable answer
                report_fields = resp
            threats.extend(self._parse_threats(resp, used_ids))

        threats = self._merge_duplicate_threats(threats)

        if report_fields is None:  # every batch returned unusable output
            report_fields = {}

        return ThreatModelReport(
            system_description=_text(report_fields.get("system_description"), system_description) or system_description,
            entrypoints=_string_list(report_fields.get("entrypoints"), entrypoints),
            trust_boundaries=_string_list(report_fields.get("trust_boundaries"), DEFAULT_TRUST_BOUNDARIES),
            assets=_string_list(report_fields.get("assets"), DEFAULT_ASSETS),
            threats=threats,
            is_simulated=any_simulated
        )

    @staticmethod
    def _merge_duplicate_threats(threats: List[ThreatItem]) -> List[ThreatItem]:
        """Merges the same threat reported by several batches (same STRIDE category, title and
        attack vector after normalization). The first report is kept, with the highest severity
        any batch gave it; otherwise every batch would synthesize and run the same attack again."""
        def norm(text: str) -> str:
            return " ".join(re.findall(r"[a-z0-9]+", text.lower()))

        merged: Dict[Any, ThreatItem] = {}
        for t in threats:
            key = (t.stride_category, norm(t.title), norm(t.attack_vector))
            kept = merged.get(key)
            if kept is None:
                merged[key] = t
            elif _SEVERITY_RANK[t.severity] < _SEVERITY_RANK[kept.severity]:
                merged[key] = kept.model_copy(update={"severity": t.severity})
        if len(merged) < len(threats):
            logger.info(bi(f"已將所有批次的 {len(threats)} 個威脅合併為 {len(merged)} 個不重複的威脅。",
                           f"Merged {len(threats)} threats from all batches into {len(merged)} distinct threats."))
        return list(merged.values())

    def _parse_threats(self, resp: Dict[str, Any], used_ids: set) -> List[ThreatItem]:
        """Validated ThreatItems from one model response; ids that collide with earlier batches are renumbered."""
        raw_threats = resp.get("threats")
        if not isinstance(raw_threats, list):
            logger.warning(bi(f"略過模型無法使用的威脅清單（收到 {type(raw_threats).__name__}）",
                              f"Ignoring unusable threat list from model (got {type(raw_threats).__name__})"))
            raw_threats = []

        threat_items: List[ThreatItem] = []
        next_fallback = 1
        for position, item in enumerate(raw_threats, start=1):
            if not isinstance(item, dict):
                logger.warning(bi(f"略過格式錯誤的威脅項目 #{position}（不是 JSON 物件）",
                                  f"Skipping malformed threat entry #{position} (not a JSON object)"))
                continue

            try:
                category = STRIDECategory(str(item.get("stride_category") or "Tampering"))
            except ValueError:
                logger.warning(bi(f"'{item.get('threat_id')}' 的 STRIDE 類別 '{item.get('stride_category')}' 未知；改用 Tampering",
                                  f"Unknown STRIDE category '{item.get('stride_category')}' on '{item.get('threat_id')}'; using Tampering"))
                category = STRIDECategory.TAMPERING

            try:
                severity = FindingSeverity(str(item.get("severity") or "HIGH").upper())
            except ValueError:
                logger.warning(bi(f"'{item.get('threat_id')}' 的嚴重度 '{item.get('severity')}' 未知；改用 HIGH",
                                  f"Unknown severity '{item.get('severity')}' on '{item.get('threat_id')}'; using HIGH"))
                severity = FindingSeverity.HIGH

            threat_id = item.get("threat_id")
            if not isinstance(threat_id, str) or not threat_id.strip() or threat_id in used_ids:
                # Only advance the fallback counter when a fallback id is actually consumed,
                # otherwise model-supplied ids leave gaps in the THREAT-XX sequence.
                while f"THREAT-{next_fallback:02d}" in used_ids:
                    next_fallback += 1
                threat_id = f"THREAT-{next_fallback:02d}"
                next_fallback += 1
            used_ids.add(threat_id)

            owasp_mapping = item.get("owasp_mapping")
            atlas_mapping = item.get("atlas_mapping")
            try:
                threat_items.append(ThreatItem(
                    threat_id=threat_id,
                    stride_category=category,
                    owasp_mapping=owasp_mapping if isinstance(owasp_mapping, str) and owasp_mapping.strip() else None,
                    atlas_mapping=atlas_mapping if isinstance(atlas_mapping, str) and atlas_mapping.strip() else None,
                    title=_text(item.get("title"), bi("未分類的威脅", "Unclassified Threat")),
                    description=_text(item.get("description"), ""),
                    asset_at_risk=_text(item.get("asset_at_risk"), "Application Data"),
                    attack_vector=_text(item.get("attack_vector"), "REST API"),
                    trust_boundary_crossed=_text(item.get("trust_boundary_crossed"), "Internet to Server"),
                    severity=severity,
                    attack_scenario=_text(item.get("attack_scenario"), ""),
                    test_verification_goal=_text(item.get("test_verification_goal"), ""),
                ))
            except ValidationError as e:
                logger.warning(bi(f"略過無法使用的威脅項目 #{position}：{e}", f"Skipping unusable threat entry #{position}: {e}"))

        return threat_items
