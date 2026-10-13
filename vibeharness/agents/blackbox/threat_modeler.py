import functools
import logging
import os
import re
import yaml
from pydantic import ValidationError
from typing import Any, Dict, List, Optional
from vibeharness.core.models import ThreatItem, ThreatModelReport, STRIDECategory, FindingSeverity, CodeSymbol
from vibeharness.core.fanout import Call, fan_out
from vibeharness.core.identity import normalize, severity_rank
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.i18n import bi
from vibeharness.core.codecontext import render_symbols, batch_symbols
from vibeharness.core.sanitize import UNTRUSTED_CODE_POLICY, untrusted_block

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "config", "threat_rules.yaml")

logger = logging.getLogger("VibeHarness.ThreatModeler")

# 威脅模型驅動所有黑箱測試，所以每個符號都必須讓它看到：如同白箱審查者，
# 符號會切成程式碼清單放得進 token 預算的批次，
# 而不是把所有東西塞進一個提示詞再默默丟掉溢出的部分。
# The threat model drives all black-box testing, so every symbol must be visible to it: like the
# white-box reviewers, symbols are split into batches whose code listing fits the token budget,
# instead of rendering everything into one prompt and silently dropping the overflow.
BATCH_MAX_TOKENS = 8000
BATCH_MAX_SYMBOLS = 15

# 模型選的威脅 id 會被重複用在測試 id、檔名與報告的程式碼區段中：不在這個純識別字字母表內的 id
# 會被替換，而不是在每個匯點各自跳脫
# The model-chosen threat id is reused in test ids, file names and report code spans: anything outside
# this plain identifier alphabet is replaced rather than escaped at every sink
_THREAT_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,40}")


def _category_key(text: str) -> str:
    return re.sub(r"[\s_\-]+", " ", text).strip().lower()


_STRIDE_BY_KEY = {_category_key(c.value): c for c in STRIDECategory}


def _stride_category(value: str) -> Optional[STRIDECategory]:
    """模型文字中的 STRIDE 類別，容忍大小寫與 `_`／`-` 分隔符（"DENIAL_OF_SERVICE"、
    "Elevation-of-Privilege"）；沒有指名任何類別時為 None。
    STRIDE category from model text, tolerant of case and `_`/`-` separators
    ("DENIAL_OF_SERVICE", "Elevation-of-Privilege"); None when it names no category."""
    return _STRIDE_BY_KEY.get(_category_key(value))



DEFAULT_TRUST_BOUNDARIES = ["Internet to Public Gateway", "Gateway to Database"]
DEFAULT_ASSETS = ["User Credentials", "Business Records"]


def _text(value: Any, default: str) -> str:
    """來自模型的字串欄位；其他任何東西（None、數字、物件）都退回預設值。
    A string field from the model; anything else (None, number, object) falls back to the default."""
    return value if isinstance(value, str) else default


def _string_list(value: Any, fallback: List[str]) -> List[str]:
    """來自模型的字串清單欄位；其他任何東西都退回本框架自己的值。
    A list-of-strings field from the model; anything else falls back to the harness's own value."""
    if isinstance(value, list):
        cleaned = [v for v in value if isinstance(v, str) and v.strip()]
        if cleaned:
            return cleaned
    return fallback


class AutomatedThreatModeler:
    """
    使用 STRIDE 與 OWASP Top 10 框架的自動化威脅建模代理。
    分析架構邊界、端點與資產，然後在設計任何黑箱測試案例之前
    綜合出一份嚴謹的威脅矩陣。
    Automated Threat Modeling Agent using STRIDE and OWASP Top 10 frameworks.
    Analyzes architectural boundaries, endpoints, and assets, then synthesizes
    a rigorous Threat Matrix before any black-box test cases are designed.
    """

    def __init__(self, gateway: LLMGateway, rules_path: str = DEFAULT_RULES_PATH):
        self.gateway = gateway
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: str) -> Dict[str, Any]:
        # 規則只是用來充實提示詞，所以檔案缺失或損壞時只發出警告並降級執行，
        # 而不是讓整個執行失敗（但絕不默默進行：它曾經從 wheel 中消失過）
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
        """來自 config/threat_rules.yaml 的 STRIDE vibe 錯誤檢查清單與 OWASP API Top 10。

        該檔案可由使用者編輯，所以每一層都做型別檢查：結構錯誤的檔案
        （例如預期是對應卻給了清單）會跳過檢查清單，而不是讓每個建模批次
        都因 AttributeError 當掉。
        STRIDE vibe-bug checklist and OWASP API Top 10 from config/threat_rules.yaml.

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
        """OWASP Top 10 for LLM Applications 2026 檢查清單，只用於有匯入 AI SDK 的目標
        （否則單純的 CRUD 服務會被憑空捏造出 LLM 威脅）。
        OWASP Top 10 for LLM Applications 2026 checklist, only for targets that import an AI SDK
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
            "blackbox_threat_modeler", system_prompt, user_prompt, json_output=True, required_keys=["threats"],
            simulated=_simulated_threat_model,
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
        對目標系統執行 STRIDE 威脅建模。
        符號分批驗證，讓模型看到全部；每個批次的威脅合併成一份報告
        （重複的 threat_id 會重新編號）。
        `ai_components`（目標匯入的 AI SDK）會加入 OWASP LLM Top 10 2026 檢查清單。
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
        # 空的符號清單仍保留一個（沒有程式碼的）批次，讓報告層級的回應仍會產生
        # An empty symbol list keeps one (code-less) batch so a report-level response is still produced
        batches = batch_symbols(ordered, root_dir or os.getcwd(), BATCH_MAX_TOKENS, BATCH_MAX_SYMBOLS) or [[]]

        logger.info(bi("開始 STRIDE 與 OWASP 威脅建模...", "Initiating STRIDE & OWASP threat modeling..."))
        calls: List[Call[Dict[str, Any]]] = [
            Call("blackbox_threat_modeler", ("威脅建模批次", "Threat modeler batch"), functools.partial(
                self._model_batch, batch, system_prompt, system_description, entrypoints_summary, routes_summary,
                root_dir, ai_components))
            for batch in batches
        ]
        # 當掉的批次由 fan_out 記成證據缺口；LLMGatewayError 與 KeyboardInterrupt 會在取消尚未開始的批次後往外拋
        # fan_out books a crashed batch as an evidence gap; LLMGatewayError and KeyboardInterrupt propagate after the
        # batches not yet started are cancelled
        responses: List[Dict[str, Any]] = [
            resp or {} for resp in fan_out(self.gateway, calls, fallback={}, logger=logger)]

        report_fields: Optional[Dict[str, Any]] = None
        threats: List[ThreatItem] = []
        used_ids: set = set()
        any_simulated = False

        for resp in responses:
            any_simulated = any_simulated or self.gateway.is_simulated(resp)
            if report_fields is None and self.gateway.is_usable(resp):
                # 報告層級欄位來自第一個產生可用答案的批次
                # Report-level fields come from the first batch that produced a usable answer
                report_fields = resp
            batch = self._parse_threats(resp, used_ids)
            if self.gateway.is_simulated(resp):
                for threat in batch:
                    threat.is_simulated = True
            threats.extend(batch)

        threats = self._merge_duplicate_threats(threats)

        if report_fields is None:  # 每個批次都回傳了無法使用的輸出 ／ every batch returned unusable output
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
        """合併多個批次回報的同一威脅（正規化後 STRIDE 類別、標題與攻擊向量相同）。
        保留第一份回報，並採用任一批次給它的最高嚴重度；否則每個批次
        都會再次合成並執行同樣的攻擊。
        Merges the same threat reported by several batches (same STRIDE category, title and
        attack vector after normalization). The first report is kept, with the highest severity
        any batch gave it; otherwise every batch would synthesize and run the same attack again."""
        # 任何文字的字母與數字都算（core/identity.py 的 normalize），中文標題才不會塌成空字串而被合併
        # Letters and digits of any script count (normalize in core/identity.py), so Chinese titles do not collapse
        # to "" and merge
        merged: Dict[Any, ThreatItem] = {}
        for t in threats:
            key = (t.stride_category, normalize(t.title), normalize(t.attack_vector))
            kept = merged.get(key)
            if kept is None:
                merged[key] = t
            elif severity_rank(t.severity) < severity_rank(kept.severity):
                merged[key] = kept.model_copy(update={"severity": t.severity})
        if len(merged) < len(threats):
            logger.info(bi(f"已將所有批次的 {len(threats)} 個威脅合併為 {len(merged)} 個不重複的威脅。",
                           f"Merged {len(threats)} threats from all batches into {len(merged)} distinct threats."))
        return list(merged.values())

    def _parse_threats(self, resp: Dict[str, Any], used_ids: set) -> List[ThreatItem]:
        """來自一個模型回應、經驗證的 ThreatItem；與先前批次衝突的 id 會重新編號。
        Validated ThreatItems from one model response; ids that collide with earlier batches are renumbered."""
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

            parsed_category = _stride_category(str(item.get("stride_category") or "Tampering"))
            if parsed_category is None:
                logger.warning(bi(f"'{item.get('threat_id')}' 的 STRIDE 類別 '{item.get('stride_category')}' 未知；改用 Tampering",
                                  f"Unknown STRIDE category '{item.get('stride_category')}' on '{item.get('threat_id')}'; using Tampering"))
            category = parsed_category or STRIDECategory.TAMPERING

            try:
                # 模型常帶空白或小寫（"CRITICAL "、"critical"）：正規化後才解析，免得默默降成 HIGH
                # Models add whitespace or lower case ("CRITICAL ", "critical"): normalize before parsing so it
                # is not silently downgraded to HIGH
                severity = FindingSeverity(str(item.get("severity") or "HIGH").strip().upper())
            except ValueError:
                logger.warning(bi(f"'{item.get('threat_id')}' 的嚴重度 '{item.get('severity')}' 未知；改用 HIGH",
                                  f"Unknown severity '{item.get('severity')}' on '{item.get('threat_id')}'; using HIGH"))
                severity = FindingSeverity.HIGH

            threat_id = item.get("threat_id")
            if isinstance(threat_id, str):
                threat_id = threat_id.strip()
            if not isinstance(threat_id, str) or not _THREAT_ID_RE.fullmatch(threat_id) or threat_id in used_ids:
                # 只在實際用掉一個後備 id 時才推進後備計數器，
                # 否則模型提供的 id 會在 THREAT-XX 序列中留下空缺。
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


def _simulated_threat_model(model_alias: str) -> Dict[str, Any]:
    """威脅建模者的模擬輸出：與目標無關的固定 STRIDE 威脅模型（BOLA、大量指派、錯誤外洩），每次呼叫都是新的 dict。
    The threat modeler's Simulated output: a fixed STRIDE threat model independent of the target (BOLA, mass
    assignment, error leakage), a new dict on every call."""
    return {
        "system_description": bi("Vibe coding 產出的網頁應用程式與 API 服務。", "Vibe-coded web application and API service."),
        "entrypoints": [bi("REST API 路由", "REST API routes"), bi("驗證標頭", "Auth headers"),
                        bi("使用者註冊／管理端點", "User registration / management endpoints")],
        "trust_boundaries": [bi("用戶端／網際網路到公開閘道", "Client / Internet to Public Gateway"),
                             bi("公開閘道到內部資料庫", "Public Gateway to Internal DB")],
        "assets": [bi("使用者憑證", "User credentials"), bi("客戶資料紀錄", "Customer data records"),
                   bi("資料庫連線字串", "Database connection strings")],
        "threats": [
            {
                "threat_id": "THREAT-01",
                "stride_category": "Elevation of Privilege",
                "owasp_mapping": "API1:2023 - Broken Object Level Authorization (BOLA)",
                "title": bi("資源更新的 BOLA / IDOR", "BOLA / IDOR on Resource Updates"),
                "description": bi("已驗證的使用者只要竄改 URL 路徑或酬載中的物件 ID，就能修改其他使用者的物件。",
                                  "An authenticated user can modify other users' objects by simply tampering with the object ID in the URL path or payload."),
                "asset_at_risk": bi("使用者帳號與私人紀錄", "User accounts & private records"),
                "attack_vector": "HTTP PUT/PATCH /api/users/{foreign_id}",
                "trust_boundary_crossed": bi("使用者 A 的邊界跨入使用者 B 的資料領域", "User A boundary into User B data domain"),
                "severity": "CRITICAL",
                "attack_scenario": bi("以使用者 A 登入，對使用者 B 的資源 ID 發出 PUT 請求。",
                                      "Login as User A, issue a PUT request targeting User B's resource ID."),
                "test_verification_goal": bi("確認狀態碼為 403 Forbidden 或 404 Not Found，絕不可為 200 OK。",
                                             "Ensure status code is 403 Forbidden or 404 Not Found, never 200 OK.")
            },
            {
                "threat_id": "THREAT-02",
                "stride_category": "Tampering",
                "owasp_mapping": "API3:2023 - Broken Object Property Level Authorization",
                "title": bi("管理員／敏感欄位的大量指派", "Mass Assignment of Admin / Sensitive Fields"),
                "description": bi("更新端點接受原始 JSON 本文並直接套用到資料庫模型，沒有嚴格的允許清單，使用者因此能注入 is_admin=true。",
                                  "The update endpoint accepts raw JSON body and applies it to the DB model without a strict whitelist, allowing users to inject is_admin=true."),
                "asset_at_risk": bi("系統授權完整性", "System authorization integrity"),
                "attack_vector": "HTTP POST/PUT with extra 'is_admin': true in payload",
                "trust_boundary_crossed": bi("無特權用戶端到特權角色", "Unprivileged client to privileged role"),
                "severity": "HIGH",
                "attack_scenario": bi("在更新個人資料時送出酬載 {'name': 'test', 'is_admin': true}。",
                                      "Send payload {'name': 'test', 'is_admin': true} during profile update."),
                "test_verification_goal": bi("確認 is_admin 維持 false，且無法透過公開端點更改。",
                                             "Ensure is_admin remains false and cannot be altered through public endpoint.")
            },
            {
                "threat_id": "THREAT-03",
                "stride_category": "Information Disclosure",
                "owasp_mapping": "API8:2023 - Security Misconfiguration",
                "title": bi("格式錯誤輸入導致堆疊追蹤與資料庫錯誤外洩", "Stack Trace & Database Error Leakage on Malformed Input"),
                "description": bi("送出無效的 JSON 或語法字元會造成未處理的 500 錯誤，外洩內部資料庫細節與檔案路徑。",
                                  "Sending invalid JSON or syntax characters causes unhandled 500 error leaking internal database details and file paths."),
                "asset_at_risk": bi("內部系統架構細節", "Internal system architecture details"),
                "attack_vector": "HTTP POST with malformed syntax / SQL injection characters",
                "trust_boundary_crossed": bi("內部錯誤日誌流到外部 HTTP 回應", "Internal error logs to external HTTP response"),
                "severity": "MEDIUM",
                "attack_scenario": bi("送出格式錯誤的酬載，並檢查 HTTP 回應本文是否含有追蹤記錄。",
                                      "Send malformed payload and inspect HTTP response body for tracebacks."),
                "test_verification_goal": bi("確認回應只含一般性的錯誤訊息，沒有檔案路徑或 SQL 關鍵字。",
                                             "Ensure response contains generic error message without file paths or SQL keywords.")
            }
        ]
    }
