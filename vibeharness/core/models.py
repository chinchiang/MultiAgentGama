from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


def text_or(value: object, default: str) -> str:
    """來自模型輸出的自由文字欄位：非空白字串直接通過，其他任何值（None、數字、
    物件、空白）都變成預設值。單靠 `dict.get(key, default)` 並不夠，因為
    模型回答 `"title": null` 會得到 None，而這些 str 型別的模型隨後會拒絕它。
    A free-text field from model output: non-blank strings pass, anything else (None, numbers,
    objects, blank) becomes the default. `dict.get(key, default)` alone is not enough, because a
    model answering `"title": null` yields None, which these str-typed models then reject."""
    return value if isinstance(value, str) and value.strip() else default


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class TestStatus(str, Enum):
    __test__ = False
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class CodeSymbol(BaseModel):
    """從 AST 擷取出的函式、方法或類別符號。
    Extracted function, method, or class symbol from AST."""
    name: str
    symbol_type: str  # 符號類型："function"、"class"、"method"、"route" ／ "function", "class", "method", "route"
    file_path: str
    line_start: int
    line_end: int
    signature: str
    docstring: Optional[str] = None
    source_code: str
    parameters: List[str] = Field(default_factory=list)
    return_type: Optional[str] = None


class VerificationVote(BaseModel):
    """某個模型對一個它自己沒有回報的發現所做的獨立裁決。
    One model's independent ruling on a finding it did not report."""
    model_alias: str
    verdict: str  # "confirm"、"reject"、"unsure" 或 "corroborated"（該模型自己也回報了同一個缺陷） ／ "confirm", "reject", "unsure", or "corroborated" (the model reported the same defect itself)
    reason: str = ""


class ReviewFinding(BaseModel):
    """由特定 LLM 審查者指出的觀察或潛在錯誤。
    An observation or potential bug identified by a specific LLM reviewer."""
    finding_id: str
    reviewer_name: str
    model_alias: str
    file_path: str
    symbol_name: Optional[str] = None
    line_number: Optional[int] = None
    severity: FindingSeverity
    title: str
    description: str
    root_cause: str
    suspected_vibe_flaw: str
    suggested_test_scenario: str
    owasp_mapping: Optional[str] = None  # 審查者給的選填分類法 id，例如 "LLM01:2026" ／ optional taxonomy id from the reviewer, e.g. "LLM01:2026"
    is_simulated: bool = False  # 由離線模擬引擎產生、而非真實模型時為 True ／ True when produced by the offline simulation engine, not a real model
    # 重複的回報被合併進這個發現時設定：其他審查者及其發現 id
    # Set when duplicate reports were merged into this finding: the other reviewers and their finding ids
    corroborated_by: List[str] = Field(default_factory=list)
    corroborating_models: List[str] = Field(default_factory=list)  # corroborated_by 對應的模型別名 ／ model aliases of corroborated_by
    merged_finding_ids: List[str] = Field(default_factory=list)
    verification_votes: List[VerificationVote] = Field(default_factory=list)


class MultiModelDebateResult(BaseModel):
    """跨模型驗證的結果：每個發現都由沒有回報它的模型裁決。
    Outcome of cross-model verification: every finding is ruled on by models that did not report it."""
    confirmed_findings: List[ReviewFinding] = Field(default_factory=list)
    disputed_findings: List[ReviewFinding] = Field(default_factory=list)
    consensus_summary: str
    # 平手投票下仍保留供測試的發現（它們在 confirmed_findings 裡，但「不是」
    # 多數確認；「已確認」的統計必須扣掉這個數字，與 consensus_summary 一致）
    # Findings kept for testing despite a tie vote (they are in confirmed_findings but are NOT
    # majority-confirmed; "confirmed" statistics must subtract this, matching consensus_summary)
    undecided_count: int = 0
    # 與最終決定一致的決定性投票（confirm／reject／corroborated）所占比例；沒有投票時為 None
    # Share of decisive votes (confirm / reject / corroborated) that match the final decision; None without votes
    model_agreement_ratio: Optional[float] = None
    arbitration_applied: bool = False  # False：沒有任何真實的驗證者投票，發現未經過濾 ／ False: no real verifier vote was cast, findings are unfiltered
    is_simulated: bool = False


class ThreatItem(BaseModel):
    """黑箱威脅建模階段產出的威脅項目。
    A threat item produced during the Black-box Threat Modeling phase."""
    threat_id: str
    stride_category: STRIDECategory
    owasp_mapping: Optional[str] = None
    atlas_mapping: Optional[str] = None  # MITRE ATLAS 技術 id，例如 "AML.T0051.001" ／ MITRE ATLAS technique id(s), e.g. "AML.T0051.001"
    title: str
    description: str
    asset_at_risk: str
    attack_vector: str
    trust_boundary_crossed: str
    severity: FindingSeverity
    attack_scenario: str
    test_verification_goal: str
    # 由離線模擬引擎產生時為 True：其標題／攻擊向量是 `bi()` 雙語字串，進指紋時只取英文半
    # True when produced by the offline simulation engine: its title / attack vector are bilingual `bi()` strings
    # and contribute their English half to fingerprints
    is_simulated: bool = False


class ThreatModelReport(BaseModel):
    """受測系統的整合威脅模型。
    Consolidated threat model of the system under test."""
    system_description: str
    entrypoints: List[str] = Field(default_factory=list)
    trust_boundaries: List[str] = Field(default_factory=list)
    assets: List[str] = Field(default_factory=list)
    threats: List[ThreatItem] = Field(default_factory=list)
    is_simulated: bool = False


class GeneratedTest(BaseModel):
    """白箱或黑箱代理產生的可執行測試規格。
    Specification of an executable test generated by white-box or black-box agents."""
    test_id: str
    test_type: str  # 測試類型："whitebox_unit"、"whitebox_probe"（確定性的 None 輸入健壯性探針）或 "blackbox_security" ／ "whitebox_unit", "whitebox_probe" (deterministic None-input robustness probe) or "blackbox_security"
    target_component: str
    title: str
    code: str
    rationale: str
    expected_outcome: str
    source_ref: Optional[str] = None  # 這個測試衍生自的 finding_id／threat_id／符號 ／ finding_id / threat_id / symbol this test was derived from
    # "python" | "javascript" | "typescript"：決定程式碼閘門、沙盒與報告的程式碼圍欄
    # "python" | "javascript" | "typescript": picks the code gate, the sandbox and the report fence
    language: str = "python"


class TestExecutionResult(BaseModel):
    __test__ = False
    """執行單一個產生的測試的結果。
    Outcome of running an individual generated test."""
    test_id: str
    test_type: str
    status: TestStatus
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    traceback: Optional[str] = None
    failure_reason: Optional[str] = None
    is_security_exploit_confirmed: bool = False
    reproduction_poc: Optional[str] = None
    source_ref: Optional[str] = None
    language: str = "python"

    @property
    def is_failure(self) -> bool:
        """測試狀態是 FAILED（白箱失敗就是 FAILED 的白箱測試；黑箱的 FAILED 再分成資安突破與未分類失敗）。
        The test FAILED (a white-box failure is a FAILED white-box test; a black-box FAILED is either a Breach or an
        Unclassified failure)."""
        return self.status == TestStatus.FAILED

    @property
    def is_not_run(self) -> bool:
        """未執行（GLOSSARY）：狀態是 ERROR 或 SKIPPED；不算已執行的證據。
        Not run (GLOSSARY): the status is ERROR or SKIPPED; it is not Executed evidence."""
        return self.status in (TestStatus.ERROR, TestStatus.SKIPPED)

    @property
    def is_unclassified_failure(self) -> bool:
        """未分類失敗（GLOSSARY）：FAILED 但不是資安突破；它是證據缺口，絕不能被略過。
        Unclassified failure (GLOSSARY): FAILED but not a Breach; it is an Evidence gap and is never dropped."""
        return self.is_failure and not self.is_security_exploit_confirmed


class CallKind(str, Enum):
    """是哪一種模型呼叫：代理在宣告與計畫上標明，閘道把它寫進每一筆呼叫紀錄（JSON 報告的 agent_calls[].kind）；
    `--estimate` 依它查每次呼叫的提示額外負擔與典型回答大小。值是對外契約，改名要升 schema_version。
    Which kind of model call this is: agents mark it on their declarations and plans, and the gateway writes it into
    every call record (agent_calls[].kind in the JSON report); `--estimate` looks up each call's prompt overhead and
    typical answer size by it. The values are a public contract: renaming one bumps schema_version."""
    REVIEWER = "reviewer"
    VERIFIER = "verifier"
    TEST_GENERATOR = "test_generator"
    HEAL = "heal"
    THREAT_MODELER = "threat_modeler"
    SYNTHESIZER = "synthesizer"


class AgentCallRecord(BaseModel):
    """透過 LLM 閘道進行的單次代理呼叫的來源紀錄。
    Provenance of a single agent invocation through the LLM gateway."""
    agent_id: str
    model_alias: str
    model_name: str
    mode: str  # "live"、"simulated"、"invalid"（真實呼叫但輸出無法使用）或 "retried"（無法使用而被重新詢問的嘗試） ／ "live", "simulated", "invalid" (live call whose output was unusable) or "retried" (an unusable attempt that was re-asked)
    reason: Optional[str] = None  # 為何使用模擬／為何輸出被拒絕 ／ why simulation was used / why the output was rejected
    # 實際送出的 system+user 提示詞的 SHA-256，讓稽核能把判定連回它的輸入，
    # 而報告不必儲存（可能敏感的）目標程式碼
    # SHA-256 of the exact system+user prompt sent, so an audit can tie a verdict to its inputs
    # without the report having to store (possibly sensitive) target code
    prompt_sha256: Optional[str] = None
    # 答案來自磁碟上的回應快取（真實模型先前對同一提示詞的回答）時為 True，
    # 因此這次沒有呼叫供應商
    # True when the answer came from the on-disk response cache (a real model's earlier answer to the
    # same prompt), so no provider call was made for it
    cached: bool = False
    # 同一次邏輯呼叫的第幾次詢問（0 = 第一次；重新詢問為 1、2……）：sorted_call_log 以（代理、原始提示 SHA、attempt）
    # 排序，同一次呼叫的 "retried" 一定排在最後的 "live"／"invalid" 之前，而且與執行緒完成順序無關
    # Which ask of the same logical call this is (0 = the first; re-asks are 1, 2, ...): sorted_call_log orders by
    # (agent, original prompt SHA, attempt), so a call's "retried" entries always precede its final "live" /
    # "invalid" one, independent of thread completion order
    attempt: int = 0
    # 這次呼叫的種類（代理宣告的）；直接呼叫 generate 而沒有給 kind 時為 None
    # This call's kind (as the agent declared it); None when generate is called directly without one
    kind: Optional[CallKind] = None


class StaticFinding(BaseModel):
    """確定性規則的命中（不涉及模型），例如不安全的模型成品載入，或
    埋在目標中、針對審查者的提示注入。
    A deterministic rule hit (no model involved), e.g. an unsafe model-artifact load or a
    reviewer-directed prompt injection planted in the target."""
    rule_id: str
    title: str
    severity: FindingSeverity
    file_path: str
    line_number: int
    evidence: str = ""
    remediation: str = ""
    owasp_mapping: Optional[str] = None
    atlas_mapping: Optional[str] = None
    cwe: Optional[str] = None
    # 命中會動搖模型驅動階段本身的可信度時為 True
    # （針對 harness 的提示注入、不可見字元）：這是一個證據缺口
    # True when the hit undermines the trustworthiness of the model-driven phases themselves
    # (prompt injection aimed at the harness, invisible characters): it is an evidence gap
    affects_review_integrity: bool = False


class RunMetadata(BaseModel):
    """產生這份報告的是什麼：日後讀取報告時，需要靠它把判定對應回 harness 版本、
    模式與目標的修訂版本（稽核軌跡）。
    What produced this report: needed to tie a verdict back to a harness version, a mode and a
    revision of the target when the report is read later (audit trail)."""
    generated_at: str  # ISO 8601 格式，UTC 時區 ／ ISO 8601, UTC
    harness_version: str
    execution_mode: str  # live／hybrid／mock 三者之一 ／ live / hybrid / mock
    config_path: str
    sandbox_provider: str
    target_path: str
    target_git_commit: Optional[str] = None  # 包含目標的版本庫的 HEAD（若有） ／ HEAD of the repository containing the target, if any
    target_git_dirty: Optional[bool] = None  # 執行時目標底下有未提交的變更 ／ uncommitted changes under the target at run time
    file_filters: List[str] = Field(default_factory=list)  # 實際套用的 include／exclude／changed-since ／ include/exclude/changed-since actually applied
    mutation_enabled: Optional[bool] = None  # 突變測試最終是否開啟 ／ whether mutation testing ended up on
    mutation_source: Optional[str] = None  # 開關的來源：cli／config／default ／ where the switch came from: cli / config / default
    node_runtime: Optional[str] = None  # 例如 JS/TS 測試有執行時為 "node v22.22.0"，否則為 None ／ e.g. "node v22.22.0" when JS/TS tests ran, else None


class MutantResult(BaseModel):
    """一個變異體的結果：改了哪一行、改成什麼，以及測試有沒有抓到。
    The result of one mutant: which line changed, what it became and whether the tests caught it."""
    file: str  # 相對於目標目錄的檔案 ／ file relative to the target directory
    line: int
    operator: str  # 運算子類別 ／ operator class: arithmetic／comparison／boolean／negation／constant
    symbol: str = ""
    original: str  # 變異前的該行（去除前後空白） ／ the line before the change (stripped)
    mutated: str  # 變異後的該行（去除前後空白） ／ the line after the change (stripped)
    status: str  # "killed"（有測試失敗或逾時）、"survived"（全部通過）、"invalid"（程式壞到無法判斷） ／ "killed" (a test failed or timed out), "survived" (all passed), "invalid" (broke the code beyond judging)


class MutationReport(BaseModel):
    """突變測試的整體結果；`score` 是下界（等價變異體算成存活）。
    The overall mutation-testing result; `score` is a lower bound (equivalent mutants count as survivors)."""
    enabled: bool = True
    score: Optional[float] = None  # killed / (killed + survived)，百分比 ／ killed / (killed + survived) as a percentage
    total: int = 0
    killed: int = 0
    survived: int = 0
    invalid: int = 0
    candidate_sites: int = 0  # 符號內所有可變異的位置 ／ every mutable spot in the covered symbols
    truncated: bool = False  # 候選位置超過 mutation_max_mutants，分數只是樣本 ／ candidates exceeded mutation_max_mutants, the score is a sample
    eligible_tests: int = 0
    skipped_reason: Optional[str] = None  # 沒有執行或沒有結論的原因 ／ why nothing ran or nothing was concluded
    mutants: List[MutantResult] = Field(default_factory=list)


class VibeHarnessSummary(BaseModel):
    """由 Commander Harness 產出的最上層評估摘要。
    Top-level assessment summary produced by the Commander Harness."""
    # Verdict 的值之一（core/verdict.py）；維持 str，無法辨識的狀態才能由 cli 以失敗收場，而不是在建構時就被拒絕
    # One of the Verdict values (core/verdict.py); kept a str so the cli can fail closed on an unrecognized status
    # instead of rejecting it at construction
    overall_status: str
    run: Optional[RunMetadata] = None
    total_whitebox_findings: int  # 審查者的原始回報數，合併重複之前 ／ raw reviewer reports, before duplicates are merged
    distinct_whitebox_findings: Optional[int] = None
    # 沒有套用跨模型驗證時為 None（JSON 為 null）：沒有任何發現被確認，0 會被誤讀成「沒有缺陷」
    # None (null in JSON) when cross-model verification was not applied: nothing was confirmed, and 0 would
    # misread as "no flaws"
    confirmed_whitebox_bugs: Optional[int]
    whitebox_tests_passed: int
    whitebox_tests_failed: int
    whitebox_tests_errored: int = 0
    total_threats_modeled: int
    critical_threats_count: int
    blackbox_tests_passed: int
    blackbox_security_breaches: int
    # 失敗卻不符合利用判斷式的攻擊測試：證據模稜兩可，
    # 必須人工調查；計為證據缺口（絕不是默默通過）
    # Attack tests that FAILED without matching the exploit predicate: ambiguous evidence that
    # must be investigated manually; counts as an evidence gap (never a silent pass)
    blackbox_tests_failed: int = 0
    blackbox_tests_errored: int = 0
    untested_threat_ids: List[str] = Field(default_factory=list)
    agent_calls: List[AgentCallRecord] = Field(default_factory=list)
    inconclusive_reasons: List[str] = Field(default_factory=list)
    # 白箱測試的行涵蓋率：line_coverage_pct 只代表 Python（pytest-cov），js_line_coverage_pct 是 JS/TS（Node 內建涵蓋率，
    # 只計入載入過的目標檔案，見 jscoverage）；沒有收集或收集不到時為 None
    # White-box line coverage: line_coverage_pct means Python only (pytest-cov), js_line_coverage_pct is JS/TS (Node's
    # built-in coverage, loaded target files only, see jscoverage); None when not collected or not collectable
    line_coverage_pct: Optional[float] = None
    js_line_coverage_pct: Optional[float] = None
    # 突變測試（--mutation）的結果；沒有啟用時為 None ／ the --mutation result; None when it is off
    mutation: Optional[MutationReport] = None
    detected_language: str = "Python"
    static_findings: List[StaticFinding] = Field(default_factory=list)
    # 目標匯入的 AI/LLM SDK；非空時會啟用 OWASP LLM Top 10 威脅建模
    # AI/LLM SDKs the target imports; non-empty switches on OWASP LLM Top 10 threat modeling
    ai_components: List[str] = Field(default_factory=list)
    reviewer_models: List[str] = Field(default_factory=list)
    key_recommendations: List[str] = Field(default_factory=list)
    # 計入判定結果的阻擋性規則命中（HIGH 以上）數；有 --baseline 時只算新的。不是品質閘門產生的摘要為 None
    # Blocking rule hits (HIGH and above) counted toward the verdict; only the new ones with --baseline. None for a
    # summary the quality gate did not produce
    new_blocking_rule_hits: Optional[int] = None
    # --baseline：先前報告已包含的問題列在這裡，且不計入判定（whitebox_tests_failed／
    # blackbox_security_breaches／new_blocking_rule_hits 只含新的問題）
    # --baseline: problems the previous report already contained are listed here and not counted
    # in the verdict (whitebox_tests_failed / blackbox_security_breaches / new_blocking_rule_hits hold new ones only)
    baseline_path: Optional[str] = None
    baseline_suppressed: List["BaselineSuppressedItem"] = Field(default_factory=list)


class BaselineSuppressedItem(BaseModel):
    kind: str  # 種類："breach" | "whitebox_failure" | "static" ／ "breach" | "whitebox_failure" | "static"
    id: str
    title: str
    fingerprint: str


VibeHarnessSummary.model_rebuild()
