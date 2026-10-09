"""雙語輸出（中文 ／ English）：原因字串與報告欄位是雙語，模型提示詞維持純英文。
Bilingual output (Chinese / English): reason strings and report-bound fields are bilingual while
every prompt sent to a model stays English-only."""
import json
import os

from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
from vibeharness.agents.whitebox.ai_static_scanner import RULES
from vibeharness.agents.whitebox.debater import MultiModelDebater
from vibeharness.agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.core.i18n import SEP, en_only, has_cjk
from vibeharness.core.llm_gateway import LLMGateway, REASON_NOT_VALID_JSON, _RETRY_SUFFIX
from vibeharness.core.models import (
    CodeSymbol, FindingSeverity, GeneratedTest, ReviewFinding, STRIDECategory, TestStatus, ThreatItem,
)
from vibeharness.runners.test_executor import (
    POC_HEADER_JS, POC_HEADER_PY, REASON_NOT_RUN_CORRECTLY, REASON_TARGET_BROKEN, TestSuiteExecutor,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")


def _bilingual(text: str) -> bool:
    """中文在前、英文在後，以全形斜線分隔。Chinese first, English second, joined by the full-width slash."""
    zh, sep, en = text.partition(SEP)
    return bool(sep) and has_cjk(zh) and not has_cjk(en)


# --- 重試提示詞 --------------------------------------------------------------------------------
# --- Retry prompt -------------------------------------------------------------------------------

def test_retry_prompt_built_from_a_bilingual_reason_has_no_cjk(fake_live):
    assert _bilingual(REASON_NOT_VALID_JSON)
    prompts = []
    answers = iter(["not json at all", json.dumps({"findings": []})])

    def responder(system, user):
        prompts.append(user)
        return next(answers)

    fake_live(responder)
    gw = LLMGateway(CONFIG, execution_mode="live")
    resp = gw.generate("whitebox_reviewer_claude", "sys", "audit this", required_keys=["findings"])
    assert gw.is_usable(resp)
    assert len(prompts) == 2 and prompts[1].startswith("audit this")
    assert "could not be used (response is not valid JSON)" in prompts[1]
    assert not has_cjk(prompts[1])
    # 即使提示詞只帶了英文那一半，登記的原因仍維持雙語
    # The booked reason stays bilingual even though the prompt only carried its English half
    assert gw.call_log[0].mode == "retried" and _bilingual(gw.call_log[0].reason)
    # 無論格式化進去的原因為何，範本本身永遠不含 CJK
    # The template itself never contains CJK, whatever reason is formatted into it
    assert not has_cjk(_RETRY_SUFFIX.format(reason=en_only(REASON_NOT_VALID_JSON)))


# --- 代理的提示詞維持英文 -----------------------------------------------------------------------
# --- Agent prompts stay English ---------------------------------------------------------------------

def _finding(fid="WB-CLA-01", model="claude"):
    return ReviewFinding(
        finding_id=fid, reviewer_name="Claude", model_alias=model, file_path="app.py", symbol_name="f",
        severity=FindingSeverity.HIGH, title="None crash", description="d", root_cause="r",
        suspected_vibe_flaw="s", suggested_test_scenario="call f(None)",
    )


def _threat():
    return ThreatItem(
        threat_id="T1", stride_category=STRIDECategory.TAMPERING, title="Mass assignment", description="",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="send is_admin", test_verification_goal="is_admin stays false",
    )


def test_agent_system_prompts_contain_no_cjk(fake_live, tmp_path):
    # 審查者的預設值（名稱／焦點）是雙語：提示詞仍必須只含英文
    # Reviewer defaults (name / focus) are bilingual: the prompt must still carry English only
    prompts = []

    def responder(system, user):
        prompts.append((system, user))
        if '"verdicts"' in system:
            return json.dumps({"verdicts": []})
        if '"threats"' in system:
            return json.dumps({"threats": []})
        if '"findings"' in system:
            return json.dumps({"findings": []})
        return json.dumps({"tests": [], "code": "def test_x():\n    assert True\n"})

    fake_live(responder)
    (tmp_path / "svc.py").write_text("def f(x):\n    return x.y\n", encoding="utf-8")
    symbols = [CodeSymbol(name="f", symbol_type="function", file_path=str(tmp_path / "svc.py"),
                          line_start=1, line_end=2, signature="def f(x)", source_code="def f(x):\n    return x.y\n")]

    gw = LLMGateway(CONFIG, execution_mode="live")
    reviewer = HeterogeneousReviewerEnsemble(gw)
    for r in reviewer.reviewer_agents:  # 強制讓雙語預設值走進提示詞路徑 ／ force the bilingual defaults into the prompt path
        r["name"] = "審查者（x） ／ Reviewer (x)"
        r["focus"] = "一般正確性與安全缺陷 ／ General correctness and security defects"
    reviewer.review_symbols(symbols, root_dir=str(tmp_path))
    MultiModelDebater(gw).arbitrate([_finding(), _finding("WB-DEE-01", "deepseek")], symbols, str(tmp_path))
    WhiteboxTestGenerator(gw).generate_tests_for_findings([_finding()], symbols, root_dir=str(tmp_path))
    AutomatedThreatModeler(gw).model_system("desc", ["/api/users"], symbols=symbols, root_dir=str(tmp_path))
    ThreatScenarioBuilder(gw).build_test_cases_from_threats([_threat()], base_url=None)

    assert len(prompts) >= 5
    kinds = {"findings", "verdicts", "threats", "tests", "code"}
    seen = {k for system, _ in prompts for k in kinds if f'"{k}"' in system}
    assert {"findings", "verdicts", "threats"} <= seen and ({"tests", "code"} & seen)
    for system, user in prompts:
        assert not has_cjk(system), system[:200]
        assert not has_cjk(user), user[:200]
    reviewer_prompts = [s for s, _ in prompts if "white-box AI code auditor" in s]
    assert reviewer_prompts and all("You are Reviewer (x)," in s for s in reviewer_prompts)
    assert all("Your primary focus: General correctness and security defects." in s for s in reviewer_prompts)


# --- AI 靜態掃描器規則目錄 ----------------------------------------------------------------------
# --- AI static scanner rule catalogue ----------------------------------------------------------------

def test_rules_titles_are_bilingual_and_evidence_stays_ascii(tmp_path):
    from vibeharness.agents.whitebox.ai_static_scanner import AISecurityStaticScanner
    assert len(RULES) == 9
    for rule_id, rule in RULES.items():
        assert rule_id.isascii() and rule["severity"].isascii() and rule["owasp"].isascii()
        assert rule["atlas"].isascii() and rule["cwe"].isascii()
        assert _bilingual(rule["title"]), rule_id
        assert _bilingual(rule["remediation"]), rule_id
    src = tmp_path / "ai.py"
    src.write_text(
        "import pickle\nfrom transformers import AutoModel\n"
        "m = AutoModel.from_pretrained('acme/llm-7b', trust_remote_code=True)\n"
        "obj = pickle.loads(open('x.bin', 'rb').read())\n",
        encoding="utf-8",
    )
    findings = AISecurityStaticScanner().scan_files([str(src)])
    assert findings
    for f in findings:
        assert _bilingual(f.title) and _bilingual(f.remediation)
        assert f.evidence.isascii(), f.evidence  # 指紋的輸入：永不翻譯 ／ fingerprint input: never translated
        assert f.rule_id.isascii()


# --- 執行器結果 --------------------------------------------------------------------------------
# --- Executor results --------------------------------------------------------------------------------

class _FailingSandbox:
    """一個 Python 批次：唯一的模組在斷言上失敗，第二個模組則在匯入目標時出錯
    （因此 FAILED 與 ERROR 兩種原因都會產生）。
    A Python batch whose only module failed on an assertion, with a second module that errored
    while importing the target (so both FAILED and ERROR reasons are produced)."""
    timeout_seconds = 30

    def execute_pytest_files(self, files, **kw):
        junit = (
            "<testsuites><testsuite>"
            "<testcase classname='test_vh_000' name='test_a' time='0.1'>"
            "<failure message='AssertionError: boundary breached'>def test_a():\n&gt;       assert False\n"
            "E       AssertionError: boundary breached\n\ntest_vh_000.py:5: AssertionError</failure></testcase>"
            "<testcase classname='test_vh_001' name='test_b' time='0.1'>"
            "<error message='collection failure'>svc.py:1: in &lt;module&gt;\n"
            "    import nonexistent_pkg_xyz\nE   ModuleNotFoundError: No module named 'nonexistent_pkg_xyz'</error>"
            "</testcase>"
            "</testsuite></testsuites>"
        )
        return 0, "", "", 0.2, None, junit


def test_failed_executor_result_reason_and_poc_are_bilingual(tmp_path):
    executor = TestSuiteExecutor(sandbox=_FailingSandbox())
    tests = [
        GeneratedTest(test_id="BB-1", test_type="blackbox_security", target_component="svc.f",
                      title="BOLA probe", code="def test_a():\n    assert False\n", rationale="r",
                      expected_outcome="e", source_ref="T1"),
        GeneratedTest(test_id="WB-1", test_type="whitebox_unit", target_component="svc.f",
                      title="import probe", code="import svc\n\ndef test_b():\n    assert svc\n", rationale="r",
                      expected_outcome="e", source_ref="WB-CLA-01"),
    ]
    results, _ = executor.execute_test_suite(tests, working_dir=str(tmp_path))
    exploit, broken = results

    assert exploit.status == TestStatus.FAILED and exploit.is_security_exploit_confirmed
    # 原始的斷言摘要是資料，原樣回報
    # A raw assertion summary is data and is reported as-is
    assert exploit.failure_reason == "AssertionError: boundary breached"
    poc = exploit.reproduction_poc
    assert poc.startswith(POC_HEADER_PY) and "# === 重現 PoC ／ Reproduction PoC ===" in poc
    assert "# 目標 ／ Target: svc.f" in poc
    assert "# 失敗情境 ／ Failure Context: BOLA probe" in poc
    assert "# 測試函式 ／ Test Function: test_a" in poc
    assert "# 測試程式碼 ／ Test Code:\ndef test_a():" in poc
    assert POC_HEADER_JS == "// === 重現 PoC ／ Reproduction PoC ==="

    assert broken.status == TestStatus.ERROR
    assert broken.failure_reason.startswith(REASON_TARGET_BROKEN)
    assert _bilingual(REASON_TARGET_BROKEN) and _bilingual(REASON_NOT_RUN_CORRECTLY)
    assert en_only(REASON_TARGET_BROKEN) == "Target code is broken and was never exercised by this test"
    assert en_only(REASON_NOT_RUN_CORRECTLY) == "Test could not run correctly"
    assert "nonexistent_pkg_xyz" in broken.failure_reason  # 原始例外文字保留在標籤之後 ／ the raw exception text is kept after the label


def test_assertion_fallback_and_js_runner_reasons_are_bilingual(tmp_path):
    executor = TestSuiteExecutor(sandbox=_FailingSandbox())  # 未設定 JS 執行器 ／ no JS runner configured
    js = GeneratedTest(test_id="J", test_type="whitebox_unit", target_component="m", title="js",
                       code="import { test } from 'node:test';\ntest('x', () => {});\n", rationale="r",
                       expected_outcome="e", source_ref="x", language="javascript")
    results, _ = executor.execute_test_suite([js], working_dir=str(tmp_path))
    reason = results[0].failure_reason
    assert results[0].status == TestStatus.ERROR
    assert has_cjk(reason) and "JavaScript/TypeScript test was not run" in reason
    assert "no JavaScript/TypeScript runner is configured" in reason

    # 沒有任何訊息的斷言失敗，會退回成一句指出測試名稱的雙語句子
    # An assertion failure without any message falls back to a bilingual sentence naming the test
    fallback = executor._aggregate(
        GeneratedTest(test_id="X", test_type="whitebox_unit", target_component="c", title="my case",
                      code="def test_x():\n    assert False\n", rationale="r", expected_outcome="e", source_ref="s"),
        "X", [{"name": "test_x", "time": 0.0, "outcome": "failure", "message": "", "details": "", "stdout": "", "stderr": ""}],
    )
    assert fallback.failure_reason == "於 my case 期間斷言失敗 ／ Assertion failed during my case"


def test_bilingual_data_fields_reach_live_prompts_in_english_only(fake_live, tmp_path):
    """hybrid 模式下模擬引擎的雙語發現／威脅會當作資料進入 live 的驗證者、測試生成與攻擊合成提示詞：只送英文半。
    In hybrid mode the simulation engine's bilingual findings / threats reach the live verifier, test-generation and
    attack-synthesis prompts as data: only the English half is sent."""
    import json
    from vibeharness.agents.whitebox.debater import MultiModelDebater
    from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
    from vibeharness.core.llm_gateway import LLMGateway
    from vibeharness.core.models import FindingSeverity, ReviewFinding, STRIDECategory, ThreatItem

    (tmp_path / "svc.py").write_text("def login(user, password):\n    return user\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    prompts = []

    def responder(system, user):
        prompts.append(user)
        if "verdicts" in system:
            return json.dumps({"verdicts": [{"index": 0, "verdict": "confirm", "reason": "ok"}]})
        return json.dumps({"tests": []})
    fake_live(responder)
    gateway = LLMGateway(CONFIG, execution_mode="live")
    finding = ReviewFinding(
        finding_id="WB-SIM-01", reviewer_name="r", model_alias="claude", file_path=str(tmp_path / "svc.py"),
        symbol_name="login", severity=FindingSeverity.HIGH, title=SEP.join(["密碼回傳", "Password echoed"]),
        description=SEP.join(["描述", "Description"]), root_cause=SEP.join(["根因", "Root cause"]),
        suspected_vibe_flaw="", suggested_test_scenario=SEP.join(["情境", "Scenario"]),
    )
    MultiModelDebater(gateway).arbitrate([finding])
    WhiteboxTestGenerator(gateway).generate_tests_for_findings([finding], symbols, root_dir=str(tmp_path))
    threat = ThreatItem(
        threat_id="THREAT-01", stride_category=STRIDECategory.SPOOFING, title=SEP.join(["標題", "Title"]),
        description="", asset_at_risk="a", attack_vector=SEP.join(["呼叫 login", "call login"]),
        trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario=SEP.join(["攻擊 login", "attack login"]), test_verification_goal=SEP.join(["目標", "goal"]),
    )
    ThreatScenarioBuilder(gateway).build_test_cases_from_threats([threat], base_url=None, symbols=symbols,
                                                                  root_dir=str(tmp_path))
    assert len(prompts) >= 3
    for user in prompts:
        assert not has_cjk(user), user[:200]
        assert "Password echoed" in user or "attack login" in user or "login" in user
