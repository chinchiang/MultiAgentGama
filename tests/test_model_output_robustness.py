"""回歸測試：格式錯誤的模型輸出會優雅降級，且探針退回機制會被揭露。
Regression tests: malformed model output degrades gracefully, and probe fallback is disclosed."""
import json
import os
import threading

import pytest

from model_answers import answer as model_answer
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.i18n import bi, en_only, has_cjk
from vibeharness.core.models import (
    AgentCallRecord,
    CodeSymbol,
    FindingSeverity,
    MultiModelDebateResult,
    ReviewFinding,
    STRIDECategory,
    TestExecutionResult,
    TestStatus,
    ThreatItem,
    ThreatModelReport,
    VibeHarnessSummary,
)
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from vibeharness.agents.whitebox.debater import MultiModelDebater
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler, DEFAULT_TRUST_BOUNDARIES, DEFAULT_ASSETS
from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
from vibeharness.reports.report_generator import ReportGenerator
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.model_output import ANY, OutputSchema

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")


def _finding(fid="A", model="claude"):
    return ReviewFinding(
        finding_id=fid, reviewer_name=model.title(), model_alias=model, file_path="app.py", symbol_name="f",
        severity=FindingSeverity.HIGH, title=f"title {fid}", description="", root_cause="",
        suspected_vibe_flaw="", suggested_test_scenario=""
    )


def _threat():
    return ThreatItem(
        threat_id="T1", stride_category=STRIDECategory.TAMPERING, title="t", description="",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="", test_verification_goal=""
    )


# --- 威脅建模器：格式錯誤的輸出必須降級，不得讓管線當機 -----------------------------------
# --- Threat modeler: malformed output must degrade, not crash the pipeline -----------------------

def test_malformed_threat_entries_are_skipped():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: model_answer(
        {"threats": ["BOLA", 7, {"threat_id": "T1", "stride_category": "Tampering"}]})
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"])
    assert [t.threat_id for t in report.threats] == ["T1"]


def test_non_list_threats_and_string_list_fields_fall_back():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: model_answer({
        "threats": {"threat_id": "T1"},  # 物件而非清單 ／ object instead of a list
        "system_description": 42,
        "entrypoints": "not a list",
        "trust_boundaries": [1, 2],
        "assets": "db",
    })
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"])
    assert report.threats == []
    assert report.system_description == "desc"
    assert report.entrypoints == ["/api/users"]
    assert report.trust_boundaries == DEFAULT_TRUST_BOUNDARIES
    assert report.assets == DEFAULT_ASSETS


def _big_symbol(name, lines=500):
    return CodeSymbol(
        name=name, symbol_type="function", file_path="app.py", line_start=1, line_end=lines,
        signature=f"{name}()", source_code=f"def {name}():\n" + "    value = 'payload token filler line'\n" * lines
    )


def test_large_targets_are_threat_modeled_in_batches():
    """每個符號都必須讓威脅建模器看得到：和審查者一樣，符號會分批，
    單一提示詞的 token 上限不能再悄悄丟掉目標的大部分內容。
    Every symbol must be visible to the threat modeler: like the reviewers, symbols are
    batched so a single-prompt token cap can no longer silently drop most of the target."""
    gw = LLMGateway(CONFIG, execution_mode="mock")
    prompts = []
    state = {"n": 0}
    # 批次會並行執行：計數要上鎖，否則兩個批次可能拿到同一個標題而被合併
    # batches run concurrently: the counter takes a lock, or two batches could get the same title and be merged
    lock = threading.Lock()

    def responder(agent_id, system_prompt, user_prompt, **k):
        with lock:
            state["n"] += 1
            n = state["n"]
            prompts.append(user_prompt)
        # 每個批次都回報相同且衝突的 threat_id，以證明重新編號有效
        # every batch reports the same colliding threat_id to prove renumbering works
        return model_answer({
            "threats": [{"threat_id": "THREAT-01", "stride_category": "Tampering", "title": f"t{n}"}],
            "entrypoints": ["/api/batch"],
        })

    gw.generate = responder
    symbols = [_big_symbol(f"f{i}") for i in range(30)]
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"], symbols=symbols, root_dir=".")
    assert state["n"] > 1  # 確實有分批 ／ batching actually happened
    # 每個符號恰好出現在一個批次提示詞中：沒有省略，也沒有重複
    # every symbol is shown in exactly one batch prompt: nothing omitted, nothing duplicated
    shown = [sym for p in prompts for sym in symbols if f"Symbol: {sym.name} " in p]
    assert sorted(s.name for s in shown) == sorted(s.name for s in symbols)
    # 衝突的模型威脅 id 會重新編號成唯一且確定性的序列
    # colliding model threat ids are renumbered into a unique, deterministic sequence
    assert [t.threat_id for t in report.threats] == [f"THREAT-{i:02d}" for i in range(1, state["n"] + 1)]
    # 報告層級的欄位來自第一個可用的批次，而非最後一個
    # report-level fields come from the first usable batch, not the last
    assert report.entrypoints == ["/api/batch"]


def test_invalid_batch_does_not_kill_threat_modeling():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    responses = [
        model_answer(mode="invalid", reason="bad json"),
        model_answer({"threats": [{"threat_id": "THREAT-01", "stride_category": "Tampering", "title": "later"}],
                      "entrypoints": ["/api/valid"]}),
    ]

    def responder(*a, **k):
        return responses.pop(0)

    gw.generate = responder
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"], symbols=[_big_symbol("a"), _big_symbol("b")], root_dir=".")
    # 批次 1 無法使用，批次 2 仍貢獻了它的威脅與報告層級欄位
    # batch 1 was unusable, batch 2 still contributed its threat and the report-level fields
    assert [t.threat_id for t in report.threats] == ["THREAT-01"]
    assert report.entrypoints == ["/api/valid"]


def test_wrong_typed_threat_fields_are_coerced_not_fatal():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: model_answer({"threats": [{
        "threat_id": "T1", "severity": None, "owasp_mapping": {"id": "API1"}, "title": 42,
        "attack_vector": ["PUT"], "stride_category": "Not-A-STRIDE-Category",
    }]})
    t = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"]).threats[0]
    assert t.severity == FindingSeverity.HIGH
    assert t.owasp_mapping is None
    assert t.title == bi("未分類的威脅", "Unclassified Threat")
    assert t.attack_vector == "REST API"
    assert t.stride_category == STRIDECategory.TAMPERING


def test_missing_threat_id_gets_a_positional_default():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: model_answer(
        {"threats": [{"title": "first"}, {"threat_id": "  ", "title": "second"}]})
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"])
    assert [t.threat_id for t in report.threats] == ["THREAT-01", "THREAT-02"]


# --- 審查者／辯論者／情境建構器：同一類的格式錯誤輸出 --------------------------------------
# --- Reviewer / debater / scenario builder: same class of malformed output ------------------------

def test_malformed_reviewer_findings_are_skipped(scripted, tmp_path):
    (tmp_path / "svc.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    transport = scripted({
        "whitebox_reviewer_claude": '{"findings": 5}',
        "whitebox_reviewer_deepseek": '{"findings": ["not a dict", {"symbol_name": "f", "title": 42, "severity": "HIGH"}]}',
        "whitebox_reviewer_glm": '{"findings": [{"symbol_name": "f", "title": "ok", "severity": "HIGH"}]}',
        "*": '{"findings": []}',
    })
    findings = HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live", transport=transport)).review_symbols(
        symbols, root_dir=str(tmp_path)
    )
    assert [f.title for f in findings] == ["ok"]


def test_non_list_verdicts_leave_findings_unfiltered(fake_live):
    fake_live(lambda s, u: '{"verdicts": 5}')
    result = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate([_finding()])
    assert not result.arbitration_applied
    assert [f.finding_id for f in result.confirmed_findings] == ["A"]


def test_non_string_synthesizer_code_leaves_threat_untested():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: model_answer({"code": 42, "title": "t"})
    tests = ThreatScenarioBuilder(gw).build_test_cases_from_threats([_threat()], base_url="http://localhost:59999")
    assert tests == []


def test_non_string_generator_tests_fall_back_to_probes(fake_live, tmp_path):
    (tmp_path / "svc.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    finding = _finding()
    finding = finding.model_copy(update={"file_path": str(tmp_path / "svc.py"), "symbol_name": "f"})
    fake_live(lambda s, u: '{"tests": "not a list"}')
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="live"))
    tests = gen.generate_tests_for_findings([finding], symbols, root_dir=str(tmp_path))
    assert tests and all(t.test_type == "whitebox_probe" for t in tests)
    assert gen.findings_without_model_tests == ["A"]


def test_generator_tracks_findings_with_and_without_model_tests(fake_live, tmp_path):
    (tmp_path / "svc.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    finding = _finding().model_copy(update={"file_path": str(tmp_path / "svc.py"), "symbol_name": "f"})
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="live"))

    fake_live(lambda s, u: '{"unrelated": true}')
    gen.generate_tests_for_findings([finding], symbols, root_dir=str(tmp_path))
    assert gen.findings_without_model_tests == ["A"]

    fake_live(lambda s, u: json.dumps({"code": "def test_ok():\n    assert True\n", "title": "t"}))
    tests = gen.generate_tests_for_findings([finding], symbols, root_dir=str(tmp_path))
    assert [t.test_type for t in tests] == ["whitebox_unit"]
    assert gen.findings_without_model_tests == []


# --- 測試框架：探針退回是證據缺口，絕不是通往 READY_TO_SHIP 的無聲捷徑 ---------------------
# --- Harness: probe fallback is an evidence gap, never a silent path to READY_TO_SHIP -------------

def test_probe_fallback_is_disclosed_and_blocks_ready_to_ship(scripted, tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "app.py").write_text(
        "def greet(name):\n    if name is None:\n        raise ValueError('name required')\n    return 'hi ' + name\n",
        encoding="utf-8"
    )
    threat = {
        "threat_id": "T1", "stride_category": "Tampering", "title": "t", "description": "d",
        "asset_at_risk": "a", "attack_vector": "greet", "trust_boundary_crossed": "b",
        "severity": "HIGH", "attack_scenario": "s", "test_verification_goal": "g",
    }

    transport = scripted({
        "whitebox_reviewer_claude": {"findings": [{
            "symbol_name": "greet", "severity": "HIGH", "title": "None crash", "description": "d",
            "root_cause": "r", "suspected_vibe_flaw": "v", "suggested_test_scenario": "call greet(None)",
        }]},
        "whitebox_verifier_*": {"verdicts": [{"index": 0, "verdict": "confirm", "reason": "real"}]},
        "whitebox_test_generator": {"unrelated": True},  # 合法的 JSON，但沒有可用的測試 ／ valid JSON, but no usable test
        "blackbox_threat_modeler": {"threats": [threat]},
        "blackbox_test_synthesizer": {"code": (
            "import pytest\nfrom app import greet\n\ndef test_defense():\n"
            "    with pytest.raises(ValueError):\n        greet(None)\n"
        )},
        "*": "{}",
    })
    summary = VibeHarnessCommander(config_path=CONFIG, execution_mode="live", transport=transport).run_full_pipeline(
        target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md"),
        output_sarif_path=str(tmp_path / "r.sarif")
    )
    # 每個執行過的測試都通過（探針與黑箱防禦），其他也沒有缺漏；
    # 在這次修正之前，只有未揭露的探針退回會讓結果成為 READY_TO_SHIP。
    # Every executed test passes (probe and black-box defense) and nothing else is missing;
    # only the undisclosed probe fallback would have allowed READY_TO_SHIP before this fix.
    assert summary.whitebox_tests_passed == 1
    assert summary.blackbox_tests_passed == 1
    assert summary.overall_status == "INCONCLUSIVE"
    assert any(
        "no usable model-generated test" in r and "WB-CLA-01" in r for r in summary.inconclusive_reasons
    )
    assert "deterministic probes" in (tmp_path / "r.md").read_text(encoding="utf-8")

    sarif = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    wb_rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "vibeharness/whitebox-finding" in wb_rules
    # 已確認的發現從擷取出的符號表解析出其行號
    # The confirmed finding resolves its line from the extracted symbol table
    wb_result = next(r for r in sarif["runs"][0]["results"] if r["properties"].get("findingId") == "WB-CLA-01")
    assert wb_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert wb_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("app.py")


# --- 報告：模型提供的文字不能破壞 Markdown 表格 ---------------------------------------------
# --- Report: model-provided text cannot break Markdown tables --------------------------------------

def test_report_table_cells_escape_pipes():
    threat = _threat().model_copy(update={
        "title": "Bulk | edit", "attack_vector": "PUT /api | mass assignment", "owasp_mapping": "API1 | BOLA",
    })
    summary = VibeHarnessSummary(
        overall_status="INCONCLUSIVE", total_whitebox_findings=0, confirmed_whitebox_bugs=0,
        whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=1,
        critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0,
    )
    result = MultiModelDebateResult(consensus_summary="")
    bb = [TestExecutionResult(
        test_id="BB|TEST", test_type="blackbox_security", status=TestStatus.FAILED, failure_reason="a | b"
    )]
    md = ReportGenerator().generate_markdown_report(
        summary, result, ThreatModelReport(
            system_description="s", entrypoints=[], trust_boundaries=[], assets=[], threats=[threat]
        ), [], bb, "app"
    )
    assert "**Bulk \\| edit**<br>*PUT /api \\| mass assignment*" in md
    assert "API1 \\| BOLA" in md
    assert "`BB\\|TEST`" in md
    assert "a \\| b" in md


def test_json_report_is_valid_and_complete():
    threat = _threat()
    summary = VibeHarnessSummary(
        overall_status="INCONCLUSIVE", total_whitebox_findings=1, confirmed_whitebox_bugs=0,
        whitebox_tests_passed=1, whitebox_tests_failed=0, total_threats_modeled=1,
        critical_threats_count=1, blackbox_tests_passed=1, blackbox_security_breaches=0,
        agent_calls=[AgentCallRecord(agent_id="claude", model_alias="claude", model_name="claude-x", mode="simulated", reason="no key")],
    )
    result = MultiModelDebateResult(consensus_summary="ok", confirmed_findings=[_finding()])
    wb = [TestExecutionResult(test_id="WB-1", test_type="whitebox_unit", status=TestStatus.PASSED)]
    bb = [TestExecutionResult(test_id="BB-1", test_type="blackbox_security", status=TestStatus.PASSED)]
    payload = json.loads(ReportGenerator().generate_json_report(
        summary, result, ThreatModelReport(
            system_description="s", entrypoints=[], trust_boundaries=[], assets=[], threats=[threat]
        ), wb, bb, "app"
    ))
    assert payload["tool"] == "vibeharness-mas"
    assert payload["summary"]["overall_status"] == "INCONCLUSIVE"
    assert payload["whitebox"]["debate"]["confirmed_findings"][0]["title"] == "title A"
    assert payload["whitebox"]["test_results"][0]["test_id"] == "WB-1"
    assert payload["threat_model"]["threats"][0]["stride_category"] == "Tampering"
    assert payload["blackbox_test_results"][0]["test_id"] == "BB-1"
    assert payload["summary"]["agent_calls"][0]["agent_id"] == "claude"


def test_sarif_report_structure_levels_and_locations(tmp_path):
    target = tmp_path / "tgt"
    target.mkdir()
    abs_file = target / "app.py"
    abs_file.write_text("x = 1\n", encoding="utf-8")
    critical = _finding("WB-CLA-01", "claude").model_copy(update={
        "severity": FindingSeverity.CRITICAL, "title": "None crash", "file_path": str(abs_file), "line_number": 7,
    })
    medium = _finding("WB-DEE-01", "deepseek").model_copy(update={
        "severity": FindingSeverity.MEDIUM, "title": "Weak guard", "file_path": "app.py", "symbol_name": "greet",
    })
    symbols = [CodeSymbol(
        name="greet", symbol_type="function", file_path="app.py", line_start=42, line_end=50,
        signature="def greet():", source_code="",
    )]
    breach = TestExecutionResult(
        test_id="BB-T1-01", test_type="blackbox_security", status=TestStatus.FAILED,
        failure_reason="defense bypassed", is_security_exploit_confirmed=True, source_ref="T1",
    )
    defended = TestExecutionResult(
        test_id="BB-T1-02", test_type="blackbox_security", status=TestStatus.PASSED,
    )
    payload = json.loads(ReportGenerator().generate_sarif_report(
        VibeHarnessSummary(overall_status="BLOCKED_CRITICAL_RISK", total_whitebox_findings=2,
                           confirmed_whitebox_bugs=2, whitebox_tests_passed=0, whitebox_tests_failed=2,
                           total_threats_modeled=1, critical_threats_count=1, blackbox_tests_passed=1,
                           blackbox_security_breaches=1),
        MultiModelDebateResult(consensus_summary="ok", confirmed_findings=[critical, medium],
                               disputed_findings=[_finding("WB-GLM-99", "glm")]),
        ThreatModelReport(system_description="s", entrypoints=[], trust_boundaries=[], assets=[], threats=[]),
        [], [breach, defended], str(target), symbols=symbols
    ))
    run = payload["runs"][0]
    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "VibeHarness-MAS"
    # 有爭議的發現與已防禦的黑箱結果不會回報；規則 id 跨執行
    # 穩定，而執行專屬的 id 放在 properties 中
    # Disputed finding and the defended black-box result are not reported; rule ids are stable
    # across runs and the run-specific ids live in the properties
    assert [r["ruleId"] for r in run["results"]] == [
        "vibeharness/whitebox-finding", "vibeharness/whitebox-finding", "vibeharness/blackbox-breach"
    ]
    by_id = {r["properties"].get("findingId") or r["properties"]["testId"]: r for r in run["results"]}
    assert list(by_id) == ["WB-CLA-01", "WB-DEE-01", "BB-T1-01"]
    assert by_id["WB-CLA-01"]["level"] == "error"          # 嚴重 ／ CRITICAL
    assert by_id["WB-DEE-01"]["level"] == "warning"        # 中等 ／ MEDIUM
    assert by_id["BB-T1-01"]["level"] == "error"
    # 行號來自 finding.line_number 與符號表；URI 相對於目標，使用正斜線
    # Line from finding.line_number and from the symbol table; URI relative to the target, forward slashes
    loc1 = by_id["WB-CLA-01"]["locations"][0]["physicalLocation"]
    assert loc1["region"]["startLine"] == 7
    assert loc1["artifactLocation"]["uri"] == "app.py"
    assert loc1["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    loc2 = by_id["WB-DEE-01"]["locations"][0]["physicalLocation"]
    assert loc2["region"]["startLine"] == 42
    # 此突破的威脅沒有指名任何擷取出的符號：沒有位置（省略，絕不是 null）
    # The breach's threat names no extracted symbol: no location (omitted, never null)
    assert "locations" not in by_id["BB-T1-01"]
    assert "defense bypassed" in by_id["BB-T1-01"]["message"]["text"]
    # 規則陣列的索引與結果上的 ruleIndex 對齊
    # Rules array indices line up with ruleIndex on results
    rules = run["tool"]["driver"]["rules"]
    for r in run["results"]:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]
        assert r["partialFingerprints"]["vibeharness/v1"]


def test_sarif_uri_relativization(tmp_path):
    (tmp_path / "a").mkdir()
    uri = ReportGenerator._sarif_uri
    assert uri(str(tmp_path / "a" / "app.py"), str(tmp_path / "a")) == "app.py"
    assert uri("app.py", str(tmp_path)) == "app.py"
    assert uri("./pkg/mod.py", str(tmp_path)) == "pkg/mod.py"
    # %SRCROOT% 之外的檔案：絕對 file:// URI，絕不是只剩檔名（那會指到版本庫根目錄下別的檔案）
    # A file outside %SRCROOT%: an absolute file:// URI, never a bare file name (that would point at another file at the repo root)
    elsewhere = tmp_path / "elsewhere" / "x.py"
    assert uri(str(elsewhere), str(tmp_path / "a")) == elsewhere.resolve().as_uri()
    assert uri("", str(tmp_path)) is None
    # 不同磁碟機無法相對化：退回絕對 file:// URI
    # A different drive cannot be made relative: fall back to an absolute file:// URI
    assert uri("E:\\other\\x.py", r"D:\work\proj") == "file:///E:/other/x.py"
    # 同一磁碟機在 Windows 與 POSIX 主機上都能一致地相對化
    # Same drive relativizes consistently on Windows and on POSIX hosts
    assert uri(r"D:\proj\app.py", r"D:\proj") == "app.py"


def test_garbage_json_object_is_recorded_as_invalid_call(fake_live):
    """一個能解析成 JSON 但沒有任何預期鍵的 live 回應，必須以 mode「invalid」
    （附上原因）記錄下來，而不是當成剛好產生零個結果的成功呼叫。
    A live response that parses as JSON but has none of the expected keys must be
    recorded with mode 'invalid' (with its reason), not treated as a successful call that
    just happens to produce zero results."""
    import json
    gw = LLMGateway(CONFIG, execution_mode="live")
    fake_live(lambda s, u: json.dumps({"sorry": "no tests in here"}))
    result = gw.generate("whitebox_test_generator", "sys", "user", json_output=True,
                         schema=OutputSchema(any_of={"tests": ANY, "code": ANY}))
    assert result.mode == "invalid" and result.data == {} and not result.usable
    assert gw.call_log[-1].mode == "invalid"
    assert "none of the expected" in gw.call_log[-1].reason


def test_reports_carry_run_metadata_and_a_schema_version(tmp_path):
    """日後讀取的報告必須說明是哪個測試框架版本、模式與目標修訂產生它的。
    A report read later must say which harness version, mode and target revision produced it."""
    import json
    from vibeharness import __version__
    from vibeharness.core.harness import VibeHarnessCommander
    target = tmp_path / "t"
    target.mkdir()
    (target / "m.py").write_text("def f(x):\n    return x\n")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    summary = commander.run_full_pipeline(
        target_dir=str(target), output_report_path=str(tmp_path / "r.json"), output_format="json",
        output_sarif_path=str(tmp_path / "r.sarif"),
    )
    run = summary.run
    assert run and run.harness_version == __version__ and run.execution_mode == "mock"
    assert run.sandbox_provider == "local_subprocess" and run.config_path == os.path.abspath(CONFIG)
    assert run.generated_at.endswith("+00:00")
    payload = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "2" and payload["summary"]["run"]["harness_version"] == __version__
    sarif = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["execution_mode"] == "mock" and "generated_at" in sarif["runs"][0]["properties"]
    commander.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "r.md"))
    md = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert f"by VibeHarness-MAS {__version__} (mode `mock`, sandbox `local_subprocess`)" in md
    assert "／ Target revision**:" in md and "／ Config**:" in md  # 雙語標籤，值在其後 ／ bilingual label, value after it


def test_provenance_rows_do_not_depend_on_call_completion_order():
    """並行呼叫的完成順序不同時，執行來源表的列序仍相同（報告可重現）。
    The Execution Provenance rows come out in the same order whatever order the concurrent calls finished in."""
    calls = [
        AgentCallRecord(agent_id="whitebox_reviewer_glm", model_alias="glm", model_name="glm-x", mode="live"),
        AgentCallRecord(agent_id="whitebox_reviewer_claude", model_alias="claude", model_name="claude-x", mode="simulated", reason="no key"),
        AgentCallRecord(agent_id="blackbox_threat_modeler", model_alias="claude", model_name="claude-x", mode="invalid", reason="bad json"),
        AgentCallRecord(agent_id="whitebox_reviewer_claude", model_alias="claude", model_name="claude-x", mode="simulated", reason="no key"),
    ]

    def provenance(order):
        summary = VibeHarnessSummary(
            overall_status="INCONCLUSIVE", total_whitebox_findings=0, confirmed_whitebox_bugs=0,
            whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0,
            critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0, agent_calls=order,
        )
        md = ReportGenerator().generate_markdown_report(
            summary, MultiModelDebateResult(consensus_summary="c"), ThreatModelReport(system_description="s"), [], [], "app")
        from vibeharness.reports.report_generator import HEADING_PROVENANCE
        start = md.index(HEADING_PROVENANCE)
        return md[start:md.index("\n\n", start)]
    first, second = provenance(calls), provenance(list(reversed(calls)))
    assert first == second
    rows = [line.split("`")[1] for line in first.splitlines() if line.startswith("| `")]
    assert rows == sorted(rows) and rows.count("whitebox_reviewer_claude") == 1


def test_agreement_display_covers_every_state():
    """一致度顯示：未套用驗證、有比例、套用但缺比例（例如讀回的 JSON）都有固定文字，不會出錯。
    The agreement display has a fixed text for not applied, a ratio, and applied without a ratio (e.g. JSON read back)."""
    from vibeharness.reports.report_generator import agreement_display
    assert "verification not applied" in agreement_display(MultiModelDebateResult(consensus_summary="c"))
    assert agreement_display(MultiModelDebateResult(consensus_summary="c", arbitration_applied=True, model_agreement_ratio=0.75)) == "75.0%"
    assert "no decisive votes" in agreement_display(MultiModelDebateResult(consensus_summary="c", arbitration_applied=True))


# --- 形狀錯誤：重新詢問一次，仍不合就記為 invalid（不再當成「什麼都沒找到」）----------------------------------
# --- Shape errors: re-asked once, booked as invalid if still wrong (no longer read as "nothing found") ---------

def _shape_cases():
    from vibeharness.agents.blackbox.scenario_builder import CODE_SCHEMA
    from vibeharness.agents.blackbox.threat_modeler import THREATS_SCHEMA
    from vibeharness.agents.whitebox.debater import verdicts_schema
    from vibeharness.agents.whitebox.multi_reviewer import FINDINGS_SCHEMA
    from vibeharness.agents.whitebox.test_generator import TESTS_SCHEMA
    return [
        ("whitebox_reviewer_claude", FINDINGS_SCHEMA, {"findings": 5}, "field 'findings' must be a list of objects (got int)"),
        ("whitebox_reviewer_claude", FINDINGS_SCHEMA, {"findings": ["x", 1]}, "field 'findings' has no usable item (2 item(s))"),
        ("whitebox_reviewer_claude", FINDINGS_SCHEMA, {"findings": [{"symbol_name": "f"}]},
         "each item needs a non-empty title or description"),
        ("whitebox_verifier_glm", verdicts_schema(1), {"verdicts": [{"index": 9, "verdict": "confirm"}]},
         "each item needs an index from 0 to 0 and a verdict of confirm, reject or unsure"),
        ("whitebox_verifier_glm", verdicts_schema(1), {"verdicts": [{"index": 0, "verdict": "maybe"}]}, "has no usable item"),
        ("blackbox_threat_modeler", THREATS_SCHEMA, {"threats": "x"}, "field 'threats' must be a list of objects (got str)"),
        ("blackbox_threat_modeler", THREATS_SCHEMA, {"threats": [1, 2]}, "each item must be an object"),
        ("whitebox_test_generator", TESTS_SCHEMA, {"tests": [{"title": "t"}]}, "each item needs non-empty code"),
        ("whitebox_test_generator", TESTS_SCHEMA, {"code": 42}, "field 'code' must be a string (got int)"),
        ("blackbox_test_synthesizer", CODE_SCHEMA, {"code": None}, "field 'code' must be a string (got null)"),
    ]


@pytest.mark.parametrize("case", range(10))
def test_a_shape_error_is_reasked_with_the_reason_then_booked_invalid(scripted, case):
    """鍵在、形狀不對的回答（`findings: 5`、沒有任何可用項目的清單、`code: 42`）過去被當成可用的回答，代理再把它讀成
    「什麼都沒找到」；現在與缺鍵一樣：以指名欄位的原因重新詢問一次，仍不合就記為 invalid（證據缺口）。
    An answer with the keys but the wrong shape (`findings: 5`, a list with no usable item, `code: 42`) used to be
    a usable answer the agent then read as "nothing found"; now it is treated like a missing key: re-asked once with
    a reason naming the field, and booked as invalid (an evidence gap) if it still does not fit."""
    agent_id, schema, answer, reason = _shape_cases()[case]
    transport = scripted({"*": answer})
    gw = LLMGateway(CONFIG, execution_mode="live", transport=transport)
    resp = gw.generate(agent_id, "sys", "user", schema=schema)
    assert not resp.usable
    assert [c.mode for c in gw.call_log] == ["retried", "invalid"]
    assert reason in gw.call_log[-1].reason and reason in transport.prompts()[1][1]
    assert not has_cjk(transport.prompts()[1][1])  # 模型只看到英文半 ／ the model sees the English half only


@pytest.mark.parametrize("answer", [
    {"findings": []},                                    # 什麼都沒找到是合法的回答 ／ "nothing found" is a legitimate answer
    {"findings": [{"title": "ok"}, "x", {"symbol_name": "f"}]},  # 部分項目不能用：略過，不重問 ／ some unusable: skipped, no re-ask
])
def test_an_empty_or_partly_usable_list_is_not_reasked(scripted, answer):
    from vibeharness.agents.whitebox.multi_reviewer import FINDINGS_SCHEMA
    gw = LLMGateway(CONFIG, execution_mode="live", transport=scripted({"*": answer}))
    assert gw.generate("whitebox_reviewer_claude", "sys", "user", schema=FINDINGS_SCHEMA).usable
    assert [c.mode for c in gw.call_log] == ["live"]


def test_a_reviewer_answering_a_non_list_is_an_evidence_gap_not_zero_findings(scripted, tmp_path):
    """端對端：審查者回答 `{"findings": 5}` 過去被登記為 live、讀成零個發現（fail open）；現在是一筆 invalid 呼叫，
    品質閘門會把它列為證據缺口。
    End to end: a reviewer answering `{"findings": 5}` used to be booked live and read as zero findings (fail open);
    now it is an invalid call, which the quality gate lists as an evidence gap."""
    (tmp_path / "svc.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    gw = LLMGateway(CONFIG, execution_mode="live",
                    transport=scripted({"whitebox_reviewer_claude": {"findings": 5}, "*": {"findings": []}}))
    assert HeterogeneousReviewerEnsemble(gw).review_symbols(symbols, root_dir=str(tmp_path)) == []
    assert [c.agent_id for c in gw.invalid_calls] == ["whitebox_reviewer_claude"]


def test_a_cached_answer_that_no_longer_fits_is_invalid_under_cache_only_and_reasked_otherwise(scripted, tmp_path):
    """舊版本存進回應快取、現在形狀已不合的回答：--cache-only 下記為 invalid，原因標明來自快取（重新詢問的提示不帶這個
    標記）；不帶 --cache-only 時重新詢問，可用的回答覆寫那筆快取。
    An answer an older version stored in the response cache that no longer fits: under --cache-only it is booked
    invalid with a reason naming the cache (a re-ask prompt never carries that mark); without --cache-only it is
    re-asked and the usable answer overwrites the cache entry."""
    from vibeharness.agents.whitebox.multi_reviewer import FINDINGS_SCHEMA
    from vibeharness.core.model_output import ANY, CACHED_ANSWER_PREFIX, OutputSchema

    def gateway(answer, cache_only=False):
        transport = scripted({"*": answer})
        gw = LLMGateway(CONFIG, execution_mode="live", transport=transport)
        gw.set_cache_dir(str(tmp_path / "cache"))
        gw.cache_only = cache_only
        return gw, transport
    old, _ = gateway({"findings": 5})  # 舊版本只檢查鍵是否存在 ／ the older version only checked that the key is there
    assert old.generate("whitebox_reviewer_claude", "sys", "user",
                        schema=OutputSchema(required={"findings": ANY})).usable
    replay, transport = gateway(pytest.fail, cache_only=True)
    assert not replay.generate("whitebox_reviewer_claude", "sys", "user", schema=FINDINGS_SCHEMA).usable
    assert [c.mode for c in replay.call_log] == ["invalid"] and not transport.requests
    assert replay.call_log[0].reason.startswith(CACHED_ANSWER_PREFIX.split(" ／ ")[0]) and en_only(CACHED_ANSWER_PREFIX) in replay.call_log[0].reason
    fresh, transport = gateway({"findings": [{"title": "ok"}]})
    assert fresh.generate("whitebox_reviewer_claude", "sys", "user", schema=FINDINGS_SCHEMA).usable
    assert [c.mode for c in fresh.call_log] == ["retried", "live"]
    assert en_only(CACHED_ANSWER_PREFIX) in fresh.call_log[0].reason
    assert en_only(CACHED_ANSWER_PREFIX) not in transport.prompts()[0][1]
    again, _ = gateway(pytest.fail, cache_only=True)
    replayed = again.generate("whitebox_reviewer_claude", "sys", "user", schema=FINDINGS_SCHEMA)
    assert replayed.data["findings"] == [{"title": "ok"}]


def test_test_generation_falls_back_to_code_when_tests_has_no_usable_item(tmp_path):
    """`tests` 是清單、卻沒有任何一項有 code 時，改用回答裡非空的 `code`：形狀檢查已經因為 `code` 可用而接受這個回答，
    代理過去卻因為 `tests` 不是空清單就忽略 `code`，那個發現因此沒有模型測試。`tests` 有可用的項目時仍忽略 `code`。
    When `tests` is a list but no item has code, the answer's non-empty `code` is used: the shape check already
    accepts the answer because `code` is usable, yet the agent used to ignore `code` as soon as `tests` was a
    non-empty list, leaving the finding without a model test. When `tests` has a usable item, `code` is still
    ignored."""
    (tmp_path / "svc.py").write_text("def f(x):\n    return x['id']\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    code = "import svc\n\ndef test_f():\n    assert svc.f({'id': 1}) == 1\n"
    finding = ReviewFinding(finding_id="WB-CLA-01", reviewer_name="Claude", model_alias="claude",
                            file_path=str(tmp_path / "svc.py"), symbol_name="f", severity=FindingSeverity.HIGH,
                            title="KeyError", description="d", root_cause="r", suspected_vibe_flaw="v",
                            suggested_test_scenario="s")

    def generator(answer):
        gw = LLMGateway(CONFIG, execution_mode="mock")
        gw.generate = lambda *a, **k: model_answer(answer)
        return WhiteboxTestGenerator(gw)
    fallback = generator({"tests": ["not an object", {"title": "no code"}], "code": code})
    tests = fallback.generate_tests_for_findings([finding], symbols, root_dir=str(tmp_path))
    assert [t.code.strip() for t in tests if t.test_type == "whitebox_unit"] == [code.strip()]
    assert fallback.findings_without_model_tests == []
    preferred = generator({"tests": [{"title": "from tests", "code": code}], "code": "def test_other():\n    assert 2\n"})
    tests = preferred.generate_tests_for_findings([finding], symbols, root_dir=str(tmp_path))
    assert [t.title for t in tests if t.test_type == "whitebox_unit"] == ["from tests"]
