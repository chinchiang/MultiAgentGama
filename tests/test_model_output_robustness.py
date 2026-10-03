"""Regression tests: malformed model output degrades gracefully, and probe fallback is disclosed."""
import json
import os

from core.llm_gateway import LLMGateway
from core.models import (
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
from agents.whitebox.ast_extractor import ASTExtractor
from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
from agents.whitebox.debater import MultiModelDebater
from agents.whitebox.test_generator import WhiteboxTestGenerator
from agents.blackbox.threat_modeler import AutomatedThreatModeler, DEFAULT_TRUST_BOUNDARIES, DEFAULT_ASSETS
from agents.blackbox.scenario_builder import ThreatScenarioBuilder
from reports.report_generator import ReportGenerator
from core.harness import VibeHarnessCommander

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "config", "agents_config.yaml")


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


# --- Threat modeler: malformed output must degrade, not crash the pipeline -----------------------

def test_malformed_threat_entries_are_skipped():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: {"threats": ["BOLA", 7, {"threat_id": "T1", "stride_category": "Tampering"}]}
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"])
    assert [t.threat_id for t in report.threats] == ["T1"]


def test_non_list_threats_and_string_list_fields_fall_back():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: {
        "threats": {"threat_id": "T1"},  # object instead of a list
        "system_description": 42,
        "entrypoints": "not a list",
        "trust_boundaries": [1, 2],
        "assets": "db",
    }
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"])
    assert report.threats == []
    assert report.system_description == "desc"
    assert report.entrypoints == ["/api/users"]
    assert report.trust_boundaries == DEFAULT_TRUST_BOUNDARIES
    assert report.assets == DEFAULT_ASSETS


def test_wrong_typed_threat_fields_are_coerced_not_fatal():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: {"threats": [{
        "threat_id": "T1", "severity": None, "owasp_mapping": {"id": "API1"}, "title": 42,
        "attack_vector": ["PUT"], "stride_category": "Not-A-STRIDE-Category",
    }]}
    t = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"]).threats[0]
    assert t.severity == FindingSeverity.HIGH
    assert t.owasp_mapping is None
    assert t.title == "Unclassified Threat"
    assert t.attack_vector == "REST API"
    assert t.stride_category == STRIDECategory.TAMPERING


def test_missing_threat_id_gets_a_positional_default():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: {"threats": [{"title": "first"}, {"threat_id": "  ", "title": "second"}]}
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"])
    assert [t.threat_id for t in report.threats] == ["THREAT-01", "THREAT-02"]


# --- Reviewer / debater / scenario builder: same class of malformed output ------------------------

def test_malformed_reviewer_findings_are_skipped(fake_live, tmp_path):
    (tmp_path / "svc.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))

    def responder(system, user):
        if "Claude Logic Reviewer" in system:
            return '{"findings": 5}'
        if "Nemotron" in system:
            return '{"findings": ["not a dict", {"symbol_name": "f", "title": 42, "severity": "HIGH"}]}'
        if "ChatGPT" in system:
            return '{"findings": [{"symbol_name": "f", "title": "ok", "severity": "HIGH"}]}'
        return '{"findings": []}'

    fake_live(responder)
    findings = HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live")).review_symbols(
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
    gw.generate = lambda *a, **k: {"code": 42, "title": "t"}
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


# --- Harness: probe fallback is an evidence gap, never a silent path to READY_TO_SHIP -------------

def test_probe_fallback_is_disclosed_and_blocks_ready_to_ship(fake_live, tmp_path):
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

    def responder(system, user):
        if "Claude Logic Reviewer" in system:
            return json.dumps({"findings": [{
                "symbol_name": "greet", "severity": "HIGH", "title": "None crash", "description": "d",
                "root_cause": "r", "suspected_vibe_flaw": "v", "suggested_test_scenario": "call greet(None)",
            }]})
        if "code-review verifier" in system:
            return json.dumps({"verdicts": [{"index": 0, "verdict": "confirm", "reason": "real"}]})
        if "QA Engineer" in system:
            return '{"unrelated": true}'  # valid JSON, but no usable test
        if "Threat Modeling Specialist" in system:
            return json.dumps({"threats": [threat]})
        if "Offensive Security" in system:
            return json.dumps({"code": (
                "import pytest\nfrom app import greet\n\ndef test_defense():\n"
                "    with pytest.raises(ValueError):\n        greet(None)\n"
            )})
        return "{}"

    fake_live(responder)
    summary = VibeHarnessCommander(config_path=CONFIG, execution_mode="live").run_full_pipeline(
        target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md"),
        output_sarif_path=str(tmp_path / "r.sarif")
    )
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
    assert "WB-CLA-01" in wb_rules
    # The confirmed finding resolves its line from the extracted symbol table
    wb_result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "WB-CLA-01")
    assert wb_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert wb_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("app.py")


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
    medium = _finding("WB-NEM-01", "nemotron").model_copy(update={
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
                               disputed_findings=[_finding("WB-CHA-99", "chatgpt")]),
        ThreatModelReport(system_description="s", entrypoints=[], trust_boundaries=[], assets=[], threats=[]),
        [], [breach, defended], str(target), symbols=symbols
    ))
    run = payload["runs"][0]
    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "VibeHarness-MAS"
    # Disputed finding and the defended black-box result are not reported
    assert [r["ruleId"] for r in run["results"]] == ["WB-CLA-01", "WB-NEM-01", "BB-T1-01"]
    by_id = {r["ruleId"]: r for r in run["results"]}
    assert by_id["WB-CLA-01"]["level"] == "error"          # CRITICAL
    assert by_id["WB-NEM-01"]["level"] == "warning"        # MEDIUM
    assert by_id["BB-T1-01"]["level"] == "error"
    # Line from finding.line_number and from the symbol table; URI relative to the target, forward slashes
    loc1 = by_id["WB-CLA-01"]["locations"][0]["physicalLocation"]
    assert loc1["region"]["startLine"] == 7
    assert loc1["artifactLocation"]["uri"] == "app.py"
    assert loc1["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    loc2 = by_id["WB-NEM-01"]["locations"][0]["physicalLocation"]
    assert loc2["region"]["startLine"] == 42
    # Breaches are system-level: no file location, failure reason in the message
    assert "locations" not in by_id["BB-T1-01"]
    assert "defense bypassed" in by_id["BB-T1-01"]["message"]["text"]
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
    assert uri(str(tmp_path / "elsewhere" / "x.py"), str(tmp_path / "a")) == "x.py"
    assert uri("", str(tmp_path)) is None
    # A different drive cannot be made relative on Windows: fall back to the file name
    assert uri("E:\\other\\x.py", r"D:\work\proj") == "x.py"
