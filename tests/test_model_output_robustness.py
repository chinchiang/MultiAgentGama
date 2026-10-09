"""Regression tests: malformed model output degrades gracefully, and probe fallback is disclosed."""
import json
import os

from vibeharness.core.llm_gateway import LLMGateway, PROVENANCE_KEY, REASON_NOT_VALID_JSON
from vibeharness.core.i18n import bi, en_only
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


def _big_symbol(name, lines=500):
    return CodeSymbol(
        name=name, symbol_type="function", file_path="app.py", line_start=1, line_end=lines,
        signature=f"{name}()", source_code=f"def {name}():\n" + "    value = 'payload token filler line'\n" * lines
    )


def test_large_targets_are_threat_modeled_in_batches():
    """Every symbol must be visible to the threat modeler: like the reviewers, symbols are
    batched so a single-prompt token cap can no longer silently drop most of the target."""
    gw = LLMGateway(CONFIG, execution_mode="mock")
    prompts = []
    state = {"n": 0}

    def responder(agent_id, system_prompt, user_prompt, **k):
        state["n"] += 1
        prompts.append(user_prompt)
        # every batch reports the same colliding threat_id to prove renumbering works
        return {
            "threats": [{"threat_id": "THREAT-01", "stride_category": "Tampering", "title": f"t{state['n']}"}],
            "entrypoints": ["/api/batch"],
        }

    gw.generate = responder
    symbols = [_big_symbol(f"f{i}") for i in range(30)]
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"], symbols=symbols, root_dir=".")
    assert state["n"] > 1  # batching actually happened
    # every symbol is shown in exactly one batch prompt: nothing omitted, nothing duplicated
    shown = [sym for p in prompts for sym in symbols if f"Symbol: {sym.name} " in p]
    assert sorted(s.name for s in shown) == sorted(s.name for s in symbols)
    # colliding model threat ids are renumbered into a unique, deterministic sequence
    assert [t.threat_id for t in report.threats] == [f"THREAT-{i:02d}" for i in range(1, state["n"] + 1)]
    # report-level fields come from the first usable batch, not the last
    assert report.entrypoints == ["/api/batch"]


def test_invalid_batch_does_not_kill_threat_modeling():
    from vibeharness.core.llm_gateway import PROVENANCE_KEY
    gw = LLMGateway(CONFIG, execution_mode="mock")
    responses = [
        {PROVENANCE_KEY: {"mode": "invalid", "model": "m", "reason": "bad json"}},
        {"threats": [{"threat_id": "THREAT-01", "stride_category": "Tampering", "title": "later"}],
         "entrypoints": ["/api/valid"]},
    ]

    def responder(*a, **k):
        return responses.pop(0)

    gw.generate = responder
    report = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"], symbols=[_big_symbol("a"), _big_symbol("b")], root_dir=".")
    # batch 1 was unusable, batch 2 still contributed its threat and the report-level fields
    assert [t.threat_id for t in report.threats] == ["THREAT-01"]
    assert report.entrypoints == ["/api/valid"]


def test_wrong_typed_threat_fields_are_coerced_not_fatal():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    gw.generate = lambda *a, **k: {"threats": [{
        "threat_id": "T1", "severity": None, "owasp_mapping": {"id": "API1"}, "title": 42,
        "attack_vector": ["PUT"], "stride_category": "Not-A-STRIDE-Category",
    }]}
    t = AutomatedThreatModeler(gw).model_system("desc", ["/api/users"]).threats[0]
    assert t.severity == FindingSeverity.HIGH
    assert t.owasp_mapping is None
    assert t.title == bi("未分類的威脅", "Unclassified Threat")
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
        if "(Claude)" in system:
            return '{"findings": 5}'
        if "DeepSeek" in system:
            return '{"findings": ["not a dict", {"symbol_name": "f", "title": 42, "severity": "HIGH"}]}'
        if "GLM" in system:
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
        if "(Claude)" in system:
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
    assert "vibeharness/whitebox-finding" in wb_rules
    # The confirmed finding resolves its line from the extracted symbol table
    wb_result = next(r for r in sarif["runs"][0]["results"] if r["properties"].get("findingId") == "WB-CLA-01")
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
    # Disputed finding and the defended black-box result are not reported; rule ids are stable
    # across runs and the run-specific ids live in the properties
    assert [r["ruleId"] for r in run["results"]] == [
        "vibeharness/whitebox-finding", "vibeharness/whitebox-finding", "vibeharness/blackbox-breach"
    ]
    by_id = {r["properties"].get("findingId") or r["properties"]["testId"]: r for r in run["results"]}
    assert list(by_id) == ["WB-CLA-01", "WB-DEE-01", "BB-T1-01"]
    assert by_id["WB-CLA-01"]["level"] == "error"          # CRITICAL
    assert by_id["WB-DEE-01"]["level"] == "warning"        # MEDIUM
    assert by_id["BB-T1-01"]["level"] == "error"
    # Line from finding.line_number and from the symbol table; URI relative to the target, forward slashes
    loc1 = by_id["WB-CLA-01"]["locations"][0]["physicalLocation"]
    assert loc1["region"]["startLine"] == 7
    assert loc1["artifactLocation"]["uri"] == "app.py"
    assert loc1["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    loc2 = by_id["WB-DEE-01"]["locations"][0]["physicalLocation"]
    assert loc2["region"]["startLine"] == 42
    # The breach's threat names no extracted symbol: no location (omitted, never null)
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
    # Same drive relativizes consistently on Windows and on POSIX hosts
    assert uri(r"D:\proj\app.py", r"D:\proj") == "app.py"


def test_clean_and_parse_json_robustness():
    gw = LLMGateway(CONFIG, execution_mode="mock")
    # 1. Pure valid JSON
    assert gw._clean_and_parse_json('{"key": "value"}') == {"key": "value"}
    # 2. Markdown fences with json / JSON / no lang tag
    assert gw._clean_and_parse_json('```json\n{"key": 1}\n```') == {"key": 1}
    assert gw._clean_and_parse_json('```JSON\n{"key": 2}\n```') == {"key": 2}
    assert gw._clean_and_parse_json('```\n{"key": 3}\n```') == {"key": 3}
    # 3. Conversational wrapper without fences
    assert gw._clean_and_parse_json('Sure! Here is the output:\n{"key": 4}\nHope this helps!') == {"key": 4}
    # 4. Text with prior non-JSON braces before the real JSON block
    assert gw._clean_and_parse_json('Note: {ignore this invalid}\nReal output:\n{"key": 5}') == {"key": 5}
    # 5. Unclosed code fence
    assert gw._clean_and_parse_json('```json\n{"key": 6}\n') == {"key": 6}
    # 6. Completely non-JSON text returns None (no sentinel dict a model could collide with)
    assert gw._clean_and_parse_json('Sorry, I cannot help with that.') is None
    # 7. A model echoing a parse-failure-shaped dict is just a normal dict, not an error
    assert gw._clean_and_parse_json('{"error": "JSONDecodeError", "raw_content": "hi"}') == {
        "error": "JSONDecodeError", "raw_content": "hi"
    }


def test_validate_output_any_of_keys():
    assert LLMGateway._validate_output({"tests": []}, True, None, ["tests", "code"]) is None
    assert LLMGateway._validate_output({"code": "def test_x(): pass"}, True, None, ["tests", "code"]) is None
    assert LLMGateway._validate_output(None, True, None, ["tests", "code"]) == REASON_NOT_VALID_JSON
    assert en_only(REASON_NOT_VALID_JSON) == "response is not valid JSON"
    problem = LLMGateway._validate_output({"oops": 1}, True, None, ["tests", "code"])
    assert problem is not None and "none of the expected" in problem
    # all-of semantics are unchanged
    assert en_only(LLMGateway._validate_output({"a": 1}, True, ["a", "b"], None)) == "response is missing required key(s): b"
    assert LLMGateway._validate_output({"a": 1, "b": 2}, True, ["a", "b"], None) is None


def test_garbage_json_object_is_recorded_as_invalid_call(fake_live):
    """A live response that parses as JSON but has none of the expected keys must be
    recorded with mode 'invalid' (with its reason), not treated as a successful call that
    just happens to produce zero results."""
    import json
    gw = LLMGateway(CONFIG, execution_mode="live")
    fake_live(lambda s, u: json.dumps({"sorry": "no tests in here"}))
    result = gw.generate("whitebox_test_generator", "sys", "user", json_output=True,
                         required_keys_any=["tests", "code"])
    assert set(result.keys()) == {PROVENANCE_KEY}
    assert gw.call_log[-1].mode == "invalid"
    assert "none of the expected" in gw.call_log[-1].reason



def test_reports_carry_run_metadata_and_a_schema_version(tmp_path):
    """A report read later must say which harness version, mode and target revision produced it."""
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
    assert payload["schema_version"] == "1" and payload["summary"]["run"]["harness_version"] == __version__
    sarif = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["execution_mode"] == "mock" and "generated_at" in sarif["runs"][0]["properties"]
    commander.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "r.md"))
    md = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert f"by VibeHarness-MAS {__version__} (mode `mock`, sandbox `local_subprocess`)" in md
    assert "／ Target revision**:" in md and "／ Config**:" in md  # bilingual label, value after it
