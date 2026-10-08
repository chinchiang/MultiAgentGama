"""Regression tests for the packaging, model-output robustness, execution and SARIF fixes."""
import os
import sys

import pytest

from core.llm_gateway import DEFAULT_CONFIG_PATH
from agents.blackbox.threat_modeler import DEFAULT_RULES_PATH

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "config", "agents_config.yaml")


# --- Packaging: the installed wheel must carry the default config it resolves at runtime -----------

@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib is Python 3.11+")
def test_wheel_ships_the_default_config_files():
    import tomllib
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), "rb") as f:
        setuptools_cfg = tomllib.load(f)["tool"]["setuptools"]
    for default_path in (DEFAULT_CONFIG_PATH, DEFAULT_RULES_PATH):
        rel = os.path.relpath(default_path, REPO_ROOT)
        package, filename = os.path.split(rel)
        # The defaults resolve relative to the install root, i.e. a top-level data package
        assert package == "config", rel
        assert package in setuptools_cfg["packages"]["find"]["include"]
        patterns = setuptools_cfg["package-data"][package]
        assert any(filename.endswith(p.lstrip("*")) for p in patterns), (filename, patterns)


# --- Model output: null / wrong-typed text fields must fall back, not crash the pipeline ----------

def _threat():
    from core.models import ThreatItem, STRIDECategory, FindingSeverity
    return ThreatItem(
        threat_id="T1", stride_category=STRIDECategory.TAMPERING, title="Mass assignment", description="",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="send is_admin", test_verification_goal="is_admin stays false"
    )


def _finding(**update):
    from core.models import ReviewFinding, FindingSeverity
    return ReviewFinding(
        finding_id="WB-CLA-01", reviewer_name="Claude", model_alias="claude", file_path="unknown",
        severity=FindingSeverity.HIGH, title="None crash", description="d", root_cause="r",
        suspected_vibe_flaw="v", suggested_test_scenario="call f(None)"
    ).model_copy(update=update)


_NULL_FIELDS = {"title": None, "rationale": None, "expected_outcome": 7}


def test_null_fields_from_the_attack_synthesizer_fall_back_to_the_threat(fake_live):
    import json
    from core.llm_gateway import LLMGateway
    from agents.blackbox.scenario_builder import ThreatScenarioBuilder
    fake_live(lambda s, u: json.dumps({"code": "def test_x():\n    assert True\n", **_NULL_FIELDS}))
    builder = ThreatScenarioBuilder(LLMGateway(CONFIG, execution_mode="live"))
    tests = builder.build_test_cases_from_threats([_threat()], base_url=None)
    assert len(tests) == 1
    assert tests[0].title == "Security test for Mass assignment"
    assert tests[0].rationale == "send is_admin"
    assert tests[0].expected_outcome == "is_admin stays false"


def test_null_fields_from_the_test_generator_fall_back_to_the_finding(fake_live, tmp_path):
    import json
    from core.llm_gateway import LLMGateway
    from agents.whitebox.test_generator import WhiteboxTestGenerator
    fake_live(lambda s, u: json.dumps({"code": "def test_x():\n    assert True\n", **_NULL_FIELDS}))
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="live"))
    tests = gen.generate_tests_for_findings([_finding()], [], root_dir=str(tmp_path))
    assert [t.test_type for t in tests] == ["whitebox_unit"]
    assert tests[0].title == "None crash"
    assert tests[0].rationale == "call f(None)"
    assert tests[0].expected_outcome == "Graceful handling without crash"


def test_non_string_test_code_is_ignored_not_fatal(fake_live, tmp_path):
    import json
    from core.llm_gateway import LLMGateway
    from agents.whitebox.test_generator import WhiteboxTestGenerator
    fake_live(lambda s, u: json.dumps({"tests": [{"code": ["not", "a", "string"]}, {"code": None}]}))
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="live"))
    assert gen.generate_tests_for_findings([_finding()], [], root_dir=str(tmp_path)) == []
    assert gen.findings_without_model_tests == ["WB-CLA-01"]


def test_null_reviewer_fields_fall_back_but_empty_findings_are_dropped(fake_live, tmp_path):
    import json
    from core.llm_gateway import LLMGateway
    from agents.whitebox.ast_extractor import ASTExtractor
    from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
    (tmp_path / "svc.py").write_text("def f(x):\n    return x.y\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    fake_live(lambda s, u: json.dumps({"findings": [
        {"symbol_name": 42, "severity": "HIGH", "title": None, "description": "x.y crashes on None",
         "root_cause": None, "suspected_vibe_flaw": None, "suggested_test_scenario": None},
        {"symbol_name": "f", "severity": "HIGH", "title": None, "description": None},
    ]}))
    findings = HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live")).review_symbols(
        symbols, root_dir=str(tmp_path)
    )
    assert len(findings) == 4  # the usable finding from each reviewer; the empty one is dropped
    assert all(f.title == "Potential Defect" and f.symbol_name is None for f in findings)
    assert all(f.description == "x.y crashes on None" and f.root_cause == "" for f in findings)


# --- Black-box: no implicit live-HTTP target -----------------------------------------------------

def test_no_base_url_means_in_process_and_no_network_probe(monkeypatch):
    from core.llm_gateway import LLMGateway
    from agents.blackbox.scenario_builder import ThreatScenarioBuilder
    builder = ThreatScenarioBuilder(LLMGateway(CONFIG, execution_mode="mock"))
    probed = []
    monkeypatch.setattr(builder, "check_server_live", lambda url, *a, **k: probed.append(url) or True)
    prompts = []
    monkeypatch.setattr(builder.gateway, "generate", lambda agent, system, user, **k: prompts.append(system) or {})
    builder.build_test_cases_from_threats([_threat()])
    assert probed == []
    assert "In-Process Contract" in prompts[0]


def test_cli_does_not_default_to_a_live_base_url(monkeypatch, tmp_path):
    import main
    seen = {}

    class _Commander:
        def __init__(self, **kwargs):
            pass

        def run_full_pipeline(self, **kwargs):
            seen.update(kwargs)
            from core.models import VibeHarnessSummary
            return VibeHarnessSummary(
                overall_status="INCONCLUSIVE", total_whitebox_findings=0, confirmed_whitebox_bugs=0,
                whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0,
                critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0,
            )

    monkeypatch.setattr(main, "VibeHarnessCommander", _Commander)
    monkeypatch.setattr(sys, "argv", ["vibeharness", "--target", str(tmp_path)])
    with pytest.raises(SystemExit) as exit_info:
        main.main()
    assert exit_info.value.code == 3
    assert seen["base_url"] is None


# --- Executor: the harness header must not break `from __future__` imports ----------------------

def _gen_test(code, test_id="T1", test_type="whitebox_unit"):
    from core.models import GeneratedTest
    return GeneratedTest(
        test_id=test_id, test_type=test_type, target_component="f", title="t", code=code,
        rationale="", expected_outcome=""
    )


@pytest.mark.parametrize("code", [
    "from __future__ import annotations\nfrom m import f\n\ndef test_a() -> None:\n    assert f(1) == 1\n",
    '"""Docstring first."""\nfrom __future__ import annotations\nfrom __future__ import division\n\n'
    "from m import f\n\ndef test_a():\n    assert f(1) == 1\n",
])
def test_future_imports_survive_the_harness_header(tmp_path, code):
    from core.models import TestStatus
    from core.sandbox import LocalSubprocessSandbox
    from runners.test_executor import TestSuiteExecutor
    (tmp_path / "m.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    results, _ = TestSuiteExecutor(LocalSubprocessSandbox(60)).execute_test_suite(
        [_gen_test(code)], working_dir=str(tmp_path)
    )
    assert results[0].status == TestStatus.PASSED, results[0].failure_reason


def test_header_still_precedes_code_without_future_imports():
    from runners.test_executor import TestSuiteExecutor
    assert TestSuiteExecutor._split_future_imports("import os\n\ndef test_a():\n    assert os\n") == (
        "", "import os\n\ndef test_a():\n    assert os\n"
    )


# --- Threat modeling: the same threat from several batches is merged ---------------------------

def test_identical_threats_from_several_batches_are_merged_keeping_highest_severity():
    from core.llm_gateway import LLMGateway
    from core.models import CodeSymbol, FindingSeverity
    from agents.blackbox.threat_modeler import AutomatedThreatModeler
    gw = LLMGateway(CONFIG, execution_mode="mock")
    calls = {"n": 0}

    def responder(agent_id, system_prompt, user_prompt, **k):
        calls["n"] += 1
        return {"threats": [
            # same threat, reworded punctuation/casing, severity differs per batch
            {"threat_id": "THREAT-01", "stride_category": "Tampering", "title": f"Mass Assignment{'!' * calls['n']}",
             "attack_vector": "PUT /users", "severity": "CRITICAL" if calls["n"] == 2 else "MEDIUM"},
            # a different route is a different threat and must be kept
            {"threat_id": "THREAT-02", "stride_category": "Tampering", "title": "Mass assignment",
             "attack_vector": f"PUT /route{calls['n']}"},
        ]}

    gw.generate = responder
    symbols = [CodeSymbol(name=f"f{i}", symbol_type="function", file_path="app.py", line_start=1, line_end=1,
                          signature="f()", source_code="def f():\n" + "    x = 1\n" * 2500) for i in range(3)]
    report = AutomatedThreatModeler(gw).model_system("desc", [], symbols=symbols, root_dir=".")
    assert calls["n"] == 3
    vectors = [t.attack_vector for t in report.threats]
    assert vectors.count("PUT /users") == 1
    assert {"PUT /route1", "PUT /route2", "PUT /route3"} <= set(vectors)
    assert next(t for t in report.threats if t.attack_vector == "PUT /users").severity == FindingSeverity.CRITICAL


def test_mock_threat_model_is_not_multiplied_by_batching(tmp_path):
    from core.llm_gateway import LLMGateway
    from agents.whitebox.ast_extractor import ASTExtractor
    from agents.blackbox.threat_modeler import AutomatedThreatModeler
    (tmp_path / "big.py").write_text("".join(f"def f{i}(x):\n    return x\n\n" for i in range(40)), encoding="utf-8")
    symbols = ASTExtractor().parse_directory(str(tmp_path))
    report = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="mock")).model_system(
        "x", [], symbols=symbols, root_dir=str(tmp_path)
    )
    assert len(report.threats) == len({t.title for t in report.threats}) == 3


def test_structurally_wrong_threat_rules_degrade_to_no_guidance(tmp_path):
    """threat_rules.yaml is user-editable: a YAML file that parses but has the wrong shape
    (a list where a mapping is expected, string entries instead of objects) must skip the
    checklist instead of raising AttributeError out of every modeling batch."""
    from core.llm_gateway import LLMGateway
    from agents.blackbox.threat_modeler import AutomatedThreatModeler
    rules = tmp_path / "threat_rules.yaml"
    rules.write_text(
        "stride_categories:\n  - just a string\n"
        "owasp_api_top10:\n  - 'also a string'\n  - {id: API1, name: BOLA}\n",
        encoding="utf-8",
    )
    tm = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="mock"), rules_path=str(rules))
    guidance = tm._rules_guidance()
    assert "API1 BOLA" in guidance  # the valid entries are still used
    assert "just a string" not in guidance


# --- Offline probes never invoke argument-less functions ---------------------------------------

def test_probes_skip_functions_without_required_arguments(tmp_path):
    from core.llm_gateway import LLMGateway
    from core.sandbox import LocalSubprocessSandbox
    from runners.test_executor import TestSuiteExecutor
    from agents.whitebox.ast_extractor import ASTExtractor
    from agents.whitebox.test_generator import WhiteboxTestGenerator
    marker = tmp_path / "SIDE_EFFECT"
    (tmp_path / "app.py").write_text(
        "def main():\n"
        f"    open({str(marker)!r}, 'w').write('ran')\n\n"
        "def serve(port=8000):\n"
        f"    open({str(marker)!r}, 'w').write('ran')\n\n"
        "def greet(name, *, loud=False):\n    return 'hi ' + name\n\n"
        "def tag(*, label):\n    return label.upper()\n",
        encoding="utf-8"
    )
    symbols = ASTExtractor().parse_file(str(tmp_path / "app.py"))
    probes = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock")).build_offline_probes(symbols)
    assert [p.target_component for p in probes] == ["greet", "tag"]
    TestSuiteExecutor(LocalSubprocessSandbox(60)).execute_test_suite(probes, working_dir=str(tmp_path))
    assert not marker.exists()


# --- SARIF: valid locations, repo-root URIs, run-independent rule ids ---------------------------

def _sarif(findings, target, symbols=None, breaches=(), threats=()):
    import json
    from core.models import MultiModelDebateResult, ThreatModelReport, VibeHarnessSummary
    from reports.report_generator import ReportGenerator
    summary = VibeHarnessSummary(
        overall_status="NEEDS_FIXES", total_whitebox_findings=len(findings), confirmed_whitebox_bugs=len(findings),
        whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=len(threats),
        critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=len(breaches),
    )
    return json.loads(ReportGenerator().generate_sarif_report(
        summary, MultiModelDebateResult(consensus_summary="", confirmed_findings=list(findings)),
        ThreatModelReport(system_description="s", threats=list(threats)), [], list(breaches), str(target),
        symbols=symbols,
    ))["runs"][0]


def test_sarif_never_emits_null_locations(tmp_path):
    run = _sarif([_finding(file_path="unknown"), _finding(finding_id="WB-CLA-02", file_path="")], tmp_path)
    assert len(run["results"]) == 2
    for result in run["results"]:
        assert "locations" not in result  # an explicit null violates the SARIF schema


def test_sarif_uris_are_relative_to_the_enclosing_repository(tmp_path):
    (tmp_path / ".git").mkdir()
    src = tmp_path / "services" / "api"
    src.mkdir(parents=True)
    app = src / "app.py"
    app.write_text("x = 1\n", encoding="utf-8")
    run = _sarif([_finding(file_path=str(app), line_number=3)], src)
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "services/api/app.py"


def test_sarif_root_ignores_a_dotfiles_repo_in_the_home_directory(tmp_path, monkeypatch):
    """A git repo at ~ (a dotfiles/config repo) must not become %SRCROOT% for targets under
    ~: the SARIF URIs would point into a private home path no CI checkout can resolve."""
    from reports.report_generator import ReportGenerator
    real_expanduser = os.path.expanduser
    fake_home = tmp_path / "home"
    (fake_home / ".git").mkdir(parents=True)
    run_dir = fake_home / "runs" / "vibe-target"
    run_dir.mkdir(parents=True)
    monkeypatch.setattr(os.path, "expanduser",
                        lambda p: str(fake_home) if p == "~" else real_expanduser(p))
    assert ReportGenerator._sarif_root(str(run_dir / "app.py")) == str(run_dir)


def test_sarif_rule_ids_and_fingerprints_do_not_depend_on_run_numbering(tmp_path):
    first = _sarif([_finding(file_path="app.py", symbol_name="f", title="None crash in f")], tmp_path)
    # Next run: same defect, renumbered and cosmetically reworded by the model
    second = _sarif([_finding(finding_id="WB-CLA-07", file_path="app.py", symbol_name="f",
                              title="None-crash in f!")], tmp_path)
    a, b = first["results"][0], second["results"][0]
    assert a["ruleId"] == b["ruleId"] == "vibeharness/whitebox-finding"
    assert a["partialFingerprints"] == b["partialFingerprints"]
    assert (a["properties"]["findingId"], b["properties"]["findingId"]) == ("WB-CLA-01", "WB-CLA-07")


def test_sarif_breach_is_located_at_the_attacked_symbol(tmp_path):
    from core.models import CodeSymbol, TestExecutionResult, TestStatus
    route = CodeSymbol(name="update_user_settings", symbol_type="route", file_path=str(tmp_path / "app.py"),
                       line_start=12, line_end=20, signature="", source_code="")
    threat = _threat().model_copy(update={"attack_vector": "PUT /settings via update_user_settings"})
    breach = TestExecutionResult(test_id="BB-TEST-T1", test_type="blackbox_security", status=TestStatus.FAILED,
                                 is_security_exploit_confirmed=True, source_ref="T1", failure_reason="is_admin set")
    run = _sarif([], tmp_path, symbols=[route], breaches=[breach], threats=[threat])
    result = run["results"][0]
    assert result["ruleId"] == "vibeharness/blackbox-breach"
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app.py"
    assert location["region"]["startLine"] == 12
    assert "Mass assignment" in result["message"]["text"]


# --- Executor: a test calling the target with the wrong signature is not a target defect --------

def test_wrong_signature_call_in_the_test_is_an_error_not_a_defect(tmp_path):
    from core.models import TestStatus
    from core.sandbox import LocalSubprocessSandbox
    from runners.test_executor import TestSuiteExecutor
    (tmp_path / "m.py").write_text("def f(x):\n    return g(x, 1)\n\ndef g(a):\n    return a\n", encoding="utf-8")
    results, _ = TestSuiteExecutor(LocalSubprocessSandbox(60)).execute_test_suite([
        _gen_test("from m import g\n\ndef test_a():\n    assert g(1, 2) == 1\n", "TEST-SIG"),
        _gen_test("from m import g\n\ndef test_a():\n    assert g(a=1, b=2) == 1\n", "TEST-KW"),
        # the same TypeError raised inside the target is a genuine defect
        _gen_test("from m import f\n\ndef test_a():\n    assert f(1) == 1\n", "TARGET-SIG"),
        # other TypeErrors raised by the test line stay defects (e.g. None handling)
        _gen_test("def test_a():\n    assert len(None) == 0\n", "OTHER"),
    ], working_dir=str(tmp_path))
    status = {r.test_id: r.status for r in results}
    assert status == {
        "TEST-SIG": TestStatus.ERROR, "TEST-KW": TestStatus.ERROR,
        "TARGET-SIG": TestStatus.FAILED, "OTHER": TestStatus.FAILED,
    }


# --- Docker: the in-container timeout follows the run's own budget ------------------------------

def test_docker_in_container_timeout_uses_the_per_run_budget(tmp_path, monkeypatch):
    from core.sandbox import DockerSandbox
    sandbox = DockerSandbox(timeout_seconds=120, verify=False)
    seen = []
    monkeypatch.setattr(sandbox, "_run", lambda cmd, **k: seen.append(cmd) or (0, "", ""))
    sandbox.execute_pytest_files({"test_x.py": "def test_x():\n    assert 1\n"}, working_dir=str(tmp_path),
                                 timeout_seconds=30)
    sandbox.execute_pytest_files({"test_x.py": "def test_x():\n    assert 1\n"}, working_dir=str(tmp_path))
    budgets = [cmd[cmd.index("--kill-after=5") + 1] for cmd in seen]
    assert budgets == ["30", "120"]


# --- Cross-verification: quoted indices count, booleans do not -----------------------------------

def test_verifier_accepts_quoted_indices_and_rejects_booleans(fake_live):
    import json
    from core.llm_gateway import LLMGateway
    from agents.whitebox.debater import MultiModelDebater
    findings = [_finding(finding_id="A", file_path="app.py"), _finding(finding_id="B", file_path="app.py")]
    # index True would have been read as 1 (bool subclasses int) and voted on finding B
    fake_live(lambda s, u: json.dumps({"verdicts": [
        {"index": " 0 ", "verdict": "Confirm "}, {"index": True, "verdict": "reject"},
    ]}))
    result = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live")).arbitrate(findings)
    votes = {f.finding_id: [v.verdict for v in f.verification_votes] for f in result.confirmed_findings}
    assert votes == {"A": ["confirm", "confirm", "confirm"], "B": []}


def test_one_crashed_verifier_batch_does_not_abort_arbitration(fake_live, monkeypatch):
    """A non-LLM crash in one verifier's batch must not propagate out of the thread pool and
    discard every other verifier's votes; live-mode LLM failures still fail the run loudly."""
    import json
    from core.llm_gateway import LLMGateway
    from agents.whitebox.debater import MultiModelDebater
    findings = [_finding(finding_id="A", file_path="app.py")]
    fake_live(lambda s, u: json.dumps({"verdicts": [{"index": 0, "verdict": "confirm"}]}))
    debater = MultiModelDebater(LLMGateway(CONFIG, execution_mode="live"))
    real_verify = debater._verify

    def flaky_verify(agent_id, *args, **kwargs):
        if agent_id == "whitebox_verifier_deepseek":
            raise RuntimeError("simulated thread crash")
        return real_verify(agent_id, *args, **kwargs)

    monkeypatch.setattr(debater, "_verify", flaky_verify)
    result = debater.arbitrate(findings)
    votes = [v.verdict for f in result.confirmed_findings for v in f.verification_votes]
    assert votes == ["confirm", "confirm"]  # glm's and gemini's votes survived deepseek's crash


# --- Coverage push: degradation and fallback paths of the reviewer ensemble and threat modeler ----

def test_reviewer_ensemble_skips_empty_symbols_without_model_calls():
    from core.llm_gateway import LLMGateway
    from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
    gw = LLMGateway(CONFIG, execution_mode="mock")

    def must_not_be_called(*a, **k):
        raise AssertionError("no model call may be made for an empty symbol list")

    gw.generate = must_not_be_called
    assert HeterogeneousReviewerEnsemble(gw).review_symbols([]) == []


def test_one_crashed_reviewer_batch_does_not_abort_the_review(fake_live, tmp_path, monkeypatch):
    """A non-LLM crash in one reviewer's batch must not discard the other reviewers' findings;
    live-mode LLM failures still propagate (they are re-raised, not swallowed)."""
    import json
    from core.llm_gateway import LLMGateway
    from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
    from agents.whitebox.ast_extractor import ASTExtractor
    (tmp_path / "svc.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    fake_live(lambda s, u: json.dumps({"findings": [{"symbol_name": "f", "title": "ok", "severity": "HIGH"}]}))
    ensemble = HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live"))
    real_batch = ensemble._review_batch

    def flaky_batch(reviewer, batch, root):
        if reviewer["agent_id"] == "whitebox_reviewer_deepseek":
            raise RuntimeError("simulated thread crash")
        return real_batch(reviewer, batch, root)

    monkeypatch.setattr(ensemble, "_review_batch", flaky_batch)
    findings = ensemble.review_symbols(symbols, root_dir=str(tmp_path))
    assert [f.title for f in findings] == ["ok", "ok", "ok"]  # claude, glm and gemini survived
    assert all(not f.is_simulated for f in findings)


def test_unknown_reviewer_severity_falls_back_to_medium(fake_live, tmp_path):
    import json
    from core.llm_gateway import LLMGateway
    from agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
    from core.models import FindingSeverity
    from agents.whitebox.ast_extractor import ASTExtractor
    (tmp_path / "svc.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    fake_live(lambda s, u: json.dumps({"findings": [
        {"symbol_name": "f", "title": "cosmic", "severity": "COSMIC"},
        {"symbol_name": "f", "title": "ok", "severity": "high"},
    ]}))
    findings = HeterogeneousReviewerEnsemble(LLMGateway(CONFIG, execution_mode="live")).review_symbols(
        symbols, root_dir=str(tmp_path)
    )
    by_title = {f.title: f.severity for f in findings}
    assert by_title["cosmic"] == FindingSeverity.MEDIUM
    assert by_title["ok"] == FindingSeverity.HIGH


def test_missing_threat_rules_file_degrades_with_warning():
    from core.llm_gateway import LLMGateway
    from agents.blackbox.threat_modeler import AutomatedThreatModeler
    tm = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="mock"), rules_path="Z:/definitely/not/here.yaml")
    assert tm.rules == {}
    report = tm.model_system("desc", [])
    assert len(report.threats) == 3  # modeling still works, just without the checklist


def test_broken_yaml_threat_rules_degrade_with_warning(tmp_path):
    from core.llm_gateway import LLMGateway
    from agents.blackbox.threat_modeler import AutomatedThreatModeler
    rules = tmp_path / "threat_rules.yaml"
    rules.write_text("stride_categories: [unclosed\n  bad yaml here", encoding="utf-8")
    tm = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="mock"), rules_path=str(rules))
    assert tm.rules == {}
    assert tm._rules_guidance() == ""


def test_non_dict_stride_category_entry_is_skipped(tmp_path):
    from core.llm_gateway import LLMGateway
    from agents.blackbox.threat_modeler import AutomatedThreatModeler
    rules = tmp_path / "threat_rules.yaml"
    rules.write_text(
        "stride_categories:\n"
        "  spoofing: \"not a mapping\"\n"
        "  tampering: {name: Tampering, common_vibe_bugs: [\"mass assignment\"]}\n",
        encoding="utf-8",
    )
    tm = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="mock"), rules_path=str(rules))
    guidance = tm._rules_guidance()
    assert "Tampering: mass assignment" in guidance
    assert "not a mapping" not in guidance


def test_unknown_threat_severity_falls_back_to_high(fake_live):
    import json
    from core.llm_gateway import LLMGateway
    from agents.blackbox.threat_modeler import AutomatedThreatModeler
    from core.models import FindingSeverity
    fake_live(lambda s, u: json.dumps({"threats": [
        {"threat_id": "THREAT-01", "stride_category": "Tampering", "title": "t", "severity": "CATASTROPHIC"},
    ]}))
    report = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="live")).model_system("desc", [])
    assert [t.severity for t in report.threats] == [FindingSeverity.HIGH]


def test_all_unusable_batches_still_produce_a_default_report(fake_live):
    from core.llm_gateway import LLMGateway
    from agents.blackbox.threat_modeler import AutomatedThreatModeler
    fake_live(lambda s, u: "I refuse to answer in JSON.")
    report = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="live")).model_system("desc", ["/api/users"])
    assert report.threats == []
    # report-level fields fall back to what the harness itself passed in
    assert report.entrypoints == ["/api/users"]
    assert not report.is_simulated


def test_coverage_extraction_ignores_malformed_totals():
    from core.sandbox import LocalSubprocessSandbox
    extract = LocalSubprocessSandbox(timeout_seconds=60)._extract_coverage_percent
    assert extract("TOTAL 10 2 87%") == 87.0
    assert extract("TOTAL 10 2 87.5%") == 87.5
    assert extract("TOTAL 10 2 not-a-number%") is None
    assert extract("no table at all") is None
