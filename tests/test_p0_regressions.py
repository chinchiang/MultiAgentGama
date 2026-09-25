"""Regression tests for executor correctness, self-healing, and result-provenance honesty."""
import os
import pytest
from core.models import GeneratedTest, TestStatus, CodeSymbol, AgentCallRecord
from core.llm_gateway import LLMGateway, LLMGatewayError
from core.sandbox import LocalSubprocessSandbox
from core.codecheck import check_test_code, strip_code_fences
from agents.whitebox.ast_extractor import ASTExtractor
from agents.whitebox.test_generator import WhiteboxTestGenerator
from agents.blackbox.threat_modeler import AutomatedThreatModeler
from agents.blackbox.scenario_builder import ThreatScenarioBuilder
from runners.test_executor import TestSuiteExecutor
from core.harness import VibeHarnessCommander

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "config", "agents_config.yaml")
EXAMPLES = os.path.join(REPO_ROOT, "examples")


def _test(test_id, code, test_type="blackbox_security"):
    return GeneratedTest(
        test_id=test_id, test_type=test_type, target_component="x",
        title=f"t {test_id}", code=code, rationale="", expected_outcome=""
    )


@pytest.fixture
def executor():
    return TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60))


# --- Executor ---------------------------------------------------------------

def test_syntax_error_does_not_poison_other_tests(executor, tmp_path):
    results, _ = executor.execute_test_suite([
        _test("OK", "def test_ok():\n    assert True"),
        _test("BROKEN", "def test_b(:\n    pass"),
    ], working_dir=str(tmp_path))
    ok, broken = results
    assert ok.status == TestStatus.PASSED
    assert broken.status == TestStatus.ERROR
    assert not ok.is_security_exploit_confirmed
    assert not broken.is_security_exploit_confirmed


def test_module_level_import_error_is_isolated(executor, tmp_path):
    results, _ = executor.execute_test_suite([
        _test("A", "import definitely_missing_mod\ndef test_a():\n    pass"),
        _test("B", "def test_b():\n    assert 1 == 2"),
    ], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR
    assert not results[0].is_security_exploit_confirmed
    assert results[1].status == TestStatus.FAILED
    assert results[1].is_security_exploit_confirmed


def test_import_error_inside_test_is_error_not_exploit(executor, tmp_path):
    results, _ = executor.execute_test_suite([
        _test("A", "def test_a():\n    import definitely_missing_mod"),
    ], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR
    assert not results[0].is_security_exploit_confirmed


def test_duplicate_ids_and_function_names_run_independently(executor, tmp_path):
    results, _ = executor.execute_test_suite([
        _test("WB-TEST-01", "def test_x():\n    assert False", "whitebox_unit"),
        _test("WB-TEST-01", "def test_x():\n    assert True", "whitebox_unit"),
    ], working_dir=str(tmp_path))
    assert [r.status for r in results] == [TestStatus.FAILED, TestStatus.PASSED]
    assert [r.test_id for r in results] == ["WB-TEST-01", "WB-TEST-01-2"]


def test_code_without_test_function_is_error(executor, tmp_path):
    results, _ = executor.execute_test_suite([_test("A", "x = 1")], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR


def test_non_assertion_crash_in_blackbox_is_failure_but_not_exploit(executor, tmp_path):
    results, _ = executor.execute_test_suite([
        _test("A", "def test_a():\n    {}['missing']"),
    ], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.FAILED
    assert not results[0].is_security_exploit_confirmed


def test_sandbox_does_not_write_into_target(executor, tmp_path):
    executor.execute_test_suite([_test("A", "def test_a():\n    assert True")], working_dir=str(tmp_path), collect_coverage=True)
    assert os.listdir(tmp_path) == []


# --- Self-healing -----------------------------------------------------------

def test_heal_keeps_valid_code_with_leading_imports():
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))
    code = "import pytest\n\ndef test_real():\n    assert 1 == 2"
    assert gen._validate_and_heal(code, 1) == code


def test_heal_strips_markdown_fences():
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))
    fenced = "```python\ndef test_real():\n    assert True\n```"
    assert gen._validate_and_heal(fenced, 1) == "def test_real():\n    assert True"


def test_check_test_code_requires_test_function():
    assert check_test_code("def helper():\n    pass") == (False, "no top-level test_ function defined")
    assert check_test_code("def test_a():\n    pass")[0] is True
    assert strip_code_fences("no fences") == "no fences"


# --- Gateway provenance -----------------------------------------------------

def test_live_mode_without_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    gateway = LLMGateway(CONFIG, execution_mode="live")
    with pytest.raises(LLMGatewayError):
        gateway.generate("whitebox_reviewer_claude", "sys", "prompt")


def test_simulated_responses_are_flagged_and_logged():
    gateway = LLMGateway(CONFIG, execution_mode="mock")
    resp = gateway.generate("whitebox_reviewer_claude", "sys", "prompt")
    assert gateway.is_simulated(resp)
    assert gateway.used_simulation
    assert gateway.call_log[0].mode == "simulated"


def test_invalid_execution_mode_rejected():
    with pytest.raises(ValueError):
        LLMGateway(CONFIG, execution_mode="yolo")


# --- No hardcoded sample-app tests -------------------------------------------

def test_offline_probes_derive_from_target_not_sample_app(executor, tmp_path):
    target = tmp_path / "shop.py"
    target.write_text(
        "def safe(x):\n    if x is None:\n        raise ValueError('x required')\n    return x\n\n"
        "def crashy(order):\n    return order['id']\n",
        encoding="utf-8"
    )
    symbols = ASTExtractor().parse_file(str(target))
    probes = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock")).build_offline_probes(symbols)
    assert [p.target_component for p in probes] == ["safe", "crashy"]
    assert all("vibe_sample_app" not in p.code for p in probes)

    results, _ = executor.execute_test_suite(probes, working_dir=str(tmp_path))
    assert [r.status for r in results] == [TestStatus.PASSED, TestStatus.FAILED]


def test_simulated_blackbox_does_not_fabricate_tests():
    gateway = LLMGateway(CONFIG, execution_mode="mock")
    threats = AutomatedThreatModeler(gateway).model_system("API", ["/api/users"]).threats
    tests = ThreatScenarioBuilder(gateway).build_test_cases_from_threats(threats, base_url="http://localhost:59999")
    assert tests == []


def test_mock_pipeline_is_never_ready_to_ship_and_report_discloses_simulation(tmp_path):
    report_path = tmp_path / "report.md"
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    summary = commander.run_full_pipeline(
        target_dir=EXAMPLES, base_url="http://localhost:59999", output_report_path=str(report_path)
    )
    assert summary.overall_status != "READY_TO_SHIP"
    assert summary.untested_threat_ids  # simulated threats have no real tests
    assert all(isinstance(c, AgentCallRecord) and c.mode == "simulated" for c in summary.agent_calls)

    report = report_path.read_text(encoding="utf-8")
    assert "SIMULATED RESULTS" in report
    assert "Threats Not Tested" in report
    assert "| Metric | Value | Target |" in report


def test_clean_target_in_mock_mode_is_inconclusive(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "ok.py").write_text(
        "def greet(name):\n    if name is None:\n        raise ValueError('name required')\n    return 'hi ' + name\n",
        encoding="utf-8"
    )
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    summary = commander.run_full_pipeline(
        target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md")
    )
    assert summary.whitebox_tests_failed == 0
    assert summary.overall_status == "INCONCLUSIVE"
    assert summary.inconclusive_reasons
