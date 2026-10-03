"""Regression tests for executor correctness, self-healing, and result-provenance honesty."""
import os
import sys
import pytest
from core.models import GeneratedTest, TestStatus, AgentCallRecord
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
        _test("A", "def test_a():\n    import definitely_missing_mod\n    assert definitely_missing_mod"),
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
        _test("A", "def test_a():\n    assert {}['missing']"),
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
    assert check_test_code("def test_a():\n    assert 1")[0] is True
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


def test_completion_without_api_key_env_fails_with_actionable_error():
    gateway = LLMGateway(CONFIG, execution_mode="mock")
    with pytest.raises(LLMGatewayError, match="api_key_env"):
        gateway._complete({}, "some-model", [{"role": "user", "content": "hi"}], 0.2)


def test_null_config_sections_are_treated_as_empty(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("global:\n  execution_mode: mock\nmodels:\nagents:\n", encoding="utf-8")
    gateway = LLMGateway(str(cfg), execution_mode="mock")
    assert gateway.models_config == {} and gateway.agents_config == {}
    resp = gateway.generate("any_agent", "sys", "user")
    assert gateway.is_simulated(resp)


def test_force_utf8_stdio_is_safe_to_call():
    from core.harness import force_utf8_stdio
    force_utf8_stdio()  # must not raise on any platform, including pytest's captured streams
    assert sys.stdout.writable()


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


# --- Gate honesty: vacuous tests, unusable model output, arbitration ---------

def test_vacuous_test_is_error_not_defended(executor, tmp_path):
    results, _ = executor.execute_test_suite([_test("A", "def test_a():\n    pass")], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR
    assert "without any assertion" in results[0].failure_reason


def test_check_test_code_accepts_assertion_forms():
    assert check_test_code("import pytest\ndef test_a():\n    with pytest.raises(ValueError):\n        int('x')")[0]
    assert check_test_code("def test_a():\n    raise AssertionError('boom')")[0]
    assert check_test_code("def test_a():\n    pytest.fail('x')")[0]
    assert not check_test_code("def test_a():\n    x = 1\ndef test_b():\n    assert x")[0]


def test_unparseable_live_output_is_recorded_invalid(fake_live):
    fake_live(lambda s, u: "Sorry, I cannot help with that.")
    gateway = LLMGateway(CONFIG, execution_mode="live")
    resp = gateway.generate("whitebox_reviewer_claude", "sys", "prompt", required_keys=["findings"])
    assert not gateway.is_usable(resp)
    assert "findings" not in resp
    assert [c.mode for c in gateway.call_log] == ["invalid"]


def test_missing_required_key_is_recorded_invalid(fake_live):
    fake_live(lambda s, u: '{"something_else": []}')
    gateway = LLMGateway(CONFIG, execution_mode="hybrid")
    gateway.generate("blackbox_threat_modeler", "sys", "prompt", required_keys=["threats"])
    assert gateway.invalid_calls and "threats" in gateway.invalid_calls[0].reason


def test_unusable_threat_model_and_modeled_criticals_never_ship_or_block(fake_live, tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "ok.py").write_text("def greet(name):\n    return 'hi'\n", encoding="utf-8")
    critical = ('{"threat_id": "T%d", "stride_category": "Spoofing", "title": "t", "severity": "CRITICAL"}')
    threats = '{"threats": [%s]}' % ", ".join(critical % i for i in range(4))

    def responder(system, user):
        if "Threat Modeling Specialist" in system:
            return threats
        return "not json"
    fake_live(responder)
    summary = VibeHarnessCommander(config_path=CONFIG, execution_mode="live").run_full_pipeline(
        target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md")
    )
    # 4 modeled CRITICAL threats are hypotheses, not evidence; unusable outputs make the run inconclusive
    assert summary.overall_status == "INCONCLUSIVE"
    assert any("unusable output" in r for r in summary.inconclusive_reasons)
    assert "invalid output" in (tmp_path / "r.md").read_text(encoding="utf-8")


def test_single_file_target_is_analyzed(tmp_path):
    target = tmp_path / "one.py"
    target.write_text("def crashy(order):\n    return order['id']\n", encoding="utf-8")
    summary = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock").run_full_pipeline(
        target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md")
    )
    assert summary.whitebox_tests_failed == 1
    assert sorted(os.listdir(tmp_path)) == ["one.py", "r.md"]


def test_server_returning_404_counts_as_live():
    import threading
    import http.server

    class NotFound(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), NotFound)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert ThreatScenarioBuilder(None).check_server_live(f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()


def test_probe_handles_keyword_only_and_skips_decorated_async(executor, tmp_path):
    target = tmp_path / "kw.py"
    target.write_text(
        "import functools\n\n"
        "def guarded(*, x):\n    if x is None:\n        raise ValueError('x required')\n    return x\n\n"
        "@functools.lru_cache\nasync def fetch(x):\n    return x['id']\n",
        encoding="utf-8"
    )
    symbols = ASTExtractor().parse_file(str(target))
    probes = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock")).build_offline_probes(symbols)
    assert [p.target_component for p in probes] == ["guarded"]
    results, _ = executor.execute_test_suite(probes, working_dir=str(tmp_path))
    assert results[0].status == TestStatus.PASSED


# --- Sandbox hardening -------------------------------------------------------

def test_sandbox_withholds_secrets_from_generated_code(executor, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak")
    results, _ = executor.execute_test_suite([_test("A", (
        "import os\n"
        "def test_env():\n"
        "    leaked = [k for k in os.environ if 'KEY' in k or 'SECRET' in k]\n"
        "    assert not leaked, leaked\n"
    ))], working_dir=str(tmp_path))
    assert results[0].status == TestStatus.PASSED, results[0].failure_reason


def test_hanging_test_does_not_void_the_batch(tmp_path):
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=8), per_test_timeout_seconds=4)
    results, _ = executor.execute_test_suite([
        _test("OK", "def test_ok():\n    assert True"),
        _test("HANG", "import time\ndef test_hang():\n    time.sleep(60)\n    assert True"),
        _test("BAD", "def test_bad():\n    assert 1 == 2"),
    ], working_dir=str(tmp_path))
    assert [r.status for r in results] == [TestStatus.PASSED, TestStatus.ERROR, TestStatus.FAILED]
    assert "timed out" in results[1].failure_reason


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group kill semantics")
def test_daemonized_grandchild_cannot_hang_the_sandbox(tmp_path):
    """A grandchild in a new session survives the process-group kill; the sandbox must
    drain its pipes with a short timeout instead of blocking on communicate() forever."""
    import subprocess
    import time
    from core.sandbox import TIMEOUT_EXIT_CODE

    code = (
        "import subprocess, sys, time\n"
        "def test_daemon():\n"
        "    subprocess.Popen(\n"
        "        [sys.executable, '-c', 'import time; time.sleep(120)'],\n"
        "        start_new_session=True,\n"
        "    )\n"
        "    time.sleep(60)\n"
    )
    sandbox = LocalSubprocessSandbox(timeout_seconds=60)
    start = time.monotonic()
    try:
        exit_code, _, stderr, *_ = sandbox.execute_pytest_files(
            {"test_daemon_test.py": code}, working_dir=str(tmp_path), timeout_seconds=2
        )
        elapsed = time.monotonic() - start
        assert exit_code == TIMEOUT_EXIT_CODE
        # kill + ~5s pipe drain; a hang would run until the 120s grandchild exits
        assert elapsed < 20, f"sandbox blocked for {elapsed:.1f}s on a daemonized grandchild"
        assert "timed out" in stderr.lower()
    finally:
        subprocess.run(["pkill", "-f", "time.sleep(120)"], capture_output=True)


def test_results_carry_their_own_output(executor, tmp_path):
    results, _ = executor.execute_test_suite([
        _test("A", "def test_a():\n    print('from-a')\n    assert True"),
        _test("B", "def test_b():\n    print('from-b')\n    assert True"),
    ], working_dir=str(tmp_path))
    assert "from-a" in results[0].stdout and "from-b" not in results[0].stdout
    assert "from-b" in results[1].stdout


def test_unimplemented_sandbox_provider_is_rejected(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("global:\n  sandbox_provider: e2b\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not implemented"):
        VibeHarnessCommander(config_path=str(cfg), execution_mode="mock")


# --- CLI surface ---------------------------------------------------------------

def test_litellm_retry_dependency_is_installed():
    # litellm needs tenacity for num_retries > 0 (live mode) but does not install it itself;
    # if requirements.txt ever drops it, this fails in CI instead of at the user's first live call.
    pytest.importorskip("litellm")
    import tenacity  # noqa: F401


def test_cli_reports_the_package_version():
    import subprocess
    from core import __version__
    proc = subprocess.run(
        [sys.executable, "main.py", "--version"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert __version__ in proc.stdout


def test_cli_rejects_unknown_report_format():
    import subprocess
    proc = subprocess.run(
        [sys.executable, "main.py", "--target", EXAMPLES, "--format", "xml"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 5  # usage errors must not collide with verdict code 2
    assert "invalid choice" in (proc.stderr + proc.stdout)


def test_cli_exit_code_semantics_are_disjoint():
    from main import verdict_exit_code
    assert verdict_exit_code("BLOCKED_CRITICAL_RISK") == 2
    assert verdict_exit_code("NEEDS_FIXES") == 1
    assert verdict_exit_code("INCONCLUSIVE") == 3
    assert verdict_exit_code("READY_TO_SHIP") == 0
    # An unknown verdict must fail closed, never as a clean pass
    assert verdict_exit_code("SOMETHING_ELSE") == 3


def test_cli_missing_config_is_usage_error_not_needs_fixes():
    import subprocess
    proc = subprocess.run(
        [sys.executable, "main.py", "--target", EXAMPLES, "--config", "/nonexistent/agents_config.yaml"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 5
    assert "Agent config not found" in proc.stderr


def test_cli_malformed_config_yaml_is_usage_error():
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        bad = os.path.join(td, "bad.yaml")
        with open(bad, "w", encoding="utf-8") as f:
            f.write("global: [unclosed\n")
        proc = subprocess.run(
            [sys.executable, "main.py", "--target", EXAMPLES, "--config", bad],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60
        )
    assert proc.returncode == 5
    assert "not valid YAML" in proc.stderr


def test_cli_missing_target_is_usage_error():
    import subprocess
    proc = subprocess.run(
        [sys.executable, "main.py", "--target", "/nonexistent/target/dir"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 5
