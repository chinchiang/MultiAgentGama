"""執行器正確性、自我修復與結果來源誠實性的回歸測試。
Regression tests for executor correctness, self-healing, and result-provenance honesty."""
import json
import os
import sys
import pytest
from vibeharness.core.models import GeneratedTest, TestStatus, AgentCallRecord
from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError
from vibeharness.core.sandbox import LocalSubprocessSandbox, SandboxRun, TIMEOUT_EXIT_CODE
from vibeharness.core.codecheck import check_test_code, strip_code_fences
from vibeharness.core.codecontext import import_instructions
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
from vibeharness.runners.test_executor import SuiteResult, TestSuiteExecutor
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.reports.report_generator import METRIC_TABLE_HEADER
from vibeharness.core.model_output import ANY, OutputSchema

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
EXAMPLES = os.path.join(REPO_ROOT, "examples")


def _test(test_id, code, test_type="blackbox_security"):
    return GeneratedTest(
        test_id=test_id, test_type=test_type, target_component="x",
        title=f"t {test_id}", code=code, rationale="", expected_outcome=""
    )


@pytest.fixture
def executor():
    return TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60))


# --- 執行器 -------------------------------------------------------------------
# --- Executor ---------------------------------------------------------------

def test_syntax_error_does_not_poison_other_tests(executor, tmp_path):
    results = executor.execute_test_suite([
        _test("OK", "def test_ok():\n    assert True"),
        _test("BROKEN", "def test_b(:\n    pass"),
    ], working_dir=str(tmp_path)).results
    ok, broken = results
    assert ok.status == TestStatus.PASSED
    assert broken.status == TestStatus.ERROR
    assert not ok.is_security_exploit_confirmed
    assert not broken.is_security_exploit_confirmed


def test_module_level_import_error_is_isolated(executor, tmp_path):
    results = executor.execute_test_suite([
        _test("A", "import definitely_missing_mod\ndef test_a():\n    pass"),
        _test("B", "def test_b():\n    assert 1 == 2"),
    ], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.ERROR
    assert not results[0].is_security_exploit_confirmed
    assert results[1].status == TestStatus.FAILED
    assert results[1].is_security_exploit_confirmed


def test_parent_dir_module_does_not_shadow_the_target(executor, tmp_path):
    """proj\\m.py 不得遮蔽 proj\\app\\m.py：在產生的標頭中，目標目錄最終位於
    sys.path[0]（與沙盒的 PYTHONPATH 順序一致），因此受測模組永遠勝過
    上層目錄中的同名模組。
    proj\\m.py must not shadow proj\\app\\m.py: in the generated header the target
    directory ends up at sys.path[0] (matching the sandbox PYTHONPATH order), so the
    module under test always wins over a same-named module in the parent directory."""
    (tmp_path / "m.py").write_text("WHO = 'parent'\ndef f(x):\n    return WHO\n", encoding="utf-8")
    app = tmp_path / "app"
    app.mkdir()
    (app / "m.py").write_text("WHO = 'target'\ndef f(x):\n    return WHO\n", encoding="utf-8")
    results = executor.execute_test_suite(
        [_test("A", "from m import f\n\ndef test_which():\n    assert f(1) == 'target'")],
        working_dir=str(app),
    ).results
    assert results[0].status == TestStatus.PASSED, results[0].failure_reason


# --- 執行器：誠實歸因沙盒／報告的失敗 -------------------------------------------------------
# --- Executor: honest attribution of sandbox/report failures -------------------------------------

def test_unparseable_junit_report_is_not_reported_as_no_tests_collected(executor, tmp_path, monkeypatch):
    """被截斷／毀損的 JUnit 報告是沙盒的問題，而不是「產生的程式碼沒有收集到任何測試」，
    後者會錯誤地歸咎於產生的測試。
    A truncated/corrupt JUnit report is a sandbox problem, not 'no test was collected
    from the generated code', which would wrongly blame the generated tests."""
    def broken_report(files, working_dir=None, **kwargs):
        return SandboxRun(0, "", "", 0.1, None, "<testsuites><truncated")

    monkeypatch.setattr(executor.sandbox, "execute_pytest_files", broken_report)
    results = executor.execute_test_suite([
        _test("A", "def test_a():\n    assert True"),
        _test("B", "def test_b():\n    assert True"),
    ], working_dir=str(tmp_path)).results
    assert [r.status for r in results] == [TestStatus.ERROR, TestStatus.ERROR]
    for r in results:
        assert "could not be parsed" in r.failure_reason
        assert "No test was collected" not in r.failure_reason


def test_rerun_report_parse_failure_is_reported_honestly(executor, tmp_path, monkeypatch):
    def batch_times_out_then_bad_report(files, working_dir=None, **kwargs):
        if len(files) > 1:
            return SandboxRun(TIMEOUT_EXIT_CODE, "", "", 0.0, None, None)
        return SandboxRun(0, "", "", 0.1, None, "<junk")

    monkeypatch.setattr(executor.sandbox, "execute_pytest_files", batch_times_out_then_bad_report)
    results = executor.execute_test_suite([
        _test("A", "def test_a():\n    assert True"),
        _test("B", "def test_b():\n    assert True"),
    ], working_dir=str(tmp_path)).results
    assert [r.status for r in results] == [TestStatus.ERROR, TestStatus.ERROR]
    for r in results:
        assert "could not be parsed" in r.failure_reason


def test_broken_target_import_is_attributed_to_the_target(executor, tmp_path):
    """連匯入都失敗的目標（缺少相依套件）代表目標本身壞了：報告必須把錯誤歸因於
    目標而非產生的測試，也不得宣稱已演練過該邊界。
    A target that cannot even be imported (missing dependency) means the target is
    broken: the report must attribute the error to the target instead of the generated
    test, and must not claim the boundary was exercised."""
    (tmp_path / "m.py").write_text("import nonexistent_pkg_xyz\n\ndef f(x):\n    return x\n", encoding="utf-8")
    results = executor.execute_test_suite(
        [_test("A", "from m import f\n\ndef test_a():\n    assert f(1) == 1")],
        working_dir=str(tmp_path),
    ).results
    r = results[0]
    assert r.status == TestStatus.ERROR
    assert "Target code is broken" in r.failure_reason, r.failure_reason
    assert "nonexistent_pkg_xyz" in r.failure_reason
    assert r.is_security_exploit_confirmed is False


def test_test_side_import_error_still_blames_the_test(executor, tmp_path):
    results = executor.execute_test_suite(
        [_test("A", "import definitely_missing_mod\n\ndef test_a():\n    assert True")],
        working_dir=str(tmp_path),
    ).results
    r = results[0]
    assert r.status == TestStatus.ERROR
    assert "Target code is broken" not in r.failure_reason
    assert "definitely_missing_mod" in r.failure_reason


def test_pytest_fail_is_recognized_as_confirmed_exploit(executor, tmp_path):
    results = executor.execute_test_suite([
        _test("FAIL_CALL", "import pytest\ndef test_exploit():\n    pytest.fail('BOLA breach succeeded')"),
    ], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.FAILED
    assert results[0].is_security_exploit_confirmed is True
    assert "BOLA breach succeeded" in (results[0].failure_reason or "")


def test_did_not_raise_is_recognized_as_confirmed_exploit(executor, tmp_path):
    """缺少防禦（`pytest.raises` 未被滿足）必須和其他斷言失敗一樣算作已確認的攻擊成功，
    而不是非安全性的測試錯誤。
    A missing defense (`pytest.raises` not satisfied) must count as a confirmed exploit
    like any other assertion failure, not as a non-security test error."""
    (tmp_path / "m.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    results = executor.execute_test_suite([
        _test("NO_RAISE", "import pytest\nfrom m import f\n\ndef test_exploit():\n"
                          "    with pytest.raises(ValueError):\n        f(None)"),
    ], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.FAILED
    assert results[0].is_security_exploit_confirmed is True
    assert "DID NOT RAISE" in (results[0].failure_reason or "")


def test_is_assertion_recognizes_assertion_and_pytest_fail():
    assert TestSuiteExecutor._is_assertion("AssertionError: value mismatch")
    assert TestSuiteExecutor._is_assertion("assert 1 == 2")
    assert TestSuiteExecutor._is_assertion("Failed: exploit confirmed")
    assert TestSuiteExecutor._is_assertion("Failed")
    assert not TestSuiteExecutor._is_assertion("TypeError: takes 0 arguments")
    assert not TestSuiteExecutor._is_assertion("ValueError: bad value")
    assert not TestSuiteExecutor._is_assertion("")


def test_import_error_inside_test_is_error_not_exploit(executor, tmp_path):
    results = executor.execute_test_suite([
        _test("A", "def test_a():\n    import definitely_missing_mod\n    assert definitely_missing_mod"),
    ], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.ERROR
    assert not results[0].is_security_exploit_confirmed


def test_duplicate_ids_and_function_names_run_independently(executor, tmp_path):
    results = executor.execute_test_suite([
        _test("WB-TEST-01", "def test_x():\n    assert False", "whitebox_unit"),
        _test("WB-TEST-01", "def test_x():\n    assert True", "whitebox_unit"),
    ], working_dir=str(tmp_path)).results
    assert [r.status for r in results] == [TestStatus.FAILED, TestStatus.PASSED]
    assert [r.test_id for r in results] == ["WB-TEST-01", "WB-TEST-01-2"]


def test_code_without_test_function_is_error(executor, tmp_path):
    results = executor.execute_test_suite([_test("A", "x = 1")], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.ERROR


def test_metadata_newlines_cannot_inject_code(executor, tmp_path):
    """產生的模組標頭會把模型控制的中繼資料內插到註解中；title／target_component 中的
    換行會逃出註解並加入未驗證的程式碼。
    The generated-module header interpolates LLM-controlled metadata into a comment;
    a newline in title/target_component would escape it and add unvalidated code."""
    injected = _test(
        "INJ",
        "def test_ok():\n    assert True",
    )
    injected = injected.model_copy(update={
        "title": "nice\ndef test_evicted():\n    assert False",
        "target_component": "x\nimport os\nassert os is None or True",
    })
    results = executor.execute_test_suite([injected], working_dir=str(tmp_path)).results
    # 只有通過驗證的測試函式會執行；注入的行只是無作用的註解文字
    # Only the validated test function runs; the injected lines are inert comment text
    assert results[0].status == TestStatus.PASSED
    assert results[0].is_security_exploit_confirmed is False


# --- JUnit 解析／重跑預算 -------------------------------------------------------
# --- JUnit parsing / rerun budget ---------------------------------------------

def test_junit_modules_beyond_999_are_not_merged():
    xml = (
        "<testsuite name='pytest'>"
        "<testcase classname='test_vh_1000' name='test_a' time='0.1'/>"
        "<testcase classname='test_vh_1001' name='test_b' time='0.1'/>"
        "</testsuite>"
    )
    cases = TestSuiteExecutor._parse_junit(xml)
    assert sorted(cases) == ["test_vh_1000", "test_vh_1001"]


def test_junit_garbage_time_does_not_crash():
    cases = TestSuiteExecutor._parse_junit(
        "<testsuite><testcase classname='test_vh_000' name='test_a' time='not-a-float'/></testsuite>"
    )
    assert cases["test_vh_000"][0]["time"] == 0.0


class _FakeSandbox:
    """沙盒的替身，讓逾時／重跑路徑不需產生行程就能執行。
    Stands in for the sandbox so timeout/rerun paths run without spawning processes."""

    def __init__(self, batch_exit=TIMEOUT_EXIT_CODE, individual_junit=None, timeout_seconds=60):
        self.timeout_seconds = timeout_seconds
        self.batch_exit = batch_exit
        self.individual_junit = individual_junit
        self.individual_calls = 0

    def execute_pytest_files(self, files, **kwargs):
        if len(files) == 1 and self.individual_junit is not None:
            self.individual_calls += 1
            return SandboxRun(0, "", "", 0.1, None, self.individual_junit)
        return SandboxRun(self.batch_exit, "", "Execution timed out after 60 seconds.", 60.0, None, None)


def test_partially_skipped_module_is_flagged(tmp_path):
    junit = (
        "<testsuite>"
        "<testcase classname='test_vh_000' name='test_a' time='0.1'/>"
        "<testcase classname='test_vh_000' name='test_b' time='0.1'><skipped message='cond'/></testcase>"
        "</testsuite>"
    )
    executor = TestSuiteExecutor(_FakeSandbox(batch_exit=0, individual_junit=junit))
    results = executor.execute_test_suite([_test("A", "def test_a():\n    assert True")], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.PASSED
    assert "skipped" in results[0].failure_reason


def test_single_module_timeout_says_so_instead_of_no_report(tmp_path):
    executor = TestSuiteExecutor(_FakeSandbox(timeout_seconds=60))
    results = executor.execute_test_suite([_test("A", "def test_a():\n    assert True")], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.ERROR
    assert "timed out" in results[0].failure_reason and "no per-test report" in results[0].failure_reason


def test_rerun_budget_is_capped_by_the_batch_budget(tmp_path):
    sandbox = _FakeSandbox(timeout_seconds=0)
    executor = TestSuiteExecutor(sandbox, per_test_timeout_seconds=30)
    results = executor.execute_test_suite([
        _test("A", "def test_a():\n    assert True"),
        _test("B", "def test_b():\n    assert True"),
    ], working_dir=str(tmp_path)).results
    # 批次逾時且（為零的）重跑預算立刻耗盡：沒有任何模組被重跑
    # The batch timed out and the (zero) rerun budget is exhausted immediately: no module is re-run
    assert sandbox.individual_calls == 0
    assert all(r.status == TestStatus.ERROR and "Rerun budget" in r.failure_reason for r in results)


def test_non_assertion_crash_in_blackbox_is_failure_but_not_exploit(executor, tmp_path):
    results = executor.execute_test_suite([
        _test("A", "def test_a():\n    assert {}['missing']"),
    ], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.FAILED
    assert not results[0].is_security_exploit_confirmed


def test_sandbox_does_not_write_into_target(executor, tmp_path):
    executor.execute_test_suite([_test("A", "def test_a():\n    assert True")], working_dir=str(tmp_path), collect_coverage=True)
    assert os.listdir(tmp_path) == []


# --- 自我修復 -------------------------------------------------------------------
# --- Self-healing -----------------------------------------------------------

def test_heal_keeps_valid_code_with_leading_imports():
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))
    code = "import pytest\n\ndef test_real():\n    assert 1 == 2"
    assert gen._validate_and_heal(code, "finding WB-F-001") == code


def test_heal_strips_markdown_fences():
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))
    fenced = "```python\ndef test_real():\n    assert True\n```"
    assert gen._validate_and_heal(fenced, "finding WB-F-001") == "def test_real():\n    assert True"


def test_check_test_code_requires_test_function():
    assert check_test_code("def helper():\n    pass") == (False, "no top-level test_ function defined")
    assert check_test_code("def test_a():\n    assert 1")[0] is True
    assert strip_code_fences("no fences") == "no fences"


def test_check_test_code_accepts_class_based_tests():
    valid = (
        "class TestRepo:\n"
        "    def test_add(self):\n"
        "        assert 1 + 1 == 2\n"
    )
    assert check_test_code(valid)[0] is True
    # 沒有任何 test_ 方法的 Test* 類別，pytest 也不會收集
    # A Test* class without any test_ method is not collected by pytest either
    helper_class = "class TestConfig:\n    def settings(self):\n        return {}\n"
    assert check_test_code(helper_class)[0] is False


def test_check_test_code_survives_null_bytes_and_deep_nesting():
    is_valid, problem = check_test_code("def test_a():\n    assert 1\x00")
    assert not is_valid and "syntax error" in problem
    is_valid, problem = check_test_code("def test_a():\n" + "    if True:\n" * 2000 + "        assert 1\n")
    assert not is_valid and "syntax error" in problem


def test_strip_code_fences_never_leaks_the_language_tag():
    assert strip_code_fences("```python3\nx = 1\n```") == "x = 1"
    assert strip_code_fences("```Python\nx = 1\n```") == "x = 1"
    assert strip_code_fences("```js\nlet x = 1;\n```") == "let x = 1;"
    assert strip_code_fences("```\nx = 1\n```") == "x = 1"
    assert strip_code_fences("```python\nx = 1\n```\n```python\ny = 2\n```") == "x = 1"


def test_mock_assertion_calls_do_not_satisfy_the_assertion_gate():
    # 只戳記錄用方法的測試，對目標沒有任何檢查
    # A test that only pokes bookkeeping methods checks nothing about the target
    is_valid, problem = check_test_code(
        "def test_a():\n"
        "    mock = FakeRepo()\n"
        "    mock.save({'id': 1})\n"
        "    mock.assert_called_once()\n"
    )
    assert not is_valid
    assert "without any assertion" in problem
    # 只是*看起來*像斷言的輔助函式也不算斷言
    # A helper that merely *looks* like an assertion is not one either
    is_valid, problem = check_test_code(
        "def test_b():\n"
        "    assert_equal(1, 2)\n"
    )
    assert not is_valid
    assert "without any assertion" in problem


# --- 閘道來源紀錄 ---------------------------------------------------------------
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
        gateway._complete("some_agent", "some_alias", {}, "some-model", [{"role": "user", "content": "hi"}], 0.2)


def test_null_config_sections_are_treated_as_empty(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("global:\n  execution_mode: mock\nmodels:\nagents:\n", encoding="utf-8")
    gateway = LLMGateway(str(cfg), execution_mode="mock")
    assert gateway.models_config == {} and gateway.agents_config == {}
    resp = gateway.generate("any_agent", "sys", "user")
    assert gateway.is_simulated(resp)


def test_force_utf8_stdio_is_safe_to_call():
    from vibeharness.core.harness import force_utf8_stdio
    force_utf8_stdio()  # 在任何平台上都不得拋出例外，包括 pytest 擷取的串流 ／ must not raise on any platform, including pytest's captured streams
    assert sys.stdout.writable()


def test_one_stdio_guard_serves_the_cli_the_action_and_the_harness():
    """CLI、Action runner 與 harness 用同一個串流防護（core/stdio.py），沒有各自的版本。
    The CLI, the Action runner and the harness share one stream guard (core/stdio.py), not versions of their own."""
    from vibeharness import action_runner, cli
    from vibeharness.core import harness, stdio
    assert cli.force_utf8_stdio is action_runner.force_utf8_stdio is harness.force_utf8_stdio is stdio.force_utf8_stdio


@pytest.mark.skipif(sys.platform == "win32", reason="Windows 一律改成 UTF-8 ／ Windows always switches to UTF-8")
def test_stdio_guard_writes_unencodable_text_with_backslashreplace(monkeypatch):
    """寫不出雙語文字的嚴格串流（例如 LANG=C 的 ASCII）改用 backslashreplace，寫中文不會當掉；UTF-8 串流不變。
    A strict stream that cannot write the bilingual text (e.g. ASCII under LANG=C) switches to backslashreplace, so
    writing Chinese no longer crashes; a UTF-8 stream is left as it is."""
    import io
    from vibeharness.core.stdio import force_utf8_stdio
    ascii_out = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
    utf8_err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict")
    monkeypatch.setattr(sys, "stdout", ascii_out)
    monkeypatch.setattr(sys, "stderr", utf8_err)
    force_utf8_stdio()
    assert (ascii_out.errors, utf8_err.errors) == ("backslashreplace", "strict")
    ascii_out.write("錯誤")
    ascii_out.flush()
    assert ascii_out.buffer.getvalue() == b"\\u932f\\u8aa4"


# --- 沒有寫死的範例應用程式測試 -------------------------------------------------
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

    results = executor.execute_test_suite(probes, working_dir=str(tmp_path)).results
    assert [r.status for r in results] == [TestStatus.PASSED, TestStatus.FAILED]


def test_offline_probes_only_target_python_functions_with_required_arguments(tmp_path):
    """None 探測只針對有必要引數的 Python 函式：類別、JS 函式與沒有必要引數的函式都不探測。
    None probes only target Python functions with required arguments: classes, JS functions and functions without
    required arguments are never probed."""
    (tmp_path / "app.py").write_text(
        "class Repo:\n    pass\n\ndef f():\n    return 1\n\ndef g(x=1):\n    return x\n\ndef h(x):\n    return x\n",
        encoding="utf-8")
    (tmp_path / "auth.mjs").write_text("export function login(user) {\n  return user.name;\n}\n", encoding="utf-8")
    symbols = ASTExtractor().parse_directory(str(tmp_path))
    assert {"Repo", "f", "g", "h", "login"} <= {s.name for s in symbols}
    probes = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock")).build_offline_probes(symbols)
    assert [p.target_component for p in probes] == ["h"]


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
    assert summary.untested_threat_ids  # 模擬的威脅沒有真正的測試 ／ simulated threats have no real tests
    assert all(isinstance(c, AgentCallRecord) and c.mode == "simulated" for c in summary.agent_calls)

    report = report_path.read_text(encoding="utf-8")
    assert "SIMULATED RESULTS" in report
    assert "Threats Not Tested" in report
    assert METRIC_TABLE_HEADER in report


# --- 關卡的誠實性：空洞測試、無法使用的模型輸出、仲裁 ---------------------------
# --- Gate honesty: vacuous tests, unusable model output, arbitration ---------

def test_vacuous_test_is_error_not_defended(executor, tmp_path):
    results = executor.execute_test_suite([_test("A", "def test_a():\n    pass")], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.ERROR
    assert "without any assertion" in results[0].failure_reason


def test_check_test_code_accepts_assertion_forms():
    assert check_test_code("import pytest\ndef test_a():\n    with pytest.raises(ValueError):\n        int('x')")[0]
    assert check_test_code("def test_a():\n    raise AssertionError('boom')")[0]
    assert check_test_code("def test_a():\n    pytest.fail('x')")[0]
    assert not check_test_code("def test_a():\n    x = 1\ndef test_b():\n    assert x")[0]


def test_check_test_code_rejects_uncalled_helper_assertion_decoy():
    # 巢狀且從未被呼叫的輔助函式內的 assert，否則也會滿足關卡
    # An assert inside a nested, never-called helper would otherwise satisfy the gate
    is_valid, problem = check_test_code("def test_a():\n    def unused():\n        assert False\n")
    assert not is_valid
    assert "without any assertion" in problem


def test_check_test_code_accepts_assertion_in_called_helper():
    code = "def test_a():\n    def check():\n        assert f(1) == 1\n    check()\n"
    assert check_test_code(code)[0] is True


def test_import_instructions_disclose_non_python_targets():
    # JS/TS 目標會得到 node:test 的指引（file:// URL、模組系統）；其他語言維持純靜態
    # JS/TS targets get node:test guidance (file:// URL, module system); other languages stay static-only
    text = import_instructions("app/server.ts", ".")
    assert "file://" in text and "TypeScript" in text and "node:" in text
    assert "importlib" not in text
    text = import_instructions("app/main.go", ".")
    assert "not a Python file" in text
    assert "importlib" not in text
    assert "cannot be imported" in text


def test_fallback_threat_ids_have_no_gaps(fake_live):
    # 模型提供的 id 不得消耗退回計數器，否則 THREAT-XX
    # 序列會跳號（THREAT-01 可能閒置，而退回的 id 跳到 02 以後）。
    # A model-supplied id must not consume the fallback counter, otherwise the THREAT-XX
    # sequence skips numbers (THREAT-01 could stay unused while fallbacks jump to 02+).
    fake_live(lambda s, u: json.dumps({"threats": [
        {"threat_id": "THREAT-02", "stride_category": "Tampering", "title": "T2", "attack_vector": "v2"},
        {"threat_id": "THREAT-02", "stride_category": "Tampering", "title": "dup", "attack_vector": "dup"},
        {"threat_id": "  ", "stride_category": "Tampering", "title": "blank", "attack_vector": "blank"},
    ]}))
    gateway = LLMGateway(CONFIG, execution_mode="live")
    report = AutomatedThreatModeler(gateway).model_system("desc", [], symbols=[], root_dir=".")
    ids = sorted(t.threat_id for t in report.threats)
    assert ids == ["THREAT-01", "THREAT-02", "THREAT-03"]


def test_unparseable_live_output_is_recorded_invalid(fake_live):
    fake_live(lambda s, u: "Sorry, I cannot help with that.")
    gateway = LLMGateway(CONFIG, execution_mode="live")
    resp = gateway.generate("whitebox_reviewer_claude", "sys", "prompt", schema=OutputSchema(required={"findings": ANY}))
    assert not gateway.is_usable(resp)
    assert "findings" not in resp
    # 無法使用的回答會再問一次（登記為 `retried`），然後登記為 `invalid`
    # The unusable answer is re-asked once (booked as `retried`), then booked as `invalid`
    assert [c.mode for c in gateway.call_log] == ["retried", "invalid"]


def test_missing_required_key_is_recorded_invalid(fake_live):
    fake_live(lambda s, u: '{"something_else": []}')
    gateway = LLMGateway(CONFIG, execution_mode="hybrid")
    gateway.generate("blackbox_threat_modeler", "sys", "prompt", schema=OutputSchema(required={"threats": ANY}))
    assert gateway.invalid_calls and "threats" in gateway.invalid_calls[0].reason


def test_report_labels_an_invalid_model_call(tmp_path):
    """無法使用的模型輸出在來源紀錄表中標為「無效輸出」（缺口本身見 test_quality_gate.py）。
    An unusable model answer is labelled "invalid output" in the provenance table (the gap itself is in test_quality_gate.py)."""
    from vibeharness.core.models import MultiModelDebateResult, ThreatModelReport, VibeHarnessSummary
    from vibeharness.reports.report_generator import ReportGenerator
    summary = VibeHarnessSummary(
        overall_status="INCONCLUSIVE", total_whitebox_findings=0, confirmed_whitebox_bugs=None, whitebox_tests_passed=0,
        whitebox_tests_failed=0, total_threats_modeled=0, critical_threats_count=0, blackbox_tests_passed=0,
        blackbox_security_breaches=0, agent_calls=[AgentCallRecord(
            agent_id="blackbox_threat_modeler", model_alias="claude", model_name="m", mode="invalid", reason="not json")],
    )
    md = ReportGenerator().generate_markdown_report(summary, MultiModelDebateResult(consensus_summary=""),
                                                    ThreatModelReport(system_description=""), [], [], "app")
    assert "invalid output" in md and "blackbox_threat_modeler" in md


def test_single_file_target_is_analyzed(tmp_path):
    target = tmp_path / "one.py"
    target.write_text("def crashy(order):\n    return order['id']\n", encoding="utf-8")
    summary = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock").run_full_pipeline(
        target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md")
    )
    assert summary.whitebox_tests_failed == 1
    assert sorted(os.listdir(tmp_path)) == ["one.py", "r.md"]


def test_failed_unclassified_blackbox_test_is_an_evidence_gap(tmp_path, monkeypatch):
    """失敗但不符合攻擊成功判斷條件的黑箱攻擊測試，必須算作模稜兩可的證據——
    關卡不得再讓這次執行以 READY_TO_SHIP 通過。
    A black-box attack test that fails without matching the exploit predicate must count
    as ambiguous evidence — the gate may no longer pass the run as READY_TO_SHIP."""
    from vibeharness.core.models import TestExecutionResult

    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")

    def fake_execute(tests, working_dir=".", collect_coverage=False):
        if collect_coverage:
            wb = [TestExecutionResult(
                test_id="WB-T", test_type="whitebox_unit", status=TestStatus.PASSED, source_ref="WB-CLA-01"
            )]
            return SuiteResult(wb, python_coverage_pct=42.0)
        bb = [TestExecutionResult(
            test_id="BB-T", test_type="blackbox_security", status=TestStatus.FAILED,
            failure_reason="TypeError: 'NoneType' object is not subscriptable", source_ref="THREAT-01"
        )]
        return SuiteResult(bb)

    monkeypatch.setattr(commander.executor, "execute_test_suite", fake_execute)
    summary = commander.run_full_pipeline(
        target_dir=EXAMPLES, base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md")
    )
    assert summary.blackbox_tests_failed == 1
    assert summary.blackbox_security_breaches == 0
    assert any("failed without a confirmed exploit" in r for r in summary.inconclusive_reasons)
    assert summary.overall_status == "INCONCLUSIVE"
    assert "unclassified" in (tmp_path / "r.md").read_text(encoding="utf-8")


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
        server.server_close()


def test_server_probe_retries_before_giving_up(monkeypatch):
    """啟動緩慢的伺服器會獲得幾次嘗試，之後測試框架才退回行程內模式。
    A slow-starting server gets a few attempts before the harness falls back to in-process mode."""
    import vibeharness.agents.blackbox.scenario_builder as sb_mod
    from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder

    builder = ThreatScenarioBuilder(None)

    class FlakyUrlopen:
        def __init__(self):
            self.calls = 0

        def __call__(self, *a, **k):
            self.calls += 1
            if self.calls == 1:
                raise OSError("connection refused")
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    fake = FlakyUrlopen()
    monkeypatch.setattr(sb_mod.urllib.request, "urlopen", fake)
    monkeypatch.setattr(sb_mod.time, "sleep", lambda s: None)
    assert builder.check_server_live("http://localhost:59998", timeout_sec=0.1) is True
    assert fake.calls == 2  # 失敗一次，重試後成功 ／ failed once, succeeded on the retry


def test_generated_attack_code_targeting_another_host_is_rejected():
    """「絕不以其他主機為目標」由靜態檢查強制執行，而不只靠提示詞指示。
    'Never target any other host' is enforced by a static check, not only by prompt instruction."""
    import threading
    import http.server
    from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
    from vibeharness.core.models import ThreatItem, STRIDECategory, FindingSeverity
    from vibeharness.core.llm_gateway import LLMGateway

    class NotFound(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), NotFound)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        threat = ThreatItem(
            threat_id="THREAT-01", stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE, title="BOLA",
            description="", asset_at_risk="a", attack_vector="GET /api/orders",
            trust_boundary_crossed="b", severity=FindingSeverity.CRITICAL,
            attack_scenario="fetch other users' orders", test_verification_goal="403"
        )
        codes = [
            "import requests\n"
            "def test_steal():\n"
            "    r = requests.get('http://evil.example.com/api/orders?id=2')\n"
            "    assert r.status_code == 403\n",       # 外部主機 -> 拒絕 ／ foreign host -> rejected
            "def test_ok():\n"
            "    import requests\n"
            f"    r = requests.get('{base_url}/api/orders?id=2')\n"
            "    assert r.status_code == 403\n",       # 宣告的目標 -> 保留 ／ declared target -> kept
        ]

        def responder(agent_id, system, user, **k):
            return {"code": codes.pop(0)}

        gw = LLMGateway(CONFIG, execution_mode="mock")
        gw.generate = responder
        builder = ThreatScenarioBuilder(gw)
        tests = builder.build_test_cases_from_threats(
            [threat, threat.model_copy(update={"threat_id": "THREAT-02"})],
            base_url=base_url
        )
        assert [t.test_id for t in tests] == ["BB-TEST-THREAT-02"]
        assert "evil.example.com" not in "".join(t.code for t in tests)
    finally:
        server.shutdown()
        server.server_close()


def test_url_guard_resolves_ipv6_literals_and_userinfo():
    """主機擷取不得被 IPv6 字面值弄壞（「[::1]」被解析成「[」），也不得被
    userinfo（「user@evil.example.com」）騙過；無法解析的字面值採保守失敗。
    Host extraction must not break on IPv6 literals ('[::1]' parsed as '[') or be
    fooled by userinfo ('user@evil.example.com'); unparseable literals fail closed."""
    check = ThreatScenarioBuilder._hosts_outside_base_url
    # IPv6 迴路字面值與迴路 base URL 是同一台機器（且同一連接埠）：不是違規者
    # an IPv6 loopback literal is the same machine (and the same port) as a loopback base URL: not an offender
    assert check('requests.get("http://[::1]:8000/admin")', "http://localhost:8000") == []
    # 宣告的 IPv6 base URL 本身永遠不是違規者
    # the declared IPv6 base URL itself is never an offender
    assert check('urllib.request.urlopen("http://[::1]:8000/api")', "http://[::1]:8000") == []
    # 真正的外部 IPv6 主機是違規者
    # a real external IPv6 host is an offender
    assert check('requests.get("http://[2001:db8::1]/x")', "http://localhost:8000") == ["http://[2001:db8::1]"]
    # userinfo 再也藏不住真正的主機
    # userinfo no longer hides the real host
    assert check('requests.get("http://user@evil.example.com/x")', "http://localhost:8000") == [
        "http://user@evil.example.com"]
    # 無法解析（被截斷）的字面值無法被排除，因此會被標示
    # an unparseable (cut-off) literal cannot be cleared, so it is flagged
    assert check('requests.get("http://[::1", timeout=1)', "http://localhost:8000") == ["http://[::1"]


def test_symbol_relevance_uses_word_boundaries():
    from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
    from vibeharness.core.models import ThreatItem, STRIDECategory, FindingSeverity, CodeSymbol

    def sym(name):
        return CodeSymbol(name=name, symbol_type="function", file_path="app.py",
                          line_start=1, line_end=2, signature=name, source_code="pass")
    threat = ThreatItem(
        threat_id="T", stride_category=STRIDECategory.TAMPERING, title="t", description="",
        asset_at_risk="a", attack_vector="tamper the input of validate_username",
        trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="no other symbol is named in the scenario", test_verification_goal=""
    )
    # 整字比對：只有 validate_username 被指名；「username」裡的「user」不得
    # 把 get_user 拖進來，未被指名的符號也不會納入。
    # Whole-word matching: only validate_username is named; "user" inside "username" must not
    # drag in get_user, and unnamed symbols stay out.
    symbols = [sym("get_user"), sym("validate_username"), sym("process_payment")]
    context, language = ThreatScenarioBuilder._code_context(threat, symbols, root_dir=".")
    assert language == "python"
    assert "Symbol: validate_username" in context
    assert "Symbol: get_user" not in context
    assert "Symbol: process_payment" not in context


def test_report_poc_fence_widens_when_code_contains_fences(tmp_path):
    from vibeharness.core.models import (
        ThreatModelReport, VibeHarnessSummary, TestExecutionResult, TestStatus,
        ThreatItem, STRIDECategory, FindingSeverity, MultiModelDebateResult,
    )
    from vibeharness.reports.report_generator import ReportGenerator
    poc = "# PoC\ntext = ```\nwith fence markers\n```\n"
    threat = ThreatItem(
        threat_id="THREAT-01", stride_category=STRIDECategory.TAMPERING, title="t", description="",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="", test_verification_goal=""
    )
    summary = VibeHarnessSummary(
        overall_status="BLOCKED_CRITICAL_RISK", total_whitebox_findings=0, confirmed_whitebox_bugs=0,
        whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=1,
        critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=1
    )
    bb = [TestExecutionResult(
        test_id="BB-1", test_type="blackbox_security", status=TestStatus.FAILED,
        is_security_exploit_confirmed=True, reproduction_poc=poc
    )]
    debate = MultiModelDebateResult(consensus_summary="")
    threat_model = ThreatModelReport(system_description="", entrypoints=[], trust_boundaries=[],
                                     assets=[], threats=[threat])
    md = ReportGenerator().generate_markdown_report(summary, debate, threat_model, [], bb, "app")
    assert "````python" in md


def test_report_flags_unknown_status_and_coerces_list_fields():
    from vibeharness.core.models import (
        ThreatModelReport, VibeHarnessSummary, MultiModelDebateResult,
    )
    from vibeharness.reports.report_generator import ReportGenerator
    summary = VibeHarnessSummary(
        overall_status="MYSTERY_STATUS", total_whitebox_findings=0, confirmed_whitebox_bugs=0,
        whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0,
        critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0
    )
    threat_model = ThreatModelReport(
        system_description="", entrypoints=[], trust_boundaries=[], assets=[], threats=[]
    ).model_copy(update={"entrypoints": "/api/users"})  # 繞過驗證：來自模型的零散字串 ／ bypass validation: stray string from a model
    md = ReportGenerator().generate_markdown_report(summary, MultiModelDebateResult(consensus_summary=""),
                                                    threat_model, [], [], "app")
    # 無法辨識的判定結果必須標示為未知，不得顯示成 BLOCKED
    # An unrecognized verdict must be flagged as unknown, not shown as BLOCKED
    assert "UNKNOWN STATUS: `MYSTERY_STATUS`" in md
    # 零散字串會呈現為單一項目，而不是逐字元拆開
    # A stray string renders as one item, not character by character
    assert "`/api/users`" in md
    assert "`/, /a/p/i//u/s/e/r/s`" not in md


def test_ast_extractor_includes_decorated_class_and_star_args(tmp_path):
    target = tmp_path / "deco.py"
    target.write_text("@functools.lru_cache\nclass Repo:\n    def load(self, *args, **kwargs):\n        return None\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(target))
    repo = next(s for s in symbols if s.name == "Repo")
    load = next(s for s in symbols if s.name == "Repo.load")
    assert repo.source_code.startswith("@functools.lru_cache")
    assert "*args, **kwargs" in load.signature
    assert load.parameters == ["self", "*args"]


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
    results = executor.execute_test_suite(probes, working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.PASSED


# --- 沙盒強化 -------------------------------------------------------------------
# --- Sandbox hardening -------------------------------------------------------

def test_sandbox_withholds_secrets_from_generated_code(executor, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak")
    results = executor.execute_test_suite([_test("A", (
        "import os\n"
        "def test_env():\n"
        "    leaked = [k for k in os.environ if 'KEY' in k or 'SECRET' in k]\n"
        "    assert not leaked, leaked\n"
    ))], working_dir=str(tmp_path)).results
    assert results[0].status == TestStatus.PASSED, results[0].failure_reason


def test_hanging_test_does_not_void_the_batch(tmp_path, monkeypatch):
    """單一測試的卡住最多只能花掉一次單測試重跑，而不是整個批次：批次會作為一個
    單位逾時，接著可疑的模組會以各自的單測試預算個別重跑。批次層級的逾時是模擬的
    （真實的 8 秒批次逾時加上真實的子行程重跑，在慢速機器上本質上取決於時序）。
    A per-test hang must cost at most a per-test rerun, not the whole batch: the batch
    times out as one unit, then the suspicious modules are rerun individually with their
    own per-test budget. The batch-level timeout is simulated (a real 8s batch timeout plus
    real subprocess reruns is inherently timing-dependent on slow machines)."""
    from vibeharness.core.sandbox import TIMEOUT_EXIT_CODE

    # 每個測試 15 秒：在負載高的 Windows 主機上，光一個 pytest 子行程就要約 4 秒，而 HANG 會睡 60 秒
    # 15s per test: one pytest subprocess alone takes ~4s on a loaded Windows host, and HANG sleeps 60s
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60), per_test_timeout_seconds=15)
    real_execute = executor.sandbox.execute_pytest_files
    calls = {"batch_timeouts": 0}

    def batch_times_out(files, working_dir=None, timeout_seconds=None, **kwargs):
        if len(files) > 1:
            calls["batch_timeouts"] += 1
            return SandboxRun(TIMEOUT_EXIT_CODE, "", "sandbox: batch timed out", 0.0, None, None)
        return real_execute(files, working_dir=working_dir, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(executor.sandbox, "execute_pytest_files", batch_times_out)
    results = executor.execute_test_suite([
        _test("OK", "def test_ok():\n    assert True"),
        _test("HANG", "import time\ndef test_hang():\n    time.sleep(60)\n    assert True"),
        _test("BAD", "def test_bad():\n    assert 1 == 2"),
    ], working_dir=str(tmp_path)).results
    assert calls["batch_timeouts"] == 1  # 批次逾時並觸發了個別重跑 ／ the batch timed out and triggered the individual reruns
    assert [r.status for r in results] == [TestStatus.PASSED, TestStatus.ERROR, TestStatus.FAILED]
    assert "timed out" in results[1].failure_reason


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group kill semantics")
def test_daemonized_grandchild_cannot_hang_the_sandbox(tmp_path):
    """新工作階段中的孫行程能在行程群組終止後存活；沙盒必須以短逾時排空其管線，
    而不是永遠卡在 communicate() 上。
    A grandchild in a new session survives the process-group kill; the sandbox must
    drain its pipes with a short timeout instead of blocking on communicate() forever."""
    import subprocess
    import time
    from vibeharness.core.sandbox import TIMEOUT_EXIT_CODE

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
        run = sandbox.execute_pytest_files(
            {"test_daemon_test.py": code}, working_dir=str(tmp_path), timeout_seconds=2
        )
        elapsed = time.monotonic() - start
        assert run.exit_code == TIMEOUT_EXIT_CODE
        # 終止 + 約 5 秒管線排空；若卡住則會跑到 120 秒的孫行程結束
        # kill + ~5s pipe drain; a hang would run until the 120s grandchild exits
        assert elapsed < 20, f"sandbox blocked for {elapsed:.1f}s on a daemonized grandchild"
        assert "timed out" in run.stderr.lower()
    finally:
        subprocess.run(["pkill", "-f", "time.sleep(120)"], capture_output=True)


def test_results_carry_their_own_output(executor, tmp_path):
    results = executor.execute_test_suite([
        _test("A", "def test_a():\n    print('from-a')\n    assert True"),
        _test("B", "def test_b():\n    print('from-b')\n    assert True"),
    ], working_dir=str(tmp_path)).results
    assert "from-a" in results[0].stdout and "from-b" not in results[0].stdout
    assert "from-b" in results[1].stdout


def test_unimplemented_sandbox_provider_is_rejected(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("global:\n  sandbox_provider: e2b\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not implemented"):
        VibeHarnessCommander(config_path=str(cfg), execution_mode="mock")


# --- CLI 介面 -------------------------------------------------------------------
# --- CLI surface ---------------------------------------------------------------

def test_litellm_retry_dependency_is_installed():
    # litellm 在 num_retries > 0（live 模式）時需要 tenacity，但不會自己安裝它；
    # 若 requirements.txt 哪天把它拿掉，這裡會在 CI 失敗，而不是在使用者第一次 live 呼叫時才失敗。
    # litellm needs tenacity for num_retries > 0 (live mode) but does not install it itself;
    # if requirements.txt ever drops it, this fails in CI instead of at the user's first live call.
    pytest.importorskip("litellm")
    import tenacity  # noqa: F401


def test_cli_reports_the_package_version():
    import subprocess
    from vibeharness import __version__
    proc = subprocess.run(
        [sys.executable, "main.py", "--version"],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert __version__ in proc.stdout


def test_cli_rejects_unknown_report_format():
    import subprocess
    proc = subprocess.run(
        [sys.executable, "main.py", "--target", EXAMPLES, "--format", "xml"],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60
    )
    assert proc.returncode == 5  # 用法錯誤不得與判定結果代碼 2 衝突 ／ usage errors must not collide with verdict code 2
    assert "invalid choice" in (proc.stderr + proc.stdout)


def test_cli_exit_code_semantics_are_disjoint():
    from vibeharness.cli import verdict_exit_code
    assert verdict_exit_code("BLOCKED_CRITICAL_RISK") == 2
    assert verdict_exit_code("NEEDS_FIXES") == 1
    assert verdict_exit_code("INCONCLUSIVE") == 3
    assert verdict_exit_code("READY_TO_SHIP") == 0
    # 未知的判定結果必須採保守失敗，絕不能當成乾淨通過
    # An unknown verdict must fail closed, never as a clean pass
    assert verdict_exit_code("SOMETHING_ELSE") == 3


def test_cli_missing_config_is_usage_error_not_needs_fixes():
    import subprocess
    proc = subprocess.run(
        [sys.executable, "main.py", "--target", EXAMPLES, "--config", "/nonexistent/agents_config.yaml"],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60
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
            cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60
        )
    assert proc.returncode == 5
    assert "not valid YAML" in proc.stderr


def test_cli_missing_target_is_usage_error():
    import subprocess
    proc = subprocess.run(
        [sys.executable, "main.py", "--target", "/nonexistent/target/dir"],
        cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60
    )
    assert proc.returncode == 5


# --- local_subprocess 資源限制 ------------------------------------------------------------------
# --- local_subprocess resource limits ------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "linux", reason="RLIMIT_AS is enforced reliably on Linux only")
def test_local_sandbox_memory_cap_stops_a_runaway_allocation(tmp_path):
    from vibeharness.core.sandbox import LocalSubprocessSandbox
    code = (
        "def test_eat_memory():\n"
        "    blob = bytearray(1024 * 1024 * 1024)  # 1 GiB\n"
        "    assert len(blob) > 0\n"
    )
    capped = LocalSubprocessSandbox(timeout_seconds=60, memory_mb=512)
    assert capped._limits(60) == {"cpu_seconds": 70, "memory_bytes": 512 * 1024 * 1024}
    run = capped.execute_pytest_files({"test_mem.py": code}, working_dir=str(tmp_path))
    assert run.exit_code != 0 and "MemoryError" in (run.stdout + run.stderr + (run.junit_xml or ""))
    uncapped = LocalSubprocessSandbox(timeout_seconds=60, memory_mb=0)
    assert "memory_bytes" not in uncapped._limits(60)


def test_docker_sandbox_never_limits_the_docker_cli():
    """docker CLI 不受記憶體／CPU 上限約束（容器自帶）；只有單檔大小上限，讓它寫進擷取暫存檔的輸出有上限。
    The docker CLI gets no memory / CPU cap (the container carries its own); only the per-file size cap, so the output it
    writes into the capture temp files is bounded."""
    from vibeharness.core.sandbox import DockerSandbox, SANDBOX_MAX_FILE_BYTES
    sandbox = DockerSandbox(verify=False)
    assert sandbox.memory_mb == 0 and sandbox._limits(60) == {"file_bytes": SANDBOX_MAX_FILE_BYTES}


def test_verdict_exit_codes_round_trip():
    """每個判定結果的結束碼都能轉回同一個判定結果；其他結束碼不是判定結果。
    Every verdict's exit code maps back to the same verdict; any other exit code is not a verdict."""
    from vibeharness.core.verdict import Verdict
    for verdict in Verdict:
        assert Verdict.from_exit_code(verdict.exit_code) is verdict
        assert f"{verdict}" == str(verdict) == verdict.value
    assert Verdict.from_exit_code(4) is None and Verdict.from_exit_code(5) is None
    assert Verdict.parse("MYSTERY_STATUS") is None
