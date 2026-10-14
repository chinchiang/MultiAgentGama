"""Node 執行環境的選擇：sandbox 模組的 build_node_sandbox 與 NodeDockerSandbox 的版本探測、harness 交給執行器的工廠，
以及執行器在 SuiteResult 帶回的 NodeRuntime。都不需要真正的 node 或 docker。
Choosing the Node runtime: the sandbox module's build_node_sandbox and NodeDockerSandbox's version probe, the factory
the harness hands the executor, and the NodeRuntime the executor brings back in SuiteResult. None of them needs a real
node or docker."""
import os
import subprocess

import pytest

from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.models import GeneratedTest
from vibeharness.core.sandbox import (
    DEFAULT_DOCKER_NODE_IMAGE, NodeDockerSandbox, NodeRuntime, NodeSubprocessSandbox, SandboxRun,
    SandboxUnavailableError, build_node_sandbox,
)
from vibeharness.runners.test_executor import SuiteResult, TestSuiteExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
EXAMPLES = os.path.join(REPO_ROOT, "examples")


# --- sandbox 模組：build_node_sandbox 與版本探測 ------------------------------------------------------------
# --- The sandbox module: build_node_sandbox and the version probe ----------------------------------------------

def test_build_node_sandbox_picks_the_provider_and_typescript_support(tmp_path, monkeypatch):
    settings = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock").settings

    def build(provider):
        return build_node_sandbox(provider, settings.node.node_bin, settings.node.image, settings.sandbox, has_typescript=True)
    # docker provider：用映像檔自帶的 Node，主機沒有 node 也能建；TS 支援看映像檔的版本
    # docker provider: the image's own Node, built even without a host node; TS support follows the image's version
    monkeypatch.setattr("vibeharness.core.sandbox.detect_node", lambda node_bin: (None, None, "no usable Node runtime found"))
    monkeypatch.setattr(NodeDockerSandbox, "probe_node_version", lambda self: (22, 9, 0))
    monkeypatch.setattr(NodeDockerSandbox, "_verify_available", lambda self: None)
    runtime = build("docker")
    sandbox = runtime.sandbox
    assert isinstance(sandbox, NodeDockerSandbox) and sandbox.supports_typescript and sandbox.strip_types
    assert runtime.label == f"docker {DEFAULT_DOCKER_NODE_IMAGE} (node v22.9.0)"
    assert runtime.problem is None and runtime.ts_problem is None
    # 映像檔版本查不到：不假設，TS 列為未執行而 JS 照跑（不帶 strip 旗標）；映像檔太舊：TS 列為問題
    # unknown image version: no guessing, TS reported as not run while JS still runs (no strip flag); an old image: TS problem
    monkeypatch.setattr(NodeDockerSandbox, "probe_node_version", lambda self: None)
    runtime = build("docker")
    assert not runtime.sandbox.supports_typescript and not runtime.sandbox.strip_types
    assert runtime.label == f"docker {DEFAULT_DOCKER_NODE_IMAGE}"
    assert "could not be read" in runtime.ts_problem
    monkeypatch.setattr(NodeDockerSandbox, "probe_node_version", lambda self: (20, 1, 0))
    runtime = build("docker")
    assert not runtime.sandbox.supports_typescript
    assert "TypeScript tests need Node >= 22.6" in runtime.ts_problem
    # 映像檔缺失：建構失敗，沒有任何 NodeRuntime 宣稱有執行環境 ／ missing image: construction fails, no NodeRuntime claims one
    monkeypatch.setattr(NodeDockerSandbox, "_verify_available", lambda self: (_ for _ in ()).throw(SandboxUnavailableError("no image")))
    with pytest.raises(SandboxUnavailableError):
        build("docker")
    monkeypatch.setattr("vibeharness.core.sandbox.detect_node", lambda node_bin: ("/usr/bin/node", (20, 5, 0), None))
    runtime = build("local_subprocess")
    sandbox = runtime.sandbox
    assert isinstance(sandbox, NodeSubprocessSandbox) and not sandbox.supports_typescript and not sandbox.strip_types
    assert "TypeScript tests need Node >= 22.6" in runtime.ts_problem


def test_probe_node_version_uses_the_sandbox_run_prefix(tmp_path, monkeypatch):
    """版本探測用與測試相同的 docker run 前綴（同使用者、掛載、限制），不是另一組手寫旗標。
    The version probe uses the same docker run prefix as the tests (same user, mounts, limits), not hand-rolled flags."""
    import vibeharness.core.sandbox as sandbox_mod
    sandbox = NodeDockerSandbox(timeout_seconds=30, verify=False, memory="256m", pids_limit=64, network="none")
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="v22.9.0\n", stderr="")
    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    assert sandbox.probe_node_version() == (22, 9, 0)
    joined = " ".join(seen["cmd"])
    assert seen["cmd"][-6:] == [DEFAULT_DOCKER_NODE_IMAGE, "timeout", "--kill-after=5", "20", "node", "--version"]
    for flag in ("--rm", "--read-only", "--network none", "--cap-drop ALL", "--memory 256m", "--pids-limit 64", "--user", "--name"):
        assert flag in joined
    assert "--pull" not in joined
    # 主機端逾時：移除容器（與測試批次相同），回傳 None ／ host-side timeout: the container is removed (as for a batch), None
    removed = []
    monkeypatch.setattr(sandbox_mod.subprocess, "run", lambda cmd, **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd, 30)))
    monkeypatch.setattr(NodeDockerSandbox, "_after_timeout", lambda self, cmd: removed.append(cmd[cmd.index("--name") + 1]))
    assert sandbox.probe_node_version() is None and len(removed) == 1


# --- harness：交給執行器的工廠 ------------------------------------------------------------------------------
# --- The harness: the factory handed to the executor ------------------------------------------------------------

def test_harness_records_the_docker_node_version_for_js_only_targets_too(monkeypatch):
    """純 JS 目標也讀映像檔內的 Node 版本：它是 RunMetadata.node_runtime 的來源；型別剝除只在有 TypeScript 時開。
    A JS-only target reads the image's Node version too (it is RunMetadata.node_runtime's provenance); type stripping
    is enabled only when TypeScript exists."""
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    commander.sandbox_node_provider = "docker"
    monkeypatch.setattr(NodeDockerSandbox, "_verify_available", lambda self: None)
    monkeypatch.setattr(NodeDockerSandbox, "probe_node_version", lambda self: (22, 9, 0))
    commander.ast_extractor.analyzed_files = ["/app/x.mjs"]
    runtime = commander.executor._js_sandbox_factory()
    assert not runtime.sandbox.strip_types and runtime.label == f"docker {DEFAULT_DOCKER_NODE_IMAGE} (node v22.9.0)"
    commander.ast_extractor.analyzed_files = ["/app/x.ts"]
    assert commander.executor._js_sandbox_factory().sandbox.strip_types


def test_harness_passes_the_node_version_to_the_sandboxes(tmp_path, monkeypatch):
    import vibeharness.core.sandbox as sandbox_module
    config = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vibeharness", "config",
                          "agents_config.yaml")
    commander = VibeHarnessCommander(config_path=config, execution_mode="mock")
    monkeypatch.setattr(sandbox_module, "detect_node", lambda node_bin: ("/usr/bin/node", (22, 14, 0), None))
    sandbox = commander.executor._js_sandbox_factory().sandbox
    assert isinstance(sandbox, NodeSubprocessSandbox) and sandbox.node_version == (22, 14, 0)


# --- 執行器與 harness：SuiteResult.node_runtime ------------------------------------------------------------------
# --- The executor and the harness: SuiteResult.node_runtime -----------------------------------------------------

_JS_CODE = 'import { test } from "node:test";\nimport assert from "node:assert/strict";\ntest("a", () => { assert.equal(1, 1); });\n'


def _test(test_id, language, test_type="whitebox_unit"):
    code = "def test_a():\n    assert 1\n" if language == "python" else _JS_CODE
    return GeneratedTest(test_id=test_id, test_type=test_type, target_component="x", title=test_id, code=code,
                         rationale="", expected_outcome="", language=language)


class _NoReportSandbox:
    """沙盒替身：每次執行都沒有報告（結果是 ERROR，與這裡要看的 node_runtime 無關）。
    A sandbox stand-in whose every run has no report (the results are ERROR, which does not matter for node_runtime)."""
    timeout_seconds = 30
    supports_typescript = True

    def js_coverage_problem(self):
        return None

    def execute_pytest_files(self, files, **kw):
        return SandboxRun(0, "", "", 0.1)


def test_suite_result_carries_the_node_runtime_only_for_suites_with_js_tests(tmp_path):
    """只有含 JS/TS 測試的 suite 帶 node_runtime；工廠只呼叫一次，後面的 suite 拿到同一個值。
    Only a suite holding JS/TS tests carries node_runtime; the factory is called once and later suites get the same
    value."""
    runtime = NodeRuntime(_NoReportSandbox(), label="node v22.9.0")
    calls = []

    def factory():
        calls.append(1)
        return runtime
    executor = TestSuiteExecutor(sandbox=_NoReportSandbox(), js_sandbox_factory=factory)
    python_only = executor.execute_test_suite([_test("P", "python")], working_dir=str(tmp_path))
    assert python_only.node_runtime is None and calls == []
    whitebox = executor.execute_test_suite([_test("J", "javascript"), _test("P", "python")], working_dir=str(tmp_path))
    blackbox = executor.execute_test_suite([_test("B", "javascript", "blackbox_security")], working_dir=str(tmp_path))
    assert whitebox.node_runtime is runtime and blackbox.node_runtime is runtime and calls == [1]
    # 已經解析過之後，沒有 JS/TS 測試的 suite 仍不帶 node_runtime
    # Once resolved, a suite with no JS/TS test still carries none
    assert executor.execute_test_suite([_test("P", "python")], working_dir=str(tmp_path)).node_runtime is None
    # 沒有工廠、或工廠拋出 SandboxUnavailableError：沒有 NodeRuntime，原因在 js_runner_problem
    # No factory, or a factory raising SandboxUnavailableError: no NodeRuntime, the reason is in js_runner_problem
    assert TestSuiteExecutor(sandbox=_NoReportSandbox()).execute_test_suite(
        [_test("J", "javascript")], working_dir=str(tmp_path)).node_runtime is None

    def missing_image():
        raise SandboxUnavailableError("no image")
    suite = TestSuiteExecutor(sandbox=_NoReportSandbox(), js_sandbox_factory=missing_image).execute_test_suite(
        [_test("J", "javascript")], working_dir=str(tmp_path))
    assert suite.node_runtime is None and suite.js_runner_problem == "SandboxUnavailableError: no image"


def test_harness_reads_the_node_runtime_from_the_blackbox_suite_too(tmp_path, monkeypatch):
    """白箱沒有 JS 測試、只有黑箱有時，RunMetadata.node_runtime 仍來自黑箱 suite 的 NodeRuntime。
    With no JS test in the white-box suite and some in the black-box one, RunMetadata.node_runtime still comes from the
    black-box suite's NodeRuntime."""
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    runtime = NodeRuntime(_NoReportSandbox(), label="node v22.9.0")

    def fake_execute(tests, working_dir=".", collect_coverage=False):
        return SuiteResult([]) if collect_coverage else SuiteResult([], node_runtime=runtime)
    monkeypatch.setattr(commander.executor, "execute_test_suite", fake_execute)
    summary = commander.run_full_pipeline(target_dir=EXAMPLES, output_report_path=str(tmp_path / "r.json"),
                                          output_format="json")
    assert summary.run is not None and summary.run.node_runtime == "node v22.9.0"
