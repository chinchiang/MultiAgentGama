"""第二輪審查的回歸測試：未驗證時已確認數為 null、安裝不完整時 exit 5、litellm 罐頭回應鍵、呼叫紀錄的時間順序、
--cache-only 的估算與 mock 警告，以及 pip 使用者的便利性（--target 預設、--init-config、設定檔探索）。
Regression tests for the second review round: a null confirmed count without verification, exit 5 on a broken
install, litellm's canned-response keys, the call log's chronology, --cache-only in the estimate and the mock
warning, and pip-user ergonomics (the --target default, --init-config, config discovery)."""
import json
import os
import random
import shutil
import subprocess
import sys

import pytest

from vibeharness import cli
from vibeharness.core.estimate import estimate_run
from vibeharness.core.harness import VibeHarnessCommander, sorted_call_log
from vibeharness.core.llm_gateway import DEFAULT_CONFIG_PATH, RESERVED_EXTRA_PARAMS, ConfigError, LLMGateway
from vibeharness.core.models import AgentCallRecord, MultiModelDebateResult, ThreatModelReport, VibeHarnessSummary
from vibeharness.reports.report_generator import JSON_SCHEMA_VERSION, ReportGenerator

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(REPO_ROOT, "examples")


def _run_cli(monkeypatch, *argv):
    """以指定參數執行 CLI，回傳它的結束碼。
    Runs the CLI with the given arguments and returns its exit code."""
    monkeypatch.setattr(sys, "argv", ["vibeharness", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return exit_info.value.code


def _capture_run(monkeypatch):
    """把 run_full_pipeline 換成只記錄設定檔與目標的替身，回傳記錄用的 dict。
    Replaces run_full_pipeline with a stand-in that records the config and the target; returns the record dict."""
    seen = {}

    def run(self, **kwargs):
        seen.update(config_path=self.config_path, target_dir=kwargs["target_dir"], cache_only=self.gateway.cache_only)
        return type("S", (), {"overall_status": "INCONCLUSIVE"})()

    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    return seen


# --- 1. 沒有交叉驗證時，已確認數為 null（不是讀起來乾淨的 0）------------------------------------------
# --- 1. Without cross-verification the confirmed count is null (not a 0 that reads as clean) --------------

def test_json_report_has_null_confirmed_count_without_verification(tmp_path):
    """mock 執行沒有真實的驗證投票：JSON 的 summary.confirmed_whitebox_bugs 是 null，schema_version 是 "2"。
    A mock run casts no real verifier vote: summary.confirmed_whitebox_bugs is null in the JSON, schema_version is "2"."""
    target = tmp_path / "app"
    target.mkdir()
    shutil.copy(os.path.join(EXAMPLES, "vibe_sample_app.py"), target)
    report = tmp_path / "r.json"
    VibeHarnessCommander(execution_mode="mock").run_full_pipeline(
        target_dir=str(target), output_report_path=str(report), output_format="json")
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert JSON_SCHEMA_VERSION == "2" and payload["schema_version"] == "2"
    assert payload["summary"]["confirmed_whitebox_bugs"] is None
    assert payload["whitebox"]["debate"]["arbitration_applied"] is False


def test_markdown_shows_na_for_a_null_confirmed_count_even_if_arbitration_is_flagged(tmp_path):
    """結果模型不一致（arbitration_applied 為 True 但已確認數為 None）時，Markdown 顯示 N/A，絕不印出 `None`。
    With inconsistent models (arbitration_applied True but a None count) the Markdown shows N/A, never `None`."""
    summary = VibeHarnessSummary(
        overall_status="INCONCLUSIVE", total_whitebox_findings=0, confirmed_whitebox_bugs=None,
        whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0, critical_threats_count=0,
        blackbox_tests_passed=0, blackbox_security_breaches=0,
    )
    debate = MultiModelDebateResult(consensus_summary="c", arbitration_applied=True)
    md = ReportGenerator().generate_markdown_report(
        summary, debate, ThreatModelReport(system_description="s"), [], [], str(tmp_path))
    assert "`None`" not in md and "`N/A`" in md
    data = json.loads(ReportGenerator().generate_json_report(
        summary, debate, ThreatModelReport(system_description="s"), [], [], str(tmp_path)))
    assert data["summary"]["confirmed_whitebox_bugs"] is None


# --- 2. 安裝不完整：exit 5，不是 1 ------------------------------------------------------------------------
# --- 2. A broken install exits 5, not 1 ---------------------------------------------------------------------

def test_missing_dependency_exits_5_with_a_clear_message(monkeypatch, capsys):
    """harness 匯入失敗（模擬缺少 yaml）時，main() 以 5 結束並說明如何重新安裝，而不是 1（NEEDS_FIXES）。
    When importing the harness fails (a simulated missing yaml), main() exits 5 and says how to reinstall,
    instead of 1 (NEEDS_FIXES)."""
    for name in cli._LAZY_IMPORTS:
        monkeypatch.delitem(cli.__dict__, name, raising=False)

    def broken(module):
        raise ModuleNotFoundError("No module named 'yaml'", name="yaml")

    monkeypatch.setattr(cli.importlib, "import_module", broken)
    assert _run_cli(monkeypatch, "--version") == cli.USAGE_ERROR_EXIT_CODE
    err = capsys.readouterr().err
    assert "pip install --force-reinstall vibeharness-mas" in err and "missing module: yaml" in err


def test_importing_the_cli_module_loads_no_third_party_dependency():
    """匯入 vibeharness.cli 不會匯入 pydantic／yaml／rich／litellm：它們的失敗必須在 main() 的防護內發生。
    Importing vibeharness.cli imports none of pydantic / yaml / rich / litellm: their failure must happen inside main()'s guard."""
    code = ("import sys, vibeharness.cli; "
            "print(sorted(m for m in ('pydantic', 'yaml', 'rich', 'litellm') if m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True,
                         env=dict(os.environ, PYTHONPATH=REPO_ROOT), check=True).stdout
    assert out.strip() == "[]"


@pytest.mark.parametrize("launcher", [
    "import runpy; runpy.run_module('vibeharness', run_name='__main__')",
    "import runpy; runpy.run_path('main.py', run_name='__main__')",
    "from vibeharness.cli import main; main()",
])
def test_every_launcher_exits_5_when_a_dependency_is_missing(launcher):
    """`python -m vibeharness`、`python main.py` 與 console script 在缺少相依套件（yaml 被封鎖）時都以 5 結束。
    `python -m vibeharness`, `python main.py` and the console script all exit 5 when a dependency (blocked yaml) is missing."""
    code = f"import sys; sys.modules['yaml'] = None; sys.argv = ['vibeharness', '--version']; {launcher}"
    proc = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True,
                          env=dict(os.environ, PYTHONPATH=REPO_ROOT))
    assert proc.returncode == 5, proc.stderr
    assert "vibeharness-mas" in proc.stderr and "Traceback" not in proc.stderr


def test_python_dash_m_vibeharness_runs_the_cli():
    """`python -m vibeharness --version` 印出版本並以 0 結束。
    `python -m vibeharness --version` prints the version and exits 0."""
    proc = subprocess.run([sys.executable, "-m", "vibeharness", "--version"], cwd=REPO_ROOT, capture_output=True,
                          text=True, env=dict(os.environ, PYTHONPATH=REPO_ROOT))
    assert proc.returncode == 0 and proc.stdout.startswith("vibeharness ")


# --- 3. litellm 的罐頭回應鍵是保留參數 --------------------------------------------------------------------
# --- 3. litellm's canned-response keys are reserved ---------------------------------------------------------

@pytest.mark.parametrize("key", ["mock_response", "mock_tool_calls", "mock_timeout", "mock_delay", "ssl_verify"])
def test_canned_response_extra_params_are_refused(tmp_path, key):
    """extra_params 裡的 mock_* 會讓 litellm 不連網就回傳假答案、被記成 live 證據：啟動即 ConfigError。
    A mock_* key in extra_params makes litellm return a fake answer with no network call, booked as live
    evidence: a ConfigError at start-up."""
    assert key in RESERVED_EXTRA_PARAMS
    path = tmp_path / "agents.yaml"
    path.write_text(f"models:\n  a: {{model: m, api_key_env: K, extra_params: {{{key}: x}}}}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=key):
        LLMGateway(str(path))


# --- 4. 呼叫紀錄確定且保留時間順序 -----------------------------------------------------------------------
# --- 4. The call log is deterministic and chronological -----------------------------------------------------

def test_sorted_call_log_keeps_retried_before_live_whatever_the_completion_order():
    """同一次邏輯呼叫的 "retried" 一定排在 "live"／"invalid" 之前，而且任何完成順序排序後都相同。
    A logical call's "retried" entries always precede its "live" / "invalid" one, and every completion order sorts the same."""
    records = []
    for i in range(6):
        sha = f"{i:064x}"
        records += [
            AgentCallRecord(agent_id=f"agent_{i % 2}", model_alias="a", model_name="m", mode="retried",
                            reason="r", prompt_sha256=sha, attempt=0),
            AgentCallRecord(agent_id=f"agent_{i % 2}", model_alias="a", model_name="m", mode="retried",
                            reason="r", prompt_sha256=sha, attempt=1),
            AgentCallRecord(agent_id=f"agent_{i % 2}", model_alias="a", model_name="m",
                            mode="live" if i % 3 else "invalid", prompt_sha256=sha, attempt=2),
        ]
    expected = sorted_call_log(records)
    for seed in range(5):
        shuffled = list(records)
        random.Random(seed).shuffle(shuffled)
        assert sorted_call_log(shuffled) == expected
    for i in range(0, len(expected), 3):
        call = expected[i:i + 3]
        assert len({r.prompt_sha256 for r in call}) == 1
        assert [r.mode for r in call][:2] == ["retried", "retried"] and [r.attempt for r in call] == [0, 1, 2]


def test_gateway_books_the_attempt_number(tmp_path, fake_live):
    """閘道在每筆紀錄上登記第幾次詢問：無法使用的第一次回答是 attempt 0 的 "retried"，重新詢問後的回答是 attempt 1 的 "live"。
    The gateway books the attempt on every record: the unusable first answer is "retried" at attempt 0, the
    answer after the re-ask is "live" at attempt 1."""
    answers = iter(["not json", '{"ok": 1}'])
    fake_live(lambda system, user: next(answers))
    path = tmp_path / "agents.yaml"
    path.write_text("global: {execution_mode: live, max_retries: 0, retry_invalid_output: 1}\n"
                    "models:\n  a: {model: m-a, api_key_env: ANTHROPIC_API_KEY}\nagents:\n  x: {model_alias: a}\n",
                    encoding="utf-8")
    gw = LLMGateway(str(path))
    assert gw.generate("x", "s", "u", required_keys=["ok"])["ok"] == 1
    assert [(r.mode, r.attempt) for r in sorted_call_log(list(reversed(gw.call_log)))] == [("retried", 0), ("live", 1)]
    assert gw.call_log[0].prompt_sha256 == gw.call_log[1].prompt_sha256


# --- 5. --cache-only：估算不乘重新詢問，mock 模式會警告 ---------------------------------------------------
# --- 5. --cache-only: the estimate has no re-asks, and mock mode warns --------------------------------------

def test_cache_only_estimate_does_not_multiply_by_re_asks(tmp_path):
    """--cache-only 絕不重新詢問：每個代理的最大呼叫數不再乘上 1 + retry_invalid_output。
    --cache-only never re-asks: no agent's max calls is multiplied by 1 + retry_invalid_output any more."""
    commander = VibeHarnessCommander(execution_mode="hybrid")
    commander.gateway.retry_invalid_output = 2
    normal = estimate_run(commander, EXAMPLES)
    commander.gateway.set_cache_dir(str(tmp_path / "cache"))
    commander.gateway.cache_only = True
    replay = estimate_run(commander, EXAMPLES)
    reviewer = next(c for c in replay.by_agent if c.calls_exact is not None and c.calls_exact > 0)
    assert reviewer.calls_max == reviewer.calls_exact
    assert next(c for c in normal.by_agent if c.agent == reviewer.agent).calls_max == reviewer.calls_exact * 3
    assert replay.calls_max < normal.calls_max


def test_cache_only_in_mock_mode_warns(monkeypatch, tmp_path, capsys):
    """--cache-only 搭配 --mode mock 沒有作用：照常執行，但在 stderr 印出雙語警告。
    --cache-only with --mode mock has no effect: the run goes ahead, with a bilingual warning on stderr."""
    _capture_run(monkeypatch)
    code = _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock", "--cache-only", "--cache-dir", str(tmp_path / "c"))
    assert code == 3
    err = capsys.readouterr().err
    assert "--cache-only has no effect in mock mode" in err and "--cache-only 在 mock 模式下沒有作用" in err


def test_cache_only_in_hybrid_mode_does_not_warn(monkeypatch, tmp_path, capsys):
    """hybrid 模式的 --cache-only 不印 mock 警告。
    --cache-only in hybrid mode prints no mock warning."""
    _capture_run(monkeypatch)
    _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "hybrid", "--cache-only", "--cache-dir", str(tmp_path / "c"))
    assert "no effect in mock mode" not in capsys.readouterr().err


# --- 6a. --target 預設為目前目錄 --------------------------------------------------------------------------
# --- 6a. --target defaults to the current directory -----------------------------------------------------------

def test_target_defaults_to_the_current_directory(monkeypatch, tmp_path):
    """沒有 --target 時稽核目前目錄。
    Without --target the current directory is audited."""
    seen = _capture_run(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert _run_cli(monkeypatch, "-m", "mock") == 3
    assert seen["target_dir"] == str(tmp_path)


# --- 6b. --init-config 寫出預設設定 -----------------------------------------------------------------------
# --- 6b. --init-config writes the default config ------------------------------------------------------------

def test_init_config_writes_the_bundled_default_to_the_current_directory(monkeypatch, tmp_path, capsys):
    """沒給路徑的 --init-config 把套件內的預設設定寫到 ./vibeharness.yaml 並以 0 結束，不啟動 harness。
    --init-config without a path writes the bundled default to ./vibeharness.yaml and exits 0 without starting the harness."""
    monkeypatch.setattr(cli.VibeHarnessCommander, "__init__", lambda *a, **k: pytest.fail("no harness for --init-config"))
    monkeypatch.chdir(tmp_path)
    assert _run_cli(monkeypatch, "--init-config") == 0
    written = tmp_path / "vibeharness.yaml"
    with open(DEFAULT_CONFIG_PATH, encoding="utf-8") as f:
        assert written.read_text(encoding="utf-8") == f.read()
    assert "vibeharness.yaml" in capsys.readouterr().out


def test_init_config_refuses_to_overwrite_without_force(monkeypatch, tmp_path):
    """已存在的檔案沒有 --force 時不覆寫（exit 5）；--force 覆寫（exit 0）。
    An existing file is not overwritten without --force (exit 5); --force overwrites it (exit 0)."""
    path = tmp_path / "custom.yaml"
    path.write_text("mine\n", encoding="utf-8")
    assert _run_cli(monkeypatch, "--init-config", str(path)) == cli.USAGE_ERROR_EXIT_CODE
    assert path.read_text(encoding="utf-8") == "mine\n"
    assert _run_cli(monkeypatch, "--init-config", str(path), "--force") == 0
    assert path.read_text(encoding="utf-8") != "mine\n"


@pytest.mark.parametrize("argv", [["--init-config", "{tmp}"], ["--init-config", "{tmp}/missing/x.yaml"], ["--force"]])
def test_init_config_usage_errors_exit_5(monkeypatch, tmp_path, argv):
    """目錄、不存在的父目錄，或沒有 --init-config 的 --force，都是用法錯誤（exit 5）。
    A directory, a missing parent directory, or --force without --init-config is a usage error (exit 5)."""
    _capture_run(monkeypatch)
    args = [a.replace("{tmp}", str(tmp_path)) for a in argv]
    assert _run_cli(monkeypatch, "-t", str(tmp_path), *args) == cli.USAGE_ERROR_EXIT_CODE


# --- 6c. 設定檔探索 ---------------------------------------------------------------------------------------
# --- 6c. Config discovery ---------------------------------------------------------------------------------

_MOCK_CONFIG = "global: {execution_mode: mock}\n"


@pytest.mark.parametrize("names, expected", [
    ((), None),
    ((".vibeharness.yaml",), ".vibeharness.yaml"),
    (("vibeharness.yaml",), "vibeharness.yaml"),
    (("vibeharness.yaml", ".vibeharness.yaml"), "vibeharness.yaml"),
])
def test_config_discovery_precedence(monkeypatch, tmp_path, capsys, names, expected):
    """沒有 --config 時：./vibeharness.yaml ＞ ./.vibeharness.yaml ＞ 套件內的預設；使用的設定檔印在 stderr。
    Without --config: ./vibeharness.yaml > ./.vibeharness.yaml > the bundled default; the config used is printed on stderr."""
    for name in names:
        (tmp_path / name).write_text(_MOCK_CONFIG, encoding="utf-8")
    seen = _capture_run(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert _run_cli(monkeypatch, "-m", "mock") == 3
    want = str(tmp_path / expected) if expected else os.path.abspath(DEFAULT_CONFIG_PATH)
    assert seen["config_path"] == want
    err = capsys.readouterr().err
    assert f"Config: {want if expected else DEFAULT_CONFIG_PATH}" in err
    assert ("found " + expected) in err if expected else "bundled default" in err


def test_explicit_config_wins_over_a_discovered_one(monkeypatch, tmp_path):
    """--config 優先於目前目錄的 vibeharness.yaml。
    --config wins over a vibeharness.yaml in the current directory."""
    (tmp_path / "vibeharness.yaml").write_text("global: [broken\n", encoding="utf-8")
    explicit = tmp_path / "other.yaml"
    explicit.write_text(_MOCK_CONFIG, encoding="utf-8")
    seen = _capture_run(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert _run_cli(monkeypatch, "-c", str(explicit)) == 3
    assert seen["config_path"] == str(explicit)


def test_a_broken_discovered_config_exits_5(monkeypatch, tmp_path):
    """探索到的設定檔與 --config 一樣受驗證：損壞的 YAML 以 5 結束。
    A discovered config is validated like --config: broken YAML exits 5."""
    (tmp_path / "vibeharness.yaml").write_text("global: [broken\n", encoding="utf-8")
    _capture_run(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert _run_cli(monkeypatch, "-m", "mock") == cli.USAGE_ERROR_EXIT_CODE


def test_resolve_config_path_uses_the_given_directory(tmp_path):
    """resolve_config_path 只看指定的目錄，而且找不到時回到套件內的預設。
    resolve_config_path looks only in the given directory and falls back to the bundled default."""
    assert cli.resolve_config_path(None, str(tmp_path))[0] == DEFAULT_CONFIG_PATH
    (tmp_path / ".vibeharness.yaml").write_text(_MOCK_CONFIG, encoding="utf-8")
    assert cli.resolve_config_path(None, str(tmp_path))[0] == str(tmp_path / ".vibeharness.yaml")
    assert cli.resolve_config_path("x.yaml", str(tmp_path)) == ("x.yaml", "--config")


def test_init_config_message_only_promises_discovery_for_discovered_names(tmp_path, capsys):
    """只有 vibeharness.yaml／.vibeharness.yaml 會被自動採用；其他檔名的訊息改為提示 --config。
    Only vibeharness.yaml / .vibeharness.yaml are picked up automatically; other names are told to use --config."""
    from vibeharness import cli
    assert cli._init_config(str(tmp_path / "vibeharness.yaml"), force=False) == 0
    assert "pick it up automatically" in capsys.readouterr().out
    assert cli._init_config(str(tmp_path / "custom.yaml"), force=False) == 0
    out = capsys.readouterr().out
    assert "not picked up automatically" in out and "--config" in out
