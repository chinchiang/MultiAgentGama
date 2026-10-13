"""CLI 結束碼、設定驗證、閘道重試與快取鍵，以及未經驗證假設的計數（審查發現的回歸測試）。
CLI exit codes, config validation, gateway re-asks and cache keys, and the unverified-hypothesis count
(regression tests for review findings)."""
import dataclasses
import os
import random
import shutil
import sys
from types import SimpleNamespace

import pytest

from vibeharness import cli
from vibeharness.core.harness import VibeHarnessCommander, sorted_call_log
from vibeharness.core.llm_gateway import ConfigError, LLMGateway, LLMGatewayError, RESERVED_EXTRA_PARAMS
from vibeharness.core.models import AgentCallRecord
from vibeharness.core.sandbox import SandboxUnavailableError
from vibeharness.core.settings import freeze, load_settings
from vibeharness.core.model_output import ANY, OutputSchema

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write_config(tmp_path, text):
    """把 YAML 文字寫成暫存設定檔並回傳路徑。
    Writes YAML text to a temporary config file and returns its path."""
    path = tmp_path / "agents.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def _run_cli(monkeypatch, *argv):
    """以指定參數執行 CLI，回傳它的結束碼。
    Runs the CLI with the given arguments and returns its exit code."""
    monkeypatch.setattr(sys, "argv", ["vibeharness", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return exit_info.value.code


# --- 結束碼：當掉絕不會被讀成判定結果 ------------------------------------------------------------
# --- Exit codes: a crash never reads as a verdict ---------------------------------------------------

def test_live_gateway_failure_exits_4(monkeypatch, tmp_path):
    """live 模式的模型呼叫失敗以 4 結束。
    A failed live-mode model invocation exits 4."""
    def run(self, **kwargs):
        raise LLMGatewayError("no key")

    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock") == 4


def test_unexpected_crash_during_run_exits_5(monkeypatch, tmp_path):
    """執行中的意外例外以 5 結束，不是 1（NEEDS_FIXES）。
    An unexpected exception during the run exits 5, not 1 (NEEDS_FIXES)."""
    def run(self, **kwargs):
        raise KeyError("boom")

    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock") == cli.USAGE_ERROR_EXIT_CODE


@pytest.mark.parametrize("error", [
    ConfigError("bad"), SandboxUnavailableError("no docker"), ValueError("bad value"),
    TypeError("int() argument must be ..."), AttributeError("'NoneType' object has no attribute 'get'"),
    OSError("disk"), RuntimeError("anything"),
])
def test_any_construction_failure_exits_5_not_1(monkeypatch, tmp_path, error):
    """建構 harness 時的任何例外都以 5 結束。
    Any exception while constructing the harness exits 5."""
    def boom(*args, **kwargs):
        raise error

    monkeypatch.setattr(cli, "VibeHarnessCommander", boom)
    assert _run_cli(monkeypatch, "-t", str(tmp_path)) == cli.USAGE_ERROR_EXIT_CODE


def test_failure_while_configuring_the_harness_exits_5(monkeypatch, tmp_path):
    """設定 harness（例如 --cache-dir）時的意外例外也以 5 結束。
    An unexpected exception while configuring the harness (e.g. --cache-dir) exits 5 too."""
    def boom(path):
        raise PermissionError("denied")

    # --cache-dir 在載入設定時準備 ／ --cache-dir is prepared while the settings are loaded
    monkeypatch.setattr("vibeharness.core.settings.prepare_cache_dir", boom)
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock", "--cache-dir", str(tmp_path / "c")) == 5


@pytest.mark.parametrize("error", [OSError("cannot write"), ValueError("bad ref"), RuntimeError("bug")])
def test_estimate_failures_exit_5(monkeypatch, tmp_path, error):
    """--estimate 的任何失敗（包含寫入 JSON 的 OSError）都以 5 結束。
    Any --estimate failure (including an OSError writing the JSON) exits 5."""
    def boom(commander, target):
        raise error

    monkeypatch.setattr(cli, "estimate_run", boom)
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock", "--estimate") == 5


def test_estimate_json_write_error_exits_5(monkeypatch, tmp_path):
    """--estimate --format json 寫入失敗時以 5 結束，而不是帶 traceback 的 1。
    A failed write of --estimate --format json exits 5, not 1 with a traceback."""
    def dump(**kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(cli, "estimate_run", lambda commander, target: SimpleNamespace(model_dump_json=dump))
    code = _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock", "--estimate", "-f", "json",
                    "-o", str(tmp_path / "e.json"))
    assert code == 5


def test_crash_outside_every_stage_exits_5(monkeypatch, tmp_path):
    """任何階段之外的例外（例如設定日誌）也由最外層攔下並以 5 結束。
    An exception outside every stage (e.g. setting up logging) is caught at the top and exits 5."""
    def boom(verbose=False):
        raise RuntimeError("logging broke")

    monkeypatch.setattr(cli, "setup_logging", boom)
    assert _run_cli(monkeypatch, "-t", str(tmp_path)) == 5


def test_config_pointing_at_a_directory_exits_5(monkeypatch, tmp_path):
    """把目錄當成 --config 以 5 結束。
    A directory passed as --config exits 5."""
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "-c", str(tmp_path)) == cli.USAGE_ERROR_EXIT_CODE


# --- 設定驗證 ----------------------------------------------------------------------------------------
# --- Config validation --------------------------------------------------------------------------------

def test_directory_as_config_is_a_config_error(tmp_path):
    """目錄設定檔是 ConfigError。
    A directory config is a ConfigError."""
    with pytest.raises(ConfigError, match="cannot be read"):
        LLMGateway(str(tmp_path))


def test_binary_config_is_a_config_error(tmp_path):
    """無法以 UTF-8 解碼的設定檔是 ConfigError。
    A config that cannot be decoded as UTF-8 is a ConfigError."""
    path = tmp_path / "bin.yaml"
    path.write_bytes(b"\xff\xfe\x00\x80garbage")
    with pytest.raises(ConfigError):
        LLMGateway(str(path))


@pytest.mark.parametrize("text", [
    "- a\n- b\n", "just a string\n", "42\n", "global: [1, 2]\n", "models: [1, 2]\n", "agents: just-a-string\n",
    "models:\n  a: [1, 2]\n", "agents:\n  x: text\n",
])
def test_non_mapping_config_is_a_config_error(tmp_path, text):
    """最上層、區段或單一項目不是對應表時都是 ConfigError。
    A non-mapping top level, section or entry is a ConfigError."""
    with pytest.raises(ConfigError, match="mapping"):
        LLMGateway(_write_config(tmp_path, text))


def test_empty_global_section_falls_back_to_defaults(tmp_path):
    """空的 `global:` 不會當掉，使用預設值。
    An empty `global:` does not crash and uses the defaults."""
    gw = LLMGateway(_write_config(tmp_path, "global:\nmodels:\nagents:\n"))
    assert gw.execution_mode == "hybrid"
    commander = VibeHarnessCommander(_write_config(tmp_path, "global:\n"), execution_mode="mock")
    assert commander.executor.per_test_timeout_seconds == 30


def test_empty_config_file_uses_defaults(tmp_path):
    """空的設定檔等於空對應表。
    An empty config file is an empty mapping."""
    assert LLMGateway(_write_config(tmp_path, "")).execution_mode == "hybrid"


# --- 沙盒設定：null／0 與文件一致 --------------------------------------------------------------------
# --- Sandbox settings: null / 0 follow the documentation --------------------------------------------

@pytest.mark.parametrize("value", ["null", "0"])
def test_null_or_zero_per_test_timeout_keeps_the_default_everywhere(tmp_path, value):
    """per_test_timeout_seconds 為 null／0 時，執行器與突變測試都用預設的 30 秒。
    A null / 0 per_test_timeout_seconds gives the executor and mutation testing the same default of 30 s."""
    commander = VibeHarnessCommander(
        _write_config(tmp_path, f"global: {{per_test_timeout_seconds: {value}}}\n"), execution_mode="mock"
    )
    assert commander.executor.per_test_timeout_seconds == 30
    assert commander.settings.mutation.timeout == 30


def test_per_test_timeout_reaches_the_executor_and_mutation(tmp_path):
    """有效的 per_test_timeout_seconds 同時用於執行器與突變測試。
    A valid per_test_timeout_seconds is used by both the executor and mutation testing."""
    commander = VibeHarnessCommander(
        _write_config(tmp_path, "global: {per_test_timeout_seconds: 7}\n"), execution_mode="mock"
    )
    assert commander.executor.per_test_timeout_seconds == 7
    assert commander.settings.mutation.timeout == 7


@pytest.mark.parametrize("value", ["-5", "1.5", "abc", "true"])
def test_invalid_per_test_timeout_is_a_config_error(tmp_path, value):
    """負數或非整數的 per_test_timeout_seconds 是 ConfigError。
    A negative or non-integer per_test_timeout_seconds is a ConfigError."""
    with pytest.raises(ConfigError, match="per_test_timeout_seconds"):
        VibeHarnessCommander(_write_config(tmp_path, f"global: {{per_test_timeout_seconds: {value}}}\n"),
                             execution_mode="mock")


def test_null_sandbox_timeout_keeps_the_default(tmp_path):
    """sandbox_timeout_seconds 為 null 時保留預設的 120 秒。
    A null sandbox_timeout_seconds keeps the default of 120 s."""
    commander = VibeHarnessCommander(
        _write_config(tmp_path, "global: {sandbox_timeout_seconds: null}\n"), execution_mode="mock"
    )
    assert commander.sandbox.timeout_seconds == 120


# --- extra_params 不能覆寫端點、憑證或控制參數 -----------------------------------------------------
# --- extra_params cannot override endpoints, credentials or control parameters ----------------------

@pytest.mark.parametrize("key", ["api_base", "base_url", "api_key", "timeout", "num_retries", "model", "messages",
                                 "aws_region_name", "stream"])
def test_reserved_extra_params_are_config_errors(tmp_path, key):
    """extra_params 中的保留鍵是 ConfigError，無法繞過 api_base 的 https 檢查。
    A reserved key in extra_params is a ConfigError, so it cannot bypass the https check on api_base."""
    text = f"models:\n  a:\n    model: m\n    api_key_env: X\n    extra_params: {{{key}: 'http://evil.example'}}\n"
    with pytest.raises(ConfigError, match=f"models.a.extra_params.*{key}"):
        LLMGateway(_write_config(tmp_path, text))


@pytest.mark.parametrize("key", ["max_tokens", "max_completion_tokens", "max_output_tokens"])
def test_output_token_caps_in_extra_params_point_at_max_output_tokens(tmp_path, key):
    """extra_params 裡的輸出 token 上限是 ConfigError，訊息指向 max_output_tokens（否則會覆寫它並讓 --estimate 失準）。
    An output-token cap in extra_params is a ConfigError whose message points at max_output_tokens (it would
    override it and skew --estimate)."""
    text = f"models:\n  a:\n    model: m\n    api_key_env: X\n    extra_params: {{{key}: 99}}\n"
    with pytest.raises(ConfigError, match=r"output-token cap.*models\.a\.max_output_tokens"):
        LLMGateway(_write_config(tmp_path, text))


def test_null_request_settings_fall_back_to_their_defaults(tmp_path, fake_live):
    """global 的 timeout_seconds／max_retries／max_output_tokens 與逐模型 max_output_tokens 為 null 時採用預設值，
    絕不把 timeout=None（不限時）傳給 litellm。
    A null global timeout_seconds / max_retries / max_output_tokens or per-model max_output_tokens means the
    default, and timeout=None (no limit) never reaches litellm."""
    text = (
        "global: {execution_mode: live, timeout_seconds: null, max_retries: null, max_output_tokens: null}\n"
        "models:\n  a: {model: m-a, api_key_env: ANTHROPIC_API_KEY, max_output_tokens: null}\n"
        "agents:\n  x: {model_alias: a}\n"
    )
    gw = LLMGateway(_write_config(tmp_path, text))
    fake = fake_live(lambda system, user: '{"ok": 1}')
    gw.generate("x", "s", "u")
    assert fake.calls[0]["timeout"] == 180
    assert fake.calls[0]["num_retries"] == 2
    assert fake.calls[0]["max_tokens"] == 16384


@pytest.mark.parametrize("setting", ["timeout_seconds: 0", "max_retries: -1", "max_output_tokens: 0", "timeout_seconds: abc"])
def test_out_of_range_request_settings_are_still_config_errors(tmp_path, setting):
    """null 是預設值，但 0、負數與非數值仍是 ConfigError。
    null is the default, but 0, negative and non-numeric values are still a ConfigError."""
    with pytest.raises(ConfigError):
        LLMGateway(_write_config(tmp_path, f"global: {{{setting}}}\n"))


def test_ordinary_extra_params_still_pass_through(tmp_path, fake_live):
    """一般的 extra_params（例如 reasoning_effort）照常傳給 litellm，保留鍵則不會。
    Ordinary extra_params (e.g. reasoning_effort) still reach litellm, reserved ones never do."""
    text = (
        "global: {execution_mode: live, max_retries: 0}\n"
        "models:\n  a: {model: m-a, api_key_env: ANTHROPIC_API_KEY, extra_params: {reasoning_effort: low}}\n"
        "agents:\n  x: {model_alias: a}\n"
    )
    settings = load_settings(_write_config(tmp_path, text), origin="explicit")
    # 縱深防禦：即使設定沒有經過載入時的驗證（直接建構），保留鍵也不會送到 litellm
    # Defense in depth: even for settings that skipped the load-time validation (built directly), a reserved key
    # never reaches litellm
    models = freeze({"a": {**settings.gateway.models["a"], "extra_params": {"reasoning_effort": "low", "api_base": "http://evil.example"}}})
    gw = LLMGateway(settings=dataclasses.replace(settings, gateway=dataclasses.replace(settings.gateway, models=models)))
    fake = fake_live(lambda system, user: '{"ok": 1}')
    gw.generate("x", "s", "u")
    assert fake.calls[0]["reasoning_effort"] == "low"
    assert "api_base" not in fake.calls[0]
    assert {"api_base", "base_url", "api_key", "timeout"} <= RESERVED_EXTRA_PARAMS


# --- 重新詢問一律從主要模型開始 ---------------------------------------------------------------------
# --- A re-ask always starts from the primary model ---------------------------------------------------

class _PrimaryDownLiteLLM:
    """主要模型一律失敗、fallback 第一次回答無法使用的假 litellm。
    A fake litellm whose primary always fails and whose fallback answers unusably the first time."""

    def __init__(self):
        self.models = []

    def completion(self, model, **kwargs):
        """記錄被呼叫的模型；主要模型拋錯，fallback 先回散文、再回 JSON。
        Records the model called; the primary raises, the fallback answers prose first, then JSON."""
        self.models.append(model)
        if model == "primary-model":
            raise RuntimeError("primary down")
        text = "not json" if self.models.count("fallback-model") == 1 else '{"ok": 1}'
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text), finish_reason="stop")])


def test_reask_after_a_fallback_answer_tries_the_primary_again(tmp_path, monkeypatch):
    """fallback 回答無法使用而重新詢問時，先試主要模型，fallback 不會被呼叫兩次而跳過主要模型。
    When a fallback answer is re-asked, the primary is tried first; the fallback is not called twice in a row."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    fake = _PrimaryDownLiteLLM()
    monkeypatch.setattr("vibeharness.core.transport.litellm", fake)
    text = (
        "global: {execution_mode: live, max_retries: 0, retry_invalid_output: 1}\n"
        "models:\n  a: {model: primary-model, fallback_model: fallback-model, api_key_env: ANTHROPIC_API_KEY}\n"
        "agents:\n  x: {model_alias: a}\n"
    )
    gw = LLMGateway(_write_config(tmp_path, text))
    result = gw.generate("x", "s", "u", schema=OutputSchema(required={"ok": ANY}))
    assert result["ok"] == 1
    assert fake.models == ["primary-model", "fallback-model", "primary-model", "fallback-model"]


# --- 回應快取的鍵包含端點身分 -----------------------------------------------------------------------
# --- The response-cache key includes the endpoint identity -----------------------------------------

@pytest.mark.parametrize("key, value", [
    ("api_base", "https://other.example/v1"), ("aws_region_name", "eu-west-1"),
    ("aws_profile_name", "other"), ("api_key_env", "OTHER_KEY"),
])
def test_cache_key_changes_with_the_endpoint(tmp_path, key, value):
    """同一個模型字串指向不同端點／區域／帳號時，快取鍵不同。
    The same model string pointed at another endpoint / region / account gets a different cache key."""
    gw = LLMGateway(_write_config(tmp_path, ""), execution_mode="mock")
    base = {"model": "m", "api_key_env": "K", "api_base": "https://a.example/v1",
            "aws_region_name": "us-east-1", "aws_profile_name": "p"}
    other = dict(base, **{key: value})
    assert gw._cache_key("a", base, 0.2, "s", "u") != gw._cache_key("a", other, 0.2, "s", "u")
    assert gw._cache_key("a", base, 0.2, "s", "u") == gw._cache_key("a", dict(base), 0.2, "s", "u")


# --- 確定性的呼叫紀錄順序 ----------------------------------------------------------------------------
# --- Deterministic call-log order ---------------------------------------------------------------------

def test_agent_calls_are_sorted_deterministically():
    """呼叫紀錄不論完成順序為何，排序後都相同。
    The call log sorts to the same order whatever the completion order was."""
    records = [
        AgentCallRecord(agent_id=f"agent_{i % 3}", model_alias="a", model_name=f"m{i % 2}", mode=mode,
                        prompt_sha256=f"{i:04d}")
        for i in range(12) for mode in ("live", "retried")
    ]
    shuffled = list(records)
    random.Random(7).shuffle(shuffled)
    assert sorted_call_log(shuffled) == sorted_call_log(records)
    assert [r.agent_id for r in sorted_call_log(shuffled)] == sorted(r.agent_id for r in records)


# --- 未經驗證的假設絕不會被算成已確認 -----------------------------------------------------------------
# --- Unverified hypotheses are never counted as confirmed --------------------------------------------

def test_unverified_findings_are_not_counted_as_confirmed(tmp_path, capsys):
    """mock 模式沒有真實的驗證投票：已確認數為 None（JSON 為 null，不是會被讀成乾淨的 0），主控台與報告顯示 N/A 與未經驗證的假設數。
    Mock mode casts no real verifier vote: the confirmed count is None (null in JSON, not a 0 that reads as
    clean) and the console and report show N/A with the number of unverified hypotheses."""
    target = tmp_path / "app"
    target.mkdir()
    shutil.copy(os.path.join(REPO_ROOT, "examples", "vibe_sample_app.py"), target)
    commander = VibeHarnessCommander(execution_mode="mock")
    report = tmp_path / "r.md"
    summary = commander.run_full_pipeline(target_dir=str(target), output_report_path=str(report))
    assert summary.total_whitebox_findings > 0
    assert summary.confirmed_whitebox_bugs is None
    assert summary.model_dump(mode="json")["confirmed_whitebox_bugs"] is None
    assert summary.agent_calls == sorted_call_log(summary.agent_calls)
    out = capsys.readouterr().out
    assert "N/A" in out and "unverified hypotheses passed to testing" in out
    text = report.read_text(encoding="utf-8")
    assert "Confirmed White-Box Logic Flaws" in text and "`N/A`" in text
    assert "unverified hypotheses; verification not applied" in text
