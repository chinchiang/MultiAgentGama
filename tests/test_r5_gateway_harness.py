"""第五輪審查的回歸測試：extra_params 保留 litellm 的記錄／callback 參數（但允許成本覆寫）、自動發現的設定檔接受先前版本的
內建模型字串、匯入 litellm 時不連網、啟動時檢查 model_alias、docker_* 的 null 保留預設值、模型字串去掉空白後保存，
以及自動發現的設定檔只能調低花費。
Regression tests from the fifth review round: extra_params reserves litellm's logging / callback parameters (but allows
cost overrides), a discovered config accepts a previous release's bundled model strings, importing litellm makes no
network call, model_alias is checked at start-up, null docker_* keys keep the default, model strings are kept
stripped, and a discovered config may only lower spend."""
import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml

from vibeharness import cli
from vibeharness.core.settings import load_settings
from vibeharness.core.llm_gateway import (
    DEFAULT_CONFIG_PATH, ConfigError, LLMGateway, _PREVIOUS_BUNDLED_MODELS, check_discovered_config,
    discovered_config_violations, is_reserved_extra_param, load_config_file,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write(tmp_path, cfg, name="agents.yaml"):
    """把設定 dict 寫成 YAML 並回傳路徑 ／ Writes a config dict as YAML and returns its path."""
    path = tmp_path / name
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return str(path)


def _bundled():
    """套件內預設設定的新副本 ／ A fresh copy of the bundled default config."""
    return load_config_file(DEFAULT_CONFIG_PATH)


def _run_cli(monkeypatch, *argv):
    """以指定參數執行 CLI，回傳它的結束碼 ／ Runs the CLI with the given arguments and returns its exit code."""
    monkeypatch.setattr(sys, "argv", ["vibeharness", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return exit_info.value.code


# --- 1. extra_params：記錄／callback 參數保留，成本覆寫允許 -------------------------------------------
# --- 1. extra_params: logging / callback parameters reserved, cost overrides allowed ---------------------

_CALLBACK_PARAMS = [
    "callbacks", "success_callback", "failure_callback", "_async_success_callback", "_async_failure_callback",
    "litellm_disabled_callbacks", "litellm_trusted_callback_vars", "my_new_callback", "service_callbacks",
    "langfuse_host", "langfuse_public_key", "langfuse_secret_key", "langsmith_api_key", "langsmith_project",
    "langsmith_base_url", "gcs_bucket_name", "gcs_path_service_account", "s3_bucket_name", "s3_region_name",
    "dd_api_key", "dd_site", "dd_agent_host", "datadog_site", "helicone_api_key", "lunary_public_key",
    "humanloop_api_key", "arize_space_key", "posthog_host", "braintrust_project", "slack_webhook_url",
    "newrelic_region", "wandb_api_key", "metadata", "litellm_metadata", "litellm_params", "prompt_id",
    "litellm_system_prompt", "model_alias_map", "context_window_fallback_dict", "some_webhook", "otel_endpoint",
]


@pytest.mark.parametrize("name", _CALLBACK_PARAMS)
def test_logging_and_callback_params_are_reserved(name):
    """重現：success_callback／langfuse_host／metadata 等會把提示（受稽核的原始碼）送到第三方觀測服務，過去可放進 extra_params。
    Reproduction: success_callback / langfuse_host / metadata and the like send the prompt (the audited source code)
    to third-party observability services and used to be accepted in extra_params."""
    assert is_reserved_extra_param(name)


@pytest.mark.parametrize("name", ["token", "access_token", "api_token", "id_token", "refresh_token", "auth_token",
                                  "aws_session_token", "gigachat_access_token", "token_provider"])
def test_real_token_and_credential_keys_stay_reserved(name):
    """真正的 token／憑證鍵仍然保留 ／ Real token / credential keys stay reserved."""
    assert is_reserved_extra_param(name)


@pytest.mark.parametrize("name", ["input_cost_per_token", "output_cost_per_token", "cache_read_input_token_cost",
                                  "cache_creation_input_token_cost", "input_cost_per_token_above_128k_tokens",
                                  "reasoning_effort", "thinking", "top_p", "seed", "response_format",
                                  "turn_off_message_logging"])
def test_cost_overrides_and_ordinary_params_are_allowed(name):
    """重現：input_cost_per_token 因名稱含 token 而被誤拒；成本覆寫不改變目的地，允許。
    Reproduction: input_cost_per_token was wrongly refused for its `token` name part; a cost override does not change
    the destination, so it is allowed."""
    assert not is_reserved_extra_param(name)


def test_every_litellm_callback_param_is_reserved():
    """與已安裝的 litellm 原始碼比對：它從 kwargs 讀取的每個 callback 動態參數都被保留（只會關閉記錄的
    turn_off_message_logging 除外）。
    Checked against the installed litellm source: every callback dynamic parameter it reads from kwargs is reserved
    (except turn_off_message_logging, which only turns logging off)."""
    params_mod = pytest.importorskip("litellm.litellm_core_utils.initialize_dynamic_callback_params")
    types_mod = pytest.importorskip("litellm.types.utils")
    names = set(getattr(params_mod, "_supported_callback_params", ()))
    names |= set(getattr(params_mod, "_request_blocked_callback_params", ()))
    names |= set(getattr(getattr(types_mod, "StandardCallbackDynamicParams", None), "__annotations__", {}))
    names.discard("turn_off_message_logging")
    assert names, "litellm's callback parameter list was not found"
    assert sorted(n for n in names if not is_reserved_extra_param(n)) == []


def test_extra_params_callback_is_a_config_error_and_cost_override_is_accepted(tmp_path):
    """extra_params 的 success_callback 在啟動時就是 ConfigError；input_cost_per_token 可以使用。
    A success_callback in extra_params is a ConfigError at start-up; input_cost_per_token is accepted."""
    cfg = _bundled()
    cfg["models"]["claude"]["extra_params"] = {"success_callback": ["langfuse"], "metadata": {"langfuse_host": "https://x"}}
    with pytest.raises(ConfigError, match="metadata, success_callback"):
        LLMGateway(_write(tmp_path, cfg), execution_mode="mock")
    cfg["models"]["claude"]["extra_params"] = {"input_cost_per_token": 3e-6, "output_cost_per_token": 1.5e-5}
    LLMGateway(_write(tmp_path, cfg), execution_mode="mock")


# --- 2. 先前版本的內建模型字串 ------------------------------------------------------------------------
# --- 2. Previous releases' bundled model strings ----------------------------------------------------------

_CONFIG_PATHS = ("vibeharness/config/agents_config.yaml", "config/agents_config.yaml")


def _git(*args):
    """在 repo 根目錄執行 git；失敗時為 None ／ Runs git in the repo root; None on failure."""
    try:
        result = subprocess.run(["git", "-C", REPO_ROOT, *args], capture_output=True, text=True, encoding="utf-8", timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def test_previous_bundled_models_cover_every_release_tag():
    """每個 v* tag 的內建設定，對目前仍存在的別名而言都是可接受的自動發現設定（模型字串在目前值或 _PREVIOUS_BUNDLED_MODELS
    中）。沒有 .git 或 tag（例如淺層 clone）時略過。
    At every v* tag, the bundled config is an acceptable discovered config for the aliases that still exist (its
    model strings are current values or in _PREVIOUS_BUNDLED_MODELS). Skipped without .git or tags (e.g. a shallow clone)."""
    if shutil.which("git") is None or not os.path.exists(os.path.join(REPO_ROOT, ".git")):
        pytest.skip("no git checkout")
    tags = (_git("tag", "-l", "v*") or "").split()
    if not tags:
        pytest.skip("no release tags in this checkout")
    reference = _bundled()
    checked = 0
    for tag in tags:
        for path in _CONFIG_PATHS:
            text = _git("show", f"{tag}:{path}")
            if text is None:
                continue
            old = yaml.safe_load(text) or {}
            models = {a: i for a, i in (old.get("models") or {}).items() if a in reference["models"]}
            problems = discovered_config_violations({"models": models}, reference)
            assert problems == [], f"{tag}:{path}: {problems}"
            checked += 1
    assert checked >= len(tags)


def test_a_previous_bundled_model_string_is_accepted_but_a_foreign_one_is_not():
    """舊版 --init-config 的覆本（claude-sonnet-5）可以採用；不曾是內建值的字串仍被拒絕。
    A copy from an older --init-config (claude-sonnet-5) is accepted; a string that was never bundled is still refused."""
    reference = _bundled()
    assert "claude-sonnet-5" in _PREVIOUS_BUNDLED_MODELS["claude"]["model"]
    old = dict(reference["models"]["claude"], model="claude-sonnet-5")
    assert discovered_config_violations({"models": {"claude": old}}, reference) == []
    assert discovered_config_violations({"models": {"gemini": dict(reference["models"]["gemini"], model="claude-sonnet-5")}},
                                        reference) == ["models.gemini.model"]


def test_the_refusal_message_explains_version_drift(tmp_path):
    """拒絕訊息提到較舊／較新版本、--config 與 --init-config --force ／ The refusal names an older / newer version,
    --config and --init-config --force."""
    path = _write(tmp_path, {"models": {"claude": {"model": "claude-sonnet-9"}}}, "vibeharness.yaml")
    with pytest.raises(ConfigError) as info:
        check_discovered_config(path)
    message = str(info.value)
    assert "older or newer VibeHarness version" in message and "較舊或較新版本" in message
    assert f"--config {path}" in message and "--init-config" in message and "--force" in message


# --- 3. 匯入 litellm 時不連網 -----------------------------------------------------------------------
# --- 3. Importing litellm makes no network call ------------------------------------------------------------

_NO_NETWORK_SCRIPT = r"""
import json, os, socket, sys
calls = []
def _blocked(*args, **kwargs):
    calls.append(repr(args[:2]))
    raise OSError("network blocked by test")
socket.getaddrinfo = _blocked
socket.socket.connect = lambda self, *a: _blocked(*a)
socket.create_connection = _blocked
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness import cli
gateway = LLMGateway(execution_mode="mock")
gateway.generate("whitebox_reviewer_claude", "system", "user")
sys.argv = ["vibeharness", "-t", sys.argv[1], "-m", "mock", "--estimate", "--config", sys.argv[2]]
try:
    cli.main()
except SystemExit as e:
    code = e.code
else:
    code = 0
print("RESULT " + json.dumps({"calls": calls, "code": code, "env": os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP")}))
"""


def _python_env(**extra):
    """子行程的環境：worktree 在 PYTHONPATH 最前面，不含 LITELLM_LOCAL_MODEL_COST_MAP。
    The child's environment: the worktree first on PYTHONPATH, without LITELLM_LOCAL_MODEL_COST_MAP."""
    env = {k: v for k, v in os.environ.items() if k != "LITELLM_LOCAL_MODEL_COST_MAP"}
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env.update(extra)
    return env


def test_importing_the_gateway_and_a_mock_estimate_make_no_network_call(tmp_path):
    """重現：匯入 litellm 會以 HTTPS 抓取模型價格表（mock 與 --estimate 也一樣）；現在預設改用本機價格表。
    Reproduction: importing litellm fetched its model cost map over HTTPS (in mock and --estimate too); the local
    cost map is now the default."""
    pytest.importorskip("litellm")
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    script = tmp_path / "probe.py"
    script.write_text(_NO_NETWORK_SCRIPT, encoding="utf-8")
    result = subprocess.run([sys.executable, str(script), str(target), DEFAULT_CONFIG_PATH], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=300, env=_python_env(), cwd=str(tmp_path))
    line = next((ln for ln in result.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line is not None, result.stdout + result.stderr
    payload = json.loads(line[len("RESULT "):])
    assert payload["calls"] == [] and payload["code"] == 0 and payload["env"] == "True"


@pytest.mark.parametrize("preset,expected", [(None, "True"), ("False", "False")])
def test_the_user_can_override_the_local_cost_map_setting(tmp_path, preset, expected):
    """setdefault：使用者自己設定的 LITELLM_LOCAL_MODEL_COST_MAP 優先 ／ setdefault: a LITELLM_LOCAL_MODEL_COST_MAP the
    user set wins."""
    script = tmp_path / "probe.py"
    # 以空的替身模組取代 litellm，只看匯入前的環境變數 ／ An empty stand-in replaces litellm; only the env var before import matters
    script.write_text("import os, sys, types\nsys.modules['litellm'] = types.ModuleType('litellm')\n"
                      "import vibeharness.core.llm_gateway\nprint('ENV', os.environ.get('LITELLM_LOCAL_MODEL_COST_MAP'))\n",
                      encoding="utf-8")
    env = _python_env(**({} if preset is None else {"LITELLM_LOCAL_MODEL_COST_MAP": preset}))
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, encoding="utf-8",
                            timeout=120, env=env, cwd=str(tmp_path))
    assert f"ENV {expected}" in result.stdout, result.stdout + result.stderr


# --- 4. 啟動時檢查 model_alias ----------------------------------------------------------------------
# --- 4. model_alias is checked at start-up -------------------------------------------------------------

def test_a_misspelled_model_alias_is_a_config_error(tmp_path):
    """重現：打錯字的 model_alias 過去在啟動時被接受（hybrid 悄悄模擬、live 付費後中途失敗）；現在是 ConfigError。
    Reproduction: a misspelled model_alias used to be accepted at start-up (hybrid simulated silently, live failed
    mid-run after paid calls); it is now a ConfigError."""
    cfg = _bundled()
    cfg["agents"]["whitebox_reviewer_claude"]["model_alias"] = "cluade"
    with pytest.raises(ConfigError, match="whitebox_reviewer_claude.model_alias 'cluade'"):
        LLMGateway(_write(tmp_path, cfg), execution_mode="hybrid")


def test_a_misspelled_model_alias_exits_5(monkeypatch, tmp_path):
    """CLI：打錯字的 model_alias 以 exit 5 結束 ／ CLI: a misspelled model_alias exits 5."""
    cfg = _bundled()
    cfg["agents"]["blackbox_threat_modeler"]["model_alias"] = "gemeni"
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock", "--config", _write(tmp_path, cfg)) == 5


def test_omitted_null_or_unconfigured_model_alias_is_still_allowed(tmp_path):
    """省略、null 或明確的 unconfigured 仍是刻意的未設定代理；內建設定照樣通過。
    Omitted, null or an explicit unconfigured is still a deliberately unconfigured agent; the bundled config passes."""
    LLMGateway(DEFAULT_CONFIG_PATH, execution_mode="mock")
    cfg = _bundled()
    cfg["agents"]["whitebox_reviewer_claude"]["model_alias"] = None
    cfg["agents"]["whitebox_reviewer_glm"].pop("model_alias")
    cfg["agents"]["whitebox_reviewer_gemini"]["model_alias"] = "unconfigured"
    LLMGateway(_write(tmp_path, cfg), execution_mode="mock")


# --- 5. docker_*：null 保留預設值，只在用到時驗證 ---------------------------------------------------------
# --- 5. docker_*: null keeps the default, validated only when used --------------------------------------------


def test_docker_image_null_keeps_the_default(tmp_path, monkeypatch):
    """docker_image: null 以預設映像建立 docker 沙盒 ／ docker_image: null builds the docker sandbox with the default image."""
    from vibeharness.core import harness, sandbox
    seen = {}
    monkeypatch.setattr(sandbox.DockerSandbox, "_verify_available", lambda self: seen.setdefault("image", self.image))
    cfg = load_config_file(DEFAULT_CONFIG_PATH)
    cfg["global"].update(sandbox_provider="docker", docker_image=None)
    settings = load_settings(_write(tmp_path, cfg), origin="explicit")
    box = harness.VibeHarnessCommander._build_sandbox(settings.sandbox)
    assert box.image == harness.DEFAULT_DOCKER_IMAGE == seen["image"]


# --- 6. 模型字串去掉空白後保存 ----------------------------------------------------------------------
# --- 6. Model strings are kept stripped ------------------------------------------------------------------

def test_model_strings_are_stored_stripped(tmp_path):
    """重現：_validate_settings 檢查 model.strip() 卻保存原值，前後空白會送進 litellm 與快取鍵。
    Reproduction: _validate_settings checked model.strip() but kept the raw value, so the whitespace reached litellm
    and the cache key."""
    cfg = _bundled()
    cfg["models"]["claude"]["model"] = "  claude-sonnet-5-5 \n"
    cfg["models"]["claude"]["fallback_model"] = " claude-haiku-4-5-20251001 "
    gateway = LLMGateway(_write(tmp_path, cfg), execution_mode="mock")
    info = gateway.models_config["claude"]
    assert info["model"] == "claude-sonnet-5-5" and info["fallback_model"] == "claude-haiku-4-5-20251001"


# --- 7. 自動發現的設定檔只能調低花費 ----------------------------------------------------------------
# --- 7. A discovered config may only lower spend ------------------------------------------------------------

@pytest.mark.parametrize("glob,key", [
    ({"execution_mode": "live"}, "global.execution_mode"),
    ({"max_concurrent_calls": 7}, "global.max_concurrent_calls"),
    ({"max_output_tokens": 32768}, "global.max_output_tokens"),
    ({"retry_invalid_output": 2}, "global.retry_invalid_output"),
    ({"max_retries": 5}, "global.max_retries"),
    ({"max_files": 500}, "global.max_files"),
    ({"max_file_bytes": 50_000_000}, "global.max_file_bytes"),
])
def test_a_discovered_config_cannot_raise_spend(glob, key):
    """重現：不可信的 checkout 可用 live 模式或更高的上限，花開發者金鑰的錢；現在只能調低。
    Reproduction: an untrusted checkout could use live mode or higher limits to spend on the developer's keys; it may
    now only lower them."""
    assert discovered_config_violations({"global": glob}, _bundled()) == [key]


@pytest.mark.parametrize("glob", [
    {"execution_mode": "mock"}, {"execution_mode": "hybrid"}, {"execution_mode": None},
    {"max_concurrent_calls": 2}, {"max_concurrent_calls": 0}, {"max_concurrent_calls": 6},
    {"max_output_tokens": 4096}, {"max_output_tokens": None}, {"retry_invalid_output": 0}, {"max_retries": 0},
    {"max_files": 5}, {"max_files": 0}, {"max_file_bytes": 1000}, {"max_model_calls": 20}, {"max_model_calls": 0},
    {"max_model_calls": None},
])
def test_a_discovered_config_may_lower_or_keep_spend(glob):
    """調低或維持內建值都允許；內建 max_model_calls 是 null（不限制），任何值都不會更高。
    Lowering or keeping the bundled values is allowed; the bundled max_model_calls is null (unlimited), so no value is higher."""
    assert discovered_config_violations({"global": glob}, _bundled()) == []


def test_a_finite_bundled_call_budget_cannot_be_lifted():
    """預設設定有有限的 max_model_calls 時，0／null／省略（不限制）或更大的值都被拒絕。
    When the default config has a finite max_model_calls, 0 / null / omitted (unlimited) or a larger value is refused."""
    reference = _bundled()
    reference["global"]["max_model_calls"] = 40
    lifted = ["global.max_model_calls"]
    for value, problems in ((0, lifted), (41, lifted), (None, lifted), (40, []), (10, [])):
        assert discovered_config_violations({"global": {"max_model_calls": value}}, reference) == problems
    # 自動發現的設定檔整份取代內建設定：省略也代表不限制 ／ A discovered config replaces the bundled one: omitted means unlimited too
    assert discovered_config_violations({"global": {}}, reference) == lifted


def test_a_discovered_per_model_output_cap_cannot_exceed_the_bundled_cap():
    """models.<alias>.max_output_tokens 不能高於內建的實際上限 ／ models.<alias>.max_output_tokens may not exceed the
    bundled effective cap."""
    reference = _bundled()
    assert discovered_config_violations({"models": {"glm": {"max_output_tokens": 65536}}}, reference) == [
        "models.glm.max_output_tokens"]
    assert discovered_config_violations({"models": {"glm": {"max_output_tokens": 8192}}}, reference) == []


def test_a_discovered_config_cannot_add_reviewers():
    """新增 whitebox_reviewer_* 代理會多一整輪付費呼叫，被拒絕；新增驗證者（依別名去重）與重新指派仍允許。
    A new whitebox_reviewer_* agent adds a whole round of paid calls and is refused; a new verifier (de-duplicated
    per alias) and reassignment are still allowed."""
    reference = _bundled()
    agents = {"whitebox_reviewer_extra": {"model_alias": "claude"}, "whitebox_verifier_extra": {"model_alias": "claude"},
              "whitebox_reviewer_claude": {"model_alias": "gemini"}}
    assert discovered_config_violations({"agents": agents}, reference) == ["agents.whitebox_reviewer_extra"]


def test_a_discovered_live_config_exits_5_but_an_explicit_one_is_trusted(monkeypatch, tmp_path, capsys):
    """CLI：./vibeharness.yaml 設定 live 以 exit 5 拒絕；以 --config 明確指定時採用（使用者信任它）。
    CLI: a ./vibeharness.yaml setting live is refused with exit 5; passed with --config it is used (the user trusts it)."""
    cfg = _bundled()
    cfg["global"]["execution_mode"] = "live"
    _write(tmp_path, cfg, "vibeharness.yaml")
    monkeypatch.chdir(tmp_path)
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "--estimate") == 5
    assert "global.execution_mode" in capsys.readouterr().err
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "--estimate", "--config", str(tmp_path / "vibeharness.yaml")) == 0
