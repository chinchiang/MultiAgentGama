"""第四輪審查的回歸測試：GitHub Action 不再以預設 input 蓋掉設定檔的成本防護、自動發現的設定檔不得改模型、
CLI 不接受縮寫旗標、null 一律保留預設值、啟動時檢查模型定義，以及預設設定檔與突變測試的細節。
Regression tests from the fourth review round: the GitHub Action no longer overrides the config's cost guard with
default inputs, a discovered config must not change the models, the CLI refuses abbreviated flags, null always keeps
the default, model definitions are checked at start-up, and details of the bundled config and mutation testing."""
import os
import shutil
import sys

import pytest
import subprocess
import yaml

from vibeharness import cli
from vibeharness.core import mutation
from vibeharness.core.harness import DEFAULT_MUTATION_MAX_MUTANTS, DEFAULT_MUTATION_MIN_SCORE, VibeHarnessCommander
from vibeharness.core.llm_gateway import (
    DEFAULT_CONFIG_PATH, DEFAULT_TEMPERATURE, ConfigError, LLMGateway, discovered_config_violations, load_config_file,
)
from vibeharness.core.sandbox import LocalSubprocessSandbox

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(_BASH is None or sys.platform == "win32", reason="bash unavailable")


def _action():
    with open(os.path.join(REPO_ROOT, "action.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _step(step_id):
    return next(s for s in _action()["runs"]["steps"] if s.get("id") == step_id)


def _prep_env(tmp_path, **overrides):
    """prep step 的環境：全部 input 都是預設值，再套用 overrides ／ The prep step's environment: every input at its
    default, then `overrides`."""
    env = {**os.environ, "VH_FAIL_ON": "needs-fixes", "VH_MUTATION": "", "VH_SANDBOX": "local_subprocess",
           "VH_FORMAT": "md", "VH_MODE": "", "VH_MAX_CALLS": "", "VH_MAX_FILES": "", "VH_OUTPUT": "",
           "GITHUB_OUTPUT": str(tmp_path / "github_output")}
    env.update(overrides)
    return env


def _run_prep(tmp_path, **overrides):
    return subprocess.run([_BASH, "-e", "-c", _step("prep")["run"]], cwd=tmp_path, capture_output=True, text=True,
                          encoding="utf-8", env=_prep_env(tmp_path, **overrides))


def _audit_args(tmp_path, **env):
    """執行 audit step 組出 CLI 參數的那幾行，回傳參數清單 ／ Runs the audit step's lines that build the CLI arguments
    and returns the argument list."""
    lines = _step("audit")["run"].splitlines()
    begin = next(i for i, line in enumerate(lines) if line.strip().startswith("args=(--target"))
    end = next(i for i in range(begin, len(lines)) if "VH_MAX_FILES" in lines[i])
    block = "\n".join(line.strip() for line in lines[begin:end + 1])
    base = {"VH_TARGET": ".", "VH_OUTPUT": "r.md", "VH_FORMAT": "md", "VH_MODE": "", "VH_MAX_CALLS": "", "VH_MAX_FILES": ""}
    out = subprocess.run([_BASH, "-c", block + '\nprintf "%s\\n" "${args[@]}"'], cwd=tmp_path, capture_output=True,
                         text=True, encoding="utf-8", env={**os.environ, **base, **env})
    assert out.returncode == 0, out.stderr
    return out.stdout.splitlines()


# --- 1. Action：留空的 input 不傳旗標，設定檔決定 ---------------------------------------------------
# --- 1. Action: an empty input passes no flag, the config decides ----------------------------------

def test_action_mode_budget_files_and_output_inputs_default_to_empty():
    """mode、max-model-calls、max-files 與 output 預設為空，不再有會蓋掉設定檔的預設值。
    mode, max-model-calls, max-files and output default to empty: no default that overrides the config any more."""
    inputs = _action()["inputs"]
    for name in ("mode", "max-model-calls", "max-files", "output"):
        assert inputs[name]["default"] == "", name


@needs_bash
def test_action_passes_no_mode_budget_or_file_flag_when_the_inputs_are_empty(tmp_path):
    """重現：過去 --max-model-calls 0 一律傳入，悄悄關掉 --config 的 max_model_calls 成本防護。
    Reproduction: --max-model-calls 0 used to be passed always, silently disabling a --config's max_model_calls cost guard."""
    args = _audit_args(tmp_path)
    assert args == ["--target", ".", "--output", "r.md", "--format", "md"]
    assert not {"--mode", "--max-model-calls", "--max-files"} & set(args)


@needs_bash
def test_action_passes_each_flag_only_when_set(tmp_path):
    """有填的 input 才轉成旗標 ／ Only a set input becomes a flag."""
    args = _audit_args(tmp_path, VH_MODE="live", VH_MAX_CALLS="80", VH_MAX_FILES="7")
    assert args[6:] == ["--mode", "live", "--max-model-calls", "80", "--max-files", "7"]
    assert _audit_args(tmp_path, VH_MAX_CALLS="0")[6:] == ["--max-model-calls", "0"]


def test_without_the_flags_the_config_cost_guard_and_limits_apply(monkeypatch, tmp_path):
    """沒有旗標時 CLI 採用 --config 的 max_model_calls、max_files 與 execution_mode。
    Without the flags the CLI uses the --config's max_model_calls, max_files and execution_mode."""
    config = load_config_file(DEFAULT_CONFIG_PATH)
    config["global"].update(max_model_calls=3, max_files=4, execution_mode="mock")
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    seen = {}

    def run(self, **kwargs):
        seen.update(calls=self.gateway.max_model_calls, files=self.max_files, mode=self.gateway.execution_mode)
        return type("S", (), {"overall_status": "INCONCLUSIVE", "agent_calls": [], "inconclusive_reasons": []})()

    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    monkeypatch.setattr(sys, "argv", ["vibeharness", "--target", str(tmp_path), "--output", str(tmp_path / "r.md"),
                                      "--config", str(path)])
    with pytest.raises(SystemExit):
        cli.main()
    assert seen == {"calls": 3, "files": 4, "mode": "mock"}


@needs_bash
@pytest.mark.parametrize("fmt,given,expected", [
    ("md", "", "vibeharness-report.md"), ("json", "", "vibeharness-report.json"), ("json", "out/r.md", "out/r.md"),
])
def test_action_derives_the_report_name_from_the_format(tmp_path, fmt, given, expected):
    """output 留空時依 format 推導報告名稱；有填就原樣使用（向後相容）。
    An empty output derives the report name from format; a set one is used as is (backward compatible)."""
    out = _run_prep(tmp_path, VH_FORMAT=fmt, VH_OUTPUT=given)
    assert out.returncode == 0, out.stdout
    assert (tmp_path / "github_output").read_text(encoding="utf-8") == f"output={expected}\n"


def test_action_report_output_and_artifact_use_the_derived_name():
    """上傳的 artifact 與稽核都用 prep step 推導出的名稱；outputs.report 由 runner 在報告確實寫出時設定（第五輪）。
    The uploaded artifact and the audit both use the name the prep step derived; outputs.report is set by the runner
    when the report was actually written (fifth round)."""
    action = _action()
    assert action["outputs"]["report"]["value"] == "${{ steps.audit.outputs.report }}"
    upload = next(s for s in action["runs"]["steps"] if "upload-artifact" in str(s.get("uses", "")))
    assert "${{ steps.prep.outputs.output }}.partial.json" in upload["with"]["path"]
    assert _step("audit")["env"]["VH_OUTPUT"] == "${{ steps.prep.outputs.output }}"


def test_action_validates_before_installing_or_building_docker_images():
    """驗證 step 排在安裝與 Docker 映像建置之前 ／ The validation step runs before the install and the Docker image build."""
    names = [s.get("id") or s.get("name") or s.get("uses") for s in _action()["runs"]["steps"]]
    assert names[0] == "prep"
    docker = next(i for i, n in enumerate(names) if "Docker" in str(n))
    install = next(i for i, n in enumerate(names) if str(n).startswith("Install"))
    assert 0 < install < docker < names.index("audit")


@needs_bash
@pytest.mark.parametrize("env,needle", [
    ({"VH_MODE": "lve"}, "unknown mode"), ({"VH_FORMAT": "xml"}, "unknown format"),
    ({"VH_MAX_FILES": "0"}, "max-files"), ({"VH_MAX_FILES": "x"}, "max-files"),
    ({"VH_MAX_CALLS": "-1"}, "max-model-calls"), ({"VH_SANDBOX": "e2b"}, "unknown sandbox"),
])
def test_action_prep_refuses_bad_inputs_with_exit_5(tmp_path, env, needle):
    """錯誤的 input 在 prep step 以 exit 5 失敗 ／ A bad input fails the prep step with exit 5."""
    out = _run_prep(tmp_path, **env)
    assert out.returncode == 5 and needle in out.stdout


def test_action_exit_code_output_mentions_interrupted():
    """exit-code output 的說明列出 130（中斷）／ The exit-code output's description lists 130 (interrupted)."""
    assert "130" in _action()["outputs"]["exit-code"]["description"]


# --- 2. 自動發現的設定檔不得改模型 -------------------------------------------------------------------
# --- 2. A discovered config must not change the models -----------------------------------------------

@pytest.mark.parametrize("models,key", [
    ({"claude": {"model": "openai/gpt-x"}}, "models.claude.model"),
    ({"claude": {"fallback_model": "openai/gpt-x"}}, "models.claude.fallback_model"),
    ({"evil": {"model": "openai/gpt-x", "api_key_env": "ANTHROPIC_API_KEY"}}, "models.evil"),
    ({"claude": {"api_key_env": "GEMINI_API_KEY"}}, "models.claude.api_key_env"),
])
def test_a_discovered_config_cannot_rewire_models_or_keys(models, key):
    """重現：自動發現的設定檔可把 ANTHROPIC_API_KEY 接到 openai/...；現在模型字串、新別名與別的別名的金鑰變數都被拒絕。
    Reproduction: a discovered config could wire ANTHROPIC_API_KEY to openai/...; the model strings, new aliases and
    another alias's key variable are now refused."""
    reference = load_config_file(DEFAULT_CONFIG_PATH)
    assert key in discovered_config_violations({"models": models}, reference)


def test_a_discovered_config_may_reassign_agents_among_bundled_aliases():
    """agent 在內建別名之間重新指派、或沿用內建值，都仍然允許 ／ Reassigning agents among the bundled aliases, or keeping
    the bundled values, is still allowed."""
    reference = load_config_file(DEFAULT_CONFIG_PATH)
    config = {"models": {"gemini": dict(reference["models"]["gemini"])},
              "agents": {name: {"model_alias": "gemini"} for name in reference["agents"]}}
    assert discovered_config_violations(config, reference) == []


# --- 3. CLI：不接受縮寫、說明文字 ----------------------------------------------------------------------
# --- 3. CLI: no abbreviations, help texts --------------------------------------------------------------

@pytest.mark.parametrize("argv", [["--conf", "x.yaml"], ["--max-f", "3"]])
def test_abbreviated_long_flags_are_usage_errors(monkeypatch, argv):
    """`--conf x` 不能被當成 --config（否則會繞過 action 的 --config 偵測）／ `--conf x` is not taken as --config
    (it would slip past the action's --config detection)."""
    monkeypatch.setattr(sys, "argv", ["vibeharness", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.USAGE_ERROR_EXIT_CODE


def test_output_and_max_files_help_texts():
    """--output 說明依 --format 寫 Markdown 或 JSON（含估算），--max-files 標出 ≥ 1。
    --output help says Markdown or JSON per --format (the estimate too), --max-files says ≥ 1."""
    actions = {a.dest: a for a in cli._build_parser()._actions}
    assert "JSON" in actions["output"].help and "--estimate" in actions["output"].help
    assert "≥ 1" in actions["max_files"].help


# --- 4. null 保留預設值 ---------------------------------------------------------------------------------
# --- 4. null keeps the default --------------------------------------------------------------------------

def test_null_mutation_settings_keep_the_defaults():
    """mutation_* 的 null（以及 timeout／copy 的 0）保留預設值 ／ null mutation_* (and 0 for timeout / copy) keep the defaults."""
    cfg = VibeHarnessCommander._mutation_settings({"mutation_max_mutants": None, "mutation_min_score": None,
                                                   "mutation_timeout_seconds": 0, "mutation_max_copy_mb": None,
                                                   "per_test_timeout_seconds": 45})
    assert cfg["max_mutants"] == DEFAULT_MUTATION_MAX_MUTANTS and cfg["min_score"] == DEFAULT_MUTATION_MIN_SCORE
    assert cfg["timeout"] == 45 and cfg["max_copy_mb"] == mutation.DEFAULT_MAX_COPY_MB


@pytest.mark.parametrize("key", ["mutation_timeout_seconds", "mutation_max_copy_mb"])
def test_negative_mutation_limits_are_config_errors(key):
    """負數是 ConfigError ／ A negative value is a ConfigError."""
    with pytest.raises(ConfigError, match=f"global.{key}"):
        VibeHarnessCommander._mutation_settings({key: -1})


def test_a_bad_mutation_min_score_names_the_global_key():
    """錯誤訊息寫出完整的鍵名 global.mutation_min_score ／ The error names the full key global.mutation_min_score."""
    with pytest.raises(ConfigError, match=r"global\.mutation_min_score"):
        VibeHarnessCommander._mutation_settings({"mutation_min_score": 101})


def _config_file(tmp_path, global_cfg=None, models=None, agents=None):
    config = load_config_file(DEFAULT_CONFIG_PATH)
    config["global"].update(global_cfg or {})
    if models is not None:
        config["models"] = models
    if agents is not None:
        config["agents"] = agents
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def test_null_sandbox_providers_mean_local_subprocess(tmp_path):
    """重現：sandbox_provider: null 曾以 "sandbox_provider 'None' 尚未實作" 失敗；現在與省略相同。
    Reproduction: sandbox_provider: null used to fail with "sandbox_provider 'None' is not implemented"; it now
    means the same as omitted."""
    commander = VibeHarnessCommander(_config_file(tmp_path, {"sandbox_provider": None, "sandbox_node_provider": None}),
                                     execution_mode="mock")
    assert commander.sandbox_provider == "local_subprocess" == commander.sandbox_node_provider
    assert type(commander.sandbox) is LocalSubprocessSandbox


def test_null_temperature_uses_the_default_and_never_sends_none(tmp_path, fake_live):
    """temperature: null 送出預設的 0.2，不是 None ／ temperature: null sends the default 0.2, not None."""
    fake = fake_live(lambda system, user: '{"ok": true}')
    models = {"deepseek": {"model": "deepseek/deepseek-v4-pro", "api_key_env": "DEEPSEEK_API_KEY"}}
    gateway = LLMGateway(_config_file(tmp_path, {"execution_mode": "live"}, models=models,
                                      agents={"a": {"model_alias": "deepseek", "temperature": None}}))
    gateway.generate("a", "s", "u", required_keys=["ok"])
    assert fake.calls[0]["temperature"] == DEFAULT_TEMPERATURE == 0.2


# --- 5. 啟動時檢查模型定義 ---------------------------------------------------------------------------------
# --- 5. Model definitions are checked at start-up ----------------------------------------------------------

@pytest.mark.parametrize("entry,needle", [
    ({"api_key_env": "X"}, "models.m.model"), ({"model": "  "}, "models.m.model"),
    ({"model": "openai/x", "fallback_model": ""}, "models.m.fallback_model"),
    ({"model": "openai/x", "base_url": "https://gw.example"}, "api_base"),
])
def test_bad_model_entries_are_config_errors(tmp_path, entry, needle):
    """沒有模型字串的項目與不會被讀取的 base_url 在啟動時就是 ConfigError ／ An entry without a model string and the
    never-read base_url are a ConfigError at start-up."""
    with pytest.raises(ConfigError, match=needle):
        LLMGateway(_config_file(tmp_path, models={"m": entry}, agents={}))


def test_a_model_entry_without_a_model_exits_5_from_the_cli(monkeypatch, tmp_path):
    """CLI 把它對應到 exit 5 ／ The CLI maps it to exit 5."""
    path = _config_file(tmp_path, models={"claude": {"api_key_env": "ANTHROPIC_API_KEY"}})
    monkeypatch.setattr(sys, "argv", ["vibeharness", "--target", str(tmp_path), "--output", str(tmp_path / "r.md"),
                                      "--config", path, "-m", "mock"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.USAGE_ERROR_EXIT_CODE


def test_the_bundled_config_passes_the_start_up_checks():
    """內建設定檔通過所有啟動檢查 ／ The bundled config passes every start-up check."""
    LLMGateway(DEFAULT_CONFIG_PATH, execution_mode="mock")


# --- 6／8. 預設設定檔與突變測試 ------------------------------------------------------------------------
# --- 6 / 8. The bundled config and mutation testing ------------------------------------------------------

def test_bundled_mutation_timeout_follows_per_test_timeout(tmp_path):
    """內建設定檔不再寫死 mutation_timeout_seconds，所以它跟隨 per_test_timeout_seconds（如文件所述）。
    The bundled config no longer hard-codes mutation_timeout_seconds, so it follows per_test_timeout_seconds (as documented)."""
    assert load_config_file(DEFAULT_CONFIG_PATH)["global"].get("mutation_timeout_seconds") is None
    commander = VibeHarnessCommander(_config_file(tmp_path, {"per_test_timeout_seconds": 45}), execution_mode="mock")
    assert commander._mutation_cfg["timeout"] == 45


def test_mutation_uses_only_the_test_types_that_are_produced():
    """whitebox_property 從未產生，不再列為可用的測試類型 ／ whitebox_property is never produced and is no longer listed."""
    assert mutation.ELIGIBLE_TEST_TYPES == ("whitebox_unit",)
