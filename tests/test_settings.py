"""設定（core/settings.py）：只透過 load_settings 測試——每個鍵的 null／0／負數／錯誤型別規則、驗證順序、探索到的設定檔政策、
CLI 覆寫值與其來源、相對路徑警告，以及載入後唯讀的 models／agents。
Settings (core/settings.py): tested only through load_settings — every key's null / 0 / negative / wrong-type rule,
the validation order, the Discovered config policy, the CLI overrides and their sources, the relative-path warnings,
and the models / agents that are read-only once loaded."""
import copy
import json
import os
import pickle
import subprocess
import sys

import pytest
import yaml

from vibeharness.core.settings import (
    DEFAULT_CONFIG_PATH, ConfigError, FrozenDict, FrozenList, Overrides, Settings, load_settings,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(DEFAULT_CONFIG_PATH, encoding="utf-8") as _f:
    BUNDLED = yaml.safe_load(_f)


def _write(tmp_path, cfg, name="agents.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return str(path)


def _config(global_=None, models=None, agents=None):
    """內建設定檔的副本，套上變更；值為 ... 表示刪除該鍵 ／ A copy of the Bundled config with changes; a value of ... deletes the key."""
    cfg = copy.deepcopy(BUNDLED)
    for section, changes in (("global", global_), ("models", models), ("agents", agents)):
        for key, value in (changes or {}).items():
            if isinstance(value, dict) and isinstance(cfg[section].get(key), dict):
                for sub, v in value.items():
                    if v is ...:
                        cfg[section][key].pop(sub, None)
                    else:
                        cfg[section][key][sub] = v
            elif value is ...:
                cfg[section].pop(key, None)
            else:
                cfg[section][key] = value
    return cfg


def _load(tmp_path, origin="explicit", overrides=None, **sections):
    return load_settings(_write(tmp_path, _config(**sections)), origin=origin, overrides=overrides)


def test_null_docker_keys_keep_their_defaults(tmp_path):
    """重現：null 的 docker_network／docker_memory／docker_cpus／docker_bin 過去是錯誤；現在保留預設值。
    Reproduction: a null docker_network / docker_memory / docker_cpus / docker_bin used to be an error; it now keeps the default."""
    nulls = {key: None for key in ("docker_network", "docker_memory", "docker_cpus", "docker_bin", "docker_pids_limit",
                                   "docker_image", "docker_node_image")}
    s = _load(tmp_path, global_={"sandbox_provider": "docker", **nulls})
    d = s.sandbox.docker
    assert (d.network, d.memory, d.cpus, d.bin, d.pids_limit, d.image) == ("none", "1g", "2", "docker", 256, "vibeharness-sandbox:latest")
    assert s.node.image == "vibeharness-sandbox-node:latest"


def test_null_mutation_settings_keep_the_defaults(tmp_path):
    """mutation_* 的 null（以及 timeout／copy 的 0）保留預設值 ／ null mutation_* (and 0 for timeout / copy) keep the defaults."""
    m = _load(tmp_path, global_={"mutation_max_mutants": None, "mutation_min_score": None, "mutation_timeout_seconds": 0,
                                 "mutation_max_copy_mb": None, "per_test_timeout_seconds": 45}).mutation
    assert (m.max_mutants, m.min_score, m.timeout, m.max_copy_mb) == (20, 70.0, 45, 200)


def test_the_python_and_node_sandboxes_share_one_validated_timeout(tmp_path):
    """兩個沙盒共用同一組驗證過的設定，不會各自解讀（例如逾時 0 一邊是 0、一邊是 120）。
    Both sandboxes share one validated set of settings, so a value is never interpreted differently (e.g. a timeout
    of 0 becoming 0 on one side and 120 on the other)."""
    s = _load(tmp_path, global_={"sandbox_timeout_seconds": 0, "sandbox_node_provider": "docker"})
    assert s.sandbox.timeout == 120 and s.node.image == "vibeharness-sandbox-node:latest"


def test_bundled_config_resolves_to_the_documented_defaults():
    s = load_settings(DEFAULT_CONFIG_PATH, origin="bundled")
    assert isinstance(s, Settings) and s.origin == "bundled" and s.warnings == ()
    g = s.gateway
    assert (g.execution_mode, g.max_model_calls, g.max_concurrent_calls, g.retry_invalid_output) == ("hybrid", None, 6, 1)
    assert (g.timeout_seconds, g.max_retries, g.max_output_tokens, g.cache_dir, g.cache_only) == (180, 2, 16384, None, False)
    assert set(g.models) == {"claude", "deepseek", "gemini", "glm"} and "whitebox_reviewer_claude" in g.agents
    sb = s.sandbox
    assert (sb.provider, sb.timeout, sb.per_test_timeout, sb.memory_mb) == ("local_subprocess", 120, 30, 2048)
    assert (sb.docker.pids_limit, sb.docker.network, sb.docker.memory, sb.docker.cpus, sb.docker.bin) == (256, "none", "1g", "2", "docker")
    assert (s.node.provider, s.node.node_bin, s.node.image) == ("local_subprocess", "node", "vibeharness-sandbox-node:latest")
    m = s.mutation
    assert (m.enabled, m.max_mutants, m.timeout, m.min_score, m.max_copy_mb) == (False, 20, 30, 70.0, 200)
    assert (s.scope.max_files, s.scope.max_file_bytes, s.scope.include, s.scope.exclude) == (50, 1_000_000, (), ())
    assert s.sources == {"mutation_testing": "config"}


# --- 每個鍵的規則（docs/configuration.md）／ every key's rule (docs/configuration.md) -----------------

def _get(s, attr):
    obj = s
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj


DOCKER = {"sandbox_provider": "docker"}
NODE_DOCKER = {"sandbox_node_provider": "docker"}
RULES = [
    # (global 變更, Settings 屬性, 期望值；或 ConfigError 訊息片段) ／ (global changes, Settings attribute, expected value; or a ConfigError message fragment)
    ({"execution_mode": None}, "gateway.execution_mode", "hybrid"),
    ({"execution_mode": "mock"}, "gateway.execution_mode", "mock"),
    ({"execution_mode": "fast"}, None, "Unknown execution_mode 'fast' (expected live, hybrid or mock)"),
    ({"max_model_calls": None}, "gateway.max_model_calls", None),
    ({"max_model_calls": 0}, "gateway.max_model_calls", None),
    ({"max_model_calls": 7}, "gateway.max_model_calls", 7),
    ({"max_model_calls": -1}, None, "global.max_model_calls must be a non-negative integer, got -1"),
    ({"max_model_calls": True}, None, "global.max_model_calls must be a non-negative integer, got True"),
    ({"max_concurrent_calls": ...}, "gateway.max_concurrent_calls", 6),
    ({"max_concurrent_calls": None}, "gateway.max_concurrent_calls", 6),
    ({"max_concurrent_calls": 0}, "gateway.max_concurrent_calls", 6),
    ({"max_concurrent_calls": 2.5}, None, "global.max_concurrent_calls must be a non-negative integer, got 2.5"),
    ({"retry_invalid_output": None}, "gateway.retry_invalid_output", 1),
    ({"retry_invalid_output": 0}, "gateway.retry_invalid_output", 0),
    ({"retry_invalid_output": 6}, None, "global.retry_invalid_output must be an integer between 0 and 5, got 6"),
    ({"timeout_seconds": None}, "gateway.timeout_seconds", 180),
    ({"timeout_seconds": 2.5}, "gateway.timeout_seconds", 2.5),
    ({"timeout_seconds": 0}, None, "global.timeout_seconds must be a number >= 1, got 0"),
    ({"max_retries": None}, "gateway.max_retries", 2),
    ({"max_retries": 0}, "gateway.max_retries", 0),
    ({"max_retries": 1.5}, None, "global.max_retries must be an integer >= 0, got 1.5"),
    ({"max_output_tokens": None}, "gateway.max_output_tokens", 16384),
    ({"max_output_tokens": 0}, None, "global.max_output_tokens must be an integer >= 1, got 0"),
    ({"sandbox_timeout_seconds": None}, "sandbox.timeout", 120),
    ({"sandbox_timeout_seconds": 0}, "sandbox.timeout", 120),
    ({"sandbox_timeout_seconds": -1}, None, "global.sandbox_timeout_seconds must be a non-negative integer, got -1"),
    ({"per_test_timeout_seconds": None}, "sandbox.per_test_timeout", 30),
    ({"per_test_timeout_seconds": 0}, "sandbox.per_test_timeout", 30),
    ({"per_test_timeout_seconds": "x"}, None, "global.per_test_timeout_seconds must be a non-negative integer, got 'x'"),
    # null 保留預設值，只有明確的 0 停用上限 ／ null keeps the default, only an explicit 0 disables the cap
    ({"sandbox_memory_mb": None}, "sandbox.memory_mb", 2048),
    ({"sandbox_memory_mb": 0}, "sandbox.memory_mb", 0),
    ({"sandbox_memory_mb": ...}, "sandbox.memory_mb", 2048),
    ({"sandbox_memory_mb": 512}, "sandbox.memory_mb", 512),
    ({"sandbox_memory_mb": -5}, None, "global.sandbox_memory_mb must be a non-negative integer, got -5"),
    ({"sandbox_provider": None}, "sandbox.provider", "local_subprocess"),
    ({"sandbox_provider": "k8s"}, None, "sandbox_provider 'k8s' is not implemented; supported: 'local_subprocess', 'docker'"),
    ({**DOCKER}, "node.provider", "docker"),  # null 的 sandbox_node_provider 跟隨 sandbox_provider ／ a null node provider follows
    ({"sandbox_node_provider": "k8s"}, None, "sandbox_node_provider 'k8s' is not implemented"),
    # docker_* 只在任一沙盒用 docker 時才驗證 ／ docker_* is validated only when either sandbox uses docker
    ({"docker_pids_limit": -2}, "sandbox.docker.pids_limit", 256),
    ({**DOCKER, "docker_pids_limit": None}, "sandbox.docker.pids_limit", 256),
    ({**DOCKER, "docker_pids_limit": 0}, "sandbox.docker.pids_limit", 256),
    ({**DOCKER, "docker_pids_limit": -1}, "sandbox.docker.pids_limit", -1),
    ({**DOCKER, "docker_pids_limit": 64}, "sandbox.docker.pids_limit", 64),
    ({**DOCKER, "docker_pids_limit": "lots"}, None, "global.docker_pids_limit must be an integer (-1 = unlimited), got 'lots'"),
    ({**DOCKER, "docker_pids_limit": True}, None, "global.docker_pids_limit must be an integer (-1 = unlimited), got True"),
    ({**NODE_DOCKER, "docker_pids_limit": -2}, None, "global.docker_pids_limit must be an integer (-1 = unlimited), got -2"),
    ({**DOCKER, "docker_network": " host "}, "sandbox.docker.network", "host"),
    ({**DOCKER, "docker_network": ""}, None, "global.docker_network must be a non-empty string"),
    ({**DOCKER, "docker_memory": "512m"}, "sandbox.docker.memory", "512m"),
    ({**DOCKER, "docker_memory": "lots"}, None, "global.docker_memory must be a Docker memory string"),
    *[({**DOCKER, "docker_memory": m}, "sandbox.docker.memory", m) for m in ("512mb", "1GiB", "2g", "1073741824")],
    ({**DOCKER, "docker_memory": " 512m "}, "sandbox.docker.memory", "512m"),
    ({**DOCKER, "docker_cpus": " 1.5 "}, "sandbox.docker.cpus", "1.5"),
    # 純本機設定檔裡殘留的 docker 鍵不擋啟動 ／ stale docker keys in a local-only config never block start-up
    ({"docker_memory": 1, "docker_network": None, "docker_cpus": "two"}, "sandbox.docker.memory", "1g"),
    ({**DOCKER, "docker_image": 123}, None, "docker_image must be a non-empty string"),
    ({**DOCKER, "docker_cpus": 1.5}, "sandbox.docker.cpus", "1.5"),
    ({**DOCKER, "docker_cpus": 0}, None, "global.docker_cpus must be a positive number, got 0"),
    ({**DOCKER, "docker_bin": " "}, None, "global.docker_bin must be a non-empty string"),
    ({**DOCKER, "docker_image": " img:1 "}, "sandbox.docker.image", "img:1"),
    ({**DOCKER, "docker_image": ""}, None, "docker_image must be a non-empty string"),
    ({"docker_image": ""}, "sandbox.docker.image", "vibeharness-sandbox:latest"),
    ({**NODE_DOCKER, "docker_node_image": ""}, None, "docker_node_image must be a non-empty string"),
    # 只有 Node 沙盒用 docker 時才驗證 ／ validated only when the Node sandbox uses docker
    ({"docker_node_image": ""}, "node.image", ""),
    ({**NODE_DOCKER, "docker_node_image": None}, "node.image", "vibeharness-sandbox-node:latest"),
    ({"node_bin": None}, "node.node_bin", "node"),
    ({"node_bin": "/opt/node/bin/node"}, "node.node_bin", "/opt/node/bin/node"),
    ({"mutation_testing": None}, "mutation.enabled", False),
    ({"mutation_testing": True}, "mutation.enabled", True),
    ({"mutation_testing": "yes"}, None, "global.mutation_testing must be true or false, got 'yes'"),
    ({"mutation_max_mutants": None}, "mutation.max_mutants", 20),
    ({"mutation_max_mutants": 0}, None, "global.mutation_max_mutants must be an integer >= 1, got 0"),
    ({"mutation_timeout_seconds": None, "per_test_timeout_seconds": 12}, "mutation.timeout", 12),
    ({"mutation_timeout_seconds": 0}, "mutation.timeout", 30),
    ({"mutation_min_score": None}, "mutation.min_score", 70.0),
    ({"mutation_min_score": 101}, None, "global.mutation_min_score must be a number between 0 and 100, got 101"),
    ({"mutation_max_copy_mb": 0}, "mutation.max_copy_mb", 200),
    ({"mutation_max_copy_mb": -1}, None, "global.mutation_max_copy_mb must be a non-negative integer, got -1"),
    ({"mutation_timeout_seconds": -1}, None, "global.mutation_timeout_seconds must be a non-negative integer, got -1"),
    ({"max_files": 0}, "scope.max_files", 50),
    ({"max_files": None}, "scope.max_files", 50),
    ({"max_files": -3}, None, "global.max_files must be a non-negative integer, got -3"),
    ({"max_file_bytes": None}, "scope.max_file_bytes", 1_000_000),
    ({"include": "src/*"}, "scope.include", ("src/*",)),
    ({"include": [" a/* ", "b"]}, "scope.include", ("a/*", "b")),
    ({"exclude": None}, "scope.exclude", ()),
    ({"exclude": [""]}, None, "global.exclude must be a list of glob patterns, got ['']"),
]


@pytest.mark.parametrize("changes, attr, expected", RULES, ids=[repr(c) for c, _, _ in RULES])
def test_each_global_key_follows_its_documented_rule(tmp_path, changes, attr, expected):
    if attr is None:
        with pytest.raises(ConfigError) as info:
            _load(tmp_path, global_=changes)
        assert expected in str(info.value)
    else:
        assert _get(_load(tmp_path, global_=changes), attr) == expected


MODEL_RULES = [
    ({"claude": {"model": ""}}, None, "models.claude.model must be a non-empty litellm model string, got ''"),
    ({"claude": {"model": ...}}, None, "models.claude.model must be a non-empty litellm model string, got None"),
    ({"claude": {"model": "  claude-x  ", "fallback_model": " f "}}, "claude", {"model": "claude-x", "fallback_model": "f"}),
    ({"claude": {"fallback_model": ""}}, None, "models.claude.fallback_model must be a non-empty string or null, got ''"),
    ({"claude": {"base_url": "https://x"}}, None, "models.claude.base_url is not read; use models.claude.api_base"),
    ({"claude": {"api_base": "http://evil.example"}}, None, "models.claude.api_base must be an https:// URL"),
    ({"claude": {"api_base": "http://localhost:4000"}}, "claude", {"api_base": "http://localhost:4000"}),
    ({"claude": {"max_output_tokens": 0}}, None, "models.claude.max_output_tokens must be an integer >= 1, got 0"),
    ({"claude": {"price_per_million_input": -1}}, None, "models.claude.price_per_million_input must be a number >= 0"),
    ({"claude": {"extra_params": ["a"]}}, None, "models.claude.extra_params must be a mapping of litellm parameter names"),
    ({"claude": {"extra_params": {"max_tokens": 1}}}, None, "models.claude.extra_params must not set the output-token cap: max_tokens"),
    ({"claude": {"extra_params": {"api_key": "k"}}}, None, "must not set reserved litellm parameter(s): api_key"),
]


@pytest.mark.parametrize("models, alias, expected", MODEL_RULES, ids=[repr(m) for m, _, _ in MODEL_RULES])
def test_models_rules(tmp_path, models, alias, expected):
    if alias is None:
        with pytest.raises(ConfigError) as info:
            _load(tmp_path, models=models)
        assert expected in str(info.value)
    else:
        info = _load(tmp_path, models=models).gateway.models[alias]
        assert {k: info[k] for k in expected} == expected


def test_agent_aliases_and_temperatures_are_checked(tmp_path):
    with pytest.raises(ConfigError, match=r"model_alias 'typo' is not defined in the models section \(defined: claude, deepseek, gemini, glm\)"):
        _load(tmp_path, agents={"whitebox_reviewer_claude": {"model_alias": "typo"}})
    with pytest.raises(ConfigError, match="agents.whitebox_reviewer_claude.temperature must be a number between 0 and 2, got 3"):
        _load(tmp_path, agents={"whitebox_reviewer_claude": {"temperature": 3}})
    for alias in (None, "unconfigured"):
        assert _load(tmp_path, agents={"whitebox_reviewer_claude": {"model_alias": alias}})


def test_cache_dir_is_created_and_must_be_writable(tmp_path):
    cache = tmp_path / "nested" / "cache"
    assert _load(tmp_path, global_={"cache_dir": str(cache)}).gateway.cache_dir == str(cache) and cache.is_dir()
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(ConfigError, match="cannot be created"):
        _load(tmp_path, global_={"cache_dir": str(blocker / "cache")})


def test_file_structure_errors(tmp_path):
    with pytest.raises(ConfigError, match="Agent config not found"):
        load_settings(str(tmp_path / "missing.yaml"), origin="explicit")
    (tmp_path / "list.yaml").write_text("- a\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="must be a YAML mapping at the top level, got list"):
        load_settings(str(tmp_path / "list.yaml"), origin="explicit")
    (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
    assert load_settings(str(tmp_path / "empty.yaml"), origin="explicit").gateway.models == {}


def test_config_errors_are_value_errors():
    assert issubclass(ConfigError, ValueError)


# --- 驗證順序 ／ validation order ---------------------------------------------------------------

@pytest.mark.parametrize("changes, first", [
    ({"max_model_calls": -1, "sandbox_timeout_seconds": -1}, "global.max_model_calls"),
    ({"sandbox_timeout_seconds": -1, "mutation_max_mutants": 0}, "global.sandbox_timeout_seconds"),
    ({"mutation_max_mutants": 0, "max_files": -1}, "global.mutation_max_mutants"),
    ({"max_files": -1, "include": [""]}, "global.max_files"),
    ({"timeout_seconds": 0, "retry_invalid_output": 9}, "global.timeout_seconds"),
])
def test_the_first_error_follows_the_former_start_up_order(tmp_path, changes, first):
    """閘道的鍵先於沙盒、沙盒先於突變測試、突變測試先於檔案上限：多個錯誤時最先回報的不變。
    The gateway's keys before the sandbox, the sandbox before mutation testing, mutation testing before the file limits:
    with several errors the first one reported is unchanged."""
    with pytest.raises(ConfigError) as info:
        _load(tmp_path, global_=changes)
    assert first in str(info.value)


def test_a_bad_agent_alias_is_reported_before_a_bad_sandbox_key(tmp_path):
    with pytest.raises(ConfigError, match="model_alias 'typo'"):
        _load(tmp_path, global_={"sandbox_memory_mb": -1}, agents={"whitebox_reviewer_claude": {"model_alias": "typo"}})


# --- 探索到的設定檔 ／ Discovered config ----------------------------------------------------------

def test_a_discovered_config_may_not_set_security_sensitive_keys(tmp_path):
    path = _write(tmp_path, _config(global_={"docker_bin": "/tmp/evil", "max_model_calls": 10**6}), "vibeharness.yaml")
    with pytest.raises(ConfigError) as info:
        load_settings(path, origin="discovered")
    message = str(info.value)
    assert "sets security-sensitive key(s): global.docker_bin" in message and f"--config {path}" in message
    # 同一個檔案以 --config 明確指定時完全受信任 ／ the same file passed with --config is fully trusted
    assert load_settings(path, origin="explicit").sandbox.docker.bin == "docker"


def test_a_discovered_copy_of_the_bundled_config_is_accepted_and_validated(tmp_path):
    assert load_settings(_write(tmp_path, _config(), "vibeharness.yaml"), origin="discovered").origin == "discovered"
    lowered = _write(tmp_path, _config(global_={"max_files": 5, "execution_mode": "mock"}), "lower.yaml")
    assert load_settings(lowered, origin="discovered").scope.max_files == 5
    # 政策通過之後仍照常驗證 ／ after the policy passes, the usual validation still applies
    bad = _write(tmp_path, _config(global_={"sandbox_timeout_seconds": -1}), "bad.yaml")
    with pytest.raises(ConfigError, match="global.sandbox_timeout_seconds"):
        load_settings(bad, origin="discovered")


def test_the_policy_compares_against_the_given_reference(tmp_path):
    reference = _write(tmp_path, _config(global_={"max_files": 500}), "reference.yaml")
    raised = _write(tmp_path, _config(global_={"max_files": 400}), "vibeharness.yaml")
    with pytest.raises(ConfigError, match="global.max_files"):
        load_settings(raised, origin="discovered")
    assert load_settings(raised, origin="discovered", reference_path=reference).scope.max_files == 400


# --- CLI 覆寫值 ／ CLI overrides ----------------------------------------------------------------

def test_overrides_replace_the_file_values(tmp_path):
    cache = tmp_path / "cache"
    s = _load(tmp_path, overrides=Overrides(
        execution_mode="mock", max_files=3, max_model_calls=9, mutation_max_mutants=4, include=("src/*",),
        exclude=("*_test.py",), changed_since="HEAD~1", cache_dir=str(cache), cache_only=True,
    ))
    assert (s.gateway.execution_mode, s.scope.max_files, s.gateway.max_model_calls, s.mutation.max_mutants) == ("mock", 3, 9, 4)
    assert (s.scope.include, s.scope.exclude, s.scope.changed_since) == (("src/*",), ("*_test.py",), "HEAD~1")
    assert s.gateway.cache_dir == str(cache) and s.gateway.cache_only and cache.is_dir()


def test_max_model_calls_override_of_zero_means_unlimited(tmp_path):
    assert _load(tmp_path, global_={"max_model_calls": 5}, overrides=Overrides(max_model_calls=0)).gateway.max_model_calls is None


def test_overrides_apply_after_the_file_is_validated(tmp_path):
    """覆寫值不會掩蓋設定檔裡的錯誤值（與過去在建構之後才設定相同）。
    An override does not hide a bad value in the file (as when it used to be set after construction)."""
    with pytest.raises(ConfigError, match="global.max_files"):
        _load(tmp_path, global_={"max_files": -1}, overrides=Overrides(max_files=3))


@pytest.mark.parametrize("file_value, override, enabled, source", [
    (..., None, False, "default"),
    (None, None, False, "default"),
    (False, None, False, "config"),
    (True, None, True, "config"),
    (True, False, False, "cli"),
    (..., True, True, "cli"),
])
def test_mutation_testing_records_where_its_value_came_from(tmp_path, file_value, override, enabled, source):
    s = _load(tmp_path, global_={"mutation_testing": file_value}, overrides=Overrides(mutation_testing=override))
    assert s.mutation.enabled is enabled and s.sources["mutation_testing"] == source


def test_cache_only_needs_a_response_cache(tmp_path):
    with pytest.raises(ConfigError, match="--cache-only needs a response cache"):
        _load(tmp_path, overrides=Overrides(cache_only=True))
    assert _load(tmp_path, global_={"cache_dir": str(tmp_path / "c")}, overrides=Overrides(cache_only=True)).gateway.cache_only


def test_overrides_reject_unknown_flags():
    with pytest.raises(TypeError):
        Overrides(max_file=3)  # type: ignore[call-arg]


# --- 警告 ／ warnings -----------------------------------------------------------------------------

def test_relative_executable_paths_are_warned_about(tmp_path):
    # sys.executable 在每個平台都是絕對路徑（Windows 上 Python 3.13 起，沒有磁碟代號的 "/usr/bin/docker" 不算絕對路徑）
    # sys.executable is absolute on every platform (on Windows, since Python 3.13, "/usr/bin/docker" without a drive is not)
    s = _load(tmp_path, global_={"node_bin": "./node", "docker_bin": sys.executable})
    assert len(s.warnings) == 1 and "global.node_bin is a relative path './node'" in s.warnings[0]


# --- 唯讀 ／ read-only ----------------------------------------------------------------------------

def test_models_and_agents_are_read_only_but_still_dicts(tmp_path):
    s = _load(tmp_path, models={"claude": {"extra_params": {"top_p": 0.9, "stop": ["x"]}}})
    models, agents = s.gateway.models, s.gateway.agents
    assert isinstance(models, dict) and isinstance(models["claude"], FrozenDict)
    assert isinstance(models["claude"]["extra_params"]["stop"], FrozenList)
    for change in (lambda: models.__setitem__("x", {}), lambda: models["claude"].update(model="m"),
                   lambda: models["claude"]["extra_params"]["stop"].append("y"), lambda: agents.pop("whitebox_reviewer_claude")):
        with pytest.raises(TypeError, match="read-only"):
            change()
    assert json.loads(json.dumps(models["claude"], sort_keys=True))["extra_params"] == {"stop": ["x"], "top_p": 0.9}
    for clone in (copy.deepcopy(models), pickle.loads(pickle.dumps(models))):
        assert clone == models and isinstance(clone["claude"], FrozenDict)
    assert dict(**models["claude"]["extra_params"]) == {"top_p": 0.9, "stop": ["x"]}


def test_settings_values_are_frozen(tmp_path):
    s = _load(tmp_path)
    with pytest.raises(AttributeError):
        s.scope.max_files = 1  # type: ignore[misc]


def test_importing_settings_loads_no_third_party_package():
    """擷取器與沙盒會匯入預設值：匯入 settings 不得載入 yaml 等套件 ／ The extractor and the sandbox import the defaults:
    importing settings must not load yaml or any other package."""
    code = ("import sys, vibeharness.core.settings; "
            "print(sorted(m for m in ('pydantic', 'yaml', 'rich', 'litellm') if m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True,
                         env=dict(os.environ, PYTHONPATH=REPO_ROOT), check=True).stdout
    assert out.strip() == "[]"
