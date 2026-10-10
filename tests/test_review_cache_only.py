"""--cache-only：每次模型呼叫只從回應快取取用；未命中絕不呼叫網路，並列為證據缺口。
--cache-only: every model call is served from the response cache only; a miss never touches the network
and is reported as an evidence gap."""
import json
import os
import sys

import pytest

from vibeharness import cli
from vibeharness.core.estimate import estimate_lines, estimate_run
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.llm_gateway import CACHE_MISS_REASON, LLMGateway, LLMGatewayError

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
EXAMPLES = os.path.join(REPO_ROOT, "examples")

_ONE_MODEL = (
    "global: {{execution_mode: {mode}, max_retries: 0, retry_invalid_output: 1}}\n"
    "models:\n  a: {{model: m-a, api_key_env: ANTHROPIC_API_KEY}}\n"
    "agents:\n  x: {{model_alias: a}}\n"
)


def _gateway(tmp_path, mode="live", cache_only=False):
    """建立只有一個模型與一個代理的閘道，快取目錄放在 tmp_path/cache。
    Builds a gateway with one model and one agent, its cache in tmp_path/cache."""
    path = tmp_path / "agents.yaml"
    path.write_text(_ONE_MODEL.format(mode=mode), encoding="utf-8")
    gw = LLMGateway(str(path))
    gw.set_cache_dir(str(tmp_path / "cache"))
    gw.cache_only = cache_only
    return gw


def _run_cli(monkeypatch, *argv):
    """以指定參數執行 CLI，回傳它的結束碼。
    Runs the CLI with the given arguments and returns its exit code."""
    monkeypatch.setattr(sys, "argv", ["vibeharness", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return exit_info.value.code


# --- 閘道：命中、未命中、絕不呼叫網路 -------------------------------------------------------------
# --- Gateway: hit, miss, never the network ------------------------------------------------------

def test_cache_hit_is_served_without_calling_litellm(tmp_path, fake_live):
    """第一次執行填好快取後，--cache-only 從快取取用同一個回答，假 litellm 一次也沒被呼叫。
    Once a first run filled the cache, --cache-only serves the same answer and the fake litellm is never called."""
    fake_live(lambda system, user: '{"ok": 1}')
    assert _gateway(tmp_path).generate("x", "s", "u", required_keys=["ok"])["ok"] == 1

    replay = _gateway(tmp_path, cache_only=True)
    fake = fake_live(lambda system, user: pytest.fail("cache-only must not call litellm"))
    result = replay.generate("x", "s", "u", required_keys=["ok"])
    assert result["ok"] == 1 and result["_provenance"]["cached"] is True
    assert fake.calls == [] and replay.live_calls_attempted == 0
    assert [rec.mode for rec in replay.call_log] == ["live"] and replay.call_log[0].cached


def test_cache_hit_needs_no_api_key(tmp_path, fake_live, monkeypatch):
    """只讀快取不需要金鑰：沒有金鑰也能重播先前的回答。
    Reading the cache needs no key: a previous answer replays even without one."""
    fake_live(lambda system, user: '{"ok": 1}')
    _gateway(tmp_path).generate("x", "s", "u")
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert _gateway(tmp_path, cache_only=True).generate("x", "s", "u")["ok"] == 1


def test_cache_miss_in_hybrid_is_simulated_and_recorded_as_a_gap(tmp_path, fake_live):
    """hybrid 下的未命中不呼叫網路、不扣預算，改用模擬並以專屬原因登記。
    A miss in hybrid makes no network call and spends no budget; it is simulated and booked with its own reason."""
    fake = fake_live(lambda system, user: pytest.fail("cache-only must not call litellm"))
    gw = _gateway(tmp_path, mode="hybrid", cache_only=True)
    result = gw.generate("x", "s", "u")
    assert fake.calls == [] and gw.live_calls_attempted == 0
    assert result["_provenance"]["mode"] == "simulated"
    assert [rec.reason for rec in gw.cache_miss_calls] == [CACHE_MISS_REASON]
    assert gw.used_simulation and not gw.budget_exhausted_calls


def test_cache_miss_in_live_raises_like_an_exhausted_budget(tmp_path, fake_live):
    """live 下的未命中與預算用盡相同：拋出 LLMGatewayError（CLI exit 4），且沒有網路呼叫。
    A miss in live is handled like an exhausted budget: LLMGatewayError (CLI exit 4), and no network call."""
    fake = fake_live(lambda system, user: pytest.fail("cache-only must not call litellm"))
    with pytest.raises(LLMGatewayError, match="cache miss in --cache-only mode"):
        _gateway(tmp_path, cache_only=True).generate("x", "s", "u")
    assert fake.calls == []


def test_unusable_cached_answer_is_never_re_asked(tmp_path, fake_live):
    """快取中的回答若對這次呼叫無法使用，--cache-only 登記為 invalid，而不是重新詢問（那是網路呼叫）。
    A cached answer that is unusable for this call is booked invalid under --cache-only, never re-asked (a network call)."""
    fake_live(lambda system, user: '{"other": 1}')
    _gateway(tmp_path).generate("x", "s", "u")
    fake = fake_live(lambda system, user: pytest.fail("cache-only must not call litellm"))
    gw = _gateway(tmp_path, cache_only=True)
    assert gw.generate("x", "s", "u", required_keys=["ok"])["_provenance"]["mode"] == "invalid"
    assert fake.calls == [] and [rec.mode for rec in gw.call_log] == ["invalid"]


def test_a_re_asked_answer_is_cached_under_the_original_prompt(tmp_path, fake_live):
    """重新詢問後的可用回答也存在原始提示的鍵下，--cache-only 重播時才不會在第一次嘗試就未命中。
    A usable answer after a re-ask is also stored under the original prompt, so a --cache-only replay does
    not miss the first attempt."""
    answers = iter(["not json", '{"ok": 2}'])
    fake_live(lambda system, user: next(answers))
    assert _gateway(tmp_path).generate("x", "s", "u", required_keys=["ok"])["ok"] == 2
    fake = fake_live(lambda system, user: pytest.fail("cache-only must not call litellm"))
    assert _gateway(tmp_path, cache_only=True).generate("x", "s", "u", required_keys=["ok"])["ok"] == 2
    assert fake.calls == []


# --- CLI：結束碼與完整執行 -------------------------------------------------------------------------
# --- CLI: exit codes and a full run -----------------------------------------------------------------

def test_cache_only_without_a_cache_exits_5(monkeypatch, tmp_path):
    """沒有 --cache-dir 也沒有 global.cache_dir 時，--cache-only 是設定錯誤（exit 5），什麼都不執行。
    Without --cache-dir or global.cache_dir, --cache-only is a configuration error (exit 5) and nothing runs."""
    def run(self, **kwargs):
        pytest.fail("the pipeline must not start")

    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock", "--cache-only") == cli.USAGE_ERROR_EXIT_CODE


def test_cache_only_accepts_the_configured_cache_dir(monkeypatch, tmp_path):
    """設定檔的 global.cache_dir 也滿足 --cache-only；閘道會進入只讀快取模式。
    global.cache_dir in the config also satisfies --cache-only; the gateway enters cache-only mode."""
    config = tmp_path / "agents.yaml"
    config.write_text(f"global: {{cache_dir: {json.dumps(str(tmp_path / 'cache'))}}}\n", encoding="utf-8")
    seen = {}

    def run(self, **kwargs):
        seen["cache_only"] = self.gateway.cache_only
        return type("S", (), {"overall_status": "INCONCLUSIVE"})()

    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    assert _run_cli(monkeypatch, "-t", str(tmp_path), "-m", "mock", "-c", str(config), "--cache-only") == 3
    assert seen == {"cache_only": True}


def test_full_hybrid_run_with_an_empty_cache_calls_nothing_and_reports_the_gap(monkeypatch, tmp_path, fake_live):
    """空快取的 hybrid --cache-only 完整執行：沒有任何網路呼叫，未命中列為證據缺口，判定絕不是 READY_TO_SHIP。
    （examples 的確定性探針會找到問題，所以判定是 NEEDS_FIXES，exit 1。）
    A full hybrid --cache-only run on an empty cache: no network call, the misses are evidence gaps, and the
    verdict is never READY_TO_SHIP. (The deterministic probes find problems in examples, so it is NEEDS_FIXES, exit 1.)"""
    fake = fake_live(lambda system, user: pytest.fail("cache-only must not call litellm"))
    report = tmp_path / "r.json"
    code = _run_cli(monkeypatch, "-t", EXAMPLES, "-m", "hybrid", "--cache-only", "--cache-dir", str(tmp_path / "cache"),
                    "--format", "json", "-o", str(report))
    assert code in (1, 2, 3) and fake.calls == []
    summary = json.loads(report.read_text(encoding="utf-8"))["summary"]
    assert summary["overall_status"] != "READY_TO_SHIP"
    assert any(reason.startswith("--cache-only") for reason in summary["inconclusive_reasons"])
    assert {call["reason"] for call in summary["agent_calls"]} == {CACHE_MISS_REASON}


def test_live_cache_only_miss_exits_4(monkeypatch, tmp_path, fake_live):
    """live 模式下 --cache-only 的未命中以 exit 4 中止，且沒有網路呼叫。
    A --cache-only miss in live mode aborts with exit 4, and no network call is made."""
    fake = fake_live(lambda system, user: pytest.fail("cache-only must not call litellm"))
    code = _run_cli(monkeypatch, "-t", EXAMPLES, "-m", "live", "--cache-only", "--cache-dir", str(tmp_path / "cache"),
                    "-o", str(tmp_path / "r.md"))
    assert code == 4 and fake.calls == []


# --- --estimate 的互動 --------------------------------------------------------------------------------
# --- Interplay with --estimate -------------------------------------------------------------------------

def test_estimate_says_cache_only_spends_nothing(tmp_path):
    """--estimate 搭配 --cache-only 時，估算標示不會呼叫供應商，也不提出預算警告。
    With --cache-only, --estimate states that no provider is called and raises no budget warning."""
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="hybrid")
    commander.gateway.set_cache_dir(str(tmp_path / "cache"))
    commander.gateway.cache_only = True
    commander.gateway.max_model_calls = 1
    est = estimate_run(commander, EXAMPLES)
    assert est.cache_only
    assert any("--cache-only" in w for w in est.warnings)
    assert not any("max_model_calls=1" in w for w in est.warnings)
    assert any("--cache-only" in line for line in estimate_lines(est))
