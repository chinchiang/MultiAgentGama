"""--estimate：不呼叫模型即可得知預期的模型呼叫次數與 token 數。
--estimate: expected model calls and tokens without calling a model."""
import json
import os
import sys

import pytest

from config_files import load_config, write_config
from vibeharness.core.estimate import estimate_lines, estimate_run
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.llm_gateway import ConfigError, LLMGateway

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
EXAMPLES = os.path.join(REPO_ROOT, "examples")


def _config(tmp_path, global_overrides=None, model_overrides=None):
    cfg = load_config()
    cfg["global"].update(global_overrides or {})
    for alias, extra in (model_overrides or {}).items():
        cfg["models"][alias] = dict(cfg["models"][alias], **extra)
    return write_config(tmp_path, cfg)


def test_exact_figures_match_what_a_real_run_spends(tmp_path):
    """審查者與威脅建模器的呼叫次數在執行前就已知：mock 執行必須恰好呼叫這麼多次。
    Reviewer and threat-modeler calls are known before the run: the mock run must make exactly that many."""
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    est = estimate_run(commander, EXAMPLES)
    assert est.symbols == 3 and est.files_analyzed == 1 and est.whitebox_batches == 1 and est.threat_batches == 1
    reviewers = [c for c in est.by_agent if c.agent.startswith("whitebox_reviewer_")]
    assert len(reviewers) == 4 and all(c.calls_exact == 1 for c in reviewers)
    modeler = next(c for c in est.by_agent if c.agent == "blackbox_threat_modeler")
    assert modeler.calls_exact == 1 and est.calls_exact == 5
    assert not commander.gateway.call_log  # 沒有任何呼叫 ／ nothing was called

    run = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    run.run_full_pipeline(target_dir=EXAMPLES, output_report_path=str(tmp_path / "r.md"))
    actual = {}
    for rec in run.gateway.call_log:
        actual[rec.agent_id] = actual.get(rec.agent_id, 0) + 1
    for c in reviewers + [modeler]:
        assert actual.get(c.agent, 0) == c.calls_exact, c.agent


def test_scenario_figures_scale_with_assumptions_and_retries(tmp_path):
    commander = VibeHarnessCommander(config_path=_config(tmp_path, {"retry_invalid_output": 0}), execution_mode="mock")
    base = estimate_run(commander, EXAMPLES, findings_per_batch=3)
    more = estimate_run(commander, EXAMPLES, findings_per_batch=30)
    assert more.calls_typical > base.calls_typical and more.calls_exact == base.calls_exact
    gen = next(c for c in base.by_agent if c.agent == "whitebox_test_generator")
    assert gen.calls_exact is None and gen.calls_typical > 0  # 只有情境估算的代理 ／ scenario-only agent
    retried = VibeHarnessCommander(config_path=_config(tmp_path, {"retry_invalid_output": 2}), execution_mode="mock")
    assert estimate_run(retried, EXAMPLES).calls_max > base.calls_max
    capped = VibeHarnessCommander(config_path=_config(tmp_path, {"max_model_calls": 3}), execution_mode="mock")
    est = estimate_run(capped, EXAMPLES)
    assert any("max_model_calls=3 is below" in w for w in est.warnings)
    assert est.calls_typical >= est.calls_exact and est.calls_max >= est.calls_typical


def test_verifier_calls_have_no_float_error(tmp_path):
    """3 個審查者 × 25 批 × 3 個發現 × 0.8 = 180 筆發現；驗證者只裁決其他兩個模型的 120 筆，每次 15 筆 = 8 次呼叫。
    以 distinct × (1 - 自家份額) 計算時浮點誤差得到 120.00000000000001，多算成 9 次。
    3 reviewers × 25 batches × 3 findings × 0.8 = 180 findings; a verifier rules on the other two models' 120 only,
    15 per call = 8 calls. Computed as distinct × (1 - own share), float error gave 120.00000000000001 and so 9."""
    cfg = load_config()
    del cfg["agents"]["whitebox_reviewer_gemini"]
    config = write_config(tmp_path, cfg)
    target = tmp_path / "target"
    target.mkdir()
    (target / "w.py").write_text("".join(f"def w_{i}(x):\n    return x + {i}\n\n" for i in range(15 * 25)), encoding="utf-8")
    est = estimate_run(VibeHarnessCommander(config_path=config, execution_mode="mock"), str(target))
    assert est.whitebox_batches == 25
    verifiers = {c.model_alias: c.calls_typical for c in est.by_agent if c.agent.startswith("whitebox_verifier_")}
    assert verifiers == {"claude": 8, "deepseek": 8, "glm": 8, "gemini": 12}


def test_prices_turn_tokens_into_cost_and_are_validated(tmp_path):
    cfg = _config(tmp_path, model_overrides={
        "claude": {"price_per_million_input": 3.0, "price_per_million_output": 15.0},
        "deepseek": {"price_per_million_input": 0.5, "price_per_million_output": 1.5},
    })
    est = estimate_run(VibeHarnessCommander(config_path=cfg, execution_mode="mock"), EXAMPLES)
    assert est.estimated_cost_usd is not None and est.estimated_cost_usd > 0
    assert "cost_usd" in est.by_model["claude"] and "cost_usd" not in est.by_model["glm"]
    assert any("No price configured for model alias 'glm'" in w for w in est.warnings)
    lines = estimate_lines(est)
    assert any("Estimated cost" in line for line in lines) and any("No model was called" in line for line in lines)
    with pytest.raises(ConfigError, match="price_per_million_input"):
        LLMGateway(_config(tmp_path, model_overrides={"glm": {"price_per_million_input": "cheap"}}), execution_mode="mock")


def test_estimate_honours_file_selection(tmp_path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("def f(x):\n    return x\n")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    commander.exclude_patterns = ["b.py"]
    est = estimate_run(commander, str(tmp_path))
    assert est.files_analyzed == 1 and est.symbols == 1
    assert any("File selection applied: exclude=b.py" in w for w in est.warnings)
    empty = tmp_path / "empty"
    empty.mkdir()
    est = estimate_run(VibeHarnessCommander(config_path=CONFIG, execution_mode="mock"), str(empty))
    assert est.calls_exact == 1  # 一個沒有程式碼的威脅建模批次 ／ one code-less threat-model batch
    assert any("No analyzable symbols" in w for w in est.warnings)


def test_cli_estimate_calls_no_model_and_exits_zero(monkeypatch, tmp_path, capsys):
    from vibeharness import cli
    called = []
    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", lambda self, **kw: called.append(1))
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", EXAMPLES, "-m", "live", "--estimate", "-o", str(tmp_path / "r.md")])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == 0 and not called
    out = capsys.readouterr().out
    assert "Model calls: " in out and "exact 5 + scenario" in out and "No model was called" in out
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", EXAMPLES, "-m", "mock", "--estimate", "--format", "json", "-o", str(tmp_path / "e.json")])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == 0
    payload = json.loads((tmp_path / "e.json").read_text(encoding="utf-8"))
    assert payload["calls_exact"] == 5 and payload["by_agent"][0]["agent"] == "whitebox_reviewer_claude"
