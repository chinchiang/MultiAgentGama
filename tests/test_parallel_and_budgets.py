"""Concurrency of test synthesis, the live model-call budget, and the configurable file / worker limits."""
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from core.llm_gateway import LLMGateway, LLMGatewayError, ConfigError, BUDGET_EXHAUSTED_REASON
from core.models import FindingSeverity, ReviewFinding, STRIDECategory, ThreatItem, CodeSymbol
from agents.whitebox.test_generator import WhiteboxTestGenerator
from agents.blackbox.scenario_builder import ThreatScenarioBuilder
from agents.blackbox.threat_modeler import AutomatedThreatModeler

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "config", "agents_config.yaml")


def _config(tmp_path, **global_overrides):
    with open(CONFIG, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    cfg["global"].update(global_overrides)
    path = tmp_path / "agents_config.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return str(path)


def _finding(i):
    return ReviewFinding(
        finding_id=f"F{i}", reviewer_name="Claude", model_alias="claude", file_path="unknown",
        severity=FindingSeverity.HIGH, title=f"defect {i}", description="", root_cause="",
        suspected_vibe_flaw="", suggested_test_scenario=""
    )


def _threat(i):
    return ThreatItem(
        threat_id=f"T{i}", stride_category=STRIDECategory.TAMPERING, title=f"threat {i}", description="",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="", test_verification_goal=""
    )


class _ConcurrencyProbe:
    """A gateway.generate stand-in that records peak parallelism; later items answer first."""

    def __init__(self, count, key):
        self.count, self.key = count, key
        self.lock = threading.Lock()
        self.in_flight = self.peak = 0

    def __call__(self, agent_id, system, user, **kwargs):
        index = int(re.search(re.escape(self.key) + r"\s*(\d+)", user).group(1))
        with self.lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        time.sleep(0.05 * (self.count - index))  # finish in reverse order
        with self.lock:
            self.in_flight -= 1
        return {"code": f"def test_{index}():\n    assert {index} == {index}\n", "title": f"for {index}"}


# --- Concurrency keeps results deterministic -----------------------------------------------------

def test_whitebox_generation_runs_concurrently_and_keeps_finding_order(tmp_path):
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))
    probe = _ConcurrencyProbe(6, "defect")
    gen.gateway.generate = probe
    tests = gen.generate_tests_for_findings([_finding(i) for i in range(6)], [], root_dir=str(tmp_path))
    assert probe.peak > 1
    assert [(t.test_id, t.source_ref, t.title) for t in tests] == [
        (f"WB-TEST-{i + 1:02d}", f"F{i}", f"for {i}") for i in range(6)
    ]


def test_blackbox_synthesis_runs_concurrently_and_keeps_threat_order():
    builder = ThreatScenarioBuilder(LLMGateway(CONFIG, execution_mode="mock"))
    probe = _ConcurrencyProbe(6, "Threat ID: T")
    builder.gateway.generate = probe
    tests = builder.build_test_cases_from_threats([_threat(i) for i in range(6)])
    assert probe.peak > 1
    assert [t.source_ref for t in tests] == [f"T{i}" for i in range(6)]


def test_threat_modeling_batches_run_concurrently_and_keep_order(tmp_path):
    tm = AutomatedThreatModeler(LLMGateway(CONFIG, execution_mode="mock"))
    symbols = [
        CodeSymbol(
            name=f"func_{i}", symbol_type="function", file_path="app.py",
            line_start=1, line_end=1000, signature=f"func_{i}()",
            source_code=f"def func_{i}():\n" + "    x = 'filler token budget'\n" * 1000
        )
        for i in range(4)
    ]

    class _ThreatProbe:
        def __init__(self):
            self.lock = threading.Lock()
            self.in_flight = self.peak = 0

        def __call__(self, agent_id, system, user, **kwargs):
            match = re.search(r"Symbol: func_(\d+)", user)
            index = int(match.group(1)) if match else 0
            with self.lock:
                self.in_flight += 1
                self.peak = max(self.peak, self.in_flight)
            time.sleep(0.05 * (4 - index))
            with self.lock:
                self.in_flight -= 1
            return {
                "threats": [{"threat_id": f"THREAT-0{index+1}", "stride_category": "Tampering", "title": f"threat for {index}"}],
                "entrypoints": [f"/api/{index}"]
            }

    probe = _ThreatProbe()
    tm.gateway.generate = probe
    report = tm.model_system("desc", ["/api"], symbols=symbols, root_dir=str(tmp_path))
    assert probe.peak > 1
    assert [t.title for t in report.threats] == [f"threat for {i}" for i in range(4)]
    assert report.entrypoints == ["/api/0"]


def test_max_concurrent_calls_bounds_the_worker_pool(tmp_path):
    gen = WhiteboxTestGenerator(LLMGateway(_config(tmp_path, max_concurrent_calls=1), execution_mode="mock"))
    probe = _ConcurrencyProbe(4, "defect")
    gen.gateway.generate = probe
    gen.generate_tests_for_findings([_finding(i) for i in range(4)], [], root_dir=str(tmp_path))
    assert probe.peak == 1


def test_one_crashed_synthesis_does_not_discard_the_others(tmp_path, monkeypatch):
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))
    real = gen._tests_for_finding

    def flaky(idx, finding, *args):
        if idx == 1:
            raise RuntimeError("boom")
        return real(idx, finding, *args)

    monkeypatch.setattr(gen, "_tests_for_finding", flaky)
    gen.gateway.generate = lambda *a, **k: {"code": "def test_ok():\n    assert True\n"}
    tests = gen.generate_tests_for_findings([_finding(i) for i in range(3)], [], root_dir=str(tmp_path))
    assert [t.source_ref for t in tests if t.test_type == "whitebox_unit"] == ["F0", "F2"]
    assert gen.findings_without_model_tests == ["F1"]

    builder = ThreatScenarioBuilder(LLMGateway(CONFIG, execution_mode="mock"))
    real_bb = builder._test_for_threat
    monkeypatch.setattr(builder, "_test_for_threat",
                        lambda threat, *a: (_ for _ in ()).throw(RuntimeError("boom")) if threat.threat_id == "T1"
                        else real_bb(threat, *a))
    builder.gateway.generate = lambda *a, **k: {"code": "def test_ok():\n    assert True\n"}
    assert [t.source_ref for t in builder.build_test_cases_from_threats([_threat(i) for i in range(3)])] == ["T0", "T2"]


def test_strict_live_failures_still_propagate_from_the_pool(tmp_path):
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))

    def fail(*a, **k):
        raise LLMGatewayError("no key")

    gen.gateway.generate = fail
    with pytest.raises(LLMGatewayError):
        gen.generate_tests_for_findings([_finding(0), _finding(1)], [], root_dir=str(tmp_path))
    builder = ThreatScenarioBuilder(LLMGateway(CONFIG, execution_mode="mock"))
    builder.gateway.generate = fail
    with pytest.raises(LLMGatewayError):
        builder.build_test_cases_from_threats([_threat(0)])


# --- Live model-call budget ----------------------------------------------------------------------

def test_budget_falls_back_to_simulation_in_hybrid_mode(fake_live, tmp_path):
    fake = fake_live(lambda s, u: json.dumps({"findings": []}))
    gw = LLMGateway(_config(tmp_path, max_model_calls=2), execution_mode="hybrid")
    for _ in range(4):
        gw.generate("whitebox_reviewer_claude", "s", "u", required_keys=["findings"])
    assert len(fake.calls) == 2
    assert [r.mode for r in gw.call_log] == ["live", "live", "simulated", "simulated"]
    assert len(gw.budget_exhausted_calls) == 2 and gw.call_log[-1].reason == BUDGET_EXHAUSTED_REASON


def test_budget_fails_loudly_in_live_mode(fake_live, tmp_path):
    fake_live(lambda s, u: json.dumps({"findings": []}))
    gw = LLMGateway(_config(tmp_path, max_model_calls=1), execution_mode="live")
    gw.generate("whitebox_reviewer_claude", "s", "u")
    with pytest.raises(LLMGatewayError, match="budget"):
        gw.generate("whitebox_reviewer_claude", "s", "u")


def test_budget_is_exact_under_concurrency(fake_live, tmp_path):
    fake = fake_live(lambda s, u: json.dumps({"ok": True}))
    gw = LLMGateway(_config(tmp_path, max_model_calls=10), execution_mode="hybrid")
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda _: gw.generate("whitebox_reviewer_claude", "s", "u"), range(50)))
    assert len(fake.calls) == 10
    assert sum(r.mode == "live" for r in gw.call_log) == 10


def test_unlimited_budget_by_default(fake_live, tmp_path):
    fake = fake_live(lambda s, u: json.dumps({"ok": True}))
    gw = LLMGateway(CONFIG, execution_mode="live")
    for _ in range(30):
        gw.generate("whitebox_reviewer_claude", "s", "u")
    assert len(fake.calls) == 30 and gw.max_model_calls is None


@pytest.mark.parametrize("key,value", [
    ("max_model_calls", -1), ("max_model_calls", "10"), ("max_concurrent_calls", True), ("max_concurrent_calls", 1.5),
])
def test_invalid_limits_are_config_errors(tmp_path, key, value):
    with pytest.raises(ConfigError, match=key):
        LLMGateway(_config(tmp_path, **{key: value}))


@pytest.mark.parametrize("key,value", [
    ("timeout_seconds", "abc"), ("timeout_seconds", 0), ("max_retries", -1), ("max_retries", 1.5),
    ("max_output_tokens", "16k"), ("max_output_tokens", 0),
])
def test_invalid_numeric_settings_are_config_errors_at_startup(tmp_path, key, value):
    """These used to be read only when a call was made: litellm rejected them, and hybrid mode booked
    the failure as "live invocation failed" and silently ran the simulation engine instead."""
    with pytest.raises(ConfigError, match=key):
        LLMGateway(_config(tmp_path, **{key: value}))


def test_invalid_per_model_tokens_and_agent_temperature_are_config_errors(tmp_path):
    with open(CONFIG, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    bad_model = dict(cfg, models=dict(cfg["models"], claude=dict(cfg["models"]["claude"], max_output_tokens="lots")))
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump(bad_model), encoding="utf-8")
    with pytest.raises(ConfigError, match="models.claude.max_output_tokens"):
        LLMGateway(str(path), execution_mode="mock")
    reviewer = dict(cfg["agents"]["whitebox_reviewer_claude"], temperature=3)
    bad_agent = dict(cfg, agents=dict(cfg["agents"], whitebox_reviewer_claude=reviewer))
    path = tmp_path / "a.yaml"
    path.write_text(yaml.safe_dump(bad_agent), encoding="utf-8")
    with pytest.raises(ConfigError, match="whitebox_reviewer_claude.temperature"):
        LLMGateway(str(path), execution_mode="mock")
    # The shipped config itself is valid, and floats are fine where a number is expected
    LLMGateway(_config(tmp_path, timeout_seconds=12.5), execution_mode="mock")


@pytest.mark.parametrize("value", [-1, "10", True, 2.5])
def test_invalid_max_files_in_config_is_a_config_error(tmp_path, value):
    """The CLI already rejects a bad --max-files; the config path must not quietly accept a negative
    slice (which analyzed all but one file) or a string (which int() happened to convert)."""
    from core.harness import VibeHarnessCommander
    with pytest.raises(ConfigError, match="max_files"):
        VibeHarnessCommander(config_path=_config(tmp_path, max_files=value), execution_mode="mock")


def test_zero_or_null_max_files_keeps_the_default(tmp_path):
    from core.harness import VibeHarnessCommander
    from agents.whitebox.ast_extractor import DEFAULT_MAX_FILES
    for value in (0, None):
        commander = VibeHarnessCommander(config_path=_config(tmp_path, max_files=value), execution_mode="mock")
        assert commander.max_files == DEFAULT_MAX_FILES


def test_single_reviewer_model_is_an_evidence_gap(tmp_path):
    """Four reviewer agents on one model cannot cross-verify each other (no model rules on its own
    findings): the run must say so in the gate, not only on the console (OWASP LLM07:2026)."""
    from core.harness import VibeHarnessCommander
    with open(CONFIG, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    for agent_id, meta in cfg["agents"].items():
        if agent_id.startswith(("whitebox_reviewer_", "whitebox_verifier_")):
            meta["model_alias"] = "gemini"
    path = tmp_path / "single.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    target = tmp_path / "app"
    target.mkdir()
    (target / "app.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    commander = VibeHarnessCommander(config_path=str(path), execution_mode="mock")
    assert commander.multi_reviewer.distinct_models == ["gemini"]
    summary = commander.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "r.md"))
    assert summary.overall_status != "READY_TO_SHIP"
    assert any("Only one distinct reviewer model (gemini)" in r for r in summary.inconclusive_reasons)


def test_exhausted_budget_makes_the_run_inconclusive(fake_live, tmp_path):
    from core.harness import VibeHarnessCommander
    target = tmp_path / "app"
    target.mkdir()
    (target / "app.py").write_text("def greet(name):\n    return 'hi ' + name\n", encoding="utf-8")
    fake_live(lambda s, u: json.dumps({"findings": [], "verdicts": [], "threats": []}))
    commander = VibeHarnessCommander(config_path=_config(tmp_path, max_model_calls=1), execution_mode="hybrid")
    summary = commander.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "r.md"))
    assert summary.overall_status in ("INCONCLUSIVE", "NEEDS_FIXES")
    assert any("max_model_calls budget (1) was exhausted" in r for r in summary.inconclusive_reasons)


# --- max_files from config and CLI ---------------------------------------------------------------

def test_max_files_comes_from_config(tmp_path):
    from core.harness import VibeHarnessCommander
    target = tmp_path / "proj"
    target.mkdir()
    for i in range(4):
        (target / f"m{i}.py").write_text(f"def f{i}(x):\n    return x\n", encoding="utf-8")
    commander = VibeHarnessCommander(config_path=_config(tmp_path, max_files=2), execution_mode="mock")
    summary = commander.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "r.md"))
    assert len(commander.ast_extractor.skipped_files) == 2
    assert any("max_files limit (2)" in r for r in summary.inconclusive_reasons)


def test_cli_limit_flags_override_the_config(monkeypatch, tmp_path):
    import main
    from core.models import VibeHarnessSummary
    seen = {}

    def run(self, **kwargs):
        seen.update(max_files=self.max_files, max_model_calls=self.gateway.max_model_calls)
        return VibeHarnessSummary(
            overall_status="INCONCLUSIVE", total_whitebox_findings=0, confirmed_whitebox_bugs=0,
            whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0,
            critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0,
        )

    monkeypatch.setattr(main.VibeHarnessCommander, "run_full_pipeline", run)
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), "-m", "mock",
                                      "--max-files", "7", "--max-model-calls", "40"])
    with pytest.raises(SystemExit):
        main.main()
    assert seen == {"max_files": 7, "max_model_calls": 40}


@pytest.mark.parametrize("argv", [["--max-files", "0"], ["--max-model-calls", "-3"]])
def test_cli_rejects_invalid_limits_with_the_usage_exit_code(monkeypatch, tmp_path, argv):
    import main
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), *argv])
    with pytest.raises(SystemExit) as exit_info:
        main.main()
    assert exit_info.value.code == main.USAGE_ERROR_EXIT_CODE
