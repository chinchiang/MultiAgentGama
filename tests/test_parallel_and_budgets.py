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

from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError, ConfigError, BUDGET_EXHAUSTED_REASON, PROVENANCE_KEY
from vibeharness.core.models import FindingSeverity, ReviewFinding, STRIDECategory, ThreatItem, CodeSymbol
from vibeharness.core.i18n import has_cjk
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")


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
    from vibeharness.core.harness import VibeHarnessCommander
    with pytest.raises(ConfigError, match="max_files"):
        VibeHarnessCommander(config_path=_config(tmp_path, max_files=value), execution_mode="mock")


def test_zero_or_null_max_files_keeps_the_default(tmp_path):
    from vibeharness.core.harness import VibeHarnessCommander
    from vibeharness.agents.whitebox.ast_extractor import DEFAULT_MAX_FILES
    for value in (0, None):
        commander = VibeHarnessCommander(config_path=_config(tmp_path, max_files=value), execution_mode="mock")
        assert commander.max_files == DEFAULT_MAX_FILES


def test_single_reviewer_model_is_an_evidence_gap(tmp_path):
    """Four reviewer agents on one model cannot cross-verify each other (no model rules on its own
    findings): the run must say so in the gate, not only on the console (OWASP LLM07:2026)."""
    from vibeharness.core.harness import VibeHarnessCommander
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
    from vibeharness.core.harness import VibeHarnessCommander
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
    from vibeharness.core.harness import VibeHarnessCommander
    target = tmp_path / "proj"
    target.mkdir()
    for i in range(4):
        (target / f"m{i}.py").write_text(f"def f{i}(x):\n    return x\n", encoding="utf-8")
    commander = VibeHarnessCommander(config_path=_config(tmp_path, max_files=2), execution_mode="mock")
    summary = commander.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "r.md"))
    assert len(commander.ast_extractor.skipped_files) == 2
    assert any("max_files limit (2)" in r for r in summary.inconclusive_reasons)


def test_cli_limit_flags_override_the_config(monkeypatch, tmp_path):
    from vibeharness import cli as main
    from vibeharness.core.models import VibeHarnessSummary
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
    from vibeharness import cli as main
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), *argv])
    with pytest.raises(SystemExit) as exit_info:
        main.main()
    assert exit_info.value.code == main.USAGE_ERROR_EXIT_CODE


# --- Re-asking after an unusable answer -------------------------------------------------------

def test_unusable_answer_is_re_asked_once_and_the_retry_can_succeed(fake_live):
    """One-off format slips (prose around the JSON, a missing key) used to turn the whole run
    INCONCLUSIVE; the gateway now re-asks once, naming the problem, before booking `invalid`."""
    answers = iter(["Sure! Here is my analysis without any JSON.", '{"findings": []}'])
    prompts = []

    def responder(system, user):
        prompts.append(user)
        return next(answers)

    fake = fake_live(responder)
    gw = LLMGateway(CONFIG, execution_mode="live")
    resp = gw.generate("whitebox_reviewer_claude", "sys", "audit this", required_keys=["findings"])
    assert gw.is_usable(resp) and resp["findings"] == []
    assert [c.mode for c in gw.call_log] == ["retried", "live"]
    assert "could not be used (response is not valid JSON)" in prompts[1] and prompts[1].startswith("audit this")
    assert not has_cjk(prompts[1])  # the bilingual reason reaches the model in English only
    assert len(fake.calls) == 2 and gw.live_calls_attempted == 2
    assert not gw.invalid_calls and len(gw.retried_calls) == 1


def test_re_ask_respects_the_call_budget_and_is_configurable(fake_live, tmp_path):
    fake = fake_live(lambda s, u: "not json")
    gw = LLMGateway(CONFIG, execution_mode="hybrid")
    gw.max_model_calls = 1
    gw.generate("whitebox_reviewer_claude", "sys", "u", required_keys=["findings"])
    # No budget left for a re-ask: booked invalid after the single attempt
    assert [c.mode for c in gw.call_log] == ["invalid"] and len(fake.calls) == 1
    gw = LLMGateway(_config(tmp_path, retry_invalid_output=0), execution_mode="hybrid")
    gw.generate("whitebox_reviewer_claude", "sys", "u", required_keys=["findings"])
    assert [c.mode for c in gw.call_log] == ["invalid"]
    gw = LLMGateway(_config(tmp_path, retry_invalid_output=2), execution_mode="hybrid")
    gw.generate("whitebox_reviewer_claude", "sys", "u", required_keys=["findings"])
    assert [c.mode for c in gw.call_log] == ["retried", "retried", "invalid"]
    # Non-JSON calls (the test-generator heal prompt) are never re-asked
    gw = LLMGateway(CONFIG, execution_mode="live")
    gw.generate("whitebox_test_generator", "sys", "u", json_output=False)
    assert [c.mode for c in gw.call_log] == ["live"]
    with pytest.raises(ConfigError, match="retry_invalid_output"):
        LLMGateway(_config(tmp_path, retry_invalid_output="twice"))


def test_extra_params_are_passed_to_litellm_and_validated(fake_live, tmp_path):
    with open(CONFIG, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    claude = dict(cfg["models"]["claude"], extra_params={"thinking": {"type": "disabled"}, "reasoning_effort": "low"})
    good = dict(cfg, models=dict(cfg["models"], claude=claude))
    path = tmp_path / "good.yaml"
    path.write_text(yaml.safe_dump(good), encoding="utf-8")
    fake = fake_live(lambda s, u: '{"findings": []}')
    LLMGateway(str(path), execution_mode="live").generate("whitebox_reviewer_claude", "s", "u", required_keys=["findings"])
    assert fake.calls[0]["thinking"] == {"type": "disabled"} and fake.calls[0]["reasoning_effort"] == "low"
    bad = dict(cfg, models=dict(cfg["models"], claude=dict(cfg["models"]["claude"], extra_params=["thinking"])))
    path.write_text(yaml.safe_dump(bad), encoding="utf-8")
    with pytest.raises(ConfigError, match="extra_params"):
        LLMGateway(str(path), execution_mode="mock")


# --- File selection ---------------------------------------------------------------------------

def _tree(tmp_path):
    for rel in ("src/app.py", "src/util.py", "tests/test_app.py", "vendor/lib.py"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"def f_{p.stem}(x):\n    return x\n")
    return tmp_path


def test_include_and_exclude_globs_select_files(tmp_path):
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
    root = _tree(tmp_path)
    ex = ASTExtractor()
    names = lambda: sorted(os.path.relpath(f, root).replace(os.sep, "/") for f in ex.analyzed_files)  # noqa: E731
    ex.parse_directory(str(root), include=["src/*"])
    assert names() == ["src/app.py", "src/util.py"] and ex.filtered_out == 2
    ex.parse_directory(str(root), exclude=["tests/*", "vendor"])
    assert names() == ["src/app.py", "src/util.py"]
    ex.parse_directory(str(root), include=["*.py"], exclude=["test_*.py"])
    assert names() == ["src/app.py", "src/util.py", "vendor/lib.py"]
    ex.parse_directory(str(root), only_files=[str(root / "src" / "util.py")])
    assert names() == ["src/util.py"] and ex.filtered_out == 3


def test_oversized_files_are_skipped_and_disclosed(tmp_path):
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
    root = _tree(tmp_path)
    (root / "src" / "bundle.min.js").write_text("var a=1;" * 2000)
    ex = ASTExtractor()
    ex.parse_directory(str(root), max_file_bytes=1000)
    assert [os.path.basename(p) for p in ex.oversized_files] == ["bundle.min.js"]
    assert "bundle.min.js" not in {os.path.basename(p) for p in ex.analyzed_files}
    from vibeharness.core.harness import VibeHarnessCommander
    commander = VibeHarnessCommander(config_path=_config(tmp_path, max_file_bytes=1000), execution_mode="mock")
    summary = commander.run_full_pipeline(target_dir=str(root), output_report_path=str(tmp_path / "r.md"))
    assert any("exceed max_file_bytes" in r and "bundle.min.js" in r for r in summary.inconclusive_reasons)
    with pytest.raises(ConfigError, match="max_file_bytes"):
        VibeHarnessCommander(config_path=_config(tmp_path, max_file_bytes=-5), execution_mode="mock")


def test_cli_file_filters_override_config(monkeypatch, tmp_path):
    from vibeharness import cli as main
    seen = {}

    def run(self, **kwargs):
        seen.update(include=self.include_patterns, exclude=self.exclude_patterns, since=self.changed_since)
        from vibeharness.core.models import VibeHarnessSummary
        return VibeHarnessSummary(
            overall_status="INCONCLUSIVE", total_whitebox_findings=0, confirmed_whitebox_bugs=0,
            whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0,
            critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0,
        )

    monkeypatch.setattr(main.VibeHarnessCommander, "run_full_pipeline", run)
    cfg = _config(tmp_path, include=["src/*"], exclude=["vendor/*"])
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), "-m", "mock", "-c", cfg,
                                      "--exclude", "tests/*", "--exclude", "*.min.js", "--changed-since", "HEAD~1"])
    with pytest.raises(SystemExit):
        main.main()
    assert seen == {"include": ["src/*"], "exclude": ["tests/*", "*.min.js"], "since": "HEAD~1"}


def test_changed_since_selects_git_changes_and_rejects_bad_refs(tmp_path):
    import subprocess
    from vibeharness.core.harness import VibeHarnessCommander
    root = _tree(tmp_path)
    git = lambda *a: subprocess.run(["git", *a], cwd=root, check=True, capture_output=True)  # noqa: E731
    git("init", "-q", ".")
    git("-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
    (root / "src" / "app.py").write_text("def f_app(x, y):\n    return x + y\n")  # modified, unstaged
    (root / "src" / "new.py").write_text("def g(x):\n    return x\n")             # untracked
    (root / "vendor" / "lib.py").write_text("def h(x):\n    return x\n")           # modified, outside target
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    changed = commander.changed_files(str(root / "src"), "HEAD")
    assert [os.path.basename(p) for p in changed] == ["app.py", "new.py"]
    commander.changed_since = "HEAD"
    summary = commander.run_full_pipeline(target_dir=str(root / "src"), output_report_path=str(tmp_path / "r.md"))
    assert summary.run is not None and summary.run.file_filters == ["changed-since=HEAD (2 file(s))"]
    assert summary.run.target_git_commit and summary.run.target_git_dirty is True
    with pytest.raises(ValueError, match="cannot be resolved"):
        commander.changed_files(str(root / "src"), "no-such-ref")
    with pytest.raises(ValueError, match="inside a git repository"):
        no_repo = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
        no_repo._git = lambda args, cwd: None  # type: ignore[method-assign]
        no_repo.changed_files(str(root / "src"), "HEAD")


# --- CLI exit codes for every failure path (in-process, so coverage sees vibeharness/cli.py) ----

def _summary(status):
    from vibeharness.core.models import VibeHarnessSummary
    return VibeHarnessSummary(
        overall_status=status, total_whitebox_findings=0, confirmed_whitebox_bugs=0,
        whitebox_tests_passed=0, whitebox_tests_failed=0, total_threats_modeled=0,
        critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=0,
    )


@pytest.mark.parametrize("outcome,code", [
    (LLMGatewayError("no key"), 4),
    (ValueError("--changed-since: git ref 'x' cannot be resolved"), 5),
    (KeyboardInterrupt(), 130),
    (RuntimeError("boom"), 5),
    (_summary("READY_TO_SHIP"), 0),
    (_summary("NEEDS_FIXES"), 1),
    (_summary("BLOCKED_CRITICAL_RISK"), 2),
    (_summary("INCONCLUSIVE"), 3),
    (_summary("WHATEVER"), 3),  # unknown verdicts fail closed
])
def test_cli_maps_every_pipeline_outcome_to_its_exit_code(monkeypatch, tmp_path, capsys, outcome, code):
    from vibeharness import cli

    def run(self, **kwargs):
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), "-m", "mock", "-o", str(tmp_path / "r.md")])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == code
    err = capsys.readouterr().err
    if isinstance(outcome, KeyboardInterrupt):
        assert "Interrupted" in err and "Traceback" not in err
    if type(outcome) is RuntimeError:
        assert "Traceback" in err and "crashed unexpectedly" in err
    if getattr(outcome, "overall_status", None) == "WHATEVER":
        assert "failing closed" in err


def test_cli_rejects_unwritable_output_and_a_directory_as_output(monkeypatch, tmp_path):
    from vibeharness import cli
    for bad in (str(tmp_path / "missing" / "r.md"), str(tmp_path)):
        monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), "-m", "mock", "-o", bad])
        with pytest.raises(SystemExit) as exit_info:
            cli.main()
        assert exit_info.value.code == cli.USAGE_ERROR_EXIT_CODE
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), "-m", "mock", "--sarif", str(tmp_path / "no" / "x.sarif")])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.USAGE_ERROR_EXIT_CODE


def test_root_main_py_is_a_launcher_for_the_cli():
    import main
    from vibeharness import cli
    assert main.main is cli.main


# --- Response cache ---------------------------------------------------------------------------

def test_response_cache_serves_repeat_prompts_without_a_provider_call(fake_live, tmp_path):
    fake = fake_live(lambda s, u: '{"findings": [{"title": "t", "description": "d"}]}')
    cache = tmp_path / "cache"
    gw = LLMGateway(_config(tmp_path, cache_dir=str(cache)), execution_mode="live")
    gw.max_model_calls = 1
    first = gw.generate("whitebox_reviewer_claude", "sys", "audit", required_keys=["findings"])
    assert first["findings"] and first[PROVENANCE_KEY]["cached"] is False
    assert len(list(cache.glob("*.json"))) == 1 and len(fake.calls) == 1
    # Second identical prompt: no provider call, no budget consumed, flagged as cached in the call log
    second = gw.generate("whitebox_reviewer_claude", "sys", "audit", required_keys=["findings"])
    assert second["findings"] == first["findings"] and second[PROVENANCE_KEY]["cached"] is True
    assert len(fake.calls) == 1 and gw.live_calls_attempted == 1
    assert [c.cached for c in gw.call_log] == [False, True] and gw.call_log[-1].mode == "live"
    assert len(gw.cached_calls) == 1
    # A different prompt, model setting or agent temperature is a different key
    gw.max_model_calls = None
    gw.generate("whitebox_reviewer_claude", "sys", "audit something else", required_keys=["findings"])
    assert len(fake.calls) == 2
    # A fresh gateway (new process) reuses the files
    gw2 = LLMGateway(_config(tmp_path, cache_dir=str(cache)), execution_mode="live")
    gw2.generate("whitebox_reviewer_claude", "sys", "audit", required_keys=["findings"])
    assert len(fake.calls) == 2 and gw2.call_log[-1].cached


def test_unusable_answers_are_never_cached_and_bad_entries_are_ignored(fake_live, tmp_path):
    fake = fake_live(lambda s, u: "not json")
    cache = tmp_path / "cache"
    gw = LLMGateway(_config(tmp_path, cache_dir=str(cache), retry_invalid_output=0), execution_mode="hybrid")
    gw.generate("whitebox_reviewer_claude", "sys", "u", required_keys=["findings"])
    assert gw.invalid_calls and not list(cache.glob("*.json"))
    # A corrupt file for the key is treated as a miss
    key = gw._cache_key("claude", gw.models_config["claude"], 0.2, "sys", "u")
    (cache / f"{key}.json").write_text("{corrupt", encoding="utf-8")
    gw.generate("whitebox_reviewer_claude", "sys", "u", required_keys=["findings"])
    assert len(fake.calls) == 2
    with pytest.raises(ConfigError, match="cache_dir"):
        bad = tmp_path / "file.txt"
        bad.write_text("x")
        LLMGateway(_config(tmp_path, cache_dir=str(bad)), execution_mode="mock")


def test_cli_cache_dir_flag_enables_the_cache(monkeypatch, tmp_path):
    from vibeharness import cli
    seen = {}

    def run(self, **kwargs):
        seen["cache_dir"] = self.gateway.cache_dir
        return _summary("INCONCLUSIVE")

    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), "-m", "mock", "--cache-dir", str(tmp_path / "c")])
    with pytest.raises(SystemExit):
        cli.main()
    assert seen["cache_dir"] == str(tmp_path / "c") and (tmp_path / "c").is_dir()


def test_cached_answers_are_labelled_in_the_provenance_table(fake_live, tmp_path):
    from vibeharness.core.harness import VibeHarnessCommander
    fake_live(lambda s, u: '{"findings": [], "verdicts": [], "threats": [], "tests": [], "code": ""}')
    target = tmp_path / "t"
    target.mkdir()
    (target / "m.py").write_text("def f(x):\n    return x\n")
    cfg = _config(tmp_path, cache_dir=str(tmp_path / "cache"))
    VibeHarnessCommander(config_path=cfg, execution_mode="live").run_full_pipeline(
        target_dir=str(target), output_report_path=str(tmp_path / "one.md"))
    VibeHarnessCommander(config_path=cfg, execution_mode="live").run_full_pipeline(
        target_dir=str(target), output_report_path=str(tmp_path / "two.md"))
    assert "response cache" not in (tmp_path / "one.md").read_text(encoding="utf-8")
    assert "🟢 真實（回應快取） ／ live (response cache)" in (tmp_path / "two.md").read_text(encoding="utf-8")


# --- Partial report on a crash -----------------------------------------------------------------

def test_a_crash_writes_a_partial_report_with_everything_so_far(tmp_path, monkeypatch):
    import json
    from vibeharness.core.harness import VibeHarnessCommander
    target = tmp_path / "t"
    target.mkdir()
    (target / "m.py").write_text("def f(x):\n    return x['k']\n")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")

    def boom(*a, **k):
        raise RuntimeError("provider melted")

    monkeypatch.setattr(commander.threat_modeler, "model_system", boom)
    out = tmp_path / "report.md"
    with pytest.raises(RuntimeError):
        commander.run_full_pipeline(target_dir=str(target), output_report_path=str(out))
    partial = json.loads((tmp_path / "report.md.partial.json").read_text(encoding="utf-8"))
    assert partial["partial"] is True and partial["phase_reached"] == 3
    assert partial["error"] == {"type": "RuntimeError", "message": "provider melted"}
    assert partial["agent_calls"] and partial["findings"] and partial["whitebox_results"]
    assert "threat_model" not in partial and not out.exists()
