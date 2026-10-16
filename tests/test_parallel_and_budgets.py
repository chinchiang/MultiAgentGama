"""測試合成的並行、live 模型呼叫預算，以及可設定的檔案／工作者上限。
Concurrency of test synthesis, the live model-call budget, and the configurable file / worker limits."""
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from config_files import load_config, write_config
from vibeharness.core.llm_gateway import LLMGateway, LLMGatewayError, ConfigError, BUDGET_EXHAUSTED_REASON, PROVENANCE_KEY
from vibeharness.core.models import FindingSeverity, ReviewFinding, STRIDECategory, ThreatItem, CodeSymbol
from vibeharness.core.i18n import has_cjk
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
from vibeharness.core.model_output import ANY, OutputSchema

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")


def _config(tmp_path, **global_overrides):
    cfg = load_config()
    cfg["global"].update(global_overrides)
    return write_config(tmp_path, cfg, "agents_config.yaml")


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
    """gateway.generate 的替身，記錄並行峰值；較後面的項目會先回答。
    A gateway.generate stand-in that records peak parallelism; later items answer first."""

    def __init__(self, count, key):
        self.count, self.key = count, key
        self.lock = threading.Lock()
        self.in_flight = self.peak = 0

    def __call__(self, agent_id, system, user, **kwargs):
        index = int(re.search(re.escape(self.key) + r"\s*(\d+)", user).group(1))
        with self.lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        time.sleep(0.05 * (self.count - index))  # 以相反順序完成 ／ finish in reverse order
        with self.lock:
            self.in_flight -= 1
        return {"code": f"def test_{index}():\n    assert {index} == {index}\n", "title": f"for {index}"}


# --- 並行仍保持結果的確定性 -----------------------------------------------------------------
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


def test_a_crashed_test_generation_is_booked_as_an_invalid_call(tmp_path):
    """測試生成在閘道之外當掉時，與其他代理一樣記成一次無效呼叫（證據缺口），而不只是「沒有模型測試」；
    其他發現的測試保留（接線測試；扇出本身見 test_fanout.py）。
    A test generation that crashes outside the gateway is booked as an invalid call (an evidence gap), like the other
    agents, not only as "no model test"; the other findings keep their tests (a wiring test; the fan-out itself is in
    test_fanout.py)."""
    from vibeharness.core.llm_gateway import REASON_CALL_CRASHED
    gen = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock"))

    def crash_on_f1(agent_id, system, user, **kwargs):
        if "defect 1" in user:
            raise RuntimeError("parser exploded")
        return {"code": "def test_ok():\n    assert True\n"}
    gen.gateway.generate = crash_on_f1
    tests = gen.generate_tests_for_findings([_finding(i) for i in range(3)], [], root_dir=str(tmp_path))
    assert [t.source_ref for t in tests if t.test_type == "whitebox_unit"] == ["F0", "F2"]
    (record,) = gen.gateway.invalid_calls
    assert record.agent_id == "whitebox_test_generator"
    assert record.reason.startswith(REASON_CALL_CRASHED) and "RuntimeError: parser exploded" in record.reason
    assert gen.findings_without_model_tests == ["F1"]


def test_a_live_failure_starts_no_queued_reviewer_call(scripted, tmp_path):
    """白箱代理在 live 失敗的那個工作執行緒裡就中止整批：主執行緒還在等前面較慢的呼叫時，
    佇列中的審查呼叫不會開始，也不會付費。
    A white-box agent aborts the batch right in the worker whose live call failed: while the main thread still
    waits on an earlier, slower call, the queued reviewer calls never start and are never paid for."""
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
    from vibeharness.agents.whitebox.multi_reviewer import HeterogeneousReviewerEnsemble
    (tmp_path / "svc.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    symbols = ASTExtractor().parse_file(str(tmp_path / "svc.py"))
    transport = scripted({
        "whitebox_reviewer_claude": lambda request: time.sleep(0.5) or {"findings": []},
        "whitebox_reviewer_deepseek": RuntimeError("provider down"),
        "*": {"findings": []},
    })
    gateway = LLMGateway(_config(tmp_path, max_concurrent_calls=2), execution_mode="live", transport=transport)
    ensemble = HeterogeneousReviewerEnsemble(gateway)
    assert [r["agent_id"] for r in ensemble.reviewer_agents][:2] == ["whitebox_reviewer_claude", "whitebox_reviewer_deepseek"]
    with pytest.raises(LLMGatewayError):
        ensemble.review_symbols(symbols, root_dir=str(tmp_path))
    assert {r.agent_id for r in transport.requests} == {"whitebox_reviewer_claude", "whitebox_reviewer_deepseek"}


# --- live 模型呼叫預算 ----------------------------------------------------------------------
# --- Live model-call budget ----------------------------------------------------------------------

def test_budget_falls_back_to_simulation_in_hybrid_mode(fake_live, tmp_path):
    fake = fake_live(lambda s, u: json.dumps({"findings": []}))
    gw = LLMGateway(_config(tmp_path, max_model_calls=2), execution_mode="hybrid")
    for _ in range(4):
        gw.generate("whitebox_reviewer_claude", "s", "u", schema=OutputSchema(required={"findings": ANY}))
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
    """這些設定過去只在發出呼叫時才讀取：litellm 拒絕它們，而 hybrid 模式把失敗登記為
    「live invocation failed」，然後默默改跑模擬引擎。
    These used to be read only when a call was made: litellm rejected them, and hybrid mode booked
    the failure as "live invocation failed" and silently ran the simulation engine instead."""
    with pytest.raises(ConfigError, match=key):
        LLMGateway(_config(tmp_path, **{key: value}))


def test_invalid_per_model_tokens_and_agent_temperature_are_config_errors(tmp_path):
    cfg = load_config()
    bad_model = dict(cfg, models=dict(cfg["models"], claude=dict(cfg["models"]["claude"], max_output_tokens="lots")))
    path = write_config(tmp_path, bad_model, "m.yaml")
    with pytest.raises(ConfigError, match="models.claude.max_output_tokens"):
        LLMGateway(path, execution_mode="mock")
    reviewer = dict(cfg["agents"]["whitebox_reviewer_claude"], temperature=3)
    bad_agent = dict(cfg, agents=dict(cfg["agents"], whitebox_reviewer_claude=reviewer))
    path = write_config(tmp_path, bad_agent, "a.yaml")
    with pytest.raises(ConfigError, match="whitebox_reviewer_claude.temperature"):
        LLMGateway(path, execution_mode="mock")
    # 隨附的設定檔本身是有效的，而且預期數字的地方給浮點數也沒問題
    # The shipped config itself is valid, and floats are fine where a number is expected
    LLMGateway(_config(tmp_path, timeout_seconds=12.5), execution_mode="mock")


@pytest.mark.parametrize("value", [-1, "10", True, 2.5])
def test_invalid_max_files_in_config_is_a_config_error(tmp_path, value):
    """CLI 已經會拒絕錯誤的 --max-files；設定檔路徑也不得悄悄接受負的切片
    （會分析除了一個以外的所有檔案）或字串（int() 剛好能轉換）。
    The CLI already rejects a bad --max-files; the config path must not quietly accept a negative
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


def test_reviewers_on_one_model_have_one_distinct_model(tmp_path):
    """四個審查代理共用一個模型時只算一個不同的模型；閘門因此記為缺口（訊息與接線見 test_quality_gate.py，OWASP LLM07:2026）。
    Four reviewer agents on one model count as one distinct model; the gate therefore records a gap (message and
    wiring in test_quality_gate.py, OWASP LLM07:2026)."""
    from vibeharness.core.harness import VibeHarnessCommander
    cfg = load_config()
    for agent_id, meta in cfg["agents"].items():
        if agent_id.startswith(("whitebox_reviewer_", "whitebox_verifier_")):
            meta["model_alias"] = "gemini"
    path = write_config(tmp_path, cfg, "single.yaml")
    commander = VibeHarnessCommander(config_path=path, execution_mode="mock")
    assert commander.multi_reviewer.distinct_models == ["gemini"]
    assert len(commander.multi_reviewer.reviewer_agents) == 4


# --- 來自設定檔與 CLI 的 max_files ----------------------------------------------------------
# --- max_files from config and CLI ---------------------------------------------------------------


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


# --- 無法使用的回答之後再問一次 -------------------------------------------------------------
# --- Re-asking after an unusable answer -------------------------------------------------------

def test_unusable_answer_is_re_asked_once_and_the_retry_can_succeed(fake_live):
    """一次性的格式失誤（JSON 周圍的散文、缺一個鍵）過去會讓整次執行變成
    INCONCLUSIVE；閘道現在會指出問題並再問一次，之後才登記為 `invalid`。
    One-off format slips (prose around the JSON, a missing key) used to turn the whole run
    INCONCLUSIVE; the gateway now re-asks once, naming the problem, before booking `invalid`."""
    answers = iter(["Sure! Here is my analysis without any JSON.", '{"findings": []}'])
    prompts = []

    def responder(system, user):
        prompts.append(user)
        return next(answers)

    fake = fake_live(responder)
    gw = LLMGateway(CONFIG, execution_mode="live")
    resp = gw.generate("whitebox_reviewer_claude", "sys", "audit this", schema=OutputSchema(required={"findings": ANY}))
    assert gw.is_usable(resp) and resp["findings"] == []
    assert [c.mode for c in gw.call_log] == ["retried", "live"]
    assert "could not be used (response is not valid JSON)" in prompts[1] and prompts[1].startswith("audit this")
    assert not has_cjk(prompts[1])  # 雙語原因只以英文送達模型 ／ the bilingual reason reaches the model in English only
    assert len(fake.calls) == 2 and gw.live_calls_attempted == 2
    assert not gw.invalid_calls and len(gw.retried_calls) == 1


def test_re_ask_respects_the_call_budget_and_is_configurable(fake_live, tmp_path):
    fake = fake_live(lambda s, u: "not json")
    gw = LLMGateway(CONFIG, execution_mode="hybrid")
    gw.max_model_calls = 1
    gw.generate("whitebox_reviewer_claude", "sys", "u", schema=OutputSchema(required={"findings": ANY}))
    # 沒有預算可以再問：單次嘗試後登記為 invalid
    # No budget left for a re-ask: booked invalid after the single attempt
    assert [c.mode for c in gw.call_log] == ["invalid"] and len(fake.calls) == 1
    gw = LLMGateway(_config(tmp_path, retry_invalid_output=0), execution_mode="hybrid")
    gw.generate("whitebox_reviewer_claude", "sys", "u", schema=OutputSchema(required={"findings": ANY}))
    assert [c.mode for c in gw.call_log] == ["invalid"]
    gw = LLMGateway(_config(tmp_path, retry_invalid_output=2), execution_mode="hybrid")
    gw.generate("whitebox_reviewer_claude", "sys", "u", schema=OutputSchema(required={"findings": ANY}))
    assert [c.mode for c in gw.call_log] == ["retried", "retried", "invalid"]
    # 非 JSON 的呼叫（測試產生器的修復提示詞）永遠不會再問
    # Non-JSON calls (the test-generator heal prompt) are never re-asked
    gw = LLMGateway(CONFIG, execution_mode="live")
    gw.generate("whitebox_test_generator", "sys", "u", json_output=False)
    assert [c.mode for c in gw.call_log] == ["live"]
    with pytest.raises(ConfigError, match="retry_invalid_output"):
        LLMGateway(_config(tmp_path, retry_invalid_output="twice"))


def test_extra_params_are_passed_to_litellm_and_validated(fake_live, tmp_path):
    cfg = load_config()
    claude = dict(cfg["models"]["claude"], extra_params={"thinking": {"type": "disabled"}, "reasoning_effort": "low"})
    good = dict(cfg, models=dict(cfg["models"], claude=claude))
    path = write_config(tmp_path, good, "good.yaml")
    fake = fake_live(lambda s, u: '{"findings": []}')
    LLMGateway(path, execution_mode="live").generate("whitebox_reviewer_claude", "s", "u", schema=OutputSchema(required={"findings": ANY}))
    assert fake.calls[0]["thinking"] == {"type": "disabled"} and fake.calls[0]["reasoning_effort"] == "low"
    bad = dict(cfg, models=dict(cfg["models"], claude=dict(cfg["models"]["claude"], extra_params=["thinking"])))
    path = write_config(tmp_path, bad, "good.yaml")
    with pytest.raises(ConfigError, match="extra_params"):
        LLMGateway(path, execution_mode="mock")


# --- 檔案選取 -------------------------------------------------------------------------------
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
    # 缺口本身由 test_quality_gate.py 的接線測試涵蓋 ／ the gap itself is covered by the wiring test in test_quality_gate.py
    from vibeharness.core.harness import VibeHarnessCommander
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
    (root / "src" / "app.py").write_text("def f_app(x, y):\n    return x + y\n")  # 已修改，未暫存 ／ modified, unstaged
    (root / "src" / "new.py").write_text("def g(x):\n    return x\n")             # 未追蹤 ／ untracked
    (root / "vendor" / "lib.py").write_text("def h(x):\n    return x\n")           # 已修改，在目標之外 ／ modified, outside target
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


# --- 每條失敗路徑的 CLI 結束代碼（行程內執行，讓覆蓋率看得到 vibeharness/cli.py）----
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
    (_summary("WHATEVER"), 3),  # 未知的判定結果採保守失敗 ／ unknown verdicts fail closed
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


# --- 回應快取 -------------------------------------------------------------------------------
# --- Response cache ---------------------------------------------------------------------------

def test_response_cache_serves_repeat_prompts_without_a_provider_call(fake_live, tmp_path):
    fake = fake_live(lambda s, u: '{"findings": [{"title": "t", "description": "d"}]}')
    cache = tmp_path / "cache"
    gw = LLMGateway(_config(tmp_path, cache_dir=str(cache)), execution_mode="live")
    gw.max_model_calls = 1
    first = gw.generate("whitebox_reviewer_claude", "sys", "audit", schema=OutputSchema(required={"findings": ANY}))
    assert first["findings"] and first[PROVENANCE_KEY]["cached"] is False
    assert len(list(cache.glob("*.json"))) == 1 and len(fake.calls) == 1
    # 第二次相同的提示詞：沒有供應商呼叫、不消耗預算，在呼叫紀錄中標示為已快取
    # Second identical prompt: no provider call, no budget consumed, flagged as cached in the call log
    second = gw.generate("whitebox_reviewer_claude", "sys", "audit", schema=OutputSchema(required={"findings": ANY}))
    assert second["findings"] == first["findings"] and second[PROVENANCE_KEY]["cached"] is True
    assert len(fake.calls) == 1 and gw.live_calls_attempted == 1
    assert [c.cached for c in gw.call_log] == [False, True] and gw.call_log[-1].mode == "live"
    assert len(gw.cached_calls) == 1
    # 不同的提示詞、模型設定或代理溫度就是不同的鍵
    # A different prompt, model setting or agent temperature is a different key
    gw.max_model_calls = None
    gw.generate("whitebox_reviewer_claude", "sys", "audit something else", schema=OutputSchema(required={"findings": ANY}))
    assert len(fake.calls) == 2
    # 新的閘道（新行程）會重用這些檔案
    # A fresh gateway (new process) reuses the files
    gw2 = LLMGateway(_config(tmp_path, cache_dir=str(cache)), execution_mode="live")
    gw2.generate("whitebox_reviewer_claude", "sys", "audit", schema=OutputSchema(required={"findings": ANY}))
    assert len(fake.calls) == 2 and gw2.call_log[-1].cached


def test_unusable_answers_are_never_cached_and_bad_entries_are_ignored(fake_live, tmp_path):
    fake = fake_live(lambda s, u: "not json")
    cache = tmp_path / "cache"
    gw = LLMGateway(_config(tmp_path, cache_dir=str(cache), retry_invalid_output=0), execution_mode="hybrid")
    gw.generate("whitebox_reviewer_claude", "sys", "u", schema=OutputSchema(required={"findings": ANY}))
    assert gw.invalid_calls and not list(cache.glob("*.json"))
    # 該鍵對應的檔案毀損時視為未命中
    # A corrupt file for the key is treated as a miss
    key = gw._cache_key("claude", gw.models_config["claude"], 0.2, "sys", "u")
    (cache / f"{key}.json").write_text("{corrupt", encoding="utf-8")
    gw.generate("whitebox_reviewer_claude", "sys", "u", schema=OutputSchema(required={"findings": ANY}))
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


# --- 當機時的部分報告 -----------------------------------------------------------------------
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


def test_null_retry_invalid_output_keeps_the_default(tmp_path):
    """`retry_invalid_output: null` 與未設定相同，用預設值；只有明確的 0 才關閉重問。
    `retry_invalid_output: null` behaves like an unset key (the default); only an explicit 0 disables re-asking."""
    from vibeharness.core.llm_gateway import DEFAULT_RETRY_INVALID_OUTPUT
    assert LLMGateway(_config(tmp_path, retry_invalid_output=None), execution_mode="hybrid").retry_invalid_output \
        == DEFAULT_RETRY_INVALID_OUTPUT
