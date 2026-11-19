"""品質閘門（core/gate.py）：只透過 evaluate() 測試，不需要 pipeline、閘道或沙盒；最後一個測試跑一次 mock
pipeline，確認各來源的事實確實送進閘門。
The quality gate (core/gate.py): tested only through evaluate(), with no pipeline, gateway or sandbox; the last
test runs one mock pipeline to check that each source's facts actually reach the gate."""
from dataclasses import replace

import pytest

from config_files import load_config, write_config
from vibeharness.core.baseline import Baseline, breach_key, finding_key, static_key
from vibeharness.core.gate import (
    ExecutionEvidence, GapCode, GateEvidence, GateLimits, ReviewEvidence, ScopeDisclosure,
)
from vibeharness.core.gate import evaluate as gate_evaluate
from vibeharness.core.llm_gateway import BUDGET_EXHAUSTED_REASON, CACHE_MISS_REASON
from vibeharness.core.models import (
    AgentCallRecord, FindingSeverity, GeneratedTest, MutantResult, MutationReport, ReviewFinding, STRIDECategory,
    StaticFinding, TestExecutionResult, TestStatus, ThreatItem, ThreatModelReport,
)
from vibeharness.core.tally import tally_evidence
from vibeharness.core.verdict import Verdict


TARGET = "/srv/app"


def _threat(tid="THREAT-01", title="Mass assignment"):
    return ThreatItem(
        threat_id=tid, stride_category=STRIDECategory.TAMPERING, title=title, description="d", asset_at_risk="a",
        attack_vector="POST /users", trust_boundary_crossed="t", severity=FindingSeverity.HIGH,
        attack_scenario="s", test_verification_goal="g",
    )


def _result(tid, status=TestStatus.PASSED, exploit=False, source_ref=None, test_type="whitebox_unit"):
    return TestExecutionResult(test_id=tid, test_type=test_type, status=status, is_security_exploit_confirmed=exploit,
                               source_ref=source_ref, failure_reason=f"{tid} failed" if status == TestStatus.FAILED else None)


def _test(tid, language="python", source_ref=None):
    return GeneratedTest(test_id=tid, test_type="whitebox_unit", target_component="c", title="t", code="",
                         rationale="r", expected_outcome="e", language=language, source_ref=source_ref)


def _rule_hit(severity=FindingSeverity.HIGH, integrity=False, evidence="pickle.load(f)"):
    return StaticFinding(rule_id="VH-AI-001", title="Unsafe load", severity=severity, file_path=f"{TARGET}/app.py",
                         line_number=3, evidence=evidence, remediation="use safetensors", owasp_mapping="LLM05",
                         affects_review_integrity=integrity)


def _finding(fid="WB-GPT-01"):
    return ReviewFinding(finding_id=fid, reviewer_name="r", model_alias="gpt", file_path=f"{TARGET}/app.py",
                         symbol_name="update_user", severity=FindingSeverity.HIGH, title="No null check",
                         description="d", root_cause="rc", suspected_vibe_flaw="f", suggested_test_scenario="s")


def _call(mode="live", reason=None, agent="whitebox_reviewer_gpt"):
    return AgentCallRecord(agent_id=agent, model_alias="gpt", model_name="gpt-x", mode=mode, reason=reason)


def clean(**changes):
    """一次沒有任何缺口、也沒有任何已執行缺陷的執行：判定結果是 READY_TO_SHIP。
    A run with no gap and no executed defect: the verdict is READY_TO_SHIP."""
    evidence = GateEvidence(
        threat_report=ThreatModelReport(system_description="app", threats=[_threat()]),
        tally=tally_evidence(),  # 由 evaluate() 依最後的證據重建 ／ rebuilt by evaluate() from the final evidence
        limits=GateLimits(max_model_calls=10, max_files=200, max_file_bytes=1000, mutation_min_score=80.0),
        call_log=[_call()],
        review=ReviewEvidence(reviewers_configured=True, reviewer_models=["gpt", "claude"]),
        scope=ScopeDisclosure(symbols_found=True, detected_langs=["Python"]),
        execution=ExecutionEvidence(wb_tests=[_test("WB-T-01")], wb_results=[_result("WB-T-01")],
                                    bb_tests=[_test("BB-T-01", source_ref="THREAT-01")], bb_results=[_result("BB-T-01", test_type="blackbox_security")]),
    )
    return replace(evidence, **changes)


def evaluate(evidence, baseline=None):
    """像 harness 一樣，從證據本身建出證據計數（含未測試的威脅與基準比對），再交給品質閘門。
    Like the harness, build the Evidence tally from the evidence itself (untested threats and the baseline comparison
    included), then hand it to the Quality Gate."""
    ex = evidence.execution
    tally = tally_evidence(wb_results=ex.wb_results, bb_tests=ex.bb_tests, bb_results=ex.bb_results,
                           static_findings=evidence.static_findings, threats=evidence.threat_report.threats,
                           confirmed_findings=evidence.review.confirmed_findings, target_dir=TARGET, baseline=baseline)
    return gate_evaluate(replace(evidence, tally=tally))


def _with_threat(evidence, tid):
    """加一個沒有任何黑箱測試指向的威脅（未測試的威脅）。
    Add a threat no black-box test points at (an untested threat)."""
    report = evidence.threat_report
    return replace(evidence, threat_report=report.model_copy(update={"threats": [*report.threats, _threat(tid, f"{tid} title")]}))


def _with(evidence, part, **changes):
    return replace(evidence, **{part: replace(getattr(evidence, part), **changes)})


def _codes(result):
    return [gap.code for gap in result.gaps]


# --- 判定階梯 ／ the verdict ladder ---------------------------------------------------------------

def test_clean_run_is_ready_to_ship():
    result = evaluate(clean())
    assert result.verdict is Verdict.READY_TO_SHIP
    assert result.gaps == [] and result.reasons == []
    assert len(result.recommendations) == 1 and "regression guards" in result.recommendations[0]


def test_a_breach_blocks_even_with_failures_and_gaps():
    evidence = _with(_with_threat(clean(), "THREAT-09"), "execution",
                     wb_results=[_result("WB-T-01", TestStatus.FAILED)],
                     bb_results=[_result("BB-T-01", TestStatus.FAILED, exploit=True, source_ref="THREAT-01")])
    result = evaluate(evidence)
    assert result.verdict is Verdict.BLOCKED_CRITICAL_RISK


def test_a_failed_whitebox_test_needs_fixes():
    result = evaluate(_with(clean(), "execution", wb_results=[_result("WB-T-01", TestStatus.FAILED)]))
    assert result.verdict is Verdict.NEEDS_FIXES


@pytest.mark.parametrize("severity, verdict", [
    (FindingSeverity.CRITICAL, Verdict.NEEDS_FIXES),
    (FindingSeverity.HIGH, Verdict.NEEDS_FIXES),
    (FindingSeverity.MEDIUM, Verdict.READY_TO_SHIP),
    (FindingSeverity.LOW, Verdict.READY_TO_SHIP),
])
def test_only_high_or_critical_rule_hits_block(severity, verdict):
    result = evaluate(clean(static_findings=[_rule_hit(severity)]))
    assert result.verdict is verdict


def test_model_findings_alone_never_fail_the_gate():
    """沒有測試確認的模型發現只是假設 ／ A model finding no test confirmed is a hypothesis."""
    result = evaluate(_with(clean(), "review", confirmed_findings=[_finding()]))
    assert result.verdict is Verdict.READY_TO_SHIP


# --- 證據缺口 ／ evidence gaps ---------------------------------------------------------------------

GAP_CASES = {
    GapCode.BUDGET_EXHAUSTED: lambda e: replace(e, call_log=[_call("simulated", BUDGET_EXHAUSTED_REASON)]),
    GapCode.CACHE_MISS: lambda e: replace(e, call_log=[_call("simulated", CACHE_MISS_REASON)]),
    GapCode.SIMULATED: lambda e: replace(e, call_log=[_call("simulated", "mock")]),
    GapCode.INVALID_OUTPUT: lambda e: replace(e, call_log=[_call("invalid", "missing keys")]),
    GapCode.FINDINGS_WITHOUT_MODEL_TESTS: lambda e: _with(e, "review", findings_without_model_tests=["WB-GPT-01"]),
    GapCode.REVIEW_INTEGRITY: lambda e: replace(e, static_findings=[_rule_hit(FindingSeverity.MEDIUM, integrity=True)]),
    GapCode.NO_REVIEWERS: lambda e: _with(e, "review", reviewers_configured=False, reviewer_models=[]),
    GapCode.SINGLE_REVIEWER_MODEL: lambda e: _with(e, "review", reviewer_models=["gpt"]),
    GapCode.NO_SYMBOLS: lambda e: _with(e, "scope", symbols_found=False),
    GapCode.PARSE_FAILURES: lambda e: _with(e, "scope", parse_failures=["bad.py"]),
    GapCode.INCOMPLETE_SCAN: lambda e: _with(e, "scope", incomplete_files=["huge.py"]),
    GapCode.OVERSIZED_FILES: lambda e: _with(e, "scope", oversized_files=["/srv/app/big.py"]),
    GapCode.MAX_FILES_SKIPPED: lambda e: _with(e, "scope", skipped_files=["z.py"]),
    GapCode.TESTS_NOT_RUN: lambda e: _with(e, "execution", wb_results=[_result("WB-T-01", TestStatus.ERROR)]),
    GapCode.MUTATION_NO_CONCLUSION: lambda e: _with(e, "execution", mutation_report=MutationReport(skipped_reason="no tests")),
    GapCode.MUTATION_BELOW_THRESHOLD: lambda e: _with(e, "execution", mutation_report=MutationReport(score=50.0, survived=1)),
    GapCode.MUTATION_TRUNCATED: lambda e: _with(e, "execution", mutation_report=MutationReport(score=100.0, truncated=True)),
    GapCode.JS_NO_TESTS: lambda e: _with(e, "scope", detected_langs=["Python", "TypeScript/JavaScript"]),
    GapCode.JS_TESTS_NOT_RUN: lambda e: _with(_with(e, "scope", detected_langs=["TypeScript/JavaScript"]), "execution",
                                              wb_tests=[_test("WB-T-01", "javascript")], js_runner_problem="no node"),
    GapCode.TS_TESTS_NOT_RUN: lambda e: _with(_with(e, "scope", detected_langs=["TypeScript/JavaScript"]), "execution",
                                              wb_tests=[_test("WB-T-01", "typescript")], ts_problem="node 20"),
    GapCode.UNSUPPORTED_LANGUAGES: lambda e: _with(e, "scope", unsupported_count=3, unsupported_languages={"Go": 3},
                                                   unsupported_files=["a.go"]),
    GapCode.CONFIG_FILES_NOT_SCANNED: lambda e: _with(e, "scope", config_files_not_fully_scanned=[".env"]),
    GapCode.UNCLASSIFIED_BLACKBOX_FAILURES: lambda e: _with(e, "execution", bb_results=[
        _result("BB-T-01", TestStatus.FAILED, test_type="blackbox_security")]),
    GapCode.NO_WHITEBOX_TESTS: lambda e: _with(e, "execution", wb_results=[]),
    GapCode.NO_THREATS: lambda e: replace(e, threat_report=ThreatModelReport(system_description="app")),
    GapCode.UNTESTED_THREATS: lambda e: _with_threat(e, "THREAT-02"),
}


def test_every_gap_code_has_a_case():
    assert set(GAP_CASES) == set(GapCode)


@pytest.mark.parametrize("code", list(GapCode), ids=lambda c: c.value)
def test_each_gap_makes_an_otherwise_clean_run_inconclusive(code):
    result = evaluate(GAP_CASES[code](clean()))
    assert code in _codes(result)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reasons == [gap.message for gap in result.gaps]
    assert "Close the evidence gaps" in result.recommendations[-1]


def test_gaps_come_in_declaration_order():
    evidence = clean()
    for code in reversed(list(GapCode)):
        evidence = GAP_CASES[code](evidence)
    order = list(GapCode)
    codes = _codes(evaluate(evidence))
    assert len(codes) > 10
    assert codes == sorted(codes, key=order.index)


def test_js_gaps_are_exclusive():
    """沒有 JS 測試、無法執行、TS 不支援三者只報最先成立的一個 ／ Only the first of no tests / cannot run / no TS is reported."""
    evidence = _with(_with(clean(), "scope", detected_langs=["TypeScript/JavaScript"]), "execution",
                     wb_tests=[_test("WB-T-01", "typescript")], js_runner_problem="no node", ts_problem="node 20")
    codes = _codes(evaluate(evidence))
    assert GapCode.JS_TESTS_NOT_RUN in codes and GapCode.TS_TESTS_NOT_RUN not in codes


def test_no_reviewers_is_not_also_reported_as_a_single_model():
    codes = _codes(evaluate(GAP_CASES[GapCode.NO_REVIEWERS](clean())))
    assert GapCode.NO_REVIEWERS in codes and GapCode.SINGLE_REVIEWER_MODEL not in codes


@pytest.mark.parametrize("arbitration, word", [(True, "confirmed"), (False, "unverified")])
def test_findings_without_model_tests_say_whether_they_were_verified(arbitration, word):
    evidence = _with(clean(), "review", findings_without_model_tests=["WB-GPT-01"], arbitration_applied=arbitration)
    gap = next(g for g in evaluate(evidence).gaps if g.code is GapCode.FINDINGS_WITHOUT_MODEL_TESTS)
    assert f"1 {word} finding(s)" in gap.message


def test_gap_messages_quote_the_limits():
    evidence = _with(clean(), "scope", oversized_files=["/srv/app/big.py"], skipped_files=["z.py"])
    reasons = " ".join(evaluate(evidence).reasons)
    assert "max_file_bytes (1000)" in reasons and "big.py" in reasons and "max_files limit (200)" in reasons


def test_gap_messages_name_the_budget_the_model_and_each_invalid_call():
    evidence = _with(clean(call_log=[
        _call("simulated", BUDGET_EXHAUSTED_REASON),
        _call("invalid", "agent call crashed before producing output: ValueError: boom", agent="whitebox_reviewer_glm"),
        _call("invalid", None, agent="blackbox_threat_modeler"),
    ]), "review", reviewer_models=["gemini"])
    result = evaluate(replace(evidence, limits=replace(evidence.limits, max_model_calls=1)))
    reasons = {gap.code: gap.message for gap in result.gaps}
    assert "max_model_calls budget (1) was exhausted; 1 later agent call(s)" in reasons[GapCode.BUDGET_EXHAUSTED]
    assert "Only one distinct reviewer model (gemini)" in reasons[GapCode.SINGLE_REVIEWER_MODEL]
    assert reasons[GapCode.INVALID_OUTPUT].endswith(
        ": blackbox_threat_modeler; whitebox_reviewer_glm (agent call crashed before producing output: ValueError: boom)")


def test_unsupported_language_gap_counts_per_language_in_both_languages():
    evidence = _with(clean(), "scope", unsupported_count=3, unsupported_languages={"java": 1, "go": 2},
                     unsupported_files=["/srv/app/a.go", "/srv/app/b.go", "/srv/app/c.java"])
    gap = next(g for g in evaluate(evidence).gaps if g.code is GapCode.UNSUPPORTED_LANGUAGES)
    assert "3 source file(s) in unsupported languages (go: 2, java: 1) were not analyzed: a.go, b.go, c.java" in gap.message
    assert "不支援語言" in gap.message


def test_no_js_gap_when_no_js_was_detected():
    evidence = _with(clean(), "scope", detected_langs=["Python", "Go"], unsupported_count=1, unsupported_languages={"go": 1})
    assert not any("JS/TS" in reason for reason in evaluate(evidence).reasons)


def test_modeled_critical_threats_alone_never_block():
    """建模出的威脅是假設：只有已確認的突破能阻擋 ／ Modeled threats are hypotheses: only a confirmed breach blocks."""
    threats = [_threat(f"THREAT-0{i}") for i in range(4)]
    for t in threats:
        t.severity = FindingSeverity.CRITICAL
    # 每個威脅都有攻擊測試，所以唯一的缺口是無效的模型回答 ／ Every threat has an attack test, so the only gap is the invalid answer
    attacks = [_test(f"BB-T-0{i}", source_ref=t.threat_id) for i, t in enumerate(threats)]
    evidence = _with(clean(threat_report=ThreatModelReport(system_description="app", threats=threats),
                           call_log=[_call("invalid", "not json", agent="blackbox_threat_modeler")]),
                     "execution", bb_tests=attacks)
    result = evaluate(evidence)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert _codes(result) == [GapCode.INVALID_OUTPUT]


def test_mutation_at_the_threshold_is_not_a_gap():
    evidence = _with(clean(), "execution", mutation_report=MutationReport(score=80.0))
    assert evaluate(evidence).verdict is Verdict.READY_TO_SHIP


# --- 基準 ／ baseline -----------------------------------------------------------------------------

def test_known_breach_and_new_blocking_rule_hit_needs_fixes():
    threat = _threat()
    breach = _result("BB-T-01", TestStatus.FAILED, exploit=True, source_ref=threat.threat_id, test_type="blackbox_security")
    baseline = Baseline(path="old.json", breaches={breach_key(breach, threat)})
    evidence = _with(clean(static_findings=[_rule_hit()]), "execution", bb_results=[breach])
    result = evaluate(evidence, baseline=baseline)
    assert result.verdict is Verdict.NEEDS_FIXES
    assert not any("Fix confirmed security breach" in r for r in result.recommendations)
    assert "already in the baseline" in result.recommendations[-1] and "`BB-T-01`" in result.recommendations[-1]


def test_a_known_whitebox_failure_and_rule_hit_do_not_count():
    finding, hit = _finding(), _rule_hit()
    failed = _result("WB-T-01", TestStatus.FAILED, source_ref=finding.finding_id)
    baseline = Baseline(path="old.json", findings={finding_key(finding, TARGET)}, static={static_key(hit, TARGET)})
    evidence = _with(_with(clean(static_findings=[hit]), "review", confirmed_findings=[finding]),
                     "execution", wb_results=[failed])
    result = evaluate(evidence, baseline=baseline)
    assert result.verdict is Verdict.READY_TO_SHIP
    assert "already in the baseline" in result.recommendations[-1]


def test_a_new_problem_still_counts_under_a_baseline():
    baseline = Baseline(path="old.json", static={"something-else"})
    result = evaluate(clean(static_findings=[_rule_hit()]), baseline=baseline)
    assert result.verdict is Verdict.NEEDS_FIXES
    assert not any("already in the baseline" in r for r in result.recommendations)


# --- 建議 ／ recommendations ---------------------------------------------------------------------

def test_recommendations_are_most_urgent_first():
    evidence = _with(_with_threat(clean(static_findings=[_rule_hit()]), "THREAT-02"), "execution",
                     wb_results=[_result("WB-T-01", TestStatus.FAILED)],
                     bb_results=[_result("BB-T-02", TestStatus.FAILED, test_type="blackbox_security"),
                                 _result("BB-T-01", TestStatus.FAILED, exploit=True, source_ref="THREAT-01")])
    recs = evaluate(evidence).recommendations
    prefixes = ["Fix confirmed security breach", "Fix `VH-AI-001`", "Fix defect exposed by", "Investigate black-box crash",
                "Write or synthesize tests", "Close the evidence gaps"]
    for rec, prefix in zip(recs, prefixes, strict=True):
        assert prefix in rec
    assert "THREAT-01 Mass assignment" in recs[0]


def test_surviving_mutants_get_a_recommendation():
    mutants = [MutantResult(file="app.py", line=n, operator="comparison", original="a", mutated="b", status="survived")
               for n in (1, 2, 3, 4)]
    evidence = _with(clean(), "execution", mutation_report=MutationReport(score=90.0, survived=4, mutants=mutants))
    result = evaluate(evidence)
    assert result.verdict is Verdict.READY_TO_SHIP
    assert "app.py:1, app.py:2, app.py:3 so the tests catch these 4 surviving mutant(s)" in result.recommendations[-1]


# --- pipeline 接線 ／ pipeline wiring ------------------------------------------------------------

def test_pipeline_wires_scope_limits_and_review_facts_into_the_gate(tmp_path, monkeypatch):
    """一次 mock 執行：擷取器、掃描器、設定上限與審查名單的事實都必須出現在閘門的缺口裡（訊息規則本身由上面的測試涵蓋）。
    One mock run: the facts of the extractor, the scanner, the configured limits and the reviewer roster must all
    reach the gate's gaps (the message rules themselves are covered by the tests above)."""
    from vibeharness.agents.whitebox.ai_static_scanner import AISecurityStaticScanner
    from vibeharness.core.harness import VibeHarnessCommander
    cfg = load_config()
    cfg["global"].update(max_files=4, max_file_bytes=1000)
    for agent_id, meta in cfg["agents"].items():
        if agent_id.startswith(("whitebox_reviewer_", "whitebox_verifier_")):
            meta["model_alias"] = "gemini"
    config = write_config(tmp_path, cfg, "single.yaml")

    target = tmp_path / "t"
    target.mkdir()
    files = {"app.py": "def add(a, b):\n    return a + b\n", "bad.py": "def broken(:\n", "big.py": "x = 1\n" * 400,
             "m1.py": "def f1(x):\n    return x\n", "m2.py": "def f2(x):\n    return x\n", "m3.py": "def f3(x):\n    return x\n",
             "main.go": "package main\n\nfunc main() {}\n", "a.yaml": "k: v\n", "big.json": '{"k": "' + "v" * 2000 + '"}'}
    for name, text in files.items():
        (target / name).write_text(text, encoding="utf-8")
    original = AISecurityStaticScanner.scan_files

    def scan_files(self, paths):
        findings = original(self, paths)
        self.incomplete_files = [str(target / "app.py")]
        return findings
    monkeypatch.setattr(AISecurityStaticScanner, "scan_files", scan_files)

    commander = VibeHarnessCommander(config_path=config, execution_mode="mock")
    summary = commander.run_full_pipeline(target_dir=str(target), output_report_path=str(tmp_path / "r.md"))
    assert summary.overall_status != "READY_TO_SHIP"
    reasons = "\n".join(summary.inconclusive_reasons)
    for expected in (
        "Only one distinct reviewer model (gemini)",
        "1 source file(s) could not be parsed",
        "could not fully scan 1 source file(s)",
        "1 source file(s) exceed max_file_bytes (1000) and were not analyzed: big.py",
        "1 source file(s) were skipped by the max_files limit (4)",
        "1 source file(s) in unsupported languages (go: 1) were not analyzed: main.go",
        "1 configuration-like file(s) were not fully secret-scanned",
    ):
        assert expected in reasons, expected
