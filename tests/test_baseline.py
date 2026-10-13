"""--baseline：只有前一份報告未包含的問題才決定判定結果。
--baseline: only problems the previous report did not contain decide the verdict."""
import json
import os
import sys

import pytest
import yaml

from vibeharness.core import baseline as bl
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.models import (
    FindingSeverity, ReviewFinding, STRIDECategory, StaticFinding, TestExecutionResult, TestStatus, ThreatItem,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
EXAMPLES = os.path.join(REPO_ROOT, "examples")


def _finding(fid="WB-CLA-01", title="Unchecked null in get_user", symbol="get_user_profile", path=None):
    return ReviewFinding(
        finding_id=fid, reviewer_name="Claude", model_alias="claude", file_path=path or os.path.join(EXAMPLES, "vibe_sample_app.py"),
        symbol_name=symbol, line_number=33, severity=FindingSeverity.HIGH, title=title, description="d", root_cause="r",
        suspected_vibe_flaw="v", suggested_test_scenario="s",
    )


def _threat(tid="THREAT-01", title="BOLA on update", vector="PUT /api/users/{id}"):
    return ThreatItem(
        threat_id=tid, stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE, title=title, description="",
        asset_at_risk="a", attack_vector=vector, trust_boundary_crossed="b", severity=FindingSeverity.CRITICAL,
        attack_scenario="", test_verification_goal="",
    )


# --- 載入 ------------------------------------------------------------------------------------
# --- Loading ---------------------------------------------------------------------------------

def test_load_baseline_rejects_partial_reports_and_foreign_files(tmp_path):
    partial = tmp_path / "r.md.partial.json"
    partial.write_text(json.dumps({"tool": "vibeharness-mas", "partial": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="partial report"):
        bl.load_baseline(str(partial))
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"tool": "something-else"}), encoding="utf-8")
    with pytest.raises(ValueError, match="not a VibeHarness JSON report"):
        bl.load_baseline(str(other))
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        bl.load_baseline(str(bad))
    with pytest.raises(ValueError, match="cannot be read"):
        bl.load_baseline(str(tmp_path / "missing.json"))


def test_a_report_without_fingerprint_fields_is_recomputed(tmp_path):
    """0.3.0 的報告早於指紋欄位出現：相同的鍵值由它們的欄位推導出來。
    0.3.0 reports predate the fingerprint field: the same keys are derived from their fields."""
    finding = _finding()
    threat = _threat()
    breach = TestExecutionResult(test_id="BB-TEST-THREAT-01", test_type="blackbox_security", status=TestStatus.FAILED,
                                 is_security_exploit_confirmed=True, source_ref="THREAT-01")
    static = StaticFinding(rule_id="VH-AI-007", title="t", severity=FindingSeverity.HIGH,
                           file_path=os.path.join(EXAMPLES, "m.py"), line_number=3, evidence="aws-access-key literal")
    probe = TestExecutionResult(test_id="WB-PROBE-01", test_type="whitebox_probe", status=TestStatus.FAILED, source_ref="get_user_profile")
    failed_for_finding = TestExecutionResult(test_id="WB-TEST-01", test_type="whitebox_unit", status=TestStatus.FAILED,
                                             source_ref=finding.finding_id)
    defended = finding.model_copy(update={"finding_id": "WB-CLA-02", "title": "a defended finding"})
    passed_for_defended = TestExecutionResult(test_id="WB-TEST-02", test_type="whitebox_unit", status=TestStatus.PASSED,
                                              source_ref=defended.finding_id)
    payload = {
        "tool": "vibeharness-mas", "schema_version": "1", "target_path": EXAMPLES,
        "summary": {"static_findings": [static.model_dump()], "run": {"generated_at": "2026-10-09T00:00:00+00:00"}},
        "whitebox": {"debate": {"confirmed_findings": [finding.model_dump(), defended.model_dump()]},
                     "test_results": [probe.model_dump(), failed_for_finding.model_dump(), passed_for_defended.model_dump()]},
        "threat_model": {"threats": [threat.model_dump()]},
        "blackbox_test_results": [breach.model_dump()],
    }
    path = tmp_path / "old.json"
    path.write_text(json.dumps(payload, default=str), encoding="utf-8")
    loaded = bl.load_baseline(str(path))
    assert loaded.generated_at == "2026-10-09T00:00:00+00:00" and loaded.size == 4
    assert bl.finding_key(finding, EXAMPLES) in loaded.findings and bl.probe_key(probe) in loaded.findings
    # 上次測試通過（防線守住）的確認發現不進基準線：它這次若失敗就是新問題
    # A confirmed finding whose test passed (boundary defended) is not seeded: a failure for it next time is new
    assert bl.finding_key(defended, EXAMPLES) not in loaded.findings
    assert bl.static_key(static, EXAMPLES) in loaded.static
    assert bl.breach_key(breach, threat) in loaded.breaches


# --- 經過關卡的端對端 -------------------------------------------------------------------------
# --- End to end through the gate ---------------------------------------------------------------

def _forced_outcomes(breach_ids, wb_fail=True):
    def fake_execute(tests, working_dir=".", collect_coverage=False):
        if collect_coverage:
            status = TestStatus.FAILED if wb_fail else TestStatus.PASSED
            return [TestExecutionResult(test_id="WB-PROBE-01", test_type="whitebox_probe", status=status,
                                        failure_reason="AssertionError: crashed", source_ref="get_user_profile")], 50.0
        return [TestExecutionResult(test_id=f"BB-TEST-{tid}", test_type="blackbox_security", status=TestStatus.FAILED,
                                    failure_reason="AssertionError: breached", is_security_exploit_confirmed=True,
                                    source_ref=tid) for tid in breach_ids], None
    return fake_execute


def test_known_problems_are_reported_but_no_longer_decide_the_verdict(tmp_path, monkeypatch):
    first = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    monkeypatch.setattr(first.executor, "execute_test_suite", _forced_outcomes(["THREAT-01"]))
    summary = first.run_full_pipeline(target_dir=EXAMPLES, output_report_path=str(tmp_path / "base.json"), output_format="json")
    assert summary.overall_status == "BLOCKED_CRITICAL_RISK" and summary.baseline_path is None
    payload = json.loads((tmp_path / "base.json").read_text(encoding="utf-8"))
    assert payload["blackbox_test_results"][0]["fingerprint"] and payload["whitebox"]["test_results"][0]["fingerprint"]
    assert all("fingerprint" in f for f in payload["whitebox"]["debate"]["confirmed_findings"])

    # 同樣的問題再次出現：全部已知，判定結果落到證據缺口（mock 模式）
    # Same problems again: all known, verdict falls through to the evidence gaps (mock mode)
    second = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    second.baseline = bl.load_baseline(str(tmp_path / "base.json"))
    monkeypatch.setattr(second.executor, "execute_test_suite", _forced_outcomes(["THREAT-01"]))
    summary = second.run_full_pipeline(target_dir=EXAMPLES, output_report_path=str(tmp_path / "r.md"))
    assert summary.overall_status == "INCONCLUSIVE"
    assert summary.blackbox_security_breaches == 0 and summary.whitebox_tests_failed == 0
    assert sorted(s.kind for s in summary.baseline_suppressed) == ["breach", "whitebox_failure"]
    assert summary.baseline_path == str(tmp_path / "base.json")
    md = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert "Known from baseline (not counted)" in md and "BB-TEST-THREAT-01" in md
    assert any("already in the baseline" in rec for rec in summary.key_recommendations)

    # 基準線不認得的突破仍會阻擋
    # A breach the baseline does not know still blocks
    third = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    third.baseline = bl.load_baseline(str(tmp_path / "base.json"))
    monkeypatch.setattr(third.executor, "execute_test_suite", _forced_outcomes(["THREAT-01", "THREAT-02"]))
    summary = third.run_full_pipeline(target_dir=EXAMPLES, output_report_path=str(tmp_path / "r2.md"))
    assert summary.overall_status == "BLOCKED_CRITICAL_RISK" and summary.blackbox_security_breaches == 1
    assert [s.id for s in summary.baseline_suppressed] == ["WB-PROBE-01", "BB-TEST-THREAT-01"]


def test_cli_baseline_flag_is_validated_before_the_run(monkeypatch, tmp_path):
    from vibeharness import cli
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), "-m", "mock", "--baseline", str(tmp_path / "none.json")])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.USAGE_ERROR_EXIT_CODE
    seen = {}

    def run(self, **kwargs):
        seen["baseline"] = self.baseline
        from vibeharness.core.models import VibeHarnessSummary
        return VibeHarnessSummary(
            overall_status="INCONCLUSIVE", total_whitebox_findings=0, confirmed_whitebox_bugs=0, whitebox_tests_passed=0,
            whitebox_tests_failed=0, total_threats_modeled=0, critical_threats_count=0, blackbox_tests_passed=0,
            blackbox_security_breaches=0,
        )

    good = tmp_path / "base.json"
    good.write_text(json.dumps({"tool": "vibeharness-mas", "target_path": str(tmp_path)}), encoding="utf-8")
    monkeypatch.setattr(cli.VibeHarnessCommander, "run_full_pipeline", run)
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path), "-m", "mock", "--baseline", str(good)])
    with pytest.raises(SystemExit):
        cli.main()
    assert seen["baseline"].path == str(good) and seen["baseline"].size == 0


# --- action.yml（複合動作定義）-----------------------------------------------------------------
# --- action.yml --------------------------------------------------------------------------------

def test_composite_action_is_well_formed():
    with open(os.path.join(REPO_ROOT, "action.yml"), encoding="utf-8") as f:
        action = yaml.safe_load(f)
    assert action["runs"]["using"] == "composite"
    assert {"target", "mode", "max-model-calls", "baseline", "sarif", "fail-on"} <= set(action["inputs"])
    assert {"verdict", "exit-code", "report", "sarif"} <= set(action["outputs"])
    steps = action["runs"]["steps"]
    assert all("@" in s["uses"] and len(s["uses"].split("@")[1].split()[0]) == 40 for s in steps if "uses" in s), "actions must be SHA-pinned"
    assert any(s.get("id") == "audit" for s in steps)


def test_old_simulated_reports_without_per_item_flags_still_match():
    """只在 threat_model／debate 層級標 is_simulated 的舊報告，重算 key 時會把旗標補到每個項目，與這一輪的模擬項目相符。
    An old report flagged is_simulated only at the threat_model / debate level gets the flag propagated to every item
    when keys are recomputed, so it matches this run's simulated items."""
    from vibeharness.core.i18n import bi
    title = bi("大量指派管理員欄位", "Mass assignment of admin fields")
    old_threat = _threat().model_copy(update={"title": title})  # is_simulated 預設 False ／ defaults to False
    breach = TestExecutionResult(test_id="BB-TEST-THREAT-01", test_type="blackbox_security", status=TestStatus.FAILED,
                                 is_security_exploit_confirmed=True, source_ref="THREAT-01")
    payload = {"tool": "vibeharness-mas", "schema_version": "1", "target_path": EXAMPLES, "summary": {},
               "whitebox": {"debate": {"confirmed_findings": []}, "test_results": []},
               "threat_model": {"threats": [old_threat.model_dump(exclude={"is_simulated"})], "is_simulated": True},
               "blackbox_test_results": [breach.model_dump()]}
    loaded = bl._keys_from_report(payload)
    new_threat = _threat().model_copy(update={"title": title, "is_simulated": True})
    assert bl.breach_key(breach, new_threat) in loaded.breaches


def test_container_level_simulated_flag_never_overrides_an_items_own_flag():
    """混合執行的舊報告：threat_model.is_simulated 為 True（any_simulated），但 live 的威脅自己帶 is_simulated=False，
    重算 key 時以項目為準。
    An old mixed-run report: threat_model.is_simulated is True (any_simulated) while a live threat carries its own
    is_simulated=False; the item's flag wins when keys are recomputed."""
    from vibeharness.core.i18n import bi
    title = bi("真實", "Real threat with a slash")
    live_threat = _threat().model_copy(update={"title": title, "is_simulated": False})
    breach = TestExecutionResult(test_id="BB-TEST-THREAT-01", test_type="blackbox_security", status=TestStatus.FAILED,
                                 is_security_exploit_confirmed=True, source_ref="THREAT-01")
    payload = {"tool": "vibeharness-mas", "schema_version": "1", "target_path": EXAMPLES, "summary": {},
               "whitebox": {"debate": {"confirmed_findings": []}, "test_results": []},
               "threat_model": {"threats": [live_threat.model_dump()], "is_simulated": True},
               "blackbox_test_results": [breach.model_dump()]}
    loaded = bl._keys_from_report(payload)
    assert bl.breach_key(breach, live_threat) in loaded.breaches


# --- 報告的規則命中列與判定結果一致 ---------------------------------------------------------------
# --- The report's rule-hit row agrees with the verdict -------------------------------------------

def _rule_row(**summary_fields):
    from vibeharness.core.models import MultiModelDebateResult, ThreatModelReport, VibeHarnessSummary
    from vibeharness.reports.report_generator import ReportGenerator
    hits = [StaticFinding(rule_id=f"VH-AI-00{n}", title="t", severity=FindingSeverity.HIGH, file_path="app.py", line_number=n)
            for n in (1, 2, 3)]
    summary = VibeHarnessSummary(
        overall_status="READY_TO_SHIP", total_whitebox_findings=0, confirmed_whitebox_bugs=0, whitebox_tests_passed=0,
        whitebox_tests_failed=0, total_threats_modeled=0, critical_threats_count=0, blackbox_tests_passed=0,
        blackbox_security_breaches=0, static_findings=hits, **summary_fields,
    )
    md = ReportGenerator().generate_markdown_report(summary, MultiModelDebateResult(consensus_summary=""),
                                                    ThreatModelReport(system_description=""), [], [], "app")
    return next(line for line in md.splitlines() if "Deterministic AI-Security Rule Hits" in line)


def test_report_rule_hit_row_counts_only_new_hits_under_a_baseline():
    """--baseline 下判定只計入新的命中，報告列也必須如此（過去會顯示全部 HIGH+，與 READY_TO_SHIP 矛盾）。
    Under --baseline the verdict counts only new hits, and so must the report row (it used to show every HIGH+
    hit, contradicting READY_TO_SHIP)."""
    row = _rule_row(baseline_path="old.json", new_blocking_rule_hits=1)
    assert "`3` (" in row and "1 HIGH+ new, 2 known from baseline" in row and "0 new HIGH+" in row


@pytest.mark.parametrize("fields", [{}, {"new_blocking_rule_hits": 3}, {"baseline_path": "old.json"}])
def test_report_rule_hit_row_without_a_baseline_is_unchanged(fields):
    assert _rule_row(**fields).endswith("| `3` (3 HIGH+) | 0 HIGH+ |")
