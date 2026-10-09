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


# --- 鍵值在重新編號、改寫措辭與行號漂移後仍不變 -----------------------------------------------
# --- Keys survive re-numbering, rewording and line drift --------------------------------------

def test_finding_key_ignores_run_numbering_and_cosmetic_rewording():
    a = bl.finding_key(_finding("WB-CLA-01", "Unchecked null in get_user"), EXAMPLES)
    b = bl.finding_key(_finding("WB-DEE-07", "unchecked NULL in get_user!"), EXAMPLES)
    c = bl.finding_key(_finding("WB-CLA-01", "SQL injection in get_user"), EXAMPLES)
    assert a == b != c
    # 同一個檔案透過另一個簽出路徑來看：鍵值相對於目標
    # Same file seen through another checkout path: the key is relative to the target
    d = bl.finding_key(_finding(path="/elsewhere/examples/vibe_sample_app.py"), "/elsewhere/examples")
    assert d == a


def test_static_key_ignores_line_drift_but_not_the_rule_or_evidence():
    def hit(line, rule="VH-AI-003", evidence="pickle.load(...)"):
        return StaticFinding(rule_id=rule, title="t", severity=FindingSeverity.MEDIUM,
                             file_path=os.path.join(EXAMPLES, "m.py"), line_number=line, evidence=evidence)
    assert bl.static_key(hit(10), EXAMPLES) == bl.static_key(hit(42), EXAMPLES)
    assert bl.static_key(hit(10), EXAMPLES) != bl.static_key(hit(10, rule="VH-AI-002"), EXAMPLES)
    assert bl.static_key(hit(10), EXAMPLES) != bl.static_key(hit(10, evidence="dill.load(...)"), EXAMPLES)


def test_breach_key_comes_from_the_threat_not_the_test_id():
    r1 = TestExecutionResult(test_id="BB-TEST-THREAT-01", test_type="blackbox_security", status=TestStatus.FAILED,
                             is_security_exploit_confirmed=True, source_ref="THREAT-01")
    r2 = TestExecutionResult(test_id="BB-TEST-THREAT-09", test_type="blackbox_security", status=TestStatus.FAILED,
                             is_security_exploit_confirmed=True, source_ref="THREAT-09")
    assert bl.breach_key(r1, _threat("THREAT-01")) == bl.breach_key(r2, _threat("THREAT-09", "bola ON update"))
    assert bl.breach_key(r1, _threat()) != bl.breach_key(r1, _threat(vector="DELETE /api/users/{id}"))
    assert bl.breach_key(r1, None) != bl.breach_key(r2, None)


def test_probe_failures_are_keyed_by_symbol():
    probe = TestExecutionResult(test_id="WB-PROBE-03", test_type="whitebox_probe", status=TestStatus.FAILED, source_ref="transfer")
    assert bl.whitebox_failure_key(probe, None, EXAMPLES) == bl.probe_key(probe)
    unresolved = TestExecutionResult(test_id="WB-TEST-01", test_type="whitebox_unit", status=TestStatus.FAILED, source_ref="WB-GONE-01")
    assert bl.whitebox_failure_key(unresolved, None, EXAMPLES) is None  # 無法比對：一律視為新的 ／ cannot be matched: always new


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


def test_keys_distinguish_cjk_titles_and_ignore_the_chinese_half_of_bilingual_text():
    """中文標題各自不同（不會塌成空字串而共用一個鍵）；`bi()` 字串只取英文半，所以 0.3.0 的鍵不變。
    CJK titles stay distinct (they no longer collapse to "" and share one key); a `bi()` string is keyed by its
    English half, so keys from 0.3.0 are unchanged."""
    from vibeharness.core.i18n import bi
    t1 = _threat().model_copy(update={"title": "大量指派管理員欄位"})
    t2 = _threat().model_copy(update={"title": "跨租戶資料竄改"})
    breach = TestExecutionResult(test_id="BB-TEST-THREAT-01", test_type="blackbox_security", status=TestStatus.FAILED,
                                 is_security_exploit_confirmed=True, source_ref="THREAT-01")
    assert bl.breach_key(breach, t1) != bl.breach_key(breach, t2)
    assert bl.normalize("大量指派管理員欄位") != "" and bl.normalize("Mass_Assignment, v2!") == "mass assignment v2"
    plain = _threat().model_copy(update={"title": "Mass assignment of admin fields"})
    simulated = _threat().model_copy(update={"title": bi("大量指派管理員欄位", "Mass assignment of admin fields"), "is_simulated": True})
    assert bl.breach_key(breach, plain) == bl.breach_key(breach, simulated)
    # 真實模型的文字原樣進鍵，即使含有全形斜線：0.3.0 的鍵不受 bi() 的分隔符影響
    # Real model text keys as is, even with a full-width slash: 0.3.0 keys are untouched by the bi() separator
    real = _threat().model_copy(update={"title": bi("大量指派管理員欄位", "Mass assignment of admin fields")})
    assert bl.breach_key(breach, real) != bl.breach_key(breach, plain)
    assert bl.normalize('token = "abc ／ def"') == "token abc def"


def test_sarif_fingerprints_use_the_same_helpers_as_the_baseline():
    """SARIF 的 partialFingerprints 與基準線鍵共用同一套 normalize／fingerprint，不會各自漂移。
    SARIF partialFingerprints and baseline keys share one normalize / fingerprint pair, so they cannot drift apart."""
    from vibeharness.reports import report_generator as rg
    assert rg.normalize is bl.normalize and rg.fingerprint is bl.fingerprint
    assert not hasattr(rg.ReportGenerator, "_normalize") and not hasattr(rg.ReportGenerator, "_fingerprint")


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
