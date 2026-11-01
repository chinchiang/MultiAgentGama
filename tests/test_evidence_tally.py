"""證據計數（GLOSSARY：Evidence tally）：一次執行裡決定判定結果的項目，依種類只算一次，每一種都分成全部、新的與已知問題。
The Evidence tally (GLOSSARY): what decides one run's Verdict, counted once by kind, each kind split into all, new and
Known problems."""

from vibeharness.core.baseline import Baseline, breach_key, finding_key, static_key
from vibeharness.core.models import (
    FindingSeverity, GeneratedTest, ReviewFinding, StaticFinding, STRIDECategory, TestExecutionResult, TestStatus,
    ThreatItem,
)
from vibeharness.core.tally import tally_evidence

TARGET = "/srv/app"


def _bb(tid, status=TestStatus.PASSED, breach=False, source_ref=None):
    return TestExecutionResult(test_id=tid, test_type="blackbox_security", status=status,
                               is_security_exploit_confirmed=breach, source_ref=source_ref)


def test_without_a_baseline_every_breach_is_new_and_none_is_known():
    """沒有基準時：每個資安突破都是新的，已知清單是空的；沒有突破的黑箱結果不算進去。
    Without a Baseline every Breach is new and none is known; black-box results that are not Breaches are left out."""
    breach = _bb("BB-T-01", TestStatus.FAILED, breach=True)
    defended = _bb("BB-T-02")
    tally = tally_evidence(bb_results=[breach, defended])
    assert tally.breaches.all == (breach,)
    assert tally.breaches.new == (breach,)
    assert tally.breaches.known == ()


def _wb(tid, status=TestStatus.PASSED, source_ref=None):
    return TestExecutionResult(test_id=tid, test_type="whitebox_unit", status=status, source_ref=source_ref)


def test_without_a_baseline_each_result_kind_is_counted_once_in_input_order():
    """沒有基準時：白箱失敗、未分類失敗、白、黑箱的未執行各自依輸入順序計數，全部都是新的，已知清單是空的。
    Without a Baseline, white-box failures, Unclassified failures and Not run on each side are counted in input
    order; all of them are new and none is known."""
    wb_fail_1, wb_pass, wb_error, wb_fail_2, wb_skip = (
        _wb("WB-1", TestStatus.FAILED), _wb("WB-2"), _wb("WB-3", TestStatus.ERROR), _wb("WB-4", TestStatus.FAILED),
        _wb("WB-5", TestStatus.SKIPPED))
    breach, crash, bb_error = _bb("BB-1", TestStatus.FAILED, breach=True), _bb("BB-2", TestStatus.FAILED), _bb("BB-3", TestStatus.ERROR)
    tally = tally_evidence(wb_results=[wb_fail_1, wb_pass, wb_error, wb_fail_2, wb_skip], bb_results=[breach, crash, bb_error])
    expected = {
        "whitebox_failures": (wb_fail_1, wb_fail_2),
        "unclassified_failures": (crash,),
        "whitebox_not_run": (wb_error, wb_skip),
        "blackbox_not_run": (bb_error,),
    }
    for kind, items in expected.items():
        split = getattr(tally, kind)
        assert (split.all, split.new, split.known) == (items, items, ()), kind


def _rule_hit(severity, line=3, evidence="pickle.load(f)"):
    return StaticFinding(rule_id="VH-AI-001", title="Unsafe load", severity=severity, file_path=f"{TARGET}/app.py",
                         line_number=line, evidence=evidence)


def test_only_critical_and_high_rule_hits_are_blocking():
    """阻擋性規則命中只有 CRITICAL 與 HIGH，依輸入順序；MEDIUM、LOW 不算。
    Only CRITICAL and HIGH rule hits are blocking, in input order; MEDIUM and LOW are not."""
    high, medium, critical, low = (_rule_hit(FindingSeverity.HIGH, 1), _rule_hit(FindingSeverity.MEDIUM, 2),
                                   _rule_hit(FindingSeverity.CRITICAL, 3), _rule_hit(FindingSeverity.LOW, 4))
    split = tally_evidence(static_findings=[high, medium, critical, low]).blocking_rule_hits
    assert (split.all, split.new, split.known) == ((high, critical), (high, critical), ())


def _threat(tid):
    return ThreatItem(threat_id=tid, stride_category=STRIDECategory.TAMPERING, title=f"{tid} title", description="d",
                      asset_at_risk="a", attack_vector="v", trust_boundary_crossed="t", severity=FindingSeverity.HIGH,
                      attack_scenario="s", test_verification_goal="g")


def _attack(tid, threat_id):
    return GeneratedTest(test_id=tid, test_type="blackbox_security", target_component="c", title="t", code="",
                         rationale="r", expected_outcome="e", source_ref=threat_id)


def test_a_threat_no_black_box_test_points_at_is_untested():
    """沒有任何黑箱測試指向的威脅是未測試的威脅（依威脅的順序，以 id 表示）；沒有威脅就沒有未測試的威脅。
    A threat no black-box test points at is an untested threat (in threat order, by id); no threats, none untested."""
    threats = [_threat("T1"), _threat("T2"), _threat("T3")]
    split = tally_evidence(threats=threats, bb_tests=[_attack("BB-1", "T2")]).untested_threats
    assert (split.all, split.new, split.known) == (("T1", "T3"), ("T1", "T3"), ())
    assert tally_evidence(bb_tests=[_attack("BB-1", "T2")]).untested_threats.all == ()


def _finding(fid, symbol):
    return ReviewFinding(finding_id=fid, reviewer_name="r", model_alias="gpt", file_path=f"{TARGET}/app.py",
                         symbol_name=symbol, severity=FindingSeverity.HIGH, title=f"{symbol} flaw", description="d",
                         root_cause="rc", suspected_vibe_flaw="f", suggested_test_scenario="s")


def test_with_a_baseline_breaches_white_box_failures_and_rule_hits_split_into_new_and_known():
    """有基準時：資安突破、白箱失敗與阻擋性規則命中分成新的與已知問題；known_problems 依 compare_with_baseline 的順序
    （規則命中、白箱失敗、資安突破）列出已知問題；基準不記錄的種類（未分類失敗、白、黑箱的未執行、未測試的威脅）照舊全部是新的。
    With a Baseline, Breaches, white-box failures and blocking rule hits split into new and Known problems; known_problems
    lists the Known problems in compare_with_baseline's order (rule hits, white-box failures, Breaches); the kinds the
    Baseline does not record (Unclassified failures, Not run on each side, untested threats) stay all new."""
    t_known, t_new = _threat("T1"), _threat("T2")
    breach_known = _bb("BB-1", TestStatus.FAILED, breach=True, source_ref="T1")
    breach_new = _bb("BB-2", TestStatus.FAILED, breach=True, source_ref="T2")
    crash, bb_error = _bb("BB-3", TestStatus.FAILED), _bb("BB-4", TestStatus.ERROR)
    f_known, f_new = _finding("WB-F-1", "load"), _finding("WB-F-2", "save")
    wb_known = _wb("WB-1", TestStatus.FAILED, source_ref="WB-F-1")
    wb_new = _wb("WB-2", TestStatus.FAILED, source_ref="WB-F-2")
    wb_skip = _wb("WB-3", TestStatus.SKIPPED)
    # 指紋不含行號，所以新的命中要有不同的證據文字 ／ The fingerprint ignores the line, so the new hit needs different evidence
    hit_known, hit_new = _rule_hit(FindingSeverity.HIGH, 1), _rule_hit(FindingSeverity.CRITICAL, 9, "torch.load(f)")
    baseline = Baseline(path="old.json", breaches={breach_key(breach_known, t_known)},
                        findings={finding_key(f_known, TARGET)}, static={static_key(hit_known, TARGET)})
    tally = tally_evidence(wb_results=[wb_known, wb_new, wb_skip], bb_results=[breach_known, breach_new, crash, bb_error],
                           bb_tests=[_attack("BB-1", "T1")],
                           static_findings=[hit_known, hit_new], threats=[t_known, t_new],
                           confirmed_findings=[f_known, f_new], target_dir=TARGET, baseline=baseline)
    assert (tally.breaches.all, tally.breaches.new, tally.breaches.known) == (
        (breach_known, breach_new), (breach_new,), (breach_known,))
    assert (tally.whitebox_failures.new, tally.whitebox_failures.known) == ((wb_new,), (wb_known,))
    assert (tally.blocking_rule_hits.new, tally.blocking_rule_hits.known) == ((hit_new,), (hit_known,))
    assert [(s.kind, s.id) for s in tally.known_problems] == [
        ("static", "VH-AI-001@app.py:1"), ("whitebox_failure", "WB-1"), ("breach", "BB-1")]
    for kind, items in {"unclassified_failures": (crash,), "whitebox_not_run": (wb_skip,),
                        "blackbox_not_run": (bb_error,), "untested_threats": ("T2",)}.items():
        split = getattr(tally, kind)
        assert (split.all, split.new, split.known) == (items, items, ()), kind


def test_without_a_baseline_there_are_no_known_problems():
    """沒有基準時沒有任何已知問題。
    Without a Baseline there are no Known problems."""
    assert tally_evidence(bb_results=[_bb("BB-1", TestStatus.FAILED, breach=True)]).known_problems == ()
