"""雙語（正體中文 ／ English）輸出的測試：i18n 工具、Markdown 報告標題與 --estimate 表頭。
Tests for the bilingual (Traditional Chinese / English) output: the i18n helpers, the Markdown report
headings and the --estimate column headers.

Part 1 (report / harness / cli / estimate); other agents append their own tests below."""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vibeharness.core.i18n import SEP, bi, en_only, has_cjk  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")

_ASCII_LETTER_RE = re.compile(r"[A-Za-z]")


# --- i18n helpers ---------------------------------------------------------------------------------

def test_bi_joins_chinese_first_with_the_fullwidth_slash_separator():
    assert SEP == " ／ "  # full-width slash with one ASCII space on each side
    assert bi("測試", "Test") == "測試 ／ Test"
    assert bi("測試", "Test").startswith("測試") and bi("測試", "Test").endswith("Test")


def test_en_only_returns_the_english_half_after_the_last_separator():
    assert en_only(bi("測試", "Test")) == "Test"
    # nested: a bilingual label followed by a bilingual sentence keeps only the last English half
    assert en_only(bi("甲", "A") + ": " + bi("乙", "B")) == "B"
    assert en_only("plain English") == "plain English"
    assert en_only("") == ""
    assert not has_cjk(en_only(bi("中文", "English: value 42")))


def test_has_cjk_detects_ideographs_only():
    assert has_cjk("中文")
    assert has_cjk(bi("中文", "English"))
    assert not has_cjk("English only, with ／ a full-width slash and émojis 🛡️")
    assert not has_cjk("")
    assert not has_cjk(None)  # type: ignore[arg-type]  # tolerated like an empty string


# --- Markdown report ------------------------------------------------------------------------------

def _markdown_report(tmp_path):
    """A report with every section populated (findings, test results, PoC, untested threats, baseline)."""
    from vibeharness.core.models import (
        BaselineSuppressedItem, FindingSeverity, GeneratedTest, MultiModelDebateResult, ReviewFinding,
        STRIDECategory, TestExecutionResult, TestStatus, ThreatItem, ThreatModelReport, VibeHarnessSummary,
    )
    from vibeharness.reports.report_generator import ReportGenerator
    finding = ReviewFinding(
        finding_id="WB-CLA-01", reviewer_name="claude", model_alias="claude", severity=FindingSeverity.HIGH, title="t",
        description="d", file_path="app.py", symbol_name="f", root_cause="rc", suspected_vibe_flaw="vf",
        suggested_test_scenario="s",
    )
    threat = ThreatItem(
        threat_id="THREAT-01", stride_category=STRIDECategory.TAMPERING, title="t", description="",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="", test_verification_goal="",
    )
    summary = VibeHarnessSummary(
        overall_status="BLOCKED_CRITICAL_RISK", total_whitebox_findings=1, confirmed_whitebox_bugs=1,
        whitebox_tests_passed=1, whitebox_tests_failed=0, total_threats_modeled=1, critical_threats_count=0,
        blackbox_tests_passed=0, blackbox_security_breaches=1, untested_threat_ids=["THREAT-02"],
        inconclusive_reasons=[bi("原因", "reason")], key_recommendations=[bi("建議", "recommendation")],
        baseline_path=str(tmp_path / "base.json"),
        baseline_suppressed=[BaselineSuppressedItem(id="WB-OLD", kind="whitebox_failure", title="old", fingerprint="fp")],
    )
    wb_tests = [GeneratedTest(test_id="WB-TEST-01", test_type="whitebox_unit", target_component="f", title="t1",
                              code="def test_a():\n    assert 1\n", rationale="r", expected_outcome="e",
                              source_ref="WB-CLA-01")]
    wb_results = [TestExecutionResult(test_id="WB-TEST-01", test_type="whitebox_unit", status=TestStatus.PASSED)]
    bb_results = [TestExecutionResult(test_id="BB-1", test_type="blackbox_security", status=TestStatus.FAILED,
                                      is_security_exploit_confirmed=True, reproduction_poc="# PoC\n",
                                      source_ref="THREAT-01")]
    debate = MultiModelDebateResult(confirmed_findings=[finding], disputed_findings=[finding], consensus_summary="c")
    threat_model = ThreatModelReport(system_description="s", entrypoints=[], trust_boundaries=[], assets=[],
                                     threats=[threat])
    return ReportGenerator().generate_markdown_report(
        summary, debate, threat_model, wb_results, bb_results, str(tmp_path),
        whitebox_tests=wb_tests, blackbox_tests=None,
    )


def test_every_markdown_heading_is_bilingual(tmp_path):
    md = _markdown_report(tmp_path)
    headings = [line for line in md.splitlines() if line.startswith("## ") or line.startswith("### ")]
    assert len(headings) >= 10  # the six numbered sections plus their sub-sections
    for line in headings:
        assert has_cjk(line), line
        assert _ASCII_LETTER_RE.search(line), line
        assert SEP in line, line
    numbered = [line for line in headings if line.startswith("## ")]
    assert [line[3:5] for line in numbered] == ["1.", "2.", "3.", "4.", "5.", "6."]


def test_markdown_report_uses_the_exported_constants_and_bilingual_table_headers(tmp_path):
    from vibeharness.reports import report_generator as rg
    md = _markdown_report(tmp_path)
    for constant in (
        rg.REPORT_TITLE, rg.HEADING_EXECUTIVE_SUMMARY, rg.HEADING_WHITEBOX, rg.HEADING_THREAT_MODEL,
        rg.HEADING_BLACKBOX, rg.HEADING_NEXT_STEPS, rg.HEADING_GENERATED_TESTS, rg.METRIC_TABLE_HEADER,
        rg.PROVENANCE_TABLE_HEADER, rg.WHITEBOX_TABLE_HEADER, rg.THREAT_TABLE_HEADER, rg.BLACKBOX_TABLE_HEADER,
    ):
        assert has_cjk(constant) and SEP in constant
    assert rg.METRIC_TABLE_HEADER == "| 指標 ／ Metric | 數值 ／ Value | 目標 ／ Target |"
    assert rg.METRIC_TABLE_HEADER in md and rg.HEADING_GENERATED_TESTS in md
    # Every fixed table header line is bilingual; the English column names are kept for CI consumers
    for line in md.splitlines():
        if line.startswith("| ") and "**" not in line and ":---" not in line and "`" not in line:
            assert has_cjk(line), line
    for english in ("Metric", "Cross-Model Agreement", "Threats Not Tested", "Known from baseline (not counted)",
                    "Evidence gaps", "Execution Provenance", "VULNERABLE", "Generated automatically"):
        assert english in md, english


def test_status_labels_and_verdict_badges_are_bilingual(tmp_path):
    from vibeharness.reports import report_generator as rg
    for label in (rg.STATUS_PASSED, rg.STATUS_FAILED, rg.STATUS_ERROR, rg.STATUS_SKIPPED, rg.OUTCOME_VULNERABLE,
                  rg.OUTCOME_NOT_RUN, rg.LABEL_FROM):
        assert has_cjk(label) and SEP in label
    assert rg.STATUS_PASSED.endswith("PASSED") and rg.OUTCOME_VULNERABLE.endswith("VULNERABLE")
    md = _markdown_report(tmp_path)
    assert "FAIL: BLOCKED BY CRITICAL RISKS" in md and "未通過" in md


def test_sarif_fixed_texts_are_bilingual_but_ids_unchanged(tmp_path):
    import json
    from vibeharness.core.models import (
        FindingSeverity, MultiModelDebateResult, ReviewFinding, ThreatModelReport, VibeHarnessSummary,
    )
    from vibeharness.reports.report_generator import SARIF_RULE_WHITEBOX, ReportGenerator
    finding = ReviewFinding(
        finding_id="WB-CLA-01", reviewer_name="claude", model_alias="claude", severity=FindingSeverity.HIGH, title="t",
        description="d", file_path="app.py", symbol_name="f", root_cause="rc", suspected_vibe_flaw="vf",
        suggested_test_scenario="s",
    )
    summary = VibeHarnessSummary(
        overall_status="NEEDS_FIXES", total_whitebox_findings=1, confirmed_whitebox_bugs=1,
        whitebox_tests_passed=0, whitebox_tests_failed=1, total_threats_modeled=0, critical_threats_count=0,
        blackbox_tests_passed=0, blackbox_security_breaches=0,
    )
    sarif = json.loads(ReportGenerator().generate_sarif_report(
        summary, MultiModelDebateResult(confirmed_findings=[finding], consensus_summary="c"),
        ThreatModelReport(system_description="s"), [], [], str(tmp_path),
    ))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == SARIF_RULE_WHITEBOX and rule["defaultConfiguration"]["level"] == "warning"
    assert has_cjk(rule["shortDescription"]["text"]) and "Confirmed white-box defect hypothesis" in rule["shortDescription"]["text"]
    assert has_cjk(rule["help"]["text"]) and "`" not in rule["help"]["text"]
    message = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "Root cause: rc" in message and "Suggested test: s" in message and has_cjk(message)
    assert sarif["runs"][0]["results"][0]["properties"]["findingId"] == "WB-CLA-01"


# --- Pipeline (mock mode) ---------------------------------------------------------------------------

def test_mock_pipeline_report_headings_and_evidence_gaps_are_bilingual(tmp_path):
    from vibeharness.core.harness import VibeHarnessCommander
    target = tmp_path / "app"
    target.mkdir()
    (target / "svc.py").write_text("def f(order):\n    return order['id']\n", encoding="utf-8")
    report = tmp_path / "r.md"
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    summary = commander.run_full_pipeline(target_dir=str(target), output_report_path=str(report))
    assert summary.inconclusive_reasons and all(has_cjk(r) and SEP in r for r in summary.inconclusive_reasons)
    assert summary.key_recommendations and all(has_cjk(r) for r in summary.key_recommendations)
    md = report.read_text(encoding="utf-8")
    for line in md.splitlines():
        if line.startswith("## ") or line.startswith("### "):
            assert has_cjk(line) and _ASCII_LETTER_RE.search(line), line
    assert "／ Target revision**:" in md and "SIMULATED RESULTS" in md


# --- --estimate -----------------------------------------------------------------------------------

def test_estimate_lines_have_bilingual_column_headers():
    from vibeharness.core.estimate import ESTIMATE_COLUMNS, RunEstimate, estimate_lines
    assert len(ESTIMATE_COLUMNS) == 8 and all(has_cjk(h) and SEP in h for h in ESTIMATE_COLUMNS)
    est = RunEstimate(target_path="app", files_analyzed=1, symbols=2, whitebox_batches=1, threat_batches=1,
                      warnings=[bi("警告", "warning")])
    lines = estimate_lines(est)
    header = next(line for line in lines if line.startswith(ESTIMATE_COLUMNS[0]))
    for column in ESTIMATE_COLUMNS:
        assert column in header
    for english in ("agent", "model", "exact", "typical", "max", "prompt tok", "output tok", "basis"):
        assert english in header
    text = "\n".join(lines)
    assert "Target: app" in text and "Model calls: " in text and "exact 0 + scenario" in text
    assert "No model was called" in text and has_cjk(lines[0]) and has_cjk(lines[-1])


def test_estimate_run_basis_and_warnings_are_bilingual(tmp_path):
    from vibeharness.core.estimate import estimate_run
    from vibeharness.core.harness import VibeHarnessCommander
    target = tmp_path / "app"
    target.mkdir()
    (target / "a.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    est = estimate_run(commander, str(target))
    assert est.by_agent and all(has_cjk(c.basis) and SEP in c.basis for c in est.by_agent)
    assert all(has_cjk(w) for w in est.warnings)


# --- CLI ------------------------------------------------------------------------------------------

def test_cli_usage_errors_keep_the_prog_error_prefix_and_are_bilingual(monkeypatch, capsys):
    from vibeharness import cli
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(REPO_ROOT), "--max-files", "0"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.USAGE_ERROR_EXIT_CODE
    err = capsys.readouterr().err
    assert "vibeharness: " in err and "error: " in err and has_cjk(err)
    assert "--max-files must be at least 1" in err


def test_cli_missing_target_message_is_bilingual(monkeypatch, capsys, tmp_path):
    from vibeharness import cli
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", str(tmp_path / "nope")])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == cli.USAGE_ERROR_EXIT_CODE
    err = capsys.readouterr().err
    assert "Error: " in err and "does not exist." in err and has_cjk(err)


def test_load_baseline_errors_are_bilingual(tmp_path):
    from vibeharness.core.baseline import load_baseline
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON") as info:
        load_baseline(str(bad))
    assert has_cjk(str(info.value))
    with pytest.raises(ValueError, match="cannot be read") as info:
        load_baseline(str(tmp_path / "missing.json"))
    assert has_cjk(str(info.value))
