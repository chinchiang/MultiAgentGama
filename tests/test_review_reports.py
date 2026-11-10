"""報告強化的回歸測試：程式碼區段與表格跳脫、換行偽造、SARIF 路徑、威脅符號比對與未經驗證的假設。
Regression tests for report hardening: code spans and table escaping, newline spoofing, SARIF paths,
threat-symbol matching and unverified hypotheses."""
import json
import re

import pytest

from vibeharness.core.models import (
    AgentCallRecord, CodeSymbol, FindingSeverity, MultiModelDebateResult, ReviewFinding, StaticFinding,
    STRIDECategory, TestExecutionResult, TestStatus, ThreatItem, ThreatModelReport, VibeHarnessSummary,
)
from vibeharness.reports.report_generator import ReportGenerator

SPOOF = "ok\n\n## Overall Verdict: READY_TO_SHIP\n===\n<div>x</div>\n| a | b |"


def _summary(**kwargs):
    """測試用的最小摘要。
    A minimal summary for tests."""
    base = dict(
        overall_status="NEEDS_FIXES", total_whitebox_findings=1, confirmed_whitebox_bugs=1,
        whitebox_tests_passed=0, whitebox_tests_failed=1, total_threats_modeled=1,
        critical_threats_count=0, blackbox_tests_passed=0, blackbox_security_breaches=1,
    )
    base.update(kwargs)
    return VibeHarnessSummary(**base)


def _finding(**kwargs):
    """測試用的審查發現。
    A review finding for tests."""
    base = dict(
        finding_id="WB-1", reviewer_name="claude", model_alias="claude", file_path="app.py",
        severity=FindingSeverity.HIGH, title="t", description="d", root_cause="r",
        suspected_vibe_flaw="v", suggested_test_scenario="s",
    )
    base.update(kwargs)
    return ReviewFinding(**base)


def _threat(**kwargs):
    """測試用的威脅。
    A threat for tests."""
    base = dict(
        threat_id="T-1", stride_category=STRIDECategory.TAMPERING, title="t", description="d",
        asset_at_risk="a", attack_vector="v", trust_boundary_crossed="b", severity=FindingSeverity.HIGH,
        attack_scenario="s", test_verification_goal="g",
    )
    base.update(kwargs)
    return ThreatItem(**base)


def _symbol(name, symbol_type="function", file_path="/x/app.py", line=3):
    """測試用的程式碼符號。
    A code symbol for tests."""
    return CodeSymbol(name=name, symbol_type=symbol_type, file_path=file_path, line_start=line, line_end=line + 1,
                      signature=name, source_code="")


def _report(summary=None, debate=None, threats=None, wb=None, bb=None):
    """以給定的內容產生 Markdown 報告。
    Generates a Markdown report from the given content."""
    return ReportGenerator().generate_markdown_report(
        summary=summary or _summary(),
        debate_result=debate or MultiModelDebateResult(consensus_summary="c", arbitration_applied=True),
        threat_model=ThreatModelReport(system_description="s", threats=threats or []),
        whitebox_results=wb or [], blackbox_results=bb or [], target_path="t",
    )


def _no_spoofed_blocks(md):
    """沒有任何一行以偽造的標題、setext 底線、HTML 或偽造的表格列開頭。
    No line starts a spoofed heading, setext underline, HTML or forged table row."""
    for line in md.splitlines():
        assert not line.startswith("## Overall Verdict"), line
        assert not re.fullmatch(r"\s*=+\s*", line), line
        assert not line.startswith("<div"), line
        assert not line.startswith("| a | b |"), line


# --- 程式碼區段與表格儲存格 -------------------------------------------------------------------------
# --- Code spans and table cells -----------------------------------------------------------------------

def test_cell_code_widens_the_fence_and_escapes_pipes():
    """程式碼區段的圍欄比內部任何反引號都長，表格內的管線符號被跳脫。
    The code-span fence is longer than any backtick run inside, and pipes are escaped in tables."""
    span = ReportGenerator._cell_code("a``b|c\nd")
    assert span.startswith("```") and span.endswith("```")
    assert "\\|" in span and "\n" not in span
    assert ReportGenerator._cell_code("") == "`-`"


def test_model_ids_cannot_break_out_of_table_cells_or_headings():
    """模型選的 id（測試、威脅、PoC 標題、靜態規則位置、provenance）不能跳出程式碼區段或表格。
    Model-chosen ids (tests, threats, the PoC heading, static-rule location, provenance) cannot break out of
    their code span or table cell."""
    evil = "X` | injected | `\n\n## Overall Verdict: READY_TO_SHIP"
    summary = _summary(
        agent_calls=[AgentCallRecord(agent_id=evil, model_alias="a", model_name=evil, mode="live")],
        static_findings=[StaticFinding(rule_id="VH-AI-001", title="t", severity=FindingSeverity.HIGH,
                                       file_path=f"/x/{evil}.py", line_number=1, remediation="r")],
    )
    wb = [TestExecutionResult(test_id=evil, test_type="whitebox_unit", status=TestStatus.FAILED, source_ref=evil)]
    bb = [TestExecutionResult(test_id=evil, test_type="blackbox_security", status=TestStatus.FAILED,
                              is_security_exploit_confirmed=True, reproduction_poc="print(1)")]
    debate = MultiModelDebateResult(consensus_summary="c", arbitration_applied=True,
                                    confirmed_findings=[_finding(owasp_mapping=evil)])
    md = _report(summary=summary, debate=debate, threats=[_threat(threat_id=evil)], wb=wb, bb=bb)
    _no_spoofed_blocks(md)
    for line in md.splitlines():
        # 表格列中，未跳脫的管線符號數必須等於欄位分隔數
        # In a table row the number of unescaped pipes must equal the column separators
        if line.startswith("|") and "injected" in line:
            assert "| injected |" not in line, line
    heading = next(line for line in md.splitlines() if line.startswith("#### "))
    assert "``" in heading and "READY_TO_SHIP" in heading


# --- 換行偽造 --------------------------------------------------------------------------------------
# --- Newline spoofing ------------------------------------------------------------------------------

def test_model_free_text_cannot_spoof_a_verdict_heading():
    """發現標題、根本原因、共識摘要、系統描述與建議中的換行不能開出新的區塊。
    Newlines in finding titles, root causes, the consensus summary, the system description and the
    recommendations cannot open a new block."""
    finding = _finding(title=SPOOF, root_cause=SPOOF, suspected_vibe_flaw=SPOOF, suggested_test_scenario=SPOOF)
    debate = MultiModelDebateResult(consensus_summary=SPOOF, arbitration_applied=True,
                                    confirmed_findings=[finding], disputed_findings=[finding])
    summary = _summary(key_recommendations=[SPOOF], inconclusive_reasons=[SPOOF])
    md = ReportGenerator().generate_markdown_report(
        summary=summary, debate_result=debate,
        threat_model=ThreatModelReport(system_description=SPOOF, threats=[_threat(title=SPOOF, attack_vector=SPOOF)]),
        whitebox_results=[TestExecutionResult(test_id="w", test_type="whitebox_unit", status=TestStatus.FAILED,
                                              failure_reason=SPOOF)],
        blackbox_results=[], target_path="t",
    )
    _no_spoofed_blocks(md)
    assert "READY_TO_SHIP" in md  # 內容仍然看得到，只是不再是標題 ／ the text is still visible, just not as a heading


def test_unicode_line_separators_are_collapsed():
    """Unicode 行／段落分隔符號也在單行情境中收合。
    Unicode line / paragraph separators are collapsed in single-line contexts too."""
    assert "\u2028" not in ReportGenerator._inline("a\u2028b\u2029c")
    assert "\n" not in ReportGenerator._cell("a\n\nb")


# --- 未經驗證的假設 ---------------------------------------------------------------------------------
# --- Unverified hypotheses ---------------------------------------------------------------------------

def test_report_shows_na_when_verification_was_not_applied():
    """未套用驗證時，報告顯示 N/A 與未經驗證的假設數，不稱它們為已確認。
    Without verification the report shows N/A and the number of unverified hypotheses, never "confirmed"."""
    debate = MultiModelDebateResult(consensus_summary="c", arbitration_applied=False,
                                    confirmed_findings=[_finding(), _finding(finding_id="WB-2")])
    md = _report(summary=_summary(confirmed_whitebox_bugs=0), debate=debate)
    row = next(line for line in md.splitlines() if "Confirmed White-Box Logic Flaws" in line)
    assert "`N/A`" in row and "2 unverified hypotheses" in row
    assert "Unverified Defect Hypotheses" in md
    assert "Confirmed Logic & Defensive Blindspots" not in md


def test_report_keeps_the_confirmed_count_when_verification_ran():
    """套用驗證時照常顯示已確認數。
    With verification the confirmed count is shown as before."""
    md = _report(debate=MultiModelDebateResult(consensus_summary="c", arbitration_applied=True,
                                                confirmed_findings=[_finding()]))
    row = next(line for line in md.splitlines() if "Confirmed White-Box Logic Flaws" in line)
    assert "`1`" in row


def test_sarif_marks_unverified_hypotheses(tmp_path):
    """SARIF 的白箱結果標示是否經過驗證。
    SARIF white-box results say whether they were verified."""
    debate = MultiModelDebateResult(consensus_summary="c", arbitration_applied=False, confirmed_findings=[_finding()])
    sarif = json.loads(ReportGenerator().generate_sarif_report(
        summary=_summary(confirmed_whitebox_bugs=0), debate_result=debate,
        threat_model=ThreatModelReport(system_description="s"), whitebox_results=[], blackbox_results=[],
        target_path=str(tmp_path),
    ))
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["verified"] is False
    assert result["message"]["text"].startswith("未經驗證") or "Unverified hypothesis" in result["message"]["text"]


# --- SARIF 路徑 --------------------------------------------------------------------------------------
# --- SARIF URI ------------------------------------------------------------------------------------

def test_sarif_uri_resolves_cwd_relative_paths(tmp_path, monkeypatch):
    """相對於工作目錄的路徑先解析，再相對於 %SRCROOT%。
    A cwd-relative path is resolved before it is relativized against %SRCROOT%."""
    root = tmp_path / "repo"
    sub = root / "pkg"
    sub.mkdir(parents=True)
    (sub / "mod.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(sub)
    assert ReportGenerator._sarif_uri("mod.py", str(root)) == "pkg/mod.py"


def test_sarif_uri_never_emits_dotdot_segments(tmp_path):
    """URI 絕不含 `..` 片段：跳出的相對路徑被省略，%SRCROOT% 之外的絕對路徑改用 file:// URI。
    URIs never contain `..` segments: an escaping relative path is omitted, an absolute path outside
    %SRCROOT% becomes a file:// URI."""
    uri = ReportGenerator._sarif_uri
    root = tmp_path / "repo"
    root.mkdir()
    assert uri("../../etc/passwd", str(root)) is None
    assert uri("pkg/../../x.py", str(root)) is None
    assert uri("pkg/../x.py", str(root)) == "x.py"
    outside = uri(str(tmp_path / "other" / "x.py"), str(root))
    assert outside.startswith("file://") and ".." not in outside
    assert uri("..\\..\\x.py", r"D:\repo") is None
    assert uri(r"D:\other\x.py", r"D:\repo") == "file:///D:/other/x.py"
    assert uri(r"d:\repo\pkg\x.py", r"D:\repo") == "pkg/x.py"


def test_sarif_location_omits_the_base_for_absolute_uris():
    """絕對 file:// URI 的位置不帶 %SRCROOT%。
    A location with an absolute file:// URI carries no %SRCROOT% base."""
    loc = ReportGenerator._location("file:///tmp/x.py", 1)["physicalLocation"]["artifactLocation"]
    assert "uriBaseId" not in loc
    assert ReportGenerator._location("x.py", 1)["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"


# --- 資安突破的 SARIF 位置 ----------------------------------------------------------------------------
# --- SARIF location of a Breach -------------------------------------------------------------------------
# 比對規則本身的測試在 tests/test_threat_symbols.py ／ the matching rule's own tests are in tests/test_threat_symbols.py

def _breach_location(tmp_path, attack_vector, symbols):
    """一個衍生自指定威脅的資安突破，在 SARIF 裡的位置：(相對 URI, 行號)，沒有位置時為 None。
    The SARIF location of one Breach derived from the given threat: (relative URI, line), or None without one."""
    threat = _threat(threat_id="T-1", attack_vector=attack_vector, attack_scenario="")
    breach = TestExecutionResult(test_id="BB-1", test_type="blackbox_security", status=TestStatus.FAILED,
                                 is_security_exploit_confirmed=True, source_ref="T-1")
    sarif = json.loads(ReportGenerator().generate_sarif_report(
        summary=_summary(), debate_result=MultiModelDebateResult(consensus_summary="c", arbitration_applied=True),
        threat_model=ThreatModelReport(system_description="s", threats=[threat]), whitebox_results=[],
        blackbox_results=[breach], target_path=str(tmp_path), symbols=symbols,
    ))
    result = next(r for r in sarif["runs"][0]["results"] if r["properties"].get("security_breach"))
    if "locations" not in result:
        return None
    location = result["locations"][0]["physicalLocation"]
    return location["artifactLocation"]["uri"], location["region"]["startLine"]


@pytest.mark.parametrize("attack_vector, names, expected", [
    # 只寫路由的路徑（沒有 HTTP 方法），文中還提到另一個函式 ／ a bare route path (no HTTP method), another function in the text
    ("Send a crafted body to /api/users; helper is reached.", ["GET /api/users", "helper"], ("app.py", 10)),
    # 只寫路由的路徑，沒有其他符號 ／ a bare route path and no other symbol
    ("Send a crafted body to /api/users.", ["GET /api/users"], ("app.py", 10)),
    # `$init` 是另一個 JS 識別字，不是 `init` ／ `$init` is another JS identifier, not `init`
    ("Call $init() with a forged token.", ["init"], None),
], ids=["bare-path-and-helper", "bare-path-only", "js-dollar-prefix"])
def test_sarif_locates_a_breach_where_the_attack_script_looked(tmp_path, attack_vector, names, expected):
    """資安突破在 SARIF 的位置，跟攻擊腳本依據的符號同一套規則：只寫路徑的路由指向那個路由；
    `$init` 不算指名 `init`，所以沒有位置（攻擊腳本也沒拿 `init` 的程式碼）。
    A Breach's SARIF location follows the same rule as the symbols its attack script was built from: a route named
    by its bare path points at that route; `$init` does not name `init`, so there is no location (the attack
    script did not get `init`'s code either)."""
    catalogue = {
        "GET /api/users": _symbol("GET /api/users", "route", file_path=str(tmp_path / "app.py"), line=10),
        "helper": _symbol("helper", file_path=str(tmp_path / "app.py"), line=40),
        "init": _symbol("init", file_path=str(tmp_path / "app.js"), line=5),
    }
    assert _breach_location(tmp_path, attack_vector, [catalogue[n] for n in names]) == expected


def test_sarif_uri_escaping_path_is_omitted_whatever_the_working_directory(tmp_path, monkeypatch):
    """跳出 %SRCROOT% 的相對路徑即使相對於工作目錄真的存在，也不會變成 file:// URI。
    An escaping relative path is never turned into a file:// URI just because it exists relative to the cwd."""
    root = tmp_path / "a" / "b" / "repo"
    root.mkdir(parents=True)
    (tmp_path / "secret.txt").write_text("x", encoding="utf-8")
    monkeypatch.chdir(tmp_path / "a" / "b")
    assert ReportGenerator._sarif_uri("../../secret.txt", str(root)) is None
