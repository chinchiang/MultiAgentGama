import html
import json
import ntpath
import os
import pathlib
import posixpath
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple
from vibeharness.core.models import (
    CodeSymbol,
    MultiModelDebateResult,
    ReviewFinding,
    ThreatItem,
    ThreatModelReport,
    TestExecutionResult,
    GeneratedTest,
    VibeHarnessSummary,
    TestStatus,
    FindingSeverity,
    StaticFinding
)
from vibeharness.core.identity import (
    is_unknown_location, sarif_breach_fingerprint, sarif_finding_fingerprint, sarif_static_fingerprint,
)
from vibeharness.core.i18n import bi
from vibeharness.core.sanitize import clean_model_text, markdown_safe

# Windows 磁碟機路徑（"C:\..."）即使在 POSIX 主機上也算絕對路徑，讓
# 在 Windows 產生的 SARIF 交給 Linux CI runner 重新處理時，相對化結果一致。
# Windows drive paths ("C:\...") count as absolute even on POSIX hosts, so a SARIF produced
# on Windows relativizes identically when re-processed by a Linux CI runner.
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
# 單行情境中要收合的換行：\n 以及 Unicode 的行／段落分隔符號（\r 已由 clean_model_text 移除）
# Line breaks collapsed in single-line contexts: \n and the Unicode line / paragraph separators
# (\r is already removed by clean_model_text)
_LINE_BREAK_RE = re.compile(r"[\n\u2028\u2029\x85]+")

# 穩定的 SARIF 規則 id：GitHub Code Scanning 以 ruleId + 指紋追蹤警示，所以每次執行
# 不同的發現 id（WB-CLA-01 只是「這次執行 Claude 的第一個發現」）會在編號變動時
# 不斷關閉又重開警示。執行專屬的 id 保留在每個結果的 properties 裡。
# Stable SARIF rule ids: GitHub Code Scanning tracks alerts by ruleId + fingerprint, so a per-run
# finding id (WB-CLA-01 is just "Claude's first finding this run") would close and reopen alerts
# whenever the numbering shifted. The run-specific ids are kept in each result's properties.
SARIF_RULE_WHITEBOX = "vibeharness/whitebox-finding"
SARIF_RULE_BLACKBOX = "vibeharness/blackbox-breach"
# 確定性 AI 資安規則保有自己的穩定 id：vibeharness/VH-AI-001、...
# Deterministic AI-security rules keep their own stable ids: vibeharness/VH-AI-001, ...
SARIF_RULE_STATIC_PREFIX = "vibeharness/"
# JSON 報告版面的版本（summary／whitebox／threat_model／blackbox_* 鍵）
# Version of the JSON report layout (summary / whitebox / threat_model / blackbox_* keys)
# "2"：沒有套用跨模型驗證時 summary.confirmed_whitebox_bugs 為 null（"1" 為 0）
# "2": summary.confirmed_whitebox_bugs is null when cross-model verification was not applied ("1" had 0)
JSON_SCHEMA_VERSION = "2"


def agreement_display(result: MultiModelDebateResult) -> str:
    """跨模型一致度的顯示字串，報告與 console 共用。`MultiModelDebater` 套用驗證時一定有決定性投票，
    但結果模型也可能由其他路徑建立（例如讀回的 JSON），所以缺少比例時仍回傳 N/A 而不是出錯。
    Display string of the cross-model agreement, shared by the report and the console. `MultiModelDebater`
    always has decisive votes when verification is applied, but the result model can be built elsewhere
    (e.g. JSON read back), so a missing ratio still yields N/A instead of an error."""
    if not result.arbitration_applied:
        return bi("N/A（未套用驗證）", "N/A (verification not applied)")
    ratio = result.model_agreement_ratio
    return f"{ratio * 100:.1f}%" if ratio is not None else bi("N/A（沒有決定性投票）", "N/A (no decisive votes)")

# 報告中的固定標題與表頭（中文 ／ English），測試可直接匯入
# Fixed report headings and table headers (Chinese / English), importable by tests
REPORT_TITLE = "# 🛡️ " + bi("VibeHarness-MAS 多代理品質與資安報告", "VibeHarness-MAS Multi-Agent Quality & Security Report")
HEADING_EXECUTIVE_SUMMARY = "## 1. 📊 " + bi("執行摘要與品質閘門", "Executive Summary & Quality Gate")
HEADING_WHITEBOX = "## 2. 🔬 " + bi("第 2–3 階段：異質白箱程式碼審查、驗證與測試",
                                   "Phases 2–3: Heterogeneous White-Box Code Review, Verification & Tests")
HEADING_THREAT_MODEL = "## 3. 🎯 " + bi("第 4 階段：黑箱威脅建模（STRIDE 與 OWASP）",
                                       "Phase 4: Black-Box Threat Modeling (STRIDE & OWASP)")
HEADING_BLACKBOX = "## 4. ⚡ " + bi("第 5 階段：威脅衍生的黑箱動態測試執行",
                                   "Phase 5: Threat-Derived Black-Box Dynamic Test Execution")
HEADING_NEXT_STEPS = "## 5. 💡 " + bi("給 Vibe Coder 的可行後續步驟", "Actionable Next Steps for Vibe Coder")
HEADING_GENERATED_TESTS = "## 6. 🧪 " + bi("產生的測試程式碼（稽核軌跡）", "Generated Test Code (audit trail)")
HEADING_VERDICT = "### " + bi("判定結果", "Verdict")
HEADING_STATIC_RULES = "### " + bi("確定性 AI 資安規則（不涉及模型）", "Deterministic AI-Security Rules (no model involved)")
HEADING_PROVENANCE = "### " + bi("執行來源", "Execution Provenance")
HEADING_CONFIRMED_FINDINGS = "### " + bi("已確認的邏輯與防禦盲點", "Confirmed Logic & Defensive Blindspots")
HEADING_UNVERIFIED_FINDINGS = "### " + bi("未經驗證的缺陷假設（未套用跨模型驗證）",
                                          "Unverified Defect Hypotheses (cross-model verification not applied)")
HEADING_DISPUTED_FINDINGS = "### " + bi("有爭議的發現（遭跨模型多數否決，未測試）",
                                        "Disputed Findings (rejected by a cross-model majority, not tested)")
HEADING_WHITEBOX_RESULTS = "### " + bi("白箱測試執行結果", "White-Box Test Execution Results")
HEADING_MUTANTS = "### 🧬 " + bi("突變測試：存活的變異體", "Mutation Testing: Surviving Mutants")
HEADING_POCS = "### 🚨 " + bi("已確認弱點的概念驗證（PoC）", "Confirmed Vulnerability Proof of Concepts (PoCs)")
HEADING_UNTESTED_THREATS = "### ⚪ " + bi("未測試的威脅", "Threats Not Tested")
METRIC_TABLE_HEADER = f"| {bi('指標', 'Metric')} | {bi('數值', 'Value')} | {bi('目標', 'Target')} |"
PROVENANCE_TABLE_HEADER = (f"| {bi('代理', 'Agent')} | {bi('模型', 'Model')} | {bi('模式', 'Mode')} | "
                           f"{bi('呼叫數', 'Calls')} | {bi('原因', 'Reason')} |")
WHITEBOX_TABLE_HEADER = (f"| {bi('測試 ID', 'Test ID')} | {bi('類型', 'Type')} | {bi('來源', 'Derived From')} | "
                         f"{bi('狀態', 'Status')} | {bi('耗時', 'Duration')} | {bi('結果', 'Outcome')} |")
MUTANT_TABLE_HEADER = (f"| {bi('位置', 'Location')} | {bi('符號', 'Symbol')} | {bi('類別', 'Operator')} | "
                        f"{bi('原本', 'Original')} | {bi('變異後', 'Mutated')} |")
THREAT_TABLE_HEADER = (f"| {bi('威脅 ID', 'Threat ID')} | {bi('STRIDE 類別', 'STRIDE Category')} | "
                       f"{bi('OWASP 對應', 'OWASP Mapping')} | MITRE ATLAS | {bi('嚴重度', 'Severity')} | "
                       f"{bi('威脅標題與攻擊向量', 'Threat Title & Attack Vector')} |")
BLACKBOX_TABLE_HEADER = (f"| {bi('測試 ID', 'Test ID')} | {bi('類型', 'Type')} | {bi('狀態', 'Status')} | "
                         f"{bi('延遲', 'Latency')} | {bi('結果與利用情形', 'Outcome / Exploitation')} |")
STATIC_TABLE_HEADER = (f"| {bi('規則', 'Rule')} | {bi('嚴重度', 'Severity')} | {bi('位置', 'Location')} | "
                       f"{bi('發現', 'Finding')} | OWASP | MITRE ATLAS | CWE |")
# 測試結果標籤 ／ Test outcome labels
STATUS_PASSED = "✅ " + bi("通過", "PASSED")
STATUS_FAILED = "❌ " + bi("失敗", "FAILED")
STATUS_ERROR = "⚠️ " + bi("錯誤（不是發現）", "ERROR (not a finding)")
STATUS_SKIPPED = "⏭️ " + bi("已略過", "SKIPPED")
OUTCOME_VULNERABLE = "❌ " + bi("存在弱點", "VULNERABLE")
OUTCOME_NOT_RUN = bi("未執行", "not run")
LABEL_FROM = bi("來自", "from")


class ReportGenerator:
    """
    產生結構化、稽核等級的 Markdown 報告，詳述完整的
    多代理白箱與黑箱驗證生命週期。
    Generates a structured, audit-grade Markdown report detailing the complete
    multi-agent white-box and black-box verification lifecycle.
    """

    def generate_markdown_report(
        self,
        summary: VibeHarnessSummary,
        debate_result: MultiModelDebateResult,
        threat_model: ThreatModelReport,
        whitebox_results: List[TestExecutionResult],
        blackbox_results: List[TestExecutionResult],
        target_path: str,
        whitebox_tests: Optional[List[GeneratedTest]] = None,
        blackbox_tests: Optional[List[GeneratedTest]] = None
    ) -> str:
        md = []

        # 標頭
        # Header
        md.append(REPORT_TITLE)
        md.append(f"**{bi('目標系統路徑', 'Target System Path')}**: {self._code_span(os.path.abspath(target_path))}  ")
        md.append(f"**{bi('協調者', 'Orchestrator')}**: {bi('Commander Harness 代理', 'Commander Harness Agent')}  ")
        md.append(f"**{bi('整體狀態', 'Overall Status')}**: `{summary.overall_status}`  ")
        if summary.run:
            run = summary.run
            revision = run.target_git_commit or bi("不是 git 版本庫", "not a git repository")
            if run.target_git_commit and run.target_git_dirty:
                revision += f" ({bi('有未提交的變更', 'uncommitted changes')})"
            md.append(f"**{bi('產生時間', 'Generated')}**: {run.generated_at} "
                      f"{bi(f'由 VibeHarness-MAS {run.harness_version} 產生', f'by VibeHarness-MAS {run.harness_version}')} "
                      f"(mode `{run.execution_mode}`, sandbox `{run.sandbox_provider}`)  ")
            md.append(f"**{bi('目標修訂', 'Target revision')}**: {self._code_span(revision)}  ")
            md.append(f"**{bi('設定檔', 'Config')}**: {self._code_span(run.config_path)}  ")
            if run.file_filters:
                md.append(f"**{bi('檔案篩選', 'File selection')}**: {self._code_span('; '.join(run.file_filters))}  ")
        md.append("\n---\n")

        simulated_calls = [c for c in summary.agent_calls if c.mode == "simulated"]
        if simulated_calls:
            all_simulated = len(simulated_calls) == len(summary.agent_calls)
            scope = "ALL" if all_simulated else "SOME"
            scope_zh = "全部" if all_simulated else "部分"
            md.append(
                f"> ⚠️ **{bi(f'模擬結果 — 本報告中{scope_zh}代理輸出來自離線模擬引擎', f'SIMULATED RESULTS — {scope} agent outputs in this report come from the offline simulation engine')}**, "
                + bi("它回傳與目標程式碼無關的固定範本回應。標示 `[SIMULATED]` 的發現、共識比例與威脅模型並非真實的模型稽核。"
                     "只有已執行的測試結果反映目標的實際行為。",
                     "which returns fixed template responses independent of the target code. "
                     "Findings, consensus ratio and threat model marked `[SIMULATED]` are NOT a real model audit. "
                     "Only executed test outcomes reflect the actual target behaviour.") + "\n"
            )

        # 1. 執行摘要
        # 1. Executive Summary
        md.append(HEADING_EXECUTIVE_SUMMARY)
        status_badge = {
            "READY_TO_SHIP": f"🟢 **{bi('通過：可以出貨', 'PASS: READY TO SHIP')}**",
            "NEEDS_FIXES": f"🟠 **{bi('未通過：需要修正', 'FAIL: NEEDS FIXES')}**",
            "INCONCLUSIVE": f"🟡 **{bi('無法判定：證據不足', 'INCONCLUSIVE: INSUFFICIENT EVIDENCE')}**",
            "BLOCKED_CRITICAL_RISK": f"🔴 **{bi('未通過：遭關鍵風險阻擋', 'FAIL: BLOCKED BY CRITICAL RISKS')}**",
        }.get(summary.overall_status, f"⚠️ **{bi('未知狀態', 'UNKNOWN STATUS')}: `{summary.overall_status}`**")
        md.append(f"{HEADING_VERDICT}: {status_badge}\n")
        if summary.baseline_path:
            n_known = len(summary.baseline_suppressed)
            md.append(f"**{bi('基準', 'Baseline')}**: {self._code_span(summary.baseline_path)} — "
                      f"{bi(f'{n_known} 個已知問題已列出但不計入判定', f'{n_known} known problem(s) reported but not counted in the verdict')}  ")
            if summary.baseline_suppressed:
                md.append(f"\n**{bi('基準中的已知問題（不計入）', 'Known from baseline (not counted)')}:**")
                for item in summary.baseline_suppressed:
                    md.append(f"- {self._code_span(item.id)} ({item.kind}): {self._inline(item.title)}")
            md.append("")
        if summary.inconclusive_reasons:
            md.append(f"**{bi('證據缺口', 'Evidence gaps')}:**")
            for reason in summary.inconclusive_reasons:
                md.append(f"- {self._inline(reason)}")  # 原因會引用模型選的 id 與失敗文字 ／ reasons quote model-chosen ids and failure text
            md.append("")

        sim_tag = " `[SIMULATED]`" if debate_result.is_simulated else ""
        md.append(METRIC_TABLE_HEADER)
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **{bi('主要目標語言', 'Primary Target Language')}** | `{summary.detected_language}` | {bi('支援的技術堆疊', 'Supported Stack')} |")
        ratio_str = agreement_display(debate_result)
        md.append(f"| **{bi('跨模型一致度', 'Cross-Model Agreement')}** | `{ratio_str}`{sim_tag} | {bi('一致度 ≥ 70%', '≥ 70% Agreement')} |")
        cov_str = f"{summary.line_coverage_pct:.1f}%" if summary.line_coverage_pct is not None else "N/A"
        if summary.js_line_coverage_pct is not None or any(r.language != "python" for r in whitebox_results):
            # 有 JS/TS 白箱測試時兩種語言分開列（各自的分母不同，不合併成一個數字）；純 Python 的報告維持原樣
            # With JS/TS white-box tests both languages are listed separately (their denominators differ, so they are
            # never merged into one number); a Python-only report stays as it was
            js_str = f"{summary.js_line_coverage_pct:.1f}%" if summary.js_line_coverage_pct is not None else "N/A"
            cov_str = f"Python {cov_str} / JS/TS {js_str}"
        md.append(f"| **{bi('程式碼行涵蓋率', 'Code Line Coverage')}** | `{cov_str}` | {bi('基準 ≥ 80%', '≥ 80% Baseline')} |")
        if summary.mutation is not None:
            mut = summary.mutation
            mut_str = f"{mut.score:.1f}% ({mut.killed} {bi('殺死', 'killed')} / {mut.survived} {bi('存活', 'survived')} / {mut.invalid} {bi('無效', 'invalid')})" \
                if mut.score is not None else "N/A"
            md.append(f"| **{bi('突變測試分數', 'Mutation Score')}** | `{mut_str}` | {bi('越高越好；是下界', 'higher is better; a lower bound')} |")
        if summary.distinct_whitebox_findings is not None:
            md.append(f"| **{bi('審查者發現（原始 → 去重後）', 'Reviewer Findings (raw → distinct)')}** | `{summary.total_whitebox_findings} → {summary.distinct_whitebox_findings}` | - |")
        if debate_result.arbitration_applied and summary.confirmed_whitebox_bugs is not None:
            md.append(f"| **{bi('已確認的白箱邏輯缺陷', 'Confirmed White-Box Logic Flaws')}** | `{summary.confirmed_whitebox_bugs}` | {bi('0 個關鍵', '0 Critical')} |")
        else:
            # 沒有套用驗證時沒有任何東西被確認：顯示 N/A 與未經驗證的假設數，而不是把它們稱為已確認的缺陷
            # Without verification nothing was confirmed: show N/A and the number of unverified hypotheses
            # instead of calling them confirmed flaws
            n_hyp = len(debate_result.confirmed_findings)
            md.append(f"| **{bi('已確認的白箱邏輯缺陷', 'Confirmed White-Box Logic Flaws')}** | `N/A` "
                      f"({bi(f'{n_hyp} 個未經驗證的假設；未套用驗證', f'{n_hyp} unverified hypotheses; verification not applied')}) | "
                      f"{bi('0 個關鍵', '0 Critical')} |")
        n_err = summary.whitebox_tests_errored
        md.append(f"| **{bi('白箱測試通過', 'White-Box Tests Passed')}** | `{summary.whitebox_tests_passed} / {len(whitebox_results)}` "
                  f"({bi(f'{n_err} 個錯誤或未執行', f'{n_err} errored / not run')}) | {bi('通過率 100%', '100% Pass Rate')} |")
        md.append(f"| **{bi('已建模的 STRIDE 威脅情境', 'STRIDE Threat Scenarios Modeled')}** | `{summary.total_threats_modeled}` | {bi('完整資產涵蓋', 'Full Asset Coverage')} |")
        md.append(f"| **{bi('沒有可執行測試的威脅', 'Threats Without Executable Test')}** | `{len(summary.untested_threat_ids)}` | {bi('0 個未測試', '0 Untested')} |")
        md.append(f"| **{bi('已確認的黑箱資安突破', 'Confirmed Black-Box Security Breaches')}** | `{summary.blackbox_security_breaches}` | {bi('不容許任何突破', '0 Breaches Tolerated')} |")
        md.append(f"| **{bi('黑箱測試失敗（未分類）', 'Black-Box Tests Failed (unclassified)')}** | `{summary.blackbox_tests_failed}` | "
                  f"{bi('0 — 失敗的攻擊腳本需人工審查', '0 — failing attack scripts need manual review')} |")
        blocking = sum(1 for f in summary.static_findings if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH))
        new_blocking = summary.new_blocking_rule_hits
        if summary.baseline_path and new_blocking is not None:
            # --baseline：與判定結果一致，只有新的 HIGH 以上命中計入；已知的另外列出
            # --baseline: as in the verdict, only new HIGH+ hits count; the known ones are shown separately
            hits = bi(f"{new_blocking} 個新的 HIGH+，{blocking - new_blocking} 個基準中已知",
                      f"{new_blocking} HIGH+ new, {blocking - new_blocking} known from baseline")
            target = bi("0 個新的 HIGH+", "0 new HIGH+")
        else:
            hits, target = f"{blocking} HIGH+", "0 HIGH+"
        md.append(f"| **{bi('確定性 AI 資安規則命中', 'Deterministic AI-Security Rule Hits')}** | `{len(summary.static_findings)}` ({hits}) | {target} |")
        md.append("\n")
        if summary.reviewer_models:
            n_models = len(summary.reviewer_models)
            md.append(f"**{bi('審查模型', 'Reviewer models')}** ({bi(f'{n_models} 個不同模型', f'{n_models} distinct')}): {self._code_span(', '.join(summary.reviewer_models))}  ")
        if summary.ai_components:
            md.append(f"**{bi('偵測到的 AI/LLM 元件', 'AI/LLM components detected')}**: {self._code_span(', '.join(summary.ai_components))} — "
                      f"{bi('威脅建模已套用 OWASP Top 10 for LLM Applications 2026', 'OWASP Top 10 for LLM Applications 2026 applied to threat modeling')}  ")
        md.append("")
        md.extend(self._static_section(summary.static_findings))

        # 執行來源
        # Provenance
        md.append(HEADING_PROVENANCE)
        if summary.agent_calls:
            md.append(PROVENANCE_TABLE_HEADER)
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            grouped: Dict[Tuple[str, str, str, str], int] = {}
            for c in summary.agent_calls:
                key = (c.agent_id, c.model_name, "cached" if c.cached else c.mode, c.reason or "")
                grouped[key] = grouped.get(key, 0) + 1
            # 依 agent、模型、模式排序：呼叫是並行完成的，照完成順序會讓同一次執行的報告每次列序不同
            # Sorted by agent, model, mode: calls finish concurrently, so completion order would make the rows
            # of the same run come out in a different order each time
            for (agent_id, model_name, mode, reason), count in sorted(grouped.items()):
                mode_label = {"live": "🟢 " + bi("真實", "live"), "cached": "🟢 " + bi("真實（回應快取）", "live (response cache)"),
                              "simulated": "🟡 " + bi("模擬", "simulated"),
                              "retried": "🟠 " + bi("無法使用，已重問", "unusable, re-asked")}.get(mode, "🔴 " + bi("無效輸出", "invalid output"))
                md.append(f"| {self._cell_code(agent_id)} | {self._cell_code(model_name)} | {mode_label} | {count} | {self._cell(reason) or '-'} |")
        else:
            md.append(bi("沒有記錄到任何代理呼叫。", "No agent invocations were recorded."))
        md.append("\n")

        # 2. 白箱多模型審查發現
        # 2. White-Box Multi-Model Review Findings
        md.append(HEADING_WHITEBOX)
        models = " / ".join(summary.reviewer_models) or "the configured reviewer models"
        models_zh = " / ".join(summary.reviewer_models) or "設定的審查模型"
        if debate_result.is_simulated or any(f.is_simulated for f in debate_result.confirmed_findings):
            md.append(f"> **{bi('去偏差架構（模擬）', 'De-biasing Architecture (SIMULATED)')}**: "
                      + bi(f"以下的審查者與驗證者輸出是模擬範本，並非真實的 {models_zh} 稽核。",
                           f"Reviewer and verifier outputs below are simulation templates, not real {models} audits.") + "\n")
        else:
            md.append(f"> **{bi('去偏差架構', 'De-biasing Architecture')}**: "
                      + bi(f"發現已由 {models_zh} 交叉稽核；沒有模型裁決自己的發現。",
                           f"Findings cross-audited across {models}; no model rules on its own finding.") + "\n")
        md.append(f"**{bi('辯論共識摘要', 'Debate Consensus Summary')}**{sim_tag}: {self._inline(debate_result.consensus_summary)}\n")

        if debate_result.confirmed_findings:
            n_tie = debate_result.undecided_count
            kept = f" ({bi(f'{n_tie} 個未決的平手已保留供測試', f'{n_tie} undecided tie(s) kept for testing')})" if n_tie else ""
            if debate_result.arbitration_applied:
                md.append(f"{HEADING_CONFIRMED_FINDINGS}{kept}:")
            else:
                md.append(f"{HEADING_UNVERIFIED_FINDINGS}:")
            for f in debate_result.confirmed_findings:
                tag = " `[SIMULATED]`" if f.is_simulated else ""
                also = f"; {bi('亦見於', 'also reported by')} {', '.join(f.corroborated_by)}" if f.corroborated_by else ""
                mapping = f" {self._code_span(f.owasp_mapping)}" if f.owasp_mapping else ""
                md.append(f"- **[{f.severity.value}] {self._inline(f.title)}**{mapping}{tag} ({bi('發現者', 'Identified by')} {f.reviewer_name}{also})")
                md.append(f"  - **{bi('根本原因', 'Root Cause')}**: {self._inline(f.root_cause)}")
                md.append(f"  - **{bi('Vibe-Coding 缺陷', 'Vibe-Coding Flaw')}**: {self._inline(f.suspected_vibe_flaw)}")
                md.append(f"  - **{bi('建議情境', 'Suggested Scenario')}**: {self._code_span(f.suggested_test_scenario)}")
                if f.verification_votes:
                    md.append(f"  - **{bi('驗證', 'Verification')}**: {self._votes(f)}")
        else:
            md.append("✅ " + bi("未發現關鍵的白箱缺陷。", "No critical white-box defects identified."))

        if debate_result.disputed_findings:
            md.append(f"\n{HEADING_DISPUTED_FINDINGS}:")
            for f in debate_result.disputed_findings:
                md.append(f"- [{f.severity.value}] {self._inline(f.title)} ({bi('發現者', 'Identified by')} {f.reviewer_name}) — {self._votes(f)}")

        md.append(f"\n{HEADING_WHITEBOX_RESULTS}")
        if whitebox_results:
            md.append(WHITEBOX_TABLE_HEADER)
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for r in whitebox_results:
                md.append(f"| {self._cell_code(r.test_id)} | {r.test_type} | {self._cell_code(r.source_ref)} | {self._status_label(r.status)} | `{r.duration_seconds}s` | {self._cell(r.failure_reason) or bi('通過', 'Passed')} |")
        else:
            md.append(bi("未執行任何白箱測試。", "No white-box tests executed."))

        mutation = summary.mutation
        if mutation is not None:
            md.append(f"\n{HEADING_MUTANTS}")
            survivors = [m for m in mutation.mutants if m.status == "survived"]
            if mutation.skipped_reason and mutation.score is None:
                md.append(f"{bi('沒有結論', 'No conclusion')}: {self._inline(mutation.skipped_reason)}")
            elif survivors:
                md.append(MUTANT_TABLE_HEADER)
                md.append("| :--- | :--- | :--- | :--- | :--- |")
                for m in survivors:
                    md.append(f"| {self._cell_code(f'{m.file}:{m.line}')} | {self._cell_code(m.symbol)} | {m.operator} | "
                              f"{self._cell_code(m.original)} | {self._cell_code(m.mutated)} |")
            else:
                md.append(bi("沒有存活的變異體。", "No surviving mutants."))

        md.append("\n")

        # 3. 黑箱威脅建模矩陣
        # 3. Black-Box Threat Modeling Matrix
        md.append(HEADING_THREAT_MODEL + (" `[SIMULATED]`" if threat_model.is_simulated else ""))
        md.append(f"**{bi('系統描述', 'System Description')}**: {self._inline(threat_model.system_description)}  ")
        md.append(f"**{bi('稽核的進入點', 'Entrypoints Audited')}**: {self._code_span(self._join_list(threat_model.entrypoints))}  ")
        md.append(f"**{bi('信任邊界', 'Trust Boundaries')}**: {self._code_span(self._join_list(threat_model.trust_boundaries))}\n")

        md.append(THREAT_TABLE_HEADER)
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for t in threat_model.threats:
            owasp = self._cell(t.owasp_mapping) or "N/A"
            atlas = self._cell(t.atlas_mapping) or "-"
            md.append(f"| {self._cell_code(t.threat_id)} | **{t.stride_category.value}** | {owasp} | {atlas} | `{t.severity.value}` | **{self._cell(t.title)}**<br>*{self._cell(t.attack_vector)}* |")

        md.append("\n")

        # 4. 黑箱動態資安執行結果
        # 4. Black-Box Dynamic Security Execution Results
        md.append(HEADING_BLACKBOX)
        if blackbox_results:
            md.append(BLACKBOX_TABLE_HEADER)
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for r in blackbox_results:
                status_icon = OUTCOME_VULNERABLE if r.is_security_exploit_confirmed else self._status_label(r.status)
                md.append(f"| {self._cell_code(r.test_id)} | {r.test_type} | {status_icon} | `{r.duration_seconds}s` | {self._cell(r.failure_reason) or bi('邊界已防禦', 'Boundary defended')} |")

            # 檢查是否有重現 PoC
            # Check for reproduction PoCs
            pocs = [r for r in blackbox_results if r.reproduction_poc and r.is_security_exploit_confirmed]
            if pocs:
                md.append(f"\n{HEADING_POCS}:")
                for p in pocs:
                    md.append(f"#### {bi('PoC 對象', 'PoC for')} {self._code_span(p.test_id)}")
                    poc_text = p.reproduction_poc or ""
                    fence = self._fence(poc_text)
                    md.append(f"{fence}{self._fence_lang(p.language)}\n{poc_text}\n{fence}")
        else:
            md.append(bi("未執行任何黑箱測試。", "No black-box tests executed."))

        if summary.untested_threat_ids:
            md.append(f"\n{HEADING_UNTESTED_THREATS}")
            md.append(bi("這些威脅沒有合成出可執行的測試；既未確認也未排除：",
                         "No executable test was synthesized for these threats; they are neither confirmed nor ruled out:"))
            for threat_id in summary.untested_threat_ids:
                md.append(f"- {self._code_span(threat_id)}")  # 模型選的 id 無法跳出程式碼區段 ／ a model-chosen id cannot break out of the span

        md.append("\n")

        # 5. 給 Vibe Coder 的關鍵建議
        # 5. Key Recommendations for Vibe Coder
        md.append(HEADING_NEXT_STEPS)
        for rec in summary.key_recommendations:
            md.append(f"- {self._inline(rec)}")

        md.extend(self._generated_tests_section(whitebox_tests, whitebox_results, blackbox_tests, blackbox_results))

        md.append("\n---\n*" + bi("由 VibeHarness-MAS Harness Commander 自動產生。",
                                   "Generated automatically by VibeHarness-MAS Harness Commander.") + "*")

        return "\n".join(md)

    def generate_json_report(
        self,
        summary: VibeHarnessSummary,
        debate_result: MultiModelDebateResult,
        threat_model: ThreatModelReport,
        whitebox_results: List[TestExecutionResult],
        blackbox_results: List[TestExecutionResult],
        target_path: str,
        whitebox_tests: Optional[List[GeneratedTest]] = None,
        blackbox_tests: Optional[List[GeneratedTest]] = None
    ) -> str:
        """與 Markdown 報告內容相同（含來源紀錄）的機器可讀報告。
        產生的測試程式碼原樣儲存，讓一次執行可被稽核、其測試可被重新執行。
        Machine-readable report with the same content as the Markdown one (provenance included).
        Generated test code is stored verbatim, so a run can be audited and its tests re-executed."""
        payload = {
            "tool": "vibeharness-mas",
            # 欄位更名／移除或語意改變時遞增；新增欄位則保持版本不變
            # Bump when a field is renamed/removed or its meaning changes; additions keep the version
            "schema_version": JSON_SCHEMA_VERSION,
            "target_path": os.path.abspath(target_path),
            "summary": summary.model_dump(),
            "whitebox": {
                "debate": debate_result.model_dump(),
                "test_results": [r.model_dump() for r in whitebox_results],
                "generated_tests": [t.model_dump() for t in whitebox_tests or []],
            },
            "threat_model": threat_model.model_dump(),
            "blackbox_test_results": [r.model_dump() for r in blackbox_results],
            "blackbox_generated_tests": [t.model_dump() for t in blackbox_tests or []],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)

    def generate_sarif_report(
        self,
        summary: VibeHarnessSummary,
        debate_result: MultiModelDebateResult,
        threat_model: ThreatModelReport,
        whitebox_results: List[TestExecutionResult],
        blackbox_results: List[TestExecutionResult],
        target_path: str,
        symbols: Optional[List[CodeSymbol]] = None
    ) -> str:
        """
        供 GitHub Code Scanning 使用的 SARIF 2.1.0 輸出：已確認的白箱發現，附上
        盡力而為的檔案／行號位置，加上已確認的黑箱突破（位於其威脅的
        攻擊向量所指名的符號，若能解析出來的話）。
        URI 相對於外層的 git 版本庫（%SRCROOT%），否則相對於目標。
        SARIF 2.1.0 output for GitHub Code Scanning: confirmed white-box findings with
        best-effort file/line locations, plus confirmed black-box breaches (located at the
        symbol their threat's attack vector names, when one can be resolved).
        URIs are relative to the enclosing git repository (%SRCROOT%), else to the target.
        模擬引擎產生的白箱發現，以及衍生自模擬威脅的突破，都是範本而非證據：它們不會成為 SARIF 結果
        （在 Code Scanning 裡看起來會和真的一樣），只在 run 的 properties 計數（simulated_*_omitted）。
        White-box findings from the simulation engine and breaches derived from a simulated threat are
        templates, not evidence: they never become SARIF results (in Code Scanning they would look real) and
        are only counted in the run properties (simulated_*_omitted).
        """
        from vibeharness import __version__
        root = self._sarif_root(target_path)

        rules: List[Dict[str, object]] = []
        rule_index: Dict[str, int] = {}
        results: List[Dict[str, object]] = []

        def add_rule(rule_id: str, short: str, full: str, level: str, help_md: Optional[str] = None) -> int:
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": short},
                    "fullDescription": {"text": full},
                    "defaultConfiguration": {"level": level},
                    # Code Scanning 會在警示頁面顯示 `help`；沒有它警示就沒有任何指引
                    # Code Scanning shows `help` on the alert page; without it the alert has no guidance
                    "help": {"text": re.sub(r"[*`]", "", help_md or full), "markdown": help_md or full},
                })
            return rule_index[rule_id]

        # 0. 確定性 AI 資安規則命中（不涉及模型）
        # 0. Deterministic AI-security rule hits (no model involved)
        for sf in summary.static_findings:
            rule_id = SARIF_RULE_STATIC_PREFIX + sf.rule_id
            mappings = " · ".join(t for t in (sf.owasp_mapping, sf.atlas_mapping, sf.cwe) if t)
            idx = add_rule(
                rule_id, sf.title, sf.remediation, self._sarif_level(sf.severity),
                help_md=f"**{sf.title}**\n\n{sf.remediation}" + (f"\n\n{bi('對應', 'Mappings')}: {mappings}" if mappings else "")
                        + "\n\n" + bi("確定性規則（不涉及模型）：命中來自程式碼本身，不是模型的意見。",
                                        "Deterministic rule (no model involved): the hit is in the code itself, not a model's opinion."),
            )
            tags = [t for t in (sf.owasp_mapping, sf.atlas_mapping, sf.cwe) if t]
            rules[idx].setdefault("properties", {"tags": ["security", *tags]})
            uri = self._sarif_uri(sf.file_path, root)
            static_result: Dict[str, object] = {
                "ruleId": rule_id,
                "ruleIndex": idx,
                "level": self._sarif_level(sf.severity),
                "message": {"text": f"{sf.title}: {clean_model_text(sf.evidence)}" if sf.evidence else sf.title},
                "partialFingerprints": {"vibeharness/v1": sarif_static_fingerprint(sf, uri)},
                "properties": {"severity": sf.severity.value, "owasp": sf.owasp_mapping or "",
                               "atlas": sf.atlas_mapping or "", "cwe": sf.cwe or "", "deterministic": True},
            }
            if uri:
                static_result["locations"] = [self._location(uri, sf.line_number)]
            results.append(static_result)

        add_rule(
            SARIF_RULE_WHITEBOX, bi("已確認的白箱缺陷假設", "Confirmed white-box defect hypothesis"),
            bi("由審查模型回報、並經跨模型驗證確認（或未決）的缺陷。",
               "A defect reported by a reviewer model and confirmed (or left undecided) by cross-model verification."),
            "warning",
            help_md=bi("審查模型回報了這個缺陷，其他模型確認了它（或投票平手）。在測試揭露之前它只是假設："
                       "請在 Markdown / JSON 報告中查看產生的測試及其結果（`properties.findingId` 指出該發現），"
                       "再修正訊息所描述的根本原因。",
                       "A reviewer model reported this defect and the other models confirmed it (or the vote tied). "
                       "It is a hypothesis until a test exposes it: check the generated test and its outcome in the "
                       "Markdown / JSON report (`properties.findingId` names the finding), then fix the root cause the "
                       "message describes."),
        )
        # 1. 已確認的白箱發現（檔案位置由 line_number 或符號表解析）
        # 1. Confirmed white-box findings (file locations resolved from line_number or the symbol table)
        omitted_findings = 0
        for f in debate_result.confirmed_findings:
            if f.is_simulated:
                omitted_findings += 1
                continue
            level = self._sarif_level(f.severity)
            desc = f.title
            if f.description:
                desc += f"\n\n{f.description}"
            if f.root_cause:
                desc += f"\n\n{bi('根本原因', 'Root cause')}: {f.root_cause}"
            if f.suggested_test_scenario:
                desc += f"\n\n{bi('建議測試', 'Suggested test')}: {f.suggested_test_scenario}"
            if not debate_result.arbitration_applied:
                # 沒有套用跨模型驗證：結果只是未經過濾的假設，訊息與 properties 都要說清楚
                # Cross-model verification was not applied: the result is an unfiltered hypothesis, and both
                # the message and the properties say so
                desc = bi("未經驗證的假設（未套用跨模型驗證）", "Unverified hypothesis (cross-model verification not applied)") + f": {desc}"
            desc = clean_model_text(desc)
            uri = self._sarif_uri(f.file_path, root)
            result: Dict[str, object] = {
                "ruleId": SARIF_RULE_WHITEBOX,
                "ruleIndex": rule_index[SARIF_RULE_WHITEBOX],
                "level": level,
                "message": {"text": desc},
                "partialFingerprints": {"vibeharness/v1": sarif_finding_fingerprint(f, uri)},
                "properties": {
                    "findingId": f.finding_id,
                    "severity": f.severity.value,
                    "reviewer": f.reviewer_name,
                    "symbol": f.symbol_name or "",
                    "corroboratedBy": f.corroborated_by,
                    "simulated": f.is_simulated,
                    "verified": debate_result.arbitration_applied,
                },
            }
            if uri:
                # 未知時省略（絕不是 null）：SARIF 要求若存在就必須是陣列
                # Omitted (never null) when unknown: SARIF requires an array if present
                result["locations"] = [self._location(uri, self._resolve_line(f, symbols))]
            results.append(result)

        # 2. 已確認的黑箱資安突破，若已知則定位在威脅所針對的符號
        # 2. Confirmed black-box security breaches, located at the symbol the threat targets if known
        threats_by_id = {t.threat_id: t for t in threat_model.threats}
        omitted_breaches = 0
        for r in blackbox_results:
            if not r.is_security_exploit_confirmed:
                continue
            threat = threats_by_id.get(r.source_ref or "")
            # 衍生自模擬威脅（或找不到威脅、而威脅模型是模擬的）的突破：攻擊腳本是範本，不列為結果
            # A breach derived from a simulated threat (or with no known threat in a simulated threat model): the
            # attack script is a template, so it is not a result
            if threat.is_simulated if threat else threat_model.is_simulated:
                omitted_breaches += 1
                continue
            if SARIF_RULE_BLACKBOX not in rule_index:
                add_rule(
                    SARIF_RULE_BLACKBOX, bi("已確認的黑箱資安突破", "Confirmed black-box security breach"),
                    bi("由威脅模型衍生、其防禦斷言對目標失敗的攻擊測試。",
                       "A threat-model-derived attack test whose defensive assertion failed against the target."),
                    "error",
                    help_md=bi("由威脅模型衍生的攻擊腳本對目標執行後，其防禦斷言失敗，也就是攻擊成功。"
                               "請用報告中的 PoC（`properties.testId`）重現，再補上威脅（`properties.threatId`）所描述的"
                               "缺少的授權、驗證或限制，並把這個測試留作回歸防護。",
                               "An attack script derived from the threat model ran against the target and its defensive "
                               "assertion failed, i.e. the attack succeeded. Reproduce it with the PoC in the report "
                               "(`properties.testId`), then add the missing authorization, validation or limit the threat "
                               "(`properties.threatId`) describes and keep the test as a regression guard."),
                )
            derived = f" ({bi('衍生自', 'derived from')} {r.source_ref}{': ' + threat.title if threat else ''})" if r.source_ref else ""
            text = (f"{bi('已確認的資安突破', 'Confirmed security breach')} {r.test_id}{derived}: "
                    f"{r.failure_reason or bi('攻擊測試成功', 'the attack test succeeded')}")
            breach: Dict[str, object] = {
                "ruleId": SARIF_RULE_BLACKBOX,
                "ruleIndex": rule_index[SARIF_RULE_BLACKBOX],
                "level": "error",
                "message": {"text": clean_model_text(text)},
                "partialFingerprints": {"vibeharness/v1": sarif_breach_fingerprint(r, threat)},
                "properties": {"testId": r.test_id, "threatId": r.source_ref or "", "security_breach": True,
                               "simulated": False},
            }
            target_symbol = self._threat_symbol(threat, symbols) if threat else None
            if target_symbol:
                uri = self._sarif_uri(target_symbol.file_path, root)
                if uri:
                    breach["locations"] = [self._location(uri, max(1, target_symbol.line_start))]
            results.append(breach)

        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VibeHarness-MAS",
                        "version": __version__,
                        "informationUri": "https://github.com/chinchiang/MultiAgentGama",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "overall_status": summary.overall_status,
                    "target": os.path.abspath(target_path),
                    # 被略過的模擬項目：Code Scanning 看不到它們，但數量仍可稽核
                    # Omitted simulated items: Code Scanning does not see them, but their number stays auditable
                    "simulated_whitebox_findings_omitted": omitted_findings,
                    "simulated_breaches_omitted": omitted_breaches,
                    **({"generated_at": summary.run.generated_at, "execution_mode": summary.run.execution_mode,
                        "target_git_commit": summary.run.target_git_commit or ""} if summary.run else {}),
                },
            }],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    @staticmethod
    def _location(uri: str, line: int) -> Dict[str, object]:
        """SARIF 位置：相對 URI 以 %SRCROOT% 為基準；%SRCROOT% 之外的檔案是絕對 file:// URI，不帶 uriBaseId。
        A SARIF location: relative URIs are based on %SRCROOT%; a file outside %SRCROOT% is an absolute
        file:// URI without a uriBaseId."""
        artifact: Dict[str, str] = {"uri": uri}
        if not uri.startswith("file:"):
            artifact["uriBaseId"] = "%SRCROOT%"
        return {
            "physicalLocation": {
                "artifactLocation": artifact,
                "region": {"startLine": line},
            }
        }


    @staticmethod
    def _threat_symbol(threat: ThreatItem, symbols: Optional[List[CodeSymbol]]) -> Optional[CodeSymbol]:
        """威脅的攻擊向量所指名的擷取符號（整字比對，路由優先）。
        The extracted symbol the threat's attack vector names (whole-word match, routes first)."""
        text = f"{threat.attack_vector} {threat.attack_scenario}"
        best: Optional[Tuple[bool, int, int]] = None
        chosen: Optional[CodeSymbol] = None
        for index, sym in enumerate(symbols or []):
            names = {sym.name, sym.name.split(".")[-1]} - {""}
            # 只比對完整的識別字／路由：前後不能緊接識別字字元，路由後面也不能接著路徑字元，
            # 所以 `get` 不會命中 `get_user`，`GET /users` 也不會命中 `GET /users/admin`
            # Whole identifiers / routes only: no identifier character may touch either end, and no path
            # character may follow, so `get` does not hit `get_user` and `GET /users` does not hit `GET /users/admin`
            matched = [n for n in names if re.search(rf"(?<!\w){re.escape(n)}(?![\w/-])", text)]
            if not matched:
                continue
            # 路由優先，其次是最長的命中（最具體的路由或完整的限定名稱），平手時取先出現的符號
            # Routes first, then the longest match (the most specific route or the full qualified name),
            # ties go to the earlier symbol
            rank = (sym.symbol_type == "route", max(len(n) for n in matched), -index)
            if best is None or rank > best:
                best, chosen = rank, sym
        return chosen

    @staticmethod
    def _sarif_root(target_path: str) -> str:
        """URI 用的 %SRCROOT%：包含目標的 git 版本庫（Code Scanning 會相對於
        版本庫根目錄解析 URI），否則是目標目錄本身。
        %SRCROOT% for URIs: the git repository containing the target (Code Scanning resolves
        URIs against the repo root), else the target directory itself."""
        start = os.path.abspath(target_path)
        if not os.path.isdir(start):
            start = os.path.dirname(start)
        home = os.path.expanduser("~")
        current = start
        while True:
            # 位於家目錄的 git 版本庫幾乎都是 dotfiles／設定檔版本庫，
            # 絕不是 SARIF 要上傳到的程式碼版本庫；這種家目錄底下的用完即丟執行目錄
            # 不能把它繼承為 %SRCROOT%。
            # A git repository at the home directory is almost always a dotfiles/config repo,
            # never the code repo the SARIF will be uploaded against; a throwaway run directory
            # under such a home must not inherit it as %SRCROOT%.
            if not ReportGenerator._same_path(current, home) and os.path.exists(os.path.join(current, ".git")):
                return current
            parent = os.path.dirname(current)
            if parent == current or ReportGenerator._same_path(current, home):
                # 沒有版本庫：使用目標目錄（檔案目標則用它自己所在的目錄）
                # No repository: the target directory (a file target's own directory)
                return start if os.path.isdir(start) else target_path
            current = parent

    @staticmethod
    def _same_path(a: str, b: str) -> bool:
        """能撐過 Windows 8.3 短檔名、大小寫差異與符號連結的路徑同一性判斷。
        Path identity that survives Windows 8.3 short names, case differences and symlinks."""
        try:
            return os.path.samefile(a, b)
        except OSError:
            return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))

    @staticmethod
    def _sarif_level(severity: FindingSeverity) -> str:
        return {
            FindingSeverity.CRITICAL: "error",
            FindingSeverity.HIGH: "error",
            FindingSeverity.MEDIUM: "warning",
            FindingSeverity.LOW: "note",
            FindingSeverity.INFO: "note",
        }[severity]

    @staticmethod
    def _sarif_uri(file_path: str, target_path: str) -> Optional[str]:
        """盡力而為、相對於版本庫根目錄且使用正斜線的 URI；未知時為 None。
        Best-effort repo-root-relative URI with forward slashes; None when unknown."""
        # 無法歸屬的位置（"unknown" 佔位字、空白）不是檔案 ／ an unattributable location ("unknown", blank) is not a file
        if is_unknown_location(file_path):
            return None
        path = file_path.strip()
        drive = _WINDOWS_DRIVE_RE.match(path)
        if not drive and not os.path.isabs(path) and os.path.isfile(path):
            # 擷取器相對於工作目錄記下的路徑（例如在子目錄執行 `--target .`）：先解析成絕對路徑，
            # 才能相對於 %SRCROOT% 正確相對化，而不是原樣輸出。只在解析結果位於 %SRCROOT% 內時採用：
            # 否則 `../../etc/passwd` 這類路徑會因工作目錄剛好在哪而變成 file:// URI
            # A path the extractor recorded relative to the working directory (e.g. `--target .` run from a
            # subdirectory): resolve it first, so it is relativized against %SRCROOT% instead of emitted as-is.
            # Only used when it lands inside %SRCROOT%: otherwise a path like `../../etc/passwd` would become a
            # file:// URI depending on where the working directory happens to be
            resolved = os.path.abspath(path)
            root = os.path.abspath(target_path or ".")
            if os.path.isfile(root):
                root = os.path.dirname(root)
            try:
                inside = os.path.commonpath([resolved, root]) == root
            except ValueError:  # Windows 上不同磁碟機 ／ different drives on Windows
                inside = False
            if inside:
                path = resolved
        if drive or _WINDOWS_DRIVE_RE.match(target_path or ""):
            return ReportGenerator._sarif_uri_windows(path, target_path)
        if os.path.isabs(path):
            base = os.path.abspath(target_path)
            if os.path.isfile(base):
                base = os.path.dirname(base)
            rel = os.path.relpath(path, base).replace("\\", "/")
            if rel == ".." or rel.startswith("../"):
                # 在 %SRCROOT% 之外：絕不輸出 `..` 片段，改用絕對 file:// URI
                # Outside %SRCROOT%: never emit `..` segments, use an absolute file:// URI instead
                return pathlib.Path(path).resolve().as_uri()
            return rel
        # 模型回報的相對路徑：`..` 片段絕不能跳出 %SRCROOT%，跳出就省略位置
        # A model-reported relative path: `..` segments must never escape %SRCROOT%; if they do, the location is omitted
        norm = posixpath.normpath(path.replace("\\", "/"))
        if norm in (".", "..") or norm.startswith("../") or norm.startswith("/"):
            return None
        return norm

    @staticmethod
    def _sarif_uri_windows(path: str, target_path: str) -> Optional[str]:
        """Windows 磁碟機路徑的 URI（在任何主機上都用 ntpath 規則）：同一磁碟機且位於基準之內時是相對路徑，
        否則是絕對 file:// URI；絕不輸出 `..` 片段。
        The URI of a Windows drive path (ntpath rules on any host): relative when it is on the same drive
        and inside the base, else an absolute file:// URI; `..` segments are never emitted."""
        if not _WINDOWS_DRIVE_RE.match(path):
            # 基準是 Windows 路徑而檔案不是：只有沒有 `..` 的相對路徑才能當成基準之下的路徑
            # The base is a Windows path but the file is not: only a relative path without `..` can sit under the base
            norm = ntpath.normpath(path).replace("\\", "/")
            if norm in (".", "..") or norm.startswith(("../", "/")):
                return None
            return norm
        absolute = "file:///" + urllib.parse.quote(ntpath.normpath(path).replace("\\", "/"), safe="/:")
        base = target_path or ""
        if not _WINDOWS_DRIVE_RE.match(base) or path[0].lower() != base[0].lower():
            return absolute
        try:
            rel = ntpath.relpath(path, base).replace("\\", "/")
        except ValueError:  # 不同磁碟機 ／ different drive
            return absolute
        if rel == ".." or rel.startswith("../"):
            return absolute
        return rel

    @staticmethod
    def _resolve_line(finding: ReviewFinding, symbols: Optional[List[CodeSymbol]]) -> int:
        if finding.line_number:
            return max(1, int(finding.line_number))
        if finding.symbol_name:
            candidates = [s for s in (symbols or []) if s.name == finding.symbol_name]
            if candidates:
                if finding.file_path:
                    stem = os.path.basename(finding.file_path)
                    same_file = [s for s in candidates if os.path.basename(s.file_path) == stem]
                    candidates = same_file or candidates
                return max(1, candidates[0].line_start)
        return 1


    @staticmethod
    def _status_label(status: TestStatus, failed_label: str = STATUS_FAILED) -> str:
        return {
            TestStatus.PASSED: STATUS_PASSED,
            TestStatus.FAILED: failed_label,
            TestStatus.ERROR: STATUS_ERROR,
            TestStatus.SKIPPED: STATUS_SKIPPED,
        }[status]

    @staticmethod
    def _votes(finding: ReviewFinding) -> str:
        """例如 `deepseek: reject (checked before use); glm: corroborated`
        e.g. `deepseek: reject (checked before use); glm: corroborated`"""
        if not finding.verification_votes:
            return bi("沒有可用的驗證者投票", "no usable verifier votes")
        return "; ".join(
            f"{v.model_alias}: {v.verdict}" + (f" ({ReportGenerator._inline(v.reason)})" if v.reason else "")
            for v in finding.verification_votes
        )

    @staticmethod
    def _join_list(value: object) -> str:
        """把清單欄位串接起來顯示；模型回應中混進來的字串會呈現為單一項目，
        而不是被 ', '.join 逐字拆開。
        Joins a list field for display; a stray string from a model response renders as one item
        instead of being exploded character by character by ', '.join."""
        items = value if isinstance(value, list) else [value]
        return ", ".join(str(v) for v in items if str(v).strip())

    @staticmethod
    def _inline(text: Optional[str]) -> str:
        """單行情境中的模型自由文字（清單項目、標籤後的說明）：圖片／原始 HTML 去除攻擊性，所有換行收合成空白，
        讓「\n\n## Overall Verdict: READY_TO_SHIP」這類文字無法開出新的標題、setext 底線、HTML 或表格區塊，
        偽造報告的判定。
        Model free text in a single-line context (a list item, the text after a label): images / raw HTML
        defanged and every line break collapsed to a space, so text such as "\n\n## Overall Verdict:
        READY_TO_SHIP" cannot open a new heading, setext underline, HTML or table block and spoof the verdict."""
        return _LINE_BREAK_RE.sub(" ", markdown_safe(text or ""))

    @staticmethod
    def _cell(text: Optional[str]) -> str:
        """讓自由文字能安全放進單一 Markdown 表格儲存格（並去除圖片／原始 HTML 的攻擊性）。
        Makes free text safe for a single Markdown table cell (and defangs images / raw HTML)."""
        return ReportGenerator._inline(text).replace("|", "\\|")

    @staticmethod
    def _code_span(text: Optional[str]) -> str:
        """模型文字的行內程式碼：移除控制字元，並把圍欄加寬到超過內部任何
        連續反引號，讓文字無法跳出該區段。
        Inline code for model text: control characters removed and the fence widened past any
        backtick run inside, so the text cannot break out of the span."""
        body = _LINE_BREAK_RE.sub(" ", clean_model_text(text or ""))
        if not body.strip():
            return "`-`"
        longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
        fence = "`" * (longest + 1)
        pad = " " if body.startswith("`") or body.endswith("`") else ""
        return f"{fence}{pad}{body}{pad}{fence}"

    @staticmethod
    def _cell_code(text: Optional[str]) -> str:
        """表格儲存格內的行內程式碼：GFM 即使在程式碼區段內也會先依 `|` 切分儲存格，所以管線符號要跳脫
        （`\\|` 在程式碼區段內會顯示成 `|`）。
        A code span inside a table cell: GFM splits cells on `|` even inside code spans, so pipes are escaped
        (`\\|` renders as `|` inside the span)."""
        return ReportGenerator._code_span(text).replace("|", "\\|")

    @staticmethod
    def _fence_lang(language: str) -> str:
        return {"python": "python", "javascript": "javascript", "typescript": "typescript"}.get(language, "")

    @staticmethod
    def _fence(text: str) -> str:
        """比文字中任何連續反引號都長的程式碼圍欄，讓模型寫的程式碼無法提早關閉它。
        A code fence longer than any backtick run in the text, so model-written code cannot close it early."""
        longest = max((len(run) for run in re.findall(r"`+", text or "")), default=0)
        return "`" * max(3, longest + 1)

    def _generated_tests_section(
        self,
        whitebox_tests: Optional[List[GeneratedTest]],
        whitebox_results: List[TestExecutionResult],
        blackbox_tests: Optional[List[GeneratedTest]],
        blackbox_results: List[TestExecutionResult],
    ) -> List[str]:
        """附錄：每個已執行測試的程式碼與其結果並列。模型寫的、「通過」的測試
        可能斷言的是缺陷本身（例如 `pytest.raises(KeyError)`），所以程式碼必須可供審閱；
        JSON 報告原樣保留它，這裡則移除控制字元以便安全渲染。
        Appendix with every executed test's code next to its outcome. A model-written test that "passes"
        may be asserting the defect itself (e.g. `pytest.raises(KeyError)`), so the code must be reviewable;
        the JSON report keeps it verbatim, here control characters are removed for safe rendering."""
        from vibeharness.runners.test_executor import TestSuiteExecutor
        if not whitebox_tests and not blackbox_tests:
            return []
        md = ["\n" + HEADING_GENERATED_TESTS,
              bi("模型寫的測試同樣是假設：請確認每個斷言編碼的是*正確*行為，而不是缺陷本身。結果對應上方的表格。",
                 "Model-written tests are hypotheses too: check that each assertion encodes the *correct* behaviour, "
                 "not the defect. Outcomes refer to the tables above.") + "\n"]
        for label, tests, results in (
            (bi("白箱測試", "White-box tests"), whitebox_tests or [], whitebox_results),
            (bi("黑箱攻擊測試", "Black-box attack tests"), blackbox_tests or [], blackbox_results),
        ):
            if not tests:
                continue
            md.append(f"### {label} ({len(tests)})")
            by_id = {r.test_id: r for r in results}
            for test_id, t in zip(TestSuiteExecutor._unique_test_ids(tests), tests, strict=True):
                result = by_id.get(test_id)
                if result is None:
                    outcome = OUTCOME_NOT_RUN
                elif result.is_security_exploit_confirmed:
                    outcome = OUTCOME_VULNERABLE
                else:
                    outcome = self._status_label(result.status)
                # <summary> 是 HTML 區塊（那裡不渲染 Markdown）：id 以 HTML 跳脫
                # <summary> is an HTML block (Markdown is not rendered there): escape ids as HTML
                source = f" — {LABEL_FROM} <code>{html.escape(clean_model_text(t.source_ref))}</code>" if t.source_ref else ""
                code = clean_model_text(t.code)
                fence = self._fence(code)
                md.append("<details>")
                md.append(f"<summary><code>{html.escape(clean_model_text(test_id))}</code> — {outcome}{source}</summary>\n")
                md.append(f"- **{bi('標題', 'Title')}**: {self._inline(t.title)}")
                md.append(f"- **{bi('理由', 'Rationale')}**: {self._inline(t.rationale)}")
                md.append(f"- **{bi('預期結果', 'Expected outcome')}**: {self._inline(t.expected_outcome)}\n")
                md.append(f"{fence}{self._fence_lang(t.language)}\n{code}\n{fence}\n")
                md.append("</details>\n")
        return md

    def _static_section(self, findings: List[StaticFinding]) -> List[str]:
        """確定性 AI 資安規則的命中（已對應 OWASP LLM Top 10 2026／MITRE ATLAS）。
        Deterministic AI-security rule hits (OWASP LLM Top 10 2026 / MITRE ATLAS mapped)."""
        md = [HEADING_STATIC_RULES]
        if not findings:
            md.append(bi("沒有規則命中。規則涵蓋不安全的模型載入與未釘選版本的模型下載（LLM04）、模型輸出流入 exec/shell/SQL "
                         "匯點（LLM10）、沒有上限的模型呼叫（LLM06）、寫死的憑證（LLM02），以及針對審查者的提示注入或不可見字元（LLM01）。",
                         "No rule hits. Rules cover unsafe model loading and unpinned model downloads (LLM04), model output "
                         "reaching exec/shell/SQL sinks (LLM10), uncapped model calls (LLM06), hard-coded credentials "
                         "(LLM02) and reviewer-directed prompt injection or invisible characters (LLM01).") + "\n")
            return md
        md.append(bi("HIGH 以上的命中會讓閘門失敗（`NEEDS_FIXES`）；提示注入與不可見字元的命中也會把模型驅動的階段標示為可能遭操弄。",
                     "HIGH+ hits fail the gate (`NEEDS_FIXES`); prompt-injection and invisible-character hits also mark "
                     "the model-driven phases as possibly manipulated.") + "\n")
        md.append(STATIC_TABLE_HEADER)
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in findings:
            evidence = f"<br>*{self._cell(f.evidence)}*" if f.evidence else ""
            md.append(
                f"| `{f.rule_id}` | `{f.severity.value}` | {self._cell_code(f'{os.path.basename(f.file_path)}:{f.line_number}')} | "
                f"**{self._cell(f.title)}**{evidence} | {self._cell(f.owasp_mapping) or '-'} | "
                f"{self._cell(f.atlas_mapping) or '-'} | {self._cell(f.cwe) or '-'} |"
            )
        md.append("")
        return md
