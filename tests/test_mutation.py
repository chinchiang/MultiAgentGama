"""突變測試：變異點、文字切換、隔離複本、殺死／存活判定、閘門語意、開關優先順序與報告。
Mutation testing: sites, text splicing, the isolated copy, killed / survived judging, gate semantics,
switch precedence and the report."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest
import yaml

from vibeharness.core import mutation as mut
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.models import (
    MultiModelDebateResult, ThreatModelReport,
    FindingSeverity, GeneratedTest, MutantResult, MutationReport, ReviewFinding, TestExecutionResult, TestStatus,
)
from vibeharness.core.sandbox import LocalSubprocessSandbox
from vibeharness.runners.test_executor import TestSuiteExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
EXAMPLES = os.path.join(REPO_ROOT, "examples")

SHOP = '''"""商店 ／ shop"""


def discount(price, member):
    """會員折扣 ／ member discount"""
    if member and price > 100:   # 大額會員 ／ big member
        return price - 10
    return price


def spin(n):
    total = 0
    while n > 0:
        total += n
        n -= 1
    return total
'''

# 強測試：多組輸入，抓得到大多數變異 ／ strong test: several inputs, catches most mutants
STRONG = '''import importlib.util
spec = importlib.util.spec_from_file_location("shop_mod", r"{root}/shop.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def test_discount():
    assert m.discount(200, True) == 190
    assert m.discount(100, True) == 100
    assert m.discount(200, False) == 200
    assert m.discount(50, True) == 50
'''
# 弱測試：過得了程式碼閘門，但幾乎不碰分支 ／ weak test: passes the code gate but barely touches a branch
WEAK = '''from shop import discount, spin

def test_weak():
    assert discount(5, False) == 5
    assert spin(0) == 0
'''


def _setup(tmp_path, source=SHOP):
    root = tmp_path / "app"
    root.mkdir()
    (root / "shop.py").write_text(source, encoding="utf-8")
    return str(root)


def _test(test_id, code, ref, test_type="whitebox_unit", language="python"):
    return GeneratedTest(test_id=test_id, test_type=test_type, target_component="x", title="t", code=code,
                         rationale="", expected_outcome="", source_ref=ref, language=language)


def _finding(finding_id, root, symbol):
    return ReviewFinding(finding_id=finding_id, reviewer_name="r", model_alias="m", file_path=os.path.join(root, "shop.py"),
                         symbol_name=symbol, severity=FindingSeverity.HIGH, title="t", description="d", root_cause="r",
                         suspected_vibe_flaw="s", suggested_test_scenario="x")


def _passed(tests):
    return [TestExecutionResult(test_id=t.test_id, test_type=t.test_type, status=TestStatus.PASSED) for t in tests]


def _symbols(root):
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
    return ASTExtractor().parse_directory(root)


def _run(tmp_path, tests, root, symbols=None, findings=None, max_mutants=12, timeout=5, results=None):
    executor = TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60), per_test_timeout_seconds=10)
    findings = findings or [_finding("F1", root, "discount"), _finding("F2", root, "spin")]
    return mut.run_mutation_testing(executor.run_mutant_batch, tests, results or _passed(tests), findings,
                                    symbols or _symbols(root), root, max_mutants, timeout)


# --- 變異點與文字切換 ------------------------------------------------------------------------
# --- Sites and text splicing -----------------------------------------------------------------

def test_sites_cover_each_operator_class_in_a_fixed_order():
    """每一類運算子都找得到，且順序固定（依行、欄）；docstring 與 `__init__` 不動。
    Every operator class is found in a fixed order (line, column); docstrings and `__init__` are left alone."""
    source = textwrap_dedent('''
        class C:
            def __init__(self):
                self.x = 1 + 2

            def f(self, a, b):
                """doc: 1 + 2 and True"""
                if not a and b >= 3 or a == 0:
                    return a * b - True
                return 1
    ''')
    sites = mut.find_mutation_sites(source, 1, 20, "C.f")
    kinds = {s.operator for s in sites}
    assert kinds == {"negation", "boolean", "comparison", "arithmetic", "constant"}
    assert [(s.line, s.col) for s in sites] == sorted((s.line, s.col) for s in sites)
    assert all(s.line != 3 for s in sites)  # __init__ 不動 ／ __init__ untouched
    assert {(s.original, s.replacement) for s in sites} >= {("not", ""), ("and", "or"), ("or", "and"), (">=", ">"),
                                                          ("==", "!="), ("*", "/"), ("-", "+"), ("True", "False")}


def textwrap_dedent(text):
    import textwrap
    return textwrap.dedent(text).lstrip("\n")


def test_non_ascii_lines_are_spliced_at_the_right_column():
    """含中文的行用字元欄位切換，而不是 UTF-8 位元組位移：註解與其餘文字原封不動。
    Lines with Chinese text are spliced by character column, not UTF-8 byte offset: comments and the rest stay intact."""
    source = 'def f(a, b):\n    名稱 = "價格 > 100"; return a + b  # 加法 + 註解\n'
    sites = mut.find_mutation_sites(source, 1, 2, "f")
    assert [(s.original, s.replacement) for s in sites] == [("+", "-")]
    assert mut.apply_mutation(source, sites[0]) == 'def f(a, b):\n    名稱 = "價格 > 100"; return a - b  # 加法 + 註解\n'


def test_apply_mutation_changes_one_token_and_drops_bad_results():
    """只改一個 token；位置對不上、結果不能解析或語法樹沒變（等價）就回傳 None。
    Exactly one token changes; a stale position, an unparsable result or an unchanged syntax tree (equivalent) gives None."""
    source = "def f(a, b):\n    return (a + b) * 2  # 備註\n"
    site = next(s for s in mut.find_mutation_sites(source, 1, 2) if s.original == "+")
    assert mut.apply_mutation(source, site) == "def f(a, b):\n    return (a - b) * 2  # 備註\n"
    assert mut.apply_mutation("def f(a, b):\n    return a  # x\n", site) is None  # 位置對不上 ／ stale position
    broken = mut.MutationSite(2, 4, "return", "retur n", "arithmetic")
    assert mut.apply_mutation(source, broken) is None  # 不能解析 ／ unparsable
    same = mut.MutationSite(2, 4, "return", "return", "arithmetic")
    assert mut.apply_mutation(source, same) is None  # 等價 ／ equivalent
    assert mut.apply_mutation(source, mut.MutationSite(99, 0, "x", "y", "arithmetic")) is None


def test_unparsable_source_has_no_sites():
    """不能解析的原始碼沒有變異點，也不會丟出例外。
    Unparsable source has no sites and raises nothing."""
    assert mut.find_mutation_sites("def f(:\n", 1, 2) == []


def test_site_selection_is_deterministic_and_spreads_across_groups():
    """選取輪流從每個（檔案，符號）群組取一個，順序固定；超過上限就截斷並回報候選總數。
    Selection takes one site per (file, symbol) group in turn in a fixed order; beyond the cap it truncates and reports the total."""
    def site(line):
        return mut.MutationSite(line, 0, "+", "-", "arithmetic")
    groups = {("b.py", "g"): [site(1), site(2), site(3)], ("a.py", "f"): [site(10), site(11)]}
    selected, total = mut.select_sites(groups, 3)
    assert total == 5 and [(f, s.line) for f, s in selected] == [("a.py", 10), ("b.py", 1), ("a.py", 11)]
    assert mut.select_sites(groups, 3) == (selected, total)
    everything, _ = mut.select_sites(groups, 99)
    assert len(everything) == 5


def test_eligible_tests_are_passed_python_unit_or_property_tests_only():
    """只有已通過的 Python 單元／性質測試可用：失敗、錯誤、JS、探針與黑箱都被排除。
    Only PASSED Python unit / property tests are usable: failed, errored, JS, probe and black-box tests are excluded."""
    tests = [_test("a", "x", "F1"), _test("b", "x", "F1", "whitebox_property"), _test("c", "x", "F1", "whitebox_probe"),
             _test("d", "x", "F1", "blackbox_security"), _test("e", "x", "F1", language="javascript"), _test("f", "x", "F1")]
    statuses = [TestStatus.PASSED, TestStatus.PASSED, TestStatus.PASSED, TestStatus.PASSED, TestStatus.PASSED, TestStatus.FAILED]
    results = [TestExecutionResult(test_id=t.test_id, test_type=t.test_type, status=s) for t, s in zip(tests, statuses, strict=True)]
    assert [t.test_id for t in mut.eligible_tests(tests, results)] == ["a", "b"]


# --- 端對端（真的本機沙盒） ------------------------------------------------------------------
# --- End to end (the real local sandbox) -----------------------------------------------------

def test_strong_tests_kill_mutants_and_weak_tests_let_them_survive(tmp_path):
    """強測試殺死變異體、弱測試讓它們存活；分數 = 殺死 /（殺死 + 存活）；原始檔案內容與 mtime 完全不變。
    A strong test kills mutants, a weak one lets them survive; score = killed / (killed + survived); the original file's
    content and mtime are untouched."""
    root = _setup(tmp_path)
    shop = os.path.join(root, "shop.py")
    before, mtime = open(shop, encoding="utf-8").read(), os.stat(shop).st_mtime_ns
    tests = [_test("T1", STRONG.format(root=root), "F1"), _test("T2", WEAK, "F2")]
    report = _run(tmp_path, tests, root)
    assert report.skipped_reason is None and report.total == 7 and report.invalid == 0
    by_symbol = {}
    for m in report.mutants:
        by_symbol.setdefault(m.symbol, []).append(m.status)
    assert set(by_symbol["discount"]) == {"killed"}            # 強測試 ／ strong test
    assert "survived" in by_symbol["spin"]                      # 弱測試 ／ weak test
    assert report.score == pytest.approx(100.0 * report.killed / (report.killed + report.survived), abs=0.1)
    assert not report.truncated and report.candidate_sites == 7
    survivor = next(m for m in report.mutants if m.status == "survived")
    assert survivor.original != survivor.mutated and survivor.file == "shop.py"
    assert open(shop, encoding="utf-8").read() == before and os.stat(shop).st_mtime_ns == mtime


def test_path_rewrite_makes_embedded_absolute_paths_hit_the_mutated_copy(tmp_path):
    """測試本體內嵌原始絕對路徑（importlib 以路徑載入）時，路徑會改寫到複本：變異體因此真的被殺，不是測到原檔。
    When a test body embeds the original absolute path (importlib by path) it is rewritten to the copy, so the mutant is
    really killed instead of the original file being tested."""
    root = _setup(tmp_path)
    report = _run(tmp_path, [_test("T1", STRONG.format(root=root), "F1")], root, max_mutants=3)
    assert report.killed == 3 and report.survived == 0 and report.score == 100.0


def test_truncation_is_reported_and_stable(tmp_path):
    """候選位置超過上限時只跑上限個，標記 truncated，兩次執行選到同樣的變異體。
    Beyond the cap only that many mutants run, `truncated` is set and two runs pick the same mutants."""
    root = _setup(tmp_path)
    tests = [_test("T1", STRONG.format(root=root), "F1"), _test("T2", WEAK, "F2")]
    first = _run(tmp_path, tests, root, max_mutants=3)
    second = _run(tmp_path, tests, root, max_mutants=3)
    assert first.truncated and first.total == 3 and first.candidate_sites == 7
    assert [(m.symbol, m.line, m.mutated) for m in first.mutants] == [(m.symbol, m.line, m.mutated) for m in second.mutants]


def test_scratch_copy_is_removed_and_the_target_is_restored_after_an_error(tmp_path, monkeypatch):
    """即使執行中出錯，暫存複本也會被刪除、原目標不被改動。
    Even when a run fails midway, the scratch copy is removed and the target is untouched."""
    root = _setup(tmp_path)
    made = []
    real = tempfile.mkdtemp
    monkeypatch.setattr(mut.tempfile, "mkdtemp", lambda *a, **k: made.append(real(*a, **k)) or made[-1])
    calls = {"n": 0}

    def flaky(tests, working_dir, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            return "survived"  # 未變異複本的檢查 ／ the unmutated-copy check
        raise RuntimeError("sandbox exploded")
    before = open(os.path.join(root, "shop.py"), encoding="utf-8").read()
    with pytest.raises(RuntimeError):
        mut.run_mutation_testing(flaky, [_test("T1", WEAK, "F1")], _passed([_test("T1", WEAK, "F1")]),
                                 [_finding("F1", root, "discount")], _symbols(root), root, 5, 5)
    assert made and not os.path.exists(made[0])
    assert open(os.path.join(root, "shop.py"), encoding="utf-8").read() == before


def test_endless_loop_mutant_is_killed_by_the_timeout_without_the_rerun_path(tmp_path):
    """會讓程式無窮迴圈的變異體由逾時殺死，而且很快（不走逾時後逐測重跑的路徑）。
    A mutant that makes the code loop forever is killed by the timeout, and quickly (no per-test rerun after a timeout)."""
    import time
    root = _setup(tmp_path, "def run(n):\n    while n > 0:\n        n = n - 1\n    return n\n")
    test = _test("T1", "from shop import run\n\ndef test_run():\n    assert run(3) == 0\n", "F1")
    started = time.monotonic()
    report = mut.run_mutation_testing(
        TestSuiteExecutor(LocalSubprocessSandbox(timeout_seconds=60), per_test_timeout_seconds=10).run_mutant_batch,
        [test], _passed([test]), [_finding("F1", root, "run")], _symbols(root), root, 4, 2)
    assert any(m.operator == "arithmetic" and m.status == "killed" for m in report.mutants)
    assert time.monotonic() - started < 40


def test_invalid_mutants_are_not_scored(tmp_path):
    """沒有結論的變異體（invalid）不算殺死也不算存活，不進分數。
    Inconclusive mutants (invalid) are neither killed nor survived and stay out of the score."""
    root = _setup(tmp_path)
    outcomes = iter(["survived", "killed", "invalid", "surprise", "survived", "killed", "killed", "killed"])
    tests = [_test("T1", WEAK, "F1")]
    report = mut.run_mutation_testing(lambda *a: next(outcomes), tests, _passed(tests), [_finding("F1", root, "discount")],
                                      _symbols(root), root, 7, 5)
    assert (report.killed, report.survived, report.invalid) == (1, 0, 2) or report.invalid >= 1
    assert report.score == pytest.approx(100.0 * report.killed / max(report.killed + report.survived, 1), abs=0.1)
    assert all(m.status in ("killed", "survived", "invalid") for m in report.mutants)


def test_skips_with_a_reason_instead_of_inventing_a_score(tmp_path):
    """沒有可用測試、沒有可變異位置、或測試在未變異複本上就不過：回報原因而不是編造分數。
    No usable tests, no mutable spots, or tests already failing on the unmutated copy: a reason is reported, not an invented score."""
    root = _setup(tmp_path)
    assert "no passed Python" in mut.run_mutation_testing(lambda *a: "survived", [], [], [], [], root, 5, 5).skipped_reason
    findings = [_finding("F1", root, "discount")]
    nothing = _setup(tmp_path / "other", "def f(a):\n    return a\n") if (tmp_path / "other").mkdir() is None else ""
    tests = [_test("T1", WEAK, "F1")]
    finding_other = [_finding("F1", nothing, "f")]
    report = mut.run_mutation_testing(lambda *a: "survived", tests, _passed(tests), finding_other, _symbols(nothing), nothing, 5, 5)
    assert "no mutable spots" in report.skipped_reason and report.score is None
    report = mut.run_mutation_testing(lambda *a: "killed", tests, _passed(tests), findings, _symbols(root), root, 5, 5)
    assert "unmutated copy" in report.skipped_reason and report.score is None and report.total == 0


def test_findings_outside_the_target_or_not_python_are_ignored(tmp_path):
    """目標目錄之外的檔案、非 .py 檔案或查不到符號的發現都被忽略。
    Findings pointing outside the target, at a non-.py file or at an unknown symbol are ignored."""
    root = _setup(tmp_path)
    outside = _finding("F1", root, "discount").model_copy(update={"file_path": str(tmp_path / "elsewhere.py")})
    js = _finding("F2", root, "discount").model_copy(update={"file_path": os.path.join(root, "x.js")})
    ghost = _finding("F3", root, "does_not_exist")
    tests = [_test("T1", WEAK, "F1"), _test("T2", WEAK, "F2"), _test("T3", WEAK, "F3")]
    report = mut.run_mutation_testing(lambda *a: "survived", tests, _passed(tests), [outside, js, ghost], _symbols(root), root, 5, 5)
    assert "no mutable spots" in report.skipped_reason


# --- 執行器：單批判定 -------------------------------------------------------------------------
# --- The executor: one-batch judging ---------------------------------------------------------

class _JunitSandbox:
    """假沙盒：回傳指定的 junit 與結束碼。
    A fake sandbox that returns a given junit report and exit code."""
    timeout_seconds = 30

    def __init__(self, junit, exit_code=0):
        self.junit, self.exit_code, self.calls = junit, exit_code, []

    def execute_pytest_files(self, files, **kwargs):
        self.calls.append(kwargs)
        return self.exit_code, "", "", 0.1, None, self.junit


def _junit(*cases):
    body = "".join(cases)
    return f"<testsuites><testsuite>{body}</testsuite></testsuites>"


PASS_CASE = '<testcase classname="test_vh_000" name="test_a" time="0.1"/>'
FAIL_CASE = '<testcase classname="test_vh_000" name="test_a" time="0.1"><failure message="assert 1 == 2">E assert</failure></testcase>'
HARNESS_FAIL = ('<testcase classname="test_vh_000" name="test_a" time="0.1"><failure message="NameError: name \'x\' is not defined">'
                'E NameError</failure></testcase>')
ERROR_CASE = '<testcase classname="test_vh_000" name="test_a" time="0.1"><error message="collection failure">boom</error></testcase>'


@pytest.mark.parametrize("junit,exit_code,expected", [
    (_junit(PASS_CASE), 0, "survived"),
    (_junit(PASS_CASE, FAIL_CASE), 1, "killed"),
    (_junit(PASS_CASE), 124, "killed"),          # 逾時算殺死 ／ a timeout counts as killed
    (_junit(HARNESS_FAIL), 1, "invalid"),        # 目標壞到匯入／命名錯誤 ／ the code broke import / names
    (_junit(ERROR_CASE), 1, "invalid"),
    ("", 1, "invalid"),
    ("<broken", 1, "invalid"),
])
def test_run_mutant_batch_judges_one_sandbox_batch(tmp_path, junit, exit_code, expected):
    """一個變異體只跑一個批次：失敗或逾時 = killed、全過 = survived、其餘 = invalid；而且傳入逾時、不收覆蓋率。
    A mutant runs exactly one batch: failure or timeout = killed, all passed = survived, everything else = invalid; the
    timeout is passed down and coverage is not collected."""
    from vibeharness.core.sandbox import TIMEOUT_EXIT_CODE
    sandbox = _JunitSandbox(junit, TIMEOUT_EXIT_CODE if exit_code == 124 else exit_code)
    executor = TestSuiteExecutor(sandbox)
    assert executor.run_mutant_batch([_test("T1", "def test_a():\n    assert 1\n", "F1")], str(tmp_path), 7) == expected
    assert len(sandbox.calls) == 1 and sandbox.calls[0]["timeout_seconds"] == 7 and sandbox.calls[0]["collect_coverage"] is False


# --- 閘門語意、開關與報告 ---------------------------------------------------------------------
# --- Gate semantics, the switch and the report -----------------------------------------------

def _pipeline(tmp_path, monkeypatch, report, enabled=True, global_overrides=None):
    """在小目標上跑 mock 管線，把突變測試換成指定的報告。
    Runs the mock pipeline on a small target with mutation testing replaced by the given report."""
    target = tmp_path / "t"
    target.mkdir(exist_ok=True)
    (target / "ok.py").write_text("def greet(name):\n    if name is None:\n        raise ValueError('x')\n    return 'hi ' + name\n", encoding="utf-8")
    cfg = yaml.safe_load(open(CONFIG, encoding="utf-8"))
    cfg["global"].update(global_overrides or {})
    config = tmp_path / "cfg.yaml"
    config.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    commander = VibeHarnessCommander(config_path=str(config), execution_mode="mock")
    if enabled is not None:
        commander.set_mutation(enabled)
    monkeypatch.setattr("vibeharness.core.harness.run_mutation_testing", lambda *a, **k: report)
    out = tmp_path / "r.md"
    summary = commander.run_full_pipeline(target_dir=str(target), base_url="http://localhost:59999", output_report_path=str(out))
    return summary, out.read_text(encoding="utf-8")


def _report(score, survived=0, killed=0, **extra):
    mutants = [MutantResult(file="ok.py", line=4, operator="arithmetic", symbol="greet", original="return 'hi ' + name",
                            mutated="return 'hi ' - name", status="survived") for _ in range(survived)]
    return MutationReport(score=score, killed=killed, survived=survived, total=killed + survived, mutants=mutants, **extra)


def test_low_score_adds_an_evidence_gap_and_never_a_failure(tmp_path, monkeypatch):
    """分數低於門檻：加證據缺口 → INCONCLUSIVE，絕不是 NEEDS_FIXES 或 READY_TO_SHIP；建議列出存活位置。
    A score below the threshold adds an evidence gap -> INCONCLUSIVE, never NEEDS_FIXES or READY_TO_SHIP; the recommendations name the survivors."""
    summary, md = _pipeline(tmp_path, monkeypatch, _report(40.0, survived=3, killed=2))
    assert summary.overall_status == "INCONCLUSIVE"
    assert any("Mutation score 40.0% is below the 70% threshold" in r for r in summary.inconclusive_reasons)
    assert any("ok.py:4" in r and "surviving mutant" in r for r in summary.key_recommendations)
    assert summary.mutation.score == 40.0 and summary.run.mutation_enabled is True and summary.run.mutation_source == "cli"
    assert "Mutation Score" in md and "Surviving Mutants" in md and "`ok.py:4`" in md


def test_a_good_score_adds_no_gap(tmp_path, monkeypatch):
    """分數達標且沒被截斷：不加任何缺口。
    A score at or above the threshold with no truncation adds no gap."""
    summary, md = _pipeline(tmp_path, monkeypatch, _report(100.0, killed=4))
    assert not any("utation" in r for r in summary.inconclusive_reasons)
    assert "No surviving mutants" in md


def test_truncated_and_inconclusive_runs_add_gaps(tmp_path, monkeypatch):
    """被截斷（分數只是樣本）與沒有結論（已要求卻沒跑成）各加一條缺口。
    A truncated list (the score is a sample) and a run with no conclusion (requested but not completed) each add a gap."""
    summary, _ = _pipeline(tmp_path, monkeypatch, _report(100.0, killed=3, truncated=True, candidate_sites=9))
    assert any("covered 3 mutant(s) of 9 candidates" in r for r in summary.inconclusive_reasons)
    skipped = MutationReport(skipped_reason="沒有 ／ nothing to mutate")
    summary, md = _pipeline(tmp_path, monkeypatch, skipped)
    assert any("requested but has no conclusion" in r and "nothing to mutate" in r for r in summary.inconclusive_reasons)
    assert "No conclusion" in md


def test_disabled_by_default_changes_nothing(tmp_path, monkeypatch):
    """預設關閉：不執行、不加缺口、報告沒有突變列，判定與沒有這個功能時相同。
    Off by default: nothing runs, no gap is added, the report has no mutation row and the verdict is as without the feature."""
    called = []
    target = tmp_path / "t"
    target.mkdir()
    (target / "ok.py").write_text("def greet(name):\n    return 'hi ' + name\n", encoding="utf-8")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    monkeypatch.setattr("vibeharness.core.harness.run_mutation_testing", lambda *a, **k: called.append(1))
    summary = commander.run_full_pipeline(target_dir=str(target), base_url="http://localhost:59999",
                                          output_report_path=str(tmp_path / "r.md"))
    assert not called and summary.mutation is None and summary.run.mutation_enabled is False and summary.run.mutation_source == "config"
    assert "Mutation" not in (tmp_path / "r.md").read_text(encoding="utf-8")


def test_mock_mode_run_reports_why_nothing_was_mutated(tmp_path):
    """真的跑一次 mock 管線並開啟突變測試：沒有通過的模型測試，所以回報原因（缺口），不編造分數。
    A real mock-mode run with mutation testing on: no passed model tests, so a reason is reported (a gap), not an invented score."""
    target = tmp_path / "t"
    target.mkdir()
    (target / "ok.py").write_text("def greet(name):\n    return 'hi ' + name\n", encoding="utf-8")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    commander.set_mutation(True)
    summary = commander.run_full_pipeline(target_dir=str(target), base_url="http://localhost:59999",
                                          output_report_path=str(tmp_path / "r.md"))
    assert summary.mutation is not None and summary.mutation.score is None and summary.mutation.skipped_reason
    assert any("requested but has no conclusion" in r for r in summary.inconclusive_reasons)


def test_a_crash_inside_mutation_testing_becomes_a_gap_not_a_failed_audit(tmp_path, monkeypatch):
    """突變測試內部出錯不會讓整個稽核失敗：揭露為證據缺口。
    An error inside mutation testing does not fail the whole audit: it is disclosed as an evidence gap."""
    target = tmp_path / "t"
    target.mkdir()
    (target / "ok.py").write_text("def greet(name):\n    return 'hi ' + name\n", encoding="utf-8")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    commander.set_mutation(True)

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr("vibeharness.core.harness.run_mutation_testing", boom)
    summary = commander.run_full_pipeline(target_dir=str(target), base_url="http://localhost:59999",
                                          output_report_path=str(tmp_path / "r.md"))
    assert summary.mutation.skipped_reason and "failed (OSError)" in summary.mutation.skipped_reason
    assert any("mutation testing failed" in r for r in summary.inconclusive_reasons)


@pytest.mark.parametrize("config_value,cli,expected,source", [
    (None, None, False, "default"),
    (False, None, False, "config"),
    (True, None, True, "config"),
    (True, False, False, "cli"),   # 設定檔開、--no-mutation ／ config on, --no-mutation
    (False, True, True, "cli"),    # 設定檔關、--mutation ／ config off, --mutation
])
def test_switch_precedence_cli_then_config_then_off(tmp_path, config_value, cli, expected, source):
    """開關優先順序：CLI 旗標 > 設定檔 > 預設關閉；最終值與來源都被記錄。
    Switch precedence: CLI flag > config file > off by default; the final value and its source are recorded."""
    cfg = yaml.safe_load(open(CONFIG, encoding="utf-8"))
    if config_value is None:
        cfg["global"].pop("mutation_testing", None)
    else:
        cfg["global"]["mutation_testing"] = config_value
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    commander = VibeHarnessCommander(config_path=str(path), execution_mode="mock")
    if cli is not None:
        commander.set_mutation(cli, "cli")
    assert (commander.mutation_testing, commander.mutation_source) == (expected, source)


def test_cli_flags_set_the_switch_and_the_cap_and_show_in_the_estimate(monkeypatch, tmp_path, capsys):
    """`--mutation`／`--no-mutation`／`--mutation-max-mutants` 生效，且 `--estimate` 只在開啟時列出突變測試上限。
    `--mutation` / `--no-mutation` / `--mutation-max-mutants` take effect, and `--estimate` lists the mutation ceiling only when it is on."""
    from vibeharness import cli

    def estimate(*flags, config=CONFIG):
        monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", EXAMPLES, "-m", "mock", "--estimate", "-c", config, "-o", str(tmp_path / "e.md"), *flags])
        with pytest.raises(SystemExit) as info:
            cli.main()
        assert info.value.code == 0
        return capsys.readouterr().out
    assert "Mutation testing" not in estimate()
    assert "up to 20 mutant(s)" in estimate("--mutation")
    assert "up to 5 mutant(s)" in estimate("--mutation", "--mutation-max-mutants", "5")
    cfg = yaml.safe_load(open(CONFIG, encoding="utf-8"))
    cfg["global"]["mutation_testing"] = True
    on = tmp_path / "on.yaml"
    on.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert "up to 20 mutant(s)" in estimate(config=str(on))
    assert "Mutation testing" not in estimate("--no-mutation", config=str(on))


def test_cli_rejects_a_bad_mutant_cap(monkeypatch, tmp_path, capsys):
    """`--mutation-max-mutants 0` 是用法錯誤（exit 5）。
    `--mutation-max-mutants 0` is a usage error (exit 5)."""
    from vibeharness import cli
    monkeypatch.setattr(sys, "argv", ["vibeharness", "-t", EXAMPLES, "-m", "mock", "--mutation-max-mutants", "0", "-o", str(tmp_path / "r.md")])
    with pytest.raises(SystemExit) as info:
        cli.main()
    assert info.value.code == 5 and "--mutation-max-mutants" in capsys.readouterr().err


@pytest.mark.parametrize("key,value,match", [
    ("mutation_testing", "yes", "mutation_testing"),
    ("mutation_max_mutants", 0, "mutation_max_mutants"),
    ("mutation_max_mutants", True, "mutation_max_mutants"),
    ("mutation_timeout_seconds", -1, "mutation_timeout_seconds"),
    ("mutation_min_score", 101, "mutation_min_score"),
    ("mutation_min_score", "high", "mutation_min_score"),
])
def test_bad_mutation_settings_fail_at_start_up(tmp_path, key, value, match):
    """壞的突變測試設定在啟動時就失敗（exit 5），不會跑到一半才炸。
    Bad mutation settings fail at start-up (exit 5) instead of midway through a run."""
    cfg = yaml.safe_load(open(CONFIG, encoding="utf-8"))
    cfg["global"][key] = value
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    with pytest.raises(Exception, match=match):
        VibeHarnessCommander(config_path=str(path), execution_mode="mock")


def test_report_json_and_partial_report_carry_the_mutation_result(tmp_path, monkeypatch):
    """JSON 報告與崩潰時的部分報告都帶 mutation 區塊；schema_version 維持 "1"。
    The JSON report and a crash's partial report both carry the mutation block; schema_version stays "1"."""
    report = _report(50.0, survived=1, killed=1)
    summary, _ = _pipeline(tmp_path, monkeypatch, report)
    from vibeharness.reports.report_generator import ReportGenerator
    payload = ReportGenerator().generate_json_report(
        summary, MultiModelDebateResult(consensus_summary="c"), ThreatModelReport(system_description="s"), [], [], str(tmp_path))
    data = json.loads(payload) if isinstance(payload, str) else payload
    assert data["schema_version"] == "1" and data["summary"]["mutation"]["score"] == 50.0
    assert data["summary"]["mutation"]["mutants"][0]["status"] == "survived"
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    commander._write_partial_report(str(tmp_path / "r.md"), str(tmp_path), {"phase": 3, "mutation": report}, RuntimeError("x"))
    partial = json.loads((tmp_path / "r.md.partial.json").read_text(encoding="utf-8"))
    assert partial["mutation"]["score"] == 50.0 and partial["phase_reached"] == 3


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash unavailable")
@pytest.mark.parametrize("value,expected_args,code", [
    ("true", ["--mutation"], 0), ("false", ["--no-mutation"], 0), ("", [], 0), ("maybe", [], 5),
])
def test_action_mutation_input_becomes_the_matching_flag(tmp_path, value, expected_args, code):
    """action.yml 的 `mutation` input：true／false 轉成對應旗標，留空不加（沿用設定檔），其他值 exit 5。
    action.yml's `mutation` input: true / false become the matching flag, empty adds none (the config decides), anything else exits 5."""
    lines = open(os.path.join(REPO_ROOT, "action.yml"), encoding="utf-8").read().splitlines()
    begin = next(i for i, line in enumerate(lines) if 'case "$VH_MUTATION" in' in line)
    end = next(i for i in range(begin, len(lines)) if lines[i].strip() == "esac")
    block = "\n".join(line.strip() for line in lines[begin:end + 1])
    script = f'args=()\n{block}\nprintf "%s\\n" "${{args[@]}}"'
    out = subprocess.run([shutil.which("bash"), "-c", script], cwd=tmp_path, capture_output=True, text=True, encoding="utf-8",
                         env={**os.environ, "VH_MUTATION": value})
    assert out.returncode == code
    assert [x for x in out.stdout.splitlines() if x and not x.startswith("::error::")] == expected_args


# --- Docker（有映像檔時才跑） -----------------------------------------------------------------
# --- Docker (only when the image exists) -----------------------------------------------------

def _docker_ready():
    from vibeharness.core.sandbox import DEFAULT_DOCKER_IMAGE
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", DEFAULT_DOCKER_IMAGE], capture_output=True).returncode == 0


@pytest.mark.skipif(not _docker_ready(), reason="Docker or the sandbox image is unavailable")
def test_mutation_testing_runs_against_the_mounted_copy_in_docker(tmp_path):
    """在 Docker 沙盒裡：複本以唯讀掛載，強測試仍能殺死變異體（路徑改寫與掛載映射一致）。
    In the Docker sandbox: the copy is mounted read-only and a strong test still kills mutants (path rewrite and mount mapping agree)."""
    from vibeharness.core.sandbox import DockerSandbox
    root = _setup(tmp_path)
    executor = TestSuiteExecutor(DockerSandbox(timeout_seconds=60), per_test_timeout_seconds=30)
    tests = [_test("T1", STRONG.format(root=root), "F1")]
    report = mut.run_mutation_testing(executor.run_mutant_batch, tests, _passed(tests), [_finding("F1", root, "discount")],
                                      _symbols(root), root, 3, 40)
    assert report.skipped_reason is None and report.killed == 3 and report.score == 100.0
