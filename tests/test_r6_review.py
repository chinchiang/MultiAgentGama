"""第六輪審查的回歸測試：非 ASCII 文字與路徑、symlink 目標、基準線鍵、估算與逐測重跑的錯誤歸因。
Regression tests of the sixth review round: non-ASCII text and paths, a symlinked target, baseline keys, the
estimate and the blame of a per-test rerun."""
import os
import subprocess
import sys

import pytest

from vibeharness.agents.blackbox.threat_modeler import AutomatedThreatModeler
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.agents.whitebox.deduplicator import deduplicate_findings
from vibeharness.agents.whitebox.test_generator import WhiteboxTestGenerator
from vibeharness.core import baseline as bl
from vibeharness.core.estimate import estimate_lines, estimate_run
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.llm_gateway import LLMGateway
from vibeharness.core.models import (
    FindingSeverity, GeneratedTest, ReviewFinding, STRIDECategory, StaticFinding, TestExecutionResult, TestStatus,
    ThreatItem,
)
from vibeharness.core.sandbox import TIMEOUT_EXIT_CODE
from vibeharness.runners.test_executor import REASON_NO_TEST_COLLECTED, TestSuiteExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
EXAMPLES = os.path.join(REPO_ROOT, "examples")


def _threat(tid, title, vector="登入表單"):
    return ThreatItem(
        threat_id=tid, stride_category=STRIDECategory.SPOOFING, title=title, description="", asset_at_risk="a",
        attack_vector=vector, trust_boundary_crossed="b", severity=FindingSeverity.HIGH, attack_scenario="",
        test_verification_goal="",
    )


def _finding(fid, title, root_cause=""):
    return ReviewFinding(
        finding_id=fid, reviewer_name=fid, model_alias=fid.lower(), file_path="app.py", symbol_name="search",
        severity=FindingSeverity.HIGH, title=title, description="", root_cause=root_cause, suspected_vibe_flaw="",
        suggested_test_scenario="",
    )


def _repo(root):
    git = lambda *a: subprocess.run(["git", *a], cwd=root, check=True, capture_output=True)  # noqa: E731
    git("init", "-q", ".")
    (root / "base.py").write_text("def base(x):\n    return x\n", encoding="utf-8")
    git("add", "-A")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
    return git


# --- 1. 中文威脅不會被合併成一個 ---------------------------------------------------------------
# --- 1. Chinese threats are not merged into one ---------------------------------------------------------

def test_distinct_chinese_threats_are_not_merged():
    threats = [_threat("THREAT-01", "偽造會話權杖"), _threat("THREAT-02", "暴力破解密碼")]
    merged = AutomatedThreatModeler._merge_duplicate_threats(threats)
    assert [t.threat_id for t in merged] == ["THREAT-01", "THREAT-02"]
    # 真正的重複（只差大小寫與標點）仍會合併 ／ a real duplicate (case and punctuation only) still merges
    again = AutomatedThreatModeler._merge_duplicate_threats([_threat("THREAT-01", "偽造會話權杖！"), _threat("THREAT-02", "偽造會話權杖")])
    assert [t.threat_id for t in again] == ["THREAT-01"]


def test_simulated_threats_with_the_same_english_half_merge_like_their_breach_keys():
    """威脅合併與 breach_key 用同一個威脅身分：模擬的雙語標題只看英文半，所以中文半不同、英文半相同的兩個模擬威脅
    是同一威脅（基準線早就把它們的突破視為同一個），合併時保留較高的嚴重度。
    The threat merge and breach_key share one threat identity: a simulated bilingual title counts by its English half,
    so two simulated threats with the same English half and different Chinese halves are one threat (the baseline
    already treats their breaches as one), and the merge keeps the higher severity."""
    from vibeharness.core.i18n import bi
    first = _threat("THREAT-01", bi("越權存取", "IDOR")).model_copy(update={"is_simulated": True})
    second = _threat("THREAT-02", bi("越權", "IDOR")).model_copy(
        update={"is_simulated": True, "severity": FindingSeverity.CRITICAL})
    merged = AutomatedThreatModeler._merge_duplicate_threats([first, second])
    assert [(t.threat_id, t.severity) for t in merged] == [("THREAT-01", FindingSeverity.CRITICAL)]
    result = TestExecutionResult(test_id="BB-TEST-1", test_type="blackbox_security", status=TestStatus.FAILED)
    assert bl.breach_key(result, first) == bl.breach_key(result, second)


def test_a_simulated_and_a_real_threat_with_the_same_bilingual_title_stay_apart():
    """真實模型的文字原樣進鍵、模擬的只取英文半：標題字面相同的一個模擬威脅與一個真實威脅不是同一威脅（breach_key 也不同），
    所以不會合併，真實威脅不會被模擬範本吞掉。
    Real model text enters the key as is and simulated text by its English half: a simulated and a real threat with
    the same literal bilingual title are not the same threat (their breach_keys differ too), so they are not merged
    and the real threat is not swallowed by a simulated template."""
    from vibeharness.core.i18n import bi
    title = bi("越權存取", "IDOR")
    simulated = _threat("THREAT-01", title).model_copy(update={"is_simulated": True})
    real = _threat("THREAT-02", title)
    merged = AutomatedThreatModeler._merge_duplicate_threats([simulated, real])
    assert [t.threat_id for t in merged] == ["THREAT-01", "THREAT-02"]
    result = TestExecutionResult(test_id="BB-TEST-1", test_type="blackbox_security", status=TestStatus.FAILED)
    assert bl.breach_key(result, simulated) != bl.breach_key(result, real)


# --- 2. --changed-since 不會漏掉非 ASCII 檔名 ---------------------------------------------------
# --- 2. --changed-since keeps non-ASCII file names --------------------------------------------------------

def test_changed_since_keeps_non_ascii_file_names(tmp_path):
    _repo(tmp_path)
    (tmp_path / "a.py").write_text("def a(x):\n    return x\n", encoding="utf-8")
    (tmp_path / "中文.py").write_text("def b(x):\n    return x\n", encoding="utf-8")
    (tmp_path / "base.py").write_text("def base(x, y):\n    return x\n", encoding="utf-8")
    changed = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock").changed_files(str(tmp_path), "HEAD")
    assert sorted(os.path.basename(p) for p in changed) == ["a.py", "base.py", "中文.py"]


# --- 3. symlink 目標下的 --changed-since 對得上檔案 -----------------------------------------------
# --- 3. --changed-since through a symlinked target matches the files ---------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_changed_since_through_a_symlinked_target_matches_the_walk(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    _repo(real)
    (real / "a.py").write_text("def a(x):\n    return x\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    changed = commander.changed_files(str(link), "HEAD")
    assert changed == [os.path.join(str(link), "a.py")]
    symbols = ASTExtractor().parse_directory(str(link), only_files=changed)
    assert [s.name for s in symbols] == ["a"]


# --- 4. 不同檔案的同名函式探測不共用基準線鍵 ----------------------------------------------------
# --- 4. Probes of same-named functions in different files do not share a baseline key ----------------------

def test_probes_of_same_named_functions_in_different_files_have_distinct_keys(tmp_path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("def process(order):\n    return order['id']\n", encoding="utf-8")
    symbols = ASTExtractor().parse_directory(str(tmp_path))
    probes = WhiteboxTestGenerator(LLMGateway(CONFIG, execution_mode="mock")).build_offline_probes(symbols, str(tmp_path))
    results = [TestExecutionResult(test_id=p.test_id, test_type=p.test_type, status=TestStatus.FAILED, source_ref=p.source_ref)
               for p in probes]
    assert len(results) == 2
    known = bl.Baseline(path="", findings={bl.probe_key(results[0])})
    cmp = bl.compare_with_baseline(known, str(tmp_path), [], results, [], [], [])
    assert [r.test_id for r in cmp.new_whitebox_failures] == [results[1].test_id]


# --- 5. 去重不會忽略中文詞 ---------------------------------------------------------------------
# --- 5. Deduplication does not ignore Chinese words ---------------------------------------------------------

def test_dedup_keeps_findings_that_differ_only_in_chinese_words():
    findings = [_finding("WB-CLA-01", "SQL 注入於搜尋參數"), _finding("WB-DEE-01", "SQL 盲注造成資料外洩")]
    assert [f.finding_id for f in deduplicate_findings(findings)] == ["WB-CLA-01", "WB-DEE-01"]
    # 同一句中文的重複回報仍會合併 ／ a repeated report of the same Chinese title still merges
    same = [_finding("WB-CLA-01", "SQL 注入於搜尋參數"), _finding("WB-DEE-01", "SQL 注入於搜尋參數")]
    assert len(deduplicate_findings(same)) == 1


# --- 6. 換機器重跑時，名稱含點的目錄目標算出相同的鍵 ----------------------------------------------
# --- 6. A dotted directory target keys the same when an old baseline is replayed elsewhere --------------------

def test_old_baseline_of_a_dotted_directory_from_another_machine_keys_the_same(tmp_path):
    here = tmp_path / "app.v2"
    (here / "src").mkdir(parents=True)
    other = "/nonexistent-ci/work/app.v2"
    sf = dict(rule_id="VH-AI-001", title="t", severity="HIGH", line_number=3, evidence="pickle.load(x)",
              remediation="")
    old = StaticFinding(**sf, file_path=f"{other}/src/x.py")
    now = StaticFinding(**sf, file_path=str(here / "src" / "x.py"))
    assert bl.target_relative(old.file_path, other) == "src/x.py"
    assert bl.static_key(old, other) == bl.static_key(now, str(here))
    # 檔案目標（不論是否存在）仍以檔名為鍵 ／ a file target (existing or not) still keys by its name
    assert bl.target_relative("/nonexistent-ci/work/app.py", "/nonexistent-ci/work/app.py") == "app.py"
    script = here / "run"
    script.write_text("print(1)\n", encoding="utf-8")
    assert bl.target_relative(str(script), str(script)) == "run"


# --- 7. --estimate 計入未變異複本上的那一批 -----------------------------------------------------
# --- 7. --estimate counts the batch on the unmutated copy -----------------------------------------------------

def test_estimate_counts_the_unmutated_baseline_batch():
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    commander.set_mutation(True, "cli")
    est = estimate_run(commander, EXAMPLES)
    assert est.mutation_sandbox_runs_max == commander.settings.mutation.max_mutants + 1 == 21
    assert any("up to 20 mutant(s)" in line and "21 sandbox batch" in line for line in estimate_lines(est))


# --- 8. 沒有報告的逐測重跑不會怪到測試頭上 -------------------------------------------------------
# --- 8. A per-test rerun with no report is not blamed on the test ----------------------------------------------

class _CrashOnRerun:
    """批次逾時；逐測重跑時 test_vh_000 的直譯器當掉（沒有 JUnit 報告），test_vh_001 通過。
    The batch times out; on the per-test rerun test_vh_000's interpreter crashes (no JUnit report), test_vh_001 passes."""
    timeout_seconds = 30

    def execute_pytest_files(self, files, timeout_seconds=None, **kw):
        if len(files) > 1:
            return TIMEOUT_EXIT_CODE, "", "timed out", 30.0, None, None
        module = os.path.splitext(next(iter(files)))[0]
        if module == "test_vh_000":
            return -9, "", "Fatal Python error: killed", 0.1, None, None
        junit = f'<testsuites><testsuite name="pytest"><testcase classname="{module}" name="test_b" time="0.1"/></testsuite></testsuites>'
        return 0, "", "", 0.1, None, junit


def test_rerun_without_a_report_is_reported_as_a_sandbox_problem(tmp_path):
    tests = [GeneratedTest(test_id=i, test_type="whitebox_unit", target_component="x", title=i, code=f"def test_{i.lower()}():\n    assert 1\n",
                           rationale="", expected_outcome="") for i in ("A", "B")]
    results, _ = TestSuiteExecutor(sandbox=_CrashOnRerun(), per_test_timeout_seconds=5).execute_test_suite(tests, working_dir=str(tmp_path))
    assert results[0].status == TestStatus.ERROR and results[0].failure_reason != REASON_NO_TEST_COLLECTED
    assert "Sandbox run produced no report" in results[0].failure_reason and "Fatal Python error" in results[0].failure_reason
    assert results[1].status == TestStatus.PASSED


# --- 9. litellm 1.105 的 signoz_ingestion_key 與其他 `key` 名稱都被保留 ---------------------------------
# --- 9. litellm 1.105's signoz_ingestion_key and other `key` names are reserved -----------------------------

def test_key_named_and_signoz_params_are_reserved():
    from vibeharness.core.llm_gateway import is_reserved_extra_param
    for name in ("signoz_ingestion_key", "signoz_endpoint_region", "public_key", "ingestion_key", "key"):
        assert is_reserved_extra_param(name), name
    for name in ("temperature", "top_k", "input_cost_per_token", "keyword_boost", "prompt_cache_key"):
        assert not is_reserved_extra_param(name), name
