"""`scripts/golden/`：重構前後比對輸出的 golden diff 工具（只供開發用，#128）。
`scripts/golden/`: the golden diff tool that compares output before and after a refactor (development only, #128)."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN_DIR = os.path.join(REPO_ROOT, "scripts", "golden")

# sdist 不含 scripts/golden/（MANIFEST.in 的 prune），整份略過
# The sdist leaves out scripts/golden/ (prune in MANIFEST.in), so the whole module skips
if not os.path.isdir(GOLDEN_DIR):
    pytest.skip("scripts/golden/ is not shipped in the sdist", allow_module_level=True)

sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
from golden.compare import IMPORT_MARKER, compare  # noqa: E402
from golden.normalize import normalize  # noqa: E402
import golden.run as golden_run  # noqa: E402
from golden.run import ScenarioCrashed, main, run_scenarios  # noqa: E402


def test_iso_timestamps_become_a_placeholder():
    """報告的產生時間每次都不同，換成固定的佔位字。
    A report's generation time differs on every run, so it becomes a fixed placeholder."""
    text = '"generated_at": "2026-11-03T00:41:31+00:00",'
    assert normalize(text) == '"generated_at": "<TIME>",'


def test_sandbox_directories_lose_their_random_suffix_wherever_they_appear():
    """沙盒目錄名稱帶隨機字尾，絕對路徑和 traceback 裡的相對路徑都要換掉。
    A sandbox directory name carries a random suffix, replaced in absolute paths and in a traceback's relative paths."""
    text = "/tmp/vibe_sandbox_8i51by4y/x.py ../vibe_sandbox_a_b9kz01/test_vh_000.py:20"
    assert normalize(text) == "/tmp/vibe_sandbox_<ID>/x.py ../vibe_sandbox_<ID>/test_vh_000.py:20"


def test_test_durations_become_a_placeholder_and_other_numbers_stay():
    """測試的執行時間每次都不同；涵蓋率、行號這些數字是真正的輸出，要留下來比對。
    A test's duration differs on every run; numbers such as coverage and line numbers are real output and stay."""
    text = '"duration_seconds": 0.012, "coverage_percent": 85.5,\n| `T-1` | unit | `app.py:47` | FAILED | `1.25s` |'
    assert normalize(text) == (
        '"duration_seconds": <DURATION>, "coverage_percent": 85.5,\n| `T-1` | unit | `app.py:47` | FAILED | `<DURATION>s` |'
    )


def test_memory_addresses_become_a_placeholder():
    """物件的 repr 帶記憶體位址，每次執行都不同；程式碼裡的十六進位常數是真正的輸出，要留下來。
    An object's repr carries a memory address that differs on every run; a hex constant in code is real output and stays."""
    text = "<object object at 0x7f3a2c1b9e40> mask = 0xFF"
    assert normalize(text) == "<object object at 0xADDR> mask = 0xFF"


def test_stderr_drops_the_clock_prefix_and_sorts_lines_interleaved_by_threads():
    """agent 呼叫在執行緒上並行，log 行的先後每次不同；去掉時刻前綴後排序。其他輸出的行序是真正的輸出，不排序。
    Agent calls run on threads, so log lines interleave differently on every run; the clock prefix goes and the lines
    are sorted. Other output keeps its order, which is real output."""
    text = "08:41:31 [INFO] b\n08:41:32 [INFO] a\n"
    assert normalize(text, stderr=True) == "[INFO] a\n[INFO] b\n"
    assert normalize(text) == text


def _write(root, files):
    """在 root 底下寫出 {相對路徑: 內容}。
    Writes {relative path: content} under root."""
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_a_changed_line_counts_once_on_each_side(tmp_path):
    """改了一行：基準那邊少一行、工作目錄這邊多一行，共 2 行、2 種。
    One changed line: one line gone on the base side and one added on the working tree's, 2 lines and 2 distinct."""
    _write(tmp_path / "base", {"md/report.md": "# Report\nPassed\nend\n"})
    _write(tmp_path / "head", {"md/report.md": "# Report\nAll passed\nend\n"})
    summary = compare(tmp_path / "base", tmp_path / "head")
    assert summary.lines == 2
    assert summary.distinct == [(1, "< Passed"), (1, "> All passed")]


def test_lines_that_differ_only_in_their_hashes_count_as_one_distinct_difference(tmp_path):
    """訊息改了，SARIF 和 JSON 報告裡的 fingerprint 都跟著變：N 算每一行，M 把只差在雜湊的行合併。
    A changed message changes the fingerprints in both the SARIF and the JSON report: N counts every line, M merges
    lines that differ only in their hashes."""
    old_fp, new_fp = "a" * 40, "b" * 40
    _write(tmp_path / "base", {
        "json/report.sarif": f'"vibeharness/v1": "{old_fp}"\n',
        "json/report.json": f'"fingerprint": "{old_fp}"\n',
        "mixed/report.json": f'"fingerprint": "{"c" * 40}"\n"prompt_sha256": "{"d" * 64}"\n',
    })
    _write(tmp_path / "head", {
        "json/report.sarif": f'"vibeharness/v1": "{new_fp}"\n',
        "json/report.json": f'"fingerprint": "{new_fp}"\n',
        "mixed/report.json": f'"fingerprint": "{"e" * 40}"\n"prompt_sha256": "{"f" * 64}"\n',
    })
    summary = compare(tmp_path / "base", tmp_path / "head")
    assert summary.lines == 8
    assert summary.distinct == [
        (2, '< "fingerprint": "<HASH>"'), (2, '> "fingerprint": "<HASH>"'),
        (1, '< "prompt_sha256": "<HASH>"'), (1, '< "vibeharness/v1": "<HASH>"'),
        (1, '> "prompt_sha256": "<HASH>"'), (1, '> "vibeharness/v1": "<HASH>"'),
    ]


def test_stderr_files_compare_regardless_of_line_order_and_other_files_do_not(tmp_path):
    """.stderr 檔的行序由執行緒決定，不算差異；報告的行序是真正的輸出，算差異。
    A .stderr file's line order is up to the threads and is no difference; a report's line order is real output and
    is."""
    _write(tmp_path / "base", {"md/run.stderr": "08:00:01 [INFO] a\n08:00:01 [INFO] b\n", "md/report.md": "a\nb\n"})
    _write(tmp_path / "head", {"md/run.stderr": "09:30:00 [INFO] b\n09:30:02 [INFO] a\n", "md/report.md": "b\na\n"})
    summary = compare(tmp_path / "base", tmp_path / "head")
    assert summary.lines == 2
    assert summary.distinct == [(1, "< b"), (1, "> b")]


def test_harness_logs_and_the_import_marker_are_not_compared_and_one_sided_files_are(tmp_path):
    """harness log 與 import marker 本來就因 revision 而不同，不比對；只在一邊出現的檔案，每一行都算差異。
    The harness log and the import marker differ by revision by design and are not compared; every line of a file
    present on one side only counts as a difference."""
    _write(tmp_path / "base", {
        "md/report.harness.log": "base log\n", f"md/{IMPORT_MARKER}": "/tmp/base/vibeharness\n",
    })
    _write(tmp_path / "head", {
        "md/report.harness.log": "head log\n", f"md/{IMPORT_MARKER}": "/repo/vibeharness\n",
        "md/new.md": "new\n",
    })
    summary = compare(tmp_path / "base", tmp_path / "head")
    assert summary.lines == 1
    assert summary.distinct == [(1, "> new")]


def test_a_mock_and_a_live_scenario_run_from_the_given_repo_and_twice_give_the_same_output(tmp_path):
    """一個 mock 與一個 live（假 litellm）情境從指定的 repo 匯入 vibeharness，寫出報告、主控台輸出與 exit code；
    跑兩次結果相同。live 的每一次 agent 呼叫都經過假 litellm，目標產生每一種結果。
    抓得到內部改動讓工具壞掉（例如假 litellm 的 patch 失效、悄悄退回模擬），每次不同的輸出，以及某種結果不再出現。
    A mock and a live (fake litellm) scenario import vibeharness from the given repo and write the report, the
    console output and the exit code; two runs give the same result. Every agent call of the live run goes through the
    fake litellm, and the target produces every kind of result. Catches the tool breaking on an internal change (the
    fake litellm patch no longer taking effect and the run falling back to simulation, say), non-deterministic output,
    and a kind of result no longer showing up."""
    for run in ("one", "two"):
        run_scenarios(REPO_ROOT, tmp_path / run, tmp_path / "work", names=["mock_md", "live_json"])
    mock = tmp_path / "one" / "mock_md"
    assert (mock / IMPORT_MARKER).read_text(encoding="utf-8").strip() == os.path.join(REPO_ROOT, "vibeharness")
    assert "# " in (mock / "report.md").read_text(encoding="utf-8")
    assert (mock / "step1.exit_code").read_text(encoding="utf-8").strip() == "1"
    assert (mock / "step1.stdout").stat().st_size > 0 and (mock / "step1.stderr").stat().st_size > 0

    summary = json.loads((tmp_path / "one" / "live_json" / "report.json").read_text(encoding="utf-8"))["summary"]
    assert summary["agent_calls"] and {call["mode"] for call in summary["agent_calls"]} == {"live"}
    for count in ("whitebox_tests_passed", "whitebox_tests_failed", "whitebox_tests_not_run",
                  "blackbox_security_breaches", "blackbox_tests_failed", "blackbox_tests_not_run"):
        assert summary[count] >= 1, count
    assert summary["untested_threat_ids"]
    assert compare(tmp_path / "one", tmp_path / "two").lines == 0


def test_the_live_markdown_scenario_writes_a_real_audit_report(tmp_path):
    """live_md 用同一個目標與假 litellm 寫出 Markdown 報告：每一次呼叫都是真實模式、沒有模擬的段落，結論和 live_json 一樣。
    抓得到情境沒註冊、參數錯誤或 md 報告沒寫出來；決定性已由上面的冒煙測試涵蓋，這裡只跑一次。
    live_md writes a Markdown report from the same target through the fake litellm: every call is live, no section is
    simulated, and the verdict matches live_json's. Catches the scenario missing, wrong arguments or no md report;
    determinism is covered by the smoke test above, so this runs once."""
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["live_md"])
    out = tmp_path / "out" / "live_md"
    report = (out / "report.md").read_text(encoding="utf-8")
    assert "🟢" in report and "SIMULATED" not in report and "🟡" not in report
    assert (out / "step1.exit_code").read_text(encoding="utf-8").strip() == "2"


def test_the_live_baseline_scenario_suppresses_what_the_first_run_found(tmp_path):
    """live_baseline_json 先寫出基準線，再以 --baseline 重跑同一個目標：突破與白箱失敗都成為已知問題、仍列在報告裡，
    但不再決定判定；剩下的只有證據缺口（沒測到的威脅、Not run），所以從 BLOCKED（2）變成 INCONCLUSIVE（3）。
    抓得到基準線步驟的參數錯誤、指紋在兩次 live 執行之間不穩定，以及已知問題不再被壓下。
    live_baseline_json writes a baseline, then reruns the same target with --baseline: the breach and the white-box
    failure become Known problems, still listed but no longer deciding the verdict; only evidence gaps remain (an
    untested threat, Not run), so BLOCKED (2) becomes INCONCLUSIVE (3). Catches wrong baseline step arguments,
    fingerprints that are unstable between two live runs, and Known problems no longer being suppressed."""
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["live_baseline_json"])
    out = tmp_path / "out" / "live_baseline_json"
    assert [(out / f"step{n}.exit_code").read_text(encoding="utf-8").strip() for n in (1, 2)] == ["2", "3"]
    summary = json.loads((out / "report.json").read_text(encoding="utf-8"))["summary"]
    assert summary["blackbox_security_breaches"] >= 1 and summary["whitebox_tests_failed"] >= 1
    assert summary["new_blackbox_security_breaches"] == 0 and summary["new_whitebox_tests_failed"] == 0
    assert {item["kind"] for item in summary["baseline_suppressed"]} >= {"breach", "whitebox_failure"}


def test_a_new_rule_hit_after_the_baseline_decides_the_verdict(tmp_path):
    """live_baseline_changed 的第 2 步換成多了 torch.load 的目標：舊的突破與白箱失敗仍被基準線壓下，新的 HIGH 規則命中
    沒有被壓下、決定判定為 NEEDS_FIXES（1），SARIF 帶著它的 static fingerprint；新函式帶來的 THREAT-05 沒有攻擊測試。
    抓得到換目標的步驟沒生效、新舊問題分錯邊，以及 SARIF 不再寫出 static fingerprint。
    live_baseline_changed's step 2 swaps in the target with a torch.load added: the old breach and white-box failure
    are still suppressed by the baseline, the new HIGH rule hit is not and makes the verdict NEEDS_FIXES (1), and the
    SARIF carries its static fingerprint; THREAT-05, brought by the new function, gets no attack test. Catches the
    target swap not taking effect, new and Known problems landing on the wrong side, and SARIF no longer writing static
    fingerprints."""
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["live_baseline_changed"])
    out = tmp_path / "out" / "live_baseline_changed"
    assert [(out / f"step{n}.exit_code").read_text(encoding="utf-8").strip() for n in (1, 2)] == ["2", "1"]
    summary = json.loads((out / "report.json").read_text(encoding="utf-8"))["summary"]
    assert summary["new_blocking_rule_hits"] >= 1
    assert summary["new_blackbox_security_breaches"] == 0 and summary["new_whitebox_tests_failed"] == 0
    assert {item["kind"] for item in summary["baseline_suppressed"]} >= {"breach", "whitebox_failure"}
    assert "THREAT-05" in summary["untested_threat_ids"]
    results = json.loads((out / "report.sarif").read_text(encoding="utf-8"))["runs"][0]["results"]
    assert any(r["ruleId"] == "vibeharness/VH-AI-002" and r.get("partialFingerprints") for r in results)


def _git_repo(root):
    """在 root 建一個只有一次提交的 git repo。
    Creates a git repo in root with a single commit."""
    root.mkdir()
    (root / "README").write_text("x\n", encoding="utf-8")
    for args in (["init", "-q"], ["add", "README"],
                 ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"]):
        subprocess.run(["git", *args], cwd=root, check=True)
    return root


def _worktrees(repo):
    """git worktree list 的行數（只有主目錄時是 1）。
    The number of lines of git worktree list (1 when only the main checkout is left)."""
    return len(subprocess.run(["git", "worktree", "list"], cwd=repo, check=True, capture_output=True,
                              text=True).stdout.splitlines())


@pytest.fixture
def scratch(tmp_path, monkeypatch):
    """main 的暫存目錄改在這裡建，測試才看得到有沒有留下東西。
    main's temporary directories are created here, so the test sees whether anything is left behind."""
    root = tmp_path / "scratch"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def test_an_unknown_revision_fails_without_leaving_anything_behind(tmp_path, scratch):
    """--against 給了不存在的 revision：結束碼是 2（無法比對，不同於有差異的 1），不留下 worktree 或暫存目錄。
    抓得到 git 失敗時被當成沒有差異，以及失敗路徑漏掉清除。
    --against names a revision that does not exist: the exit code is 2 (could not compare, unlike 1 for differences),
    and no worktree or temporary directory is left. Catches a git failure taken as no differences, and the failure
    path skipping the cleanup."""
    repo = _git_repo(tmp_path / "repo")
    assert main(["--against", "no-such-rev"], repo=str(repo)) == 2
    assert _worktrees(repo) == 1
    assert list(scratch.iterdir()) == []


def test_a_crashing_scenario_run_fails_and_still_removes_the_worktree(tmp_path, scratch, monkeypatch):
    """worktree 建好之後情境執行當掉：結束碼是 2，worktree 和暫存的輸出都被移除。
    抓得到例外跳過清除，留下 worktree 讓下一次 git worktree add 失敗。
    The scenario run crashes after the worktree is added: the exit code is 2, and the worktree and the temporary
    outputs are removed. Catches an exception skipping the cleanup and leaving a worktree that breaks the next git
    worktree add."""
    repo = _git_repo(tmp_path / "repo")

    def crash(*args, **kwargs):
        raise RuntimeError("scenario crashed")

    monkeypatch.setattr(golden_run, "run_scenarios", crash)
    assert main(["--against", "HEAD"], repo=str(repo)) == 2
    assert _worktrees(repo) == 1
    assert list(scratch.iterdir()) == []


def test_both_sides_crashing_the_same_way_is_a_failure_to_compare_not_zero_differences(tmp_path, scratch):
    """兩邊的 CLI 子行程以同樣的方式當掉（這裡是 vibeharness.cli 不存在，像內部改名讓匯入失敗）：輸出一模一樣，
    但那不是「行為不變」，所以結束碼是 2，不是 0；worktree 照樣移除。抓得到 traceback 或沒寫出報告被當成 0 行差異。
    Both sides' CLI child processes crash the same way (here vibeharness.cli does not exist, as when an internal rename
    breaks an import): the outputs are identical, but that is not "behaviour unchanged", so the exit code is 2, not 0,
    and the worktree is still removed. Catches a traceback or a missing report being taken as 0 differing lines."""
    repo = _git_repo(tmp_path / "repo")
    config = repo / "vibeharness" / "config"
    config.mkdir(parents=True)
    (repo / "vibeharness" / "__init__.py").write_text("", encoding="utf-8")
    with open(os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml"), encoding="utf-8") as f:
        (config / "agents_config.yaml").write_text(f.read(), encoding="utf-8")
    subprocess.run(["git", "add", "vibeharness"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "broken"], cwd=repo,
                   check=True)
    assert main(["--against", "HEAD", "mock_md"], repo=str(repo)) == 2
    assert _worktrees(repo) == 1
    assert list(scratch.iterdir()) == []


def test_hybrid_with_one_key_unset_simulates_that_model_even_when_the_shell_has_a_real_key(tmp_path, monkeypatch):
    """hybrid_missing_key 移除 GEMINI_API_KEY：即使開發者的 shell 有一把真的金鑰，Gemini 的每一次呼叫都是模擬的，
    原因寫著金鑰沒設定，其他模型照常 live；品質閘門記下模擬引擎的證據缺口。
    抓得到真的金鑰漏進子行程（會打到真的供應商，或讓情境悄悄變成全 live），以及缺金鑰的 hybrid 路徑不再出現。
    hybrid_missing_key removes GEMINI_API_KEY: even with a real key in the developer's shell, every Gemini call is
    simulated with the key named as not set, the other models stay live, and the Quality Gate records the simulation
    Evidence gap. Catches a real key leaking into the child (which would reach the real provider, or quietly make the
    scenario all live) and the missing-key hybrid path no longer showing up."""
    monkeypatch.setenv("GEMINI_API_KEY", "real-looking-key")
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["hybrid_missing_key"])
    summary = json.loads((tmp_path / "out" / "hybrid_missing_key" / "report.json").read_text(encoding="utf-8"))["summary"]
    gemini = [call for call in summary["agent_calls"] if call["model_alias"] == "gemini"]
    others = [call for call in summary["agent_calls"] if call["model_alias"] != "gemini"]
    assert gemini and others
    assert {call["mode"] for call in gemini} == {"simulated"}
    assert all("API key env var GEMINI_API_KEY is not set" in call["reason"] for call in gemini)
    assert {call["mode"] for call in others} == {"live"}
    assert any("Simulation engine (not real models) was used for" in reason for reason in summary["inconclusive_reasons"])


def test_a_primary_model_that_fails_is_answered_by_its_fallback_and_the_run_stays_live(tmp_path):
    """primary_down 讓 DeepSeek 的主模型（deepseek/deepseek-v4-pro）一律失敗：每一次 DeepSeek 呼叫都由
    fallback_model（deepseek/deepseek-v4-flash）回答，仍是 live，每一次主模型的失敗在 stderr 記一行，判定和 live_json 一樣。
    抓得到 fallback 路徑不再被走到、失敗被改成模擬，以及呼叫紀錄記錯回答的模型。
    primary_down makes DeepSeek's primary model (deepseek/deepseek-v4-pro) always fail: every DeepSeek call is answered
    by its fallback_model (deepseek/deepseek-v4-flash) and stays live, each failure of the primary is one stderr line, and
    the Verdict matches live_json's. Catches the fallback path no longer being reached, a failure turned into simulation,
    and the call log naming the wrong answering model."""
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["primary_down"])
    out = tmp_path / "out" / "primary_down"
    summary = json.loads((out / "report.json").read_text(encoding="utf-8"))["summary"]
    deepseek = [call for call in summary["agent_calls"] if call["model_alias"] == "deepseek"]
    assert deepseek and {call["mode"] for call in summary["agent_calls"]} == {"live"}
    assert {call["model_name"] for call in deepseek} == {"deepseek/deepseek-v4-flash"}
    assert (out / "step1.stderr").read_text(encoding="utf-8").count("Model deepseek/deepseek-v4-pro failed") == len(deepseek)
    assert (out / "step1.exit_code").read_text(encoding="utf-8").strip() == "2"


def test_an_exhausted_budget_simulates_every_later_call_in_hybrid_mode(tmp_path):
    """budget 以 hybrid 模式、--max-model-calls 5 執行：剛好 5 次呼叫是 live，其後每一次都改用模擬並寫明預算用盡，
    品質閘門記下預算用盡的證據缺口。max_concurrent_calls 設為 1，哪 5 次拿到預算才每次相同。
    抓得到預算計數改變（多扣或少扣）、用盡後仍呼叫模型，以及預算缺口不再出現。
    budget runs hybrid with --max-model-calls 5: exactly 5 calls are live, every later one is simulated with the
    budget named as exhausted, and the Quality Gate records the exhausted-budget Evidence gap. max_concurrent_calls is
    1, so the same 5 calls get the budget on every run. Catches the budget counting changing (charging more or less),
    calls still reaching a model after it runs out, and the budget gap no longer showing up."""
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["budget"])
    summary = json.loads((tmp_path / "out" / "budget" / "report.json").read_text(encoding="utf-8"))["summary"]
    live = [call for call in summary["agent_calls"] if call["mode"] == "live"]
    later = [call for call in summary["agent_calls"] if call["mode"] != "live"]
    assert len(live) == 5 and later
    assert all(call["mode"] == "simulated" and "max_model_calls budget exhausted" in call["reason"] for call in later)
    assert any("The max_model_calls budget (5) was exhausted" in reason for reason in summary["inconclusive_reasons"])


def test_a_filled_response_cache_answers_every_call_of_a_cache_only_rerun(tmp_path):
    """live_cache 第 1 步以 --cache-dir 填滿回應快取，第 2 步加 --cache-only 在同一個工作目錄重跑：第 1 步每一次呼叫都是
    真實呼叫，第 2 步同樣多的呼叫全部由快取回答，沒有快取未命中的證據缺口。
    抓得到快取鍵改變（重跑全部未命中）、快取不再寫入，以及 --cache-only 仍呼叫模型。
    live_cache step 1 fills the response cache with --cache-dir, and step 2 reruns in the same working directory with
    --cache-only: every call of step 1 is a real call, the same number of calls in step 2 are all answered from the
    cache, and there is no cache-miss Evidence gap. Catches a changed cache key (every rerun call missing), the cache no
    longer being written, and --cache-only still calling a model."""
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["live_cache"])
    out = tmp_path / "out" / "live_cache"
    fill, replay = (json.loads((out / name).read_text(encoding="utf-8"))["summary"] for name in ("fill.json", "replay.json"))
    assert fill["agent_calls"] and len(replay["agent_calls"]) == len(fill["agent_calls"])
    assert {(call["mode"], call["cached"]) for call in fill["agent_calls"]} == {("live", False)}
    assert {(call["mode"], call["cached"]) for call in replay["agent_calls"]} == {("live", True)}
    assert not any("had no answer in the response cache" in reason for reason in replay["inconclusive_reasons"])


def test_unusable_output_is_re_asked_once_and_booked_invalid_when_it_stays_unusable(tmp_path):
    """invalid_output 讓威脅建模第一次回答非 JSON、重問後才給有效的 JSON，Claude 審查者則一律回答非 JSON：
    威脅建模是一次 retried（attempt 0）接一次 live（attempt 1）；Claude 審查者重問一次後仍無法使用，最後記成 invalid，
    品質閘門記下無效輸出的證據缺口。
    抓得到重問次數改變、重問後的可用回答沒被採用，以及無效輸出被當成「沒有發現」而不是證據缺口。
    invalid_output makes the threat modeler answer non-JSON first and valid JSON once re-asked, and the Claude reviewer
    always answer non-JSON: the threat modeler is one retried call (attempt 0) then one live call (attempt 1); the
    Claude reviewer is still unusable after one re-ask and ends booked invalid, and the Quality Gate records the
    invalid-output Evidence gap. Catches the number of re-asks changing, a usable answer after a re-ask not being
    used, and invalid output taken as "no findings" instead of an Evidence gap."""
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["invalid_output"])
    summary = json.loads((tmp_path / "out" / "invalid_output" / "report.json").read_text(encoding="utf-8"))["summary"]
    calls = summary["agent_calls"]
    threat = [(call["mode"], call["attempt"]) for call in calls if call["kind"] == "threat_modeler"]
    claude = [(call["mode"], call["attempt"]) for call in calls if call["agent_id"] == "whitebox_reviewer_claude"]
    assert threat == [("retried", 0), ("live", 1)]
    assert claude == [("retried", 0), ("invalid", 1)]
    assert any("model call(s) returned unusable output or crashed before answering" in reason
               for reason in summary["inconclusive_reasons"])


def test_a_crashed_reviewer_batch_is_booked_as_a_failed_call_and_the_others_carry_on(tmp_path):
    """crash 讓 Gemini 審查者的批次在 gateway 之外丟出一般例外：那一次呼叫記成當掉的 invalid 呼叫，其他每一次呼叫照常 live，
    品質閘門記下證據缺口；stderr 只有一行錯誤、沒有 traceback（否則 run_scenarios 會丟出 ScenarioCrashed）。
    抓得到當掉的批次讓整次執行失敗、被悄悄丟掉（變成「沒有發現」），以及它的紀錄不再標明是當掉。
    crash makes the Gemini reviewer's batch raise an ordinary exception outside the gateway: that call is booked as a
    crashed invalid call, every other call stays live, and the Quality Gate records the Evidence gap; stderr holds one
    error line for it and no traceback (run_scenarios would raise ScenarioCrashed otherwise). Catches a crashed batch failing
    the whole run or being dropped silently (as "no findings"), and its record no longer saying it crashed."""
    run_scenarios(REPO_ROOT, tmp_path / "out", tmp_path / "work", names=["crash"])
    out = tmp_path / "out" / "crash"
    summary = json.loads((out / "report.json").read_text(encoding="utf-8"))["summary"]
    crashed = [call for call in summary["agent_calls"]
               if call["kind"] == "reviewer" and call["agent_id"] == "whitebox_reviewer_gemini"]
    others = [call for call in summary["agent_calls"] if call not in crashed]
    assert len(crashed) == 1 and crashed[0]["mode"] == "invalid"
    assert "agent call crashed before producing output" in crashed[0]["reason"]
    assert {call["kind"] for call in others} > {"reviewer"} and {call["mode"] for call in others} == {"live"}
    # fan_out 的錯誤是雙語的一行，中英兩半都帶著例外訊息 ／ fan_out's error is one bilingual line, the exception in both halves
    lines = (out / "step1.stderr").read_text(encoding="utf-8").splitlines()
    assert len([line for line in lines if "golden fake: injected crash in whitebox_reviewer_gemini's batch" in line]) == 1
    assert any("model call(s) returned unusable output or crashed before answering" in reason
               for reason in summary["inconclusive_reasons"])


def _copy_of_vibeharness(root):
    """把這個 repo 的 vibeharness/ 複製到 root 底下，當作另一個 revision。
    Copies this repo's vibeharness/ under root, standing in for another revision."""
    shutil.copytree(os.path.join(REPO_ROOT, "vibeharness"), root / "vibeharness",
                    ignore=shutil.ignore_patterns("__pycache__"))
    return root


def test_the_crash_scenario_fails_to_compare_when_its_patch_target_is_missing(tmp_path):
    """另一個 revision 把 _review_batch 改了名：crash 的 patch 目標不存在，情境當掉（之後 main 回傳 2），
    不會悄悄沒注入就跑完、被當成行為不同或相同。
    Another revision renamed _review_batch: crash's patch target is missing, so the scenario crashes (main then exits
    2) instead of running without the injection and comparing as different or the same."""
    repo = _copy_of_vibeharness(tmp_path / "repo")
    reviewer = repo / "vibeharness" / "agents" / "whitebox" / "multi_reviewer.py"
    reviewer.write_text(re.sub(r"\b_review_batch\b", "_review_one", reviewer.read_text(encoding="utf-8")),
                        encoding="utf-8")
    with pytest.raises(ScenarioCrashed):
        run_scenarios(repo, tmp_path / "out", tmp_path / "work", names=["crash"])


def test_the_crash_scenario_fails_to_compare_when_its_patch_never_fires(tmp_path):
    """另一個 revision 的 Gemini 審查者換了 agent id：patch 還在，卻從沒判斷到要當掉的批次，情境照樣當掉（main 回傳 2）。
    改 agent id 代表 patch 用來認出批次的依據變了這一類改動（參數形狀改變也屬於這類）：抓得到它們讓注入悄悄失效。
    Another revision gives the Gemini reviewer another agent id: the patch is in place but never meets the batch it
    should crash, and the scenario still crashes (main exits 2). The agent id stands for any change to what the patch
    recognises its batch by (a changed argument shape is another): catches such a change silently disabling the
    injection."""
    repo = _copy_of_vibeharness(tmp_path / "repo")
    config = repo / "vibeharness" / "config" / "agents_config.yaml"
    config.write_text(config.read_text(encoding="utf-8").replace("whitebox_reviewer_gemini:", "whitebox_reviewer_gem:"),
                      encoding="utf-8")
    with pytest.raises(ScenarioCrashed):
        run_scenarios(repo, tmp_path / "out", tmp_path / "work", names=["crash"])


def test_a_config_override_fails_to_compare_when_its_key_is_missing_on_that_side(tmp_path):
    """另一個 revision 把 max_concurrent_calls 改了名（vibeharness 不會拒絕不認得的鍵）：budget 的覆寫找不到要改的鍵，
    情境當掉（main 回傳 2），不會悄悄新增一個沒人讀的鍵、讓覆寫失效卻照常比對。
    Another revision renamed max_concurrent_calls (vibeharness does not reject an unknown key): budget's override finds
    no key to change, so the scenario crashes (main exits 2) instead of quietly adding a key nothing reads and comparing
    with the override lost."""
    repo = _copy_of_vibeharness(tmp_path / "repo")
    config = repo / "vibeharness" / "config" / "agents_config.yaml"
    config.write_text(config.read_text(encoding="utf-8").replace("  max_concurrent_calls:", "  max_parallel_calls:"),
                      encoding="utf-8")
    with pytest.raises(ScenarioCrashed):
        run_scenarios(repo, tmp_path / "out", tmp_path / "work", names=["budget"])


def test_primary_down_fails_to_compare_when_its_model_string_is_gone_on_that_side(tmp_path):
    """另一個 revision 把 DeepSeek 的主模型換了字串：primary_down 的注入從沒擋下任何呼叫，情境當掉（main 回傳 2），
    不會悄悄沒注入就跑完、被當成行為不同。
    Another revision gives DeepSeek another primary model string: primary_down's injection never blocks a call, so the
    scenario crashes (main exits 2) instead of quietly running without it and comparing as a behaviour change."""
    repo = _copy_of_vibeharness(tmp_path / "repo")
    config = repo / "vibeharness" / "config" / "agents_config.yaml"
    config.write_text(config.read_text(encoding="utf-8").replace('model: "deepseek/deepseek-v4-pro"',
                                                                 'model: "deepseek/deepseek-v5-pro"'), encoding="utf-8")
    with pytest.raises(ScenarioCrashed):
        run_scenarios(repo, tmp_path / "out", tmp_path / "work", names=["primary_down"])


def test_invalid_output_fails_to_compare_when_the_re_ask_sentence_changed_on_that_side(tmp_path):
    """另一個 revision 改寫了重問的句子：invalid_output 認不出重問，威脅建模從沒在重問後拿到有效的 JSON，情境當掉
    （main 回傳 2），不會把變形的注入當成行為不同。
    Another revision rewords the re-ask sentence: invalid_output no longer recognises a re-ask, so the threat modeler
    never gets valid JSON after one, and the scenario crashes (main exits 2) instead of comparing a warped injection
    as a behaviour change."""
    repo = _copy_of_vibeharness(tmp_path / "repo")
    gateway = repo / "vibeharness" / "core" / "llm_gateway.py"
    gateway.write_text(gateway.read_text(encoding="utf-8").replace("Your previous answer could not be used (",
                                                                   "Your last answer was unusable ("), encoding="utf-8")
    with pytest.raises(ScenarioCrashed):
        run_scenarios(repo, tmp_path / "out", tmp_path / "work", names=["invalid_output"])
