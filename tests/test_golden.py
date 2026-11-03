"""`scripts/golden/`：重構前後比對輸出的 golden diff 工具（只供開發用，#128）。
`scripts/golden/`: the golden diff tool that compares output before and after a refactor (development only, #128)."""

import json
import os
import sys

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
from golden.run import run_scenarios  # noqa: E402


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
