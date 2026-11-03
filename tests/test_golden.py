"""`scripts/golden/`：重構前後比對輸出的 golden diff 工具（只供開發用，#128）。
`scripts/golden/`: the golden diff tool that compares output before and after a refactor (development only, #128)."""

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
from golden.normalize import normalize  # noqa: E402


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
