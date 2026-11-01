"""在本機重現 CI 的 package job：建 sdist、解到暫存目錄、在裡面跑測試套件。

sdist 不帶 `.github/` 與 `AGENTS.md`，所以只在 repo 裡跑的測試會漏掉兩種錯誤：讀那些檔案卻沒有略過的測試，
以及 sdist 漏打包、但文件或測試會用到的檔案。新增檔案或測試時，推送前跑這支 script。
與 CI 的差別：用目前的 Python 環境跑（CI 另建一個以 `requirements.lock` 安裝的 venv）。

用法：
    python scripts/test_sdist.py                 # 隔離建置 sdist，跑整個測試套件
    python scripts/test_sdist.py --no-isolation  # 用目前環境的建置後端（需要已安裝 setuptools）
    python scripts/test_sdist.py tests/test_x.py -k name   # 其餘參數原樣交給 pytest

Reproduce CI's package job locally: build the sdist, extract it into a temporary directory and run the suite there.

The sdist ships neither `.github/` nor `AGENTS.md`, so running the tests from the repo misses two kinds of mistake: a
test that reads those files without skipping, and a file the docs or tests use that the sdist does not ship. Run
this script before pushing when you add files or tests. Unlike CI it uses the current Python environment (CI builds a
fresh venv from `requirements.lock`).

Usage:
    python scripts/test_sdist.py                 # build the sdist in isolation and run the whole suite
    python scripts/test_sdist.py --no-isolation  # use the current environment's build backend (needs setuptools)
    python scripts/test_sdist.py tests/test_x.py -k name   # any other arguments go to pytest unchanged
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable, Sequence

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTEST_ARGS = ("-q", "-p", "no:cacheprovider")

Runner = Callable[..., int]


def _run(cmd: Sequence[str], cwd: str, env: dict[str, str] | None = None) -> int:
    return subprocess.run(list(cmd), cwd=cwd, env=env).returncode


def extract(archive: str, dest: str) -> str:
    """把 sdist 解到 dest，回傳解開後的專案目錄（封存檔裡唯一的頂層目錄）。
    Extract the sdist into dest and return the project directory (the archive's single top-level directory)."""
    # 一律用 data filter（拒絕絕對路徑、`..`、連結到目的地之外與裝置檔）；沒有它的 Python 不解壓縮
    # Always use the data filter (it refuses absolute paths, `..`, links out of the destination and device files);
    # a Python without it does not extract at all
    if not hasattr(tarfile, "data_filter"):
        raise RuntimeError("extracting the sdist safely needs tarfile's data filter (Python 3.11.4 or later)")
    with tarfile.open(archive) as tar:
        tar.extractall(dest, filter="data")
    tops = [p for p in glob.glob(os.path.join(dest, "*")) if os.path.isdir(p)]
    if len(tops) != 1:
        raise RuntimeError(f"expected one top-level directory in {archive}, found {len(tops)}")
    return tops[0]


def run_sdist_tests(pytest_args: Sequence[str], isolation: bool = True, run: Runner = _run,
               python: str = sys.executable) -> int:
    """建 sdist、解開、在裡面跑 pytest，回傳 exit code（建置失敗回傳建置的 exit code）。暫存目錄跑完就刪除。
    Build the sdist, extract it and run pytest inside; return the exit code (the build's when the build fails). The
    temporary directory is removed afterwards."""
    with tempfile.TemporaryDirectory(prefix="vh-sdist-") as tmp:
        dist = os.path.join(tmp, "dist")
        build = [python, "-m", "build", "--sdist", "--outdir", dist] + ([] if isolation else ["--no-isolation"])
        code = run(build, cwd=REPO_ROOT)
        if code != 0:
            print(f"Building the sdist failed (exit {code}).", file=sys.stderr)
            return code
        archives = glob.glob(os.path.join(dist, "*.tar.gz"))
        if len(archives) != 1:
            print(f"Expected one sdist in {dist}, found {len(archives)}.", file=sys.stderr)
            return 2
        project = extract(archives[0], os.path.join(tmp, "src"))
        print(f"Running the tests from {os.path.basename(project)} (the extracted sdist)...", flush=True)
        # CI 也設定它：tests/test_review_build.py 會比對封存檔內容 ／ CI sets it too: tests/test_review_build.py checks the archive
        env = {**os.environ, "VIBEHARNESS_SDIST": archives[0]}
        return run([python, "-m", "pytest", *PYTEST_ARGS, *pytest_args], cwd=project, env=env)


def main(argv: Sequence[str] | None = None) -> int:
    """命令列進入點：`--no-isolation` 之外的參數都交給 pytest。
    Command-line entry point: every argument except `--no-isolation` goes to pytest."""
    args = list(sys.argv[1:] if argv is None else argv)
    isolation = "--no-isolation" not in args
    return run_sdist_tests([a for a in args if a != "--no-isolation"], isolation=isolation)


if __name__ == "__main__":
    sys.exit(main())
