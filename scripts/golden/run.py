"""golden diff 的進入點：在一個 revision 與工作目錄上跑同一組情境並比對輸出（#128）。
The golden diff entry point: runs one set of scenarios on a revision and on the working tree and compares the
output (#128)."""

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    # 以 `python scripts/golden/run.py` 執行時，讓 `golden` 套件可以匯入
    # When run as `python scripts/golden/run.py`, make the `golden` package importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from golden.compare import IMPORT_MARKER  # noqa: E402
from golden.targets import MOCK_TARGET  # noqa: E402

# 子行程：從指定的 repo 匯入 vibeharness、記下匯入位置，再以其餘參數執行 CLI
# The child process: imports vibeharness from the given repo, records where it came from, then runs the CLI with the
# remaining arguments
_CHILD = """\
import os, sys
repo, marker = sys.argv[1], sys.argv[2]
sys.path.insert(0, repo)
import vibeharness
with open(marker, "w", encoding="utf-8") as f:
    f.write(os.path.dirname(os.path.abspath(vibeharness.__file__)) + "\\n")
from vibeharness.cli import main
sys.argv = ["vibeharness"] + sys.argv[3:]
main()
"""

# 主控台寬度與雜湊種子固定，輸出才不隨終端機或執行而變
# A fixed console width and hash seed, so the output does not vary with the terminal or the run
_ENV = {"COLUMNS": "120", "PYTHONHASHSEED": "0", "PYTHONIOENCODING": "utf-8"}


@dataclass(frozen=True)
class Scenario:
    """一個情境：目標檔案、CLI 參數，以及要收集的輸出檔。
    One scenario: the target files, the CLI arguments and the output files to collect."""

    target: dict[str, str]
    args: tuple[str, ...]
    outputs: tuple[str, ...]


SCENARIOS = {
    "mock_md": Scenario(MOCK_TARGET, ("-m", "mock", "--format", "md", "-o", "report.md"), ("report.md",)),
}


def run_scenarios(repo, out, work, names: Optional[list[str]] = None) -> None:
    """在子行程裡以 repo 的 vibeharness 跑各情境，結果寫到 out/<情境>/；work 是兩邊共用的工作目錄。
    Runs each scenario with repo's vibeharness in a child process and writes the results to out/<scenario>/; work is
    the working directory both sides share."""
    repo = os.path.abspath(repo)
    for name in names or list(SCENARIOS):
        _run(repo, name, SCENARIOS[name], Path(out) / name, Path(work) / name)


def _run(repo: str, name: str, scenario: Scenario, out: Path, work: Path) -> None:
    """在全新的 work 裡寫出目標與設定、跑一次 CLI，把輸出收進 out。
    Writes the target and the config into a fresh work, runs the CLI once and collects the output into out."""
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    out.mkdir(parents=True, exist_ok=True)
    for rel, content in scenario.target.items():
        (work / rel).write_text(content, encoding="utf-8")
    # 設定檔複製進 work：報告記下的路徑兩邊相同，設定內容的改動仍然看得到
    # The config is copied into work: the path the report records is the same on both sides, and a change to its
    # content still shows
    shutil.copyfile(os.path.join(repo, "vibeharness", "config", "agents_config.yaml"), work / "vibeharness.yaml")
    target = next(iter(scenario.target)) if len(scenario.target) == 1 else "."
    proc = subprocess.run(
        [sys.executable, "-I", "-c", _CHILD, repo, str(out / IMPORT_MARKER), "-t", target, "-c", "vibeharness.yaml",
         *scenario.args],
        cwd=work, env={**os.environ, **_ENV}, capture_output=True, text=True, encoding="utf-8",
    )
    (out / "stdout").write_text(proc.stdout, encoding="utf-8")
    (out / "run.stderr").write_text(proc.stderr, encoding="utf-8")
    (out / "exit_code").write_text(f"{proc.returncode}\n", encoding="utf-8")
    for rel in scenario.outputs:
        if (work / rel).is_file():
            shutil.copyfile(work / rel, out / rel)
