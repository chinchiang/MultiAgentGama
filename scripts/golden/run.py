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
from golden.targets import LIVE_TARGET, MOCK_TARGET  # noqa: E402

# 子行程：從指定的 repo 匯入 vibeharness、記下匯入位置，live 情境再裝上這份工具的假 litellm（兩邊用同一份），
# 最後以其餘參數執行 CLI
# The child process: imports vibeharness from the given repo, records where it came from, for a live scenario
# installs this tool's fake litellm (the same one on both sides), then runs the CLI with the remaining arguments
_CHILD = """\
import os, sys
repo, marker, golden_parent = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, repo)
import vibeharness
with open(marker, "w", encoding="utf-8") as f:
    f.write(os.path.dirname(os.path.abspath(vibeharness.__file__)) + "\\n")
if golden_parent:
    sys.path.append(golden_parent)
    from golden.fake_llm import install
    install()
from vibeharness.cli import main
sys.argv = ["vibeharness"] + sys.argv[4:]
main()
"""

# 主控台寬度與雜湊種子固定，輸出才不隨終端機或執行而變
# A fixed console width and hash seed, so the output does not vary with the terminal or the run
_ENV = {"COLUMNS": "120", "PYTHONHASHSEED": "0", "PYTHONIOENCODING": "utf-8"}
# live 模式要求有 API 金鑰；假 litellm 不會用到它們
# Live mode requires API keys; the fake litellm never uses them
_FAKE_KEYS = {var: "golden-fake-key" for var in ("ANTHROPIC_API_KEY", "ZAI_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY")}
_GOLDEN_PARENT = str(Path(__file__).resolve().parent.parent)


@dataclass(frozen=True)
class Scenario:
    """一個情境：目標檔案、依序執行的各步驟 CLI 參數（例如 --baseline 要先有一份報告）、要收集的輸出檔，
    以及是否以 live 模式經過假 litellm。
    One scenario: the target files, the CLI arguments of each step in order (--baseline, say, needs a report
    first), the output files to collect, and whether it runs in live mode through the fake litellm."""

    target: dict[str, str]
    steps: tuple[tuple[str, ...], ...]
    outputs: tuple[str, ...]
    live: bool = False


_MOCK = ("-m", "mock")
_LIVE = ("-m", "live")

SCENARIOS = {
    "mock_md": Scenario(MOCK_TARGET, ((*_MOCK, "--format", "md", "-o", "report.md"),), ("report.md",)),
    "mock_json": Scenario(MOCK_TARGET, (
        (*_MOCK, "--format", "json", "-o", "report.json", "--sarif", "report.sarif", "--summary-json", "summary.json"),
    ), ("report.json", "report.sarif", "summary.json")),
    "mock_estimate": Scenario(MOCK_TARGET, ((*_MOCK, "--estimate"),), ()),
    "mock_estimate_json": Scenario(MOCK_TARGET, (
        (*_MOCK, "--estimate", "--format", "json", "-o", "estimate.json"),
    ), ("estimate.json",)),
    "mock_mutation": Scenario(MOCK_TARGET, ((*_MOCK, "--mutation", "--format", "json", "-o", "report.json"),),
                              ("report.json",)),
    "mock_baseline": Scenario(MOCK_TARGET, (
        (*_MOCK, "--format", "json", "-o", "baseline.json"),
        (*_MOCK, "--baseline", "baseline.json", "--format", "json", "-o", "report.json"),
    ), ("baseline.json", "report.json")),
    "live_json": Scenario(LIVE_TARGET, (
        (*_LIVE, "--format", "json", "-o", "report.json", "--sarif", "report.sarif"),
    ), ("report.json", "report.sarif"), live=True),
}


def run_scenarios(repo, out, work, names: Optional[list[str]] = None) -> None:
    """在子行程裡以 repo 的 vibeharness 跑各情境，結果寫到 out/<情境>/；work 是兩邊共用的工作目錄。
    Runs each scenario with repo's vibeharness in a child process and writes the results to out/<scenario>/; work is
    the working directory both sides share."""
    repo = os.path.abspath(repo)
    for name in names or list(SCENARIOS):
        _run(repo, name, SCENARIOS[name], Path(out) / name, Path(work) / name)


def _run(repo: str, name: str, scenario: Scenario, out: Path, work: Path) -> None:
    """在全新的 work 裡寫出目標與設定、依序跑每一步，把輸出收進 out（第 N 步的主控台輸出是 stepN.*）。
    Writes the target and the config into a fresh work, runs each step in order and collects the output into out
    (step N's console output is stepN.*)."""
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
    for number, args in enumerate(scenario.steps, 1):
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _CHILD, repo, str(out / IMPORT_MARKER), _GOLDEN_PARENT if scenario.live else "",
             "-t", target, "-c", "vibeharness.yaml", *args],
            cwd=work, env={**os.environ, **_ENV, **(_FAKE_KEYS if scenario.live else {})}, capture_output=True,
            text=True, encoding="utf-8",
        )
        (out / f"step{number}.stdout").write_text(proc.stdout, encoding="utf-8")
        (out / f"step{number}.stderr").write_text(proc.stderr, encoding="utf-8")
        (out / f"step{number}.exit_code").write_text(f"{proc.returncode}\n", encoding="utf-8")
    for rel in scenario.outputs:
        if (work / rel).is_file():
            shutil.copyfile(work / rel, out / rel)
