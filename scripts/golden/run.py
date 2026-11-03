"""golden diff 的進入點：在一個 revision 與工作目錄上跑同一組情境並比對輸出（#128）。
The golden diff entry point: runs one set of scenarios on a revision and on the working tree and compares the
output (#128)."""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    # 以 `python scripts/golden/run.py` 執行時，讓 `golden` 套件可以匯入
    # When run as `python scripts/golden/run.py`, make the `golden` package importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from golden.compare import IMPORT_MARKER, compare  # noqa: E402
from golden.targets import LIVE_TARGET, LIVE_TARGET_CHANGED, MOCK_TARGET  # noqa: E402

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
# 這份工具所在的 repo：工作目錄那一邊，也是 worktree 掛上去的地方
# The repo this tool lives in: the working-tree side, and where the worktree is added
_REPO = str(Path(__file__).resolve().parent.parent.parent)
_TRACEBACK = "Traceback (most recent call last)"


class ScenarioCrashed(RuntimeError):
    """情境的某一步當掉（stderr 有未捕捉例外的 traceback），或沒寫出宣告的輸出檔。
    A scenario step crashed (an uncaught exception's traceback in its stderr) or did not write a declared output."""


@dataclass(frozen=True)
class Scenario:
    """一個情境：目標檔案、依序執行的各步驟 CLI 參數（例如 --baseline 要先有一份報告）、要收集的輸出檔、
    是否以 live 模式經過假 litellm，以及第 2 步起換上的目標檔案（基準線之後目標改了）。
    One scenario: the target files, the CLI arguments of each step in order (--baseline, say, needs a report
    first), the output files to collect, whether it runs in live mode through the fake litellm, and the target files
    swapped in from step 2 on (the target changed after the baseline)."""

    target: dict[str, str]
    steps: tuple[tuple[str, ...], ...]
    outputs: tuple[str, ...]
    live: bool = False
    changed_target: Optional[dict[str, str]] = None


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
    "live_md": Scenario(LIVE_TARGET, ((*_LIVE, "--format", "md", "-o", "report.md"),), ("report.md",), live=True),
    "live_baseline_json": Scenario(LIVE_TARGET, (
        (*_LIVE, "--format", "json", "-o", "baseline.json"),
        (*_LIVE, "--baseline", "baseline.json", "--format", "json", "-o", "report.json"),
    ), ("baseline.json", "report.json"), live=True),
    "live_baseline_md": Scenario(LIVE_TARGET, (
        (*_LIVE, "--format", "json", "-o", "baseline.json"),
        (*_LIVE, "--baseline", "baseline.json", "--format", "md", "-o", "report.md"),
    ), ("baseline.json", "report.md"), live=True),
    "live_baseline_changed": Scenario(LIVE_TARGET, (
        (*_LIVE, "--format", "json", "-o", "baseline.json"),
        (*_LIVE, "--baseline", "baseline.json", "--format", "json", "-o", "report.json", "--sarif", "report.sarif"),
    ), ("baseline.json", "report.json", "report.sarif"), live=True, changed_target=LIVE_TARGET_CHANGED),
}


def run_scenarios(repo, out, work, names: Optional[list[str]] = None) -> None:
    """在子行程裡以 repo 的 vibeharness 跑各情境，結果寫到 out/<情境>/；work 是兩邊共用的工作目錄。
    某一步當掉或沒寫出宣告的輸出檔時丟出 ScenarioCrashed（已寫出的輸出留在 out）。
    Runs each scenario with repo's vibeharness in a child process and writes the results to out/<scenario>/; work is
    the working directory both sides share. Raises ScenarioCrashed when a step crashes or a declared output is not
    written (the output written so far stays in out)."""
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
        if number == 2 and scenario.changed_target:
            for rel, content in scenario.changed_target.items():
                (work / rel).write_text(content, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _CHILD, repo, str(out / IMPORT_MARKER), _GOLDEN_PARENT if scenario.live else "",
             "-t", target, "-c", "vibeharness.yaml", *args],
            cwd=work, env={**os.environ, **_ENV, **(_FAKE_KEYS if scenario.live else {})}, capture_output=True,
            text=True, encoding="utf-8",
        )
        (out / f"step{number}.stdout").write_text(proc.stdout, encoding="utf-8")
        (out / f"step{number}.stderr").write_text(proc.stderr, encoding="utf-8")
        (out / f"step{number}.exit_code").write_text(f"{proc.returncode}\n", encoding="utf-8")
        # 結束碼不能拿來判斷當掉：mock 的 1、2、3 本來就是判定結果。兩邊以同樣方式當掉時輸出相同，卻不代表行為不變
        # The exit code cannot tell a crash: mock's 1, 2 and 3 are Verdicts. Two sides crashing the same way give the
        # same output, which does not mean the behaviour is unchanged
        if _TRACEBACK in proc.stderr:
            raise ScenarioCrashed(f"{name} step {number} crashed; see {out / f'step{number}.stderr'}")
    missing = []
    for rel in scenario.outputs:
        if (work / rel).is_file():
            shutil.copyfile(work / rel, out / rel)
        else:
            missing.append(rel)
    if missing:
        raise ScenarioCrashed(f"{name} wrote no {', '.join(missing)}; see the stepN.stderr files in {out}")


def main(argv: Optional[list[str]] = None, repo: str = _REPO) -> int:
    """把 --against 的 revision 掛成 detached worktree，兩邊跑同一組情境並印出差異摘要。
    結束碼：0 沒有差異、1 有差異、2 無法比對（git 失敗、某一邊的情境步驟丟出 traceback 或沒寫出宣告的輸出檔、參數錯誤，
    或這份工具本身出錯）。worktree 與輸出一律移除，只有 --keep 留下輸出。
    Adds the --against revision as a detached worktree, runs the same scenarios on both sides and prints a summary of
    the differences. Exit code: 0 no differences, 1 differences, 2 could not compare (git failed, a scenario step on
    either side printed a traceback or wrote no declared output, a bad argument, or this tool itself failed). The
    worktree and the outputs are always removed; only --keep keeps the outputs."""
    parser = argparse.ArgumentParser(prog="python scripts/golden/run.py", description=main.__doc__)
    parser.add_argument("--against", required=True, metavar="REV", help="the revision to compare the working tree with")
    parser.add_argument("--keep", metavar="DIR", help="keep both sides' outputs in DIR (base/ and head/)")
    parser.add_argument("scenarios", nargs="*", metavar="SCENARIO",
                        help="the scenarios to run (default: all): " + ", ".join(SCENARIOS))
    args = parser.parse_args(argv)
    unknown = [name for name in args.scenarios if name not in SCENARIOS]
    if unknown:
        parser.error("unknown scenario(s): " + ", ".join(unknown))
    names = args.scenarios or None
    scratch = Path(tempfile.mkdtemp(prefix="vh_golden_"))
    worktree = scratch / "base"
    out = Path(args.keep) if args.keep else scratch / "out"
    # --keep 指到先前用過的目錄時，舊的輸出不能混進這次的比對
    # When --keep points at a directory used before, its old outputs must not mix into this comparison
    for side in ("base", "head"):
        shutil.rmtree(out / side, ignore_errors=True)
    try:
        subprocess.run(["git", "worktree", "add", "--detach", str(worktree), args.against], cwd=repo, check=True,
                       capture_output=True, text=True)
        # 兩邊用同一個工作目錄：報告裡的目標與設定路徑才相同
        # Both sides use the same working directory, so the target and config paths in the reports are the same
        run_scenarios(worktree, out / "base", scratch / "work", names)
        run_scenarios(repo, out / "head", scratch / "work", names)
        summary = compare(out / "base", out / "head")
    except Exception as exc:
        # git 的錯誤訊息在它的 stderr 裡；當掉的情境已經指向它的 stderr 檔；其他例外是這份工具的錯，印出 traceback
        # git's error message is in its stderr; a crashed scenario already points at its stderr file; any other
        # exception is this tool's fault and prints its traceback
        if isinstance(exc, subprocess.CalledProcessError):
            detail = exc.stderr
        elif isinstance(exc, ScenarioCrashed):
            detail = ""
        else:
            detail = traceback.format_exc()
        print(f"golden diff could not compare: {exc}\n{detail}", file=sys.stderr)
        return 2
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo, capture_output=True)
        subprocess.run(["git", "worktree", "prune"], cwd=repo, capture_output=True)
        shutil.rmtree(scratch, ignore_errors=True)
    print(f"{summary.lines} differing line(s), {len(summary.distinct)} distinct")
    for count, line in summary.distinct:
        print(f"{count:>5}  {line}")
    return 1 if summary.lines else 0


if __name__ == "__main__":
    sys.exit(main())
