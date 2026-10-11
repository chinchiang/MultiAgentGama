"""GitHub Action（action.yml）的稽核啟動器：audit step 的 bash 以 `exec python -I -m vibeharness.action_runner ...`
把自己換成這個行程，它在同一個行程內執行 CLI，再寫出 step outputs、step summary 與警告，並依 fail-on 決定 exit code。
The audit launcher of the GitHub Action (action.yml): the audit step's bash replaces itself with this process via
`exec python -I -m vibeharness.action_runner ...`, which runs the CLI in-process, then writes the step outputs, the
step summary and the warnings, and picks the exit code from fail-on.

為什麼要在同一個行程內：step 的環境裡有供應商金鑰。過去 bash 是 harness 的父行程，而 bash 的
/proc/<pid>/environ 對同一使用者的產生測試（local_subprocess 沙盒）是可讀的；exec 之後，初始環境裡帶著金鑰的
行程只剩 harness 本身，而它在啟動本機沙盒子行程前會變成不可 dump（sandbox.harden_harness_process）。
Why in-process: the step's environment holds the provider keys. bash used to be the harness's parent, and bash's
/proc/<pid>/environ is readable by a same-uid generated test (local_subprocess sandbox); after exec, the only
process whose initial environment holds the keys is the harness itself, which turns non-dumpable before it
launches local sandbox children (sandbox.harden_harness_process).

環境變數 ／ Environment: VH_FAIL_ON、VH_OUTPUT、VH_SARIF、VH_MODE、GITHUB_OUTPUT、GITHUB_STEP_SUMMARY、RUNNER_TEMP。
"""
import json
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional

from vibeharness.core.i18n import bi

FAIL_ON_VALUES = ("blocked", "needs-fixes", "inconclusive", "never")
# exit code → 判定 ／ exit code → verdict
VERDICTS = {0: "READY_TO_SHIP", 1: "NEEDS_FIXES", 2: "BLOCKED_CRITICAL_RISK", 3: "INCONCLUSIVE"}
USAGE_ERROR_EXIT_CODE = 5


def fails_job(fail_on: str, rc: int) -> bool:
    """判定碼 `rc`（0-3）在 `fail_on` 之下是否讓 job 失敗 ／ Whether verdict code `rc` (0-3) fails the job under `fail_on`."""
    if fail_on == "blocked":
        return rc == 2
    if fail_on == "needs-fixes":
        return rc in (1, 2)
    if fail_on == "inconclusive":
        return rc != 0
    return False


def run_cli(argv: List[str]) -> int:
    """在同一個行程內執行 vibeharness CLI，回傳它的 exit code（main() 一律以 sys.exit 結束）。
    Runs the vibeharness CLI in-process and returns its exit code (main() always ends with sys.exit)."""
    from vibeharness import cli
    saved = sys.argv
    sys.argv = ["vibeharness", *argv]
    try:
        cli.main()
    except SystemExit as e:
        code = e.code
        if code is None:
            return 0
        return code if isinstance(code, int) else USAGE_ERROR_EXIT_CODE
    finally:
        sys.argv = saved
    # main() 沒有以 sys.exit 結束：不可能發生，以 harness 錯誤保守收場
    # main() returned without sys.exit: cannot happen, so fail closed as a harness error
    return USAGE_ERROR_EXIT_CODE


def _append(path: Optional[str], text: str) -> None:
    """附加到 GITHUB_OUTPUT／GITHUB_STEP_SUMMARY；沒有設定（例如在本機執行）時略過。
    Appends to GITHUB_OUTPUT / GITHUB_STEP_SUMMARY; skipped when unset (e.g. when run locally)."""
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)


def _read_summary(path: str) -> Optional[Dict[str, Any]]:
    """讀取 --summary-json；harness 失敗而沒寫出時為 None ／ Reads --summary-json; None when a failed harness wrote none."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def warnings_for(rc: int, fail_on: str, summary: Optional[Dict[str, Any]]) -> List[str]:
    """要以 ::warning:: 發出的訊息：判定為 INCONCLUSIVE 而 fail-on 不會因此讓 job 失敗，以及 hybrid／live 模式下
    每一次模型呼叫都是模擬的（例如來自 fork 的 PR 拿不到 secrets）。
    The messages emitted as ::warning::: an INCONCLUSIVE verdict that fail-on does not fail the job on, and every
    model call being simulated in hybrid / live mode (e.g. a pull request from a fork, which gets no secrets)."""
    warnings: List[str] = []
    if summary and summary.get("all_simulated") and summary.get("execution_mode") in ("hybrid", "live"):
        warnings.append(bi(
            "每一次模型呼叫都是模擬的：沒有任何供應商金鑰送進 action（例如來自 fork 的 PR 拿不到 secrets）；"
            "這次的判定不是模型證據，請在有金鑰的情況下重跑",
            "every model call was simulated: no provider key reached the action (e.g. a pull request from a fork "
            "gets no secrets), so this verdict is not model evidence; re-run it with the keys available",
        ))
    if rc == 3 and not fails_job(fail_on, rc):
        warnings.append(bi(
            f"判定為 INCONCLUSIVE（有證據缺口），但 fail-on: {fail_on} 不會因此讓 job 失敗；請查看報告的證據缺口",
            f"the verdict is INCONCLUSIVE (there are evidence gaps), but fail-on: {fail_on} does not fail the job on it; "
            "check the evidence gaps in the report",
        ))
    return warnings


def main(argv: Optional[List[str]] = None) -> int:
    """執行稽核、寫出 outputs 與 summary，回傳 step 的 exit code ／ Runs the audit, writes the outputs and summary,
    and returns the step's exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    fail_on = os.environ.get("VH_FAIL_ON", "needs-fixes")
    if fail_on not in FAIL_ON_VALUES:
        print(f"::error::unknown fail-on value '{fail_on}' (use {', '.join(FAIL_ON_VALUES)})", flush=True)
        return USAGE_ERROR_EXIT_CODE
    summary_path = os.path.join(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(), "vibeharness-summary.json")
    try:
        os.remove(summary_path)
    except OSError:
        pass
    # 放在最後：argparse 取最後一個，extra-args 裡的 --summary-json 不會蓋掉它
    # Last: argparse keeps the last one, so a --summary-json in extra-args cannot override it
    rc = run_cli(argv + ["--summary-json", summary_path])
    sys.stdout.flush()
    sys.stderr.flush()
    verdict = VERDICTS.get(rc, "ERROR")
    _append(os.environ.get("GITHUB_OUTPUT"), f"verdict={verdict}\nexit-code={rc}\n")
    output, sarif = os.environ.get("VH_OUTPUT", ""), os.environ.get("VH_SARIF", "")
    _append(os.environ.get("GITHUB_STEP_SUMMARY"),
            f"## VibeHarness-MAS: {verdict} (exit {rc})\n"
            f"Report: `{output}`" + (f", SARIF: `{sarif}`" if sarif else "") + "\n")
    if rc >= 4:
        print(f"::error::VibeHarness-MAS could not complete the audit (exit {rc})", flush=True)
        return rc
    for warning in warnings_for(rc, fail_on, _read_summary(summary_path)):
        print(f"::warning::{warning}", flush=True)
    return 1 if fails_job(fail_on, rc) else 0


if __name__ == "__main__":
    sys.exit(main())
