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

環境變數 ／ Environment: VH_FAIL_ON、VH_OUTPUT、VH_SARIF、GITHUB_OUTPUT、GITHUB_STEP_SUMMARY、RUNNER_TEMP。
"""
import json
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from vibeharness.core.i18n import bi
from vibeharness.core.stdio import force_utf8_stdio
from vibeharness.core.verdict import Verdict

FAIL_ON_VALUES = ("blocked", "needs-fixes", "inconclusive", "never")
USAGE_ERROR_EXIT_CODE = 5
# CLI 旗標（dest）→ 顯示名稱。這些旗標讓 CLI 不稽核就以 0 結束（job 會以 READY_TO_SHIP 通過）、在 workspace 寫檔，
# 或蓋掉 runner 自己的 --summary-json，所以不能放進 extra-args
# CLI flags (dest) -> display name. They make the CLI exit 0 without an audit (the job would pass as READY_TO_SHIP),
# write into the workspace, or override the runner's own --summary-json, so extra-args must not hold them
NON_AUDIT_FLAGS = {
    "estimate": "--estimate", "help": "--help/-h", "version": "--version", "init_config": "--init-config",
    "force": "--force", "summary_json": "--summary-json",
}
# 有專屬 input 的旗標：放在 extra-args 會讓 report／sarif outputs 與 artifact 指向錯誤的檔案
# Flags with a dedicated input: in extra-args they would point the report / sarif outputs and the artifact at the wrong file
ACTION_OWNED_FLAGS = {"output": "--output/-o (input: output)", "format": "--format/-f (input: format)",
                      "sarif": "--sarif (input: sarif)"}


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


def _non_audit_error(flags: List[str]) -> str:
    """extra-args 帶了不執行稽核的旗標時的訊息 ／ The message for non-audit flags in extra-args."""
    return bi(f"extra-args 不得包含不執行稽核的旗標：{', '.join(flags)}",
              f"extra-args must not contain non-audit flags: {', '.join(flags)}")


def given_flags(argv: List[str], flags: Dict[str, str]) -> List[str]:
    """`argv` 中出現的 `flags`（以 CLI 自己的解析器判斷，合併的短旗標也算）；無法解析時回傳空清單，交給 CLI 回報用法錯誤。
    The `flags` present in `argv` (decided by the CLI's own parser, combined short flags included); an unparsable
    argv returns an empty list and is left to the CLI to report as a usage error."""
    from vibeharness.cli import parse_args_for_inspection
    try:
        given = vars(parse_args_for_inspection(argv))
    except ValueError:
        return []
    return [flag for dest, flag in flags.items() if dest in given]


def check_extra_args(extra: List[str]) -> Tuple[Optional[str], List[str]]:
    """檢查 action 的 extra-args：回傳（其中的 --config，沒有則為 None；錯誤訊息清單）。
    以 CLI 自己的解析器判斷，所以 `-vc x`、`-vcx`、`--config=x` 都認得，與 CLI 實際採用的值（最後一個）一致。
    Checks the action's extra-args: returns (its --config, or None; the list of error messages). The CLI's own parser
    decides, so `-vc x`, `-vcx` and `--config=x` are all recognized, matching the value the CLI actually uses (the last)."""
    from vibeharness.cli import parse_args_for_inspection
    try:
        given = vars(parse_args_for_inspection(extra))
    except ValueError as e:
        return None, [bi(f"extra-args 不是有效的 vibeharness 參數：{e}", f"extra-args are not valid vibeharness arguments: {e}")]
    errors = []
    non_audit = [flag for dest, flag in NON_AUDIT_FLAGS.items() if dest in given]
    if non_audit:
        errors.append(_non_audit_error(non_audit))
    owned = [flag for dest, flag in ACTION_OWNED_FLAGS.items() if dest in given]
    if owned:
        errors.append(bi(f"extra-args 不得包含有專屬 input 的旗標，請改用該 input：{', '.join(owned)}",
                         f"extra-args must not contain flags that have a dedicated input; use the input instead: {', '.join(owned)}"))
    config = given.get("config")
    return (config if isinstance(config, str) else None), errors


def config_from_extra_args(extra: List[str]) -> Optional[str]:
    """extra-args 裡 CLI 會採用的 --config；沒有（或無法解析）時為 None ／ The --config the CLI would use from extra-args;
    None when there is none (or they cannot be parsed)."""
    return check_extra_args(extra)[0]


def extra_args_main(args_file: str, config_file: str) -> int:
    """audit step 的 extra-args 檢查：讀取 NUL 分隔的 `args_file`；有錯誤時印出 ::error:: 並回傳 5；
    extra-args 有 --config 時把它寫到 `config_file`（沒有則不建立該檔）。
    The audit step's extra-args check: reads the NUL-separated `args_file`; on errors prints ::error:: and returns 5;
    when extra-args hold a --config it is written to `config_file` (which is not created otherwise)."""
    with open(args_file, encoding="utf-8") as f:
        extra = [a for a in f.read().split("\0") if a]
    try:
        os.remove(config_file)
    except OSError:
        pass
    config, errors = check_extra_args(extra)
    for error in errors:
        print(f"::error::{error}", flush=True)
    if errors:
        return USAGE_ERROR_EXIT_CODE
    if config is not None:
        with open(config_file, "w", encoding="utf-8") as f:
            f.write(config)
    return 0


def _written(path: str) -> str:
    """outputs 用的路徑：檔案存在、而且路徑放得進 GITHUB_OUTPUT 的一行時為 `path`，否則為空字串。
    The path for the outputs: `path` when the file exists and the path fits on one GITHUB_OUTPUT line, else empty."""
    if not path or "\n" in path or "\r" in path:
        return ""
    return path if os.path.isfile(path) else ""


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
    # 雙語的 ::error:: 與摘要在 Windows 的 cp1252 主控台會 UnicodeEncodeError；與 CLI 一樣先把 stdio 改成可寫出它們
    # Bilingual ::error:: lines and the summary raise UnicodeEncodeError on a Windows cp1252 console; make stdio able
    # to write them first, as the CLI does
    force_utf8_stdio()
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
    # 不稽核就結束的旗標（--estimate、--help……）在執行前就拒絕：CLI 會以 0 結束，被讀成 READY_TO_SHIP
    # Flags that end without an audit (--estimate, --help, ...) are refused before running: the CLI would exit 0,
    # which reads as READY_TO_SHIP
    non_audit = given_flags(argv, NON_AUDIT_FLAGS)
    if non_audit:
        print(f"::error::{_non_audit_error(non_audit)}", flush=True)
        _append(os.environ.get("GITHUB_OUTPUT"), f"verdict=ERROR\nexit-code={USAGE_ERROR_EXIT_CODE}\nreport=\nsarif=\n")
        return USAGE_ERROR_EXIT_CODE
    # 放在最後：argparse 取最後一個，extra-args 裡的 --summary-json 不會蓋掉它
    # Last: argparse keeps the last one, so a --summary-json in extra-args cannot override it
    rc = run_cli(argv + ["--summary-json", summary_path])
    sys.stdout.flush()
    sys.stderr.flush()
    summary = _read_summary(summary_path)
    if Verdict.from_exit_code(rc) is not None and not (summary and summary.get("tool") == "vibeharness" and summary.get("exit_code") == rc):
        # 判定碼卻沒有對應的稽核摘要：CLI 沒有執行稽核（例如漏網的非稽核旗標），絕不能讀成判定
        # A verdict code without a matching audit summary: the CLI did not run an audit (e.g. a non-audit flag that
        # slipped through), so it must never read as a verdict
        print("::error::" + bi(
            f"vibeharness 以 {rc} 結束卻沒有寫出對應的稽核摘要，所以沒有判定；extra-args 不得包含不執行稽核的旗標"
            "（--estimate、--help、--version、--init-config）",
            f"vibeharness exited {rc} without writing a matching audit summary, so there is no verdict; extra-args "
            "must not contain non-audit flags (--estimate, --help, --version, --init-config)"), flush=True)
        rc = USAGE_ERROR_EXIT_CODE
    verdict = str(Verdict.from_exit_code(rc) or "ERROR")
    # 報告與 SARIF 只在稽核完成時寫出：沒有判定時 outputs 為空（workspace 裡舊的同名檔案不算）
    # The report and the SARIF are written only when the audit completes: without a verdict the outputs are empty
    # (an old file of the same name in the workspace does not count)
    output, sarif = os.environ.get("VH_OUTPUT", ""), os.environ.get("VH_SARIF", "")
    report_out, sarif_out = (_written(output), _written(sarif)) if verdict != "ERROR" else ("", "")
    _append(os.environ.get("GITHUB_OUTPUT"), f"verdict={verdict}\nexit-code={rc}\nreport={report_out}\nsarif={sarif_out}\n")
    written = (f"Report: `{report_out}`" + (f", SARIF: `{sarif_out}`" if sarif_out else "")) if report_out \
        else bi("沒有寫出報告", "No report was written")
    _append(os.environ.get("GITHUB_STEP_SUMMARY"), f"## VibeHarness-MAS: {verdict} (exit {rc})\n{written}\n")
    if rc >= 4:
        print(f"::error::VibeHarness-MAS could not complete the audit (exit {rc})", flush=True)
        return rc
    for warning in warnings_for(rc, fail_on, summary):
        print(f"::warning::{warning}", flush=True)
    return 1 if fails_job(fail_on, rc) else 0


if __name__ == "__main__":
    sys.exit(main())
