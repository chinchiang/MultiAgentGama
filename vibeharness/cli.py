#!/usr/bin/env python3
import argparse
import logging
import sys
import os
import traceback

from vibeharness import __version__
from vibeharness.core.harness import VibeHarnessCommander, force_utf8_stdio
from vibeharness.core.llm_gateway import LLMGatewayError, ConfigError, DEFAULT_CONFIG_PATH
from vibeharness.core.sandbox import SandboxUnavailableError
from vibeharness.agents.blackbox.scenario_builder import validate_base_url
from vibeharness.core.baseline import load_baseline
from vibeharness.core.estimate import estimate_lines, estimate_run
from vibeharness.core.i18n import bi

# 保留給 harness／用法問題的結束碼。判定結果碼（0/1/2/3/4）記載於
# README；這些碼絕不能與之衝突，否則 CI 會把當掉的執行誤讀成判定結果。
# Exit codes reserved for harness/usage problems. Verdict codes (0/1/2/3/4) are documented in
# the README; these must never collide with them, or CI would misread a crashed run as a verdict.
USAGE_ERROR_EXIT_CODE = 5
# Ctrl-C：慣例上的 128 + SIGINT，與所有判定結果碼及用法錯誤碼都不同
# Ctrl-C: the conventional 128 + SIGINT, distinct from every verdict and usage code
INTERRUPTED_EXIT_CODE = 130


class _UsageErrorParser(argparse.ArgumentParser):
    """argparse 預設在用法錯誤時以 2 結束，這與 BLOCKED_CRITICAL_RISK 衝突。
    argparse exits 2 on usage errors by default, which collides with BLOCKED_CRITICAL_RISK."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: {bi('錯誤', 'error')}: {message}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)


force_utf8_stdio()


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )


_VERDICT_STATUSES = ("BLOCKED_CRITICAL_RISK", "NEEDS_FIXES", "INCONCLUSIVE", "READY_TO_SHIP")


def verdict_exit_code(overall_status: str) -> int:
    """把品質閘門的判定結果對應到其 CLI 結束碼。

    無法辨識的判定結果字串以 INCONCLUSIVE 碼（3）保守失敗，絕不會以
    READY_TO_SHIP（0）結束 —— 無法辨識的判定結果不得被讀成健康無虞。
    Maps a quality-gate verdict to its CLI exit code.

    Unknown verdict strings fail closed with the INCONCLUSIVE code (3), never with
    READY_TO_SHIP (0) — an unrecognized verdict must not read as a clean bill of health.
    """
    if overall_status == "BLOCKED_CRITICAL_RISK":
        return 2
    if overall_status == "NEEDS_FIXES":
        return 1
    if overall_status == "READY_TO_SHIP":
        return 0
    # INCONCLUSIVE 以及任何無法辨識的狀態
    # INCONCLUSIVE and any unrecognized status
    return 3


def _writable_location(path: str) -> bool:
    """當 `path` 可被建立或覆寫時為 True：其目錄存在且可寫入。
    True when `path` can be created or overwritten: its directory exists and is writable."""
    target = os.path.abspath(path)
    if os.path.isdir(target):
        return False
    if os.path.exists(target):
        return os.access(target, os.W_OK)
    return os.access(os.path.dirname(target) or os.curdir, os.W_OK)


def main():
    parser = _UsageErrorParser(
        description="[VibeHarness-MAS] 針對 vibe coding 的多代理白箱與黑箱測試 harness ／ "
                    "Multi-Agent White-Box & Black-Box Testing Harness for Vibe Coding"
    )
    parser.add_argument(
        "--target", "-t",
        default="examples",
        help="要稽核與測試的目標目錄或檔案（預設 'examples'）／ Directory or file of the target codebase to audit and test (default: 'examples')"
    )
    parser.add_argument(
        "--base-url", "-u",
        default=None,
        help="執行中目標的 base URL，供 live HTTP 黑箱攻擊（例如 'http://localhost:8000'）；未指定時黑箱測試改在行程內匯入目標，"
             "不會探測任何預設位址，攻擊不可能打到無關的本機服務 ／ Base URL of a running instance of the target for live HTTP "
             "black-box attacks (e.g. 'http://localhost:8000'). Without it, black-box tests import the target in-process; "
             "a default is never probed, so attacks cannot hit an unrelated local service"
    )
    parser.add_argument(
        "--output", "-o",
        default="vibe_harness_report.md",
        help="稽核報告的輸出路徑（預設 'vibe_harness_report.md'）／ Output path for the generated Markdown audit report (default: 'vibe_harness_report.md')"
    )
    parser.add_argument(
        "--desc", "-d",
        default=None,
        help="系統的高階描述，供威脅建模參考 ／ High-level description of the system for Threat Modeling guidance"
    )
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG_PATH,
        help="agent 與模型設定 YAML 的路徑（預設為套件內的 config/agents_config.yaml）／ Path to agents and models configuration YAML (default: the bundled config/agents_config.yaml)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["live", "hybrid", "mock"],
        default=None,
        help="覆蓋設定檔的 execution_mode：live（只用真實 API，否則失敗）、hybrid 或 mock ／ Override execution_mode from config: live (real APIs only, fail otherwise), hybrid, or mock"
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="覆蓋 global.max_files：分析的原始碼檔案數（其餘列為 skipped）／ Override global.max_files: number of source files analyzed (the rest are reported as skipped)"
    )
    parser.add_argument(
        "--max-model-calls",
        type=int,
        default=None,
        help="覆蓋 global.max_model_calls：每次執行的真實模型呼叫上限（0 = 不限）／ Override global.max_model_calls: cost guard on live model invocations per run (0 = unlimited)"
    )
    parser.add_argument(
        "--include",
        action="append",
        metavar="GLOB",
        default=None,
        help="只分析路徑（相對於 --target）或檔名符合此 glob 的原始碼檔案；可重複指定，覆蓋設定檔的 global.include ／ "
             "Only analyze source files whose path (relative to --target) or name matches this glob; "
             "repeatable. Overrides global.include from the config"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        metavar="GLOB",
        default=None,
        help="略過路徑或檔名符合此 glob 的原始碼檔案（例如 'tests/*'、'vendor/*'）；可重複指定，覆蓋設定檔的 global.exclude ／ "
             "Skip source files whose path or name matches this glob (e.g. 'tests/*', 'vendor/*'); "
             "repeatable. Overrides global.exclude from the config"
    )
    parser.add_argument(
        "--changed-since",
        metavar="GIT_REF",
        default=None,
        help="只分析 --target 下自此 git ref 以來有變更的檔案（已提交、已暫存、未暫存或未追蹤），例如 PR 檢查用 'origin/main'；"
             "目標必須在 git repo 內 ／ Only analyze files under --target that changed since this git ref (committed, staged, "
             "unstaged or untracked), e.g. 'origin/main' in a PR check; the target must be inside a git repo"
    )
    parser.add_argument(
        "--baseline",
        metavar="REPORT_JSON",
        default=None,
        help="先前的 --format json 報告：其中已有的發現、突破與 HIGH 以上的規則命中仍會列出，但不再決定判定／exit code，"
             "CI 只對新問題反應（崩潰留下的 .partial.json 會被拒絕）／ A previous --format json report: findings, breaches and "
             "HIGH+ rule hits it already contains are listed but no longer decide the verdict / exit code, so CI reacts to "
             "new problems only (a .partial.json from a crashed run is refused)"
    )
    parser.add_argument(
        "--estimate",
        action="store_true",
        help="不呼叫任何模型：只跑第 1 階段（符號擷取），印出每個 agent／模型的預期呼叫數與 prompt／輸出 token"
             "（有設定 models.<alias>.price_per_million_* 時連費用一起）；--format json 時估算寫到 --output。exit 0 ／ "
             "Do not call any model: run Phase 1 (symbol extraction) and print the expected number of model calls "
             "and prompt/output tokens per agent and per model (cost too when models.<alias>.price_per_million_* "
             "is configured); with --format json the estimate is written to --output. Exit 0"
    )
    parser.add_argument(
        "--cache-dir",
        metavar="DIR",
        default=None,
        help="把可用的 live 模型回答快取在 DIR（不存在會建立），之後同模型、同設定、同提示的執行直接取用；命中時不呼叫供應商、"
             "不扣預算。覆蓋 global.cache_dir。目錄裡是原始的模型回答，請比照報告保管 ／ Cache usable live model answers in DIR "
             "(created if missing) and reuse them on later runs with the same model, settings and prompt; a cache hit makes "
             "no provider call and costs no budget. Overrides global.cache_dir. The directory holds raw model answers: "
             "treat it like the reports"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="開啟除錯日誌 ／ Enable debug logging"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["md", "json"],
        default="md",
        help="寫到 --output 的報告格式：Markdown（預設）或機器可讀的 JSON ／ Report format written to --output: Markdown (default) or machine-readable JSON"
    )
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        default=None,
        help="另外把 SARIF 2.1.0 報告寫到 PATH，供 GitHub Code Scanning（以 github/codeql-action 上傳）／ Also write a SARIF 2.1.0 report to PATH for GitHub Code Scanning (upload via github/codeql-action)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"{bi('錯誤', 'Error')}: {bi(f'目標路徑 {target_path!r} 不存在。', f'Target path {target_path!r} does not exist.')}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)

    if args.max_files is not None and args.max_files < 1:
        parser.error(bi("--max-files 至少要是 1", "--max-files must be at least 1"))
    if args.max_model_calls is not None and args.max_model_calls < 0:
        parser.error(bi("--max-model-calls 不可為負數", "--max-model-calls must not be negative"))
    if args.base_url is not None:
        try:
            args.base_url = validate_base_url(args.base_url)
        except ValueError as e:
            parser.error(f"--base-url: {e}")
    # 在為任何模型呼叫付費之前就失敗，而不是等整個流程跑完之後
    # Fail before any model call is paid for, not after the whole pipeline ran
    for flag, path in (("--output", args.output), ("--sarif", args.sarif)):
        if path is not None and not _writable_location(path):
            parser.error(f"{flag}: " + bi(f"無法寫入 '{path}'（目錄不存在或不可寫入）",
                                           f"cannot write to '{path}' (directory missing or not writable)"))
    try:
        commander = VibeHarnessCommander(config_path=args.config, execution_mode=args.mode)
        if args.max_files is not None:
            commander.max_files = args.max_files
        if args.max_model_calls is not None:
            commander.gateway.max_model_calls = args.max_model_calls or None
        if args.include is not None:
            commander.include_patterns = args.include
        if args.exclude is not None:
            commander.exclude_patterns = args.exclude
        if args.changed_since:
            commander.changed_since = args.changed_since
        if args.cache_dir:
            commander.gateway.set_cache_dir(args.cache_dir)
        if args.baseline:
            commander.baseline = load_baseline(args.baseline)
    except (ConfigError, ValueError, SandboxUnavailableError) as e:
        print(f"{bi('錯誤', 'Error')}: {bi('harness 設定問題', 'harness configuration problem')}: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)
    if args.estimate:
        try:
            estimate = estimate_run(commander, target_path)
        except ValueError as e:
            print(f"{bi('錯誤', 'Error')}: {e}", file=sys.stderr)
            sys.exit(USAGE_ERROR_EXIT_CODE)
        if args.format == "json":
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(estimate.model_dump_json(indent=2))
            print(bi(f"估算已寫入 {args.output}", f"Estimate written to {args.output}"))
        else:
            print("\n".join(estimate_lines(estimate)))
        sys.exit(0)
    try:
        summary = commander.run_full_pipeline(
            target_dir=target_path,
            system_description=args.desc,
            base_url=args.base_url,
            output_report_path=args.output,
            output_format=args.format,
            output_sarif_path=args.sarif
        )
    except LLMGatewayError as e:
        print(f"{bi('錯誤', 'Error')}: "
              + bi("在嚴格的 'live' 模式下真實模型呼叫失敗", "live model invocation failed in strict 'live' mode")
              + f": {e}", file=sys.stderr)
        sys.exit(4)
    except ValueError as e:
        # 例如無法解析的 --changed-since ref：執行開始後才發現的用法問題
        # e.g. an unresolvable --changed-since ref: a usage problem found once the run started
        print(f"{bi('錯誤', 'Error')}: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)
    except KeyboardInterrupt:
        print(bi("已中斷；沒有寫出完整報告（--output 旁可能有 .partial.json；進行中的模型呼叫可能需要片刻才會停止）。",
                 "Interrupted; no full report was written (a .partial.json may exist next to --output; "
                 "in-flight model calls may take a moment to stop)."), file=sys.stderr)
        sys.exit(INTERRUPTED_EXIT_CODE)
    except Exception as e:
        # 當掉的執行絕不能落到結束碼 1，CI 會把它讀成 NEEDS_FIXES
        # A crashed run must never fall through to exit code 1, which CI reads as NEEDS_FIXES
        traceback.print_exc(file=sys.stderr)
        print(f"{bi('錯誤', 'Error')}: {bi('harness 意外崩潰', 'harness crashed unexpectedly')}: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)

    # 依品質閘門回傳結束碼
    # Return exit code based on Quality Gate
    if summary.overall_status not in _VERDICT_STATUSES:
        print(f"{bi('錯誤', 'Error')}: "
              + bi(f"未知的整體狀態 '{summary.overall_status}'；以失敗收場（failing closed）。",
                   f"unknown overall status '{summary.overall_status}'; failing closed."), file=sys.stderr)
    sys.exit(verdict_exit_code(summary.overall_status))


if __name__ == "__main__":
    main()
