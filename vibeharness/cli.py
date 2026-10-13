#!/usr/bin/env python3
"""`vibeharness` 指令列介面。模組層級只匯入標準函式庫與零相依的 vibeharness 模組：harness 本體
（pydantic、yaml、rich、litellm……）在 main() 的防護內才延遲匯入，所以安裝不完整或缺少相依套件時
以 exit 5 結束並說明原因，絕不會在 main() 之前以 Python 預設的 1（= NEEDS_FIXES）當掉。
The `vibeharness` command-line interface. At module level only the standard library and the
dependency-free vibeharness modules are imported: the harness itself (pydantic, yaml, rich, litellm, ...)
is imported lazily inside main()'s guard, so a broken install or a missing dependency exits 5 with an
explanation instead of crashing before main() with Python's default 1 (= NEEDS_FIXES)."""
import argparse
import importlib
import logging
import sys
import os
import traceback
from typing import TYPE_CHECKING, Any, List, NoReturn, Optional, Tuple

from vibeharness import __version__
from vibeharness.core.i18n import bi
from vibeharness.core.verdict import Verdict

if TYPE_CHECKING:
    # 型別檢查器看得到這些名稱；執行時由 _load_dependencies() 放進模組命名空間
    # Type checkers see these names; at run time _load_dependencies() puts them into the module namespace
    from vibeharness.core.harness import VibeHarnessCommander, force_utf8_stdio
    from vibeharness.core.llm_gateway import LLMGatewayError, ConfigError
    from vibeharness.core.settings import Origin, Overrides, load_settings
    from vibeharness.core.sandbox import SandboxUnavailableError
    from vibeharness.agents.blackbox.scenario_builder import validate_base_url
    from vibeharness.core.baseline import load_baseline
    from vibeharness.core.estimate import estimate_lines, estimate_run

# 延遲匯入的名稱 → （模組, 屬性）；測試以 cli.<名稱> 存取或替換它們，與過去的模組層級匯入相同
# Lazily imported names -> (module, attribute); tests read or replace them as cli.<name>, as with the former module-level imports
_LAZY_IMPORTS = {
    "VibeHarnessCommander": ("vibeharness.core.harness", "VibeHarnessCommander"),
    "force_utf8_stdio": ("vibeharness.core.harness", "force_utf8_stdio"),
    "LLMGatewayError": ("vibeharness.core.llm_gateway", "LLMGatewayError"),
    "ConfigError": ("vibeharness.core.llm_gateway", "ConfigError"),
    "Overrides": ("vibeharness.core.settings", "Overrides"),
    "load_settings": ("vibeharness.core.settings", "load_settings"),
    "SandboxUnavailableError": ("vibeharness.core.sandbox", "SandboxUnavailableError"),
    "validate_base_url": ("vibeharness.agents.blackbox.scenario_builder", "validate_base_url"),
    "load_baseline": ("vibeharness.core.baseline", "load_baseline"),
    "estimate_lines": ("vibeharness.core.estimate", "estimate_lines"),
    "estimate_run": ("vibeharness.core.estimate", "estimate_run"),
}

# 套件內的預設設定（與 llm_gateway.DEFAULT_CONFIG_PATH 相同）；在這裡計算，--init-config 不需要載入 harness 的相依套件
# The bundled default config (the same as llm_gateway.DEFAULT_CONFIG_PATH); computed here so --init-config needs none
# of the harness's dependencies
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "agents_config.yaml")
# 沒有 --config 時，依序在目前目錄尋找這些檔名；都沒有就用套件內的預設設定
# Without --config these file names are looked for in the current directory, in order; if none exists the bundled default is used
DISCOVERED_CONFIG_NAMES = ("vibeharness.yaml", ".vibeharness.yaml")
# --init-config 沒給路徑時寫到這裡 ／ where --init-config writes when no path is given
DEFAULT_INIT_CONFIG_PATH = "vibeharness.yaml"


def __getattr__(name: str) -> Any:
    """模組層級的延遲匯入（PEP 562）：第一次存取 cli.<名稱> 時才匯入並快取在模組命名空間。
    Module-level lazy import (PEP 562): cli.<name> is imported on first access and cached in the module namespace."""
    if name not in _LAZY_IMPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module, attr = _LAZY_IMPORTS[name]
    value = getattr(importlib.import_module(module), attr)
    globals()[name] = value
    return value


def _load_dependencies() -> None:
    """匯入 CLI 需要的每個 harness 名稱；已經存在（例如被測試替換）的名稱保留原值。
    Imports every harness name the CLI needs; a name already present (e.g. replaced by a test) keeps its value."""
    for name in _LAZY_IMPORTS:
        if name not in globals():
            __getattr__(name)


def _print_error(text: str) -> None:
    """印到 stderr；主控台無法編碼某些字元時（例如還沒重新設定的 Windows 字碼頁）以 ? 取代，而不是當掉。
    Prints to stderr; characters the console cannot encode (e.g. a Windows codepage not yet reconfigured)
    are replaced with ? instead of crashing."""
    try:
        print(text, file=sys.stderr)
    except UnicodeEncodeError:
        encoding = getattr(sys.stderr, "encoding", None) or "ascii"
        print(text.encode(encoding, "replace").decode(encoding), file=sys.stderr)

# 保留給 harness／用法問題的結束碼。判定結果碼 0-3 與 live 失敗碼 4 記載於
# README；這些碼絕不能與之衝突，否則 CI 會把當掉的執行誤讀成判定結果。
# Exit codes reserved for harness/usage problems. The verdict codes 0-3 and the live-failure code 4 are documented
# in the README; these must never collide with them, or CI would misread a crashed run as a verdict.
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



def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    )


def verdict_exit_code(overall_status: str) -> int:
    """把品質閘門的判定結果對應到其 CLI 結束碼。

    無法辨識的判定結果字串以 INCONCLUSIVE 碼（3）保守失敗，絕不會以
    READY_TO_SHIP（0）結束 —— 無法辨識的判定結果不得被讀成健康無虞。
    Maps a quality-gate verdict to its CLI exit code.

    Unknown verdict strings fail closed with the INCONCLUSIVE code (3), never with
    READY_TO_SHIP (0) — an unrecognized verdict must not read as a clean bill of health.
    """
    return (Verdict.parse(overall_status) or Verdict.INCONCLUSIVE).exit_code


def _writable_location(path: str) -> bool:
    """當 `path` 可被建立或覆寫時為 True：其目錄存在且可寫入。
    True when `path` can be created or overwritten: its directory exists and is writable."""
    target = os.path.abspath(path)
    if os.path.isdir(target):
        return False
    if os.path.exists(target):
        return os.access(target, os.W_OK)
    return os.access(os.path.dirname(target) or os.curdir, os.W_OK)


def _crash_exit(stage_zh: str, stage_en: str, exc: BaseException) -> NoReturn:
    """意外例外的共同出口：印出 traceback 後以 USAGE_ERROR_EXIT_CODE 結束，絕不落到結束碼 1（CI 會讀成 NEEDS_FIXES）。
    The common exit for an unexpected exception: print the traceback and exit with USAGE_ERROR_EXIT_CODE,
    never falling through to exit code 1, which CI reads as NEEDS_FIXES."""
    traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
    print(f"{bi('錯誤', 'Error')}: {bi(stage_zh, stage_en)}: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(USAGE_ERROR_EXIT_CODE)


def resolve_config_path(explicit: Optional[str], cwd: Optional[str] = None) -> Tuple[str, str]:
    """決定要用的設定檔與它的來源說明。優先序：--config ＞ ./vibeharness.yaml ＞ ./.vibeharness.yaml ＞ 套件內的預設。
    --config 原樣回傳（不存在時由 harness 以 ConfigError 回報，exit 5）。
    Decides which config file is used and describes where it came from. Precedence: --config >
    ./vibeharness.yaml > ./.vibeharness.yaml > the bundled default. --config is returned as given (if it does
    not exist the harness reports a ConfigError, exit 5)."""
    if explicit is not None:
        return explicit, "--config"
    base = cwd or os.getcwd()
    for name in DISCOVERED_CONFIG_NAMES:
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate):
            return candidate, bi(f"在目前目錄找到 {name}", f"found {name} in the current directory")
    return DEFAULT_CONFIG_PATH, bi("套件內的預設設定", "bundled default")


def _init_config(path: str, force: bool) -> int:
    """--init-config：把套件內的預設設定複製到 `path`。成功回傳 0；已存在（沒有 --force）、是符號連結或不是一般檔案、
    或無法寫入時回傳 5。目標絕不經由符號連結寫入：不可信 checkout 裡的（懸空）符號連結不能讓它建立或覆寫別處的檔案。
    --init-config: copies the bundled default config to `path`. Returns 0 on success; 5 when the file exists
    (without --force), is a symlink or not a regular file, or cannot be written. The target is never written through
    a symlink: a (dangling) symlink in an untrusted checkout cannot make it create or overwrite a file elsewhere."""
    target = os.path.abspath(path)
    if os.path.islink(target):
        _print_error(f"{bi('錯誤', 'Error')}: " + bi(f"--init-config：'{path}' 是符號連結，拒絕經由它寫入",
                                                    f"--init-config: '{path}' is a symlink; refusing to write through it"))
        return USAGE_ERROR_EXIT_CODE
    if os.path.isdir(target):
        _print_error(f"{bi('錯誤', 'Error')}: " + bi(f"--init-config：'{path}' 是目錄，請給檔案路徑",
                                                    f"--init-config: '{path}' is a directory; give a file path"))
        return USAGE_ERROR_EXIT_CODE
    if os.path.lexists(target) and not force:
        _print_error(f"{bi('錯誤', 'Error')}: " + bi(f"--init-config：'{path}' 已存在，未覆寫（要覆寫請加 --force）",
                                                    f"--init-config: '{path}' already exists and was not overwritten (add --force to overwrite)"))
        return USAGE_ERROR_EXIT_CODE
    if os.path.lexists(target) and not os.path.isfile(target):
        # FIFO、裝置等：--force 也不寫（開啟 FIFO 會卡住）／ A FIFO, a device, ...: not even with --force (opening a FIFO blocks)
        _print_error(f"{bi('錯誤', 'Error')}: " + bi(f"--init-config：'{path}' 不是一般檔案",
                                                    f"--init-config: '{path}' is not a regular file"))
        return USAGE_ERROR_EXIT_CODE
    # O_NOFOLLOW：檢查之後才換成的符號連結也不會被跟隨（有提供的平台）；沒有 --force 時 O_EXCL 讓已存在的檔案失敗
    # O_NOFOLLOW: a symlink swapped in after the checks is not followed either (where available); without --force,
    # O_EXCL makes an existing file fail
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    flags |= os.O_TRUNC if force else os.O_EXCL
    try:
        with open(DEFAULT_CONFIG_PATH, "rb") as f:
            content = f.read()
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(content)
    except FileExistsError:
        _print_error(f"{bi('錯誤', 'Error')}: " + bi(f"--init-config：'{path}' 已存在，未覆寫（要覆寫請加 --force）",
                                                    f"--init-config: '{path}' already exists and was not overwritten (add --force to overwrite)"))
        return USAGE_ERROR_EXIT_CODE
    except OSError as e:
        _print_error(f"{bi('錯誤', 'Error')}: " + bi(f"--init-config：無法寫入 '{path}'", f"--init-config: cannot write '{path}'") + f": {e}")
        return USAGE_ERROR_EXIT_CODE
    # 只有 DISCOVERED_CONFIG_NAMES 裡的檔名會被自動採用；其他檔名只能以 --config 指定
    # Only the file names in DISCOVERED_CONFIG_NAMES are picked up automatically; any other name needs --config
    if os.path.basename(target) in DISCOVERED_CONFIG_NAMES:
        print(bi(f"已寫入預設設定 {path}；編輯後在同一個目錄執行 vibeharness 就會自動採用（或以 --config 指定）",
                 f"Default config written to {path}; edit it, then run vibeharness in the same directory to pick it up "
                 "automatically (or pass it with --config)"))
    else:
        print(bi(f"已寫入預設設定 {path}；這個檔名不會被自動採用，執行時請以 --config {path} 指定",
                 f"Default config written to {path}; this file name is not picked up automatically, so pass "
                 f"--config {path} when running"))
    return 0


def main():
    """CLI 進入點。任何沒被下方各階段處理的例外都以 5 結束（Ctrl-C 為 130），絕不以 Python 預設的 1 結束：
    1 專屬於 NEEDS_FIXES 判定，當掉的執行絕不能被誤讀成判定結果。
    The CLI entry point. Any exception not handled by the stages below exits 5 (Ctrl-C 130), never with
    Python's default 1: that code belongs to the NEEDS_FIXES verdict, and a crash must never read as a verdict.
    安裝不完整（缺少相依套件、損壞的模組）也在這裡處理：harness 是在防護內才匯入的。
    A broken install (a missing dependency, a corrupt module) is handled here too: the harness is imported inside the guard.
    參數先解析：--help、--version 與 --init-config 不載入任何 harness 相依套件，所以又快、在安裝不完整時也能用；
    真正的稽核才在載入失敗時以 exit 5 結束。
    Arguments are parsed first: --help, --version and --init-config load none of the harness's dependencies, so
    they are fast and work even on a broken install; only a real audit exits 5 when loading fails."""
    # 解析參數、--help／--version 與 --init-config 也在防護內：任何意外錯誤都是 5，不是 Python 預設的 1
    # Parsing, --help / --version and --init-config are inside the guard too: any unexpected error is 5, not Python's default 1
    try:
        _force_utf8_stdio()
        parser = _build_parser()
        args = parser.parse_args()
        if args.init_config is not None:
            sys.exit(_init_config(args.init_config, args.force))
        if args.force:
            parser.error(bi("--force 只能與 --init-config 一起使用", "--force is only valid with --init-config"))
    except KeyboardInterrupt:
        _print_error(bi("已中斷。", "Interrupted."))
        sys.exit(INTERRUPTED_EXIT_CODE)
    except Exception as e:
        _crash_exit("參數解析意外失敗", "argument handling failed unexpectedly", e)
    try:
        _load_dependencies()
    except KeyboardInterrupt:
        _print_error(bi("已中斷。", "Interrupted."))
        sys.exit(INTERRUPTED_EXIT_CODE)
    except Exception as e:
        # 不印 traceback：使用者需要的是重新安裝的指示，不是 harness 內部的堆疊
        # No traceback: the user needs reinstall instructions, not the harness's internal stack
        missing = getattr(e, "name", None)
        zh_missing = f"（缺少的模組：{missing}）" if missing else ""
        en_missing = f" (missing module: {missing})" if missing else ""
        _print_error(f"{bi('錯誤', 'Error')}: " + bi(
            f"VibeHarness 安裝不完整，無法載入 harness（{type(e).__name__}: {e}）{zh_missing}。"
            "請在同一個 Python 環境重新安裝：pip install --force-reinstall vibeharness-mas",
            f"VibeHarness is not installed correctly and the harness could not be loaded ({type(e).__name__}: {e}){en_missing}. "
            "Reinstall it in the same Python environment: pip install --force-reinstall vibeharness-mas",
        ))
        sys.exit(USAGE_ERROR_EXIT_CODE)
    try:
        force_utf8_stdio()
        _main(parser, args)
    except KeyboardInterrupt:
        print(bi("已中斷。", "Interrupted."), file=sys.stderr)
        sys.exit(INTERRUPTED_EXIT_CODE)
    except Exception as e:
        _crash_exit("harness 意外崩潰", "harness crashed unexpectedly", e)


# 能否輸出雙語文字的探測字串（中文、全形斜線、破折號）／ The probe for whether bilingual text can be written
# (Chinese, the full-width slash, a dash)
_STDIO_PROBE = "錯誤／—"


def _force_utf8_stdio() -> None:
    """只用標準函式庫的 stdout／stderr 防護，在解析參數（--help 的中文說明）之前執行，不必先載入 harness：
    Windows 上設為 UTF-8；其他平台上，若串流的編碼寫不出雙語文字（例如 PYTHONIOENCODING=ascii、LANG=C），
    改以 backslashreplace 輸出無法編碼的字元，而不是以 UnicodeEncodeError 當掉。
    A standard-library-only stdout / stderr guard that runs before the arguments are parsed (--help's Chinese text),
    without loading the harness first: on Windows the streams become UTF-8; elsewhere, when a stream's encoding
    cannot write the bilingual text (e.g. PYTHONIOENCODING=ascii, LANG=C), characters it cannot encode are written
    with backslashreplace instead of crashing with a UnicodeEncodeError."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            if sys.platform == "win32":
                reconfigure(encoding="utf-8", errors="replace")
                continue
            if getattr(stream, "errors", "strict") != "strict":
                # 已經不會因無法編碼的字元而當掉（例如 stderr 預設的 backslashreplace）
                # Already cannot crash on an unencodable character (e.g. stderr's default backslashreplace)
                continue
            try:
                _STDIO_PROBE.encode(getattr(stream, "encoding", None) or "ascii")
            except (UnicodeEncodeError, LookupError):
                reconfigure(errors="backslashreplace")
        except (OSError, ValueError):
            pass


class _InspectionParser(argparse.ArgumentParser):
    """parse_args_for_inspection 用的解析器：用法錯誤以 ValueError 拋出，不印訊息也不結束行程。
    The parser behind parse_args_for_inspection: usage errors raise ValueError instead of printing and exiting."""

    def error(self, message):
        raise ValueError(message)


def _build_parser(inspection: bool = False) -> argparse.ArgumentParser:
    """CLI 的參數解析器；只用標準函式庫，建立時不載入任何 harness 相依套件。`inspection` 為 True 時見
    parse_args_for_inspection：--help／--version 只是布林旗標、沒有預設值、用法錯誤拋出 ValueError。
    The CLI's argument parser; standard library only, building it loads none of the harness's dependencies. With
    `inspection` see parse_args_for_inspection: --help / --version are plain booleans, there are no defaults and
    usage errors raise ValueError."""
    # 固定程式名稱：Python 3.14 的 argparse 在 `python -m` 下會改用模組路徑當 prog
    # Fixed program name: Python 3.14's argparse derives prog from the module path under `python -m`
    parser = (_InspectionParser if inspection else _UsageErrorParser)(
        prog="vibeharness",
        # 不接受縮寫的長旗標：`--conf x` 不能繞過 GitHub Action 對 --config 的偵測
        # No abbreviated long flags: `--conf x` cannot slip past the GitHub Action's --config detection
        allow_abbrev=False,
        add_help=not inspection,
        description="[VibeHarness-MAS] 針對 vibe coding 的多代理白箱與黑箱測試 harness ／ "
                    "Multi-Agent White-Box & Black-Box Testing Harness for Vibe Coding"
    )
    if inspection:
        parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument(
        "--target", "-t",
        default=".",
        help="要稽核與測試的目標目錄或檔案（預設為目前目錄 '.'）／ Directory or file of the target codebase to audit and test (default: the current directory '.')"
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
        help="稽核報告的輸出路徑：依 --format 寫 Markdown 或 JSON（--estimate --format json 時寫估算）；"
             "預設 'vibe_harness_report.md' ／ Output path of the audit report, Markdown or JSON per --format (with "
             "--estimate --format json, the estimate); default 'vibe_harness_report.md'"
    )
    parser.add_argument(
        "--desc", "-d",
        default=None,
        help="系統的高階描述，供威脅建模參考 ／ High-level description of the system for Threat Modeling guidance"
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="agent 與模型設定 YAML 的路徑；未指定時依序使用目前目錄的 ./vibeharness.yaml、./.vibeharness.yaml，"
             "都沒有才用套件內的 config/agents_config.yaml ／ Path to agents and models configuration YAML; without it "
             "./vibeharness.yaml, then ./.vibeharness.yaml in the current directory is used, and the bundled "
             "config/agents_config.yaml only when neither exists"
    )
    parser.add_argument(
        "--init-config",
        nargs="?",
        const=DEFAULT_INIT_CONFIG_PATH,
        default=None,
        metavar="PATH",
        help=f"把套件內的預設 agents_config.yaml 複製到 PATH（預設 ./{DEFAULT_INIT_CONFIG_PATH}，之後在該目錄執行會自動採用）後結束（exit 0）；"
             "已存在的檔案不會被覆寫，除非加上 --force ／ Write a copy of the bundled default agents_config.yaml to PATH "
             f"(default ./{DEFAULT_INIT_CONFIG_PATH}, which later runs in that directory pick up automatically) and exit 0; "
             "an existing file is never overwritten unless --force is given"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="與 --init-config 一起使用：覆寫已存在的檔案 ／ With --init-config: overwrite an existing file"
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
        help="覆蓋 global.max_files：分析的原始碼檔案數（≥ 1；其餘列為 skipped）／ Override global.max_files: number of source files analyzed (≥ 1; the rest are reported as skipped)"
    )
    parser.add_argument(
        "--max-model-calls",
        type=int,
        default=None,
        help="覆蓋 global.max_model_calls：每次執行的真實模型呼叫上限（0 = 不限）／ Override global.max_model_calls: cost guard on live model invocations per run (0 = unlimited)"
    )
    parser.add_argument(
        "--mutation",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="開啟或關閉突變測試（--mutation／--no-mutation，優先於設定檔的 global.mutation_testing，預設關閉）："
             "對已通過的白箱測試所涵蓋的函式做確定性的小改動，檢查測試會不會失敗；不呼叫模型，只加證據缺口、不影響 NEEDS_FIXES ／ "
             "Turn mutation testing on or off (--mutation / --no-mutation, wins over global.mutation_testing in the config, off by default): "
             "applies small deterministic changes to the functions the passing white-box tests cover and checks whether the tests fail; "
             "no model is called, it only adds evidence gaps and never causes NEEDS_FIXES"
    )
    parser.add_argument(
        "--mutation-max-mutants",
        type=int,
        metavar="N",
        default=None,
        help="覆蓋 global.mutation_max_mutants：突變測試最多產生幾個變異體（每個一次沙盒批次）／ "
             "Override global.mutation_max_mutants: the most mutants mutation testing creates (one sandbox batch each)"
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
        "--cache-only",
        action="store_true",
        help="每次模型呼叫都只從回應快取取用（需要 --cache-dir 或 global.cache_dir，否則 exit 5），絕不呼叫供應商、不扣預算、不重新詢問；"
             "快取沒有的呼叫列為證據缺口：hybrid 改用模擬（判定不會是 READY_TO_SHIP），live 以 exit 4 中止 ／ "
             "Serve every model call from the response cache only (needs --cache-dir or global.cache_dir, else exit 5): "
             "no provider call, no budget, no re-ask. A call the cache cannot answer is an evidence gap: simulated in "
             "hybrid (the verdict cannot be READY_TO_SHIP), exit 4 in live"
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
        "--summary-json",
        metavar="PATH",
        default=None,
        help="稽核結束後把機器可讀的簡短摘要（判定、exit code、執行模式、各模式的模型呼叫數、是否全部模擬）寫到 PATH，"
             "與 --format 無關；GitHub Action 用它發出警告 ／ After the audit, write a short machine-readable summary "
             "(verdict, exit code, execution mode, model calls per mode, whether every call was simulated) to PATH, "
             "whatever --format is; the GitHub Action uses it for its warnings"
    )
    if inspection:
        parser.add_argument("--version", action="store_true")
        # 沒有預設值：命名空間裡只有實際給出的參數 ／ No defaults: the namespace holds only the arguments actually given
        for action in parser._actions:
            action.default = argparse.SUPPRESS
    else:
        parser.add_argument(
            "--version",
            action="version",
            version=f"%(prog)s {__version__}"
        )
    return parser


def parse_args_for_inspection(argv: List[str]) -> argparse.Namespace:
    """以 CLI 自己的規則解析 `argv`（合併的短旗標 `-vc x`、`-vcx`、`--opt=值`、最後一個為準）但沒有副作用：
    --help／--version 不印出也不結束，命名空間只含實際給出的參數（dest 名稱），用法錯誤拋出 ValueError。
    GitHub Action 用它檢查 extra-args，而不是自己比對字串。
    Parses `argv` by the CLI's own rules (combined short flags `-vc x`, `-vcx`, `--opt=value`, the last one wins) but
    without side effects: --help / --version neither print nor exit, the namespace holds only the arguments actually
    given (by dest name), and usage errors raise ValueError. The GitHub Action checks extra-args with it instead of
    matching strings itself."""
    return _build_parser(inspection=True).parse_args(argv)


def _summary_json(summary: Any, execution_mode: str) -> str:
    """--summary-json 的內容：判定、exit code、執行模式與每種模式的模型呼叫數（"retried" 是同一次呼叫的中間詢問，不計入 total）。
    all_simulated 為 True 表示有模型呼叫、而且每一次都是模擬的（例如 hybrid 模式下沒有任何供應商金鑰）。
    The --summary-json content: verdict, exit code, execution mode and the model calls per mode ("retried" entries
    are intermediate asks of one call and are not counted in total). all_simulated is True when there were model
    calls and every one was simulated (e.g. hybrid mode without any provider key)."""
    import json
    calls = [c for c in summary.agent_calls if c.mode != "retried"]
    counts = {mode: sum(1 for c in calls if c.mode == mode) for mode in ("live", "simulated", "invalid")}
    payload = {
        "tool": "vibeharness",
        "version": __version__,
        "verdict": summary.overall_status,
        "exit_code": verdict_exit_code(summary.overall_status),
        "execution_mode": execution_mode,
        "model_calls": {"total": len(calls), **counts, "cached": sum(1 for c in calls if c.cached)},
        "all_simulated": bool(calls) and counts["simulated"] == len(calls),
        "inconclusive_reasons": list(summary.inconclusive_reasons),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _main(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    setup_logging(args.verbose)
    explicit_config = args.config is not None
    args.config, config_source = resolve_config_path(args.config)
    print(f"{bi('設定檔', 'Config')}: {args.config} ({config_source})", file=sys.stderr)
    origin: "Origin"
    if explicit_config:
        origin = "explicit"
    elif os.path.abspath(args.config) == os.path.abspath(DEFAULT_CONFIG_PATH):
        origin = "bundled"
    else:
        # 自動發現的設定檔可能來自不可信的 checkout：在 harness 執行任何東西之前拒絕安全敏感的鍵
        # A discovered config may come from an untrusted checkout: refuse security-sensitive keys before the
        # harness runs anything
        origin = "discovered"
    # 設定檔只載入、驗證一次，連同 CLI 旗標的覆寫值；任何設定問題都在檢查目標與旗標之前回報
    # The config is loaded and validated once, together with the CLI flags' overrides; every config problem is
    # reported before the target and the flags are checked
    try:
        settings = load_settings(args.config, origin=origin, overrides=Overrides(
            execution_mode=args.mode, max_files=args.max_files, max_model_calls=args.max_model_calls,
            mutation_testing=args.mutation, mutation_max_mutants=args.mutation_max_mutants,
            include=None if args.include is None else tuple(args.include),
            exclude=None if args.exclude is None else tuple(args.exclude),
            changed_since=args.changed_since or None, cache_dir=args.cache_dir or None, cache_only=bool(args.cache_only),
        ))
    except ConfigError as e:
        print(f"{bi('錯誤', 'Error')}: {bi('harness 設定問題', 'harness configuration problem')}: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)
    except Exception as e:
        # 與下方當掉的執行一樣：載入設定時的意外錯誤絕不能落到結束碼 1（NEEDS_FIXES）
        # Like a crashed run below: an unexpected error while loading the config must never fall through to exit
        # code 1 (NEEDS_FIXES)
        _crash_exit("harness 無法啟動", "harness failed to start", e)
    for warning in settings.warnings:
        print(f"{bi('警告', 'Warning')}: {warning}", file=sys.stderr)

    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"{bi('錯誤', 'Error')}: {bi(f'目標路徑 {target_path!r} 不存在。', f'Target path {target_path!r} does not exist.')}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)

    if args.max_files is not None and args.max_files < 1:
        parser.error(bi("--max-files 至少要是 1", "--max-files must be at least 1"))
    if args.mutation_max_mutants is not None and args.mutation_max_mutants < 1:
        parser.error(bi("--mutation-max-mutants 至少要是 1", "--mutation-max-mutants must be at least 1"))
    if args.max_model_calls is not None and args.max_model_calls < 0:
        parser.error(bi("--max-model-calls 不可為負數", "--max-model-calls must not be negative"))
    if args.base_url is not None:
        try:
            args.base_url = validate_base_url(args.base_url)
        except ValueError as e:
            parser.error(f"--base-url: {e}")
    # 在為任何模型呼叫付費之前就失敗，而不是等整個流程跑完之後
    # Fail before any model call is paid for, not after the whole pipeline ran
    for flag, path in (("--output", args.output), ("--sarif", args.sarif), ("--summary-json", args.summary_json)):
        if path is not None and not _writable_location(path):
            parser.error(f"{flag}: " + bi(f"無法寫入 '{path}'（目錄不存在或不可寫入）",
                                           f"cannot write to '{path}' (directory missing or not writable)"))
    try:
        commander = VibeHarnessCommander(settings=settings)
        if settings.gateway.cache_only and settings.gateway.execution_mode == "mock":
            # mock 模式根本不讀快取：--cache-only 不會有任何作用，說出來而不是默默接受
            # Mock mode never reads the cache: --cache-only has no effect, so say so instead of silently accepting it
            print(f"{bi('警告', 'Warning')}: " + bi(
                "--cache-only 在 mock 模式下沒有作用：每次呼叫都是模擬的，不會讀取回應快取（要重播快取請用 --mode hybrid 或 live）",
                "--cache-only has no effect in mock mode: every call is simulated and the response cache is never "
                "read (use --mode hybrid or live to replay the cache)"), file=sys.stderr)
        if args.baseline:
            commander.baseline = load_baseline(args.baseline)
    except (ConfigError, ValueError, SandboxUnavailableError) as e:
        print(f"{bi('錯誤', 'Error')}: {bi('harness 設定問題', 'harness configuration problem')}: {e}", file=sys.stderr)
        sys.exit(USAGE_ERROR_EXIT_CODE)
    except Exception as e:
        # 與下方當掉的執行一樣：建構或設定 harness 時的意外錯誤絕不能落到結束碼 1（NEEDS_FIXES）
        # Like a crashed run below: an unexpected error while building or configuring the harness must
        # never fall through to exit code 1 (NEEDS_FIXES)
        _crash_exit("harness 無法啟動", "harness failed to start", e)
    if args.estimate:
        try:
            estimate = estimate_run(commander, target_path)
            if args.format == "json":
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(estimate.model_dump_json(indent=2))
                print(bi(f"估算已寫入 {args.output}", f"Estimate written to {args.output}"))
            else:
                print("\n".join(estimate_lines(estimate)))
        except (ValueError, OSError) as e:
            # 例如無法解析的 --changed-since ref，或寫不進 --output
            # e.g. an unresolvable --changed-since ref, or --output cannot be written
            print(f"{bi('錯誤', 'Error')}: {e}", file=sys.stderr)
            sys.exit(USAGE_ERROR_EXIT_CODE)
        except Exception as e:
            _crash_exit("估算意外失敗", "the estimate failed unexpectedly", e)
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
        _crash_exit("harness 意外崩潰", "harness crashed unexpectedly", e)

    if args.summary_json:
        try:
            with open(args.summary_json, "w", encoding="utf-8") as f:
                f.write(_summary_json(summary, commander.gateway.execution_mode))
        except OSError as e:
            # 報告已經寫好：摘要寫不出來只是警告，不改變判定的 exit code
            # The report is already written: a summary that cannot be written is only a warning and keeps the verdict's exit code
            print(f"{bi('警告', 'Warning')}: " + bi(f"無法寫入 --summary-json '{args.summary_json}'",
                                                   f"cannot write --summary-json '{args.summary_json}'") + f": {e}", file=sys.stderr)
    # 依品質閘門回傳結束碼
    # Return exit code based on Quality Gate
    if Verdict.parse(summary.overall_status) is None:
        print(f"{bi('錯誤', 'Error')}: "
              + bi(f"未知的整體狀態 '{summary.overall_status}'；以失敗收場（failing closed）。",
                   f"unknown overall status '{summary.overall_status}'; failing closed."), file=sys.stderr)
    sys.exit(verdict_exit_code(summary.overall_status))


if __name__ == "__main__":
    main()
