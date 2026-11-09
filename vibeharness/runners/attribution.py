"""結果歸因（result attribution）：把沙盒的 JUnit 報告變成每個產生的測試的測試狀態，並判定資安突破（GLOSSARY：Breach）。
這裡只有純函式，不碰沙盒；沙盒的執行、分組與重跑在 test_executor.py。
Result attribution: turns the sandbox's JUnit report into each generated test's status and decides Breaches
(GLOSSARY). Pure functions only, no sandbox; running, grouping and rerunning the sandbox live in test_executor.py."""
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from vibeharness.core.i18n import bi
from vibeharness.core.models import GeneratedTest, TestExecutionResult, TestStatus

# 與執行器同一個紀錄器名稱：log 格式會印出名稱，搬家不能改變輸出
# The executor's logger name: the log format prints the name, so the move must not change the output
logger = logging.getLogger("VibeHarness.TestExecutor")

# 使用者可見的原因字串（中文 ／ English）；測試以 == / startswith 比對的匯出為常數
# User-visible reason strings (Chinese / English); the ones tests compare with == / startswith are exported
REASON_NOT_RUN_CORRECTLY = bi("測試無法正常執行", "Test could not run correctly")
REASON_TARGET_BROKEN = bi("目標程式碼已損壞，此測試從未實際執行到它", "Target code is broken and was never exercised by this test")
REASON_UNKNOWN_FAILURE = bi("不明的執行失敗", "Unknown execution failure")
REASON_SKIPPED = bi("已略過", "Skipped")
POC_HEADER_PY = "# === " + bi("重現 PoC", "Reproduction PoC") + " ==="
POC_HEADER_JS = "// === " + bi("重現 PoC", "Reproduction PoC") + " ==="
# 代表產生的測試／harness 設定壞掉、而非目標缺陷的例外
# Exceptions that indicate a broken generated test / harness setup rather than a defect in the target
HARNESS_ERROR_EXCEPTIONS = (
    "ImportError", "ModuleNotFoundError", "NameError", "SyntaxError", "IndentationError"
)

# 關於呼叫參數數量／關鍵字的 TypeError，代表產生的測試用了錯誤的簽章呼叫目標——
# 但只有當它是在測試模組本身拋出時（最內層的回溯
# 框架）才算。同樣的訊息若在目標內部拋出，就是目標真正的缺陷。
# A TypeError about call arity/keywords means the generated test called the target with the wrong
# signature — but only when it was raised in the test module itself (the innermost traceback
# frame). The same message raised inside the target is a genuine defect in the target.
_SIGNATURE_TYPEERROR_RE = re.compile(
    r"^TypeError: .*(missing \d+ required (?:positional|keyword-only) argument|"
    r"takes \d+ positional arguments? but \d+ (?:was|were) given|takes no arguments|"
    r"got an unexpected keyword argument|got multiple values for argument|"
    r"takes from \d+ to \d+ positional arguments)"
)
_RAISED_IN_TEST_MODULE_RE = re.compile(r"test_vh_\d+\.py:\d+: TypeError\s*$")
# pytest 長回溯的最後一行指出最內層框架與例外名稱（'path.py:LINE: NameError'）
# The last line of pytest's long traceback names the innermost frame and the exception ('path.py:LINE: NameError')
_INNERMOST_LOCATION_RE = re.compile(r"^(\S.*?\.py):\d+: ([\w.]+)\s*$", re.MULTILINE)
# 代表目標（或其相依套件）根本載入不了的環境類例外：在目標框架裡拋出的匯入失敗（延遲匯入沙盒中沒有的套件），
# 或指向某個真實原始檔的語法錯誤（測試裡匯入的目標子模組壞掉）。邊界從未被測到，所以是 REASON_TARGET_BROKEN
# 的 ERROR，絕不是缺陷（FAILED）；NameError 不在此列——目標裡拋出的 NameError 是真正的缺陷
# Environment-type exceptions meaning the target (or a dependency) could not even load: an import failure raised in
# a target frame (a lazy import of a package missing from the sandbox), or a syntax error pointing at a real source
# file (a broken target submodule imported inside the test). The boundary was never exercised, so this is an ERROR
# with REASON_TARGET_BROKEN, never a defect (FAILED); NameError is deliberately absent — a NameError raised inside
# the target is a genuine defect
_TARGET_IMPORT_EXCEPTIONS = ("ImportError", "ModuleNotFoundError")
_TARGET_SYNTAX_EXCEPTIONS = ("SyntaxError", "IndentationError", "TabError")
# SyntaxError 回溯中指出壞掉原始檔的那一行（'E     File "/srv/app/sub.py", line 3'）；'<unknown>'／'<string>'
# 代表目標在執行期解析輸入（ast.parse、compile），那是目標行為，不是載入失敗
# The line of a SyntaxError traceback naming the broken source file ('E     File "/srv/app/sub.py", line 3');
# '<unknown>' / '<string>' means the target parsed input at run time (ast.parse, compile), which is target behaviour,
# not a load failure
_SYNTAX_ERROR_FILE_RE = re.compile(r'^E?\s*File "([^"]+)", line \d+', re.MULTILINE)
# pytest 長回溯中各框架之間的分隔線（'_ _ _ ... _'）；最後一段就是最內層框架
# The separator between frames in pytest's long traceback ('_ _ _ ... _'); the last section is the innermost frame
_TRACEBACK_ENTRY_SEP_RE = re.compile(r"^(?:_ )+_\s*$", re.MULTILINE)
# 最內層框架是匯入機制本身（importlib.import_module、importlib.reload、__import__ 走到的凍結模組）
# The innermost frame is the import machinery itself (the frozen modules importlib.import_module, importlib.reload and
# __import__ end up in)
_IMPORT_MACHINERY_FRAME_RE = re.compile(r"^<frozen importlib\._bootstrap(?:_external)?>:\d+: [\w.]+\s*$", re.MULTILINE)
# 最內層框架裡出錯的那一行（pytest 用 '>' 標示）是匯入陳述式或匯入呼叫
# The failing line of the innermost frame (marked '>' by pytest) is an import statement or an import call
_IMPORT_SOURCE_LINE_RE = re.compile(
    r"^>\s+(?:(?:import|from)\s+[\w.]|.*\b(?:__import__|import_module|reload)\s*\()", re.MULTILINE
)
# 在產生的測試模組（最內層框架）拋出時，代表測試呼叫了目標上不存在的函式／屬性（測試端的錯誤）；
# 在目標內部拋出的同樣訊息仍是目標的缺陷
# Raised in the generated test module (innermost frame) this means the test called a function / attribute the target
# does not have (a test-side mistake); the same message raised inside the target stays a defect in the target
_MISSING_ATTRIBUTE_RE = re.compile(r"^AttributeError: (?:module|type object) '[^']+' has no attribute '[^']+'")
# 沙盒的單檔大小上限（RLIMIT_FSIZE，見 sandbox.SANDBOX_MAX_FILE_BYTES）讓寫入失敗時的 OSError：是沙盒的限制，
# 不是目標的缺陷
# The OSError a write gets once it hits the sandbox's per-file size cap (RLIMIT_FSIZE, see
# sandbox.SANDBOX_MAX_FILE_BYTES): a sandbox limit, not a defect in the target
_FILE_TOO_LARGE_RE = re.compile(r"^OSError: \[Errno 27\]")

# --- JavaScript／TypeScript（node:test）分類 ---------------------------------------
# --- JavaScript / TypeScript (node:test) classification ---------------------------------------
# 產生的模組本身的載入／解析失敗，絕不是目標的缺陷
# Load / resolution failures of the generated module itself, never a defect in the target
_JS_HARNESS_MARKERS = ("ERR_MODULE_NOT_FOUND", "Cannot find module", "Cannot find package", "ERR_UNKNOWN_FILE_EXTENSION",
                       "ERR_UNSUPPORTED_DIR_IMPORT", "ERR_REQUIRE_ESM", "ERR_PACKAGE_PATH_NOT_EXPORTED",
                       "ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX", "SyntaxError")
# 沙盒的單檔大小上限讓 Node 寫入失敗（'Error: EFBIG: file too large, write'）：與 Python 的 [Errno 27] 一樣是沙盒
# 的限制。只有 libuv 的系統錯誤才算——它在內文帶有 `errno: -27` 與 `code: 'EFBIG'`；目標自己 new Error('EFBIG: ...')
# 拋出的訊息不帶 errno，維持為目標的行為
# The sandbox's per-file size cap failing a Node write ('Error: EFBIG: file too large, write'): a sandbox limit like
# Python's [Errno 27]. Only libuv's system error counts — its body carries `errno: -27` and `code: 'EFBIG'`; a message
# the target throws itself with new Error('EFBIG: ...') has no errno and stays target behaviour
_JS_FILE_TOO_LARGE_RE = re.compile(r"^Error: EFBIG: file too large")
_JS_EFBIG_ERRNO_RE = re.compile(r"^\s*errno: -27,?\s*$", re.MULTILINE)
_JS_EFBIG_CODE_RE = re.compile(r"^\s*code: 'EFBIG',?\s*$", re.MULTILINE)
# 從產生的模組（最內層 V8 框架）拋出時屬於測試端的錯誤
# Test-side mistakes when raised from the generated module (innermost V8 frame)
_JS_TEST_SIDE_ERRORS = ("ReferenceError", "TypeError")
# V8 堆疊框架最內層在前："    at fn (file:///x/y.mjs:3:9)" 或 "    at file:///x/y.mjs:3:9"
# V8 stack frames are innermost-first: "    at fn (file:///x/y.mjs:3:9)" or "    at file:///x/y.mjs:3:9"
_V8_FRAME_RE = re.compile(r"^\s+at (?:.*?\()?((?:file:///|/|[A-Za-z]:[\\/])[^\s)]+?):\d+:\d+\)?\s*$", re.MULTILINE)
_JS_CAUSE_RE = re.compile(r"^\s*cause:\s*([\w$]*Error\b.*?)\s*\{?\s*$", re.MULTILINE)  # 加了引號的 cause（'test failed'）什麼都沒說 ／ a quoted cause ('test failed') says nothing
_JS_ERROR_LINE_RE = re.compile(r"^\s*\[?(\w*Error(?: \[\w+\])?: .+)$", re.MULTILINE)
# Node 22 會在錯誤名稱後加上建構式標籤（'TypeError [Error]: null'）；只剝掉這種類別名標籤，
# 有意義的錯誤碼（'Error [ERR_MODULE_NOT_FOUND]: ...'）保留，harness 標記要靠它比對
# Node 22 tags the error name with its constructor ('TypeError [Error]: null'); only such class-name tags are stripped,
# meaningful codes ('Error [ERR_MODULE_NOT_FOUND]: ...') are kept, the harness markers match on them
_JS_CLASS_TAG_RE = re.compile(r"^([\w$]*Error) \[[\w$]*Error\]:")
_V8_STACK_LINE_RE = re.compile(r"^\s+at ", re.MULTILINE)
# 一個 JUnit testcase：name、time、outcome、message、details、stdout、stderr
# One JUnit testcase: name, time, outcome, message, details, stdout, stderr
JunitCase = Dict[str, Any]

# 檔案層級 case 的名字就是測試檔路徑：對 basename 做完整比對，名稱只是「結尾像檔名」的 test() 不算
# A file-level case is named after the test file path: full match on the basename, a test() whose name merely ends
# like a file name does not count
_JS_FILE_CASE_RE = re.compile(r"test_vh_\d+\.(?:mjs|cjs|js)")


def parse_junit(junit_xml: Optional[str], language: str = "python", module: Optional[str] = None,
                runner_stdout: Optional[str] = None) -> Optional[Dict[str, List[JunitCase]]]:
    """把 JUnit 的 testcase 依產生的模組名稱（test_vh_NNN）分組。

    pytest 把模組放在 `classname`（收集錯誤時放在 `name`）。Node 的 junit 報告器
    兩者都不填（classname 是字面上的 "test"；只有從未執行到 test() 的檔案
    會以名稱出現），所以 Node 的報告是每個模組各產一份，由 `module` 把每個案例
    歸給它；外層的 `<testsuite name>` 祖先則作為後備來搜尋。從未執行到 test() 的
    Node 檔案會被回報成單一個通過的檔案層級案例：這個
    偽案例會被丟棄（空檔案不能算通過），而失敗的那種
    （載入錯誤）則保留為該模組的失敗。
    給了 `runner_stdout`（Node 那次執行的 stdout）時，它會補在載入失敗的檔案層級案例的 details 前面：
    junit 內文只說 "test failed"，實際的錯誤（ERR_MODULE_NOT_FOUND、載入時的 ReferenceError）在 stdout 上，
    分類時需要先看到它。
    什麼都沒產生（或什麼都沒比對到）時回傳 {}，報告存在但無法解析時回傳
    None——呼叫端不得把後者回報成「沒有收集到測試」，那會把壞掉的沙盒報告
    歸咎於產生的程式碼。
    Groups JUnit testcases by generated module name (test_vh_NNN).

    pytest puts the module in `classname` (collection errors: in `name`). Node's junit reporter
    names neither (classname is the literal "test"; only a file that never reached a test()
    appears by name), so a Node report is produced per module and `module` assigns every case
    to it; the enclosing `<testsuite name>` ancestors are searched as a fallback. A Node file
    that never reached a test() is reported as a single passing file-level case: that
    pseudo-case is dropped (an empty file must not count as a pass), while a failing one (a
    load error) is kept as the module's failure.
    With `runner_stdout` (the stdout of that Node run), it is prepended to the details of a file-level case that
    failed to load: the junit body only says "test failed", while the actual error (ERR_MODULE_NOT_FOUND, a
    ReferenceError at load) is on stdout, which the classification needs to see first.
    Returns {} when nothing was produced (or nothing matched), and None when a report
    existed but could not be parsed — the caller must not report that as "no test
    collected", which blames the generated code for a broken sandbox report.
    """
    grouped: Dict[str, List[JunitCase]] = {}
    if module is not None:
        grouped[module] = []  # 模組有執行；沒有任何案例就是「沒有收集到測試」，絕不是通過 ／ the module ran; without any case it is "no test collected", never a pass
    if not junit_xml:
        return grouped
    try:
        root = ET.fromstring(junit_xml)
    except ET.ParseError as e:
        logger.error(bi(f"無法解析 JUnit XML：{e}", f"Unable to parse JUnit XML: {e}"))
        return None

    parents = {child: parent for parent in root.iter() for child in parent}
    for tc in root.iter("testcase"):
        match = re.search(r"test_vh_\d+", tc.get("classname") or "") or re.search(r"test_vh_\d+", tc.get("name") or "")
        node = tc
        while match is None and node in parents:
            node = parents[node]
            if node.tag == "testsuite":
                match = re.search(r"test_vh_\d+", node.get("name") or "")
        group = match.group(0) if match else module
        if not group:
            continue
        is_file_case = language != "python" and bool(_JS_FILE_CASE_RE.fullmatch(os.path.basename(tc.get("name") or "")))
        outcome, message, details = "passed", None, None
        out, err = "", ""
        for child in tc:
            if child.tag in ("failure", "error", "skipped") and outcome == "passed":
                outcome = child.tag
                message = child.get("message") or ""
                details = child.text or ""
            elif child.tag == "system-out":
                out += child.text or ""
            elif child.tag == "system-err":
                err += child.text or ""
        if is_file_case and outcome == "failure" and runner_stdout is not None:
            details = f"{runner_stdout[:6000]}\n{details or ''}"
        if is_file_case and outcome == "passed":
            grouped.setdefault(group, [])  # 檔案有執行，但裡面沒有 test()：沒有可計算的東西 ／ the file ran, but no test() inside it: nothing to count
            continue
        try:
            case_time = float(tc.get("time") or 0.0)
        except (TypeError, ValueError):
            case_time = 0.0  # 這份 XML 來自執行不受信任程式碼的容器；絕不能因它崩潰 ／ the XML came from a container running untrusted code; never crash on it
        grouped.setdefault(group, []).append({
            "name": tc.get("name"),
            "time": case_time,
            "outcome": outcome,
            "message": message,
            "details": details,
            "stdout": out,
            "stderr": err,
        })
    return grouped


def attribute(test: GeneratedTest, test_id: str, cases: List[JunitCase]) -> TestExecutionResult:
    """一個產生的測試模組的 JUnit 案例 -> 它的結果：目標的缺陷是 FAILED（只有黑箱測試的斷言失敗才是資安突破），
    怪測試或目標載入不了是 ERROR，全部略過是 SKIPPED，其餘是 PASSED（部分略過時附上說明）。
    One generated test module's JUnit cases -> its result: a defect in the target is FAILED (only a black-box
    assertion failure is a Breach), a test-side problem or a target that cannot load is ERROR, all skipped is
    SKIPPED, otherwise PASSED (with a note when some cases were skipped)."""
    duration = round(sum(c["time"] for c in cases), 3)
    # 呈現這個測試自己擷取到的輸出，而不是整個批次的
    # Report this test's own captured output rather than the whole batch's
    stdout = "".join(c["stdout"] for c in cases)
    stderr = "".join(c["stderr"] for c in cases)
    is_js = test.language != "python"
    errors = [c for c in cases if c["outcome"] == "error"]
    failures = [c for c in cases if c["outcome"] == "failure"]
    harness_failures = [c for c in failures if (_js_is_harness_failure(c) if is_js else _is_harness_failure(c))]
    defect_failures = [c for c in failures if c not in harness_failures]

    if defect_failures:
        case = defect_failures[0]
        is_assertion = _js_is_assertion(case) if is_js else _is_assertion(case["message"])
        reason = (_js_exception_summary(case) if is_js else "") or _first_line(case["message"]) \
            or bi(f"於 {test.title} 期間斷言失敗", f"Assertion failed during {test.title}")
        return _result(
            test, test_id, TestStatus.FAILED,
            failure_reason=reason,
            traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr,
            is_exploit=test.test_type == "blackbox_security" and is_assertion,
            poc=_generate_poc(test, case["name"])
        )
    if errors or harness_failures:
        case = (errors or harness_failures)[0]
        if is_js:
            summary = _js_exception_summary(case)
            if _js_raised_in_target_code(case) and any(m in summary for m in _JS_HARNESS_MARKERS):
                return _result(
                    test, test_id, TestStatus.ERROR,
                    failure_reason=(f"{REASON_TARGET_BROKEN}: "
                                    f"{summary} (raised outside the generated test module)"),
                    traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
                )
            return _result(
                test, test_id, TestStatus.ERROR,
                failure_reason=f"{REASON_NOT_RUN_CORRECTLY}: {summary or REASON_UNKNOWN_FAILURE}",
                traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
            )
        summary = _exception_summary(case)
        collection_broken = case["outcome"] == "error" and _raised_in_target_code(case) \
            and summary.startswith(HARNESS_ERROR_EXCEPTIONS)
        if collection_broken or (case["outcome"] == "failure" and _target_failed_to_load(case)):
            # 匯入／語法失敗發生在目標（或其相依套件）裡，
            # 而不是產生的測試裡：邊界從未被測到，
            # 報告不可因目標壞掉而怪罪測試。收集階段與測試執行中（延遲匯入）同樣處理。
            # The import/syntax failure happened in the target (or its dependencies),
            # not in the generated test: the boundary was never exercised and the
            # report must not blame the test for the target being broken. Collection time and
            # test run time (a lazy import) are treated alike.
            return _result(
                test, test_id, TestStatus.ERROR,
                failure_reason=(f"{REASON_TARGET_BROKEN}: "
                                f"{summary} (raised outside the generated test module)"),
                traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
            )
        reason = (summary or _first_line(case["message"])
                  or _first_line(case["details"]) or REASON_UNKNOWN_FAILURE)
        return _result(
            test, test_id, TestStatus.ERROR,
            failure_reason=f"{REASON_NOT_RUN_CORRECTLY}: {reason}",
            traceback=case["details"], duration=duration, stdout=stdout, stderr=stderr
        )
    if all(c["outcome"] == "skipped" for c in cases):
        return _result(
            test, test_id, TestStatus.SKIPPED,
            failure_reason=_first_line(cases[0]["message"]) or REASON_SKIPPED,
            duration=duration, stdout=stdout, stderr=stderr
        )
    passed = _result(test, test_id, TestStatus.PASSED, duration=duration, stdout=stdout, stderr=stderr)
    skipped_count = sum(1 for c in cases if c["outcome"] == "skipped")
    if skipped_count:
        # 部分被跳過的模組，其證據比完全通過弱；要明確說出來，
        # 而不是把未驗證的邊界算成已防禦。
        # A partially skipped module is weaker evidence than a clean pass; say so explicitly
        # instead of counting unverified boundaries as defended.
        passed.failure_reason = bi(
            f"此模組內 {len(cases)} 個案例中有 {skipped_count} 個被略過；只有實際執行的案例能驗證邊界",
            f"{skipped_count} of {len(cases)} case(s) were skipped inside this module; "
            "only the executed cases verify the boundary"
        )
    return passed


def not_run(test: GeneratedTest, test_id: str, reason: str, *, stdout: str = "", stderr: str = "") -> TestExecutionResult:
    """執行器沒有可判定的報告時（逾時、沒有報告、預算用盡、無法執行）的結果：帶著原因的 ERROR，絕不是資安突破。
    The result when the executor has no report to judge (a timeout, no report, an exhausted budget, not
    executable): an ERROR carrying the reason, never a Breach."""
    return _result(test, test_id, TestStatus.ERROR, failure_reason=reason, stdout=stdout, stderr=stderr)


def mutant_outcome(cases: Optional[Dict[str, List[JunitCase]]]) -> str:
    """一個變異體批次解析後的報告 -> "killed"（有目標缺陷造成的失敗）、"survived"（全部通過），或 "invalid"
    （沒有報告、解析不了、沒有 case，或怪測試的失敗／錯誤：無法下結論）。逾時算 killed 看的是結束碼，由執行器判斷。
    One mutant batch's parsed report -> "killed" (a failure caused by a defect in the target), "survived" (all
    passed) or "invalid" (no report, an unparsable report, no case, or a test-side failure / error: nothing can be
    concluded). A timeout counting as killed depends on the exit code and is decided by the executor."""
    if not cases:
        return "invalid"
    flat = [case for module_cases in cases.values() for case in module_cases]
    if any(c["outcome"] == "failure" and not _is_harness_failure(c) for c in flat):
        return "killed"
    if any(c["outcome"] in ("error", "failure") for c in flat) or not flat:
        return "invalid"
    return "survived"


def _is_harness_failure(case: dict) -> bool:
    """由產生的測試本身、沙盒限制或目標根本載入不了（而非目標行為）所造成的失敗。
    A failure caused by the generated test itself, a sandbox limit, or the target failing to load at all,
    rather than by the target's behaviour."""
    message = case["message"] or ""
    if _target_failed_to_load(case):
        return True  # 由 attribute 回報成 REASON_TARGET_BROKEN ／ reported as REASON_TARGET_BROKEN by attribute
    if message.startswith(HARNESS_ERROR_EXCEPTIONS):
        # 與 TypeError 分支同樣看最內層框架：在產生的測試模組拋出才是 harness 錯誤；在目標內部拋出的
        # NameError 是目標真正的缺陷（FAILED，非資安利用）。沒有回溯時維持保守（歸在測試端）
        # Same innermost-frame check as the TypeError branch: only raised in the generated test module is it a
        # harness error; a NameError raised inside the target is a genuine defect (FAILED, not an exploit).
        # Without a traceback the answer stays conservative (test-side)
        return _innermost_location(case) is None or _raised_in_test_module(case)
    if _FILE_TOO_LARGE_RE.match(message):
        return True
    if _MISSING_ATTRIBUTE_RE.match(message):
        # 測試呼叫了目標上不存在的函式（mod.nonexist()）：只有在測試模組拋出時才是測試端的錯誤
        # The test called a function the target does not have (mod.nonexist()): test-side only when raised in
        # the test module
        return _raised_in_test_module(case)
    return bool(_SIGNATURE_TYPEERROR_RE.match(message)
                and _RAISED_IN_TEST_MODULE_RE.search(case["details"] or ""))


def _innermost_location(case: dict) -> Optional[Tuple[str, str]]:
    """pytest 長回溯的最內層框架 (路徑, 例外名稱)；沒有可用的回溯時為 None。
    The innermost frame (path, exception name) of pytest's long traceback; None without a usable traceback."""
    locations = _INNERMOST_LOCATION_RE.findall(case["details"] or "")
    return locations[-1] if locations else None


def _raised_in_test_module(case: dict) -> bool:
    """最內層框架是產生的測試模組（test_vh_NNN.py）時為 True；沒有回溯時為 False。
    True when the innermost frame is the generated test module (test_vh_NNN.py); False without a traceback."""
    location = _innermost_location(case)
    return location is not None and os.path.basename(location[0]).startswith("test_vh_")


def _target_failed_to_load(case: dict) -> bool:
    """測試執行中（非收集階段）目標根本載入不了時為 True，與收集錯誤路徑一樣歸為 REASON_TARGET_BROKEN 的 ERROR：
    - 在目標框架裡拋出的 ImportError／ModuleNotFoundError（延遲匯入沙盒中沒有的套件）。這是刻意的設計：目標函式
      內部的選用匯入（`import yaml` 放在函式裡）在沙盒缺少該套件時，邊界從未被測到，所以是 ERROR 而不是缺陷；
      代價是目標真的匯入了不存在的模組名稱時也只會得到 ERROR。
    - 匯入時發生的 SyntaxError 家族：錯誤指向一個真實的 .py 原始檔（非產生的測試模組、非 '<string>' 之類），
      而且最內層框架顯示它來自匯入——出錯的那一行是 import 陳述式／__import__／import_module 呼叫，或最內層框架
      是 `<frozen importlib._bootstrap>`（測試或目標匯入了壞掉的子模組）。目標自己用 compile()／ast.parse()／exec
      解析檔案（即使帶著真實的檔名）而拋出的 SyntaxError 不算：那是目標沒有包住錯誤的缺陷（FAILED）。
    True when the target could not even load during a test (not at collection), classified like the
    collection-error path as an ERROR with REASON_TARGET_BROKEN:
    - an ImportError / ModuleNotFoundError raised in a target frame (a lazy import of a package missing from the
      sandbox). This is by design: an optional import inside a target function (`import yaml` in a function body)
      whose package the sandbox lacks means the boundary was never exercised, so it is an ERROR, not a defect; the
      price is that a target importing a module name that truly does not exist also only gets an ERROR.
    - a SyntaxError-family error raised by an import: it points at a real .py source file (neither the generated
      test module nor '<string>' and the like) and the innermost frame shows it came from importing — the failing
      line is an import statement / __import__ / import_module call, or the innermost frame is
      `<frozen importlib._bootstrap>` (the test or the target imported a broken submodule). A SyntaxError the
      target raises itself by parsing a file with compile() / ast.parse() / exec (even under a real file name)
      does not count: not wrapping it is a defect in the target (FAILED)."""
    details = case["details"] or ""
    location = _innermost_location(case)
    exception = location[1].rsplit(".", 1)[-1] if location else None
    if location is not None and exception in _TARGET_IMPORT_EXCEPTIONS:
        return not os.path.basename(location[0]).startswith("test_vh_")
    innermost = _TRACEBACK_ENTRY_SEP_RE.split(details)[-1]
    machinery = _IMPORT_MACHINERY_FRAME_RE.search(innermost)
    if exception is None and machinery:
        exception = machinery.group(0).rsplit(":", 1)[-1].strip().rsplit(".", 1)[-1]
    if exception not in _TARGET_SYNTAX_EXCEPTIONS:
        return False
    files = _SYNTAX_ERROR_FILE_RE.findall(details)
    if not files or files[-1].startswith("<") or not files[-1].endswith((".py", ".pyw")) \
            or os.path.basename(files[-1]).startswith("test_vh_"):
        return False
    return bool(machinery or _IMPORT_SOURCE_LINE_RE.search(innermost))


def _exception_summary(case: dict) -> str:
    """pytest 回溯中拋出的例外（'E   ModuleNotFoundError: ...'）。

    JUnit 對收集錯誤的訊息只有 'collection failure'，完全看不出
    實際壞在哪裡；回溯中的 E 開頭那一行才會點出例外。
    The raised exception ('E   ModuleNotFoundError: ...') from pytest's traceback.

    JUnit's message for collection errors is just 'collection failure', which says
    nothing about what actually broke; the traceback's E-line names the exception.
    """
    details = case["details"] or ""
    e_lines = re.findall(r"^E\s+(.+)$", details, re.MULTILINE)
    return (e_lines[-1].strip() if e_lines else (case["message"] or "").strip())[:300]


def _raised_in_target_code(case: dict) -> bool:
    """最內層的回溯框架不是產生的測試模組時為 True（pytest 的
    junit 回溯使用簡短的 'path.py:LINE: in ...' 格式）：是目標或它的
    相依鏈拋出的。沒有可用的回溯時，答案維持保守
    （歸在測試端），以免有任何東西被過度歸咎於目標。
    True when the innermost traceback frame is not the generated test module (pytest
    junit tracebacks use the short 'path.py:LINE: in ...' format): the target, or its
    dependency chain, is what raised. Without a usable traceback the answer stays
    conservative (test-side framing) so nothing is over-attributed to the target."""
    details = case["details"] or ""
    frames = re.findall(r'File "([^"]+?\.py)"', details) \
        or re.findall(r"^(.+\.py):\d+: in ", details, re.MULTILINE)
    if not frames:
        return False
    return not os.path.basename(frames[-1]).startswith("test_vh_")


def _js_is_harness_failure(case: dict) -> bool:
    """由產生的模組造成的 node:test 失敗（無法解析的匯入、語法）、沙盒的單檔大小上限（EFBIG 系統錯誤），或由
    該模組本身拋出的測試端 ReferenceError／TypeError。
    A node:test failure caused by the generated module (unresolvable import, syntax), by the sandbox's per-file
    size cap (an EFBIG system error), or by a test-side ReferenceError/TypeError raised from the module itself."""
    # 只看 Node 回報的例外本身（cause 行或第一個 XError 行）：斷言失敗的內文可能提到目標拋出的
    # SyntaxError（例如 assert.doesNotThrow 的 actual），整段比對會把真正的突破降級成 harness 錯誤
    # Only the exception Node reports (the cause line or the first XError line): an assertion failure's body may
    # mention a SyntaxError the target threw (e.g. assert.doesNotThrow's actual), and matching the whole body
    # would downgrade a genuine breach to a harness error
    if _JS_FILE_CASE_RE.fullmatch(os.path.basename(case.get("name") or "")):
        return True  # 檔案層級的失敗 = 模組沒載入，從未執行任何 test() ／ a file-level failure = the module never loaded, no test() ran
    summary = _js_exception_summary(case)
    if any(marker in summary for marker in _JS_HARNESS_MARKERS):
        return True
    details = case.get("details") or ""
    if _JS_FILE_TOO_LARGE_RE.match(summary) and _JS_EFBIG_ERRNO_RE.search(details) \
            and _JS_EFBIG_CODE_RE.search(details):
        return True  # 沙盒的單檔大小上限，不是目標的缺陷 ／ the sandbox's per-file size cap, not a defect in the target
    return summary.startswith(_JS_TEST_SIDE_ERRORS) and not _js_raised_in_target_code(case) \
        and bool(_V8_FRAME_RE.search(case.get("details") or ""))


def _js_raised_in_target_code(case: dict) -> bool:
    """V8 堆疊把最內層框架列在最前面；沒有框架時，什麼都不會歸咎於目標。
    V8 stacks list the innermost frame first; without frames nothing is attributed to the target."""
    frames = _V8_FRAME_RE.findall(case.get("details") or "")
    if not frames:
        return False
    return not os.path.basename(frames[0]).startswith("test_vh_")


def _js_exception_summary(case: dict) -> str:
    """`_js_raw_exception_summary` 去掉 Node 的類別名標籤後的結果（'TypeError [Error]: x' -> 'TypeError: x'）。
    `_js_raw_exception_summary` without Node's class-name tag ('TypeError [Error]: x' -> 'TypeError: x')."""
    return _JS_CLASS_TAG_RE.sub(r"\1:", _js_raw_exception_summary(case))


def _js_raw_exception_summary(case: dict) -> str:
    """Node 回報的錯誤：junit 內文的 `cause:` 行，否則是第一個 `XError: ...` 行，
    否則是 junit 訊息（對斷言而言就是單純的期望文字）。
    The error Node reports: the `cause:` line of the junit body, else the first `XError: ...` line,
    else the junit message (which for assertions is the bare expectation text)."""
    details = case.get("details") or ""
    cause = _JS_CAUSE_RE.search(details)
    if cause:
        return cause.group(1).strip().rstrip("{").strip()[:300]
    # 檔案層級失敗的 junit 內文只有「Error: test failed」佔位行，真正的錯誤（例如 ERR_MODULE_NOT_FOUND）
    # 在 runner 輸出裡；跳過佔位行，取第一個有內容的 XError 行
    # A file-level failure's junit body only has the "Error: test failed" placeholder; the real error (e.g.
    # ERR_MODULE_NOT_FOUND) is in the runner output, so skip the placeholder and take the first real XError line
    candidates = [(m.group(1).strip(), m.end()) for m in _JS_ERROR_LINE_RE.finditer(details)
                  if not m.group(1).strip().startswith("Error: test failed")]
    # 補進來的 runner 輸出可能含目標自己印的「Error: …」行：優先取帶 harness 標記的那行，再來是後面緊接著
    # 堆疊框架（真的被拋出）的那行，最後才是第一行
    # The folded runner output may contain "Error: ..." lines the target printed itself: prefer the line carrying
    # a harness marker, then one followed by a stack frame (actually thrown), and only then the first one
    for text, _ in candidates:
        if any(marker in text for marker in _JS_HARNESS_MARKERS):
            return text[:300]
    for text, end in candidates:
        if _V8_STACK_LINE_RE.match(details[end:].lstrip("\n")[:200]):
            return text[:300]
    if candidates:
        return candidates[0][0][:300]
    return (case.get("message") or "").strip()[:300]


def _js_is_assertion(case: dict) -> bool:
    """node:assert 的失敗會在內文帶有 ERR_ASSERTION／AssertionError（junit 訊息是
    單純的期望文字）；expect() 風格的函式庫則會寫出該呼叫的名稱。
    node:assert failures carry ERR_ASSERTION / AssertionError in the body (the junit message is the
    bare expectation text); expect()-style libraries name the call."""
    text = f"{case.get('message') or ''}\n{case.get('details') or ''}"
    return "ERR_ASSERTION" in text or "AssertionError" in text or "Error: expect(" in text


def _is_assertion(message: Optional[str]) -> bool:
    """pytest 會回報明確的 AssertionError、改寫過的裸 assert（'assert x == y'），
    以及透過 pytest.fail() 的明確測試失敗（'Failed: ...'）。
    pytest reports explicit AssertionErrors, rewritten bare asserts ('assert x == y'),
    and explicit test failures via pytest.fail() ('Failed: ...')."""
    msg = (message or "").strip()
    return (
        msg.startswith("AssertionError")
        or msg.startswith("assert ")
        or msg.startswith("assert\n")
        or msg == "assert"
        or msg.startswith("Failed:")
        or msg.startswith("Failed ")
        or msg == "Failed"
    )


def _first_line(text: Optional[str]) -> str:
    return (text or "").strip().splitlines()[0][:300] if (text or "").strip() else ""


def _result(
    test: GeneratedTest,
    test_id: str,
    status: TestStatus,
    failure_reason: Optional[str] = None,
    traceback: Optional[str] = None,
    duration: float = 0.0,
    stdout: str = "",
    stderr: str = "",
    is_exploit: bool = False,
    poc: Optional[str] = None
) -> TestExecutionResult:
    return TestExecutionResult(
        test_id=test_id,
        test_type=test.test_type,
        status=status,
        duration_seconds=duration,
        stdout=stdout[:500],
        stderr=stderr[:500],
        traceback=traceback[:2000] if traceback else None,
        failure_reason=failure_reason,
        is_security_exploit_confirmed=is_exploit,
        reproduction_poc=poc,
        source_ref=test.source_ref,
        language=test.language,
    )


def _generate_poc(test: GeneratedTest, fn_name: str) -> str:
    """為已確認的失敗建構重現腳本。
    Constructs a reproduction script for a confirmed failure."""
    is_js = test.language != "python"
    c = "//" if is_js else "#"
    header = POC_HEADER_JS if is_js else POC_HEADER_PY
    return (
        f"{header}\n"
        f"{c} {bi('目標', 'Target')}: {_header_field(test.target_component)}\n"
        f"{c} {bi('失敗情境', 'Failure Context')}: {_header_field(test.title)}\n"
        f"{c} {bi('測試函式', 'Test Function')}: {fn_name}\n"
        f"{c} {bi('測試程式碼', 'Test Code')}:\n{test.code}\n"
    )


def _header_field(text: Optional[str]) -> str:
    """插入產生的原始碼中 '#' 註解的中繼資料。

    CR／LF（及其他行分隔符）會逃出註解並注入 check_test_code()
    從未驗證過的程式碼，所以每個行分隔符都換成空格。
    Metadata interpolated into a '#' comment in generated source.

    CR/LF (and other line separators) would escape the comment and inject code that
    check_test_code() never validated, so every line separator becomes a space.
    """
    return " ".join(str(text or "").splitlines()) or "-"
