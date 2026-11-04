"""結果歸因（result attribution）：把沙盒的 JUnit 報告變成每個產生的測試的測試狀態，並判定資安突破（GLOSSARY：Breach）。
這裡只有純函式，不碰沙盒；沙盒的執行、分組與重跑在 test_executor.py。
Result attribution: turns the sandbox's JUnit report into each generated test's status and decides Breaches
(GLOSSARY). Pure functions only, no sandbox; running, grouping and rerunning the sandbox live in test_executor.py."""
import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from vibeharness.core.i18n import bi

# 與執行器同一個紀錄器名稱：log 格式會印出名稱，搬家不能改變輸出
# The executor's logger name: the log format prints the name, so the move must not change the output
logger = logging.getLogger("VibeHarness.TestExecutor")

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
