"""JS／TS 行涵蓋率：Node 測試執行器的涵蓋率旗標（依版本偵測）、解析它寫出的 lcov 報告、只留下目標自己的原始檔
（排除產生的測試模組 test_vh_*、node_modules 與目標目錄以外的檔案），並把各模組的結果合併成「任一模組執行到就算涵蓋」
的聯集。
JS/TS line coverage: the Node test runner's coverage flags (detected by version), parsing the lcov report it writes,
keeping only the target's own source files (dropping the generated test modules test_vh_*, node_modules and anything
outside the target directory), and merging the modules into a union where a line counts as covered when any module
executed it.

語意：只計入至少被一個模組載入過的檔案。V8 的涵蓋率只知道載入過的腳本，Node 也不會回報從未載入的檔案
（--test-coverage-include 只是篩選，不會把未載入的檔案補成 0%）；要把未載入的檔案算成 0% 就得自己猜哪些行可執行，
所以刻意不做。這與 pytest-cov 不同：`--cov=<目錄>` 會把該目錄（與套件子目錄）裡從未匯入的 .py 檔算成 0%，
因此 JS/TS 的數字是「已載入檔案」的涵蓋率，通常比同樣情況下的 Python 數字高。
Semantics: only files loaded by at least one module count. V8 coverage only knows scripts that were loaded and Node
never reports a file that was not (--test-coverage-include only filters, it does not add unloaded files at 0%);
counting unloaded files as 0% would mean guessing their executable lines, which is deliberately not done. This differs
from pytest-cov: `--cov=<dir>` counts never-imported .py files in that directory (and its package sub-directories) as
0%, so the JS/TS figure is the coverage of the loaded files and usually reads higher than the Python figure would in
the same situation."""
import ntpath
import os
import posixpath
import re
import sys
import urllib.parse
from typing import Dict, Iterable, List, Optional, Tuple

from vibeharness.core.i18n import bi

# lcov 報告在執行目錄裡的檔名 ／ The lcov report's file name inside the run directory
LCOV_REPORT_NAME = "lcov.info"
# 收集涵蓋率的版本門檻。lcov 報告器本身較早就有（v21.2.0，20.x 為 v20.10.0）；真正的門檻是一起傳入的
# --disable-warning（見 _DISABLE_LISTENER_WARNING），它從 v21.3.0（20.x 為 v20.11.0）才有。更舊的 Node 看到不認得的
# 選項會讓整次執行失敗，所以低於門檻時完全不收集涵蓋率（測試照常執行）
# The version gate for collecting coverage. The lcov reporter itself arrived earlier (v21.2.0, v20.10.0 on 20.x); the
# real gate is the --disable-warning passed along with it (see _DISABLE_LISTENER_WARNING), which exists from v21.3.0
# (v20.11.0 on 20.x). An older Node fails the whole run on an unknown option, so below the threshold no coverage is
# collected at all (the tests still run)
MIN_NODE_VERSION_LCOV_20 = (20, 11, 0)
MIN_NODE_VERSION_LCOV = (21, 3, 0)
# --test-coverage-include／--test-coverage-exclude 從 v22.5.0 起才有；更舊的版本只靠自己篩選 lcov
# --test-coverage-include / --test-coverage-exclude exist from v22.5.0; older versions rely on filtering the lcov only
MIN_NODE_VERSION_COVERAGE_GLOBS = (22, 5, 0)
# 第三個報告器（lcov）會讓 Node 的 TestsStream 超過 10 個監聽器並在 stderr 印出警告；那行警告會蓋掉
# 「沙盒沒有產生報告」原因裡真正的錯誤，所以只停用這一種警告
# A third reporter (lcov) takes Node's TestsStream past 10 listeners and prints a warning on stderr; that line would
# push the real error out of the "sandbox produced no report" reason, so only this one warning type is disabled
_DISABLE_LISTENER_WARNING = "--disable-warning=MaxListenersExceededWarning"
# 產生的測試模組（test_vh_NNN.mjs 等）；它們的程式碼不是目標的程式碼
# The generated test modules (test_vh_NNN.mjs and so on); their code is not the target's code
_TEST_MODULE_RE = re.compile(r"test_vh_\d+\.[A-Za-z]+")
# glob 的特殊字元：根目錄含有它們時不加 include 模式（照字面比對不到），只靠排除模式與自己的篩選
# Glob metacharacters: a root containing one gets no include pattern (it would not match literally), only the exclude
# patterns and our own filtering
_GLOB_META_RE = re.compile(r"[*?\[\]{}()!+@\\]")
_WINDOWS_DRIVE_URL_RE = re.compile(r"^/[A-Za-z]:")


# Node >= 22.5 處理 --test-coverage-include／--test-coverage-exclude 時會在 stderr 印出這個沒有警告碼的
# ExperimentalWarning（以及第一次警告後的 --trace-warnings 提示行）。--disable-warning 只接受警告碼或整個警告類型，
# 停用整個 ExperimentalWarning 會連 --experimental-strip-types 等其他實驗功能的警告一起藏起來，所以改為只從擷取到的
# stderr 拿掉這一則（見 strip_coverage_glob_warning）
# Node >= 22.5 prints this code-less ExperimentalWarning on stderr when handling --test-coverage-include /
# --test-coverage-exclude (plus the --trace-warnings hint after the first warning). --disable-warning only accepts a
# warning code or a whole warning type, and disabling all of ExperimentalWarning would also hide the warnings of other
# experimental features such as --experimental-strip-types, so only this one message is removed from the captured
# stderr instead (see strip_coverage_glob_warning)
_GLOB_WARNING_RE = re.compile(
    r"^\(node:\d+\) ExperimentalWarning: glob is an experimental feature and might change at any time(?:\r?\n|\Z)"
    r"(?:\(Use `node --trace-warnings \.\.\.` to show where the warning was created\)(?:\r?\n|\Z))?",
    re.MULTILINE,
)


def strip_coverage_glob_warning(stderr: str) -> str:
    """從 Node 的 stderr 拿掉涵蓋率 glob 篩選引起的 ExperimentalWarning（與緊接著的 --trace-warnings 提示行），
    其他內容原封不動；讓「沙盒沒有產生報告」之類的原因顯示真正的錯誤。
    Removes the ExperimentalWarning the coverage glob filters cause (and the --trace-warnings hint right after it)
    from Node's stderr, leaving everything else untouched, so reasons such as "sandbox produced no report" show the
    real error."""
    if not stderr or "ExperimentalWarning: glob" not in stderr:
        return stderr
    return _GLOB_WARNING_RE.sub("", stderr)


def _version_text(version: Tuple[int, int, int]) -> str:
    return ".".join(map(str, version))


def node_coverage_problem(version: Optional[Tuple[int, int, int]]) -> Optional[str]:
    """這個 Node 版本收集不到 JS/TS 涵蓋率的原因；可以收集時為 None。
    Why this Node version cannot collect JS/TS coverage; None when it can."""
    if version is None:
        return bi("無法判斷 Node 版本，因此不收集 JS/TS 行涵蓋率（需要 Node >= 20.11 或 >= 21.3）",
                  "the Node version could not be determined, so JS/TS line coverage is not collected "
                  "(needs Node >= 20.11 or >= 21.3)")
    if version >= MIN_NODE_VERSION_LCOV or MIN_NODE_VERSION_LCOV_20 <= version < (21, 0, 0):
        return None
    found = _version_text(version)
    return bi(f"Node v{found} 不支援收集涵蓋率所需的 --disable-warning（需要 Node >= 20.11 或 >= 21.3），"
              "因此不收集 JS/TS 行涵蓋率",
              f"Node v{found} lacks the --disable-warning option coverage collection needs (needs Node >= 20.11 or "
              ">= 21.3), so JS/TS line coverage is not collected")


def node_coverage_args(version: Tuple[int, int, int], include_root: Optional[str]) -> Tuple[List[str], List[str]]:
    """(放在 --test 之前的 Node 選項, 涵蓋率篩選旗標)。篩選旗標只在 Node >= 22.5 時給：include 限制在目標目錄
    （絕對路徑且不含 glob 特殊字元；Windows 路徑先改成正斜線，見 _glob_include_root），
    exclude 去掉目標根目錄以下的 node_modules（沒有 include 時是任何 node_modules）與產生的測試模組。明確的 include
    會取代 Node 預設「路徑含 /node_modules/ 就排除」的規則，所以本身位於某個 node_modules 底下的目標
    （/x/node_modules/pkg 或 C:/x/node_modules/pkg）也收得到涵蓋率。不論有沒有這些旗標，解析 lcov 時都會再篩一次。
    (Node options placed before --test, coverage filter flags). The filter flags are only given on Node >= 22.5: the
    include limits the report to the target directory (an absolute path without glob metacharacters; a Windows path
    is rewritten to forward slashes, see _glob_include_root), the excludes drop
    node_modules below the target root (any node_modules without an include) and the generated test modules. An
    explicit include replaces Node's default rule of dropping every path containing /node_modules/, so a target that
    itself lives under a node_modules (/x/node_modules/pkg or C:/x/node_modules/pkg) still gets coverage. The lcov
    is filtered again when parsed, with or without them."""
    options = ["--experimental-test-coverage", _DISABLE_LISTENER_WARNING]
    filters: List[str] = []
    if version >= MIN_NODE_VERSION_COVERAGE_GLOBS:
        root = _glob_include_root(include_root)
        if root:
            filters += [f"--test-coverage-include={root}/**", f"--test-coverage-exclude={root}/**/node_modules/**"]
        else:
            filters.append("--test-coverage-exclude=**/node_modules/**")
        filters.append("--test-coverage-exclude=**/test_vh_*")
    return options, filters


def parse_lcov(text: str) -> List[Tuple[str, Dict[int, int]]]:
    """把 lcov 文字解析成 [(SF 路徑, {行號: 執行次數})]，依出現順序。只看 SF／DA／end_of_record：分支（BRDA、BRF、BRH）、
    函式（FN、FNDA、FNF、FNH）、摘要（LF、LH）與 TN 一律忽略；壞掉的行（非數字、行號 < 1）跳過；缺少 end_of_record
    的紀錄在下一個 SF 或檔尾結束；同一紀錄內重複的 DA 取最大的次數。報告來自執行不受信任程式碼的行程，絕不因它出錯。
    Parses lcov text into [(SF path, {line: hit count})], in order of appearance. Only SF / DA / end_of_record are read:
    branches (BRDA, BRF, BRH), functions (FN, FNDA, FNF, FNH), summaries (LF, LH) and TN are ignored; broken lines
    (non-numeric, line < 1) are skipped; a record missing end_of_record ends at the next SF or at the end of the text;
    a DA repeated inside one record keeps the highest count. The report comes from a process running untrusted code, so
    nothing in it may raise."""
    records: List[Tuple[str, Dict[int, int]]] = []
    current: Optional[str] = None
    lines: Dict[int, int] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            if current is not None:
                records.append((current, lines))
            current, lines = line[3:].strip(), {}
        elif line == "end_of_record":
            if current is not None:
                records.append((current, lines))
            current, lines = None, {}
        elif line.startswith("DA:") and current is not None:
            fields = line[3:].split(",")
            if len(fields) < 2:
                continue
            try:
                number, hits = int(fields[0]), int(float(fields[1]))
            except ValueError:
                continue
            if number >= 1:
                lines[number] = max(lines.get(number, 0), max(hits, 0))
    if current is not None:
        records.append((current, lines))
    return [(path, data) for path, data in records if path]


def resolve_source_path(source: str, cwd: str, windows: Optional[bool] = None) -> str:
    """lcov 的 SF 值轉成絕對、正規化的路徑：file:// URL 先還原成路徑（Windows 的 /C:/... 去掉開頭斜線），相對路徑
    （Node 寫的是相對於行程 cwd 的路徑）以 cwd 為基準。`windows` 決定路徑規則（預設看目前平台；容器內一律 POSIX）。
    An lcov SF value as an absolute, normalised path: a file:// URL becomes a path first (Windows /C:/... loses its
    leading slash), a relative path (Node writes paths relative to the process cwd) is joined onto cwd. `windows` picks
    the path rules (the current platform by default; always POSIX inside a container)."""
    windows = sys.platform == "win32" if windows is None else windows
    path_mod = ntpath if windows else posixpath
    path = source.strip()
    if path.lower().startswith("file:"):
        path = urllib.parse.unquote(urllib.parse.urlparse(path).path)
        if windows and _WINDOWS_DRIVE_URL_RE.match(path):
            path = path[1:]
    if not path_mod.isabs(path) or (windows and not ntpath.splitdrive(path)[0]):
        path = path_mod.join(cwd, path)
    return path_mod.normpath(path)


def target_relative_path(path: str, roots: Iterable[str], windows: Optional[bool] = None) -> Optional[str]:
    """`path` 是目標自己的原始檔時，回傳它相對於目標根目錄、以 '/' 分隔的路徑；在任何根目錄之外、位於 node_modules
    底下，或是產生的測試模組時回傳 None。Windows 規則下不分大小寫比對，回傳的路徑也轉成小寫（os.path.normcase）。
    The path of `path` relative to the target root, '/'-separated, when it is one of the target's own source files;
    None when it is outside every root, under node_modules, or a generated test module. Case-insensitive under the
    Windows rules, where the returned path is lower-cased as well (os.path.normcase)."""
    windows = sys.platform == "win32" if windows is None else windows
    path_mod = ntpath if windows else posixpath
    norm = path_mod.normcase if windows else (lambda p: p)
    candidate = path_mod.normpath(path)
    for root in roots:
        if not root:
            continue
        base = path_mod.normpath(root)
        prefix = base if base.endswith(path_mod.sep) else base + path_mod.sep
        if not norm(candidate).startswith(norm(prefix)):
            continue
        parts = [p for p in re.split(r"[\\/]" if windows else "/", candidate[len(prefix):]) if p]
        if not parts or any(norm(p) == "node_modules" for p in parts) or _TEST_MODULE_RE.fullmatch(parts[-1]):
            return None
        # Windows 規則下鍵也用 normcase（小寫）：同一個模組以不同大小寫匯入時，V8 可能寫出兩筆 SF，合併時不能重複計算
        # Under the Windows rules the key is normcased (lower case) too: a module imported with different letter case
        # may get two SF records from V8, which must not be counted twice when merged
        return "/".join(norm(p) for p in parts)
    return None


class JsLineCoverage:
    """一次執行（全部模組）合併後的 JS/TS 行涵蓋率：{目標相對路徑: {行號: 是否執行過}}。同一個檔案在不同模組
    （或同一份報告重複的 SF 紀錄）裡的行取聯集：任一來源執行過就算涵蓋。
    The merged JS/TS line coverage of one run (all modules): {target-relative path: {line: executed}}. A file's lines
    from different modules (or from a repeated SF record within one report) are united: covered when any source
    executed them."""

    def __init__(self) -> None:
        self.files: Dict[str, Dict[int, bool]] = {}
        # 讀到的 lcov 報告數（含沒有任何目標檔案的報告） ／ lcov reports read (including ones without any target file)
        self.reports = 0

    def add_lcov(self, text: str, roots: Iterable[str], cwd: str, windows: Optional[bool] = None) -> None:
        """解析一份 lcov 報告，只把目標自己的原始檔併進來。
        Parses one lcov report and merges in the target's own source files only."""
        roots = list(roots)
        self.reports += 1
        for source, lines in parse_lcov(text):
            relative = target_relative_path(resolve_source_path(source, cwd, windows), roots, windows)
            if relative is None:
                continue
            merged = self.files.setdefault(relative, {})
            for number, hits in lines.items():
                merged[number] = merged.get(number, False) or hits > 0

    def merge(self, other: "JsLineCoverage") -> None:
        """把另一份涵蓋率以聯集併進來 ／ Merges another coverage in as a union."""
        self.reports += other.reports
        for relative, lines in other.files.items():
            merged = self.files.setdefault(relative, {})
            for number, hit in lines.items():
                merged[number] = merged.get(number, False) or hit

    @property
    def instrumented_lines(self) -> int:
        return sum(len(lines) for lines in self.files.values())

    @property
    def covered_lines(self) -> int:
        return sum(sum(1 for hit in lines.values() if hit) for lines in self.files.values())

    def percent(self) -> Optional[float]:
        """涵蓋的行 ／ 有插樁的行（只計入載入過的目標檔案），四捨五入到小數一位；沒有任何插樁行時為 None。
        Covered lines / instrumented lines (loaded target files only), rounded to one decimal; None without any
        instrumented line."""
        total = self.instrumented_lines
        if not total:
            return None
        return round(100.0 * self.covered_lines / total, 1)


def read_lcov_file(path: str) -> Optional[str]:
    """讀回 lcov 報告；檔案不存在或讀不了時為 None ／ Reads the lcov report back; None when it is missing or unreadable."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _glob_include_root(include_root: Optional[str]) -> Optional[str]:
    """可當成 --test-coverage-include 的絕對路徑；不行時為 None。
    Windows 路徑（磁碟機代號或反斜線）先改成正斜線：Node 的 path.win32.matchesGlob 用 minimatch 的
    windowsPathsNoEscape，把 `/` 與 `\\` 都當分隔符，所以 `C:/proj/pkg/**` 比對得到 `C:\\proj\\pkg\\m.mjs`。
    含 glob 特殊字元（含 POSIX 路徑裡的反斜線）時不加 include，避免模式被當成跳脫或字元集合。
    An absolute path usable as --test-coverage-include, or None. A Windows path (a drive prefix or
    backslashes) is rewritten to forward slashes: Node's path.win32.matchesGlob uses minimatch with
    windowsPathsNoEscape, so `/` and `\\` are both separators and `C:/proj/pkg/**` matches
    `C:\\proj\\pkg\\m.mjs`. A path with glob metacharacters (including a backslash in a POSIX path) gets
    no include, so the pattern is not read as an escape or a character class."""
    if not include_root:
        return None
    looks_windows = "\\" in include_root or (len(include_root) >= 2 and include_root[1] == ":")
    normalized = include_root.replace("\\", "/") if looks_windows else include_root
    if _GLOB_META_RE.search(normalized):
        return None
    drive = len(normalized) >= 3 and normalized[1] == ":" and normalized[2] == "/"
    if not (normalized.startswith("/") or drive):
        return None
    return normalized.rstrip("/")
