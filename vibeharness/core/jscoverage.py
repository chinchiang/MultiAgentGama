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
import errno
import logging
import ntpath
import os
import posixpath
import re
import stat
import sys
import urllib.parse
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from vibeharness.core.i18n import bi

logger = logging.getLogger("VibeHarness.JsCoverage")

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


def node_coverage_args(version: Tuple[int, int, int], include_root: Union[str, Sequence[str], None],
                       windows: Optional[bool] = None) -> Tuple[List[str], List[str]]:
    """(放在 --test 之前的 Node 選項, 涵蓋率篩選旗標)。篩選旗標只在 Node >= 22.5 時給：include 限制在目標目錄
    （絕對路徑且不含 glob 特殊字元；Windows 路徑先改成正斜線，見 _glob_include_root；include_root 可以是同一個目錄的
    幾種拼法，各給一個 include，見 _glob_include_roots；`windows` 決定路徑規則，預設看目前平台），
    exclude 去掉目標根目錄以下的 node_modules（沒有 include 時是任何 node_modules）與產生的測試模組。明確的 include
    會取代 Node 預設「路徑含 /node_modules/ 就排除」的規則，所以本身位於某個 node_modules 底下的目標
    （/x/node_modules/pkg 或 C:/x/node_modules/pkg）也收得到涵蓋率。不論有沒有這些旗標，解析 lcov 時都會再篩一次。
    (Node options placed before --test, coverage filter flags). The filter flags are only given on Node >= 22.5: the
    include limits the report to the target directory (an absolute path without glob metacharacters; a Windows path
    is rewritten to forward slashes, see _glob_include_root; include_root may be several spellings of the same
    directory, each getting its own include, see _glob_include_roots; `windows` picks the path rules, the current
    platform by default), the excludes drop
    node_modules below the target root (any node_modules without an include) and the generated test modules. An
    explicit include replaces Node's default rule of dropping every path containing /node_modules/, so a target that
    itself lives under a node_modules (/x/node_modules/pkg or C:/x/node_modules/pkg) still gets coverage. The lcov
    is filtered again when parsed, with or without them."""
    options = ["--experimental-test-coverage", _DISABLE_LISTENER_WARNING]
    filters: List[str] = []
    if version >= MIN_NODE_VERSION_COVERAGE_GLOBS:
        roots = _glob_include_roots(include_root, windows)
        if roots:
            filters += [f"--test-coverage-include={root}/**" for root in roots]
            filters += [f"--test-coverage-exclude={root}/**/node_modules/**" for root in roots]
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


def _reparse_point(st: os.stat_result) -> bool:
    """Windows 的重新剖析點（symlink、junction 等）；其他平台一律 False。
    A Windows reparse point (symlink, junction and so on); always False elsewhere."""
    return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def read_untrusted_file(path: str, max_bytes: int) -> Tuple[Optional[str], Optional[str]]:
    """讀回沙盒裡不受信任的程式碼可以改寫的檔案（junit.xml、lcov 報告）：(文字, None)；檔案不存在時 (None, None)；
    拒絕或讀不了時 (None, 雙語原因)。被測程式碼（容器裡的 nobody，或本機沙盒的同一使用者）可以把報告換成指向
    主機檔案的 symlink、FIFO 或裝置，所以：POSIX 上以 O_NOFOLLOW 開啟（最後一段是 symlink 就失敗）並加上
    O_NONBLOCK（FIFO 不會讓 harness 卡住）；Windows 沒有 O_NOFOLLOW，改為開啟前以 lstat 拒絕 symlink／重新剖析點，
    開啟後再比對 fstat 與 lstat 是同一個檔案。開啟後只接受一般檔案（S_ISREG）、只有一個硬連結（不能是主機檔案的
    硬連結），且不超過 max_bytes（最多讀 max_bytes + 1 位元組，讀的過程中變大也會被拒絕）。換行正規化成 \\n。
    Reads back a file the untrusted code in the sandbox can rewrite (junit.xml, the lcov report): (text, None); (None,
    None) when it does not exist; (None, bilingual reason) when it is refused or unreadable. The code under test (nobody
    in the container, or the same user in the local sandbox) can replace a report with a symlink to a host file, a
    FIFO or a device, so: on POSIX it is opened with O_NOFOLLOW (fails when the last component is a symlink) plus
    O_NONBLOCK (a FIFO cannot hang the harness); Windows has no O_NOFOLLOW, so a symlink / reparse point is refused
    with lstat before opening and fstat is compared with lstat after opening (the same file). Once open only a regular
    file (S_ISREG) with a single hard link (not a hard link to a host file) of at most max_bytes is accepted (at most
    max_bytes + 1 bytes are read, so growing while being read is refused too). Newlines are normalised to \\n."""
    name = os.path.basename(path)

    def refused(zh: str, en: str) -> Tuple[Optional[str], Optional[str]]:
        reason = bi(f"拒絕讀回沙盒產生的 {name}：{zh}", f"Refused to read back the sandbox's {name}: {en}")
        logger.warning(reason)
        return None, reason

    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return refused(f"無法讀取（{e}）", f"it is unreadable ({e})")
    if stat.S_ISLNK(before.st_mode) or _reparse_point(before):
        return refused("它是 symlink／重新剖析點", "it is a symbolic link / reparse point")
    if not stat.S_ISREG(before.st_mode):
        return refused("它不是一般檔案", "it is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        if e.errno == errno.ELOOP:  # 檢查之後才被換成 symlink ／ swapped for a symlink after the check
            return refused("它是 symlink／重新剖析點", "it is a symbolic link / reparse point")
        return refused(f"無法讀取（{e}）", f"it is unreadable ({e})")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return refused("它不是一般檔案", "it is not a regular file")
        if (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            return refused("檢查之後被換掉了", "it was replaced after being checked")
        if st.st_nlink > 1:
            return refused("它有其他硬連結", "it has other hard links")
        if st.st_size > max_bytes:
            return refused(f"超過 {max_bytes} 位元組的上限", f"it exceeds the {max_bytes}-byte cap")
        chunks: List[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining <= 0:
            return refused(f"超過 {max_bytes} 位元組的上限", f"it exceeds the {max_bytes}-byte cap")
    except OSError as e:
        return refused(f"無法讀取（{e}）", f"it is unreadable ({e})")
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n"), None


# 讀回的 junit.xml／lcov 報告的大小上限：與本機沙盒（RLIMIT_FSIZE）和 docker 沙盒（--ulimit fsize）寫檔的上限相同，
# 正常寫出的報告不會超過它
# The size cap of a junit.xml / lcov report read back: the same as the cap on writing a file in the local sandbox
# (RLIMIT_FSIZE) and the docker sandbox (--ulimit fsize), so a report written normally never exceeds it
MAX_REPORT_BYTES = 64 * 1024 * 1024


def read_lcov_file(path: str) -> Optional[str]:
    """讀回 lcov 報告（見 read_untrusted_file）；檔案不存在、被拒絕或讀不了時為 None（被拒絕時記一行雙語 WARNING）。
    Reads the lcov report back (see read_untrusted_file); None when it is missing, refused or unreadable (a refusal
    logs a bilingual WARNING)."""
    return read_untrusted_file(path, MAX_REPORT_BYTES)[0]


_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _glob_include_root(include_root: Optional[str], windows: Optional[bool] = None) -> Optional[str]:
    """可當成 --test-coverage-include 的絕對路徑；不行時為 None。`windows` 決定路徑規則（預設看目前平台；容器內
    一律 POSIX），與 target_relative_path 相同。
    Windows 規則（或帶磁碟機代號的路徑）下反斜線是分隔符，先改成正斜線：Node 的 path.win32.matchesGlob 用 minimatch
    的 windowsPathsNoEscape，把 `/` 與 `\\` 都當分隔符，所以 `C:/proj/pkg/**` 比對得到 `C:\\proj\\pkg\\m.mjs`（磁碟機
    代號不分大小寫，目錄名稱分大小寫）。UNC 路徑（\\\\server\\share\\x）可以；`\\\\?\\`、`\\\\.\\` 裝置路徑與只有磁碟機
    代號的相對路徑（C:foo）不行。POSIX 規則下反斜線是 glob 的跳脫字元，含反斜線的路徑不加 include（v0.9.0 的行為），
    絕不把 /home/u/a\\b 改成指向別處的 /home/u/a/b。含 glob 特殊字元時同樣不加 include，避免模式被當成跳脫或字元
    集合；根目錄本身（/）也不加（等於沒有篩選）。
    An absolute path usable as --test-coverage-include, or None. `windows` picks the path rules (the current platform
    by default; always POSIX inside a container), like target_relative_path.
    Under the Windows rules (or for a path with a drive prefix) a backslash is a separator and is rewritten to a
    forward slash first: Node's path.win32.matchesGlob uses minimatch with windowsPathsNoEscape, so `/` and `\\` are
    both separators and `C:/proj/pkg/**` matches `C:\\proj\\pkg\\m.mjs` (the drive letter is case-insensitive, directory
    names are case-sensitive). A UNC path (\\\\server\\share\\x) works; a `\\\\?\\` / `\\\\.\\` device path and a
    drive-relative path (C:foo) do not. Under the POSIX rules a backslash is the glob escape character, so a path with
    one gets no include (the v0.9.0 behaviour) and /home/u/a\\b is never rewritten into /home/u/a/b, which points
    elsewhere. A path with glob metacharacters likewise gets no include, so the pattern is not read as an escape or a
    character class; neither does the root itself (/), which would filter nothing."""
    if not include_root:
        return None
    windows = sys.platform == "win32" if windows is None else windows
    windows_rules = windows or bool(_WINDOWS_DRIVE_RE.match(include_root))
    normalized = include_root.replace("\\", "/") if windows_rules else include_root
    if _GLOB_META_RE.search(normalized):
        return None
    if windows_rules:
        if normalized.startswith("//"):
            # UNC：至少要有 //server/share，且不能是 //./ 或 //?/ 裝置路徑（? 已被特殊字元擋下）
            # UNC: needs at least //server/share and must not be a //./ or //?/ device path (? is already caught)
            parts = normalized[2:].split("/")
            if len(parts) < 2 or not parts[0] or not parts[1] or parts[0] == ".":
                return None
            return "//" + "/".join(p for p in parts if p)
        if not re.match(r"^[A-Za-z]:/", normalized):
            return None  # 沒有磁碟機的 /x、相對路徑或 C:foo ／ /x without a drive, a relative path or C:foo
        # 磁碟機根目錄 C:/ 變成 C:（模式是 C:/**）；連續的斜線收成一個 ／ the drive root C:/ becomes C: (pattern C:/**); repeated slashes collapse
        return normalized[:2] + re.sub(r"/+", "/", normalized[2:]).rstrip("/")
    if not normalized.startswith("/"):
        return None
    collapsed = re.sub(r"/+", "/", normalized).rstrip("/")
    return collapsed or None


def _glob_include_roots(include_roots: Union[str, Sequence[str], None], windows: Optional[bool] = None) -> List[str]:
    """所有拼法都能當 include 時，回傳去重後的 include 根目錄；否則為空串列（不加 include，退回只用排除模式與自己的
    篩選）。include 只是縮小報告的最佳化（以及讓位於 node_modules 底下的目標收得到涵蓋率）：多收的檔案會被解析 lcov
    時的篩選丟掉，但漏掉 Node 實際回報的那個拼法就會讓涵蓋率變成 0，所以任何一個拼法表達不了就整個不加。
    Windows 上兩個拼法（abspath 與 realpath）只在磁碟機代號大小寫不同時才算同一個；其他差異（對應的網路磁碟機
    Z:\\ 與 realpath 的 \\\\server\\share、目錄名稱大小寫、junction）都不加 include：Node 回報的是匯入時的拼法，
    而 include 的目錄名稱分大小寫，猜錯就什麼都不剩。POSIX 上每個拼法各給一個 include（Node 把多個 include 以 OR 合併）。
    The deduplicated include roots when every spelling can be one; otherwise an empty list (no include, falling back to
    the excludes and our own filtering). The include only narrows the report (and lets a target under node_modules get
    coverage): files collected in excess are dropped by the filtering when the lcov is parsed, but missing the spelling
    Node actually reports turns the coverage into 0, so when any one spelling cannot be expressed none is given.
    On Windows two spellings (abspath and realpath) only count as one when they differ in the drive letter's case
    alone; any other difference (a mapped drive Z:\\ against the realpath \\\\server\\share, directory-name case, a
    junction) gets no include: Node reports the spelling the module was imported with and the include's directory names
    are case-sensitive, so a wrong guess leaves nothing. On POSIX each spelling gets its own include (Node ORs several
    includes)."""
    if include_roots is None:
        return []
    candidates = [include_roots] if isinstance(include_roots, str) else list(include_roots)
    windows = sys.platform == "win32" if windows is None else windows
    roots: List[str] = []
    for candidate in candidates:
        root = _glob_include_root(candidate, windows)
        if root is None:
            return []
        if windows and _WINDOWS_DRIVE_RE.match(root):
            root = root[0].upper() + root[1:]  # 磁碟機代號不分大小寫 ／ the drive letter is case-insensitive
        if root not in roots:
            roots.append(root)
    if windows and len(roots) > 1:
        return []
    return roots
