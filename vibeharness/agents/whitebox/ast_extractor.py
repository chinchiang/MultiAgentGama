import ast
import fnmatch
import logging
import os
from dataclasses import dataclass, field as dataclass_field
from types import MappingProxyType
from typing import AbstractSet, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from vibeharness.agents.whitebox._js_extractor import extract_js_ts_symbols
from vibeharness.core.i18n import bi
from vibeharness.core.models import CodeSymbol
# max_files、max_file_bytes 與 SKIPPED_DIRS 定義在 core/settings.py（該模組匯入時不載入第三方套件），此處轉匯出相容常數
# max_files, max_file_bytes and SKIPPED_DIRS live in core/settings.py (which loads no third-party package on import) and are re-exported here
from vibeharness.core.settings import (
    DEFAULT_MAX_FILE_BYTES as DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES as DEFAULT_MAX_FILES,
    SKIPPED_DIRS as SKIPPED_DIRS,
    is_unsafe_file,
)

logger = logging.getLogger("VibeHarness.ASTExtractor")

SOURCE_EXTENSIONS = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
# 擷取器不支援的程式語言原始碼（依副檔名）：記錄為證據缺口而不是默默丟掉。刻意不含 shell 腳本、SQL、HTML/CSS
# 這類在任何專案裡都常見的附屬檔案，也不含文件、圖片、鎖定檔與設定檔
# Source code in languages the extractor does not support (by extension): recorded as an evidence gap instead of being
# silently dropped. Shell scripts, SQL and HTML/CSS (incidental in almost any project) are deliberately left out, as
# are docs, images, lockfiles and configuration files
UNSUPPORTED_SOURCE_EXTENSIONS: Dict[str, str] = {
    ".go": "go", ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".rs": "rust",
    ".c": "c", ".h": "c", ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".hpp": "c++", ".hh": "c++", ".hxx": "c++",
    ".cs": "c#", ".php": "php", ".rb": "ruby", ".swift": "swift", ".scala": "scala", ".sc": "scala",
    ".m": "objective-c", ".mm": "objective-c", ".dart": "dart", ".lua": "lua", ".pl": "perl", ".pm": "perl",
    ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".hs": "haskell", ".clj": "clojure", ".fs": "f#",
    ".fsx": "f#", ".vb": "visual-basic", ".groovy": "groovy", ".vue": "vue", ".svelte": "svelte", ".sol": "solidity",
}
# 不支援語言的檔案只保留這麼多個路徑當樣本（計數不設上限）
# Only this many paths of unsupported-language files are kept as a sample (the count is unbounded)
UNSUPPORTED_SAMPLE_SIZE = 20
# 只在本機做確定性密鑰掃描（VH-AI-007）的設定類檔案：絕不送給模型，因為它們不是被分析的符號
# Configuration-like files that only get the local, deterministic secret scan (VH-AI-007): never sent to a model,
# since they are not analyzed symbols
CONFIG_EXTENSIONS = (".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".properties", ".tf", ".tfvars", ".env")
CONFIG_NAMES = {"dockerfile", ".env", ".npmrc", ".pypirc", ".netrc"}
# 自動產生的鎖定檔：內容是套件雜湊而不是設定，略過
# Generated lockfiles: package hashes rather than configuration, skipped
LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock"}
# 一次執行最多掃描的設定類檔案數（超過的列為證據缺口）
# The most configuration-like files one run scans (the rest are reported as an evidence gap)
DEFAULT_MAX_CONFIG_FILES = 200
# FastAPI/Starlette 動詞加上 Flask/Quart 的路由裝飾器
# FastAPI/Starlette verbs plus Flask/Quart route decorators
ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "route", "api_route", "websocket"}
# 即使路徑不是字串字面值也會註冊路由的 Python 裝飾器接收者
# Python decorator receivers that register routes even when the path is not a string literal
_PY_ROUTE_RECEIVERS = {"app", "router", "api", "bp", "blueprint", "application", "server"}
# 以方法呼叫（而非裝飾器）註冊檢視函式的方法：方法名稱 → （檢視函式的位置索引、關鍵字名稱）
# Methods that register a view function by call (not decorator): method name -> (positional index, keyword)
# of the view function
_PY_VIEW_REGISTRATIONS: Mapping[str, Tuple[int, str]] = MappingProxyType({
    "add_url_rule": (2, "view_func"),  # Flask／Quart，參數依序為 (rule, endpoint, view_func) ／ Flask / Quart: (rule, endpoint, view_func)
    "add_api_route": (1, "endpoint"),  # FastAPI，參數依序為 (path, endpoint) ／ FastAPI: (path, endpoint)
    "add_api_websocket_route": (1, "endpoint"),  # FastAPI 的 WebSocket ／ FastAPI WebSocket
    "add_route": (1, "route"),  # Starlette，參數依序為 (path, route) ／ Starlette: (path, route)
    "add_websocket_route": (1, "route"),  # Starlette 的 WebSocket ／ Starlette WebSocket
})
# 建構時就註冊端點的路由類別：類別名稱 → （端點的位置索引、關鍵字名稱）；名稱很普通，所以只認從
# _PY_ROUTE_CLASS_PACKAGES 匯入的
# Route classes that register an endpoint when constructed: class name -> (positional index, keyword) of the
# endpoint; the names are common, so only those imported from _PY_ROUTE_CLASS_PACKAGES count
_PY_ROUTE_CLASSES: Mapping[str, Tuple[int, str]] = MappingProxyType({
    "Route": (1, "endpoint"),
    "WebSocketRoute": (1, "endpoint"),
    "APIRoute": (1, "endpoint"),
    "APIWebSocketRoute": (1, "endpoint"),
})
_PY_ROUTE_CLASS_PACKAGES = {"starlette", "fastapi"}


@dataclass(frozen=True)
class ScopeResult:
    """一次走訪的檔案範圍：分析了哪些原始碼檔案、哪些因為什麼原因沒有分析，以及偵測到的語言。harness 的閘門、
    主控台、Node 沙盒的 TypeScript 判斷與 --estimate 都讀這個值，而不是擷取器在最後一次呼叫後留下的狀態。
    `filters` 是 harness 套用的檔案篩選條件的描述（擷取器本身不填）。
    One walk's file scope: which source files were analyzed, which were not and why, and the languages detected.
    The harness's gate, console, the Node sandbox's TypeScript choice and --estimate read this value rather than
    the state the extractor was left in after its last call. `filters` describes the file selection the harness
    applied (the extractor itself leaves it empty)."""
    analyzed_files: Tuple[str, ...] = ()
    skipped_files: Tuple[str, ...] = ()  # 超過 max_files ／ beyond max_files
    oversized_files: Tuple[str, ...] = ()  # 超過 max_file_bytes ／ over max_file_bytes
    # 解析到目標之外或不是一般檔案的連結與特殊檔案（沒有讀取） ／ links resolving outside the target, and non-regular
    # files (not read)
    unsafe_files: Tuple[str, ...] = ()
    parse_failures: Tuple[str, ...] = ()
    filtered_out: int = 0  # 被篩選條件排除的原始碼檔案（明確指定時不是證據缺口） ／ source files dropped by filters (not a gap when explicit)
    discovered_filtered: int = 0  # 由自動發現設定檔排除的檔案（證據缺口） ／ files excluded by a discovered config (a gap)
    unsupported_count: int = 0
    # 唯讀的對照表 ／ a read-only mapping
    unsupported_languages: Mapping[str, int] = dataclass_field(default_factory=lambda: MappingProxyType({}))
    unsupported_files: Tuple[str, ...] = ()  # 樣本 ／ a sample
    config_files: Tuple[str, ...] = ()
    skipped_config_files: Tuple[str, ...] = ()
    oversized_config_files: Tuple[str, ...] = ()
    detected_languages: Tuple[str, ...] = ()  # 已排序 ／ sorted
    filters: Tuple[str, ...] = ()


class ASTExtractor:
    """
    把原始碼解析成結構化的 CodeSymbol 物件。
    Python 以原生 AST 解析；JavaScript/TypeScript 委派給無相依的純詞法原語（`core/js_lex.py`）與單一檔案解析器
    （`_js_extractor.py`），在清空字串、樣板字面值、註解與正規表達式字面值後以真實括號配對擷取宣告與路由。
    Parses source code into structured CodeSymbol objects.
    Python is parsed with the native AST; JavaScript/TypeScript delegates to the dependency-free lexical primitives
    (`core/js_lex.py`) and per-file parser (`_js_extractor.py`), extracting declarations and routes with real bracket
    matching on masked source.
    """

    def __init__(self):
        self.detected_languages = set()
        # 無法讀取／解析的檔案，以及因 max_files 上限而被排除的檔案
        # Files that could not be read/parsed, and files left out by the max_files cap
        self.parse_failures: List[str] = []
        self.skipped_files: List[str] = []
        # 因超過 max_file_bytes 而被排除的檔案
        # Files left out because they exceed max_file_bytes
        self.oversized_files: List[str] = []
        self.unsafe_files: List[str] = []
        # 被 include/exclude 樣式或 only_files 篩選器排除的原始碼檔案（使用者明確指定時不是證據缺口）
        # Source files dropped by include/exclude patterns or the only_files filter (not a gap when explicitly requested)
        self.filtered_out: int = 0
        # 由自動發現設定檔未受信任的 include/exclude 樣式排除的檔案（證據缺口）
        # Files dropped by untrusted include/exclude patterns from a discovered config (an evidence gap)
        self.discovered_filtered: int = 0
        # 在 max_files 上限之內的原始碼檔案（靜態 AI 安全規則掃描的正是這些）
        # Source files within the max_files cap (the static AI-security rules scan exactly these)
        self.analyzed_files: List[str] = []
        # 因語言不支援而沒有分析的原始碼檔案：總數、各語言計數，以及最多 UNSUPPORTED_SAMPLE_SIZE 個路徑樣本
        # Source files not analyzed because their language is unsupported: the total, per-language counts, and a
        # sample of at most UNSUPPORTED_SAMPLE_SIZE paths
        self.unsupported_count: int = 0
        self.unsupported_languages: Dict[str, int] = {}
        self.unsupported_files: List[str] = []
        # 只做本機密鑰掃描的設定類檔案；因數量上限或 max_file_bytes 而沒有掃描的設定類檔案
        # Configuration-like files that only get the local secret scan; those left unscanned by the count cap or by
        # max_file_bytes
        self.config_files: List[str] = []
        self.skipped_config_files: List[str] = []
        self.oversized_config_files: List[str] = []

    def parse_file(self, file_path: str) -> List[CodeSymbol]:
        if not os.path.exists(file_path):
            return []

        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".py":
            self.detected_languages.add("Python")
            return self._parse_python_file(file_path)
        elif ext in [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]:
            self.detected_languages.add("TypeScript/JavaScript")
            return self._parse_js_ts_file(file_path)
        return []

    def parse_directory(
        self,
        dir_path: str,
        max_files: int = DEFAULT_MAX_FILES,
        include: Optional[Sequence[str]] = None,
        exclude: Optional[Sequence[str]] = None,
        only_files: Optional[Iterable[str]] = None,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_config_files: int = DEFAULT_MAX_CONFIG_FILES,
        trusted_baseline: Optional[Tuple[Sequence[str], Sequence[str]]] = None,
    ) -> List[CodeSymbol]:
        """解析一個目錄樹（最多 max_files 個原始碼檔案）或單一原始碼檔案。

        `include` / `exclude` 是以相對於 dir_path 的路徑（正斜線；`**` 沒有特殊意義，fnmatch 的 `*`
        本來就能跨越目錄）比對的 glob 樣式，例如 `src/**/*.py` 或 `tests/*`。`only_files` 把走訪
        限制在那些絕對路徑（例如 git diff 觸及的檔案）。`trusted_baseline` 不為 None 時為受信任的
        `(include, exclude)` 基準：通過基準卻被未受信任的自動發現篩選排除的檔案會計入 `discovered_filtered`
        （證據缺口）。大於 max_file_bytes 的檔案列在 `oversized_files` 中且不解析。
        Parses a directory tree (up to max_files source files) or a single source file.

        `include` / `exclude` are glob patterns matched against the path relative to dir_path (forward
        slashes; `**` is not special, fnmatch's `*` already crosses directories), e.g. `src/**/*.py`
        or `tests/*`. `only_files` restricts the walk to those absolute paths (e.g. the files a git diff
        touched). When `trusted_baseline` is given, it is the trusted `(include, exclude)` baseline: files
        kept by that baseline yet dropped by untrusted discovered filters are counted in `discovered_filtered`
        (an evidence gap). Files larger than max_file_bytes are listed in `oversized_files` and not parsed.

        同樣的走訪規則（略過的目錄、隱藏目錄、include/exclude、only_files）也用來收集：不支援語言的原始碼檔案
        （`unsupported_*`，證據缺口）與只做本機密鑰掃描的設定類檔案（`config_files`，最多 max_config_files 個）。
        The same walk rules (skipped directories, hidden directories, include/exclude, only_files) also collect
        source files in unsupported languages (`unsupported_*`, an evidence gap) and configuration-like files that
        only get the local secret scan (`config_files`, at most max_config_files).
        """
        self.detected_languages = set()
        self.parse_failures, self.skipped_files, self.analyzed_files = [], [], []
        self.oversized_files, self.filtered_out, self.discovered_filtered = [], 0, 0
        self.unsupported_count, self.unsupported_languages, self.unsupported_files = 0, {}, []
        self.config_files, self.skipped_config_files, self.oversized_config_files = [], [], []
        self.unsafe_files = []
        if os.path.isfile(dir_path):
            kind = self._file_kind(os.path.basename(dir_path))
            if kind == "source":
                if self._too_large(dir_path, max_file_bytes):
                    self.oversized_files = [dir_path]
                    return []
                self.analyzed_files = [dir_path]
            elif kind is not None:
                self._collect_other(dir_path, kind, max_file_bytes, max_config_files)
            return self.parse_file(dir_path)
        source_files: List[str] = []
        wanted = {os.path.normcase(os.path.abspath(p)) for p in only_files} if only_files is not None else None
        real_root = os.path.realpath(dir_path)
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in SKIPPED_DIRS)
            for f in sorted(files):
                kind = self._file_kind(f)
                if kind is None:
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, dir_path).replace(os.sep, "/")
                if wanted is not None and os.path.normcase(os.path.abspath(full)) not in wanted:
                    if kind == "source":
                        self.filtered_out += 1
                    continue
                if not self._selected(rel, include, exclude):
                    if kind == "source":
                        self.filtered_out += 1
                    if trusted_baseline is not None and self._selected(rel, *trusted_baseline):
                        self.discovered_filtered += 1
                    continue
                # 原始碼會送給模型、設定類檔案會被掃描：兩者都不讀目標之外的連結或特殊檔案（/dev/zero 讀不完）
                # Source goes to the models and config-like files get scanned: neither reads a link out of the target
                # or a special file (/dev/zero never ends)
                if not kind.startswith("unsupported:") and is_unsafe_file(full, real_root):
                    self.unsafe_files.append(full)
                    continue
                if kind != "source":
                    self._collect_other(full, kind, max_file_bytes, max_config_files)
                    continue
                if self._too_large(full, max_file_bytes):
                    self.oversized_files.append(full)
                    continue
                source_files.append(full)
        if self.unsupported_count:
            langs = ", ".join(f"{lang}: {n}" for lang, n in sorted(self.unsupported_languages.items()))
            logger.warning(bi(f"{self.unsupported_count} 個不支援語言的原始碼檔案（{langs}）未納入分析。",
                              f"{self.unsupported_count} source file(s) in unsupported languages ({langs}) are not analyzed."))
        if self.oversized_files:
            logger.warning(bi(f"{len(self.oversized_files)} 個原始碼檔案超過 max_file_bytes（{max_file_bytes}），已略過。",
                              f"{len(self.oversized_files)} source file(s) exceed max_file_bytes ({max_file_bytes}) and were skipped."))

        self.skipped_files = source_files[max_files:]
        if self.skipped_files:
            logger.warning(bi(f"{len(source_files)} 個原始碼檔案只分析前 {max_files} 個；略過 {len(self.skipped_files)} 個。",
                              f"Only the first {max_files} of {len(source_files)} source files are analyzed; {len(self.skipped_files)} skipped."))
        self.analyzed_files = source_files[:max_files]
        all_symbols: List[CodeSymbol] = []
        for full_path in self.analyzed_files:
            try:
                all_symbols.extend(self.parse_file(full_path))
            except Exception as e:  # noqa: BLE001
                # 最後一道防線：單一檔案的意外錯誤不會中止整次執行；該檔案列入 parse_failures（證據缺口）
                # Last line of defense: an unexpected error in one file never aborts the run; the file is listed
                # in parse_failures (an evidence gap)
                logger.warning(bi(f"無法分析 {full_path}（{type(e).__name__}），已略過：{e}",
                                  f"Could not analyze {full_path} ({type(e).__name__}), skipped: {e}"))
                if full_path not in self.parse_failures:
                    self.parse_failures.append(full_path)
        return all_symbols

    def scan_directory(
        self,
        dir_path: str,
        max_files: int = DEFAULT_MAX_FILES,
        include: Optional[Sequence[str]] = None,
        exclude: Optional[Sequence[str]] = None,
        only_files: Optional[Iterable[str]] = None,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_config_files: int = DEFAULT_MAX_CONFIG_FILES,
        trusted_baseline: Optional[Tuple[Sequence[str], Sequence[str]]] = None,
    ) -> Tuple[List[CodeSymbol], ScopeResult]:
        """parse_directory 的符號，加上這次走訪的範圍（不可變）。參數與 parse_directory 相同。
        parse_directory's symbols plus this walk's scope (immutable). Same arguments as parse_directory."""
        symbols = self.parse_directory(dir_path, max_files=max_files, include=include, exclude=exclude,
                                       only_files=only_files, max_file_bytes=max_file_bytes,
                                       max_config_files=max_config_files, trusted_baseline=trusted_baseline)
        return symbols, ScopeResult(
            analyzed_files=tuple(self.analyzed_files), skipped_files=tuple(self.skipped_files),
            oversized_files=tuple(self.oversized_files), parse_failures=tuple(self.parse_failures),
            unsafe_files=tuple(self.unsafe_files),
            filtered_out=self.filtered_out, discovered_filtered=self.discovered_filtered,
            unsupported_count=self.unsupported_count,
            unsupported_languages=MappingProxyType(dict(self.unsupported_languages)),
            unsupported_files=tuple(self.unsupported_files),
            config_files=tuple(self.config_files), skipped_config_files=tuple(self.skipped_config_files),
            oversized_config_files=tuple(self.oversized_config_files),
            detected_languages=tuple(sorted(self.detected_languages)),
        )

    @staticmethod
    def _file_kind(name: str) -> Optional[str]:
        """檔案的類別：'source'（會分析）、'config'（只做密鑰掃描）、'unsupported:<語言>'，或 None（不相關）。
        隱藏檔只有已知的設定檔名（.env、.env.*、.npmrc …）才算。
        The file's category: 'source' (analyzed), 'config' (secret scan only), 'unsupported:<language>', or None
        (irrelevant). Hidden files only count for the known configuration names (.env, .env.*, .npmrc ...)."""
        lower = name.lower()
        if lower.endswith(SOURCE_EXTENSIONS):
            return "source"
        if lower in LOCKFILE_NAMES or lower.endswith(".lock"):
            return None
        if lower in CONFIG_NAMES or lower.startswith((".env.", "dockerfile.")) or lower.endswith(".dockerfile"):
            return "config"
        if lower.startswith("."):
            return None
        if lower.endswith(CONFIG_EXTENSIONS):
            return "config"
        lang = UNSUPPORTED_SOURCE_EXTENSIONS.get(os.path.splitext(lower)[1])
        return f"unsupported:{lang}" if lang else None

    def _collect_other(self, path: str, kind: str, max_file_bytes: int, max_config_files: int) -> None:
        """記錄一個不會被分析的檔案：不支援的語言（計數加樣本）或設定類檔案（受數量與大小上限限制）。
        Records a file that is not analyzed: an unsupported language (count plus sample) or a configuration-like file
        (subject to the count and size caps)."""
        if kind.startswith("unsupported:"):
            lang = kind.split(":", 1)[1]
            self.unsupported_count += 1
            self.unsupported_languages[lang] = self.unsupported_languages.get(lang, 0) + 1
            if len(self.unsupported_files) < UNSUPPORTED_SAMPLE_SIZE:
                self.unsupported_files.append(path)
        elif self._too_large(path, max_file_bytes):
            self.oversized_config_files.append(path)
        elif len(self.config_files) < max_config_files:
            self.config_files.append(path)
        else:
            self.skipped_config_files.append(path)

    @staticmethod
    def _selected(rel_path: str, include: Optional[Sequence[str]], exclude: Optional[Sequence[str]]) -> bool:
        """include 樣式（若有）必須符合相對路徑或其基底檔名；exclude 樣式優先。
        include patterns (if any) must match the relative path or its basename; exclude patterns win."""
        name = rel_path.rsplit("/", 1)[-1]
        if include and not any(fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(name, p) for p in include):
            return False
        if exclude and any(fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(name, p)
                           or fnmatch.fnmatch(rel_path, p.rstrip("/") + "/*") for p in exclude):
            return False
        return True

    @staticmethod
    def _too_large(path: str, max_file_bytes: int) -> bool:
        try:
            return max_file_bytes > 0 and os.path.getsize(path) > max_file_bytes
        except OSError:
            return False

    def _parse_python_file(self, file_path: str) -> List[CodeSymbol]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source, filename=file_path)
        except Exception as e:
            logger.warning(bi(f"無法解析 {file_path}：{e}", f"Could not parse {file_path}: {e}"))
            self.parse_failures.append(file_path)
            return []

        symbols: List[CodeSymbol] = []
        # 只依 "\n" 切行：ast 的行號只算 "\n"（讀檔時通用換行已把 "\r\n"／"\r" 轉成 "\n"），而 splitlines() 還會在
        # \x0b \x0c \x1c-\x1e \x85 U+2028 U+2029 切開，幾個這種字元就能讓每個片段錯位、藏起函式真正的內容
        # Split on "\n" only: ast counts "\n" alone (universal newlines turned "\r\n" / "\r" into "\n" on read), while
        # splitlines() also splits on \x0b \x0c \x1c-\x1e \x85 U+2028 U+2029, so a few of them shift every snippet and
        # hide a function's real body
        source_lines = source.split("\n")
        registered = self._registered_python_views(tree)

        for node in self._py_definitions(tree.body):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.append(self._extract_python_function(node, file_path, source_lines, registered=registered))
                symbols.extend(self._nested_python_routes(node, file_path, source_lines, registered))
            elif isinstance(node, ast.ClassDef):
                symbols.append(self._extract_python_class(node, file_path, source_lines))
                for item in self._py_definitions(node.body):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        symbols.append(self._extract_python_function(item, file_path, source_lines, class_name=node.name,
                                                                     registered=registered))
                        symbols.extend(self._nested_python_routes(item, file_path, source_lines, registered))

        return symbols

    @staticmethod
    def _py_definitions(body: List[ast.stmt]) -> List[ast.stmt]:
        """一個主體中的 def／class，包括包在 `if`／`try`／`with`／`for`／`while`／`match` 裡的
        （例如 `if TYPE_CHECKING:` 或 `try: ... except ImportError:` 底下定義的函式）。
        The defs/classes of a body, including those wrapped in `if` / `try` / `with` / `for` / `while` /
        `match` (e.g. functions defined under `if TYPE_CHECKING:` or `try: ... except ImportError:`)."""
        found: List[ast.stmt] = []
        stack = list(reversed(body))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                found.append(node)
                continue
            children: List[ast.stmt] = []
            for field in ("body", "orelse", "finalbody"):
                children += [n for n in getattr(node, field, []) or [] if isinstance(n, ast.stmt)]
            for handler in getattr(node, "handlers", []) or []:
                children += handler.body
            for case in getattr(node, "cases", []) or []:
                children += case.body
            if isinstance(node, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)) \
                    or type(node).__name__ in ("Match", "TryStar"):
                stack.extend(reversed(children))
        return found

    @staticmethod
    def _registered_python_views(tree: ast.Module) -> Set[str]:
        """以呼叫註冊為檢視函式的名稱，整個模組任意深度：路由器方法（`app.add_url_rule("/x", view_func=handler)`、
        `router.add_api_route("/x", handler)`），以及從 Starlette／FastAPI 匯入的路由類別（`Route("/x", handler)`、
        `routing.Route(...)`，別名也算）。只收裸名稱：`views.handler` 這類屬性指向別的模組，`Cls.as_view(...)`
        是類別式檢視。
        Names registered as view functions by a call, anywhere in the module: router methods
        (`app.add_url_rule("/x", view_func=handler)`, `router.add_api_route("/x", handler)`) and route classes
        imported from Starlette / FastAPI (`Route("/x", handler)`, `routing.Route(...)`, aliases included).
        Only bare names count: an attribute such as `views.handler` points into another module, and
        `Cls.as_view(...)` is a class-based view."""
        # 綁定到路由類別的名稱（別名 → 類別名稱），以及綁定到 Starlette／FastAPI 模組的名稱
        # Names bound to a route class (alias -> class name) and names bound to a Starlette / FastAPI module
        class_names: Dict[str, str] = {}
        module_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0 \
                    and (node.module or "").split(".")[0] in _PY_ROUTE_CLASS_PACKAGES:
                for alias in node.names:
                    bound = alias.asname or alias.name
                    if alias.name in _PY_ROUTE_CLASSES:
                        class_names[bound] = alias.name
                    else:
                        module_names.add(bound)  # 模組本身，例如 `from starlette import routing` ／ the module itself, e.g. `from starlette import routing`
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in _PY_ROUTE_CLASS_PACKAGES:
                        # `import starlette.routing` 綁定 `starlette`；`import starlette.routing as r` 綁定 `r`
                        # `import starlette.routing` binds `starlette`; `import starlette.routing as r` binds `r`
                        module_names.add(alias.asname or alias.name.split(".")[0])

        names: Set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            spec: Optional[Tuple[int, str]] = None
            if isinstance(func, ast.Name) and func.id in class_names:
                spec = _PY_ROUTE_CLASSES[class_names[func.id]]
            elif isinstance(func, ast.Attribute):
                root = func.value
                while isinstance(root, ast.Attribute):
                    root = root.value
                if func.attr in _PY_ROUTE_CLASSES and isinstance(root, ast.Name) and root.id in module_names:
                    spec = _PY_ROUTE_CLASSES[func.attr]
                else:
                    spec = _PY_VIEW_REGISTRATIONS.get(func.attr)
            if spec is None:
                continue
            index, keyword = spec
            view = node.args[index] if len(node.args) > index else next(
                (k.value for k in node.keywords if k.arg == keyword), None)
            if isinstance(view, ast.Name):
                names.add(view.id)
        return names

    def _nested_python_routes(self, func: Union[ast.FunctionDef, ast.AsyncFunctionDef], file_path: str,
                              source_lines: List[str], registered: AbstractSet[str]) -> List[CodeSymbol]:
        """函式內部註冊的路由處理函式（Flask `create_app()` 工廠中的 `@app.route` 或 `add_url_rule`），任意深度。
        Route handlers registered inside a function (`@app.route` or `add_url_rule` in a Flask `create_app()`
        factory), at any depth."""
        return [self._extract_python_function(node, file_path, source_lines, registered=registered)
                for node in self._routes_within(func, registered)]

    def _routes_within(self, func: Union[ast.FunctionDef, ast.AsyncFunctionDef],
                       registered: AbstractSet[str]) -> List[Union[ast.FunctionDef, ast.AsyncFunctionDef]]:
        """func 內部（不含 func 本身）的路由處理函式：有路由裝飾器，或以名稱出現在 registered（類別方法除外）。
        The route handlers inside func (func itself excluded): route-decorated, or named in registered (class
        methods excepted)."""
        methods = {id(item) for n in ast.walk(func) if isinstance(n, ast.ClassDef) for item in n.body}
        return [node for node in ast.walk(func)
                if node is not func and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and (any(self._is_route_decorator(dec) for dec in node.decorator_list)
                     or (id(node) not in methods and node.name in registered))]

    def _parse_js_ts_file(self, file_path: str) -> List[CodeSymbol]:
        """擷取 JS/TS 的函式、箭頭函式、含方法的類別，以及 HTTP 路由處理函式。
        Extracts JS/TS functions, arrows, classes with methods, and HTTP route handlers."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logger.warning(bi(f"無法讀取 {file_path}：{e}", f"Could not read {file_path}: {e}"))
            self.parse_failures.append(file_path)
            return []

        try:
            return extract_js_ts_symbols(content, file_path)
        except Exception as e:  # noqa: BLE001
            # 詞法分析器的任何意外錯誤（例如病態輸入）只略過這個檔案並回報為解析失敗（證據缺口），不中止整次執行
            # Any unexpected lexer error (e.g. a pathological input) only skips this file and reports it as a
            # parse failure (an evidence gap); it never aborts the whole run
            logger.warning(bi(f"無法分析 {file_path}（{type(e).__name__}），已略過：{e}",
                              f"Could not analyze {file_path} ({type(e).__name__}), skipped: {e}"))
            self.parse_failures.append(file_path)
            return []

    def _extract_python_function(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        file_path: str,
        source_lines: List[str],
        class_name: Optional[str] = None,
        registered: AbstractSet[str] = frozenset(),
    ) -> CodeSymbol:
        # 包含裝飾器：它們帶有審查者需要看到的路由路徑與授權守衛
        # Include decorators: they carry route paths and auth guards the reviewers need to see
        start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        end = node.end_lineno or start
        source_snippet = self._without_nested_routes(node, source_lines, start, end, registered)

        args = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        # *args / **kwargs 是函式契約的一部分；審查者與探測都需要它們
        # *args / **kwargs are part of the function's contract; reviewers and probes need them
        if node.args.vararg:
            args.append(f"*{node.args.vararg.arg}")
        kw_vararg = [f"**{node.args.kwarg.arg}"] if node.args.kwarg else []
        symbol_type = "method" if class_name else "function"
        full_name = f"{class_name}.{node.name}" if class_name else node.name

        docstring = ast.get_docstring(node)

        # 方法不會以裸名稱註冊（`view_func=self.x` 是屬性），所以只看函式
        # Methods are never registered by bare name (`view_func=self.x` is an attribute), so only functions count
        if any(self._is_route_decorator(dec) for dec in node.decorator_list) \
                or (class_name is None and node.name in registered):
            symbol_type = "route"

        return CodeSymbol(
            name=full_name,
            symbol_type=symbol_type,
            file_path=file_path,
            line_start=start,
            line_end=end,
            signature=f"{node.name}({', '.join(args + kw_vararg)})",
            docstring=docstring,
            source_code=source_snippet,
            parameters=args
        )

    def _without_nested_routes(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], source_lines: List[str],
                               start: int, end: int, registered: AbstractSet[str]) -> str:
        """第 start–end 行的原始碼，其中巢狀路由處理函式（Flask 工廠裡的 `@app.route` 或 `add_url_rule` 註冊的檢視函式）
        的本體縮成一行佔位註解。

        那些處理函式各自以 route 符號送審（`_nested_python_routes`），所以外層函式不必再帶一次它們的本體；
        裝飾器與 `def` 行保留（註冊的脈絡），佔位行寫出被省略的檔案行號，讓審查者仍能對應回檔案。
        結果仍是合法的 Python（本體是 `...`）。
        The source of lines start-end, with the body of each nested route handler (an `@app.route` or
        `add_url_rule` view in a Flask factory) collapsed into a one-line placeholder comment.

        Those handlers are reviewed as their own route symbols (`_nested_python_routes`), so the enclosing
        function need not carry their bodies again; the decorators and the `def` line stay (registration
        context) and the placeholder names the omitted file lines, so reviewers can still map back to the
        file. The result is still valid Python (the body is `...`)."""
        nested = self._routes_within(node, registered)
        # 只收合最外層的巢狀路由：更深的那些已經在它們的本體裡
        # Collapse only the outermost nested routes: deeper ones are already inside their bodies
        outermost = [n for n in nested if not any(o is not n and o.lineno < n.lineno <= (o.end_lineno or o.lineno)
                                                  for o in nested)]
        lines = source_lines[start - 1:end]
        # 由下往上替換，讓前面的行號維持有效
        # Replace bottom-up so earlier line numbers stay valid
        for route in sorted(outermost, key=lambda n: n.lineno, reverse=True):
            body_start, body_end = route.body[0].lineno, route.end_lineno or route.lineno
            if body_start <= route.lineno:
                continue  # 單行處理函式（`def f(): return 1`）已經夠短 ／ a one-line handler is already short
            # 沿用原本的縮排字元（tab 或空白），讓結果仍可解析
            # Reuse the original indentation characters (tabs or spaces) so the result still parses
            indent = source_lines[body_start - 1][:route.body[0].col_offset]
            lines[body_start - start:body_end - start + 1] = [
                f"{indent}...  # lines {body_start}-{body_end}: body of route handler `{route.name}`, listed separately"
            ]
        return "\n".join(lines)

    @staticmethod
    def _is_route_decorator(dec: ast.expr) -> bool:
        """`@app.get("/x")` 形式的註冊；`@mock.patch("x")` 或 `@cache.delete(k)` 不是路由。
        `@app.get("/x")`-style registrations; `@mock.patch("x")` or `@cache.delete(k)` are not routes."""
        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                and dec.func.attr in ROUTE_DECORATORS):
            return False
        receiver = dec.func.value
        name = (receiver.attr if isinstance(receiver, ast.Attribute) else getattr(receiver, "id", "")).lower()
        # 路由器接收者先判斷：`APIRouter(prefix=...)` 上的 `@router.get("")` 與不以 '/' 開頭的路徑都是路由
        # The router receiver is checked first: `@router.get("")` on an `APIRouter(prefix=...)` and paths
        # without a leading '/' are routes
        if name in _PY_ROUTE_RECEIVERS or name.endswith(("router", "_bp", "blueprint", "_app", "_api")):
            return True
        first = dec.args[0] if dec.args else next((k.value for k in dec.keywords if k.arg in ("path", "rule")), None)
        return isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.startswith("/")

    def _extract_python_class(
        self,
        node: ast.ClassDef,
        file_path: str,
        source_lines: List[str]
    ) -> CodeSymbol:
        # 包含裝飾器，與函式一致：它們帶有註冊／行為的脈絡
        # Include decorators, consistent with functions: they carry registration/behavior context
        start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        end = node.end_lineno or start
        source_snippet = "\n".join(source_lines[start - 1 : end])

        return CodeSymbol(
            name=node.name,
            symbol_type="class",
            file_path=file_path,
            line_start=start,
            line_end=end,
            signature=f"class {node.name}",
            docstring=ast.get_docstring(node),
            source_code=source_snippet,
            parameters=[]
        )
