import ast
import fnmatch
import logging
import os
import re
from bisect import bisect_right
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union
from vibeharness.core.models import CodeSymbol
from vibeharness.core.i18n import bi

logger = logging.getLogger("VibeHarness.ASTExtractor")

DEFAULT_MAX_FILES = 50
# 單一原始碼檔案超過此大小就略過（回報為證據缺口）：壓縮過的 bundle 與
# 產生的程式碼無法審查，而且 JS/TS 詞法分析器是逐字元的 Python 迴圈
# A single source file above this size is skipped (reported as an evidence gap): minified bundles and
# generated code are not reviewable, and the JS/TS lexer is a character-by-character Python loop
DEFAULT_MAX_FILE_BYTES = 1_000_000
# 絕不進入的目錄名稱（再加上任何以 '.' 開頭的名稱）
# Directory names never descended into (plus any name starting with '.')
SKIPPED_DIRS = {"venv", "__pycache__", "node_modules", "dist", "build", "site-packages"}
SOURCE_EXTENSIONS = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
# FastAPI/Starlette 動詞加上 Flask/Quart 的路由裝飾器
# FastAPI/Starlette verbs plus Flask/Quart route decorators
ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "route", "api_route", "websocket"}

# JS/TS 中辨識的 HTTP 動詞：router 方法（app.get(...)）與 Next.js 處理函式名稱
# HTTP verbs recognized in JS/TS, as router methods (app.get(...)) and Next.js handler names
_JS_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}
# 屬於控制流程而非方法宣告的 `identifier(...) {` 序列
# `identifier(...) {` sequences that are control flow, not method declarations
_JS_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "const", "let",
                        "var", "new", "typeof", "delete", "void", "do", "else", "try", "class", "await", "yield"}
# 這些關鍵字之後的 `/` 是正規表達式字面值的開頭，不是除法
# After these keywords a `/` starts a regex literal, not division
_JS_REGEX_KEYWORDS = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
                      "case", "do", "else", "yield", "await"}
_JS_IDENTIFIER = r"[A-Za-z0-9_$]+"
# 可能含 JSX 的副檔名：.ts/.mts/.cts 不算（`<T>x` 是型別斷言，不是 JSX）
# Extensions that may hold JSX: .ts/.mts/.cts are excluded (`<T>x` is a type assertion there, not JSX)
_JSX_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".tsx")
# JSX 標籤名稱（含成員與命名空間：`Foo.Bar`、`svg:rect`）、屬性名稱與結尾標籤
# JSX tag names (members and namespaces included: `Foo.Bar`, `svg:rect`), attribute names and closing tags
_JSX_NAME_RE = re.compile(r"[A-Za-z][\w$.:-]*")
_JSX_ATTR_RE = re.compile(r"[A-Za-z_$][\w$:.-]*")
_JSX_CLOSE_RE = re.compile(r"</\s*([A-Za-z][\w$.:-]*)?\s*>")
# JSX 巢狀層數上限（每層是兩個遞迴呼叫）；更深的 `<` 照一般程式碼分析
# Maximum JSX nesting depth (each level is two recursive calls); a deeper `<` is lexed as plain code
_JSX_MAX_DEPTH = 120
# 每個檔案最多容許幾次失敗的 JSX 嘗試（每次可能掃到檔尾）；用完後其餘的 `<` 照一般程式碼分析，避免平方時間
# How many failed JSX attempts a file may have (each may scan to the end of the file); once spent, the remaining
# `<` are lexed as plain code, which avoids quadratic time
_JSX_MAX_FAILURES = 32
# 路由註冊方法：HTTP 動詞加上 Express 的 `all`（`route` 另外處理：鏈式與物件形式）
# Route registration methods: the HTTP verbs plus Express's `all` (`route` is handled separately: chained and object forms)
_JS_ROUTE_METHODS = _JS_HTTP_VERBS | {"all"}
# 常見的路由器接收者名稱：路徑可以是識別字（`app.post(USERS_PATH, h)`）或空字串（`router.get("", h)`）
# Common router receiver names: the path may be an identifier (`app.post(USERS_PATH, h)`) or empty (`router.get("", h)`)
_JS_ROUTE_RECEIVERS = {"app", "router", "server", "fastify", "instance", "api", "routes", "route", "r",
                       "koa", "hono", "elysia", "srv", "application"}
# 以這些字尾結尾的名稱也視為路由器（usersRouter、adminApp、v1Routes）
# Names ending with these suffixes count as routers too (usersRouter, adminApp, v1Routes)
_JS_ROUTE_RECEIVER_SUFFIXES = ("router", "routes", "app", "server")
# HTTP 用戶端：`axios.get('/api/users', cb)` 是發出請求，不是註冊路由
# HTTP clients: `axios.get('/api/users', cb)` sends a request, it does not register a route
_JS_HTTP_CLIENTS = {"axios", "http", "https", "client", "httpclient", "request", "req", "res", "response",
                    "supertest", "superagent", "agent", "ky", "got", "fetch", "fetcher", "needle", "$http",
                    "$", "jquery", "rest", "msw", "mock", "nock"}
# 變數綁定：`name[: Type] = <運算式>`，運算式可延續到以 `.` 開頭的下一行
# A variable binding: `name[: Type] = <expression>`, the expression may continue on a next line starting with `.`
_JS_BINDING_RE = re.compile(rf"(?<![\w$.])({_JS_IDENTIFIER})\s*(?::[^=;\n]*)?=(?![=>])\s*((?:[^;\n]|\n\s*\.)*)")
# 綁定運算式中任何位置出現這些工廠時，該變數就是路由器（`require('express').Router()`、`new Koa()`）
# A binding whose expression contains one of these factories anywhere is a router (`require('express').Router()`, `new Koa()`)
_JS_ROUTER_FACTORY_RE = re.compile(
    r"(?:\bexpress\s*\(|\bRouter\s*\(|\b[Ff]astify\s*\(|\bnew\s+(?:Koa|Hono|Elysia|Router|KoaRouter)\b|"
    r"\bHono\s*\(|\bElysia\s*\(|\bKoaRouter\s*\(|\bcreateRouter\s*\(|\bpolka\s*\(|\brestify\s*\.\s*createServer\s*\()"
)
# 綁定運算式中出現這些時，該變數是 HTTP 用戶端（`const api = axios.create()`）
# A binding whose expression contains one of these is an HTTP client (`const api = axios.create()`)
_JS_CLIENT_FACTORY_RE = re.compile(
    r"\b(?:axios\s*\.\s*create|ky\s*\.\s*(?:create|extend)|got\s*\.\s*extend|supertest|superagent)\b"
)
# Next.js 的別名匯出：`export { handler as GET, handler as POST }`（`... from '...'` 的轉匯出除外）
# Next.js alias exports: `export { handler as GET, handler as POST }` (re-exports `... from '...'` excluded)
_JS_EXPORT_LIST_RE = re.compile(r"\bexport\s*\{([^{}]*)\}(?!\s*from\b)")
# 單行的正規表達式字面值（含字元類別與跳脫）加上旗標，用於辨識正規表達式路由路徑
# A single-line regex literal (character classes and escapes included) plus flags, to recognize regex route paths
_JS_REGEX_LITERAL_RE = re.compile(r"/(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\[\n])+/[A-Za-z]*")
# 即使路徑不是字串字面值也會註冊路由的 Python 裝飾器接收者
# Python decorator receivers that register routes even when the path is not a string literal
_PY_ROUTE_RECEIVERS = {"app", "router", "api", "bp", "blueprint", "application", "server"}


class ASTExtractor:
    """
    把原始碼解析成結構化的 CodeSymbol 物件。
    Python 以原生 AST 解析。JavaScript/TypeScript 由一個不依賴外部套件的詞法分析器解析：
    它先把字串、樣板字面值、註解與正規表達式字面值清空（因此註解與字面值都無法製造幻影宣告），
    再以真正的大括號／小括號配對擷取宣告，給出準確的行範圍而不是固定行數的視窗。
    Parses source code into structured CodeSymbol objects.
    Python is parsed with the native AST. JavaScript/TypeScript is parsed by a dependency-free
    lexer that blanks out strings, template literals, comments and regex literals (so neither
    comments nor literals can create phantom declarations) and then extracts declarations with
    real brace/parenthesis matching, giving accurate line spans instead of fixed-line windows.
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
        # 被 include/exclude 樣式或 only_files 篩選器排除的原始碼檔案（不是證據缺口：
        # 是使用者要求排除它們的）
        # Source files dropped by include/exclude patterns or the only_files filter (not evidence gaps:
        # the user asked for them to be left out)
        self.filtered_out: int = 0
        # 在 max_files 上限之內的原始碼檔案（靜態 AI 安全規則掃描的正是這些）
        # Source files within the max_files cap (the static AI-security rules scan exactly these)
        self.analyzed_files: List[str] = []

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
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        only_files: Optional[Iterable[str]] = None,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> List[CodeSymbol]:
        """解析一個目錄樹（最多 max_files 個原始碼檔案）或單一原始碼檔案。

        `include` / `exclude` 是以相對於 dir_path 的路徑（正斜線；`**` 沒有特殊意義，fnmatch 的 `*`
        本來就能跨越目錄）比對的 glob 樣式，例如 `src/**/*.py` 或 `tests/*`。`only_files` 把走訪
        限制在那些絕對路徑（例如 git diff 觸及的檔案）。大於 max_file_bytes 的檔案列在
        `oversized_files` 中且不解析。
        Parses a directory tree (up to max_files source files) or a single source file.

        `include` / `exclude` are glob patterns matched against the path relative to dir_path (forward
        slashes; `**` is not special, fnmatch's `*` already crosses directories), e.g. `src/**/*.py`
        or `tests/*`. `only_files` restricts the walk to those absolute paths (e.g. the files a git diff
        touched). Files larger than max_file_bytes are listed in `oversized_files` and not parsed.
        """
        self.parse_failures, self.skipped_files, self.analyzed_files = [], [], []
        self.oversized_files, self.filtered_out = [], 0
        if os.path.isfile(dir_path):
            if dir_path.lower().endswith(SOURCE_EXTENSIONS):
                if self._too_large(dir_path, max_file_bytes):
                    self.oversized_files = [dir_path]
                    return []
                self.analyzed_files = [dir_path]
            return self.parse_file(dir_path)
        source_files: List[str] = []
        wanted = {os.path.normcase(os.path.abspath(p)) for p in only_files} if only_files is not None else None
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in SKIPPED_DIRS)
            for f in sorted(files):
                if not f.lower().endswith(SOURCE_EXTENSIONS):
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, dir_path).replace(os.sep, "/")
                if (wanted is not None and os.path.normcase(os.path.abspath(full)) not in wanted) \
                        or not self._selected(rel, include, exclude):
                    self.filtered_out += 1
                    continue
                if self._too_large(full, max_file_bytes):
                    self.oversized_files.append(full)
                    continue
                source_files.append(full)
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
            all_symbols.extend(self.parse_file(full_path))
        return all_symbols

    @staticmethod
    def _selected(rel_path: str, include: Optional[List[str]], exclude: Optional[List[str]]) -> bool:
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
        source_lines = source.splitlines()

        for node in self._py_definitions(tree.body):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbols.append(self._extract_python_function(node, file_path, source_lines))
                symbols.extend(self._nested_python_routes(node, file_path, source_lines))
            elif isinstance(node, ast.ClassDef):
                symbols.append(self._extract_python_class(node, file_path, source_lines))
                for item in self._py_definitions(node.body):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        symbols.append(self._extract_python_function(item, file_path, source_lines, class_name=node.name))
                        symbols.extend(self._nested_python_routes(item, file_path, source_lines))

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

    def _nested_python_routes(self, func: Union[ast.FunctionDef, ast.AsyncFunctionDef], file_path: str,
                              source_lines: List[str]) -> List[CodeSymbol]:
        """函式內部以路由裝飾器註冊的處理函式（Flask `create_app()` 工廠中的 `@app.route`），任意深度。
        Route handlers registered with a route decorator inside a function (`@app.route` in a Flask
        `create_app()` factory), at any depth."""
        routes: List[CodeSymbol] = []
        for node in ast.walk(func):
            if node is func or not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(self._is_route_decorator(dec) for dec in node.decorator_list):
                routes.append(self._extract_python_function(node, file_path, source_lines))
        return routes

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

        masked = self._mask_source(content, jsx=file_path.lower().endswith(_JSX_EXTENSIONS))
        line_offsets = [0] + [i + 1 for i, ch in enumerate(masked) if ch == "\n"]

        def line_of(pos: int) -> int:
            return bisect_right(line_offsets, pos)

        functions = self._extract_js_functions(content, masked, file_path, line_of)
        routes = self._extract_js_routes(content, masked, file_path, line_of, functions)
        # Next.js 動詞處理函式被改標為路由；只保留一個符號，讓它只被審查一次
        # A Next.js verb handler is retagged as a route; keep one symbol so it is reviewed once
        retagged = {(r.name, r.line_start) for r in routes}
        return [f for f in functions if (f.name, f.line_start) not in retagged] + routes

    # --- JS/TS 詞法分析輔助函式 ---
    # --- JS/TS lexing helpers ---------------------------------------------------

    @staticmethod
    def _mask_source(source: str, jsx: bool = False) -> str:
        """把註解、字串／樣板／正規表達式字面值清空，同時保留長度與換行。

        結構性掃描（宣告的正規表達式、大括號配對）在清空後的文字上執行，因此被註解掉的
        路由或含有 'function fake()' 的字串都無法製造幻影。`jsx=True`（.js/.jsx/.tsx 等可能含 JSX 的檔案）時，
        位於運算式位置的 JSX 元素會被當成 JSX 解析：子元素文字被清空，因此文字裡的 `/*`、反引號或引號
        不會開啟註解或字面值；不是合法 JSX 的 `<`（例如 TS 泛型）會還原成一般詞法分析。
        Blanks out comments, string/template/regex literals while preserving length and newlines.

        Structural scans (declaration regexes, brace matching) run on the masked text so a
        commented-out route or a string containing 'function fake()' cannot create phantoms. With
        `jsx=True` (.js/.jsx/.tsx and other files that may hold JSX) a JSX element in expression position is
        parsed as JSX: its child text is blanked, so a `/*`, a backtick or a quote in that text opens no
        comment or literal; a `<` that is not valid JSX (e.g. a TS generic) falls back to plain lexing.
        """
        out = list(source)
        ASTExtractor._mask_code(source, out, 0, [_JSX_MAX_FAILURES] if jsx else None, 0)
        return "".join(out)

    @staticmethod
    def _mask_code(source: str, out: List[str], i: int, jsx: Optional[List[int]], depth: int) -> Optional[int]:
        """從 i 起詞法分析程式碼並清空其中的註解與字面值。depth 為 0 時處理到檔尾並回傳 n；
        depth > 0 時是在 JSX 運算式容器 `{...}` 裡（i 指向 `{` 之後），回傳配對的 `}` 之後的位置，
        若到檔尾都沒有閉合則回傳 None。`jsx` 是剩餘的 JSX 失敗次數（單一元素的串列，整個檔案共用），None 表示不辨識 JSX。
        Lexes code from i, blanking its comments and literals. At depth 0 it runs to the end of the file and
        returns n; at depth > 0 it is inside a JSX expression container `{...}` (i points just after the `{`)
        and returns the position after the matching `}`, or None when the file ends before it closes. `jsx` is
        the remaining JSX failure budget (a one-element list shared by the whole file); None disables JSX."""
        n = len(source)
        prev_char = "{" if depth else ""  # 最後看到的有意義程式碼字元 ／ last significant code character seen
        prev_word = ""       # 最後看到的識別字／關鍵字 ／ last identifier/keyword seen
        # prev_char 之前的兩個有意義字元：用來辨識後置的 `a++ / 2`
        # The two significant characters before prev_char: they recognize a postfix `a++ / 2`
        prev2 = prev3 = ""
        braces = 0           # 運算式容器內未閉合的 `{` 數 ／ unclosed `{` inside an expression container
        while i < n:
            c = source[i]
            nxt = source[i + 1] if i + 1 < n else ""
            if c == "/" and nxt == "/":
                while i < n and source[i] != "\n":
                    out[i] = " "
                    i += 1
                continue
            if c == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                i += 2
                while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                    if source[i] != "\n":
                        out[i] = " "
                    i += 1
                i += 2
                continue
            glued = i > 0 and (source[i - 1].isalnum() or source[i - 1] in "_$") and prev_word not in _JS_REGEX_KEYWORDS
            if c in "\"'" and not glued:
                # 緊貼在識別字後的引號（JSX 文字中的 `Don't`）不可能開啟 JS 字串
                # A quote glued to an identifier (`Don't` in JSX text) cannot open a JS string
                i = ASTExtractor._mask_quoted(source, out, i, c)
                prev_char, prev_word = c, ""
                continue
            if c == "`":
                i = ASTExtractor._mask_template(source, out, i)
                prev_char, prev_word = c, ""
                continue
            if c in "/<":
                # 值結尾 token 之後是運算子位置（`/` 是除法、`<` 是比較），除非該 token 是會開啟運算式的
                # 關鍵字（return /x/、typeof /y/、return <p/>）
                # After a value-ending token we are in operator position (`/` divides, `<` compares), unless
                # the token is a keyword that opens an expression (return /x/, typeof /y/, return <p/>)
                after_value = bool(prev_char) and (prev_char.isalnum() or prev_char in ")]}$_.\"'`")
                # 值之後的後置 ++／-- 仍是值：`a++ / 2` 是除法
                # A postfix ++ / -- after a value is still a value: `a++ / 2` is division
                if prev_char in ("+", "-") and prev2 == prev_char and prev3 and (prev3.isalnum() or prev3 in ")]_$"):
                    after_value = True
                expression_pos = not after_value or prev_word in _JS_REGEX_KEYWORDS
                if c == "<" and jsx is not None and jsx[0] > 0 and expression_pos and depth < _JSX_MAX_DEPTH \
                        and (nxt.isalpha() or nxt == ">"):
                    end = ASTExtractor._mask_jsx(source, out, i, depth + 1, jsx)
                    if end is not None:
                        # JSX 元素是一個值 ／ A JSX element is a value
                        i = end
                        prev3, prev2, prev_char, prev_word = "", "", ")", ""
                        continue
                # 正規表達式字面值還是除法？`</tag>` 與 `/>` 是 JSX，正規表達式字面值也絕不跨行
                # Regex literal or division? `</tag>` and `/>` are JSX, and a regex literal never spans a line break
                if c == "/" and nxt not in ("", "/", "*", ">") and prev_char != "<" and expression_pos:
                    end_re = ASTExtractor._mask_regex(source, out, i)
                    if end_re is not None:
                        i = end_re
                        prev_char, prev_word = c, ""
                        continue
            if depth:
                if c == "{":
                    braces += 1
                elif c == "}":
                    if braces == 0:
                        return i + 1
                    braces -= 1
            if not c.isspace():
                word_continues = prev_char and (prev_char.isalnum() or prev_char in "_$")
                if c.isalnum() or c in "_$":
                    prev_word = (prev_word + c) if word_continues else c
                else:
                    prev_word = ""
                prev3, prev2, prev_char = prev2, prev_char, c
            i += 1
        return None if depth else n

    @staticmethod
    def _mask_jsx(source: str, out: List[str], i: int, depth: int, budget: List[int]) -> Optional[int]:
        """把 i 處開始的 JSX 元素當成 JSX 處理，回傳元素結束後的位置；不是合法的 JSX 時還原 out 並回傳 None。

        屬性字串與子元素文字被清空（保留換行）；`{...}` 運算式容器與巢狀元素遞迴處理。開頭標籤裡出現
        非屬性語法（`<T,>`）、結尾標籤名稱不符或到檔尾都沒有閉合時視為不是 JSX，讓呼叫端照一般程式碼分析。
        Treats the JSX element starting at i as JSX and returns the position after it; when it is not valid
        JSX, out is restored and None is returned.

        Attribute strings and child text are blanked (newlines kept); `{...}` expression containers and
        nested elements are handled recursively. Non-attribute syntax in the opening tag (`<T,>`), a
        mismatched closing tag name, or reaching the end of the file unclosed means it is not JSX, so the
        caller lexes it as plain code."""
        n = len(source)

        def fail(upto: int) -> Optional[int]:
            # 呼叫端還沒碰過 i 之後的位置，所以原文就是正確的還原值
            # The caller has not touched anything after i yet, so the source is the right value to restore
            out[i:upto] = source[i:upto]
            budget[0] -= 1
            return None

        m = _JSX_NAME_RE.match(source, i + 1)
        name = m.group(0) if m else ""
        j = m.end() if m else i + 1
        # 開頭標籤：屬性、`{...props}` 展開，直到 `>` 或 `/>`
        # The opening tag: attributes and `{...props}` spreads, up to `>` or `/>`
        while True:
            while j < n and source[j].isspace():
                j += 1
            if j >= n:
                return fail(n)
            ch = source[j]
            if ch == "/" and source[j + 1:j + 2] == ">" and name:
                return j + 2  # 自我閉合 ／ self-closing
            if ch == ">":
                j += 1
                break
            if not name:
                return fail(j)
            if ch == "{":
                end = ASTExtractor._mask_code(source, out, j + 1, budget, depth)
                if end is None:
                    return fail(n)
                j = end
                continue
            attr = _JSX_ATTR_RE.match(source, j)
            if attr is None:
                return fail(j)
            j = attr.end()
            k = j
            while k < n and source[k].isspace():
                k += 1
            if k >= n or source[k] != "=":
                continue  # 沒有值的布林屬性 ／ a boolean attribute without a value
            k += 1
            while k < n and source[k].isspace():
                k += 1
            if k < n and source[k] in "\"'":
                close = source.find(source[k], k + 1)
                if close < 0:
                    return fail(n)
                for p in range(k + 1, close):
                    if source[p] != "\n":
                        out[p] = " "
                j = close + 1
            elif k < n and source[k] == "{":
                end = ASTExtractor._mask_code(source, out, k + 1, budget, depth)
                if end is None:
                    return fail(n)
                j = end
            else:
                return fail(k)
        # 子元素：文字、`{...}` 運算式容器與巢狀元素，直到名稱相符的結尾標籤
        # Children: text, `{...}` expression containers and nested elements, up to the closing tag of the same name
        while True:
            while j < n and source[j] not in "<{":
                if source[j] != "\n":
                    out[j] = " "
                j += 1
            if j >= n:
                return fail(n)
            if source[j] == "{":
                end = ASTExtractor._mask_code(source, out, j + 1, budget, depth)
                if end is None:
                    return fail(n)
                j = end
                continue
            if source[j + 1:j + 2] == "/":
                closing = _JSX_CLOSE_RE.match(source, j)
                if closing is None or (closing.group(1) or "") != name:
                    return fail(j)
                return closing.end()
            end = None if depth >= _JSX_MAX_DEPTH else ASTExtractor._mask_jsx(source, out, j, depth + 1, budget)
            if end is None:
                # JSX 子元素文字裡不可能有落單的 `<`：這不是 JSX
                # A stray `<` cannot appear in JSX child text: this is not JSX
                return fail(j)
            j = end

    @staticmethod
    def _mask_quoted(source: str, out: List[str], i: int, quote: str) -> int:
        """清空 '...' 或 "..." 字面值；它在結尾引號或未跳脫的換行處結束（JS 字串不能跨行，所以落單的引號絕不會吞掉檔案其餘部分）。
        Masks a '...' or "..." literal; it ends at the closing quote or an unescaped newline
        (JS strings cannot span lines, so a stray quote never swallows the rest of the file)."""
        n = len(source)
        i += 1
        while i < n and source[i] != quote:
            if source[i] == "\n":
                return i  # 未結束：換行結束它 ／ unterminated: the line break ends it
            if source[i] == "\\":
                out[i] = " "
                i += 1
            if i < n and source[i] != "\n":
                out[i] = " "
            i += 1
        if i < n:
            out[i] = " "  # 結尾引號 ／ closing quote
        return i + 1

    @staticmethod
    def _mask_template(source: str, out: List[str], i: int) -> int:
        n = len(source)
        i += 1
        while i < n and source[i] != "`":
            if source[i] == "\\":
                out[i] = " "
                i += 1
                if i < n and source[i] != "\n":
                    out[i] = " "
                i += 1
                continue
            if source[i] == "$" and i + 1 < n and source[i + 1] == "{":
                out[i] = out[i + 1] = " "
                i = ASTExtractor._mask_substitution(source, out, i + 2)
                continue
            if source[i] != "\n":
                out[i] = " "
            i += 1
        if i < n:
            out[i] = " "  # 結尾反引號 ／ closing backtick
        return i + 1

    @staticmethod
    def _mask_substitution(source: str, out: List[str], i: int) -> int:
        """清空樣板字面值的 `${...}` 插值（i 指向 `${` 之後），回傳結尾 `}` 之後的位置。

        插值內是程式碼：其中的字串、巢狀樣板、註解與正規表達式字面值都正確詞法分析，
        因此 `${s.replace(/\\{/g, "")}` 或 `${x || "{"}` 裡落單的 `{` 不會吞掉檔案其餘部分。
        Blanks a template literal's `${...}` interpolation (i points just after `${`) and returns the
        position after its closing `}`.

        The interpolation is code: strings, nested templates, comments and regex literals inside it are
        lexed properly, so a stray `{` in `${s.replace(/\\{/g, "")}` or `${x || "{"}` cannot swallow the
        rest of the file."""
        n = len(source)
        start = i
        depth = 1
        prev_char = "{"
        while i < n:
            c = source[i]
            nxt = source[i + 1] if i + 1 < n else ""
            if c == "/" and nxt == "/":
                while i < n and source[i] != "\n":
                    i += 1
                continue
            if c == "/" and nxt == "*":
                end = source.find("*/", i + 2)
                i = n if end < 0 else end + 2
                continue
            if c in "\"'":
                i = ASTExtractor._mask_quoted(source, out, i, c)
                prev_char = c
                continue
            if c == "`":
                i = ASTExtractor._mask_template(source, out, i)
                prev_char = c
                continue
            if c == "/" and not (prev_char.isalnum() or prev_char in ")]}$_.\"'`"):
                end_re = ASTExtractor._mask_regex(source, out, i)
                if end_re is not None:
                    i = end_re
                    prev_char = "/"
                    continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            if not c.isspace():
                prev_char = c
            i += 1
        # 整個插值（含結尾的 '}'，那是樣板語法而不是程式碼）都清空
        # The whole interpolation (including its closing '}', template syntax rather than code) is blanked
        for k in range(start, min(i, n)):
            if source[k] != "\n":
                out[k] = " "
        return i

    @staticmethod
    def _mask_regex(source: str, out: List[str], i: int) -> Optional[int]:
        """清空正規表達式字面值；若它沒有在同一行結束則回傳 None（什麼都不清空）。
        Masks a regex literal; None (nothing masked) when it is not closed on its own line."""
        n = len(source)
        j = i + 1
        in_class = False
        while j < n and source[j] != "\n":
            if source[j] == "\\":
                j += 2
                continue
            if source[j] == "[":
                in_class = True
            elif source[j] == "]":
                in_class = False
            elif source[j] == "/" and not in_class:
                break
            j += 1
        if j >= n or source[j] != "/":
            return None
        i += 1
        in_class = False
        while i < n:
            if source[i] == "\\":
                out[i] = " "
                i += 1
                if i < n and source[i] != "\n":
                    out[i] = " "
                i += 1
                continue
            if source[i] == "[":
                in_class = True
            elif source[i] == "]":
                in_class = False
            elif source[i] == "/" and not in_class:
                out[i] = " "
                i += 1
                break
            if i < n and source[i] != "\n":
                out[i] = " "
            i += 1
        while i < n and (source[i].isalpha()):
            out[i] = " "  # 旗標（g、i、m、...） ／ flags (g, i, m, ...)
            i += 1
        return i

    @staticmethod
    def _match_delim(masked: str, open_pos: int, open_ch: str, close_ch: str) -> Optional[int]:
        """與 open_pos 處分隔符配對的分隔符位置（字面值／註解已清空）。
        Position of the delimiter matching the one at open_pos (literals/comments are blanked)."""
        depth = 0
        for i in range(open_pos, len(masked)):
            c = masked[i]
            if c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return i
        return None

    @staticmethod
    def _split_params(params_text: str) -> List[str]:
        """以頂層逗號切分參數清單；去掉預設值與 TS 型別註記。
        Splits a parameter list on top-level commas; drops defaults and TS annotations."""
        params: List[str] = []
        depth = 0
        current: List[str] = []
        for c in params_text:
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            if c == "," and depth == 0:
                params.append("".join(current))
                current = []
            else:
                current.append(c)
        params.append("".join(current))
        cleaned = []
        for p in params:
            p = p.split("=")[0].split(":")[0].strip()
            if p:
                cleaned.append(p)
        return cleaned

    def _snippet(self, content: str, line_of, start_pos: int, end_pos: int, file_path: str,
                 name: str, symbol_type: str, parameters: Optional[List[str]] = None,
                 signature: Optional[str] = None) -> CodeSymbol:
        start_line, end_line = line_of(start_pos), line_of(end_pos)
        lines = content.splitlines()
        return CodeSymbol(
            name=name,
            symbol_type=symbol_type,
            file_path=file_path,
            line_start=start_line,
            line_end=end_line,
            signature=signature or f"{name}({', '.join(parameters or [])})",
            source_code="\n".join(lines[start_line - 1:end_line]),
            parameters=parameters or []
        )

    # --- JS/TS 擷取 ---
    # --- JS/TS extraction ---------------------------------------------------------

    def _extract_js_functions(self, content: str, masked: str, file_path: str, line_of) -> List[CodeSymbol]:
        symbols: List[CodeSymbol] = []
        taken: List[Tuple[int, int]] = []  # 已包含在某個符號內的清空文字範圍 ／ masked-text ranges already inside a symbol

        def overlaps(start: int, end: int) -> bool:
            return any(start < t_end and end > t_start for t_start, t_end in taken)

        # 函式宣告與函式運算式：
        # [export] [default] [async] function[*] name[<T>](params)[: ReturnType] {...}
        # function declarations and function expressions:
        # [export] [default] [async] function[*] name[<T>](params)[: ReturnType] {...}
        fn_re = re.compile(
            rf"(?<![\w$.])(?:export\s+)?(?:default\s+)?(?:async\s+)?\bfunction\b\s*\*?\s*"
            rf"({_JS_IDENTIFIER})\s*(?:<[^(){{}};]*>\s*)?\("
        )
        for m in fn_re.finditer(masked):
            open_paren = m.end() - 1
            close_paren = self._match_delim(masked, open_paren, "(", ")")
            if close_paren is None:
                continue
            name = m.group(1)
            params = self._split_params(content[open_paren + 1:close_paren])
            body_pos = self._body_after_params(masked, close_paren)
            if body_pos is None or masked[body_pos] == ";" or re.match(
                    r"(?:export|function|declare|async)\b", masked[body_pos:body_pos + 8]):
                # 沒有本體的宣告（TS 多載簽章、`declare function`）：實作本身才是符號
                # A declaration without a body (a TS overload signature, `declare function`): the implementation is the symbol
                continue
            end_pos = close_paren
            if masked[body_pos] == "{":
                end_pos = self._match_delim(masked, body_pos, "{", "}") or close_paren
            else:
                # 直接用在運算式陳述式中的函式運算式
                # a function expression used directly in an expression statement
                end_pos = self._end_of_statement(masked, body_pos)
            if overlaps(m.start(), end_pos):
                continue
            taken.append((m.start(), end_pos))
            symbols.append(self._snippet(
                content, line_of, m.start(), end_pos, file_path, name, "function", params
            ))

        # 指派給變數的箭頭函式：[export] [const|let|var] name = [async] (params) => body
        # arrow functions assigned to variables: [export] [const|let|var] name = [async] (params) => body
        for arrow_pos in [m.start() for m in re.finditer(r"=>", masked)]:
            start_pos, name, close_paren = self._arrow_declaration_back(masked, arrow_pos)
            if start_pos is None or name is None:
                continue
            body_pos = self._skip_ws(masked, arrow_pos + 2)
            if body_pos is None:
                continue
            if masked[body_pos] == "{":
                end_pos = self._match_delim(masked, body_pos, "{", "}") or arrow_pos + 1
            else:
                end_pos = self._end_of_statement(masked, body_pos)
            if overlaps(start_pos, end_pos):
                continue
            taken.append((start_pos, end_pos))
            arrow_params: List[str] = []
            if close_paren is not None:
                open_paren = self._find_open_paren(masked, close_paren)
                arrow_params = self._split_params(content[open_paren + 1:close_paren])
            symbols.append(self._snippet(
                content, line_of, start_pos, end_pos, file_path, name, "function", arrow_params
            ))

        # 含方法的類別：[export] [abstract] class Name [...] { ... }
        # classes with methods: [export] [abstract] class Name [...] { ... }
        class_re = re.compile(rf"(?:export\s+)?(?:abstract\s+)?class\s+({_JS_IDENTIFIER})[^{{;]*\{{")
        for m in class_re.finditer(masked):
            open_brace = m.end() - 1
            close_brace = self._match_delim(masked, open_brace, "{", "}")
            if close_brace is None:
                continue
            symbols.append(self._snippet(
                content, line_of, m.start(), close_brace, file_path, m.group(1), "class", [],
                signature=f"class {m.group(1)}"
            ))
            symbols.extend(self._extract_js_methods(content, masked, file_path, line_of, m.group(1),
                                                    open_brace + 1, close_brace))
        return symbols

    def _extract_js_methods(self, content: str, masked: str, file_path: str, line_of,
                            class_name: str, body_start: int, body_end: int) -> List[CodeSymbol]:
        """類別主體頂層的方法：[modifiers] name(params) { ... }。
        Methods at the top level of a class body: [modifiers] name(params) { ... }."""
        symbols: List[CodeSymbol] = []
        pos = body_start
        while pos < body_end:
            if not masked[pos].isspace():
                pos += 1
                continue
            m = re.match(
                rf"\s+((?:(?:public|private|protected|static|async|override|readonly|abstract)\s+|\*\s*)*"
                rf"({_JS_IDENTIFIER}))\s*(?:<[^(){{}};]*>\s*)?\(",
                masked[pos:body_end],
            )
            if not m:
                pos += 1
                continue
            name = m.group(2)
            if name in _JS_CONTROL_KEYWORDS:
                pos += 1
                continue
            open_paren = pos + m.end() - 1
            close_paren = self._match_delim(masked, open_paren, "(", ")")
            if close_paren is None:
                pos += 1
                continue
            body_pos = self._body_after_params(masked, close_paren)
            if body_pos is None or masked[body_pos] != "{":
                pos += 1
                continue
            close_body = self._match_delim(masked, body_pos, "{", "}")
            if close_body is None or close_body > body_end:
                pos += 1
                continue
            params = self._split_params(content[open_paren + 1:close_paren])
            symbols.append(self._snippet(
                content, line_of, pos + 1, close_body, file_path, f"{class_name}.{name}", "method", params
            ))
            pos = close_body + 1
        return symbols

    def _extract_js_routes(self, content: str, masked: str, file_path: str, line_of,
                           functions: List[CodeSymbol]) -> List[CodeSymbol]:
        """<router>.<verb>(path, handler) 呼叫、鏈式 `app.route('/x').get(h)`、物件形式
        `server.route({method, path})` 與 hapi 的陣列形式 `server.route([{...}, {...}])`，加上 Next.js
        以動詞命名（或以別名匯出）的處理函式。

        已知的路由器接收者（常見名稱、`*Router`／`*App` 等名稱，以及綁定運算式中含有
        express()/Router()/fastify()/new Koa()/... 的變數）接受以 `/` 開頭的字串、空字串、含 `/` 的
        樣板字面值，或（有處理函式引數時）識別字路徑或正規表達式字面值。其他任何接收者只有在第一個引數是 `/` 開頭的
        路徑、而且後面跟著像處理函式的引數時才算；HTTP 用戶端（axios、`axios.create()` 的結果…）
        永遠不算。因此 `map.get('key')`、`headers.get("authorization")` 與 `cache.delete(key)` 都不是路由。
        <router>.<verb>(path, handler) calls, chained `app.route('/x').get(h)`, the object form
        `server.route({method, path})` and hapi's array form `server.route([{...}, {...}])`, plus Next.js
        verb-named (or alias-exported) handlers.

        Known router receivers (common names, `*Router` / `*App`-style names, and variables whose binding
        expression contains express()/Router()/fastify()/new Koa()/...) accept a string starting with `/`,
        an empty string, a template literal containing `/`, or (with a handler argument) an identifier path
        or a regex literal.
        Any other receiver counts only when the first argument is a `/` path followed by a handler-like
        argument; HTTP clients (axios, the result of `axios.create()`, ...) never count. So `map.get('key')`,
        `headers.get("authorization")` and `cache.delete(key)` are not routes."""
        symbols: List[CodeSymbol] = []
        routers, clients = self._js_router_bindings(masked)

        def is_router(receiver: str) -> bool:
            low = receiver.lower()
            return receiver in routers or low in _JS_ROUTE_RECEIVERS or low.endswith(_JS_ROUTE_RECEIVER_SUFFIXES)

        verbs = "|".join(sorted(_JS_ROUTE_METHODS))
        route_re = re.compile(rf"(?:^|[^.\w$])(({_JS_IDENTIFIER})\.({verbs}))\s*\(")
        for m in route_re.finditer(masked):
            receiver, verb = m.group(2), m.group(3)
            if receiver in clients or receiver.lower() in _JS_HTTP_CLIENTS or receiver in _JS_CONTROL_KEYWORDS:
                continue
            open_paren = m.end() - 1
            close_paren = self._match_delim(masked, open_paren, "(", ")")
            if close_paren is None:
                continue
            path = self._route_path(content, masked, open_paren, close_paren, is_router(receiver))
            if path is None:
                continue
            name = f"{verb.upper()} {path}"
            symbols.append(self._snippet(
                content, line_of, m.start(1), close_paren, file_path, name, "route", [],
                signature=name
            ))
        symbols.extend(self._js_route_method_calls(content, masked, file_path, line_of, clients))
        symbols.extend(self._nextjs_handlers(masked, functions))
        return symbols

    @staticmethod
    def _js_router_bindings(masked: str) -> Tuple[Set[str], Set[str]]:
        """綁定運算式中含有路由器工廠的變數，以及含有 HTTP 用戶端工廠的變數。
        Variables whose binding expression contains a router factory, and those containing an HTTP-client factory."""
        routers: Set[str] = set()
        clients: Set[str] = set()
        for b in _JS_BINDING_RE.finditer(masked):
            if _JS_CLIENT_FACTORY_RE.search(b.group(2)):
                clients.add(b.group(1))
            elif _JS_ROUTER_FACTORY_RE.search(b.group(2)):
                routers.add(b.group(1))
        return routers, clients

    @staticmethod
    def _top_level_args(content: str, masked: str, open_paren: int, close_paren: int) -> List[Tuple[int, int]]:
        """呼叫的頂層引數範圍（字面值已清空，所以字串裡的逗號不會切分）；空白引數（尾端逗號）被略過。
        Spans of a call's top-level arguments (literals are blanked, so commas inside strings do not split);
        blank arguments (a trailing comma) are dropped."""
        spans: List[Tuple[int, int]] = []
        depth = 0
        start = open_paren + 1
        for i in range(open_paren + 1, close_paren):
            c = masked[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == "," and depth == 0:
                spans.append((start, i))
                start = i + 1
        spans.append((start, close_paren))
        return [(s, e) for s, e in spans if content[s:e].strip()]

    def _route_path(self, content: str, masked: str, open_paren: int, close_paren: int,
                    known_router: bool) -> Optional[str]:
        """路由註冊呼叫的路徑文字；不像路由註冊時回傳 None。
        The path text of a route-registration call; None when it does not look like one."""
        args = self._top_level_args(content, masked, open_paren, close_paren)
        if not args:
            return None
        start, end = args[0]
        raw = content[start:end].strip()
        handler = len(args) >= 2 and self._handler_like(masked[args[-1][0]:args[-1][1]])
        if raw[:1] in "\"'":
            path = self._first_string_literal(raw)
            if path is None:
                return None
            if path.startswith("/") or path == "*":
                return path if known_router or handler else None
            # 已知路由器上的空路徑（掛在帶前綴的路由器上）；`app.get('port')` 是設定讀取，不是路由
            # An empty path on a known router (mounted under a prefix); `app.get('port')` is a settings read, no route
            return '""' if known_router and path == "" and len(args) >= 2 else None
        if raw[:1] == "`":
            template = self._first_string_literal(raw)
            if template is None or "/" not in template:
                return None
            return template if known_router or handler else None
        if raw[:1] == "/" and known_router and handler and _JS_REGEX_LITERAL_RE.fullmatch(raw):
            # Express 的正規表達式路徑：`app.get(/^\/users\/(\d+)$/, h)` -> `GET /^\/users\/(\d+)$/`
            # An Express regex path: `app.get(/^\/users\/(\d+)$/, h)` -> `GET /^\/users\/(\d+)$/`
            return raw
        # 識別字路徑只在有處理函式引數時才算：沒有處理函式的 `app.get(PATH)` 刻意不是路由，
        # 因為 Express 的 `app.get('setting')`／`app.get(SETTING_NAME)` 是讀取應用程式設定
        # An identifier path counts only with a handler argument: `app.get(PATH)` without one is intentionally
        # not a route, because Express's `app.get('setting')` / `app.get(SETTING_NAME)` reads an app setting
        if known_router and handler and re.fullmatch(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*", raw):
            return raw
        return None

    @staticmethod
    def _handler_like(arg: str) -> bool:
        """引數看起來像處理函式（識別字、成員、呼叫結果、箭頭或 function 運算式），而不是設定物件或數字。
        Whether an argument looks like a handler (identifier, member, call result, arrow or function
        expression) rather than a config object or a number."""
        text = arg.strip()
        if not text or text[0] in "{[" or text[0].isdigit():
            return False
        return bool("=>" in text or re.match(r"(?:async\s+)?function\b", text)
                    or re.match(r"[A-Za-z_$][\w$.]*\s*(?:\(|$)", text))

    def _js_route_method_calls(self, content: str, masked: str, file_path: str, line_of,
                               clients: Set[str]) -> List[CodeSymbol]:
        """`<recv>.route('/x').get(h).post(h)`（Express 鏈式）、`<recv>.route({method, url|path})`（Fastify／Hapi），
        以及 hapi 的陣列形式 `<recv>.route([{...}, {...}])`（每個物件各成一個路由，範圍是該物件）。
        `<recv>.route('/x').get(h).post(h)` (Express chain), `<recv>.route({method, url|path})` (Fastify / Hapi),
        and hapi's array form `<recv>.route([{...}, {...}])` (one route per object, spanning that object)."""
        symbols: List[CodeSymbol] = []
        verbs = "|".join(sorted(_JS_ROUTE_METHODS))
        for m in re.finditer(rf"(?:^|[^.\w$])(({_JS_IDENTIFIER})\.route)\s*\(", masked):
            receiver = m.group(2)
            if receiver in clients or receiver.lower() in _JS_HTTP_CLIENTS:
                continue
            open_paren = m.end() - 1
            close_paren = self._match_delim(masked, open_paren, "(", ")")
            if close_paren is None:
                continue
            first = self._skip_ws(masked, open_paren + 1)
            if first is None:
                continue
            if masked[first] == "{":
                name = self._object_route_name(content[first:close_paren])
                if name is not None:
                    symbols.append(self._snippet(content, line_of, m.start(1), close_paren, file_path, name, "route",
                                                 [], signature=name))
                continue
            if masked[first] == "[":
                close_bracket = self._match_delim(masked, first, "[", "]")
                if close_bracket is None or close_bracket > close_paren:
                    continue
                for obj_start, obj_end in self._top_level_args(content, masked, first, close_bracket):
                    obj_open = self._skip_ws(masked, obj_start)
                    if obj_open is None or masked[obj_open] != "{":
                        continue
                    obj_close = self._match_delim(masked, obj_open, "{", "}")
                    if obj_close is None or obj_close > obj_end:
                        continue
                    name = self._object_route_name(content[obj_open:obj_close])
                    if name is not None:
                        symbols.append(self._snippet(content, line_of, obj_open, obj_close, file_path, name, "route",
                                                     [], signature=name))
                continue
            if content[first] not in "\"'`":
                continue
            path = self._first_string_literal(content[first:close_paren])
            if path is None or not path.startswith("/"):
                continue
            # 沿著鏈往後：.get(h).post(h)...
            # Follow the chain: .get(h).post(h)...
            seg_start, pos = m.start(1), close_paren
            while True:
                nxt = self._skip_ws(masked, pos + 1)
                chained = re.match(rf"\.\s*({verbs})\s*\(", masked[nxt:]) if nxt is not None else None
                if nxt is None or chained is None:
                    break
                call_open = nxt + chained.end() - 1
                call_close = self._match_delim(masked, call_open, "(", ")")
                if call_close is None:
                    break
                name = f"{chained.group(1).upper()} {path}"
                symbols.append(self._snippet(content, line_of, seg_start, call_close, file_path, name, "route", [],
                                             signature=name))
                seg_start, pos = nxt, call_close
        return symbols

    @staticmethod
    def _object_route_name(obj: str) -> Optional[str]:
        """`{method, url|path}` 路由物件的名稱（`GET|POST /x`）；缺少任何一個時回傳 None。
        The name of a `{method, url|path}` route object (`GET|POST /x`); None when either is missing."""
        methods = re.search(r"\bmethod\s*:\s*(\[[^\]]*\]|['\"][A-Za-z*]+['\"])", obj)
        path_m = re.search(r"\b(?:url|path)\s*:\s*(['\"`])([^'\"`\n]*)\1", obj)
        if not methods or not path_m:
            return None
        verb_list = [v.upper() for v in re.findall(r"[A-Za-z]+|\*", methods.group(1))]
        return f"{'|'.join(verb_list)} {path_m.group(2)}"

    @staticmethod
    def _nextjs_handlers(masked: str, functions: List[CodeSymbol]) -> List[CodeSymbol]:
        """Next.js App Router 處理函式：`export [async] function GET(...)`、`export const GET = ...`，
        以及以別名匯出的 `export { handler as GET }`（處理函式本身被重新標記，因此只審查一次）。
        Next.js App Router handlers: `export [async] function GET(...)`, `export const GET = ...`, and
        alias exports `export { handler as GET }` (the handler itself is retagged, so it is reviewed once)."""
        verb_names = {v.upper() for v in _JS_HTTP_VERBS}
        aliased: Dict[str, List[str]] = {}
        for m in _JS_EXPORT_LIST_RE.finditer(masked):
            for entry in m.group(1).split(","):
                parts = entry.split()
                if len(parts) == 3 and parts[1] == "as" and parts[2] in verb_names:
                    aliased.setdefault(parts[0], []).append(parts[2])
                elif len(parts) == 1 and parts[0] in verb_names:
                    aliased.setdefault(parts[0], []).append(parts[0])
        symbols: List[CodeSymbol] = []
        for sym in functions:
            if sym.symbol_type != "function":
                continue
            # Next.js 要求完全相同的大寫匯出名稱；輔助函式 `function get(key)` 不是路由
            # Next.js requires the exact upper-case export name; a helper `function get(key)` is no route
            if sym.name in verb_names and sym.source_code.lstrip().startswith("export"):
                signature = f"export async function {sym.name}({', '.join(sym.parameters)})"
            elif sym.name in aliased:
                signature = "export { " + ", ".join(
                    v if v == sym.name else f"{sym.name} as {v}" for v in aliased[sym.name]) + " }"
            else:
                continue
            symbols.append(sym.model_copy(update={"symbol_type": "route", "signature": signature}))
        return symbols

    # --- 小型掃描器 ---
    # --- small scanners ---------------------------------------------------------------

    @staticmethod
    def _skip_ws(masked: str, pos: int) -> Optional[int]:
        n = len(masked)
        while pos < n:
            if masked[pos].isspace():
                pos += 1
            else:
                return pos
        return None

    @staticmethod
    def _find_open_paren(masked: str, close_pos: int) -> int:
        """與 close_pos 處的 ')' 配對的 '(' 的位置（含端點）；不平衡時回傳 0。
        Position of the '(' matching the ')' at close_pos (inclusive); returns 0 when unbalanced."""
        depth = 0
        for i in range(close_pos, -1, -1):
            c = masked[i]
            if c == ")":
                depth += 1
            elif c == "(":
                depth -= 1
                if depth == 0:
                    return i
        return 0

    def _arrow_declaration_back(self, masked: str, arrow_pos: int) -> Tuple[Optional[int], Optional[str], Optional[int]]:
        """從 '=>' 往回走到 [export] [const|let|var] name = 宣告。
        回傳 (start_pos, name, close_paren_of_params)，若箭頭不是被指派的箭頭函式
        （例如比較運算，或當作呼叫引數傳入的箭頭函式）則回傳 (None, None, None)。
        Walks back from '=>' to the [export] [const|let|var] name = declaration.
        Returns (start_pos, name, close_paren_of_params) or (None, None, None) when the arrow is
        not an assigned arrow function (e.g. a comparison, or an arrow passed as a call argument)."""
        close_paren = None
        i = arrow_pos - 1
        # (params) 或單一不加括號的參數（const f = x => ...）
        # (params) or a single bare parameter (const f = x => ...)
        j = self._skip_ws_back(masked, i)
        if j is not None and masked[j] != ")":
            # 參數與箭號之間的 TS 回傳型別：(a: number): number => ...
            # a TS return type between the params and the arrow: (a: number): number => ...
            colon = self._annotation_colon_back(masked, j)
            before = self._skip_ws_back(masked, colon - 1) if colon is not None else None
            if before is not None and masked[before] == ")":
                j = before
        if j is not None and masked[j] == ")":
            close_paren = j
            i = self._find_open_paren(masked, j) - 1
            # 參數前的 TS 泛型參數：<T,>(x: T) => x
            # TS generic parameters before the params: <T,>(x: T) => x
            g = self._skip_ws_back(masked, i)
            if g is not None and masked[g] == ">":
                lt = masked.rfind("<", 0, g)
                if lt >= 0:
                    i = lt - 1
        else:
            word, w_start = self._word_back(masked, i)
            if word:
                i = w_start - 1
        # '=' 與參數之間可選的 async
        # optional async between '=' and the params
        word, w_start = self._word_back(masked, i)
        if word == "async":
            i = w_start - 1
        # 指派用的 '='（而不是 ==、<=、=> 等）
        # the '=' of the assignment (and not ==, <=, =>, ...)
        j = self._skip_ws_back(masked, i)
        if j is None or masked[j] != "=" or (j > 0 and masked[j - 1] in "=!<>+-*/%&|^"):
            return None, None, None
        # 被指派的變數名稱，可能帶型別註記：const handler: NextApiHandler = ...
        # the assigned variable name, possibly annotated: const handler: NextApiHandler = ...
        name, name_start = self._word_back(masked, j - 1)
        type_end = self._skip_ws_back(masked, j - 1)
        colon = self._annotation_colon_back(masked, type_end) if type_end is not None else None
        if colon is not None:
            var, var_start = self._word_back(masked, colon - 1)
            keyword = self._word_back(masked, var_start - 1)[0] if var else None
            if var and keyword in ("const", "let", "var"):
                name, name_start = var, var_start
        if not name:
            return None, None, None
        start = name_start
        # 可選的 const/let/var，再來是可選的 export
        # optional const/let/var, then optional export
        word, w_start = self._word_back(masked, start - 1)
        if word in ("const", "let", "var"):
            start = w_start
            word, w_start = self._word_back(masked, start - 1)
            if word == "export":
                start = w_start
        return start, name, close_paren

    def _body_after_params(self, masked: str, close_paren: int) -> Optional[int]:
        """參數列之後第一個有意義的位置，會略過 TS 回傳型別註記。
        First significant position after a parameter list, skipping a TS return type annotation."""
        pos = self._skip_ws(masked, close_paren + 1)
        if pos is not None and masked[pos] == ":":
            return self._skip_type(masked, pos)
        return pos

    def _skip_type(self, masked: str, colon: int) -> Optional[int]:
        """從 TS 回傳型別的 ':' 起算，其後函式本體 '{' 的位置（None：沒有本體）。
        From the ':' of a TS return type, the position of the body '{' after it (None: no body)."""
        n = len(masked)
        i = colon + 1
        depth = 0
        expect_type = True  # 緊接在 ':'、'|'、'&'、','、'<'、'(' 或 '=>' 之後的 '{' 是物件型別 ／ right after ':', '|', '&', ',', '<', '(' or '=>' a '{' is an object type
        while i < n:
            c = masked[i]
            if c.isspace():
                i += 1
                continue
            if c == "=" and masked[i + 1:i + 2] == ">":
                expect_type = True
                i += 2
                continue
            if c == "{":
                if not expect_type and depth == 0:
                    return i
                close = self._match_delim(masked, i, "{", "}")
                if close is None:
                    return None
                i, expect_type = close + 1, False
                continue
            if depth == 0 and c in ";=":
                return None  # 多載／沒有本體的宣告 ／ an overload / declaration without a body
            if depth == 0 and not masked[i - 1].isalnum() and re.match(r"(?:function|export|declare)\b", masked[i:i + 9]):
                return None  # 沒有分號的多載後面緊接下一個宣告 ／ a semicolon-less overload followed by the next declaration
            if c in "([<":
                depth += 1
                expect_type = True
            elif c in ")]>":
                if depth == 0:
                    return None
                depth -= 1
                expect_type = False
            else:
                expect_type = c in "|&,?:"
            i += 1
        return None

    @staticmethod
    def _annotation_colon_back(masked: str, pos: int) -> Optional[int]:
        """從 TS 型別的最後一個字元往回走，找出開始型別註記的 ':'。
        Walking back from the last character of a TS type, the ':' that starts the annotation."""
        depth = 0
        k = pos
        while k >= 0:
            c = masked[k]
            if c == ">" and k > 0 and masked[k - 1] == "=":
                k -= 2  # 函式型別的箭號 ／ the arrow of a function type
                continue
            if c in ")]}>":
                depth += 1
            elif c in "([{<":
                if depth == 0:
                    return None
                depth -= 1
            elif depth == 0 and c == ":":
                return k
            elif depth == 0 and c in ";=,\n":
                return None
            k -= 1
        return None

    @staticmethod
    def _word_back(masked: str, pos: int) -> Tuple[Optional[str], int]:
        """在 pos 或其之前結束的識別字／關鍵字（跳過空白）；沒有則回傳 (None, pos)。
        The identifier/keyword ending at or before pos (skipping whitespace); (None, pos) if none."""
        j = ASTExtractor._skip_ws_back(masked, pos)
        if j is None:
            return None, pos
        k = j
        while k >= 0 and (masked[k].isalnum() or masked[k] in "_$"):
            k -= 1
        word = masked[k + 1:j + 1]
        return (word, k + 1) if word else (None, pos)

    @staticmethod
    def _skip_ws_back(masked: str, pos: int) -> Optional[int]:
        while pos >= 0 and masked[pos].isspace():
            pos -= 1
        return pos if pos >= 0 else None

    @staticmethod
    def _end_of_statement(masked: str, pos: int) -> int:
        """不帶大括號的箭頭函式主體的結尾：所有括號再次閉合時的換行（或 ';'）。
        End of a brace-less arrow body: the newline (or ';') where all brackets are closed again."""
        depth = 0
        n = len(masked)
        i = pos
        while i < n:
            c = masked[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif depth == 0 and (c == ";" or c == "\n"):
                return i
            i += 1
        return n - 1

    @staticmethod
    def _first_string_literal(text: str) -> Optional[str]:
        """給定文字中的第一個引號字串（單引號、雙引號或樣板字面值）。
        The first quoted string in the given text (single, double or template literal)."""
        n = len(text)
        i = 0
        while i < n:
            c = text[i]
            if c in "\"'`":
                quote = c
                i += 1
                chars: List[str] = []
                while i < n and text[i] != quote:
                    if text[i] == "\\" and i + 1 < n:
                        chars.append(text[i + 1])
                        i += 2
                        continue
                    if quote != "`" and text[i] == "\n":
                        return None  # 未結束的單行字串：不是真正的路徑字面值 ／ unterminated line string: not a real path literal
                    chars.append(text[i])
                    i += 1
                return "".join(chars)
            i += 1
        return None

    def _extract_python_function(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        file_path: str,
        source_lines: List[str],
        class_name: Optional[str] = None
    ) -> CodeSymbol:
        # 包含裝飾器：它們帶有審查者需要看到的路由路徑與授權守衛
        # Include decorators: they carry route paths and auth guards the reviewers need to see
        start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        end = node.end_lineno or start
        source_snippet = self._without_nested_routes(node, source_lines, start, end)

        args = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        # *args / **kwargs 是函式契約的一部分；審查者與探測都需要它們
        # *args / **kwargs are part of the function's contract; reviewers and probes need them
        if node.args.vararg:
            args.append(f"*{node.args.vararg.arg}")
        kw_vararg = [f"**{node.args.kwarg.arg}"] if node.args.kwarg else []
        symbol_type = "method" if class_name else "function"
        full_name = f"{class_name}.{node.name}" if class_name else node.name

        docstring = ast.get_docstring(node)

        if any(self._is_route_decorator(dec) for dec in node.decorator_list):
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
                               start: int, end: int) -> str:
        """第 start–end 行的原始碼，其中巢狀路由處理函式（Flask 工廠裡的 `@app.route`）的本體縮成一行佔位註解。

        那些處理函式各自以 route 符號送審（`_nested_python_routes`），所以外層函式不必再帶一次它們的本體；
        裝飾器與 `def` 行保留（註冊的脈絡），佔位行寫出被省略的檔案行號，讓審查者仍能對應回檔案。
        結果仍是合法的 Python（本體是 `...`）。
        The source of lines start-end, with the body of each nested route handler (`@app.route` in a Flask
        factory) collapsed into a one-line placeholder comment.

        Those handlers are reviewed as their own route symbols (`_nested_python_routes`), so the enclosing
        function need not carry their bodies again; the decorators and the `def` line stay (registration
        context) and the placeholder names the omitted file lines, so reviewers can still map back to the
        file. The result is still valid Python (the body is `...`)."""
        nested = [n for n in ast.walk(node) if n is not node and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and any(self._is_route_decorator(dec) for dec in n.decorator_list)]
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
