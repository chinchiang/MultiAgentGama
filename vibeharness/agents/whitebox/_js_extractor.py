"""單一檔案的 JavaScript／TypeScript 符號與 HTTP 路由擷取器。每次呼叫建立一個短生命週期的 `_JsTsExtractor`
實例保存該檔案的配對表、備忘表與掃描預算，回傳後即釋放，`ASTExtractor` 不保留任何跨呼叫的暫存狀態。
Per-file JavaScript / TypeScript symbol and HTTP route extractor. Each call builds a short-lived `_JsTsExtractor`
holding that file's pair tables, memos and scan budgets and discards it on return, so `ASTExtractor` keeps no
per-file scratch state."""

import re
from bisect import bisect_left, bisect_right
from typing import Callable, Dict, List, Optional, Set, Tuple

from vibeharness.core.js_lex import JSX_EXTENSIONS, mask_js_source, match_delim
from vibeharness.core.models import CodeSymbol

# JS/TS 中辨識的 HTTP 動詞：router 方法（app.get(...)）與 Next.js 處理函式名稱
# HTTP verbs recognized in JS/TS, as router methods (app.get(...)) and Next.js handler names
_JS_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}
# 屬於控制流程而非方法宣告的 `identifier(...) {` 序列
# `identifier(...) {` sequences that are control flow, not method declarations
_JS_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "const", "let",
                        "var", "new", "typeof", "delete", "void", "do", "else", "try", "class", "await", "yield"}
_JS_IDENTIFIER = r"[A-Za-z0-9_$]+"
# TS 泛型參數 `<...>` 最多看幾個字元（箭頭函式前往回找、宣告名稱後往前比對）：泛型清單很短，
# 不設上限時每個沒有結尾的 `<` 都可能掃到檔頭或檔尾（平方時間）
# How many characters a TS generic parameter list `<...>` may span (looked for backwards before an arrow, matched
# forwards after a declaration name): generic lists are short, and without a bound every unterminated `<` may scan
# to the start or the end of the file (quadratic time)
_JS_GENERIC_LOOKBACK = 512
# 宣告名稱（`function List<...>(`、`.post<...>(`）之後的 TS 泛型參數清單：可含物件型別 `{ id: string; n: number }`，
# 但不含括號；類別方法的版本也不含 `;`（類別主體裡的 `;` 結束屬性宣告）
# A TS generic parameter list after a declaration name (`function List<...>(`, `.post<...>(`): it may hold object
# types `{ id: string; n: number }` but no parentheses; the class-method variant has no `;` either (a `;` in a class
# body ends a property declaration)
_JS_DECL_GENERIC = rf"<[^()]{{0,{_JS_GENERIC_LOOKBACK}}}>"
_JS_METHOD_GENERIC = rf"<[^();]{{0,{_JS_GENERIC_LOOKBACK}}}>"
# 路由引數、參數清單與路由物件最多檢查幾個字元：判斷只需要開頭，切出整個（可能巢狀到檔尾的）引數是平方時間
# How many characters of a route argument, a parameter list or a route object are inspected: the verdict only needs
# the beginning, and slicing out the whole argument (which may nest to the end of the file) takes quadratic time
_JS_ARG_SCAN = 4096
# 路由路徑文字的長度上限（且不得含換行）：真正的 HTTP 路由簡短且單行，多行或過長字面值不是路由
# Maximum length of a route path (which must also be single-line): real HTTP routes are short and single-line
_JS_MAX_ROUTE_PATH = 256
# 每個檔案所有符號原始碼的總字元數上限（檔案大小的倍數再加上固定額度）：巢狀類別／路由的片段彼此包含，
# 總量可能是檔案大小的平方；超過時該檔案略過並回報為解析失敗
# The cap on the total source characters of all symbols of one file (a multiple of the file size plus a fixed
# allowance): snippets of nested classes / routes contain one another and their total can be quadratic in the file
# size; beyond it the file is skipped and reported as a parse failure
_JS_SNIPPET_FACTOR = 16
_JS_SNIPPET_ALLOWANCE = 2_000_000
# 符號前後同一行上超過這麼多字元時，片段在那一側以字元位置切齊而不是取整行（壓縮過的單行檔案）
# When more than this many characters of the same line lie before / after a symbol, the snippet is cut at the
# character position on that side instead of taking the whole line (minified one-line files)
_SNIPPET_LINE_PAD = 2000
# 類別主體頂層的方法宣告開頭（從一段空白開始比對）與一段空白
# The start of a method declaration at the top level of a class body (matched from a whitespace run), and a whitespace run
_JS_METHOD_RE = re.compile(
    rf"\s+((?:(?:public|private|protected|static|async|override|readonly|abstract)\s+|\*\s*)*"
    rf"({_JS_IDENTIFIER}))\s*(?:{_JS_METHOD_GENERIC}\s*)?\("
)
_WHITESPACE_RUN_RE = re.compile(r"\s+")
_NON_SPACE_RE = re.compile(r"\S")
# 引數清單中的頂層 token：逗號與開啟括號（及其配對）
# Top-level tokens of an argument list: commas and opening brackets (and their partners)
_ARG_TOKEN_RE = re.compile(r"[,(\[{]")
_CLOSERS = {"(": ")", "[": "]", "{": "}"}
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
_JS_BINDING_RE = re.compile(
    rf"(?<![\w$.])({_JS_IDENTIFIER})\s*(?::[^=;\n]{{0,{_JS_GENERIC_LOOKBACK}}})?=(?![=>])\s*((?:[^;\n]|\n\s*\.)*)"
)
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


class _ExtractionBudgetExceeded(RuntimeError):
    """單一檔案的擷取超過資源上限；該檔案略過並回報為解析失敗。
    Extraction of one file exceeded a resource cap; the file is skipped and reported as a parse failure."""


def extract_js_ts_symbols(content: str, file_path: str) -> List[CodeSymbol]:
    """從單一 JS/TS/JSX 檔案內容擷取函式、箭頭函式、含方法的類別與 HTTP 路由處理函式。
    Extracts functions, arrow functions, classes with methods, and HTTP route handlers from one JS/TS/JSX file."""
    masked = mask_js_source(content, jsx=file_path.lower().endswith(JSX_EXTENSIONS))
    return _JsTsExtractor(content, masked).extract(content, masked, file_path)


class _JsTsExtractor:
    """單一 JS/TS 檔案的狀態化宣告與路由解析器：持有該檔案的配對表、備忘表與掃描預算。
    Stateful declaration and route parser for one JS/TS file: holds that file's pair tables, memos and scan budgets."""

    def __init__(self, content: str = "", masked: Optional[str] = None) -> None:
        # 正在分析的 JS/TS 檔案的（原文, 行串列），每個檔案只切一次行；以及 match_delim 的配對表
        # (content, lines) of the JS/TS file being analyzed, split into lines once per file; and match_delim's pair tables
        self._content_lines: Optional[Tuple[str, List[str]]] = (
            (content, content.split("\n")) if masked is not None else None
        )
        # 目前檔案剩餘的回傳型別掃描預算與符號原始碼字元預算（None：不限，例如直接呼叫輔助函式時）
        # The current file's remaining return-type scan budget and symbol-source character budget (None: unlimited,
        # e.g. when a helper is called directly)
        self._type_scan_left: Optional[int] = (4 * len(masked) + 100_000) if masked is not None else None
        self._snippet_left: Optional[int] = (
            (_JS_SNIPPET_FACTOR * len(content) + _JS_SNIPPET_ALLOWANCE) if masked is not None else None
        )
        self._delim_src: Optional[str] = None
        self._delim_cache: Dict[Tuple[str, str], Dict[int, int]] = {}
        # `_statement_end` 的索引：（括號位置, 該括號之後的深度, 深度 -> `;`／換行位置）
        # `_statement_end`'s index: (bracket positions, the depth after each, depth -> `;` / newline positions)
        self._stmt_src: Optional[str] = None
        self._stmt_index: Tuple[List[int], List[int], Dict[int, List[int]]] = ([], [], {})
        # `_annotation_colon_back` 的備忘表：深度 0 的位置 -> 找到的 ':'（或 None）
        # `_annotation_colon_back`'s memo: a position at depth 0 -> the ':' found (or None)
        self._colon_src: Optional[str] = None
        self._colon_memo: Dict[int, Optional[int]] = {}

    def extract(self, content: str, masked: str, file_path: str) -> List[CodeSymbol]:
        """以預先計算的行偏移量擷取函式與路由，並對重新標記為路由的 Next.js 處理函式去重。
        Extracts functions and routes with precomputed line offsets and deduplicates Next.js handlers retagged as routes."""
        line_offsets = [0] + [i + 1 for i, ch in enumerate(masked) if ch == "\n"]

        def line_of(pos: int) -> int:
            return bisect_right(line_offsets, pos)

        functions = self._extract_js_functions(content, masked, file_path, line_of)
        routes = self._extract_js_routes(content, masked, file_path, line_of, functions)
        # Next.js 動詞處理函式被改標為路由；只保留一個符號，讓它只被審查一次
        # A Next.js verb handler is retagged as a route; keep one symbol so it is reviewed once
        retagged = {(r.name, r.line_start) for r in routes}
        return [f for f in functions if (f.name, f.line_start) not in retagged] + routes

    def _match_pair(self, masked: str, open_pos: int, open_ch: str, close_ch: str) -> Optional[int]:
        """與 `match_delim` 結果相同（open_pos 必須是開啟分隔符），但每種分隔符在每個檔案只以堆疊配對一次（線性），
        之後查表；否則每個未閉合的 `(` 都要掃到檔尾，許多未閉合的呼叫會變成平方時間。
        Same result as `match_delim` (open_pos must be an opening delimiter), but each delimiter kind is paired
        once per file with a stack (linear) and then looked up; otherwise every unclosed `(` would scan to the
        end of the file and many unclosed calls would take quadratic time."""
        if masked[open_pos:open_pos + 1] != open_ch:
            return match_delim(masked, open_pos, open_ch, close_ch)
        return self._pairs(masked, open_ch, close_ch).get(open_pos)

    def _pairs(self, masked: str, open_ch: str, close_ch: str) -> Dict[int, int]:
        """清空文字中 open_ch／close_ch 的配對表（開啟位置 -> 閉合位置），每個檔案只建一次；反向表存在
        (close_ch, open_ch) 鍵下。
        The open_ch / close_ch pair table of the masked text (open position -> close position), built once per
        file; the reverse table is stored under the (close_ch, open_ch) key."""
        if self._delim_src is not masked:
            self._delim_src, self._delim_cache = masked, {}
        key = (open_ch, close_ch)
        pairs = self._delim_cache.get(key)
        if pairs is None:
            pairs = {}
            stack: List[int] = []
            for m in re.finditer(re.escape(open_ch) + "|" + re.escape(close_ch), masked):
                if m.group(0) == open_ch:
                    stack.append(m.start())
                elif stack:
                    pairs[stack.pop()] = m.start()
            self._delim_cache[key] = pairs
            self._delim_cache[(close_ch, open_ch)] = {v: k for k, v in pairs.items()}
        return pairs

    def _params(self, content: str, masked: str, open_paren: int, close_paren: int) -> List[str]:
        """參數清單（在 open_paren 與 close_paren 之間）的參數名稱；去掉預設值與 TS 型別註記。

        以清空後的文字切分頂層逗號（巢狀括號整段跳過，字串裡的逗號不會切分），每個參數只看開頭
        _JS_GENERIC_LOOKBACK 個字元，因此巢狀到檔尾的參數清單不會讓每一層都逐字元重掃（平方時間）。
        The parameter names of the list between open_paren and close_paren; defaults and TS annotations dropped.

        Top-level commas are split on the masked text (nested brackets skipped whole, commas inside strings do
        not split) and only the first _JS_GENERIC_LOOKBACK characters of each parameter are read, so a parameter
        list nesting to the end of the file does not make every level rescan it character by character
        (quadratic time)."""
        params: List[str] = []
        # 型別註記裡 `<...>` 內的逗號（`app: Hono<E, S>`）不分隔參數：`<` 多於 `>` 的片段接到下一個片段裡
        # A comma inside `<...>` of a type annotation (`app: Hono<E, S>`) does not separate parameters: a piece with
        # more `<` than `>` continues into the next one
        open_angles = 0
        for a, b in self._top_level_args(content, masked, open_paren, close_paren):
            head = masked[a:min(b, a + _JS_GENERIC_LOOKBACK)]
            inside = open_angles > 0
            open_angles = max(0, open_angles + head.count("<") - head.count(">") + head.count("=>"))
            if inside:
                continue
            name = content[a:min(b, a + _JS_GENERIC_LOOKBACK)].split("=")[0].split(":")[0].strip()
            if name:
                params.append(name)
        return params

    def _snippet(self, content: str, line_of: Callable[[int], int], start_pos: int, end_pos: int, file_path: str,
                 name: str, symbol_type: str, parameters: Optional[List[str]] = None,
                 signature: Optional[str] = None) -> CodeSymbol:
        start_line, end_line = line_of(start_pos), line_of(end_pos)
        # 片段通常是完整的行；但符號前後在同一行上還有超過 _SNIPPET_LINE_PAD 個字元時（壓縮過的單行檔案），
        # 那一側改以字元位置切齊，否則每個方法的片段都是整個檔案，總量會超過上限而讓整個檔案遺失
        # A snippet is normally whole lines; but when more than _SNIPPET_LINE_PAD characters of the same line lie
        # before or after the symbol (a minified one-line file), that side is cut at the character position instead,
        # otherwise every method's snippet would be the whole file and the total would exceed the cap, losing the file
        long_before = start_pos > _SNIPPET_LINE_PAD and content.rfind("\n", start_pos - _SNIPPET_LINE_PAD, start_pos) < 0
        long_after = end_pos + _SNIPPET_LINE_PAD < len(content) \
            and content.find("\n", end_pos, end_pos + _SNIPPET_LINE_PAD + 1) < 0
        if long_before or long_after:
            left = start_pos if long_before else content.rfind("\n", 0, start_pos) + 1
            right_nl = -1 if long_after else content.find("\n", end_pos)
            right = end_pos + 1 if long_after else (len(content) if right_nl < 0 else right_nl)
            source_code = content[left:right]
        else:
            cached = self._content_lines
            # 與 line_of 一樣只依 "\n" 切行（見 ast_extractor._parse_python_file）
            # Split on "\n" only, like line_of (see ast_extractor._parse_python_file)
            lines = cached[1] if cached is not None and cached[0] is content else content.split("\n")
            source_code = "\n".join(lines[start_line - 1:end_line])
        if self._snippet_left is not None:
            self._snippet_left -= len(source_code)
            if self._snippet_left < 0:
                raise _ExtractionBudgetExceeded("total symbol source exceeds the cap (too many nested snippets)")
        return CodeSymbol(
            name=name,
            symbol_type=symbol_type,
            file_path=file_path,
            line_start=start_line,
            line_end=end_line,
            signature=signature or f"{name}({', '.join(parameters or [])})",
            source_code=source_code,
            parameters=parameters or []
        )

    # --- JS/TS 擷取 ---
    # --- JS/TS extraction ---------------------------------------------------------

    def _extract_js_functions(self, content: str, masked: str, file_path: str,
                              line_of: Callable[[int], int]) -> List[CodeSymbol]:
        symbols: List[CodeSymbol] = []
        # 已包含在某個符號內的清空文字範圍，依起點排序（彼此不重疊且長度為正，所以終點也有序）
        # Masked-text ranges already inside a symbol, sorted by start (disjoint and non-empty, so the ends are sorted too)
        taken_starts: List[int] = []
        taken_ends: List[int] = []

        def overlaps(start: int, end: int) -> bool:
            # 起點在 end 之前的範圍中，終點最大的是最後一個：只需比較它（對數時間，而不是每個符號線性掃描）
            # Among the ranges starting before end the last one has the largest end: only it needs checking
            # (logarithmic time instead of a linear scan per symbol)
            idx = bisect_left(taken_starts, end)
            return idx > 0 and taken_ends[idx - 1] > start

        def take(start: int, end: int) -> None:
            idx = bisect_left(taken_starts, start)
            taken_starts.insert(idx, start)
            taken_ends.insert(idx, end)

        # 函式宣告與函式運算式：
        # [export] [default] [async] function[*] name[<T>](params)[: ReturnType] {...}
        # function declarations and function expressions:
        # [export] [default] [async] function[*] name[<T>](params)[: ReturnType] {...}
        fn_re = re.compile(
            rf"(?<![\w$.])(?:export\s+)?(?:default\s+)?(?:async\s+)?\bfunction\b\s*\*?\s*"
            rf"({_JS_IDENTIFIER})\s*(?:{_JS_DECL_GENERIC}\s*)?\("
        )
        for m in fn_re.finditer(masked):
            open_paren = m.end() - 1
            close_paren = self._match_pair(masked, open_paren, "(", ")")
            if close_paren is None:
                continue
            name = m.group(1)
            params = self._params(content, masked, open_paren, close_paren)
            body_pos = self._body_after_params(masked, close_paren)
            if body_pos is None or masked[body_pos] == ";" or re.match(
                    r"(?:export|function|declare|async)\b", masked[body_pos:body_pos + 8]):
                # 沒有本體的宣告（TS 多載簽章、`declare function`）：實作本身才是符號
                # A declaration without a body (a TS overload signature, `declare function`): the implementation is the symbol
                continue
            end_pos = close_paren
            if masked[body_pos] == "{":
                end_pos = self._match_pair(masked, body_pos, "{", "}") or close_paren
            else:
                # 直接用在運算式陳述式中的函式運算式
                # a function expression used directly in an expression statement
                end_pos = self._statement_end(masked, body_pos)
            if overlaps(m.start(), end_pos):
                continue
            take(m.start(), end_pos)
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
                end_pos = self._match_pair(masked, body_pos, "{", "}") or arrow_pos + 1
            else:
                end_pos = self._statement_end(masked, body_pos)
            if overlaps(start_pos, end_pos):
                continue
            take(start_pos, end_pos)
            arrow_params: List[str] = []
            if close_paren is not None:
                open_paren = self._find_open_paren(masked, close_paren)
                arrow_params = self._params(content, masked, open_paren, close_paren)
            symbols.append(self._snippet(
                content, line_of, start_pos, end_pos, file_path, name, "function", arrow_params
            ))

        # 含方法的類別：[export] [abstract] class Name [...] { ... }
        # classes with methods: [export] [abstract] class Name [...] { ... }
        # 名稱之後第一個 `{` 或 `;` 以預先排序的位置表二分搜尋（等同 `[^{;]*\{`，但沒有 `{` 的檔案不會讓每個
        # `class X` 都掃到檔尾）。位於已擷取類別之內的巢狀類別不再各自成為符號：它們的原始碼已在外層
        # 類別／方法中，否則巢狀的片段總量是平方大小
        # The first `{` or `;` after the name is found by bisecting a presorted position table (equivalent to
        # `[^{;]*\{`, but a file without `{` no longer makes every `class X` scan to the end of the file). A class nested
        # inside an extracted class is no symbol of its own: its source is already in the enclosing class / method,
        # and nested snippets would otherwise add up to quadratic size
        class_re = re.compile(rf"(?:export\s+)?(?:abstract\s+)?class\s+({_JS_IDENTIFIER})")
        stops = [s.start() for s in re.finditer(r"[{;]", masked)]
        consumed = 0
        class_end = -1
        for m in class_re.finditer(masked):
            if m.start() < consumed:
                continue
            k = bisect_left(stops, m.end())
            k = self._skip_heritage_type_literals(masked, stops, k, m.end())
            if k >= len(stops) or masked[stops[k]] != "{":
                continue
            open_brace = stops[k]
            consumed = open_brace + 1
            if m.start() < class_end:
                continue
            close_brace = self._match_pair(masked, open_brace, "{", "}")
            if close_brace is None:
                continue
            class_end = close_brace
            symbols.append(self._snippet(
                content, line_of, m.start(), close_brace, file_path, m.group(1), "class", [],
                signature=f"class {m.group(1)}"
            ))
            symbols.extend(self._extract_js_methods(content, masked, file_path, line_of, m.group(1),
                                                    open_brace + 1, close_brace))
        return symbols

    def _skip_heritage_type_literals(self, masked: str, stops: List[int], k: int, name_end: int) -> int:
        """類別名稱之後的 `{` 若位於未閉合的 `<...>` 裡（`extends React.Component<{ n: number }, S>`、
        `class A<T extends { id: string }>`），它是型別字面值而不是類別主體：整段跳過，回傳下一個 `{`／`;` 在 stops 中的索引。
        只檢查名稱之後 _JS_ARG_SCAN 個字元、最多跳過 16 個型別字面值，讓每個 `class` 的成本有上限。
        When a `{` after a class name lies inside an unclosed `<...>` (`extends React.Component<{ n: number }, S>`,
        `class A<T extends { id: string }>`) it is a type literal, not the class body: it is skipped whole and the
        index in stops of the next `{` / `;` is returned. Only the _JS_ARG_SCAN characters after the name are examined
        and at most 16 type literals skipped, so each `class` costs a bounded amount."""
        for _ in range(16):
            if k >= len(stops) or masked[stops[k]] != "{" or stops[k] - name_end > _JS_ARG_SCAN:
                return k
            head = masked[name_end:stops[k]]
            if head.count("<") <= head.count(">") - head.count("=>"):
                return k
            close = self._match_pair(masked, stops[k], "{", "}")
            if close is None:
                return k
            k = bisect_left(stops, close + 1)
        return k

    def _extract_js_methods(self, content: str, masked: str, file_path: str, line_of: Callable[[int], int],
                            class_name: str, body_start: int, body_end: int) -> List[CodeSymbol]:
        """類別主體頂層的方法：[modifiers] name(params) { ... }。
        Methods at the top level of a class body: [modifiers] name(params) { ... }."""
        symbols: List[CodeSymbol] = []
        # 只在每段空白的開頭嘗試比對（`\s+` 可回溯，所以同一段空白裡較後的位置只會得到相同結果），並以 pos/endpos
        # 比對而不是切片：否則長段空白的類別主體是平方時間
        # Matching is tried only where a whitespace run starts (`\s+` backtracks, so a later position in the same run
        # gives the same result) and uses pos/endpos rather than a slice: otherwise a class body with long
        # whitespace runs takes quadratic time
        pos = body_start
        while pos < body_end:
            run = _WHITESPACE_RUN_RE.search(masked, pos, body_end)
            if run is None:
                break
            pos, run_end = run.start(), run.end()
            m = _JS_METHOD_RE.match(masked, pos, body_end)
            if not m:
                pos = run_end
                continue
            name = m.group(2)
            if name in _JS_CONTROL_KEYWORDS:
                pos = run_end
                continue
            open_paren = m.end() - 1
            close_paren = self._match_pair(masked, open_paren, "(", ")")
            if close_paren is None:
                pos = run_end
                continue
            body_pos = self._body_after_params(masked, close_paren)
            if body_pos is None or masked[body_pos] != "{":
                pos = run_end
                continue
            close_body = self._match_pair(masked, body_pos, "{", "}")
            if close_body is None or close_body > body_end:
                pos = run_end
                continue
            params = self._params(content, masked, open_paren, close_paren)
            symbols.append(self._snippet(
                content, line_of, pos + 1, close_body, file_path, f"{class_name}.{name}", "method", params
            ))
            pos = close_body + 1
        return symbols

    def _extract_js_routes(self, content: str, masked: str, file_path: str, line_of: Callable[[int], int],
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
        route_re = re.compile(rf"(?:^|[^.\w$])(({_JS_IDENTIFIER})\.({verbs}))\s*(?:{_JS_DECL_GENERIC}\s*)?\(")
        for m in route_re.finditer(masked):
            receiver, verb = m.group(2), m.group(3)
            if receiver in clients or receiver.lower() in _JS_HTTP_CLIENTS or receiver in _JS_CONTROL_KEYWORDS:
                continue
            open_paren = m.end() - 1
            close_paren = self._match_pair(masked, open_paren, "(", ")")
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

    def _top_level_args(self, content: str, masked: str, open_paren: int, close_paren: int) -> List[Tuple[int, int]]:
        """呼叫的頂層引數範圍（字面值已清空，所以字串裡的逗號不會切分）；空白引數（尾端逗號）被略過。

        巢狀的括號以每個檔案只建一次的配對表整段跳過（未閉合時其後不再有頂層逗號），因此巢狀呼叫不會讓
        每一層都把內層逐字元重掃一遍（平方時間）。
        Spans of a call's top-level arguments (literals are blanked, so commas inside strings do not split);
        blank arguments (a trailing comma) are dropped.

        Nested brackets are skipped whole via the pair tables built once per file (an unclosed one leaves no
        further top-level comma), so nested calls do not make every level rescan the inner ones character by
        character (quadratic time)."""
        spans: List[Tuple[int, int]] = []
        start = open_paren + 1
        i = start
        while i < close_paren:
            m = _ARG_TOKEN_RE.search(masked, i, close_paren)
            if m is None:
                break
            c, i = m.group(0), m.start()
            if c == ",":
                spans.append((start, i))
                start = i + 1
                i += 1
                continue
            close = self._match_pair(masked, i, c, _CLOSERS[c])
            if close is None:
                break
            i = close + 1
        spans.append((start, close_paren))
        return [(s, e) for s, e in spans if _NON_SPACE_RE.search(content, s, e)]

    @staticmethod
    def _valid_route_text(text: Optional[str]) -> bool:
        return text is not None and "\r" not in text and "\n" not in text and len(text) <= _JS_MAX_ROUTE_PATH

    def _route_path(self, content: str, masked: str, open_paren: int, close_paren: int,
                    known_router: bool) -> Optional[str]:
        """路由註冊呼叫的路徑文字；不像路由註冊時回傳 None。
        The path text of a route-registration call; None when it does not look like one."""
        args = self._top_level_args(content, masked, open_paren, close_paren)
        if not args:
            return None
        start, end = args[0]
        # 只看開頭 _JS_ARG_SCAN 個字元；更長的第一個引數只可能是字串路徑，不會是識別字或正規表達式路徑
        # Only the first _JS_ARG_SCAN characters are inspected; a longer first argument can only be a string path,
        # never an identifier or regex path
        long_arg = end - start > _JS_ARG_SCAN
        raw = content[start:min(end, start + _JS_ARG_SCAN)].strip()
        last_start, last_end = args[-1]
        handler = len(args) >= 2 and self._handler_like(masked[last_start:min(last_end, last_start + _JS_ARG_SCAN)])
        if raw[:1] in "\"'":
            path = self._first_string_literal(raw)
            if not self._valid_route_text(path):
                return None
            assert path is not None
            if path.startswith("/") or path == "*":
                return path if known_router or handler else None
            # 已知路由器上的空路徑（掛在帶前綴的路由器上）；`app.get('port')` 是設定讀取，不是路由
            # An empty path on a known router (mounted under a prefix); `app.get('port')` is a settings read, no route
            return '""' if known_router and path == "" and len(args) >= 2 else None
        if raw[:1] == "`":
            template = self._first_string_literal(raw)
            if not self._valid_route_text(template) or template is None or "/" not in template:
                return None
            return template if known_router or handler else None
        if raw[:1] == "/" and known_router and handler and not long_arg and self._valid_route_text(raw) \
                and _JS_REGEX_LITERAL_RE.fullmatch(raw):
            # Express 的正規表達式路徑：`app.get(/^\/users\/(\d+)$/, h)` -> `GET /^\/users\/(\d+)$/`
            # An Express regex path: `app.get(/^\/users\/(\d+)$/, h)` -> `GET /^\/users\/(\d+)$/`
            return raw
        # 識別字路徑只在有處理函式引數時才算：沒有處理函式的 `app.get(PATH)` 刻意不是路由，
        # 因為 Express 的 `app.get('setting')`／`app.get(SETTING_NAME)` 是讀取應用程式設定
        # An identifier path counts only with a handler argument: `app.get(PATH)` without one is intentionally
        # not a route, because Express's `app.get('setting')` / `app.get(SETTING_NAME)` reads an app setting
        if known_router and handler and not long_arg and self._valid_route_text(raw) \
                and re.fullmatch(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*", raw):
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

    def _js_route_method_calls(self, content: str, masked: str, file_path: str, line_of: Callable[[int], int],
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
            close_paren = self._match_pair(masked, open_paren, "(", ")")
            if close_paren is None:
                continue
            first = self._skip_ws(masked, open_paren + 1)
            if first is None:
                continue
            if masked[first] == "{":
                name = self._object_route_name(self._object_head(content, masked, first, close_paren))
                if name is not None:
                    symbols.append(self._snippet(content, line_of, m.start(1), close_paren, file_path, name, "route",
                                                 [], signature=name))
                continue
            if masked[first] == "[":
                close_bracket = self._match_pair(masked, first, "[", "]")
                if close_bracket is None or close_bracket > close_paren:
                    continue
                for obj_start, obj_end in self._top_level_args(content, masked, first, close_bracket):
                    obj_open = self._skip_ws(masked, obj_start)
                    if obj_open is None or masked[obj_open] != "{":
                        continue
                    obj_close = self._match_pair(masked, obj_open, "{", "}")
                    if obj_close is None or obj_close > obj_end:
                        continue
                    name = self._object_route_name(self._object_head(content, masked, obj_open, obj_close))
                    if name is not None:
                        symbols.append(self._snippet(content, line_of, obj_open, obj_close, file_path, name, "route",
                                                     [], signature=name))
                continue
            if content[first] not in "\"'`":
                continue
            path = self._first_string_literal(content[first:min(close_paren, first + _JS_ARG_SCAN)])
            if not self._valid_route_text(path) or path is None or not path.startswith("/"):
                continue
            # 沿著鏈往後：.get(h).post(h)...
            # Follow the chain: .get(h).post(h)...
            seg_start, pos = m.start(1), close_paren
            chain_re = re.compile(rf"\.\s*({verbs})\s*\(")
            while True:
                nxt = self._skip_ws(masked, pos + 1)
                chained = chain_re.match(masked, nxt) if nxt is not None else None
                if nxt is None or chained is None:
                    break
                call_open = chained.end() - 1
                call_close = self._match_pair(masked, call_open, "(", ")")
                if call_close is None:
                    break
                name = f"{chained.group(1).upper()} {path}"
                symbols.append(self._snippet(content, line_of, seg_start, call_close, file_path, name, "route", [],
                                             signature=name))
                seg_start, pos = nxt, call_close
        return symbols

    def _object_head(self, content: str, masked: str, obj_open: int, obj_close: int) -> str:
        """物件字面值的頂層屬性，每個只取開頭 _JS_GENERIC_LOOKBACK 個字元，以逗號串接成 `{...}`：
        `method`／`path` 在處理函式本體之後也找得到，而巢狀到檔尾的物件不會被整段切出（平方時間）。
        The top-level properties of an object literal, each cut to its first _JS_GENERIC_LOOKBACK characters and
        joined with commas into `{...}`: `method` / `path` are found even after a long handler body, and an object
        nesting to the end of the file is never sliced out whole (quadratic time)."""
        props = self._top_level_args(content, masked, obj_open, obj_close)
        return "{" + ",".join(content[a:min(b, a + _JS_GENERIC_LOOKBACK)] for a, b in props) + "}"

    @staticmethod
    def _object_route_name(obj: str) -> Optional[str]:
        """`{method, url|path}` 路由物件的名稱（`GET|POST /x`）；缺少任何一個時回傳 None。
        The name of a `{method, url|path}` route object (`GET|POST /x`); None when either is missing."""
        methods = re.search(r"\bmethod\s*:\s*(\[[^\]]*\]|['\"][A-Za-z*]+['\"])", obj)
        path_m = re.search(r"\b(?:url|path)\s*:\s*(['\"`])([^'\"`\r\n]*)\1", obj)
        if not methods or not path_m or len(path_m.group(2)) > _JS_MAX_ROUTE_PATH:
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

    def _find_open_paren(self, masked: str, close_pos: int) -> int:
        """與 close_pos 處的 ')' 配對的 '(' 的位置（含端點）；不平衡時回傳 0。查每個檔案只建一次的配對表，
        所以許多未配對的 `) =>` 不會各自往回掃到檔頭（平方時間）。
        Position of the '(' matching the ')' at close_pos (inclusive); returns 0 when unbalanced. It looks up the
        pair table built once per file, so many unmatched `) =>` do not each scan back to the start of the file
        (quadratic time)."""
        if masked[close_pos:close_pos + 1] != ")":
            return 0
        self._pairs(masked, "(", ")")
        return self._delim_cache[(")", "(")].get(close_pos, 0)

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
                # 泛型參數清單很短：只往回找有限的距離，否則每個 `>(...) =>` 都可能掃到檔頭
                # Generic parameter lists are short: look back a bounded distance, otherwise every `>(...) =>` may scan to the start of the file
                lt = masked.rfind("<", max(0, g - _JS_GENERIC_LOOKBACK), g)
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

        每個檔案的型別掃描共用一份與檔案大小成正比的預算（`_type_scan_left`）：許多未閉合的 `(): <` 否則會
        各自掃到檔尾（平方時間）；預算用完後其餘的回傳型別視為沒有本體。
        From the ':' of a TS return type, the position of the body '{' after it (None: no body).

        The type scans of a file share a budget proportional to the file size (`_type_scan_left`): many
        unclosed `(): <` would otherwise each scan to the end of the file (quadratic time); once it is spent the
        remaining return types count as having no body."""
        n = len(masked)
        i = colon + 1
        depth = 0
        expect_type = True  # 緊接在 ':'、'|'、'&'、','、'<'、'(' 或 '=>' 之後的 '{' 是物件型別 ／ right after ':', '|', '&', ',', '<', '(' or '=>' a '{' is an object type
        while i < n:
            if self._type_scan_left is not None:
                self._type_scan_left -= 1
                if self._type_scan_left < 0:
                    return None
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
                close = self._match_pair(masked, i, "{", "}")
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

    def _annotation_colon_back(self, masked: str, pos: int) -> Optional[int]:
        """從 TS 型別的最後一個字元往回走，找出開始型別註記的 ':'。

        `()`、`[]`、`{}` 群組以每個檔案只建一次的配對表整段跳過（沒有配對的結尾括號：不是型別註記），只有 `<...>`
        以計數處理，而且在 `<...>` 裡最多走 _JS_GENERIC_LOOKBACK 步。深度 0 時的結果只取決於位置，所以記在每個檔案
        共用的備忘表裡：一長串 `=>=>=>...` 不會讓每個箭號各自往回走到檔頭（平方時間）；`<...>` 裡的步數也從
        `_type_scan_left` 預算扣除。
        Walking back from the last character of a TS type, the ':' that starts the annotation.

        `()`, `[]` and `{}` groups are skipped whole via the pair tables built once per file (an unmatched closing
        bracket: no annotation); only `<...>` is counted, with at most _JS_GENERIC_LOOKBACK steps inside it. At depth 0
        the result depends only on the position, so it is memoized in a per-file table: a long run of `=>=>=>...` does
        not make every arrow walk back to the start of the file (quadratic time); the steps inside `<...>` are charged
        to the `_type_scan_left` budget too."""
        if self._colon_src is not masked:
            self._colon_src, self._colon_memo = masked, {}
        memo = self._colon_memo
        reverse = {")": "(", "]": "[", "}": "{"}
        visited: List[int] = []  # 深度 0 時走過的位置（結果相同） ／ positions passed at depth 0 (same result)
        result: Optional[int] = None
        depth = 0
        angle_steps = 0
        k = pos
        while k >= 0:
            if depth == 0:
                if k in memo:
                    result = memo[k]
                    break
                visited.append(k)
                # 上限按每段 `<...>` 計，結果才只取決於位置 ／ the cap is per `<...>` run, so the result depends only on the position
                angle_steps = 0
            c = masked[k]
            if c == ">" and k > 0 and masked[k - 1] == "=":
                k -= 2  # 函式型別的箭號 ／ the arrow of a function type
                continue
            if c in reverse:
                self._pairs(masked, reverse[c], c)
                opener = self._delim_cache[(c, reverse[c])].get(k)
                if opener is None:
                    break
                k = opener - 1
                continue
            if c in "([{":
                if depth == 0:
                    break
                depth -= 1
                k -= 1
                continue
            if depth:
                angle_steps += 1
                if self._type_scan_left is not None:
                    self._type_scan_left -= 1
                if angle_steps > _JS_GENERIC_LOOKBACK or (self._type_scan_left is not None and self._type_scan_left < 0):
                    break
            if c == ">":
                depth += 1
            elif c == "<":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and c == ":":
                result = k
                break
            elif depth == 0 and c in ";=,\n":
                break
            k -= 1
        for v in visited:
            memo[v] = result
        return result

    @staticmethod
    def _word_back(masked: str, pos: int) -> Tuple[Optional[str], int]:
        """在 pos 或其之前結束的識別字／關鍵字（跳過空白）；沒有則回傳 (None, pos)。
        The identifier/keyword ending at or before pos (skipping whitespace); (None, pos) if none."""
        j = _JsTsExtractor._skip_ws_back(masked, pos)
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

    def _statement_end(self, masked: str, pos: int) -> int:
        """與 `_end_of_statement` 結果相同，但查每個檔案只建一次的索引：每個括號深度下 `;`／換行的位置。
        否則許多未閉合的 `=> (` 會各自掃到檔尾（平方時間）。
        Same result as `_end_of_statement`, but looks up an index built once per file: the positions of `;` /
        newlines at each bracket depth. Otherwise many unclosed `=> (` would each scan to the end of the file
        (quadratic time)."""
        if self._stmt_src is not masked:
            bracket_pos: List[int] = []
            bracket_depth: List[int] = []  # 該括號之後的深度 ／ the depth after that bracket
            ends: Dict[int, List[int]] = {}
            depth = 0
            for m in re.finditer(r"[(\[{)\]};\n]", masked):
                c = m.group(0)
                if c in ";\n":
                    ends.setdefault(depth, []).append(m.start())
                    continue
                depth += 1 if c in "([{" else -1
                bracket_pos.append(m.start())
                bracket_depth.append(depth)
            self._stmt_src, self._stmt_index = masked, (bracket_pos, bracket_depth, ends)
        bracket_pos, bracket_depth, ends = self._stmt_index
        k = bisect_left(bracket_pos, pos)
        base = bracket_depth[k - 1] if k else 0
        candidates = ends.get(base, [])
        idx = bisect_left(candidates, pos)
        return candidates[idx] if idx < len(candidates) else len(masked) - 1

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
