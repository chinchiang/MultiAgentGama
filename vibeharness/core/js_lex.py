"""JavaScript／TypeScript／JSX 的無相依純詞法原語：清空註解與字串／樣板／正規表達式／JSX 文字（保留長度與換行），
以及在清空後的文字上配對括號分隔符。不讀取檔案、不載入第三方套件，供程式碼閘門、匯入脈絡與白箱 JS 擷取器共用。
Dependency-free pure lexical primitives for JavaScript / TypeScript / JSX: blanking comments and string / template /
regex / JSX text (preserving length and newlines), and matching bracket delimiters on masked text. Performs no I/O
and imports no third-party package; shared by the code gate, import context and the white-box JS extractor."""

import re
from bisect import bisect_left
from typing import Dict, List, Optional

# 這些關鍵字之後的 `/` 是正規表達式字面值的開頭，不是除法
# After these keywords a `/` starts a regex literal, not division
_JS_REGEX_KEYWORDS = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
                      "case", "do", "else", "yield", "await"}
# 可能含 JSX 的副檔名：.ts/.mts/.cts 不算（`<T>x` 是型別斷言，不是 JSX）
# Extensions that may hold JSX: .ts/.mts/.cts are excluded (`<T>x` is a type assertion there, not JSX)
JSX_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".tsx")
# JSX 標籤名稱（含成員與命名空間：`Foo.Bar`、`svg:rect`）、屬性名稱與結尾標籤
# JSX tag names (members and namespaces included: `Foo.Bar`, `svg:rect`), attribute names and closing tags
_JSX_NAME_RE = re.compile(r"[A-Za-z][\w$.:-]*")
_JSX_ATTR_RE = re.compile(r"[A-Za-z_$][\w$:.-]*")
_JSX_CLOSE_RE = re.compile(r"</\s*([A-Za-z][\w$.:-]*)?\s*>")
# JSX 巢狀層數上限（每層是兩個遞迴呼叫）；更深的 `<` 照一般程式碼分析
# Maximum JSX nesting depth (each level is two recursive calls); a deeper `<` is lexed as plain code
_JSX_MAX_DEPTH = 120
# 失敗的 JSX 嘗試共用的掃描預算（字元數）：檔案大小的 _JSX_FAILED_SCAN_FACTOR 倍，至少 _JSX_FAILED_SCAN_MIN。
# 每次失敗按它實際掃過的字元數扣除，所以馬上失敗的便宜嘗試（`<T,>`）幾乎不花預算；用完後其餘的 `<` 照一般程式碼分析，
# 進行中的嘗試也立即放棄，讓最壞情況維持在檔案大小的線性倍數
# The scan budget (in characters) shared by failed JSX attempts: _JSX_FAILED_SCAN_FACTOR times the file size, at
# least _JSX_FAILED_SCAN_MIN. Each failure is charged the characters it actually scanned, so a cheap attempt that
# fails at once (`<T,>`) costs almost nothing; once spent, the remaining `<` are lexed as plain code and attempts in
# progress are abandoned at once, which keeps the worst case a linear multiple of the file size
_JSX_FAILED_SCAN_FACTOR = 4
_JSX_FAILED_SCAN_MIN = 256_000
# 已知的 TS 泛型開頭（`<T,>`、`<T extends U>`、`<T = U>`）：絕不是 JSX，所以不嘗試
# Known TS generic openings (`<T,>`, `<T extends U>`, `<T = U>`): never JSX, so no attempt is made
_TS_GENERIC_RE = re.compile(r"<\s*[A-Za-z_$][\w$]*\s*(?:,|=|extends\b)")


class _RegexCloser:
    """查出從某個 `/` 開始的正規表達式字面值的結尾 `/`：跳脫字元（`\\x`）與字元類別（`[...]`，類別內的 `/`
    不結束字面值）都照 JS 規則處理，字面值不跨行（跳脫字元後面接換行也不算）。

    第一次查詢某一行時，由行尾往回以動態規劃一次算出該行每個位置在「類別外／類別內」兩種狀態下的結尾位置，
    之後的查詢都是查表，所以總時間與檔案大小成正比。
    Finds the closing `/` of a regex literal starting at a given `/`: escapes (`\\x`) and character classes
    (`[...]`, a `/` inside a class does not end the literal) follow the JS rules, and the literal never spans a
    line (an escape followed by a line break does not either).

    The first query on a line computes, by dynamic programming from the end of the line backwards, the closing
    position from every position of that line in both states (outside / inside a class); later queries are table
    lookups, so the total time is linear in the file size."""

    def __init__(self, source: str) -> None:
        self.source = source
        self._newlines: Optional[List[int]] = None
        # 行首 -> 從該行每個位置（類別外）起算的結尾 `/` 位置（-1：該行內沒有） ／ line start -> the closing `/`
        # position from every position of the line, outside a class (-1: none on the line)
        self._lines: Dict[int, List[int]] = {}

    def close(self, slash: int) -> Optional[int]:
        """`slash` 處的 `/` 開始的字面值的結尾 `/` 位置；同一行內沒有結尾時回傳 None。
        The position of the closing `/` of the literal opened by the `/` at `slash`; None when the line has none."""
        source = self.source
        if self._newlines is None:
            self._newlines = [m.start() for m in re.finditer("\n", source)]
        k = bisect_left(self._newlines, slash)
        line_start = self._newlines[k - 1] + 1 if k else 0
        line_end = self._newlines[k] if k < len(self._newlines) else len(source)
        table = self._lines.get(line_start)
        if table is None:
            table = self._lines[line_start] = self._line_table(source, line_start, line_end)
        pos = slash + 1 - line_start
        found = table[pos] if pos < len(table) else -1
        return None if found < 0 else found + line_start

    @staticmethod
    def _line_table(source: str, start: int, end: int) -> List[int]:
        """[start, end) 這一行的表：位置 p（相對 start）在類別外開始掃描時的結尾 `/`（相對位置；-1 表示沒有）。
        The table of the line [start, end): the closing `/` (relative; -1 for none) when a scan starts at position p
        (relative to start) outside a class."""
        length = end - start
        outside = [-1] * (length + 2)
        inside = [-1] * (length + 2)
        for p in range(length - 1, -1, -1):
            c = source[start + p]
            if c == "\\":
                if p + 1 < length:
                    outside[p], inside[p] = outside[p + 2], inside[p + 2]
            elif c == "[":
                outside[p] = inside[p] = inside[p + 1]
            elif c == "]":
                outside[p] = inside[p] = outside[p + 1]
            elif c == "/":
                outside[p], inside[p] = p, inside[p + 1]
            else:
                outside[p], inside[p] = outside[p + 1], inside[p + 1]
        return outside


def mask_js_source(source: str, *, jsx: bool = False) -> str:
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
    budget = [max(_JSX_FAILED_SCAN_MIN, _JSX_FAILED_SCAN_FACTOR * len(source))] if jsx else None
    _mask_code(source, out, 0, budget, 0, _RegexCloser(source))
    return "".join(out)


def match_delim(masked: str, open_pos: int, open_ch: str, close_ch: str) -> Optional[int]:
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


def _mask_code(source: str, out: List[str], i: int, jsx: Optional[List[int]], depth: int,
               rx: Optional[_RegexCloser] = None) -> Optional[int]:
    """從 i 起詞法分析程式碼並清空其中的註解與字面值。depth 為 0 時處理到檔尾並回傳 n；
    depth > 0 時是在 JSX 運算式容器 `{...}` 裡（i 指向 `{` 之後），回傳配對的 `}` 之後的位置，
    若到檔尾都沒有閉合（或 JSX 掃描預算已用完，放棄進行中的嘗試）則回傳 None。`jsx` 是剩餘的 JSX 失敗掃描預算
    （單一元素的串列，整個檔案共用），None 表示不辨識 JSX。
    Lexes code from i, blanking its comments and literals. At depth 0 it runs to the end of the file and
    returns n; at depth > 0 it is inside a JSX expression container `{...}` (i points just after the `{`)
    and returns the position after the matching `}`, or None when the file ends before it closes (or the JSX
    scan budget is spent, abandoning the attempt in progress). `jsx` is the remaining failed-JSX scan budget
    (a one-element list shared by the whole file); None disables JSX."""
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
            i = _mask_quoted(source, out, i, c)
            prev_char, prev_word = c, ""
            continue
        if c == "`":
            i = _mask_template(source, out, i, rx)
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
                    and (nxt.isalpha() or nxt == ">") and not _TS_GENERIC_RE.match(source, i):
                end = _mask_jsx(source, out, i, depth + 1, jsx, rx)
                if end is not None:
                    # JSX 元素是一個值 ／ A JSX element is a value
                    i = end
                    prev3, prev2, prev_char, prev_word = "", "", ")", ""
                    continue
                if depth and jsx[0] <= 0:
                    # 預算用完：外層的 JSX 嘗試也放棄，不再把檔案其餘部分重新掃一遍
                    # Budget spent: the enclosing JSX attempt gives up too instead of re-scanning the rest of the file
                    return None
            # 正規表達式字面值還是除法？`</tag>` 與 `/>` 是 JSX，正規表達式字面值也絕不跨行
            # Regex literal or division? `</tag>` and `/>` are JSX, and a regex literal never spans a line break
            if c == "/" and nxt not in ("", "/", "*", ">") and prev_char != "<" and expression_pos:
                end_re = _mask_regex(source, out, i, rx)
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
            # 只有緊鄰的前一個字元是識別字字元時才延續同一個詞（`x\nreturn` 是兩個詞）；超過最長關鍵字的詞
            # 不再加長，否則一長串 `A class A class ...` 會讓字串串接變成平方時間
            # The word continues only when the immediately preceding character is an identifier character
            # (`x\nreturn` is two words); a word longer than the longest keyword stops growing, otherwise a long
            # run like `A class A class ...` makes the string concatenation quadratic
            prev_src = source[i - 1] if i > 0 else ""
            word_continues = prev_src.isalnum() or prev_src in ("_", "$")
            if c.isalnum() or c in "_$":
                prev_word = (prev_word + c if len(prev_word) < 16 else prev_word) if word_continues else c
            else:
                prev_word = ""
            prev3, prev2, prev_char = prev2, prev_char, c
        i += 1
    return None if depth else n


def _mask_jsx(source: str, out: List[str], i: int, depth: int, budget: List[int],
              rx: Optional[_RegexCloser] = None) -> Optional[int]:
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
        # 呼叫端還沒碰過 i 之後的位置，所以原文就是正確的還原值。按掃過的字元數扣預算；預算用完時
        # 所有外層嘗試都會跟著失敗，只有最外層（depth 1）還原到檔尾，涵蓋被放棄的內層寫入
        # The caller has not touched anything after i yet, so the source is the right value to restore. The
        # budget is charged the characters scanned; once it is spent every enclosing attempt fails too, and only
        # the outermost one (depth 1) restores to the end of the file, covering the abandoned inner writes
        budget[0] -= max(1, upto - i)
        if budget[0] > 0:
            out[i:upto] = source[i:upto]
        elif depth == 1:
            out[i:] = source[i:]
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
            end = _mask_code(source, out, j + 1, budget, depth, rx)
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
            end = _mask_code(source, out, k + 1, budget, depth, rx)
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
            end = _mask_code(source, out, j + 1, budget, depth, rx)
            if end is None:
                return fail(n)
            j = end
            continue
        if source[j + 1:j + 2] == "/":
            closing = _JSX_CLOSE_RE.match(source, j)
            if closing is None or (closing.group(1) or "") != name:
                return fail(j)
            return closing.end()
        end = None if depth >= _JSX_MAX_DEPTH else _mask_jsx(source, out, j, depth + 1, budget, rx)
        if end is None:
            # JSX 子元素文字裡不可能有落單的 `<`：這不是 JSX
            # A stray `<` cannot appear in JSX child text: this is not JSX
            return fail(j)
        j = end


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


def _mask_template(source: str, out: List[str], i: int, rx: Optional[_RegexCloser] = None) -> int:
    """清空從 i 處反引號開始的樣板字面值，回傳結尾反引號之後的位置（未閉合時為檔尾）。

    `${...}` 插值內是程式碼：其中的字串、巢狀樣板、註解與正規表達式字面值都正確詞法分析，
    因此 `${s.replace(/\\{/g, "")}` 或 `${x || "{"}` 裡落單的 `{` 不會吞掉檔案其餘部分。整個插值
    （含結尾的 `}`，那是樣板語法而不是程式碼）都清空。巢狀的樣板與插值用明確的堆疊處理而不是遞迴，
    所以 `${` 巢狀數百層的檔案不會觸發 RecursionError。
    Blanks the template literal whose backtick is at i and returns the position after its closing
    backtick (the end of the file when it is unclosed).

    A `${...}` interpolation is code: strings, nested templates, comments and regex literals inside it are
    lexed properly, so a stray `{` in `${s.replace(/\\{/g, "")}` or `${x || "{"}` cannot swallow the rest
    of the file. The whole interpolation (including its closing `}`, template syntax rather than code) is
    blanked. Nested templates and interpolations use an explicit stack instead of recursion, so a file
    nesting `${` hundreds deep cannot raise RecursionError."""
    n = len(source)
    # 堆疊的每一層：None 是樣板文字；[起點, 大括號深度, 前一個有意義字元] 是 `${...}` 插值
    # One stack entry per level: None is template text; [start, brace depth, previous significant char] is a `${...}` interpolation
    stack: List[Optional[List]] = [None]
    open_interpolations = 0
    i += 1
    while stack and i < n:
        c = source[i]
        frame = stack[-1]
        if frame is None:
            # 樣板文字 ／ template text
            if c == "`":
                out[i] = " "  # 結尾反引號 ／ closing backtick
                i += 1
                stack.pop()
                if stack:
                    stack[-1][2] = "`"  # type: ignore[index]
                continue
            if c == "\\":
                out[i] = " "
                i += 1
                if i < n and source[i] != "\n":
                    out[i] = " "
                i += 1
                continue
            if c == "$" and i + 1 < n and source[i + 1] == "{":
                out[i] = out[i + 1] = " "
                stack.append([i + 2, 1, "{"])
                open_interpolations += 1
                i += 2
                continue
            if c != "\n":
                out[i] = " "
            i += 1
            continue
        # `${...}` 插值裡的程式碼 ／ code inside a `${...}` interpolation
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
            i = _mask_quoted(source, out, i, c)
            frame[2] = c
            continue
        if c == "`":
            stack.append(None)
            i += 1
            continue
        prev_char = frame[2]
        if c == "/" and not (prev_char.isalnum() or prev_char in ")]}$_.\"'`"):
            end_re = _mask_regex(source, out, i, rx)
            if end_re is not None:
                i = end_re
                frame[2] = "/"
                continue
        if c == "{":
            frame[1] += 1
        elif c == "}":
            frame[1] -= 1
            if frame[1] == 0:
                i += 1
                stack.pop()
                open_interpolations -= 1
                if open_interpolations == 0:
                    # 只清空最外層的插值：它涵蓋內層，巢狀時才不會重複清空成平方時間
                    # Only the outermost interpolation is blanked: it covers the inner ones, so nesting
                    # does not re-blank the same text quadratically
                    _blank_range(source, out, frame[0], i)
                continue
        if not c.isspace():
            frame[2] = c
        i += 1
    # 到檔尾仍未閉合：未閉合的插值照樣清空（只需清最外層，它涵蓋內層）
    # Unclosed at the end of the file: unclosed interpolations are blanked all the same (the outermost covers the inner ones)
    outermost = next((f for f in stack if f is not None), None)
    if outermost is not None:
        _blank_range(source, out, outermost[0], n)
    return min(i, n) if stack else i


def _blank_range(source: str, out: List[str], start: int, end: int) -> None:
    """清空 [start, end)，保留換行。
    Blanks [start, end), keeping newlines."""
    for k in range(start, min(end, len(source))):
        if source[k] != "\n":
            out[k] = " "


def _mask_regex(source: str, out: List[str], i: int, rx: Optional[_RegexCloser] = None) -> Optional[int]:
    """清空正規表達式字面值；若它沒有在同一行結束則回傳 None（什麼都不清空）。結尾的 `/` 由 `_RegexCloser`
    以每行只算一次的表查出，所以一行裡許多失敗的嘗試（`/[/[/[...`）不會各自掃到行尾（平方時間）。
    Masks a regex literal; None (nothing masked) when it is not closed on its own line. The closing `/` is
    looked up by `_RegexCloser` in a table computed once per line, so many failed attempts on one line
    (`/[/[/[...`) do not each scan to the end of the line (quadratic time)."""
    close = (rx or _RegexCloser(source)).close(i)
    if close is None:
        return None
    for k in range(i + 1, close + 1):
        out[k] = " "  # 主體與結尾的 `/`（同一行，沒有換行） ／ the body and the closing `/` (one line, no newline)
    i = close + 1
    n = len(source)
    while i < n and (source[i].isalpha()):
        out[i] = " "  # 旗標（g、i、m、...） ／ flags (g, i, m, ...)
        i += 1
    return i
