"""威脅文字指向哪些擷取的符號：攻擊腳本依據的程式碼（ScenarioBuilder）與資安突破在 SARIF 的位置（報告）
都問這裡，所以兩者走同一套比對規則。
Which extracted symbols a threat's text names: the code an attack script is built from (the scenario builder) and
the SARIF location of a Breach (the report) both ask here, so they follow one matching rule."""
import re
from typing import List, Optional, Tuple

from vibeharness.core.models import CodeSymbol

Span = Tuple[int, int]


def named_symbols(symbols: List[CodeSymbol], text: str) -> List[CodeSymbol]:
    """文字以完整識別字（或完整路由）指名的符號，照 `symbols` 的順序。

    整字比對：子字串測試會把每個提到 "user" 的威脅都綁到 get_user() 符號，把真正相關的程式碼藏在它後面；
    識別字邊界把 `_` 與 JS 的 `$` 都算成識別字字元。路由後面不能再接路徑字元（`/`、`-`），所以
    "GET /users/admin" 不會指名 `GET /users`。偏好最長的比對：只出現在另一個符號比對範圍內的符號會被丟掉，
    所以 "/api/users/:id" 不會連帶拉進 "/api/users"，"Service.get_user" 也不會拉進同名函式。
    The symbols the text names by a whole identifier (or a whole route), in the order of `symbols`.

    Whole-word matching: a substring test would tie every threat mentioning "user" to a get_user() symbol and hide
    the actually relevant code behind it; identifier boundaries count both `_` and the JS `$` as identifier
    characters. No path character (`/`, `-`) may follow a route, so "GET /users/admin" does not name `GET /users`.
    The longest match wins: a symbol matched only inside another symbol's match is dropped, so "/api/users/:id"
    does not drag in "/api/users" and "Service.get_user" does not drag in a same-named function."""
    return [sym for sym, _spans in _matches(symbols, text)]


def target_symbol(symbols: List[CodeSymbol], text: str) -> Optional[CodeSymbol]:
    """`named_symbols` 的結果裡最具體的一個：路由優先，其次是最長的命中，平手時取 `symbols` 裡先出現的；
    文字沒有指名任何符號時為 None。資安突破在 SARIF 的位置就是它。
    The most specific of `named_symbols`' result: routes first, then the longest match, ties to the one earlier in
    `symbols`; None when the text names no symbol. It is the SARIF location of a Breach."""
    order = {id(sym): index for index, sym in enumerate(symbols)}
    ranked = [((sym.symbol_type == "route", max(end - start for start, end in spans), -order[id(sym)]), sym)
              for sym, spans in _matches(symbols, text)]
    return max(ranked, key=lambda pair: pair[0])[1] if ranked else None


def _matches(symbols: List[CodeSymbol], text: str) -> List[Tuple[CodeSymbol, List[Span]]]:
    """每個被指名的符號與它在文字裡的比對範圍；只落在另一個符號較長比對範圍內的符號已經去掉。
    Each named symbol with its match spans in the text; a symbol matched only inside another symbol's longer
    match is already dropped."""
    found: List[Tuple[CodeSymbol, List[Span]]] = []
    for sym in symbols:
        spans = [m.span() for key in _symbol_keys(sym) for m in re.finditer(_key_pattern(key), text)]
        if spans:
            found.append((sym, spans))
    all_spans = [span for _sym, spans in found for span in spans]

    def inside_longer(span: Span) -> bool:
        return any(o[0] <= span[0] and span[1] <= o[1] and o != span for o in all_spans)

    return [(sym, spans) for sym, spans in found if not all(inside_longer(span) for span in spans)]


def _symbol_keys(sym: CodeSymbol) -> List[str]:
    """文字中可以指名這個符號的寫法：完整名稱，方法再加上最後一段；"GET /api/x" 這種路由再加上路徑本身
    （路徑裡的 "." 不是方法分隔符）。
    The spellings by which text can name the symbol: the full name, plus the last part for a method; a
    "GET /api/x" route also by its bare path (a "." in a path is no method separator)."""
    name = sym.name.strip()
    if " " in name or name.startswith("/"):
        path = name.split(" ", 1)[-1].strip()
        return [k for k in dict.fromkeys([name, path]) if k]
    return [k for k in dict.fromkeys([name, name.split(".")[-1]]) if k]


def _key_pattern(key: str) -> str:
    """比對一個符號鍵的正規表達式：識別字邊界把 `_` 與 JS 的 `$` 都算成識別字字元；路由後面不能接路徑字元。

    只由符號組成的路由路徑（根路由 `/`、萬用路由 `*`）在一般文字中到處都是（"and/or"、"read/write"、
    "1 * 10^6"），所以單獨的路徑只在被引號或反引號包住時才算（`'/'`、`` `*` ``）；完整的 "GET /" 形式後面
    不可緊接路徑字元，因此 "GET /admin" 或 "GET /.env" 不會指名根路由。其他路由（含路徑本身）後面也不能接
    `/` 或 `-`："/users/admin" 與 "/users-export" 指的是別的路徑。
    The regex matching one symbol key: identifier boundaries count both `_` and the JS `$` as identifier
    characters; no path character may follow a route.

    Route paths made only of symbols (the root route `/`, the wildcard `*`) occur all over ordinary text
    ("and/or", "read/write", "1 * 10^6"), so such a bare path only counts inside quotes or backticks (`'/'`,
    `` `*` ``); the full "GET /" form must not be followed by a path character, so "GET /admin" or "GET /.env"
    does not name the root route. Any other route (its bare path included) may not be followed by `/` or `-`
    either: "/users/admin" and "/users-export" name other paths."""
    path = key.split(" ", 1)[-1]
    symbolic = not re.search(r"[\w$]", path)
    if symbolic and " " not in key:
        return r"(?<=['\"`])" + re.escape(key) + r"(?=['\"`])"
    head = r"(?<![\w$])" if re.match(r"[\w$]", key) else ""
    if symbolic:
        tail = r"(?![\w$/*]|\.[\w$])"
    elif "/" in path:
        tail = r"(?![\w$/-])"
    else:
        tail = r"(?![\w$])" if re.search(r"[\w$]$", key) else ""
    return head + re.escape(key) + tail
