"""威脅文字指向哪些擷取的符號：攻擊腳本依據的程式碼（ScenarioBuilder）與資安突破在 SARIF 的位置（報告）
都問這裡，所以兩者走同一套比對規則。
Which extracted symbols a threat's text names: the code an attack script is built from (the scenario builder) and
the SARIF location of a Breach (the report) both ask here, so they follow one matching rule."""
import re
from typing import List, Optional, Tuple

from vibeharness.core.models import CodeSymbol, ThreatItem

Span = Tuple[int, int]

# 完整 URL 的 `scheme://主機:連接埠`，到第一個 `/` 或空白為止 ／ a full URL's `scheme://host:port`, up to the first `/` or space
_URL_AUTHORITY_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^/\s'\"`<>]*")


def named_symbols(symbols: List[CodeSymbol], threat: ThreatItem) -> List[CodeSymbol]:
    """文字以完整識別字（或完整路由）指名的符號，照 `symbols` 的順序。

    整字比對：子字串測試會把每個提到 "user" 的威脅都綁到 get_user() 符號，把真正相關的程式碼藏在它後面；
    識別字邊界把 `_` 與 JS 的 `$` 都算成識別字字元。每一種路由後面都不能再接路徑字元（`/`、`-`），只寫路徑時
    前面也不能，所以 "GET /users/admin" 不會指名 `GET /users`，"/v2/api/users" 也不會指名 `GET /api/users`；
    完整 URL 的 `scheme://主機:連接埠` 不算路徑。偏好最長的比對：只出現在另一個符號比對範圍內的符號會被丟掉，
    所以 "/api/users/:id" 不會連帶拉進 "/api/users"，"Service.get_user" 也不會拉進同名函式。
    The symbols the text names by a whole identifier (or a whole route), in the order of `symbols`.

    Whole-word matching: a substring test would tie every threat mentioning "user" to a get_user() symbol and hide
    the actually relevant code behind it; identifier boundaries count both `_` and the JS `$` as identifier
    characters. No path character (`/`, `-`) may follow any route, nor precede its bare path, so "GET /users/admin"
    does not name `GET /users` and "/v2/api/users" does not name `GET /api/users`; a full URL's
    `scheme://host:port` is no path. The longest match wins: a symbol matched only inside another symbol's match is dropped, so "/api/users/:id"
    does not drag in "/api/users" and "Service.get_user" does not drag in a same-named function."""
    return [sym for sym, _spans in _matches(symbols, _threat_text(threat))]


def target_symbol(symbols: List[CodeSymbol], threat: ThreatItem) -> Optional[CodeSymbol]:
    """`named_symbols` 的結果裡最具體的一個：路由優先，其次是最長的命中，平手時取 `symbols` 裡先出現的；
    文字沒有指名任何符號時為 None。資安突破在 SARIF 的位置就是它。
    The most specific of `named_symbols`' result: routes first, then the longest match, ties to the one earlier in
    `symbols`; None when the text names no symbol. It is the SARIF location of a Breach."""
    order = {id(sym): index for index, sym in enumerate(symbols)}
    ranked = [((sym.symbol_type == "route", max(end - start for start, end in spans), -order[id(sym)]), sym)
              for sym, spans in _matches(symbols, _threat_text(threat))]
    return max(ranked, key=lambda pair: pair[0])[1] if ranked else None


def _threat_text(threat: ThreatItem) -> str:
    """威脅裡用來比對符號的文字：攻擊向量加上攻擊情境。
    The threat text symbols are matched in: the attack vector plus the attack scenario."""
    return f"{threat.attack_vector} {threat.attack_scenario}"


def _matches(symbols: List[CodeSymbol], text: str) -> List[Tuple[CodeSymbol, List[Span]]]:
    """每個被指名的符號與它在文字裡的比對範圍；只落在另一個符號較長比對範圍內的符號已經去掉。
    Each named symbol with its match spans in the text; a symbol matched only inside another symbol's longer
    match is already dropped."""
    # URL 的 `scheme://主機:連接埠` 換成等長的空白：範圍不位移，而路徑前面不再像是另一段路徑
    # A URL's `scheme://host:port` becomes as many spaces: spans keep their place, and the path no longer looks
    # like it continues another path
    text = _URL_AUTHORITY_RE.sub(lambda m: " " * len(m.group(0)), text)
    found: List[Tuple[CodeSymbol, List[Span]]] = []
    for sym in symbols:
        spans = [m.span() for key, route in _symbol_keys(sym) for m in re.finditer(_key_pattern(key, route), text)]
        if spans:
            found.append((sym, spans))
    all_spans = [span for _sym, spans in found for span in spans]

    def inside_longer(span: Span) -> bool:
        return any(o[0] <= span[0] and span[1] <= o[1] and o != span for o in all_spans)

    return [(sym, spans) for sym, spans in found if not all(inside_longer(span) for span in spans)]


def _symbol_keys(sym: CodeSymbol) -> List[Tuple[str, bool]]:
    """文字中可以指名這個符號的寫法，以及它是不是路由：完整名稱，方法再加上最後一段；"GET /api/x" 這種路由
    再加上路徑本身（路徑裡的 "." 不是方法分隔符）。
    The spellings by which text can name the symbol, with whether it is a route: the full name, plus the last
    part for a method; a "GET /api/x" route also by its bare path (a "." in a path is no method separator)."""
    name = sym.name.strip()
    if sym.symbol_type == "route" or " " in name or name.startswith("/"):
        path = name.split(" ", 1)[-1].strip()
        return [(k, True) for k in dict.fromkeys([name, path]) if k]
    return [(k, False) for k in dict.fromkeys([name, name.split(".")[-1]]) if k]


def _key_pattern(key: str, route: bool) -> str:
    """比對一個符號鍵的正規表達式：識別字邊界把 `_` 與 JS 的 `$` 都算成識別字字元；路由後面不能接路徑字元，
    只寫路徑時前面也不能。

    只由符號組成的路由路徑（根路由 `/`、萬用路由 `*`）在一般文字中到處都是（"and/or"、"read/write"、
    "1 * 10^6"），所以單獨的路徑只在被引號或反引號包住時才算（`'/'`、`` `*` ``）；完整的 "GET /" 形式後面
    不可緊接路徑字元，因此 "GET /admin"、"GET /.env" 或 "GET /-admin" 不會指名根路由。每一種路由（含路徑本身）
    後面都不能接 `/` 或 `-`，只寫路徑時前面也不能："/users/admin"、"/users-export" 與 "/v2/users" 指的是別的路徑。
    The regex matching one symbol key: identifier boundaries count both `_` and the JS `$` as identifier
    characters; no path character may follow a route, nor precede its bare path.

    Route paths made only of symbols (the root route `/`, the wildcard `*`) occur all over ordinary text
    ("and/or", "read/write", "1 * 10^6"), so such a bare path only counts inside quotes or backticks (`'/'`,
    `` `*` ``); the full "GET /" form must not be followed by a path character, so "GET /admin" or "GET /.env"
    does not name the root route ("GET /-admin" neither). No route (its bare path included) may be followed by `/`
    or `-`, and no bare path may be preceded by one: "/users/admin", "/users-export" and "/v2/users" name other
    paths."""
    path = key.split(" ", 1)[-1]
    symbolic = not re.search(r"[\w$]", path)
    if symbolic and " " not in key:
        return r"(?<=['\"`])" + re.escape(key) + r"(?=['\"`])"
    if route and " " not in key:
        head = r"(?<![\w$/-])"
    else:
        head = r"(?<![\w$])" if re.match(r"[\w$]", key) else ""
    if not route:
        tail = r"(?![\w$])" if re.search(r"[\w$]$", key) else ""
    elif symbolic:
        tail = r"(?![\w$/*-]|\.[\w$])"
    else:
        tail = r"(?![\w$/-])"
    return head + re.escape(key) + tail
