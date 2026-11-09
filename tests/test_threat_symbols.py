"""威脅文字指向哪些擷取的符號（`vibeharness/core/threat_symbols.py`）：攻擊腳本依據的程式碼與 SARIF 標的位置
走同一套規則。
Which extracted symbols a threat's text names (`vibeharness/core/threat_symbols.py`): the code an attack script is
built from and the SARIF location of its Breach follow one rule."""
import pytest

from vibeharness.core.models import CodeSymbol, FindingSeverity, STRIDECategory, ThreatItem
from vibeharness.core.threat_symbols import named_symbols, target_symbol


def _sym(name, kind="function", path="app.py", line=1):
    return CodeSymbol(name=name, symbol_type=kind, file_path=path, line_start=line, line_end=line + 1,
                      signature=name, source_code="")


def _threat(attack_vector, attack_scenario=""):
    return ThreatItem(threat_id="T-1", stride_category=STRIDECategory.TAMPERING, title="t", description="d",
                      asset_at_risk="a", attack_vector=attack_vector, trust_boundary_crossed="b",
                      severity=FindingSeverity.HIGH, attack_scenario=attack_scenario, test_verification_goal="g")


def _named(symbols, text):
    return named_symbols(symbols, _threat(text))


def _target(symbols, text):
    return target_symbol(symbols, _threat(text))


def _names(text, symbols):
    return [s.name for s in _named(symbols, text)]


# --- #142：兩套規則分歧的案例 ／ #142: the cases where the two rules disagreed -------------------------------------

ROUTE = _sym("GET /api/users", "route", line=10)
HELPER = _sym("helper", line=40)
INIT = _sym("init", path="app.js", line=5)


@pytest.mark.parametrize("text, symbols, named, target", [
    # 只寫路由的路徑，文中還提到另一個函式 ／ a bare route path, another function in the text
    ("Send a crafted body to /api/users; helper is reached.", [ROUTE, HELPER], ["GET /api/users", "helper"], ROUTE),
    # 只寫路由的路徑，沒有其他符號 ／ a bare route path and no other symbol
    ("Send a crafted body to /api/users.", [ROUTE], ["GET /api/users"], ROUTE),
    # `$init` 是另一個 JS 識別字，不是 `init` ／ `$init` is another JS identifier, not `init`
    ("Call $init() with a forged token.", [INIT], [], None),
], ids=["bare-path-and-helper", "bare-path-only", "js-dollar-prefix"])
def test_the_attack_code_and_the_breach_location_come_from_one_match(text, symbols, named, target):
    """攻擊腳本拿到的符號（`named_symbols`）與 SARIF 的位置（`target_symbol`）來自同一次比對。
    The symbols the attack script gets (`named_symbols`) and the SARIF location (`target_symbol`) come from one
    match."""
    assert _names(text, symbols) == named
    assert _target(symbols, text) is target


@pytest.mark.parametrize("text", ["HTTP GET /users/admin without a token", "GET /users-export", "call /users/admin"])
def test_a_longer_path_does_not_name_a_shorter_route(text):
    """路由後面不能再接路徑字元（`/`、`-`）：只有 `GET /users` 時，這些文字指的是別的路徑，不是它。
    No path character (`/`, `-`) may follow a route: with only `GET /users`, these texts name another path, not it."""
    short = _sym("GET /users", "route")
    assert _named([short], text) == []
    assert _target([short], text) is None



@pytest.mark.parametrize("route, text", [
    ("GET /", "GET /-admin"),
    ("GET *", "GET *-x"),
    ("GET *.json", "GET *.json/x"),
])
def test_no_path_character_follows_any_route(route, text):
    """每一種路由（根路由、萬用路由、帶副檔名的路徑）後面都不能接 `/` 或 `-`：那是另一個路徑。
    No `/` or `-` may follow any route (the root, a wildcard, a path with an extension): that is another path."""
    sym = _sym(route, "route", "a.js")
    assert _named([sym], text) == []
    assert _target([sym], text) is None


@pytest.mark.parametrize("text", ["call /v2/api/users", "GET /v2/api/users"])
def test_a_route_path_inside_a_longer_path_names_no_route(text):
    """只寫路徑的路由前面也不能接路徑字元：`/v2/api/users` 是另一個路徑，不是 `GET /api/users`。
    No path character may precede a route's bare path either: `/v2/api/users` is another path, not
    `GET /api/users`."""
    route = _sym("GET /api/users", "route")
    assert _named([route], text) == []
    assert _target([route], text) is None


@pytest.mark.parametrize("text", ["POST http://localhost:8000/api/users with a forged id",
                                  "curl https://example.com/api/users"])
def test_a_route_path_in_a_url_names_the_route(text):
    """寫成完整 URL 時，主機與連接埠不算路徑：`http://localhost:8000/api/users` 仍然指名 `GET /api/users`。
    In a full URL the host and port are no path: `http://localhost:8000/api/users` still names `GET /api/users`."""
    route = _sym("GET /api/users", "route")
    assert _named([route], text) == [route]
    assert _target([route], text) is route


def test_the_attack_scenario_names_symbols_too():
    """威脅的攻擊向量與攻擊情境都算：只在情境裡提到的符號也會被指名。
    Both the threat's attack vector and its attack scenario count: a symbol mentioned only in the scenario is
    named too."""
    fn = _sym("reset_password")
    threat = _threat("POST /reset", "then call reset_password with a stale token")
    assert named_symbols([fn], threat) == [fn]
    assert target_symbol([fn], threat) is fn

# --- 識別字與路由的整字比對 ／ Whole-word matching of identifiers and routes --------------------------------------
# 從 tests/test_review_reports.py、tests/test_r2_extractor_scanner.py、tests/test_review_sanitize_blackbox_fixes.py
# 搬來（原本呼叫 ReportGenerator._threat_symbol 與 ThreatScenarioBuilder._named_symbols）
# Moved from tests/test_review_reports.py, tests/test_r2_extractor_scanner.py and
# tests/test_review_sanitize_blackbox_fixes.py (they called ReportGenerator._threat_symbol and
# ThreatScenarioBuilder._named_symbols)

def test_target_matches_whole_identifiers_only():
    """`get` 不會命中 `get_user`；完整的識別字才算。
    `get` does not hit `get_user`; only a whole identifier counts."""
    get = _sym("get")
    assert _target([get], "call get_user with a foreign id") is None
    assert _target([get], "call get(1)") is get


def test_target_prefers_the_longest_route():
    """`GET /users/admin` 優先於 `GET /users`，且 `GET /users` 不會命中 `GET /users/admin`。
    `GET /users/admin` wins over `GET /users`, and `GET /users` alone does not hit `GET /users/admin`."""
    short = _sym("GET /users", "route", line=1)
    long_ = _sym("GET /users/admin", "route", line=9)
    text = "HTTP GET /users/admin without a token"
    assert _target([short, long_], text) is long_
    assert _target([long_, short], text) is long_
    assert _target([short], text) is None
    assert _target([short, long_], "GET /users?page=2") is short


def test_target_prefers_routes_over_functions():
    """路由仍然優先於同名的函式。
    Routes still win over functions."""
    fn = _sym("users")
    route = _sym("GET /users", "route")
    assert _target([fn, route], "GET /users") is route
    # 函式的命中比路由長時，路由仍然優先 ／ a route still wins when a function's match is longer
    me = _sym("GET /me", "route")
    long_fn = _sym("update_profile_settings")
    assert _named([long_fn, me], "GET /me calls update_profile_settings") == [long_fn, me]
    assert _target([long_fn, me], "GET /me calls update_profile_settings") is me


_ROUTES = [_sym("GET /", "route", "a.js"), _sym("GET *", "route", "a.js"), _sym("POST /login", "route", "a.js")]


@pytest.mark.parametrize("text", ["read/write and/or", "1 * 10^6 requests", "GET /admin bypass", "GET /.env",
                                  "x / y", "a*b", "path/to/file"])
def test_bare_slash_and_star_in_prose_do_not_name_root_or_wildcard_routes(text):
    assert _named(_ROUTES, text) == []


@pytest.mark.parametrize("text,expected", [
    ("the GET / handler", ["GET /"]),
    ("route '/' leaks", ["GET /"]),
    ('the "/" page', ["GET /"]),
    ("the `*` catch-all", ["GET *"]),
    ("GET * catch-all", ["GET *"]),
    ("POST /login brute force", ["POST /login"]),
])
def test_root_and_wildcard_routes_match_by_full_form_or_quoted_path(text, expected):
    assert _names(text, _ROUTES) == expected


def test_longest_route_match_wins():
    routes = [_sym("GET /api/users", "route", "app.js"), _sym("GET /api/users/:id", "route", "app.js")]
    assert _names("IDOR on GET /api/users/:id with a foreign id", routes) == ["GET /api/users/:id"]
    assert _names("list via GET /api/users", routes) == ["GET /api/users"]


def test_route_paths_with_dots_and_js_identifiers_match_whole():
    symbols = [_sym("GET /api/report.json", "route", "app.js"), _sym("json", path="app.js"),
               _sym("$fetch", path="app.js"), _sym("fetch", path="app.js")]
    assert _names("download /api/report.json unauthenticated", symbols) == ["GET /api/report.json"]
    assert _names("abuse $fetch with a crafted url", symbols) == ["$fetch"]


def test_qualified_method_name_does_not_drag_in_a_same_named_function():
    symbols = [_sym("Service.get_user", "method", "svc.py"), _sym("get_user", "function", "svc.py")]
    assert _names("tamper Service.get_user", symbols) == ["Service.get_user"]
    assert sorted(_names("call get_user directly", symbols)) == ["Service.get_user", "get_user"]
