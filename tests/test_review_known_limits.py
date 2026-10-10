"""先前列為「尚未實作」的符號擷取與 VH-AI-006 限制的回歸測試：JSX 文字詞法分析、hapi 陣列路由、
正規表達式路徑、Flask 工廠的巢狀路由只送審一次，以及指派給名稱的字面值引數清單。
Regression tests for symbol-extraction and VH-AI-006 limits previously listed as not implemented: JSX
text lexing, hapi array routes, regex paths, Flask-factory nested routes reviewed once, and literal
argument lists assigned to a name."""
import ast
import textwrap

from vibeharness.agents.whitebox.ai_static_scanner import AISecurityStaticScanner
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.core.codecontext import render_symbols


def _symbols(tmp_path, name, code):
    f = tmp_path / name
    f.write_text(code, encoding="utf-8")
    return ASTExtractor().parse_file(str(f))


def _by_name(symbols):
    return {s.name: s for s in symbols}


def _routes(symbols):
    return sorted(s.name for s in symbols if s.symbol_type == "route")


def _argv_hits(tmp_path, code):
    path = tmp_path / "app.py"
    path.write_text(code, encoding="utf-8")
    return [f.line_number for f in AISecurityStaticScanner().scan_files([str(path)]) if f.rule_id == "VH-AI-006"]


# --- JSX 文字：`/*`、反引號與引號不會開啟註解或字面值 ---
# --- JSX text: `/*`, backticks and quotes open no comment or literal --------------------------------

def test_block_comment_opener_in_jsx_text_does_not_hide_the_file(tmp_path):
    by = _by_name(_symbols(tmp_path, "page.jsx", (
        "export function Page() {\n"
        "    return <p>Use /* wildcard</p>;\n"
        "}\n"
        "export function later(x) {\n"
        "    return x;\n"
        "}\n"
        "/* a real comment: function phantom() {} */\n"
    )))
    assert set(by) == {"Page", "later"}
    assert (by["Page"].line_start, by["Page"].line_end) == (1, 3)
    assert (by["later"].line_start, by["later"].line_end) == (4, 6)


def test_lone_backtick_and_quotes_in_nested_jsx_text(tmp_path):
    by = _by_name(_symbols(tmp_path, "list.tsx", (
        "export const List = ({ items }) => (\n"
        "    <ul className=\"list\" onClick={() => go(`x`)}>\n"
        "        <li>don`t \"quote {items.length} it's</li>\n"
        "        <>fragment `text</>\n"
        "        {items.map(i => <li key={i}>{i} /* x</li>)}\n"
        "    </ul>\n"
        ");\n"
        "function later() {\n"
        "    return `ok`;\n"
        "}\n"
    )))
    assert set(by) == {"List", "later"}
    assert (by["List"].line_start, by["List"].line_end) == (1, 7)
    assert (by["later"].line_start, by["later"].line_end) == (8, 10)


def test_jsx_text_is_blanked_but_code_and_line_breaks_are_kept():
    source = "const a = <p>Use /* x\nmore `text</p>;\nconst b = 1;\n"
    masked = ASTExtractor._mask_source(source, jsx=True)
    assert len(masked) == len(source) and masked.count("\n") == source.count("\n")
    assert "/*" not in masked and "`" not in masked
    assert "const b = 1;" in masked
    # 沒有 jsx 旗標時（例如 .ts 檔）維持原本的詞法分析 ／ without the jsx flag (e.g. a .ts file) plain lexing stays
    assert "const b = 1;" not in ASTExtractor._mask_source(source)


def test_typescript_generics_in_tsx_fall_back_to_plain_lexing(tmp_path):
    by = _by_name(_symbols(tmp_path, "gen.tsx", (
        "const ident = <T,>(x: T): T => x;\n"
        "const pick = <T extends object>(a: T) => a;\n"
        "function later(y: number): number {\n"
        "    return y < 2 ? y : y / 2;\n"
        "}\n"
    )))
    assert {"ident", "pick", "later"} <= set(by)
    assert (by["later"].line_start, by["later"].line_end) == (3, 5)


def test_failed_jsx_attempts_are_budgeted_per_file(tmp_path):
    # 每個 `<T>` 都是一次掃到檔尾的失敗嘗試；預算用完後照一般程式碼分析，所有函式仍被擷取
    # Each `<T>` is a failed attempt scanning to the end of the file; once the budget is spent plain lexing
    # takes over and every function is still extracted
    code = "".join(f"const g{i} = <T extends object>(x: T) => x;\n" for i in range(200))
    by = _by_name(_symbols(tmp_path, "many.tsx", code))
    assert len(by) == 200 and by["g199"].line_start == 200


# --- 路由：hapi 陣列形式與正規表達式路徑 ---
# --- Routes: hapi array form and regex paths -----------------------------------------------------

def test_hapi_array_form_registers_one_route_per_object(tmp_path):
    symbols = _symbols(tmp_path, "server.js", (
        "server.route([\n"
        "    { method: 'GET', path: '/a', handler },\n"
        "    {\n"
        "        method: ['PUT', 'POST'],\n"
        "        path: '/b/{id}',\n"
        "        handler: (req, h) => h.response('ok'),\n"
        "    },\n"
        "    { notARoute: true },\n"
        "]);\n"
    ))
    by = _by_name(symbols)
    assert _routes(symbols) == ["GET /a", "PUT|POST /b/{id}"]
    assert (by["GET /a"].line_start, by["GET /a"].line_end) == (2, 2)
    assert (by["PUT|POST /b/{id}"].line_start, by["PUT|POST /b/{id}"].line_end) == (3, 7)


def test_regex_paths_on_known_routers_are_routes(tmp_path):
    symbols = _symbols(tmp_path, "routes.js", (
        "app.get(/^\\/users\\/(\\d+)$/, showUser);\n"
        "router.post(/\\/items\\/[a-z]+/i, (req, res) => res.send(1));\n"
        "cache.get(/key/, fallback);\n"
        "app.get(/no-handler/);\n"
    ))
    assert _routes(symbols) == ["GET /^\\/users\\/(\\d+)$/", "POST /\\/items\\/[a-z]+/i"]


def test_identifier_path_without_a_handler_stays_a_settings_read(tmp_path):
    symbols = _symbols(tmp_path, "app.js", (
        "const port = app.get(PORT_SETTING);\n"
        "app.get(USERS_PATH, listUsers);\n"
    ))
    assert _routes(symbols) == ["GET USERS_PATH"]


# --- Python：Flask 工廠的巢狀路由只送審一次 ---
# --- Python: a Flask factory's nested route is reviewed once ---------------------------------------

_FACTORY = (
    "from flask import Flask\n"
    "def create_app():\n"
    "    app = Flask(__name__)\n"
    "    @app.route('/')\n"
    "    def index():\n"
    "        handler_body_marker = 1\n"
    "        return 'x'\n"
    "    @app.get('/one')\n"
    "    def one(): return 1\n"
    "    def register(bp):\n"
    "        @bp.route('/deep')\n"
    "        def deep():\n"
    "            deep_body_marker = 2\n"
    "            return deep_body_marker\n"
    "    return app\n"
)


def test_nested_route_body_appears_once_with_resolvable_lines(tmp_path):
    symbols = _symbols(tmp_path, "factory.py", _FACTORY)
    by = _by_name(symbols)
    outer = by["create_app"]
    assert (outer.line_start, outer.line_end) == (2, 15)
    assert "handler_body_marker" not in outer.source_code and "deep_body_marker" not in outer.source_code
    # 裝飾器與 def 行保留，佔位行寫出被省略的檔案行號
    # Decorators and the def line stay, and the placeholder names the omitted file lines
    assert "@app.route('/')" in outer.source_code and "def index():" in outer.source_code
    assert "...  # lines 6-7: body of route handler `index`, listed separately" in outer.source_code
    assert "lines 13-14: body of route handler `deep`" in outer.source_code
    assert "def one(): return 1" in outer.source_code
    ast.parse(textwrap.dedent(outer.source_code))
    assert "handler_body_marker" in by["index"].source_code and by["index"].line_start == 4
    assert "deep_body_marker" in by["deep"].source_code
    assert _routes(symbols) == ["deep", "index", "one"]


def test_rendered_code_context_carries_each_handler_body_once(tmp_path):
    symbols = _symbols(tmp_path, "factory.py", _FACTORY)
    listing = render_symbols(symbols, str(tmp_path), max_tokens=100_000)
    assert listing.count("handler_body_marker") == 1
    assert listing.count("deep_body_marker = 2") == 1
    # 緊的預算仍然有效：區塊被截斷而不是失敗 ／ a tight budget still works: blocks are truncated, not failed
    tight = render_symbols(symbols, str(tmp_path), max_tokens=120)
    assert tight and len(tight) < len(listing)


# --- VH-AI-006：指派給名稱的字面值引數清單 ---
# --- VH-AI-006: literal argument lists assigned to a name ------------------------------------------

def test_named_literal_argv_gets_the_list_exemption(tmp_path):
    hits = _argv_hits(tmp_path, (
        "import subprocess, openai\n"
        "def run(llm):\n"
        "    branch = llm.predict('which branch?')\n"
        "    cmd = ['git', 'checkout', branch]\n"
        "    subprocess.run(cmd)\n"
        "    shell = ['/bin/sh', '-c', branch]\n"
        "    subprocess.run(shell)\n"
        "    prog = (branch, 'x')\n"
        "    subprocess.run(prog)\n"
        "    status = ['git', 'status']\n"
        "    status.append('--short')\n"
        "    subprocess.run(status)\n"
        "    same = ['git', branch]\n"
        "    subprocess.run(same, shell=True)\n"
    ))
    assert hits == [7, 9, 14]


def test_named_argv_is_conservative_when_rebound_or_mutated(tmp_path):
    hits = _argv_hits(tmp_path, (
        "import subprocess, openai\n"
        "def run(llm, args):\n"
        "    branch = llm.predict('which branch?')\n"
        "    grown = ['git', 'log']\n"
        "    grown.append(branch)\n"
        "    subprocess.run(grown)\n"
        "    extended = ['git']\n"
        "    extended += [branch]\n"
        "    subprocess.run(extended)\n"
        "    rebound = ['git', 'x']\n"
        "    rebound = branch.split()\n"
        "    subprocess.run(rebound)\n"
        "    moved = ['git', 'x']\n"
        "    moved.insert(0, 'sh')\n"
        "    moved.append(branch)\n"
        "    subprocess.run(moved)\n"
        "    for loop in [['git', branch]]:\n"
        "        subprocess.run(loop)\n"
        "    subprocess.run(args)\n"
    ))
    assert hits == [6, 9, 12, 16, 18]
