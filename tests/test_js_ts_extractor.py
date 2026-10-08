"""JS/TS extractor: real brace matching, literal/comment masking, arrows, class methods, routes."""
import os

from vibeharness.agents.whitebox.ast_extractor import ASTExtractor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _symbols(tmp_path, name, code):
    f = tmp_path / name
    f.write_text(code, encoding="utf-8")
    extractor = ASTExtractor()
    return extractor, extractor.parse_file(str(f))


def _by_name(symbols):
    return {s.name: s for s in symbols}


# --- Accurate spans -------------------------------------------------------------------

def test_function_span_covers_the_whole_body(tmp_path):
    _, symbols = _symbols(tmp_path, "a.js", (
        "function handler(req) {\n" +
        "    const step = req.body;\n" * 40 +
        "    return step;\n"
        "}\n"
    ))
    sym = _by_name(symbols)["handler"]
    # 42 lines total: no fixed 25-line window truncating the body
    assert sym.line_start == 1 and sym.line_end == 43
    assert sym.source_code.count("const step = req.body;") == 40
    assert sym.source_code.rstrip().endswith("}")
    assert sym.parameters == ["req"]


def test_adjacent_symbols_do_not_duplicate_each_other(tmp_path):
    _, symbols = _symbols(tmp_path, "a.js", (
        "function first() {\n    return 1;\n}\n\n"
        "function second() {\n    return 2;\n}\n"
    ))
    by = _by_name(symbols)
    assert "return 2;" not in by["first"].source_code
    assert "return 1;" not in by["second"].source_code
    assert by["first"].line_end == 3 and by["second"].line_start == 5


# --- Masking: comments, strings and regex literals cannot create phantoms --------------

def test_comments_and_strings_do_not_create_phantoms(tmp_path):
    _, symbols = _symbols(tmp_path, "a.js", (
        "// app.get('/ghost', handler);\n"
        "/* function commentedOut() { */\n"
        "const s = \"function fakeInString() {\";\n"
        "const re = /function fakeRegex\\(\\) \\{/g;\n"
        "function real() { return 1; }\n"
    ))
    names = [s.name for s in symbols]
    assert names == ["real"]


def test_braces_inside_strings_do_not_confuse_matching(tmp_path):
    _, symbols = _symbols(tmp_path, "a.js", (
        "function tricky() {\n"
        "    const json = '{ not a real brace }';\n"
        "    const t = `template ${withBraces({a: 1})} literal`;\n"
        "    return json;\n"
        "}\n"
    ))
    sym = _by_name(symbols)["tricky"]
    assert sym.line_end == 5
    assert sym.source_code.rstrip().endswith("}")


# --- Declaration variants ---------------------------------------------------------------

def test_arrow_function_variants(tmp_path):
    _, symbols = _symbols(tmp_path, "a.ts", (
        "const one = x => x + 1;\n"
        "export const two = async (a, b = f(1)) => {\n"
        "    return a + b;\n"
        "};\n"
        "let three = (x) =>\n"
        "    x.map(v => v * 2);\n"
    ))
    by = _by_name(symbols)
    assert set(by) == {"one", "two", "three"}
    assert by["two"].line_end == 4
    assert by["two"].parameters == ["a", "b"]
    # single-expression arrow bodies stop at the statement, not at file end
    assert by["one"].source_code.strip() == "const one = x => x + 1;"
    assert "x.map(v => v * 2)" in by["three"].source_code
    assert by["three"].line_end == 6


def test_generators_and_multiline_signatures(tmp_path):
    _, symbols = _symbols(tmp_path, "a.js", (
        "function* ids() {\n"
        "    yield 1;\n"
        "}\n"
        "async function\n"
        "    spaced(\n"
        "        a,\n"
        "        b\n"
        "    ) {\n"
        "    return a + b;\n"
        "}\n"
    ))
    by = _by_name(symbols)
    assert by["ids"].line_start == 1 and by["ids"].line_end == 3
    assert by["spaced"].line_start == 4 and by["spaced"].line_end == 10
    assert by["spaced"].parameters == ["a", "b"]


def test_class_methods_are_extracted_with_control_flow_ignored(tmp_path):
    _, symbols = _symbols(tmp_path, "a.js", (
        "class Cart {\n"
        "    constructor(items) {\n"
        "        this.items = items;\n"
        "    }\n"
        "    static build(items) {\n"
        "        if (items.length === 0) {\n"
        "            return null;\n"
        "        }\n"
        "        while (items.length > 10) {\n"
        "            items.pop();\n"
        "        }\n"
        "        return new Cart(items);\n"
        "    }\n"
        "    async total() { return 0; }\n"
        "}\n"
    ))
    by = _by_name(symbols)
    assert "Cart" in by and by["Cart"].symbol_type == "class"
    assert by["Cart.constructor"].symbol_type == "method"
    assert by["Cart.build"].symbol_type == "method"
    assert by["Cart.build"].parameters == ["items"]
    assert by["Cart.total"].line_start == 14
    # control flow statements are not methods
    assert "Cart.if" not in by and "Cart.while" not in by


# --- Routes ------------------------------------------------------------------------------

def test_routes_across_receivers_and_multiline_calls(tmp_path):
    _, symbols = _symbols(tmp_path, "a.js", (
        "app.get('/api/orders', (req, res) => {\n"
        "    res.json([]);\n"
        "});\n"
        "router.post('/api/orders', createOrder);\n"
        "server.delete(\n"
        "    '/api/orders/:id',\n"
        "    removeOrder\n"
        ");\n"
        "fastify.patch('/api/orders/:id', async (req) => { return {}; });\n"
    ))
    routes = {s.name: s for s in symbols if s.symbol_type == "route"}
    assert set(routes) == {
        "GET /api/orders", "POST /api/orders", "DELETE /api/orders/:id", "PATCH /api/orders/:id"
    }
    # the span covers the whole callback, not a fixed 15-line window
    assert routes["GET /api/orders"].line_start == 1 and routes["GET /api/orders"].line_end == 3
    assert "res.json" in routes["GET /api/orders"].source_code


def test_nextjs_app_router_handlers_are_routes(tmp_path):
    _, symbols = _symbols(tmp_path, "route.ts", (
        "export async function GET(request: Request) {\n"
        "    return Response.json({});\n"
        "}\n"
        "export async function POST(request: Request) {\n"
        "    return Response.json({});\n"
        "}\n"
    ))
    routes = [s for s in symbols if s.symbol_type == "route"]
    assert sorted(r.name for r in routes) == ["GET", "POST"]


def test_route_paths_from_template_literals(tmp_path):
    _, symbols = _symbols(tmp_path, "a.js", "app.get(`/api/items`, listItems);\n")
    assert [s.name for s in symbols if s.symbol_type == "route"] == ["GET /api/items"]
