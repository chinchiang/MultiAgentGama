"""第二輪審查修正的回歸測試：JS/TS 詞法分析器的遞迴與時間上限、JSX 掃描預算、VH-AI-006 的 argv 程式解析
（直譯器、包裝前綴、常數名稱、可變位置引數與關鍵字引數），以及根路由／萬用路由的符號比對。
時間測試的上限刻意寬鬆（修正前要數十秒，修正後只要幾秒），只用來攔截退回平方時間的回歸。
Regression tests for the second-round review fixes: recursion and time bounds of the JS/TS lexer, the JSX scan
budget, VH-AI-006 argv program resolution (interpreters, wrapper prefixes, constant names, variadic and keyword
arguments), and symbol matching of root / wildcard routes.
Timing bounds are deliberately generous (tens of seconds before the fix, a few seconds after it); they only
catch a regression back to quadratic time."""
import sys
import textwrap
import time

import pytest

from vibeharness.agents.blackbox.scenario_builder import ThreatScenarioBuilder
from vibeharness.agents.whitebox.ai_static_scanner import AISecurityStaticScanner
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
from vibeharness.core.models import CodeSymbol

# 約 1 MB 的一般程式碼 ／ about 1 MB of ordinary code
_FILLER = "".join(f"function f{i}() {{ return {i} }}\n" for i in range(36000))


def _parse(tmp_path, name, code):
    f = tmp_path / name
    f.write_text(code, encoding="utf-8")
    extractor = ASTExtractor()
    return extractor, extractor.parse_file(str(f))


def _names(symbols):
    return [s.name for s in symbols]


# 逐行追蹤器（coverage 預設的 ctrace、除錯器）讓這些純 Python 掃描慢約 4 倍；量到的時間先除掉這個倍數，
# 時間上限仍是沒有追蹤時的數字。sys.monitoring（COVERAGE_CORE=sysmon）不設追蹤器，不受影響。
# A line tracer (coverage's default ctrace core, a debugger) makes these pure-Python scans about 4x slower; the
# measured time is divided by that factor first, so the limits stay the untraced figures. sys.monitoring
# (COVERAGE_CORE=sysmon) sets no tracer and is not affected.
_TRACER_SLOWDOWN = 4


def _timed(fn):
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    return result, elapsed / _TRACER_SLOWDOWN if sys.gettrace() is not None else elapsed


# --- 1. 樣板字面值不再遞迴；單一檔案的意外錯誤不中止整次執行 ---
# --- 1. Template literals no longer recurse; an unexpected error in one file does not abort the run --------------

def test_deeply_nested_template_substitutions_do_not_raise_recursion_error(tmp_path):
    code = "const x = `" + "${`" * 3000 + "`}" * 3000 + "`;\nfunction after() { return 1 }\n"
    extractor, symbols = _parse(tmp_path, "deep.js", code)
    assert "after" in _names(symbols)
    assert extractor.parse_failures == []


def test_unclosed_nested_templates_reach_the_end_of_the_file_without_crashing(tmp_path):
    extractor, symbols = _parse(tmp_path, "open.js", "function ok() { return 1 }\nconst x = `" + "${`" * 3000)
    assert _names(symbols) == ["ok"]


def test_template_masking_still_lexes_interpolations_as_code():
    masked = ASTExtractor._mask_source('const s = `a ${x.replace(/\\{/g, "{")} b ${`in ${y}`}`; const t = 1;')
    assert "const t = 1;" in masked
    assert "{" not in masked.split("const s =")[1].split(";")[0]


def test_parse_directory_skips_a_file_whose_lexing_fails_and_keeps_going(tmp_path, monkeypatch):
    (tmp_path / "a_bad.js").write_text("function bad() {}\n", encoding="utf-8")
    (tmp_path / "b_good.js").write_text("function good() {}\n", encoding="utf-8")
    original = ASTExtractor._mask_source

    def flaky(source, jsx=False):
        if "bad" in source:
            raise RecursionError("simulated")
        return original(source, jsx)

    monkeypatch.setattr(ASTExtractor, "_mask_source", staticmethod(flaky))
    extractor = ASTExtractor()
    symbols = extractor.parse_directory(str(tmp_path))
    assert _names(symbols) == ["good"]
    assert extractor.parse_failures == [str(tmp_path / "a_bad.js")]


def test_parse_directory_survives_an_unexpected_error_outside_the_lexer(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("def a():\n    pass\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def b():\n    pass\n", encoding="utf-8")
    original = ASTExtractor._parse_python_file

    def flaky(self, path):
        if path.endswith("a.py"):
            raise MemoryError("simulated")
        return original(self, path)

    monkeypatch.setattr(ASTExtractor, "_parse_python_file", flaky)
    extractor = ASTExtractor()
    assert _names(extractor.parse_directory(str(tmp_path))) == ["b"]
    assert extractor.parse_failures == [str(tmp_path / "a.py")]


def test_nested_snippets_beyond_the_size_cap_become_a_parse_failure(tmp_path):
    # 巢狀的路由片段彼此包含（總量是平方大小）：超過上限時檔案略過並回報，而不是耗盡記憶體
    # Nested route snippets contain one another (quadratic total): beyond the cap the file is skipped and reported
    code = "app.get('/x', () => {\n" * 2000 + "})\n" * 2000
    extractor, symbols = _parse(tmp_path, "nested.js", code)
    assert symbols == []
    assert extractor.parse_failures == [str(tmp_path / "nested.js")]


def test_nested_classes_are_reviewed_inside_the_enclosing_class(tmp_path):
    code = "class A {\n m() {" * 3000 + "}}" * 3000
    _, symbols = _parse(tmp_path, "nested_class.js", code)
    assert _names(symbols) == ["A", "A.m"]
    assert sum(len(s.source_code) for s in symbols) <= 3 * len(code)


def test_a_newline_ends_the_previous_word_so_return_starts_a_regex():
    # 修正前 `b\nreturn` 被當成一個詞 "breturn"，`/{x/` 變成除法，`{` 沒被清空
    # Before the fix `b\nreturn` was one word "breturn", so `/{x/` was division and the `{` stayed
    assert ASTExtractor._mask_source("const a = b\nreturn /{x/.test(c)\n") == "const a = b\nreturn /   .test(c)\n"


# --- 4. JSX 掃描預算：便宜的失敗不花預算，總掃描量與檔案大小成線性 ---
# --- 4. The JSX scan budget: cheap failures cost nothing, total scanning is linear in the file size ---------------

@pytest.mark.parametrize("generic", ["<T,>(x: T) => x", "<T extends unknown>(x: T) => x", "<T = string>() => 1"])
def test_ts_generics_do_not_spend_the_jsx_budget(tmp_path, generic):
    code = f"const g = {generic};\n" * 60 + "const el = <div>a /* b</div>;\nfunction after() { return 1 }\n"
    _, symbols = _parse(tmp_path, "page.tsx", code)
    assert "after" in _names(symbols)


def test_cheap_jsx_failures_do_not_spend_the_budget(tmp_path):
    code = "y = <a % b;\n" * 200 + "const el = <p>a /* b</p>;\nfunction after() { return 1 }\n"
    _, symbols = _parse(tmp_path, "cmp.jsx", code)
    assert "after" in _names(symbols)


def test_unclosed_jsx_attribute_containers_scan_linear_time(tmp_path):
    # 修正前約 12–60 秒 ／ about 12-60 s before the fix
    code = "x = <a b={\n" * 40 + _FILLER
    (_, symbols), elapsed = _timed(lambda: _parse(tmp_path, "unclosed.js", code))
    assert elapsed < 40
    assert "f35999" in _names(symbols)


def test_many_unclosed_jsx_elements_scan_linear_time(tmp_path):
    code = "x = <a>\n" * 2000 + "x = <a b=\"\n" * 2000 + _FILLER
    _, elapsed = _timed(lambda: _parse(tmp_path, "open.jsx", code))
    assert elapsed < 40


# --- 5. JS 擷取器的近線性時間 ---
# --- 5. Near-linear time of the JS extractor ------------------------------------------------------------------------

def test_a_one_megabyte_file_of_functions_parses_quickly(tmp_path):
    # 修正前約 30 秒（每個符號都重新切行，重疊檢查是線性的） ／ about 30 s before the fix (lines re-split per symbol, linear overlap check)
    (_, symbols), elapsed = _timed(lambda: _parse(tmp_path, "many.js", _FILLER))
    assert len(symbols) == 36000
    assert elapsed < 20


def test_whitespace_heavy_class_body_parses_quickly(tmp_path):
    code = "class A {\n" + "a " * 150000 + "\n  m() { return 1 }\n" + " " * 300000 + "}\n"
    (_, symbols), elapsed = _timed(lambda: _parse(tmp_path, "ws.js", code))
    assert _names(symbols) == ["A", "A.m"]
    assert elapsed < 20


@pytest.mark.parametrize("unit", [
    "function a(\n", ") =>\n", "x = a => (\n", "app.get(\n", "class A ", "function a <", "a(): <\n",
    "app.route({", "function f(): (",
])
def test_pathological_repetitions_parse_in_linear_time(tmp_path, unit):
    code = unit * (600_000 // len(unit))
    extractor, elapsed = _timed(lambda: _parse(tmp_path, "rep.ts", code)[0])
    assert elapsed < 20
    assert extractor.parse_failures == []


@pytest.mark.parametrize("unit,close", [("app.get(", ")"), ("app.route([", "])"), ("function a(", ")")])
def test_deeply_nested_calls_parse_in_linear_time(tmp_path, unit, close):
    n = 300_000 // len(unit + close)
    _, elapsed = _timed(lambda: _parse(tmp_path, "nest.js", unit * n + close * n))
    assert elapsed < 20


def test_lookup_tables_agree_with_the_reference_scans():
    # 配對表／敘述結尾索引與原本逐字元掃描的結果完全相同（隨機的括號字串）
    # The pair tables / statement-end index give exactly the results of the original character scans (random bracket strings)
    import random
    rng = random.Random(7)

    def reference_open_paren(masked, close_pos):
        depth = 0
        for i in range(close_pos, -1, -1):
            if masked[i] == ")":
                depth += 1
            elif masked[i] == "(":
                depth -= 1
                if depth == 0:
                    return i
        return 0

    for _ in range(200):
        masked = "".join(rng.choice("(){}[];\n ab") for _ in range(rng.randint(1, 80)))
        extractor = ASTExtractor()
        for pos, c in enumerate(masked):
            for open_ch, close_ch in (("(", ")"), ("{", "}"), ("[", "]")):
                if c == open_ch:
                    assert extractor._match_pair(masked, pos, open_ch, close_ch) == \
                        ASTExtractor._match_delim(masked, pos, open_ch, close_ch)
            if c == ")":
                assert extractor._find_open_paren(masked, pos) == reference_open_paren(masked, pos)
            assert extractor._statement_end(masked, pos) == ASTExtractor._end_of_statement(masked, pos)


def test_routes_and_methods_are_unchanged_by_the_lookup_tables(tmp_path):
    _, symbols = _parse(tmp_path, "srv.js", textwrap.dedent("""\
        const app = express();
        app.get('/users/:id', (req, res) => { res.send(req.params.id) });
        server.route({ method: 'POST', handler: (r) => { return [1, 2, 3].map((x) => x * 2) }, path: '/later' });
        class Svc {
          async load(id: string): Promise<Array<{ id: string }>> { return [] }
          static make<T>(x: T) { return x }
        }
        const fn = (a, b) => a + b
        """))
    assert sorted(_names(symbols)) == sorted(["GET /users/:id", "POST /later", "Svc", "Svc.load", "Svc.make", "fn"])


# --- 2／3. VH-AI-006：argv 的程式解析 ---
# --- 2 / 3. VH-AI-006: resolving the argv program --------------------------------------------------------------------

def _argv_hit(tmp_path, line):
    code = textwrap.dedent(f"""\
        import asyncio, os, shutil, subprocess, sys, openai
        SHELL = "bash"
        GIT = "git"
        BASH = shutil.which("bash")
        GITW = shutil.which("git")
        client = openai.OpenAI()
        async def f(self, exe):
            a = client.chat.completions.create(model="m", max_tokens=5)
            {line}
        """)
    path = tmp_path / "app.py"
    path.write_text(code, encoding="utf-8")
    return any(x.rule_id == "VH-AI-006" for x in AISecurityStaticScanner().scan_files([str(path)]))


@pytest.mark.parametrize("line", [
    "subprocess.run([sys.executable, '-c', a])",
    "subprocess.run(['python3.11', '-c', a])",
    "subprocess.run(['node18', '-e', a])",
    "subprocess.run(['pwsh', '-Command', a])",
    "subprocess.run(['perl', '-e', a])",
    "subprocess.run(['ruby', '-e', a])",
    "subprocess.run(['php', '-r', a])",
    "subprocess.run(['deno', 'eval', a])",
    "subprocess.run(['bun', '-e', a])",
    "subprocess.run(['/usr/local/bin/python3', '-c', a])",
    "subprocess.run(['C:\\\\Python\\\\python.exe', '-c', a])",
    "subprocess.run(['/usr/bin/env', 'python3', '-c', a])",
    "subprocess.run(['env', 'FOO=1', 'bash', '-c', a])",
    "subprocess.run(['ssh', 'host', a])",
    "subprocess.run(['sudo', 'bash', '-c', a])",
    "subprocess.run(['sudo', '-u', 'bob', 'bash', '-c', a])",
    "subprocess.run(['doas', 'sh', '-c', a])",
    "subprocess.run(['nohup', 'sh', '-c', a])",
    "subprocess.run(['xargs', 'sh', '-c', a])",
    "subprocess.run(['timeout', '5', 'sh', '-c', a])",
    "subprocess.run(['nice', '-n', '10', 'sh', '-c', a])",
    "subprocess.run(['sudo', a])",
    "subprocess.run([SHELL, '-c', a])",
    "subprocess.run([BASH, '-c', a])",
    "subprocess.run([exe, '-c', a])",
    "subprocess.run([self.exe, '-c', a])",
    "subprocess.run(['x', '-c', a], executable='/bin/bash')",
    "await asyncio.create_subprocess_exec('bash', '-c', a)",
    "await asyncio.create_subprocess_exec(*['bash', '-c', a])",
    "subprocess.run(args=a, shell=True)",
    "subprocess.run(args=['bash', '-c', a])",
    "os.system(command=a)",
])
def test_interpreter_argv_with_model_output_is_flagged(tmp_path, line):
    assert _argv_hit(tmp_path, line)


@pytest.mark.parametrize("line", [
    "subprocess.run(['git', 'checkout', '--', a])",
    "subprocess.run([GIT, 'checkout', a])",
    "subprocess.run([GITW, 'checkout', a])",
    "subprocess.run(['sudo', 'git', 'checkout', a])",
    "subprocess.run(['sudo', '-u', 'bob', 'git', 'pull', a])",
    "subprocess.run(['timeout', '10', 'git', 'pull', a])",
    "await asyncio.create_subprocess_exec('git', 'checkout', a)",
    "subprocess.run([sys.executable, '-m', 'pip', 'install', 'x'])",
    "subprocess.run(args=['git', 'checkout', a])",
])
def test_plain_program_argv_keeps_the_list_exemption(tmp_path, line):
    assert not _argv_hit(tmp_path, line)


def test_a_name_rebound_to_a_non_constant_is_not_a_known_program(tmp_path):
    # `GIT` 若也被綁定到非常數，就無法確定是哪個程式：保守地標記
    # When `GIT` is also bound to a non-constant the program cannot be determined: flagged conservatively
    assert _argv_hit(tmp_path, "GIT = os.environ['X']; subprocess.run([GIT, 'checkout', a])")


def test_scanner_skips_a_file_whose_analysis_fails(tmp_path, monkeypatch):
    bad, good = tmp_path / "bad.py", tmp_path / "good.py"
    bad.write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
    good.write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
    original = AISecurityStaticScanner._scan_python

    def flaky(self, path, text):
        if path.endswith("bad.py"):
            raise RecursionError("simulated")
        return original(self, path, text)

    monkeypatch.setattr(AISecurityStaticScanner, "_scan_python", flaky)
    findings = AISecurityStaticScanner().scan_files([str(bad), str(good)])
    assert {f.file_path for f in findings if f.rule_id == "VH-AI-003"} == {str(good)}


# --- 6. 根路由與萬用路由的符號比對 ---
# --- 6. Symbol matching of root and wildcard routes ------------------------------------------------------------------

def _route(name):
    return CodeSymbol(name=name, symbol_type="route", file_path="a.js", line_start=1, line_end=1, signature=name,
                      source_code="", parameters=[])


_ROUTES = [_route("GET /"), _route("GET *"), _route("POST /login")]


@pytest.mark.parametrize("text", ["read/write and/or", "1 * 10^6 requests", "GET /admin bypass", "GET /.env",
                                  "x / y", "a*b", "path/to/file"])
def test_bare_slash_and_star_in_prose_do_not_name_root_or_wildcard_routes(text):
    assert ThreatScenarioBuilder._named_symbols(_ROUTES, text) == []


@pytest.mark.parametrize("text,expected", [
    ("the GET / handler", ["GET /"]),
    ("route '/' leaks", ["GET /"]),
    ('the "/" page', ["GET /"]),
    ("the `*` catch-all", ["GET *"]),
    ("GET * catch-all", ["GET *"]),
    ("POST /login brute force", ["POST /login"]),
])
def test_root_and_wildcard_routes_match_by_full_form_or_quoted_path(text, expected):
    assert [s.name for s in ThreatScenarioBuilder._named_symbols(_ROUTES, text)] == expected
