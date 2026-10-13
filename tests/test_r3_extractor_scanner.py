"""第三輪審查修正的回歸測試：JS/TS 詞法分析器與 VH-AI-006 污染分析的平方時間路徑（箭號往回找型別註記、行內失敗的正規表達式
嘗試、綁定的型別註記、每個執行點重掃範疇、深層屬性鏈）、每個檔案的分析時間上限、argv 程式解析（直譯器的腳本／模組、
包裝程式的選項值、執行器、標準輸入、別名與新的執行點），以及 JS 擷取的缺口（物件型別泛型、`extends X<{...}>`、
`.post<{...}>` 路由、壓縮過的單行檔案）。
時間測試的上限刻意寬鬆（修正前要數十秒，修正後不到一秒），只用來攔截退回平方時間的回歸。
Regression tests for the third-round review fixes: the quadratic paths of the JS/TS lexer and the VH-AI-006 taint
analysis (the arrow look-back for a type annotation, failed regex attempts on one line, binding annotations, every
sink rescanning its scope, deep attribute chains), the per-file analysis time cap, argv program resolution
(interpreter scripts / modules, wrapper option values, runners, standard input, aliases and new sinks), and JS
extraction gaps (object-type generics, `extends X<{...}>`, `.post<{...}>` routes, minified one-line files).
Timing bounds are deliberately generous (tens of seconds before the fix, under a second after it); they only catch a
regression back to quadratic time."""
import logging
import random
import textwrap
import time

import pytest

import vibeharness.agents.whitebox.ai_static_scanner as scanner_module
from vibeharness.agents.whitebox.ai_static_scanner import AISecurityStaticScanner
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor


def _parse(tmp_path, name, code):
    f = tmp_path / name
    f.write_text(code, encoding="utf-8")
    extractor = ASTExtractor()
    return extractor, extractor.parse_file(str(f))


def _timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def _by_name(symbols):
    return {s.name: s for s in symbols}


# --- 1. JS/TS 詞法分析器：線性時間 ---
# --- 1. JS/TS lexer: linear time ----------------------------------------------------------------------------------

@pytest.mark.parametrize("name,code", [
    ("arrows.ts", "=>" * 20000),            # 修正前約 20 秒 ／ about 20 s before the fix
    ("arrows_ws.ts", "x: a => " * 20000),
    ("regex.js", "/[" * 20000),             # 修正前約 50 秒，同一行 ／ about 50 s before the fix, one line
    ("regex2.js", "x = (/a" * 20000),
    ("binding.ts", "a: b " * 40000),        # 修正前約 30 秒 ／ about 30 s before the fix
])
def test_pathological_lines_lex_in_linear_time(tmp_path, name, code):
    (extractor, _), elapsed = _timed(lambda: _parse(tmp_path, name, code))
    assert elapsed < 10
    assert extractor.parse_failures == []


def _reference_mask_regex(source, out, i):
    """修正前的正規表達式字面值掃描（逐次掃到行尾），作為結果相同的參考。
    The regex-literal scan before the fix (each attempt scans to the end of the line), the reference for equal results."""
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
    while i < n and source[i].isalpha():
        out[i] = " "
        i += 1
    return i


def test_regex_table_agrees_with_the_reference_scan():
    # 每行只算一次的結尾表與原本逐次掃描的結果相同（跳脫字元後接換行除外：正規表達式字面值不能跨行）
    # The once-per-line closing table gives the original scan's results (except an escape followed by a line break:
    # a regex literal cannot span lines)
    rng = random.Random(11)
    for _ in range(300):
        source = "".join(rng.choice("/[]\\ab\n") for _ in range(rng.randint(1, 60)))
        if "\\\n" in source:
            continue
        for i, c in enumerate(source):
            if c != "/":
                continue
            expected_out, actual_out = list(source), list(source)
            assert ASTExtractor._mask_regex(source, actual_out, i) == _reference_mask_regex(source, expected_out, i)
            assert actual_out == expected_out


def _reference_colon_back(masked, pos):
    """修正前的型別註記往回走（無上限），作為結果相同的參考 ／ The unbounded annotation walk-back before the fix."""
    depth = 0
    k = pos
    while k >= 0:
        c = masked[k]
        if c == ">" and k > 0 and masked[k - 1] == "=":
            k -= 2
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


def test_annotation_look_back_agrees_with_the_reference_walk():
    # 備忘的往回走與原本的走法結果相同（沒有括號群組的隨機型別片段；群組改用配對表跳過）
    # The memoized walk-back gives the original walk's results (random type fragments without bracket groups; groups
    # are now skipped via the pair tables)
    rng = random.Random(5)
    for _ in range(300):
        masked = "".join(rng.choice("ab:<>=;, \n") for _ in range(rng.randint(1, 50)))
        extractor = ASTExtractor()
        for pos in range(len(masked)):
            assert extractor._annotation_colon_back(masked, pos) == _reference_colon_back(masked, pos)


def test_return_type_and_annotated_arrows_are_still_found(tmp_path):
    _, symbols = _parse(tmp_path, "a.ts", textwrap.dedent("""\
        const add = (a: number, b: number): Promise<Array<{ id: string }>> => fetchAll(a, b)
        export const handler: NextApiHandler<{ ok: boolean }> = async (req, res) => { res.json({}) }
        const id = <T,>(x: T): T => x
        """))
    assert sorted(_by_name(symbols)) == ["add", "handler", "id"]


# --- 7. JS 擷取的缺口 ---
# --- 7. JS extraction gaps ----------------------------------------------------------------------------------------

def test_object_type_generics_keep_the_function(tmp_path):
    _, symbols = _parse(tmp_path, "list.tsx", textwrap.dedent("""\
        export function List<T extends { id: string }>(props: { items: T[] }) {
          return <ul>{props.items.map(i => <li key={i.id}>x</li>)}</ul>
        }
        function useX<T extends {id:string; n: number}>(x: T) {
          return x
        }
        """))
    by_name = _by_name(symbols)
    assert sorted(by_name) == ["List", "useX"]
    assert (by_name["List"].line_start, by_name["List"].line_end) == (1, 3)


def test_class_extending_a_generic_with_an_object_type_keeps_its_body(tmp_path):
    _, symbols = _parse(tmp_path, "legacy.tsx", textwrap.dedent("""\
        class Legacy extends React.Component<{ n: number }, { m: string }> {
          state = { m: '' }
          render() {
            return <div>{this.props.n}</div>
          }
          componentDidMount() {
            this.setState({ m: 'x' })
          }
        }
        """))
    by_name = _by_name(symbols)
    assert sorted(by_name) == ["Legacy", "Legacy.componentDidMount", "Legacy.render"]
    assert (by_name["Legacy"].line_start, by_name["Legacy"].line_end) == (1, 9)


def test_fastify_generic_route_registrations_are_routes(tmp_path):
    _, symbols = _parse(tmp_path, "srv.ts", textwrap.dedent("""\
        const server = Fastify()
        server.post<{ Body: { a: string }; Reply: string }>('/ping', opts, async (req, reply) => {
          return 'pong'
        })
        server.get<{ Querystring: Q }>('/q', async (req) => req.query)
        """))
    assert sorted(s.name for s in symbols if s.symbol_type == "route") == ["GET /q", "POST /ping"]


def test_commas_inside_generic_parameter_types_do_not_split_parameters(tmp_path):
    _, symbols = _parse(tmp_path, "p.ts", "function route(path: string, app: Hono<E, S, B>, extra?: Map<K, V>) { return 1 }\n")
    assert symbols[0].parameters == ["path", "app", "extra?"]


# --- 8. 壓縮過的單行檔案：片段以字元位置切齊 ---
# --- 8. Minified one-line files: snippets are cut at character positions -------------------------------------------

def test_symbols_of_a_minified_one_line_file_survive_the_snippet_cap(tmp_path):
    code = ("class A{constructor(){this.x=1}foo(a){return a+1}bar(b){return b*2}}"
            + "".join(f"function f{i}(x){{return x+{i}}}" for i in range(3000)) + "\n")
    extractor, symbols = _parse(tmp_path, "min.js", code)
    assert extractor.parse_failures == []
    by_name = _by_name(symbols)
    assert len(symbols) == 3001
    assert by_name["f2999"].source_code == "function f2999(x){return x+2999}"
    assert all(len(s.source_code) < 3000 for s in symbols)


def test_ordinary_files_keep_whole_line_snippets(tmp_path):
    _, symbols = _parse(tmp_path, "a.js", "const pad = 1; function f() { return 1 }\n")
    assert _by_name(symbols)["f"].source_code == "const pad = 1; function f() { return 1 }"


# --- 1／4. VH-AI-006：線性時間與每個檔案的時間上限 ---
# --- 1 / 4. VH-AI-006: linear time and the per-file time cap --------------------------------------------------------

_AI_HEAD = ("import subprocess, openai\nclient = openai.OpenAI()\ndef f():\n"
            "    a = client.chat.completions.create(model='m', max_tokens=1)\n")


@pytest.mark.parametrize("body", [
    "    cmd = ['git', a]\n" + "    subprocess.run(cmd)\n" * 4000,       # 修正前約 2 分鐘 ／ about 2 min before the fix
    "    cmd = ['git', a]\n    subprocess.run(cmd)\n" * 2000,            # 修正前約 30 秒 ／ about 30 s before the fix
    "    cmd = ['git']\n" + "    cmd.append('x')\n    subprocess.run(cmd)\n" * 2000,
    ("    x = a" + ".b" * 3000 + "\n") * 20,                               # 修正前約 20 秒 ／ about 20 s before the fix
])
def test_many_sinks_and_deep_chains_scan_in_linear_time(tmp_path, body):
    path = tmp_path / "app.py"
    path.write_text(_AI_HEAD + body, encoding="utf-8")
    scanner = AISecurityStaticScanner()
    _, elapsed = _timed(lambda: scanner.scan_files([str(path)]))
    assert elapsed < 10
    assert scanner.incomplete_files == []


def test_a_file_over_the_time_cap_is_disclosed_and_the_scan_goes_on(tmp_path, monkeypatch, caplog):
    slow, other = tmp_path / "slow.py", tmp_path / "other.py"
    slow.write_text(_AI_HEAD + "    key = 'AKIAABCDEFGHIJKLMNOP'\n" + "    x = a + 1\n" * 3000, encoding="utf-8")
    other.write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
    monkeypatch.setattr(scanner_module, "_MAX_SCAN_SECONDS_PER_FILE", 0.0)
    scanner = AISecurityStaticScanner()
    with caplog.at_level(logging.WARNING, logger="VibeHarness.AIStaticScanner"):
        findings = scanner.scan_files([str(slow), str(other)])
    assert scanner.incomplete_files == [str(slow)]
    assert any("slow.py" in r.getMessage() and "cap" in r.getMessage() for r in caplog.records)
    # 與語言無關的規則已在 Python 分析之前執行，其他檔案的分析照常（時間上限每個檔案重新計算）
    # The language-agnostic rules ran before the Python analysis, and the other file is analyzed as usual (the cap
    # restarts for each file)
    assert {f.rule_id for f in findings if f.file_path == str(slow)} >= {"VH-AI-007"}
    monkeypatch.setattr(scanner_module, "_MAX_SCAN_SECONDS_PER_FILE", 30.0)
    assert [f.rule_id for f in AISecurityStaticScanner().scan_files([str(other)])] == ["VH-AI-003"]


# --- 5／6. VH-AI-006：argv 的程式解析 ---
# --- 5 / 6. VH-AI-006: resolving the argv program -------------------------------------------------------------------

def _verdict(tmp_path, lines):
    code = textwrap.dedent("""\
        import asyncio, functools, os, pty, shutil, subprocess, sys, openai
        from subprocess import PIPE
        SHELL = "bash"
        GIT = "git"
        TOOL = os.environ.get("TOOL", "tool")
        client = openai.OpenAI()
        async def f(self, exe, loop, proto):
            a = client.chat.completions.create(model="m", max_tokens=5)
        """) + "".join(f"    {line}\n" for line in lines.split("; "))
    path = tmp_path / "app.py"
    path.write_text(code, encoding="utf-8")
    hits = [x for x in AISecurityStaticScanner().scan_files([str(path)]) if x.rule_id == "VH-AI-006"]
    return hits[0].severity.value if hits else None


@pytest.mark.parametrize("line", [
    "subprocess.run([sys.executable, 'tool.py', a])",
    "subprocess.run([sys.executable, '-m', 'mytool', a])",
    "subprocess.run(['python3', 'script.py', a])",
    "subprocess.run(['node', 'cli.js', a])",
    "subprocess.run(['bash', 'script.sh', a])",
    "subprocess.run(['sh', '-c', 'echo \"$1\"', 'x', a])",
    "subprocess.run(['nice', '-n', '5', 'python', 'tool.py', a])",
    "subprocess.run(['xargs', '-0', 'rm', a])",
    "subprocess.run(['xargs', 'rm'], input=a)",
    "subprocess.run(['command', '-v', a])",
    "subprocess.run(['sudo', '-g', 'sh', 'git', a])",
    "subprocess.run(['timeout', '10s', 'git', a])",
    "subprocess.run(['git', 'checkout', '--', a])",
    "subprocess.run(['git', 'switch', '-c', a])",
    "subprocess.run(['python3', 'x.py'], input=a)",
    "subprocess.run(['docker', 'build', a])",
    "subprocess.run(['uv', 'pip', 'install', a])",
    "subprocess.run(['find', '.', '-name', a])",
    "subprocess.run(['grep', '-e', a, 'file'])",
    "os.execv('/usr/bin/git', ['git', 'checkout', a])",
    "subprocess.run(['git', 'checkout', a], executable='bash')",
])
def test_scripts_modules_and_wrapper_option_values_are_not_flagged(tmp_path, line):
    assert _verdict(tmp_path, line) is None


@pytest.mark.parametrize("line", [
    "subprocess.run(['sudo', '-u', 'bob', '--', 'bash', '-c', a])",
    "subprocess.run(['timeout', '--signal', 'KILL', '5', 'bash', '-c', a])",
    "subprocess.run(['env', '-S', 'bash -c', a])",
    "subprocess.run(['uv', 'run', 'python', '-c', a])",
    "subprocess.run(['poetry', 'run', 'python', '-c', a])",
    "subprocess.run(['pipenv', 'run', 'sh', '-c', a])",
    "subprocess.run(['conda', 'run', '-n', 'env', 'python', '-c', a])",
    "subprocess.run(['pdm', 'run', 'python', '-c', a])",
    "subprocess.run(['npx', 'tsx', '-e', a])",
    "subprocess.run(['npx', a])",
    "subprocess.run(['pnpm', 'exec', 'node', '-e', a])",
    "subprocess.run(['docker', 'exec', '-it', 'c', 'sh', '-c', a])",
    "subprocess.run(['docker', 'run', '--rm', '-v', '/a:/b', 'img', 'sh', '-c', a])",
    "subprocess.run(['kubectl', 'exec', 'p', '--', 'sh', '-c', a])",
    "subprocess.run(['find', '.', '-exec', 'sh', '-c', a, ';'])",
    "subprocess.run(['flock', '/tmp/l', 'sh', '-c', a])",
    "subprocess.run(['strace', '-f', 'sh', '-c', a])",
    "subprocess.run(['script', '-q', '-c', a, '/dev/null'])",
    "subprocess.run(['watch', a])",
    "subprocess.run(['python3.11-dbg', '-c', a])",
    "subprocess.run(['bash', '-ec', a])",
    "subprocess.run(['perl', '-ne', a])",
    "subprocess.run(['cmd', '/c', 'dir', a])",
    "subprocess.run(['powershell', 'Get-Item', a])",
    "subprocess.run(['sed', a, 'f'])",
    "subprocess.run(['sqlite3', 'db', a])",
    "subprocess.run(['psql', '-c', a])",
    "subprocess.run(['mysql', '-e', a])",
    "subprocess.run(['git', '-c', f'core.sshCommand={a}', 'fetch'])",
    "subprocess.run(['python3'], input=a)",
    "subprocess.run(['sh'], input=a)",
    "subprocess.run(['ssh', 'host'], input=a)",
    "subprocess.run(['xargs', '-I{}', 'sh', '-c', 'echo {}'], input=a)",
    "p = subprocess.Popen(['sh'], stdin=PIPE); p.communicate(a)",
    "subprocess.Popen(['sh'], stdin=PIPE).communicate(a)",
    "proc = await asyncio.create_subprocess_exec('python3', stdin=PIPE); await proc.communicate(a)",
    "await asyncio.create_subprocess_exec(program=a)",
    "subprocess.run(a, shell=1)",
    "subprocess.run(['git', a], **{'shell': True})",
    "r = subprocess.run; r(['git', a], shell=True)",
    "getattr(subprocess, 'run')(a, shell=True)",
    "functools.partial(subprocess.run, shell=True)(a)",
    "run_sh = functools.partial(subprocess.run, shell=True); run_sh(a)",
    "os.posix_spawn(a, [a], {})",
    "os.posix_spawnp('sh', ['sh', '-c', a], {})",
    "pty.spawn(['bash', '-c', a])",
    "os.execv('/bin/sh', ['sh', '-c', a])",
    "os.execvp(a, ['x'])",
    "os.execl('/bin/bash', 'bash', '-c', a)",
    "os.execlpe('sh', 'sh', '-c', a, {})",
    "os.spawnv(os.P_WAIT, '/bin/sh', ['sh', '-c', a])",
    "os.spawnlp(os.P_WAIT, 'python3', 'python3', '-c', a)",
    "loop.subprocess_shell(proto, a)",
    "subprocess.run([exe, '-c', a])",
])
def test_runners_wrappers_stdin_aliases_and_new_sinks_are_flagged_high(tmp_path, line):
    assert _verdict(tmp_path, line) == "HIGH"


@pytest.mark.parametrize("line", [
    "subprocess.run([TOOL, a])",
    "subprocess.run([exe, 'checkout', a])",
    "subprocess.run(['git', a], shell=bool(1))",
])
def test_an_undeterminable_program_or_shell_flag_is_medium(tmp_path, line):
    # 程式（或 shell=）無法確定時仍保守地標記，但只到 MEDIUM；看起來像直譯器（`[exe, "-c", x]`）才是 HIGH
    # A program (or shell=) that cannot be determined is still flagged conservatively, but only at MEDIUM; looking
    # like an interpreter (`[exe, "-c", x]`) is what makes it HIGH
    assert _verdict(tmp_path, line) == "MEDIUM"


def test_medium_findings_say_the_program_cannot_be_determined(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(_AI_HEAD + "    import os\n    subprocess.run([os.environ['TOOL'], a])\n", encoding="utf-8")
    [hit] = [x for x in AISecurityStaticScanner().scan_files([str(path)]) if x.rule_id == "VH-AI-006"]
    assert hit.severity.value == "MEDIUM" and "cannot be determined" in hit.evidence
