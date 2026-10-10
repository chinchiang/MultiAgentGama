"""審查回歸測試：JSX/TS 詞法分析、路由偵測，以及 VH-AI-004/005/006 的精確度。
Review regressions: JSX/TS lexing, route detection, and VH-AI-004/005/006 precision."""
import os

from vibeharness.agents.whitebox.ai_static_scanner import AISecurityStaticScanner
from vibeharness.agents.whitebox.ast_extractor import ASTExtractor


def _symbols(tmp_path, name, code):
    f = tmp_path / name
    f.write_text(code, encoding="utf-8")
    return ASTExtractor().parse_file(str(f))


def _by_name(symbols):
    return {s.name: s for s in symbols}


def _scan(tmp_path, code, name="app.py"):
    path = tmp_path / name
    path.write_text(code, encoding="utf-8")
    return AISecurityStaticScanner().scan_files([str(path)])


def _hits(findings):
    return [(f.rule_id, f.line_number) for f in findings]


# --- JSX：文字中的撇號與結尾標籤不會遮蔽後面的符號 ---
# --- JSX: prose apostrophes and closing tags do not hide later symbols -----------------------

def test_jsx_apostrophe_does_not_swallow_the_rest_of_the_file(tmp_path):
    by = _by_name(_symbols(tmp_path, "page.jsx", (
        "export function Page() { return <p>Don't click</p>; }\n"
        "export function helper(x) {\n"
        "    return x + 1;\n"
        "}\n"
    )))
    assert set(by) == {"Page", "helper"}
    assert by["Page"].line_end == 1
    assert by["helper"].line_start == 2 and by["helper"].line_end == 4


def test_jsx_closing_and_self_closing_tags_are_not_regex_literals(tmp_path):
    by = _by_name(_symbols(tmp_path, "card.tsx", (
        "export function Card({ a }) {\n"
        "    return <div>{a}<br /></div>;\n"
        "}\n"
        "function second(y) {\n"
        "    return y;\n"
        "}\n"
    )))
    assert set(by) == {"Card", "second"}
    assert by["Card"].line_start == 1 and by["Card"].line_end == 3
    assert by["second"].line_start == 4 and by["second"].line_end == 6


def test_unterminated_quote_or_regex_ends_at_the_line_break(tmp_path):
    by = _by_name(_symbols(tmp_path, "a.js", (
        "const total = a / b; const half = c / 2;\n"
        "const msg = \"unterminated\n"
        "function later() { return 1; }\n"
        "const keyword = typeof'x';\n"
    )))
    assert "later" in by


# --- TypeScript 宣告 ---
# --- TypeScript declarations ---------------------------------------------------------------

def test_typescript_return_types_generics_and_annotations(tmp_path):
    by = _by_name(_symbols(tmp_path, "svc.ts", (
        "export function generic<T extends Record<string, number>>(x: T): T {\n"
        "    return x;\n"
        "}\n"
        "export async function load(id: string): Promise<{ id: string }> {\n"
        "    return { id };\n"
        "}\n"
        "const add = (a: number, b: number): number => a + b;\n"
        "const ident = <T,>(x: T): T => x;\n"
        "export const handler: NextApiHandler = async (req, res) => {\n"
        "    res.end();\n"
        "};\n"
        "class Users {\n"
        "    async getUser(id: string): Promise<User> {\n"
        "        return db.find(id);\n"
        "    }\n"
        "    private cached<T>(key: string): T | undefined {\n"
        "        return undefined;\n"
        "    }\n"
        "}\n"
    )))
    assert by["generic"].parameters == ["x"] and by["generic"].line_end == 3
    assert by["load"].line_start == 4 and by["load"].line_end == 6
    assert by["add"].parameters == ["a", "b"]
    assert by["ident"].parameters == ["x"]
    assert by["handler"].parameters == ["req", "res"] and by["handler"].line_end == 11
    assert "NextApiHandler" not in by
    assert by["Users.getUser"].line_start == 13 and by["Users.getUser"].line_end == 15
    assert by["Users.cached"].parameters == ["key"]


def test_function_keyword_needs_word_boundaries(tmp_path):
    names = [s.name for s in _symbols(tmp_path, "a.js", (
        "const r = functionalUpdate(state);\n"
        "obj.function(x);\n"
        "export default function main(argv) { return argv; }\n"
    ))]
    assert names == ["main"]


# --- 路由 ---
# --- Routes ----------------------------------------------------------------------------------

def test_non_router_calls_are_not_routes(tmp_path):
    symbols = _symbols(tmp_path, "a.js", (
        "const token = headers.get(\"authorization\");\n"
        "cache.delete(key);\n"
        "app.get('port');\n"
        "const users = express.Router();\n"
        "users.post('/users', create);\n"
        "ordersRouter.delete('/orders/:id', remove);\n"
        "api.get(`/health`, ok);\n"
    ))
    routes = sorted(s.name for s in symbols if s.symbol_type == "route")
    assert routes == ["DELETE /orders/:id", "GET /health", "POST /users"]


def test_nextjs_handler_is_reviewed_once_and_needs_the_exact_export(tmp_path):
    symbols = _symbols(tmp_path, "route.ts", (
        "export async function GET(request: Request): Promise<Response> {\n"
        "    return Response.json({});\n"
        "}\n"
        "function get(key) { return store[key]; }\n"
    ))
    assert [(s.name, s.symbol_type) for s in symbols] == [("get", "function"), ("GET", "route")]


def test_python_route_decorators_need_a_router_or_a_path(tmp_path):
    by = _by_name(_symbols(tmp_path, "views.py", (
        "from unittest import mock\n"
        "@app.get('/users')\n"
        "def users():\n    return []\n"
        "@router.post(PATH)\n"
        "def create():\n    return 1\n"
        "@mock.patch('os.getcwd')\n"
        "def patched(m):\n    return m\n"
        "@cache.delete(key)\n"
        "def evict():\n    return None\n"
    )))
    assert by["users"].symbol_type == "route"
    assert by["create"].symbol_type == "route"
    assert by["patched"].symbol_type == "function"
    assert by["evict"].symbol_type == "function"


# --- VH-AI-006：污染追蹤精確度 ---
# --- VH-AI-006: taint precision -----------------------------------------------------------------

def test_taint_does_not_spread_to_subscript_keys_or_attribute_bases(tmp_path):
    findings = _scan(tmp_path, (
        "import subprocess\n"
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "class Bot:\n"
        "    def ask(self, cmd, cache):\n"
        "        cache[cmd] = client.chat.completions.create(model='m', messages=[], max_tokens=5)\n"
        "        subprocess.run(cmd)\n"
        "        self.last = client.chat.completions.create(model='m', messages=[], max_tokens=5)\n"
        "        eval(self.safe_expr)\n"
        "        eval(self.last.choices[0].message.content)\n"
        "        exec(cache)\n"
    ))
    assert _hits(f for f in findings if f.rule_id == "VH-AI-006") == [("VH-AI-006", 10), ("VH-AI-006", 11)]


def test_taint_follows_loops_context_managers_and_comprehensions(tmp_path):
    findings = _scan(tmp_path, (
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "def stream(db):\n"
        "    for chunk in client.messages.create(model='m', messages=[], max_tokens=5, stream=True):\n"
        "        eval(chunk)\n"
        "    with client.messages.stream(model='m', messages=[], max_tokens=5) as s:\n"
        "        db.execute(s.text)\n"
        "    resp = client.messages.create(model='m', messages=[], max_tokens=5)\n"
        "    [exec(block.text) for block in resp.content]\n"
    ))
    assert _hits(f for f in findings if f.rule_id == "VH-AI-006") == [
        ("VH-AI-006", 5), ("VH-AI-006", 7), ("VH-AI-006", 9),
    ]


# --- VH-AI-005：只計真正的模型用戶端 ---
# --- VH-AI-005: only real model clients -------------------------------------------------------

def test_uncapped_call_rule_needs_an_ai_receiver(tmp_path):
    findings = _scan(tmp_path, (
        "import boto3\n"
        "from openai import OpenAI\n"
        "from anthropic import Anthropic\n"
        "from twilio.rest import Client\n"
        "tw = Client('sid', 'token')\n"
        "claude = Anthropic()\n"
        "lam = boto3.client('lambda')\n"
        "def notify(to, llm):\n"
        "    tw.messages.create(to=to, body='hi')\n"
        "    claude.messages.create(model='m', messages=[])\n"
        "    Anthropic().messages.create(model='m', messages=[])\n"
        "    OpenAI().chat.completions.create(model='m', messages=[])\n"
        "    out = lam.invoke(FunctionName='f')\n"
        "    eval(out)\n"
        "    answer = llm.invoke('q')\n"
        "    eval(answer)\n"
    ))
    assert _hits(findings) == [("VH-AI-005", 10), ("VH-AI-005", 11), ("VH-AI-005", 12), ("VH-AI-006", 16)]


# --- VH-AI-004：本機檢查點以被掃描檔案為基準解析，而不是框架的工作目錄 ---
# --- VH-AI-004: local checkpoints resolve against the scanned file, not the harness CWD ----------

def test_local_model_dir_is_resolved_relative_to_the_scanned_file(tmp_path, monkeypatch):
    code = "from transformers import AutoModel\nm = AutoModel.from_pretrained('acme/model')\n"
    target = tmp_path / "target"
    target.mkdir()
    elsewhere = tmp_path / "cwd"
    (elsewhere / "acme" / "model").mkdir(parents=True)
    monkeypatch.chdir(elsewhere)
    assert _hits(_scan(target, code)) == [("VH-AI-004", 2)]
    (target / "acme" / "model").mkdir(parents=True)
    assert _hits(_scan(target, code)) == []
    assert os.getcwd() == str(elsewhere)
