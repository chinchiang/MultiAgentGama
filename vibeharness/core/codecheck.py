import ast
import re
from typing import Dict, List, Optional, Tuple, Union

from vibeharness.core.js_lex import mask_js_source, match_delim

_TestNode = Union[ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef]

# 任何 ```<lang> 標籤（python、python3、Python、js、...）接著換行即開啟區塊；
# 語言標籤本身絕不能滲入擷取出的程式碼
# Any ```<lang> tag (python, python3, Python, js, ...) followed by a newline opens the block;
# the language tag itself must never leak into the extracted code
_FENCE_RE = re.compile(r"```[\w-]*[ \t]*\r?\n([\s\S]*?)```")

# 使用到即算是明確檢查目標行為的 pytest 輔助函式
# pytest helpers whose use counts as an explicit check of target behaviour
_ASSERTING_CALLS = {"raises", "fail", "warns", "deprecated_call", "approx"}


def strip_code_fences(text: str) -> str:
    """若有圍欄程式碼區塊則回傳第一個的內容，否則回傳去除前後空白的文字。
    Returns the first fenced code block's body if present, otherwise the stripped text."""
    if not text:
        return ""
    match = _FENCE_RE.search(text)
    return (match.group(1) if match else text).strip()


def _top_level_test_nodes(tree: ast.Module) -> List[_TestNode]:
    """模組層級的 pytest 測試：`test_*` 函式，以及含有測試方法的 `Test*` 類別。
    Module-level pytest tests: `test_*` functions and `Test*` classes that contain test methods."""
    nodes: List[_TestNode] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            nodes.append(node)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            if any(isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name.startswith("test_")
                   for m in node.body):
                nodes.append(node)
    return nodes


def _has_assertion(fn: ast.AST) -> bool:
    """
    函式本體含有 assert、raise AssertionError，或使用 pytest.raises／fail／... 時為 True。
    巢狀函式裡的 assert 只有在該輔助函式確實從測試本體被呼叫時才算數，
    否則一個從未被呼叫的輔助函式就能在什麼都沒檢查的情況下通過閘門。
    True if the function body contains an assert, raises AssertionError, or uses pytest.raises/fail/...
    An assert inside a nested function counts only when that helper is actually called from the
    test body, otherwise an uncalled helper would satisfy the gate without checking anything.
    """
    called_helpers = {
        node.func.id for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if isinstance(node, ast.Lambda) or node.name not in called_helpers:
                continue  # 從未被呼叫的巢狀函式：它的 assert 什麼都證明不了 ／ never-called nested function: its assert proves nothing
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if isinstance(exc, ast.Name) and exc.id == "AssertionError":
                return True
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            # 只有已知的斷言輔助函式才算數。不採用單純的 startswith("assert") 規則：
            # 否則 mock.assert_called_once() 之類的記帳方法也會在沒有檢查任何
            # 目標行為的情況下通過閘門。
            # Only known asserting helpers count. A bare startswith("assert") rule is not used:
            # mock.assert_called_once() and similar bookkeeping methods would otherwise satisfy
            # the gate without checking any target behaviour.
            if name in _ASSERTING_CALLS:
                return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _parse_and_check_python(code: str) -> Tuple[Optional[ast.Module], Optional[str]]:
    """單次解析並驗證產生的 pytest 程式碼：有效時回傳 `(tree, None)`，無效時回傳 `(None, problem_description)`。
    Parses and validates generated pytest code in one pass: returns `(tree, None)` when valid, `(None, problem)` when
    invalid."""
    if not code or not code.strip():
        return None, "empty test code"
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError) as e:
        # ValueError：原始碼含有 null 位元組；RecursionError：巢狀深得離譜
        # ValueError: source with null bytes; RecursionError: absurdly deep nesting
        return None, f"syntax error: {e}"
    installer = _package_install_call(tree)
    if installer:
        return None, f"test installs packages at run time ({installer}); refused (slopsquatting / OWASP LLM04:2026)"
    unreadable = _unreadable_call(tree)
    if unreadable:
        return None, (f"could not check whether the test installs packages: {unreadable}; refused "
                      "(slopsquatting / OWASP LLM04:2026)")
    tests = _top_level_test_nodes(tree)
    if not tests:
        return None, "no top-level test_ function defined"
    try:
        vacuous = [name for t in tests for name in _vacuous_tests(t, tree)]
    except RecursionError:
        # 走訪本身是迭代的；這只是保險：保守地視為找不到斷言證據，絕不讓整次執行崩潰
        # The walk itself is iterative; this is only a safety net: conservatively treated as no assertion evidence
        # found, never crashing the whole run
        return None, "test function(s) without any assertion: analysis too deep"
    if vacuous:
        return None, f"test function(s) without any assertion: {', '.join(vacuous)}"
    return tree, None


def check_test_code(code: str) -> Tuple[bool, Optional[str]]:
    """驗證產生的 pytest 片段。
    回傳 (is_valid, problem_description)。有效代表：能解析、至少定義一個 test_ 函式，
    且每個 test_ 函式都含有斷言（否則空洞的測試會被算成已防禦的邊界）。
    Validates a generated pytest snippet.
    Returns (is_valid, problem_description). Valid means: parses, defines at least one test_ function,
    and every test_ function contains an assertion (a vacuous test would otherwise count as a defended boundary)."""
    tree, problem = _parse_and_check_python(code)
    return tree is not None, problem


_INSTALLER_RE = re.compile(r"\b(?:pip3?|uv|poetry|conda|mamba|npm|pnpm|yarn|bun|ensurepip)\b")
_INSTALL_VERB_RE = re.compile(r"\b(?:install|add)\b")


def _call_name(node: ast.Call) -> Optional[str]:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# 粗規則（CODING_STANDARDS 第 8 條）：檢查只接受它完整讀得懂的形式。啟動行程、動態執行、把模組物件當值傳遞，
# 一律算「無法檢查」而拒絕，不論命令是不是字面值：逐一比對已知拼法的做法連兩輪審查都被繞過
# The coarse rule (CODING_STANDARDS rule 8): the check accepts only forms it fully reads. Starting a process, dynamic
# execution and passing a module object around as a value are all refused as "could not check", whether or not the
# command is a literal: matching known spellings was bypassed in two review rounds in a row
#
# 匯入就拒絕的模組：啟動行程、動態執行，或直接取得行程與直譯器能力 ／ Modules refused on import: they start
# processes, execute code dynamically, or reach process and interpreter capabilities directly
_REFUSED_MODULES = frozenset({
    "subprocess", "pty", "multiprocessing", "concurrent", "runpy", "ctypes", "cffi", "builtins", "code", "codeop",
    "pip", "ensurepip", "_posixsubprocess", "posix", "nt", "signal", "pdb", "imp", "zipimport", "pkgutil",
})
# 屬於「能力模組」的名稱：它們的模組物件不能當值傳遞，也不能從其他物件的屬性取得（`app.os.system`）
# "Capability modules": their module objects may not be passed around as values, nor reached as an attribute of
# another object (`app.os.system`)
_CAPABILITY_MODULES = frozenset({"os", "sys", "importlib", "asyncio", "shutil", "io", "socket", *_REFUSED_MODULES})
# 從其他物件的屬性取得就拒絕的模組名稱：只收不會和常見屬性撞名的（`.code`、`.io`、`.signal` 是常見的屬性名稱）
# Module names refused when reached as another object's attribute: only those that do not collide with common
# attribute names (`.code`, `.io`, `.signal` are common attributes)
_REACHABLE_MODULE_ATTRS = frozenset({"os", "sys", "subprocess", "importlib", "builtins", "ctypes", "pty", "runpy",
                                     "shutil", "multiprocessing", "__builtins__"})
# os 與 asyncio 中啟動行程的屬性（不只呼叫：`r = os.system` 也算） ／ Process-starting attributes of os and asyncio
# (not only calls: `r = os.system` counts too)
_PROCESS_ATTRS = frozenset({
    "system", "popen", "fork", "forkpty", "startfile", "posix_spawn", "posix_spawnp", "execl", "execle", "execlp",
    "execlpe", "execv", "execve", "execvp", "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
    "spawnve", "spawnvp", "spawnvpe", "create_subprocess_exec", "create_subprocess_shell", "modules",
})
# 出現就拒絕的內建名稱（呼叫或當值都算） ／ Builtins refused on any reference (a call or a value)
_DYNAMIC_BUILTINS = frozenset({"eval", "exec", "compile", "__import__", "globals", "locals", "vars", "breakpoint",
                               "__builtins__", "open_code"})
_ATTR_BUILTINS = frozenset({"getattr", "setattr", "delattr", "hasattr"})
# importlib 唯一接受的用法：以字面值載入目標模組（提示詞與探針都這樣寫）
# The only importlib uses accepted: loading the target module from literals (as the prompts and probes write it)
_IMPORTLIB_LITERAL_CALLS = frozenset({"import_module", "spec_from_file_location"})
_IMPORTLIB_ALLOWED_ATTRS = frozenset({"util", "import_module", "spec_from_file_location", "module_from_spec",
                                      "loader", "exec_module"})


def _literal_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _unreadable_call(tree: ast.Module) -> Optional[str]:
    """檢查讀不懂、因此無法確認不會安裝套件的寫法，否則為 None。依粗規則拒絕：匯入 `_REFUSED_MODULES`、
    `from X import *`、取用 os／asyncio 啟動行程的屬性、參考 `_DYNAMIC_BUILTINS`、屬性名稱不是字面值（或是能力模組名稱）
    的 getattr 一類、字面值以外的 importlib 用法、把能力模組物件當值使用（`x = os`、`f(os)`），以及呼叫的對象是查表
    結果（`handlers[k]()`）。這是品質閘門（擋下模型幻想出來的套件），不是隔離：隔離是沙盒的事。
    A form the check cannot read, so cannot confirm installs nothing, or None. Refused by the coarse rule: importing
    `_REFUSED_MODULES`, `from X import *`, using a process-starting attribute of os / asyncio, referencing
    `_DYNAMIC_BUILTINS`, getattr and friends with a non-literal attribute name (or the name of a capability module),
    importlib beyond loading from literals, using a capability module object as a value (`x = os`, `f(os)`), and a
    call whose callee is a lookup (`handlers[k]()`). This is a quality gate (it stops packages a model hallucinated),
    not isolation: isolation is the sandbox's job."""
    modules: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in _REFUSED_MODULES:
                    return f"import of {root}"
                if root in _CAPABILITY_MODULES:
                    modules[a.asname or root] = root
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if any(a.name == "*" for a in node.names):
                return f"from {node.module} import *"
            if root in _REFUSED_MODULES:
                return f"import from {root}"
            if root in _CAPABILITY_MODULES:
                for a in node.names:
                    if a.name in _PROCESS_ATTRS or a.name in _CAPABILITY_MODULES or (
                            root == "importlib" and a.name not in _IMPORTLIB_ALLOWED_ATTRS):
                        return f"from {root} import {a.name}"
    parents: Dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in _DYNAMIC_BUILTINS:
            return f"{node.id} (dynamic execution)"
        if isinstance(node, ast.Name) and node.id in modules and isinstance(node.ctx, ast.Load):
            parent = parents.get(id(node))
            if not (isinstance(parent, ast.Attribute) and parent.value is node):
                return f"the module {node.id} used as a value"
        if isinstance(node, ast.Attribute):
            base = node.value.id if isinstance(node.value, ast.Name) else None
            base_module = modules.get(base or "")
            if node.attr in _PROCESS_ATTRS and base_module in ("os", "sys", "asyncio", None):
                return f".{node.attr} (starts a process or reaches loaded modules)"
            if node.attr in _REACHABLE_MODULE_ATTRS and base_module is None:
                return f".{node.attr} (a module reached as an attribute)"
            if base_module == "importlib" and node.attr not in _IMPORTLIB_ALLOWED_ATTRS:
                return f"importlib.{node.attr}"
        if not isinstance(node, ast.Call):
            continue
        func, name = node.func, _call_name(node)
        if isinstance(func, ast.Name) and name in _ATTR_BUILTINS:
            attr = node.args[1] if len(node.args) >= 2 else None
            if not (isinstance(attr, ast.Constant) and isinstance(attr.value, str)) \
                    or attr.value in _REACHABLE_MODULE_ATTRS or attr.value in _PROCESS_ATTRS:
                return f"{name}() with an attribute name the check cannot read"
        if name in _IMPORTLIB_LITERAL_CALLS and isinstance(func, ast.Attribute):
            if not node.args or not all(_literal_str(a) for a in node.args):
                return f"{name}() of a name the check cannot read"
        if isinstance(func, (ast.Subscript, ast.Call)):
            return "a call through a lookup the check cannot read"
    return None


def _package_install_call(tree: ast.Module) -> Optional[str]:
    """會安裝套件的呼叫（`pip install`、`subprocess.run([sys.executable, '-m', 'pip', 'install', ...])`、
    `pip.main(['install', ...])`），否則為 None。產生的程式碼不得拉取模型可能幻想出來的套件
    （而攻擊者可能已用該名稱註冊：MITRE ATLAS AML.T0060）。
    A call that installs packages (`pip install`, `subprocess.run([sys.executable, '-m', 'pip', 'install', ...])`,
    `pip.main(['install', ...])`), or None. Generated code must not pull packages a model may have hallucinated
    (and an attacker may have registered under that name: MITRE ATLAS AML.T0060)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name.split(".")[0] in ("pip", "ensurepip") for a in node.names):
            return f"import {node.names[0].name}"
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in ("pip", "ensurepip"):
            return f"from {node.module} import ..."
        if not isinstance(node, ast.Call):
            continue
        if _call_name(node) in ("__import__", "import_module") and node.args and isinstance(node.args[0], ast.Constant) \
                and str(node.args[0].value).split(".")[0] in ("pip", "ensurepip"):
            return f"{_call_name(node)}({node.args[0].value!r})"
        words = " ".join(
            c.value for c in ast.walk(node) if isinstance(c, ast.Constant) and isinstance(c.value, str)
        ).lower()
        if _INSTALLER_RE.search(words) and _INSTALL_VERB_RE.search(words):
            return words[:60]
    return None


def _vacuous_tests(test_node: _TestNode, tree: Optional[ast.Module] = None) -> List[str]:
    """單一最上層測試節點中沒有任何斷言的測試名稱。每個測試函式與類別的每個 `test_` 方法都必須各自含斷言，
    或（遞移地）呼叫到同一模組裡含斷言的程式：模組層級的輔助函式（`check(resp)`），以及 `self.<名稱>()`
    呼叫到的類別方法——包括定義在同一模組中的基底類別的方法。一個有斷言的方法不能替同類別裡空洞的方法背書，
    否則空洞的方法會被算成已防禦的邊界；呼叫模組外（看不到原始碼）的函式仍不算斷言證據。
    Names of the tests in one top-level test node that contain no assertion. Every test function and every `test_`
    method of a class must assert on its own or (transitively) call same-module code that does: a module-level
    helper (`check(resp)`), or a class method called as `self.<name>()` — including methods of base classes defined
    in the same module. One asserting method must not vouch for a vacuous sibling, which would otherwise count as a
    defended boundary; a call to a function outside the module (source not visible) is still no assertion evidence."""
    functions = {n.name: n for n in (tree.body if tree else []) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if not isinstance(test_node, ast.ClassDef):
        return [] if _asserts(test_node, functions, {}, set()) else [test_node.name]
    classes = {n.name: n for n in (tree.body if tree else []) if isinstance(n, ast.ClassDef)}
    methods = _class_methods(test_node, classes, {test_node.name})
    return [
        f"{test_node.name}.{name}" for name, method in methods.items()
        if name.startswith("test_") and not _asserts(method, functions, methods, set())
    ]


def _class_methods(cls: ast.ClassDef, classes: dict, seen: set) -> dict:
    """類別的方法，加上同一模組中定義的基底類別（遞移地）繼承來的方法；子類別的定義覆蓋基底類別的同名方法。
    A class's methods plus those inherited (transitively) from base classes defined in the same module; the
    subclass's definition overrides a base method of the same name."""
    methods: dict = {}
    for base in reversed(cls.bases):  # 第一個基底類別優先，與 MRO 的大方向一致 ／ the first base wins, in line with the MRO
        if isinstance(base, ast.Name) and base.id in classes and base.id not in seen:
            seen.add(base.id)
            methods.update(_class_methods(classes[base.id], classes, seen))
    methods.update({m.name: m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))})
    return methods


def _asserts(fn: ast.AST, functions: dict, methods: dict, seen: set) -> bool:
    """函式本身含斷言，或它（遞移地）呼叫的同模組輔助函式（`name(...)`）或類別方法（`self.<名稱>()`）含斷言時為 True。
    以明確的堆疊走訪呼叫圖（不遞迴），數千層的輔助函式鏈也不會拋出 RecursionError；`seen` 讓每個函式只看一次。
    True when the function asserts itself, or a same-module helper (`name(...)`) or class method (`self.<name>()`) it
    calls does (transitively). The call graph is walked with an explicit stack (no recursion), so a helper chain
    thousands deep cannot raise RecursionError; `seen` visits every function once."""
    stack: List[Tuple[ast.AST, dict]] = [(fn, methods)]
    while stack:
        current, current_methods = stack.pop()
        if _has_assertion(current):
            return True
        for node in ast.walk(current):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in functions and ("f", func.id) not in seen:
                seen.add(("f", func.id))
                # 模組層級的函式沒有 self：在它裡面不解析 self.<名稱>() ／ a module-level function has no self: no self.<name>() in it
                stack.append((functions[func.id], {}))
            elif (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "self"
                    and func.attr in current_methods and ("m", func.attr) not in seen):
                seen.add(("m", func.attr))
                stack.append((current_methods[func.attr], current_methods))
    return False


# --- JavaScript／TypeScript（node:test 模組）-----------------------------------------------
# --- JavaScript / TypeScript (node:test modules) -----------------------------------------------

_JS_TEST_CALL_RE = re.compile(r"(?<![\w.$])(?:test|it)\s*\(")
_JS_ASSERT_RE = re.compile(r"\bassert\b\s*[.(]|\bexpect\s*\(|\bthrow\b|\.(?:throws|rejects|doesNotThrow|doesNotReject)\s*\(")
_JS_INSTALL_RE = re.compile(r"\b(?:npm|pnpm|yarn|bun)\s+(?:install|add|i|exec|dlx|x)\b|\bnpx\b|\bpip3?\s+install\b", re.I)
_JS_SHELL_RE = re.compile(r"child_process|\bexecSync\s*\(|\bspawnSync\s*\(|\bexecFileSync\s*\(")
_JS_OPEN, _JS_CLOSE = "([{", ")]}"
# 粗規則（見 _unreadable_call）：啟動行程、動態執行與動態取得模組物件一律拒絕。模組名稱是遮罩後的字串，所以在原文上比對
# The coarse rule (see _unreadable_call): starting a process, dynamic execution and fetching module objects
# dynamically are all refused. Module specifiers are masked strings, so they are matched on the original text
# child_process 與 worker_threads 不論寫法；vm、module 一類的短名稱只在帶 `node:` 或出現在 require(／from 之後時才算，
# 斷言裡的普通字串（`'module'`）不受影響
# child_process and worker_threads in any spelling; short names such as vm and module only with `node:` or after
# require( / from, so a plain string in an assertion (`'module'`) is unaffected
_JS_REFUSED_SPECIFIER_RE = re.compile(
    r"""["'`](?:node:)?(?:child_process|worker_threads)["'`]"""
    r"""|["'`]node:(?:vm|cluster|module|inspector|repl|wasi)["'`]"""
    r"""|(?:\brequire\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*)["'`](?:vm|cluster|module|inspector|repl|wasi)["'`]""")
_JS_DYNAMIC_EXEC_RE = re.compile(
    r"(?<![\w$.])(?:eval|Function)\s*\(|\bnew\s+Function\b|\.getBuiltinModule\b|\bprocess\s*\.\s*(?:binding|dlopen|"
    r"mainModule|_linkedBinding)\b|\bcreateRequire\b|\bmodule\s*\.\s*require\b|\bsetTimeout\s*\(\s*[\"'`]")
# 動態載入模組：第一個參數必須是單一的字串字面值，否則檢查讀不懂 ／ Dynamic module loads: the first argument must be a
# single string literal, or the check cannot read it
_JS_DYNAMIC_LOAD_RE = re.compile(r"(?<![\w$.])(?:require|import)\s*\(")


def _js_literal_argument(code: str, masked: str, open_paren: int) -> bool:
    """`open_paren` 之後的第一個參數是單一字串字面值（沒有 `+` 串接、沒有 `${}` 插值）。遮罩把字面值內容（含結尾引號）
    換成空白，所以字面值在遮罩後是「引號 + 空白」，接著必須是 `,` 或 `)`。
    The first argument after `open_paren` is a single string literal (no `+` concatenation, no `${}` interpolation).
    Masking blanks a literal's content (closing quote included), so a literal reads "quote + spaces" in the masked
    source and must be followed by `,` or `)`."""
    i = open_paren + 1
    while i < len(masked) and masked[i].isspace():
        i += 1
    if i >= len(masked) or masked[i] not in "'\"`":
        return False
    start = i
    i += 1
    while i < len(masked) and masked[i] == " ":
        i += 1
    if i >= len(masked) or masked[i] not in ",)":
        return False
    return not (masked[start] == "`" and "${" in code[start:i])


def _js_unreadable_call(code: str, masked: str) -> Optional[str]:
    """檢查讀不懂的 JS/TS 寫法（CODING_STANDARDS 第 8 條的粗規則）：匯入 child_process、vm、worker_threads 一類模組、
    eval／Function／getBuiltinModule／createRequire／process.binding 一類動態執行或取得模組，以及模組名稱不是字面值的
    require／import()；否則為 None。
    A JS/TS form the check cannot read (the coarse rule of CODING_STANDARDS rule 8): importing child_process, vm,
    worker_threads and the like, dynamic execution or module fetching such as eval / Function / getBuiltinModule /
    createRequire / process.binding, and require / import() of a non-literal module name; else None."""
    specifier = _JS_REFUSED_SPECIFIER_RE.search(code)
    if specifier:
        return f"the module {specifier.group(0)} (starts processes or executes code)"
    dynamic = _JS_DYNAMIC_EXEC_RE.search(masked)
    if dynamic:
        return f"{dynamic.group(0).strip(' (')} (dynamic execution)"
    for m in _JS_DYNAMIC_LOAD_RE.finditer(masked):
        if not _js_literal_argument(code, masked, m.end() - 1):
            return f"{m.group(0).strip(' (.')}() of a module name the check cannot read"
    return None


def _js_balanced(masked: str) -> bool:
    stack: List[str] = []
    for ch in masked:
        if ch in _JS_OPEN:
            stack.append(ch)
        elif ch in _JS_CLOSE:
            if not stack or _JS_OPEN.index(stack.pop()) != _JS_CLOSE.index(ch):
                return False
    return not stack


def _js_call_span(masked: str, open_paren: int) -> int:
    close = match_delim(masked, open_paren, "(", ")")
    return close if close is not None else len(masked) - 1


def check_js_test_code(code: str) -> Tuple[bool, Optional[str]]:
    """check_test_code 的 JS/TS 對應版，用於 `node:test` 模組：解析得夠好（遮罩後的原始碼
    分隔符平衡）、不安裝任何東西、至少定義一個 test()／it() 呼叫，且每個
    測試都有斷言。這裡沒有 JS 解析器，所以閘門只是詞法層級的近似；
    無法解析的部分由 Node 在執行期回報（歸類為 harness 錯誤，而非缺陷）。
    The JS/TS counterpart of check_test_code for `node:test` modules: parses well enough (balanced
    delimiters on masked source), installs nothing, defines at least one test()/it() call, and every
    test asserts on something. There is no JS parser here, so the gate is a lexer-level approximation;
    Node itself reports what it cannot parse at run time (classified as a harness error, not a defect)."""
    if not code or not code.strip():
        return False, "empty test code"
    if "\x00" in code:
        return False, "syntax error: source contains a NUL byte"
    if _JS_INSTALL_RE.search(code) or (_JS_SHELL_RE.search(code) and _INSTALLER_RE.search(code)):
        m = _JS_INSTALL_RE.search(code) or _INSTALLER_RE.search(code)
        return False, (f"test installs packages at run time ({m.group(0) if m else 'installer call'}); "
                       "refused (slopsquatting / OWASP LLM04:2026)")
    masked = mask_js_source(code)
    if not _js_balanced(masked):
        return False, "syntax error: unbalanced delimiters"
    unreadable = _js_unreadable_call(code, masked)
    if unreadable:
        return False, (f"could not check whether the test installs packages: {unreadable}; refused "
                       "(slopsquatting / OWASP LLM04:2026)")
    tests = list(_JS_TEST_CALL_RE.finditer(masked))
    if not tests:
        return False, "no test()/it() call defined"
    vacuous: List[str] = []
    for m in tests:
        open_paren = m.end() - 1
        close = _js_call_span(masked, open_paren)
        if not _JS_ASSERT_RE.search(masked[open_paren:close + 1]):
            literal = re.search(r"""["'`]([^"'`\n]{0,60})["'`]""", code[open_paren:close + 1])
            vacuous.append(literal.group(1) if literal else f"test at offset {m.start()}")
    if vacuous:
        return False, f"test(s) without any assertion: {', '.join(vacuous)}"
    return True, None


def check_test_code_for(code: str, language: str) -> Tuple[bool, Optional[str]]:
    """依測試的語言分派到對應的閘門。
    Dispatches to the gate for the test's language."""
    if language in ("javascript", "typescript"):
        return check_js_test_code(code)
    return check_test_code(code)


def split_future_imports(code: str, tree: Optional[ast.Module] = None) -> Tuple[str, str]:
    """拆出必須留在檔案最頂端的開頭 docstring 與 `from __future__` 匯入。
    Splits off the leading docstring and `from __future__` imports, which must stay at the very top."""
    if tree is None:
        tree = ast.parse(code)
    last_line = 0
    for i, node in enumerate(tree.body):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            last_line = node.end_lineno or node.lineno
        elif i == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            continue  # 模組 docstring 可以出現在 future 匯入之前 ／ module docstring may precede future imports
        else:
            break
    if not last_line:
        return "", code
    lines = code.splitlines(keepends=True)
    preamble = "".join(lines[:last_line])
    return (preamble if preamble.endswith("\n") else preamble + "\n"), "".join(lines[last_line:])


def prepare_test_code(code: str, language: str = "python") -> Tuple[str, Optional[str], str, str]:
    """剝除程式碼圍欄，以單次解析依語言做靜態檢查，並拆出 Python 的前導 docstring 與 `from __future__` 匯入。
    回傳 `(cleaned_code, problem, preamble, body)`；`problem` 為 `None` 代表有效。
    Strips code fences, runs language-specific static validation in a single parse, and splits off Python's leading
    docstring and `from __future__` imports. Returns `(cleaned_code, problem, preamble, body)`, where `problem` is
    `None` when valid."""
    cleaned = strip_code_fences(code)
    if language in ("javascript", "typescript"):
        _, problem = check_js_test_code(cleaned)
        return cleaned, problem, "", cleaned
    tree, problem = _parse_and_check_python(cleaned)
    if tree is None:
        return cleaned, problem, "", cleaned
    preamble, body = split_future_imports(cleaned, tree=tree)
    return cleaned, None, preamble, body
