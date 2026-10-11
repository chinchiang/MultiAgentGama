import ast
import re
from typing import List, Optional, Tuple, Union

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


def check_test_code(code: str) -> Tuple[bool, Optional[str]]:
    """
    驗證產生的 pytest 片段。
    回傳 (is_valid, problem_description)。有效代表：能解析、至少定義一個 test_ 函式，
    且每個 test_ 函式都含有斷言（否則空洞的測試會被算成已防禦的邊界）。
    Validates a generated pytest snippet.
    Returns (is_valid, problem_description). Valid means: parses, defines at least one test_ function,
    and every test_ function contains an assertion (a vacuous test would otherwise count as a defended boundary).
    """
    if not code or not code.strip():
        return False, "empty test code"
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError) as e:
        # ValueError：原始碼含有 null 位元組；RecursionError：巢狀深得離譜
        # ValueError: source with null bytes; RecursionError: absurdly deep nesting
        return False, f"syntax error: {e}"
    installer = _package_install_call(tree)
    if installer:
        return False, f"test installs packages at run time ({installer}); refused (slopsquatting / OWASP LLM04:2026)"
    tests = _top_level_test_nodes(tree)
    if not tests:
        return False, "no top-level test_ function defined"
    try:
        vacuous = [name for t in tests for name in _vacuous_tests(t, tree)]
    except RecursionError:
        # 走訪本身是迭代的；這只是保險：保守地視為找不到斷言證據，絕不讓整次執行崩潰
        # The walk itself is iterative; this is only a safety net: conservatively treated as no assertion evidence
        # found, never crashing the whole run
        return False, "test function(s) without any assertion: analysis too deep"
    if vacuous:
        return False, f"test function(s) without any assertion: {', '.join(vacuous)}"
    return True, None


_INSTALLER_RE = re.compile(r"\b(?:pip3?|uv|poetry|conda|mamba|npm|pnpm|yarn|bun|ensurepip)\b")
_INSTALL_VERB_RE = re.compile(r"\b(?:install|add)\b")


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


def _js_masked(code: str) -> str:
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor  # 不會循環匯入：它只匯入 models ／ no cycle: it imports only models
    return ASTExtractor._mask_source(code)


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
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor
    close = ASTExtractor._match_delim(masked, open_paren, "(", ")")
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
    masked = _js_masked(code)
    if not _js_balanced(masked):
        return False, "syntax error: unbalanced delimiters"
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
