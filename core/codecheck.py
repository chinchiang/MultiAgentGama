import ast
import re
from typing import List, Optional, Tuple, Union

_TestNode = Union[ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef]

# Any ```<lang> tag (python, python3, Python, js, ...) followed by a newline opens the block;
# the language tag itself must never leak into the extracted code
_FENCE_RE = re.compile(r"```[\w-]*[ \t]*\r?\n([\s\S]*?)```")

# pytest helpers whose use counts as an explicit check of target behaviour
_ASSERTING_CALLS = {"raises", "fail", "warns", "deprecated_call", "approx"}


def strip_code_fences(text: str) -> str:
    """Returns the first fenced code block's body if present, otherwise the stripped text."""
    if not text:
        return ""
    match = _FENCE_RE.search(text)
    return (match.group(1) if match else text).strip()


def _top_level_test_nodes(tree: ast.Module) -> List[_TestNode]:
    """Module-level pytest tests: `test_*` functions and `Test*` classes that contain test methods."""
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
                continue  # never-called nested function: its assert proves nothing
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if isinstance(exc, ast.Name) and exc.id == "AssertionError":
                return True
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            # Only known asserting helpers count. A bare startswith("assert") rule is not used:
            # mock.assert_called_once() and similar bookkeeping methods would otherwise satisfy
            # the gate without checking any target behaviour.
            if name in _ASSERTING_CALLS:
                return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def check_test_code(code: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a generated pytest snippet.
    Returns (is_valid, problem_description). Valid means: parses, defines at least one test_ function,
    and every test_ function contains an assertion (a vacuous test would otherwise count as a defended boundary).
    """
    if not code or not code.strip():
        return False, "empty test code"
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError) as e:
        # ValueError: source with null bytes; RecursionError: absurdly deep nesting
        return False, f"syntax error: {e}"
    installer = _package_install_call(tree)
    if installer:
        return False, f"test installs packages at run time ({installer}); refused (slopsquatting / OWASP LLM04:2026)"
    tests = _top_level_test_nodes(tree)
    if not tests:
        return False, "no top-level test_ function defined"
    vacuous = [t.name for t in tests if not _test_has_assertion(t)]
    if vacuous:
        return False, f"test function(s) without any assertion: {', '.join(vacuous)}"
    return True, None


_INSTALLER_RE = re.compile(r"\b(?:pip3?|uv|poetry|conda|mamba|npm|pnpm|yarn|ensurepip)\b")
_INSTALL_VERB_RE = re.compile(r"\b(?:install|add)\b")


def _package_install_call(tree: ast.Module) -> Optional[str]:
    """A call that installs packages (`pip install`, `subprocess.run([sys.executable, '-m', 'pip', 'install', ...])`,
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


def _test_has_assertion(test_node: _TestNode) -> bool:
    """Assertion gate for one top-level test node; for a class, any test method with an assertion counts."""
    if isinstance(test_node, ast.ClassDef):
        return any(
            _has_assertion(m) for m in test_node.body
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
    return _has_assertion(test_node)
