import ast
import re
from typing import List, Optional, Tuple

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


def _top_level_test_nodes(tree: ast.Module) -> List[ast.AST]:
    return [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    ]


def top_level_test_functions(code: str) -> List[str]:
    """Names of module-level pytest test functions; raises SyntaxError on invalid code."""
    return [node.name for node in _top_level_test_nodes(ast.parse(code))]


def _has_assertion(fn: ast.AST) -> bool:
    """True if the function body contains an assert, raises AssertionError, or uses pytest.raises/fail/..."""
    for node in ast.walk(fn):
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
    except SyntaxError as e:
        return False, f"syntax error: {e}"
    tests = _top_level_test_nodes(tree)
    if not tests:
        return False, "no top-level test_ function defined"
    vacuous = [t.name for t in tests if not _has_assertion(t)]
    if vacuous:
        return False, f"test function(s) without any assertion: {', '.join(vacuous)}"
    return True, None
