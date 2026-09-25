import ast
import re
from typing import List, Optional, Tuple

_FENCE_RE = re.compile(r"```(?:python|py)?\s*\n?([\s\S]*?)```")


def strip_code_fences(text: str) -> str:
    """Returns the first fenced code block's body if present, otherwise the stripped text."""
    if not text:
        return ""
    match = _FENCE_RE.search(text)
    return (match.group(1) if match else text).strip()


def top_level_test_functions(code: str) -> List[str]:
    """Names of module-level pytest test functions; raises SyntaxError on invalid code."""
    tree = ast.parse(code)
    return [
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    ]


def check_test_code(code: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a generated pytest snippet.
    Returns (is_valid, problem_description). Valid means: parses, and defines at least one test_ function.
    """
    if not code or not code.strip():
        return False, "empty test code"
    try:
        names = top_level_test_functions(code)
    except SyntaxError as e:
        return False, f"syntax error: {e}"
    if not names:
        return False, "no top-level test_ function defined"
    return True, None
