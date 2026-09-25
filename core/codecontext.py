"""Helpers that give model prompts the target's real code and an import path that works in the sandbox."""
import ast
import math
import os
import textwrap
from typing import Iterable, List, Optional

from core.models import CodeSymbol

_FENCE_LANG = {".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript", ".tsx": "tsx"}
# Rough tokenizer-free estimate: code averages ~3.5 characters per token; non-ASCII (e.g. CJK) is ~1 token each.
# Deliberately conservative so budgets are not overshot on real tokenizers.
_ASCII_CHARS_PER_TOKEN = 3.5


def estimate_tokens(text: str) -> int:
    non_ascii = sum(1 for ch in text if ord(ch) > 127)
    return math.ceil((len(text) - non_ascii) / _ASCII_CHARS_PER_TOKEN) + non_ascii


def truncate_to_tokens(text: str, max_tokens: int, marker: str = "\n# ... (truncated)") -> str:
    if estimate_tokens(text) <= max_tokens:
        return text
    # Binary search for the longest prefix that fits; estimate_tokens is monotonic in prefix length
    lo, hi = 0, len(text)
    budget = max(max_tokens - estimate_tokens(marker), 0)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if estimate_tokens(text[:mid]) <= budget:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo] + marker


def fence_language(file_path: str) -> str:
    return _FENCE_LANG.get(os.path.splitext(file_path)[1].lower(), "")


def module_import_name(file_path: str, root_dir: str) -> Optional[str]:
    """
    Dotted module name for a Python file relative to root_dir (the sandbox puts root_dir on sys.path),
    or None when the file is outside root_dir or is not Python.
    """
    if not file_path.endswith(".py"):
        return None
    rel = os.path.relpath(os.path.abspath(file_path), os.path.abspath(root_dir))
    if rel.startswith(".."):
        return None
    parts = rel[:-3].split(os.sep)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts and all(p.isidentifier() for p in parts) else None


def import_instructions(file_path: str, root_dir: str, symbol_name: Optional[str] = None) -> str:
    """Tells the model exactly how the generated test must import the code under test."""
    abs_path = os.path.abspath(file_path)
    module = module_import_name(file_path, root_dir)
    lines = [f"Target file (absolute path): {abs_path}"]
    if module:
        top = (symbol_name or "").split(".")[0]
        example = f"from {module} import {top}" if top else f"import {module}"
        lines.append(f"The directory {os.path.abspath(root_dir)} is on sys.path, so import it as: `{example}`")
    else:
        lines.append(
            "Load it with importlib: `spec = importlib.util.spec_from_file_location('target', r'<absolute path>')`"
        )
    return "\n".join(lines)


def class_skeleton(source: str) -> str:
    """
    A Python class with method bodies replaced by `...`. Methods are extracted as their own symbols,
    so rendering the full class next to them would send every method body twice.
    Returns the source unchanged if it cannot be parsed.
    """
    dedented = textwrap.dedent(source)
    try:
        tree = ast.parse(dedented)
    except SyntaxError:
        return source
    cls = next((n for n in tree.body if isinstance(n, ast.ClassDef)), None)
    if cls is None:
        return source
    lines = dedented.splitlines()
    # Replace bottom-up so earlier line numbers stay valid
    methods = [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in sorted(methods, key=lambda n: n.lineno, reverse=True):
        body_start = node.body[0].lineno
        indent = " " * node.body[0].col_offset
        if body_start > node.lineno:
            lines[body_start - 1:node.end_lineno] = [f"{indent}...  # body listed separately"]
        # One-line methods (`def f(self): return 1`) are already as short as a skeleton
    return "\n".join(lines)


def symbol_source(sym: CodeSymbol) -> str:
    if sym.symbol_type == "class" and sym.file_path.endswith(".py"):
        return class_skeleton(sym.source_code)
    return sym.source_code


def render_symbol(sym: CodeSymbol, root_dir: str, max_tokens: Optional[int] = None) -> str:
    """One symbol's listing block; its source is truncated if the block alone would exceed max_tokens."""
    module = module_import_name(sym.file_path, root_dir)
    header = (
        f"File: {sym.file_path} (Lines {sym.line_start}-{sym.line_end})"
        + (f" | module: {module}" if module else "")
        + f"\nSymbol: {sym.name} [{sym.symbol_type}]\n"
        f"```{fence_language(sym.file_path)}\n"
    )
    footer = "\n```"
    source = symbol_source(sym)
    if max_tokens is not None:
        source = truncate_to_tokens(source, max(max_tokens - estimate_tokens(header + footer), 0))
    return header + source + footer


def render_symbols(symbols: Iterable[CodeSymbol], root_dir: str, max_tokens: int = 3000) -> str:
    """Source listing of symbols (with import paths), within an estimated token budget."""
    blocks: List[str] = []
    used = 0
    omitted = 0
    for sym in symbols:
        # The first block is always included (truncated if needed) so the prompt is never empty
        block = render_symbol(sym, root_dir, max_tokens if not blocks else None)
        cost = estimate_tokens(block)
        if blocks and used + cost > max_tokens:
            omitted += 1
            continue
        blocks.append(block)
        used += cost
    if omitted:
        blocks.append(f"... {omitted} more symbol(s) omitted for length.")
    return "\n\n".join(blocks)


def batch_symbols(
    symbols: List[CodeSymbol], root_dir: str, max_tokens: int, max_symbols: int
) -> List[List[CodeSymbol]]:
    """
    Splits symbols into batches whose rendered listing fits max_tokens, so render_symbols never has to
    omit any of them. A symbol too large for a batch on its own gets a batch to itself (and is truncated).
    """
    batches: List[List[CodeSymbol]] = []
    current: List[CodeSymbol] = []
    used = 0
    for sym in symbols:
        cost = estimate_tokens(render_symbol(sym, root_dir)) + 1  # +1 for the blank-line separator
        if current and (used + cost > max_tokens or len(current) >= max_symbols):
            batches.append(current)
            current, used = [], 0
        current.append(sym)
        used += cost
    if current:
        batches.append(current)
    return batches


def file_source(file_path: str, max_tokens: int = 3000) -> str:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return ""
    return truncate_to_tokens(text, max_tokens)
