"""Helpers that give model prompts the target's real code and an import path that works in the sandbox."""
import os
from typing import Iterable, List, Optional

from core.models import CodeSymbol

_FENCE_LANG = {".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript", ".tsx": "tsx"}


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


def render_symbols(symbols: Iterable[CodeSymbol], root_dir: str, max_chars: int = 12000) -> str:
    """Source listing of symbols (with import paths), truncated to a character budget."""
    blocks: List[str] = []
    used = 0
    omitted = 0
    for sym in symbols:
        module = module_import_name(sym.file_path, root_dir)
        block = (
            f"File: {sym.file_path} (Lines {sym.line_start}-{sym.line_end})"
            + (f" | module: {module}" if module else "")
            + f"\nSymbol: {sym.name} [{sym.symbol_type}]\n"
            f"```{fence_language(sym.file_path)}\n{sym.source_code}\n```"
        )
        if used + len(block) > max_chars and blocks:
            omitted += 1
            continue
        blocks.append(block)
        used += len(block)
    if omitted:
        blocks.append(f"... {omitted} more symbol(s) omitted for length.")
    return "\n\n".join(blocks)


def file_source(file_path: str, max_chars: int = 12000) -> str:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return ""
    return text if len(text) <= max_chars else text[:max_chars] + "\n# ... (truncated)"
