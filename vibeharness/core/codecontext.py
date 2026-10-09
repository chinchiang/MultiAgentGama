"""Helpers that give model prompts the target's real code and an import path that works in the sandbox."""
import ast
import json
import math
import os
import pathlib
import re
import textwrap
from typing import Iterable, List, Optional

from vibeharness.core.models import CodeSymbol
from vibeharness.core.sanitize import prepare_untrusted_code

_FENCE_LANG = {".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript", ".tsx": "tsx",
               ".mjs": "javascript", ".cjs": "javascript", ".mts": "typescript", ".cts": "typescript"}
_JS_EXTS = {".js", ".jsx", ".mjs", ".cjs"}
_TS_EXTS = {".ts", ".tsx", ".mts", ".cts"}
# Rough tokenizer-free estimate: code averages ~3.5 characters per token; non-ASCII (e.g. CJK) is ~1 token each.
# Deliberately conservative so budgets are not overshot on real tokenizers.
_ASCII_CHARS_PER_TOKEN = 3.5

# Below this many tokens a partial block is not worth keeping; the symbol is omitted instead
_MIN_TRUNCATED_BLOCK_TOKENS = 80


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


def import_root(root_dir: str) -> str:
    """The directory a generated test must have on sys.path to import the target by name.

    The sandbox puts both the target directory and its parent on sys.path. When the target
    directory is itself a package (it has an ``__init__.py``), modules in it must be imported
    through the package (``from shop.app import checkout``): importing ``app`` directly makes the
    package's own relative imports (``from .models import ...``) fail with "attempted relative
    import with no known parent package", which the executor then blames on the target.
    """
    root = os.path.abspath(root_dir)
    if os.path.isfile(os.path.join(root, "__init__.py")) and os.path.basename(root).isidentifier():
        return os.path.dirname(root)
    return root


def module_import_name(file_path: str, root_dir: str) -> Optional[str]:
    """
    Dotted module name for a Python file under root_dir, importable from the sandbox's sys.path
    (root_dir, or its parent when root_dir is a package; see import_root), or None when the file
    is outside root_dir or is not Python.
    """
    if not file_path.endswith(".py"):
        return None
    try:
        rel = os.path.relpath(os.path.abspath(file_path), import_root(root_dir))
    except ValueError:  # Windows: file and root on different drives
        return None
    if rel.startswith(".."):
        return None
    parts = rel[:-3].split(os.sep)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts and all(p.isidentifier() for p in parts) else None


def language_for_file(file_path: str) -> str:
    """"typescript", "javascript" or "python" (the default: the Python sandbox is the fallback)."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in _TS_EXTS:
        return "typescript"
    if ext in _JS_EXTS:
        return "javascript"
    return "python"


def target_file_url(file_path: str, path_cls: type = pathlib.Path) -> str:
    """The file:// URL a Node test imports the target through (`file:///C:/proj/app.js` on Windows)."""
    return path_cls(os.path.abspath(file_path)).as_uri()


def _masked_js(source: str) -> str:
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor  # no cycle: it imports only models
    return ASTExtractor._mask_source(source)


_JS_ESM_RE = re.compile(r"^\s*export\s|^\s*import\s+(?!\()", re.MULTILINE)
_JS_CJS_RE = re.compile(r"\brequire\s*\(|\bmodule\.exports\b|\bexports\.[A-Za-z_$][\w$]*\s*=")


def _nearest_package_type(file_path: str) -> Optional[str]:
    directory = os.path.dirname(os.path.abspath(file_path))
    while True:
        candidate = os.path.join(directory, "package.json")
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return "esm" if isinstance(data, dict) and data.get("type") == "module" else "cjs"
            except (OSError, ValueError):
                return None
        parent = os.path.dirname(directory)
        if parent == directory:
            return None
        directory = parent


def js_module_kind(file_path: str, source: Optional[str] = None) -> str:
    """"esm", "cjs" or "unknown": extension first, then the file's own top-level syntax (on masked
    source, so comments and strings cannot fake it), then the nearest package.json "type"."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".mjs", ".mts"):
        return "esm"
    if ext in (".cjs", ".cts"):
        return "cjs"
    if source is None:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
        except (OSError, UnicodeDecodeError):
            source = ""
    masked = _masked_js(source)
    if _JS_ESM_RE.search(masked):
        return "esm"
    if _JS_CJS_RE.search(masked):
        return "cjs"
    return _nearest_package_type(file_path) or "unknown"


_JS_EXPORT_RES = [
    re.compile(r"\bexport\s+(?:default\s+)?(?:async\s+)?(?:function\*?|class|const|let|var)\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"\bexport\s*\{([^}]*)\}"),
    re.compile(r"\bexports\.([A-Za-z_$][\w$]*)\s*="),
    re.compile(r"\bmodule\.exports\s*=\s*\{([^}]*)\}"),
]


def js_exported_names(file_path: str, source: Optional[str] = None, limit: int = 30) -> List[str]:
    """Names the file exports (ESM `export`, CommonJS `exports.x` / `module.exports = {...}`), in order."""
    if source is None:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
        except (OSError, UnicodeDecodeError):
            return []
    masked = _masked_js(source)
    names: List[str] = []
    for pattern in _JS_EXPORT_RES:
        for m in pattern.finditer(masked):
            group = m.group(1)
            if pattern.pattern.startswith("\\bexport\\s*\\{") or pattern.pattern.startswith("\\bmodule"):
                parts = [p.strip() for p in group.split(",")]
                for part in parts:
                    name = part.split(" as ")[-1].split(":")[0].strip()
                    if name and re.fullmatch(r"[A-Za-z_$][\w$]*", name) and name not in names:
                        names.append(name)
            elif group and group not in names:
                names.append(group)
            if len(names) >= limit:
                return names[:limit]
    return names


def import_instructions(file_path: str, root_dir: str, symbol_name: Optional[str] = None) -> str:
    """Tells the model exactly how the generated test must import the code under test."""
    abs_path = os.path.abspath(file_path)
    language = language_for_file(file_path)
    if language != "python":
        return js_import_instructions(file_path, symbol_name)
    if not file_path.endswith(".py"):
        # Neither Python nor JS/TS: nothing can execute it, so no import or executable test code
        return (
            f"Target file (absolute path): {abs_path}\n"
            "This is not a Python file: it can be reviewed statically but cannot be imported or "
            "executed by the test sandbox, so write no import or executable test code for it."
        )
    module = module_import_name(file_path, root_dir)
    lines = [f"Target file (absolute path): {abs_path}"]
    if module:
        top = (symbol_name or "").split(".")[0]
        example = f"from {module} import {top}" if top else f"import {module}"
        lines.append(f"The directory {import_root(root_dir)} is on sys.path, so import it as: `{example}`")
    else:
        lines.append(
            "Load it with importlib: `spec = importlib.util.spec_from_file_location('target', r'<absolute path>')`"
        )
    return "\n".join(lines)


def js_import_instructions(file_path: str, symbol_name: Optional[str] = None) -> str:
    """How a `node:test` module (always ESM, run from a temp directory) imports the target: through its
    file:// URL, with the import form that matches the target's module system."""
    abs_path = os.path.abspath(file_path)
    url = target_file_url(file_path)
    kind = js_module_kind(file_path)
    top = (symbol_name or "").split(".")[0] or "<symbol>"
    lines = [f"Target file (absolute path): {abs_path}", f"Import URL (use exactly this): {url}"]
    if kind == "esm":
        lines.append(f"Module system: ESM (top-level import/export detected). Import named exports: "
                     f"`import {{ {top} }} from \"{url}\"`.")
    elif kind == "cjs":
        lines.append(f"Module system: CommonJS (require/module.exports detected). Import it as: "
                     f"`import target from \"{url}\"; const {{ {top} }} = target;` or "
                     f"`import {{ createRequire }} from \"node:module\"; const require = createRequire(import.meta.url); "
                     f"const {{ {top} }} = require({abs_path!r});`")
    else:
        lines.append("Module system: not detected. Try the ESM named import first; if Node reports a CommonJS "
                     "module, use the default-import form.")
    if language_for_file(file_path) == "typescript":
        lines.append("TypeScript: the file is executed with Node's type stripping (types only); it must not depend "
                     "on enums, namespaces, parameter properties or decorators; import it with its \".ts\" extension.")
    names = js_exported_names(file_path)
    if names:
        lines.append("Exported names detected: " + ", ".join(names))
    lines.append("Only node: built-ins and the target's own dependencies are available; never install packages.")
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
    """The symbol's code as shown to models: invisible characters stripped and secrets redacted."""
    if sym.symbol_type == "class" and sym.file_path.endswith(".py"):
        return prepare_untrusted_code(class_skeleton(sym.source_code))
    return prepare_untrusted_code(sym.source_code)


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
    """Source listing of symbols (with import paths), within an estimated token budget.

    A block that exceeds the remaining budget is truncated to fit rather than omitted
    (partial code is still context); only blocks too small to truncate meaningfully are dropped.
    """
    blocks: List[str] = []
    used = 0
    omitted = 0
    for sym in symbols:
        # The first block is always included (truncated if needed) so the prompt is never empty
        block = render_symbol(sym, root_dir, max_tokens if not blocks else None)
        cost = estimate_tokens(block)
        if blocks and used + cost > max_tokens:
            remaining = max_tokens - used - 2  # blank-line separator
            if remaining >= _MIN_TRUNCATED_BLOCK_TOKENS:
                block = render_symbol(sym, root_dir, remaining)
                cost = estimate_tokens(block)
                if used + cost <= max_tokens:
                    blocks.append(block)
                    used += cost
                    continue
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
    except (OSError, UnicodeDecodeError):
        # Undecodable (non-UTF-8 or binary) targets must degrade to an empty listing,
        # not crash the pipeline.
        return ""
    return truncate_to_tokens(prepare_untrusted_code(text), max_tokens)
