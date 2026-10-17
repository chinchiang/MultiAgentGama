"""提供模型提示詞目標的真實程式碼，以及在沙盒中可用的匯入路徑的輔助函式。
Helpers that give model prompts the target's real code and an import path that works in the sandbox."""
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
# 不用分詞器的粗略估計：程式碼平均每個 token 約 3.5 個字元；非 ASCII（例如 CJK）約每字 1 個 token。
# 刻意保守，以免在真實分詞器上超出預算。
# Rough tokenizer-free estimate: code averages ~3.5 characters per token; non-ASCII (e.g. CJK) is ~1 token each.
# Deliberately conservative so budgets are not overshot on real tokenizers.
_ASCII_CHARS_PER_TOKEN = 3.5

# 低於這個 token 數的部分區塊不值得保留；改為省略該符號
# Below this many tokens a partial block is not worth keeping; the symbol is omitted instead
_MIN_TRUNCATED_BLOCK_TOKENS = 80


def estimate_tokens(text: str) -> int:
    non_ascii = sum(1 for ch in text if ord(ch) > 127)
    return math.ceil((len(text) - non_ascii) / _ASCII_CHARS_PER_TOKEN) + non_ascii


def truncate_to_tokens(text: str, max_tokens: int, marker: str = "\n# ... (truncated)") -> str:
    if estimate_tokens(text) <= max_tokens:
        return text
    # 二分搜尋能塞進去的最長前綴；estimate_tokens 隨前綴長度單調遞增
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


def target_root(root_dir: Optional[str], file_path: str) -> str:
    """呈現目標程式碼時路徑的相對基準：呼叫端給的 `root_dir`，沒有時是 `file_path` 所在的目錄
    （harness 一律給 root_dir；這只是函式庫呼叫端的退路）。
    The base that paths are shown relative to when presenting target code: the caller's `root_dir`, else the
    directory of `file_path` (the harness always passes root_dir; this is only a fallback for library callers)."""
    return root_dir or os.path.dirname(os.path.abspath(file_path))


def import_root(root_dir: str) -> str:
    """產生的測試要能以名稱匯入目標，sys.path 上必須有的那個目錄。

    沙盒會把目標目錄及其父目錄都放上 sys.path。當目標目錄本身就是一個套件
    （它有 ``__init__.py``）時，裡面的模組必須透過套件匯入
    （``from shop.app import checkout``）：直接匯入 ``app`` 會讓套件自己的相對匯入
    （``from .models import ...``）失敗並出現 "attempted relative
    import with no known parent package"，而執行器接著會把這歸咎於目標。
    The directory a generated test must have on sys.path to import the target by name.

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
    root_dir 底下某個 Python 檔案的點分模組名稱，可從沙盒的 sys.path
    （root_dir，或當 root_dir 是套件時其父目錄；見 import_root）匯入；若該檔案
    在 root_dir 之外或不是 Python，則為 None。
    Dotted module name for a Python file under root_dir, importable from the sandbox's sys.path
    (root_dir, or its parent when root_dir is a package; see import_root), or None when the file
    is outside root_dir or is not Python.
    """
    if not file_path.endswith(".py"):
        return None
    try:
        rel = os.path.relpath(os.path.abspath(file_path), import_root(root_dir))
    except ValueError:  # Windows：檔案與根目錄在不同磁碟機 ／ Windows: file and root on different drives
        return None
    if rel.startswith(".."):
        return None
    parts = rel[:-3].split(os.sep)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts and all(p.isidentifier() for p in parts) else None


def language_for_file(file_path: str) -> str:
    """"typescript"、"javascript" 或 "python"（預設值：Python 沙盒是後備方案）。
    "typescript", "javascript" or "python" (the default: the Python sandbox is the fallback)."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in _TS_EXTS:
        return "typescript"
    if ext in _JS_EXTS:
        return "javascript"
    return "python"


def target_file_url(file_path: str, path_cls: type = pathlib.Path) -> str:
    """Node 測試用來匯入目標的 file:// URL（Windows 上為 `file:///C:/proj/app.js`）。
    The file:// URL a Node test imports the target through (`file:///C:/proj/app.js` on Windows)."""
    return path_cls(os.path.abspath(file_path)).as_uri()


def _masked_js(source: str) -> str:
    from vibeharness.agents.whitebox.ast_extractor import ASTExtractor  # 不會循環匯入：它只匯入 models ／ no cycle: it imports only models
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
    """"esm"、"cjs" 或 "unknown"：先看副檔名，再看檔案自己的最上層語法（在遮罩後的
    原始碼上，所以註解與字串無法偽造），最後看最近的 package.json 的 "type"。
    "esm", "cjs" or "unknown": extension first, then the file's own top-level syntax (on masked
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
    """該檔案匯出的名稱（ESM `export`、CommonJS `exports.x`／`module.exports = {...}`），依出現順序。
    Names the file exports (ESM `export`, CommonJS `exports.x` / `module.exports = {...}`), in order."""
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
    """精確地告訴模型產生的測試必須如何匯入受測程式碼。
    Tells the model exactly how the generated test must import the code under test."""
    abs_path = os.path.abspath(file_path)
    language = language_for_file(file_path)
    if language != "python":
        return js_import_instructions(file_path, symbol_name)
    if not file_path.endswith(".py"):
        # 既不是 Python 也不是 JS/TS：沒有東西能執行它，所以不產生匯入，也不產生可執行的測試程式碼
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
    """`node:test` 模組（一律是 ESM，從暫存目錄執行）如何匯入目標：透過它的
    file:// URL，並使用符合目標模組系統的匯入形式。
    How a `node:test` module (always ESM, run from a temp directory) imports the target: through its
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
    方法本體被換成 `...` 的 Python 類別。方法會被擷取成各自的符號，
    所以若把完整類別連同它們一起呈現，每個方法本體都會被送兩次。
    若無法解析，則原樣回傳原始碼。
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
    # 由下往上替換，讓前面的行號維持有效
    # Replace bottom-up so earlier line numbers stay valid
    methods = [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in sorted(methods, key=lambda n: n.lineno, reverse=True):
        body_start = node.body[0].lineno
        indent = " " * node.body[0].col_offset
        if body_start > node.lineno:
            lines[body_start - 1:node.end_lineno] = [f"{indent}...  # body listed separately"]
        # 單行方法（`def f(self): return 1`）已經和骨架一樣短
        # One-line methods (`def f(self): return 1`) are already as short as a skeleton
    return "\n".join(lines)


def symbol_source(sym: CodeSymbol) -> str:
    """呈現給模型的符號程式碼：不可見字元已剔除、機密已遮蔽。
    The symbol's code as shown to models: invisible characters stripped and secrets redacted."""
    if sym.symbol_type == "class" and sym.file_path.endswith(".py"):
        return prepare_untrusted_code(class_skeleton(sym.source_code))
    return prepare_untrusted_code(sym.source_code)


def render_symbol(sym: CodeSymbol, root_dir: str, max_tokens: Optional[int] = None) -> str:
    """單一符號的清單區塊；若光是這個區塊就會超過 max_tokens，其原始碼會被截斷。
    One symbol's listing block; its source is truncated if the block alone would exceed max_tokens."""
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
    """各符號的原始碼清單（附匯入路徑），控制在估算的 token 預算內。

    超出剩餘預算的區塊會被截斷以塞進去，而不是整個省略
    （部分程式碼仍是上下文）；只有小到無法有意義截斷的區塊才會被捨棄。
    Source listing of symbols (with import paths), within an estimated token budget.

    A block that exceeds the remaining budget is truncated to fit rather than omitted
    (partial code is still context); only blocks too small to truncate meaningfully are dropped.
    """
    blocks: List[str] = []
    used = 0
    omitted = 0
    for sym in symbols:
        # 第一個區塊一律納入（必要時截斷），讓提示詞永遠不會是空的
        # The first block is always included (truncated if needed) so the prompt is never empty
        block = render_symbol(sym, root_dir, max_tokens if not blocks else None)
        cost = estimate_tokens(block)
        if blocks and used + cost > max_tokens:
            remaining = max_tokens - used - 2  # 空行分隔符 ／ blank-line separator
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
    把符號切成多個批次，每批渲染後的清單都能塞進 max_tokens，讓 render_symbols 永遠不必
    省略任何符號。單一符號若本身就塞不進一個批次，則自成一批（並被截斷）。
    Splits symbols into batches whose rendered listing fits max_tokens, so render_symbols never has to
    omit any of them. A symbol too large for a batch on its own gets a batch to itself (and is truncated).
    """
    batches: List[List[CodeSymbol]] = []
    current: List[CodeSymbol] = []
    used = 0
    for sym in symbols:
        cost = estimate_tokens(render_symbol(sym, root_dir)) + 1  # +1 是空行分隔符 ／ +1 for the blank-line separator
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
        # 無法解碼（非 UTF-8 或二進位）的目標必須降級成空的清單，
        # 而不是讓整條管線崩潰。
        # Undecodable (non-UTF-8 or binary) targets must degrade to an empty listing,
        # not crash the pipeline.
        return ""
    return truncate_to_tokens(prepare_untrusted_code(text), max_tokens)
