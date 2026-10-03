import ast
import logging
import os
import re
from typing import List, Optional
from core.models import CodeSymbol

logger = logging.getLogger("VibeHarness.ASTExtractor")

SOURCE_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx")
# FastAPI/Starlette verbs plus Flask/Quart route decorators
ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "route", "api_route", "websocket"}


class ASTExtractor:
    """
    Parses source code into structured CodeSymbol objects.
    Supports Python via native AST parsing, and TypeScript/JavaScript via structural regex extraction.
    """

    def __init__(self):
        self.detected_languages = set()
        # Files that could not be read/parsed, and files left out by the max_files cap
        self.parse_failures: List[str] = []
        self.skipped_files: List[str] = []

    def parse_file(self, file_path: str) -> List[CodeSymbol]:
        if not os.path.exists(file_path):
            return []

        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".py":
            self.detected_languages.add("Python")
            return self._parse_python_file(file_path)
        elif ext in [".js", ".jsx", ".ts", ".tsx"]:
            self.detected_languages.add("TypeScript/JavaScript")
            return self._parse_js_ts_file(file_path)
        return []

    def parse_directory(self, dir_path: str, max_files: int = 50) -> List[CodeSymbol]:
        """Parses a directory tree (up to max_files source files) or a single source file."""
        self.parse_failures, self.skipped_files = [], []
        if os.path.isfile(dir_path):
            return self.parse_file(dir_path)
        source_files: List[str] = []
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in ["venv", "__pycache__", "node_modules", "dist", "build"])
            source_files.extend(os.path.join(root, f) for f in sorted(files) if f.lower().endswith(SOURCE_EXTENSIONS))

        self.skipped_files = source_files[max_files:]
        if self.skipped_files:
            logger.warning(f"Only the first {max_files} of {len(source_files)} source files are analyzed; {len(self.skipped_files)} skipped.")
        all_symbols: List[CodeSymbol] = []
        for full_path in source_files[:max_files]:
            all_symbols.extend(self.parse_file(full_path))
        return all_symbols

    def _parse_python_file(self, file_path: str) -> List[CodeSymbol]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source, filename=file_path)
        except Exception as e:
            logger.warning(f"Could not parse {file_path}: {e}")
            self.parse_failures.append(file_path)
            return []

        symbols: List[CodeSymbol] = []
        source_lines = source.splitlines()

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sym = self._extract_python_function(node, file_path, source_lines)
                if sym:
                    symbols.append(sym)
            elif isinstance(node, ast.ClassDef):
                sym = self._extract_python_class(node, file_path, source_lines)
                if sym:
                    symbols.append(sym)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_sym = self._extract_python_function(item, file_path, source_lines, class_name=node.name)
                        if method_sym:
                            symbols.append(method_sym)

        return symbols

    def _parse_js_ts_file(self, file_path: str) -> List[CodeSymbol]:
        """Heuristic extractor for JS/TS functions, classes, and Express/Next.js route handlers."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            self.parse_failures.append(file_path)
            return []

        symbols: List[CodeSymbol] = []
        lines = content.splitlines()

        # Match function declarations: function name(...) or const name = (...) =>
        fn_pattern = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+([a-zA-Z0-9_$]+)|const\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(([^)]*)\))")
        # Match routes: app.get('/...', ...), router.post('/...', ...)
        route_pattern = re.compile(r"^\s*(?:app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]")

        for idx, line in enumerate(lines):
            route_match = route_pattern.search(line)
            if route_match:
                method, path = route_match.groups()
                symbols.append(CodeSymbol(
                    name=f"{method.upper()} {path}",
                    symbol_type="route",
                    file_path=file_path,
                    line_start=idx + 1,
                    line_end=min(idx + 15, len(lines)),
                    signature=f"{method.upper()} {path}",
                    source_code="\n".join(lines[idx:min(idx + 15, len(lines))]),
                    parameters=[]
                ))
                continue

            fn_match = fn_pattern.search(line)
            if fn_match:
                name = fn_match.group(1) or fn_match.group(2)
                params = [p.strip() for p in (fn_match.group(3) or "").split(",") if p.strip()]
                symbols.append(CodeSymbol(
                    name=name,
                    symbol_type="function",
                    file_path=file_path,
                    line_start=idx + 1,
                    line_end=min(idx + 25, len(lines)),
                    signature=f"{name}({', '.join(params)})",
                    source_code="\n".join(lines[idx:min(idx + 25, len(lines))]),
                    parameters=params
                ))

        return symbols

    def _extract_python_function(
        self,
        node: ast.FunctionDef,
        file_path: str,
        source_lines: List[str],
        class_name: Optional[str] = None
    ) -> Optional[CodeSymbol]:
        # Include decorators: they carry route paths and auth guards the reviewers need to see
        start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        end = getattr(node, "end_lineno", node.lineno + 1)
        source_snippet = "\n".join(source_lines[start - 1 : end])

        args = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        # *args / **kwargs are part of the function's contract; reviewers and probes need them
        if node.args.vararg:
            args.append(f"*{node.args.vararg.arg}")
        kw_vararg = [f"**{node.args.kwarg.arg}"] if node.args.kwarg else []
        symbol_type = "method" if class_name else "function"
        full_name = f"{class_name}.{node.name}" if class_name else node.name

        docstring = ast.get_docstring(node)

        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in ROUTE_DECORATORS:
                    symbol_type = "route"

        return CodeSymbol(
            name=full_name,
            symbol_type=symbol_type,
            file_path=file_path,
            line_start=start,
            line_end=end,
            signature=f"{node.name}({', '.join(args + kw_vararg)})",
            docstring=docstring,
            source_code=source_snippet,
            parameters=args
        )

    def _extract_python_class(
        self,
        node: ast.ClassDef,
        file_path: str,
        source_lines: List[str]
    ) -> Optional[CodeSymbol]:
        # Include decorators, consistent with functions: they carry registration/behavior context
        start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        end = getattr(node, "end_lineno", start + 1)
        source_snippet = "\n".join(source_lines[start - 1 : end])

        return CodeSymbol(
            name=node.name,
            symbol_type="class",
            file_path=file_path,
            line_start=start,
            line_end=end,
            signature=f"class {node.name}",
            docstring=ast.get_docstring(node),
            source_code=source_snippet,
            parameters=[]
        )
