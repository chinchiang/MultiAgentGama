import ast
import os
import re
from typing import List, Dict, Any, Optional
from core.models import CodeSymbol


class ASTExtractor:
    """
    Parses source code into structured CodeSymbol objects.
    Supports Python via native AST parsing, and TypeScript/JavaScript via structural regex extraction.
    """

    def __init__(self):
        self.detected_languages = set()

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
        if os.path.isfile(dir_path):
            return self.parse_file(dir_path)
        all_symbols: List[CodeSymbol] = []
        count = 0
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ["venv", "__pycache__", "node_modules", "dist", "build"]]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in [".py", ".js", ".jsx", ".ts", ".tsx"]:
                    full_path = os.path.join(root, file)
                    all_symbols.extend(self.parse_file(full_path))
                    count += 1
                    if count >= max_files:
                        break
            if count >= max_files:
                break
        return all_symbols

    def _parse_python_file(self, file_path: str) -> List[CodeSymbol]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source, filename=file_path)
        except Exception:
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
        except Exception:
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
        start = node.lineno
        end = getattr(node, "end_lineno", start + 1)
        source_snippet = "\n".join(source_lines[start - 1 : end])

        args = [arg.arg for arg in node.args.args]
        symbol_type = "method" if class_name else "function"
        full_name = f"{class_name}.{node.name}" if class_name else node.name

        docstring = ast.get_docstring(node)

        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in ["get", "post", "put", "delete", "patch"]:
                    symbol_type = "route"

        return CodeSymbol(
            name=full_name,
            symbol_type=symbol_type,
            file_path=file_path,
            line_start=start,
            line_end=end,
            signature=f"{node.name}({', '.join(args)})",
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
        start = node.lineno
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
