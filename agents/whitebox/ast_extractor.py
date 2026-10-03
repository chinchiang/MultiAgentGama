import ast
import logging
import os
import re
from bisect import bisect_right
from typing import List, Optional, Tuple, Union
from core.models import CodeSymbol

logger = logging.getLogger("VibeHarness.ASTExtractor")

SOURCE_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx")
# FastAPI/Starlette verbs plus Flask/Quart route decorators
ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "route", "api_route", "websocket"}

# HTTP verbs recognized in JS/TS, as router methods (app.get(...)) and Next.js handler names
_JS_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}
# `identifier(...) {` sequences that are control flow, not method declarations
_JS_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "const", "let",
                        "var", "new", "typeof", "delete", "void", "do", "else", "try", "class", "await", "yield"}
# After these keywords a `/` starts a regex literal, not division
_JS_REGEX_KEYWORDS = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
                      "case", "do", "else", "yield", "await"}
_JS_IDENTIFIER = r"[A-Za-z0-9_$]+"


class ASTExtractor:
    """
    Parses source code into structured CodeSymbol objects.
    Python is parsed with the native AST. JavaScript/TypeScript is parsed by a dependency-free
    lexer that blanks out strings, template literals, comments and regex literals (so neither
    comments nor literals can create phantom declarations) and then extracts declarations with
    real brace/parenthesis matching, giving accurate line spans instead of fixed-line windows.
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
        """Extracts JS/TS functions, arrows, classes with methods, and HTTP route handlers."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            self.parse_failures.append(file_path)
            return []

        masked = self._mask_source(content)
        line_offsets = [0] + [i + 1 for i, ch in enumerate(masked) if ch == "\n"]

        def line_of(pos: int) -> int:
            return bisect_right(line_offsets, pos)

        symbols: List[CodeSymbol] = []
        functions = self._extract_js_functions(content, masked, file_path, line_of)
        symbols.extend(functions)
        symbols.extend(self._extract_js_routes(content, masked, file_path, line_of, functions))
        return symbols

    # --- JS/TS lexing helpers ---------------------------------------------------

    @staticmethod
    def _mask_source(source: str) -> str:
        """Blanks out comments, string/template/regex literals while preserving length and newlines.

        Structural scans (declaration regexes, brace matching) run on the masked text so a
        commented-out route or a string containing 'function fake()' cannot create phantoms.
        """
        out = list(source)
        n = len(source)
        i = 0
        prev_char = ""       # last significant code character seen
        prev_word = ""       # last identifier/keyword seen
        while i < n:
            c = source[i]
            nxt = source[i + 1] if i + 1 < n else ""
            if c == "/" and nxt == "/":
                while i < n and source[i] != "\n":
                    out[i] = " "
                    i += 1
                continue
            if c == "/" and nxt == "*":
                out[i] = out[i + 1] = " "
                i += 2
                while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                    if source[i] != "\n":
                        out[i] = " "
                    i += 1
                i += 2
                continue
            if c in "\"'":
                i = ASTExtractor._mask_quoted(source, out, i, c)
                prev_char, prev_word = c, ""
                continue
            if c == "`":
                i = ASTExtractor._mask_template(source, out, i)
                prev_char, prev_word = c, ""
                continue
            if c == "/" and nxt not in ("", "/", "*"):
                # Regex literal or division? A `/` after a value-ending token is division,
                # unless the token is a keyword that opens a regex position (return /x/, typeof /y/).
                after_value = prev_char and (prev_char.isalnum() or prev_char in ")]}$_.\"'`")
                if not after_value or prev_word in _JS_REGEX_KEYWORDS:
                    i = ASTExtractor._mask_regex(source, out, i)
                    prev_char, prev_word = c, ""
                    continue
            if not c.isspace():
                word_continues = prev_char and (prev_char.isalnum() or prev_char in "_$")
                if c.isalnum() or c in "_$":
                    prev_word = (prev_word + c) if word_continues else c
                else:
                    prev_word = ""
                prev_char = c
            i += 1
        return "".join(out)

    @staticmethod
    def _mask_quoted(source: str, out: List[str], i: int, quote: str) -> int:
        n = len(source)
        i += 1
        while i < n and source[i] != quote:
            if source[i] == "\\":
                out[i] = " "
                i += 1
            if i < n and source[i] != "\n":
                out[i] = " "
            i += 1
        if i < n:
            out[i] = " "  # closing quote
        return i + 1

    @staticmethod
    def _mask_template(source: str, out: List[str], i: int) -> int:
        n = len(source)
        i += 1
        while i < n and source[i] != "`":
            if source[i] == "\\":
                out[i] = " "
                i += 1
                if i < n and source[i] != "\n":
                    out[i] = " "
                i += 1
                continue
            if source[i] == "$" and i + 1 < n and source[i + 1] == "{":
                out[i] = out[i + 1] = " "
                i += 2
                depth = 1
                while i < n and depth:
                    if source[i] == "$" and i + 1 < n and source[i + 1] == "{":
                        depth += 1
                        out[i] = out[i + 1] = " "
                        i += 2
                        continue
                    if source[i] == "{":
                        depth += 1
                    elif source[i] == "}":
                        depth -= 1
                    # the closing '}' of the interpolation is template syntax, not code
                    if source[i] != "\n":
                        out[i] = " "
                    i += 1
                continue
            if source[i] != "\n":
                out[i] = " "
            i += 1
        if i < n:
            out[i] = " "  # closing backtick
        return i + 1

    @staticmethod
    def _mask_regex(source: str, out: List[str], i: int) -> int:
        n = len(source)
        i += 1
        in_class = False
        while i < n:
            if source[i] == "\\":
                out[i] = " "
                i += 1
                if i < n and source[i] != "\n":
                    out[i] = " "
                i += 1
                continue
            if source[i] == "[":
                in_class = True
            elif source[i] == "]":
                in_class = False
            elif source[i] == "/" and not in_class:
                out[i] = " "
                i += 1
                break
            if i < n and source[i] != "\n":
                out[i] = " "
            i += 1
        while i < n and (source[i].isalpha()):
            out[i] = " "  # flags (g, i, m, ...)
            i += 1
        return i

    @staticmethod
    def _match_delim(masked: str, open_pos: int, open_ch: str, close_ch: str) -> Optional[int]:
        """Position of the delimiter matching the one at open_pos (literals/comments are blanked)."""
        depth = 0
        for i in range(open_pos, len(masked)):
            c = masked[i]
            if c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return i
        return None

    @staticmethod
    def _split_params(params_text: str) -> List[str]:
        """Splits a parameter list on top-level commas; drops defaults and TS annotations."""
        params: List[str] = []
        depth = 0
        current: List[str] = []
        for c in params_text:
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            if c == "," and depth == 0:
                params.append("".join(current))
                current = []
            else:
                current.append(c)
        params.append("".join(current))
        cleaned = []
        for p in params:
            p = p.split("=")[0].split(":")[0].strip()
            if p:
                cleaned.append(p)
        return cleaned

    def _snippet(self, content: str, line_of, start_pos: int, end_pos: int, file_path: str,
                 name: str, symbol_type: str, parameters: Optional[List[str]] = None,
                 signature: Optional[str] = None) -> CodeSymbol:
        start_line, end_line = line_of(start_pos), line_of(end_pos)
        lines = content.splitlines()
        return CodeSymbol(
            name=name,
            symbol_type=symbol_type,
            file_path=file_path,
            line_start=start_line,
            line_end=end_line,
            signature=signature or f"{name}({', '.join(parameters or [])})",
            source_code="\n".join(lines[start_line - 1:end_line]),
            parameters=parameters or []
        )

    # --- JS/TS extraction ---------------------------------------------------------

    def _extract_js_functions(self, content: str, masked: str, file_path: str, line_of) -> List[CodeSymbol]:
        symbols: List[CodeSymbol] = []
        taken: List[Tuple[int, int]] = []  # masked-text ranges already inside a symbol

        def overlaps(start: int, end: int) -> bool:
            return any(start < t_end and end > t_start for t_start, t_end in taken)

        # function declarations and function expressions: [export] [async] function[*] name(params) {...}
        fn_re = re.compile(rf"(?:export\s+)?(?:async\s+)?function\s*\*?\s*({_JS_IDENTIFIER})\s*\(")
        for m in fn_re.finditer(masked):
            open_paren = masked.index("(", m.end() - 1)
            close_paren = self._match_delim(masked, open_paren, "(", ")")
            if close_paren is None:
                continue
            name = m.group(1)
            params = self._split_params(content[open_paren + 1:close_paren])
            body_pos = self._skip_ws(masked, close_paren + 1)
            end_pos = close_paren
            if body_pos is not None and masked[body_pos] == "{":
                end_pos = self._match_delim(masked, body_pos, "{", "}") or close_paren
            elif body_pos is not None and masked[body_pos] != ";":
                # a function expression used directly in an expression statement
                end_pos = self._end_of_statement(masked, body_pos)
            if overlaps(m.start(), end_pos):
                continue
            taken.append((m.start(), end_pos))
            symbols.append(self._snippet(
                content, line_of, m.start(), end_pos, file_path, name, "function", params
            ))

        # arrow functions assigned to variables: [export] [const|let|var] name = [async] (params) => body
        for arrow_pos in [m.start() for m in re.finditer(r"=>", masked)]:
            start_pos, name, close_paren = self._arrow_declaration_back(masked, arrow_pos)
            if start_pos is None or name is None:
                continue
            body_pos = self._skip_ws(masked, arrow_pos + 2)
            if body_pos is None:
                continue
            if masked[body_pos] == "{":
                end_pos = self._match_delim(masked, body_pos, "{", "}") or arrow_pos + 1
            else:
                end_pos = self._end_of_statement(masked, body_pos)
            if overlaps(start_pos, end_pos):
                continue
            taken.append((start_pos, end_pos))
            arrow_params: List[str] = []
            if close_paren is not None:
                open_paren = self._find_open_paren(masked, close_paren)
                arrow_params = self._split_params(content[open_paren + 1:close_paren])
            symbols.append(self._snippet(
                content, line_of, start_pos, end_pos, file_path, name, "function", arrow_params
            ))

        # classes with methods: [export] [abstract] class Name [...] { ... }
        class_re = re.compile(rf"(?:export\s+)?(?:abstract\s+)?class\s+({_JS_IDENTIFIER})[^{{;]*\{{")
        for m in class_re.finditer(masked):
            open_brace = m.end() - 1
            close_brace = self._match_delim(masked, open_brace, "{", "}")
            if close_brace is None:
                continue
            symbols.append(self._snippet(
                content, line_of, m.start(), close_brace, file_path, m.group(1), "class", [],
                signature=f"class {m.group(1)}"
            ))
            symbols.extend(self._extract_js_methods(content, masked, file_path, line_of, m.group(1),
                                                    open_brace + 1, close_brace))
        return symbols

    def _extract_js_methods(self, content: str, masked: str, file_path: str, line_of,
                            class_name: str, body_start: int, body_end: int) -> List[CodeSymbol]:
        """Methods at the top level of a class body: [modifiers] name(params) { ... }."""
        symbols: List[CodeSymbol] = []
        pos = body_start
        while pos < body_end:
            if not masked[pos].isspace():
                pos += 1
                continue
            m = re.match(rf"\s+((?:async\s+|static\s+|\*\s*)*({_JS_IDENTIFIER}))\s*\(", masked[pos:body_end])
            if not m:
                pos += 1
                continue
            name = m.group(2)
            if name in _JS_CONTROL_KEYWORDS:
                pos += 1
                continue
            open_paren = pos + m.end() - 1
            close_paren = self._match_delim(masked, open_paren, "(", ")")
            if close_paren is None:
                pos += 1
                continue
            body_pos = self._skip_ws(masked, close_paren + 1)
            if body_pos is None or masked[body_pos] != "{":
                pos += 1
                continue
            close_body = self._match_delim(masked, body_pos, "{", "}")
            if close_body is None or close_body > body_end:
                pos += 1
                continue
            params = self._split_params(content[open_paren + 1:close_paren])
            symbols.append(self._snippet(
                content, line_of, pos + 1, close_body, file_path, f"{class_name}.{name}", "method", params
            ))
            pos = close_body + 1
        return symbols

    def _extract_js_routes(self, content: str, masked: str, file_path: str, line_of,
                           functions: List[CodeSymbol]) -> List[CodeSymbol]:
        """app/router/server/fastify.<verb>('/path', handler) calls, plus Next.js verb-named handlers."""
        symbols: List[CodeSymbol] = []
        verbs = "|".join(_JS_HTTP_VERBS)
        route_re = re.compile(rf"(?:^|[^.\w])(({_JS_IDENTIFIER})\.({verbs}))\s*\(")
        for m in route_re.finditer(masked):
            receiver, verb = m.group(2), m.group(3)
            if receiver in _JS_CONTROL_KEYWORDS:
                continue
            open_paren = m.end() - 1
            close_paren = self._match_delim(masked, open_paren, "(", ")")
            if close_paren is None:
                continue
            path = self._first_string_literal(content[open_paren + 1:close_paren])
            name = f"{verb.upper()} {path}" if path else f"{verb.upper()} {receiver}.{verb}"
            symbols.append(self._snippet(
                content, line_of, m.start(1), close_paren, file_path, name, "route", [],
                signature=name
            ))
        # Next.js App Router handlers: export [async] function GET(request) {...} — the verb-named
        # functions are retagged as routes.
        verb_names = {v.upper() for v in _JS_HTTP_VERBS}
        for sym in functions:
            if sym.symbol_type == "function" and sym.name.upper() in verb_names:
                symbols.append(sym.model_copy(update={
                    "symbol_type": "route",
                    "signature": f"export async function {sym.name}({', '.join(sym.parameters)})",
                }))
        return symbols

    # --- small scanners ---------------------------------------------------------------

    @staticmethod
    def _skip_ws(masked: str, pos: int) -> Optional[int]:
        n = len(masked)
        while pos < n:
            if masked[pos].isspace():
                pos += 1
            else:
                return pos
        return None

    @staticmethod
    def _find_open_paren(masked: str, close_pos: int) -> int:
        """Position of the '(' matching the ')' at close_pos (inclusive); returns 0 when unbalanced."""
        depth = 0
        for i in range(close_pos, -1, -1):
            c = masked[i]
            if c == ")":
                depth += 1
            elif c == "(":
                depth -= 1
                if depth == 0:
                    return i
        return 0

    def _arrow_declaration_back(self, masked: str, arrow_pos: int) -> Tuple[Optional[int], Optional[str], Optional[int]]:
        """Walks back from '=>' to the [export] [const|let|var] name = declaration.
        Returns (start_pos, name, close_paren_of_params) or (None, None, None) when the arrow is
        not an assigned arrow function (e.g. a comparison, or an arrow passed as a call argument)."""
        close_paren = None
        i = arrow_pos - 1
        # (params) or a single bare parameter (const f = x => ...)
        j = self._skip_ws_back(masked, i)
        if j is not None and masked[j] == ")":
            close_paren = j
            i = self._find_open_paren(masked, j) - 1
        else:
            word, w_start = self._word_back(masked, i)
            if word:
                i = w_start - 1
        # optional async between '=' and the params
        word, w_start = self._word_back(masked, i)
        if word == "async":
            i = w_start - 1
        # the '=' of the assignment (and not ==, <=, =>, ...)
        j = self._skip_ws_back(masked, i)
        if j is None or masked[j] != "=" or (j > 0 and masked[j - 1] in "=!<>+-*/%&|^"):
            return None, None, None
        # the assigned variable name
        name, name_start = self._word_back(masked, j - 1)
        if not name:
            return None, None, None
        start = name_start
        # optional const/let/var, then optional export
        word, w_start = self._word_back(masked, start - 1)
        if word in ("const", "let", "var"):
            start = w_start
            word, w_start = self._word_back(masked, start - 1)
            if word == "export":
                start = w_start
        return start, name, close_paren

    @staticmethod
    def _word_back(masked: str, pos: int) -> Tuple[Optional[str], int]:
        """The identifier/keyword ending at or before pos (skipping whitespace); (None, pos) if none."""
        j = ASTExtractor._skip_ws_back(masked, pos)
        if j is None:
            return None, pos
        k = j
        while k >= 0 and (masked[k].isalnum() or masked[k] in "_$"):
            k -= 1
        word = masked[k + 1:j + 1]
        return (word, k + 1) if word else (None, pos)

    @staticmethod
    def _skip_ws_back(masked: str, pos: int) -> Optional[int]:
        while pos >= 0 and masked[pos].isspace():
            pos -= 1
        return pos if pos >= 0 else None

    @staticmethod
    def _end_of_statement(masked: str, pos: int) -> int:
        """End of a brace-less arrow body: the newline (or ';') where all brackets are closed again."""
        depth = 0
        n = len(masked)
        i = pos
        while i < n:
            c = masked[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif depth == 0 and (c == ";" or c == "\n"):
                return i
            i += 1
        return n - 1

    @staticmethod
    def _first_string_literal(text: str) -> Optional[str]:
        """The first quoted string in the given text (single, double or template literal)."""
        n = len(text)
        i = 0
        while i < n:
            c = text[i]
            if c in "\"'`":
                quote = c
                i += 1
                chars: List[str] = []
                while i < n and text[i] != quote:
                    if text[i] == "\\" and i + 1 < n:
                        chars.append(text[i + 1])
                        i += 2
                        continue
                    if quote != "`" and text[i] == "\n":
                        return None  # unterminated line string: not a real path literal
                    chars.append(text[i])
                    i += 1
                return "".join(chars)
            i += 1
        return None

    def _extract_python_function(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        file_path: str,
        source_lines: List[str],
        class_name: Optional[str] = None
    ) -> Optional[CodeSymbol]:
        # Include decorators: they carry route paths and auth guards the reviewers need to see
        start = min([d.lineno for d in node.decorator_list] + [node.lineno])
        end = node.end_lineno or start
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
        end = node.end_lineno or start
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
