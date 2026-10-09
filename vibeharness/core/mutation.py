"""突變測試（第一版，僅限 Python）：對「已通過」的白箱測試所涵蓋的函式做確定性的小改動
（單一 token 的運算子或常數切換），再檢查這些測試會不會失敗。不呼叫任何模型，也不寫入使用者的目標。
Mutation testing (first version, Python only): applies small deterministic single-token changes
(operator or constant swaps) to the functions that PASSED white-box tests cover and checks whether those
tests fail. No model is called and the user's target is never written to.

分數是下界：行為等價的變異體無法判定，會被算成存活。
The score is a lower bound: behaviour-equivalent mutants cannot be decided and count as survivors.
"""
import ast
import bisect
import io
import logging
import os
import shutil
import tempfile
import tokenize
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from vibeharness.core.i18n import bi
from vibeharness.core.models import (
    CodeSymbol, GeneratedTest, MutantResult, MutationReport, ReviewFinding, TestExecutionResult, TestStatus,
)
from vibeharness.core.sandbox import rewrite_host_paths

logger = logging.getLogger("VibeHarness.Mutation")

# 變異體只用這幾類測試的結果：探針會吞掉例外，幾乎必過，沒有訊號
# Only these test types are used: probes swallow exceptions, pass almost always and carry no signal
ELIGIBLE_TEST_TYPES = ("whitebox_unit", "whitebox_property")

_ARITHMETIC = {ast.Add: ("+", "-"), ast.Sub: ("-", "+"), ast.Mult: ("*", "/"), ast.Div: ("/", "*")}
_COMPARISON = {
    ast.Eq: ("==", "!="), ast.NotEq: ("!=", "=="), ast.Lt: ("<", "<="), ast.LtE: ("<=", "<"),
    ast.Gt: (">", ">="), ast.GtE: (">=", ">"),
}
_BOOLEAN = {ast.And: ("and", "or"), ast.Or: ("or", "and")}


@dataclass(frozen=True)
class MutationSite:
    """一個可變異的位置：行（從 1 起算）、字元欄位、原文與替換文字。
    One mutable spot: line (1-based), character column, the original token and its replacement."""
    line: int
    col: int
    original: str
    replacement: str
    operator: str
    symbol: str = ""


@dataclass
class _Tokens:
    """tokenize 的結果與位置索引（tokenize 的欄位是字元位移，不是 UTF-8 位元組）。
    The tokenize result plus a position index (tokenize columns are character offsets, not UTF-8 bytes)."""
    items: List[tokenize.TokenInfo]
    starts: List[Tuple[int, int]]

    @classmethod
    def of(cls, source: str) -> "_Tokens":
        items = [t for t in tokenize.generate_tokens(io.StringIO(source).readline)
                 if t.type in (tokenize.OP, tokenize.NAME, tokenize.NUMBER)]
        return cls(items, [t.start for t in items])

    def find(self, text: str, after: Tuple[int, int], before: Optional[Tuple[int, int]] = None) -> Optional[tokenize.TokenInfo]:
        """第一個字串為 text、起點不早於 after 且終點不晚於 before 的 token。
        The first token spelled `text` that starts at or after `after` and ends no later than `before`."""
        for token in self.items[bisect.bisect_left(self.starts, after):]:
            if before is not None and token.end > before:
                return None
            if token.string == text:
                return token
        return None


def _char_pos(lines: Sequence[str], lineno: int, byte_offset: int) -> Tuple[int, int]:
    """AST 的欄位是 UTF-8 位元組位移：換成字元欄位，含中文的行才不會切錯位置。
    AST columns are UTF-8 byte offsets: convert to a character column so lines with Chinese text are not split wrongly."""
    line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
    return lineno, len(line.encode("utf-8")[:byte_offset].decode("utf-8", "ignore"))


def _start(lines: Sequence[str], node: ast.AST) -> Tuple[int, int]:
    return _char_pos(lines, node.lineno, node.col_offset)  # type: ignore[attr-defined]


def _end(lines: Sequence[str], node: ast.AST) -> Tuple[int, int]:
    return _char_pos(lines, node.end_lineno, node.end_col_offset)  # type: ignore[attr-defined]


def _function_nodes(tree: ast.AST, line_start: int, line_end: int) -> List[ast.AST]:
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name != "__init__" and line_start <= n.lineno <= line_end and (n.end_lineno or n.lineno) <= line_end]


def find_mutation_sites(source: str, line_start: int, line_end: int, symbol: str = "") -> List[MutationSite]:
    """某個符號（行範圍）內的所有變異位置，依位置排序、去重，順序固定。只看函式本體：
    不動 docstring、裝飾器、型別註解與 `__init__`。
    Every mutation site inside one symbol's line range, sorted by position and deduplicated, in a fixed order.
    Only function bodies are touched: no docstrings, decorators, annotations or `__init__`."""
    try:
        tree = ast.parse(source)
        tokens = _Tokens.of(source)
    except (SyntaxError, tokenize.TokenError, IndentationError, ValueError):
        return []
    lines = source.split("\n")
    found: Dict[Tuple[int, int], MutationSite] = {}

    def add(token: Optional[tokenize.TokenInfo], replacement: str, operator: str) -> None:
        if token is not None:
            found.setdefault(token.start, MutationSite(token.start[0], token.start[1], token.string, replacement, operator, symbol))

    for function in _function_nodes(tree, line_start, line_end):
        body = list(function.body)  # type: ignore[attr-defined]
        if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                and isinstance(body[0].value.value, str):  # type: ignore[attr-defined]
            body = body[1:]  # 略過文件字串 ／ skip the docstring
        for statement in body:
            for node in ast.walk(statement):
                if isinstance(node, ast.BinOp) and type(node.op) in _ARITHMETIC:
                    original, replacement = _ARITHMETIC[type(node.op)]
                    add(tokens.find(original, _end(lines, node.left), _start(lines, node.right)), replacement, "arithmetic")
                elif isinstance(node, ast.Compare):
                    previous = node.left
                    for op, comparator in zip(node.ops, node.comparators, strict=True):
                        if type(op) in _COMPARISON:
                            original, replacement = _COMPARISON[type(op)]
                            add(tokens.find(original, _end(lines, previous), _start(lines, comparator)), replacement, "comparison")
                        previous = comparator
                elif isinstance(node, ast.BoolOp) and type(node.op) in _BOOLEAN:
                    original, replacement = _BOOLEAN[type(node.op)]
                    for left, right in zip(node.values, node.values[1:], strict=False):
                        add(tokens.find(original, _end(lines, left), _start(lines, right)), replacement, "boolean")
                elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                    add(tokens.find("not", _start(lines, node)), "", "negation")
                elif isinstance(node, ast.Constant):
                    if node.value is True or node.value is False:
                        text = "True" if node.value else "False"
                        add(tokens.find(text, _start(lines, node), _end(lines, node)), "False" if node.value else "True", "constant")
                    elif type(node.value) is int and node.value in (0, 1):
                        add(tokens.find(str(node.value), _start(lines, node), _end(lines, node)), "1" if node.value == 0 else "0", "constant")
    return [found[key] for key in sorted(found)]


def apply_mutation(source: str, site: MutationSite) -> Optional[str]:
    """把 site 切換進 source：只改一個 token，註解與其餘文字原封不動。結果不能解析、
    或語法樹與原本相同（等價）時回傳 None。
    Splices `site` into `source`: exactly one token changes, comments and the rest of the text stay as they are.
    Returns None when the result does not parse or its syntax tree equals the original (equivalent)."""
    lines = source.split("\n")
    if not 0 < site.line <= len(lines):
        return None
    line = lines[site.line - 1]
    if line[site.col:site.col + len(site.original)] != site.original:
        return None
    lines[site.line - 1] = line[:site.col] + site.replacement + line[site.col + len(site.original):]
    mutated = "\n".join(lines)
    try:
        if ast.dump(ast.parse(mutated)) == ast.dump(ast.parse(source)):
            return None
    except (SyntaxError, ValueError):
        return None
    return mutated


def select_sites(groups: Dict[Tuple[str, str], List[MutationSite]], limit: int) -> Tuple[List[Tuple[str, MutationSite]], int]:
    """輪流從每個（檔案，符號）群組取一個位置，直到湊滿 limit：變異體分散在各處，順序固定。
    回傳（選中的（檔案，位置）、候選總數）。
    Takes one site from each (file, symbol) group in turn until `limit` is reached, so mutants spread out in a
    fixed order. Returns (the selected (file, site) pairs, the total candidate count)."""
    ordered = [(key, list(sites)) for key, sites in sorted(groups.items())]
    total = sum(len(sites) for _, sites in ordered)
    selected: List[Tuple[str, MutationSite]] = []
    depth = 0
    while len(selected) < limit and any(depth < len(sites) for _, sites in ordered):
        for (file_path, _symbol), sites in ordered:
            if depth < len(sites) and len(selected) < limit:
                selected.append((file_path, sites[depth]))
        depth += 1
    return selected, total


def eligible_tests(tests: Sequence[GeneratedTest], results: Sequence[TestExecutionResult]) -> List[GeneratedTest]:
    """已通過的 Python 白箱測試（單元／性質）：變異體只用它們。
    The PASSED Python white-box tests (unit / property): the only ones mutants are run against."""
    return [t for t, r in zip(tests, results, strict=False)
            if r.status == TestStatus.PASSED and t.language == "python" and t.test_type in ELIGIBLE_TEST_TYPES]


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", newline="") as f:
        return f.read()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def _skipped(reason_zh: str, reason_en: str, eligible: int = 0) -> MutationReport:
    return MutationReport(enabled=True, eligible_tests=eligible, skipped_reason=bi(reason_zh, reason_en))


def run_mutation_testing(
    run_batch: Callable[[List[GeneratedTest], str, int], str],
    tests: Sequence[GeneratedTest],
    results: Sequence[TestExecutionResult],
    findings: Sequence[ReviewFinding],
    symbols: Sequence[CodeSymbol],
    work_dir: str,
    max_mutants: int,
    timeout_seconds: int,
) -> MutationReport:
    """對已通過的白箱測試所涵蓋的符號做突變測試。`run_batch(tests, working_dir, timeout)` 回傳
    "killed"（有測試失敗或逾時）、"survived"（全數通過）或 "invalid"（變異體讓程式壞到無法判斷）。
    複本放在暫存目錄，每個變異體只覆寫一個檔案並在 finally 還原；使用者的目標絕不會被寫入。
    Runs mutation testing on the symbols the PASSED white-box tests cover. `run_batch(tests, working_dir,
    timeout)` returns "killed" (a test failed or timed out), "survived" (all passed) or "invalid" (the mutant
    broke the code so badly that nothing can be concluded). The copy lives in a temp directory, each mutant
    overwrites one file and is restored in a finally block; the user's target is never written to."""
    usable = eligible_tests(tests, results)
    if not usable:
        return _skipped("沒有可用的已通過 Python 白箱測試", "no passed Python white-box tests to mutate against")
    root = os.path.abspath(work_dir)
    by_id = {f.finding_id: f for f in findings}
    groups: Dict[Tuple[str, str], List[MutationSite]] = {}
    sources: Dict[str, str] = {}
    for test in usable:
        finding = by_id.get(test.source_ref or "")
        if finding is None or not finding.file_path.endswith(".py") or not finding.symbol_name:
            continue
        file_path = os.path.abspath(finding.file_path)
        key = (file_path, finding.symbol_name)
        if key in groups or not (file_path == root or file_path.startswith(root + os.sep)) or not os.path.isfile(file_path):
            continue
        symbol = next((s for s in symbols if s.name == finding.symbol_name and os.path.abspath(s.file_path) == file_path), None)
        if symbol is None:
            continue
        sources.setdefault(file_path, _read(file_path))
        groups[key] = find_mutation_sites(sources[file_path], symbol.line_start, symbol.line_end, symbol.name)
    selected, candidates = select_sites({k: v for k, v in groups.items() if v}, max(1, max_mutants))
    if not selected:
        return _skipped("測試涵蓋的符號裡沒有可變異的位置", "no mutable spots in the symbols the tests cover", len(usable))

    scratch = tempfile.mkdtemp(prefix="vibe_mutation_")
    report = MutationReport(enabled=True, eligible_tests=len(usable), candidate_sites=candidates,
                            truncated=candidates > len(selected))
    try:
        copy_dir = os.path.join(scratch, os.path.basename(root.rstrip("/\\")) or "target")
        shutil.copytree(root, copy_dir, ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__", "*.pyc"))
        rewritten = [t.model_copy(update={"code": rewrite_host_paths(t.code, [(root, copy_dir)])}) for t in usable]
        # 先確認測試在未變異的複本上全部通過：否則複本或路徑改寫有問題，之後的「殺死」都不可信
        # First confirm the tests all pass on the unmutated copy: otherwise the copy or the path rewrite is off
        # and every later kill would be meaningless
        if run_batch(rewritten, copy_dir, timeout_seconds) != "survived":
            return _skipped("測試在未變異的複本上沒有全部通過，無法判斷變異體", "the tests do not all pass on the unmutated copy, so mutants cannot be judged", len(usable))
        for file_path, site in selected:
            relative = os.path.relpath(file_path, root)
            target = os.path.join(copy_dir, relative)
            original = sources[file_path]
            mutated = apply_mutation(original, site)
            if mutated is None:
                continue
            _write(target, mutated)
            try:
                outcome = run_batch(rewritten, copy_dir, timeout_seconds)
            finally:
                _write(target, original)
            lines = original.split("\n")
            report.mutants.append(MutantResult(
                file=relative.replace(os.sep, "/"), line=site.line, operator=site.operator, symbol=site.symbol,
                original=lines[site.line - 1].strip(),
                mutated=mutated.split("\n")[site.line - 1].strip(),
                status=outcome if outcome in ("killed", "survived") else "invalid"))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    report.killed = sum(1 for m in report.mutants if m.status == "killed")
    report.survived = sum(1 for m in report.mutants if m.status == "survived")
    report.invalid = sum(1 for m in report.mutants if m.status == "invalid")
    report.total = len(report.mutants)
    decided = report.killed + report.survived
    report.score = round(100.0 * report.killed / decided, 1) if decided else None
    if decided == 0:
        report.skipped_reason = bi("沒有任何變異體得出結論", "no mutant produced a conclusive result")
    logger.info(bi(f"突變測試：{report.killed} 殺死、{report.survived} 存活、{report.invalid} 無效",
                   f"Mutation testing: {report.killed} killed, {report.survived} survived, {report.invalid} invalid"))
    return report
