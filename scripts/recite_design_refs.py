"""檢查並重新對應設計文件裡的 `path:line` 引用。

`docs/design.md` 與 `docs/design.en.md` 以三種寫法引用程式碼行號：`path.py:N`（或 `N-M`）、只寫 `:N`
（指同一段文字裡最近一次出現的檔案），以及附錄 18.2 索引裡的「`名稱` N」。這支 script 解析三種寫法，
`--check` 檢查每個緊跟在名稱後面的引用仍落在那個名稱的定義上；不帶參數時，依 git diff 把每個引用從文件
引用的 commit 對應到目前的程式碼，再把文件引用的 commit 改成 HEAD。`tests/test_design_refs.py` 在 CI 跑同一套檢查。

用法：
    python scripts/recite_design_refs.py               # 重新對應到目前的程式碼，引用 HEAD 的 commit
    python scripts/recite_design_refs.py --tag v1.2.3  # 發布時：同上，但引用 release tag
    python scripts/recite_design_refs.py --check       # 只檢查，不改檔案

Check and remap the `path:line` references in the design documents.

`docs/design.md` and `docs/design.en.md` cite code lines in three forms: `path.py:N` (or `N-M`), a bare `:N`
(the file named last in the same text), and "`name` N" in the index of appendix 18.2. This script parses all
three; `--check` verifies that every reference right after a name still lands on that name's definition, and
without arguments it maps every reference from the commit the documents cite to the current code via git diff,
then makes the documents cite HEAD. `tests/test_design_refs.py` runs the same check in CI.

Usage:
    python scripts/recite_design_refs.py               # remap to the current code, cite HEAD's commit
    python scripts/recite_design_refs.py --tag v1.2.3  # at release: the same, but cite the release tag
    python scripts/recite_design_refs.py --check       # check only, change nothing
"""

from __future__ import annotations

import argparse
import ast
import difflib
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ("docs/design.md", "docs/design.en.md")

_SPAN_RE = re.compile(r"`([^`\n]+)`")
# 含目錄的路徑才算「換檔」；只寫檔名（`threat_rules.yaml`、`__init__.py`、`test_vh_NNN.py`）是行文，不是引用目標
# Only a path with a directory switches the current file; a bare file name (`threat_rules.yaml`, `__init__.py`,
# `test_vh_NNN.py`) is prose, not a reference target
_PATH = r"(?:[\w-][\w.-]*/)+[\w.-]+\.(?:py|ya?ml|toml|json|js|ts)"
_FULL_REF_RE = re.compile(rf"^({_PATH}):(\d+)(?:-(\d+))?$")
_BARE_REF_RE = re.compile(r"^:(\d+)(?:-(\d+))?$")
_PATH_RE = re.compile(rf"^{_PATH}$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\(\))?$")
# 名稱與引用之間只能隔著這些分隔符號，引用才算「指向這個名稱」
# A reference points at a name only when nothing but one of these separators stands between them
_ANCHOR_GAPS = {"（", " (", "(", "，", ", ", "、", " "}
# 這些引用指向的是「填入或使用這個值的程式碼」，不在名稱的定義或用到名稱的行上；只檢查行號範圍
# These references cite the code that fills or uses the value, not a line that defines or names it; only their
# line range is checked
_LOOSE_ANCHORS = {
    ("Settings.sources", "vibeharness/core/settings.py"),
    ("GatewaySettings", "vibeharness/core/settings.py"),
    ("DockerSandbox", "vibeharness/core/sandbox.py"),
}
_INDEX_HEADINGS = ("### 18.2",)
_CONSTANT_TABLE_HEADINGS = ("### 18.1",)
_INDEX_LINE_RE = re.compile(r"^- `([^`]+)`(?:：|: )(.*)$")
# 索引項目：一個或多個以 ／ 或 / 相連的名稱，可選的說明，接著行號
# Index entry: one or more names joined by ／ or /, an optional note, then the line number(s)
_INDEX_ENTRY_RE = re.compile(r"((?:`[^`]+`(?:／| / )?)+)([^`\d]*?)\s*(\d+)(?:-(\d+))?(?=、|, |$)")
# 文件引用的 revision（第 5 行與附錄 18 開頭各一次；commit 加上「發布時改為 release tag」，或 release tag）
# The revision the documents cite (once on line 5 and once at the start of appendix 18: a commit plus "the
# release tag will replace it", or a release tag)
_REV_PATTERNS = (
    (re.compile(r"以 (commit|tag) `([^`]+)` 的檔案為準(（發布時改為 release tag）)?"),
     "以 {kind} `{rev}` 的檔案為準{note}", "（發布時改為 release tag）"),
    (re.compile(r"行號對應 (commit|tag) `([^`]+)` 的程式碼(（發布時改為 release tag）)?"),
     "行號對應 {kind} `{rev}` 的程式碼{note}", "（發布時改為 release tag）"),
    (re.compile(r"to the files at (commit|tag) `([^`]+)`( \(the release tag will replace it\))?"),
     "to the files at {kind} `{rev}`{note}", " (the release tag will replace it)"),
    (re.compile(r"refer to the code at (commit|tag) `([^`]+)`( \(the release tag will replace it\))?"),
     "refer to the code at {kind} `{rev}`{note}", " (the release tag will replace it)"),
)


@dataclass(frozen=True)
class Ref:
    """文件裡的一個行號引用：所在行與欄位（數字部分）、指向的檔案與行號範圍，以及它指向的名稱（若有）。
    One line reference in a document: its line and columns (the number part), the file and line range it
    points at, and the names it points at, if any."""

    line: int
    col_start: int
    col_end: int
    path: str
    start: int
    end: int
    names: tuple[str, ...] = ()
    # 索引的單一名稱、無說明的項目：行號必須正好是定義那一行
    # An index entry with one name and no note: the line must be exactly the definition line
    exact: bool = False

    @property
    def span(self) -> str:
        """引用的數字部分，`N` 或 `N-M`。
        The number part of the reference, `N` or `N-M`."""
        return str(self.start) if self.start == self.end else f"{self.start}-{self.end}"


def _names_in(text: str) -> tuple[str, ...]:
    return tuple(s for s in _SPAN_RE.findall(text) if _IDENT_RE.match(s))


def parse_refs(text: str) -> list[Ref]:
    """解析文件裡的所有行號引用，依出現順序回傳。
    Parse every line reference in a document, in order of appearance."""
    refs: list[Ref] = []
    current: str | None = None
    in_index = in_constants = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.startswith("#"):
            in_index = line.startswith(_INDEX_HEADINGS)
            in_constants = line.startswith(_CONSTANT_TABLE_HEADINGS)
        index_line = _INDEX_LINE_RE.match(line) if in_index else None
        if index_line and _PATH_RE.match(index_line.group(1)):
            refs.extend(_parse_index_line(lineno, line, index_line))
            current = index_line.group(1)
            continue
        # 表格列（附錄 18.1）：引用指向第一欄的名稱
        # Table row (appendix 18.1): the references point at the names in the first cell
        row_names = _names_in(line.split("|")[1]) if in_constants and line.startswith("|") and line.count("|") > 2 else ()
        anchor: tuple[str, int] | None = None
        for match in _SPAN_RE.finditer(line):
            span = match.group(1)
            full = _FULL_REF_RE.match(span)
            bare = _BARE_REF_RE.match(span)
            if full:
                current = full.group(1)
                start, end, num_col = int(full.group(2)), int(full.group(3) or full.group(2)), match.start(1) + full.start(2)
            elif bare and current is not None:
                start, end, num_col = int(bare.group(1)), int(bare.group(2) or bare.group(1)), match.start(1) + 1
            else:
                if _PATH_RE.match(span):
                    current = span
                elif _IDENT_RE.match(span):
                    anchor = (span, match.end())
                continue
            names: tuple[str, ...] = row_names
            if not names and anchor is not None and line[anchor[1]:match.start()] in _ANCHOR_GAPS:
                names = (anchor[0],)
            refs.append(Ref(lineno, num_col, match.end() - 1, current, start, end, names))
    return refs


def _parse_index_line(lineno: int, line: str, index_line: re.Match[str]) -> list[Ref]:
    refs = []
    offset = index_line.start(2)
    for entry in _INDEX_ENTRY_RE.finditer(index_line.group(2)):
        names = _names_in(entry.group(1))
        start, end = int(entry.group(3)), int(entry.group(4) or entry.group(3))
        exact = len(names) == 1 and not entry.group(2).strip() and entry.group(4) is None
        refs.append(Ref(lineno, offset + entry.start(3), offset + entry.end(), index_line.group(1),
                        start, end, names, exact))
    return refs


@lru_cache(maxsize=64)
def definitions(source: str) -> dict[str, list[tuple[int, int]]]:
    """Python 原始碼裡每個名稱的定義範圍（def、class、指派；任何深度），名稱對應到 (起始行, 結束行) 清單。
    The definition spans of every name in Python source (def, class, assignment; any depth), mapping a name to
    a list of (first line, last line)."""
    spans: dict[str, list[tuple[int, int]]] = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            targets = [node.name]
        elif isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
        else:
            continue
        for name in targets:
            spans.setdefault(name, []).append((node.lineno, node.end_lineno or node.lineno))
    return spans


def _bare(name: str) -> str:
    return name.removesuffix("()").rsplit(".", 1)[-1]


def problem(ref: Ref, source: str | None) -> str | None:
    """引用有問題時回傳原因，沒問題回傳 None。指向名稱的引用必須與該名稱的定義重疊，或在範圍內用到這個名稱；
    索引項目必須正好是定義那一行。名稱在該檔案裡沒有定義（說明的是某個值或別的檔案的函式）時只檢查行號範圍。
    The reason a reference is wrong, or None. A reference that points at a name must overlap that name's
    definition or use the name within its range; an index entry must be exactly the definition line. When the
    name has no definition in that file (the reference describes a value or another file's function), only the
    line range is checked."""
    if source is None:
        return "file not found"
    lines = source.splitlines()
    if not 1 <= ref.start <= ref.end <= len(lines):
        return f"outside the file ({len(lines)} lines)"
    if not ref.names or not ref.path.endswith(".py"):
        return None
    defs = definitions(source)
    known = [n for n in ref.names if _bare(n) in defs and (n, ref.path) not in _LOOSE_ANCHORS]
    if not known:
        return None
    cited = "\n".join(lines[ref.start - 1:ref.end])
    for name in known:
        # 說明使用處的引用（`raise LLMGatewayError`、`self._inline(...)`）：名稱以完整單字出現在範圍內
        # A reference describing a use site (`raise LLMGatewayError`, `self._inline(...)`): the name appears as a
        # whole word in the range
        if not ref.exact and re.search(rf"\b{re.escape(_bare(name))}\b", cited):
            return None
        for first, last in defs[_bare(name)]:
            if ref.exact and first == ref.start:
                return None
            if not ref.exact and first <= ref.end and ref.start <= last:
                return None
    where = ", ".join(f"{_bare(n)} {_spans_text(defs[_bare(n)])}" for n in known)
    return f"does not land on {where}"


def _spans_text(spans: list[tuple[int, int]]) -> str:
    return "/".join(f"{a}-{b}" if a != b else str(a) for a, b in spans)


def _read_worktree(path: str) -> str | None:
    try:
        with open(os.path.join(REPO_ROOT, path), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def check(text: str, read: Callable[[str], str | None] = _read_worktree) -> list[str]:
    """檢查一份文件的所有引用，回傳「行號: 引用: 原因」清單。
    Check every reference of one document; return a list of "line: reference: reason"."""
    cache: dict[str, str | None] = {}
    issues = []
    for ref in parse_refs(text):
        if ref.path not in cache:
            cache[ref.path] = read(ref.path)
        reason = problem(ref, cache[ref.path])
        if reason:
            label = f"{'/'.join(ref.names)} " if ref.names else ""
            issues.append(f"{ref.line}: {label}{ref.path}:{ref.span}: {reason}")
    return issues


def cited_revision(text: str) -> set[str]:
    """文件引用的 revision（每一處都列出；一致時只有一個）。
    The revisions a document cites (every occurrence; one when consistent)."""
    return {m.group(2) for pattern, _, _ in _REV_PATTERNS for m in pattern.finditer(text)}


def with_revision(text: str, rev: str, tag: bool) -> str:
    """把文件引用的 revision 改成 `rev`：commit 附上「發布時改為 release tag」，tag 則不附。
    Make the document cite `rev`: a commit with "the release tag will replace it", a tag without."""
    for pattern, template, note in _REV_PATTERNS:
        text = pattern.sub(template.format(kind="tag" if tag else "commit", rev=rev, note="" if tag else note), text)
    return text


class LineMap:
    """依 diff 把舊版檔案的行號對應到新版；落在改動區塊裡的行對應不到（None）。
    Map line numbers of an old file version to the new one via diff; lines inside a changed block map to None."""

    def __init__(self, old: str, new: str):
        self.old, self.new = old, new
        self._defs: dict[str, dict[str, list[tuple[int, int]]]] = {}
        self._map: dict[int, int] = {}
        matcher = difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False)
        for tag, i1, i2, j1, _ in matcher.get_opcodes():
            if tag == "equal":
                for k in range(i2 - i1):
                    self._map[i1 + k + 1] = j1 + k + 1

    def line(self, n: int) -> int | None:
        """舊行號 n 在新版的行號。
        The new line number of old line n."""
        return self._map.get(n)

    def defs(self, which: str) -> dict[str, list[tuple[int, int]]]:
        """舊版（"old"）或新版（"new"）的定義範圍。
        Definition spans of the old ("old") or new ("new") version."""
        if which not in self._defs:
            self._defs[which] = definitions(self.old if which == "old" else self.new)
        return self._defs[which]


def remap(ref: Ref, lines: LineMap) -> tuple[int, int] | None:
    """把一個引用的行號從舊版對應到新版；對應不到時回傳 None（要人工核對）。
    起訖行各自依 diff 對應；落在改動區塊裡的那一端改以引用指向的名稱的定義為錨點。
    Map a reference's lines from the old version to the new one; None when it cannot (check by hand). The start
    and the end are each mapped via the diff; either one that falls in a changed block is anchored on the
    definition of a name the reference points at instead."""
    if ref.exact:
        mapped = lines.line(ref.start)
        new_defs = lines.defs("new").get(_bare(ref.names[0]), []) if ref.path.endswith(".py") else []
        if mapped is not None and (not ref.path.endswith(".py") or any(first == mapped for first, _ in new_defs)):
            return mapped, mapped
        first = _via_definition(ref, lines, ref.start)
        return (first, first) if first is not None else None
    start = lines.line(ref.start) or _via_definition(ref, lines, ref.start)
    end = lines.line(ref.end) or _via_definition(ref, lines, ref.end)
    if start is None or end is None or start > end:
        return None
    return start, end


def _via_definition(ref: Ref, lines: LineMap, n: int) -> int | None:
    # 舊版第 n 行所在的、引用指向的名稱的定義（必須唯一），在新版的對應行：
    # 定義的最後一行對應到新定義的最後一行，其餘保持與定義開頭的相對位移
    # The new line for old line n, via the definition (which must be unique) of a name the reference points at
    # that contains line n: the definition's last line maps to the new definition's last line, any other keeps
    # its offset from the start of the definition
    if not ref.path.endswith(".py"):
        return None
    for name in ref.names:
        old_spans = [s for s in lines.defs("old").get(_bare(name), []) if s[0] <= n <= s[1]]
        new_spans = lines.defs("new").get(_bare(name), [])
        if len(old_spans) != 1 or not new_spans:
            continue
        old_first, old_last = old_spans[0]
        anchor = lines.line(old_first)
        new_first, new_last = min(new_spans, key=lambda s: abs(s[0] - anchor) if anchor is not None else 0)
        if n == old_last:
            return new_last
        return min(new_first + (n - old_first), new_last)
    return None


def recite(text: str, old: Callable[[str], str | None], new: Callable[[str], str | None]) -> tuple[str, list[str]]:
    """把文件的每個引用從舊版程式碼對應到新版，回傳 (新文件, 對應不到的引用清單)。對應不到的引用保留原值。
    Map every reference of a document from the old code to the new; return (new document, the references that
    could not be mapped). Those keep their old value."""
    maps: dict[str, LineMap | None] = {}
    out = text.splitlines(keepends=True)
    unresolved = []
    # 由行尾往前改，同一行前面的欄位不會位移
    # Edit from the end of each line backwards, so earlier columns on the line do not shift
    for ref in sorted(parse_refs(text), key=lambda r: (r.line, r.col_start), reverse=True):
        if ref.path not in maps:
            before, after = old(ref.path), new(ref.path)
            maps[ref.path] = LineMap(before, after) if before is not None and after is not None else None
        line_map = maps[ref.path]
        mapped = remap(ref, line_map) if line_map is not None else None
        if mapped is None:
            label = f"{'/'.join(ref.names)} " if ref.names else ""
            unresolved.append(f"{ref.line}: {label}{ref.path}:{ref.span}")
            continue
        span = str(mapped[0]) if mapped[0] == mapped[1] else f"{mapped[0]}-{mapped[1]}"
        row = out[ref.line - 1]
        out[ref.line - 1] = row[:ref.col_start] + span + row[ref.col_end:]
    return "".join(out), sorted(unresolved, key=lambda s: int(s.split(":", 1)[0]))


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True,
                          encoding="utf-8").stdout


def _read_at(rev: str) -> Callable[[str], str | None]:
    def read(path: str) -> str | None:
        try:
            return _git("show", f"{rev}:{path}")
        except subprocess.CalledProcessError:
            return None
    return read


def _read_doc(path: str) -> str:
    with open(os.path.join(REPO_ROOT, path), encoding="utf-8") as f:
        return f.read()


def main(argv: list[str] | None = None) -> int:
    """命令列進入點；回傳 exit code（0 成功，1 有引用要人工核對或檢查失敗，2 用法或狀態錯誤）。
    Command-line entry point; returns the exit code (0 success, 1 references to check by hand or a failed
    check, 2 a usage or state error)."""
    parser = argparse.ArgumentParser(description="Check and remap the path:line references in docs/design*.md.")
    parser.add_argument("--check", action="store_true", help="check only, change nothing")
    parser.add_argument("--tag", help="cite this release tag instead of HEAD's commit")
    args = parser.parse_args(argv)

    texts = {doc: _read_doc(doc) for doc in DOCS}
    if args.check:
        issues = [f"{doc}:{issue}" for doc, text in texts.items() for issue in check(text)]
        print("\n".join(issues) or "All references land on the code they name.")
        return 1 if issues else 0

    revs = set().union(*(cited_revision(t) for t in texts.values()))
    if len(revs) != 1:
        print(f"The design documents must cite one revision; found {sorted(revs) or 'none'}.", file=sys.stderr)
        return 2
    old_rev = revs.pop()
    cited_files = sorted({ref.path for text in texts.values() for ref in parse_refs(text)})
    if _git("status", "--porcelain", "--", *cited_files).strip():
        print("Commit the code changes first: the documents will cite HEAD, so the cited files must match it.",
              file=sys.stderr)
        return 2
    try:
        _git("rev-parse", "--verify", f"{old_rev}^{{commit}}")
    except subprocess.CalledProcessError:
        print(f"Cannot resolve the cited revision {old_rev!r} (a shallow clone? run `git fetch --unshallow`).",
              file=sys.stderr)
        return 2
    head = _git("rev-parse", "--short", "HEAD").strip()
    unresolved = []
    for doc, text in texts.items():
        new_text, missed = recite(text, _read_at(old_rev), _read_worktree)
        new_text = with_revision(new_text, args.tag or head, tag=bool(args.tag))
        with open(os.path.join(REPO_ROOT, doc), "w", encoding="utf-8", newline="\n") as f:
            f.write(new_text)
        unresolved += [f"{doc}:{m}" for m in missed]
        issues = check(new_text)
        unresolved += [f"{doc}:{issue}" for issue in issues]
    print(f"Remapped {old_rev} -> {args.tag or head}.")
    if unresolved:
        print("Check these by hand (left unchanged or still off):", *unresolved, sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
