"""既有 `bi()` 的英文半被改掉或移除時，兩份 CHANGELOG 的 `[Unreleased]` 都要寫出舊的英文（CODING_STANDARDS 第 6 條）。

CI 與指紋比對靠英文半，所以它原則上不改；維護者核准的改動要在 CHANGELOG 寫出舊的與新的英文。這支 script 比對
基準 revision 與工作目錄裡 `vibeharness/` 與 `main.py` 的每個 `bi()` 呼叫：第二個參數是字串常值或 f-string 時取它
當英文半（f-string 的欄位寫成 `{}`，所以只改變數名稱不算改動），基準有、現在沒有的英文半，`CHANGELOG.md` 與
`CHANGELOG.en.md` 的 `[Unreleased]` 都要寫出它的文字（`{}` 之間的每一段）。每一段（去掉兩端的空白與標點）仍完整地是
工作目錄裡某個字串常值的，只是搬到別處組字（例如移進 helper 的參數），照樣通過；這個靜態檢查的極限是某一段剛好等於
無關的字串常值。`.github/workflows/bi-english.yml`
在每個 PR 以 PR 的基準 commit 執行。

用法：
    python scripts/check_bi_english.py                  # 基準是 HEAD 與 origin/master 的 merge-base
    python scripts/check_bi_english.py --base <rev>

When the English half of an existing `bi()` changes or goes away, the `[Unreleased]` section of both CHANGELOGs must
name the old English text (CODING_STANDARDS rule 6).

CI and fingerprint matching rely on the English half, so it does not change by default; a change the maintainer
approves names the old and the new English text in the CHANGELOG. This script compares every `bi()` call in
`vibeharness/` and `main.py` between a base revision and the working tree: a second argument that is a string literal
or an f-string is the English half (an f-string's fields become `{}`, so renaming a variable is not a change). Each
English half the base has and the working tree lacks must be named, every piece between its `{}`, in the
`[Unreleased]` section of both `CHANGELOG.md` and `CHANGELOG.en.md`. One whose every piece (without edge whitespace
and punctuation) is still a whole string literal somewhere in the working tree only moved, say into a helper's
argument, and passes; the limit of this static check is a piece that happens to equal an unrelated literal. `.github/workflows/bi-english.yml` runs it on
every PR against the PR's base commit.

Usage:
    python scripts/check_bi_english.py                  # the base is the merge-base of HEAD and origin/master
    python scripts/check_bi_english.py --base <rev>
"""

from __future__ import annotations

import argparse
import ast
import os
import subprocess
import sys
from collections.abc import Iterable

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE_ROOTS = ("vibeharness", "main.py")
CHANGELOGS = ("CHANGELOG.md", "CHANGELOG.en.md")
_UNRELEASED = "## [Unreleased]"


def _literal(node: ast.expr) -> str | None:
    # 字串常值，或欄位寫成 {} 的 f-string；其他運算式為 None
    # A string literal, or an f-string with its fields written as {}; None for any other expression
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(str(v.value) if isinstance(v, ast.Constant) else "{}" for v in node.values)
    return None


def english_halves(source: str) -> set[str]:
    """一份 Python 原始碼裡每個 `bi(中文, English)` 呼叫的英文半（`bi` 或 `模組.bi`）。
    The English half of every `bi(zh, en)` call in Python source (`bi` or `module.bi`)."""
    halves = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
        english = _literal(node.args[1]) if name == "bi" else None
        if english is not None:
            halves.add(english)
    return halves


_EDGE = " \t\n,.;:()（）、，。／/"


def _pieces(english: str) -> list[str]:
    # `{}` 之間的每一段，去掉兩端的空白與標點 ／ Every piece between the `{}`, without edge whitespace and punctuation
    return [piece for piece in (p.strip(_EDGE) for p in english.split("{}")) if piece]


def string_pieces(source: str) -> set[str]:
    """一份原始碼裡每個字串常值（含 f-string 的固定部分），去掉兩端的空白與標點。
    Every string literal in source (including an f-string's fixed parts), without edge whitespace and punctuation."""
    return {node.value.strip(_EDGE) for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)} - {""}


def unreleased(changelog: str) -> str:
    """CHANGELOG 的 `[Unreleased]` 區段：從標題到下一個版本標題。
    A CHANGELOG's `[Unreleased]` section: from its heading to the next release heading."""
    start = changelog.find(_UNRELEASED)
    if start < 0:
        return ""
    end = changelog.find("\n## [", start + len(_UNRELEASED))
    return changelog[start:end if end >= 0 else len(changelog)]


def unnamed_changes(old: Iterable[str], new: Iterable[str], changelogs: Iterable[str],
                    new_strings: Iterable[str] = ()) -> list[str]:
    """基準有、現在沒有，而且沒有在每份 CHANGELOG 的 `[Unreleased]` 寫出的英文半，排序後回傳。每一段仍完整地是新程式碼
    某個字串常值（`new_strings`）的英文半，視為只是搬到別處組字（例如移進 helper 的參數），不算改動。
    The English halves the base has and the new code lacks that some CHANGELOG's `[Unreleased]` does not name,
    sorted. One whose every piece is still a whole string literal of the new code (`new_strings`) only moved to be
    assembled elsewhere (say, into a helper's argument) and is not a change."""
    sections = [unreleased(c) for c in changelogs]
    available = set(new_strings)
    gone = {e for e in set(old) - set(new) if not all(piece in available for piece in _pieces(e))}
    return sorted(e for e in gone if not all(piece in s for s in sections for piece in _pieces(e)))


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True,
                          encoding="utf-8").stdout


def _halves_at(rev: str) -> set[str]:
    halves: set[str] = set()
    for path in _git("ls-tree", "-r", "--name-only", rev, "--", *SOURCE_ROOTS).splitlines():
        if path.endswith(".py"):
            halves |= english_halves(_git("show", f"{rev}:{path}"))
    return halves


def _worktree() -> tuple[set[str], set[str]]:
    # 工作目錄的英文半與字串常值 ／ The working tree's English halves and string literals
    halves: set[str] = set()
    strings: set[str] = set()
    for path in _git("ls-files", "--", *SOURCE_ROOTS).splitlines():
        full = os.path.join(REPO_ROOT, path)
        if path.endswith(".py") and os.path.exists(full):
            with open(full, encoding="utf-8") as f:
                source = f.read()
            halves |= english_halves(source)
            strings |= string_pieces(source)
    return halves, strings


def main(argv: list[str] | None = None) -> int:
    """命令列進入點；回傳 exit code（0 通過，1 有沒寫進 CHANGELOG 的英文半，2 git 錯誤）。
    Command-line entry point; returns the exit code (0 pass, 1 an English half the CHANGELOGs do not name, 2 a git
    error)."""
    parser = argparse.ArgumentParser(description="Check that changed bi() English halves are named in the CHANGELOGs.")
    parser.add_argument("--base", help="the revision to compare with (default: merge-base of HEAD and origin/master)")
    args = parser.parse_args(argv)
    try:
        base = args.base or _git("merge-base", "HEAD", "origin/master").strip()
        old = _halves_at(base)
    except subprocess.CalledProcessError as e:
        print(f"git failed: {' '.join(e.cmd)}\n{e.stderr}", file=sys.stderr)
        return 2
    texts = []
    for name in CHANGELOGS:
        with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as f:
            texts.append(f.read())
    new, new_strings = _worktree()
    missing = unnamed_changes(old, new, texts, new_strings)
    if not missing:
        print(f"No English half of an existing bi() changed without a CHANGELOG entry (base {base[:12]}).")
        return 0
    print(f"These English halves of bi() changed or went away since {base[:12]}. Rule 6 of CODING_STANDARDS: name "
          "the old (and the new) English text in [Unreleased] of both CHANGELOG.md and CHANGELOG.en.md, or keep it.")
    for english in missing:
        print(f"  - {english!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
