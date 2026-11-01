"""設計文件 `path:line` 引用的檢查（`scripts/recite_design_refs.py`）。
程式碼移動了行號而文件沒有跟著重新對應時，這裡會失敗；修法是先 commit 程式碼，再跑
`python scripts/recite_design_refs.py`。
Checks of the `path:line` references in the design documents (`scripts/recite_design_refs.py`). These fail when
code moved lines and the documents were not remapped; the fix is to commit the code, then run
`python scripts/recite_design_refs.py`."""

import importlib.util
import os
import sys
from collections import defaultdict

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("recite_design_refs",
                                               os.path.join(REPO_ROOT, "scripts", "recite_design_refs.py"))
assert _spec and _spec.loader
refs_tool = importlib.util.module_from_spec(_spec)
# dataclass 需要模組已登記在 sys.modules
# dataclass needs the module registered in sys.modules
sys.modules[_spec.name] = refs_tool
_spec.loader.exec_module(refs_tool)

FIX_HINT = "commit the code, then run `python scripts/recite_design_refs.py` and check what it lists"


def _doc(path):
    with open(os.path.join(REPO_ROOT, path), encoding="utf-8") as f:
        return f.read()


@pytest.mark.parametrize("doc", refs_tool.DOCS)
def test_every_design_reference_lands_on_the_code_it_names(doc):
    """每個引用都在檔案範圍內；緊跟在名稱後面的引用落在那個名稱的定義或使用處，索引項目正好是定義那一行。
    Every reference is inside its file; one right after a name lands on that name's definition or a use of it,
    and an index entry is exactly the definition line."""
    issues = refs_tool.check(_doc(doc))
    assert issues == [], f"{doc}: {FIX_HINT}\n" + "\n".join(issues)


def test_the_check_covers_most_references():
    """大部分引用都有名稱可以核對（防止解析器改壞後變成什麼都不檢查）。
    Most references have a name to verify against (so a broken parser cannot quietly check nothing)."""
    refs = refs_tool.parse_refs(_doc("docs/design.md"))
    assert len(refs) > 1000
    assert sum(1 for r in refs if r.names) > 0.7 * len(refs)
    assert sum(1 for r in refs if r.exact) > 350


def test_zh_and_en_design_documents_cite_the_same_lines_line_for_line():
    """中英設計文件逐行對應，每一行引用的檔案與行號也必須相同（只重新對應其中一份會失敗）。
    The zh / en design documents correspond line for line, and so must the files and lines each line cites
    (remapping only one of them fails)."""
    def by_line(doc):
        cited = defaultdict(list)
        for ref in refs_tool.parse_refs(_doc(doc)):
            cited[ref.line].append((ref.path, ref.start, ref.end))
        return {line: sorted(refs) for line, refs in cited.items()}
    assert by_line("docs/design.md") == by_line("docs/design.en.md")


def test_both_design_documents_cite_one_revision():
    """兩份文件的第 5 行與附錄 18 引用同一個 commit 或 tag。
    Line 5 and appendix 18 of both documents cite the same commit or tag."""
    revisions = set().union(*(refs_tool.cited_revision(_doc(d)) for d in refs_tool.DOCS))
    assert len(revisions) == 1, revisions
    for doc in refs_tool.DOCS:
        assert len(refs_tool.cited_revision(_doc(doc))) == 1


# --- 解析與重新對應 ------------------------------------------------------------------------------------------
# --- Parsing and remapping -----------------------------------------------------------------------------------

OLD_CODE = """\
LIMIT = 3


def alpha():
    return LIMIT


def beta():
    return alpha()
"""

# 檔頭多兩行，alpha 的本體多一行
# Two more lines at the top, one more line in alpha's body
NEW_CODE = """\
import os

LIMIT = 3


def alpha():
    value = LIMIT
    return value


def beta():
    return alpha()
"""

DOC = """\
# Design

`alpha`（`pkg/mod.py:4-5`）returns `LIMIT`，`:1`；`beta`，`:8-9` calls it (`:9`).
A bare file name such as `notes.py` does not switch files: `beta` (`:8-9`).

### 18.2 Index

- `pkg/mod.py`：`alpha` 4、`beta` 8、`LIMIT`／`alpha`（both）1-5
"""


def _reader(files):
    return lambda path: files.get(path)


def test_bare_references_resolve_to_the_last_full_path_and_names_anchor_adjacent_references():
    """`:N` 指向最近一次出現的完整路徑；只有緊跟在名稱後面的引用才指向那個名稱；索引的單一名稱項目要求精確。
    `:N` resolves to the full path named last; only a reference right after a name points at it; an index entry
    with one name is exact."""
    refs = refs_tool.parse_refs(DOC)
    assert [(r.path, r.span, r.names, r.exact) for r in refs] == [
        ("pkg/mod.py", "4-5", ("alpha",), False),
        ("pkg/mod.py", "1", ("LIMIT",), False),
        ("pkg/mod.py", "8-9", ("beta",), False),
        ("pkg/mod.py", "9", (), False),
        ("pkg/mod.py", "8-9", ("beta",), False),
        ("pkg/mod.py", "4", ("alpha",), True),
        ("pkg/mod.py", "8", ("beta",), True),
        ("pkg/mod.py", "1-5", ("LIMIT", "alpha"), False),
    ]


def test_check_reports_references_left_behind_by_moved_code():
    """程式碼移動後沒有重新對應的引用會被列出；對應前的程式碼則全部通過。
    References not remapped after the code moved are listed; against the code they were written for, all pass."""
    assert refs_tool.check(DOC, _reader({"pkg/mod.py": OLD_CODE})) == []
    issues = refs_tool.check(DOC, _reader({"pkg/mod.py": NEW_CODE}))
    assert issues[0] == "3: alpha pkg/mod.py:4-5: does not land on alpha 6-8"
    assert any(issue.startswith("8: alpha pkg/mod.py:4:") for issue in issues)
    assert refs_tool.check(DOC, _reader({})) == [f"{line}: {label}pkg/mod.py:{span}: file not found" for line, label, span in [
        (3, "alpha ", "4-5"), (3, "LIMIT ", "1"), (3, "beta ", "8-9"), (3, "", "9"), (4, "beta ", "8-9"),
        (8, "alpha ", "4"), (8, "beta ", "8"), (8, "LIMIT/alpha ", "1-5")]]


def test_recite_maps_every_reference_form_to_the_new_code():
    """重新對應後三種寫法都指向新版的程式碼，而且通過檢查；改動區塊裡的行以名稱的定義為錨點。
    After remapping all three forms point at the new code and pass the check; a line inside a changed block is
    anchored on the name's definition."""
    new_doc, unresolved = refs_tool.recite(DOC, _reader({"pkg/mod.py": OLD_CODE}),
                                           _reader({"pkg/mod.py": NEW_CODE}))
    assert unresolved == []
    assert "`alpha`（`pkg/mod.py:6-8`）returns `LIMIT`，`:3`；`beta`，`:11-12` calls it (`:12`)." in new_doc
    assert "- `pkg/mod.py`：`alpha` 6、`beta` 11、`LIMIT`／`alpha`（both）3-8" in new_doc
    assert refs_tool.check(new_doc, _reader({"pkg/mod.py": NEW_CODE})) == []


def test_recite_leaves_unmappable_references_alone_and_lists_them():
    """對應不到的引用（行被改掉、沒有可用的名稱）保留原值並列出，交給人核對。
    A reference that cannot be mapped (its line changed and no usable name) keeps its value and is listed for
    a human to check."""
    doc = "`pkg/mod.py:5` is the return.\n"
    new_doc, unresolved = refs_tool.recite(doc, _reader({"pkg/mod.py": OLD_CODE}), _reader({"pkg/mod.py": NEW_CODE}))
    assert new_doc == doc
    assert unresolved == ["1: pkg/mod.py:5"]


def test_with_revision_switches_between_a_commit_and_the_release_tag():
    """引用 commit 時附上「發布時改為 release tag」，引用 tag 時拿掉；中英兩種句型都改。
    Citing a commit adds "the release tag will replace it", citing a tag drops it; both the zh and en wordings
    are rewritten."""
    zh = "文中的 `path:line` 引用以 tag `v0.15.0` 的檔案為準。\n行號對應 tag `v0.15.0` 的程式碼；核對\n"
    en = ("Every `path:line` reference is to the files at tag `v0.15.0`.\n"
          "Line numbers refer to the code at tag `v0.15.0`; verify\n")
    zh_commit = refs_tool.with_revision(zh, "abc1234", tag=False)
    assert zh_commit == ("文中的 `path:line` 引用以 commit `abc1234` 的檔案為準（發布時改為 release tag）。\n"
                         "行號對應 commit `abc1234` 的程式碼（發布時改為 release tag）；核對\n")
    en_commit = refs_tool.with_revision(en, "abc1234", tag=False)
    assert en_commit == ("Every `path:line` reference is to the files at commit `abc1234` (the release tag will replace it).\n"
                         "Line numbers refer to the code at commit `abc1234` (the release tag will replace it); verify\n")
    assert refs_tool.with_revision(zh_commit, "v0.16.0", tag=True) == zh.replace("v0.15.0", "v0.16.0")
    assert refs_tool.with_revision(en_commit, "v0.16.0", tag=True) == en.replace("v0.15.0", "v0.16.0")
    assert refs_tool.cited_revision(zh_commit + en_commit) == {"abc1234"}
