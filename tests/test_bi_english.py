"""`scripts/check_bi_english.py`：既有 `bi()` 的英文半被改掉或移除時，兩份 CHANGELOG 的 `[Unreleased]` 都要寫出舊的英文
（CODING_STANDARDS 第 6 條；#119）。
`scripts/check_bi_english.py`: when the English half of an existing `bi()` changes or goes away, the `[Unreleased]`
section of both CHANGELOGs must name the old English text (CODING_STANDARDS rule 6; #119)."""

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("check_bi_english", os.path.join(REPO_ROOT, "scripts", "check_bi_english.py"))
assert _spec and _spec.loader
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)

SOURCE = '''\
from vibeharness.core.i18n import bi
from vibeharness.core import i18n

a = bi("通過", "Passed")
b = bi(f"{n_err} 個錯誤或未執行", f"{n_err} errored / not run")
c = i18n.bi("中", "Multi" "line")
d = bi("中", english_from_somewhere)
e = print("not", "bi")
'''


def test_english_halves_are_literal_second_arguments_with_placeholders_for_fields():
    """英文半是第二個參數的字串常值；f-string 的欄位寫成 {}，非常值的參數略過，其他函式不算。
    An English half is the second argument's string literal; an f-string's fields become {}, a non-literal
    argument is skipped, and other functions do not count."""
    assert tool.english_halves(SOURCE) == {"Passed", "{} errored / not run", "Multiline"}


def test_a_renamed_field_inside_an_f_string_is_not_a_change():
    """f-string 裡改了變數名稱，輸出的英文不變，不算改動。
    Renaming a variable inside an f-string leaves the English output unchanged, so it is not a change."""
    renamed = SOURCE.replace("n_err", "n_not_run")
    assert tool.unnamed_changes(tool.english_halves(SOURCE), tool.english_halves(renamed), ["", ""]) == []


CHANGELOG_ZH = """\
# Changelog

## [Unreleased]

### 變更

- 白箱列：英文半由「errored / not run」改為「not run」。

## [0.15.0] - 2026-10-31

- 舊的：Passed
"""

CHANGELOG_EN = CHANGELOG_ZH.replace("白箱列：英文半由", "The white-box row's English half changes from").replace("改為", "to")


def test_a_changed_or_removed_english_half_must_be_named_in_both_unreleased_sections():
    """被改掉或移除的英文半，只有兩份 CHANGELOG 的 [Unreleased] 都寫出它時才通過；寫在舊版本的區段裡不算；新增的英文半不必寫。
    A changed or removed English half passes only when both CHANGELOGs' [Unreleased] name it; naming it under an
    older release does not count; an added English half needs no entry."""
    old = tool.english_halves(SOURCE)
    new = tool.english_halves(SOURCE.replace("errored / not run", "not run").replace('"Passed"', '"OK"')) | {"Brand new"}
    assert tool.unnamed_changes(old, new, [CHANGELOG_ZH, CHANGELOG_EN]) == ["Passed"]
    assert tool.unnamed_changes(old, new, [CHANGELOG_ZH, "# Changelog\n\n## [Unreleased]\n"]) == [
        "Passed", "{} errored / not run"]
    assert tool.unnamed_changes(old, old, ["", ""]) == []


def test_unreleased_is_the_section_up_to_the_next_release():
    assert tool.unreleased(CHANGELOG_ZH).strip().endswith("改為「not run」。")
    assert "Passed" not in tool.unreleased(CHANGELOG_ZH)


def test_an_english_half_whose_pieces_moved_into_a_helper_is_not_a_change():
    """英文半的每一段仍完整地是新程式碼的字串常值（例如搬進 helper 的參數）時，輸出的英文沒變，不算改動；真的改掉的文字照樣算。
    When every piece of an English half is still a whole string literal of the new code (say, moved into a helper's
    argument), the English output is unchanged and it is not a change; text that really changed still is."""
    old_src = 'x = bi(f"{n} 個新的 HIGH+，{k} 個已知", f"{n} HIGH+ new, {k} known from baseline")\n'
    new_src = ('def split(n, k, zh, en):\n    return bi(f"{n} {zh}，{k} 個已知", f"{n} {en}, {k} known from baseline")\n'
               'x = split(n, k, "個新的 HIGH+", "HIGH+ new")\n')
    old, new = tool.english_halves(old_src), tool.english_halves(new_src)
    assert tool.unnamed_changes(old, new, ["", ""], tool.string_pieces(new_src)) == []
    reworded = new_src.replace('"HIGH+ new"', '"new HIGH+"')
    assert tool.unnamed_changes(old, tool.english_halves(reworded), ["", ""], tool.string_pieces(reworded)) == [
        "{} HIGH+ new, {} known from baseline"]


WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "bi-english.yml")


@pytest.mark.skipif(not os.path.isfile(WORKFLOW), reason=".github/ is not shipped in the sdist")
def test_the_workflow_runs_the_script_against_the_pr_base_with_read_only_permissions():
    """workflow 只有讀取權限、取完整歷史，基準 commit 經 env 傳入而不在 shell 裡展開 `${{ }}`。
    The workflow has read-only permissions, fetches the full history, and passes the base commit through env
    rather than expanding `${{ }}` in the shell."""
    with open(WORKFLOW, encoding="utf-8") as f:
        text = f.read()
    assert "permissions: {}" in text and "write" not in text
    assert "fetch-depth: 0" in text
    assert "BASE_SHA: ${{ github.event.pull_request.base.sha }}" in text
    assert 'run: python3 scripts/check_bi_english.py --base "$BASE_SHA"' in text
