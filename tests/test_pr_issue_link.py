"""行為改動的 PR 必須連到 issue（`scripts/check_pr_issue_link.py`，`pr-issue-link.yml` 的 `issue-link` job）。
A behaviour-changing PR must link an issue (`scripts/check_pr_issue_link.py`, the `issue-link` job of
`pr-issue-link.yml`)."""

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("check_pr_issue_link",
                                               os.path.join(REPO_ROOT, "scripts", "check_pr_issue_link.py"))
assert _spec and _spec.loader
link = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = link
_spec.loader.exec_module(link)

WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "pr-issue-link.yml")
needs_github = pytest.mark.skipif(not os.path.isfile(WORKFLOW), reason=".github/ is not shipped in the sdist")

CODE = ["vibeharness/core/gate.py", "tests/test_gate.py"]
DOCS_ONLY = ["docs/design.md", "tests/test_gate.py"]


@pytest.mark.parametrize("title", ["fix: x", "feat: x", "perf: x", "fix(gate): x", "fix!: x", "feat(cli)!: x",
                                   "  fix: leading space"])
def test_fix_feat_and_perf_need_an_issue_by_prefix_alone(title):
    """fix／feat／perf（含 scope 與 `!`）只看前綴：連只改文件的也要 issue。
    fix / feat / perf (scope and `!` included) go by prefix alone: even a docs-only change needs an issue."""
    assert link.needs_issue(title, DOCS_ONLY)


def test_refactor_needs_an_issue_only_when_it_changes_vibeharness():
    """refactor 只有改到 `vibeharness/` 底下的檔案才需要 issue。
    A refactor needs an issue only when it changes files under `vibeharness/`."""
    assert link.needs_issue("refactor: x", CODE)
    assert link.needs_issue("refactor(core)!: x", CODE)
    assert not link.needs_issue("refactor: x", DOCS_ONLY)
    assert not link.needs_issue("refactor: x", ["scripts/vibeharness/x.py"])


@pytest.mark.parametrize("title", ["docs: x", "chore: x", "ci: x", "build(deps): x", "test: x", "build!: x",
                                   "fixup: x", "feature: x", "Fix: x", "refactoring: x"])
def test_other_prefixes_need_no_issue(title):
    """其他前綴（以及只是字首相同的詞）不需要 issue。
    Other prefixes (and words that merely start the same way) need no issue."""
    assert not link.needs_issue(title, CODE)


def test_closing_refs_reads_every_closing_keyword_once_in_order():
    """GitHub 的每個關閉關鍵字都算（不分大小寫，可帶冒號），重複的只算一次；單純的 `#N` 不算。
    Every GitHub closing keyword counts (any case, optional colon), repeats once; a bare `#N` does not."""
    body = "Closes #12\nfixes #7, Resolved: #12\nsee #99\nClose #3 and fixed #40"
    assert link.closing_refs(body) == [12, 7, 3, 40]
    assert link.closing_refs("") == []
    assert link.closing_refs(None) == []
    assert link.closing_refs("prefixes #5") == []


def test_mentions_matches_the_exact_number():
    """`#12` 不會被 `#123` 誤認。
    `#12` is not mistaken for `#123`."""
    assert link.mentions(["fix: x\n\nRefs #12"], 12)
    assert not link.mentions(["fix: x\n\nRefs #123"], 12)
    assert not link.mentions([], 12)


GOOD = dict(title="fix: x", author="chinchiang", body="Closes #12", files=CODE, messages=["fix: x\n\nRefs #12"],
            is_issue={12: True})


def _problems(**changes):
    return link.problems(**{**GOOD, **changes})


def test_a_behaviour_change_linking_an_issue_from_both_places_passes():
    """描述 `Closes #N` 加上 commit 訊息 `Refs #N`，而且 #N 是 issue：通過。
    `Closes #N` in the description, `Refs #N` in a commit message, and #N is an issue: passes."""
    assert _problems() == []


def test_a_behaviour_change_without_closes_fails_and_says_how_to_fix():
    """沒有 `Closes #N`：失敗，並說明要開 issue、寫哪三段。
    No `Closes #N`: fails, saying to open an issue and which three sections it has."""
    assert _problems(body="Fixes the gate.", is_issue={}) == [
        "The description has no `Closes #N`: open an issue (## Problem / ## Expected / ## Acceptance) and link it."]


def test_a_link_to_a_pull_request_or_a_missing_number_fails():
    """#N 是 PR（共用編號）或不存在：失敗。
    #N is a pull request (they share numbers) or does not exist: fails."""
    assert _problems(is_issue={12: False}) == ["#12 is a pull request, not an issue."]
    assert _problems(is_issue={12: None}) == ["#12 is not found, not an issue."]


def test_one_real_issue_among_the_links_is_enough():
    """描述連了好幾個編號時，只要其中一個是 issue 而且 commit 提到它就通過。
    When the description links several numbers, one issue that a commit mentions is enough."""
    assert _problems(body="Closes #11\nCloses #12", is_issue={11: False, 12: True}) == []


def test_commits_that_never_mention_the_issue_fail():
    """commit 訊息都沒提到 #N：失敗，因為 /code-review 從 commit 訊息找 spec。
    No commit message mentions #N: fails, because /code-review finds the spec in the commit messages."""
    assert _problems(messages=["fix: x", "test: y\n\nRefs #123"]) == [
        "No commit message mentions #12: add a `Refs #N` line so /code-review finds the spec."]


def test_exempt_prs_and_dependabot_pass_without_any_link():
    """豁免的前綴、沒改到 vibeharness/ 的 refactor 與 Dependabot：不需要連結就通過。
    Exempt prefixes, a refactor not touching vibeharness/, and Dependabot: pass without any link."""
    assert _problems(title="docs: x", body="", messages=[], is_issue={}) == []
    assert _problems(title="refactor: x", files=DOCS_ONLY, body="", messages=[], is_issue={}) == []
    assert _problems(author="dependabot[bot]", body="", messages=[], is_issue={}) == []


@needs_github
def test_the_workflow_runs_the_script_with_read_only_permissions():
    """workflow 名稱與 job 名稱是必要檢查用的，不能改；權限只有讀取；標題與描述不經 `${{ }}` 進 shell。
    The workflow and job names back the required check and must stay; permissions are read-only; the title and
    body never reach the shell through `${{ }}`."""
    with open(WORKFLOW, encoding="utf-8") as f:
        text = f.read()
    assert text.startswith("name: PR issue link\n")
    assert "\n  issue-link:\n" in text
    assert "permissions: {}" in text
    assert "write" not in text
    assert "run: python3 scripts/check_pr_issue_link.py" in text
    assert "github.event.pull_request.title" not in text and "github.event.pull_request.body" not in text
    for event in ("opened", "edited", "synchronize", "reopened"):
        assert event in text
