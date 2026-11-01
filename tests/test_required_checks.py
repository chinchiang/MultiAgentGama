"""master 必要檢查的三方比對（`scripts/check_required_checks.py`）：workflow 產生的名稱、`CONTRIBUTING.md` 的數量與
點名、ruleset 的實際設定。ruleset 由 `.github/workflows/required-checks.yml` 在 push 到 master 與每週讀取；這裡只比對
前兩者，並以假的 ruleset 驗證每一種不一致。
The three-way comparison of master's required checks (`scripts/check_required_checks.py`): the names the workflows
produce, the count and names in `CONTRIBUTING.md`, and the ruleset's actual setting. The ruleset is read by
`.github/workflows/required-checks.yml` on pushes to master and weekly; here only the first two are compared, and every
kind of mismatch is checked against a fake ruleset."""

import importlib.util
import os
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("check_required_checks",
                                               os.path.join(REPO_ROOT, "scripts", "check_required_checks.py"))
assert _spec and _spec.loader
rc = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rc
_spec.loader.exec_module(rc)

WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")
needs_github = pytest.mark.skipif(not os.path.isdir(WORKFLOWS), reason=".github/ is not shipped in the sdist")

TESTS_YML = """
jobs:
  lint: {runs-on: x}
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        python-version: ["3.11", "3.12"]
        include:
          - {os: macos-latest, python-version: "3.12"}
"""
CODEQL_YML = """
jobs:
  analyze:
    name: Analyze (${{ matrix.language }})
    strategy:
      matrix:
        include:
          - {language: python, build-mode: none}
          - {language: actions, build-mode: none}
"""


def test_job_checks_expands_the_matrix_like_github_names_the_checks():
    """沒有 name 的 job 是 `id (值, …)`，有 name 的代入 matrix；include 不相符時新增一格。
    A job without a name is `id (value, …)`, one with a name gets the matrix substituted; a non-matching include
    adds a cell."""
    assert rc.job_checks(yaml.safe_load(TESTS_YML)) == [
        "lint", "test (ubuntu-latest, 3.11)", "test (ubuntu-latest, 3.12)", "test (windows-latest, 3.11)",
        "test (windows-latest, 3.12)", "test (macos-latest, 3.12)"]
    assert rc.job_checks(yaml.safe_load(CODEQL_YML)) == ["Analyze (python)", "Analyze (actions)"]


def test_an_include_matching_a_cell_adds_no_new_cell_and_exclude_removes_one():
    """與既有格子相同的 include 不會多一格；exclude 會剔除那一格。
    An include equal to an existing cell adds none; exclude removes that cell."""
    doc = {"jobs": {"t": {"strategy": {"matrix": {"os": ["a", "b"], "include": [{"os": "a"}],
                                                   "exclude": [{"os": "b"}]}}}}}
    assert rc.job_checks(doc) == ["t (a)"]


CONTRIBUTING = ("必要檢查共 3 項：`lint`、`audit`，以及 `issue-link`（不要改名）。\n"
                "There are 3 required checks: `lint`, `audit` and `issue-link` from `x.yml`.\n")
REQUIRED = ["lint", "audit", "issue-link"]


def test_documented_reads_both_counts_and_the_named_jobs():
    """中英兩句的數量都讀到；反引號裡的檔名不算 job。
    Both counts are read; a file name in backticks is not a job."""
    assert rc.documented(CONTRIBUTING) == ([3, 3], {"lint", "audit", "issue-link"})


def test_consistent_docs_workflows_and_ruleset_have_no_problems():
    """三方一致：沒有問題。
    All three agree: no problems."""
    assert rc.problems(REQUIRED, [3, 3], {"lint", "audit"}, ["issue-link", "lint", "audit"]) == []


def test_each_kind_of_drift_is_reported():
    """ruleset 少一項（忘了存檔）、多一項（改名後等不到）、文件數量不符、點名了不存在的 job：都會報告。
    A ruleset missing a check (an unsaved edit), one with an extra (renamed, would wait forever), a wrong count in
    the docs, and a named job that does not exist: each is reported."""
    assert rc.problems(REQUIRED, [3, 3], set(), ["lint", "audit"]) == ["The ruleset does not require `issue-link`"]
    assert rc.problems(REQUIRED, [3, 3], set(), REQUIRED + ["old-name"]) == [
        "The ruleset requires `old-name`, which no required workflow job reports (it would wait forever)"]
    assert rc.problems(REQUIRED, [3, 2], set(), None) == ["CONTRIBUTING.md says 2 required checks, the workflows produce 3"]
    assert rc.problems(REQUIRED, [3, 3], {"gone"}, None) == [
        "CONTRIBUTING.md names `gone`, which no required workflow job reports"]
    assert rc.problems(REQUIRED, [3], set(), None) == [
        "CONTRIBUTING.md should state the count once in zh and once in en; found [3]"]


@needs_github
def test_contributing_and_the_workflows_agree_on_the_required_checks():
    """不用網路的那一半：CONTRIBUTING 的數量與點名和 workflow 產生的必要檢查一致（目前 15 項）。
    The offline half: CONTRIBUTING's count and named jobs agree with the required checks the workflows produce
    (15 today)."""
    required = rc.required_from_workflows(WORKFLOWS)
    with open(os.path.join(REPO_ROOT, "CONTRIBUTING.md"), encoding="utf-8") as f:
        counts, named = rc.documented(f.read())
    assert rc.problems(required, counts, named, None) == []
    assert len(required) == 15
    assert {"lint", "audit", "package", "issue-link", "Analyze (python)", "Analyze (actions)",
            "test (macos-latest, 3.12)", "test (windows-latest, 3.14)"} <= set(required)


@needs_github
def test_the_drift_workflow_never_runs_on_pull_requests_and_only_reads():
    """比對 ruleset 的 workflow 只在 push 到 master、排程與手動時執行（不在 PR 上，免得新增必要檢查的 PR 卡住自己），
    而且只有讀取權限。
    The ruleset-drift workflow runs only on pushes to master, on a schedule and by hand (never on PRs, so a PR adding
    a required check cannot block itself), with read-only permissions."""
    with open(os.path.join(WORKFLOWS, "required-checks.yml"), encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    triggers = doc.get("on", doc.get(True))
    assert set(triggers) == {"push", "schedule", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["master"]
    assert doc["permissions"] == {"contents": "read"}
    assert "required-checks.yml" not in rc.REQUIRED_WORKFLOWS
