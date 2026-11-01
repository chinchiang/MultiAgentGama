"""檢查行為改動的 PR 連到一個 issue（`.github/workflows/pr-issue-link.yml` 的 `issue-link` job）。

需要 issue 的 PR：標題前綴是 `fix`、`feat`、`perf`（可帶 scope 與 `!`），或改到 `vibeharness/` 底下檔案的
`refactor`。這些 PR 的描述要以 GitHub 的關閉關鍵字（`Closes #N`）連到一個存在的 issue（不是 PR），而且 PR 至少
有一個 commit 訊息提到 `#N`（`Refs #N`），`/code-review` 從 commit 訊息找 spec。Dependabot 的 PR 不檢查。

用法（CI 設定 `PR_NUMBER`、`GH_REPO`、`GH_TOKEN`）：
    python scripts/check_pr_issue_link.py

Check that a behaviour-changing PR links an issue (the `issue-link` job of `.github/workflows/pr-issue-link.yml`).

A PR needs an issue when its title prefix is `fix`, `feat` or `perf` (scope and `!` allowed), or it is a `refactor`
that changes files under `vibeharness/`. Its description must link an existing issue (not a PR) with a GitHub
closing keyword (`Closes #N`), and at least one of its commit messages must mention `#N` (`Refs #N`), because
`/code-review` finds the spec in the commit messages. Dependabot PRs are not checked.

Usage (CI sets `PR_NUMBER`, `GH_REPO` and `GH_TOKEN`):
    python scripts/check_pr_issue_link.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable

_BEHAVIOUR_RE = re.compile(r"^(?:fix|feat|perf)(?:\([^)]*\))?!?:")
_REFACTOR_RE = re.compile(r"^refactor(?:\([^)]*\))?!?:")
# GitHub 的關閉關鍵字（close／closes／closed／fix／fixes／fixed／resolve／resolves／resolved）
# GitHub's closing keywords (close / closes / closed / fix / fixes / fixed / resolve / resolves / resolved)
_CLOSING_RE = re.compile(r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?):?\s+#(\d+)\b", re.IGNORECASE)
_DEPENDABOT = "dependabot[bot]"
ISSUE_FIELDS = "## Problem / ## Expected / ## Acceptance"


def needs_issue(title: str, files: Iterable[str]) -> bool:
    """這個 PR 是否需要連到 issue：fix／feat／perf 只看前綴，refactor 看有沒有改到 `vibeharness/`。
    Whether this PR must link an issue: fix / feat / perf by prefix alone, refactor by whether it changes
    `vibeharness/`."""
    title = title.strip()
    if _BEHAVIOUR_RE.match(title):
        return True
    return bool(_REFACTOR_RE.match(title)) and any(path.startswith("vibeharness/") for path in files)


def closing_refs(body: str) -> list[int]:
    """描述裡以關閉關鍵字連到的編號，依出現順序、不重複。
    The numbers the description links with a closing keyword, in order of appearance, without repeats."""
    return list(dict.fromkeys(int(n) for n in _CLOSING_RE.findall(body or "")))


def mentions(messages: Iterable[str], number: int) -> bool:
    """commit 訊息裡有沒有任何一則提到 `#number`。
    Whether any of the commit messages mentions `#number`."""
    pattern = re.compile(rf"#{number}\b")
    return any(pattern.search(message) for message in messages)


def problems(title: str, author: str, body: str, files: Iterable[str], messages: Iterable[str],
             is_issue: dict[int, bool | None]) -> list[str]:
    """PR 不符合規則的原因；空清單表示通過。`is_issue[n]` 為 True（是 issue）、False（是 PR）或 None（不存在）。
    Why the PR breaks the rule; an empty list means it passes. `is_issue[n]` is True (an issue), False (a PR) or
    None (does not exist)."""
    if author == _DEPENDABOT or not needs_issue(title, files):
        return []
    refs = closing_refs(body)
    if not refs:
        return [f"The description has no `Closes #N`: open an issue ({ISSUE_FIELDS}) and link it."]
    issues = [n for n in refs if is_issue.get(n)]
    if not issues:
        return [f"#{n} is {'a pull request' if is_issue.get(n) is False else 'not found'}, not an issue."
                for n in refs]
    messages = list(messages)
    if not any(mentions(messages, n) for n in issues):
        listed = ", ".join(f"#{n}" for n in issues)
        return [f"No commit message mentions {listed}: add a `Refs #N` line so /code-review finds the spec."]
    return []


def _gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True, encoding="utf-8").stdout


def _is_issue(number: int) -> bool | None:
    try:
        data = json.loads(_gh("api", f"repos/{{owner}}/{{repo}}/issues/{number}"))
    except subprocess.CalledProcessError:
        return None
    return "pull_request" not in data


def main() -> int:
    """CI 進入點：讀取 PR、印出結果；回傳 0（通過）或 1（不通過）。
    CI entry point: read the PR and print the outcome; return 0 (pass) or 1 (fail)."""
    number = os.environ["PR_NUMBER"]
    pr = json.loads(_gh("pr", "view", number, "--json", "title,body,author,files,commits"))
    files = [f["path"] for f in pr["files"]]
    messages = [f"{c['messageHeadline']}\n{c['messageBody']}" for c in pr["commits"]]
    author = pr["author"]["login"]
    # GitHub CLI 把 app 作者顯示成 app/dependabot ／ The GitHub CLI shows app authors as app/dependabot
    if author == "app/dependabot":
        author = _DEPENDABOT
    is_issue = {n: _is_issue(n) for n in closing_refs(pr["body"])}
    issues = problems(pr["title"], author, pr["body"], files, messages, is_issue)
    if issues:
        print("\n".join(issues))
        return 1
    print("OK: linked issue found." if needs_issue(pr["title"], files) else "OK: no issue needed for this PR.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
