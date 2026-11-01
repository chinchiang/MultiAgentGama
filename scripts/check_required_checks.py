"""比對 master 的必要檢查：workflow 產生的檢查名稱、`CONTRIBUTING.md` 寫的數量與名稱、repo ruleset 的實際設定。

必要檢查的名稱由 `REQUIRED_WORKFLOWS` 裡每個 job 展開 matrix 得到（例如 `test (ubuntu-latest, 3.11)`、
`Analyze (python)`）。`CONTRIBUTING.md` 中英兩句「必要檢查共 N 項」／「There are N required checks」的 N 必須等於
名稱的數量，句子裡用反引號點名的 job 必須存在。ruleset 以 `gh api` 讀取（`.github/workflows/required-checks.yml`
在 push 到 master 與每週執行），必須剛好是這些名稱；`--offline` 只比對前兩者（測試套件就是這樣用）。

Compare master's required checks: the check names the workflows produce, the count and names `CONTRIBUTING.md` gives,
and the repository ruleset's actual setting.

The required names come from expanding the matrix of every job in `REQUIRED_WORKFLOWS` (e.g.
`test (ubuntu-latest, 3.11)`, `Analyze (python)`). The N in the zh and en sentences of `CONTRIBUTING.md`
("必要檢查共 N 項" / "There are N required checks") must equal the number of names, and the jobs those sentences
name in backticks must exist. The ruleset is read with `gh api` (`.github/workflows/required-checks.yml` runs it on
pushes to master and weekly) and must be exactly those names; `--offline` compares only the first two (as the test
suite does).
"""

from __future__ import annotations

import itertools
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping
from typing import Any

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 這些 workflow 的每個 job 都是 master 的必要檢查 ／ Every job of these workflows is a required check on master
REQUIRED_WORKFLOWS = ("tests.yml", "codeql.yml", "pr-issue-link.yml")
_COUNT_RES = (re.compile(r"必要檢查共 (\d+) 項：([^。]*)"), re.compile(r"There are (\d+) required checks: ([^.]*)"))
_JOB_NAME_RE = re.compile(r"^[A-Za-z][\w-]*$")
_MATRIX_EXPR_RE = re.compile(r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}")
RULES_QUERY = ".[] | select(.type == \"required_status_checks\") | .parameters.required_status_checks[].context"


def _combinations(matrix: Mapping[str, Any]) -> list[dict[str, Any]]:
    """展開 GitHub Actions 的 matrix：各軸的乘積，再加上 include 裡不與任何組合相符的項目（exclude 先剔除）。
    Expand a GitHub Actions matrix: the product of its axes, plus the include entries that match no combination
    (exclude is removed first)."""
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    combos = [dict(zip(axes, values, strict=True)) for values in itertools.product(*axes.values())] if axes else []
    for ex in matrix.get("exclude", []) or []:
        combos = [c for c in combos if any(c.get(k) != v for k, v in ex.items())]
    for inc in matrix.get("include", []) or []:
        matched = [c for c in combos if all(c.get(k) == v for k, v in inc.items() if k in axes)]
        if axes and matched and all(k in axes for k in inc):
            continue
        if axes and matched:
            for c in matched:
                c.update(inc)
        else:
            combos.append(dict(inc))
    return combos


def _substitute(template: str, combo: Mapping[str, Any]) -> str:
    return _MATRIX_EXPR_RE.sub(lambda m: str(combo.get(m.group(1), "")), template)


def job_checks(workflow: Mapping[str, Any]) -> list[str]:
    """一個 workflow 的每個 job 回報的檢查名稱，依 GitHub 的規則：有 `name` 就代入 matrix 值，沒有就是
    `job-id (值, 值, …)`。
    The check names each job of a workflow reports, by GitHub's rule: a `name` gets the matrix values substituted,
    otherwise it is `job-id (value, value, …)`."""
    names = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        matrix = ((job.get("strategy") or {}).get("matrix")) or {}
        combos = _combinations(matrix) if matrix else [{}]
        for combo in combos:
            if "name" in job:
                names.append(_substitute(job["name"], combo))
            elif combo:
                names.append(f"{job_id} ({', '.join(str(v) for v in combo.values())})")
            else:
                names.append(job_id)
    return names


def required_from_workflows(workflows_dir: str) -> list[str]:
    """`REQUIRED_WORKFLOWS` 產生的所有必要檢查名稱。
    Every required check name `REQUIRED_WORKFLOWS` produce."""
    names: list[str] = []
    for file in REQUIRED_WORKFLOWS:
        with open(os.path.join(workflows_dir, file), encoding="utf-8") as f:
            names += job_checks(yaml.safe_load(f))
    return names


def documented(contributing: str) -> tuple[list[int], set[str]]:
    """`CONTRIBUTING.md` 中英兩句寫的必要檢查數量，以及句子裡用反引號點名的 job 名稱。
    The required-check counts the zh and en sentences of `CONTRIBUTING.md` give, and the job names they put in
    backticks."""
    counts, names = [], set()
    for pattern in _COUNT_RES:
        for match in pattern.finditer(contributing):
            counts.append(int(match.group(1)))
            names |= {s for s in re.findall(r"`([^`]+)`", match.group(2)) if _JOB_NAME_RE.match(s) and s != "test"}
    return counts, names


def problems(required: Iterable[str], counts: list[int], named: set[str], actual: Iterable[str] | None) -> list[str]:
    """三方比對的問題清單；`actual` 為 None 時不比對 ruleset。
    The problems of the three-way comparison; the ruleset is not compared when `actual` is None."""
    required = list(required)
    issues = []
    if len(set(required)) != len(required):
        issues.append(f"The workflows produce duplicate check names: {sorted(required)}")
    if len(counts) != 2:
        issues.append(f"CONTRIBUTING.md should state the count once in zh and once in en; found {counts}")
    issues += [f"CONTRIBUTING.md says {n} required checks, the workflows produce {len(set(required))}"
               for n in counts if n != len(set(required))]
    issues += [f"CONTRIBUTING.md names `{n}`, which no required workflow job reports" for n in sorted(named - set(required))]
    if actual is not None:
        actual = set(actual)
        issues += [f"The ruleset does not require `{n}`" for n in sorted(set(required) - actual)]
        issues += [f"The ruleset requires `{n}`, which no required workflow job reports (it would wait forever)"
                   for n in sorted(actual - set(required))]
    return issues


def ruleset_checks(repo: str) -> list[str]:
    """master 的 ruleset 實際要求的檢查（`gh api`，需要 `GH_TOKEN`）。
    The checks master's ruleset actually requires (`gh api`, needs `GH_TOKEN`)."""
    out = subprocess.run(["gh", "api", f"repos/{repo}/rules/branches/master", "--jq", RULES_QUERY],
                         check=True, capture_output=True, text=True, encoding="utf-8").stdout
    return [line for line in out.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    """命令列進入點；`--offline` 不讀 ruleset。回傳 0（一致）或 1（有問題）。
    Command-line entry point; `--offline` skips the ruleset. Returns 0 (consistent) or 1 (problems)."""
    args = sys.argv[1:] if argv is None else argv
    required = required_from_workflows(os.path.join(REPO_ROOT, ".github", "workflows"))
    with open(os.path.join(REPO_ROOT, "CONTRIBUTING.md"), encoding="utf-8") as f:
        counts, named = documented(f.read())
    actual = None if "--offline" in args else ruleset_checks(os.environ.get("GH_REPO", "chinchiang/MultiAgentGama"))
    issues = problems(required, counts, named, actual)
    print(json.dumps({"required": sorted(required), "ruleset": None if actual is None else sorted(actual)}, indent=1))
    if issues:
        print("\n".join(issues))
        return 1
    print(f"OK: {len(required)} required checks agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
