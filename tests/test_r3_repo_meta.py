"""repo 中繼設定的回歸測試：SECURITY.md 的支援版本跟著 `__version__`、每個 workflow 的權限都有上限、
workflow 檔名與其 `name` 相符，以及 publish.yml 從 CHANGELOG.en.md 取出 Release 內文的 awk。
Regression tests for the repository meta setup: SECURITY.md's supported versions follow `__version__`, every
workflow's permissions are bounded, workflow file names match their `name`, and the awk in publish.yml that
extracts the Release body from CHANGELOG.en.md."""
import os
import re
import shutil
import subprocess
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from vibeharness import __version__  # noqa: E402

WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")
# sdist 不含 .github：那些檢查在 sdist 裡略過 ／ The sdist does not ship .github: those checks skip there
needs_github = pytest.mark.skipif(not os.path.isdir(WORKFLOWS), reason=".github/ is not shipped in the sdist")


def _read(*parts):
    """讀取 repo 內的文字檔。
    Reads a text file inside the repository."""
    with open(os.path.join(REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _workflows():
    """所有 workflow 檔（檔名 → 解析後的 YAML）。
    Every workflow file (file name → parsed YAML)."""
    names = sorted(f for f in os.listdir(WORKFLOWS) if f.endswith((".yml", ".yaml")))
    return {name: yaml.safe_load(_read(".github", "workflows", name)) for name in names}


# --- SECURITY.md 的支援版本 ----------------------------------------------------------------------
# --- SECURITY.md supported versions --------------------------------------------------------------

def test_security_supported_versions_follow_the_current_minor():
    """SECURITY.md 兩個語言的支援版本表都是「目前 major.minor 的 .x ✅、更舊 ❌」，各只有這兩列（發布清單第 4 步）。
    Both language tables of SECURITY.md read "the current major.minor .x ✅, older ❌", with exactly those two rows
    (release checklist step 4)."""
    minor = ".".join(__version__.split(".")[:2])
    text = _read("SECURITY.md")
    rows = re.findall(r"^\| ([^|]+?) \| :?(✅|❌):? \|$", text, re.MULTILINE)
    # 兩張表（中文、英文）各兩列 ／ Two tables (zh, en) with two rows each
    assert rows == [(f"{minor}.x", "✅"), (f"< {minor}", "❌")] * 2, rows


# --- workflow 權限與命名 -------------------------------------------------------------------------
# --- Workflow permissions and naming -------------------------------------------------------------

def _write_scopes(permissions):
    """權限設定中帶寫入權的範圍（`write-all` 視為全部）。
    The scopes with write access in a permissions block (`write-all` counts as everything)."""
    if permissions == "write-all":
        return ["*"]
    if isinstance(permissions, dict):
        return sorted(scope for scope, level in permissions.items() if level == "write")
    return []


@needs_github
def test_every_workflow_sets_read_only_top_level_permissions():
    """每個 workflow 都有頂層 `permissions`，且頂層不給任何寫入權（需要寫入的 job 自己宣告）。
    Every workflow sets top-level `permissions` granting no write access (jobs that need write access declare it)."""
    for name, doc in _workflows().items():
        assert "permissions" in doc, f"{name}: missing top-level permissions"
        assert doc["permissions"] in ({}, "read-all") or isinstance(doc["permissions"], dict), name
        assert _write_scopes(doc["permissions"]) == [], f"{name}: top-level write permissions"


# 帶祕密的 job 允許的寫入範圍（目前沒有）；GITHUB_TOKEN 本身（github.token）不算祕密
# Write scopes allowed in a job holding secrets (none today); the GITHUB_TOKEN itself (github.token) is not a secret
_SECRET_JOB_WRITE_ALLOWED: set = set()


@needs_github
def test_jobs_using_secrets_have_no_write_permissions():
    """引用 `secrets.` 的 job 實際生效的權限（job 層覆寫頂層）沒有寫入權，且該 workflow 不由 pull_request_target 觸發。
    A job referencing `secrets.` has no write access in its effective permissions (job level overrides top level),
    and its workflow is not triggered by pull_request_target."""
    for name, doc in _workflows().items():
        # PyYAML 把 `on` 讀成 True ／ PyYAML reads the `on` key as True
        triggers = doc.get(True, doc.get("on"))
        for job_name, job in (doc.get("jobs") or {}).items():
            if "secrets." not in yaml.safe_dump(job):
                continue
            effective = job.get("permissions", doc.get("permissions"))
            extra = set(_write_scopes(effective)) - _SECRET_JOB_WRITE_ALLOWED
            assert not extra, f"{name}:{job_name} holds secrets with write scopes {sorted(extra)}"
            assert "pull_request_target" not in str(triggers), f"{name}:{job_name} exposes secrets to fork PRs"


def _slug(text):
    """小寫並只留英數字。
    Lower case with only letters and digits kept."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


@needs_github
def test_workflow_file_names_match_their_names():
    """workflow 檔名（去掉副檔名）必須出現在它的 `name` 裡，避免像 nightly-full.yml 裝的其實是 CodeQL 這種誤導的檔名。
    A workflow's file name (without extension) must appear in its `name`, avoiding misleading names such as a
    nightly-full.yml that actually holds CodeQL."""
    for name, doc in _workflows().items():
        stem = os.path.splitext(name)[0]
        assert _slug(stem) in _slug(str(doc.get("name", ""))), f"{name} vs name {doc.get('name')!r}"


@needs_github
def test_codeql_keeps_the_required_check_names():
    """CodeQL workflow 的名稱與 job 名稱是 master 的必要檢查（`Analyze (python)`、`Analyze (actions)`），不得改名。
    The CodeQL workflow and job names are required checks on master (`Analyze (python)`, `Analyze (actions)`) and
    must not be renamed."""
    doc = _workflows()["codeql.yml"]
    assert doc["name"] == "CodeQL Advanced"
    job = doc["jobs"]["analyze"]
    assert job["name"] == "Analyze (${{ matrix.language }})"
    assert {entry["language"] for entry in job["strategy"]["matrix"]["include"]} == {"python", "actions"}
    assert job["permissions"] == {"security-events": "write", "contents": "read"}
    assert job["timeout-minutes"] > 0


@needs_github
def test_codeql_runs_on_every_pull_request_not_only_those_targeting_master():
    """CodeQL 對所有 PR 執行：疊在其他 PR 上的 PR 改目標成 master 時不會觸發 workflow，必要檢查會等不到。
    CodeQL runs on every PR: a stacked PR retargeted to master triggers no workflow, so its required checks would
    wait forever."""
    doc = _workflows()["codeql.yml"]
    # PyYAML 把 `on` 讀成 True ／ PyYAML reads the `on` key as True
    triggers = doc.get("on", doc.get(True))
    assert "pull_request" in triggers
    assert not (triggers["pull_request"] or {}).get("branches")
    assert triggers["push"]["branches"] == ["master"]


# --- publish.yml 的 Release 內文 -----------------------------------------------------------------
# --- The Release body in publish.yml -------------------------------------------------------------

def _release_notes_awk():
    """取出 publish.yml 裡從 CHANGELOG.en.md 擷取 Release 內文的 awk 程式。
    Extracts the awk program in publish.yml that pulls the Release body out of CHANGELOG.en.md."""
    doc = yaml.safe_load(_read(".github", "workflows", "publish.yml"))
    script = next(s["run"] for s in doc["jobs"]["build"]["steps"] if "CHANGELOG.en.md" in str(s.get("run", "")))
    m = re.search(r"""awk -v ver="\$\{GITHUB_REF_NAME#v\}" '(.*?)' CHANGELOG\.en\.md""", script, re.DOTALL)
    assert m, "release-notes awk not found in publish.yml"
    return m.group(1)


def _run_awk(program, version, path):
    """以指定版本執行 awk 程式，回傳輸出。
    Runs the awk program for the given version and returns its output."""
    return subprocess.run(["awk", "-v", f"ver={version}", program, str(path)], check=True,
                          capture_output=True, text=True, encoding="utf-8").stdout


@needs_github
@pytest.mark.skipif(shutil.which("awk") is None, reason="awk unavailable")
def test_release_notes_are_the_changelog_section_of_the_version():
    """目前版本的 Release 內文是 CHANGELOG.en.md 的對應區段：非空、不含標題本身與下一個區段，頭尾沒有空行。
    The Release body for the current version is its CHANGELOG.en.md section: non-empty, without the heading itself
    or the next section, and no leading or trailing blank lines."""
    program = _release_notes_awk()
    notes = _run_awk(program, __version__, os.path.join(REPO_ROOT, "CHANGELOG.en.md"))
    changelog = _read("CHANGELOG.en.md")
    section = changelog.split(f"## [{__version__}]", 1)[1].split("\n", 1)[1].split("\n## [", 1)[0].strip()
    assert notes.strip() == section
    assert notes == section + "\n"
    assert "## [" not in notes


@needs_github
@pytest.mark.skipif(shutil.which("awk") is None, reason="awk unavailable")
def test_release_notes_stop_at_link_definitions_and_miss_unknown_versions(tmp_path):
    """最後一個區段在檔尾的連結定義前結束；沒有該版本的區段時輸出為空（release job 改用 --generate-notes）；
    `0.1.1` 不會誤配到 `0.1.10`。
    The last section ends before the link definitions at the bottom; a version without a section yields nothing
    (the release job falls back to --generate-notes); `0.1.1` never matches `0.1.10`."""
    changelog = tmp_path / "CHANGELOG.en.md"
    changelog.write_text("# Changelog\n\n## [Unreleased]\n\n## [0.1.10] - 2026-01-02\n\n- ten\n\n"
                         "## [0.1.1] - 2026-01-01\n\n### Fixed\n\n- one\n\n\n"
                         "[Unreleased]: https://example.invalid/a\n[0.1.1]: https://example.invalid/b\n",
                         encoding="utf-8")
    program = _release_notes_awk()
    assert _run_awk(program, "0.1.1", changelog) == "### Fixed\n\n- one\n"
    assert _run_awk(program, "0.1.10", changelog) == "- ten\n"
    assert _run_awk(program, "9.9.9", changelog) == ""
