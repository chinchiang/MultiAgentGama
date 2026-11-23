"""公開發布後的打包、版本參照與 CI 文件的回歸測試：PyPI 中繼資料、README 絕對連結、`@vX.Y.Z` 參照與
`__version__` 一致、帶雜湊的建置後端、action 的 sandbox／artifact-name 輸入、CHANGELOG 比較連結，以及
設計文件 §15.2／§16.4、用法範例與 workflow 釘版的一致性。
Regression tests for packaging, version references and the CI docs after the public release: PyPI metadata,
absolute README links, `@vX.Y.Z` references matching `__version__`, the hash-verified build backend, the
action's sandbox / artifact-name inputs, the CHANGELOG compare links, and pin parity across design §15.2 / §16.4,
the usage examples and the workflows."""
import os
import re
import subprocess
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from vibeharness import __version__  # noqa: E402

WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")
GITHUB = "https://github.com/chinchiang/MultiAgentGama"
# sdist 不含 .github：那些檢查在 sdist 裡略過 ／ The sdist does not ship .github: those checks skip there
needs_github = pytest.mark.skipif(not os.path.isdir(WORKFLOWS), reason=".github/ is not shipped in the sdist")


def _read(*parts):
    """讀取 repo 內的文字檔。
    Reads a text file inside the repository."""
    with open(os.path.join(REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _pyproject():
    """解析 pyproject.toml。
    Parses pyproject.toml."""
    import tomllib
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), "rb") as f:
        return tomllib.load(f)


def _action():
    """解析 action.yml。
    Parses action.yml."""
    return yaml.safe_load(_read("action.yml"))


# --- 版本參照 ------------------------------------------------------------------------------------
# --- Version references --------------------------------------------------------------------------

_VERSIONED_FILES = ["action.yml", "README.md", "README.en.md", "CONTRIBUTING.md", "SECURITY.md",
                    "docs/design.md", "docs/design.en.md", "docs/configuration.md", "docs/configuration.en.md"]
_REF_RES = [re.compile(r"MultiAgentGama@v(\d+\.\d+\.\d+)"), re.compile(r"vibeharness-mas==(\d+\.\d+\.\d+)")]


def test_every_pinned_release_reference_matches_the_package_version():
    """`MultiAgentGama@vX.Y.Z` 與 `vibeharness-mas==X.Y.Z` 參照都必須等於 `vibeharness.__version__`
    （發布清單的第 3 步；CHANGELOG 是歷史紀錄，不檢查）。
    Every `MultiAgentGama@vX.Y.Z` and `vibeharness-mas==X.Y.Z` reference must equal `vibeharness.__version__`
    (step 3 of the release checklist; the CHANGELOGs are history and are not checked)."""
    found, stale = [], []
    for rel in _VERSIONED_FILES:
        path = os.path.join(REPO_ROOT, *rel.split("/"))
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            lines = list(f)
        for lineno, line in enumerate(lines, 1):
            for pattern in _REF_RES:
                for version in pattern.findall(line):
                    found.append(rel)
                    if version != __version__:
                        stale.append(f"{rel}:{lineno}: {version} != {__version__}")
    assert stale == [], "\n".join(stale)
    # 確認這個檢查真的有東西可比 ／ Make sure the check actually has something to compare
    assert {"action.yml", "README.md", "README.en.md"} <= set(found)


# --- PyPI 中繼資料 -------------------------------------------------------------------------------
# --- PyPI metadata -------------------------------------------------------------------------------

def test_pyproject_carries_the_pypi_metadata():
    """pyproject 帶 project URLs、作者、keywords、Beta／Typed 等 classifier；PEP 639 的 license 表達式不與
    License classifier 並存；長描述用 README.en.md。
    pyproject carries the project URLs, authors, keywords and the Beta / Typed classifiers; the PEP 639 license
    expression is not combined with a License classifier; the long description is README.en.md."""
    project = _pyproject()["project"]
    assert project["readme"] == "README.en.md"
    assert project["license"] == "MIT"
    assert {"Homepage", "Source", "Issues", "Changelog", "Documentation"} <= set(project["urls"])
    assert all(url.startswith(GITHUB) for url in project["urls"].values())
    assert project["authors"] and project["authors"][0]["name"] == "chinchiang"
    assert project["keywords"]
    for classifier in ("Development Status :: 4 - Beta", "Environment :: Console", "Intended Audience :: Developers",
                       "Topic :: Software Development :: Testing",
                       "Topic :: Software Development :: Quality Assurance", "Topic :: Security", "Typing :: Typed"):
        assert classifier in project["classifiers"], classifier
    assert not [c for c in project["classifiers"] if c.startswith("License ::")]


def test_the_package_ships_the_pep_561_marker():
    """`Typing :: Typed` 需要 vibeharness/py.typed，而且要列在 package-data 裡才會進 wheel。
    `Typing :: Typed` needs vibeharness/py.typed, listed in package-data so it lands in the wheel."""
    assert os.path.isfile(os.path.join(REPO_ROOT, "vibeharness", "py.typed"))
    package_data = _pyproject()["tool"]["setuptools"]["package-data"]
    assert "py.typed" in package_data["vibeharness"]


@pytest.mark.parametrize("readme", ["README.md", "README.en.md"])
def test_readme_links_are_absolute_so_they_work_on_pypi(readme):
    """README 的 Markdown 連結都是絕對網址（或頁內錨點），在 pypi.org 上不會壞掉。
    The README Markdown links are all absolute (or in-page anchors), so they do not break on pypi.org."""
    relative = [t for t in re.findall(r"\]\(([^)\s]+)\)", _read(readme))
                if not re.match(r"^(https?:|mailto:|#)", t)]
    assert relative == []


def test_readmes_stay_line_for_line_in_sync():
    """兩份 README 逐行對應（行數相同）。
    The two READMEs correspond line for line (same line count)."""
    assert len(_read("README.md").splitlines()) == len(_read("README.en.md").splitlines())


# --- 帶雜湊的建置後端 ----------------------------------------------------------------------------
# --- Hash-verified build backend -----------------------------------------------------------------

def test_build_backend_lock_is_hashed_and_matches_the_build_system_range():
    """requirements-build.in 的範圍等於 [build-system] requires，requirements-build.txt 釘的 setuptools
    帶雜湊且落在該範圍內。
    requirements-build.in carries the same range as [build-system] requires, and the setuptools pinned in
    requirements-build.txt is hashed and inside that range."""
    requires = _pyproject()["build-system"]["requires"]
    spec_lines = [line.strip() for line in _read("requirements-build.in").splitlines()
                  if line.strip() and not line.startswith("#")]
    assert spec_lines == requires
    lock = _read("requirements-build.txt")
    m = re.search(r"^setuptools==(\d+)\.(\d+)\.(\d+)", lock, re.MULTILINE)
    assert m, "setuptools is not pinned in requirements-build.txt"
    assert "--hash=sha256:" in lock.split(m.group(0), 1)[1].split("\n#", 1)[0]
    low, high = re.fullmatch(r"setuptools>=(\d+),<(\d+)", requires[0]).groups()
    assert int(low) <= int(m.group(1)) < int(high)


def test_action_installs_without_build_isolation_from_hashed_files():
    """action 的安裝以 --require-hashes 裝 requirements.lock 與 requirements-build.txt，再以
    --no-build-isolation 安裝套件，建置不會抓未釘版的 setuptools；README.en.md（pyproject 的 readme）一併複製。
    The action installs requirements.lock and requirements-build.txt with --require-hashes, then the package with
    --no-build-isolation, so the build never fetches an unpinned setuptools; README.en.md (pyproject's readme) is
    copied too."""
    install = next(s for s in _action()["runs"]["steps"] if s.get("name", "").startswith("Install"))
    script = install["run"]
    assert '-r "$GITHUB_ACTION_PATH/requirements-build.txt"' in script
    assert "--require-hashes" in script
    assert '--no-deps --no-build-isolation "$src"' in script
    assert '"$GITHUB_ACTION_PATH/README.en.md"' in script


@needs_github
@pytest.mark.parametrize("workflow,job", [("tests.yml", "package"), ("publish.yml", "build")])
def test_release_builds_use_the_hashed_build_backend(workflow, job):
    """tests.yml 的 package 與 publish.yml 的 build 先以 --require-hashes 安裝 requirements-build.txt，
    再以 `python -m build --no-isolation` 建置。
    tests.yml's package job and publish.yml's build job install requirements-build.txt with --require-hashes and
    then build with `python -m build --no-isolation`."""
    doc = yaml.safe_load(_read(".github", "workflows", workflow))
    script = "\n".join(str(s.get("run", "")) for s in doc["jobs"][job]["steps"])
    assert "--require-hashes -r requirements-build.txt" in script
    assert "python -m build --no-isolation" in script
    assert not re.search(r"python -m build\s*$", script, re.MULTILINE)


# --- action 的 sandbox 與 artifact-name 輸入 -----------------------------------------------------
# --- The action's sandbox and artifact-name inputs -----------------------------------------------

def test_artifact_name_input_names_the_uploaded_artifact():
    """artifact-name 預設 vibeharness-report，上傳 step 用它命名（矩陣使用者可設成不重複的名稱）。
    artifact-name defaults to vibeharness-report and names the upload (matrix users can make it unique)."""
    action = _action()
    assert action["inputs"]["artifact-name"]["default"] == "vibeharness-report"
    upload = next(s for s in action["runs"]["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == "${{ inputs.artifact-name }}"


def test_sandbox_input_builds_the_images_from_the_action_path():
    """sandbox 預設 local_subprocess；docker 時從 $GITHUB_ACTION_PATH 的 Dockerfile 建置兩個沙盒映像，未知值 exit 5。
    sandbox defaults to local_subprocess; docker builds both sandbox images from the Dockerfiles under
    $GITHUB_ACTION_PATH, and an unknown value exits 5."""
    action = _action()
    assert action["inputs"]["sandbox"]["default"] == "local_subprocess"
    steps = action["runs"]["steps"]
    build = next(s for s in steps if "docker build" in str(s.get("run", "")))
    assert build["if"] == "inputs.sandbox == 'docker'"
    assert ('-t vibeharness-sandbox:latest -f "$GITHUB_ACTION_PATH/docker/sandbox.Dockerfile" "$GITHUB_ACTION_PATH"'
            in build["run"])
    assert '-f "$GITHUB_ACTION_PATH/docker/sandbox-node.Dockerfile"' in build["run"]
    audit = next(s for s in steps if s.get("id") == "audit")
    assert audit["env"]["VH_SANDBOX"] == "${{ inputs.sandbox }}"
    assert "unknown sandbox value" in audit["run"] and '"${config_override[@]}"' in audit["run"]


def _sandbox_config_snippet():
    """取出 audit step 裡寫 docker 設定檔覆本的 Python heredoc。
    Extracts the Python heredoc in the audit step that writes the docker config copy."""
    script = next(s for s in _action()["runs"]["steps"] if s.get("id") == "audit")["run"]
    body = script.split("<<'PY'", 1)[1].split("\nPY\n", 1)[0]
    return body.split("\n", 1)[1]


@pytest.mark.parametrize("extra", [[], ["--exclude", "x", "-c", "{base}"], ["--config={base}"], ["-c{base}"]])
def test_sandbox_docker_config_copy_keeps_the_base_and_sets_the_provider(tmp_path, extra):
    """docker 設定檔覆本以 extra-args 的 --config（各種寫法）或內建設定檔為底稿，只改 sandbox_provider。
    The docker config copy uses extra-args' --config (in every spelling) or the bundled config as the base and
    only changes sandbox_provider."""
    base = tmp_path / "custom.yaml"
    base.write_text("global:\n  max_files: 7\n", encoding="utf-8")
    script = tmp_path / "snippet.py"
    script.write_text(_sandbox_config_snippet(), encoding="utf-8")
    args_file = tmp_path / "args"
    args_file.write_text("".join(a.format(base=base) + "\0" for a in extra), encoding="utf-8")
    out = tmp_path / "out.yaml"
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    # 在暫存目錄執行：片段會把工作目錄移出 sys.path，cwd 若是 repo 根目錄就會連 PYTHONPATH 一起移除
    # Run from tmp_path: the snippet drops the working directory from sys.path, which would also drop the
    # PYTHONPATH entry if the cwd were the repository root
    subprocess.run([sys.executable, str(script), str(args_file), str(out)], check=True, env=env,
                   capture_output=True, text=True, cwd=str(tmp_path))
    config = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert config["global"]["sandbox_provider"] == "docker"
    if extra:
        assert config["global"]["max_files"] == 7
    else:
        # 內建設定檔：agents 區段原封不動 ／ The bundled config: the agents section is carried over unchanged
        assert config.get("agents")


# --- CHANGELOG 比較連結 --------------------------------------------------------------------------
# --- CHANGELOG compare links ---------------------------------------------------------------------

@pytest.mark.parametrize("changelog", ["CHANGELOG.md", "CHANGELOG.en.md"])
def test_every_changelog_section_has_a_compare_link(changelog):
    """每個 `## [X]` 區段在檔尾都有連結定義：[Unreleased] 從最新版本比較到 HEAD，其餘從上一版比較，最早的版本連到 release tag。
    Every `## [X]` section has a link definition at the bottom: [Unreleased] compares the latest version to HEAD,
    the others compare from the previous version, and the first version links to its release tag."""
    text = _read(changelog)
    sections = re.findall(r"^## \[([^\]]+)\]", text, re.MULTILINE)
    links = dict(re.findall(r"^\[([^\]]+)\]: (\S+)$", text, re.MULTILINE))
    assert sections[0] == "Unreleased" and len(sections) > 1
    releases = sections[1:]
    assert links["Unreleased"] == f"{GITHUB}/compare/v{releases[0]}...HEAD"
    for version, previous in zip(releases[:-1], releases[1:], strict=True):
        assert links[version] == f"{GITHUB}/compare/v{previous}...v{version}", version
    assert links[releases[-1]] == f"{GITHUB}/releases/tag/v{releases[-1]}"
    # 最新的版本區段就是目前的套件版本 ／ The newest version section is the current package version
    assert releases[0] == __version__


def _is_heading(line):
    """`## `、`### ` 或 `#### ` 開頭的 Markdown 標題 ／ A Markdown heading starting `## `, `### ` or `#### `."""
    return re.match(r"#{2,4} ", line) is not None


def _unreleased_layout_problems(text):
    """CHANGELOG `## [Unreleased]` 區段的版面問題，每筆是「line N: 說明」：標題後面沒有接一個空行；`###` 子區段的空行
    後面不是條目（`- `，空的子區段也算）；`## [Unreleased]` 的空行後面不是子區段或下一個版本；條目後面直接接標題
    （包括下一個 `## [` 版本標題）；連續兩個空行。已發布的區段不檢查。
    The layout problems of a CHANGELOG's `## [Unreleased]` section, each "line N: what": a heading not followed by
    one blank line; a `###` subsection whose blank line is not followed by an entry (`- `; an empty subsection
    counts); `## [Unreleased]`'s blank line not followed by a subsection or the next version; a heading straight
    after an entry (the next `## [` version heading included); two blank lines in a row. Released sections are not
    checked."""
    lines = text.split("\n")
    start = next((i for i, line in enumerate(lines) if line.startswith("## [Unreleased]")), None)
    assert start is not None, "no ## [Unreleased] section"
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")), len(lines))
    problems = []
    # 也看下一個版本標題那一行（只看它前面有沒有空行），所以多看一行
    # One line further, the next version heading, so only the blank line before it is checked
    for i in range(start, min(end + 1, len(lines))):
        line, number = lines[i], i + 1
        if _is_heading(line) and i < end:
            after = lines[i + 1] if i + 1 < len(lines) else ""
            following = lines[i + 2] if i + 2 < len(lines) else ""
            if after.strip():
                problems.append(f"line {number}: heading {line!r} is not followed by one blank line")
            elif not following.strip():
                pass  # 第二個空行由下面「連續兩個空行」回報 ／ a second blank line is reported below as two in a row
            elif line.startswith("### ") and not following.startswith("- "):
                problems.append(f"line {number}: heading {line!r} is not followed by an entry")
            elif line.startswith("## ") and not following.startswith(("### ", "## [")):
                problems.append(f"line {number}: heading {line!r} is not followed by a subsection")
        if _is_heading(line) and i > start and lines[i - 1].strip() and not _is_heading(lines[i - 1]):
            problems.append(f"line {number}: heading {line!r} has no blank line before it")
        if i > start and not line.strip() and not lines[i - 1].strip():
            problems.append(f"line {number}: two blank lines in a row")
    return problems


_GOOD_UNRELEASED = """\
# Changelog

## [Unreleased]

### Fixed

- one fix
- another fix

### Engineering

- one tool change

## [0.1.0] - 2026-01-01
### Added
- old entries sit right under their heading
"""


@pytest.mark.parametrize("good, bad, line, problem", [
    ("### Fixed\n\n- one fix", "### Fixed\n- one fix", 5, "is not followed by one blank line"),
    ("- another fix\n\n### Engineering", "- another fix\n### Engineering", 9, "has no blank line before it"),
    ("### Engineering\n\n- one", "### Engineering\n\n\n- one", 12, "two blank lines"),
    ("## [Unreleased]\n\n### Fixed", "## [Unreleased]\n### Fixed", 3, "is not followed by one blank line"),
    ("### Engineering\n\n- one", "### Engineering\n- one", 10, "is not followed by one blank line"),
    ("### Fixed\n\n- one fix\n- another fix\n\n", "### Fixed\n\n", 5, "is not followed by an entry"),
])
def test_the_unreleased_layout_check_names_each_misplaced_line(good, bad, line, problem):
    """`[Unreleased]` 的版面檢查：標題後面接一個空行再接條目（或子區段）、標題前面有空行、不連續空兩行；違規時寫出行號與問題。
    已發布的區段不檢查（[0.4.0] 以前的條目直接接在標題下）（#199）。
    The `[Unreleased]` layout check: a heading is followed by one blank line and then an entry (or a subsection), a heading has a blank
    line before it, and no two blank lines follow each other; a violation names its line and the problem. Released
    sections are not checked (entries up to [0.4.0] sit right under their headings) (#199)."""
    assert _unreleased_layout_problems(_GOOD_UNRELEASED) == []
    assert good in _GOOD_UNRELEASED
    text = _GOOD_UNRELEASED.replace(good, bad, 1)
    problems = _unreleased_layout_problems(text)
    assert len(problems) == 1 and problems[0].startswith(f"line {line}: ") and problem in problems[0], problems


@pytest.mark.parametrize("changelog", ["CHANGELOG.md", "CHANGELOG.en.md"])
def test_the_unreleased_section_keeps_its_blank_lines(changelog):
    """兩份 CHANGELOG 的 `[Unreleased]` 標題後面都接一個空行：#197 用固定行號插入條目，把空行擠到條目後面，而中英行數相同的
    測試照樣是綠的（#199）。
    Both CHANGELOGs keep one blank line after each `[Unreleased]` heading: #197 inserted an entry at a fixed line
    number, pushing the blank line below it, and the zh / en line-count test stayed green (#199)."""
    problems = _unreleased_layout_problems(_read(changelog))
    assert problems == [], f"{changelog}:\n" + "\n".join(problems)


# --- 設計文件 §15.2／§16.4、用法範例與 workflow 釘版 ---------------------------------------------
# --- Design §15.2 / §16.4, the usage examples and the workflow pins ------------------------------

_DESIGN_ACTIONS = {
    "checkout": "actions/checkout", "setup-python": "actions/setup-python", "upload-artifact": "actions/upload-artifact",
    "download-artifact": "actions/download-artifact", "setup-node": "actions/setup-node",
    "gh-action-pypi-publish": "pypa/gh-action-pypi-publish", "codeql-action": "github/codeql-action",
}
_ACTION_PIN_RE = re.compile(
    r"uses:\s*(?P<repo>[\w.-]+/[\w.-]+)(?:/(?P<sub>[\w./-]+))?@(?P<sha>[0-9a-f]{40})\s*#\s*(?P<version>v[\d.]+)"
)


def _design_section(design, start, end):
    """取出設計文件兩個標題之間的區段文字。
    Extracts the text between two headings of a design document."""
    return _read(*design.split("/")).split(start, 1)[1].split(end, 1)[0]


def _workflow_pins():
    """workflow 與 action.yml 中每個第三方 action 的版本註解（action 名 → 版本集合）。
    The version comment of every third-party action in the workflows and action.yml (action name → versions)."""
    pins = {}
    files = [os.path.join(REPO_ROOT, "action.yml")] + [
        os.path.join(WORKFLOWS, f) for f in sorted(os.listdir(WORKFLOWS)) if f.endswith((".yml", ".yaml"))]
    for path in files:
        for m in _ACTION_PIN_RE.finditer(_read(path)):
            pins.setdefault(m["repo"], set()).add(m["version"])
    return pins


@needs_github
@pytest.mark.parametrize("design", ["docs/design.md", "docs/design.en.md"])
def test_design_section_15_2_lists_the_pinned_action_versions(design):
    """設計文件 §15.2 列出的每個 action 版本，都等於 workflow 裡實際的釘版（每個 action 只用一個版本）。
    Every action version listed in design §15.2 equals the actual pin in the workflows (one version per action)."""
    section = _design_section(design, "### 15.2", "### 15.3")
    listed = dict(re.findall(r"\b(" + "|".join(map(re.escape, _DESIGN_ACTIONS)) + r") (v\d+\.\d+\.\d+)", section))
    assert set(listed) == set(_DESIGN_ACTIONS), set(_DESIGN_ACTIONS) - set(listed)
    pins = _workflow_pins()
    mismatched = {name: (version, pins.get(_DESIGN_ACTIONS[name]))
                  for name, version in listed.items() if pins.get(_DESIGN_ACTIONS[name]) != {version}}
    assert mismatched == {}


@pytest.mark.parametrize("design", ["docs/design.md", "docs/design.en.md"])
def test_design_section_15_2_lists_the_pinned_lint_tool_versions(design):
    """設計文件 §15.2 列出的 ruff 與 mypy 版本等於 requirements-dev.txt 的釘版；
    在有 .github/ 的環境裡，pre-commit 的 7 字元 SHA 前綴也等於 .pre-commit-config.yaml 的 ruff rev。
    The ruff and mypy versions listed in design §15.2 equal the pins in requirements-dev.txt; when .github/ is
    present, the 7-character pre-commit SHA prefix also equals the ruff rev in .pre-commit-config.yaml."""
    dev = _read("requirements-dev.txt")
    expected = dict(re.findall(r"^(ruff|mypy)==(\S+)", dev, re.MULTILINE))
    assert set(expected) == {"ruff", "mypy"}
    section = _design_section(design, "### 15.2", "### 15.3")
    assert re.findall(r"\b(ruff|mypy) (\d+\.\d+\.\d+)", section) == [
        ("ruff", expected["ruff"]), ("mypy", expected["mypy"])]
    frozen = re.findall(r"rev:\s*([0-9a-f]{7})…\s+#\s*frozen:\s*v(\d+\.\d+\.\d+)", section)
    assert len(frozen) == 1, frozen
    rev_prefix, frozen_version = frozen[0]
    assert frozen_version == expected["ruff"]
    if os.path.isdir(WORKFLOWS):
        pre_commit = yaml.safe_load(_read(".pre-commit-config.yaml"))
        rev = next(r["rev"] for r in pre_commit["repos"] if r["repo"].endswith("/ruff-pre-commit"))
        assert rev_prefix == rev[:7]


def test_upload_sarif_examples_and_design_16_4_match_the_codeql_workflow_pin():
    """action.yml 與兩份 README 的用法範例以 SHA＋v4 版本註解釘住同一個 upload-sarif 並列出權限，
    兩份設計文件 §16.4 列出同一個 7 字元 SHA 前綴與版本；在有 .github/ 的環境裡，這些釘版也等於
    codeql.yml 所有 github/codeql-action 步驟的釘版。
    The usage examples in action.yml and both READMEs pin the same upload-sarif by SHA + v4 version comment and
    list the required permissions, and both design §16.4 sections list the same 7-character SHA prefix and version;
    when .github/ is present, they also equal every github/codeql-action pin in codeql.yml."""
    pins = set()
    for name in ("action.yml", "README.md", "README.en.md"):
        doc = _read(name)
        matches = [(m["sha"], m["version"]) for m in _ACTION_PIN_RE.finditer(doc)
                   if (m["repo"], m["sub"]) == ("github/codeql-action", "upload-sarif")]
        assert len(matches) == 1 and doc.count("github/codeql-action/") == 1, (name, matches)
        sha, version = matches[0]
        assert version.startswith("v4.")
        pins.add((sha, version))
        assert "security-events: write" in doc and "contents: read" in doc
        assert "9f759ee644a3e7c15c1390abf49868036c00067b" not in doc
    assert len(pins) == 1, pins
    sha, version = next(iter(pins))
    for design in ("docs/design.md", "docs/design.en.md"):
        section = _design_section(design, "### 16.4", "## 17.")
        assert re.findall(r"`upload-sarif@([0-9a-f]{7})…`\s+(v[\d.]+)", section) == [(sha[:7], version)], design
    if os.path.isdir(WORKFLOWS):
        codeql_doc = _read(".github", "workflows", "codeql.yml")
        workflow_matches = [(m["sha"], m["version"]) for m in _ACTION_PIN_RE.finditer(codeql_doc)
                            if m["repo"] == "github/codeql-action" and m["sub"]]
        assert len(workflow_matches) == codeql_doc.count("github/codeql-action/") >= 2
        assert set(workflow_matches) == {(sha, version)}


@pytest.mark.parametrize("pair", [("docs/design.md", "docs/design.en.md"), ("CHANGELOG.md", "CHANGELOG.en.md"),
                                  ("CODING_STANDARDS.md", "CODING_STANDARDS.en.md")])
def test_bilingual_doc_pairs_have_the_same_line_count(pair):
    """中英文件成對逐行對應（行數相同）。
    The zh / en document pairs correspond line for line (same line count)."""
    zh, en = (len(_read(*p.split("/")).splitlines()) for p in pair)
    assert zh == en
