"""建置、CI 與打包設定的回歸測試：釘 SHA 的 Actions、workflow 輸入不內插進腳本、沙盒映像的 digest 與雜湊、
帶雜湊的鎖定檔、sdist 內容，以及各處版本範圍的一致性。
Regression tests for the build, CI and packaging setup: SHA-pinned Actions, workflow inputs never interpolated
into scripts, sandbox image digests and hashes, the hashed locks, the sdist contents, and consistent version
ranges everywhere."""
import os
import re
import tarfile

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")
# sdist 不含 .github：那些檢查在 sdist 裡略過 ／ The sdist does not ship .github: those checks skip there
needs_github = pytest.mark.skipif(not os.path.isdir(WORKFLOWS), reason=".github/ is not shipped in the sdist")

_SHA_PIN_RE = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def _read(*parts):
    """讀取 repo 內的文字檔。
    Reads a text file inside the repository."""
    with open(os.path.join(REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _workflow_files():
    """所有 workflow 檔與 action.yml 的路徑（沒有 .github 時只有 action.yml）。
    Paths of every workflow file plus action.yml (only action.yml when .github is absent)."""
    files = [os.path.join(REPO_ROOT, "action.yml")]
    if os.path.isdir(WORKFLOWS):
        files += sorted(os.path.join(WORKFLOWS, f) for f in os.listdir(WORKFLOWS) if f.endswith((".yml", ".yaml")))
    return files


def _steps(doc):
    """產生 workflow 或複合 action 的每一個 step（含所屬 job 名稱）。
    Yields every step of a workflow or composite action (with the job it belongs to)."""
    if "runs" in doc:
        for step in doc["runs"].get("steps", []):
            yield "action", step
    for job_name, job in (doc.get("jobs") or {}).items():
        for step in job.get("steps", []) or []:
            yield job_name, step


def _pins(text):
    """解析 requirements 風格檔案的 名稱==版本（名稱正規化為小寫、底線轉連字號）。
    Parses name==version pins of a requirements-style file (names normalized to lower case with dashes)."""
    pins = {}
    for line in text.splitlines():
        m = _REQ_RE.match(line)
        if m:
            pins[re.sub(r"[._]+", "-", m.group(1)).lower()] = m.group(2)
    return pins


def _requirement_blocks(text):
    """把帶雜湊的鎖定檔切成每個需求一段（需求行加上其後的接續行）。
    Splits a hashed lock into one block per requirement (the requirement line plus its continuation lines)."""
    blocks, current = [], None
    for line in text.splitlines():
        if _REQ_RE.match(line):
            current = [line]
            blocks.append(current)
        elif current is not None and line.startswith(" "):
            current.append(line)
        else:
            current = None
    return blocks


# --- Actions 與 workflow -------------------------------------------------------------------------
# --- Actions and workflows -----------------------------------------------------------------------

def test_every_action_is_pinned_to_a_commit_sha_with_a_version_comment():
    """每個 `uses:` 都釘在 40 字元的 SHA，且行尾註解標出版本 tag（本地的 ./ 與 reusable workflow 除外）。
    Every `uses:` is pinned to a 40-character SHA with the version tag in a trailing comment (local ./ refs and
    reusable workflows excepted)."""
    offenders = []
    for path in _workflow_files():
        with open(path, encoding="utf-8") as f:
            lines = list(f)
        for lineno, line in enumerate(lines, 1):
            m = re.match(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$", line)
            if not m or m.group(1).startswith("./"):
                continue
            if not _SHA_PIN_RE.match(m.group(1)) or not re.search(r"#\s*v\d", m.group(2)):
                offenders.append(f"{os.path.relpath(path, REPO_ROOT)}:{lineno}: {line.strip()}")
    assert offenders == [], "\n".join(offenders)


def test_pypi_publish_is_not_pinned_to_the_annotated_tag_object():
    """v1.13.0 的 annotated tag 物件 SHA（106e0b0…）不是 commit；釘版必須是它指向的 commit。
    The annotated tag object SHA of v1.13.0 (106e0b0...) is not a commit; the pin must be the commit it points to."""
    for path in _workflow_files():
        with open(path, encoding="utf-8") as f:
            assert "106e0b0b7c337fa67ed433972f777c6357f78598" not in f.read(), path


def test_no_expression_is_interpolated_into_a_run_script():
    """`run:` 本文不得含 `${{ }}`：inputs、ref 等一律經 env 傳入並加引號，避免 shell 注入（有些 step 帶著金鑰）。
    `run:` bodies must not contain `${{ }}`: inputs, refs and the like go through env and are quoted, preventing
    shell injection (some steps hold secrets)."""
    offenders = []
    for path in _workflow_files():
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        for job, step in _steps(doc):
            if "${{" in str(step.get("run", "")):
                offenders.append(f"{os.path.relpath(path, REPO_ROOT)}:{job}:{step.get('name', step.get('run', '')[:40])}")
    assert offenders == [], "\n".join(offenders)


def test_action_installs_from_its_own_path_with_hash_verified_dependencies():
    """action 從 $GITHUB_ACTION_PATH 安裝（`uses: ./` 也可用），相依套件以 requirements.lock 帶雜湊安裝。
    The action installs from $GITHUB_ACTION_PATH (so `uses: ./` works too), with hash-verified dependencies from
    requirements.lock."""
    action = yaml.safe_load(_read("action.yml"))
    install = next(s for s in action["runs"]["steps"] if s.get("name", "").startswith("Install"))
    script = install["run"]
    assert "git+https://" not in script
    assert '--require-hashes -r "$GITHUB_ACTION_PATH/requirements.lock"' in script
    assert '--no-deps --no-build-isolation "$src"' in script
    assert "exit 5" in script


@needs_github
def test_live_smoke_validates_inputs_and_never_runs_uncapped():
    """live-smoke：inputs 經 env 傳入並驗證；唯一會呼叫模型的執行用正數上限，絕不傳 `--max-model-calls 0`（0 = 不限）；
    JSON 重跑用 `--cache-only` 與同一個 `--cache-dir`，不會再呼叫模型。
    live-smoke: inputs go through env and are validated; the only run that calls models uses the positive cap
    and never passes `--max-model-calls 0` (0 = unlimited); the JSON re-run uses `--cache-only` with the same
    `--cache-dir` and makes no further model calls."""
    doc = yaml.safe_load(_read(".github", "workflows", "live-smoke.yml"))
    step = next(s for s in doc["jobs"]["live"]["steps"] if "main.py" in str(s.get("run", "")))
    script = step["run"]
    assert {"VH_TARGET", "VH_MODE", "VH_MAX_CALLS"} <= set(step["env"])
    assert not re.search(r"--max-model-calls\s+\"?0\"?\s", script)
    # 只看指令本身：註解裡也會提到這些旗標 ／ Only the commands themselves: the comments mention the flags too
    commands = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
    runs = commands.split("python main.py")[1:]
    assert len(runs) == 2
    first, rerun = runs
    assert '--max-model-calls "$VH_MAX_CALLS"' in first and "--cache-only" not in first
    assert "--cache-only" in rerun and "--format json" in rerun
    # 兩次執行共用同一個快取目錄 ／ Both runs share the same cache directory
    cache_dirs = [re.search(r"--cache-dir\s+(\S+)", chunk).group(1) for chunk in runs]
    assert cache_dirs[0] == cache_dirs[1]
    assert "live|hybrid)" in script and "^[1-9][0-9]" in script


@needs_github
def test_publish_grants_write_only_to_the_release_job_and_gates_on_tests():
    """publish：預設唯讀，只有 release job 有 contents: write；建置前先跑 tests workflow。
    publish: read-only by default, only the release job has contents: write; the tests workflow runs before the build."""
    doc = yaml.safe_load(_read(".github", "workflows", "publish.yml"))
    assert doc["permissions"] == {"contents": "read"}
    writers = [name for name, job in doc["jobs"].items() if (job.get("permissions") or {}).get("contents") == "write"]
    assert writers == ["release"]
    assert doc["jobs"]["tests"]["uses"] == "./.github/workflows/tests.yml"
    assert doc["jobs"]["build"]["needs"] == "tests"
    tests = yaml.safe_load(_read(".github", "workflows", "tests.yml"))
    # PyYAML 把 `on` 讀成 True ／ PyYAML reads the `on` key as True
    assert "workflow_call" in tests[True]


@needs_github
def test_python_versions_agree_across_ci_classifiers_and_requires_python():
    """CI 矩陣的每個 Python 版本都有 classifier，且矩陣最低版本等於 requires-python 的下限。
    Every Python version in the CI matrix has a classifier, and the lowest matrix version equals requires-python's floor."""
    import tomllib
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), "rb") as f:
        project = tomllib.load(f)["project"]
    matrix = yaml.safe_load(_read(".github", "workflows", "tests.yml"))["jobs"]["test"]["strategy"]["matrix"]
    versions = set(matrix["python-version"]) | {c["python-version"] for c in matrix.get("include", [])}
    classifiers = {c.rsplit(":: ", 1)[1] for c in project["classifiers"] if re.search(r"Python :: 3\.\d+$", c)}
    assert versions <= classifiers, versions - classifiers
    assert project["requires-python"] == ">=" + min(versions, key=lambda v: tuple(map(int, v.split("."))))


def test_pre_commit_ruff_matches_the_dev_pin():
    """.pre-commit-config.yaml 的 ruff rev 釘在 40 字元的 commit SHA，行尾 `# frozen: vX.Y.Z` 等於 requirements-dev.txt 的 ruff 釘版。
    The ruff rev in .pre-commit-config.yaml is a 40-character commit SHA whose trailing `# frozen: vX.Y.Z` equals the
    ruff pin in requirements-dev.txt."""
    path = os.path.join(REPO_ROOT, ".pre-commit-config.yaml")
    if not os.path.exists(path):
        pytest.skip(".pre-commit-config.yaml is not shipped in the sdist")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    config = yaml.safe_load(text)
    rev = next(r["rev"] for r in config["repos"] if r["repo"].endswith("/ruff-pre-commit"))
    assert re.fullmatch(r"[0-9a-f]{40}", rev), rev
    # 版本在 YAML 讀不到的行尾註解裡 ／ The version lives in the trailing comment, which YAML drops
    frozen = re.search(r"^\s*rev:\s*" + rev + r"\s+#\s*frozen:\s*v(\S+)\s*$", text, re.MULTILINE)
    assert frozen, "missing `# frozen: vX.Y.Z` comment on the ruff-pre-commit rev"
    assert frozen.group(1) == _pins(_read("requirements-dev.txt"))["ruff"]


# --- 鎖定檔與沙盒映像 ----------------------------------------------------------------------------
# --- Locks and the sandbox images ----------------------------------------------------------------

@pytest.mark.parametrize("lock", ["requirements.lock", "docker/sandbox-requirements.txt"])
def test_every_locked_requirement_carries_hashes(lock):
    """鎖定檔的每個需求都帶 --hash，才能用 --require-hashes 安裝。
    Every requirement in the lock carries --hash, so it can be installed with --require-hashes."""
    blocks = _requirement_blocks(_read(*lock.split("/")))
    assert blocks
    unhashed = [b[0] for b in blocks if not any("--hash=sha256:" in line for line in b)]
    assert unhashed == []


def test_sandbox_requirements_match_requirements_lock():
    """沙盒映像的雜湊鎖定檔與 requirements.lock 的版本相同，容器行為與 CI 一致。
    The sandbox image's hashed lock pins the same versions as requirements.lock, so the container behaves like CI."""
    lock = _pins(_read("requirements.lock"))
    sandbox = _pins(_read("docker", "sandbox-requirements.txt"))
    assert {"pytest", "pytest-cov", "requests", "hypothesis"} <= set(sandbox)
    # 只有 hypothesis 與其相依 sortedcontainers 不在 requirements.lock 中，由沙盒鎖定檔自行釘版
    # Only hypothesis and its dependency sortedcontainers are absent from requirements.lock; the sandbox lock pins them
    sandbox_only = {"hypothesis", "sortedcontainers"}
    assert sandbox_only.isdisjoint(lock)
    assert {name: v for name, v in sandbox.items() if name not in sandbox_only and lock.get(name) != v} == {}


@pytest.mark.parametrize("dockerfile", ["sandbox.Dockerfile", "sandbox-node.Dockerfile"])
def test_sandbox_images_pin_the_base_by_digest_and_run_as_nobody(dockerfile):
    """沙盒 Dockerfile 以 tag＋多架構 digest 釘基底映像，最後的 USER 是 65534（nobody）。
    The sandbox Dockerfiles pin the base image by tag + multi-arch digest and end on USER 65534 (nobody)."""
    text = _read("docker", dockerfile)
    froms = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
    assert froms and all(re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", f) for f in froms), froms
    users = re.findall(r"^USER\s+(\S+)", text, re.MULTILINE)
    assert users and users[-1] == "65534:65534"


def test_python_sandbox_installs_only_hash_verified_packages():
    """Python 沙盒映像只以 --require-hashes 從 docker/sandbox-requirements.txt 安裝。
    The Python sandbox image installs only with --require-hashes from docker/sandbox-requirements.txt."""
    text = _read("docker", "sandbox.Dockerfile")
    installs = re.findall(r"^RUN .*pip install.*$", text, re.MULTILINE)
    assert installs and all("--require-hashes" in line for line in installs)
    assert "COPY docker/sandbox-requirements.txt" in text


# --- sdist（原始碼封存檔）-----------------------------------------------------------------------
# --- sdist (source archive) ----------------------------------------------------------------------

SDIST_REQUIRED = [
    "PKG-INFO", "pyproject.toml", "MANIFEST.in", "LICENSE", "README.md", "README.en.md", "CHANGELOG.md",
    "CHANGELOG.en.md", "CONTRIBUTING.md", "SECURITY.md", "main.py", "action.yml", "requirements.txt",
    "requirements-dev.txt", "requirements.lock", "requirements-build.in", "requirements-build.txt",
    "docker/sandbox.Dockerfile", "docker/sandbox-node.Dockerfile", "vibeharness/py.typed",
    "docker/sandbox-requirements.in", "docker/sandbox-requirements.txt", "examples/vibe_sample_app.py",
    "tests/conftest.py", "tests/test_review_build.py", "vibeharness/config/agents_config.yaml", "docs/design.md",
]


def test_sdist_ships_everything_needed_to_rebuild_and_test():
    """VIBEHARNESS_SDIST 指向的 sdist（CI 的 package job 設定）必須含有重建與測試所需的全部檔案，
    包括 tests/ 底下的每一個 .py；沒有設定時略過。
    The sdist VIBEHARNESS_SDIST points at (set by CI's package job) must ship everything needed to rebuild and
    test, including every .py under tests/; skipped when unset."""
    sdist = os.environ.get("VIBEHARNESS_SDIST")
    if not sdist:
        pytest.skip("VIBEHARNESS_SDIST is not set (CI's package job sets it)")
    with tarfile.open(sdist) as tar:
        names = {n.split("/", 1)[1] for n in tar.getnames() if "/" in n}
    missing = [p for p in SDIST_REQUIRED if p not in names]
    assert missing == []
    tests_dir = os.path.join(REPO_ROOT, "tests")
    local_tests = {f"tests/{f}" for f in os.listdir(tests_dir) if f.endswith(".py")}
    assert local_tests - names == set()
    assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc")]


def test_manifest_lists_the_sdist_extras():
    """MANIFEST.in 明列 sdist 額外需要的檔案（setuptools 預設不會帶的那些）。
    MANIFEST.in lists the extra files the sdist needs (the ones setuptools would not include by default)."""
    manifest = _read("MANIFEST.in")
    for needle in ("CONTRIBUTING.md", "SECURITY.md", "main.py", "action.yml", "requirements.lock", "requirements-build.txt",
                   "requirements-dev.txt", "docker/sandbox-requirements.txt", "recursive-include tests *.py",
                   "recursive-include examples *.py", "CHANGELOG.en.md"):
        assert needle in manifest, needle
