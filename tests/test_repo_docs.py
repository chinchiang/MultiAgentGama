"""repo 文件與測試套件本身的一致性：README 的檔案樹列出每個檔案、規則文件點名的名稱與路徑都存在、讀 `.github/` 的
測試在 sdist 裡會略過（sdist 不帶 `.github/`）。
Consistency of the repo's documents and of the suite itself: the README file trees list every file, the names and
paths the rule documents cite exist, and tests that read `.github/` skip in the sdist (which does not ship it)."""

import ast
import builtins
import glob
import keyword
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 檔案樹必須列出的檔案：(目錄, 副檔名, 是否遞迴)
# Files the trees must list: (directory, extensions, recursive)
_TREE_SOURCES = (
    ("tests", (".py",), False),
    ("scripts", (".py",), False),
    (os.path.join(".github", "workflows"), (".yml", ".yaml"), False),
    ("vibeharness", (".py",), True),
    ("docs", (".md",), True),
)


def _tree_files(directory, extensions, recursive):
    pattern = os.path.join(REPO_ROOT, directory, "**" if recursive else "", "*")
    # 一律用 `/`：Windows 的 relpath 是反斜線 ／ Always `/`: relpath gives backslashes on Windows
    return sorted(os.path.relpath(p, REPO_ROOT).replace(os.sep, "/") for p in glob.glob(pattern, recursive=recursive)
                  if p.endswith(extensions) and os.path.basename(p) != "__init__.py" and "__pycache__" not in p)


_TREE_ENTRY_RE = re.compile(r"^((?:│   |    )*)[├└]── (\S+)")
TREE_ROOT = "MultiAgentGama/"


def tree_paths(text):
    """把 README 的檔案樹還原成相對於 repo 根目錄的路徑：每層縮排 4 個字元，目錄以 `/` 結尾。
    Turn a README file tree back into paths relative to the repo root: each level indents 4 characters, and
    directories end in `/`."""
    lines = text.split("\n")
    start = next(i for i, line in enumerate(lines) if line.strip() == TREE_ROOT)
    stack, paths = [], set()
    for line in lines[start + 1:]:
        if line.startswith("```"):
            break
        match = _TREE_ENTRY_RE.match(line)
        if not match:
            continue
        depth, name = len(match.group(1)) // 4, match.group(2)
        stack = stack[:depth] + [name.rstrip("/")]
        paths.add("/".join(stack) + ("/" if name.endswith("/") else ""))
    return paths


@pytest.mark.parametrize("readme", ["README.md", "README.en.md"])
def test_the_readme_file_tree_lists_every_file(readme):
    """README 的檔案樹在正確的目錄底下列出每個測試檔、script、workflow、`vibeharness/` 模組與 `docs/` 文件。
    The README file tree lists every test file, script, workflow, `vibeharness/` module and `docs/` document under
    the right directory."""
    with open(os.path.join(REPO_ROOT, readme), encoding="utf-8") as f:
        listed = tree_paths(f.read())
    missing = []
    for directory, extensions, recursive in _TREE_SOURCES:
        # sdist 不帶 .github/：沒有的目錄略過 ／ The sdist does not ship .github/: a missing directory is skipped
        if not os.path.isdir(os.path.join(REPO_ROOT, directory)):
            continue
        missing += [p for p in _tree_files(directory, extensions, recursive) if p not in listed]
    assert missing == [], f"list these under their directory in the file tree of {readme}:\n" + "\n".join(missing)


def test_tree_paths_follows_the_indentation_and_catches_a_file_under_the_wrong_directory():
    """縮排決定所屬目錄：列在 `scripts/` 底下的測試檔還原成 `scripts/…`，不會被當成 `tests/…`。
    Indentation decides the directory: a test file listed under `scripts/` comes back as `scripts/…`, not
    `tests/…`."""
    text = "\n".join([
        "```text", TREE_ROOT,
        "├── scripts/",
        "│   ├── tool.py                  # a script",
        "│   └── test_misplaced.py        # listed in the wrong place",
        "├── tests/",
        "│   └── test_a.py",
        "└── vibeharness/",
        "    └── core/",
        "        └── gate.py",
        "```",
        "├── ignored.py  (after the tree)",
    ])
    assert tree_paths(text) == {"scripts/", "scripts/tool.py", "scripts/test_misplaced.py", "tests/", "tests/test_a.py",
                                "vibeharness/", "vibeharness/core/", "vibeharness/core/gate.py"}
    assert "tests/test_misplaced.py" not in tree_paths(text)


# --- 規則文件點名的名稱與路徑 ----------------------------------------------------------------------------
# --- Names and paths cited by the rule documents -----------------------------------------------------------

RULE_DOCS = ("CODING_STANDARDS.md", "CODING_STANDARDS.en.md", "CONTRIBUTING.md", "AGENTS.md")
_SPAN_RE = re.compile(r"`([^`\n]+)`")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\(\))?$")
_FILE_RE = re.compile(r"^[\w.*/-]+\.(?:py|ya?ml|md|toml|in|txt|lock|json|cfg|Dockerfile)$")
_CAMEL_RE = re.compile(r"^[A-Z][a-z0-9]+[A-Z]")
# 只寫檔名時會去找的目錄 ／ Where a bare file name is looked for
_FILE_DIRS = ("", ".github", os.path.join(".github", "workflows"), "docker", "docs", "scripts", "tests")


def _definitions():
    names, literals = set(), set()
    product = (glob.glob(os.path.join(REPO_ROOT, "vibeharness", "**", "*.py"), recursive=True)
               + glob.glob(os.path.join(REPO_ROOT, "scripts", "*.py")) + [os.path.join(REPO_ROOT, "main.py")])
    tests = glob.glob(os.path.join(REPO_ROOT, "tests", "*.py"))
    for path in product + tests:
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
            # 產品程式碼裡整個字串就是一個識別字（設定鍵、標籤名稱）；不含 docstring 裡順帶提到的名稱，也不收測試裡的字串
            # A string in product code that is one identifier (a config key, a label); not a name mentioned inside a
            # docstring, and not strings from the tests
            elif (isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.isidentifier()
                  and path not in tests):
                literals.add(node.value)
    return names, literals


def _looks_like_code(name):
    return (name.startswith("_") or "_" in name.strip("_") and not name.isupper()
            or bool(_CAMEL_RE.match(name)))


# sdist 刻意不打包的檔案：在 sdist 裡（沒有 .github/）無法核對
# Files the sdist deliberately leaves out: they cannot be checked from the sdist (no .github/)
_NOT_SHIPPED = ("AGENTS.md",)


def _file_exists(span):
    if span in _NOT_SHIPPED and not os.path.isdir(os.path.join(REPO_ROOT, ".github")):
        return True
    if "/" in span:
        if span.startswith(".github") and not os.path.isdir(os.path.join(REPO_ROOT, ".github")):
            return True
        return bool(glob.glob(os.path.join(REPO_ROOT, span)))
    if any(glob.glob(os.path.join(REPO_ROOT, d, span)) for d in _FILE_DIRS):
        return True
    # sdist 不帶 .github/：只寫檔名的 workflow 在那裡無法核對 ／ The sdist has no .github/: a bare workflow name cannot be checked there
    return span.endswith((".yml", ".yaml")) and not os.path.isdir(os.path.join(REPO_ROOT, ".github"))


def stale_citations(text, names, literals):
    """一份規則文件裡指向不存在的檔案或定義的反引號片段。檔案以路徑（可含 glob）找；看起來像程式碼的名稱
    （底線開頭、`()` 結尾、snake_case 或駝峰式）必須在 vibeharness／scripts／tests 有定義，設定鍵可以只是字串。
    The backticked spans of a rule document that point at a missing file or definition. Files are looked up by
    path (globs allowed); a code-looking name (leading underscore, `()`, snake_case or CamelCase) must be defined in
    vibeharness / scripts / tests, while a config key may be just a string."""
    known = names | set(dir(builtins)) | set(keyword.kwlist)
    stale = []
    for span in dict.fromkeys(_SPAN_RE.findall(text)):
        if _FILE_RE.match(span) and " " not in span:
            if not _file_exists(span):
                stale.append(span)
            continue
        if not _IDENT_RE.match(span):
            continue
        name = span.removesuffix("()").rsplit(".", 1)[-1]
        if not _looks_like_code(name) or name in known:
            continue
        if not span.endswith("()") and not name.startswith("_") and name in literals:
            continue
        stale.append(span)
    return stale


@pytest.mark.parametrize("doc", RULE_DOCS)
def test_rule_documents_cite_files_and_definitions_that_exist(doc):
    """規則文件點名的檔案與函式、類別、常數都還存在（重構後過時的名稱會在這裡失敗）。
    The files, functions, classes and constants the rule documents name still exist (names left stale by a refactor
    fail here)."""
    path = os.path.join(REPO_ROOT, doc)
    if not os.path.isfile(path):
        pytest.skip(f"{doc} is not shipped in the sdist")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    assert stale_citations(text, *_definitions()) == []


def test_stale_citations_flags_a_removed_function_but_not_a_docstring_mention():
    """已移除的函式即使還在 docstring 裡被提到也算過時；存在的定義、設定鍵、內建名稱、一般單字與檔案不算。
    A removed function counts as stale even when a docstring still mentions it; existing definitions, config keys,
    builtins, plain words and existing files do not."""
    names, literals = _definitions()
    text = ("`_validate_settings` `LLMGateway.__init__` `load_settings` `ask()` `ConfigError` `ValueError` "
            "`max_model_calls` `master` `vX.Y.Z` `CODING_STANDARDS.md` `docs/design*.md` `tests/conftest.py` "
            "`gone_helper()` `docs/missing.md` `NoSuchClass`")
    assert stale_citations(text, names, literals) == ["_validate_settings", "gone_helper()", "docs/missing.md",
                                                      "NoSuchClass"]


# --- 讀 .github/ 的測試必須在 sdist 裡略過 ------------------------------------------------------------------
# --- Tests that read .github/ must skip in the sdist -------------------------------------------------------

def _reads_repo_github(call):
    # `_read(".github", ...)` 或 `os.path.join(REPO_ROOT, ".github", ...)`；暫存目錄裡的假檔名不算
    # `_read(".github", ...)` or `os.path.join(REPO_ROOT, ".github", ...)`; a fake file name in a temp dir does not count
    args = call.args
    if not any(isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.startswith(".github") for a in args):
        return False
    func = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
    return func == "_read" or any(isinstance(a, ast.Name) and a.id in ("REPO_ROOT", "ROOT") for a in args)


def _mentions_github(node, github_names):
    return any(isinstance(n, ast.Call) and _reads_repo_github(n)
               or isinstance(n, ast.Name) and n.id in github_names
               for n in ast.walk(node))


def _guarded(func):
    for decorator in func.decorator_list:
        if any(isinstance(n, (ast.Name, ast.Attribute)) and getattr(n, "id", getattr(n, "attr", "")) in
               ("needs_github", "skipif") for n in ast.walk(decorator)):
            return True
    # 本體自己檢查目錄或檔案在不在，或呼叫 pytest.skip ／ The body checks the directory or file itself, or calls pytest.skip
    return any(isinstance(n, ast.Attribute) and n.attr in ("isdir", "isfile", "exists", "skip")
               for n in ast.walk(func))


def unguarded_github_tests(source):
    """測試模組裡讀 `.github/`、卻沒有 `needs_github`／`skipif`、也沒自行檢查或略過的測試函式。
    The test functions of a module that read `.github/` without `needs_github` / `skipif` and without checking or
    skipping themselves."""
    tree = ast.parse(source)
    github_names = {t.id for node in tree.body if isinstance(node, ast.Assign) and _mentions_github(node.value, set())
                    for t in node.targets if isinstance(t, ast.Name)}
    return [node.name for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
            and _mentions_github(node, github_names) and not _guarded(node)]


def test_every_test_that_reads_github_skips_without_it():
    """CI 的 package job 在解開的 sdist 裡重跑測試，那裡沒有 `.github/`；讀它的測試要加 `needs_github`。
    CI's package job reruns the suite from the unpacked sdist, which has no `.github/`; a test that reads it needs
    `needs_github`."""
    offenders = []
    for path in sorted(glob.glob(os.path.join(REPO_ROOT, "tests", "*.py"))):
        with open(path, encoding="utf-8") as f:
            offenders += [f"{os.path.basename(path)}::{name}" for name in unguarded_github_tests(f.read())]
    assert offenders == [], "add @needs_github to:\n" + "\n".join(offenders)


def test_unguarded_github_tests_flags_a_bare_read_and_accepts_the_guards():
    """直接讀 `.github/` 的測試會被列出；`needs_github`、`skipif`、自行檢查與 `pytest.skip` 都算有防護。
    A test reading `.github/` directly is listed; `needs_github`, `skipif`, checking itself and `pytest.skip` all
    count as guarded."""
    source = '''
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "x.yml")
def test_bare():
    open(WORKFLOW).read()
def test_literal():
    _read(".github", "CODEOWNERS")
def test_fake_names_in_a_temp_dir():
    names = ["src/app.py", ".github/workflows/ci.yml"]
@needs_github
def test_marked():
    open(WORKFLOW).read()
@pytest.mark.skipif(True, reason="r")
def test_skipif():
    open(WORKFLOW).read()
def test_checks_itself():
    if not os.path.isfile(WORKFLOW):
        pytest.skip("absent")
def test_unrelated():
    assert 1
'''
    assert unguarded_github_tests(source) == ["test_bare", "test_literal"]
