"""repo 文件與測試套件本身的一致性：README 的檔案樹列出每個檔案且沒有過時項目、規則文件點名的名稱與路徑都存在、
讀 `.github/` 的測試在 sdist 裡會略過（sdist 不帶 `.github/`）。
Consistency of the repo's documents and of the suite itself: the README file trees list every file without stale
entries, the names and paths the rule documents cite exist, and tests that read `.github/` skip in the sdist (which
does not ship it)."""

import ast
import builtins
import glob
import keyword
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(REPO_ROOT, "MANIFEST.in")
# sdist 刻意不打包的檔案：在 sdist 裡（沒有 .github/）無法核對
# Files the sdist deliberately leaves out: they cannot be checked from the sdist (no .github/)
_NOT_SHIPPED = ("AGENTS.md", ".pre-commit-config.yaml")


def pruned_dirs(manifest):
    """MANIFEST.in 用 prune 排除的目錄，依出現順序，不帶結尾的 `/`；參數當成字面上的目錄，不展開樣式。
    The directories a MANIFEST.in excludes with prune, in order and without a trailing `/`; the argument is taken
    as a literal directory, not expanded as a pattern."""
    with open(manifest, encoding="utf-8") as f:
        lines = [line.split() for line in f]
    return [words[1].rstrip("/") for words in lines if len(words) == 2 and words[0] == "prune"]

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


_TREE_ENTRY_RE = re.compile(r"^((?:│   |    )*)[├└]── ([^\s#/]+/?)(?:\s+#.*)?$")
TREE_ROOT = "MultiAgentGama/"


def tree_paths(text):
    """把 README 的檔案樹（緊接在開頭程式碼圍欄後的 `MultiAgentGama/` 到 ` ``` ` 為止）還原成相對於 repo 根目錄的路徑：
    每層縮排 4 個字元，每個項目是單一檔名或以 `/` 結尾的目錄名；找不到檔頭、圍欄內有無法解析的行、`.`／`..` 名稱、
    跳層縮排、掛在一般檔案底下的子項目、重複項目或缺少 ` ``` ` 結束圍欄時丟出 ValueError。
    Turn a README file tree (from `MultiAgentGama/` right after an opening code fence to ` ``` `) back into paths
    relative to the repo root: each level indents 4 characters, and each entry is a single file name or `/`-suffixed
    directory name; a missing header, an unparseable line, a `.` / `..` name, a skipped indent level, a child under a
    non-directory entry, a duplicate entry or a missing ` ``` ` closing fence raises ValueError."""
    lines = text.split("\n")
    start = next((i for i, line in enumerate(lines) if line == TREE_ROOT), None)
    if start is None or start == 0 or not lines[start - 1].startswith("```"):
        raise ValueError("missing README tree header")
    stack, paths = [], set()
    for line in lines[start + 1:]:
        if line == "```":
            return paths
        match = _TREE_ENTRY_RE.match(line)
        if not match or match.group(2).rstrip("/") in ("", ".", ".."):
            raise ValueError(f"could not parse README tree line: {line!r}")
        depth, name = len(match.group(1)) // 4, match.group(2)
        if depth > len(stack) or (depth > 0 and not stack[depth - 1].endswith("/")):
            raise ValueError(f"invalid indentation in README tree line: {line!r}")
        stack = stack[:depth] + [name]
        entry = "/".join(p.rstrip("/") for p in stack) + ("/" if name.endswith("/") else "")
        if entry in paths:
            raise ValueError(f"duplicate README tree entry: {entry}")
        paths.add(entry)
    raise ValueError("unclosed README tree code fence")


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


def test_tree_paths_rejects_malformed_lines_bad_indentation_duplicates_and_unclosed_fences():
    """找不到緊接圍欄的檔頭、圍欄內無法解析的行、含額外 `/` 或 `.`／`..` 的名稱、跳層縮排、掛在一般檔案底下的子項目、
    重複項目、結束圍欄帶多餘字元或缺少結束圍欄，都會丟出 ValueError，不會被悄悄略過。
    A missing fenced header, an unparseable line, a name with extra `/` or `.` / `..`, a skipped indent level, a child
    under a non-directory entry, a duplicate entry, trailing text on the closing fence or a missing closing fence
    raises ValueError instead of being silently ignored."""
    for bad_doc, match in [
        ("no tree here", "missing README tree header"),
        ("\n".join(["```text", "stray before root", TREE_ROOT, "└── a.py", "```"]), "missing README tree header"),
        ("\n".join([TREE_ROOT, "└── a.py", "```"]), "missing README tree header"),
        ("\n".join(["```text", TREE_ROOT, "└── a.py", "``` extra"]), "could not parse"),
        ("\n".join(["```text", TREE_ROOT, "└── a.py"]), "unclosed"),
    ]:
        with pytest.raises(ValueError, match=match):
            tree_paths(bad_doc)
    for bad, match in [
        (["├── a.py", "|-- old.py"], "could not parse"),
        (["├── dir/", "│  └── old.py"], "could not parse"),
        (["├── a.py stray_words"], "could not parse"),
        (["├── a/b.py"], "could not parse"),
        (["├── dir//"], "could not parse"),
        (["├── /"], "could not parse"),
        (["├── ./"], "could not parse"),
        (["├── ../"], "could not parse"),
        (["    └── skipped_level.py"], "invalid indentation"),
        (["├── file.py", "│   └── under_file.py"], "invalid indentation"),
        (["├── a.py", "└── a.py"], "duplicate"),
    ]:
        with pytest.raises(ValueError, match=match):
            tree_paths("\n".join(["```text", TREE_ROOT, *bad, "```"]))


def _unshipped_in_sdist(path):
    return path in _NOT_SHIPPED or path.startswith(".github/")


def _under_absent_pruned(path, root, pruned):
    return any(path.startswith(d + "/") and not os.path.isdir(os.path.join(root, d)) for d in pruned)


def _exists_exact_case(root, path):
    full = os.path.join(root, path.rstrip("/"))
    if not (os.path.isdir(full) if path.endswith("/") else os.path.isfile(full)):
        return False
    parent, name = os.path.split(full)
    return name in os.listdir(parent)


def stale_tree_paths(text, root=REPO_ROOT, manifest=MANIFEST):
    """README 檔案樹裡在磁碟上找不到（區分大小寫），或型別不符（目錄沒加 `/`、一般檔案加了 `/`）的路徑，依字母排序。
    在解開的 sdist 裡（沒有 `.github/`），`_unshipped_in_sdist`、被 `MANIFEST.in` prune 掉且不存在的目錄，以及因
    prune 而變成不存在的上層目錄會略過。
    Listed paths in a README file tree that are missing on disk (case-exact) or have the wrong kind (a directory
    without `/`, a regular file with `/`), sorted. In the unpacked sdist (no `.github/`), `_unshipped_in_sdist`, absent
    directories `MANIFEST.in` prunes, and ancestor directories absent only because a child was pruned are skipped."""
    pruned = pruned_dirs(manifest)
    in_sdist = not os.path.isdir(os.path.join(root, ".github"))
    stale = []
    for path in sorted(tree_paths(text)):
        if in_sdist:
            if _unshipped_in_sdist(path) or _under_absent_pruned(path, root, pruned):
                continue
            if path.endswith("/") and any(d.startswith(path) and not os.path.isdir(os.path.join(root, d)) for d in pruned):
                if not os.path.exists(os.path.join(root, path.rstrip("/"))):
                    continue
        if not _exists_exact_case(root, path):
            stale.append(path)
    return stale


@pytest.mark.parametrize("readme", ["README.md", "README.en.md"])
def test_the_readme_file_tree_has_no_stale_entries(readme):
    """README 的檔案樹不殘留已刪除或型別不符的路徑（目錄必須以 `/` 結尾，一般檔案不得以 `/` 結尾）。
    The README file tree holds no deleted or wrong-kind paths (directories end in `/`, regular files do not)."""
    with open(os.path.join(REPO_ROOT, readme), encoding="utf-8") as f:
        stale = stale_tree_paths(f.read())
    assert stale == [], f"remove these stale entries from the file tree of {readme}:\n" + "\n".join(stale)


def test_stale_tree_paths_flags_missing_entries_and_kind_mismatches(tmp_path, monkeypatch):
    """完整的 checkout 裡，已刪除的檔案與目錄（含 `.github/`、存在的 prune 目錄底下，以及整個消失但仍寫在
    `MANIFEST.in` 的 prune 目錄）、沒加 `/` 的目錄、加了 `/` 的一般檔案、大小寫不同的檔名，以及缺少的
    `.pre-commit-config.yaml` 都會被列出；存在的項目不算。
    In a full checkout, deleted files and directories (under `.github/`, under a present pruned directory, and a
    pruned directory missing on disk while still named in `MANIFEST.in`), a directory without `/`, a regular file with
    `/`, a wrong-case name, and a missing `.pre-commit-config.yaml` are all listed; existing entries are not."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "tests.yml").write_text("", encoding="utf-8")
    (tmp_path / ".pre-commit-config.yaml").write_text("", encoding="utf-8")
    (tmp_path / "MANIFEST.in").write_text("prune scripts/golden\nprune scripts/gone_pruned\n", encoding="utf-8")
    (tmp_path / "scripts" / "golden").mkdir(parents=True)
    (tmp_path / "scripts" / "golden" / "run.py").write_text("", encoding="utf-8")
    (tmp_path / "scripts" / "sub").mkdir()
    (tmp_path / "vibeharness" / "core").mkdir(parents=True)
    (tmp_path / "vibeharness" / "core" / "gate.py").write_text("", encoding="utf-8")
    (tmp_path / "vibeharness" / "core" / "models.py").write_text("", encoding="utf-8")
    text = "\n".join([
        "```text", TREE_ROOT,
        "├── .github/",
        "│   └── workflows/",
        "│       ├── tests.yml",
        "│       └── old.yml",
        "├── .pre-commit-config.yaml",
        "├── scripts/",
        "│   ├── golden/",
        "│   │   ├── run.py",
        "│   │   └── old.py",
        "│   ├── gone_pruned/",
        "│   └── sub",
        "└── vibeharness/",
        "    ├── core/",
        "    │   ├── fanout.py",
        "    │   ├── gate.py",
        "    │   └── models.py/",
        "    └── legacy/",
        "```",
    ])
    manifest = tmp_path / "MANIFEST.in"
    assert stale_tree_paths(text, root=tmp_path, manifest=manifest) == [
        ".github/workflows/old.yml",
        "scripts/golden/old.py",
        "scripts/gone_pruned/",
        "scripts/sub",
        "vibeharness/core/fanout.py",
        "vibeharness/core/models.py/",
        "vibeharness/legacy/",
    ]
    (tmp_path / ".pre-commit-config.yaml").unlink()
    assert ".pre-commit-config.yaml" in stale_tree_paths(text, root=tmp_path, manifest=manifest)
    # 不分大小寫的檔案系統（macOS／Windows）上，`isfile` 對錯誤大小寫回傳 True，仍須被 `listdir` 攔下
    # On a case-insensitive filesystem (macOS / Windows), `isfile` returns True for wrong case and `listdir` still catches it
    real_isfile = os.path.isfile
    monkeypatch.setattr(os.path, "isfile", lambda p: True if str(p).endswith("Gate.py") else real_isfile(p))
    wrong_case = "\n".join(["```text", TREE_ROOT, "└── vibeharness/", "    └── core/", "        └── Gate.py", "```"])
    assert stale_tree_paths(wrong_case, root=tmp_path, manifest=manifest) == ["vibeharness/core/Gate.py"]


def test_stale_tree_paths_skips_repo_only_and_pruned_entries_in_sdist(tmp_path):
    """在解開的 sdist 裡（沒有 `.github/`，也沒有 `MANIFEST.in` prune 掉的目錄），`.github/`、`_NOT_SHIPPED`、
    被 prune 的目錄，以及因 prune 而空掉消失的上層目錄會略過，但其他不存在的路徑照樣列出；缺少 `MANIFEST.in` 時直接報錯。
    In an unpacked sdist (no `.github/`, and no directory `MANIFEST.in` prunes), `.github/`, `_NOT_SHIPPED`, pruned
    directories, and ancestor directories absent because their pruned child was omitted are skipped while other missing
    paths are still listed; a missing `MANIFEST.in` raises."""
    (tmp_path / "MANIFEST.in").write_text("prune scripts/golden\nprune dev_only/tools\n", encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "vibeharness" / "core").mkdir(parents=True)
    (tmp_path / "vibeharness" / "core" / "gate.py").write_text("", encoding="utf-8")
    text = "\n".join([
        "```text", TREE_ROOT,
        "├── .github/",
        "│   └── workflows/",
        "│       └── tests.yml",
        "├── .pre-commit-config.yaml",
        "├── dev_only/",
        "│   └── tools/",
        "├── scripts/",
        "│   └── golden/",
        "└── vibeharness/",
        "    └── core/",
        "        ├── fanout.py",
        "        └── gate.py",
        "```",
    ])
    assert stale_tree_paths(text, root=tmp_path, manifest=tmp_path / "MANIFEST.in") == ["vibeharness/core/fanout.py"]
    with pytest.raises(FileNotFoundError):
        stale_tree_paths(text, root=tmp_path, manifest=tmp_path / "missing.in")


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


def _file_exists(span, pruned):
    in_sdist = not os.path.isdir(os.path.join(REPO_ROOT, ".github"))
    if in_sdist and _unshipped_in_sdist(span):
        return True
    if "/" in span:
        # sdist 也不帶 MANIFEST.in prune 掉的目錄（例如只供開發用的 scripts/golden/）
        # Nor does it ship the directories MANIFEST.in prunes (such as the development-only scripts/golden/)
        if _under_absent_pruned(span, REPO_ROOT, pruned):
            return True
        return bool(glob.glob(os.path.join(REPO_ROOT, span)))
    if any(glob.glob(os.path.join(REPO_ROOT, d, span)) for d in _FILE_DIRS):
        return True
    # sdist 不帶 .github/：只寫檔名的 workflow 在那裡無法核對 ／ The sdist has no .github/: a bare workflow name cannot be checked there
    return in_sdist and span.endswith((".yml", ".yaml"))


def stale_citations(text, names, literals, manifest=MANIFEST):
    """一份規則文件裡指向不存在的檔案或定義的反引號片段。檔案以路徑（可含 glob）找；看起來像程式碼的名稱
    （底線開頭、`()` 結尾、snake_case 或駝峰式）必須在 vibeharness／scripts／tests 有定義，設定鍵可以只是字串。
    The backticked spans of a rule document that point at a missing file or definition. Files are looked up by
    path (globs allowed); a code-looking name (leading underscore, `()`, snake_case or CamelCase) must be defined in
    vibeharness / scripts / tests, while a config key may be just a string."""
    pruned = pruned_dirs(manifest)
    known = names | set(dir(builtins)) | set(keyword.kwlist)
    stale = []
    for span in dict.fromkeys(_SPAN_RE.findall(text)):
        if _FILE_RE.match(span) and " " not in span:
            if not _file_exists(span, pruned):
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


def test_pruned_dirs_lists_every_prune_line_of_the_manifest_and_nothing_else(tmp_path):
    """MANIFEST.in 裡每一條 prune 的目錄都讀出來，依出現順序；註解與其他指令（include、recursive-include）不算。
    Every directory a MANIFEST.in prunes is read, in order; comments and other commands (include,
    recursive-include) are not."""
    manifest = tmp_path / "MANIFEST.in"
    manifest.write_text("# prune docs/commented-out\n"
                        "include README.md\n"
                        "prune scripts/golden\n"
                        "recursive-include tests *.py\n"
                        "prune docs/drafts\n", encoding="utf-8")
    assert pruned_dirs(manifest) == ["scripts/golden", "docs/drafts"]


def test_pruned_dirs_reads_indented_tab_separated_and_slash_ended_prune_lines(tmp_path):
    """行首縮排、prune 後接 tab、目錄以 `/` 結尾的寫法都讀得出來，目錄不帶結尾的 `/`：否則 `prune scripts/golden/`
    比對不到任何路徑，檢查會悄悄失效。
    Indented lines, a tab after prune and a directory ending in `/` are all read, without the trailing `/`:
    otherwise `prune scripts/golden/` matches no path and the check silently stops working."""
    manifest = tmp_path / "MANIFEST.in"
    manifest.write_text("  prune docs/indented\n"
                        "prune\tdocs/tabbed\n"
                        "prune scripts/golden/\n", encoding="utf-8")
    assert pruned_dirs(manifest) == ["docs/indented", "docs/tabbed", "scripts/golden"]


def test_stale_citations_skips_a_path_under_a_pruned_dir_the_checkout_lacks(tmp_path):
    """MANIFEST.in prune 掉、而且這份 checkout 裡沒有的目錄（在 sdist 裡跑的情況），底下的路徑無法核對，不算過時；
    其他不存在的路徑照樣算。
    A path under a directory MANIFEST.in prunes and this checkout lacks (as when run from the sdist) cannot be
    checked, so it is not stale; other missing paths still are."""
    manifest = tmp_path / "MANIFEST.in"
    manifest.write_text("prune docs/pruned-away\n", encoding="utf-8")
    text = "`docs/pruned-away/notes.md` `docs/missing.md`"
    assert stale_citations(text, set(), set(), manifest=manifest) == ["docs/missing.md"]


def test_stale_citations_still_flags_a_missing_path_under_a_pruned_dir_the_checkout_has(tmp_path):
    """MANIFEST.in prune 掉、但這份 checkout 裡還有的目錄（在 repo 裡跑的情況）照樣核對：底下不存在的路徑算過時。
    A directory MANIFEST.in prunes but this checkout has (as when run from the repo) is still checked: a missing
    path under it is stale."""
    manifest = tmp_path / "MANIFEST.in"
    manifest.write_text("prune docs\n", encoding="utf-8")
    assert stale_citations("`docs/no-such-file.md`", set(), set(), manifest=manifest) == ["docs/no-such-file.md"]


def test_stale_citations_fails_loudly_when_the_manifest_is_missing(tmp_path):
    """MANIFEST.in 不見時直接出錯，即使文件沒有引用任何路徑：sdist 一定帶著它，不見了表示打包壞了。
    A missing MANIFEST.in raises even when the document cites no path: the sdist always ships it, so its absence
    means the packaging broke."""
    with pytest.raises(FileNotFoundError):
        stale_citations("`README.md`", set(), set(), manifest=tmp_path / "MANIFEST.in")


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
