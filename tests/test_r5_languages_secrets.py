"""第五輪：不支援語言的原始碼檔案不再被默默丟掉（記錄為證據缺口，判定不能是 READY_TO_SHIP），以及設定類檔案
（.env、YAML、JSON、TOML、Dockerfile、Terraform …）的本機確定性密鑰掃描（VH-AI-007），且這些檔案絕不送給模型。
Round five: source files in unsupported languages are no longer silently dropped (they are recorded as an evidence
gap, so the verdict cannot be READY_TO_SHIP), and configuration-like files (.env, YAML, JSON, TOML, Dockerfile,
Terraform ...) get a local, deterministic secret scan (VH-AI-007) and are never sent to a model."""
import json
import os

import pytest

from vibeharness.agents.whitebox import ai_static_scanner
from vibeharness.agents.whitebox.ai_static_scanner import AISecurityStaticScanner
from vibeharness.agents.whitebox.ast_extractor import UNSUPPORTED_SAMPLE_SIZE, ASTExtractor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REPO_ROOT, "vibeharness", "config", "agents_config.yaml")
# 執行時才組出看起來像真的金鑰，原始檔裡沒有完整的金鑰字面值
# The real-looking keys are assembled at run time, so no complete key literal sits in this source file
ANTHROPIC_KEY = "sk-ant-" + "api03-" + "Zq7Xw2Lm9Pv4Rt8Ks1Hd6Jf3"
AWS_KEY = "AKIA" + "Z7Q2M4X9W3R8T6Y1"


def _write(root, rel, text=""):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- 不支援的語言 ／ Unsupported languages -------------------------------------------------------------

def test_unsupported_source_files_are_counted_per_language_with_the_same_walk_rules(tmp_path):
    for rel in ("cmd/main.go", "pkg/util.go", "pkg/util_test.go", "src/App.java", "app.py"):
        _write(tmp_path, rel, "x = 1\n" if rel.endswith(".py") else "package main\n")
    # 略過的目錄、隱藏目錄與非原始碼檔案都不算 ／ skipped dirs, hidden dirs and non-source files do not count
    for rel in ("node_modules/dep/x.go", "build/y.go", ".git/hooks/z.go", "README.md", "logo.png",
                "go.sum", "go.mod", "Cargo.lock", "notes.txt", "run.sh", "schema.sql"):
        _write(tmp_path, rel, "data\n")
    ex = ASTExtractor()
    ex.parse_directory(str(tmp_path))
    assert ex.unsupported_count == 4
    assert ex.unsupported_languages == {"go": 3, "java": 1}
    assert sorted(os.path.basename(p) for p in ex.unsupported_files) == ["App.java", "main.go", "util.go", "util_test.go"]
    assert [os.path.basename(p) for p in ex.analyzed_files] == ["app.py"]


def test_unsupported_files_respect_include_exclude_and_only_files(tmp_path):
    keep = _write(tmp_path, "svc/a.go", "package a\n")
    _write(tmp_path, "legacy/b.go", "package b\n")
    _write(tmp_path, "svc/c.rs", "fn main() {}\n")
    ex = ASTExtractor()
    ex.parse_directory(str(tmp_path), exclude=["legacy/"])
    assert ex.unsupported_languages == {"go": 1, "rust": 1}
    ex.parse_directory(str(tmp_path), include=["*.go"])
    assert ex.unsupported_languages == {"go": 2}
    ex.parse_directory(str(tmp_path), only_files=[str(keep)])
    assert ex.unsupported_count == 1 and ex.unsupported_files == [str(keep)]
    # include/exclude 排除的不是證據缺口，也不計入 filtered_out（那是指受支援的原始碼）
    # Files left out by include/exclude are not a gap and do not count as filtered_out (that is supported source)
    assert ex.filtered_out == 0


def test_the_unsupported_sample_is_capped_but_the_count_is_not(tmp_path):
    for i in range(UNSUPPORTED_SAMPLE_SIZE + 5):
        _write(tmp_path, f"f{i:02d}.kt", "fun main() {}\n")
    ex = ASTExtractor()
    ex.parse_directory(str(tmp_path), max_files=1)
    assert ex.unsupported_count == UNSUPPORTED_SAMPLE_SIZE + 5
    assert len(ex.unsupported_files) == UNSUPPORTED_SAMPLE_SIZE
    assert ex.unsupported_languages == {"kotlin": UNSUPPORTED_SAMPLE_SIZE + 5}


def test_a_single_file_target_in_an_unsupported_language_is_recorded(tmp_path):
    target = _write(tmp_path, "main.go", "package main\n")
    ex = ASTExtractor()
    assert ex.parse_directory(str(target)) == []
    assert ex.unsupported_count == 1 and ex.unsupported_languages == {"go": 1}


def test_a_new_walk_resets_the_unsupported_and_config_state(tmp_path):
    _write(tmp_path, "a/main.go", "package main\n")
    _write(tmp_path, "a/.env", "X=1\n")
    _write(tmp_path, "b/app.py", "x = 1\n")
    ex = ASTExtractor()
    ex.parse_directory(str(tmp_path / "a"))
    assert ex.unsupported_count == 1 and len(ex.config_files) == 1
    ex.parse_directory(str(tmp_path / "b"))
    assert ex.unsupported_count == 0 and ex.unsupported_languages == {} and ex.config_files == []


def test_scan_directory_returns_the_walk_scope_as_an_immutable_value(tmp_path):
    """scan_directory 回傳這次走訪的範圍：分析的檔案、超過大小的、不支援語言的、設定類檔案與偵測到的語言；
    它是不可變的值（欄位不能重新指定，語言計數也唯讀）。
    scan_directory returns this walk's scope: the analyzed files, the oversized ones, the unsupported ones, the
    configuration-like files and the languages detected; it is an immutable value (fields cannot be reassigned and
    the language counts are read-only)."""
    import dataclasses
    app = _write(tmp_path, "a/app.py", "def f():\n    return 1\n")
    big = _write(tmp_path, "a/big.py", "x = 1\n" * 400)
    _write(tmp_path, "a/main.go", "package main\n")
    env = _write(tmp_path, "a/.env", "X=1\n")
    ex = ASTExtractor()
    symbols, scope = ex.scan_directory(str(tmp_path / "a"), max_file_bytes=1000)
    assert [s.name for s in symbols] == ["f"]
    assert scope.analyzed_files == (str(app),) and scope.oversized_files == (str(big),)
    assert (scope.unsupported_count, dict(scope.unsupported_languages)) == (1, {"go": 1})
    assert scope.config_files == (str(env),) and scope.detected_languages == ("Python",)
    assert scope.filters == ()  # 篩選條件由 harness 填 ／ the harness fills in the filters
    with pytest.raises(dataclasses.FrozenInstanceError):
        scope.analyzed_files = ()
    with pytest.raises(TypeError):
        scope.unsupported_languages["go"] = 2


def test_detected_languages_belong_to_one_walk(tmp_path):
    """同一個擷取器走訪兩個目標時，第二次的語言只來自第二個目標（過去會累積上一次的語言）。
    When one extractor walks two targets, the second walk's languages come from the second target only (they used
    to accumulate the previous walk's)."""
    _write(tmp_path, "js/ui.js", "function g() { return 2 }\n")
    _write(tmp_path, "py/app.py", "def f():\n    return 1\n")
    ex = ASTExtractor()
    assert ex.scan_directory(str(tmp_path / "js"))[1].detected_languages == ("TypeScript/JavaScript",)
    assert ex.scan_directory(str(tmp_path / "py"))[1].detected_languages == ("Python",)


def test_select_symbols_returns_the_scope_with_the_filters_applied(tmp_path):
    """harness 的 select_symbols 回傳的範圍帶著它套用的篩選條件描述，--estimate 與報告都從這裡讀。
    The harness's select_symbols returns the scope with a description of the filters it applied, which --estimate
    and the report read."""
    from vibeharness.core.harness import VibeHarnessCommander
    _write(tmp_path, "keep.py", "def f():\n    return 1\n")
    _write(tmp_path, "skip.py", "def g():\n    return 2\n")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    commander.exclude_patterns = ["skip.py"]
    symbols, scope = commander.select_symbols(str(tmp_path))
    assert [s.name for s in symbols] == ["f"] and scope.filtered_out == 1
    assert scope.filters == ("exclude=skip.py",) and scope.analyzed_files == (str(tmp_path / "keep.py"),)


def test_a_run_keeps_the_scope_phase_1_selected(tmp_path):
    """一次 mock 執行之後，commander.scope 就是第 1 階段選定的範圍（延遲建立的 Node 沙盒讀它判斷有沒有 TypeScript）。
    After a mock run, commander.scope is the scope phase 1 selected (the lazily built Node sandbox reads it to tell
    whether there is TypeScript)."""
    from vibeharness.core.harness import VibeHarnessCommander
    _write(tmp_path, "t/ui.ts", "export function g(x: number): number { return x }\n")
    commander = VibeHarnessCommander(config_path=CONFIG, execution_mode="mock")
    assert commander.scope is None
    commander.run_full_pipeline(str(tmp_path / "t"), output_report_path=str(tmp_path / "r.md"))
    assert commander.scope == commander.select_symbols(str(tmp_path / "t"))[1]
    assert commander.scope.analyzed_files == (str(tmp_path / "t" / "ui.ts"),)


# --- 設定類檔案的選取 ／ Selecting configuration-like files --------------------------------------------

def test_config_like_files_are_selected_and_lockfiles_are_not(tmp_path):
    wanted = [".env", ".env.production", ".env.example", "config.yaml", "docker-compose.override.yml",
              "settings.json", "pyproject.toml", "setup.cfg", "app.ini", "app.properties", "Dockerfile",
              "api.Dockerfile", "main.tf", "prod.tfvars", ".npmrc", ".pypirc", ".netrc"]
    ignored = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
               "README.md", ".gitignore", ".editorconfig", "logo.svg", "node_modules/pkg/config.json",
               ".github/workflows/ci.yml"]
    for rel in wanted + ignored:
        _write(tmp_path, rel, "k = v\n")
    ex = ASTExtractor()
    ex.parse_directory(str(tmp_path))
    assert sorted(os.path.basename(p) for p in ex.config_files) == sorted(wanted)
    assert ex.unsupported_count == 0 and ex.analyzed_files == []


def test_config_files_respect_the_count_cap_size_limit_and_filters(tmp_path):
    for name in ("a.yaml", "b.yaml", "c.yaml"):
        _write(tmp_path, name, "k: v\n")
    _write(tmp_path, "big.json", "{" + " " * 300 + "}")
    _write(tmp_path, "skip/d.yaml", "k: v\n")
    ex = ASTExtractor()
    ex.parse_directory(str(tmp_path), max_config_files=2, max_file_bytes=100, exclude=["skip/*"])
    assert [os.path.basename(p) for p in ex.config_files] == ["a.yaml", "b.yaml"]
    assert [os.path.basename(p) for p in ex.skipped_config_files] == ["c.yaml"]
    assert [os.path.basename(p) for p in ex.oversized_config_files] == ["big.json"]


# --- 設定類檔案的密鑰掃描 ／ Secret scan of configuration-like files ------------------------------------

def test_a_real_looking_key_in_dotenv_is_reported_with_its_line(tmp_path):
    env = _write(tmp_path, ".env", f"# local settings\nDEBUG=1\nANTHROPIC_API_KEY={ANTHROPIC_KEY}\n"
                                   f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    found = AISecurityStaticScanner().scan_config_files([str(env)])
    assert [(f.rule_id, f.line_number) for f in found] == [("VH-AI-007", 3), ("VH-AI-007", 4)]
    assert all(f.file_path == str(env) and f.severity.value == "HIGH" for f in found)
    # 證據絕不含值本身 ／ The evidence never holds the value itself
    assert all(ANTHROPIC_KEY not in f.evidence and AWS_KEY not in f.evidence for f in found)


BENIGN_YAML = """\
# 範例設定 ／ example configuration
llm:
  api_key: ${ANTHROPIC_API_KEY}
  model: claude-sonnet
  openai_key: "<your-openai-key>"
database:
  url: postgres://postgres:postgres@db:5432/app
  local: mysql://root:secret@localhost:3306/dev
  template: postgresql://user:${DB_PASSWORD}@prod-db.internal/app
  masked: redis://:****@cache.example.com:6379
secret_key: changeme
token: xxxxxxxxxxxxxxxx
docs: https://example.com/docs#auth:token@section
"""


def test_docs_and_example_like_yaml_does_not_false_positive(tmp_path):
    files = [_write(tmp_path, "config.example.yaml", BENIGN_YAML), _write(tmp_path, ".env.example", (
        "ANTHROPIC_API_KEY=\nOPENAI_API_KEY=sk-your-key-here\nDATABASE_URL=postgres://app:app@localhost/app\n"))]
    scanner = AISecurityStaticScanner()
    assert scanner.scan_config_files([str(p) for p in files]) == []
    assert scanner.incomplete_config_files == []


def test_the_repository_own_config_files_are_clean():
    """自家試用：本儲存庫自己的 YAML/TOML 設定檔（含範例設定）不得被讀成寫死的憑證。
    Dogfooding: this repository's own YAML/TOML configuration (example configs included) must not read as
    hard-coded credentials."""
    ex = ASTExtractor()
    ex.parse_directory(REPO_ROOT, max_files=1)
    assert any(p.endswith("agents_config.yaml") for p in ex.config_files)
    found = AISecurityStaticScanner().scan_config_files(ex.config_files)
    assert found == [], [(os.path.relpath(f.file_path, REPO_ROOT), f.line_number) for f in found]


def test_chunking_keeps_line_numbers_and_never_splits_a_private_key(tmp_path, monkeypatch):
    monkeypatch.setattr(ai_static_scanner, "_CONFIG_SCAN_CHUNK_CHARS", 32)
    key = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(["MIIEow" + "A" * 58] * 6) + "\n-----END RSA PRIVATE KEY-----\n"
    text = "a: 1\n" * 20 + f"key: {AWS_KEY}\n" + "b: 2\n" * 3 + key + "c: 3\n" * 10 + f"other: {AWS_KEY}\n"
    path = _write(tmp_path, "secrets.yaml", text)
    found = AISecurityStaticScanner().scan_config_files([str(path)])
    lines = text.splitlines()
    expected = sorted([21, 25, lines.index(f"other: {AWS_KEY}") + 1])
    assert [f.line_number for f in found] == expected
    assert sorted(f.evidence.split()[0] for f in found) == ["aws-access-key", "aws-access-key", "private-key"]


def test_the_per_file_time_cap_keeps_earlier_hits_and_marks_the_file_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(ai_static_scanner, "_CONFIG_SCAN_CHUNK_CHARS", 16)
    monkeypatch.setattr(ai_static_scanner, "_MAX_SCAN_SECONDS_PER_FILE", 0.0)
    path = _write(tmp_path, "app.ini", f"key={AWS_KEY}\n" + "x=1\n" * 50 + f"late={AWS_KEY}\n")
    scanner = AISecurityStaticScanner()
    found = scanner.scan_config_files([str(path)])
    assert [f.line_number for f in found] == [1]
    assert scanner.incomplete_config_files == [str(path)]


def test_an_unreadable_config_file_is_marked_incomplete(tmp_path):
    scanner = AISecurityStaticScanner()
    assert scanner.scan_config_files([str(tmp_path / "missing.yaml")]) == []
    assert scanner.incomplete_config_files == [str(tmp_path / "missing.yaml")]


# --- 端對端 ／ End to end ------------------------------------------------------------------------------

def _target(tmp_path):
    target = tmp_path / "target"
    _write(target, "app.py", "def add(a, b):\n    return a + b\n")
    _write(target, "svc/main.go", "package main\n\nfunc main() {}\n")
    _write(target, ".env", f"APP_ENV=prod\nANTHROPIC_API_KEY={ANTHROPIC_KEY}\n")
    _write(target, "deploy/values.yaml", BENIGN_YAML)
    return target


def test_go_file_and_dotenv_key_block_ready_to_ship_and_reach_sarif(tmp_path):
    from vibeharness.core.harness import VibeHarnessCommander
    target = _target(tmp_path)
    sarif_path = tmp_path / "r.sarif"
    summary = VibeHarnessCommander(CONFIG, execution_mode="mock").run_full_pipeline(
        str(target), output_report_path=str(tmp_path / "r.md"), output_sarif_path=str(sarif_path))
    assert summary.overall_status != "READY_TO_SHIP"
    assert [(f.rule_id, os.path.basename(f.file_path), f.line_number) for f in summary.static_findings] == [
        ("VH-AI-007", ".env", 2)]
    assert any("1 source file(s) in unsupported languages (go: 1) were not analyzed" in r and "main.go" in r
               for r in summary.inconclusive_reasons)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    hits = [r for r in sarif["runs"][0]["results"] if r["ruleId"].endswith("VH-AI-007")]
    assert len(hits) == 1
    location = hits[0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == ".env" and location["region"]["startLine"] == 2
    assert ANTHROPIC_KEY not in sarif_path.read_text(encoding="utf-8")
    assert ANTHROPIC_KEY not in (tmp_path / "r.md").read_text(encoding="utf-8")


def test_config_and_unsupported_files_are_never_sent_to_a_model(tmp_path, fake_live):
    from vibeharness.core.harness import VibeHarnessCommander
    target = _target(tmp_path)
    prompts = []

    def responder(system, user):
        prompts.append(system + "\n" + user)
        return "{}"

    fake_live(responder)
    VibeHarnessCommander(CONFIG, execution_mode="live").run_full_pipeline(
        str(target), base_url="http://localhost:59999", output_report_path=str(tmp_path / "r.md"))
    assert prompts
    joined = "\n".join(prompts)
    assert ANTHROPIC_KEY not in joined and "APP_ENV=prod" not in joined
    assert "func main()" not in joined and "prod-db.internal" not in joined


@pytest.mark.parametrize("name", [".env", "prod.env", "Dockerfile"])
def test_a_single_config_file_target_is_scanned(tmp_path, name):
    target = _write(tmp_path, name, f"ENV TOKEN={AWS_KEY}\n")
    ex = ASTExtractor()
    ex.parse_directory(str(target))
    assert ex.config_files == [str(target)]
    assert [f.line_number for f in AISecurityStaticScanner().scan_config_files(ex.config_files)] == [1]
