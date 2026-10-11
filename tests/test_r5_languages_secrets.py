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


def test_unsupported_files_alone_keep_the_verdict_off_ready_to_ship(tmp_path):
    from vibeharness.core.harness import VibeHarnessCommander
    target = tmp_path / "t"
    _write(target, "app.py", "def add(a, b):\n    return a + b\n")
    for rel in ("a.go", "b.go", "c.java"):
        _write(target, rel, "class X {}\n")
    summary = VibeHarnessCommander(CONFIG, execution_mode="mock").run_full_pipeline(
        str(target), output_report_path=str(tmp_path / "r.md"))
    assert summary.overall_status != "READY_TO_SHIP"
    gap = next(r for r in summary.inconclusive_reasons if "unsupported languages" in r)
    assert "3 source file(s) in unsupported languages (go: 2, java: 1)" in gap and "不支援語言" in gap


def test_truncated_config_scan_is_an_evidence_gap(tmp_path, monkeypatch):
    from vibeharness.core.harness import VibeHarnessCommander
    # max_config_files 是最後一個預設參數：改成 1 ／ max_config_files is the last default argument: make it 1
    defaults = list(ASTExtractor.parse_directory.__defaults__)
    monkeypatch.setattr(ASTExtractor.parse_directory, "__defaults__", tuple(defaults[:-1] + [1]))
    target = tmp_path / "t"
    _write(target, "app.py", "def add(a, b):\n    return a + b\n")
    _write(target, "a.yaml", "k: v\n")
    _write(target, "b.yaml", "k: v\n")
    summary = VibeHarnessCommander(CONFIG, execution_mode="mock").run_full_pipeline(
        str(target), output_report_path=str(tmp_path / "r.md"))
    assert any("1 configuration-like file(s) were not fully secret-scanned" in r for r in summary.inconclusive_reasons)


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
