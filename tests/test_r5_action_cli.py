"""第五輪審查的回歸測試：GitHub Action 的判定只取自稽核摘要、extra-args 以 CLI 自己的解析器檢查（拒絕不執行稽核的旗標、
認得合併的短旗標 --config）、docker 沙盒也涵蓋 JS／TS 測試、report／sarif outputs 只指向實際寫出的檔案，
以及 CLI 的 --init-config 不跟隨符號連結、在無法編碼雙語文字的 stdout 上也不會當掉。
Regression tests from the fifth review round: the GitHub Action takes its verdict from the audit summary only,
extra-args are checked with the CLI's own parser (non-audit flags are refused, a --config in combined short flags is
recognized), the docker sandbox covers JS / TS tests too, the report / sarif outputs only point at files actually
written, and the CLI's --init-config never follows symlinks and does not crash on a stdout that cannot encode the
bilingual text."""
import json
import os
import shutil
import subprocess
import sys

import pytest
import yaml

from vibeharness import action_runner, cli
from vibeharness.core.llm_gateway import DEFAULT_CONFIG_PATH
from vibeharness.core.verdict import Verdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SMALL_TARGET = os.path.join(REPO_ROOT, "vibeharness", "core", "i18n.py")
_BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(_BASH is None or sys.platform == "win32", reason="bash unavailable")


def _action():
    with open(os.path.join(REPO_ROOT, "action.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _step(step_id):
    return next(s for s in _action()["runs"]["steps"] if s.get("id") == step_id)


def _env(tmp_path, **extra):
    """在 tmp_path 執行 runner／CLI 子行程的環境：從工作樹匯入 ／ The environment for runner / CLI subprocesses in
    tmp_path: imports come from the working tree."""
    env = {**os.environ, "PYTHONPATH": REPO_ROOT, "RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(tmp_path / "out"),
           "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"), "VH_FAIL_ON": "needs-fixes"}
    env.pop("PYTHONIOENCODING", None)
    env.update(extra)
    return env


def _outputs(tmp_path):
    path = tmp_path / "out"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    return dict(line.split("=", 1) for line in lines)


def _run_cli(monkeypatch, *argv):
    """以指定參數在同一個行程內執行 CLI，回傳結束碼 ／ Runs the CLI in-process with the arguments; returns the exit code."""
    monkeypatch.setattr(sys, "argv", ["vibeharness", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return exit_info.value.code


# --- 1. 判定只取自稽核摘要；不執行稽核的旗標被拒絕 -------------------------------------------------------
# --- 1. The verdict comes from the audit summary only; non-audit flags are refused --------------------------

@pytest.mark.parametrize("extra", [["--estimate"], ["--help"], ["-h"], ["-vh"], ["--version"], ["--init-config"],
                                   ["--init-config", "x.yaml", "--force"], ["--summary-json", "s.json"]])
def test_runner_refuses_non_audit_flags_before_running(monkeypatch, tmp_path, capsys, extra):
    """重現：--estimate 等讓 CLI 不稽核就以 0 結束，job 以 READY_TO_SHIP 通過。現在 runner 不執行 CLI，verdict=ERROR、exit 5。
    Reproduction: --estimate and friends made the CLI exit 0 without an audit, so the job passed as READY_TO_SHIP.
    Now the runner does not run the CLI: verdict=ERROR, exit 5."""
    monkeypatch.setattr(action_runner, "run_cli", lambda argv: pytest.fail("the CLI must not run"))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out"))
    monkeypatch.setenv("VH_FAIL_ON", "needs-fixes")
    assert action_runner.main(["--target", ".", *extra]) == 5
    assert _outputs(tmp_path) == {"verdict": "ERROR", "exit-code": "5", "report": "", "sarif": ""}
    assert "::error::" in capsys.readouterr().out


@pytest.mark.parametrize("summary", [None, {"tool": "vibeharness", "exit_code": 1}, {"exit_code": 0}, ["not", "a dict"]])
def test_a_verdict_code_without_a_matching_audit_summary_is_an_error(monkeypatch, tmp_path, capsys, summary):
    """CLI 以 0 結束卻沒有寫出對應的稽核摘要（或摘要不符）：verdict=ERROR、exit 5，絕不是 READY_TO_SHIP。
    The CLI exits 0 without writing a matching audit summary (or a mismatching one): verdict=ERROR, exit 5, never
    READY_TO_SHIP."""
    def fake_cli(argv):
        if summary is not None:
            with open(argv[argv.index("--summary-json") + 1], "w", encoding="utf-8") as f:
                json.dump(summary, f)
        return 0

    monkeypatch.setattr(action_runner, "run_cli", fake_cli)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "r.md").write_text("stale report from the checkout\n", encoding="utf-8")
    for name, value in {"RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(tmp_path / "out"), "VH_FAIL_ON": "never",
                        "VH_OUTPUT": "r.md", "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md")}.items():
        monkeypatch.setenv(name, value)
    assert action_runner.main(["--target", "."]) == 5
    assert _outputs(tmp_path) == {"verdict": "ERROR", "exit-code": "5", "report": "", "sarif": ""}
    out = capsys.readouterr().out
    assert "without writing a matching audit summary" in out and "non-audit flags" in out
    assert "No report was written" in (tmp_path / "summary.md").read_text(encoding="utf-8")


def test_the_real_runner_refuses_estimate_and_reports_a_real_audit(tmp_path):
    """端到端：--estimate 以 exit 5 拒絕；真正的 mock 稽核得到判定，report output 指向寫出的報告。
    End to end: --estimate is refused with exit 5; a real mock audit gets a verdict and the report output points at
    the written report."""
    base = ["-m", "vibeharness.action_runner", "-m", "mock", "-t", SMALL_TARGET, "-o", "r.md"]
    out = subprocess.run([sys.executable, *base, "--estimate"], cwd=tmp_path, capture_output=True, text=True,
                         encoding="utf-8", env=_env(tmp_path, VH_OUTPUT="r.md"))
    assert out.returncode == 5 and _outputs(tmp_path)["verdict"] == "ERROR"
    assert not (tmp_path / "vibeharness.yaml").exists()
    (tmp_path / "out").unlink()
    out = subprocess.run([sys.executable, *base], cwd=tmp_path, capture_output=True, text=True, encoding="utf-8",
                         env=_env(tmp_path, VH_OUTPUT="r.md", VH_SARIF="none.sarif", VH_FAIL_ON="never"))
    assert out.returncode == 0, out.stdout + out.stderr
    outputs = _outputs(tmp_path)
    assert Verdict.parse(outputs["verdict"]) is not None
    assert outputs["report"] == "r.md" and (tmp_path / "r.md").is_file()
    # 沒有傳 --sarif 給 CLI：檔案不存在，output 為空 ／ No --sarif was passed to the CLI: no file, so an empty output
    assert outputs["sarif"] == ""


# --- 1 / 2. extra-args 以 CLI 自己的解析器檢查 ------------------------------------------------------------
# --- 1 / 2. extra-args are checked with the CLI's own parser ----------------------------------------------

@pytest.mark.parametrize("extra,config", [
    ([], None), (["--exclude", "x"], None), (["-c", "a.yaml"], "a.yaml"), (["--config=a.yaml"], "a.yaml"),
    (["-ca.yaml"], "a.yaml"), (["-vc", "my.yaml"], "my.yaml"), (["-vcmy.yaml"], "my.yaml"),
    (["-c", "a.yaml", "--config", "b.yaml"], "b.yaml"),
])
def test_check_extra_args_finds_the_config_the_cli_would_use(extra, config):
    """重現：bash 的樣式比對認不得 `-vc my.yaml`／`-vcmy.yaml`，使用者的設定檔被內建設定檔悄悄取代。
    Reproduction: bash pattern matching missed `-vc my.yaml` / `-vcmy.yaml`, silently replacing the user's config
    with the bundled one."""
    assert action_runner.check_extra_args(extra) == (config, [])
    assert action_runner.config_from_extra_args(extra) == config


@pytest.mark.parametrize("extra,needle", [
    (["--estimate"], "--estimate"), (["-vh"], "--help/-h"), (["--version"], "--version"),
    (["--init-config"], "--init-config"), (["--summary-json", "x"], "--summary-json"),
    (["-o", "x.md"], "--output/-o"), (["--format", "json"], "--format/-f"), (["--sarif", "x.sarif"], "--sarif"),
    (["--no-such-flag"], "not valid vibeharness arguments"), (["--max-files", "many"], "not valid vibeharness arguments"),
])
def test_check_extra_args_refuses_bad_flags(extra, needle):
    """不執行稽核的旗標、有專屬 input 的旗標與無法解析的參數都是錯誤 ／ Non-audit flags, flags with a dedicated input
    and unparsable arguments are errors."""
    _, errors = action_runner.check_extra_args(extra)
    assert errors and needle in " ".join(errors)


def test_inspection_parsing_has_no_side_effects(capsys):
    """parse_args_for_inspection：--help／--version 不印出也不結束，命名空間只含給出的參數。
    parse_args_for_inspection: --help / --version neither print nor exit, the namespace holds only the given arguments."""
    assert vars(cli.parse_args_for_inspection([])) == {}
    assert vars(cli.parse_args_for_inspection(["-vh", "--version"])) == {"verbose": True, "help": True, "version": True}
    assert capsys.readouterr().out == ""
    with pytest.raises(ValueError):
        cli.parse_args_for_inspection(["--conf", "x"])


def _audit_config_block(tmp_path):
    """audit step 從切字到決定 config_override 的那一段，python 改用目前的直譯器（PYTHONPATH 指向工作樹）。
    The audit step from the split up to choosing config_override, with python replaced by the current interpreter
    (PYTHONPATH points at the working tree)."""
    lines = _step("audit")["run"].splitlines()
    begin = next(i for i, line in enumerate(lines) if "extra-args-split-begin" in line)
    end = next(i for i, line in enumerate(lines) if line.strip().startswith('case "$VH_SANDBOX" in'))
    block = "\n".join(lines[begin:end])
    block = block.replace("python -I -c", f'"{sys.executable}" -c').replace("python -c", f'"{sys.executable}" -c')
    return block + '\necho "has_config=$has_config"\n'


@needs_bash
@pytest.mark.parametrize("extra,code,has_config", [
    ("--exclude 'tests/*'", 0, "0"), ("-vc my.yaml", 0, "1"), ("-vcmy.yaml", 0, "1"), ("--config=x.yaml", 0, "1"),
    ("--estimate", 5, None), ("-vh", 5, None), ("--init-config", 5, None), ("--output other.md", 5, None),
])
def test_the_audit_step_checks_extra_args_with_the_cli_parser(tmp_path, extra, code, has_config):
    """audit step：合併的短旗標 --config 也算 has_config；不執行稽核的旗標以 ::error:: exit 5，不建立任何檔案。
    The audit step: a --config in combined short flags counts for has_config; non-audit flags exit 5 with ::error::
    and create no file."""
    out = subprocess.run([_BASH, "-c", _audit_config_block(tmp_path)], cwd=tmp_path, capture_output=True, text=True,
                         encoding="utf-8", env=_env(tmp_path, VH_EXTRA=extra))
    assert out.returncode == code, out.stdout + out.stderr
    if code:
        assert "::error::" in out.stdout and not (tmp_path / "vibeharness.yaml").exists()
    else:
        assert f"has_config={has_config}" in out.stdout


def test_the_audit_step_no_longer_pattern_matches_config_flags():
    """audit step 不再以 bash 樣式比對 --config，docker 片段也改用 CLI 的解析器 ／ The audit step no longer pattern-matches
    --config in bash, and the docker snippet uses the CLI's parser too."""
    script = _step("audit")["run"]
    assert "-c?*" not in script and 'arg.startswith("-c")' not in script
    assert "extra_args_main" in script and "config_from_extra_args" in script


# --- 3. docker 沙盒也涵蓋 JS／TS 測試 ---------------------------------------------------------------------
# --- 3. The docker sandbox covers JS / TS tests too ---------------------------------------------------------

def _sandbox_config_snippet():
    script = _step("audit")["run"]
    body = script.split("<<'PY'", 1)[1].split("\nPY\n", 1)[0]
    return body.split("\n", 1)[1]


@pytest.mark.parametrize("extra", [["-vc", "{base}"], ["-vc{base}"], ["--config", "{base}"]])
def test_docker_config_copy_moves_js_tests_into_docker_too(tmp_path, extra):
    """重現：底稿的 sandbox_node_provider: local_subprocess 讓 JS 測試留在 runner 上；覆本現在兩者都設為 docker，
    合併短旗標的 --config 也被當成底稿。
    Reproduction: a base's sandbox_node_provider: local_subprocess kept JS tests on the runner; the copy now sets both
    to docker, and a --config in combined short flags is used as the base."""
    base = tmp_path / "custom.yaml"
    base.write_text("global:\n  max_files: 7\n  sandbox_node_provider: local_subprocess\n", encoding="utf-8")
    script = tmp_path / "snippet.py"
    script.write_text(_sandbox_config_snippet(), encoding="utf-8")
    args_file = tmp_path / "args"
    args_file.write_text("".join(a.format(base=base) + "\0" for a in extra), encoding="utf-8")
    out = tmp_path / "out.yaml"
    subprocess.run([sys.executable, str(script), str(args_file), str(out)], check=True, env=_env(tmp_path),
                   capture_output=True, text=True, cwd=str(tmp_path))
    config = yaml.safe_load(out.read_text(encoding="utf-8"))["global"]
    assert config["sandbox_provider"] == "docker" and config["sandbox_node_provider"] == "docker"
    assert config["max_files"] == 7


def test_sandbox_input_documents_the_node_provider():
    """sandbox input 的說明提到 sandbox_node_provider ／ The sandbox input's description mentions sandbox_node_provider."""
    assert "sandbox_node_provider: docker" in _action()["inputs"]["sandbox"]["description"]


# --- 7. report／sarif outputs 只指向這次寫出的檔案 ---------------------------------------------------------
# --- 7. The report / sarif outputs only point at files this audit wrote ----------------------------------------

def test_report_and_sarif_outputs_come_from_the_runner():
    """outputs.report／sarif 由 audit step（runner）設定，說明提到失敗時為空 ／ outputs.report / sarif are set by the
    audit step (the runner) and their descriptions say they are empty on failure."""
    outputs = _action()["outputs"]
    assert outputs["report"]["value"] == "${{ steps.audit.outputs.report }}"
    assert outputs["sarif"]["value"] == "${{ steps.audit.outputs.sarif }}"
    for name in ("report", "sarif"):
        assert "ERROR" in outputs[name]["description"]


@needs_bash
def test_prep_refuses_a_sarif_path_with_a_line_break(tmp_path):
    """sarif 路徑會寫進 GITHUB_OUTPUT：含換行時 prep step 以 exit 5 拒絕 ／ The sarif path goes into GITHUB_OUTPUT: the prep
    step refuses one with a line break with exit 5."""
    env = _env(tmp_path, VH_MUTATION="", VH_SANDBOX="local_subprocess", VH_FORMAT="md", VH_MODE="", VH_MAX_CALLS="",
               VH_MAX_FILES="", VH_OUTPUT="", VH_SARIF="a.sarif\nverdict=READY_TO_SHIP")
    out = subprocess.run([_BASH, "-e", "-c", _step("prep")["run"]], cwd=tmp_path, capture_output=True, text=True,
                         encoding="utf-8", env=env)
    assert out.returncode == 5 and "sarif must not contain a line break" in out.stdout


# --- 4. --init-config 不跟隨符號連結 -----------------------------------------------------------------------
# --- 4. --init-config never follows symlinks ----------------------------------------------------------------

def _symlink(target, link):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


@pytest.mark.parametrize("force", [False, True])
def test_init_config_refuses_a_dangling_symlink(monkeypatch, tmp_path, force):
    """重現：不可信 checkout 裡懸空的 vibeharness.yaml 符號連結讓 --init-config 在別處建立檔案。現在 exit 5，目標不會出現。
    Reproduction: a dangling vibeharness.yaml symlink in an untrusted checkout made --init-config create a file
    elsewhere. Now it exits 5 and the target never appears."""
    elsewhere = tmp_path / "elsewhere.yaml"
    _symlink(str(elsewhere), str(tmp_path / "vibeharness.yaml"))
    monkeypatch.chdir(tmp_path)
    assert _run_cli(monkeypatch, "--init-config", *(["--force"] if force else [])) == 5
    assert not elsewhere.exists()


def test_init_config_force_does_not_clobber_a_symlink_target(monkeypatch, tmp_path, capsys):
    """--force 也不經由符號連結覆寫目標檔案 ／ --force does not overwrite the target file through a symlink either."""
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n", encoding="utf-8")
    link = tmp_path / "link.yaml"
    _symlink(str(victim), str(link))
    assert _run_cli(monkeypatch, "--init-config", str(link), "--force") == 5
    assert victim.read_text(encoding="utf-8") == "keep me\n"
    assert "symlink" in capsys.readouterr().err


def test_init_config_force_overwrites_a_regular_file(tmp_path):
    """--force 照常覆寫一般檔案，內容與內建設定檔相同 ／ --force still overwrites a regular file with the bundled config."""
    path = tmp_path / "vibeharness.yaml"
    path.write_text("old\n", encoding="utf-8")
    assert cli._init_config(str(path), force=True) == 0
    with open(DEFAULT_CONFIG_PATH, "rb") as f:
        assert path.read_bytes() == f.read()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs")
def test_init_config_refuses_a_fifo_even_with_force(tmp_path):
    """FIFO 不是一般檔案：--force 也拒絕，而不是卡在開啟 ／ A FIFO is not a regular file: refused even with --force
    instead of blocking on open."""
    fifo = tmp_path / "vibeharness.yaml"
    os.mkfifo(fifo)
    assert cli._init_config(str(fifo), force=True) == 5


def test_an_unexpected_init_config_error_exits_5_not_1(monkeypatch, tmp_path):
    """--init-config 的意外錯誤在防護內：exit 5，不是 Python 預設的 1（= NEEDS_FIXES）。
    An unexpected --init-config error is inside the guard: exit 5, not Python's default 1 (= NEEDS_FIXES)."""
    def boom(path, force):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "_init_config", boom)
    assert _run_cli(monkeypatch, "--init-config", str(tmp_path / "x.yaml")) == 5


# --- 5. 無法編碼雙語文字的 stdout ---------------------------------------------------------------------------
# --- 5. A stdout that cannot encode the bilingual text ---------------------------------------------------------

@pytest.mark.parametrize("encoding", ["ascii", "latin-1"])
@pytest.mark.parametrize("argv,code", [(["--help"], 0), (["--version"], 0), (["--init-config"], 0),
                                       (["-m", "mock", "-t", SMALL_TARGET, "-o", "r.md"], None)])
def test_cli_works_on_a_non_utf8_stdout(tmp_path, encoding, argv, code):
    """重現：PYTHONIOENCODING=ascii 時 --help／--init-config 以 1（UnicodeEncodeError）結束、完整稽核以 5 結束。
    現在無法編碼的字元以 backslashreplace 輸出：--help 等為 0，稽核得到判定碼（0-3）。
    Reproduction: with PYTHONIOENCODING=ascii, --help / --init-config exited 1 (UnicodeEncodeError) and a full audit
    exited 5. Unencodable characters are now written with backslashreplace: --help and friends exit 0, the audit gets
    a verdict code (0-3)."""
    out = subprocess.run([sys.executable, "-m", "vibeharness.cli", *argv], cwd=tmp_path, capture_output=True,
                         env=_env(tmp_path, PYTHONIOENCODING=encoding))
    stderr = out.stderr.decode("ascii", "replace")
    if code is None:
        assert out.returncode in (0, 1, 2, 3), stderr
        assert (tmp_path / "r.md").is_file()
    else:
        assert out.returncode == code, stderr
    assert "UnicodeEncodeError" not in stderr
    if argv == ["--init-config"]:
        assert (tmp_path / "vibeharness.yaml").is_file()
    if argv == ["--help"]:
        assert b"--init-config" in out.stdout


def test_the_runner_survives_a_cp1252_console(tmp_path):
    """Windows runner 的主控台是 cp1252：雙語的 ::error:: 不能讓 runner 以 UnicodeEncodeError 結束（exit 1）。
    A Windows runner's console is cp1252: the bilingual ::error:: must not end the runner with UnicodeEncodeError (exit 1)."""
    out = subprocess.run([sys.executable, "-m", "vibeharness.action_runner", "-t", ".", "--estimate"], cwd=tmp_path,
                         capture_output=True, env=_env(tmp_path, VH_OUTPUT="r.md", PYTHONIOENCODING="cp1252"))
    assert out.returncode == 5, out.stderr.decode("cp1252", "replace")
    assert b"UnicodeEncodeError" not in out.stderr
    assert _outputs(tmp_path)["verdict"] == "ERROR"


def test_action_error_paths_always_write_outputs_and_summary_and_guard_sarif_upload(monkeypatch, tmp_path, capsys):
    """early exit-5（無效 fail-on、non-audit 旗標、prep 失敗、非映射設定檔）皆寫出完整 ERROR outputs 與摘要；
    舊的 `.partial.json` 會在執行前清掉，upload-artifact 與 upload-sarif 範例只讀 audit 實際寫出的路徑。
    Early exit-5 paths (bad fail-on, non-audit flags, prep failure, non-mapping config) always write complete ERROR
    outputs and step summary; stale `.partial.json` is cleared before running, and upload-artifact / upload-sarif use
    runner-verified outputs."""
    # 1. action_runner：無效 fail-on 與 non-audit 旗標都寫出 GITHUB_OUTPUT 與 GITHUB_STEP_SUMMARY
    # action_runner: both bad fail-on and non-audit flags write GITHUB_OUTPUT and GITHUB_STEP_SUMMARY
    for idx, (fail_on, argv) in enumerate([("bogus", ["--target", "."]), ("needs-fixes", ["--target", ".", "--estimate"])]):
        cell = tmp_path / f"case_{idx}"
        cell.mkdir()
        monkeypatch.setenv("RUNNER_TEMP", str(cell))
        monkeypatch.setenv("GITHUB_OUTPUT", str(cell / "out"))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(cell / "summary.md"))
        monkeypatch.setenv("VH_FAIL_ON", fail_on)
        assert action_runner.main(argv) == 5
        assert _outputs(cell) == {"verdict": "ERROR", "exit-code": "5", "report": "", "sarif": ""}
        summary_text = (cell / "summary.md").read_text(encoding="utf-8")
        assert "ERROR (exit 5)" in summary_text and "No report was written" in summary_text
    capsys.readouterr()

    # 2. 舊的 `<output>.partial.json` 在稽核開始前會被清除，不會在正常完成或用法錯誤後殘留上傳
    # Stale `<output>.partial.json` is removed before the audit starts so it is not uploaded from a prior run
    run_cell = tmp_path / "stale_partial"
    run_cell.mkdir()
    stale_partial = run_cell / "r.md.partial.json"
    stale_partial.write_text('{"stale": true}\n', encoding="utf-8")
    monkeypatch.chdir(run_cell)
    for k, v in {"RUNNER_TEMP": str(run_cell), "GITHUB_OUTPUT": str(run_cell / "out"),
                 "GITHUB_STEP_SUMMARY": str(run_cell / "summary.md"), "VH_FAIL_ON": "never",
                 "VH_OUTPUT": "r.md", "VH_SARIF": ""}.items():
        monkeypatch.setenv(k, v)

    def ok_cli(argv):
        (run_cell / "r.md").write_text("# report\n", encoding="utf-8")
        with open(argv[argv.index("--summary-json") + 1], "w", encoding="utf-8") as f:
            json.dump({"tool": "vibeharness", "exit_code": 0}, f)
        return 0

    monkeypatch.setattr(action_runner, "run_cli", ok_cli)
    assert action_runner.main(["--target", "."]) == 0
    assert not stale_partial.exists()

    # 3. Docker 設定複製片段：非 dict YAML 或非 dict global 以 ::error:: exit 5 拒絕，不噴 AttributeError
    # Docker config-copy snippet: non-dict YAML or non-dict global exits 5 cleanly with ::error::, no traceback
    snippet = tmp_path / "docker_cfg.py"
    snippet.write_text(_sandbox_config_snippet(), encoding="utf-8")
    for bad_idx, content in enumerate(["- just\n- a\n- list\n", "global: 123\n"]):
        bad_cfg = tmp_path / f"bad_{bad_idx}.yaml"
        bad_cfg.write_text(content, encoding="utf-8")
        args_file = tmp_path / f"args_{bad_idx}"
        args_file.write_text(f"--config\0{bad_cfg}\0", encoding="utf-8")
        res = subprocess.run(
            [sys.executable, str(snippet), str(args_file), str(tmp_path / f"out_{bad_idx}.yaml")],
            capture_output=True, text=True, env=_env(tmp_path), cwd=str(tmp_path),
        )
        assert res.returncode == 5 and "::error::" in res.stdout and "Traceback" not in res.stderr

    # 4. prep／install 失敗亦寫出 ERROR outputs 與摘要；prep 通過時清除舊的 .partial.json 並輸出 partial 路徑
    # prep / install failures write ERROR outputs & summary; prep success clears stale .partial.json and outputs partial
    if _BASH is not None and sys.platform != "win32":
        prep_cell = tmp_path / "prep_fail"
        prep_cell.mkdir()
        prep_res = subprocess.run(
            [_BASH, "-e", "-c", _step("prep")["run"]], cwd=prep_cell, capture_output=True, text=True,
            encoding="utf-8", env=_env(prep_cell, VH_FAIL_ON="typo", VH_MUTATION="", VH_SANDBOX="local_subprocess",
                                       VH_FORMAT="md", VH_MODE="", VH_MAX_CALLS="", VH_MAX_FILES="", VH_OUTPUT="",
                                       VH_SARIF=""),
        )
        assert prep_res.returncode == 5
        assert _outputs(prep_cell) == {"verdict": "ERROR", "exit-code": "5", "report": "", "sarif": ""}
        assert "ERROR (exit 5)" in (prep_cell / "summary.md").read_text(encoding="utf-8")

        prep_ok = tmp_path / "prep_ok"
        prep_ok.mkdir()
        stale_prep = prep_ok / "vibeharness-report.md.partial.json"
        stale_prep.write_text('{"old": 1}\n', encoding="utf-8")
        prep_ok_res = subprocess.run(
            [_BASH, "-e", "-c", _step("prep")["run"]], cwd=prep_ok, capture_output=True, text=True,
            encoding="utf-8", env=_env(prep_ok, VH_FAIL_ON="never", VH_MUTATION="", VH_SANDBOX="local_subprocess",
                                       VH_FORMAT="md", VH_MODE="", VH_MAX_CALLS="", VH_MAX_FILES="", VH_OUTPUT="",
                                       VH_SARIF=""),
        )
        assert prep_ok_res.returncode == 0 and not stale_prep.exists()
        assert _outputs(prep_ok) == {"output": "vibeharness-report.md"}

        inst_step = next(s for s in _action()["runs"]["steps"] if str(s.get("name", "")).startswith("Install"))
        inst_cell = tmp_path / "inst_fail"
        inst_cell.mkdir()
        inst_res = subprocess.run(
            [_BASH, "-e", "-c", inst_step["run"]], cwd=inst_cell, capture_output=True, text=True,
            encoding="utf-8", env=_env(inst_cell, GITHUB_ACTION_PATH="", VH_ACTION_REF="test"),
        )
        assert inst_res.returncode == 5
        assert _outputs(inst_cell) == {"verdict": "ERROR", "exit-code": "5", "report": "", "sarif": ""}
        assert "ERROR (exit 5)" in (inst_cell / "summary.md").read_text(encoding="utf-8")

    action_data = _action()
    upload_step = next(s for s in action_data["runs"]["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    assert "steps.prep.outputs.output != ''" in upload_step["if"]
    upload_paths = [ln.strip() for ln in upload_step["with"]["path"].splitlines() if ln.strip()]
    assert "${{ steps.audit.outputs.report }}" in upload_paths
    assert "${{ steps.prep.outputs.output }}.partial.json" in upload_paths
    assert "${{ steps.audit.outputs.sarif }}" in upload_paths
    assert "${{ inputs.sarif }}" not in upload_paths

    for doc_name in ("action.yml", "README.md", "README.en.md"):
        with open(os.path.join(REPO_ROOT, doc_name), encoding="utf-8") as f:
            doc = f.read()
        assert "steps.audit.outputs.sarif != ''" in doc, doc_name
        assert "${{ steps.audit.outputs.sarif }}" in doc, doc_name
