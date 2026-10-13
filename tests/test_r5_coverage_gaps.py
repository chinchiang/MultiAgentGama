"""補齊 core/baseline.py 與 core/sandbox.py 穩定輔助函式的涵蓋率缺口：只經由公開函式測試目前的行為。
Fills the coverage gaps of core/baseline.py and the stable helpers of core/sandbox.py: tests the current behaviour
through public functions only."""
import json
import logging
import os
import subprocess
import sys

import pytest

import vibeharness.core.sandbox as sandbox_mod
from vibeharness.core import baseline as bl
from vibeharness.core.i18n import bi
from vibeharness.core.models import (
    FindingSeverity, ReviewFinding, STRIDECategory, StaticFinding, TestExecutionResult, TestStatus, ThreatItem,
)
from vibeharness.core.sandbox import (
    DockerSandbox, LocalSubprocessSandbox, NodeSubprocessSandbox, SandboxUnavailableError, build_safe_env,
    filter_custom_env, link_node_modules, rewrite_host_paths, sandbox_home_env, sandbox_temp_env,
)


def _finding(fid="WB-CLA-01", title="Unchecked null", path="/t/app.py", simulated=False):
    return ReviewFinding(
        finding_id=fid, reviewer_name="Claude", model_alias="claude", file_path=path, symbol_name="f",
        line_number=3, severity=FindingSeverity.HIGH, title=title, description="d", root_cause="r",
        suspected_vibe_flaw="v", suggested_test_scenario="s", is_simulated=simulated,
    )


def _threat(tid="THREAT-01", title="BOLA", simulated=False):
    return ThreatItem(
        threat_id=tid, stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE, title=title, description="",
        asset_at_risk="a", attack_vector="PUT /u/{id}", trust_boundary_crossed="b", severity=FindingSeverity.CRITICAL,
        attack_scenario="", test_verification_goal="", is_simulated=simulated,
    )


def _static(line=1, evidence="pickle.load(x)"):
    return StaticFinding(rule_id="VH-AI-003", title="t", severity=FindingSeverity.MEDIUM, file_path="/t/app.py",
                         line_number=line, evidence=evidence)


def _result(tid, status=TestStatus.FAILED, ref=None, ttype="whitebox_unit", exploit=False):
    return TestExecutionResult(test_id=tid, test_type=ttype, status=status, source_ref=ref,
                               is_security_exploit_confirmed=exploit)


def _write(tmp_path, payload):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"tool": bl.TOOL_NAME, **payload}), encoding="utf-8")
    return str(path)


# --- baseline：從沒有 fingerprint 的報告重算鍵，略過壞掉的項目 ---------------------------------------------
# --- baseline: keys recomputed from reports without fingerprints, broken items skipped ---------------------

def test_load_skips_bad_items(tmp_path):
    sim_finding = _finding("WB-SIM-01", bi("未檢查的空值", "Unchecked null"), simulated=True)
    sim_threat = _threat("THREAT-07", bi("越權", "BOLA"), simulated=True)
    item_finding = sim_finding.model_dump(mode="json")
    item_finding.pop("is_simulated")
    item_threat = sim_threat.model_dump(mode="json")
    item_threat.pop("is_simulated")
    payload = {
        "target_path": "/t",
        "summary": {
            "run": "not a dict",
            "static_findings": [{"rule_id": "broken"}, _static().model_dump(mode="json"), "not a dict"],
        },
        "whitebox": {
            "debate": {"is_simulated": True, "confirmed_findings": [{"finding_id": "broken"}, item_finding]},
            "test_results": [
                {"status": "FAILED"},  # 缺 test_id：略過 ／ no test_id: skipped
                {"test_id": "WB-TEST-01", "test_type": "whitebox_unit", "status": "PASSED", "source_ref": "WB-SIM-01"},
                {"test_id": "WB-TEST-02", "test_type": "whitebox_unit", "status": "FAILED", "source_ref": "WB-SIM-01"},
                {"test_id": "WB-TEST-03", "test_type": "whitebox_unit", "status": "FAILED", "source_ref": "WB-GONE"},
            ],
        },
        "threat_model": {"is_simulated": True, "threats": [{"threat_id": "broken"}, item_threat]},
        "blackbox_test_results": [
            {"is_security_exploit_confirmed": True},  # 缺欄位：略過 ／ missing fields: skipped
            {"test_id": "BB-1", "test_type": "blackbox_security", "status": "FAILED", "source_ref": "THREAT-07",
             "is_security_exploit_confirmed": True},
            {"test_id": "BB-2", "test_type": "blackbox_security", "status": "PASSED", "source_ref": "THREAT-07",
             "is_security_exploit_confirmed": False},
        ],
    }
    base = bl.load_baseline(_write(tmp_path, payload))
    assert base.generated_at is None
    assert base.static == {bl.static_key(_static(), "/t")}
    # 容器層級的 is_simulated 補到項目上，重算的鍵只取雙語字串的英文半
    # The container-level is_simulated is propagated to the items; recomputed keys use the English half only
    assert base.findings == {bl.finding_key(sim_finding, "/t")}
    assert base.findings == {bl.finding_key(_finding("X", "Unchecked null"), "/t")}
    breach = bl.breach_key(_result("BB-1", ref="THREAT-07", exploit=True), sim_threat)
    assert base.breaches == {breach}
    assert base.size == 3


def test_load_non_dict_sections(tmp_path):
    base = bl.load_baseline(_write(tmp_path, {"summary": [], "whitebox": [], "threat_model": [],
                                              "blackbox_test_results": {}}))
    assert base.size == 0 and base.path == os.path.abspath(str(tmp_path / "report.json"))


@pytest.mark.parametrize("content, needle", [
    ("{not json", "not valid JSON"),
    ("[]", "not a VibeHarness JSON report"),
])
def test_load_rejects(tmp_path, content, needle):
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=needle):
        bl.load_baseline(str(path))


def test_load_missing_file(tmp_path):
    with pytest.raises(ValueError, match="cannot be read"):
        bl.load_baseline(str(tmp_path / "nope.json"))


# --- baseline：annotate_report_payload 與 compare_with_baseline --------------------------------------------
# --- baseline: annotate_report_payload and compare_with_baseline -------------------------------------------

def test_annotate_whitebox_and_breach():
    finding, threat = _finding(), _threat()
    results = [_result("WB-1", ref=finding.finding_id), _result("WB-2", TestStatus.PASSED, ref=finding.finding_id),
               _result("WB-3", ref="WB-GONE")]
    breaches = [_result("BB-1", ref=threat.threat_id, ttype="blackbox_security", exploit=True),
                _result("BB-2", TestStatus.PASSED, ref=threat.threat_id, ttype="blackbox_security")]
    payload = {
        "summary": {"static_findings": [{}]},
        "whitebox": {"debate": {"confirmed_findings": [{}]}, "test_results": [{}, {}, {}]},
        "blackbox_test_results": [{}, {}],
    }
    bl.annotate_report_payload(payload, "/t", [_static()], [finding], results, breaches, [threat])
    assert payload["summary"]["static_findings"][0]["fingerprint"] == bl.static_key(_static(), "/t")
    tr = payload["whitebox"]["test_results"]
    assert tr[0]["fingerprint"] == bl.finding_key(finding, "/t")
    assert "fingerprint" not in tr[1] and "fingerprint" not in tr[2]  # 通過或無法解析 ／ passed or unresolved
    bb = payload["blackbox_test_results"]
    assert bb[0]["fingerprint"] == bl.breach_key(breaches[0], threat) and "fingerprint" not in bb[1]


def test_compare_splits_new_and_known():
    finding, threat = _finding(), _threat()
    known_static, new_static = _static(1), _static(2, evidence="eval(x)")
    probe = _result("WB-PROBE-1", ref="transfer", ttype="whitebox_probe")
    wb_known = _result("WB-1", ref=finding.finding_id)
    wb_new = _result("WB-2", ref="WB-GONE")
    wb_passed = _result("WB-3", TestStatus.PASSED, ref=finding.finding_id)
    bb_known = _result("BB-1", ref=threat.threat_id, ttype="blackbox_security", exploit=True)
    bb_orphan = _result("BB-9", ref="THREAT-GONE", ttype="blackbox_security", exploit=True)
    bb_new = _result("BB-2", ref="THREAT-02", ttype="blackbox_security", exploit=True)
    bb_safe = _result("BB-3", TestStatus.PASSED, ref=threat.threat_id, ttype="blackbox_security")
    base = bl.Baseline(
        path="/b.json",
        static={bl.static_key(known_static, "/t")},
        findings={bl.finding_key(finding, "/t"), bl.probe_key(probe)},
        breaches={bl.breach_key(bb_known, threat), bl.breach_key(bb_orphan, None)},
    )
    out = bl.compare_with_baseline(base, "/t", [known_static, new_static], [probe, wb_known, wb_new, wb_passed],
                                   [finding], [bb_known, bb_orphan, bb_new, bb_safe],
                                   [threat, _threat("THREAT-02", "Other")])
    assert out.new_static_blocking == [new_static]
    assert out.new_whitebox_failures == [wb_new]
    assert out.new_breaches == [bb_new]
    by_id = {s.id: (s.kind, s.title) for s in out.suppressed}
    assert by_id == {
        "VH-AI-003@app.py:1": ("static", "t"),
        "WB-PROBE-1": ("whitebox_failure", "WB-PROBE-1"),  # 探測沒有發現：標題退回測試 id ／ a probe has no finding: the title falls back to the id
        "WB-1": ("whitebox_failure", finding.title),
        "BB-1": ("breach", threat.title),
        "BB-9": ("breach", "BB-9"),
    }


# --- sandbox：環境變數輔助函式 -------------------------------------------------------------------------
# --- sandbox: environment helpers --------------------------------------------------------------------

def test_filter_env_empty():
    assert filter_custom_env(None) == {} and filter_custom_env({}) == {}


def test_filter_env_drops(caplog):
    with caplog.at_level(logging.WARNING, logger=sandbox_mod.logger.name):
        kept = filter_custom_env({"MY_API_KEY": "x", "ld_preload": "y", "APP_MODE": "test"})
    assert kept == {"APP_MODE": "test"}
    assert "MY_API_KEY" in caplog.text and "ld_preload" in caplog.text


def test_safe_env_allowlist(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("LC_VH_TEST", "C")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    env = build_safe_env({"EXTRA": "1"})
    assert env["PATH"] == "/usr/bin" and env["LC_VH_TEST"] == "C" and env["EXTRA"] == "1"
    assert "OPENAI_API_KEY" not in env


def test_temp_env(tmp_path):
    env = sandbox_temp_env(str(tmp_path))
    temp = os.path.join(str(tmp_path), "tmp")
    assert env == {"TMPDIR": temp, "TMP": temp, "TEMP": temp} and os.path.isdir(temp)


def test_home_env_site_failure(tmp_path, monkeypatch):
    import site

    def boom():
        raise RuntimeError("embedded interpreter")
    # site 不完整時不帶 PYTHONUSERBASE，但仍回傳假家目錄
    # An incomplete site yields no PYTHONUSERBASE, but the fake home is still returned
    monkeypatch.setattr(site, "getusersitepackages", boom)
    monkeypatch.setattr(site, "ENABLE_USER_SITE", True)
    env = sandbox_home_env(str(tmp_path))
    assert env["HOME"] == os.path.join(str(tmp_path), "home") and "PYTHONUSERBASE" not in env


def test_home_env_win32(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    env = sandbox_home_env(str(tmp_path))
    home = os.path.join(str(tmp_path), "home")
    assert env["USERPROFILE"] == home
    assert env["APPDATA"] == os.path.join(home, "AppData", "Roaming") and os.path.isdir(env["LOCALAPPDATA"])


# --- sandbox：逾時與命令組成 -------------------------------------------------------------------------
# --- sandbox: timeouts and command construction ------------------------------------------------------

@pytest.mark.parametrize("given, expected", [(None, 7), (0, 7), (-3, 7), ("5", 7), (0.4, 1), (3.9, 3), (12, 12)])
def test_effective_timeout(given, expected):
    assert LocalSubprocessSandbox(timeout_seconds=7)._effective_timeout(given) == expected


def test_local_cmd_custom_env(tmp_path):
    cmd, _, env = LocalSubprocessSandbox()._build_command(
        str(tmp_path), ["test_a.py"], str(tmp_path), False, None, {"APP_MODE": "x", "DB_PASSWORD": "p"})
    assert cmd[:3] == [sys.executable, "-m", "pytest"] and os.path.join(str(tmp_path), "test_a.py") in cmd
    assert env["APP_MODE"] == "x" and "DB_PASSWORD" not in env


def test_rewrite_no_mapping():
    assert rewrite_host_paths("/t/x.py", []) == "/t/x.py"


def _docker(**kw):
    return DockerSandbox(docker_bin=sys.executable, verify=False, **kw)


def test_docker_cmd(tmp_path):
    run_dir, base = str(tmp_path / "run"), str(tmp_path / "proj")
    os.makedirs(run_dir)
    cmd, cwd, _ = _docker(network="bridge", memory="512m", cpus=1, pids_limit=64)._build_command(
        run_dir, ["test_a.py"], base, True, os.path.join(base, "pkg"), {"APP_MODE": "x", "MY_TOKEN": "t"}, 9)
    assert cwd == run_dir and cmd[1:3] == ["run", "--rm"]
    for flag, value in (("--network", "bridge"), ("--memory", "512m"), ("--cpus", "1"), ("--pids-limit", "64"),
                        ("-w", "/work/proj")):
        assert cmd[cmd.index(flag) + 1] == value
    assert "APP_MODE=x" in cmd and not any(c.startswith("MY_TOKEN=") for c in cmd)
    assert cmd[cmd.index("timeout") + 2] == "9"
    assert "--cov=/work/proj/pkg" in cmd and f"{sandbox_mod.CONTAINER_RUN_DIR}/test_a.py" in cmd


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX uid only")
def test_docker_user_root(monkeypatch):
    monkeypatch.setattr(sandbox_mod.os, "getuid", lambda: 0)
    assert DockerSandbox._user() == "65534:65534"


def test_docker_user_win32(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert DockerSandbox._user() == "65534:65534"


def test_docker_verify(monkeypatch):
    sandbox = _docker()

    def oserror(*a, **k):
        raise OSError("daemon gone")
    monkeypatch.setattr(sandbox_mod.subprocess, "run", oserror)
    with pytest.raises(SandboxUnavailableError, match="daemon gone"):
        sandbox._verify_available()
    monkeypatch.setattr(sandbox_mod.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, "", "No such image"))
    with pytest.raises(SandboxUnavailableError, match="No such image"):
        sandbox._verify_available()


def test_docker_verify_no_cli():
    with pytest.raises(SandboxUnavailableError, match="docker CLI"):
        DockerSandbox(docker_bin="vh-no-such-docker-cli", verify=True)


def test_docker_rm_failures(monkeypatch, caplog):
    sandbox = _docker()
    cmd = ["docker", "run", "--name", "vibeharness-abc"]
    monkeypatch.setattr(sandbox_mod.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 1))
    with caplog.at_level(logging.WARNING, logger=sandbox_mod.logger.name):
        sandbox._after_timeout(cmd)
        assert "rc=1" in caplog.text

        def timeout(*a, **k):
            raise subprocess.TimeoutExpired(a[0], 60)
        monkeypatch.setattr(sandbox_mod.subprocess, "run", timeout)
        sandbox._after_timeout(cmd)
    assert "Could not remove container vibeharness-abc" in caplog.text


# --- sandbox：node_modules 連結與 Node 沙盒 -------------------------------------------------------------
# --- sandbox: node_modules linking and the Node sandbox ------------------------------------------------

def _node_dirs(tmp_path):
    run_dir, base = tmp_path / "run", tmp_path / "proj"
    (base / "node_modules").mkdir(parents=True)
    run_dir.mkdir()
    return str(run_dir), str(base)


def test_link_none_without_modules(tmp_path):
    assert link_node_modules(str(tmp_path), str(tmp_path / "missing")) is None


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_link_symlink(tmp_path):
    run_dir, base = _node_dirs(tmp_path)
    link = link_node_modules(run_dir, base)
    assert link == os.path.join(run_dir, "node_modules") and os.path.realpath(link) == os.path.realpath(
        os.path.join(base, "node_modules"))


def _no_symlink(*a, **k):
    raise OSError("symlink privilege not held")


def test_link_fallback_posix(tmp_path, monkeypatch):
    run_dir, base = _node_dirs(tmp_path)
    monkeypatch.setattr(sandbox_mod.os, "symlink", _no_symlink)
    monkeypatch.setattr(sys, "platform", "linux")
    assert link_node_modules(run_dir, base) is None


@pytest.mark.parametrize("outcome, linked", [(0, True), (1, False), (OSError("no cmd"), False)])
def test_link_junction(tmp_path, monkeypatch, outcome, linked):
    run_dir, base = _node_dirs(tmp_path)
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if isinstance(outcome, Exception):
            raise outcome
        return subprocess.CompletedProcess(cmd, outcome)
    monkeypatch.setattr(sandbox_mod.os, "symlink", _no_symlink)
    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "platform", "win32")
    result = link_node_modules(run_dir, base)
    assert calls and calls[0][:4] == ["cmd", "/c", "mklink", "/J"]
    assert result == (os.path.join(run_dir, "node_modules") if linked else None)


def test_node_path_fallback(tmp_path, monkeypatch):
    run_dir, base = _node_dirs(tmp_path)
    monkeypatch.setattr(sandbox_mod, "link_node_modules", lambda r, b: None)
    _, cwd, env = NodeSubprocessSandbox(node_version=(22, 10, 0))._build_command(
        run_dir, ["test_vh_001.mjs"], base, False, None, None)
    assert cwd == base and env["NODE_PATH"] == os.path.join(base, "node_modules") and env["NODE_ENV"] == "test"


def test_node_version_probe_fails(tmp_path):
    sandbox = NodeSubprocessSandbox(node_bin=str(tmp_path / "vh-no-such-node"))
    assert sandbox._node_version_for_coverage() is None
    assert sandbox.js_coverage_problem() is not None
    # 收集不到涵蓋率時不讀 lcov ／ no lcov is read when coverage cannot be collected
    assert sandbox._collect_coverage(str(tmp_path), "", str(tmp_path), None, None) is None


def test_node_no_lcov(tmp_path):
    sandbox = NodeSubprocessSandbox(node_version=(22, 10, 0))
    assert sandbox._collect_coverage(str(tmp_path), "", str(tmp_path), None, None) is None
