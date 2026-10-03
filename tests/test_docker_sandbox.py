"""Docker sandbox: host-path mapping, container hardening flags, and (when Docker is available) real runs."""
import os
import shutil
import subprocess

import pytest

import core.sandbox as sandbox_mod
from core.harness import VibeHarnessCommander
from core.models import GeneratedTest, TestStatus
from core.sandbox import (
    DockerSandbox, SandboxUnavailableError, TIMEOUT_EXIT_CODE, DEFAULT_DOCKER_IMAGE,
    container_target_dir, rewrite_host_paths,
)
from runners.test_executor import TestSuiteExecutor

WIN_MAP = [(r"D:\work\proj", "/work/proj"), (r"D:\work", "/work")]
POSIX_MAP = [("/home/u/proj", "/work/proj"), ("/home/u", "/work")]


def test_container_target_dir_uses_a_safe_name():
    assert container_target_dir(os.path.join("x", "my_app")) == "/work/my_app"
    assert container_target_dir(os.path.join("x", "my app!")) == "/work/target"


@pytest.mark.parametrize("code, expected", [
    # repr() form, as written by the executor header
    ("sys.path.insert(0, 'D:\\\\work\\\\proj')", "sys.path.insert(0, '/work/proj')"),
    ("p = 'D:\\\\work\\\\proj\\\\pkg\\\\app.py'", "p = '/work/proj/pkg/app.py'"),
    # raw string and forward-slash forms, any drive-letter case
    ("p = r'd:\\work\\PROJ\\app.py'", "p = r'/work/proj/app.py'"),
    ("p = 'D:/work/proj/app.py'", "p = '/work/proj/app.py'"),
    # the parent directory (also on sys.path locally) maps to /work
    ("sys.path.insert(0, 'D:\\\\work')", "sys.path.insert(0, '/work')"),
    # a sibling directory with the same prefix is not the target
    ("p = 'D:\\\\work\\\\proj2\\\\x.py'", "p = '/work/proj2/x.py'"),
    ("p = 'E:\\\\other\\\\x.py'", "p = 'E:\\\\other\\\\x.py'"),
])
def test_rewrite_windows_host_paths(code, expected):
    assert rewrite_host_paths(code, WIN_MAP, windows=True) == expected


def test_rewrite_posix_host_paths():
    code = "a = '/home/u/proj/app.py'\nb = '/home/u/proj'\nc = '/home/u/projX/y'\nd = '/etc/passwd'\ne = '/home/u/proj\\n'"
    assert rewrite_host_paths(code, POSIX_MAP, windows=False) == (
        "a = '/work/proj/app.py'\nb = '/work/proj'\nc = '/work/projX/y'\nd = '/etc/passwd'\ne = '/work/proj\\n'"
    )


def test_only_the_target_is_mapped_and_sibling_paths_are_left_alone():
    mapping = DockerSandbox._path_mapping("/home/u/proj")
    assert mapping == [("/home/u/proj", "/work/proj")]
    # A sibling is not mounted; rewriting it to /work/<sibling> would point at a nonexistent
    # container path. Keeping the host path makes the failure obvious.
    code = "p = '/home/u/other/x.py'"
    assert rewrite_host_paths(code, mapping, windows=False) == code


def _sandbox(**kwargs):
    return DockerSandbox(timeout_seconds=30, verify=False, **kwargs)


def test_run_command_is_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    target = tmp_path / "app"
    target.mkdir()
    run_dir = tmp_path / "run"
    cmd, cwd, cli_env = _sandbox(network="none", memory="512m")._build_command(
        str(run_dir), ["test_vh_000.py"], str(target), True, None, {"TARGET_URL": "http://svc"}
    )
    joined = " ".join(cmd)
    for flag in ("--rm", "--read-only", "--network none", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--memory 512m", "--pids-limit 256", "--user"):
        assert flag in joined
    # defense in depth: /tmp tmpfs and the writable run dir must not allow executing binaries
    assert "/tmp:rw,nosuid,noexec,size=256m" in cmd
    assert f"{run_dir}:/sandbox:nosuid,noexec" in cmd
    assert f"type=bind,source={target},target=/work/app,readonly" in joined
    assert "PYTHONPATH=/work/app:/work" in cmd and "TARGET_URL=http://svc" in cmd
    assert "sk-secret" not in joined  # host secrets never reach the container
    image_at = cmd.index(DEFAULT_DOCKER_IMAGE)
    # in-container timeout backstop: pytest dies even if host-side cleanup fails
    assert cmd[image_at + 1:image_at + 8] == [
        "timeout", "--kill-after=5", "30", "python", "-m", "pytest", "/sandbox/test_vh_000.py"
    ]
    assert "--junitxml=/sandbox/junit.xml" in cmd and "--cov=/work/app" in cmd
    assert cwd == str(run_dir) and "OPENAI_API_KEY" not in cli_env


def test_custom_env_cannot_carry_credentials_or_injection_vectors(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    env = {
        "TARGET_URL": "http://svc",           # benign, kept
        "OPENAI_API_KEY": "sk-secret",        # credential, dropped
        "MY_SERVICE_SECRET": "x",             # credential, dropped
        "AWS_SESSION_TOKEN": "x",             # credential, dropped
        "DB_PASSWORD": "x",                   # credential, dropped
        "BASH_ENV": "/tmp/evil.sh",           # injection vector, dropped
        "LD_PRELOAD": "/tmp/evil.so",         # injection vector, dropped
    }
    cmd, _, _ = _sandbox()._build_command(str(tmp_path / "run"), ["test_x.py"], str(target), False, None, env)
    joined = " ".join(cmd)
    assert "TARGET_URL=http://svc" in joined
    for forbidden in ("sk-secret", "MY_SERVICE_SECRET", "AWS_SESSION_TOKEN", "DB_PASSWORD",
                      "BASH_ENV=", "LD_PRELOAD="):
        assert forbidden not in joined


def test_root_harness_runs_the_container_as_nobody(tmp_path, monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("POSIX only")
    monkeypatch.setattr(sandbox_mod.os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(sandbox_mod.os, "getgid", lambda: 0, raising=False)
    assert DockerSandbox._user() == "65534:65534"
    monkeypatch.setattr(sandbox_mod.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(sandbox_mod.os, "getgid", lambda: 1001, raising=False)
    assert DockerSandbox._user() == "1000:1001"  # uid and gid need not match (e.g. GH runners)


def test_bind_quotes_paths_with_commas():
    assert DockerSandbox._bind("/a,b", "/t", readonly=True) == 'type=bind,"source=/a,b",target=/t,readonly'


def test_timeout_removes_the_container(tmp_path, monkeypatch):
    sandbox = _sandbox()
    monkeypatch.setattr(sandbox, "_run", lambda *a, **k: (None, "", ""))
    calls = []
    monkeypatch.setattr(sandbox_mod.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    exit_code, _, stderr, *_ = sandbox.execute_pytest_files({"test_x.py": "def test_x(): pass"}, working_dir=str(tmp_path))
    assert exit_code == TIMEOUT_EXIT_CODE and "timed out" in stderr
    assert len(calls) == 1 and calls[0][1:3] == ["rm", "-f"] and calls[0][3].startswith("vibeharness-")


def test_missing_docker_is_reported(tmp_path, monkeypatch):
    with pytest.raises(SandboxUnavailableError, match="docker CLI"):
        DockerSandbox(docker_bin="no-such-docker-binary-vh")
    monkeypatch.setattr(sandbox_mod.shutil, "which", lambda name: None)
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("global:\n  sandbox_provider: docker\n", encoding="utf-8")
    with pytest.raises(SandboxUnavailableError):
        VibeHarnessCommander(config_path=str(cfg), execution_mode="mock")


# --- Real container runs --------------------------------------------------------------

def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", DEFAULT_DOCKER_IMAGE], capture_output=True).returncode == 0


_REQUIRED = os.environ.get("VIBEHARNESS_REQUIRE_DOCKER") == "1"
if _REQUIRED and not _docker_ready():
    raise RuntimeError(f"VIBEHARNESS_REQUIRE_DOCKER=1 but Docker or image {DEFAULT_DOCKER_IMAGE} is unavailable")
docker_only = pytest.mark.skipif(not _docker_ready(), reason=f"Docker or image {DEFAULT_DOCKER_IMAGE} unavailable")


def _test(test_id, code):
    return GeneratedTest(test_id=test_id, test_type="whitebox_unit", target_component="x",
                         title=f"t {test_id}", code=code, rationale="", expected_outcome="")


@docker_only
def test_container_runs_tests_against_the_mounted_target(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    target = tmp_path / "app"
    target.mkdir()
    (target / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    abs_calc = str(target / "calc.py")
    tests = [
        _test("imports", "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"),
        _test("by_path", "import importlib.util\n\ndef test_load():\n"
                         f"    spec = importlib.util.spec_from_file_location('c', {abs_calc!r})\n"
                         "    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
                         "    assert m.add(2, 2) == 4\n"),
        _test("fails", "from calc import add\n\ndef test_bug():\n    assert add(1, 1) == 3\n"),
        _test("no_net", "import socket, pytest\n\ndef test_net():\n"
                        "    with pytest.raises(OSError):\n"
                        "        socket.create_connection(('1.1.1.1', 53), timeout=3)\n"),
        _test("ro_target", "import pytest\n\ndef test_ro():\n    with pytest.raises(OSError):\n"
                           f"        open({str(target / 'x.txt')!r}, 'w')\n"),
        _test("no_secret", "import os\n\ndef test_env():\n    assert 'OPENAI_API_KEY' not in os.environ\n"),
    ]
    results, coverage = TestSuiteExecutor(DockerSandbox(timeout_seconds=120)).execute_test_suite(
        tests, working_dir=str(target), collect_coverage=True
    )
    status = {r.test_id: r.status for r in results}
    assert status == {
        "imports": TestStatus.PASSED, "by_path": TestStatus.PASSED, "fails": TestStatus.FAILED,
        "no_net": TestStatus.PASSED, "ro_target": TestStatus.PASSED, "no_secret": TestStatus.PASSED,
    }, [(r.test_id, r.failure_reason) for r in results]
    assert coverage == 100.0
    assert not (target / "x.txt").exists() and not (target / "__pycache__").exists()


@docker_only
def test_container_is_killed_on_timeout(tmp_path):
    sandbox = DockerSandbox(timeout_seconds=5)
    exit_code, *_ = sandbox.execute_pytest_files(
        {"test_hang.py": "import time\n\ndef test_hang():\n    time.sleep(120)\n"}, working_dir=str(tmp_path)
    )
    assert exit_code == TIMEOUT_EXIT_CODE
    running = subprocess.run(["docker", "ps", "-q", "--filter", "name=vibeharness-"], capture_output=True, text=True)
    assert running.stdout.strip() == ""
