"""Docker 沙盒：主機路徑對應、容器強化旗標，以及（Docker 可用時）真正的執行。
Docker sandbox: host-path mapping, container hardening flags, and (when Docker is available) real runs."""
import os
import shutil
import subprocess

import pytest

import vibeharness.core.sandbox as sandbox_mod
from vibeharness.core.harness import VibeHarnessCommander
from vibeharness.core.models import GeneratedTest, TestStatus
from vibeharness.core.sandbox import (
    DockerSandbox, SandboxUnavailableError, TIMEOUT_EXIT_CODE, DEFAULT_DOCKER_IMAGE,
    container_target_dir, rewrite_host_paths,
)
from vibeharness.runners.test_executor import TestSuiteExecutor

WIN_MAP = [(r"D:\work\proj", "/work/proj"), (r"D:\work", "/work")]
POSIX_MAP = [("/home/u/proj", "/work/proj"), ("/home/u", "/work")]


def test_container_target_dir_uses_a_safe_name():
    assert container_target_dir(os.path.join("x", "my_app")) == "/work/my_app"
    assert container_target_dir(os.path.join("x", "my app!")) == "/work/target"


@pytest.mark.parametrize("code, expected", [
    # repr() 形式，如執行器標頭所寫
    # repr() form, as written by the executor header
    ("sys.path.insert(0, 'D:\\\\work\\\\proj')", "sys.path.insert(0, '/work/proj')"),
    ("p = 'D:\\\\work\\\\proj\\\\pkg\\\\app.py'", "p = '/work/proj/pkg/app.py'"),
    # 原始字串與正斜線形式，磁碟機代號大小寫不拘
    # raw string and forward-slash forms, any drive-letter case
    ("p = r'd:\\work\\PROJ\\app.py'", "p = r'/work/proj/app.py'"),
    ("p = 'D:/work/proj/app.py'", "p = '/work/proj/app.py'"),
    # 上層目錄（本機也在 sys.path 上）對應到 /work
    # the parent directory (also on sys.path locally) maps to /work
    ("sys.path.insert(0, 'D:\\\\work')", "sys.path.insert(0, '/work')"),
    # 同前綴的同層目錄不是目標
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
    # 同層目錄沒有掛載；把它改寫成 /work/<sibling> 會指向不存在的
    # 容器路徑。保留主機路徑能讓失敗一目了然。
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
    run_dir.mkdir()  # execute_pytest_files 總是先建立它；root 身分的測試框架會對它 chmod ／ execute_pytest_files always creates it first; a root harness chmods it
    cmd, cwd, cli_env = _sandbox(network="none", memory="512m")._build_command(
        str(run_dir), ["test_vh_000.py"], str(target), True, None, {"TARGET_URL": "http://svc"}
    )
    joined = " ".join(cmd)
    for flag in ("--rm", "--read-only", "--network none", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--memory 512m", "--pids-limit 256", "--user"):
        assert flag in joined
    # 縱深防禦：/tmp 的 tmpfs 不得允許執行二進位檔；可寫的執行
    # 目錄 bind 無法加上 nosuid/noexec（docker 拒絕 type=bind 的掛載旗標），因此
    # 此斷言精確記載了所支援的強化措施。
    # defense in depth: the /tmp tmpfs must not allow executing binaries; the writable run
    # dir bind cannot take nosuid/noexec (docker rejects mount flags for type=bind), so the
    # assertion documents the supported hardening exactly.
    assert "/tmp:rw,nosuid,noexec,size=256m" in cmd
    assert f"type=bind,source={target},target=/work/app,readonly" in joined
    assert f"type=bind,source={run_dir},target=/sandbox" in joined
    assert "PYTHONPATH=/work/app:/work" in cmd and "TARGET_URL=http://svc" in cmd
    assert "sk-secret" not in joined  # 主機的祕密永遠不會進入容器 ／ host secrets never reach the container
    image_at = cmd.index(DEFAULT_DOCKER_IMAGE)
    # 容器內的逾時後盾：即使主機端清理失敗，pytest 也會被終止
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
        "TARGET_URL": "http://svc",           # 無害，保留 ／ benign, kept
        "OPENAI_API_KEY": "sk-secret",        # 憑證，捨棄 ／ credential, dropped
        "MY_SERVICE_SECRET": "x",             # 憑證，捨棄 ／ credential, dropped
        "AWS_SESSION_TOKEN": "x",             # 憑證，捨棄 ／ credential, dropped
        "DB_PASSWORD": "x",                   # 憑證，捨棄 ／ credential, dropped
        "BASH_ENV": "/tmp/evil.sh",           # 注入途徑，捨棄 ／ injection vector, dropped
        "LD_PRELOAD": "/tmp/evil.so",         # 注入途徑，捨棄 ／ injection vector, dropped
    }
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cmd, _, _ = _sandbox()._build_command(str(run_dir), ["test_x.py"], str(target), False, None, env)
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
    assert DockerSandbox._user() == "1000:1001"  # uid 與 gid 不必相同（例如 GH runner） ／ uid and gid need not match (e.g. GH runners)


def test_root_harness_opens_the_run_dir_for_nobody(tmp_path, monkeypatch):
    """以 root 執行時容器會以 nobody 身分執行，因此執行目錄（junit.xml、coverage）必須
    讓它可寫：目錄交給 nobody（chown 65534:65534）並設成 0700，而不是開放給所有人的 0777；
    CI runner 不是 root，所以這條分支靠偽造 uid 與 chown 來演練。
    As root the container runs as nobody, so the run dir (junit.xml, coverage) must be writable
    for it: the dir is handed to nobody (chown 65534:65534) with mode 0700, not opened to everyone with
    0777; CI runners are not root, so this branch is exercised by faking the uid and chown."""
    if not hasattr(os, "getuid"):
        pytest.skip("POSIX only")
    monkeypatch.setattr(sandbox_mod.os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(sandbox_mod.os, "getgid", lambda: 0, raising=False)
    chowned = []
    monkeypatch.setattr(sandbox_mod.os, "chown", lambda path, uid, gid: chowned.append((path, uid, gid)), raising=False)
    target = tmp_path / "app"
    target.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o755)
    cmd, _, _ = _sandbox()._build_command(str(run_dir), ["test_vh_000.py"], str(target), False, None, None)
    assert "--user" in cmd and cmd[cmd.index("--user") + 1] == "65534:65534"
    assert chowned == [(str(run_dir), 65534, 65534)]
    assert run_dir.stat().st_mode & 0o777 == 0o700


def test_bind_quotes_paths_with_commas():
    assert DockerSandbox._bind("/a,b", "/t", readonly=True) == 'type=bind,"source=/a,b",target=/t,readonly'


def test_timeout_removes_the_container(tmp_path, monkeypatch):
    sandbox = _sandbox()
    monkeypatch.setattr(sandbox, "_run", lambda *a, **k: (None, "", ""))
    calls = []
    monkeypatch.setattr(sandbox_mod.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    run = sandbox.execute_pytest_files({"test_x.py": "def test_x(): pass"}, working_dir=str(tmp_path))
    assert run.exit_code == TIMEOUT_EXIT_CODE and "timed out" in run.stderr
    assert len(calls) == 1 and calls[0][1:3] == ["rm", "-f"] and calls[0][3].startswith("vibeharness-")


def test_missing_docker_is_reported(tmp_path, monkeypatch):
    with pytest.raises(SandboxUnavailableError, match="docker CLI"):
        DockerSandbox(docker_bin="no-such-docker-binary-vh")
    monkeypatch.setattr(sandbox_mod.shutil, "which", lambda name: None)
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("global:\n  sandbox_provider: docker\n", encoding="utf-8")
    with pytest.raises(SandboxUnavailableError):
        VibeHarnessCommander(config_path=str(cfg), execution_mode="mock")


# --- 真正的容器執行 ---------------------------------------------------------------------
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
    run = sandbox.execute_pytest_files(
        {"test_hang.py": "import time\n\ndef test_hang():\n    time.sleep(120)\n"}, working_dir=str(tmp_path)
    )
    assert run.exit_code == TIMEOUT_EXIT_CODE
    running = subprocess.run(["docker", "ps", "-q", "--filter", "name=vibeharness-"], capture_output=True, text=True)
    assert running.stdout.strip() == ""
