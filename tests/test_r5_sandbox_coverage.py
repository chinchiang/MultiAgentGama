"""第五輪審查（沙盒／JS 涵蓋率）的回歸測試：主機讀回沙盒可寫入的報告時不跟隨 symlink、不被 FIFO 卡住、不讀巨大的
檔案；root harness 把執行目錄交給 nobody（0700）而不是開放成 0777；POSIX 上反斜線不再被當成分隔符；同一目錄的
abspath 與 realpath 各給一個 include（Windows 上兩者不同時不加 include）；docker CLI 寫進主機擷取暫存檔的輸出有上限。
Regression tests for the fifth review round (sandbox / JS coverage): reading back the reports the sandbox can write
neither follows a symlink, nor hangs on a FIFO, nor reads a huge file; a root harness hands the run dir to nobody
(0700) instead of opening it with 0777; a backslash is no longer a separator on POSIX; the abspath and realpath of one
directory each get an include (on Windows no include when they differ); the docker CLI's output into the host-side
capture temp files is capped."""
import os
import shutil
import subprocess
import sys
import threading

import pytest

import vibeharness.core.sandbox as sandbox_mod
from vibeharness.core.jscoverage import (
    LCOV_REPORT_NAME, JsLineCoverage, _glob_include_root, _glob_include_roots, node_coverage_args, read_lcov_file,
    read_untrusted_file,
)
from vibeharness.core.codecontext import target_file_url
from vibeharness.core.sandbox import (
    DEFAULT_DOCKER_IMAGE, EXECUTION_FAILURE_EXIT_CODE, OUTPUT_CAP_NOTE, SANDBOX_MAX_FILE_BYTES, DockerSandbox,
    LocalSubprocessSandbox, NodeSubprocessSandbox, detect_node,
)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink / FIFO / rlimit semantics")
_NODE_PATH, _NODE_VERSION, _ = detect_node("node")
node_globs_only = pytest.mark.skipif(_NODE_VERSION is None or _NODE_VERSION < (22, 5, 0) or _NODE_PATH is None,
                                     reason="Node >= 22.5 (coverage include / exclude) unavailable")

SECRET = "TOP-SECRET-HOST-CONTENT"
LCOV_FOR_M = "SF:{path}\nDA:1,1\nend_of_record\n"


def _no_hang(func, *args, seconds=10):
    """在背景執行緒中呼叫 func，最多等 seconds 秒；卡住就讓測試失敗（舊版讀回 FIFO 會永遠卡住）。
    Calls func in a background thread and waits at most `seconds`; a hang fails the test (the old read-back of a FIFO
    blocked forever)."""
    result = []
    thread = threading.Thread(target=lambda: result.append(func(*args)), daemon=True)
    thread.start()
    thread.join(seconds)
    assert result, "read-back hung"
    return result[0]


# --- 1. 讀回不受信任的報告 ---------------------------------------------------------------------------------
# --- 1. Reading back untrusted reports ----------------------------------------------------------------------

def test_read_untrusted_file_reads_a_regular_file_and_reports_a_missing_one(tmp_path):
    report = tmp_path / "junit.xml"
    report.write_bytes(b"<testsuites>\r\n</testsuites>\r\n")
    assert read_untrusted_file(str(report), 1024) == ("<testsuites>\n</testsuites>\n", None)
    assert read_untrusted_file(str(tmp_path / "missing.xml"), 1024) == (None, None)


@posix_only
def test_read_untrusted_file_refuses_a_symlink_to_a_host_file(tmp_path):
    host_file = tmp_path / "host_secret.txt"
    host_file.write_text(SECRET, encoding="utf-8")
    link = tmp_path / "junit.xml"
    link.symlink_to(host_file)
    text, reason = read_untrusted_file(str(link), 1024)
    assert text is None and "symbolic link" in reason and "symlink" in reason and SECRET not in reason
    os.unlink(link)
    link.symlink_to("/dev/zero")
    assert _no_hang(read_untrusted_file, str(link), 1024)[0] is None


@posix_only
def test_read_untrusted_file_refuses_a_fifo_without_hanging(tmp_path):
    fifo = tmp_path / "junit.xml"
    os.mkfifo(fifo)
    text, reason = _no_hang(read_untrusted_file, str(fifo), 1024)
    assert text is None and "not a regular file" in reason
    # 指向 FIFO 的 symlink 同樣被拒絕，不會在 open 卡住 ／ a symlink to a FIFO is refused too, never hanging in open
    link = tmp_path / LCOV_REPORT_NAME
    link.symlink_to(fifo)
    assert _no_hang(read_lcov_file, str(link)) is None


def test_read_untrusted_file_refuses_an_oversized_file_and_a_directory(tmp_path):
    big = tmp_path / "junit.xml"
    big.write_bytes(b"x" * 2048)
    text, reason = read_untrusted_file(str(big), 1024)
    assert text is None and "1024-byte cap" in reason
    assert read_untrusted_file(str(big), 2048)[0] == "x" * 2048  # 剛好在上限內 ／ exactly at the cap
    (tmp_path / "dir.xml").mkdir()
    assert "not a regular file" in read_untrusted_file(str(tmp_path / "dir.xml"), 1024)[1]


@posix_only
def test_read_untrusted_file_refuses_a_hard_link(tmp_path):
    host_file = tmp_path / "host_secret.txt"
    host_file.write_text(SECRET, encoding="utf-8")
    os.link(host_file, tmp_path / "junit.xml")
    text, reason = read_untrusted_file(str(tmp_path / "junit.xml"), 1024)
    assert text is None and "hard link" in reason


def _planting_run(plant):
    """取代 _run：照 cmd 找出執行目錄裡的 junit 路徑，呼叫 plant(junit_path) 後回報成功結束。
    Replaces _run: finds the junit path in the run dir from cmd, calls plant(junit_path) and reports a clean exit."""
    def run(cmd, cwd, env, timeout, limits=None):
        junit = next(a.split("=", 1)[1] for a in cmd if a.startswith("--junitxml="))
        plant(junit)
        return 0, "", ""
    return run


@posix_only
@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_local_sandbox_does_not_follow_a_planted_junit(tmp_path, monkeypatch, kind):
    host_file = tmp_path / "host_secret.xml"
    host_file.write_text(f"<testsuites><testsuite name='{SECRET}'/></testsuites>", encoding="utf-8")
    sandbox = LocalSubprocessSandbox(timeout_seconds=30)

    def plant(junit):
        if kind == "symlink":
            os.symlink(host_file, junit)
        else:
            os.mkfifo(junit)

    monkeypatch.setattr(sandbox, "_run", _planting_run(plant))
    rc, _, stderr, _, _, junit_xml = _no_hang(
        lambda: sandbox.execute_pytest_files({"test_x.py": "def test_x(): pass\n"}, working_dir=str(tmp_path)))
    assert rc == 0 and junit_xml is None
    assert stderr.startswith("拒絕讀回沙盒產生的 junit.xml") and "Refused to read back the sandbox's junit.xml" in stderr
    assert SECRET not in stderr


@posix_only
def test_node_lcov_read_back_does_not_follow_a_symlink(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    host_lcov = tmp_path / "host_lcov.info"
    host_lcov.write_text(LCOV_FOR_M.format(path=target / "m.mjs"), encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    sandbox = NodeSubprocessSandbox(node_version=(22, 14, 0))
    (run_dir / LCOV_REPORT_NAME).write_text(host_lcov.read_text(encoding="utf-8"), encoding="utf-8")
    assert sandbox._collect_coverage(str(run_dir), "", str(target), None, JsLineCoverage()) == 100.0
    os.unlink(run_dir / LCOV_REPORT_NAME)
    os.symlink(host_lcov, run_dir / LCOV_REPORT_NAME)
    sink = JsLineCoverage()
    assert sandbox._collect_coverage(str(run_dir), "", str(target), None, sink) is None and sink.reports == 0


# --- 2. root harness 把執行目錄交給 nobody ----------------------------------------------------------------
# --- 2. A root harness hands the run dir to nobody ---------------------------------------------------------

def test_non_root_harness_leaves_the_run_dir_alone(tmp_path, monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("POSIX only")
    monkeypatch.setattr(sandbox_mod.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(sandbox_mod.os, "chown", lambda *a: pytest.fail("chown called"), raising=False)
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    DockerSandbox(verify=False)._docker_run_prefix(str(run_dir), str(tmp_path), {})
    assert run_dir.stat().st_mode & 0o777 == 0o700


def _docker_ready(image=DEFAULT_DOCKER_IMAGE) -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0


_DOCKER_REQUIRED = os.environ.get("VIBEHARNESS_REQUIRE_DOCKER") == "1"
if _DOCKER_REQUIRED and not _docker_ready():
    raise RuntimeError(f"VIBEHARNESS_REQUIRE_DOCKER=1 but Docker or image {DEFAULT_DOCKER_IMAGE} is unavailable")
docker_only = pytest.mark.skipif(not _docker_ready(), reason=f"Docker or image {DEFAULT_DOCKER_IMAGE} unavailable")


def _docker_as_root(*args):
    """以容器裡的 root 對主機上的 tmp 目錄做 chown／chmod／rm（測試者本身不是 root）。
    Runs chown / chmod / rm on a host tmp directory as root inside a container (the tester is not root)."""
    return subprocess.run(["docker", "run", "--rm", "--log-driver", "none", "--user", "0:0", "--entrypoint", "sh",
                           *args], capture_output=True, text=True, timeout=120)


@docker_only
@posix_only
def test_real_container_as_nobody_writes_into_a_nobody_owned_0700_run_dir(tmp_path, monkeypatch):
    """模擬 root harness：執行目錄交給 nobody 並設成 0700（以容器裡的 root 做 chown，因為測試者不是 root），
    容器以 nobody 執行時 junit.xml 照樣寫得出來。
    Simulates a root harness: the run dir is handed to nobody with 0700 (chowned by root inside a container, since the
    tester is not root), and a container running as nobody still writes junit.xml."""
    target = tmp_path / "app"
    target.mkdir()
    (target / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    holder = tmp_path / "holder"
    holder.mkdir()
    run_dir = holder / "run"
    run_dir.mkdir()
    (run_dir / "test_vh_000.py").write_text("from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
                                            encoding="utf-8")
    prep = _docker_as_root("-v", f"{holder}:/h", DEFAULT_DOCKER_IMAGE, "-c",
                           "chown 65534:65534 /h/run && chmod 0700 /h/run && chmod 0644 /h/run/test_vh_000.py")
    assert prep.returncode == 0, prep.stderr
    try:
        monkeypatch.setattr(DockerSandbox, "_user", staticmethod(lambda: "65534:65534"))
        sandbox = DockerSandbox(timeout_seconds=120)
        cmd, cwd, env = sandbox._build_command(str(run_dir), ["test_vh_000.py"], str(target), True, None, None)
        # 真正的 root harness 能 chdir 進 nobody 的 0700 目錄，測試者不行：改在 tmp_path 啟動 docker CLI
        # A real root harness can chdir into nobody's 0700 dir, the tester cannot: the docker CLI starts in tmp_path
        assert cwd == str(run_dir)
        rc, stdout, stderr = sandbox._run(cmd, cwd=str(tmp_path), env=env, timeout=120, limits=sandbox._limits(120))
        assert rc == 0, stdout + stderr
        listing = _docker_as_root("-v", f"{holder}:/h", DEFAULT_DOCKER_IMAGE, "-c",
                                  "stat -c '%u %a' /h/run && stat -c %u /h/run/junit.xml && grep -c '<testcase ' /h/run/junit.xml")
        assert listing.stdout.split() == ["65534", "700", "65534", "1"], listing.stdout + listing.stderr
        assert "TOTAL" in stdout  # pytest-cov 也寫得出 .coverage ／ pytest-cov could write .coverage as well
    finally:
        _docker_as_root("-v", f"{holder}:/h", DEFAULT_DOCKER_IMAGE, "-c", "rm -rf /h/run")


@docker_only
def test_real_container_cannot_make_the_host_follow_a_junit_symlink(tmp_path):
    """容器裡的測試在 pytest 寫完報告後（atexit）把 /sandbox/junit.xml 換成指向主機檔案的 symlink：主機拒絕讀回。
    A test in the container swaps /sandbox/junit.xml for a symlink to a host file after pytest wrote the report
    (atexit): the host refuses to read it back."""
    target = tmp_path / "app"
    target.mkdir()
    host_file = tmp_path / "host_secret.xml"
    host_file.write_text(f"<testsuites><testsuite name='{SECRET}'/></testsuites>", encoding="utf-8")
    code = ("import atexit, os\n\n"
            "def _swap():\n"
            "    os.unlink('/sandbox/junit.xml')\n"
            f"    os.symlink({str(host_file)!r}, '/sandbox/junit.xml')\n\n"
            "atexit.register(_swap)\n\n"
            "def test_x():\n    assert True\n")
    rc, _, stderr, _, _, junit_xml = DockerSandbox(timeout_seconds=120).execute_pytest_files(
        {"test_vh_000.py": code}, working_dir=str(target))
    assert junit_xml is None and "symbolic link" in stderr and SECRET not in stderr, (rc, stderr)


# --- 3. POSIX 上的反斜線、各種根目錄 ------------------------------------------------------------------------
# --- 3. Backslashes on POSIX, assorted roots -------------------------------------------------------------------

@pytest.mark.parametrize("root, windows, expected", [
    # POSIX：反斜線是 glob 跳脫字元，不是分隔符 ／ POSIX: a backslash is the glob escape, not a separator
    ("/home/u/a\\b", False, None),
    ("/home/u/a\\b", True, None),            # Windows 規則下沒有磁碟機的 /x 不是絕對路徑 ／ /x without a drive is not absolute under the Windows rules
    ("/srv/app", False, "/srv/app"),
    ("/srv/app//", False, "/srv/app"),       # 結尾斜線 ／ trailing slashes
    ("//srv//app", False, "/srv/app"),
    ("/", False, None),                      # 根目錄本身不篩選 ／ the root itself filters nothing
    ("srv/app", False, None),
    ("/srv/my app", False, "/srv/my app"),   # 空白 ／ spaces
    ("/srv/a#b,c", False, "/srv/a#b,c"),     # # 與 , ／ # and ,
    ("/srv/app[1]", False, None),
    # Windows：磁碟機、UNC、裝置路徑 ／ Windows: drives, UNC, device paths
    ("C:\\proj\\app", False, "C:/proj/app"),  # 磁碟機前綴在任何平台都照 Windows 規則 ／ a drive prefix follows the Windows rules anywhere
    ("C:\\proj\\app", True, "C:/proj/app"),
    ("c:\\proj\\app\\", True, "c:/proj/app"),  # 小寫磁碟機與結尾反斜線 ／ lowercase drive and trailing backslash
    ("C:\\", True, "C:"),                      # 磁碟機根目錄：模式是 C:/** ／ the drive root: the pattern is C:/**
    ("C:/", True, "C:"),
    ("C:foo", True, None),                     # 只有磁碟機的相對路徑 ／ drive-relative
    ("C:foo", False, None),
    ("\\\\server\\share\\x", True, "//server/share/x"),
    ("\\\\server\\share\\x", False, None),     # POSIX：反斜線 ／ POSIX: backslashes
    ("\\\\server", True, None),
    ("\\\\?\\C:\\x", True, None),              # \\?\ 前綴 ／ the \\?\ prefix
    ("\\\\.\\C:\\x", True, None),
    ("C:\\Program Files (x86)\\app", True, None),  # 括號保守地當成特殊字元 ／ parentheses are conservatively metacharacters
    ("C:\\My Projects\\a#b,c", True, "C:/My Projects/a#b,c"),
    ("\\proj", True, None),
    (None, False, None),
    ("", True, None),
])
def test_glob_include_root_edge_cases(root, windows, expected):
    assert _glob_include_root(root, windows) == expected


def test_posix_backslash_path_gets_no_include():
    _, filters = node_coverage_args((22, 14, 0), "/home/u/a\\b", windows=False)
    assert not any(f.startswith("--test-coverage-include") for f in filters)
    assert "--test-coverage-exclude=**/node_modules/**" in filters
    _, root_filters = node_coverage_args((22, 14, 0), "C:\\", windows=True)
    assert root_filters[0] == "--test-coverage-include=C:/**"


# --- 4. 同一目錄的多種拼法 -----------------------------------------------------------------------------------
# --- 4. Several spellings of one directory -----------------------------------------------------------------------

def test_posix_gets_one_include_per_distinct_spelling():
    _, filters = node_coverage_args((22, 14, 0), ["/link/app", "/real/app", "/real/app/"], windows=False)
    assert filters == ["--test-coverage-include=/link/app/**", "--test-coverage-include=/real/app/**",
                       "--test-coverage-exclude=/link/app/**/node_modules/**",
                       "--test-coverage-exclude=/real/app/**/node_modules/**",
                       "--test-coverage-exclude=**/test_vh_*"]
    # 任何一個拼法表達不了就整個不加 include ／ when any spelling cannot be expressed, no include at all
    assert _glob_include_roots(["/link/app", "/real/app[1]"], windows=False) == []


def test_windows_include_only_when_the_spellings_agree():
    assert _glob_include_roots(["c:\\proj\\app", "C:\\proj\\app"], windows=True) == ["C:/proj/app"]
    # 對應的網路磁碟機：abspath 是 Z:\，realpath 是 UNC ／ a mapped drive: abspath is Z:\, realpath is UNC
    assert _glob_include_roots(["Z:\\proj", "\\\\server\\share\\proj"], windows=True) == []
    # 目錄名稱大小寫不同（include 分大小寫） ／ directory-name case differs (the include is case-sensitive)
    assert _glob_include_roots(["C:\\Proj", "C:\\proj"], windows=True) == []
    _, filters = node_coverage_args((22, 14, 0), ["Z:\\proj", "\\\\server\\share\\proj"], windows=True)
    assert not any(f.startswith("--test-coverage-include") for f in filters)
    assert _glob_include_roots("\\\\server\\share\\proj", windows=True) == ["//server/share/proj"]


@posix_only
def test_node_subprocess_sandbox_passes_abspath_and_realpath_includes(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    sandbox = NodeSubprocessSandbox(node_version=(22, 14, 0))
    cmd, _, _ = sandbox._build_command(str(run_dir), ["test_vh_000.mjs"], str(link), True, None, None)
    includes = [a for a in cmd if a.startswith("--test-coverage-include=")]
    assert includes == [f"--test-coverage-include={link}/**", f"--test-coverage-include={os.path.realpath(real)}/**"]


@node_globs_only
@posix_only
def test_real_node_target_behind_a_symlink_is_covered(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "m.mjs").write_text("export const f = (x) => x + 1;\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    code = ('import { test } from "node:test";\nimport assert from "node:assert/strict";\n'
            f'import {{ f }} from "{target_file_url(str(link / "m.mjs"))}";\n'
            'test("a", () => { assert.equal(f(1), 2); });\n')
    sink = JsLineCoverage()
    NodeSubprocessSandbox(timeout_seconds=60, node_version=_NODE_VERSION).execute_pytest_files(
        {"test_vh_000.mjs": code}, working_dir=str(link), collect_coverage=True, coverage_sink=sink)
    assert list(sink.files) == ["m.mjs"] and sink.percent() == 100.0


# --- 5. 擷取輸出的上限（本機與 docker CLI） -------------------------------------------------------------------
# --- 5. The captured-output cap (local and the docker CLI) --------------------------------------------------------

def test_docker_cli_is_capped_and_the_container_logs_nowhere():
    sandbox = DockerSandbox(verify=False)
    assert sandbox._limits(60) == {"file_bytes": SANDBOX_MAX_FILE_BYTES}
    prefix = sandbox._docker_run_prefix("/tmp/run", "/tmp/app", {})
    assert prefix[prefix.index("--ulimit") + 1] == f"fsize={SANDBOX_MAX_FILE_BYTES}"
    assert prefix[prefix.index("--log-driver") + 1] == "none"


def test_docker_output_cap_removes_the_container_and_reads_no_report(tmp_path, monkeypatch):
    sandbox = DockerSandbox(verify=False)
    monkeypatch.setattr(sandbox, "_run", lambda *a, **k: (1, "x", f"write /dev/stdout: file too large\n{OUTPUT_CAP_NOTE}"))
    removed = []
    monkeypatch.setattr(sandbox_mod.subprocess, "run", lambda cmd, **k: removed.append(cmd))
    rc, _, stderr, _, coverage, junit_xml = sandbox.execute_pytest_files(
        {"test_x.py": "def test_x(): pass\n"}, working_dir=str(tmp_path), collect_coverage=True)
    assert rc == EXECUTION_FAILURE_EXIT_CODE and junit_xml is None and coverage is None
    assert stderr.endswith(OUTPUT_CAP_NOTE) and "per-file size cap" in stderr and "單檔大小上限" in stderr
    assert len(removed) == 1 and removed[0][1:3] == ["rm", "-f"]


@posix_only
def test_local_output_cap_is_noted_but_the_report_is_kept(tmp_path):
    flood = ("import os\nfor _ in range(64):\n    try:\n        os.write(1, b'y' * 65536)\n"
             "    except OSError:\n        break\n")
    rc, stdout, stderr = LocalSubprocessSandbox._run([sys.executable, "-c", flood], cwd=str(tmp_path), env=dict(os.environ),
                                                     timeout=60, limits={"file_bytes": 1024 * 1024})
    assert rc == 0 and len(stdout) == 1024 * 1024 and stderr == OUTPUT_CAP_NOTE
    small = LocalSubprocessSandbox._run([sys.executable, "-c", "print('ok')"], cwd=str(tmp_path), env=dict(os.environ),
                                        timeout=60, limits={"file_bytes": 1024 * 1024})
    assert small == (0, "ok\n", "")
    # 本機沙盒只是寫不下更多輸出，報告照常讀回 ／ a local sandbox merely cannot write more output, its reports are read as usual
    assert LocalSubprocessSandbox()._after_output_cap(["python"]) is False


@docker_only
@posix_only
def test_real_docker_cli_output_beyond_the_cap_is_an_error_not_a_crash(tmp_path, monkeypatch):
    """容器輸出超過（這裡縮小成 1 MiB 的）上限：docker CLI 得到 EFBIG 而結束，容器被移除，結果是帶著雙語說明的
    無法正常執行，而不是例外或卡住。
    The container's output exceeds the cap (shrunk to 1 MiB here): the docker CLI gets EFBIG and exits, the container is
    removed, and the outcome is a not-run-correctly result with a bilingual note, not an exception or a hang."""
    target = tmp_path / "app"
    target.mkdir()
    sandbox = DockerSandbox(timeout_seconds=120)
    monkeypatch.setattr(sandbox, "_limits", lambda timeout: {"file_bytes": 1024 * 1024})
    names = []
    original = sandbox._after_timeout
    monkeypatch.setattr(sandbox, "_after_timeout",
                        lambda cmd: (names.append(cmd[cmd.index("--name") + 1]), original(cmd))[1])
    code = "def test_flood():\n    assert False, 'z' * (8 * 1024 * 1024)\n"
    rc, _, stderr, duration, _, junit_xml = sandbox.execute_pytest_files({"test_vh_000.py": code},
                                                                         working_dir=str(target))
    assert rc == EXECUTION_FAILURE_EXIT_CODE and junit_xml is None and stderr.endswith(OUTPUT_CAP_NOTE), stderr[-500:]
    assert len(names) == 1 and duration < 60
    left = subprocess.run(["docker", "ps", "-aq", "--filter", f"name=^{names[0]}$"], capture_output=True, text=True)
    assert left.stdout.strip() == ""


@docker_only
def test_real_docker_cli_keeps_working_under_the_cap(tmp_path):
    target = tmp_path / "app"
    target.mkdir()
    rc, stdout, stderr, _, _, junit_xml = DockerSandbox(timeout_seconds=120).execute_pytest_files(
        {"test_vh_000.py": "def test_ok():\n    print('hello')\n    assert True\n"}, working_dir=str(target))
    assert rc == 0 and junit_xml and "test_ok" in junit_xml and OUTPUT_CAP_NOTE not in stderr, stdout + stderr
