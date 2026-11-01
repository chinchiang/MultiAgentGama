"""`scripts/test_sdist.py`：在本機重現 CI 的 package job（建 sdist、解開、在裡面跑測試）。
`scripts/test_sdist.py`: reproduces CI's package job locally (build the sdist, extract it, run the tests inside)."""

import importlib.util
import io
import os
import sys
import tarfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("test_sdist_tool", os.path.join(REPO_ROOT, "scripts", "test_sdist.py"))
assert _spec and _spec.loader
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)


def _write_sdist(outdir, members=("pkg-1.0/tests/test_a.py",)):
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "pkg-1.0.tar.gz")
    with tarfile.open(path, "w:gz") as tar:
        for name in members:
            data = b"def test_a():\n    assert True\n"
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


class FakeRunner:
    """記下每個指令；build 那一步寫出一個 sdist，其餘回傳設定好的 exit code。
    Records every command; the build step writes an sdist, the others return the configured exit code."""

    def __init__(self, build_code=0, pytest_code=0):
        self.calls, self.build_code, self.pytest_code = [], build_code, pytest_code

    def __call__(self, cmd, cwd, env=None):
        self.calls.append((list(cmd), cwd, env))
        if "build" in cmd:
            if self.build_code == 0:
                _write_sdist(cmd[cmd.index("--outdir") + 1])
            return self.build_code
        return self.pytest_code


def test_the_suite_runs_inside_the_extracted_sdist_with_vibeharness_sdist_set():
    """pytest 在解開的專案目錄裡執行，帶 CI 的參數、使用者的參數，以及指向封存檔的 VIBEHARNESS_SDIST。
    pytest runs in the extracted project directory with CI's arguments, the user's arguments and VIBEHARNESS_SDIST
    pointing at the archive."""
    run = FakeRunner(pytest_code=0)
    assert tool.run_sdist_tests(["tests/test_a.py", "-k", "x"], run=run, python="py") == 0
    (build, build_cwd, _), (pytest_cmd, cwd, env) = run.calls
    assert build[:5] == ["py", "-m", "build", "--sdist", "--outdir"] and "--no-isolation" not in build
    assert build_cwd == tool.REPO_ROOT
    assert pytest_cmd == ["py", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_a.py", "-k", "x"]
    assert os.path.basename(cwd) == "pkg-1.0" and os.path.basename(os.path.dirname(cwd)) == "src"
    assert env["VIBEHARNESS_SDIST"].endswith("pkg-1.0.tar.gz")
    # 跑完後暫存目錄已刪除 ／ The temporary directory is gone afterwards
    assert not os.path.exists(cwd)


def test_a_failing_suite_returns_its_exit_code():
    """測試失敗時回傳 pytest 的 exit code。
    A failing suite returns pytest's exit code."""
    assert tool.run_sdist_tests([], run=FakeRunner(pytest_code=1), python="py") == 1


def test_a_failed_build_stops_before_pytest():
    """建置失敗時回傳建置的 exit code，不跑 pytest。
    A failed build returns the build's exit code and never runs pytest."""
    run = FakeRunner(build_code=3)
    assert tool.run_sdist_tests([], run=run, python="py") == 3
    assert len(run.calls) == 1


def test_main_passes_no_isolation_to_build_and_the_rest_to_pytest(monkeypatch):
    """`--no-isolation` 交給 build，其餘參數交給 pytest。
    `--no-isolation` goes to build, every other argument to pytest."""
    seen = {}
    monkeypatch.setattr(tool, "run_sdist_tests", lambda args, isolation=True: seen.update(args=args, isolation=isolation) or 0)
    assert tool.main(["--no-isolation", "tests/test_a.py"]) == 0
    assert seen == {"args": ["tests/test_a.py"], "isolation": False}
    assert tool.main([]) == 0 and seen == {"args": [], "isolation": True}


def test_extract_needs_exactly_one_top_level_directory(tmp_path):
    """封存檔必須只有一個頂層目錄（sdist 的格式）。
    The archive must have exactly one top-level directory (the sdist layout)."""
    archive = _write_sdist(str(tmp_path / "d"), members=("a-1/x.py", "b-1/y.py"))
    with pytest.raises(RuntimeError, match="one top-level directory"):
        tool.extract(archive, str(tmp_path / "out"))


@pytest.mark.skipif(not hasattr(tarfile, "data_filter"), reason="needs tarfile's data filter (Python 3.11.4+)")
def test_extract_refuses_a_path_outside_the_destination(tmp_path):
    """封存檔裡的 `..` 路徑會被 data filter 拒絕，不會寫到目的地之外。
    A `..` path in the archive is refused by the data filter and never written outside the destination."""
    archive = _write_sdist(str(tmp_path / "d"), members=("pkg-1.0/ok.py", "../escaped.py"))
    with pytest.raises(tarfile.FilterError):
        tool.extract(archive, str(tmp_path / "out"))
    assert not (tmp_path / "escaped.py").exists()
