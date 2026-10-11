"""Windows 的環境變數上限是 32767 個字元。pytest 會把測試 ID 寫進 PYTEST_CURRENT_TEST，數十 KB 到 1 MB 的
參數字串會讓測試在 setup 就失敗（ValueError），所以長字串參數改用短 ID。
Windows caps an environment variable at 32767 characters. pytest writes the test id into PYTEST_CURRENT_TEST, so a
parameter string of tens of KB to 1 MB fails the test at setup (ValueError); long string parameters get a short id."""

# CreateProcess / os.environ 的上限 ／ the CreateProcess / os.environ limit
_WINDOWS_ENV_LIMIT = 32767


def test_long_string_parameters_stay_under_the_windows_env_limit(request):
    """註冊的 pytest_make_parametrize_id 必須把會塞爆 PYTEST_CURRENT_TEST 的字串收成短 ID，短字串則維持 pytest 自己的 ID。
    The registered pytest_make_parametrize_id must shorten strings that would overflow PYTEST_CURRENT_TEST, and leave
    short strings to pytest's own id."""
    make_id = request.config.hook.pytest_make_parametrize_id
    samples = [
        ("code", "=>" * 20000),                 # test_pathological_lines_lex_in_linear_time
        ("text", "\n" * 1_000_000),             # test_line_heavy_input_is_fast
        ("body", "    subprocess.run(cmd)\n" * 4000),  # test_many_sinks_and_deep_chains_scan_in_linear_time
    ]
    for argname, value in samples:
        assert len(value) > _WINDOWS_ENV_LIMIT
        ident = make_id(config=request.config, val=value, argname=argname)
        nodeid = f"tests/test_r3_extractor_scanner.py::test_name[{ident}] (setup)"
        assert isinstance(ident, str) and len(ident) < 80, ident
        assert len(nodeid) < _WINDOWS_ENV_LIMIT
        assert value[:12] not in ident
    assert make_id(config=request.config, val="arrows.ts", argname="name") is None
