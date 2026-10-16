"""主控台串流的防護：讓 stdout／stderr 寫得出雙語輸出。只用標準函式庫，CLI 可以在解析參數（--help 的中文說明）之前、
載入 harness 之前呼叫它；Action 的 runner 與以函式庫方式使用的 harness 也呼叫同一個函式。
The console-stream guard: makes stdout / stderr able to write the bilingual output. Standard library only, so the
CLI can call it before parsing its arguments (--help's Chinese text) and before loading the harness; the Action
runner and the harness used as a library call the same function."""
import sys

# 能否輸出雙語文字的探測字串（中文、全形斜線、破折號）／ The probe for whether bilingual text can be written
# (Chinese, the full-width slash, a dash)
_STDIO_PROBE = "錯誤／—"


def force_utf8_stdio() -> None:
    """Windows 上把 stdout／stderr 設為 UTF-8（取代無法呈現的字元），讓重導向到 cp950 之類字碼頁時不會當掉或變成亂碼；
    其他平台上，若串流的編碼寫不出雙語文字（例如 PYTHONIOENCODING=ascii、LANG=C），改以 backslashreplace 輸出無法
    編碼的字元，而不是以 UnicodeEncodeError 當掉。具冪等性；串流已能處理或無法重新設定時不做任何事。
    On Windows, makes stdout / stderr UTF-8 (replacing unrenderable characters) so output redirected to a codepage
    such as cp950 never crashes or garbles; elsewhere, when a stream's encoding cannot write the bilingual text (e.g.
    PYTHONIOENCODING=ascii, LANG=C), characters it cannot encode are written with backslashreplace instead of
    crashing with a UnicodeEncodeError. Idempotent, and a no-op where a stream already copes or cannot be
    reconfigured."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            if sys.platform == "win32":
                reconfigure(encoding="utf-8", errors="replace")
                continue
            if getattr(stream, "errors", "strict") != "strict":
                # 已經不會因無法編碼的字元而當掉（例如 stderr 預設的 backslashreplace）
                # Already cannot crash on an unencodable character (e.g. stderr's default backslashreplace)
                continue
            try:
                _STDIO_PROBE.encode(getattr(stream, "encoding", None) or "ascii")
            except (UnicodeEncodeError, LookupError):
                reconfigure(errors="backslashreplace")
        except (OSError, ValueError):
            pass
