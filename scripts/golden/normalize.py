"""把每次執行都會變的內容換成固定的佔位字，讓兩次執行的輸出可以逐行比對。
Replaces what changes on every run with fixed placeholders, so the output of two runs compares line by line."""

import re

_ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?")
# tempfile.mkdtemp 的字尾是 8 個小寫英數字或底線
# tempfile.mkdtemp's suffix is 8 lowercase letters, digits or underscores
_SANDBOX_DIR = re.compile(r"vibe_sandbox_[a-z0-9_]{8}")
# JSON 的 duration_seconds，以及 Markdown 表格裡的 `1.25s`
# duration_seconds in JSON, and `1.25s` in a Markdown table
_JSON_DURATION = re.compile(r'("duration_seconds": )\d+(?:\.\d+)?')
_MD_DURATION = re.compile(r"`\d+(?:\.\d+)?s`")
# 只換 repr 的「at 0x…」，程式碼裡的十六進位常數保留
# Only a repr's "at 0x…" is replaced; hex constants in code stay
_ADDRESS = re.compile(r"\bat 0x[0-9a-fA-F]+")
# log 行開頭的時刻（logging 的 %H:%M:%S）
# The clock time at the start of a log line (logging's %H:%M:%S)
_CLOCK_PREFIX = re.compile(r"^\d{2}:\d{2}:\d{2} ", re.MULTILINE)


def normalize(text: str, *, stderr: bool = False) -> str:
    """回傳正規化後的文字；stderr=True 時再去掉每行的時刻前綴並排序（執行緒讓 log 行的先後每次不同）。
    Returns the normalised text; with stderr=True, also drops each line's clock prefix and sorts the lines (threads
    interleave log lines differently on every run)."""
    text = _ISO_TIME.sub("<TIME>", text)
    text = _SANDBOX_DIR.sub("vibe_sandbox_<ID>", text)
    text = _JSON_DURATION.sub(r"\1<DURATION>", text)
    text = _MD_DURATION.sub("`<DURATION>s`", text)
    text = _ADDRESS.sub("at 0xADDR", text)
    if stderr:
        text = "".join(line + "\n" for line in sorted(_CLOCK_PREFIX.sub("", text).splitlines()))
    return text
