"""固定輸出文字的中／英雙語工具：報告、終端機、日誌與原因字串都寫成「中文 ／ English」。
Bilingual (Traditional Chinese / English) helpers for every fixed output string: reports, console,
logs and reason strings are written as "中文 ／ English".

模型提示詞維持英文：雙語原因要進入提示詞之前先用 `en_only` 取英文半。
Model prompts stay English: use `en_only` before a bilingual reason goes into a prompt.
"""
import re
from typing import Optional, Tuple

# 全形斜線（U+FF0F）前後各一個半形空格，與設定檔、CLI --help 的慣例相同
# A full-width slash (U+FF0F) with one ASCII space on each side, the same convention as the config files and CLI --help
SEP = " ／ "

_CJK_RE = re.compile(r"[㐀-䶿一-鿿豈-﫿]")


def bi(zh: str, en: str) -> str:
    """把中文與英文組成一條雙語輸出字串。
    Joins the Chinese and the English form of one output string."""
    return f"{zh}{SEP}{en}"


def _bilingual_split(text: str) -> Optional[Tuple[str, str]]:
    """`bi()` 產生的字串在最後一個分隔符處切成（中文半, 英文半）；否則為 None。

    只有分隔符前面含中日韓表意文字、後面不含時才算 `bi()` 的產物：模型自己寫的中文描述
    可能剛好含有「 ／ 」，切開它會把描述截斷成最後一小段。
    (Chinese half, English half) of a `bi()` string, split at the last separator; else None.

    Only text with CJK before the separator and none after it counts as `bi()` output: a model's own
    Chinese description may happen to contain " ／ ", and splitting it would truncate the description
    to its last fragment.
    """
    head, sep, tail = (text or "").rpartition(SEP)
    if sep and _CJK_RE.search(head) and not _CJK_RE.search(tail):
        return head, tail
    return None


def en_only(text: str) -> str:
    """取雙語字串的英文半（最後一個分隔符之後）；不是 `bi()` 產生的字串就原樣回傳。
    The English half of a bilingual string (after the last separator); text not produced by `bi()` is unchanged."""
    parts = _bilingual_split(text)
    return parts[1] if parts else text


def zh_only(text: str) -> str:
    """取雙語字串的中文半（最後一個分隔符之前）；不是 `bi()` 產生的字串就原樣回傳。
    The Chinese half of a bilingual string (before the last separator); text not produced by `bi()` is unchanged."""
    parts = _bilingual_split(text)
    return parts[0] if parts else text


def has_cjk(text: str) -> bool:
    """文字是否含有中日韓表意文字（供測試檢查雙語與提示詞純英文）。
    Whether the text contains CJK ideographs (tests use it to check bilingual output and English-only prompts)."""
    return bool(_CJK_RE.search(text or ""))
