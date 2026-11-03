"""比對兩個情境輸出目錄：正規化後逐行比較，算出不同的行數與種類。
Compares two scenario output directories: normalises them, compares line by line, and counts the differing lines and
the distinct differences."""

import difflib
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from golden.normalize import normalize

# fingerprint（sha1，40 字元）與 prompt_sha256（64 字元）：只在計算種類時合併，行數照原樣算
# Fingerprints (sha1, 40 characters) and prompt_sha256 (64 characters): merged only when counting distinct
# differences; the line count is taken as is
# run_scenarios 記錄這次匯入的 vibeharness 位置的檔名
# The name of the file in which run_scenarios records where vibeharness was imported from
IMPORT_MARKER = "imported_from.txt"

_HASH = re.compile(r"\b(?:[0-9a-f]{64}|[0-9a-f]{40})\b")


@dataclass
class Summary:
    """比對結果：lines 是不同的行數（N），distinct 是 (次數, 行) 的清單，長度就是種類數（M）。
    The comparison result: lines is the number of differing lines (N); distinct lists (count, line), and its length
    is the number of distinct differences (M)."""

    lines: int = 0
    distinct: list[tuple[int, str]] = field(default_factory=list)


def compare(base_out: Path, head_out: Path) -> Summary:
    """比對 base_out 與 head_out 底下的每一個檔案。
    Compares every file under base_out and head_out."""
    differing: list[str] = []
    base_out, head_out = Path(base_out), Path(head_out)
    for rel in sorted(_files(base_out) | _files(head_out)):
        base_lines = _read(base_out / rel)
        head_lines = _read(head_out / rel)
        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, base_lines, head_lines, autojunk=False).get_opcodes():
            if op != "equal":
                differing += ["< " + line for line in base_lines[i1:i2]]
                differing += ["> " + line for line in head_lines[j1:j2]]
    counts = Counter(_HASH.sub("<HASH>", line) for line in differing)
    return Summary(len(differing), sorted(((n, line) for line, n in counts.items()), key=lambda item: (-item[0], item[1])))


def _files(root: Path) -> set[str]:
    """root 底下要比對的每一個檔案的相對路徑（正斜線）；harness log 與 import marker 不算。
    The relative path (forward slashes) of every file under root to compare, leaving out harness logs and the import
    marker."""
    return {
        path.relative_to(root).as_posix() for path in root.rglob("*")
        if path.is_file() and not path.name.endswith(".harness.log") and path.name != IMPORT_MARKER
    }


def _read(path: Path) -> list[str]:
    """讀出正規化後的各行（.stderr 檔依 stderr 的規則）；檔案不存在時是空的。
    Reads the normalised lines (a .stderr file by the stderr rules); empty when the file does not exist."""
    if not path.is_file():
        return []
    return normalize(path.read_text(encoding="utf-8"), stderr=path.name.endswith(".stderr")).splitlines()
