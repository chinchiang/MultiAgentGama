"""情境用的目標程式碼，以字串保存，執行時才寫進工作目錄（Q7：不能是會被 CodeQL、ruff、mypy 掃描的 .py 檔）。
The scenarios' target code, kept as strings and written into the working directory at run time (Q7: never .py files
that CodeQL, ruff or mypy would scan)."""

# 有缺陷的小型庫存服務：不存在的品項、負數數量、None 輸入都會出錯；in_stock 正確處理 None，
# 它的探測會通過，突變測試才有通過的測試可用
# A small, flawed inventory service: an unknown item, a negative quantity and None inputs all go wrong; in_stock
# handles None correctly, so its probe passes and mutation testing has a passed test to work with
MOCK_TARGET = {
    "inventory.py": '''\
"""A small inventory service with deliberate flaws, used as a golden diff target."""
from typing import Dict

STOCK: Dict[str, int] = {"apple": 5, "pear": 0}


def reserve(item: str, quantity: int) -> int:
    """Reserve stock; returns what is left. Flaw: no check for unknown items or negative quantities."""
    left = STOCK[item] - quantity
    STOCK[item] = left
    return left


def in_stock(item: str) -> bool:
    """Whether any of item is left; rejects anything that is not a name."""
    if not isinstance(item, str):
        return False
    return STOCK.get(item, 0) > 0


def price_with_tax(price: float, rate: float) -> float:
    """Flaw: crashes on None instead of rejecting it."""
    return round(price * (1 + rate), 2)
''',
}
