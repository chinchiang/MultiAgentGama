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

# live 情境的目標：假 litellm 依函式名稱寫測試，讓每一種結果都出現（見 fake_llm）
# The live scenarios' target: the fake litellm writes tests by function name, so every kind of result shows up (see
# fake_llm)
LIVE_TARGET = {
    "shop.py": '''\
"""A small shop with deliberate flaws, used as a golden diff target."""
from typing import Dict

ORDERS: Dict[int, dict] = {1: {"owner": "alice", "total": 30}, 2: {"owner": "bob", "total": 99}}
ROLES: Dict[str, str] = {"alice": "user", "root": "admin"}


def get_order(order_id: int, user: str) -> dict:
    """Flaw: any user can read any order (no owner check)."""
    return ORDERS[order_id]


def apply_discount(total: float, percent: float) -> float:
    """Flaw: a discount over 100 percent makes the total negative."""
    return total - total * percent / 100


def safe_quantity(value: int) -> int:
    """Correct: rejects anything that is not a positive integer."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("quantity must be a positive integer")
    return value


def lookup_role(name: str) -> str:
    """Flaw: an unknown user raises KeyError instead of getting the guest role."""
    return ROLES[name]
''',
}
