"""
典型「Vibe-Coded」微服務應用程式的範例。
示範常見的 AI 產生捷徑：
1. 快樂路徑假設：查詢結果缺少 null 檢查。
2. BOLA / IDOR：缺少對照 token 宣告的授權驗證。
3. 大量指派：把任意 JSON 欄位套用到內部的使用者狀態。
4. 錯誤外洩：把原始的內部例外暴露給呼叫端。
Example of a typical 'Vibe-Coded' microservice application.
Demonstrates common AI-generated shortcuts:
1. Happy path assumption: missing null checks on query results.
2. BOLA / IDOR: missing authorization validation against token claim.
3. Mass assignment: applying arbitrary JSON fields to internal user state.
4. Error leakage: exposing raw internal exceptions to callers.
"""

from typing import Dict, Any

# 記憶體內的資料庫模擬
# In-memory database simulation
DATABASE: Dict[str, Dict[str, Any]] = {
    "usr_001": {
        "id": "usr_001",
        "username": "alice",
        "email": "alice@example.com",
        "is_admin": False,
        "balance": 100,
        "profile": {"bio": "Hello world"}
    },
    "usr_002": {
        "id": "usr_002",
        "username": "bob",
        "email": "bob@example.com",
        "is_admin": True,
        "balance": 5000,
        "profile": None  # 個人資料可能是 None！ ／ Profile can be None!
    }
}


def get_user_profile(user_id: str) -> Dict[str, Any]:
    """
    Vibe-coding 缺陷：假設使用者一定存在且 profile 絕不為 None。
    profile 為 None 時以 TypeError 當掉，user_id 不在資料庫時以 KeyError 當掉。
    Vibe-coding flaw: Assumes user always exists and profile is never None.
    Crashes with TypeError if profile is None, or KeyError if user_id not in DB.
    """
    user = DATABASE[user_id]
    # 危險的直接存取：
    # Dangerous direct access:
    return {
        "id": user["id"],
        "bio": user["profile"]["bio"]
    }


def update_user_settings(caller_token_id: str, target_user_id: str, new_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Vibe-coding 缺陷（BOLA 與大量指派）：
    1. 沒有檢查 caller_token_id == target_user_id（BOLA / IDOR）。
    2. 直接把 new_data 合併進使用者字典，讓呼叫端得以注入 is_admin=True 或 balance=999999。
    Vibe-coding flaw (BOLA & Mass Assignment):
    1. Does not check if caller_token_id == target_user_id (BOLA / IDOR).
    2. Directly merges new_data into user dictionary, allowing caller to inject is_admin=True or balance=999999.
    """
    user = DATABASE.get(target_user_id)
    if not user:
        return {"status": "error", "message": f"User {target_user_id} not found"}

    # 缺陷：不受限制的大量指派
    # Flaw: Unrestricted mass assignment
    user.update(new_data)
    return {"status": "success", "user": user}


def process_payment_transfer(from_id: str, to_id: str, amount: float) -> Dict[str, Any]:
    """
    Vibe-coding 缺陷（缺少交易回滾與負數金額檢查）：
    1. 允許負數金額（反轉交易以竊取資金）。
    2. 先從寄件者扣款，但若收款失敗，不會回滾扣款。
    Vibe-coding flaw (Missing Transaction Rollback & Negative Amount Check):
    1. Allows negative amounts (reversing transaction to steal funds).
    2. Deducts from sender, but if receiving fails, does not roll back deduction.
    """
    sender = DATABASE.get(from_id)
    recipient = DATABASE.get(to_id)

    # 缺少的檢查：if amount <= 0: raise ValueError("Invalid amount")
    # Missing check: if amount <= 0: raise ValueError("Invalid amount")
    sender["balance"] -= amount

    # 模擬中途可能發生的失敗
    # Simulating potential failure midway
    if not recipient:
        # 寄件者的錢已被扣除卻沒有回滾！
        # sender's money was deducted without rollback!
        raise RuntimeError("Recipient database connection lost midway")

    recipient["balance"] += amount
    return {"status": "completed", "sender_balance": sender["balance"]}
