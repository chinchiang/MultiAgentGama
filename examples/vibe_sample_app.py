"""
Example of a typical 'Vibe-Coded' microservice application.
Demonstrates common AI-generated shortcuts:
1. Happy path assumption: missing null checks on query results.
2. BOLA / IDOR: missing authorization validation against token claim.
3. Mass assignment: applying arbitrary JSON fields to internal user state.
4. Error leakage: exposing raw internal exceptions to callers.
"""

from typing import Dict, Any, Optional

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
        "profile": None  # Profile can be None!
    }
}


def get_user_profile(user_id: str) -> Dict[str, Any]:
    """
    Vibe-coding flaw: Assumes user always exists and profile is never None.
    Crashes with TypeError if profile is None, or KeyError if user_id not in DB.
    """
    user = DATABASE[user_id]
    # Dangerous direct access:
    return {
        "id": user["id"],
        "bio": user["profile"]["bio"]
    }


def update_user_settings(caller_token_id: str, target_user_id: str, new_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Vibe-coding flaw (BOLA & Mass Assignment):
    1. Does not check if caller_token_id == target_user_id (BOLA / IDOR).
    2. Directly merges new_data into user dictionary, allowing caller to inject is_admin=True or balance=999999.
    """
    user = DATABASE.get(target_user_id)
    if not user:
        return {"status": "error", "message": f"User {target_user_id} not found"}

    # Flaw: Unrestricted mass assignment
    user.update(new_data)
    return {"status": "success", "user": user}


def process_payment_transfer(from_id: str, to_id: str, amount: float) -> Dict[str, Any]:
    """
    Vibe-coding flaw (Missing Transaction Rollback & Negative Amount Check):
    1. Allows negative amounts (reversing transaction to steal funds).
    2. Deducts from sender, but if receiving fails, does not roll back deduction.
    """
    sender = DATABASE.get(from_id)
    recipient = DATABASE.get(to_id)

    # Missing check: if amount <= 0: raise ValueError("Invalid amount")
    sender["balance"] -= amount

    # Simulating potential failure midway
    if not recipient:
        # sender's money was deducted without rollback!
        raise RuntimeError("Recipient database connection lost midway")

    recipient["balance"] += amount
    return {"status": "completed", "sender_balance": sender["balance"]}
