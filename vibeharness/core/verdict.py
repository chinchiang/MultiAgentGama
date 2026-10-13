"""品質閘門的四種判定結果與它們的結束碼。不匯入任何第三方套件：cli 與 action_runner 在載入
pydantic 之前就需要它。
The quality gate's four verdicts and their exit codes. Imports no third-party package: cli and action_runner
need it before pydantic is loaded."""
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    """一次執行的判定結果。值就是報告、--summary-json 與 Action 輸出中的字串。
    A run's verdict. The value is the string in the reports, --summary-json and the Action outputs."""
    READY_TO_SHIP = "READY_TO_SHIP"
    NEEDS_FIXES = "NEEDS_FIXES"
    BLOCKED_CRITICAL_RISK = "BLOCKED_CRITICAL_RISK"
    INCONCLUSIVE = "INCONCLUSIVE"

    # str() 與 f-string 都給出值（Python 3.12 起 str 混入的 Enum 預設會印成 "Verdict.X"）
    # str() and f-strings give the value (since Python 3.12 a str-mixin Enum prints as "Verdict.X" by default)
    __str__ = str.__str__
    __format__ = str.__format__

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES[self]

    @classmethod
    def from_exit_code(cls, code: int) -> Optional["Verdict"]:
        """判定結果的結束碼（0–3）對應的判定結果；其他結束碼不是判定結果，回傳 None。
        The verdict for a verdict exit code (0-3); any other exit code is not a verdict and gives None."""
        return next((v for v, c in _EXIT_CODES.items() if c == code), None)

    @classmethod
    def parse(cls, status: str) -> Optional["Verdict"]:
        """把判定結果字串轉回 Verdict；無法辨識的字串回傳 None。
        Turns a verdict string back into a Verdict; an unrecognized string gives None."""
        try:
            return cls(status)
        except ValueError:
            return None


_EXIT_CODES = {
    Verdict.READY_TO_SHIP: 0,
    Verdict.NEEDS_FIXES: 1,
    Verdict.BLOCKED_CRITICAL_RISK: 2,
    Verdict.INCONCLUSIVE: 3,
}
