"""單一測試結果的判斷（GLOSSARY：未分類失敗、未執行）只定義在 `TestExecutionResult` 上，每種狀態都有固定的答案。
The predicates on one test result (GLOSSARY: Unclassified failure, Not run) are defined only on
`TestExecutionResult`, with a fixed answer for every status."""

import pytest

from vibeharness.core.models import TestExecutionResult, TestStatus


def _result(status, breach=False):
    return TestExecutionResult(test_id="T", test_type="blackbox_security", status=status,
                               is_security_exploit_confirmed=breach)


@pytest.mark.parametrize("status, breach, expected", [
    (TestStatus.PASSED, False, False),
    (TestStatus.FAILED, False, True),
    (TestStatus.FAILED, True, True),
    (TestStatus.ERROR, False, False),
    (TestStatus.SKIPPED, False, False),
])
def test_is_failure_is_true_only_for_failed(status, breach, expected):
    """`is_failure`：只有 FAILED 為真，不論是否為資安突破（白箱失敗就是 FAILED 的白箱測試）。
    `is_failure`: true for FAILED only, Breach or not (a white-box failure is a FAILED white-box test)."""
    assert _result(status, breach).is_failure is expected


@pytest.mark.parametrize("status, expected", [
    (TestStatus.PASSED, False),
    (TestStatus.FAILED, False),
    (TestStatus.ERROR, True),
    (TestStatus.SKIPPED, True),
])
def test_is_not_run_covers_error_and_skipped(status, expected):
    """`is_not_run`（GLOSSARY：未執行）：ERROR 與 SKIPPED 為真；它們不算已執行的證據。
    `is_not_run` (GLOSSARY: Not run): true for ERROR and SKIPPED; they are not Executed evidence."""
    assert _result(status).is_not_run is expected


@pytest.mark.parametrize("status, breach, expected", [
    (TestStatus.PASSED, False, False),
    (TestStatus.FAILED, False, True),
    (TestStatus.FAILED, True, False),
    (TestStatus.ERROR, False, False),
    (TestStatus.SKIPPED, False, False),
])
def test_is_unclassified_failure_is_a_failure_that_is_not_a_breach(status, breach, expected):
    """`is_unclassified_failure`（GLOSSARY：未分類失敗）：FAILED 但不是資安突破；資安突破與未執行都不算。
    `is_unclassified_failure` (GLOSSARY: Unclassified failure): FAILED but not a Breach; neither a Breach nor a Not
    run test counts."""
    assert _result(status, breach).is_unclassified_failure is expected
