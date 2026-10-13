"""扇出模組（core/fanout.py）：依呼叫順序收集結果、當掉的呼叫換成 fallback 並記成無效呼叫、live 失敗或中斷時
佇列中的呼叫不會開始。各代理只各保留一個接線測試，確認當機記在自己的 agent_id 名下。
The fan-out module (core/fanout.py): results are collected in call order, a crashed call takes the fallback and is
booked as an invalid call, and after a live failure or an interrupt no queued call starts. Each agent keeps only one
wiring test that its crash is booked under its own agent_id."""
import logging
import os
import threading
import time

import pytest

from vibeharness.core.fanout import Call, fan_out
from vibeharness.core.i18n import bi
from vibeharness.core.llm_gateway import REASON_CALL_CRASHED, LLMGateway, LLMGatewayError

CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vibeharness", "config", "agents_config.yaml")
AGENT = "whitebox_reviewer_claude"
LOGGER = logging.getLogger("VibeHarness.FanOutTest")


def _gateway(max_concurrent_calls=4):
    gateway = LLMGateway(CONFIG, execution_mode="mock")
    gateway.max_concurrent_calls = max_concurrent_calls
    return gateway


def _call(run, label=("標籤", "label")):
    return Call(AGENT, label, run)


def test_results_come_back_in_call_order_even_when_later_calls_finish_first():
    def answer(i):
        def run():
            time.sleep(0.02 * (5 - i))  # 以相反順序完成 ／ finish in reverse order
            return i
        return run
    assert fan_out(_gateway(), [_call(answer(i)) for i in range(5)], fallback=None, logger=LOGGER) == [0, 1, 2, 3, 4]


def test_a_successful_none_is_kept_not_replaced_by_the_fallback():
    assert fan_out(_gateway(), [_call(lambda: None)], fallback="fallback", logger=LOGGER) == [None]


def test_a_crash_takes_the_fallback_and_is_booked_under_its_agent(caplog):
    def boom():
        raise ValueError("x")
    gateway = _gateway()
    with caplog.at_level(logging.ERROR, logger=LOGGER.name):
        results = fan_out(gateway, [_call(lambda: 1), _call(boom, ("第二批", "batch two")), _call(lambda: 3)],
                          fallback="fallback", logger=LOGGER)
    assert results == [1, "fallback", 3]
    (record,) = gateway.invalid_calls
    assert record.agent_id == AGENT and record.model_alias == "claude"
    assert record.reason == f"{REASON_CALL_CRASHED}: ValueError: x"
    # 錯誤行由呼叫端的 logger 寫出，標籤的中英兩半各自接上「失敗」 ／ the caller's logger writes the error line, each half
    # of the label followed by "failed"
    assert [(r.name, r.levelno, r.getMessage()) for r in caplog.records] == [
        (LOGGER.name, logging.ERROR, bi("第二批失敗：ValueError: x", "batch two failed: ValueError: x"))]


@pytest.mark.parametrize("fatal", [LLMGatewayError("down"), KeyboardInterrupt()])
def test_a_fatal_failure_starts_no_queued_call_and_propagates(fatal):
    started = []
    lock = threading.Lock()

    def call(i):
        def run():
            with lock:
                started.append(i)
            if i == 0:
                raise fatal
            time.sleep(0.05)
            return i
        return _call(run)
    gateway = _gateway(max_concurrent_calls=1)
    with pytest.raises(type(fatal)) as raised:
        fan_out(gateway, [call(i) for i in range(6)], fallback=None, logger=LOGGER)
    assert raised.value is fatal and started == [0]
    assert not gateway.invalid_calls  # 致命的失敗不是當機，不會記成無效呼叫 ／ a fatal failure is not a crash and is not booked


def test_the_fatal_failure_propagates_even_when_an_earlier_call_is_still_running():
    gate = threading.Event()
    started = []

    def slow():
        gate.wait(2)
        return "slow"

    def fatal():
        try:
            raise LLMGatewayError("down")
        finally:
            gate.set()

    def never():
        started.append("never")
        return "never"
    with pytest.raises(LLMGatewayError):
        fan_out(_gateway(max_concurrent_calls=2), [_call(slow), _call(fatal), _call(never)], fallback=None, logger=LOGGER)
    assert started == []


def test_concurrency_never_exceeds_max_concurrent_calls():
    lock = threading.Lock()
    state = {"in_flight": 0, "peak": 0}

    def run():
        with lock:
            state["in_flight"] += 1
            state["peak"] = max(state["peak"], state["in_flight"])
        time.sleep(0.02)
        with lock:
            state["in_flight"] -= 1
    fan_out(_gateway(max_concurrent_calls=2), [_call(run) for _ in range(6)], fallback=None, logger=LOGGER)
    assert state["peak"] == 2


def test_no_calls_returns_an_empty_list_without_a_pool(monkeypatch):
    def no_pool(*a, **k):
        raise AssertionError("no thread pool may be opened for an empty list of calls")
    monkeypatch.setattr("vibeharness.core.fanout.ThreadPoolExecutor", no_pool)
    assert fan_out(_gateway(), [], fallback=None, logger=LOGGER) == []
