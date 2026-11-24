"""共用的 Node 標記：測試檔用 `from node_marks import node_only` 標記需要真實 Node 的測試，`tests/conftest.py` 匯入這裡的
hook。不是測試模組（檔名不以 `test_` 開頭）。沒有可用的 Node 時，設定 VIBEHARNESS_REQUIRE_NODE=1（CI 每一格測試都有）
就是失敗，否則略過並寫出偵測到的問題（#210）。
The shared Node markers: test files mark tests that need a real Node with `from node_marks import node_only`, and
`tests/conftest.py` imports the hooks here. Not a test module (the name does not start with `test_`). Without a
usable Node, VIBEHARNESS_REQUIRE_NODE=1 (set in every CI test cell) makes such a test fail; otherwise it is skipped
with the detection problem (#210)."""
import os
from typing import Optional, Tuple

import pytest

from vibeharness.core.jscoverage import node_coverage_problem
from vibeharness.core.sandbox import detect_node

NODE_PATH, NODE_VERSION, NODE_PROBLEM = detect_node("node")
NODE_REQUIRED = os.environ.get("VIBEHARNESS_REQUIRE_NODE") == "1"

node_only = pytest.mark.node


def node_feature(unsupported: Optional[str]) -> pytest.MarkDecorator:
    """需要 Node 某項功能的標記：`unsupported` 是這個 Node 缺少那項功能的原因，有那項功能時為 None。完全沒有可用的
    Node 時跟 `node_only` 一樣；有 Node 但缺少功能時一律略過，必須有 Node 也一樣（CONTRIBUTING.md）。
    A marker for a test that needs one Node feature: `unsupported` is why this Node lacks it, None when it has it.
    Without a usable Node at all it acts as `node_only`; a Node that lacks the feature is always skipped, even when
    Node is required (CONTRIBUTING.md)."""
    return pytest.mark.node(unsupported=unsupported)


def node_at_least(minimum: Tuple[int, int, int], feature: str) -> pytest.MarkDecorator:
    """需要 Node >= `minimum` 才有 `feature` 的 `node_feature` 標記 ／ A `node_feature` marker for a `feature` that needs
    Node >= `minimum`."""
    if NODE_VERSION is not None and NODE_VERSION >= minimum:
        return node_feature(None)
    found = "v" + ".".join(map(str, NODE_VERSION)) if NODE_VERSION else "none"
    return node_feature(f"Node >= {'.'.join(map(str, minimum))} ({feature}) unavailable (found {found})")


# 收集 JS/TS 涵蓋率需要的 Node 版本（jscoverage.node_coverage_problem）／ The Node versions JS/TS coverage needs
node_coverage_only = node_feature(None if NODE_VERSION is None else node_coverage_problem(NODE_VERSION))


def pytest_configure(config):
    """註冊 `node` 標記 ／ Registers the `node` marker."""
    config.addinivalue_line("markers", "node: needs a real Node runtime (tests/node_marks.py)")


def _missing_node(item) -> bool:
    return item.get_closest_marker("node") is not None and NODE_PATH is None


def pytest_runtest_setup(item):
    """在建夾具前略過：不必有 Node 時，標了 `node` 而沒有可用 Node 的測試，理由是偵測到的問題；有可用的 Node 但缺少
    `node_feature` 標記的功能時，理由是那項功能缺少的原因。
    Skips before the fixtures are built: when Node is not required, a test marked `node` without a usable Node, with
    the detection problem as the reason; with a usable Node that lacks a `node_feature` marker's feature, with that
    feature's reason."""
    if not NODE_REQUIRED and _missing_node(item):
        pytest.skip(f"Node unavailable: {NODE_PROBLEM}")
    if NODE_PATH is not None:
        for mark in item.iter_markers("node"):
            if mark.kwargs.get("unsupported"):
                pytest.skip(mark.kwargs["unsupported"])


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_call(item):
    """必須有 Node 時，標了 `node` 而沒有可用 Node 的測試在執行階段失敗（在 setup 階段失敗會算成 error，不是 failed）。
    When Node is required, a test marked `node` without a usable Node fails in the call phase (failing in setup would
    count as an error, not a failure)."""
    if NODE_REQUIRED and _missing_node(item):
        pytest.fail(f"VIBEHARNESS_REQUIRE_NODE=1 but no usable Node runtime: {NODE_PROBLEM}", pytrace=False)
