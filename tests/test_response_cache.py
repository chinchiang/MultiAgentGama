"""回應快取（`vibeharness/core/response_cache.py`）：鍵、讀取與寫入，以及重新詢問時存兩把鍵的規則。
透過閘道的整合行為（`--cache-only`、重新詢問、預算）在 tests/test_review_cache_only.py 與
tests/test_parallel_and_budgets.py。
The response cache (`vibeharness/core/response_cache.py`): the key, lookup and store, and the rule that stores a
re-asked answer under both keys. The integration through the gateway (`--cache-only`, re-asks, the budget) is in
tests/test_review_cache_only.py and tests/test_parallel_and_budgets.py."""
import json

import pytest

from vibeharness.core.response_cache import key, lookup, store

INFO = {"model": "anthropic/claude-x", "fallback_model": "openai/gpt-y", "max_output_tokens": 1234,
        "extra_params": {"top_p": 0.9}, "api_key_env": "K", "api_base": "https://a.example/v1",
        "aws_region_name": "us-east-1", "aws_profile_name": "p"}


def _key(**overrides):
    parts = dict(model_alias="claude", model_info=INFO, temperature=0.2, max_output_tokens=1234,
                 system_prompt="sys prompt", user_prompt="user prompt")
    parts.update(overrides)
    return key(**parts)


def _store(cache_dir, k, **overrides):
    fields = dict(agent_id="whitebox_reviewer_claude", model="anthropic/claude-x", raw_text='{"findings": []}',
                  finish_reason="stop", prompt_sha256="abc")
    fields.update(overrides)
    store(cache_dir, k, **fields)


# --- 鍵 ／ key --------------------------------------------------------------------------------------------------

def test_the_key_is_the_one_master_computes():
    """同一個請求的鍵與 master（`LLMGateway._cache_key`，`ef0d19c`）算出的完全相同：搬家後，舊的快取仍然命中。
    The key of a request is exactly the one master computes (`LLMGateway._cache_key`, `ef0d19c`): after the move an
    existing cache still hits."""
    assert _key() == "73c2bbb6a4077b1f3a90172f6b4c9b75313a45d74aaa6e8779f7435bbe844f6d"


@pytest.mark.parametrize("part, value", [
    ("model_alias", "gpt"), ("temperature", 0.3), ("max_output_tokens", 4096), ("system_prompt", "other sys"),
    ("user_prompt", "other user"), ("model_info", dict(INFO, model="anthropic/claude-z")),
    ("model_info", dict(INFO, fallback_model=None)), ("model_info", dict(INFO, extra_params={"top_p": 0.5})),
])
def test_every_part_of_the_request_is_in_the_key(part, value):
    """請求的每一部分都在鍵內：任何一部分不同，就不會取用到別的請求的回答。
    Every part of the request is in the key: when any part differs, another request's answer is never served."""
    assert _key(**{part: value}) != _key()


@pytest.mark.parametrize("field, value", [
    ("api_base", "https://other.example/v1"), ("aws_region_name", "eu-west-1"),
    ("aws_profile_name", "other"), ("api_key_env", "OTHER_KEY"),
])
def test_the_key_changes_with_the_endpoint(field, value):
    """同一個模型字串指向不同端點／區域／帳號時，快取鍵不同（從 tests/test_review_cli_config.py 搬來）。
    The same model string pointed at another endpoint / region / account gets a different cache key (moved from
    tests/test_review_cli_config.py)."""
    assert _key(model_info=dict(INFO, **{field: value})) != _key()
    assert _key(model_info=dict(INFO)) == _key()


# --- 讀取 ／ lookup ---------------------------------------------------------------------------------------------

def test_lookup_without_a_cache_directory_is_a_miss():
    assert lookup(None, _key()) is None


@pytest.mark.parametrize("content", [
    None,                                   # 沒有檔案 ／ no file
    "{corrupt",                             # 毀損的 JSON ／ corrupt JSON
    "[1, 2]",                               # 不是物件 ／ not an object
    '{"raw_text": 5}',                      # raw_text 不是字串 ／ raw_text is not a string
], ids=["missing", "corrupt", "not-an-object", "raw-text-not-a-string"])
def test_lookup_reads_an_unusable_file_as_a_miss(tmp_path, content):
    """沒有檔案、毀損或形狀不對的檔案都算未命中（毀損的情況從 tests/test_parallel_and_budgets.py 搬來）。
    A missing, corrupt or wrongly shaped file is a miss (the corrupt case moved from
    tests/test_parallel_and_budgets.py)."""
    k = _key()
    if content is not None:
        (tmp_path / f"{k}.json").write_text(content, encoding="utf-8")
    assert lookup(str(tmp_path), k) is None


# --- 寫入 ／ store ----------------------------------------------------------------------------------------------

def test_store_then_lookup_returns_the_entry(tmp_path):
    """寫入的項目讀得回來，磁碟上的欄位與 master 相同，沒有留下暫存檔。
    A stored entry reads back, with the same fields on disk as master, and no temporary file is left."""
    k = _key()
    _store(str(tmp_path), k)
    entry = lookup(str(tmp_path), k)
    assert entry is not None
    assert set(entry) == {"agent_id", "model", "finish_reason", "raw_text", "prompt_sha256", "created_at"}
    assert (entry["agent_id"], entry["model"], entry["finish_reason"], entry["raw_text"], entry["prompt_sha256"]) == (
        "whitebox_reviewer_claude", "anthropic/claude-x", "stop", '{"findings": []}', "abc")
    assert [p.name for p in tmp_path.iterdir()] == [f"{k}.json"]
    assert json.loads((tmp_path / f"{k}.json").read_text(encoding="utf-8")) == entry


def test_store_after_a_re_ask_writes_both_keys(tmp_path):
    """重新詢問後的可用回答存到原始提示的鍵與重新詢問的鍵：之後 --cache-only 對第一次嘗試也會命中。
    A usable answer after a re-ask is stored under the original prompt's key and the re-ask's key: a later
    --cache-only run then hits on the first attempt."""
    original, reask = _key(), _key(user_prompt="user prompt\n\nYour previous answer was unusable")
    _store(str(tmp_path), original, reask_key=reask)
    assert lookup(str(tmp_path), original) == lookup(str(tmp_path), reask)
    assert lookup(str(tmp_path), original) is not None
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([f"{original}.json", f"{reask}.json"])


def test_store_without_a_cache_directory_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _store(None, _key())
    assert list(tmp_path.iterdir()) == []


def test_a_write_that_fails_halfway_leaves_no_torn_entry_at_the_key(tmp_path, monkeypatch, caplog):
    """寫到一半失敗（例如磁碟滿）時，這把鍵的位置不會出現寫了一半的檔案：並行的讀取端只會看到完整的項目或未命中。
    A write that fails halfway (e.g. a full disk) leaves no half-written file at the key: a concurrent reader only ever
    sees a whole entry or a miss."""
    import vibeharness.core.response_cache as rc

    def half_then_fail(obj, f, **kwargs):
        f.write('{"raw_text": "par')
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(rc.json, "dump", half_then_fail)
    k = _key()
    _store(str(tmp_path), k)
    assert not (tmp_path / f"{k}.json").exists()
    assert "Could not write the response cache entry" in caplog.text


def _leftover_temp_files(cache_dir):
    return sorted(p.name for p in cache_dir.iterdir() if p.name.startswith(".tmp-"))


def test_a_write_that_fails_halfway_leaves_no_temp_file(tmp_path, monkeypatch, caplog):
    """寫到一半失敗（例如磁碟滿）時，快取目錄不會留下 `.tmp-*.json`：磁碟滿時每次呼叫都會再失敗一次，
    留下的暫存檔會越積越多，裡面還是寫了一半的模型回答（#145）。
    A write that fails halfway (e.g. a full disk) leaves no `.tmp-*.json` in the cache directory: on a full disk every
    further call fails again, so leftovers would pile up, each holding a half-written model answer (#145)."""
    import vibeharness.core.response_cache as rc

    def half_then_fail(obj, f, **kwargs):
        f.write('{"raw_text": "par')
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(rc.json, "dump", half_then_fail)
    _store(str(tmp_path), _key())
    assert _leftover_temp_files(tmp_path) == []
    assert "Could not write the response cache entry" in caplog.text


def test_a_publish_that_fails_leaves_no_temp_file(tmp_path, monkeypatch, caplog):
    """暫存檔已經寫完，卻無法換到這把鍵的位置（例如權限不足）時，暫存檔也要刪掉（#145）。
    When the temporary file is fully written but cannot be moved onto the key (e.g. a permission error), it is
    removed too (#145)."""
    import vibeharness.core.response_cache as rc

    def refuse(src, dst):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(rc.os, "replace", refuse)
    k = _key()
    _store(str(tmp_path), k)
    assert _leftover_temp_files(tmp_path) == []
    assert not (tmp_path / f"{k}.json").exists()
    assert "Could not write the response cache entry" in caplog.text


def test_a_temp_file_that_cannot_be_removed_still_only_warns(tmp_path, monkeypatch, caplog):
    """寫入失敗後，連暫存檔都刪不掉時，`store` 仍然只記警告、不丟例外：快取寫不進去不能讓模型呼叫失敗（#145）。
    When the write fails and the temporary file cannot be removed either, `store` still only logs a warning and
    does not raise: a cache that cannot be written must not fail the model call (#145)."""
    import vibeharness.core.response_cache as rc

    def full_disk(obj, f, **kwargs):
        raise OSError(28, "No space left on device")

    def refuse(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(rc.json, "dump", full_disk)
    monkeypatch.setattr(rc.os, "unlink", refuse)
    _store(str(tmp_path), _key())
    assert "Could not write the response cache entry" in caplog.text


def test_store_that_cannot_write_warns_and_does_not_raise(tmp_path, caplog):
    """寫不進去（目錄不存在）時只記警告，不讓模型呼叫失敗。
    When it cannot write (the directory does not exist) it only logs a warning; the model call does not fail."""
    _store(str(tmp_path / "missing"), _key())
    assert "Could not write the response cache entry" in caplog.text
