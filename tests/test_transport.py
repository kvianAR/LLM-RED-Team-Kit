import asyncio

import pytest

from llmrt.config import TargetConfig
from llmrt.transport import Budget, BudgetExceeded, TransportError, read_body, resolve_address


def config(**updates):
    return TargetConfig(
        target_id="demo_target",
        endpoint="http://127.0.0.1:8765/chat",
        policy_file="policy.yaml",
        corpus_dir="corpus",
        auth_token_env="DEMO_TOKEN",
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[8765],
        **updates,
    )


async def test_private_addresses_require_opt_in_and_scope():
    with pytest.raises(TransportError):
        await resolve_address("http://127.0.0.1:8765/chat", config())
    with pytest.raises(TransportError):
        await resolve_address("http://169.254.169.254/", config(allow_private=True))
    parts, address, port = await resolve_address(
        "http://127.0.0.1:8765/chat", config(allow_private=True)
    )
    assert address == "127.0.0.1" and port == 8765


async def test_budget_release_and_used_attempts():
    budget = Budget(config(max_requests=1))
    with pytest.raises(RuntimeError):
        async with budget.reserve():
            raise RuntimeError()
    assert budget.reserved == 0 and budget.used == 0
    async with budget.reserve() as dispatch:
        dispatch()
    assert budget.used == 1 and budget.reserved == 0
    with pytest.raises(BudgetExceeded):
        async with budget.reserve():
            pass


async def test_request_encoding_failure_releases_unused_reservation(demo, monkeypatch):
    from llmrt.config import read_config
    from llmrt.transport import HTTPAdapter

    root, _, _ = demo
    target, _, _ = read_config(root / "protected.yaml")
    monkeypatch.setenv("LLMRT_DEMO_TOKEN", "invalid-unicode-\u00e9")
    budget = Budget(target)
    with pytest.raises(UnicodeError):
        await HTTPAdapter(target, budget).request("GET", target.trusted_fixture_url)
    assert budget.used == budget.reserved == 0


@pytest.mark.parametrize(
    "headers,body",
    [
        ({"content-length": "9999"}, b""),
        ({"transfer-encoding": "chunked", "content-length": "1"}, b""),
        ({"transfer-encoding": "chunked"}, b"-1\r\n"),
        ({"transfer-encoding": "chunked"}, b"100\r\n"),
    ],
)
async def test_response_framing_limits(headers, body):
    reader = asyncio.StreamReader()
    reader.feed_data(body)
    reader.feed_eof()
    with pytest.raises(TransportError):
        await read_body(reader, headers, 100)
