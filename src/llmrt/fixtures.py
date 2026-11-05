"""Optional fixture leases reserve cleanup capacity before creating isolated state."""

import asyncio
import json
import sys
import time
import uuid
from contextlib import asynccontextmanager

from llmrt.policy import self_check
from llmrt.transport import TransportError


async def fixture_request(adapter, method, url, payload, dispatch, cleanup=False):
    timeout = (
        2
        if cleanup
        else min(adapter.config.timeout_seconds, adapter.budget.deadline - time.monotonic())
    )
    if timeout <= 0:
        raise TimeoutError("Fixture setup deadline exceeded")
    async with asyncio.timeout(timeout):
        status, headers, body = await adapter._exchange(method, url, payload, dispatch)
    if not 200 <= status < 300 or headers.get("content-encoding", "identity") != "identity":
        raise TransportError("Fixture control response failed; redirects/compression are disabled")
    try:
        response = json.loads(body)
    except (ValueError, RecursionError):
        raise TransportError("Invalid fixture control response") from None
    if not isinstance(response, dict):
        raise TransportError("Fixture control response must be an object")
    return response


@asynccontextmanager
async def fixture_context(adapter, policy, manifest):
    session = uuid.uuid4().hex
    url = adapter.config.fixture_session_url
    if not url:
        yield manifest, session
        return
    async with adapter.budget.reserve() as cleanup_dispatch:
        try:
            async with adapter.budget.reserve() as setup_dispatch:
                fresh = await fixture_request(
                    adapter, "POST", url, {"session_id": session}, setup_dispatch
                )
            if fresh.get("session_id") != session or self_check(
                policy, fresh, adapter.config.principal
            ):
                raise ValueError("Fresh fixture fails its policy/session self-check")
            yield fresh, session
        finally:
            unwinding = sys.exc_info()[0] is not None
            try:
                await fixture_request(
                    adapter,
                    "DELETE",
                    url.rstrip("/") + "/" + session,
                    None,
                    cleanup_dispatch,
                    cleanup=True,
                )
            except (OSError, ValueError, TransportError, TimeoutError, asyncio.IncompleteReadError):
                if not unwinding:
                    raise TransportError(
                        "Fixture cleanup failed; state removal is unverified"
                    ) from None
