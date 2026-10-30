"""M6 hardening helpers."""
from __future__ import annotations

import asyncio

import pytest

from critforge.hardening import (
    FailClosedError,
    RetriesExhausted,
    TimeoutExceeded,
    require,
    retry,
    with_timeout,
)


@pytest.mark.asyncio
async def test_with_timeout_ok():
    async def ok():
        return 42

    assert await with_timeout(ok(), 1.0) == 42


@pytest.mark.asyncio
async def test_with_timeout_expires():
    async def slow():
        await asyncio.sleep(1.0)
        return 1

    with pytest.raises(TimeoutExceeded):
        await with_timeout(slow(), 0.05, label="slow")


@pytest.mark.asyncio
async def test_with_timeout_fail_closed_nonpositive():
    async def ok():
        return 1

    coro = ok()
    try:
        with pytest.raises(FailClosedError):
            await with_timeout(coro, 0)
    finally:
        coro.close()


@pytest.mark.asyncio
async def test_retry_succeeds_after_failures():
    state = {"n": 0}

    async def flaky():
        state["n"] += 1
        if state["n"] < 3:
            raise RuntimeError("nope")
        return "ok"

    assert await retry(flaky, attempts=3, base_delay=0.001) == "ok"


@pytest.mark.asyncio
async def test_retry_exhausted():
    async def always():
        raise ValueError("x")

    with pytest.raises(RetriesExhausted):
        await retry(always, attempts=2, base_delay=0.001)


@pytest.mark.asyncio
async def test_retry_fail_closed_zero_attempts():
    async def ok():
        return 1

    with pytest.raises(FailClosedError):
        await retry(ok, attempts=0)


def test_require():
    require(True, "ok")
    with pytest.raises(FailClosedError):
        require(False, "boom")
