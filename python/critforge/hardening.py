"""M6 Hardening helpers — retries, timeouts, fail-closed wrappers.

Pure asyncio utilities used by the scanner engine and CLI. No network,
no payloads. Fail-closed: empty/None inputs and exhausted retries raise.
"""
from __future__ import annotations

import asyncio
import functools
import random
from typing import Any, Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")


class HardeningError(Exception):
    """Base for hardening-layer failures."""


class TimeoutExceeded(HardeningError):
    pass


class RetriesExhausted(HardeningError):
    pass


class FailClosedError(HardeningError):
    """Raised when a fail-closed precondition is violated."""


async def with_timeout(coro: Awaitable[T], timeout: float, *, label: str = "op") -> T:
    """Await coro with a hard timeout. Raises TimeoutExceeded on expiry."""
    if timeout is None or timeout <= 0:
        raise FailClosedError(f"{label}: timeout must be positive (fail-closed)")
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError as e:
        raise TimeoutExceeded(f"{label}: timed out after {timeout}s") from e


async def retry(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    base_delay: float = 0.05,
    max_delay: float = 2.0,
    jitter: float = 0.1,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    label: str = "op",
) -> T:
    """Retry an async callable with exponential backoff + jitter.

    Fail-closed: attempts < 1 raises immediately. After exhaustion, raises
    RetriesExhausted wrapping the last error.
    """
    if attempts < 1:
        raise FailClosedError(f"{label}: attempts must be >= 1 (fail-closed)")
    last: Optional[BaseException] = None
    for i in range(attempts):
        try:
            return await fn()
        except retry_on as e:  # type: ignore[misc]
            last = e
            if i == attempts - 1:
                break
            delay = min(max_delay, base_delay * (2 ** i))
            delay = delay * (1.0 + random.uniform(-jitter, jitter))
            await asyncio.sleep(max(0.0, delay))
    raise RetriesExhausted(
        f"{label}: retries exhausted after {attempts} attempts: {last}"
    ) from last


def require(condition: Any, message: str) -> None:
    """Fail-closed assertion. Raises FailClosedError if condition is falsy."""
    if not condition:
        raise FailClosedError(message)


def sync_retry(
    attempts: int = 3,
    base_delay: float = 0.01,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
):
    """Decorator for sync callables (used sparingly; prefer async retry)."""

    def deco(fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> T:
            import time

            if attempts < 1:
                raise FailClosedError("attempts must be >= 1 (fail-closed)")
            last: Optional[BaseException] = None
            for i in range(attempts):
                try:
                    return fn(*args, **kwargs)
                except retry_on as e:  # type: ignore[misc]
                    last = e
                    if i == attempts - 1:
                        break
                    time.sleep(base_delay * (2 ** i))
            raise RetriesExhausted(f"retries exhausted: {last}") from last

        return wrapper

    return deco
