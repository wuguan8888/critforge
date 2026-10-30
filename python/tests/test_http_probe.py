"""Localhost-only HTTP probe unit tests (no live lab required for refuse path)."""
from __future__ import annotations

import pytest

from critforge.http_probe import HttpObserveProbe, _is_loopback
from critforge.target import parse


def test_loopback_helper():
    assert _is_loopback("127.0.0.1")
    assert _is_loopback("localhost")
    assert _is_loopback("::1")
    assert not _is_loopback("example.com")
    assert not _is_loopback("8.8.8.8")


@pytest.mark.asyncio
async def test_http_probe_refuses_non_loopback():
    probe = HttpObserveProbe()
    result = await probe.observe(parse("https://example.com"), timeout=2.0)
    assert result.ok is False
    assert "non-loopback" in (result.error or "")


@pytest.mark.asyncio
async def test_offensive_stubs_still_raise():
    from critforge.detectors.real_safe import ReflectionXSSDetector

    with pytest.raises(NotImplementedError):
        ReflectionXSSDetector().craft_offensive_payload("x")
