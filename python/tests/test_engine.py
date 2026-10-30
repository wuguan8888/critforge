"""M2 scanner engine tests — orchestration only, safe mock probes."""
from __future__ import annotations

import asyncio
import os

import pytest

from critforge.engine import EngineConfig, RateLimiter, ScannerEngine
from critforge.hardening import FailClosedError
from critforge.probes import MockSignalProbe, NoOpProbe, ProbeResult
from critforge.scope import load
from critforge.target import parse

SCOPE = os.path.join(os.path.dirname(__file__), "scope.test.yaml")


@pytest.fixture
def scope():
    return load(SCOPE)


@pytest.mark.asyncio
async def test_engine_rejects_out_of_scope(scope, tmp_path):
    sink_path = tmp_path / "audit.jsonl"
    from critforge.audit import JSONLSink

    engine = ScannerEngine(
        scope,
        [NoOpProbe()],
        config=EngineConfig(probe_timeout=2.0),
        sink=JSONLSink(str(sink_path)),
    )
    result = await engine.run(["evil.not-in-scope.test", "https://example.com/"])
    assert "https://example.com/" in result.authorized
    assert any(t == "evil.not-in-scope.test" for t, _ in result.rejected)
    assert result.ok_count >= 1


@pytest.mark.asyncio
async def test_engine_denylist_precedence(scope, tmp_path):
    from critforge.audit import JSONLSink

    engine = ScannerEngine(
        scope, [NoOpProbe()], sink=JSONLSink(str(tmp_path / "a.jsonl"))
    )
    # secret.lab.example.com is denylisted even though *.lab.example.com is allowed
    result = await engine.run(["secret.lab.example.com"])
    assert result.authorized == []
    assert len(result.rejected) == 1


@pytest.mark.asyncio
async def test_engine_malformed_target_rejected(scope, tmp_path):
    from critforge.audit import JSONLSink

    engine = ScannerEngine(
        scope, [NoOpProbe()], sink=JSONLSink(str(tmp_path / "a.jsonl"))
    )
    result = await engine.run(["http://"])
    assert result.authorized == []
    assert len(result.rejected) == 1


@pytest.mark.asyncio
async def test_engine_mock_probe_signals(scope, tmp_path):
    from critforge.audit import JSONLSink

    probe = MockSignalProbe({"injection_indicator": "param:q"})
    engine = ScannerEngine(
        scope, [probe], sink=JSONLSink(str(tmp_path / "a.jsonl"))
    )
    result = await engine.run(["example.com"])
    assert result.ok_count == 1
    assert result.results[0].signals["injection_indicator"] == "param:q"


@pytest.mark.asyncio
async def test_engine_probe_failure_isolated(scope, tmp_path):
    from critforge.audit import JSONLSink

    engine = ScannerEngine(
        scope,
        [MockSignalProbe(fail=True), NoOpProbe()],
        sink=JSONLSink(str(tmp_path / "a.jsonl")),
    )
    result = await engine.run(["example.com"])
    assert result.err_count == 1
    assert result.ok_count == 1


@pytest.mark.asyncio
async def test_engine_timeout(scope, tmp_path):
    from critforge.audit import JSONLSink
    from critforge.probes import Probe
    from critforge.target import Target

    class SlowProbe(Probe):
        name = "slow"

        async def observe(self, target: Target, *, timeout: float = 30.0) -> ProbeResult:
            await asyncio.sleep(5.0)
            return ProbeResult(probe=self.name, target=target.raw, ok=True)

    engine = ScannerEngine(
        scope,
        [SlowProbe()],
        config=EngineConfig(probe_timeout=0.05),
        sink=JSONLSink(str(tmp_path / "a.jsonl")),
    )
    result = await engine.run(["example.com"])
    assert result.err_count == 1
    assert "timed out" in (result.results[0].error or "")


def test_rate_limiter_fail_closed():
    with pytest.raises(FailClosedError):
        RateLimiter(0, 1)
    with pytest.raises(FailClosedError):
        RateLimiter(1, 0)


def test_engine_requires_probes(scope):
    with pytest.raises(FailClosedError):
        ScannerEngine(scope, [])


@pytest.mark.asyncio
async def test_host_error_cache_skips_after_threshold(scope, tmp_path):
    from critforge.audit import JSONLSink

    # threshold=2: first two fail probes trip the skip; third is short-circuited
    failing = MockSignalProbe(fail=True)
    failing.name = "fail_a"
    failing2 = MockSignalProbe(fail=True)
    failing2.name = "fail_b"
    later = NoOpProbe()
    engine = ScannerEngine(
        scope,
        [failing, failing2, later],
        config=EngineConfig(probe_timeout=2.0, host_error_threshold=2),
        sink=JSONLSink(str(tmp_path / "a.jsonl")),
    )
    result = await engine.run(["example.com"])
    assert "example.com" in result.skipped_hosts or any(
        "host skipped" in (r.error or "") for r in result.results
    )
    skipped_results = [r for r in result.results if r.error and "host skipped" in r.error]
    assert len(skipped_results) >= 1


def test_host_error_cache_fail_closed():
    from critforge.engine import HostErrorCache

    with pytest.raises(FailClosedError):
        HostErrorCache(0)
