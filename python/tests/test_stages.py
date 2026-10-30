"""Composable stage waterfall tests."""
from __future__ import annotations

import os

import pytest

from critforge.audit import JSONLSink
from critforge.engine import EngineConfig
from critforge.probes import MockSignalProbe, NoOpProbe
from critforge.scope import Severity, load
from critforge.stages import StageContext, default_stages, run_stages

SCOPE = os.path.join(os.path.dirname(__file__), "scope.test.yaml")


@pytest.mark.asyncio
async def test_stages_waterfall(tmp_path):
    scope = load(SCOPE)
    ctx = StageContext(
        scope=scope,
        raw_targets=["https://example.com/app", "evil.out"],
        probes=[
            NoOpProbe(),
            MockSignalProbe(
                {
                    "misconfig_indicator": "banner",
                    "misconfig_severity": "High",
                    "injection_indicator": "q",
                    "repeatable": True,
                    "confirmation_marker": True,
                }
            ),
        ],
        engine_config=EngineConfig(probe_timeout=2.0, actor="test"),
        sink=JSONLSink(str(tmp_path / "a.jsonl")),
    )
    ctx = await run_stages(ctx, default_stages())
    assert ctx.run is not None
    assert "https://example.com/app" in ctx.run.authorized
    assert any(t == "evil.out" for t, _ in ctx.run.rejected)
    assert ctx.findings
    assert ctx.verifications
    assert ctx.report is not None
    # Dual-axis: High severity + calibrated confidence should surface
    assert all(
        f.severity in (Severity.HIGH, Severity.CRITICAL)
        or f.confidence.value  # chain etc.
        for f in ctx.report.findings
    )
    assert ctx.meta.get("stages")
    assert ctx.crawled_routes
