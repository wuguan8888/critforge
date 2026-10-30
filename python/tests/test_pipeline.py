"""End-to-end pipeline tests (M2–M5 glue)."""
from __future__ import annotations

import os

import pytest

from critforge.audit import JSONLSink
from critforge.engine import EngineConfig
from critforge.pipeline import run_pipeline
from critforge.probes import MockSignalProbe, NoOpProbe
from critforge.scope import load
from critforge.secrets import SecretStore, InteractiveOAuthProvider

SCOPE = os.path.join(os.path.dirname(__file__), "scope.test.yaml")


@pytest.mark.asyncio
async def test_pipeline_happy_path(tmp_path):
    scope = load(SCOPE)
    store = SecretStore(str(tmp_path / "secrets.yaml"))
    await InteractiveOAuthProvider("github").acquire(store)
    store.save()

    result = await run_pipeline(
        scope,
        ["https://example.com/app", "out.of.scope.invalid"],
        probes=[
            NoOpProbe(),
            MockSignalProbe(
                {
                    "injection_indicator": "id",
                    "misconfig_indicator": "banner",
                    "misconfig_severity": "High",
                }
            ),
        ],
        engine_config=EngineConfig(probe_timeout=2.0, actor="test"),
        sink=JSONLSink(str(tmp_path / "a.jsonl")),
        secret_store=store,
    )
    assert "https://example.com/app" in result.run.authorized
    assert any(t == "out.of.scope.invalid" for t, _ in result.run.rejected)
    assert result.report is not None
    # injection=High + misconfig=High both pass the High gate
    assert len(result.report.findings) >= 2
    assert any(p.platform == "github" for p in result.pending_authorizations)


@pytest.mark.asyncio
async def test_pipeline_fail_closed_empty_targets_ok(tmp_path):
    # empty list is allowed (returns empty run); None would fail closed inside engine
    scope = load(SCOPE)
    result = await run_pipeline(
        scope,
        [],
        probes=[NoOpProbe()],
        sink=JSONLSink(str(tmp_path / "a.jsonl")),
    )
    assert result.run.authorized == []
    assert result.report is not None
    assert result.report.findings == []
