"""CritForge FastAPI app (asyncio).

Endpoints:
  GET  /health              — scope spine check (503 on fail-closed)
  POST /authorize           — M1 scope-gate decision
  POST /pipeline/run        — staged waterfall (probe→detect→verify→chain→gate)
  GET  /keys/pending        — M5 pending OAuth authorizations

No exploit / network-attack capability is exposed.
CRITFORGE_SCOPE selects the scope file (default: scope.yaml).
CRITFORGE_SECRETS selects the secrets file (default: secrets.yaml).
"""
from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import audit
from .engine import EngineConfig
from .gate import authorize
from .pipeline import run_pipeline
from .probes import MockSignalProbe, NoOpProbe
from .scope import ScopeError, load
from .secrets import SecretStore

app = FastAPI(title="CritForge", version="0.3.0")


def _scope_path() -> str:
    return os.getenv("CRITFORGE_SCOPE") or "scope.yaml"


def _secrets_path() -> str:
    return os.getenv("CRITFORGE_SECRETS") or "secrets.yaml"


class AuthorizeRequest(BaseModel):
    target: str
    actor: str = "api"


class PipelineRequest(BaseModel):
    targets: list[str] = Field(min_length=1)
    actor: str = "api"
    mock_signals: Optional[dict[str, Any]] = None
    concurrency: int = 8
    per_host: int = 2
    timeout: float = 10.0


@app.get("/health")
async def health():
    sink = audit.default_sink()
    path = _scope_path()
    try:
        scope = load(path)
    except (ScopeError, OSError) as e:
        audit.record(sink, "api", "health.scope_check_failed", path, str(e))
        raise HTTPException(status_code=503, detail=f"scope invalid: {e}")
    audit.record(sink, "api", "health.ok", scope.project, "M7 spine healthy")
    return {
        "status": "ok",
        "project": scope.project,
        "targets": len(scope.allowlist),
        "severity_gate": scope.severity_gate.value,
        "confidence_gate": scope.confidence_gate,
        "version": "0.3.0",
    }


@app.post("/authorize")
async def authorize_endpoint(req: AuthorizeRequest):
    sink = audit.default_sink()
    path = _scope_path()
    try:
        scope = load(path)
    except (ScopeError, OSError) as e:
        raise HTTPException(status_code=503, detail=f"scope invalid: {e}")
    decision = authorize(scope, req.target, actor=req.actor, sink=sink)
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "matched_rule": decision.matched_rule,
        "target": None
        if decision.target is None
        else {
            "scheme": decision.target.scheme,
            "host": decision.target.host,
            "port": decision.target.port,
            "path": decision.target.path,
            "is_ip": decision.target.is_ip,
            "ip_version": decision.target.ip_version,
        },
    }


@app.post("/pipeline/run")
async def pipeline_run(req: PipelineRequest):
    sink = audit.default_sink()
    path = _scope_path()
    try:
        scope = load(path)
    except (ScopeError, OSError) as e:
        raise HTTPException(status_code=503, detail=f"scope invalid: {e}")

    probes = [NoOpProbe()]
    if req.mock_signals:
        probes.append(MockSignalProbe(req.mock_signals))

    store = None
    sp = _secrets_path()
    if os.path.exists(sp):
        store = SecretStore(sp)

    cfg = EngineConfig(
        global_concurrency=req.concurrency,
        per_host_concurrency=req.per_host,
        probe_timeout=req.timeout,
        actor=req.actor,
    )
    result = await run_pipeline(
        scope,
        list(req.targets),
        probes=probes,
        engine_config=cfg,
        sink=sink,
        secret_store=store,
    )
    assert result.report is not None
    return {
        "report": result.report.to_dict(),
        "rejected": [{"target": t, "reason": r} for t, r in result.run.rejected],
        "pending_authorizations": [p.to_dict() for p in result.pending_authorizations],
        "chains": [c.to_dict() for c in result.chains],
        "approvals_pending": [a.to_dict() for a in result.approvals],
        "verifications": len(result.verifications),
    }


@app.get("/keys/pending")
async def keys_pending():
    sp = _secrets_path()
    if not os.path.exists(sp):
        return {"pending": []}
    store = SecretStore(sp)
    return {"pending": [p.to_dict() for p in store.pending()]}
