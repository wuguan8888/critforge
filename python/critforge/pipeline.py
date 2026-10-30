"""End-to-end black-box pipeline: staged waterfall over M0–M7.

Glues authorize → (mock) discover → probe → crawl → detect → verify →
chain → dual-axis gate → report. Methodology-only: safe probes, signal
detectors, no exploit payloads, no real network attacks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import audit
from .attackchain import AttackChain
from .detectors import DetectorRegistry, default_registry
from .engine import EngineConfig, RunResult
from .finding import Finding
from .hitl import ApprovalRequest, HITLGate
from .oob import NoopOOBChannel, OutOfBandChannel
from .probes import Probe, default_registry as default_probe_registry
from .reporting import Report
from .scope import Scope
from .secrets import PendingAuthorization, SecretStore
from .stages import StageContext, default_stages, run_stages
from .verify import VerificationResult, Verifier, default_verifier


@dataclass
class PipelineResult:
    run: RunResult
    findings: list[Finding] = field(default_factory=list)
    report: Optional[Report] = None
    pending_authorizations: list[PendingAuthorization] = field(default_factory=list)
    verifications: list[VerificationResult] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    approvals: list[ApprovalRequest] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def _default_brain(mode: Optional[str]):
    """AI on when a DeepSeek key resolves (mode auto/on); off -> deterministic."""
    from .ai_detect import AIBrain, ai_mode_from_env

    mode = (mode or ai_mode_from_env()).lower()
    try:
        return AIBrain.auto(mode)
    except Exception:  # noqa: BLE001 - never block the scan on AI setup
        return AIBrain(enabled=False)


async def run_pipeline(
    scope: Scope,
    raw_targets: list[str],
    *,
    probes: Optional[list[Probe]] = None,
    detectors: Optional[DetectorRegistry] = None,
    engine_config: Optional[EngineConfig] = None,
    sink: Optional[audit.Sink] = None,
    secret_store: Optional[SecretStore] = None,
    apply_severity_gate: bool = True,  # retained for API compat; stages always gate
    verifier: Optional[Verifier] = None,
    oob: Optional[OutOfBandChannel] = None,
    hitl: Optional[HITLGate] = None,
    ai: Any = None,
    ai_mode: Optional[str] = None,
) -> PipelineResult:
    """Run the staged waterfall. Fail-closed on bad scope."""
    del apply_severity_gate  # stages always apply dual-axis gate at the end
    scope.validate()
    sink = sink or audit.default_sink()
    if probes is None:
        probes = default_probe_registry().all()
    if detectors is None:
        detectors = default_registry()

    ctx = StageContext(
        scope=scope,
        raw_targets=raw_targets,
        probes=probes,
        detectors=detectors,
        engine_config=engine_config,
        sink=sink,
        verifier=verifier or default_verifier(),
        oob=oob or NoopOOBChannel(),
        hitl=hitl or HITLGate(),
        ai=ai if ai is not None else _default_brain(ai_mode),
    )
    ctx = await run_stages(ctx, default_stages())

    pending: list[PendingAuthorization] = []
    if secret_store is not None:
        pending = secret_store.pending()

    run = ctx.run or RunResult()
    audit.record(
        sink,
        (engine_config.actor if engine_config else "pipeline"),
        "pipeline.complete",
        scope.project,
        f"findings={len(ctx.report.findings) if ctx.report else 0} "
        f"suppressed={len(ctx.report.suppressed) if ctx.report else 0} "
        f"chains={len(ctx.chains)} approvals={len(ctx.approvals)} "
        f"pending_authz={len(pending)}",
    )
    return PipelineResult(
        run=run,
        findings=list(ctx.findings),
        report=ctx.report,
        pending_authorizations=pending,
        verifications=list(ctx.verifications),
        chains=list(ctx.chains),
        approvals=list(ctx.approvals),
        meta=dict(ctx.meta),
    )
