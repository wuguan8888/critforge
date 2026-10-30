"""Composable pipeline stages (mock-safe).

Stage order mirrors the fusion-plan waterfall:
  discovery → probe → crawl → detect → verify → chain → severity-gate

Each stage is a pure/async callable over a shared StageContext. Real network
discovery / crawl / nuclei probes are NOT implemented — mocks only.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Optional

from .attackchain import AttackChain, synthesize
from .detectors import DetectorRegistry, SignalBundle, default_registry
from .engine import EngineConfig, RunResult, ScannerEngine
from .finding import Confidence, Finding
from .hitl import ApprovalRequest, HITLGate
from .oob import NoopOOBChannel, OutOfBandChannel
from .probes import Probe
from .reporting import Report, build_report
from .scope import Scope
from .verify import VerificationResult, Verifier, default_verifier


STAGE_ORDER = (
    "discovery",
    "probe",
    "ai_recon",
    "crawl",
    "detect",
    "verify",
    "ai_judge",
    "chain",
    "severity_gate",
)


@dataclass
class StageContext:
    """Shared mutable bag passed through the stage pipeline."""

    scope: Scope
    raw_targets: list[str]
    probes: list[Probe] = field(default_factory=list)
    detectors: Optional[DetectorRegistry] = None
    engine_config: Optional[EngineConfig] = None
    sink: Any = None
    verifier: Optional[Verifier] = None
    oob: Optional[OutOfBandChannel] = None
    hitl: Optional[HITLGate] = None
    ai: Any = None  # ai_detect.AIBrain (None/disabled -> deterministic path)
    # Outputs accumulated across stages:
    discovered: list[str] = field(default_factory=list)
    crawled_routes: list[str] = field(default_factory=list)
    run: Optional[RunResult] = None
    bundles: dict[str, SignalBundle] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    verifications: list[VerificationResult] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    approvals: list[ApprovalRequest] = field(default_factory=list)
    report: Optional[Report] = None
    meta: dict[str, Any] = field(default_factory=dict)


class Stage(abc.ABC):
    name: str = "stage"

    @abc.abstractmethod
    async def run(self, ctx: StageContext) -> StageContext:
        raise NotImplementedError


class DiscoveryStage(Stage):
    """Asset discovery seed — for local labs, echoes authorized raw targets.

    External ASM (subfinder/FOFA/Shodan) is intentionally not called here;
    range tests stay loopback-scoped.
    """

    name = "discovery"

    async def run(self, ctx: StageContext) -> StageContext:
        ctx.discovered = list(ctx.raw_targets)
        ctx.meta["discovery"] = {
            "count": len(ctx.discovered),
            "mode": "seed_local",
            "note": "no external ASM; targets must already be allowlisted",
        }
        return ctx


class ProbeStage(Stage):
    """Authorize + run safe probes via ScannerEngine."""

    name = "probe"

    async def run(self, ctx: StageContext) -> StageContext:
        targets = ctx.discovered or ctx.raw_targets
        engine = ScannerEngine(
            ctx.scope,
            ctx.probes,
            config=ctx.engine_config,
            sink=ctx.sink,
        )
        ctx.run = await engine.run(targets)
        return ctx


class AIReconStage(Stage):
    """AI recon reasoning: prioritise observed endpoints + suggest extra GET paths.

    Suggestions are filtered (relative, safe-to-fetch, capped) and executed by the
    deterministic loopback-only HttpObserveProbe through the scope-gated engine.
    """

    name = "ai_recon"

    async def run(self, ctx: StageContext) -> StageContext:
        from .ai_detect import observations_from_run

        brain = ctx.ai
        if brain is None or not getattr(brain, "live", False) or not ctx.run:
            ctx.meta["ai_recon"] = {"mode": "offline"}
            return ctx
        obs = observations_from_run(ctx.run)
        tech = sorted({t for r in ctx.run.results for t in ((r.signals or {}).get("tech") or [])})
        plan = await brain.plan_recon({
            "targets": ctx.run.authorized,
            "tech": tech,
            "observed_paths": sorted({str(o.get("path")) for o in obs if o.get("path")})[:150],
            "observations": [{k: o.get(k) for k in ("path", "status", "cls", "content_type")} for o in obs][:120],
        })
        executed = 0
        has_http = any(getattr(p, "name", "") == "http_observe" for p in ctx.probes)
        if plan.get("suggested_paths") and has_http and ctx.run.authorized:
            from .http_probe import HttpObserveProbe

            paths = tuple(s["path"] for s in plan["suggested_paths"])
            engine = ScannerEngine(
                ctx.scope,
                [HttpObserveProbe(paths=paths, discover=False, error_trigger=False, backup_check=False)],
                config=ctx.engine_config,
                sink=ctx.sink,
            )
            extra = await engine.run(list(ctx.run.authorized))
            for r in extra.results:
                r.signals = dict(r.signals or {})
                r.signals["ai_suggested"] = True
            ctx.run.results.extend(extra.results)
            executed = len(paths)
        ctx.meta["ai_recon"] = {**plan, "executed_paths": executed}
        return ctx


class AIJudgeStage(Stage):
    """AI judges every evidence-backed finding (after deterministic verification);
    may promote grounded observations. Its verdict sets the final confidence."""

    name = "ai_judge"

    async def run(self, ctx: StageContext) -> StageContext:
        from .ai_detect import observations_from_run

        brain = ctx.ai
        if brain is None or not getattr(brain, "live", False):
            ctx.meta["ai_judge"] = {"mode": "offline"}
            return ctx
        ctx.findings, stats = await brain.judge(ctx.findings, observations_from_run(ctx.run))
        ctx.meta["ai_judge"] = stats
        return ctx


class CrawlStage(Stage):
    """Crawl / route extraction.

    Prefer routes harvested by safe HTTP probes (loopback-only). Fall back to
    a mock root marker when no HTTP routes were observed (unit-test path).
    """

    name = "crawl"

    async def run(self, ctx: StageContext) -> StageContext:
        routes: list[str] = []
        mode = "mock"
        if ctx.run:
            for r in ctx.run.results:
                if not r.ok:
                    continue
                for path in (r.signals or {}).get("routes") or []:
                    routes.append(str(path))
            routes = sorted(set(routes))
            if routes:
                mode = "http_safe"
            else:
                for raw in ctx.run.authorized:
                    routes.append(raw.rstrip("/") + "/(mock-root)")
        ctx.crawled_routes = routes
        ctx.meta["crawl"] = {"routes": len(routes), "mode": mode}
        return ctx


class DetectStage(Stage):
    """Run plugin detectors over probe signal bundles."""

    name = "detect"

    async def run(self, ctx: StageContext) -> StageContext:
        detectors = ctx.detectors or default_registry()
        findings: list[Finding] = []
        bundles: dict[str, SignalBundle] = {}
        if ctx.run:
            by_target: dict[str, list] = {}
            for r in ctx.run.results:
                by_target.setdefault(r.target, []).append(r)
            for target, results in by_target.items():
                bundle = SignalBundle.from_results(target, results)
                bundles[target] = bundle
                findings.extend(detectors.run_all(bundle))
        from .dedup import merge_findings

        raw = len(findings)
        findings = merge_findings(findings)
        ctx.meta["detect"] = {"raw": raw, "after_dedup": len(findings)}
        ctx.bundles = bundles
        ctx.findings = findings
        return ctx


class VerifyStage(Stage):
    """Three-stage verification + optional HITL recording."""

    name = "verify"

    async def run(self, ctx: StageContext) -> StageContext:
        verifier = ctx.verifier or default_verifier()
        ctx.verifications = verifier.verify_all(ctx.findings, ctx.bundles)
        hitl = ctx.hitl or HITLGate()
        ctx.hitl = hitl
        approvals: list[ApprovalRequest] = []
        for f in ctx.findings:
            req = hitl.maybe_request_for_finding(
                f.id, f.severity, f.confidence, title=f.title
            )
            if req is not None:
                approvals.append(req)
        ctx.approvals = approvals
        return ctx


class ChainStage(Stage):
    """Attack-chain synthesis; only High/Critical endpoints surface."""

    name = "chain"

    async def run(self, ctx: StageContext) -> StageContext:
        ctx.chains = synthesize(ctx.findings)
        chain_findings = [c.to_finding() for c in ctx.chains]
        ctx.findings = list(ctx.findings) + chain_findings
        ctx.meta["chains"] = len(ctx.chains)
        brain = ctx.ai
        if brain is not None and getattr(brain, "live", False):
            ctx.meta["ai_chains"] = await brain.narrate_chains(ctx.chains, ctx.findings)
        else:
            ctx.meta["ai_chains"] = {"mode": "offline"}
        return ctx


class SeverityGateStage(Stage):
    """Apply dual-axis severity × confidence gate → Report."""

    name = "severity_gate"

    async def run(self, ctx: StageContext) -> StageContext:
        meta = {
            **ctx.meta,
            "authorized": ctx.run.authorized if ctx.run else [],
            "rejected": (
                [{"target": t, "reason": r} for t, r in ctx.run.rejected] if ctx.run else []
            ),
            "probe_ok": ctx.run.ok_count if ctx.run else 0,
            "probe_err": ctx.run.err_count if ctx.run else 0,
            "skipped_hosts": ctx.run.skipped_hosts if ctx.run else [],
            "approvals_pending": len(ctx.approvals),
            "verifications": len(ctx.verifications),
            "stages": list(STAGE_ORDER),
        }
        brain = ctx.ai
        meta["ai"] = {
            "enabled": bool(brain is not None and getattr(brain, "live", False)),
            "models": sorted(getattr(brain, "models", set()) or []),
            "calls": list(getattr(brain, "log", []) or []),
        }
        ctx.meta = meta
        ctx.report = build_report(ctx.scope, ctx.findings, meta=meta, apply_gate=True)
        return ctx


def default_stages() -> list[Stage]:
    return [
        DiscoveryStage(),
        ProbeStage(),
        AIReconStage(),
        CrawlStage(),
        DetectStage(),
        VerifyStage(),
        AIJudgeStage(),
        ChainStage(),
        SeverityGateStage(),
    ]


async def run_stages(ctx: StageContext, stages: Optional[list[Stage]] = None) -> StageContext:
    """Execute stages in order. Fail-closed: scope must already be valid."""
    ctx.scope.validate()
    if ctx.oob is None:
        ctx.oob = NoopOOBChannel()
    if ctx.hitl is None:
        ctx.hitl = HITLGate()
    for stage in stages or default_stages():
        ctx = await stage.run(ctx)
    return ctx
