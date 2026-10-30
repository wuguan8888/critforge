"""M2 Scanner engine — async orchestration, rate limiting, host-error cache.

This is the orchestration framework that would drive probes. It:
  - Requires a validated Scope (fail-closed if missing/empty).
  - Runs EVERY raw target through the M1 authorize() gate BEFORE any probe.
  - Applies per-host and global concurrency limits (semaphores).
  - Skips a host after N consecutive probe failures (host-error cache).
  - Aggregates ProbeResults; supports cancellation and per-probe timeouts.

CRITICAL: This engine does NOT perform network scanning or attacks. It only
orchestrates pluggable Probe objects. Ship with NoOpProbe / MockSignalProbe
for tests. Real offensive probes are intentionally out of scope.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from . import audit
from .gate import authorize
from .hardening import FailClosedError, TimeoutExceeded, require, with_timeout
from .probes import Probe, ProbeResult
from .scope import Scope


@dataclass
class EngineConfig:
    """Tunables for the async runner."""

    global_concurrency: int = 8
    per_host_concurrency: int = 2
    probe_timeout: float = 10.0
    actor: str = "engine"
    # Host-error cache: skip further probes on a host after this many failures.
    host_error_threshold: int = 3


@dataclass
class RunResult:
    """Aggregated outcome of one engine.run() invocation."""

    authorized: list[str] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (raw, reason)
    results: list[ProbeResult] = field(default_factory=list)
    skipped_hosts: list[str] = field(default_factory=list)
    cancelled: bool = False
    duration_ms: float = 0.0

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def err_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)


class HostErrorCache:
    """Per-host consecutive-failure counter. Skip host once threshold is hit."""

    def __init__(self, threshold: int = 3) -> None:
        require(threshold >= 1, "host_error_threshold must be >= 1 (fail-closed)")
        self.threshold = threshold
        self._failures: dict[str, int] = defaultdict(int)
        self._skipped: set[str] = set()

    def record_failure(self, host: str) -> bool:
        """Record a failure. Returns True if the host is now skipped."""
        self._failures[host] += 1
        if self._failures[host] >= self.threshold:
            self._skipped.add(host)
            return True
        return False

    def record_success(self, host: str) -> None:
        self._failures[host] = 0

    def is_skipped(self, host: str) -> bool:
        return host in self._skipped

    @property
    def skipped_hosts(self) -> list[str]:
        return sorted(self._skipped)


class RateLimiter:
    """Per-host + global concurrency limiter via asyncio.Semaphore."""

    def __init__(self, global_limit: int, per_host_limit: int) -> None:
        require(global_limit >= 1, "global_concurrency must be >= 1 (fail-closed)")
        require(per_host_limit >= 1, "per_host_concurrency must be >= 1 (fail-closed)")
        self._global = asyncio.Semaphore(global_limit)
        self._per_host: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(per_host_limit)
        )
        self._per_host_limit = per_host_limit

    def host_sem(self, host: str) -> asyncio.Semaphore:
        return self._per_host[host]

    @property
    def global_sem(self) -> asyncio.Semaphore:
        return self._global


class ScannerEngine:
    """Authorize-then-probe orchestration engine with host-error cache."""

    def __init__(
        self,
        scope: Scope,
        probes: list[Probe],
        *,
        config: Optional[EngineConfig] = None,
        sink: Optional[audit.Sink] = None,
    ) -> None:
        require(scope is not None, "scope is required (fail-closed)")
        scope.validate()
        require(probes, "at least one probe is required (fail-closed)")
        self.scope = scope
        self.probes = list(probes)
        self.config = config or EngineConfig()
        self.sink = sink or audit.default_sink()
        self._limiter = RateLimiter(
            self.config.global_concurrency, self.config.per_host_concurrency
        )
        self._errors = HostErrorCache(self.config.host_error_threshold)
        self._cancel = asyncio.Event()

    def cancel(self) -> None:
        self._cancel.set()

    async def run(self, raw_targets: list[str]) -> RunResult:
        """Authorize each target, then run all probes against allowed ones."""
        require(raw_targets is not None, "targets list is required (fail-closed)")
        t0 = time.perf_counter()
        out = RunResult()

        allowed: list[tuple[str, object]] = []
        for raw in raw_targets:
            decision = authorize(
                self.scope, raw, actor=self.config.actor, sink=self.sink
            )
            if not decision.allowed or decision.target is None:
                out.rejected.append((raw, decision.reason))
                continue
            out.authorized.append(raw)
            allowed.append((raw, decision.target))

        if not allowed:
            out.duration_ms = (time.perf_counter() - t0) * 1000
            audit.record(
                self.sink,
                self.config.actor,
                "engine.run.empty",
                self.scope.project,
                "no authorized targets",
            )
            return out

        # Schedule serially per (target, probe) so the host-error cache can
        # short-circuit subsequent probes on a failing host. Concurrency is
        # still applied inside _run_one via semaphores; we gather by target
        # groups to preserve skip semantics without races on the counter.
        for raw, target in allowed:
            host = target.host  # type: ignore[attr-defined]
            for probe in self.probes:
                if self._errors.is_skipped(host):
                    out.results.append(
                        ProbeResult(
                            probe=probe.name,
                            target=target.raw,  # type: ignore[attr-defined]
                            ok=False,
                            error=f"host skipped after {self.config.host_error_threshold} failures",
                        )
                    )
                    continue
                result = await self._run_one(probe, target)
                out.results.append(result)
                if result.ok:
                    self._errors.record_success(host)
                else:
                    if self._errors.record_failure(host):
                        audit.record(
                            self.sink,
                            self.config.actor,
                            "engine.host.skipped",
                            host,
                            f"threshold={self.config.host_error_threshold}",
                        )
                if self._cancel.is_set():
                    out.cancelled = True
                    break
            if out.cancelled:
                break

        out.skipped_hosts = self._errors.skipped_hosts
        out.duration_ms = (time.perf_counter() - t0) * 1000
        audit.record(
            self.sink,
            self.config.actor,
            "engine.run.complete",
            self.scope.project,
            f"auth={len(out.authorized)} reject={len(out.rejected)} "
            f"ok={out.ok_count} err={out.err_count} "
            f"skipped_hosts={len(out.skipped_hosts)} ms={out.duration_ms:.1f}",
        )
        return out

    async def _run_one(self, probe: Probe, target) -> ProbeResult:
        if self._cancel.is_set():
            return ProbeResult(
                probe=probe.name, target=target.raw, ok=False, error="cancelled"
            )
        host_sem = self._limiter.host_sem(target.host)
        async with self._limiter.global_sem:
            async with host_sem:
                if self._cancel.is_set():
                    return ProbeResult(
                        probe=probe.name,
                        target=target.raw,
                        ok=False,
                        error="cancelled",
                    )
                t0 = time.perf_counter()
                try:
                    result = await with_timeout(
                        probe.observe(target, timeout=self.config.probe_timeout),
                        self.config.probe_timeout,
                        label=f"probe:{probe.name}",
                    )
                    result.duration_ms = (time.perf_counter() - t0) * 1000
                    return result
                except TimeoutExceeded as e:
                    return ProbeResult(
                        probe=probe.name,
                        target=target.raw,
                        ok=False,
                        error=str(e),
                        duration_ms=(time.perf_counter() - t0) * 1000,
                    )
                except Exception as e:  # noqa: BLE001 — isolate probe failures
                    return ProbeResult(
                        probe=probe.name,
                        target=target.raw,
                        ok=False,
                        error=f"{type(e).__name__}: {e}",
                        duration_ms=(time.perf_counter() - t0) * 1000,
                    )
