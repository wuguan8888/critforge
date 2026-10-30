"""M2 Probe interface — pluggable, safe-by-default observation hooks.

A Probe is an abstract unit of black-box observation. CritForge ships ONLY
safe no-op / mock probes. Real network scanners, enumerators, or attack
probes are intentionally NOT implemented here.

Contract:
  - Probes receive an already-authorized Target (the engine gates first).
  - Probes MUST NOT send exploit payloads or perform offensive actions.
  - Probes return ProbeResult records; they never raise for "no signal".
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Optional

from .target import Target


@dataclass
class ProbeResult:
    """Outcome of one probe invocation against one target."""

    probe: str
    target: str
    ok: bool
    signals: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0


class Probe(abc.ABC):
    """Abstract probe. Subclasses implement observe() without network attacks."""

    name: str = "probe"
    description: str = ""

    @abc.abstractmethod
    async def observe(self, target: Target, *, timeout: float = 30.0) -> ProbeResult:
        """Observe an already-authorized target. No offensive payloads."""
        raise NotImplementedError


class NoOpProbe(Probe):
    """Safe no-op probe used in tests and as a default placeholder."""

    name = "noop"
    description = "Safe no-op probe — returns an empty signal set."

    async def observe(self, target: Target, *, timeout: float = 30.0) -> ProbeResult:
        return ProbeResult(
            probe=self.name,
            target=target.raw,
            ok=True,
            signals={"observed": True, "host": target.host},
        )


class MockSignalProbe(Probe):
    """Test probe that echoes a pre-configured signal dict (no network)."""

    name = "mock_signal"
    description = "Injects caller-supplied signals for unit tests."

    def __init__(self, signals: Optional[dict[str, Any]] = None, *, fail: bool = False) -> None:
        self._signals = signals or {}
        self._fail = fail

    async def observe(self, target: Target, *, timeout: float = 30.0) -> ProbeResult:
        if self._fail:
            return ProbeResult(
                probe=self.name,
                target=target.raw,
                ok=False,
                error="mock failure (injected)",
            )
        return ProbeResult(
            probe=self.name,
            target=target.raw,
            ok=True,
            signals=dict(self._signals),
        )


class Registry:
    """Simple name -> Probe factory registry."""

    def __init__(self) -> None:
        self._probes: dict[str, Probe] = {}

    def register(self, probe: Probe) -> None:
        self._probes[probe.name] = probe

    def get(self, name: str) -> Optional[Probe]:
        return self._probes.get(name)

    def list(self) -> list[str]:
        return sorted(self._probes.keys())

    def all(self) -> list[Probe]:
        return [self._probes[k] for k in self.list()]


def default_registry() -> Registry:
    """Registry pre-loaded with safe built-in probes only."""
    r = Registry()
    r.register(NoOpProbe())
    return r


def lab_safe_probe_registry(scope=None, *, nuclei: bool = False):
    """Safe probes for authorized localhost range tests (includes HTTP observer)."""
    # Imported lazily so unit tests without httpx still load probes.py.
    from .http_probe import HttpCrawlProbe, HttpObserveProbe

    r = Registry()
    r.register(NoOpProbe())
    r.register(HttpObserveProbe())
    r.register(HttpCrawlProbe())
    if nuclei:
        if scope is None:
            raise ValueError("nuclei engine requires a Scope (gate-checked per target)")
        from .nuclei import NucleiProbe

        r.register(NucleiProbe(scope))
    return r
