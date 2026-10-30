"""Out-of-band (OOB) channel abstraction — interface only.

CritForge does NOT ship a real Interactsh / collaborator client. This module
defines the contract a future authorized OOB backend would implement, plus a
Noop channel for tests and dry-runs. No network I/O, no DNS/HTTP callbacks.
"""
from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class OOBEvent:
    """One correlation event observed on an OOB channel (mock-friendly)."""

    correlation_id: str
    source: str = "noop"
    received_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    meta: dict[str, Any] = field(default_factory=dict)


class OutOfBandChannel(abc.ABC):
    """Abstract OOB channel. Subclasses must not perform real callbacks here."""

    name: str = "oob"

    @abc.abstractmethod
    async def register(self, *, label: str = "") -> str:
        """Reserve a correlation id for a future (authorized) OOB check."""
        raise NotImplementedError

    @abc.abstractmethod
    async def poll(self, correlation_id: str) -> list[OOBEvent]:
        """Return events for a correlation id (empty if none)."""
        raise NotImplementedError

    @abc.abstractmethod
    async def close(self) -> None:
        raise NotImplementedError


class NoopOOBChannel(OutOfBandChannel):
    """Safe no-op OOB channel — never contacts the network."""

    name = "noop"

    def __init__(self) -> None:
        self._ids: set[str] = set()
        self._injected: dict[str, list[OOBEvent]] = {}

    async def register(self, *, label: str = "") -> str:
        cid = f"oob-{uuid.uuid4().hex[:12]}"
        self._ids.add(cid)
        return cid

    async def poll(self, correlation_id: str) -> list[OOBEvent]:
        return list(self._injected.get(correlation_id, []))

    async def close(self) -> None:
        self._ids.clear()
        self._injected.clear()

    def inject_for_tests(self, correlation_id: str, event: Optional[OOBEvent] = None) -> None:
        """Test helper: inject a fake OOB event (no network)."""
        if correlation_id not in self._ids:
            self._ids.add(correlation_id)
        ev = event or OOBEvent(correlation_id=correlation_id, source="test-inject")
        self._injected.setdefault(correlation_id, []).append(ev)
