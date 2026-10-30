"""CritForge's append-only audit spine (Python port of M0 audit).

Entries are append-only JSONL. They are never mutated or deleted. A PostgreSQL
sink is an M1+ concern; this module uses JSONL, matching the Go skeleton.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Protocol


@dataclass(frozen=True)
class Entry:
    """One append-only audit record."""
    timestamp: str
    actor: str
    action: str
    scope: str
    detail: str = ""


class Sink(Protocol):
    def write(self, entry: Entry) -> None: ...


class JSONLSink:
    """Appends entries to a JSONL file."""

    def __init__(self, path: str) -> None:
        self.path = path

    def write(self, entry: Entry) -> None:
        line = json.dumps(asdict(entry), separators=(",", ":"), sort_keys=False)
        # Append-only: O_APPEND, never truncate or rewrite.
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def default_sink() -> Sink:
    path = os.getenv("CRITFORGE_AUDIT_LOG") or "critforge-audit.jsonl"
    return JSONLSink(path)


def record(sink: Sink, actor: str, action: str, scope: str, detail: str = "") -> None:
    """Stamp the time (UTC) and write one entry."""
    sink.write(
        Entry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            scope=scope,
            detail=detail,
        )
    )
