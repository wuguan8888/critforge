"""HITL (human-in-the-loop) approval gate stub.

High-confidence / high-severity actions can be recorded as pending approval
without blocking the automated pipeline or tests. A real console would
surface these for Ernest to approve/deny.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .finding import Confidence
from .scope import Severity


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass
class ApprovalRequest:
    action: str
    reason: str
    finding_id: str = ""
    severity: str = ""
    confidence: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    decided_at: Optional[str] = None
    decided_by: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class HITLGate:
    """In-memory approval ledger. Does not block callers by default."""

    def __init__(self) -> None:
        self._items: dict[str, ApprovalRequest] = {}

    def request(
        self,
        action: str,
        reason: str,
        *,
        finding_id: str = "",
        severity: Severity | str = "",
        confidence: Confidence | str = "",
        meta: Optional[dict[str, Any]] = None,
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            action=action,
            reason=reason,
            finding_id=finding_id,
            severity=severity.value if isinstance(severity, Severity) else str(severity or ""),
            confidence=(
                confidence.value if isinstance(confidence, Confidence) else str(confidence or "")
            ),
            meta=meta or {},
        )
        self._items[req.id] = req
        return req

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self._items.values() if r.status == ApprovalStatus.PENDING]

    def all(self) -> list[ApprovalRequest]:
        return list(self._items.values())

    def decide(
        self, request_id: str, *, approved: bool, decided_by: str = "operator"
    ) -> ApprovalRequest:
        req = self._items.get(request_id)
        if req is None:
            raise KeyError(f"unknown approval request: {request_id}")
        req.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.decided_by = decided_by
        return req

    def maybe_request_for_finding(
        self,
        finding_id: str,
        severity: Severity,
        confidence: Confidence,
        *,
        title: str = "",
    ) -> Optional[ApprovalRequest]:
        """Record HITL when Critical+Confirmed or High+Confirmed (policy stub)."""
        needs = (
            severity == Severity.CRITICAL and confidence in (Confidence.HIGH, Confidence.CONFIRMED)
        ) or (
            severity == Severity.HIGH and confidence == Confidence.CONFIRMED
        )
        if not needs:
            return None
        return self.request(
            action="escalate_finding",
            reason=f"dual-axis policy: {severity.value} × {confidence.value}",
            finding_id=finding_id,
            severity=severity,
            confidence=confidence,
            meta={"title": title},
        )
