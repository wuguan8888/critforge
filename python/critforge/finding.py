"""M4 Finding model — structured vulnerability / observation record.

Findings are the currency of CritForge's black-box pipeline. Detectors emit
them; the verifier upgrades confidence; the reporter aggregates and orders
them. Dual-axis gating (severity × confidence) is applied before a finding
is reported to the operator.

This module contains NO exploit payloads, scan logic, or network code.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .scope import Severity


class FindingCategory(str, enum.Enum):
    INJECTION = "injection"
    XSS = "xss"
    AUTH_FLAW = "auth_flaw"
    MISCONFIG = "misconfig"
    INFO = "info"
    OTHER = "other"
    CHAIN = "chain"


class Confidence(str, enum.Enum):
    """Confidence axis — independent of severity (dual-axis model).

    Low/Medium: signal-only or weakly corroborated (higher FP risk).
    High: corroborating evidence / confirmation stage passed.
    Confirmed: evidence pack complete (and optional second-pass agree).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


_CONFIDENCE_RANK = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
    Confidence.CONFIRMED: 3,
}


def confidence_meets(c: Confidence, threshold: Confidence) -> bool:
    """True iff c is at or above the confidence gate."""
    return _CONFIDENCE_RANK[c] >= _CONFIDENCE_RANK[threshold]


@dataclass
class Finding:
    """One structured finding produced by a detector, verifier, or chain."""

    category: FindingCategory
    severity: Severity
    title: str
    target: str
    evidence: dict[str, Any] = field(default_factory=dict)
    detector: str = ""
    description: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    # Optional references (CWE/OWASP ids, methodology notes) — never payloads.
    references: list[str] = field(default_factory=list)
    # Dual-axis: confidence is calibrated separately from severity.
    confidence: Confidence = Confidence.MEDIUM
    # Verification metadata (filled by verifier; empty until then).
    verification_stage: str = ""
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


# Rank for sorting (Critical first, then higher confidence).
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_sort_key(f: Finding) -> tuple:
    return (
        _SEVERITY_ORDER.get(f.severity, 99),
        -_CONFIDENCE_RANK.get(f.confidence, 0),
        f.timestamp,
        f.id,
    )
