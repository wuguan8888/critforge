"""M0 Scope & Policy — the first-class authorization object (Python port).

Fail-closed posture:
  - empty allowlist          -> refuse to run (EmptyScopeError)
  - missing authorized_by    -> refuse to run
  - invalid severity_gate    -> refuse to run
InScope() enforces denylist precedence over allowlist.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional

import yaml


class Severity(str, enum.Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_meets(s: Severity, threshold: Severity) -> bool:
    """Reports whether s is at or above the gate threshold."""
    return _SEVERITY_RANK[s] >= _SEVERITY_RANK[threshold]


class ScopeError(Exception):
    """Base class for scope authorization failures."""


class EmptyScopeError(ScopeError):
    """Raised when no authorized targets are configured (fail closed)."""


@dataclass
class ModelRouting:
    planner: str = ""
    worker: str = ""
    verifier: str = ""


# Dual-axis confidence gate labels (mirrors finding.Confidence; kept here as
# plain strings so scope.py does not import finding.py and create a cycle).
CONFIDENCE_GATES = ("low", "medium", "high", "confirmed")


@dataclass
class Scope:
    """First-class authorization object for a CritForge engagement."""

    project: str = ""
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    severity_gate: Severity = Severity.HIGH
    # Dual-axis: minimum confidence to surface in operator reports.
    confidence_gate: str = "medium"
    model_routing: ModelRouting = field(default_factory=ModelRouting)
    authorized_by: str = ""
    authorization_reference: str = ""
    # Targets recorded but NOT active until a signed authorization is provided.
    pending_authorization: list[str] = field(default_factory=list)

    def validate(self) -> None:
        """Enforce the authorization gate. Raises on any failure (fail closed)."""
        if not any((a or "").strip() for a in self.allowlist):
            raise EmptyScopeError(
                "authorization gate: scope allowlist is empty; CritForge refuses to run"
            )
        if not isinstance(self.severity_gate, Severity):
            raise ScopeError(f"invalid severity_gate {self.severity_gate!r}")
        cg = (self.confidence_gate or "").strip().lower()
        if cg not in CONFIDENCE_GATES:
            raise ScopeError(
                f"invalid confidence_gate {self.confidence_gate!r}; "
                f"expected one of {CONFIDENCE_GATES}"
            )
        self.confidence_gate = cg
        if not (self.authorized_by or "").strip():
            raise ScopeError("authorization gate: authorized_by must be set")

    def in_scope(self, target: str) -> bool:
        """Allowed iff on allowlist AND not denied. Denylist takes precedence."""
        t = (target or "").strip().lower()
        for d in self.denylist:
            if (d or "").strip().lower() == t:
                return False
        for a in self.allowlist:
            if (a or "").strip().lower() == t:
                return True
        return False


def load(path: str) -> Scope:
    """Read and validate a scope.yaml file. Fails closed on any violation."""
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    if not isinstance(raw, dict):
        raise ScopeError("parse scope: top-level document must be a mapping")

    gate_raw = raw.get("severity_gate")
    if gate_raw in (None, ""):
        severity_gate = Severity.HIGH  # default gate
    else:
        try:
            severity_gate = Severity(str(gate_raw))
        except ValueError:
            raise ScopeError(f"invalid severity_gate {gate_raw!r}")

    mr_raw = raw.get("model_routing") or {}
    model_routing = ModelRouting(
        planner=str(mr_raw.get("planner", "") or ""),
        worker=str(mr_raw.get("worker", "") or ""),
        verifier=str(mr_raw.get("verifier", "") or ""),
    )

    conf_raw = raw.get("confidence_gate")
    if conf_raw in (None, ""):
        confidence_gate = "medium"
    else:
        confidence_gate = str(conf_raw).strip().lower()

    scope = Scope(
        project=str(raw.get("project", "") or ""),
        allowlist=[str(x) for x in (raw.get("allowlist") or [])],
        denylist=[str(x) for x in (raw.get("denylist") or [])],
        severity_gate=severity_gate,
        confidence_gate=confidence_gate,
        model_routing=model_routing,
        authorized_by=str(raw.get("authorized_by", "") or ""),
        authorization_reference=str(raw.get("authorization_reference", "") or ""),
        pending_authorization=[str(x) for x in (raw.get("pending_authorization") or [])],
    )
    scope.validate()
    return scope
