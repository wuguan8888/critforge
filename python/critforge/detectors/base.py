"""Common detector interface — plugin-friendly with matcher / evidence hooks."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..finding import Confidence, Finding, FindingCategory
from ..probes import ProbeResult
from ..scope import Severity


@dataclass
class MatcherSpec:
    """Declarative matcher description (Nuclei-template-like, methodology only).

    Matchers describe *what signal keys* a detector looks for. They never
    contain exploit payloads or attack strings.
    """

    name: str
    signal_key: str
    description: str = ""
    confidence_hint: Confidence = Confidence.MEDIUM


@dataclass
class SignalBundle:
    """Normalized view of probe signals for a single target."""

    target: str
    signals: dict[str, Any] = field(default_factory=dict)
    probe_errors: list[str] = field(default_factory=list)

    @classmethod
    def from_results(cls, target: str, results: Iterable[ProbeResult]) -> "SignalBundle":
        merged: dict[str, Any] = {}
        errors: list[str] = []
        for r in results:
            if r.target != target and r.target != "?":
                continue
            if not r.ok and r.error:
                errors.append(f"{r.probe}: {r.error}")
            for k, v in (r.signals or {}).items():
                merged[k] = v
        return cls(target=target, signals=merged, probe_errors=errors)


class Detector(abc.ABC):
    """Abstract black-box detector. evaluate() consumes signals, emits Findings."""

    name: str = "detector"
    category: FindingCategory = FindingCategory.OTHER
    default_severity: Severity = Severity.INFO
    default_confidence: Confidence = Confidence.MEDIUM

    @abc.abstractmethod
    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        """Classify signals into zero-or-more Findings. No network I/O."""
        raise NotImplementedError

    def matchers(self) -> list[MatcherSpec]:
        """Declare signal matchers this detector understands (plugin metadata)."""
        return []

    def evidence_hook(self, bundle: SignalBundle, matched: MatcherSpec) -> dict[str, Any]:
        """Build a methodology evidence dict for a matched signal. No payloads."""
        return {
            "signal": matched.signal_key,
            "value": bundle.signals.get(matched.signal_key),
            "matcher": matched.name,
            "note": "methodology-only; no exploit attempted",
        }

    def confidence_for(self, bundle: SignalBundle, matched: MatcherSpec) -> Confidence:
        """Initial confidence hint before independent verification."""
        # Richer signal sets start slightly higher; verifier still calibrates.
        if bundle.signals.get("confirmation_marker") or bundle.signals.get("repeatable"):
            return Confidence.HIGH
        return matched.confidence_hint or self.default_confidence

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        """Intentionally unimplemented.

        CritForge is methodology-only. Detectors MUST NOT generate or transmit
        exploit / injection / XSS / attack payloads. Subclasses that would
        need an offensive payload leave this stub in place and raise.
        """
        raise NotImplementedError(
            f"{self.name}: offensive payload generation is out of scope "
            "(architecture/methodology only — no exploit payloads)"
        )


class DetectorRegistry:
    def __init__(self) -> None:
        self._items: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        self._items[detector.name] = detector

    def get(self, name: str) -> Optional[Detector]:
        return self._items.get(name)

    def list(self) -> list[str]:
        return sorted(self._items.keys())

    def all(self) -> list[Detector]:
        return [self._items[k] for k in self.list()]

    def matcher_index(self) -> dict[str, list[str]]:
        """Map signal_key → detector names (plugin discovery aid)."""
        idx: dict[str, list[str]] = {}
        for d in self.all():
            for m in d.matchers():
                idx.setdefault(m.signal_key, []).append(d.name)
        return idx

    def run_all(self, bundle: SignalBundle) -> list[Finding]:
        findings: list[Finding] = []
        for d in self.all():
            findings.extend(d.evaluate(bundle))
        return findings
