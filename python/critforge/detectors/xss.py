"""XSS detector skeleton (black-box methodology only).

Classifies reflection / sink signals. Does NOT craft or send XSS payloads.
"""
from __future__ import annotations

from ..finding import Confidence, Finding, FindingCategory
from ..scope import Severity
from .base import Detector, MatcherSpec, SignalBundle


class XSSDetector(Detector):
    name = "xss.skeleton"
    category = FindingCategory.XSS
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.MEDIUM

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="xss_reflection_indicator",
                signal_key="xss_reflection_indicator",
                description="Signal that a reflected-input surface was indicated",
                confidence_hint=Confidence.MEDIUM,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        findings: list[Finding] = []
        for m in self.matchers():
            marker = bundle.signals.get(m.signal_key)
            if not marker:
                continue
            findings.append(
                Finding(
                    category=self.category,
                    severity=self.default_severity,
                    confidence=self.confidence_for(bundle, m),
                    title="Potential XSS reflection surface indicated by probe signal",
                    target=bundle.target,
                    detector=self.name,
                    description=(
                        "A probe signal suggested a reflected-input surface. "
                        "No XSS payload was generated or transmitted."
                    ),
                    evidence=self.evidence_hook(bundle, m),
                    references=["CWE-79", "OWASP-A03"],
                )
            )
        return findings

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "XSSDetector: offensive payload generation is out of scope"
        )
