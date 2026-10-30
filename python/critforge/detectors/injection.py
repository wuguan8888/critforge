"""Injection detector skeleton (black-box methodology only).

Evaluates injected/mock *signals* for indicators of injection-class issues.
Does NOT craft or send SQL/command/LDAP injection payloads.
"""
from __future__ import annotations

from ..finding import Confidence, Finding, FindingCategory
from ..scope import Severity
from .base import Detector, MatcherSpec, SignalBundle


class InjectionDetector(Detector):
    name = "injection.skeleton"
    category = FindingCategory.INJECTION
    default_severity = Severity.HIGH
    default_confidence = Confidence.MEDIUM

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="injection_indicator",
                signal_key="injection_indicator",
                description="Signal that an injection-class input surface was indicated",
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
                    title="Potential injection-class surface indicated by probe signal",
                    target=bundle.target,
                    detector=self.name,
                    description=(
                        "A probe signal suggested an injection-class input surface. "
                        "Manual / authorized follow-up required. No payload was sent."
                    ),
                    evidence=self.evidence_hook(bundle, m),
                    references=["CWE-74", "OWASP-A03"],
                )
            )
        return findings

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        """Stub — CritForge never generates injection payloads."""
        raise NotImplementedError(
            "InjectionDetector: offensive payload generation is out of scope"
        )
