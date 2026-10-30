"""Auth-flaw detector skeleton (black-box methodology only).

Looks for auth-related signals. Does NOT attempt credential stuffing, bypass
attacks, or session hijacking.
"""
from __future__ import annotations

from ..finding import Confidence, Finding, FindingCategory
from ..scope import Severity
from .base import Detector, MatcherSpec, SignalBundle


class AuthFlawDetector(Detector):
    name = "auth.skeleton"
    category = FindingCategory.AUTH_FLAW
    default_severity = Severity.HIGH
    default_confidence = Confidence.MEDIUM

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="auth_weakness_indicator",
                signal_key="auth_weakness_indicator",
                description="Signal that an authentication weakness was indicated",
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
                    title="Potential authentication weakness indicated by probe signal",
                    target=bundle.target,
                    detector=self.name,
                    description=(
                        "A probe signal suggested an authentication-related weakness. "
                        "No credential attack or bypass was attempted."
                    ),
                    evidence=self.evidence_hook(bundle, m),
                    references=["CWE-287", "OWASP-A07"],
                )
            )
        return findings

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "AuthFlawDetector: offensive payload generation is out of scope"
        )
