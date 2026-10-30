"""Misconfiguration detector skeleton (black-box methodology only).

Classifies configuration / exposure signals. Does NOT brute-force directories
or exploit misconfigurations.
"""
from __future__ import annotations

from ..finding import Confidence, Finding, FindingCategory
from ..scope import Severity
from .base import Detector, MatcherSpec, SignalBundle


class MisconfigDetector(Detector):
    name = "misconfig.skeleton"
    category = FindingCategory.MISCONFIG
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.MEDIUM

    def matchers(self) -> list[MatcherSpec]:
        return [
            MatcherSpec(
                name="misconfig_indicator",
                signal_key="misconfig_indicator",
                description="Signal that a configuration / exposure issue was indicated",
                confidence_hint=Confidence.MEDIUM,
            )
        ]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        findings: list[Finding] = []
        for m in self.matchers():
            marker = bundle.signals.get(m.signal_key)
            if not marker:
                continue
            sev = self.default_severity
            sev_raw = bundle.signals.get("misconfig_severity")
            if isinstance(sev_raw, str):
                try:
                    sev = Severity(sev_raw)
                except ValueError:
                    pass
            findings.append(
                Finding(
                    category=self.category,
                    severity=sev,
                    confidence=self.confidence_for(bundle, m),
                    title="Potential misconfiguration indicated by probe signal",
                    target=bundle.target,
                    detector=self.name,
                    description=(
                        "A probe signal suggested a configuration / exposure issue. "
                        "No exploitation was attempted."
                    ),
                    evidence=self.evidence_hook(bundle, m),
                    references=["CWE-16", "OWASP-A05"],
                )
            )
        return findings

    def craft_offensive_payload(self, *args, **kwargs):  # noqa: ANN001
        raise NotImplementedError(
            "MisconfigDetector: offensive payload generation is out of scope"
        )
