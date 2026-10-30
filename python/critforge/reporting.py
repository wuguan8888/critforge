"""M4 Reporting — aggregate Findings into structured reports.

Produces JSON and human-readable text. Applies dual-axis gating:
  - Scope.severity_gate  (severity axis)
  - confidence_gate      (confidence axis; default Medium)
Only findings meeting BOTH axes appear in the default operator view.
No network, no payloads.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .finding import Confidence, Finding, confidence_meets, severity_sort_key
from .scope import Scope, Severity, severity_meets

COVERAGE_DISCLAIMER = (
    "Coverage limitation: passive-only, limited coverage. CritForge ran black-box, "
    "non-intrusive observation (safe GET probes, benign malformed-input error triggers, "
    "backup-name checks, and Nuclei information/misconfiguration/exposure templates if enabled). "
    "Injection, XSS, authentication/session, access-control logic, XXE, deserialization, "
    "SSRF and business-logic flaws are NOT tested. Absence of a finding is not evidence of "
    "absence of a vulnerability. (Benchmark: ~12.5% of OWASP Juice Shop categories.)"
)


ACTIVE_TESTING_NOTE = (
    "Categories untestable under the red lines (no exploit payloads) require the "
    "HITL-approved, authorized active-testing path; the AI only analyses evidence "
    "gathered by non-intrusive probes and never generates payloads."
)


@dataclass
class Report:
    """Aggregated, severity×confidence-ordered findings for one engagement run."""

    project: str
    generated_at: str
    severity_gate: Severity
    confidence_gate: Confidence
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)  # below either gate
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def counts_by_confidence(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.confidence.value] = counts.get(f.confidence.value, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "generated_at": self.generated_at,
            "severity_gate": self.severity_gate.value,
            "confidence_gate": self.confidence_gate.value,
            "counts_by_severity": self.counts_by_severity,
            "counts_by_confidence": self.counts_by_confidence,
            "findings": [f.to_dict() for f in self.findings],
            "suppressed_count": len(self.suppressed),
            "meta": self.meta,
            "coverage_disclaimer": COVERAGE_DISCLAIMER,
            "active_testing_note": ACTIVE_TESTING_NOTE,
            "analysis_engine": self.analysis_engine,
        }

    @property
    def analysis_engine(self) -> str:
        ai = (self.meta or {}).get("ai") or {}
        if ai.get("enabled") and ai.get("models"):
            return "AI-driven (" + ", ".join(ai["models"]) + ") over deterministic evidence"
        return "deterministic (offline fallback; AI disabled or unavailable)"

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def to_text(self) -> str:
        lines = [
            f"CritForge Report — {self.project}",
            f"Generated: {self.generated_at}",
            f"Severity gate: {self.severity_gate.value}",
            f"Confidence gate: {self.confidence_gate.value}",
            f"Findings (pass both gates): {len(self.findings)}",
            f"Suppressed (below either gate): {len(self.suppressed)}",
            f"Counts by severity: {self.counts_by_severity}",
            f"Counts by confidence: {self.counts_by_confidence}",
            f"Analysis engine: {self.analysis_engine}",
            f"NOTE: {COVERAGE_DISCLAIMER}",
            f"NOTE: {ACTIVE_TESTING_NOTE}",
            "-" * 60,
        ]
        nar = ((self.meta or {}).get("ai_chains") or {}).get("narrative")
        if nar:
            lines.append(f"AI attack-chain narrative: {nar}")
            for c in ((self.meta or {}).get("ai_chains") or {}).get("chains") or []:
                lines.append(f"  - chain: {c.get('title')} [{c.get('severity')}] ids={c.get('finding_ids')}")
            lines.append("-" * 60)
        if not self.findings:
            lines.append("(no findings at or above dual-axis gates)")
        for i, f in enumerate(self.findings, 1):
            lines.append(
                f"{i}. [{f.severity.value}|{f.confidence.value}] "
                f"{f.category.value} — {f.title}"
            )
            lines.append(f"   target: {f.target}")
            lines.append(f"   detector: {f.detector or '-'}")
            if f.verification_stage:
                lines.append(f"   verified_stage: {f.verification_stage}")
            aj = (f.evidence or {}).get("ai_judgment") or {}
            if aj.get("rationale"):
                lines.append(
                    f"   AI verdict: {aj.get('verdict')} (confidence={aj.get('confidence')}, "
                    f"grounded={aj.get('grounded')})"
                )
                lines.append(f"   AI rationale: {aj.get('rationale')}")
                if aj.get("evidence_cited"):
                    lines.append(f"   AI cited evidence: {aj.get('evidence_cited')}")
            if f.description:
                lines.append(f"   {f.description}")
            lines.append(f"   id: {f.id}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


def build_report(
    scope: Scope,
    findings: list[Finding],
    *,
    meta: Optional[dict[str, Any]] = None,
    apply_gate: bool = True,
    confidence_gate: Optional[Confidence] = None,
) -> Report:
    """Sort findings and filter by severity × confidence dual-axis gates."""
    if confidence_gate is not None:
        conf_gate = confidence_gate
    else:
        raw_cg = getattr(scope, "confidence_gate", None) or "medium"
        if isinstance(raw_cg, Confidence):
            conf_gate = raw_cg
        else:
            conf_gate = Confidence(str(raw_cg).strip().lower())
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        if apply_gate:
            sev_ok = severity_meets(f.severity, scope.severity_gate)
            conf_ok = confidence_meets(f.confidence, conf_gate)
            if not (sev_ok and conf_ok):
                suppressed.append(f)
                continue
        kept.append(f)
    kept.sort(key=severity_sort_key)
    suppressed.sort(key=severity_sort_key)
    return Report(
        project=scope.project,
        generated_at=datetime.now(timezone.utc).isoformat(),
        severity_gate=scope.severity_gate,
        confidence_gate=conf_gate,
        findings=kept,
        suppressed=suppressed,
        meta=meta or {},
    )
