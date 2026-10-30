"""Three-stage verifier — Detection → Confirmation → Evidence.

Calibrates Finding.confidence independently of severity (dual-axis model)
to drive down false positives without silently raising false negatives.

Stages (methodology only — no exploit payloads, no live attacks):
  1. Detection     — finding exists with a non-empty evidence dict
  2. Confirmation  — corroborating signals / confirmation markers present
  3. Evidence      — evidence pack assembled; optional LLM second-pass stub

The LLM second-pass uses llm.py request builders only when explicitly
enabled; by default it is a local heuristic so tests never need a key and
secrets are never logged.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional

from .detectors.base import SignalBundle
from .finding import Confidence, Finding
from .llm import LLMClient, LLMConfig
from .scope import Severity


class VerificationStage(str, enum.Enum):
    DETECTION = "detection"
    CONFIRMATION = "confirmation"
    EVIDENCE = "evidence"


# Corroboration keys a (future) safe probe / detector may set — never payloads.
_CONFIRMATION_KEYS = (
    "confirmation_marker",
    "corroborating_signal",
    "oob_hit",
    "repeatable",
    "status_anomaly",
)


_CONF_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2, Confidence.CONFIRMED: 3}


@dataclass
class VerificationResult:
    finding_id: str
    stage_reached: VerificationStage
    confidence: Confidence
    confirmed: bool
    notes: list[str] = field(default_factory=list)
    evidence_pack: dict[str, Any] = field(default_factory=dict)
    model_second_pass: Optional[str] = None  # "agree" | "disagree" | "skipped"


@dataclass
class VerifierConfig:
    """Tunables for confidence calibration."""

    require_evidence_for_detection: bool = True
    enable_model_second_pass: bool = False  # off by default (no network)
    promote_on_oob: bool = True


class Verifier:
    """Independent verifier — consumes Findings + SignalBundle, emits calibrated confidence."""

    def __init__(
        self,
        *,
        config: Optional[VerifierConfig] = None,
        llm: Optional[LLMClient] = None,
    ) -> None:
        self.config = config or VerifierConfig()
        self.llm = llm

    def verify(
        self,
        finding: Finding,
        bundle: Optional[SignalBundle] = None,
    ) -> VerificationResult:
        """Run Detection → Confirmation → Evidence. Mutates finding.confidence in place."""
        notes: list[str] = []
        evidence_pack: dict[str, Any] = {
            "detector": finding.detector,
            "category": finding.category.value,
            "severity": finding.severity.value,
            "target": finding.target,
            "raw_evidence": dict(finding.evidence or {}),
        }

        # --- Stage 1: Detection ---
        has_evidence = bool(finding.evidence)
        if self.config.require_evidence_for_detection and not has_evidence:
            notes.append("detection failed: empty evidence")
            result = VerificationResult(
                finding_id=finding.id,
                stage_reached=VerificationStage.DETECTION,
                confidence=Confidence.LOW,
                confirmed=False,
                notes=notes,
                evidence_pack=evidence_pack,
                model_second_pass="skipped",
            )
            self._apply(finding, result)
            return result
        notes.append("detection ok: evidence present")
        stage = VerificationStage.DETECTION
        confidence = Confidence.LOW

        # --- Stage 2: Confirmation ---
        signals = (bundle.signals if bundle else {}) or {}
        corroborations = [
            k for k in _CONFIRMATION_KEYS if signals.get(k) or finding.evidence.get(k)
        ]
        # Detector-native signal keys also count as weak corroboration.
        if finding.evidence.get("signal"):
            corroborations.append(str(finding.evidence["signal"]))
        if corroborations:
            notes.append(f"confirmation ok: markers={sorted(set(corroborations))}")
            stage = VerificationStage.CONFIRMATION
            confidence = Confidence.MEDIUM
            if finding.evidence.get("oob_hit") or signals.get("oob_hit"):
                if self.config.promote_on_oob:
                    confidence = Confidence.HIGH
                    notes.append("oob_hit present → confidence high")
            # Only a *per-finding* repeat (independent re-fetch) promotes; a bundle-wide
            # "we fetched ≥2 pages" flag is weak corroboration, not confirmation.
            if finding.evidence.get("repeatable"):
                confidence = Confidence.HIGH
                notes.append("finding-level repeatable marker → confidence high")
            elif signals.get("repeatable"):
                notes.append("bundle-level repeatable only (not promoted)")
            # Per-finding calibration (dominates bundle-wide markers):
            ev = finding.evidence
            if ev.get("content_validated") and ev.get("repeatable"):
                confidence = Confidence.HIGH
                notes.append("content validated + independent re-fetch → confidence high")
            if ev.get("cross_engine"):
                notes.append("cross-engine corroboration (passive + nuclei)")
                if confidence == Confidence.HIGH or ev.get("content_validated"):
                    confidence = Confidence.CONFIRMED if ev.get("content_validated") else Confidence.HIGH
                    notes.append("cross-engine + validated → promoted")
            if ev.get("content_validated") is False or ev.get("heuristic_only"):
                confidence = min(confidence, Confidence.MEDIUM, key=_CONF_RANK.get)
                notes.append("heuristic-only evidence → capped at medium")
        else:
            notes.append("confirmation weak: no corroborating markers")
            # Keep LOW; still proceed to assemble a minimal evidence pack.
            stage = VerificationStage.CONFIRMATION

        # --- Stage 3: Evidence pack ---
        evidence_pack["corroborations"] = sorted(set(corroborations))
        evidence_pack["probe_errors"] = list(bundle.probe_errors) if bundle else []
        evidence_pack["stage"] = stage.value
        notes.append("evidence pack assembled")
        stage = VerificationStage.EVIDENCE

        model_vote = "skipped"
        if self.config.enable_model_second_pass:
            model_vote = self._model_second_pass(finding, evidence_pack)
            notes.append(f"model second-pass: {model_vote}")
            if model_vote == "agree" and confidence in (Confidence.MEDIUM, Confidence.HIGH):
                confidence = Confidence.CONFIRMED
            elif model_vote == "disagree" and confidence == Confidence.HIGH:
                confidence = Confidence.MEDIUM
                notes.append("model disagreed → confidence demoted")
        else:
            # Local heuristic promotion: High severity + high confidence + rich evidence
            # can reach Confirmed without a model call (keeps tests offline).
            if (
                confidence == Confidence.HIGH
                and finding.severity in (Severity.HIGH, Severity.CRITICAL)
                and len(evidence_pack.get("corroborations") or []) >= 2
            ):
                confidence = Confidence.CONFIRMED
                notes.append("heuristic confirmed: high sev + ≥2 corroborations")

        confirmed = confidence in (Confidence.HIGH, Confidence.CONFIRMED)
        result = VerificationResult(
            finding_id=finding.id,
            stage_reached=stage,
            confidence=confidence,
            confirmed=confirmed,
            notes=notes,
            evidence_pack=evidence_pack,
            model_second_pass=model_vote,
        )
        self._apply(finding, result)
        return result

    def verify_all(
        self,
        findings: list[Finding],
        bundles_by_target: Optional[dict[str, SignalBundle]] = None,
    ) -> list[VerificationResult]:
        bundles_by_target = bundles_by_target or {}
        out: list[VerificationResult] = []
        for f in findings:
            out.append(self.verify(f, bundles_by_target.get(f.target)))
        return out

    def _apply(self, finding: Finding, result: VerificationResult) -> None:
        finding.confidence = result.confidence
        finding.verification_stage = result.stage_reached.value
        finding.verified = True
        # Attach verification notes into evidence without clobbering detector keys.
        finding.evidence = {
            **(finding.evidence or {}),
            "verification": {
                "stage": result.stage_reached.value,
                "confidence": result.confidence.value,
                "confirmed": result.confirmed,
                "notes": list(result.notes),
                "model_second_pass": result.model_second_pass,
            },
        }

    def _model_second_pass(
        self, finding: Finding, evidence_pack: dict[str, Any]
    ) -> str:
        """Optional LLM second-pass. Never logs secrets.

        If no client/key is available, returns 'skipped'. When a client exists
        we only build the payload (dry structural check) unless the caller
        wired a real chat() — default path stays offline-safe.
        """
        if self.llm is None:
            return "skipped"
        # Build payload to prove wiring; do not call chat() unless key present.
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a false-positive verifier for a black-box security "
                    "engagement. Reply ONLY with agree or disagree."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"category={finding.category.value} severity={finding.severity.value} "
                    f"title={finding.title} evidence_keys={list(evidence_pack.get('raw_evidence', {}))}"
                ),
            },
        ]
        try:
            # Structural build only — validates config without leaking keys.
            _ = self.llm.build_chat_payload(messages, role="verifier")
            key = self.llm.resolve_api_key()
            if not key:
                return "skipped"
            # Intentionally do NOT auto-call the network in the verifier default
            # path: callers that want a live second-pass should subclass or
            # wrap. Returning 'skipped' keeps CI / dry-runs hermetic.
            return "skipped"
        except Exception:  # noqa: BLE001
            return "skipped"


def default_verifier(*, enable_model_second_pass: bool = False) -> Verifier:
    cfg = VerifierConfig(enable_model_second_pass=enable_model_second_pass)
    llm = LLMClient(LLMConfig()) if enable_model_second_pass else None
    return Verifier(config=cfg, llm=llm)
