"""Three-stage verifier + confidence calibration tests."""
from __future__ import annotations

from critforge.detectors.base import SignalBundle
from critforge.finding import Confidence, Finding, FindingCategory
from critforge.scope import Severity
from critforge.verify import VerificationStage, Verifier, VerifierConfig


def _finding(**kwargs) -> Finding:
    base = dict(
        category=FindingCategory.INJECTION,
        severity=Severity.HIGH,
        title="t",
        target="https://example.com",
        detector="test",
        evidence={"signal": "injection_indicator", "value": "q"},
        confidence=Confidence.MEDIUM,
    )
    base.update(kwargs)
    return Finding(**base)


def test_empty_evidence_stays_low():
    v = Verifier()
    f = _finding(evidence={})
    r = v.verify(f)
    assert r.stage_reached == VerificationStage.DETECTION
    assert r.confidence == Confidence.LOW
    assert f.confidence == Confidence.LOW
    assert f.verified is True


def test_signal_corroboration_reaches_medium():
    v = Verifier()
    f = _finding()
    r = v.verify(f, SignalBundle(target=f.target, signals={}))
    assert r.stage_reached == VerificationStage.EVIDENCE
    assert r.confidence == Confidence.MEDIUM
    assert "verification" in f.evidence


def test_repeatable_promotes_high():
    # pt42u calibration: only a finding-level repeat (independent re-fetch) promotes.
    v = Verifier()
    f = _finding()
    f.evidence["repeatable"] = True
    r = v.verify(f, SignalBundle(target=f.target, signals={}))
    assert r.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
    assert r.confirmed is True


def test_bundle_level_repeatable_does_not_promote():
    v = Verifier()
    f = _finding()
    r = v.verify(f, SignalBundle(target=f.target, signals={"repeatable": True}))
    assert r.confidence == Confidence.MEDIUM


def test_heuristic_confirmed_with_two_corroborations():
    v = Verifier()
    f = _finding(
        evidence={
            "signal": "injection_indicator",
            "repeatable": True,
            "oob_hit": True,
        }
    )
    r = v.verify(f, SignalBundle(target=f.target, signals={"repeatable": True, "oob_hit": 1}))
    assert r.confidence == Confidence.CONFIRMED
    assert r.stage_reached == VerificationStage.EVIDENCE


def test_model_second_pass_skipped_without_key():
    from critforge.llm import LLMClient

    v = Verifier(
        config=VerifierConfig(enable_model_second_pass=True),
        llm=LLMClient(),
    )
    f = _finding()
    r = v.verify(f)
    assert r.model_second_pass == "skipped"


def test_verify_all():
    v = Verifier()
    findings = [_finding(target="https://example.com"), _finding(evidence={})]
    results = v.verify_all(findings)
    assert len(results) == 2
