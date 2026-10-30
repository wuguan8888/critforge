"""M3 detector framework tests — signal classification only, no payloads."""
from __future__ import annotations

import pytest

from critforge.detectors import (
    AuthFlawDetector,
    InjectionDetector,
    MisconfigDetector,
    SignalBundle,
    XSSDetector,
    default_registry,
)
from critforge.finding import FindingCategory
from critforge.scope import Severity


def test_injection_emits_on_signal():
    d = InjectionDetector()
    bundle = SignalBundle(target="https://example.com", signals={"injection_indicator": "id"})
    findings = d.evaluate(bundle)
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.INJECTION
    assert findings[0].severity == Severity.HIGH


def test_injection_silent_without_signal():
    d = InjectionDetector()
    assert d.evaluate(SignalBundle(target="t", signals={})) == []


def test_xss_emits_on_signal():
    d = XSSDetector()
    findings = d.evaluate(
        SignalBundle(target="t", signals={"xss_reflection_indicator": True})
    )
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.XSS


def test_auth_emits_on_signal():
    d = AuthFlawDetector()
    findings = d.evaluate(
        SignalBundle(target="t", signals={"auth_weakness_indicator": "open-admin"})
    )
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.AUTH_FLAW


def test_misconfig_severity_override():
    d = MisconfigDetector()
    findings = d.evaluate(
        SignalBundle(
            target="t",
            signals={"misconfig_indicator": "verbose-banner", "misconfig_severity": "Critical"},
        )
    )
    assert findings[0].severity == Severity.CRITICAL


def test_offensive_payload_stub_raises():
    for d in (InjectionDetector(), XSSDetector(), AuthFlawDetector(), MisconfigDetector()):
        with pytest.raises(NotImplementedError):
            d.craft_offensive_payload("anything")


def test_registry_run_all():
    reg = default_registry()
    assert set(reg.list()) == {
        "injection.skeleton",
        "xss.skeleton",
        "auth.skeleton",
        "misconfig.skeleton",
    }
    bundle = SignalBundle(
        target="https://example.com",
        signals={
            "injection_indicator": "q",
            "xss_reflection_indicator": 1,
            "auth_weakness_indicator": "x",
            "misconfig_indicator": "y",
        },
    )
    findings = reg.run_all(bundle)
    assert len(findings) == 4


def test_signal_bundle_from_results():
    from critforge.probes import ProbeResult

    results = [
        ProbeResult(probe="a", target="t", ok=True, signals={"k": 1}),
        ProbeResult(probe="b", target="t", ok=False, error="boom", signals={}),
        ProbeResult(probe="c", target="other", ok=True, signals={"k": 99}),
    ]
    bundle = SignalBundle.from_results("t", results)
    assert bundle.signals == {"k": 1}
    assert any("boom" in e for e in bundle.probe_errors)


def test_matcher_specs_and_index():
    reg = default_registry()
    idx = reg.matcher_index()
    assert "injection_indicator" in idx
    assert "xss_reflection_indicator" in idx
    inj = InjectionDetector()
    specs = inj.matchers()
    assert specs and specs[0].signal_key == "injection_indicator"


def test_detector_emits_confidence():
    d = InjectionDetector()
    findings = d.evaluate(
        SignalBundle(target="t", signals={"injection_indicator": "q", "repeatable": True})
    )
    assert findings[0].confidence.value in {"medium", "high"}
