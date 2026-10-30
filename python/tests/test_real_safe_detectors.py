"""Real-safe detector unit tests using synthetic signal bundles."""
from __future__ import annotations

from critforge.detectors.base import SignalBundle
from critforge.detectors.real_safe import real_safe_detectors
from critforge.finding import FindingCategory
from critforge.scope import Severity


def test_real_safe_detectors_emit_from_signals():
    bundle = SignalBundle(
        target="http://127.0.0.1:8765/",
        signals={
            "missing_security_headers": ["content-security-policy", "x-frame-options"],
            "directory_listing": True,
            "directory_listing_path": "/files/",
            "verbose_error": True,
            "verbose_error_path": "/debug/error",
            "server_banner": ["server: CritForge-VulnLab/0.1"],
            "default_cred_page": True,
            "default_cred_path": "/admin/login",
            "auth_weakness_indicator": "default_credentials_hint",
            "sensitive_endpoint_open": True,
            "sensitive_endpoint_path": "/api/users",
            "xss_reflection_indicator": True,
            "reflection_path": "/search?q=critforge_marker_range_ok",
            "reflection_marker": "critforge_marker_range_ok",
            "repeatable": True,
            "confirmation_marker": True,
        },
    )
    findings = []
    for d in real_safe_detectors():
        findings.extend(d.evaluate(bundle))
    cats = {f.category for f in findings}
    assert FindingCategory.MISCONFIG in cats
    assert FindingCategory.AUTH_FLAW in cats
    assert FindingCategory.XSS in cats
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any(f.evidence.get("ground_truth_hint") == "GT-1" for f in findings)
    assert any(f.evidence.get("ground_truth_hint") == "GT-5" for f in findings)
