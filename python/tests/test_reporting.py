"""M4 reporting tests — dual-axis severity × confidence."""
from __future__ import annotations

import json
import os

from critforge.finding import Confidence, Finding, FindingCategory
from critforge.reporting import build_report
from critforge.scope import Severity, load

SCOPE = os.path.join(os.path.dirname(__file__), "scope.test.yaml")


def _f(sev: Severity, title: str = "t", conf: Confidence = Confidence.MEDIUM) -> Finding:
    return Finding(
        category=FindingCategory.MISCONFIG,
        severity=sev,
        confidence=conf,
        title=title,
        target="example.com",
        detector="test",
        evidence={"signal": "x"},
    )


def test_severity_gate_filters():
    scope = load(SCOPE)  # gate = High, confidence default medium
    findings = [
        _f(Severity.CRITICAL, "c"),
        _f(Severity.HIGH, "h"),
        _f(Severity.MEDIUM, "m"),
        _f(Severity.LOW, "l"),
        _f(Severity.INFO, "i"),
    ]
    report = build_report(scope, findings, apply_gate=True)
    assert [f.severity for f in report.findings] == [Severity.CRITICAL, Severity.HIGH]
    assert len(report.suppressed) == 3


def test_confidence_gate_filters_low():
    scope = load(SCOPE)
    findings = [
        _f(Severity.CRITICAL, "hi", Confidence.HIGH),
        _f(Severity.HIGH, "lo", Confidence.LOW),  # severity ok, confidence below medium
    ]
    report = build_report(scope, findings, apply_gate=True)
    assert len(report.findings) == 1
    assert report.findings[0].title == "hi"
    assert len(report.suppressed) == 1


def test_report_json_and_text():
    scope = load(SCOPE)
    report = build_report(scope, [_f(Severity.CRITICAL, "crit", Confidence.CONFIRMED)])
    data = json.loads(report.to_json())
    assert data["project"] == scope.project
    assert data["counts_by_severity"]["Critical"] == 1
    assert data["confidence_gate"] == "medium"
    assert data["counts_by_confidence"]["confirmed"] == 1
    text = report.to_text()
    assert "CritForge Report" in text
    assert "crit" in text
    assert "confirmed" in text


def test_empty_report():
    scope = load(SCOPE)
    report = build_report(scope, [])
    assert "no findings" in report.to_text()
