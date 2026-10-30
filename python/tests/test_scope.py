import os

import pytest

from critforge.scope import (
    EmptyScopeError,
    ScopeError,
    Scope,
    Severity,
    load,
    severity_meets,
)

HERE = os.path.dirname(os.path.abspath(__file__))
SCOPE = os.path.join(HERE, "scope.test.yaml")


def test_load_valid_scope():
    s = load(SCOPE)
    assert s.project == "TEST-lab-engagement"
    assert s.severity_gate is Severity.HIGH
    assert "example.com" in s.allowlist


def test_default_severity_gate_high(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("allowlist: ['example.com']\nauthorized_by: 'x'\n")
    s = load(str(p))
    assert s.severity_gate is Severity.HIGH


def test_empty_allowlist_fails_closed(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("allowlist: []\nauthorized_by: 'x'\n")
    with pytest.raises(EmptyScopeError):
        load(str(p))


def test_missing_authorized_by_fails_closed(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("allowlist: ['example.com']\n")
    with pytest.raises(ScopeError):
        load(str(p))


def test_invalid_severity_gate(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("allowlist: ['example.com']\nauthorized_by: 'x'\nseverity_gate: 'Bogus'\n")
    with pytest.raises(ScopeError):
        load(str(p))


def test_in_scope_denylist_precedence():
    s = Scope(allowlist=["example.com"], denylist=["example.com"], authorized_by="x")
    assert s.in_scope("example.com") is False


def test_severity_meets_ordering():
    assert severity_meets(Severity.CRITICAL, Severity.HIGH)
    assert severity_meets(Severity.HIGH, Severity.HIGH)
    assert not severity_meets(Severity.LOW, Severity.HIGH)


def test_default_confidence_gate_medium(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("allowlist: ['example.com']\nauthorized_by: 'x'\n")
    s = load(str(p))
    assert s.confidence_gate == "medium"


def test_invalid_confidence_gate(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(
        "allowlist: ['example.com']\nauthorized_by: 'x'\nconfidence_gate: 'nope'\n"
    )
    with pytest.raises(ScopeError):
        load(str(p))
