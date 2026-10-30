import json
import os

import pytest

from critforge import audit
from critforge.gate import authorize, evaluate
from critforge.scope import load

HERE = os.path.dirname(os.path.abspath(__file__))
SCOPE = os.path.join(HERE, "scope.test.yaml")


@pytest.fixture
def scope():
    return load(SCOPE)


def test_in_scope_hostname(scope):
    d = evaluate(scope, "https://example.com/login")
    assert d.allowed and d.matched_rule == "example.com"


def test_in_scope_subdomain_wildcard(scope):
    # api.lab.example.com is a subdomain of allowlisted example.com AND of the
    # *.lab.example.com wildcard; either match is in-scope.
    d = evaluate(scope, "api.lab.example.com")
    assert d.allowed and d.matched_rule in ("example.com", "*.lab.example.com")

    # A host that matches ONLY the wildcard entry (not the apex example.com).
    from critforge.scope import Scope
    wildcard_only = Scope(allowlist=["*.lab.internal"], authorized_by="x")
    d2 = evaluate(wildcard_only, "api.lab.internal")
    assert d2.allowed and d2.matched_rule == "*.lab.internal"
    assert not evaluate(wildcard_only, "lab.internal.evil.com").allowed


def test_in_scope_ip(scope):
    d = evaluate(scope, "10.0.0.5:8443")
    assert d.allowed and d.matched_rule == "10.0.0.5"


def test_in_scope_ipv6(scope):
    d = evaluate(scope, "2001:db8::1")
    assert d.allowed


def test_out_of_scope_host(scope):
    d = evaluate(scope, "notmine.org")
    assert not d.allowed and "out of scope" in d.reason


def test_denylist_precedence_even_if_in_allowlist(scope):
    # secret.lab.example.com matches *.lab.example.com allowlist, but is denied.
    d = evaluate(scope, "https://secret.lab.example.com")
    assert not d.allowed and "denylist" in d.reason.lower()


def test_denylisted_apex(scope):
    d = evaluate(scope, "do-not-touch.example.com")
    assert not d.allowed


def test_malformed_input_denied(scope):
    d = evaluate(scope, "has space.com")
    assert not d.allowed and "malformed" in d.reason


def test_ip_not_matched_as_subdomain(scope):
    # A different IP must not be allowed.
    d = evaluate(scope, "10.0.0.6")
    assert not d.allowed


def test_authorize_writes_audit(scope, tmp_path):
    log = tmp_path / "audit.jsonl"
    sink = audit.JSONLSink(str(log))
    authorize(scope, "example.com", actor="tester", sink=sink)
    authorize(scope, "notmine.org", actor="tester", sink=sink)
    lines = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    assert lines[0]["action"] == "scope.authorize.allow"
    assert lines[1]["action"] == "scope.authorize.deny"
    assert lines[0]["actor"] == "tester"
