"""Attack-chain synthesis tests."""
from __future__ import annotations

from critforge.attackchain import synthesize
from critforge.finding import Confidence, Finding, FindingCategory
from critforge.scope import Severity


def _f(cat, sev, target="https://example.com", **kw) -> Finding:
    return Finding(
        category=cat,
        severity=sev,
        confidence=kw.get("confidence", Confidence.MEDIUM),
        title=kw.get("title", cat.value),
        target=target,
        detector="t",
        evidence={"signal": cat.value},
    )


def test_chain_requires_min_nodes_and_high_endpoint():
    findings = [
        _f(FindingCategory.MISCONFIG, Severity.MEDIUM),
        _f(FindingCategory.INJECTION, Severity.HIGH),
    ]
    chains = synthesize(findings)
    assert len(chains) == 1
    assert chains[0].endpoint_severity == "High"
    assert len(chains[0].nodes) >= 2


def test_low_endpoint_suppressed():
    findings = [
        _f(FindingCategory.MISCONFIG, Severity.LOW),
        _f(FindingCategory.XSS, Severity.MEDIUM),
    ]
    assert synthesize(findings) == []


def test_single_finding_no_chain():
    assert synthesize([_f(FindingCategory.INJECTION, Severity.CRITICAL)]) == []


def test_chain_to_finding():
    findings = [
        _f(FindingCategory.AUTH_FLAW, Severity.HIGH),
        _f(FindingCategory.INJECTION, Severity.CRITICAL),
    ]
    chain = synthesize(findings)[0]
    f = chain.to_finding()
    assert f.category == FindingCategory.CHAIN
    assert f.severity == Severity.CRITICAL
