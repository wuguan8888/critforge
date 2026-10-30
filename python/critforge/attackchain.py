"""Attack-chain synthesis — link findings into methodology chains.

Builds a lightweight graph over Findings (same host / related categories)
and surfaces only chains whose *endpoint* severity is High or Critical.
No exploit steps, no payloads — nodes are finding ids + metadata only.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from .finding import Confidence, Finding, FindingCategory
from .scope import Severity, severity_meets


# Soft edges: category A may precede category B in a methodology chain.
_CATEGORY_EDGES: dict[FindingCategory, tuple[FindingCategory, ...]] = {
    FindingCategory.MISCONFIG: (
        FindingCategory.AUTH_FLAW,
        FindingCategory.INJECTION,
        FindingCategory.XSS,
    ),
    FindingCategory.AUTH_FLAW: (
        FindingCategory.INJECTION,
        FindingCategory.XSS,
        FindingCategory.MISCONFIG,
    ),
    FindingCategory.INJECTION: (FindingCategory.AUTH_FLAW, FindingCategory.MISCONFIG),
    FindingCategory.XSS: (FindingCategory.AUTH_FLAW,),
}


@dataclass
class ChainNode:
    finding_id: str
    target: str
    category: str
    severity: str
    confidence: str
    title: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChain:
    """Ordered finding chain. endpoint_* describe the terminal node."""

    title: str
    nodes: list[ChainNode] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    endpoint_severity: str = ""
    endpoint_confidence: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "endpoint_severity": self.endpoint_severity,
            "endpoint_confidence": self.endpoint_confidence,
            "nodes": [n.to_dict() for n in self.nodes],
            "meta": self.meta,
        }

    def to_finding(self) -> Finding:
        """Materialize the chain as a Finding (category=CHAIN) for reporting."""
        sev = Severity(self.endpoint_severity) if self.endpoint_severity else Severity.HIGH
        conf = (
            Confidence(self.endpoint_confidence)
            if self.endpoint_confidence
            else Confidence.MEDIUM
        )
        return Finding(
            category=FindingCategory.CHAIN,
            severity=sev,
            confidence=conf,
            title=self.title,
            target=self.nodes[-1].target if self.nodes else "",
            detector="attackchain.synthesize",
            description=(
                f"Methodology attack chain with {len(self.nodes)} nodes. "
                "No exploit steps were executed."
            ),
            evidence={
                "chain_id": self.id,
                "node_ids": [n.finding_id for n in self.nodes],
                "note": "methodology-only chain synthesis",
            },
            references=["attack-chain"],
            verified=True,
            verification_stage="evidence",
        )


def _node_from(f: Finding) -> ChainNode:
    return ChainNode(
        finding_id=f.id,
        target=f.target,
        category=f.category.value,
        severity=f.severity.value,
        confidence=f.confidence.value,
        title=f.title,
    )


def synthesize(
    findings: list[Finding],
    *,
    min_endpoint_severity: Severity = Severity.HIGH,
    min_nodes: int = 2,
) -> list[AttackChain]:
    """Group same-target findings and emit chains whose endpoint clears the gate.

    Single-node "chains" are dropped (min_nodes default 2) to avoid noise.
    Only chains whose terminal finding severity meets min_endpoint_severity
    are returned — Low/Medium endpoints stay internal.
    """
    by_target: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category == FindingCategory.CHAIN:
            continue
        by_target.setdefault(f.target, []).append(f)

    chains: list[AttackChain] = []
    rank = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    for target, group in by_target.items():
        # Informational nodes (fingerprints, inventories) are context, not chain steps;
        # keep them out so they can't become the terminal node and sink the chain.
        group = [f for f in group if f.severity not in (Severity.INFO,)]
        # One node per distinct issue.
        uniq: dict[str, Finding] = {}
        for f in group:
            k = str((f.evidence or {}).get("issue_key") or (f.evidence or {}).get("check_id") or f.id)
            if k not in uniq or rank[f.severity] > rank[uniq[k].severity]:
                uniq[k] = f
        group = list(uniq.values())
        if len(group) < min_nodes:
            continue
        # Methodology order: recon-ish (lower severity) first; the most severe,
        # most confident issue is the chain endpoint.
        order = {
            FindingCategory.MISCONFIG: 0,
            FindingCategory.AUTH_FLAW: 1,
            FindingCategory.INJECTION: 2,
            FindingCategory.XSS: 3,
            FindingCategory.INFO: 4,
            FindingCategory.OTHER: 5,
        }
        conf_rank = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2, Confidence.CONFIRMED: 3}
        ordered = sorted(group, key=lambda f: (rank[f.severity], conf_rank.get(f.confidence, 0),
                                               -order.get(f.category, 9)))
        # The endpoint must be a concrete exposure/flaw, not generic hardening noise.
        hardening = ("missing_security_headers", "server_banner", "tech_fingerprint", "api_surface")
        def _is_hardening(f: Finding) -> bool:
            k = str((f.evidence or {}).get("issue_key") or (f.evidence or {}).get("check_id") or "")
            return k.startswith(hardening) or f.detector.endswith(("server_banner", "missing_security_headers"))
        substantive = [f for f in ordered if not _is_hardening(f)]
        if substantive:
            end = substantive[-1]
            ordered = [f for f in ordered if f is not end] + [end]
        path = ordered[-6:]  # cap chain length; keep the most severe tail
        if len(path) < min_nodes:
            continue

        endpoint = path[-1]
        if not severity_meets(endpoint.severity, min_endpoint_severity):
            continue

        nodes = [_node_from(f) for f in path]
        tags = {t for f in path for t in ((f.evidence or {}).get("tags") or [])}
        theme = (
            "information disclosure → credential/config exposure" if "secret_exposure" in tags
            else "route/source disclosure → targeted attack surface" if tags & {"route_map", "source_exposure", "actuator"}
            else " → ".join(dict.fromkeys(n.category for n in nodes))
        )
        title = f"Chain on {target}: {theme} (endpoint: {endpoint.title})"
        chains.append(
            AttackChain(
                title=title,
                nodes=nodes,
                endpoint_severity=endpoint.severity.value,
                endpoint_confidence=endpoint.confidence.value,
                meta={"target": target, "length": len(nodes)},
            )
        )
    return chains


def chains_as_findings(
    findings: list[Finding],
    *,
    min_endpoint_severity: Severity = Severity.HIGH,
) -> list[Finding]:
    """Convenience: synthesize chains and return them as Finding records."""
    return [
        c.to_finding()
        for c in synthesize(findings, min_endpoint_severity=min_endpoint_severity)
    ]
