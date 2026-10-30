"""Finding de-duplication + cross-engine merge.

Findings that describe the same issue on the same target (same ``issue_key``)
collapse into one record. When the merged group came from >=2 independent
sources (e.g. passive HTTP observer + Nuclei), the survivor is marked
``cross_engine=True`` — an independent corroboration the verifier uses for
confidence calibration.
"""
from __future__ import annotations

from .finding import Finding
from .scope import Severity

_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def issue_key(f: Finding) -> str:
    ev = f.evidence or {}
    return str(ev.get("issue_key") or ev.get("check_id") or f"{f.detector}:{f.title}")


def merge_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    order: list[tuple[str, str]] = []
    for f in findings:
        k = (f.target, issue_key(f))
        if k not in groups:
            order.append(k)
        groups.setdefault(k, []).append(f)
    out: list[Finding] = []
    for k in order:
        g = groups[k]
        if len(g) == 1:
            out.append(g[0])
            continue
        # Prefer passive (content-validated) record, then highest severity.
        g.sort(key=lambda f: (f.detector != "engine.nuclei", _RANK.get(f.severity, 0)), reverse=True)
        keep = g[0]
        sources = sorted({s for f in g for s in (f.evidence or {}).get("sources", [f.detector])})
        refs = list(dict.fromkeys(r for f in g for r in f.references))
        keep.references = refs
        keep.evidence = {
            **(keep.evidence or {}),
            "sources": sources,
            "merged_from": [f.detector + ":" + f.title for f in g[1:]],
            "merged_count": len(g),
        }
        if len(sources) >= 2:
            keep.evidence["cross_engine"] = True
            keep.evidence["corroborating_signal"] = True
        out.append(keep)
    return out
