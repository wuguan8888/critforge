"""Nuclei detection-engine integration (non-intrusive templates only).

Safety contract:
  - Runs ONLY against targets the M1 gate reports as 'authorized'
    (denylist / pending_authorization / out_of_scope are refused — e.g. kuaishou.com).
  - Loopback-only by default (lab ranges); non-loopback requires explicit opt-in.
  - Template selection: official nuclei-templates filtered to passive
    information / misconfiguration / exposure tags, with intrusive / exploit
    categories excluded (-etags) — honouring the no-payload red line.
  - Output is mapped to CritForge Findings; matched values are truncated and
    run through secret redaction, never echoed raw.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from typing import Any, Iterable, Optional

from .finding import Confidence, Finding, FindingCategory
from .probes import Probe, ProbeResult
from .scope import Scope, Severity
from .target import Target

SAFE_TAGS = ("exposure", "misconfig", "tech", "panel", "config", "files", "disclosure", "headers")
EXCLUDED_TAGS = (
    "intrusive", "fuzz", "dos", "rce", "sqli", "xss", "lfi", "rfi", "ssrf", "xxe",
    "injection", "cve", "default-login", "bruteforce", "brute-force", "takeover",
    "oast", "redirect", "traversal", "deserialization", "auth-bypass", "kev",
)
EXCLUDED_TEMPLATE_TYPES = ("code", "headless", "javascript", "tcp", "dns", "file", "ssl", "whois", "websocket")
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}

_SEV = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL, "unknown": Severity.INFO,
}


def find_binary() -> Optional[str]:
    return os.environ.get("CRITFORGE_NUCLEI_BIN") or shutil.which("nuclei") or (
        os.path.expanduser("~/go/bin/nuclei") if os.path.exists(os.path.expanduser("~/go/bin/nuclei")) else None
    )


def build_command(binary: str, url: str, *, rate_limit: int = 10) -> list[str]:
    """Nuclei argv: GET-centric passive templates, intrusive categories excluded."""
    return [
        binary, "-u", url, "-jsonl", "-silent", "-no-color", "-disable-update-check",
        "-tags", ",".join(SAFE_TAGS),
        "-etags", ",".join(EXCLUDED_TAGS),
        "-type", "http",  # HTTP templates only (no code/headless/javascript/network)
        "-rate-limit", str(rate_limit), "-concurrency", "5", "-timeout", "5",
        "-no-interactsh", "-omit-raw",
    ]


def parse_jsonl(text: str) -> list[dict[str, Any]]:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


_SECRETISH = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----.*|"
    r"(?i:(?:api[_-]?key|token|secret|password|passwd|authorization)\s*[:=]\s*)\S+|"
    r"\b(?:gh[pousr]_|sk-|AKIA|xox[bap]-)[A-Za-z0-9_\-]{8,}|"
    r"\b[A-Za-z0-9+/_\-]{32,}={0,2})"
)


def _redact(v: Any) -> str:
    """Truncate and mask secret-looking substrings — never echo raw values."""
    return _SECRETISH.sub("[REDACTED]", str(v)[:120])


def _category(tags: Iterable[str]) -> FindingCategory:
    t = {x.lower() for x in tags}
    if t & {"panel", "default-login", "auth", "unauth"}:
        return FindingCategory.AUTH_FLAW
    if t & {"exposure", "misconfig", "config", "files", "disclosure", "headers"}:
        return FindingCategory.MISCONFIG
    return FindingCategory.INFO


def is_safe_result(r: dict[str, Any]) -> bool:
    tags = (r.get("info") or {}).get("tags") or []
    if isinstance(tags, str):
        tags = tags.split(",")
    return not ({x.strip().lower() for x in tags} & set(EXCLUDED_TAGS))


def same_origin(r: dict[str, Any], url: str) -> bool:
    """Drop results whose matched endpoint is not the scanned host:port (scope hygiene)."""
    from urllib.parse import urlparse

    m = r.get("matched-at") or r.get("url") or url
    a, b = urlparse(m if "://" in m else "http://" + m), urlparse(url)
    return (a.hostname, a.port or 80) == (b.hostname, b.port or 80)


def issue_key(r: dict[str, Any]) -> str:
    """Normalised issue identity used to merge nuclei hits with passive detectors."""
    from urllib.parse import urlparse

    tid = str(r.get("template-id") or "")
    info = r.get("info") or {}
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [x.strip() for x in tags.split(",")]
    m = r.get("matched-at") or r.get("url") or ""
    path = urlparse(m if "://" in m else "http://" + m).path.rstrip("/") or "/"
    if tid == "http-missing-security-headers":
        return "missing_security_headers"
    if set(tags) & {"exposure", "files", "config", "disclosure", "misconfig", "panel"} and path != "/":
        return f"exposure:{path}"
    if "tech" in tags:
        return "tech_fingerprint:" + tid
    return f"nuclei:{tid}:{path}"


def map_results(target: str, results: list[dict[str, Any]]) -> list[Finding]:
    """Map + collapse: one Finding per (template-id, matched endpoint); matcher names merged."""
    grouped: dict[tuple, list[dict[str, Any]]] = {}
    for r in results:
        if not is_safe_result(r):
            continue
        key = (r.get("template-id"), r.get("matched-at") or r.get("url"))
        grouped.setdefault(key, []).append(r)
    findings: list[Finding] = []
    for group in grouped.values():
        r = dict(group[0])
        matchers = sorted({str(x.get("matcher-name")) for x in group if x.get("matcher-name")})
        info = r.get("info") or {}
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [x.strip() for x in tags.split(",") if x.strip()]
        sev = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        endpoint = r.get("matched-at") or r.get("url") or r.get("host") or target
        extracted = [_redact(x) for x in (r.get("extracted-results") or [])[:5]]
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        cls = info.get("classification") or {}
        cwe = cls.get("cwe-id") or []
        findings.append(
            Finding(
                category=_category(tags),
                severity=sev,
                confidence=Confidence.MEDIUM if sev in (Severity.INFO, Severity.LOW) else Confidence.HIGH,
                title=f"[nuclei] {info.get('name') or r.get('template-id')}",
                target=target,
                detector="engine.nuclei",
                description=_redact(info.get("description") or "")[:300],
                evidence={
                    "signal": "nuclei_results",
                    "check_id": f"nuclei:{r.get('template-id')}:{endpoint}",
                    "template_id": r.get("template-id"),
                    "matcher_name": r.get("matcher-name"),
                    "matcher_names": matchers,
                    "issue_key": issue_key(r),
                    "sources": ["nuclei"],
                    "endpoint": endpoint,
                    "type": r.get("type"),
                    "tags": tags,
                    "extracted": extracted,
                    "note": "nuclei passive template match; raw request/response omitted",
                },
                references=[str(x) for x in (cwe if isinstance(cwe, list) else [cwe])] + [str(x) for x in refs[:3]],
            )
        )
    return findings


class NucleiProbe(Probe):
    """Runs nuclei (safe template subset) against a gate-authorized target."""

    name = "nuclei"
    description = "Nuclei passive exposure/misconfig templates (scope-gated)."

    def __init__(self, scope: Scope, *, allow_non_loopback: bool = False,
                 binary: Optional[str] = None, rate_limit: int = 10) -> None:
        self.scope = scope
        self.allow_non_loopback = allow_non_loopback
        self.binary = binary
        self.rate_limit = rate_limit

    def _fail(self, target: Target, t0: float, err: str) -> ProbeResult:
        return ProbeResult(probe=self.name, target=target.raw, ok=False, error=err,
                           duration_ms=(time.perf_counter() - t0) * 1000)

    async def observe(self, target: Target, *, timeout: float = 600.0) -> ProbeResult:
        from .gate import target_status

        t0 = time.perf_counter()
        status = target_status(self.scope, target.raw)
        if status != "authorized":
            return self._fail(target, t0, f"scope gate refused nuclei: status={status}")
        if target.host.lower() not in _LOOPBACK and not self.allow_non_loopback:
            return self._fail(target, t0, "refusing non-loopback host (nuclei lab mode)")
        binary = self.binary or find_binary()
        if not binary:
            return self._fail(target, t0, "nuclei not installed")
        scheme = target.scheme or "http"
        url = f"{scheme}://{target.host}" + (f":{target.port}" if target.port else "")
        cmd = build_command(binary, url, rate_limit=self.rate_limit)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except Exception as e:  # noqa: BLE001
            return self._fail(target, t0, f"nuclei failed: {type(e).__name__}")
        if proc.returncode not in (0, None) and not out.strip():
            return self._fail(target, t0, f"nuclei exited rc={proc.returncode}")
        results = [r for r in parse_jsonl(out.decode("utf-8", "replace"))
                   if is_safe_result(r) and same_origin(r, url)]
        signals: dict[str, Any] = {"nuclei_ran": True, "nuclei_results": results}
        if results:
            signals["confirmation_marker"] = True
        return ProbeResult(probe=self.name, target=target.raw, ok=True, signals=signals,
                           duration_ms=(time.perf_counter() - t0) * 1000)
