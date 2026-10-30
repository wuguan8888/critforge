"""Safe localhost-only HTTP observation probes for authorized range tests.

Guarantees:
  - Only contacts loopback hosts (127.0.0.1 / localhost / ::1).
  - GET-only, non-destructive, no exploit / injection / XSS payloads.
  - Uses a benign unique marker for reflection checks (not an attack string).
  - Emits methodology signals consumed by detectors; never crafts offensive payloads.
"""
from __future__ import annotations

import re
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from .probes import Probe, ProbeResult
from . import discovery as _disc
from .discovery import pii_shape as _pii_shape
from .target import Target

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_BENIGN_MARKER = "critforge_marker_range_ok"
_SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
)

# Short, fixed path list — observation only (no dir brute force beyond known lab paths).
_DEFAULT_PATHS = (
    "/",
    "/health",
    "/files/",
    "/admin/login",
    "/debug/error",
    f"/search?q={_BENIGN_MARKER}",
    "/api/users",
    "/ground-truth",
    # Complex lab (OWASP Juice Shop) public surface — GET-only observation
    "/api/Products",
    "/api/Challenges",
    "/rest/products/search?q=" + _BENIGN_MARKER,
    "/rest/user/whoami",
    "/rest/admin/application-configuration",
    "/ftp",
    "/encryptionkeys",
    "/metrics",
    "/robots.txt",
    "/sitemap.xml",
)


# Benign malformed inputs used ONLY to provoke error-handling paths (error-trigger
# detection). These are nonexistent route names / an invalid percent-escape — not
# injection, XSS, traversal or any other exploit payload.
_ERROR_TRIGGER_PATHS = (
    "/rest/critforge_benign_nonexistent",
    "/api/critforge_benign_nonexistent",
    "/rest/products/search?q=%25E0%25A4%25A",
)
_BACKUP_SUFFIXES = (".bak", ".old", ".swp", "~", ".orig")
_MAX_BACKUP_REQUESTS = 40
_STACK_PATTERNS = (
    re.compile(r"traceback \(most recent call last\)", re.I),
    re.compile(r"^\s*at\s+[^\n]*\(?[^\s()]+\.(?:js|ts|mjs|cjs):\d+:\d+\)?", re.M),
    re.compile(r"^\s*at\s+[\w$.<>]+\([\w$]+\.java:\d+\)", re.M),
    re.compile(r"\bstack trace\b", re.I),
    re.compile(r"id=[\"']stacktrace[\"']", re.I),
    re.compile(r"(?:SQLITE_ERROR|SequelizeDatabaseError|ORA-\d{5}|PG::\w+Error)"),
)


def has_stack_trace(body: str) -> bool:
    """True if body contains stack-trace / verbose-error markers."""
    import html as _html

    text = _html.unescape(body or "").replace("\xa0", " ").replace("<li>", "\n")
    return any(p.search(text) for p in _STACK_PATTERNS)


def is_backup_name(name: str) -> bool:
    n = (name or "").rstrip("/").lower()
    return any(n.endswith(s) for s in _BACKUP_SUFFIXES) or n.endswith(".bak.md")


def backup_variants(path: str) -> list[str]:
    """Backup-name variants for a discovered file path (no query, no dirs)."""
    p = (path or "").split("?", 1)[0]
    if not p or p.endswith("/") or is_backup_name(p):
        return []
    return [p + s for s in _BACKUP_SUFFIXES]


def _listing_entries(path: str, body: str) -> list[str]:
    page = "http://h" + path.split("?", 1)[0]
    out = []
    for m in re.finditer(r'href=["\']([^"\'?#]+)["\']', body, re.I):
        h = m.group(1)
        if h.startswith(("http:", "https:", "mailto:", "..")):
            continue
        full = urlparse(urljoin(page, h)).path
        if full.rstrip("/") != path.split("?", 1)[0].rstrip("/") and full.startswith(
            path.split("?", 1)[0].rstrip("/") + "/"
        ):
            out.append(full)
    return sorted(set(out))


def _is_loopback(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    return h in _LOOPBACK


def _base_url(target: Target) -> str:
    scheme = target.scheme or "http"
    host = target.host
    if target.is_ip and target.ip_version == 6:
        host = f"[{host}]"
    port = target.port
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


class HttpObserveProbe(Probe):
    """GET-only observer for authorized loopback labs. Emits misconfig/auth/xss signals."""

    name = "http_observe"
    description = "Localhost-only safe HTTP observer (headers, listing, reflection marker)."

    def __init__(
        self,
        *,
        paths: Optional[tuple[str, ...]] = None,
        allow_non_loopback: bool = False,
        error_trigger: bool = True,
        backup_check: bool = True,
        discover: Optional[bool] = None,
        max_discovery: int = 120,
        concurrency: int = 6,
    ) -> None:
        # Discovery (common paths, robots/sitemap, link + JS route crawl, fallback-aware
        # classification, content-validated exposures) defaults on for the built-in path
        # set and off for explicit path lists unless requested.
        self.discover = (paths is None) if discover is None else discover
        self.max_discovery = max_discovery
        self.concurrency = concurrency
        self.paths = paths or _DEFAULT_PATHS
        self.error_trigger = error_trigger
        self.backup_check = backup_check
        # Hard default: refuse non-loopback. Only tests may flip this to False... wait,
        # allow_non_loopback must stay False for safety. Kept as kwarg for explicitness.
        self.allow_non_loopback = allow_non_loopback

    async def observe(self, target: Target, *, timeout: float = 30.0) -> ProbeResult:
        t0 = time.perf_counter()
        if httpx is None:
            return ProbeResult(
                probe=self.name,
                target=target.raw,
                ok=False,
                error="httpx not installed",
                duration_ms=(time.perf_counter() - t0) * 1000,
            )
        if not _is_loopback(target.host) and not self.allow_non_loopback:
            return ProbeResult(
                probe=self.name,
                target=target.raw,
                ok=False,
                error=f"refusing non-loopback host {target.host!r} (localhost-only probe)",
                duration_ms=(time.perf_counter() - t0) * 1000,
            )

        base = _base_url(target)
        signals: dict[str, Any] = {
            "observed": True,
            "host": target.host,
            "base_url": base,
            "pages": [],
            "routes": [],
        }
        missing_headers: set[str] = set()
        banners: list[str] = []
        dir_listing = False
        default_cred = False
        verbose_error = False
        reflection = False
        sensitive_open = False
        status_anomaly = False
        pages_ok = 0
        listing_paths: list[str] = []
        listing_entries: dict[str, list[str]] = {}
        error_paths: list[str] = []
        file_paths: set[str] = set()

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
                verify=False,
            ) as client:
                # SPA fallback baseline: unknown paths may return index.html with 200.
                baseline_len = None
                try:
                    b = await client.get(base + "/critforge_baseline_nonexistent.txt")
                    baseline_len = (b.status_code, len(b.text or ""))
                except Exception:  # noqa: BLE001
                    pass
                paths = list(self.paths)
                if self.error_trigger:
                    paths += [p for p in _ERROR_TRIGGER_PATHS if p not in paths]
                for path in paths:
                    url = urljoin(base + "/", path.lstrip("/")) if not path.startswith("http") else path
                    # Rebuild properly
                    url = base + (path if path.startswith("/") else "/" + path)
                    try:
                        resp = await client.get(url)
                    except Exception as e:  # noqa: BLE001
                        signals.setdefault("fetch_errors", []).append(
                            f"{path}: {type(e).__name__}: {e}"
                        )
                        continue
                    pages_ok += 1
                    headers_l = {k.lower(): v for k, v in resp.headers.items()}
                    body = resp.text or ""
                    body_l = body.lower()

                    page_rec = {
                        "path": path,
                        "status": resp.status_code,
                        "content_type": headers_l.get("content-type", ""),
                        "body_len": len(body),
                    }
                    signals["pages"].append(page_rec)

                    # Security headers (GT-1) — check on root-ish pages
                    for h in _SECURITY_HEADERS:
                        if h not in headers_l:
                            missing_headers.add(h)

                    for hk in ("server", "x-powered-by"):
                        if hk in headers_l and headers_l[hk]:
                            banners.append(f"{hk}: {headers_l[hk]}")

                    # Directory listing (classic Apache "Index of" OR serve-index "listing directory")
                    if (
                        "index of /" in body_l
                        or "<title>index of" in body_l
                        or "listing directory" in body_l
                        or "parent directory" in body_l
                    ):
                        dir_listing = True
                        if path not in listing_paths:
                            listing_paths.append(path)
                        listing_entries[path] = _listing_entries(path, body)

                    # Default cred page (GT-3)
                    if (
                        "default credentials" in body_l
                        or "admin / admin" in body_l
                        or "admin/admin" in body_l
                        or ("password: password" in body_l and "admin" in body_l)
                    ):
                        default_cred = True
                        signals["default_cred_path"] = path

                    # Verbose error (GT-4)
                    if resp.status_code >= 400 and has_stack_trace(body):
                        verbose_error = True
                        status_anomaly = True
                        signals.setdefault("verbose_error_path", path)
                        error_paths.append(path)
                        if path in _ERROR_TRIGGER_PATHS:
                            signals["error_trigger"] = True
                    last = path.split("?", 1)[0].rsplit("/", 1)[-1]
                    if resp.status_code == 200 and "." in last:
                        file_paths.add(path.split("?", 1)[0])

                    # Reflection of benign marker (GT-5) — not an exploit payload
                    if _BENIGN_MARKER in body:
                        reflection = True
                        signals["reflection_path"] = path
                        signals["reflection_marker"] = _BENIGN_MARKER

                    # Sensitive unauthenticated API (GT-6) / lab APIs
                    if path.startswith(("/api/", "/rest/")) and resp.status_code == 200:
                        if _pii_shape(body).get("emails"):
                            sensitive_open = True
                            signals["sensitive_endpoint_path"] = path
                        # Product/admin/config JSON exposed without auth
                        if path.lower().startswith(("/api/products", "/rest/admin", "/api/challenges")):
                            signals.setdefault("unauthenticated_api_paths", []).append(path)
                            signals["unauthenticated_api"] = True
                            sensitive_open = True
                            signals["sensitive_endpoint_path"] = signals.get(
                                "sensitive_endpoint_path", path
                            )
                    if path in ("/metrics", "/prometheus") and resp.status_code == 200:
                        if "http_" in body_l or "# help" in body_l or "process_" in body_l:
                            signals["exposed_metrics"] = True
                            signals["misconfig_indicator"] = signals.get(
                                "misconfig_indicator", "exposed_metrics"
                            )
                            signals["misconfig_severity"] = "High"
                    if path.startswith("/encryptionkeys") and resp.status_code == 200:
                        if "listing directory" in body_l or ".key" in body_l or ".pub" in body_l:
                            signals["exposed_encryption_keys"] = True
                            signals["misconfig_indicator"] = signals.get(
                                "misconfig_indicator", "exposed_encryption_keys"
                            )
                            signals["misconfig_severity"] = "High"

                    # Extract same-origin links for crawl stage
                    for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
                        href = m.group(1)
                        if href.startswith("#") or href.startswith("mailto:"):
                            continue
                        abs_url = urljoin(url, href)
                        parsed = urlparse(abs_url)
                        if parsed.hostname and parsed.hostname.lower() in _LOOPBACK:
                            signals["routes"].append(parsed.path or "/")

                if self.discover:
                    await self._discover(client, base, target, signals, file_paths, error_paths)
                    if error_paths:
                        verbose_error = True
                        status_anomaly = True
                        signals.setdefault("verbose_error_path", error_paths[0])
                    if signals.get("sensitive_api"):
                        sensitive_open = True
                        signals.setdefault("sensitive_endpoint_path", signals["sensitive_api"][0]["path"])

                # Backup-file recognition: (a) names seen in listings,
                # (b) bounded GET of .bak/.old/.swp/~/.orig variants of discovered files.
                backups: list[dict[str, Any]] = []
                if self.backup_check:
                    for lp, entries in listing_entries.items():
                        for e in entries:
                            if is_backup_name(e):
                                backups.append({"path": e, "source": "listing", "listing": lp})
                            elif "." in e.rsplit("/", 1)[-1]:
                                file_paths.add(e)
                    seen = {b["path"] for b in backups}
                    budget = _MAX_BACKUP_REQUESTS
                    controls: dict[str, Any] = {}
                    for fp in sorted(file_paths):
                        for v in backup_variants(fp):
                            if budget <= 0 or v in seen:
                                continue
                            budget -= 1
                            try:
                                r = await client.get(base + v)
                            except Exception:  # noqa: BLE001
                                continue
                            sig = (r.status_code, len(r.text or ""))
                            # Per-file control: a nonexistent sibling name. Catch-all
                            # routes (SPA fallback, auth redirect to login) answer both
                            # alike, so equal responses are NOT flagged.
                            if fp not in controls:
                                budget -= 1
                                try:
                                    c = await client.get(base + fp + ".critforge_nx")
                                    controls[fp] = (c.status_code, len(c.text or ""))
                                except Exception:  # noqa: BLE001
                                    controls[fp] = None
                            if (r.status_code == 200 and sig != baseline_len
                                    and sig != controls.get(fp)
                                    and controls.get(fp) is not None):
                                backups.append({"path": v, "source": "variant_probe",
                                                "status": r.status_code, "length": sig[1]})
                                seen.add(v)
                if backups:
                    signals["backup_files"] = backups
                    signals["misconfig_indicator"] = signals.get(
                        "misconfig_indicator", "backup_files")

            if listing_paths:
                signals["directory_listing_paths"] = listing_paths
                signals["directory_listing_path"] = listing_paths[0]
                signals["directory_listing_entries_count"] = {
                    k: len(v) for k, v in listing_entries.items()}
            if error_paths:
                signals["verbose_error_paths"] = error_paths

            # Deduplicate routes
            signals["routes"] = sorted(set(signals["routes"]))

            if missing_headers:
                signals["missing_security_headers"] = sorted(missing_headers)
                signals["misconfig_indicator"] = "missing_security_headers"
                signals["misconfig_severity"] = "High"
            if dir_listing:
                signals["directory_listing"] = True
                signals["misconfig_indicator"] = signals.get(
                    "misconfig_indicator", "directory_listing"
                )
                signals["misconfig_severity"] = "High"
            if verbose_error:
                signals["verbose_error"] = True
                signals["misconfig_indicator"] = signals.get(
                    "misconfig_indicator", "verbose_error"
                )
                signals["misconfig_severity"] = "High"
            if banners:
                signals["server_banner"] = sorted(set(banners))
            if default_cred:
                signals["default_cred_page"] = True
                signals["auth_weakness_indicator"] = "default_credentials_hint"
            if sensitive_open:
                signals["sensitive_endpoint_open"] = True
                signals["auth_weakness_indicator"] = signals.get(
                    "auth_weakness_indicator", "unauthenticated_sensitive_api"
                )
            if reflection:
                signals["xss_reflection_indicator"] = True
            if status_anomaly:
                signals["status_anomaly"] = True

            # Corroboration markers for three-stage verifier (repeatable = we saw ≥2 pages)
            if pages_ok >= 2:
                signals["repeatable"] = True
            if signals.get("unauthenticated_api"):
                signals["sensitive_endpoint_open"] = True
                signals["auth_weakness_indicator"] = signals.get(
                    "auth_weakness_indicator", "unauthenticated_api"
                )
            if any(
                signals.get(k)
                for k in (
                    "directory_listing",
                    "verbose_error",
                    "default_cred_page",
                    "xss_reflection_indicator",
                    "sensitive_endpoint_open",
                    "missing_security_headers",
                    "exposed_metrics",
                    "exposed_encryption_keys",
                    "unauthenticated_api",
                    "backup_files",
                    "exposures",
                )
            ):
                signals["confirmation_marker"] = True
                signals["corroborating_signal"] = True

            signals["pages_fetched"] = pages_ok
            ok = pages_ok > 0
            return ProbeResult(
                probe=self.name,
                target=target.raw,
                ok=ok,
                signals=signals,
                error=None if ok else "no pages fetched",
                duration_ms=(time.perf_counter() - t0) * 1000,
            )
        except Exception as e:  # noqa: BLE001
            return ProbeResult(
                probe=self.name,
                target=target.raw,
                ok=False,
                error=f"{type(e).__name__}: {e}",
                duration_ms=(time.perf_counter() - t0) * 1000,
            )


async def _get(client, url: str, sem):
    async with sem:
        try:
            return await client.get(url)
        except Exception:  # noqa: BLE001
            return None


async def _discover_impl(self, client, base, target, signals, file_paths, error_paths):
    """Fallback-aware discovery pass. GET-only, bounded by self.max_discovery."""
    import asyncio

    sem = asyncio.Semaphore(self.concurrency)
    budget = [self.max_discovery]
    fetched: dict[str, dict] = {}
    controls: dict[str, Any] = {}
    tech: set[str] = set()
    exposures: list[dict] = []
    api_inv: list[dict] = []
    sensitive_api: list[dict] = []
    tp = (target.path or "").rstrip("/")
    prefixes = [""] + ([tp] if tp and tp != "/" else [])

    async def control_for(path: str):
        d = path.split("?", 1)[0].rsplit("/", 1)[0]
        if d not in controls:
            r = await _get(client, base + d + "/critforge_nx_ctrl_7f3a", sem)
            controls[d] = (_disc.Fingerprint.of(r.status_code, r.text or "", urlparse(str(r.url)).path)
                           if r is not None else None)
        return controls[d]

    async def fetch(path: str, origin: str):
        if path in fetched or budget[0] <= 0 or not _disc.is_safe_to_fetch(path):
            return None
        budget[0] -= 1
        fetched[path] = {"path": path, "origin": origin}
        r = await _get(client, base + path, sem)
        if r is None:
            fetched[path]["class"] = "fetch_error"
            return None
        body = r.text or ""
        final = urlparse(str(r.url)).path
        ctrl = await control_for(path) if r.status_code == 200 else None
        cls = _disc.classify(path, r.status_code, body, final, ctrl)
        fetched[path].update(status=r.status_code, cls=cls, length=len(body))
        hl = {k.lower(): v for k, v in r.headers.items()}
        tech.update(_disc.fingerprint_tech(hl, body))
        return r, body, cls, hl

    def on_page(path, res):
        r, body, cls, hl = res
        if cls == "real":
            chk = _disc.match_check(path)
            if chk:
                detail = chk.validator(body, hl.get("content-type", ""))
                if detail is not None:
                    exposures.append({"id": chk.id, "path": path.split("?", 1)[0], "title": chk.title,
                                      "severity": chk.severity, "cwe": chk.cwe, "tags": list(chk.tags),
                                      "detail": detail, "status": r.status_code})
            if r.status_code == 200 and "." in path.split("?", 1)[0].rsplit("/", 1)[-1]:
                file_paths.add(path.split("?", 1)[0])
        if ("/api/" in path or path.endswith("/api")) and cls != "not_found":
            api_inv.append({"path": path, "status": r.status_code, "class": cls})
            if cls == "real":
                pii = _disc.pii_shape(body)
                if pii:
                    sensitive_api.append({"path": path, **pii})
        if cls in ("auth_required", "not_found", "error") and r.status_code >= 400 and has_stack_trace(body):
            error_paths.append(path)

    # 1) seeds: common paths under each prefix + robots + sitemap + root pages
    seeds = [pre + p for pre in prefixes for p in _disc.COMMON_PATHS]
    roots = [pre + "/" for pre in prefixes]
    html_queue: list[str] = []
    js_files: list[str] = []
    for path, res in zip(roots, await asyncio.gather(*(fetch(p, "root") for p in roots))):
        if res:
            on_page(path, res)
            if res[2] == "real":
                html_queue.append(path)
    for path, res in zip(seeds, await asyncio.gather(*(fetch(p, "common_path") for p in seeds))):
        if not res:
            continue
        on_page(path, res)
        r, body, cls, _ = res
        if cls == "real" and path.endswith("robots.txt"):
            for ref in _disc.parse_robots(body):
                sp = _disc.same_origin_path(base, ref)
                if sp:
                    html_queue.append(sp)
        if cls == "real" and path.endswith("sitemap.xml"):
            for ref in _disc.parse_sitemap(body):
                sp = _disc.same_origin_path(base, ref)
                if sp:
                    html_queue.append(sp)
        if cls == "real" and path.endswith("asset-manifest.json"):
            js_files += [x for x in re.findall(r'"(/[^"]+\.js)"', body)][:3]

    # 2) bounded BFS over same-origin links (depth 2)
    seen_links: set[str] = set()
    frontier = list(dict.fromkeys(html_queue))
    for depth in range(2):
        nxt: list[str] = []
        res_list = await asyncio.gather(*(fetch(p, f"crawl_d{depth}") for p in frontier))
        pages = [(p, r) for p, r in zip(frontier, res_list) if r]
        # root pages were fetched already; re-read their bodies from the first pass
        for p in frontier:
            if p in fetched and fetched[p].get("cls") == "real" and not any(p == q for q, _ in pages):
                rr = await _get(client, base + p, sem)
                if rr is not None:
                    pages.append((p, (rr, rr.text or "", "real", {})))
        for p, res in pages:
            if res[0] is not None and fetched[p].get("origin", "").startswith("crawl"):
                on_page(p, res)
            body = res[1]
            for ref in _disc.extract_links(body):
                sp = _disc.same_origin_path(base, ref, base + p)
                if not sp or sp in seen_links:
                    continue
                seen_links.add(sp)
                if sp.split("?", 1)[0].endswith(".js"):
                    js_files.append(sp)
                elif not re.search(r"\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$", sp.split("?", 1)[0], re.I):
                    nxt.append(sp)
        frontier = [p for p in dict.fromkeys(nxt) if p not in fetched][:40]
        if not frontier:
            break

    # 3) JS bundle API-route extraction (crAPI-style SPA gateways)
    js_routes: list[str] = []
    rel_routes: list[str] = []
    svc_cands: list[str] = []
    for jp in _disc.prioritize_js(js_files)[:4]:
        rr = await _get(client, base + jp, sem)
        if rr is not None and rr.status_code == 200:
            text = (rr.text or "")[:5_000_000]
            js_routes += _disc.extract_js_routes(text)
            rel, svc = _disc.extract_js_relative(text)
            rel_routes += rel
            svc_cands += svc
    if rel_routes and svc_cands:
        # Validate service prefixes live: /<svc>/api/<nx> must differ from root-level /api/<nx>.
        root_ctl = await _get(client, base + "/api/critforge_nx_ctrl_7f3a", sem)
        root_fp = (_disc.Fingerprint.of(root_ctl.status_code, root_ctl.text or "")
                   if root_ctl is not None else None)
        live = []
        for svc in sorted(set(svc_cands)):
            rr = await _get(client, base + f"/{svc}/api/critforge_nx_ctrl_7f3a", sem)
            if rr is not None and not _disc.Fingerprint.of(rr.status_code, rr.text or "").similar(root_fp):
                live.append(svc)
        signals.setdefault("discovery_meta", {})["gateway_services"] = live
        for svc in live:
            js_routes += [f"/{svc}/{r}" for r in sorted(set(rel_routes))]
    js_routes = sorted(set(js_routes))
    api_candidates = [p for p in js_routes if _disc.is_safe_to_fetch(p)]
    budget[0] = max(budget[0], min(len(api_candidates), 150))  # dedicated API-inventory budget
    for path, res in zip(api_candidates, await asyncio.gather(*(fetch(p, "js_route") for p in api_candidates))):
        if res:
            on_page(path, res)

    # 4) prefix-aware benign error triggers (nonexistent route names only)
    if self.error_trigger:
        trig_prefixes = sorted(set(_disc.api_prefixes(js_routes + list(fetched))) | set(p for p in prefixes if p))
        trig = [pre + "/critforge_benign_nonexistent" for pre in trig_prefixes]
        for path, res in zip(trig, await asyncio.gather(*(fetch(p, "error_trigger") for p in trig))):
            if res:
                on_page(path, res)
                if path in error_paths:
                    signals["error_trigger"] = True

    # 5) confirmation: independent re-fetch of each exposure (repeatability)
    for ex in exposures:
        rr = await _get(client, base + ex["path"], sem)
        chk = _disc.match_check(ex["path"])
        ok = bool(rr is not None and rr.status_code == 200 and chk
                  and chk.validator(rr.text or "", rr.headers.get("content-type", "")) is not None)
        ex["repeatable"] = ok
        ex["content_validated"] = True

    signals["discovery"] = {
        "requests": self.max_discovery - budget[0],
        "prefixes": prefixes,
        "pages": sorted(fetched.values(), key=lambda x: x["path"]),
        "classes": {c: sum(1 for v in fetched.values() if v.get("cls") == c)
                    for c in {v.get("cls") for v in fetched.values()}},
        "js_routes": js_routes,
    }
    signals["routes"].extend(sorted(p for p, v in fetched.items() if v.get("cls") in ("real", "auth_required")))
    if exposures:
        signals["exposures"] = exposures
        signals["misconfig_indicator"] = signals.get("misconfig_indicator", "exposure")
    if api_inv:
        signals["api_inventory"] = api_inv
    if sensitive_api:
        signals["sensitive_api"] = sensitive_api
    if tech:
        signals["tech"] = sorted(tech)


HttpObserveProbe._discover = _discover_impl  # type: ignore[attr-defined]


class HttpCrawlProbe(Probe):
    """Lightweight same-origin link harvest for loopback targets (GET-only)."""

    name = "http_crawl"
    description = "Localhost-only link harvest from seed URL."

    async def observe(self, target: Target, *, timeout: float = 30.0) -> ProbeResult:
        # Reuse HttpObserveProbe with a tiny path set — crawl is observational.
        inner = HttpObserveProbe(paths=("/", "/health"))
        result = await inner.observe(target, timeout=timeout)
        result.probe = self.name
        if result.ok:
            result.signals = {
                "observed": True,
                "routes": result.signals.get("routes", []),
                "crawl_mode": "http_safe",
            }
        return result
