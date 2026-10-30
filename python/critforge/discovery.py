"""Passive content discovery + fallback-aware page classification (GET-only).

Pieces used by HttpObserveProbe when ``discover=True``:

* ``COMMON_PATHS``      — small curated list of well-known exposure locations
                          (not a brute-force wordlist).
* ``parse_robots`` / ``parse_sitemap`` / ``extract_links`` / ``extract_js_routes``
                        — same-origin route harvesting.
* ``Fingerprint`` / ``classify``
                        — distinguishes *real* content from SPA catch-all pages,
                          soft-404s and redirect-to-login fallbacks, so a 200 on
                          ``/actuator`` is judged by content, not by status code.
* ``EXPOSURE_CHECKS``   — content validators (e.g. ``.env`` must look like
                          KEY=VALUE lines). Validators return only counts / key
                          *shapes*; response bodies and secret values are never
                          stored or echoed.

No payloads, no mutation: candidate API routes whose names look state-changing
are skipped entirely.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------- common paths
# Relative to every discovered prefix ("" and e.g. "/WebGoat").
COMMON_PATHS: tuple[str, ...] = (
    "/.env", "/.git/HEAD", "/.git/config", "/.svn/entries", "/.DS_Store",
    "/.htaccess", "/.npmrc", "/config.json", "/package.json",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/mappings", "/actuator/configprops", "/actuator/beans",
    "/actuator/metrics", "/actuator/prometheus", "/actuator/loggers",
    "/metrics", "/prometheus", "/server-status", "/server-info",
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    "/swagger-ui.html", "/swagger-ui/index.html", "/api-docs", "/api/swagger.json",
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/manifest.json", "/asset-manifest.json", "/health", "/status", "/version",
    "/phpinfo.php", "/info.php", "/console", "/h2-console", "/api/v2/messages",
)


_VENDOR_JS = re.compile(r"(?:jquery|bootstrap|angular-\d|moment|lodash|polyfill|vendor|runtime|filesize)", re.I)


def prioritize_js(paths: list[str]) -> list[str]:
    """App bundles first (main/app/controllers/chunk), well-known vendor libraries last."""
    def score(p: str) -> int:
        n = p.rsplit("/", 1)[-1].lower()
        if _VENDOR_JS.search(n):
            return 2
        return 0 if re.search(r"main|app|bundle|controllers|index|chunk", n) else 1
    return sorted(dict.fromkeys(paths), key=score)
# Never fetched even if discovered: large binary dumps / state-changing actuators.
NEVER_FETCH = re.compile(
    r"/(?:heapdump|threaddump|shutdown|restart|refresh|jolokia|logfile)(?:$|[/?])", re.I)
# Route segments suggesting a state change — skipped during API discovery (GET-only safety).
MUTATING = re.compile(
    r"(?:^|[/_-])(?:delete|remove|reset|logout|signout|update|edit|create|apply|buy|"
    r"order|return|pay|add|resend|convert|receive|contact|download|validate|unlock|login|coupon|"
    r"checkout|transfer|upload|change|verify|otp|send|register|signup|"
    r"forget|forgot|unsubscribe|cancel|approve|admin/.*/(?:set|add))(?:$|[/_?-])", re.I)

MAX_DISCOVERED = 120  # hard cap on extra discovery requests per target


# ---------------------------------------------------------------- harvesting
def parse_robots(body: str) -> list[str]:
    out = []
    for line in (body or "").splitlines():
        m = re.match(r"\s*(?:dis)?allow\s*:\s*(\S+)", line, re.I)
        if m and m.group(1) not in ("/", "*") and "*" not in m.group(1):
            out.append(m.group(1).split("$", 1)[0])
        m = re.match(r"\s*sitemap\s*:\s*(\S+)", line, re.I)
        if m:
            out.append(m.group(1))
    return out


def parse_sitemap(body: str) -> list[str]:
    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body or "", re.I)[:50]


def same_origin_path(base: str, ref: str, page_url: Optional[str] = None) -> Optional[str]:
    """Resolve *ref* against page/base; return path(+query) if same origin else None."""
    if not ref or ref.startswith(("#", "mailto:", "javascript:", "data:", "tel:")):
        return None
    full = urljoin(page_url or base + "/", ref)
    a, b = urlparse(full), urlparse(base)
    if (a.hostname, a.port or 80) != (b.hostname, b.port or 80):
        return None
    path = a.path or "/"
    return path + (("?" + a.query) if a.query else "")


def extract_links(body: str) -> list[str]:
    return re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\'<>\s]+)["\']', body or "", re.I)


_JS_ROUTE = re.compile(r'["\'`](/(?:[A-Za-z0-9_.-]+/){0,3}api/[A-Za-z0-9_./-]{1,80})["\'`]')


def extract_js_routes(js: str) -> list[str]:
    """API path literals in a JS bundle (e.g. "/workshop/api/shop/products")."""
    out = set()
    for m in _JS_ROUTE.finditer(js or ""):
        p = m.group(1).rstrip("/")
        if "//" in p or "{" in p or ":" in p:
            continue
        out.add(p)
    return sorted(out)


_JS_REL_ROUTE = re.compile(r'["\'`]((?:v\d[\w.]*/)?api/[A-Za-z0-9_./-]{1,80})["\'`]')
_JS_SVC = re.compile(r'["\'`]/?([a-z][a-z0-9-]{2,24})/["\'`]')


def extract_js_relative(js: str) -> tuple[list[str], list[str]]:
    """Relative API literals ("api/shop/products") + service-prefix candidates ("workshop/").

    SPA gateways (e.g. crAPI) build URLs as SERVICE + "api/...". Prefix candidates
    are later validated live (only prefixes whose /<svc>/api/ answers differently
    from a root-level control are used).
    """
    rel = sorted({m.group(1).rstrip("/") for m in _JS_REL_ROUTE.finditer(js or "")
                  if "{" not in m.group(1) and ":" not in m.group(1)})
    svc = sorted({m.group(1) for m in _JS_SVC.finditer(js or "")} - {"api", "static", "assets", "http", "https"})
    return rel[:80], svc[:15]


def is_safe_to_fetch(path: str) -> bool:
    p = path.split("?", 1)[0]
    return not NEVER_FETCH.search(p) and not MUTATING.search(p)


def api_prefixes(paths: list[str]) -> list[str]:
    """'/identity/api/v2/x' -> '/identity/api' (used for prefix-aware error triggers)."""
    out = set()
    for p in paths:
        m = re.match(r"(/(?:[A-Za-z0-9_.-]+/)*?api)(?:/|$)", p)
        if m:
            out.add(m.group(1))
    return sorted(out)


# ---------------------------------------------------------------- classification
def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    return (m.group(1).strip().lower()[:80]) if m else ""


def _shape(body: str) -> str:
    """Structure hash that ignores digits/tokens (CSRF tokens, session ids, timestamps)."""
    t = re.sub(r"[0-9a-f]{8,}|\d+", "", (body or "")[:20000].lower())
    return hashlib.sha1(t.encode("utf-8", "ignore")).hexdigest()[:16]


@dataclass(frozen=True)
class Fingerprint:
    status: int
    length: int
    title: str
    shape: str
    final_path: str

    @classmethod
    def of(cls, status: int, body: str, final_path: str = "") -> "Fingerprint":
        return cls(status, len(body or ""), _title(body), _shape(body), final_path)

    def similar(self, other: Optional["Fingerprint"]) -> bool:
        if other is None or self.status != other.status:
            return False
        if self.shape == other.shape:
            return True
        if self.title and self.title == other.title:
            big = max(self.length, other.length, 1)
            return abs(self.length - other.length) / big < 0.10
        return False


_LOGIN_TITLE = re.compile(r"<title>[^<]*(?:log ?in|sign ?in|anmelden|登录)[^<]*</title>", re.I)
_PASSWORD = re.compile(r"type=[\"']password[\"']", re.I)


def is_login_page(body: str) -> bool:
    """Login page = login-ish title, or a small page whose main purpose is a password form.

    A password field inside a large app shell (e.g. a settings modal) is NOT a login page.
    """
    b = body or ""
    if _LOGIN_TITLE.search(b):
        return True
    return bool(_PASSWORD.search(b)) and len(b) < 6000 and re.search(r"<form[^>]*>", b, re.I) is not None


def classify(
    path: str,
    status: int,
    body: str,
    final_path: str,
    control: Optional[Fingerprint],
) -> str:
    """Return one of: real | soft404 | login_redirect | auth_required | not_found | error | redirect."""
    req = path.split("?", 1)[0].rstrip("/") or "/"
    fin = (final_path or req).split(";", 1)[0].rstrip("/") or "/"
    if status in (401, 403):
        return "auth_required"
    if status in (404, 410):
        return "not_found"
    if status >= 500:
        return "error"
    if status >= 400:
        return "client_error"
    if status >= 300:
        return "redirect"
    if fin != req and ("login" in fin.lower() or "signin" in fin.lower() or is_login_page(body)):
        return "login_redirect"
    fp = Fingerprint.of(status, body, fin)
    if control is not None and fp.similar(control):
        return "soft404"
    if is_login_page(body) and "login" not in req.lower() and "signin" not in req.lower():
        return "login_redirect"
    return "real"


# ---------------------------------------------------------------- exposure validators
def _json(body: str) -> Any:
    try:
        return json.loads(body)
    except Exception:  # noqa: BLE001
        return None


def _v_env(body: str, ct: str) -> Optional[dict]:
    if "<html" in body[:500].lower():
        return None
    keys = re.findall(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,60})\s*=", body, re.M)
    if len(keys) < 2:
        return None
    sens = [k for k in keys if re.search(r"PASS|SECRET|TOKEN|KEY|PWD|CRED|DB_", k)]
    return {"variables": len(keys), "sensitive_like_variables": len(sens)}


def _v_git_head(body: str, ct: str) -> Optional[dict]:
    return {"format": "git HEAD"} if re.match(r"ref: refs/|[0-9a-f]{40}\s*$", body.strip()) else None


def _v_git_config(body: str, ct: str) -> Optional[dict]:
    return {"format": "git config"} if "[core]" in body and "repositoryformatversion" in body else None


def _v_svn(body: str, ct: str) -> Optional[dict]:
    return {"format": "svn entries"} if re.match(r"\d+\s*\n", body) and "dir" in body[:200] else None


def _v_ds_store(body: str, ct: str) -> Optional[dict]:
    return {"format": ".DS_Store"} if "Bud1" in body[:16] else None


def _v_actuator_index(body: str, ct: str) -> Optional[dict]:
    j = _json(body)
    if isinstance(j, dict) and isinstance(j.get("_links"), dict) and "self" in j["_links"]:
        names = sorted(k for k in j["_links"] if k != "self")
        return {"endpoints_listed": len(names), "endpoint_names": names[:30]}
    return None


def _v_actuator_env(body: str, ct: str) -> Optional[dict]:
    j = _json(body)
    if isinstance(j, dict) and "propertySources" in j:
        n = sum(len((s or {}).get("properties") or {}) for s in j["propertySources"] if isinstance(s, dict))
        return {"property_sources": len(j["propertySources"]), "properties": n}
    return None


def _v_actuator_json(keys: tuple[str, ...]) -> Callable[[str, str], Optional[dict]]:
    def v(body: str, ct: str) -> Optional[dict]:
        j = _json(body)
        if isinstance(j, dict) and any(k in j for k in keys):
            return {"top_level_keys": sorted(j)[:10]}
        return None
    return v


def _v_metrics(body: str, ct: str) -> Optional[dict]:
    n = len(re.findall(r"^# (?:HELP|TYPE) ", body, re.M))
    return {"metric_families": n // 2 or n} if n >= 2 else None


def _v_openapi(body: str, ct: str) -> Optional[dict]:
    j = _json(body)
    if isinstance(j, dict) and ("openapi" in j or "swagger" in j) and "paths" in j:
        return {"spec_version": str(j.get("openapi") or j.get("swagger")), "paths": len(j.get("paths") or {})}
    return None


def _v_swagger_ui(body: str, ct: str) -> Optional[dict]:
    return {"ui": "swagger-ui"} if re.search(r"swagger-ui(?:-bundle)?(?:\.js|\.css|\")", body, re.I) else None


def _v_server_status(body: str, ct: str) -> Optional[dict]:
    return {"format": "apache server-status"} if "Apache Server Status" in body else None


def _v_phpinfo(body: str, ct: str) -> Optional[dict]:
    return {"format": "phpinfo"} if "phpinfo()" in body and "PHP Version" in body else None


def _v_h2(body: str, ct: str) -> Optional[dict]:
    return {"format": "H2 console"} if ("H2 Console" in body or ("h2-console" in body.lower() and "jdbc" in body.lower())) else None


def _v_npmrc(body: str, ct: str) -> Optional[dict]:
    return {"auth_token_like": bool(re.search(r"_auth(?:Token)?\s*=", body))} if re.search(r"^\s*(?:registry|//)", body, re.M) and "<html" not in body[:300].lower() else None


def _v_mailhog(body: str, ct: str) -> Optional[dict]:
    j = _json(body)
    if isinstance(j, dict) and "total" in j and "items" in j:
        return {"messages_total": int(j.get("total") or 0)}
    return None


@dataclass(frozen=True)
class ExposureCheck:
    id: str
    suffix: str            # matched against the path end (prefix-agnostic)
    title: str
    severity: str          # Severity value
    cwe: str
    validator: Callable[[str, str], Optional[dict]]
    category: str = "misconfig"
    tags: tuple[str, ...] = ()


EXPOSURE_CHECKS: tuple[ExposureCheck, ...] = (
    ExposureCheck("env_file", "/.env", "Environment file (.env) publicly readable", "High", "CWE-538", _v_env,
                  tags=("secret_exposure",)),
    ExposureCheck("git_head", "/.git/HEAD", "Git metadata (.git/HEAD) exposed", "High", "CWE-527", _v_git_head,
                  tags=("source_exposure",)),
    ExposureCheck("git_config", "/.git/config", "Git config (.git/config) exposed", "High", "CWE-527", _v_git_config,
                  tags=("source_exposure",)),
    ExposureCheck("svn_entries", "/.svn/entries", "SVN metadata exposed", "High", "CWE-527", _v_svn,
                  tags=("source_exposure",)),
    ExposureCheck("ds_store", "/.DS_Store", ".DS_Store file listing exposed", "Low", "CWE-538", _v_ds_store),
    ExposureCheck("npmrc", "/.npmrc", ".npmrc exposed", "High", "CWE-538", _v_npmrc, tags=("secret_exposure",)),
    ExposureCheck("actuator_env", "/actuator/env", "Spring Boot Actuator /env exposed without authentication",
                  "High", "CWE-215", _v_actuator_env, tags=("secret_exposure", "actuator")),
    ExposureCheck("actuator_configprops", "/actuator/configprops", "Spring Boot Actuator /configprops exposed",
                  "High", "CWE-215", _v_actuator_json(("contexts",)), tags=("secret_exposure", "actuator")),
    ExposureCheck("actuator_index", "/actuator", "Spring Boot Actuator endpoint index exposed",
                  "Medium", "CWE-200", _v_actuator_index, tags=("actuator",)),
    ExposureCheck("actuator_mappings", "/actuator/mappings", "Spring Boot Actuator /mappings exposed (route map)",
                  "Medium", "CWE-200", _v_actuator_json(("contexts",)), tags=("actuator", "route_map")),
    ExposureCheck("actuator_beans", "/actuator/beans", "Spring Boot Actuator /beans exposed",
                  "Low", "CWE-200", _v_actuator_json(("contexts",)), tags=("actuator",)),
    ExposureCheck("actuator_loggers", "/actuator/loggers", "Spring Boot Actuator /loggers exposed",
                  "Medium", "CWE-200", _v_actuator_json(("loggers", "levels")), tags=("actuator",)),
    ExposureCheck("actuator_metrics", "/actuator/metrics", "Spring Boot Actuator /metrics exposed",
                  "Low", "CWE-200", _v_actuator_json(("names",)), tags=("actuator",)),
    ExposureCheck("prometheus", "/actuator/prometheus", "Prometheus metrics exposed", "Medium", "CWE-200", _v_metrics),
    ExposureCheck("metrics", "/metrics", "Prometheus-style metrics exposed", "Medium", "CWE-200", _v_metrics),
    ExposureCheck("openapi_spec", "/v3/api-docs", "OpenAPI specification publicly accessible", "Low", "CWE-200",
                  _v_openapi, tags=("route_map",)),
    ExposureCheck("openapi_spec_v2", "/v2/api-docs", "OpenAPI specification publicly accessible", "Low", "CWE-200",
                  _v_openapi, tags=("route_map",)),
    ExposureCheck("openapi_json", "/openapi.json", "OpenAPI specification publicly accessible", "Low", "CWE-200",
                  _v_openapi, tags=("route_map",)),
    ExposureCheck("swagger_json", "/swagger.json", "Swagger specification publicly accessible", "Low", "CWE-200",
                  _v_openapi, tags=("route_map",)),
    ExposureCheck("swagger_ui", "/swagger-ui/index.html", "Swagger UI publicly accessible", "Low", "CWE-200",
                  _v_swagger_ui, tags=("route_map",)),
    ExposureCheck("swagger_ui_html", "/swagger-ui.html", "Swagger UI publicly accessible", "Low", "CWE-200",
                  _v_swagger_ui, tags=("route_map",)),
    ExposureCheck("server_status", "/server-status", "Apache server-status exposed", "Medium", "CWE-200",
                  _v_server_status),
    ExposureCheck("phpinfo", "/phpinfo.php", "phpinfo() page exposed", "Medium", "CWE-200", _v_phpinfo),
    ExposureCheck("mailhog_api", "/api/v2/messages", "Mail-catcher (MailHog) API readable without authentication",
                  "Medium", "CWE-306", _v_mailhog, category="auth_flaw", tags=("admin_surface", "mail_access")),
    ExposureCheck("h2_console", "/h2-console", "H2 database console reachable", "High", "CWE-306", _v_h2,
                  tags=("admin_surface",)),
)


def match_check(path: str) -> Optional[ExposureCheck]:
    p = path.split("?", 1)[0].rstrip("/")
    best = None
    for c in EXPOSURE_CHECKS:
        if p.endswith(c.suffix) and (best is None or len(c.suffix) > len(best.suffix)):
            best = c
    return best


# ---------------------------------------------------------------- tech fingerprint
_TECH_RULES: tuple[tuple[str, str, str], ...] = (
    # (where, regex, label)
    ("cookie", r"\bJSESSIONID=", "Java Servlet container"),
    ("cookie", r"\bconnect\.sid=", "Node.js Express (express-session)"),
    ("cookie", r"\bPHPSESSID=", "PHP"),
    ("cookie", r"\bcsrftoken=", "Django"),
    ("header", r"x-powered-by:\s*express", "Node.js Express"),
    ("header", r"server:\s*openresty", "OpenResty"),
    ("header", r"server:\s*nginx", "nginx"),
    ("header", r"server:\s*apache", "Apache httpd"),
    ("header", r"x-application-context|spring", "Spring"),
    ("body", r"__NEXT_DATA__", "Next.js"),
    ("body", r"<app-root|ng-version=", "Angular"),
    ("body", r"id=[\"']root[\"']|create react app|react-dom", "React"),
    ("body", r"Whitelabel Error Page", "Spring Boot"),
    ("body", r"/webjars/|thymeleaf", "Spring MVC / Thymeleaf"),
    ("content_type", r"vnd\.spring-boot\.actuator", "Spring Boot Actuator"),
)


def fingerprint_tech(headers: dict[str, str], body: str) -> set[str]:
    hdr = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
    cookie = headers.get("set-cookie", "")
    ct = headers.get("content-type", "")
    found = set()
    for where, rx, label in _TECH_RULES:
        hay = {"cookie": cookie, "header": hdr, "body": (body or "")[:50000], "content_type": ct}[where]
        if re.search(rx, hay, re.I):
            found.add(label)
    return found


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def pii_shape(body: str) -> dict[str, int]:
    """Counts only (never values): emails inside a JSON document."""
    j = _json(body)
    if j is None:
        return {}
    text = json.dumps(j)
    emails = len(set(_EMAIL.findall(text)))
    return {"emails": emails} if emails else {}
