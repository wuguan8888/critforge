"""pt42u: discovery, fallback-aware classification, exposure validators, dedup,
calibration and chain synthesis. All local / GET-only; no payloads."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from critforge import discovery as d
from critforge.attackchain import synthesize
from critforge.dedup import merge_findings
from critforge.detectors import lab_safe_registry
from critforge.detectors.base import SignalBundle
from critforge.finding import Confidence, Finding, FindingCategory
from critforge.http_probe import HttpObserveProbe
from critforge.nuclei import issue_key as nuclei_issue_key, map_results
from critforge.scope import Severity
from critforge.target import parse as parse_target
from critforge.verify import Verifier

ENV_BODY = "DB_NAME=x\nDB_PASSWORD=supersecretvalue\nJWT_SECRET=abc\n"
LOGIN = "<html><head><title>Login Page</title></head><form><input type='password'></form></html>"
JS = 'const S="shop/";fetch("/svc/api/items");const R={A:"api/catalog/list",B:"api/user/delete_account"};'


class _Spring(BaseHTTPRequestHandler):
    """Spring-like lab: unknown paths 302 → /app/login; actuator real; SPA root."""

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", loc=None):
        b = body.encode()
        self.send_response(code)
        if loc:
            self.send_header("Location", loc)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):  # noqa: C901
        p = self.path
        if p == "/app/login":
            return self._send(200, LOGIN)
        if p == "/app/actuator":
            return self._send(200, json.dumps({"_links": {"self": {"href": "x"}, "env": {"href": "y"}}}),
                              "application/vnd.spring-boot.actuator.v3+json")
        if p == "/app/actuator/env":
            return self._send(200, json.dumps({"activeProfiles": [], "propertySources": [
                {"name": "a", "properties": {"k": {"value": "SECRETVALUE"}}}]}), "application/json")
        if p == "/.env":
            return self._send(200, ENV_BODY, "application/octet-stream")
        if p == "/":
            return self._send(200, '<html><title>Shop</title><script src="/static/main.js"></script>'
                                   '<a href="/about">a</a></html>')
        if p == "/about":
            return self._send(200, "<html><title>About</title>about us page</html>")
        if p == "/static/main.js":
            return self._send(200, JS, "application/javascript")
        if p.startswith("/shop/api/catalog/list"):
            return self._send(401, '{"error":"Unauthorized"}', "application/json")
        if p.startswith("/shop/api/"):
            return self._send(404, '{"message":"no route"}', "application/json")
        if p.startswith("/svc/api/items"):
            return self._send(200, json.dumps([{"email": "a@b.example"}]), "application/json")
        if p.startswith("/app/"):
            return self._send(302, "", loc="/app/login")
        if p.startswith("/api/"):
            return self._send(404, "<html>404</html>")
        # SPA catch-all for everything else (incl. /.git/HEAD!)
        return self._send(200, "<html><title>Shop</title><div id=root></div></html>")


@pytest.fixture()
def spring():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Spring)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _run(url):
    return asyncio.run(HttpObserveProbe(paths=("/",), discover=True).observe(parse_target(url), timeout=5))


# ---------------------------------------------------------------- unit helpers
def test_classify_login_redirect_and_soft404():
    ctrl = d.Fingerprint.of(200, "<html><title>Shop</title><div id=root></div></html>", "/x")
    assert d.classify("/app/actuator/mappings", 200, LOGIN, "/app/login;jsessionid=AB", None) == "login_redirect"
    assert d.classify("/.git/HEAD", 200, "<html><title>Shop</title><div id=root></div></html>", "/.git/HEAD", ctrl) == "soft404"
    assert d.classify("/app/actuator", 200, '{"_links":{}}', "/app/actuator", ctrl) == "real"
    assert d.classify("/x", 401, "", "/x", None) == "auth_required"
    assert d.classify("/x", 405, "", "/x", None) == "client_error"


def test_login_heuristic_ignores_password_field_in_large_app():
    big = "<html><title>MailHog</title>" + "x" * 9000 + "<input type='password'></html>"
    assert not d.is_login_page(big)
    assert d.is_login_page(LOGIN)


def test_validators_and_no_values_leaked():
    det = d._v_env(ENV_BODY, "")
    assert det == {"variables": 3, "sensitive_like_variables": 3}
    assert "supersecretvalue" not in json.dumps(det)
    assert d._v_env("<html>DB=1\nA=2</html>", "") is None
    assert d._v_git_head("ref: refs/heads/main\n", "")
    assert d._v_git_head("<html>", "") is None
    assert d._v_actuator_index('{"_links":{"self":{},"env":{}}}', "")["endpoint_names"] == ["env"]
    assert d._v_openapi('{"openapi":"3.0.1","paths":{"/a":{}}}', "")["paths"] == 1
    assert d._v_metrics("# HELP a\n# TYPE a counter\na 1\n", "")


def test_harvesters():
    assert "/secret" in d.parse_robots("User-agent: *\nDisallow: /secret\nDisallow: /")
    assert d.parse_sitemap("<urlset><loc>http://h/a</loc></urlset>") == ["http://h/a"]
    assert d.same_origin_path("http://127.0.0.1:1", "http://evil.example/x") is None
    assert d.same_origin_path("http://127.0.0.1:1", "/a?b=1") == "/a?b=1"
    assert d.extract_js_routes(JS) == ["/svc/api/items"]
    rel, svc = d.extract_js_relative(JS)
    assert "api/catalog/list" in rel and "shop" in svc
    assert d.api_prefixes(["/identity/api/v2/x", "/api/a"]) == ["/api", "/identity/api"]


def test_safety_filters():
    for bad in ("/actuator/heapdump", "/actuator/shutdown", "/api/user/delete_account",
                "/identity/api/auth/reset-password", "/api/v2/vehicle/add_vehicle", "/logout"):
        assert not d.is_safe_to_fetch(bad), bad
    assert d.is_safe_to_fetch("/workshop/api/shop/products")
    assert d.prioritize_js(["/js/jquery-1.11.min.js", "/js/controllers.js"])[0] == "/js/controllers.js"


# ---------------------------------------------------------------- live local lab
def test_discovery_finds_real_exposures_not_fallbacks(spring):
    r = _run(spring + "/app")
    s = r.signals
    ids = {e["id"]: e for e in s.get("exposures", [])}
    assert {"actuator_index", "actuator_env", "env_file"} <= set(ids)
    assert "git_head" not in ids  # SPA catch-all 200 must not count
    assert all(e["repeatable"] and e["content_validated"] for e in ids.values())
    blob = json.dumps(s)
    assert "supersecretvalue" not in blob and "SECRETVALUE" not in blob
    classes = s["discovery"]["classes"]
    assert classes.get("login_redirect", 0) >= 1 and classes.get("soft404", 0) >= 1
    # JS route discovery incl. gateway prefix composition, mutating route skipped
    assert "/svc/api/items" in s["discovery"]["js_routes"]
    assert "/shop/api/catalog/list" in s["discovery"]["js_routes"]
    paths = {p["path"] for p in s["discovery"]["pages"]}
    assert not any("delete_account" in p for p in paths)
    inv = {i["path"]: i["class"] for i in s["api_inventory"]}
    assert inv["/shop/api/catalog/list"] == "auth_required"
    assert s["sensitive_api"][0] == {"path": "/svc/api/items", "emails": 1}


def test_detectors_emit_exposure_findings(spring):
    r = _run(spring + "/app")
    fs = lab_safe_registry().run_all(SignalBundle.from_results(spring + "/app", [r]))
    titles = " ".join(f.title for f in fs)
    assert "Actuator /env" in titles and ".env" in titles
    env = next(f for f in fs if f.evidence.get("exposure_id") == "env_file")
    assert env.severity == Severity.HIGH and env.evidence["content_validated"]


# ---------------------------------------------------------------- nuclei / dedup / verify / chain
def _nuc(tid, at, tags="exposure,config", sev="high", matcher=None):
    return {"template-id": tid, "matched-at": at, "matcher-name": matcher,
            "info": {"name": tid, "severity": sev, "tags": tags}}


def test_nuclei_collapses_matchers_and_keys():
    res = [_nuc("http-missing-security-headers", "http://127.0.0.1:1/", "misconfig,headers", "info", m)
           for m in ("csp", "xfo", "hsts")]
    res += [_nuc("dotenv-file", "http://127.0.0.1:1/.env"), _nuc("laravel-env", "http://127.0.0.1:1/.env")]
    fs = map_results("t", res)
    assert len(fs) == 3
    hdr = next(f for f in fs if f.evidence["template_id"] == "http-missing-security-headers")
    assert hdr.evidence["matcher_names"] == ["csp", "hsts", "xfo"]
    assert nuclei_issue_key(res[-1]) == "exposure:/.env"
    merged = merge_findings(fs)
    assert len(merged) == 2  # two .env templates → one issue


def test_cross_engine_merge_and_calibration():
    passive = Finding(category=FindingCategory.MISCONFIG, severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                      title=".env", target="t", detector="misconfig.exposure",
                      evidence={"signal": "exposures", "issue_key": "exposure:/.env", "sources": ["http_observe"],
                                "content_validated": True, "repeatable": True})
    nuc = map_results("t", [_nuc("dotenv-file", "http://127.0.0.1:1/.env")])[0]
    merged = merge_findings([nuc, passive])
    assert len(merged) == 1 and merged[0] is passive
    assert merged[0].evidence["cross_engine"] and merged[0].evidence["sources"] == ["http_observe", "nuclei"]
    r = Verifier().verify(merged[0], SignalBundle(target="t", signals={}))
    assert r.confidence == Confidence.CONFIRMED


def test_heuristic_only_is_capped():
    f = Finding(category=FindingCategory.AUTH_FLAW, severity=Severity.HIGH, confidence=Confidence.HIGH,
                title="x", target="t", detector="d",
                evidence={"signal": "s", "repeatable": True, "heuristic_only": True})
    assert Verifier().verify(f, SignalBundle(target="t", signals={})).confidence == Confidence.MEDIUM


def _f(sev, key, cat=FindingCategory.MISCONFIG, tags=None):
    return Finding(category=cat, severity=sev, confidence=Confidence.HIGH, title=key, target="t",
                   detector="misconfig.exposure", evidence={"issue_key": key, "tags": tags or []})


def test_chain_fires_on_real_exposure_and_ignores_info_endpoint():
    fs = [_f(Severity.LOW, "missing_security_headers"), _f(Severity.MEDIUM, "exposure:/actuator", tags=["actuator"]),
          _f(Severity.HIGH, "exposure:/actuator/env", tags=["secret_exposure"]),
          _f(Severity.INFO, "tech_fingerprint", FindingCategory.INFO)]
    chains = synthesize(fs)
    assert len(chains) == 1
    c = chains[0]
    assert c.nodes[-1].title == "exposure:/actuator/env"
    assert "credential/config exposure" in c.title
    assert all(n.severity != "Info" for n in c.nodes)


def test_chain_requires_two_distinct_issues():
    assert synthesize([_f(Severity.HIGH, "exposure:/.env"), _f(Severity.HIGH, "exposure:/.env")]) == []
