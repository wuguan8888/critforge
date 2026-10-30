"""Regression tests for pt37u coverage improvements (passive only, no payloads)."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from critforge.detectors.base import SignalBundle
from critforge.detectors.real_safe import (
    BackupFileDetector, DirectoryListingDetector, NucleiFindingDetector, VerboseErrorDetector,
)
from critforge.http_probe import (
    HttpObserveProbe, _ERROR_TRIGGER_PATHS, backup_variants, has_stack_trace, is_backup_name,
)
from critforge import nuclei
from critforge.reporting import COVERAGE_DISCLAIMER, build_report
from critforge.scope import Scope, Severity
from critforge.target import parse as parse_target

NODE_STACK = "Error: Unexpected path\n    at /app/routes/x.js:12:7\n    at Layer.handle (/app/node_modules/express/lib/router/layer.js:95:5)"
PY_STACK = "Traceback (most recent call last):\n  File \"a.py\", line 1"


class _Lab(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path
        if p == "/ftp":
            return self._send(200, '<title>listing directory /ftp</title><a href="/ftp/package.json.bak">a</a><a href="/ftp/notes.md">b</a>')
        if p == "/encryptionkeys":
            return self._send(200, '<title>listing directory /encryptionkeys</title><a href="/encryptionkeys/jwt.pub">k</a>')
        if p in ("/rest/critforge_benign_nonexistent", "/api/critforge_benign_nonexistent"):
            return self._send(500, NODE_STACK)
        if p == "/robots.txt":
            return self._send(200, "User-agent: *")
        if p == "/robots.txt.bak":
            return self._send(200, "old robots")
        if p == "/":
            return self._send(200, "<html>home</html>")
        return self._send(200, "<html>SPA</html>")  # SPA fallback


@pytest.fixture()
def lab():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _observe(url, paths):
    return asyncio.run(HttpObserveProbe(paths=paths).observe(parse_target(url), timeout=5))


# ---- (1a) error-trigger ----------------------------------------------------
def test_stack_trace_patterns():
    assert has_stack_trace(NODE_STACK)
    assert has_stack_trace(PY_STACK)
    assert has_stack_trace("at com.x.Foo(Foo.java:42)")
    assert not has_stack_trace("<html>Not found</html>")


def test_error_trigger_paths_are_benign():
    bad = ("'", "<", ">", "script", "union", "select", "../", "${", "{{", ";", "|")
    for p in _ERROR_TRIGGER_PATHS:
        assert not any(b in p.lower() for b in bad), p


def test_error_trigger_flags_verbose_error(lab):
    r = _observe(lab, ("/",))
    assert r.signals.get("verbose_error") and r.signals.get("error_trigger")
    fs = VerboseErrorDetector().evaluate(SignalBundle(target=lab, signals=r.signals))
    assert len(fs) == 1 and fs[0].evidence["error_trigger"] is True


# ---- (1b) backup files -----------------------------------------------------
def test_backup_helpers():
    assert is_backup_name("package.json.bak") and is_backup_name("x~") and is_backup_name(".a.swp")
    assert not is_backup_name("notes.md")
    assert backup_variants("/robots.txt") == [f"/robots.txt{s}" for s in (".bak", ".old", ".swp", "~", ".orig")]
    assert backup_variants("/dir/") == [] and backup_variants("/a.bak") == []


def test_backup_detection_listing_and_variant(lab):
    r = _observe(lab, ("/", "/ftp", "/robots.txt"))
    got = {b["path"]: b["source"] for b in r.signals["backup_files"]}
    assert got.get("/ftp/package.json.bak") == "listing"
    assert got.get("/robots.txt.bak") == "variant_probe"
    # SPA fallback (200 w/ same body as baseline) must NOT be flagged
    assert "/ftp/notes.md.old" not in got and "/robots.txt.orig" not in got
    fs = BackupFileDetector().evaluate(SignalBundle(target=lab, signals=r.signals))
    assert {f.evidence["check_id"] for f in fs} == {f"backup_file:{p}" for p in got}


# ---- (1c) directory listing split -----------------------------------------
def test_directory_listing_split_into_separate_checks(lab):
    r = _observe(lab, ("/", "/ftp", "/encryptionkeys"))
    assert r.signals["directory_listing_paths"] == ["/ftp", "/encryptionkeys"]
    fs = DirectoryListingDetector().evaluate(SignalBundle(target=lab, signals=r.signals))
    assert sorted(f.evidence["check_id"] for f in fs) == [
        "directory_listing:/encryptionkeys", "directory_listing:/ftp"]
    assert len({f.id for f in fs}) == 2


def test_directory_listing_legacy_single_signal():
    fs = DirectoryListingDetector().evaluate(SignalBundle(
        target="http://127.0.0.1", signals={"directory_listing": True, "directory_listing_path": "/files/"}))
    assert len(fs) == 1 and fs[0].evidence["path"] == "/files/"


# ---- (2) nuclei (MOCKED output; see test_nuclei_live_* for the real binary) --
MOCK_JSONL = "\n".join(json.dumps(x) for x in [
    {"template-id": "prometheus-metrics", "matcher-name": "", "type": "http",
     "matched-at": "http://127.0.0.1:3000/metrics",
     "info": {"name": "Prometheus Metrics - Detect", "severity": "medium",
              "tags": ["exposure", "prometheus", "misconfig"],
              "classification": {"cwe-id": ["CWE-200"]}},
     "extracted-results": ["token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"]},
    {"template-id": "evil-sqli", "type": "http", "matched-at": "http://127.0.0.1:3000/x",
     "info": {"name": "SQLi", "severity": "critical", "tags": "sqli,intrusive"}},
]) + "\nnot json\n"


def test_nuclei_command_excludes_intrusive():
    cmd = nuclei.build_command("nuclei", "http://127.0.0.1:3000")
    et = cmd[cmd.index("-etags") + 1].split(",")
    for t in ("intrusive", "fuzz", "dos", "rce", "sqli", "xss", "cve", "default-login"):
        assert t in et
    assert "-no-interactsh" in cmd


def test_nuclei_mapping_mock():
    fs = nuclei.map_results("http://127.0.0.1:3000", nuclei.parse_jsonl(MOCK_JSONL))
    assert len(fs) == 1  # intrusive-tagged result dropped
    f = fs[0]
    assert f.title == "[nuclei] Prometheus Metrics - Detect"
    assert f.severity == Severity.MEDIUM
    assert f.evidence["endpoint"] == "http://127.0.0.1:3000/metrics"
    assert "CWE-200" in f.references
    assert "ghp_" not in json.dumps(f.to_dict())  # secret redacted
    det = NucleiFindingDetector().evaluate(SignalBundle(
        target="http://127.0.0.1:3000", signals={"nuclei_results": nuclei.parse_jsonl(MOCK_JSONL)}))
    assert len(det) == 1


def _scope():
    return Scope(project="t", allowlist=["127.0.0.1"], denylist=[],
                 pending_authorization=["kuaishou.com"], severity_gate=Severity.LOW)


@pytest.mark.parametrize("tgt", ["https://kuaishou.com", "https://www.kuaishou.com", "https://example.org"])
def test_nuclei_scope_gate_blocks(tgt, monkeypatch):
    called = []
    monkeypatch.setattr(nuclei.asyncio, "create_subprocess_exec",
                        lambda *a, **k: called.append(a))
    p = nuclei.NucleiProbe(_scope(), binary="/bin/false", allow_non_loopback=True)
    r = asyncio.run(p.observe(parse_target(tgt)))
    assert not r.ok and "scope gate refused" in r.error and not called


def test_nuclei_probe_with_mocked_binary(tmp_path):
    fake = tmp_path / "nuclei"
    data = tmp_path / "out.jsonl"
    data.write_text(MOCK_JSONL)
    fake.write_text(f"#!/bin/sh\ncat {data}\n")
    fake.chmod(0o755)
    r = asyncio.run(nuclei.NucleiProbe(_scope(), binary=str(fake)).observe(parse_target("http://127.0.0.1:3000")))
    assert r.ok and len(r.signals["nuclei_results"]) == 1


# ---- report disclaimer -----------------------------------------------------
def test_report_has_coverage_disclaimer():
    rep = build_report(_scope(), [])
    assert "passive-only, limited coverage" in rep.to_text()
    assert rep.to_dict()["coverage_disclaimer"] == COVERAGE_DISCLAIMER


def test_stack_trace_html_escaped_express():
    body = '<ul id="stacktrace"><li> &nbsp; &nbsp;at /app/build/routes/angular.js:18:18</li></ul>'
    assert has_stack_trace(body)


def test_listing_relative_hrefs_resolved():
    from critforge.http_probe import _listing_entries
    body = '<a href=".">.</a><a href="ftp">ftp</a><a href="ftp/a.bak">a</a><a href="ftp/quarantine">q</a>'
    assert _listing_entries("/ftp", body) == ["/ftp/a.bak", "/ftp/quarantine"]


def test_nuclei_drops_other_port_results():
    r = {"matched-at": "http://127.0.0.1:6080/vnc.html", "info": {"tags": ["panel"]}}
    assert not nuclei.same_origin(r, "http://127.0.0.1:3000")
    assert nuclei.same_origin({"matched-at": "http://127.0.0.1:3000/metrics"}, "http://127.0.0.1:3000")


class _CatchAll(BaseHTTPRequestHandler):
    """Spring-style app: any unknown path under /app/ redirects to a 200 login page."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = (b"<html>login</html>" if self.path != "/" else b"<html>root 404 page here</html>")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_backup_variant_no_fp_on_catch_all_routes():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _CatchAll)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        r = _observe(url, ("/", "/app/index.html"))
        assert not r.signals.get("backup_files")
    finally:
        srv.shutdown()
