import os

import pytest
from fastapi.testclient import TestClient

HERE = os.path.dirname(os.path.abspath(__file__))
SCOPE = os.path.join(HERE, "scope.test.yaml")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CRITFORGE_SCOPE", SCOPE)
    monkeypatch.setenv("CRITFORGE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    from critforge.app import app

    return TestClient(app)


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health_fails_closed_on_empty_scope(tmp_path, monkeypatch):
    bad = tmp_path / "bad.yaml"
    bad.write_text("allowlist: []\nauthorized_by: 'x'\n")
    monkeypatch.setenv("CRITFORGE_SCOPE", str(bad))
    monkeypatch.setenv("CRITFORGE_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    from critforge.app import app

    r = TestClient(app, raise_server_exceptions=False).get("/health")
    assert r.status_code == 503


def test_authorize_allow(client):
    r = client.post("/authorize", json={"target": "example.com"})
    assert r.status_code == 200 and r.json()["allowed"] is True


def test_authorize_deny_denylist(client):
    r = client.post("/authorize", json={"target": "secret.lab.example.com"})
    assert r.status_code == 200 and r.json()["allowed"] is False


def test_pipeline_run_with_mock_signals(client):
    r = client.post(
        "/pipeline/run",
        json={
            "targets": ["example.com", "evil.out.of.scope"],
            "mock_signals": {"misconfig_indicator": "x", "misconfig_severity": "High"},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["report"]["findings"]
    assert any(x["target"] == "evil.out.of.scope" for x in body["rejected"])


def test_keys_pending_empty(client, tmp_path, monkeypatch):
    monkeypatch.setenv("CRITFORGE_SECRETS", str(tmp_path / "missing.yaml"))
    r = client.get("/keys/pending")
    assert r.status_code == 200
    assert r.json()["pending"] == []
