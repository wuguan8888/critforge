"""CLI smoke tests for M7 polish."""
from __future__ import annotations

import os
from pathlib import Path

from critforge.cli import main

SCOPE = os.path.join(os.path.dirname(__file__), "scope.test.yaml")


def test_cli_health(tmp_path, monkeypatch):
    monkeypatch.setenv("CRITFORGE_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    assert main(["health", "--scope", SCOPE]) == 0


def test_cli_check_allow_deny(tmp_path, monkeypatch):
    monkeypatch.setenv("CRITFORGE_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    assert main(["check", "--scope", SCOPE, "example.com"]) == 0
    assert main(["check", "--scope", SCOPE, "evil.example.invalid"]) == 3


def test_cli_run_and_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("CRITFORGE_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    secrets = str(tmp_path / "secrets.yaml")
    assert main(["keys", "--secrets", secrets, "--bootstrap"]) == 0
    out = Path(tmp_path / "report.json")
    rc = main(
        [
            "run",
            "--scope",
            SCOPE,
            "--secrets",
            secrets,
            "--format",
            "json",
            "--output",
            str(out),
            "--mock-signals",
            '{"misconfig_indicator":"x","misconfig_severity":"High"}',
            "example.com",
        ]
    )
    assert rc == 0
    assert out.exists()
