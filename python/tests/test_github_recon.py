from critforge.github_recon import _redact, _scan_text


def test_redact_does_not_echo_secret():
    s = "ghp_" + ("A" * 36)
    out = _redact(s)
    assert "AAAA" not in out
    assert "REDACTED" in out


def test_scan_text_finds_and_redacts_pat():
    text = "token = ghp_" + ("B" * 36) + "\n"
    hits = _scan_text("owner/repo", "config.env", text)
    assert any(h.kind == "secret" and h.secret_type == "github_pat" for h in hits)
    for h in hits:
        assert "BBBBBB" not in h.evidence_redacted


def test_scan_config_path():
    hits = _scan_text("owner/repo", ".env.production", "FOO=bar\n")
    assert any(h.kind == "config_file" for h in hits)
