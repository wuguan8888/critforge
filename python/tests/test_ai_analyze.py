from critforge.ai_analyze import _offline_analyze, analyze_findings


def test_offline_analyze_ranks():
    findings = [
        {"kind": "secret", "severity_hint": "High", "secret_type": "github_pat", "repo": "a/b", "path": ".env"},
        {"kind": "api_endpoint", "severity_hint": "Info", "repo": "a/b", "path": "x.py"},
    ]
    res = _offline_analyze(findings)
    assert res.mode == "offline_fallback"
    assert res.prioritized
    assert res.prioritized[0]["severity"] in ("High", "Critical")


def test_analyze_findings_without_key_falls_back(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    res = analyze_findings([{"kind": "config_file", "severity_hint": "Medium", "path": "settings.yaml"}])
    assert res.mode == "offline_fallback"
