"""AI brain wired into the main pipeline — mocked LLM, fully offline."""
import asyncio
import json

from critforge.ai_detect import AIBrain, observations_from_run, scrub
from critforge.engine import ProbeResult, RunResult
from critforge.finding import Confidence, Finding, FindingCategory
from critforge.scope import Severity


def _resp(obj, model="deepseek-chat"):
    return {"model": model, "choices": [{"message": {"content": json.dumps(obj)}}]}


def _f(title, ev, sev=Severity.MEDIUM):
    return Finding(category=FindingCategory.MISCONFIG, severity=sev, title=title,
                   target="http://127.0.0.1:3000/", evidence=ev, detector="t")


def test_scrub_redacts_secrets():
    s = scrub({"body": "api_key=abcd1234efgh token: sk-AAAAAAAAAAAAAAAA", "password": "x"})
    blob = json.dumps(s)
    assert "abcd1234efgh" not in blob and "AAAAAAAAAAAA" not in blob and '"x"' not in blob


def test_offline_brain_is_noop():
    b = AIBrain(enabled=False)
    fs = [_f("a", {"path": "/.env"})]
    out, stats = asyncio.run(b.judge(fs, []))
    assert out == fs and stats["mode"] == "offline"


def test_judge_confirms_rejects_and_grounds():
    good = _f("env exposed", {"path": "/.env", "status": 200})
    bad = _f("soft404", {"path": "/backup.zip", "status": 200})

    def chat(messages, role):
        payload = json.loads(messages[1]["content"])
        ids = {c["title"]: c["id"] for c in payload["candidates"]}
        return _resp({
            "verdicts": [
                {"id": ids["env exposed"], "verdict": "confirm", "severity": "High",
                 "confidence": "high", "rationale": "/.env returned 200", "evidence_cited": ["/.env"]},
                {"id": ids["soft404"], "verdict": "reject", "confidence": "low",
                 "rationale": "SPA fallback", "evidence_cited": ["/backup.zip"]},
                {"id": "deadbeef", "verdict": "confirm", "severity": "Critical"},  # unknown id
            ],
            "new_findings": [
                {"path": "/actuator/env", "title": "Actuator env open", "severity": "High",
                 "confidence": "confirmed", "rationale": "200 JSON", "evidence_cited": ["/actuator/env"]},
                {"path": "/invented", "title": "Made up", "severity": "Critical"},
            ],
        })

    obs = [{"target": "http://127.0.0.1:8080/", "path": "/actuator/env", "status": 200, "cls": "real"}]
    out, stats = asyncio.run(AIBrain(chat_fn=chat).judge([good, bad], obs))
    assert good.severity == Severity.HIGH and good.confidence == Confidence.HIGH
    assert good.evidence["ai_judgment"]["grounded"] is True
    assert bad.confidence == Confidence.LOW
    promoted = [f for f in out if f.detector == "ai_detect"]
    assert len(promoted) == 1 and promoted[0].confidence == Confidence.HIGH  # capped
    assert stats["ungrounded_dropped"] == 1 and stats["rejected"] == 1
    assert all(f.evidence for f in out)


def test_ungrounded_citation_downgrades():
    f = _f("x", {"path": "/a"})

    def chat(messages, role):
        cid = json.loads(messages[1]["content"])["candidates"][0]["id"]
        return _resp({"verdicts": [{"id": cid, "verdict": "confirm", "confidence": "confirmed",
                                     "evidence_cited": ["something not in evidence"]}]})

    asyncio.run(AIBrain(chat_fn=chat).judge([f], []))
    assert f.confidence == Confidence.MEDIUM


def test_plan_recon_filters_unsafe_paths():
    def chat(messages, role):
        return _resp({"priorities": [{"path": "/api", "reason": "api"}, {"path": "/nope"}],
                      "suggested_paths": [
                          {"path": "/actuator/health"}, {"path": "http://evil.example/x"},
                          {"path": "/../etc/passwd"}, {"path": "/a?q=<script>"},
                          {"path": "//evil"}, {"path": "/api"}]})

    plan = asyncio.run(AIBrain(chat_fn=chat).plan_recon({"observed_paths": ["/api"]}))
    assert [s["path"] for s in plan["suggested_paths"]] == ["/actuator/health"]
    assert [p["path"] for p in plan["priorities"]] == ["/api"]


def test_llm_failure_falls_back():
    def chat(messages, role):
        raise RuntimeError("boom")

    b = AIBrain(chat_fn=chat)
    f = _f("x", {"path": "/a"})
    out, stats = asyncio.run(b.judge([f], []))
    assert out == [f] and stats["mode"] == "offline" and b.log[0]["ok"] is False


def test_observations_from_run():
    run = RunResult(results=[ProbeResult(probe="http_observe", target="t", ok=True, signals={
        "pages": [{"path": "/", "status": 200}],
        "discovery": {"pages": [{"path": "/ftp", "status": 200, "cls": "real"}]}})])
    paths = {o["path"] for o in observations_from_run(run)}
    assert paths == {"/", "/ftp"}


def test_pipeline_runs_ai_stages_with_mock(tmp_path):
    from critforge.audit import JSONLSink
    from critforge.pipeline import run_pipeline
    from critforge.probes import MockSignalProbe, NoOpProbe
    from critforge.scope import load

    calls = []

    def chat(messages, role):
        calls.append(role)
        p = json.loads(messages[1]["content"])
        if "candidates" in p:
            return _resp({"verdicts": [{"id": c["id"], "verdict": "confirm", "severity": "High",
                                        "confidence": "high", "rationale": "evidence ok",
                                        "evidence_cited": [c["detector"]]} for c in p["candidates"]]})
        return _resp({"narrative": "n", "chains": []})

    import os
    scope = load(os.path.join(os.path.dirname(__file__), "scope.test.yaml"))
    tgt = scope.targets[0] if hasattr(scope, "targets") else None
    res = asyncio.run(run_pipeline(
        scope, ["http://127.0.0.1:9/"] if tgt is None else ["http://127.0.0.1:9/"],
        probes=[NoOpProbe(), MockSignalProbe({"missing_security_headers": ["x-frame-options"],
                                              "server_banner": "nginx/1.0"})],
        sink=JSONLSink(str(tmp_path / "a.jsonl")), ai=AIBrain(chat_fn=chat)))
    assert res.meta["ai"]["enabled"] is True
    assert "deepseek-chat" in res.meta["ai"]["models"]
    assert "ai_judge" in res.meta["stages"]
    assert "AI-driven" in res.report.analysis_engine
    assert "Coverage limitation" in res.report.to_text()


def test_cited_in_key_value_form():
    from critforge.ai_detect import _cited_in
    ev = json.dumps({"path": "/WebGoat/actuator/env", "status": 200})
    assert _cited_in("path: /WebGoat/actuator/env", ev)
    assert not _cited_in("path: /other", ev)
