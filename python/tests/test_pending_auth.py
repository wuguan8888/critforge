import pytest
from critforge.audit import JSONLSink
from critforge.engine import ScannerEngine
from critforge.gate import evaluate, target_status
from critforge.probes import NoOpProbe
from critforge.scope import Scope


def _scope():
    return Scope(project="t", allowlist=["127.0.0.1", "kuaishou.com"],
                 pending_authorization=["kuaishou.com"], authorized_by="tester")


@pytest.mark.parametrize("t", ["kuaishou.com", "https://www.kuaishou.com/x", "api.kuaishou.com:443"])
def test_kuaishou_pending_not_scannable(t):
    s = _scope()
    assert target_status(s, t) == "pending_authorization"
    assert not evaluate(s, t).allowed


def test_authorized_still_allowed():
    assert target_status(_scope(), "http://127.0.0.1:8765/") == "authorized"


async def test_engine_refuses_pending(tmp_path):
    eng = ScannerEngine(_scope(), [NoOpProbe()], sink=JSONLSink(str(tmp_path / "a.jsonl")))
    res = await eng.run(["https://kuaishou.com"])
    assert res.authorized == [] and res.results == []
    assert "pending authorization" in res.rejected[0][1]
