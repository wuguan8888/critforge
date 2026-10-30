"""OOB interface + HITL gate stub tests."""
from __future__ import annotations

import pytest

from critforge.finding import Confidence
from critforge.hitl import ApprovalStatus, HITLGate
from critforge.oob import NoopOOBChannel, OOBEvent
from critforge.scope import Severity


@pytest.mark.asyncio
async def test_noop_oob_register_poll_inject():
    ch = NoopOOBChannel()
    cid = await ch.register(label="test")
    assert cid.startswith("oob-")
    assert await ch.poll(cid) == []
    ch.inject_for_tests(cid, OOBEvent(correlation_id=cid, source="test"))
    ev = await ch.poll(cid)
    assert len(ev) == 1
    assert ev[0].correlation_id == cid
    await ch.close()


def test_hitl_pending_and_decide():
    gate = HITLGate()
    req = gate.request("escalate_finding", "policy", finding_id="f1")
    assert req.status == ApprovalStatus.PENDING
    assert len(gate.pending()) == 1
    decided = gate.decide(req.id, approved=True, decided_by="ernest")
    assert decided.status == ApprovalStatus.APPROVED
    assert gate.pending() == []


def test_hitl_policy_critical_confirmed():
    gate = HITLGate()
    req = gate.maybe_request_for_finding(
        "fid", Severity.CRITICAL, Confidence.CONFIRMED, title="x"
    )
    assert req is not None
    assert req.action == "escalate_finding"
    assert gate.maybe_request_for_finding("fid2", Severity.LOW, Confidence.LOW) is None
