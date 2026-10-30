"""M1 scope validation gate.

The authorization gate that sits in FRONT of any future scanning. Every target
must pass here before CritForge would ever act on it. There is no scanner yet;
this is purely a parse + authorize decision.

Matching rules (host-based, case-insensitive):
  - Denylist takes precedence over allowlist (deny wins).
  - Exact host match.
  - Subdomain / wildcard match: an allowlist/denylist entry `example.com` or
    `*.example.com` matches `sub.example.com`. A bare `example.com` entry also
    matches the apex `example.com`. IPs match only exactly.
Every decision — allow or deny, including parse failures — is audited.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import audit
from .scope import Scope
from .target import Target, TargetParseError, parse


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    target: Optional[Target] = None
    matched_rule: Optional[str] = None


def _normalize_rule(rule: str) -> str:
    r = (rule or "").strip().lower().rstrip(".")
    if r.startswith("*."):
        r = r[2:]
    return r


def _host_matches(host: str, rule: str) -> bool:
    """True if host equals rule or is a subdomain of rule (wildcard-aware)."""
    r = _normalize_rule(rule)
    if not r:
        return False
    if host == r:
        return True
    # subdomain match only for name-based rules (a dotted suffix boundary)
    return host.endswith("." + r)


def _matches_any(host: str, is_ip: bool, rules: list[str]) -> Optional[str]:
    for rule in rules:
        rr = (rule or "").strip().lower().rstrip(".")
        if not rr:
            continue
        if is_ip:
            # IPs only match exactly (no subdomain semantics).
            if host == rr:
                return rule
        else:
            if _host_matches(host, rule):
                return rule
    return None


def evaluate(scope: Scope, raw_target: str) -> Decision:
    """Parse raw_target and decide allow/deny against scope. Denylist wins."""
    try:
        target = parse(raw_target)
    except TargetParseError as e:
        # Fail closed: malformed input is denied.
        return Decision(allowed=False, reason=f"malformed target: {e}", target=None)

    deny = _matches_any(target.host, target.is_ip, scope.denylist)
    if deny is not None:
        return Decision(
            allowed=False,
            reason=f"denylisted by rule {deny!r} (denylist precedence)",
            target=target,
            matched_rule=deny,
        )

    pending = _matches_any(
        target.host, target.is_ip, getattr(scope, "pending_authorization", []) or []
    )
    if pending is not None:
        return Decision(
            allowed=False,
            reason=(
                f"pending authorization by rule {pending!r}: recorded as target, "
                "not active until signed authorization is provided (fail-closed)"
            ),
            target=target,
            matched_rule=pending,
        )

    allow = _matches_any(target.host, target.is_ip, scope.allowlist)
    if allow is not None:
        return Decision(
            allowed=True,
            reason=f"in scope via allowlist rule {allow!r}",
            target=target,
            matched_rule=allow,
        )

    return Decision(
        allowed=False,
        reason="not in allowlist (out of scope)",
        target=target,
    )


def authorize(
    scope: Scope,
    raw_target: str,
    *,
    actor: str = "system",
    sink: Optional[audit.Sink] = None,
) -> Decision:
    """Evaluate a target and AUDIT the decision. This is the public gate."""
    if sink is None:
        sink = audit.default_sink()
    decision = evaluate(scope, raw_target)
    action = "scope.authorize.allow" if decision.allowed else "scope.authorize.deny"
    host = decision.target.host if decision.target else raw_target
    audit.record(
        sink,
        actor=actor,
        action=action,
        scope=scope.project,
        detail=f"target={raw_target!r} host={host!r} reason={decision.reason}",
    )
    return decision


def target_status(scope: Scope, raw_target: str) -> str:
    """'denied' | 'pending_authorization' | 'authorized' | 'out_of_scope' | 'malformed'."""
    d = evaluate(scope, raw_target)
    if d.allowed:
        return "authorized"
    if d.target is None:
        return "malformed"
    if d.reason.startswith("pending authorization"):
        return "pending_authorization"
    if d.reason.startswith("denylisted"):
        return "denied"
    return "out_of_scope"
