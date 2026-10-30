"""CritForge control CLI (Python).

Commands:
  health   — validate the authorization spine (fail-closed)
  check    — authorize a single target (M1 gate)
  run      — authorize → safe-probe → detect → report (M2–M4 pipeline)
  keys     — bootstrap / list key slots + pending OAuth authorizations (M5)
  report   — render the last pipeline JSON report (helper)

CritForge is AUTHORIZED-USE-ONLY. No exploit payloads, no real network
attacks. Probes shipped here are safe no-op / mock only.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import audit
from .engine import EngineConfig
from .pipeline import run_pipeline
from .probes import MockSignalProbe, NoOpProbe
from .scope import EmptyScopeError, ScopeError, load
from .secrets import SecretStore, bootstrap_keys, default_providers
from .gate import authorize, target_status


def _cmd_health(args) -> int:
    sink = audit.default_sink()
    try:
        scope = load(args.scope)
    except EmptyScopeError as e:
        audit.record(sink, args.actor, "health.scope_check_failed", args.scope, str(e))
        print("authorization gate: refusing to run with empty scope", file=sys.stderr)
        return 1
    except (ScopeError, OSError) as e:
        audit.record(sink, args.actor, "health.scope_check_failed", args.scope, str(e))
        print(f"health: {e}", file=sys.stderr)
        return 1
    audit.record(sink, args.actor, "health.ok", scope.project, "M7 spine healthy")
    print(
        f'OK  project="{scope.project}" targets={len(scope.allowlist)} '
        f"gate={scope.severity_gate.value} conf={scope.confidence_gate}"
    )
    return 0


def _cmd_check(args) -> int:
    sink = audit.default_sink()
    try:
        scope = load(args.scope)
    except (ScopeError, OSError) as e:
        audit.record(sink, args.actor, "check.scope_check_failed", args.scope, str(e))
        print(f"check: {e}", file=sys.stderr)
        return 1
    decision = authorize(scope, args.target, actor=args.actor, sink=sink)
    verdict = "ALLOW" if decision.allowed else "DENY"
    print(f"{verdict}  target={args.target!r}  reason={decision.reason}")
    return 0 if decision.allowed else 3


def _cmd_run(args) -> int:
    sink = audit.default_sink()
    try:
        scope = load(args.scope)
    except (ScopeError, OSError) as e:
        audit.record(sink, args.actor, "run.scope_check_failed", args.scope, str(e))
        print(f"run: {e}", file=sys.stderr)
        return 1

    probes = [NoOpProbe()]
    # Optional: inject mock signals for demo / dry-run (still no network).
    if args.mock_signals:
        try:
            signals = json.loads(args.mock_signals)
        except json.JSONDecodeError as e:
            print(f"run: invalid --mock-signals JSON: {e}", file=sys.stderr)
            return 1
        probes.append(MockSignalProbe(signals))

    store = None
    if args.secrets:
        store = SecretStore(args.secrets)

    cfg = EngineConfig(
        global_concurrency=args.concurrency,
        per_host_concurrency=args.per_host,
        probe_timeout=args.timeout,
        actor=args.actor,
    )
    result = asyncio.run(
        run_pipeline(
            scope,
            list(args.targets),
            probes=probes,
            engine_config=cfg,
            sink=sink,
            secret_store=store,
            ai_mode=getattr(args, "ai", None),
        )
    )
    assert result.report is not None
    if args.format == "json":
        print(result.report.to_json())
    else:
        print(result.report.to_text())
        if result.run.rejected:
            print("Rejected (out of scope):")
            for t, reason in result.run.rejected:
                print(f"  - {t}: {reason}")
        if result.pending_authorizations:
            print("\nPending platform authorizations (user action required):")
            for p in result.pending_authorizations:
                print(f"  - {p.platform}: {p.reason}")
                if p.auth_url_hint:
                    print(f"    hint: {p.auth_url_hint}")

    if args.output:
        Path(args.output).write_text(result.report.to_json(), encoding="utf-8")
        print(f"(wrote {args.output})", file=sys.stderr)
    return 0


def _cmd_status(args) -> int:
    try:
        scope = load(args.scope)
    except (ScopeError, OSError) as e:
        print(f"status: {e}", file=sys.stderr)
        return 1
    st = target_status(scope, args.target)
    print(f"{st}  target={args.target!r}")
    return 0 if st == "authorized" else 3


def _cmd_keys(args) -> int:
    store = SecretStore(args.secrets)
    if args.bootstrap:
        pending = asyncio.run(bootstrap_keys(store, default_providers()))
        print(f"bootstrapped; secrets={store.list_names()} pending={len(pending)}")
    else:
        pending = store.pending()
        print(f"secrets={store.list_names()}")
    if pending:
        print("Pending authorizations (user one-time OAuth grant required):")
        for p in pending:
            print(f"  - platform={p.platform}")
            print(f"    reason={p.reason}")
            if p.auth_url_hint:
                print(f"    auth_url_hint={p.auth_url_hint}")
    else:
        print("No pending authorizations.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="critforge",
        description=(
            "CritForge — authorized-use-only black-box pentest orchestration "
            "(methodology only; no exploit payloads)."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    h = sub.add_parser("health", help="Validate the spine and write one audit entry.")
    h.add_argument("--scope", default="scope.yaml", help="path to scope file")
    h.add_argument("--actor", default="system")
    h.set_defaults(func=_cmd_health)

    c = sub.add_parser("check", help="Authorize a target against scope (M1 gate).")
    c.add_argument("--scope", default="scope.yaml", help="path to scope file")
    c.add_argument("--actor", default="system")
    c.add_argument("target", help="URL / host / IP to authorize")
    c.set_defaults(func=_cmd_check)

    r = sub.add_parser(
        "run",
        help="Authorize → safe-probe → detect → report (no real attacks).",
    )
    r.add_argument("--scope", default="scope.yaml")
    r.add_argument("--actor", default="system")
    r.add_argument("--concurrency", type=int, default=8)
    r.add_argument("--per-host", type=int, default=2)
    r.add_argument("--timeout", type=float, default=10.0)
    r.add_argument("--format", choices=("text", "json"), default="text")
    r.add_argument("--output", default="", help="optional path to write JSON report")
    r.add_argument("--secrets", default="", help="optional secrets YAML path")
    r.add_argument(
        "--mock-signals",
        default="",
        help="JSON object of mock probe signals (for dry-run / tests)",
    )
    r.add_argument(
        "--ai",
        choices=("auto", "on", "off"),
        default=None,
        help="AI analysis brain (DeepSeek): auto=on when key present (default; env CRITFORGE_AI)",
    )
    r.add_argument("targets", nargs="+", help="one or more targets to authorize+probe")
    r.set_defaults(func=_cmd_run)

    s = sub.add_parser("status", help="Show target authorization state (incl. pending).")
    s.add_argument("--scope", default="scope.yaml")
    s.add_argument("target")
    s.set_defaults(func=_cmd_status)

    k = sub.add_parser("keys", help="List / bootstrap API key slots (M5).")
    k.add_argument(
        "--secrets",
        default="secrets.yaml",
        help="path to secrets YAML (never commit real values)",
    )
    k.add_argument(
        "--bootstrap",
        action="store_true",
        help="run default OAuth provider stubs; record pending grants",
    )
    k.set_defaults(func=_cmd_keys)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
