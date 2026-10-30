# CritForge

CritForge is a **black-box, AI-driven autonomous penetration-test orchestration
platform**. It is **AUTHORIZED-USE-ONLY**: it must only ever be pointed at
systems the operator is explicitly permitted to test, as enforced by the
Scope & Policy authorization gate.

> ✅ **Python backend (M0–M7) is the active implementation** under `python/`.
> Go tree at repo root remains the original M0 skeleton (left intact).
>
> ⚠️ **Methodology only.** No exploit payloads, PoCs, or real network-attack
> code. Probes are safe no-op/mock; detectors classify signals; every target
> must pass the M1 scope gate first.
>
> Legacy note on the Go tree:
> ⚠️ **M0 status — skeleton & compliance shell only.**
> This milestone contains **no** scanning, enumeration, network, or exploit
> capability. The offensive modules are documentation stubs that only fix module
> boundaries. The only runnable command is `critforge health`.

## Module map

| Module | Package | Role |
|---|---|---|
| Scope & Policy | `internal/scopepolicy` | First-class authorization gate (allowlist/denylist, severity gate, model routing). Refuses empty scope. |
| CritHarness | `internal/critharness` | Agent runtime (agentcore loop, tool dispatch, permission checkpoints, memory, transcript). |
| Attack Surface Discovery | `internal/attacksurface` | External asset collection (subdomains, ports, fingerprints, routes, JS routes). *stub* |
| Planner | `internal/planner` | Directs worker agents; phase/tool selection. *stub* |
| Asset Graph | `internal/assetgraph` | Hosts/services/weaknesses graph. *stub* |
| Attack Graph | `internal/attackgraph` | Explored paths & candidate chains. *stub* |
| Vuln ID & Severity Gate | `internal/vulnid` | Finding ID; filters to High/Critical+. *stub* |
| Attack Chain Synthesis | `internal/attackchain` | Combines low/med/high into attack chains. *stub* |
| Finding Store | `internal/findingstore` | Finding/evidence persistence. *stub* |
| MCP Gateway | `internal/mcpgateway` | Unified function interface / MCP tool registry. *stub* |
| Secrets Vault | `internal/secretsvault` | Runtime-managed API keys (auth-once, auto-rotate). *stub* |
| Verifier | `internal/verifier` | Independent validation to cut false positives. *stub* |
| Deep-Dive Trigger | `internal/deepdive` | Black-box decision on source-code deep-dive. *stub* |
| Reporter | `internal/reporter` | Reviewable reports & transcripts. *stub* |
| Console | `console/` | Next.js operator console (placeholder). |

Plus the M0 spine: `internal/audit` (append-only audit log) and
`cmd/critforge` (control binary).

## Quick start (Python — recommended)

```sh
cd python
../.venv/bin/pip install -e ".[dev]"   # or: python3 -m venv ../.venv && ...
cp ../scope.example.yaml scope.yaml    # edit with YOUR authorized targets
../.venv/bin/python -m critforge.cli health --scope scope.yaml
../.venv/bin/python -m pytest -q
```

See `python/README.md` for M2–M7 commands (`run`, `keys`, FastAPI).

## Quick start (Go M0 skeleton)

```sh
make build
cp scope.example.yaml scope.yaml   # then edit with YOUR authorized targets
make health                        # validates spine + writes one audit entry
```

`make health` uses `scope.example.yaml`. With an empty allowlist the authorization
gate refuses to run.

## Build order

M0 skeleton → M1 scope/asset-graph core → M2 attack-surface discovery →
M3 vuln ID + severity gate → M4 attack-chain synthesis → M5 verifier →
M6 reporter/console → M7 hardening. See `ARCHITECTURE.md` and the design doc.

## Docs
- `ARCHITECTURE.md` — module list & design-doc backlink
- `SECURITY.md` — authorized-use, HITL gating, runtime secrets
