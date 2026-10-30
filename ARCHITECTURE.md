# CritForge Architecture (M0)

This file points back to the **CritForge design document** (Cursor canvas, the
"CritForge 最终架构设计" page) which is the source of truth. M0 implements only
the skeleton and the authorization/audit spine; every other module is a stub
whose only job is to fix the boundary named in the design doc.

## Module boundaries (M0 stubs unless noted)

- **Scope & Policy** (`internal/scopepolicy`) — *implemented in M0*: the
  first-class authorization gate. Loads `scope.yaml` (allowlist, denylist,
  severity gate, model routing), defaults the gate to `High`, and refuses to run
  when the allowlist is empty.
- **CritHarness** (`internal/critharness`) — agent runtime harness: agentcore
  streaming loop, tool dispatch, permission checkpoints, memory, transcript.
- **Attack Surface Discovery** (`internal/attacksurface`) — external asset
  collection: subdomain enum, port scan, fingerprinting, dir/route brute, JS
  route extraction. No functional code in M0.
- **Planner** (`internal/planner`) — directs workers; selects phase/tools.
- **Asset Graph** (`internal/assetgraph`) / **Attack Graph** (`internal/attackgraph`)
  — the two shared graphs that carry global state.
- **Vuln ID & Severity Gate** (`internal/vulnid`) — filters to High/Critical+.
- **Attack Chain Synthesis** (`internal/attackchain`) — combines low/med/high
  points into attack chains (attack path synthesis).
- **Finding Store** (`internal/findingstore`), **MCP Gateway**
  (`internal/mcpgateway`), **Secrets Vault** (`internal/secretsvault`),
  **Verifier** (`internal/verifier`), **Deep-Dive Trigger** (`internal/deepdive`),
  **Reporter** (`internal/reporter`) — as named in the design doc.
- **Console** (`console/`) — Next.js operator console placeholder.

## M0 spine
- `internal/audit` — append-only audit log (JSONL in M0; PostgreSQL via the
  `audit_log` table + immutability trigger in M1+).
- `cmd/critforge` — control binary; `health` validates the spine.
- `db/migrations` — `project`, `scope`, `audit_log` (append-only).

## Milestones
M0 skeleton → M1 scope/graph core → M2 discovery → M3 vuln+gate →
M4 chain synthesis → M5 verifier → M6 reporter/console → M7 hardening.

## Stack decision (M0)
Go chosen for the harness/API per the design default (Go vs Python still pending
Ernest's final confirmation). The skeleton is deliberately thin so a backend
swap stays cheap. Next.js console is a placeholder; PostgreSQL schema is defined
but DB wiring is deferred to M1 (M0 audit uses JSONL).
