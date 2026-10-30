# Contributing to CritForge

See `ARCHITECTURE.md` for the module map and the design document (the
"CritForge 最终架构设计" canvas) for the authoritative design.

## Ground rules
- **Authorized-use-only.** Never add code that acts on a target outside the
  Scope & Policy allowlist, and never bypass the authorization gate.
- **No offensive code in skeleton milestones.** Keep stubs as stubs until their
  milestone.
- Every change must `make build`, `make test`, and `make lint` cleanly.
- Control-plane actions must emit an append-only audit entry.
- Never commit secrets; the Secrets Vault manages them at runtime.

## Dev loop
```sh
make build && make test && make lint
```
