# CritForge Security & Use Policy

## Authorized use only
CritForge may only be operated against systems for which the operator holds
explicit, documented authorization. The **Scope & Policy** module is a hard,
fail-closed gate: an empty allowlist (or a missing `authorized_by`) causes
CritForge to refuse to run. Targets not on the allowlist — or present on the
denylist — are out of scope by construction.

## M0 contains no offensive capability
This milestone is a skeleton and compliance shell. It performs no scanning,
enumeration, network interaction, or exploitation. Those modules are stubs.

## HITL gating
High-risk actions require human-in-the-loop approval (permission checkpoints in
CritHarness). No automated action bypasses the approval gate; the design keeps
the platform semi-autonomous by default.

## Audit
All control-plane actions are recorded to an **append-only** audit log
(JSONL in M0, PostgreSQL `audit_log` with an immutability trigger in M1+).
Entries are never updated or deleted.

## Secrets are runtime-managed
API keys and platform credentials are handled by the Secrets Vault at runtime
(authorized once, then auto-applied and rotated). Secrets are **never** committed
to the repo, config, or this document, and the vault's operation is intentionally
out of the architecture document surface.

## Reporting
Report security concerns about CritForge itself to the maintainer named in the
engagement authorization.
