# CritForge — HITL-Approved Active Testing Path (DESIGN ONLY)

> Status: **design document, not implemented.** No active scanner is wired or run.
> CritForge's default mode stays **passive-only, black-box, no exploit payloads**.

## 1. Goal
Close the coverage gap left by passive detection (Injection, XSS, auth/session,
access-control logic, XXE, deserialization, SSRF, business logic) by handing
off — only after explicit human approval — to an **authorized external active
scanner** (reference: OWASP ZAP active scan). CritForge itself never crafts
payloads; `craft_offensive_payload()` stubs stay `NotImplementedError`.

## 2. Preconditions (all mandatory)
1. Target gate status == `authorized` (M1). `denied`, `out_of_scope`, and
   `pending_authorization` (e.g. `kuaishou.com`) are hard-refused; there is
   no code path that promotes a pending target.
2. Signed authorization artifact referenced in scope
   (`authorized_by`, `authorization_reference`) **and** a separate
   `active_testing: {approved: false}` block that defaults to false.
3. A passive run for the same target completed (provides the URL/route
   inventory the active scan is restricted to).
4. Target environment classified (`lab` / `staging` / `production`).
   Production requires a second approver and a maintenance window.

## 3. Approval flow (HITL)
```
passive run ─► ActiveTestRequest (draft) ─► approver #1 (scope owner)
             ─► [prod only] approver #2 (system owner) ─► signed token (TTL ≤ 24h)
             ─► dispatcher hands job to ZAP ─► results ─► merge ─► report
```
- Request contents: target, route allowlist, scan policy name, rate limits,
  window start/end, kill-switch contact, expected impact.
- Approval stored via existing `hitl.py` queue + `audit.py` (append-only JSONL):
  who, when, what diff of scope, token hash (never the token itself).
- Token bound to (target, policy hash, window); any change ⇒ re-approval.
- No auto-approve, no CLI `--yes` bypass, no LLM approval.
- Kill switch: approver or operator can revoke; dispatcher polls revocation
  every ≤10 s and calls ZAP `ascan/action/stop`.

## 4. Scope constraints for the handoff
- ZAP context = only gate-authorized host(s); `includeInContext` regexes
  generated from the passive route inventory; `excludeFromContext` for
  logout, delete, payment, password-reset, admin-mutation paths.
- Denylist / pending_authorization re-evaluated by the dispatcher immediately
  before start and on every redirect host seen in ZAP's sites tree; any
  out-of-scope host ⇒ abort.
- Scan policy: start from ZAP "Default Policy", disable DoS, fuzzers with
  destructive intent, and any rule flagged `intrusive` for production.
- Test accounts only (dedicated low-privilege creds from the vault, never
  echoed); no real-user data writes.

## 5. Rate limits & safety rails
| Env | req/s | concurrent threads | max duration | window |
|---|---|---|---|---|
| lab | 50 | 5 | 2 h | any |
| staging | 10 | 2 | 4 h | approved window |
| production | 2 | 1 | 2 h | maintenance window only |
- Auto-abort on: 5xx rate > 10 % over 60 s, p95 latency ×3 baseline, or any
  out-of-scope request.

## 6. Result merging
- Import ZAP JSON alerts → `Finding` via a mapper analogous to
  `critforge/nuclei.py::map_results` (title, severity riskcode→Severity,
  confidence→Confidence, endpoint=`uri`, evidence = alert id/param name/CWE;
  request/response bodies and any secrets **redacted**, not stored raw).
- Dedup key: `(category, endpoint-path, CWE)`; passive + active hits on the
  same key merge into one Finding with `sources=[passive, nuclei, zap]` and
  confidence raised one step (corroboration).
- Active findings go through the existing three-stage verifier and the
  severity × confidence dual-axis gate; `evidence.source = "zap_active"`.
- Report shows a separate "Active (HITL approved, token #hash)" section and
  keeps the coverage disclaimer, updated to state what was actively tested.

## 7. Out of scope
CI/CD integration, white-box/source analysis, autonomous exploitation,
post-exploitation, credential attacks.
