"""CritForge — authorized-use-only, black-box pentest orchestration platform.

Python backend (asyncio + FastAPI). Modules:
  - M0: Scope & Policy authorization spine + append-only audit (+ confidence gate)
  - M1: Target parsing + scope validation gate
  - M2: Async scanner engine (rate limits, host-error cache, pluggable probes)
  - M3: Black-box detector framework (plugin matchers / evidence hooks)
  - M4: Structured findings + dual-axis (severity × confidence) reporting
  - M5: Key-management runtime (config store + pending OAuth grants)
  - M6: Hardening (retries, timeouts, fail-closed helpers)
  - M7: CLI / health / docs polish
  - verify / attackchain / oob / hitl / stages: fusion-plan upgrades

CRITICAL: methodology and orchestration ONLY. No exploit payloads, no PoCs,
no real network-attack or enumeration code. Probes shipped here are safe
no-op / mock. Detectors classify signals; offensive payload methods raise
NotImplementedError by design.
"""

__version__ = "0.3.0"
