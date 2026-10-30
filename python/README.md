# CritForge — Python backend (asyncio + FastAPI)

**Authorized-use-only, black-box pentest orchestration platform.**

Python implementation covering **M0–M7**:

| Milestone | What |
|-----------|------|
| M0 | Scope & Policy spine + dual-axis gates (severity × confidence) + audit |
| M1 | Target parsing (URL/host/IPv4/IPv6) + scope validation gate |
| M2 | Async scanner engine: rate limits, host-error cache, pluggable probes |
| M3 | Plugin detectors (matchers / evidence hooks; injection/XSS/auth/misconfig) |
| M4 | Findings + dual-axis reporting (severity × confidence) |
| M5 | Key-management runtime (YAML store, OAuth stubs, pending grants) |
| M6 | Hardening helpers (retries, timeouts, fail-closed) |
| M7 | CLI / FastAPI polish + staged waterfall (verify / chain / HITL / OOB stubs) |

> **Methodology only.** CritForge ships **no** exploit payloads, PoCs, or
> real network-attack / enumeration code. Probes are safe no-op / mock.
> Detector `craft_offensive_payload()` methods raise `NotImplementedError`
> by design. Every target must pass the M1 gate before any probe runs.

## Layout
```
python/
  pyproject.toml
  critforge/
    scope.py audit.py          # M0 (+ confidence_gate)
    target.py gate.py          # M1
    probes.py engine.py        # M2 (+ host-error cache)
    detectors/                 # M3 plugin matchers / evidence hooks
    finding.py reporting.py    # M4 dual-axis
    verify.py                  # three-stage verifier
    attackchain.py             # attack-chain synthesis
    oob.py hitl.py             # OOB interface + HITL stub
    stages.py pipeline.py      # composable waterfall
    secrets.py                 # M5
    hardening.py llm.py        # M6 + DeepSeek client
    cli.py app.py              # M7
  tests/
```

## Quickstart
```bash
# from python/
python3 -m venv ../.venv
../.venv/bin/pip install -e ".[dev]"
cp ../scope.example.yaml scope.yaml   # edit for YOUR authorized engagement

../.venv/bin/python -m critforge.cli health --scope scope.yaml
../.venv/bin/python -m pytest -q
../.venv/bin/python -m critforge.cli check --scope scope.yaml https://example.com

# dry-run pipeline with mock signals (still no network attacks):
../.venv/bin/python -m critforge.cli run --scope scope.yaml \
  --mock-signals '{"misconfig_indicator":"banner","misconfig_severity":"High"}' \
  https://example.com

# bootstrap key slots (records pending OAuth grants; does not block):
../.venv/bin/python -m critforge.cli keys --secrets secrets.yaml --bootstrap

# FastAPI:
../.venv/bin/uvicorn critforge.app:app --app-dir . --port 8000
# GET /health  POST /authorize  POST /pipeline/run  GET /keys/pending
```

## AI model provider
Default LLM provider is **DeepSeek** (OpenAI-compatible):
- `base_url`: `https://api.deepseek.com/v1`
- models: `deepseek-reasoner` (planner), `deepseek-chat` (worker / verifier)
- API key: set `DEEPSEEK_API_KEY` in `.env` (referenced as `env:DEEPSEEK_API_KEY` in `secrets.yaml`)

OpenAI / Anthropic slots have been removed.

## Fail-closed posture
- Empty allowlist or missing `authorized_by` → refuse to run
- Out-of-scope / denylisted / malformed targets → rejected before probes
- Probe failures are isolated; engine continues
- Offensive payload hooks are stubs that raise

## Go skeleton
The original M0 Go tree at the repo root is left intact. Nothing deleted.

## Local range test

Docker was unavailable on the build box; a stdlib vulnerable lab binds to `127.0.0.1:8765` only.
See `/workspace/critforge/RANGE_TEST_REPORT.md` and `lab/run_range_test.py`.
Scope file: `scope.lab.yaml` (loopback allowlist, fail-closed).

