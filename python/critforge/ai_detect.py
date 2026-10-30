"""AI brain for the main scan pipeline (DeepSeek, OpenAI-compatible).

Division of labour ("brain" vs "hands/eyes"):
  * Deterministic probes (http_probe / discovery / nuclei) gather EVIDENCE with
    non-intrusive GET requests only. They are the only thing that touches targets.
  * The AI reasons over that evidence:
      1. plan_recon      — prioritise observed endpoints, suggest extra GET-only paths
      2. judge           — decide per observation whether it is a real finding,
                           assign category/severity/confidence + cite evidence;
                           may promote raw observations to findings (grounded only)
      3. narrate_chains  — synthesise attack-chain impact narratives
Guardrails (never relaxed by the AI):
  * no evidence -> no finding; AI cannot invent ids or paths that were not observed
  * suggested paths are relative, same-origin, pass discovery.is_safe_to_fetch,
    capped, and still run through the scope gate + loopback-only probe
  * secrets scrubbed before anything leaves the box; no payload generation asked
  * any LLM failure -> deterministic fallback, pipeline never crashes
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .finding import Confidence, Finding, FindingCategory
from .scope import Severity

_SECRET_RE = re.compile(
    r"(ghp_|gho_|github_pat_|sk-|AKIA|xox[baprs]-|eyJ)[A-Za-z0-9_\-\.]{8,}"
)
_KV_SECRET_RE = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)"
    r"[\"'\s:=]+)([^\s\"',;&<>]{4,})"
)
_MAX_SUGGEST = 15
_SEV = {s.value.lower(): s for s in Severity}
_CONF = {c.value: c for c in Confidence}
_CAT = {c.value: c for c in FindingCategory}


def scrub(obj: Any, *, max_str: int = 400) -> Any:
    """Recursively redact secret-looking values and truncate long strings."""
    if isinstance(obj, str):
        s = _SECRET_RE.sub(lambda m: m.group(1) + "***REDACTED***", obj)
        s = _KV_SECRET_RE.sub(lambda m: m.group(1) + "***REDACTED***", s)
        return s[:max_str]
    if isinstance(obj, dict):
        out = {}
        for k, v in list(obj.items())[:40]:
            if str(k).lower() in ("raw", "value", "secret", "token", "password", "api_key"):
                out[k] = "***REDACTED***"
            else:
                out[k] = scrub(v, max_str=max_str)
        return out
    if isinstance(obj, (list, tuple)):
        return [scrub(v, max_str=max_str) for v in list(obj)[:30]]
    return obj


def _cited_in(cite: str, ev_text: str) -> bool:
    """A citation is grounded if its path / value tokens literally occur in the evidence."""
    if not cite:
        return False
    parts = [cite, cite.split(": ", 1)[-1]] + re.findall(r"/[\w./\-]{2,}", cite)
    return any(len(p.strip()) >= 3 and p.strip().split("?")[0][:60] in ev_text for p in parts)


def ai_mode_from_env() -> str:
    """CRITFORGE_AI: auto (default) | on | off."""
    v = (os.environ.get("CRITFORGE_AI") or "auto").strip().lower()
    return v if v in ("auto", "on", "off") else "auto"


def _parse_json(content: str) -> Optional[dict]:
    try:
        v = json.loads(content)
        return v if isinstance(v, dict) else None
    except (json.JSONDecodeError, TypeError):
        m = re.search(r"\{[\s\S]*\}", content or "")
        if m:
            try:
                v = json.loads(m.group(0))
                return v if isinstance(v, dict) else None
            except json.JSONDecodeError:
                return None
    return None


_SYSTEM = (
    "You are the analysis brain of CritForge, an AUTHORIZED black-box, NON-INTRUSIVE "
    "security assessment platform. You only reason over evidence collected by safe GET "
    "probes. Never produce exploit payloads, attack strings, or intrusive steps. Never "
    "request or reveal secret values. Every judgement MUST cite the provided evidence. "
    "Reply with STRICT JSON only."
)


@dataclass
class AIBrain:
    """LLM-backed reasoning for the pipeline. `chat_fn` is injectable for tests."""

    client: Any = None  # LLMClient
    chat_fn: Optional[Callable[[list[dict], str], dict]] = None
    enabled: bool = True
    log: list[dict[str, Any]] = field(default_factory=list)
    models: set[str] = field(default_factory=set)

    @classmethod
    def auto(cls, mode: Optional[str] = None, client: Any = None) -> "AIBrain":
        mode = mode or ai_mode_from_env()
        if mode == "off":
            return cls(enabled=False)
        from .llm import LLMClient, default_config

        llm = client or LLMClient(default_config())
        has_key = bool(llm.resolve_api_key())
        return cls(client=llm, enabled=has_key)

    @property
    def live(self) -> bool:
        return self.enabled and (self.chat_fn is not None or self.client is not None)

    async def _ask(self, step: str, payload: dict, role: str = "worker") -> Optional[dict]:
        if not self.live:
            return None
        messages = [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": json.dumps(scrub(payload, max_str=1200), ensure_ascii=False)},
        ]
        try:
            if self.chat_fn is not None:
                body = await asyncio.to_thread(self.chat_fn, messages, role)
            else:
                body = await asyncio.to_thread(
                    self.client.chat, messages, role=role, temperature=0.1, timeout=120.0
                )
            model = str(body.get("model") or "")
            content = ((body.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
            parsed = _parse_json(content)
            if model:
                self.models.add(model)
            self.log.append({"step": step, "ok": parsed is not None, "model": model})
            return parsed
        except Exception as e:  # noqa: BLE001 - never crash the pipeline
            # Error text from llm.py is status-only (no body / key).
            self.log.append({"step": step, "ok": False, "error": f"{type(e).__name__}: {str(e)[:120]}"})
            return None

    # ------------------------------------------------------------ 1. recon
    async def plan_recon(self, observations: dict[str, Any]) -> dict[str, Any]:
        """Return {"priorities": [...], "suggested_paths": [...]} (filtered)."""
        from .discovery import is_safe_to_fetch

        observed = set(observations.get("observed_paths") or [])
        parsed = await self._ask(
            "plan_recon",
            {
                "task": (
                    "Given observed endpoints/tech of an authorized lab, (a) rank the most "
                    "security-relevant observed paths for passive review and explain why; "
                    "(b) suggest up to 15 ADDITIONAL same-origin relative paths worth a benign "
                    "GET (e.g. framework config/docs/health/backup/metadata locations implied "
                    "by the tech stack). No query strings with attack strings, no mutation, "
                    "no payloads. JSON: {priorities:[{path,reason}], "
                    "suggested_paths:[{path,reason}]}"
                ),
                "observations": observations,
            },
            role="worker",
        )
        if not parsed:
            return {"priorities": [], "suggested_paths": [], "mode": "offline"}
        sugg: list[dict] = []
        for s in parsed.get("suggested_paths") or []:
            p = str((s or {}).get("path") if isinstance(s, dict) else s or "").strip()
            if (
                not p.startswith("/") or p.startswith("//") or "://" in p
                or len(p) > 200 or re.search(r"[<>\"'`\s;|$]|\.\./|%00", p)
                or not is_safe_to_fetch(p) or p in observed
            ):
                continue
            if p not in [x["path"] for x in sugg]:
                sugg.append({"path": p, "reason": str((s or {}).get("reason", "") if isinstance(s, dict) else "")[:200]})
            if len(sugg) >= _MAX_SUGGEST:
                break
        pri = [
            {"path": str(x.get("path")), "reason": str(x.get("reason", ""))[:200]}
            for x in (parsed.get("priorities") or [])[:20]
            if isinstance(x, dict) and str(x.get("path")) in observed
        ]
        return {"priorities": pri, "suggested_paths": sugg, "mode": "ai"}

    # ------------------------------------------------------------ 2. judge
    async def judge(
        self,
        findings: list[Finding],
        observations: list[dict[str, Any]],
    ) -> tuple[list[Finding], dict[str, Any]]:
        """AI judges detector findings and may promote grounded observations.

        Returns (new finding list, stats). Offline -> findings unchanged.
        """
        stats = {"mode": "offline", "judged": 0, "confirmed": 0, "rejected": 0,
                 "promoted": 0, "ungrounded_dropped": 0}
        candidates = [f for f in findings if f.evidence]  # guardrail: evidence required
        stats["no_evidence_dropped"] = len(findings) - len(candidates)
        if not self.live:
            return findings, stats
        by_id = {f.id[:8]: f for f in candidates}
        obs_by_path = {str(o.get("path")): o for o in observations if o.get("path")}
        parsed = await self._ask(
            "judge",
            {
                "task": (
                    "For EACH candidate decide if the evidence shows a genuine security issue. "
                    "Return verdicts:[{id, verdict:'confirm'|'reject', category, severity, "
                    "confidence, rationale, evidence_cited:[exact evidence strings/paths]}]. "
                    "Also review raw observations and return new_findings:[{path, title, "
                    "category, severity, confidence, rationale, evidence_cited}] ONLY for "
                    "issues visibly proven by that observation (e.g. exposed config, secrets "
                    "file readable, admin/debug endpoint open without auth). Do not duplicate "
                    "candidates. category in "
                    + str(sorted(_CAT)) + "; severity in Critical/High/Medium/Low/Info; "
                    "confidence in low/medium/high/confirmed."
                ),
                "candidates": [
                    {"id": k, "title": f.title, "category": f.category.value,
                     "severity": f.severity.value, "detector": f.detector,
                     "target": f.target, "evidence": f.evidence}
                    for k, f in by_id.items()
                ][:40],
                "observations": observations[:60],
            },
            role="verifier",
        )
        if not parsed:
            return findings, stats
        stats["mode"] = "ai"
        out: list[Finding] = [f for f in findings if not f.evidence]  # kept but flagged below
        for f in out:
            f.evidence.setdefault("ai_judgment", {"verdict": "skipped_no_evidence"})
        seen: set[str] = set()
        for v in parsed.get("verdicts") or []:
            if not isinstance(v, dict):
                continue
            f = by_id.get(str(v.get("id", ""))[:8])
            if f is None or f.id in seen:
                continue  # AI cannot reference unknown findings
            seen.add(f.id)
            stats["judged"] += 1
            ev_text = json.dumps(f.evidence, default=str)
            cited = [str(c)[:200] for c in (v.get("evidence_cited") or [])][:6]
            grounded = any(_cited_in(c, ev_text) for c in cited)
            self._apply(f, v, grounded)
            if str(v.get("verdict")).lower() == "reject":
                stats["rejected"] += 1
                f.confidence = Confidence.LOW  # AI downgrade -> suppressed by gate
            else:
                stats["confirmed"] += 1
        for f in candidates:
            if f.id not in seen:
                f.evidence["ai_judgment"] = {"verdict": "not_judged"}
            out.append(f)
        for nf in parsed.get("new_findings") or []:
            if not isinstance(nf, dict):
                continue
            path = str(nf.get("path") or "")
            obs = obs_by_path.get(path)
            if obs is None or int(obs.get("status") or 0) >= 400 or obs.get("cls") not in (None, "real"):
                stats["ungrounded_dropped"] += 1  # no real observation behind it
                continue
            if any(path in json.dumps(f.evidence, default=str) for f in candidates):
                continue  # already covered by a detector finding
            sev = _SEV.get(str(nf.get("severity", "")).lower(), Severity.MEDIUM)
            cat = _CAT.get(str(nf.get("category", "")).lower(), FindingCategory.MISCONFIG)
            if cat == FindingCategory.CHAIN:
                cat = FindingCategory.MISCONFIG
            f = Finding(
                category=cat, severity=sev,
                title=f"[AI] {str(nf.get('title') or path)[:150]}",
                target=str(obs.get("target") or ""),
                evidence={"observation": scrub(obs)},
                detector="ai_detect",
                description="Promoted by AI from a deterministic observation.",
            )
            self._apply(f, nf, True)
            # promoted findings cap at HIGH until deterministic verification agrees
            if f.confidence == Confidence.CONFIRMED:
                f.confidence = Confidence.HIGH
            out.append(f)
            stats["promoted"] += 1
        return out, stats

    @staticmethod
    def _apply(f: Finding, v: dict, grounded: bool) -> None:
        sev = _SEV.get(str(v.get("severity", "")).lower())
        conf = _CONF.get(str(v.get("confidence", "")).lower())
        cat = _CAT.get(str(v.get("category", "")).lower())
        if not grounded and conf is not None:
            conf = Confidence.LOW if conf in (Confidence.LOW, Confidence.MEDIUM) else Confidence.MEDIUM
        if sev is not None:
            f.severity = sev
        if conf is not None:
            f.confidence = conf
        if cat is not None and cat != FindingCategory.CHAIN and f.category != FindingCategory.CHAIN:
            f.category = cat
        f.evidence["ai_judgment"] = {
            "verdict": str(v.get("verdict") or "confirm"),
            "rationale": scrub(str(v.get("rationale") or ""), max_str=600),
            "evidence_cited": scrub([str(c) for c in (v.get("evidence_cited") or [])][:6]),
            "grounded": grounded,
            "confidence": f.confidence.value,
        }

    # ------------------------------------------------------------ 3. chains
    async def narrate_chains(self, chains: list, findings: list[Finding]) -> dict[str, Any]:
        if not self.live or not findings:
            return {"mode": "offline", "narrative": "", "chains": []}
        reportable = [f for f in findings if f.confidence != Confidence.LOW][:30]
        ids = {f.id[:8] for f in reportable}
        parsed = await self._ask(
            "narrate_chains",
            {
                "task": (
                    "Combine these confirmed findings into realistic attack chains and an "
                    "impact narrative for the defender (methodology level, no payloads). "
                    "JSON: {narrative, chains:[{title, finding_ids:[ids], impact, severity}]}"
                ),
                "findings": [
                    {"id": f.id[:8], "title": f.title, "category": f.category.value,
                     "severity": f.severity.value, "target": f.target,
                     "rationale": (f.evidence.get("ai_judgment") or {}).get("rationale", "")}
                    for f in reportable
                ],
                "rule_based_chains": [c.title for c in chains][:10],
            },
            role="planner",
        )
        if not parsed:
            return {"mode": "offline", "narrative": "", "chains": []}
        ai_chains = []
        for c in parsed.get("chains") or []:
            if not isinstance(c, dict):
                continue
            fids = [str(i)[:8] for i in (c.get("finding_ids") or []) if str(i)[:8] in ids]
            if len(fids) < 2:
                continue  # chain must link >=2 real findings
            ai_chains.append({
                "title": str(c.get("title", ""))[:200], "finding_ids": fids,
                "impact": scrub(str(c.get("impact", "")), max_str=600),
                "severity": str(c.get("severity", "")),
            })
        return {"mode": "ai", "narrative": scrub(str(parsed.get("narrative", "")), max_str=1500),
                "chains": ai_chains[:8]}


def observations_from_run(run) -> list[dict[str, Any]]:
    """Flatten probe page records + nuclei hits into scrubbed observations."""
    obs: list[dict[str, Any]] = []
    if run is None:
        return obs
    for r in run.results:
        if not r.ok:
            continue
        sig = r.signals or {}
        for p in sig.get("pages") or []:
            if isinstance(p, dict) and p.get("path"):
                obs.append({"target": r.target, "probe": r.probe, **scrub(p)})
        disc = sig.get("discovery") or {}
        for p in (disc.get("pages") if isinstance(disc, dict) else None) or []:
            if isinstance(p, dict) and p.get("path"):
                obs.append({"target": r.target, "probe": r.probe, **scrub(p)})
        for e in sig.get("exposures") or []:
            if isinstance(e, dict):
                obs.append({"target": r.target, "probe": r.probe, "kind": "exposure", **scrub(e)})
        for n in (sig.get("nuclei_results") or [])[:30]:
            if isinstance(n, dict):
                obs.append({"target": r.target, "probe": "nuclei", "kind": "nuclei",
                            "path": str(n.get("matched-at") or n.get("matched_at") or ""),
                            "template": n.get("template-id") or n.get("template_id"),
                            "name": (n.get("info") or {}).get("name") if isinstance(n.get("info"), dict) else n.get("name"),
                            "status": 200})
    # de-dup by (target, path, kind)
    seen, uniq = set(), []
    for o in obs:
        k = (o.get("target"), o.get("path"), o.get("kind"))
        if k not in seen:
            seen.add(k)
            uniq.append(o)
    return uniq[:200]
