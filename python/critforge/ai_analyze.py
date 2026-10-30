"""Real DeepSeek analysis pass over redacted recon findings.

Uses LLMClient (DeepSeek OpenAI-compatible API). Never sends raw secret values —
callers must pass already-redacted evidence. On API failure, falls back to an
offline heuristic analyzer and records that fact.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from .hardening import FailClosedError
from .llm import LLMClient, LLMConfig, default_config


@dataclass
class AIAnalysisResult:
    ok: bool
    mode: str  # "deepseek_live" | "offline_fallback"
    model: str = ""
    summary: str = ""
    prioritized: list[dict[str, Any]] = field(default_factory=list)
    confidence_notes: list[str] = field(default_factory=list)
    raw_excerpt: str = ""  # truncated model text, never secrets
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _offline_analyze(findings: list[dict[str, Any]]) -> AIAnalysisResult:
    """Heuristic ranking when DeepSeek is unreachable — methodology only."""
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    scored = sorted(
        findings,
        key=lambda f: (
            rank.get(str(f.get("severity_hint") or f.get("severity") or "Info"), 9),
            str(f.get("kind") or f.get("category") or ""),
        ),
    )
    prioritized = []
    for f in scored[:20]:
        prioritized.append(
            {
                "title": f.get("title") or f.get("secret_type") or f.get("kind") or "finding",
                "severity": f.get("severity_hint") or f.get("severity") or "Medium",
                "confidence": "medium",
                "rationale": "offline heuristic: ranked by severity_hint / kind",
                "repo": f.get("repo") or f.get("target") or "",
                "path": f.get("path") or "",
            }
        )
    kinds = {}
    for f in findings:
        k = str(f.get("kind") or f.get("category") or "other")
        kinds[k] = kinds.get(k, 0) + 1
    summary = (
        f"Offline fallback analysis of {len(findings)} redacted findings. "
        f"Kind counts: {kinds}. Prefer live DeepSeek when key is healthy."
    )
    return AIAnalysisResult(
        ok=True,
        mode="offline_fallback",
        model="offline-heuristic",
        summary=summary,
        prioritized=prioritized,
        confidence_notes=[
            "No live model call — confidence not calibrated by LLM second-pass",
            "Treat offline rankings as methodology guidance only",
        ],
    )


def analyze_findings(
    findings: list[dict[str, Any]],
    *,
    client: Optional[LLMClient] = None,
    role: str = "planner",
    max_items: int = 40,
) -> AIAnalysisResult:
    """Send redacted findings to DeepSeek; fall back offline on any failure."""
    # Sanitize: strip any accidental long secret-looking blobs
    safe: list[dict[str, Any]] = []
    for f in findings[:max_items]:
        item = {k: v for k, v in f.items() if k not in ("raw", "value", "secret", "token")}
        # Force redact evidence fields
        for key in ("evidence_redacted", "evidence", "description"):
            if key in item and isinstance(item[key], str):
                item[key] = re.sub(r"(ghp_|sk-|AKIA|xox[baprs]-)[A-Za-z0-9_\-]{8,}", r"\1***REDACTED***", item[key])
        safe.append(item)

    if not safe:
        return AIAnalysisResult(
            ok=True,
            mode="offline_fallback",
            model="offline-heuristic",
            summary="No findings to analyze.",
            prioritized=[],
            confidence_notes=["empty input"],
        )

    llm = client or LLMClient(default_config())
    key = llm.resolve_api_key()
    if not key:
        res = _offline_analyze(safe)
        res.error = "DEEPSEEK_API_KEY missing"
        return res

    prompt = {
        "task": (
            "You are the CritForge planner/verifier. Analyze these REDACTED security "
            "findings from an authorized engagement (owner's own GitHub repos and/or "
            "local lab). Do NOT ask for secret values. Return STRICT JSON with keys: "
            "summary (string), prioritized (array of {title, severity, confidence, "
            "rationale, repo, path}), confidence_notes (array of strings). "
            "severity in {Critical,High,Medium,Low,Info}; confidence in {low,medium,high,confirmed}."
        ),
        "evaluation_theory": (
            "Minimize false positives via corroboration; dual-axis severity×confidence; "
            "three-stage verification mindset (detection→confirmation→evidence)."
        ),
        "findings": safe,
    }
    messages = [
        {
            "role": "system",
            "content": "You are a security methodology analyst. Reply with JSON only. Never request or invent secret values.",
        },
        {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
    ]
    try:
        body = llm.chat(messages, role=role, temperature=0.1, timeout=90.0)
        model = (body.get("model") or llm.config.model_for(role))
        content = ((body.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        excerpt = content[:1500]
        # Extract JSON object
        parsed = None
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            m = re.search(r"\{[\s\S]*\}", content)
            if m:
                try:
                    parsed = json.loads(m.group(0))
                except json.JSONDecodeError:
                    parsed = None
        if not isinstance(parsed, dict):
            # Live call succeeded but non-JSON — keep excerpt, merge offline ranking
            offline = _offline_analyze(safe)
            return AIAnalysisResult(
                ok=True,
                mode="deepseek_live",
                model=str(model),
                summary=excerpt[:500] or offline.summary,
                prioritized=offline.prioritized,
                confidence_notes=["model returned non-JSON; used offline ranking for prioritized list"],
                raw_excerpt=excerpt,
            )
        return AIAnalysisResult(
            ok=True,
            mode="deepseek_live",
            model=str(model),
            summary=str(parsed.get("summary") or "")[:2000],
            prioritized=list(parsed.get("prioritized") or [])[:30],
            confidence_notes=[str(x) for x in (parsed.get("confidence_notes") or [])][:20],
            raw_excerpt=excerpt,
        )
    except FailClosedError as e:
        res = _offline_analyze(safe)
        res.error = str(e)
        return res
    except Exception as e:  # noqa: BLE001
        res = _offline_analyze(safe)
        res.error = f"{type(e).__name__}: {e}"
        return res
