"""Read-only recon of the authenticated user's OWN GitHub repositories.

Hard rules:
  - Only repos returned by GET /user/repos?affiliation=owner (token owner).
  - Never scan third-party / arbitrary public repos.
  - Redact secret values; report location + type only.
  - No writes, no PRs, no issue creation unless explicitly asked elsewhere.
"""
from __future__ import annotations

import base64
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
from urllib.parse import quote

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

API = "https://api.github.com"
UA = "CritForge-OwnRepoRecon/0.3"

# Patterns that suggest secrets / sensitive config. Captures are REDACTED.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{20,}")),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{20,}")),
    ("stripe_key", re.compile(r"sk_live_[A-Za-z0-9]{16,}")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key_assignment", re.compile(
        r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{16,})"
    )),
    ("password_assignment", re.compile(
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})"
    )),
]

_INTERNAL_DOMAIN = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)*(?:internal|corp|intranet|local|lan|svc)\.[a-z0-9.-]+\b"
    r"|\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
)

_API_ENDPOINT = re.compile(
    r"(?i)https?://[^\s'\"<>]+|/api/v\d+/[A-Za-z0-9_./\-]+|/v\d+/[A-Za-z0-9_./\-]+"
)

_CONFIG_NAMES = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\..+)?|credentials(?:\..+)?|secrets?\.(?:ya?ml|json|toml|ini)|"
    r"config\.(?:ya?ml|json|toml|ini|py)|settings\.(?:ya?ml|json|py)|"
    r"application(?:-\w+)?\.(?:ya?ml|properties)|docker-compose(?:\..+)?\.ya?ml)$"
)

# Skip obviously huge / binary paths
_SKIP_PATH = re.compile(
    r"(?i)\.(?:png|jpg|jpeg|gif|webp|ico|pdf|zip|gz|tgz|jar|war|class|exe|dll|so|o|a|"
    r"woff2?|ttf|eot|mp4|mp3|wav|lock)$|/(?:node_modules|vendor|\.git|dist|build|__pycache__)/"
)


@dataclass
class FindingHit:
    kind: str  # secret | internal_domain | api_endpoint | config_file
    secret_type: str = ""
    repo: str = ""
    path: str = ""
    line: int = 0
    evidence_redacted: str = ""
    severity_hint: str = "High"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RepoScanResult:
    full_name: str
    private: bool
    default_branch: str
    scanned_files: int = 0
    hits: list[FindingHit] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "full_name": self.full_name,
            "private": self.private,
            "default_branch": self.default_branch,
            "scanned_files": self.scanned_files,
            "hit_count": len(self.hits),
            "hits": [h.to_dict() for h in self.hits],
            "error": self.error,
        }


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "***REDACTED***"
    return s[:3] + "…" + "***REDACTED***"


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": UA,
    }


def load_token_from_env_file(path: str) -> Optional[str]:
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k == "GITHUB_TOKEN" and v.strip():
                return v.strip()
    except OSError:
        pass
    return os.environ.get("GITHUB_TOKEN") or None


def verify_token(token: str, *, timeout: float = 20.0) -> dict[str, Any]:
    if httpx is None:
        return {"ok": False, "error": "httpx missing"}
    r = httpx.get(f"{API}/user", headers=_headers(token), timeout=timeout)
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "error": "bad_credentials_or_forbidden"}
    u = r.json()
    return {"ok": True, "login": u.get("login"), "id": u.get("id"), "type": u.get("type")}


def list_own_repos(token: str, *, timeout: float = 30.0) -> list[dict[str, Any]]:
    """ONLY affiliation=owner — never search arbitrary public third-party repos."""
    if httpx is None:
        raise RuntimeError("httpx required")
    out: list[dict[str, Any]] = []
    page = 1
    with httpx.Client(headers=_headers(token), timeout=timeout) as c:
        while True:
            r = c.get(
                f"{API}/user/repos",
                params={
                    "affiliation": "owner",
                    "per_page": 100,
                    "page": page,
                    "sort": "updated",
                },
            )
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            out.extend(batch)
            if len(batch) < 100:
                break
            page += 1
    return out


def _scan_text(repo: str, path: str, text: str) -> list[FindingHit]:
    hits: list[FindingHit] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for stype, pat in _SECRET_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            raw = m.group(0)
            hits.append(
                FindingHit(
                    kind="secret",
                    secret_type=stype,
                    repo=repo,
                    path=path,
                    line=i,
                    evidence_redacted=f"{stype} match at L{i}: {_redact(raw)}",
                    severity_hint="Critical" if "key" in stype or "pat" in stype or "private" in stype else "High",
                )
            )
        for m in _INTERNAL_DOMAIN.finditer(line):
            hits.append(
                FindingHit(
                    kind="internal_domain",
                    secret_type="internal_host",
                    repo=repo,
                    path=path,
                    line=i,
                    evidence_redacted=f"internal-looking host at L{i}: {m.group(0)[:80]}",
                    severity_hint="Medium",
                )
            )
        for m in _API_ENDPOINT.finditer(line):
            ep = m.group(0)
            # Skip common noise
            if any(x in ep.lower() for x in ("schema.org", "w3.org", "github.com", "githubusercontent")):
                continue
            hits.append(
                FindingHit(
                    kind="api_endpoint",
                    secret_type="url",
                    repo=repo,
                    path=path,
                    line=i,
                    evidence_redacted=f"endpoint at L{i}: {ep[:120]}",
                    severity_hint="Info",
                )
            )
    if _CONFIG_NAMES.search(path):
        hits.append(
            FindingHit(
                kind="config_file",
                secret_type="config_path",
                repo=repo,
                path=path,
                line=0,
                evidence_redacted=f"config-like path present: {path}",
                severity_hint="Medium",
            )
        )
    return hits


def _list_tree(client: "httpx.Client", full_name: str, branch: str) -> list[dict[str, Any]]:
    # recursive tree
    r = client.get(f"{API}/repos/{full_name}/git/trees/{quote(branch)}", params={"recursive": "1"})
    if r.status_code != 200:
        # try default via commits
        return []
    data = r.json()
    return [t for t in data.get("tree") or [] if t.get("type") == "blob"]


def _get_file(client: "httpx.Client", full_name: str, path: str, ref: str) -> Optional[str]:
    r = client.get(
        f"{API}/repos/{full_name}/contents/{quote(path)}",
        params={"ref": ref},
        headers={**dict(client.headers), "Accept": "application/vnd.github.raw"},
    )
    if r.status_code == 200:
        # raw may be text
        try:
            return r.text
        except Exception:  # noqa: BLE001
            return None
    # fallback JSON+base64
    r2 = client.get(f"{API}/repos/{full_name}/contents/{quote(path)}", params={"ref": ref})
    if r2.status_code != 200:
        return None
    j = r2.json()
    if isinstance(j, dict) and j.get("encoding") == "base64" and j.get("content"):
        try:
            return base64.b64decode(j["content"]).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return None
    return None


def scan_own_repo(
    token: str,
    repo: dict[str, Any],
    *,
    max_files: int = 80,
    max_bytes: int = 200_000,
    timeout: float = 30.0,
) -> RepoScanResult:
    full = repo["full_name"]
    branch = repo.get("default_branch") or "main"
    result = RepoScanResult(
        full_name=full,
        private=bool(repo.get("private")),
        default_branch=branch,
    )
    if httpx is None:
        result.error = "httpx missing"
        return result
    try:
        with httpx.Client(headers=_headers(token), timeout=timeout) as c:
            trees = _list_tree(c, full, branch)
            # Prefer config-like and source files
            blobs = []
            for t in trees:
                path = t.get("path") or ""
                if _SKIP_PATH.search(path):
                    continue
                size = int(t.get("size") or 0)
                if size > max_bytes:
                    continue
                score = 0
                if _CONFIG_NAMES.search(path):
                    score += 10
                if path.endswith((".env", ".yml", ".yaml", ".json", ".py", ".js", ".ts", ".go", ".java", ".php", ".rb", ".sh")):
                    score += 3
                blobs.append((score, path, size))
            blobs.sort(key=lambda x: (-x[0], x[1]))
            for _, path, _size in blobs[:max_files]:
                text = _get_file(c, full, path, branch)
                if text is None:
                    continue
                if len(text) > max_bytes:
                    text = text[:max_bytes]
                result.scanned_files += 1
                result.hits.extend(_scan_text(full, path, text))
    except Exception as e:  # noqa: BLE001
        result.error = f"{type(e).__name__}: {e}"
    return result


def scan_all_own_repos(
    token: str,
    *,
    max_repos: int = 20,
    max_files_per_repo: int = 60,
) -> dict[str, Any]:
    auth = verify_token(token)
    if not auth.get("ok"):
        return {
            "ok": False,
            "auth": auth,
            "repos": [],
            "hits": [],
            "note": "GITHUB_TOKEN invalid or unauthorized; own-repo scan skipped",
        }
    repos = list_own_repos(token)
    # Prefer non-forks first
    repos_sorted = sorted(repos, key=lambda r: (bool(r.get("fork")), -(r.get("pushed_at") is not None)))
    scanned: list[RepoScanResult] = []
    for repo in repos_sorted[:max_repos]:
        scanned.append(scan_own_repo(token, repo, max_files=max_files_per_repo))
    all_hits = [h.to_dict() for s in scanned for h in s.hits]
    return {
        "ok": True,
        "auth": {"login": auth.get("login"), "type": auth.get("type")},
        "repo_count_owned": len(repos),
        "repo_count_scanned": len(scanned),
        "repos": [s.to_dict() for s in scanned],
        "hits": all_hits,
        "hit_count": len(all_hits),
        "note": "Only affiliation=owner repos; secret values redacted",
    }
