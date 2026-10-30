"""M5 Key-management runtime layer (config-file backed).

Provides:
  - A SecretStore that reads/writes API keys to a local YAML config file.
  - An OAuthProvider interface for auto-acquiring platform keys where the
    platform supports headless / client-credentials style flows.
  - A PendingAuthorization registry for platforms that require a one-time
    interactive user grant (OAuth authorization-code / device flow). Those
    are recorded, NOT blocked on — the operator sees them in the final
    report and can authorize later.

NO real secrets are committed. Placeholders and env-var references only.
CritForge never logs secret values into the audit spine.
"""
from __future__ import annotations

import abc
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from .hardening import FailClosedError, require


@dataclass
class SecretRef:
    """A named secret slot (value may be empty / pending)."""

    name: str
    platform: str
    value: str = ""  # never commit real values; prefer env:VAR form
    source: str = "config"  # config | env | oauth | pending
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class PendingAuthorization:
    """A platform key that still needs the user's one-time OAuth grant."""

    platform: str
    reason: str
    auth_url_hint: str = ""
    requested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SecretStore:
    """YAML-backed secret store. Values may be literal or `env:VARNAME`."""

    def __init__(self, path: str) -> None:
        require(path, "secret store path required (fail-closed)")
        self.path = path
        self._secrets: dict[str, SecretRef] = {}
        self._pending: list[PendingAuthorization] = []
        if Path(path).exists():
            self._load()

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        if not isinstance(raw, dict):
            raise FailClosedError("secrets file must be a mapping")
        for item in raw.get("secrets") or []:
            ref = SecretRef(
                name=str(item.get("name", "")),
                platform=str(item.get("platform", "")),
                value=str(item.get("value", "") or ""),
                source=str(item.get("source", "config") or "config"),
                updated_at=str(
                    item.get("updated_at")
                    or datetime.now(timezone.utc).isoformat()
                ),
            )
            if ref.name:
                self._secrets[ref.name] = ref
        for item in raw.get("pending_authorizations") or []:
            self._pending.append(
                PendingAuthorization(
                    platform=str(item.get("platform", "")),
                    reason=str(item.get("reason", "")),
                    auth_url_hint=str(item.get("auth_url_hint", "") or ""),
                    requested_at=str(
                        item.get("requested_at")
                        or datetime.now(timezone.utc).isoformat()
                    ),
                )
            )

    def save(self) -> None:
        data = {
            "secrets": [
                {
                    "name": s.name,
                    "platform": s.platform,
                    "value": s.value,  # may be env:VAR — never log this
                    "source": s.source,
                    "updated_at": s.updated_at,
                }
                for s in self._secrets.values()
            ],
            "pending_authorizations": [p.to_dict() for p in self._pending],
        }
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    def set(self, name: str, platform: str, value: str, *, source: str = "config") -> SecretRef:
        require(name, "secret name required")
        require(platform, "platform required")
        ref = SecretRef(
            name=name,
            platform=platform,
            value=value,
            source=source,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        self._secrets[name] = ref
        return ref

    def get(self, name: str) -> Optional[str]:
        """Resolve a secret. Supports `env:VARNAME` indirection. Never logs value."""
        ref = self._secrets.get(name)
        if ref is None:
            return None
        val = ref.value
        if val.startswith("env:"):
            env_name = val[4:]
            return os.environ.get(env_name)
        return val or None

    def list_names(self) -> list[str]:
        return sorted(self._secrets.keys())

    def add_pending(self, platform: str, reason: str, *, auth_url_hint: str = "") -> PendingAuthorization:
        # Deduplicate by platform.
        for p in self._pending:
            if p.platform == platform:
                return p
        pending = PendingAuthorization(
            platform=platform, reason=reason, auth_url_hint=auth_url_hint
        )
        self._pending.append(pending)
        return pending

    def pending(self) -> list[PendingAuthorization]:
        return list(self._pending)

    def clear_pending(self, platform: str) -> None:
        self._pending = [p for p in self._pending if p.platform != platform]


class OAuthProvider(abc.ABC):
    """Interface for auto-acquiring a platform API key via OAuth."""

    platform: str = "unknown"

    @abc.abstractmethod
    async def acquire(self, store: SecretStore) -> Optional[SecretRef]:
        """Try to acquire a key. Return SecretRef on success.

        If interactive user authorization is required, record a
        PendingAuthorization on the store and return None (do NOT block).
        """
        raise NotImplementedError


class ClientCredentialsProvider(OAuthProvider):
    """Headless client-credentials style acquisition (env-driven).

    Looks for CRITFORGE_<PLATFORM>_CLIENT_ID / _CLIENT_SECRET. If present,
    writes an `env:`-indirected placeholder for the access-token slot.
    Does NOT perform a real HTTP token exchange here (no network in M5
    skeleton) — records the wiring and leaves the live exchange to a
    future connector. If env vars are missing, records a pending auth.
    """

    def __init__(self, platform: str, secret_name: str) -> None:
        self.platform = platform
        self.secret_name = secret_name

    async def acquire(self, store: SecretStore) -> Optional[SecretRef]:
        plat = self.platform.upper().replace("-", "_")
        cid = os.environ.get(f"CRITFORGE_{plat}_CLIENT_ID")
        csec = os.environ.get(f"CRITFORGE_{plat}_CLIENT_SECRET")
        if not cid or not csec:
            store.add_pending(
                self.platform,
                reason=(
                    f"missing CRITFORGE_{plat}_CLIENT_ID / "
                    f"CRITFORGE_{plat}_CLIENT_SECRET; "
                    "one-time OAuth grant or env wiring required"
                ),
                auth_url_hint=f"https://{self.platform}.example/oauth/authorize",
            )
            return None
        # Wire an env-indirected access-token slot (no real HTTP call).
        token_env = f"CRITFORGE_{plat}_ACCESS_TOKEN"
        ref = store.set(
            self.secret_name,
            self.platform,
            value=f"env:{token_env}",
            source="oauth",
        )
        store.clear_pending(self.platform)
        return ref


class InteractiveOAuthProvider(OAuthProvider):
    """Always-pending provider for platforms that need a browser grant."""

    def __init__(self, platform: str, *, auth_url_hint: str = "") -> None:
        self.platform = platform
        self.auth_url_hint = auth_url_hint or f"https://{platform}/oauth/authorize"

    async def acquire(self, store: SecretStore) -> Optional[SecretRef]:
        store.add_pending(
            self.platform,
            reason="interactive OAuth authorization-code / device flow required",
            auth_url_hint=self.auth_url_hint,
        )
        return None


async def bootstrap_keys(
    store: SecretStore,
    providers: list[OAuthProvider],
) -> list[PendingAuthorization]:
    """Run all providers; return the pending list (never blocks on user)."""
    require(store is not None, "store required (fail-closed)")
    for p in providers:
        await p.acquire(store)
    store.save()
    return store.pending()


def default_providers() -> list[OAuthProvider]:
    """Built-in provider stubs. None perform real network OAuth in M5.

    AI model provider is DeepSeek (API key via DEEPSEEK_API_KEY /
    env:DEEPSEEK_API_KEY). OpenAI / Anthropic slots are retired.
    """
    return [
        ClientCredentialsProvider("deepseek", "deepseek_api_key"),
        InteractiveOAuthProvider(
            "github",
            auth_url_hint="https://github.com/login/oauth/authorize",
        ),
    ]
