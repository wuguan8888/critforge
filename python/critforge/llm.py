"""LLM client for CritForge agents (planner / worker / verifier).

Default provider: DeepSeek via its OpenAI-compatible HTTP API.
  base_url: https://api.deepseek.com/v1
  models:   deepseek-chat (worker/verifier), deepseek-reasoner (planner)

API keys are resolved from the environment (DEEPSEEK_API_KEY) or a
SecretStore slot (`deepseek_api_key` → env:DEEPSEEK_API_KEY). Secret
values are never logged.

Network calls are optional — tests and dry-runs can use the config /
request-builder without contacting the provider.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from .hardening import FailClosedError, require
from .secrets import SecretStore


DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
DEFAULT_PLANNER_MODEL = "deepseek-reasoner"
DEFAULT_WORKER_MODEL = "deepseek-chat"
DEFAULT_VERIFIER_MODEL = "deepseek-chat"
DEFAULT_API_KEY_ENV = "DEEPSEEK_API_KEY"
DEFAULT_SECRET_NAME = "deepseek_api_key"


@dataclass
class LLMConfig:
    """Provider + routing configuration (no secrets stored here)."""

    provider: str = "deepseek"
    base_url: str = DEFAULT_BASE_URL
    api_key_env: str = DEFAULT_API_KEY_ENV
    secret_name: str = DEFAULT_SECRET_NAME
    planner_model: str = DEFAULT_PLANNER_MODEL
    worker_model: str = DEFAULT_WORKER_MODEL
    verifier_model: str = DEFAULT_VERIFIER_MODEL

    def model_for(self, role: str) -> str:
        role = (role or "").strip().lower()
        if role == "planner":
            return self.planner_model
        if role == "verifier":
            return self.verifier_model
        return self.worker_model

    def endpoint(self, path: str = "/chat/completions") -> str:
        base = self.base_url.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        return f"{base}{path}"


def default_config() -> LLMConfig:
    return LLMConfig()


def config_from_scope_routing(
    planner: str = "",
    worker: str = "",
    verifier: str = "",
    *,
    base_url: str = DEFAULT_BASE_URL,
) -> LLMConfig:
    """Build LLMConfig, filling blank model slots with DeepSeek defaults."""
    return LLMConfig(
        provider="deepseek",
        base_url=base_url or DEFAULT_BASE_URL,
        planner_model=planner or DEFAULT_PLANNER_MODEL,
        worker_model=worker or DEFAULT_WORKER_MODEL,
        verifier_model=verifier or DEFAULT_VERIFIER_MODEL,
    )


@dataclass
class LLMClient:
    """Thin OpenAI-compatible chat client with configurable base_url."""

    config: LLMConfig = field(default_factory=default_config)
    store: Optional[SecretStore] = None

    def resolve_api_key(self) -> Optional[str]:
        """Resolve API key; never logs the value."""
        if self.store is not None:
            val = self.store.get(self.config.secret_name)
            if val:
                return val
        return os.environ.get(self.config.api_key_env) or None

    def build_chat_payload(
        self,
        messages: list[dict[str, str]],
        *,
        role: str = "worker",
        temperature: float = 0.2,
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        require(messages, "messages required (fail-closed)")
        payload: dict[str, Any] = {
            "model": self.config.model_for(role),
            "messages": messages,
            "temperature": temperature,
        }
        if extra:
            payload.update(extra)
        return payload

    def build_headers(self, api_key: Optional[str] = None) -> dict[str, str]:
        key = api_key if api_key is not None else self.resolve_api_key()
        require(key, "DeepSeek API key missing (set DEEPSEEK_API_KEY)")
        return {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        role: str = "worker",
        temperature: float = 0.2,
        timeout: float = 60.0,
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """POST /chat/completions against the configured base_url.

        Returns the parsed JSON body. Raises FailClosedError if the key
        is missing or the HTTP call fails.
        """
        payload = self.build_chat_payload(
            messages, role=role, temperature=temperature, extra=extra
        )
        headers = self.build_headers()
        url = self.config.endpoint("/chat/completions")
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            # Do not include response body (may echo prompts); status only.
            raise FailClosedError(f"LLM HTTP {e.code} from {self.config.provider}") from e
        except urllib.error.URLError as e:
            raise FailClosedError(f"LLM unreachable: {e.reason}") from e
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise FailClosedError("LLM returned non-JSON body") from e
