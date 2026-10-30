"""DeepSeek LLM client config / request-builder tests (no network)."""
from __future__ import annotations

import os

import pytest

from critforge.hardening import FailClosedError
from critforge.llm import (
    DEFAULT_BASE_URL,
    LLMClient,
    LLMConfig,
    config_from_scope_routing,
    default_config,
)
from critforge.secrets import SecretStore


def test_default_config_is_deepseek():
    cfg = default_config()
    assert cfg.provider == "deepseek"
    assert cfg.base_url == "https://api.deepseek.com/v1"
    assert cfg.base_url == DEFAULT_BASE_URL
    assert cfg.api_key_env == "DEEPSEEK_API_KEY"
    assert cfg.planner_model == "deepseek-reasoner"
    assert cfg.worker_model == "deepseek-chat"
    assert cfg.verifier_model == "deepseek-chat"
    assert cfg.endpoint() == "https://api.deepseek.com/v1/chat/completions"


def test_config_from_scope_routing_fills_defaults():
    cfg = config_from_scope_routing("", "", "")
    assert cfg.planner_model == "deepseek-reasoner"
    assert cfg.worker_model == "deepseek-chat"
    cfg2 = config_from_scope_routing("custom-p", "custom-w", "custom-v")
    assert cfg2.planner_model == "custom-p"
    assert cfg2.worker_model == "custom-w"
    assert cfg2.verifier_model == "custom-v"


def test_build_payload_and_headers_from_env(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-not-real")
    client = LLMClient()
    payload = client.build_chat_payload(
        [{"role": "user", "content": "ping"}], role="planner"
    )
    assert payload["model"] == "deepseek-reasoner"
    headers = client.build_headers()
    assert headers["Authorization"] == "Bearer test-key-not-real"
    assert "Content-Type" in headers


def test_resolve_from_secret_store(tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    store = SecretStore(str(tmp_path / "s.yaml"))
    store.set("deepseek_api_key", "deepseek", value="env:DEEPSEEK_API_KEY", source="config")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "from-store-env")
    client = LLMClient(store=store)
    assert client.resolve_api_key() == "from-store-env"


def test_missing_key_fail_closed(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    client = LLMClient()
    with pytest.raises(FailClosedError):
        client.build_headers()


def test_custom_base_url():
    cfg = LLMConfig(base_url="https://example.invalid/v1")
    assert cfg.endpoint("/models") == "https://example.invalid/v1/models"
