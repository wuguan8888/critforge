"""M5 secrets / pending-auth tests."""
from __future__ import annotations

import os

import pytest

from critforge.secrets import (
    ClientCredentialsProvider,
    InteractiveOAuthProvider,
    SecretStore,
    bootstrap_keys,
)


@pytest.mark.asyncio
async def test_store_roundtrip(tmp_path):
    path = tmp_path / "secrets.yaml"
    store = SecretStore(str(path))
    store.set("demo.key", "demo", value="env:DEMO_KEY", source="config")
    store.save()

    store2 = SecretStore(str(path))
    assert store2.list_names() == ["demo.key"]
    os.environ["DEMO_KEY"] = "super-secret-do-not-log"
    assert store2.get("demo.key") == "super-secret-do-not-log"
    del os.environ["DEMO_KEY"]
    assert store2.get("demo.key") is None  # env missing -> None (fail soft on read)


@pytest.mark.asyncio
async def test_client_credentials_pending_without_env(tmp_path):
    store = SecretStore(str(tmp_path / "s.yaml"))
    # Ensure env clean.
    for k in list(os.environ):
        if k.startswith("CRITFORGE_ACME_"):
            del os.environ[k]
    provider = ClientCredentialsProvider("acme", "acme.api_key")
    ref = await provider.acquire(store)
    assert ref is None
    pending = store.pending()
    assert len(pending) == 1
    assert pending[0].platform == "acme"


@pytest.mark.asyncio
async def test_client_credentials_wires_env_slot(tmp_path):
    store = SecretStore(str(tmp_path / "s.yaml"))
    os.environ["CRITFORGE_ACME_CLIENT_ID"] = "id"
    os.environ["CRITFORGE_ACME_CLIENT_SECRET"] = "sec"
    try:
        provider = ClientCredentialsProvider("acme", "acme.api_key")
        ref = await provider.acquire(store)
        assert ref is not None
        assert ref.value == "env:CRITFORGE_ACME_ACCESS_TOKEN"
        assert store.pending() == []
    finally:
        del os.environ["CRITFORGE_ACME_CLIENT_ID"]
        del os.environ["CRITFORGE_ACME_CLIENT_SECRET"]


@pytest.mark.asyncio
async def test_interactive_always_pending(tmp_path):
    store = SecretStore(str(tmp_path / "s.yaml"))
    p = InteractiveOAuthProvider("github", auth_url_hint="https://github.com/login/oauth/authorize")
    assert await p.acquire(store) is None
    assert store.pending()[0].platform == "github"


@pytest.mark.asyncio
async def test_bootstrap_default_providers(tmp_path):
    store = SecretStore(str(tmp_path / "s.yaml"))
    from critforge.secrets import default_providers

    pending = await bootstrap_keys(store, default_providers())
    platforms = {p.platform for p in pending}
    # Without env credentials, deepseek/github should be pending.
    assert "deepseek" in platforms
    assert "github" in platforms
    assert "openai" not in platforms
    assert "anthropic" not in platforms
    assert (tmp_path / "s.yaml").exists()
