import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


@pytest.fixture(autouse=True)
def _no_live_ai(monkeypatch):
    """Tests never call DeepSeek: default AI mode off; AI tests inject a mock brain."""
    monkeypatch.setenv("CRITFORGE_AI", "off")
