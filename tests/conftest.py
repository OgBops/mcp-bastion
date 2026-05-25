"""Shared test fixtures.

Most tests don't care about signatures and shouldn't write keys to the user's
real ~/.mcp-firewall directory. We patch the key paths into a per-test tmp
dir at session scope.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_pqc_keys(tmp_path, monkeypatch):
    from mcp_firewall import crypto

    monkeypatch.setattr(crypto, "PUBLIC_KEY_PATH", tmp_path / "k.pub")
    monkeypatch.setattr(crypto, "SECRET_KEY_PATH", tmp_path / "k.key")
    yield
