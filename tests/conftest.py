"""Shared test fixtures.

Most tests don't care about signatures and shouldn't write keys to the user's
real ~/.mcp-bastion directory. We patch the key paths into a per-test tmp
dir at session scope.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_pqc_keys(tmp_path, monkeypatch):
    """Per-test isolation:

    1. Redirect file paths to tmp_path so we never touch ~/.mcp-bastion/.
    2. Disable the OS keyring so tests don't accumulate entries in the
       developer's macOS Keychain. Real-keyring behavior is exercised by
       a single dedicated test that sets the env var.
    """
    from mcp_bastion import crypto

    monkeypatch.setattr(crypto, "PUBLIC_KEY_PATH", tmp_path / "k.pub")
    monkeypatch.setattr(crypto, "SECRET_KEY_PATH", tmp_path / "k.key")
    monkeypatch.setenv("MCP_BASTION_KEYRING", "0")
    yield
