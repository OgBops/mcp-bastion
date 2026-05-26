"""v0.3.1 follow-up tests for the L1-L5 hardening work."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_bastion.audit import AuditLog
from mcp_bastion.jsonrpc import parse_frame
from mcp_bastion.policy import Policy, PolicyEngine, safe_tool_label
from mcp_bastion.types import Decision, DecisionType, Direction, FrameKind


# ---- L3: log scrubbing ----

def test_safe_tool_label_is_stable_and_short():
    a = safe_tool_label("filesystem.read_file")
    b = safe_tool_label("filesystem.read_file")
    c = safe_tool_label("github.create_issue")
    assert a == b
    assert a != c
    assert a.startswith("tool#")
    assert len(a) == len("tool#") + 8


def test_decision_reason_does_not_echo_tool_name():
    """A tool whose name embeds a secret never appears in decision.reason."""
    secret_tool = "shell.exec_with_token_sk-deadbeefdeadbeefdeadbeef"
    engine = PolicyEngine(Policy.from_dict({"deny_tools": ["shell.*"]}))
    raw = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": secret_tool, "arguments": {}},
            }
        )
        + "\n"
    ).encode("utf-8")
    frame = parse_frame(raw, Direction.CLIENT_TO_SERVER)
    decision = engine.evaluate(frame)
    assert decision.type == DecisionType.DENY
    assert "sk-deadbeef" not in decision.reason
    assert secret_tool not in decision.reason
    # The hashed label IS allowed
    assert safe_tool_label(secret_tool) in decision.reason


# ---- L4: external anchor ----

def test_anchor_file_is_written(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.sqlite", sign=True, anchor_every=2)
    raw = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n").encode()
    frame = parse_frame(raw, Direction.CLIENT_TO_SERVER)
    # Write 5 rows; expect anchor entries at seq=1 and seq=2,4
    for i in range(5):
        log.append(frame, Decision(type=DecisionType.ALLOW, reason="ok"))
    log.close()

    anchor = tmp_path / "audit.anchor.jsonl"
    assert anchor.exists()
    lines = anchor.read_text().strip().splitlines()
    # seq 1 (always anchored) + seq 2 + seq 4 = 3 entries
    assert len(lines) >= 2
    for line in lines:
        entry = json.loads(line)
        assert "seq" in entry and "entry_hash" in entry
        assert entry["signing_algorithm"] == "ML-DSA-44"


def test_anchor_detects_truncation(tmp_path: Path):
    """If the audit DB is truncated below an anchor, verify_anchor catches it."""
    db_path = tmp_path / "audit.sqlite"
    log = AuditLog(db_path, sign=True, anchor_every=1)
    raw = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n").encode()
    frame = parse_frame(raw, Direction.CLIENT_TO_SERVER)
    for _ in range(5):
        log.append(frame, Decision(type=DecisionType.ALLOW, reason="ok"))
    log.close()

    # Tamper: delete the last 2 audit rows (truncation attack).
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM audit WHERE seq >= 4")
    conn.commit()
    conn.close()

    log2 = AuditLog(db_path, sign=True, anchor_every=1)
    ok, broken_seq, msg = log2.verify_anchor()
    assert ok is False
    # The anchor at seq=4 (or 5) has no matching DB row
    assert broken_seq in (4, 5)
    assert "truncated" in msg.lower() or "no matching row" in msg.lower()
    log2.close()


def test_anchor_detects_hash_substitution(tmp_path: Path):
    """If the DB row's entry_hash is changed, the anchor mismatch is caught."""
    db_path = tmp_path / "audit.sqlite"
    log = AuditLog(db_path, sign=True, anchor_every=1)
    raw = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n").encode()
    frame = parse_frame(raw, Direction.CLIENT_TO_SERVER)
    for _ in range(3):
        log.append(frame, Decision(type=DecisionType.ALLOW, reason="ok"))
    log.close()

    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE audit SET entry_hash = ? WHERE seq = 2", ("f" * 64,)
    )
    conn.commit()
    conn.close()

    log2 = AuditLog(db_path, sign=True, anchor_every=1)
    ok, broken_seq, msg = log2.verify_anchor()
    assert ok is False
    assert broken_seq == 2
    assert "mismatch" in msg.lower()
    log2.close()


# ---- L5: keyring storage ----

def test_keyring_disabled_falls_back_to_file(tmp_path: Path, monkeypatch):
    """With MCP_BASTION_KEYRING=0, keys must land on disk (already covered
    by the conftest fixture but we assert explicitly)."""
    monkeypatch.setenv("MCP_BASTION_KEYRING", "0")
    from mcp_bastion import crypto

    monkeypatch.setattr(crypto, "PUBLIC_KEY_PATH", tmp_path / "k.pub")
    monkeypatch.setattr(crypto, "SECRET_KEY_PATH", tmp_path / "k.key")
    crypto.ensure_keypair()
    assert (tmp_path / "k.pub").exists()
    assert (tmp_path / "k.key").exists()
    assert (tmp_path / "k.key").stat().st_mode & 0o777 == 0o600


def test_keyring_enabled_skips_secret_file(tmp_path: Path, monkeypatch):
    """With keyring on (and a stub backend), the secret key file is NOT
    written — the secret lives in the keyring instead."""
    monkeypatch.setenv("MCP_BASTION_KEYRING", "1")
    from mcp_bastion import crypto

    # Stub the keyring set/get to use a dict so the test doesn't touch the
    # real macOS Keychain.
    storage: dict[tuple[str, str], str] = {}

    def fake_set(secret_key: bytes) -> bool:
        import base64

        storage[(crypto.KEYRING_SERVICE, crypto.KEYRING_SECRET_KEY)] = (
            base64.b64encode(secret_key).decode("ascii")
        )
        return True

    def fake_get() -> bytes | None:
        import base64

        v = storage.get((crypto.KEYRING_SERVICE, crypto.KEYRING_SECRET_KEY))
        return base64.b64decode(v) if v else None

    monkeypatch.setattr(crypto, "_try_keyring_set", fake_set)
    monkeypatch.setattr(crypto, "_try_keyring_get", fake_get)
    monkeypatch.setattr(crypto, "PUBLIC_KEY_PATH", tmp_path / "k.pub")
    monkeypatch.setattr(crypto, "SECRET_KEY_PATH", tmp_path / "k.key")

    kp1 = crypto.ensure_keypair()
    assert (tmp_path / "k.pub").exists()
    assert not (tmp_path / "k.key").exists(), "secret key should NOT touch disk"
    # Round-trip: second call returns the same keypair from the keyring
    kp2 = crypto.ensure_keypair()
    assert kp1.secret_key == kp2.secret_key
    assert kp1.public_key == kp2.public_key
