"""Audit log with PQC signatures end-to-end."""

import json
from pathlib import Path

from mcp_bastion.audit import AuditLog
from mcp_bastion.jsonrpc import parse_frame
from mcp_bastion.types import Decision, DecisionType, Direction


def _frame(payload):
    return parse_frame((json.dumps(payload) + "\n").encode("utf-8"), Direction.CLIENT_TO_SERVER)


def test_signed_log_verifies(tmp_path: Path, monkeypatch):
    # Force keypair into tmp so we don't pollute ~/.mcp-bastion/keys
    from mcp_bastion import crypto

    monkeypatch.setattr(crypto, "PUBLIC_KEY_PATH", tmp_path / "k.pub")
    monkeypatch.setattr(crypto, "SECRET_KEY_PATH", tmp_path / "k.key")

    log = AuditLog(tmp_path / "audit.sqlite", sign=True)
    for i in range(3):
        f = _frame({"jsonrpc": "2.0", "id": i, "method": "tools/list"})
        row = log.append(f, Decision(type=DecisionType.ALLOW, reason="ok"))
        assert row.signing_algorithm == crypto.SIGNING_ALGORITHM
        assert row.signature_b64 is not None
        assert len(row.signature_b64) > 100  # base64 of ~2420 bytes
    ok, broken_seq, msg = log.verify_chain(verify_signatures=True)
    assert ok, f"verify failed: {msg} at seq={broken_seq}"
    log.close()


def test_unsigned_mode_still_works(tmp_path: Path, monkeypatch):
    from mcp_bastion import crypto

    monkeypatch.setattr(crypto, "PUBLIC_KEY_PATH", tmp_path / "k.pub")
    monkeypatch.setattr(crypto, "SECRET_KEY_PATH", tmp_path / "k.key")

    log = AuditLog(tmp_path / "audit.sqlite", sign=False)
    f = _frame({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    row = log.append(f, Decision(type=DecisionType.ALLOW, reason="ok"))
    assert row.signature_b64 is None
    ok, _, _ = log.verify_chain(verify_signatures=True)
    assert ok
    log.close()
