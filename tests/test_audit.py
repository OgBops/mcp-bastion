import json
import sqlite3
from pathlib import Path

from mcp_bastion.audit import AuditLog
from mcp_bastion.jsonrpc import parse_frame
from mcp_bastion.types import Decision, DecisionType, Direction


def _frame(payload):
    return parse_frame((json.dumps(payload) + "\n").encode("utf-8"), Direction.CLIENT_TO_SERVER)


def test_append_and_tail(tmp_path: Path):
    log = AuditLog(tmp_path / "a.sqlite")
    f = _frame({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    d = Decision(type=DecisionType.ALLOW, reason="ok")
    row = log.append(f, d)
    assert row.seq == 1
    assert row.entry_hash != row.prev_hash
    assert log.tail(1)[0]["decision_type"] == "allow"
    log.close()


def test_chain_verifies_clean(tmp_path: Path):
    log = AuditLog(tmp_path / "a.sqlite")
    for i in range(5):
        f = _frame({"jsonrpc": "2.0", "id": i, "method": "tools/list"})
        log.append(f, Decision(type=DecisionType.ALLOW, reason="ok"))
    ok, broken_seq, msg = log.verify_chain()
    assert ok is True
    assert broken_seq is None
    assert msg == "ok"
    log.close()


def test_chain_detects_tampering(tmp_path: Path):
    db_path = tmp_path / "a.sqlite"
    log = AuditLog(db_path)
    for i in range(3):
        f = _frame({"jsonrpc": "2.0", "id": i, "method": "tools/list"})
        log.append(f, Decision(type=DecisionType.ALLOW, reason="ok"))
    log.close()

    # Tamper: rewrite a payload directly in SQLite
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audit SET decision_reason='tampered' WHERE seq=2")
    conn.commit()
    conn.close()

    log2 = AuditLog(db_path)
    ok, broken_seq, msg = log2.verify_chain()
    assert ok is False
    assert broken_seq == 2
    log2.close()
