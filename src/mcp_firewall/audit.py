"""Tamper-evident audit log.

Every intercepted frame produces one row. Each row's `entry_hash` is
SHA256(prev_hash || canonical_json(this_row_minus_hash)) — i.e., a hash chain.
A single missing or modified row breaks the chain and `verify_chain()` will
flag the position.

This is *not* full cryptographic logging (no signing key, no remote anchoring)
— that's v0.2. But it's enough to make casual tampering detectable and gives
us a clean shape for SIEM forwarders later.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .types import Decision, MCPFrame

GENESIS_PREV_HASH = "0" * 64


@dataclass
class AuditRow:
    seq: int
    timestamp: str
    direction: str
    method: str | None
    tool_name: str | None
    rpc_id: str | None
    decision_type: str
    decision_reason: str
    matched_rule: str | None
    payload_json: str
    prev_hash: str
    entry_hash: str


class AuditLog:
    """SQLite-backed hash-chained append-only log."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                direction TEXT NOT NULL,
                method TEXT,
                tool_name TEXT,
                rpc_id TEXT,
                decision_type TEXT NOT NULL,
                decision_reason TEXT,
                matched_rule TEXT,
                payload_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
            """
        )
        self.conn.commit()

    def append(self, frame: MCPFrame, decision: Decision) -> AuditRow:
        prev_hash = self._last_hash()
        timestamp = datetime.now(timezone.utc).isoformat()
        # Use the rewritten payload if redaction occurred so the log reflects
        # what was actually forwarded.
        payload = decision.rewritten_payload or frame.payload
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        body = {
            "timestamp": timestamp,
            "direction": frame.direction.value,
            "method": frame.method,
            "tool_name": frame.tool_name,
            "rpc_id": str(frame.rpc_id) if frame.rpc_id is not None else None,
            "decision_type": decision.type.value,
            "decision_reason": decision.reason,
            "matched_rule": decision.matched_rule,
            "payload_json": payload_json,
            "prev_hash": prev_hash,
        }
        entry_hash = _hash_body(body)

        cur = self.conn.execute(
            """
            INSERT INTO audit
            (timestamp, direction, method, tool_name, rpc_id,
             decision_type, decision_reason, matched_rule,
             payload_json, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                body["timestamp"],
                body["direction"],
                body["method"],
                body["tool_name"],
                body["rpc_id"],
                body["decision_type"],
                body["decision_reason"],
                body["matched_rule"],
                body["payload_json"],
                body["prev_hash"],
                entry_hash,
            ),
        )
        self.conn.commit()
        return AuditRow(
            seq=cur.lastrowid or 0,
            timestamp=body["timestamp"],
            direction=body["direction"],
            method=body["method"],
            tool_name=body["tool_name"],
            rpc_id=body["rpc_id"],
            decision_type=body["decision_type"],
            decision_reason=body["decision_reason"],
            matched_rule=body["matched_rule"],
            payload_json=body["payload_json"],
            prev_hash=body["prev_hash"],
            entry_hash=entry_hash,
        )

    def _last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else GENESIS_PREV_HASH

    def verify_chain(self) -> tuple[bool, int | None, str]:
        """Recompute every hash from the head. Returns (ok, broken_seq, message)."""
        prev = GENESIS_PREV_HASH
        for row in self.conn.execute("SELECT * FROM audit ORDER BY seq ASC"):
            body = {
                "timestamp": row["timestamp"],
                "direction": row["direction"],
                "method": row["method"],
                "tool_name": row["tool_name"],
                "rpc_id": row["rpc_id"],
                "decision_type": row["decision_type"],
                "decision_reason": row["decision_reason"],
                "matched_rule": row["matched_rule"],
                "payload_json": row["payload_json"],
                "prev_hash": row["prev_hash"],
            }
            if body["prev_hash"] != prev:
                return (False, row["seq"], f"prev_hash mismatch at seq={row['seq']}")
            recomputed = _hash_body(body)
            if recomputed != row["entry_hash"]:
                return (False, row["seq"], f"entry_hash mismatch at seq={row['seq']}")
            prev = row["entry_hash"]
        return (True, None, "ok")

    def tail(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self.conn.close()


def _hash_body(body: dict[str, Any]) -> str:
    serialized = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
