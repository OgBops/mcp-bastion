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

import base64
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import crypto
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
    signature_b64: str | None = None
    signing_algorithm: str | None = None


class AuditLog:
    """SQLite-backed hash-chained append-only log with optional PQC signatures."""

    def __init__(self, path: Path, sign: bool = True) -> None:
        import os as _os

        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            _os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        try:
            _os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._keypair = crypto.ensure_keypair() if sign else None
        self._sign_enabled = sign
        if self._keypair is not None:
            self._enforce_pinned_fingerprint()

    def _enforce_pinned_fingerprint(self) -> None:
        """Pin the first-seen public key fingerprint inside the DB.

        Defends against an attacker who can rewrite both the audit DB *and*
        the keypair on disk: the pinned fingerprint inside the DB must match
        the current public key, otherwise verify_chain refuses the file.
        """
        if self._keypair is None:
            return
        fp = crypto.public_key_fingerprint(self._keypair.public_key)
        cur = self.conn.execute(
            "SELECT value FROM audit_meta WHERE key = 'public_key_fingerprint'"
        ).fetchone()
        if cur is None:
            self.conn.execute(
                "INSERT INTO audit_meta (key, value) VALUES (?, ?)",
                ("public_key_fingerprint", fp),
            )
            self.conn.commit()
        elif cur["value"] != fp:
            raise RuntimeError(
                "audit log public-key fingerprint mismatch: "
                f"db pinned {cur['value'][:16]}…, current key {fp[:16]}…. "
                "Either someone substituted the keypair OR you're pointing at "
                "another machine's audit log. Refusing to use this DB."
            )

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
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
                entry_hash TEXT NOT NULL,
                signature_b64 TEXT,
                signing_algorithm TEXT
            )
            """
        )
        # Best-effort migration: add signature columns to a pre-v0.2 schema.
        for col, decl in (
            ("signature_b64", "TEXT"),
            ("signing_algorithm", "TEXT"),
        ):
            try:
                self.conn.execute(f"ALTER TABLE audit ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError:
                pass
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

        signature_b64: str | None = None
        signing_algorithm: str | None = None
        if self._sign_enabled and self._keypair is not None:
            sig = crypto.sign(self._keypair.secret_key, entry_hash.encode("utf-8"))
            signature_b64 = base64.b64encode(sig).decode("ascii")
            signing_algorithm = crypto.SIGNING_ALGORITHM

        cur = self.conn.execute(
            """
            INSERT INTO audit
            (timestamp, direction, method, tool_name, rpc_id,
             decision_type, decision_reason, matched_rule,
             payload_json, prev_hash, entry_hash,
             signature_b64, signing_algorithm)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                signature_b64,
                signing_algorithm,
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
            signature_b64=signature_b64,
            signing_algorithm=signing_algorithm,
        )

    def _last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else GENESIS_PREV_HASH

    def verify_chain(self, verify_signatures: bool = True) -> tuple[bool, int | None, str]:
        """Recompute every hash from the head and (optionally) verify each signature.

        Returns (ok, broken_seq, message).
        """
        public_key = self._keypair.public_key if self._keypair else None
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

            sig_b64 = row["signature_b64"] if "signature_b64" in row.keys() else None
            if verify_signatures and sig_b64 and public_key is not None:
                sig = base64.b64decode(sig_b64)
                if not crypto.verify(public_key, row["entry_hash"].encode("utf-8"), sig):
                    return (
                        False,
                        row["seq"],
                        f"PQC signature invalid at seq={row['seq']}",
                    )

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
