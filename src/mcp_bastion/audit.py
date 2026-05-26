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

    def __init__(
        self,
        path: Path,
        sign: bool = True,
        anchor_every: int = 100,
        anchor_path: Path | None = None,
    ) -> None:
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

        # External anchor: a sidecar append-only file separate from the SQLite
        # DB. An attacker who rewrites both the DB and the signing key still
        # has to overwrite the anchor file, which we keep on a different
        # filesystem path with O_APPEND-only semantics where the OS supports
        # it (chattr +a / chflags uappend). v0.3.1 just makes the file
        # append-only via mode + open flags; OS-level immutability is opt-in.
        self._anchor_every = max(1, anchor_every)
        self._anchor_path = (
            Path(anchor_path).expanduser()
            if anchor_path is not None
            else self.path.with_suffix(".anchor.jsonl")
        )

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
        seq = cur.lastrowid or 0
        # Periodic external anchor — see _write_anchor for what this defends.
        if seq == 1 or (seq % self._anchor_every) == 0:
            self._write_anchor(seq, entry_hash, body["timestamp"])
        return AuditRow(
            seq=seq,
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

    def _write_anchor(self, seq: int, entry_hash: str, timestamp: str) -> None:
        """Append a (seq, entry_hash, sig) triple to the sidecar anchor file.

        An attacker who truncates the SQLite tail must also truncate this
        file. Because we open it O_APPEND only, and (on platforms that
        support it) advertise it for OS-level immutability, this raises the
        bar materially.

        Customers wanting *real* tamper-proofing should pair this with the
        cloud control plane's S3 Object Lock anchor (CONTROL_PLANE.md).
        """
        import os as _os

        try:
            self._anchor_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return

        sig_b64 = ""
        if self._sign_enabled and self._keypair is not None:
            anchor_msg = f"{seq}|{entry_hash}|{timestamp}".encode("utf-8")
            sig = crypto.sign(self._keypair.secret_key, anchor_msg)
            sig_b64 = base64.b64encode(sig).decode("ascii")

        line = json.dumps(
            {
                "seq": seq,
                "entry_hash": entry_hash,
                "timestamp": timestamp,
                "signature_b64": sig_b64,
                "signing_algorithm": (
                    crypto.SIGNING_ALGORITHM if self._sign_enabled else None
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        # Open with O_APPEND so concurrent writers race-safely append, AND
        # the file cannot be truncated mid-write without explicit ftruncate.
        flags = _os.O_WRONLY | _os.O_CREAT | _os.O_APPEND
        try:
            fd = _os.open(self._anchor_path, flags, 0o600)
        except OSError:
            return
        try:
            _os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            _os.close(fd)
        try:
            _os.chmod(self._anchor_path, 0o600)
        except OSError:
            pass

    def verify_anchor(self) -> tuple[bool, int | None, str]:
        """Verify every anchor entry against the audit DB.

        Returns (ok, last_anchored_seq, message). An anchor seq whose
        entry_hash doesn't match the DB row at that seq → tampering detected.
        """
        if not self._anchor_path.exists():
            return (True, None, "no anchor file")
        public_key = self._keypair.public_key if self._keypair else None
        last_seq: int | None = None
        with open(self._anchor_path, "rb") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    return (False, last_seq, "anchor file contains invalid JSON")
                seq = entry.get("seq")
                anchored_hash = entry.get("entry_hash")
                ts = entry.get("timestamp")
                if not isinstance(seq, int) or not isinstance(anchored_hash, str):
                    return (False, last_seq, f"anchor entry malformed near seq={seq}")
                # Look up the row in the DB
                row = self.conn.execute(
                    "SELECT entry_hash FROM audit WHERE seq = ?", (seq,)
                ).fetchone()
                if row is None:
                    return (
                        False,
                        seq,
                        f"anchor at seq={seq} has no matching row "
                        "(audit log was truncated below this seq)",
                    )
                if row["entry_hash"] != anchored_hash:
                    return (
                        False,
                        seq,
                        f"anchor hash mismatch at seq={seq}: "
                        f"audit_db={row['entry_hash'][:16]}…, "
                        f"anchor={anchored_hash[:16]}…",
                    )
                # Verify the anchor signature too (defends against an
                # attacker editing the anchor file after acquiring the key).
                if public_key is not None and entry.get("signature_b64"):
                    sig = base64.b64decode(entry["signature_b64"])
                    msg = f"{seq}|{anchored_hash}|{ts}".encode("utf-8")
                    if not crypto.verify(public_key, msg, sig):
                        return (
                            False,
                            seq,
                            f"anchor signature invalid at seq={seq}",
                        )
                last_seq = seq
        return (True, last_seq, "ok")

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
