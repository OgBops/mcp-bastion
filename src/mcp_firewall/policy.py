"""Policy engine.

Loads a YAML policy, evaluates each parsed JSON-RPC frame, returns a Decision.
v0 supports four primitives:

  1. deny_tools         — glob pattern match on tool name
  2. redact_args        — regex substitution on tools/call arguments
  3. require_approval   — block destructive tools until approved out-of-band
  4. tool_description_pinning — SHA256 of tool descriptions; alert/block on drift
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .types import Decision, DecisionType, FrameKind, MCPFrame


@dataclass
class RedactRule:
    pattern: re.Pattern[str]
    replacement: str
    raw_pattern: str


@dataclass
class Policy:
    deny_tools: list[str] = field(default_factory=list)
    redact_rules: list[RedactRule] = field(default_factory=list)
    require_approval: list[str] = field(default_factory=list)
    pinning_enabled: bool = False
    pinning_on_drift: str = "alert"  # "alert" or "block"
    audit_path: Path = field(default_factory=lambda: Path("~/.mcp-firewall/audit.sqlite"))

    @classmethod
    def from_yaml(cls, path: Path) -> Policy:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        deny_tools = list(data.get("deny_tools", []) or [])
        require_approval = list(data.get("require_approval", []) or [])

        redact_rules: list[RedactRule] = []
        for entry in data.get("redact_args", []) or []:
            pattern = entry.get("pattern")
            replacement = entry.get("replacement", "[REDACTED]")
            if pattern:
                redact_rules.append(
                    RedactRule(
                        pattern=re.compile(pattern),
                        replacement=replacement,
                        raw_pattern=pattern,
                    )
                )

        pinning_cfg = (data.get("tool_description_pinning") or {})
        pinning_enabled = bool(pinning_cfg.get("enabled", False))
        pinning_on_drift = str(pinning_cfg.get("on_drift", "alert")).lower()
        if pinning_on_drift not in {"alert", "block"}:
            pinning_on_drift = "alert"

        audit_cfg = data.get("audit") or {}
        audit_path = Path(audit_cfg.get("path", "~/.mcp-firewall/audit.sqlite")).expanduser()

        return cls(
            deny_tools=deny_tools,
            redact_rules=redact_rules,
            require_approval=require_approval,
            pinning_enabled=pinning_enabled,
            pinning_on_drift=pinning_on_drift,
            audit_path=audit_path,
        )


def _match_glob_any(name: str, patterns: list[str]) -> str | None:
    """Return the first matching pattern, else None."""
    for pat in patterns:
        if fnmatch.fnmatchcase(name, pat):
            return pat
    return None


class PolicyEngine:
    """Evaluates frames against a Policy. Stateful: tracks pinned tool descriptions."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        # Local pin store. Production would persist this; v0 keeps it in-process
        # plus persists in SQLite via record_pin().
        self._pins: dict[str, str] = {}  # tool_name -> sha256(description)
        self._pin_db: sqlite3.Connection | None = None

    def attach_pin_store(self, db: sqlite3.Connection) -> None:
        """Persist tool description pins to SQLite for cross-restart durability."""
        self._pin_db = db
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_pins (
                tool_name TEXT PRIMARY KEY,
                description_sha256 TEXT NOT NULL,
                first_seen_at TEXT NOT NULL
            )
            """
        )
        db.commit()
        for row in db.execute("SELECT tool_name, description_sha256 FROM tool_pins"):
            self._pins[row[0]] = row[1]

    def evaluate(self, frame: MCPFrame) -> Decision:
        """Decide what to do with a single frame."""
        if frame.kind == FrameKind.INVALID:
            return Decision(type=DecisionType.ALLOW, reason="non-mcp frame, pass through")

        # tools/list response: pin or detect drift
        if (
            frame.kind == FrameKind.RESPONSE
            and self.policy.pinning_enabled
        ):
            drift = self._check_tools_list_drift(frame)
            if drift is not None:
                return drift

        # tools/call request: deny / redact / require approval
        if frame.kind == FrameKind.REQUEST and frame.method == "tools/call":
            return self._evaluate_tools_call(frame)

        return Decision(type=DecisionType.ALLOW, reason="default allow")

    # ---- internals ----

    def _evaluate_tools_call(self, frame: MCPFrame) -> Decision:
        tool = frame.tool_name or ""

        if (matched := _match_glob_any(tool, self.policy.deny_tools)) is not None:
            return Decision(
                type=DecisionType.DENY,
                reason=f"tool '{tool}' matched deny rule '{matched}'",
                matched_rule=matched,
            )

        if (matched := _match_glob_any(tool, self.policy.require_approval)) is not None:
            return Decision(
                type=DecisionType.REQUIRE_APPROVAL,
                reason=f"tool '{tool}' requires human approval (rule '{matched}')",
                matched_rule=matched,
            )

        # Redaction. We deep-copy params and walk all string leaves.
        if self.policy.redact_rules:
            new_payload = copy.deepcopy(frame.payload)
            params = new_payload.get("params") or {}
            args = params.get("arguments") if isinstance(params, dict) else None
            redacted, count = _redact_in_place(args, self.policy.redact_rules)
            if count > 0:
                # Reflect possibly-replaced root back
                if isinstance(params, dict):
                    params["arguments"] = redacted
                    new_payload["params"] = params
                return Decision(
                    type=DecisionType.REDACT,
                    reason=f"redacted {count} match(es) in tool arguments",
                    rewritten_payload=new_payload,
                )

        return Decision(type=DecisionType.ALLOW, reason="no rule matched")

    def _check_tools_list_drift(self, frame: MCPFrame) -> Decision | None:
        """Look for tools/list responses; pin or detect drift."""
        result = frame.payload.get("result")
        if not isinstance(result, dict):
            return None
        tools = result.get("tools")
        if not isinstance(tools, list):
            return None

        drifted: list[str] = []
        notes: list[str] = []
        for t in tools:
            if not isinstance(t, dict):
                continue
            name = t.get("name")
            description = t.get("description", "") or ""
            if not isinstance(name, str):
                continue
            digest = hashlib.sha256(description.encode("utf-8")).hexdigest()
            prior = self._pins.get(name)
            if prior is None:
                self._pins[name] = digest
                self._persist_pin(name, digest)
                notes.append(f"pinned new tool '{name}'")
            elif prior != digest:
                drifted.append(name)

        if not drifted:
            return Decision(type=DecisionType.ALLOW, reason="; ".join(notes) or "tools list ok")

        # Drift detected
        if self.policy.pinning_on_drift == "block":
            return Decision(
                type=DecisionType.DENY,
                reason=f"tool description drift detected for: {', '.join(drifted)}",
                matched_rule="tool_description_pinning",
                notes=drifted,
            )
        return Decision(
            type=DecisionType.ALLOW,
            reason=f"DRIFT ALERT for: {', '.join(drifted)} (allowed; alert mode)",
            matched_rule="tool_description_pinning",
            notes=drifted,
        )

    def _persist_pin(self, tool_name: str, digest: str) -> None:
        if self._pin_db is None:
            return
        from datetime import datetime, timezone

        self._pin_db.execute(
            "INSERT OR REPLACE INTO tool_pins (tool_name, description_sha256, first_seen_at) "
            "VALUES (?, ?, ?)",
            (tool_name, digest, datetime.now(timezone.utc).isoformat()),
        )
        self._pin_db.commit()


def _redact_in_place(node: Any, rules: list[RedactRule]) -> tuple[Any, int]:
    """Walk a JSON-ish structure; apply regex substitutions to all string leaves.

    Returns (possibly-new-root, total_substitution_count).
    """
    if isinstance(node, str):
        new = node
        total = 0
        for r in rules:
            new, n = r.pattern.subn(r.replacement, new)
            total += n
        return new, total
    if isinstance(node, list):
        out: list[Any] = []
        total = 0
        for item in node:
            new_item, n = _redact_in_place(item, rules)
            out.append(new_item)
            total += n
        return out, total
    if isinstance(node, dict):
        out_d: dict[Any, Any] = {}
        total = 0
        for k, v in node.items():
            new_v, n = _redact_in_place(v, rules)
            out_d[k] = new_v
            total += n
        return out_d, total
    return node, 0
