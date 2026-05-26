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
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .limits import (
    MAX_REDACT_DEPTH,
    MAX_REDACT_NODES,
    MAX_REGEX_PATTERN_LEN,
    REGEX_TIMEOUT_SECONDS,
)
from .types import Decision, DecisionType, FrameKind, MCPFrame

# Prefer the third-party `regex` package because it supports per-call
# timeouts (defends against catastrophic backtracking on adversarial input).
# Fall back to stdlib `re` with a chunked-window strategy when unavailable.
try:
    import regex as _regex_engine  # type: ignore[import-not-found]

    _HAVE_REGEX_TIMEOUT = True
except ImportError:  # pragma: no cover
    _regex_engine = re
    _HAVE_REGEX_TIMEOUT = False


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
    audit_path: Path = field(default_factory=lambda: Path("~/.mcp-bastion/audit.sqlite"))
    classifier_enabled: bool = False
    classifier_threshold: float = 0.85
    classifier_on_match: str = "alert"  # "alert" or "block"
    classifier_model: str = "protectai/deberta-v3-base-prompt-injection-v2"

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
            if not pattern:
                continue
            if not isinstance(pattern, str):
                raise ValueError(
                    f"redact_args.pattern must be a string, got {type(pattern).__name__}"
                )
            if len(pattern) > MAX_REGEX_PATTERN_LEN:
                raise ValueError(
                    f"redact_args.pattern too long ({len(pattern)} > "
                    f"{MAX_REGEX_PATTERN_LEN}); refusing to load policy"
                )
            try:
                compiled = _regex_engine.compile(pattern)
            except _regex_engine.error as e:
                raise ValueError(f"redact_args.pattern is invalid regex: {e}") from e
            redact_rules.append(
                RedactRule(pattern=compiled, replacement=replacement, raw_pattern=pattern)
            )

        pinning_cfg = (data.get("tool_description_pinning") or {})
        pinning_enabled = bool(pinning_cfg.get("enabled", False))
        pinning_on_drift = str(pinning_cfg.get("on_drift", "alert")).lower()
        if pinning_on_drift not in {"alert", "block"}:
            pinning_on_drift = "alert"

        audit_cfg = data.get("audit") or {}
        audit_path = Path(audit_cfg.get("path", "~/.mcp-bastion/audit.sqlite")).expanduser()

        cls_cfg = data.get("classifier") or {}
        classifier_enabled = bool(cls_cfg.get("enabled", False))
        classifier_threshold = float(cls_cfg.get("threshold", 0.85))
        classifier_on_match = str(cls_cfg.get("on_match", "alert")).lower()
        if classifier_on_match not in {"alert", "block"}:
            classifier_on_match = "alert"
        classifier_model = str(
            cls_cfg.get("model", "protectai/deberta-v3-base-prompt-injection-v2")
        )

        return cls(
            deny_tools=deny_tools,
            redact_rules=redact_rules,
            require_approval=require_approval,
            pinning_enabled=pinning_enabled,
            pinning_on_drift=pinning_on_drift,
            audit_path=audit_path,
            classifier_enabled=classifier_enabled,
            classifier_threshold=classifier_threshold,
            classifier_on_match=classifier_on_match,
            classifier_model=classifier_model,
        )


def _match_glob_any(name: str, patterns: list[str]) -> str | None:
    """Return the first matching pattern, else None."""
    for pat in patterns:
        if fnmatch.fnmatchcase(name, pat):
            return pat
    return None


def safe_tool_label(tool_name: str) -> str:
    """Stable, side-channel-safe label for a tool name.

    Used in stderr logs and JSON-RPC error responses so a tool whose name
    embeds a secret (rare but possible — think `db.query_<token>`) doesn't
    leak the secret to the client or the log file.

    Format: 'tool#<8 hex chars>'  — derived from SHA256(tool_name).
    """
    digest = hashlib.sha256(tool_name.encode("utf-8")).hexdigest()
    return f"tool#{digest[:8]}"


class PolicyEngine:
    """Evaluates frames against a Policy. Stateful: tracks pinned tool descriptions."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        # Local pin store. Production would persist this; v0 keeps it in-process
        # plus persists in SQLite via record_pin().
        self._pins: dict[str, str] = {}  # tool_name -> sha256(description)
        self._pin_db: sqlite3.Connection | None = None
        self._classifier = None
        if policy.classifier_enabled:
            from . import classifier as _cls

            self._classifier = _cls.get_classifier(policy.classifier_model)

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

        # tools/list response: pin / detect drift / classify
        if frame.kind == FrameKind.RESPONSE and (
            self.policy.pinning_enabled or self.policy.classifier_enabled
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
        label = safe_tool_label(tool) if tool else "tool#<unknown>"

        if (matched := _match_glob_any(tool, self.policy.deny_tools)) is not None:
            return Decision(
                type=DecisionType.DENY,
                reason=f"{label} matched deny rule '{matched}'",
                matched_rule=matched,
            )

        if (matched := _match_glob_any(tool, self.policy.require_approval)) is not None:
            return Decision(
                type=DecisionType.REQUIRE_APPROVAL,
                reason=f"{label} requires human approval (rule '{matched}')",
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
        """Look for tools/list responses; pin/detect drift, classify descriptions."""
        result = frame.payload.get("result")
        if not isinstance(result, dict):
            return None
        tools = result.get("tools")
        if not isinstance(tools, list):
            return None

        drifted: list[str] = []
        notes: list[str] = []
        suspicious: list[str] = []
        for t in tools:
            if not isinstance(t, dict):
                continue
            name = t.get("name")
            description = t.get("description", "") or ""
            if not isinstance(name, str):
                continue

            label = safe_tool_label(name)
            if self._classifier is not None:
                score = self._classifier.score(description)
                if score is not None and score >= self.policy.classifier_threshold:
                    suspicious.append(f"{label}={score:.2f}")

            digest = hashlib.sha256(description.encode("utf-8")).hexdigest()
            prior = self._pins.get(name)
            if prior is None:
                self._pins[name] = digest
                self._persist_pin(name, digest)
                notes.append(f"pinned new {label}")
            elif prior != digest:
                drifted.append(label)

        # Classifier match takes priority — it's a stronger signal than drift.
        if suspicious:
            reason = (
                f"prompt-injection classifier flagged tool description(s): "
                f"{', '.join(suspicious)} (threshold={self.policy.classifier_threshold})"
            )
            if self.policy.classifier_on_match == "block":
                return Decision(
                    type=DecisionType.DENY,
                    reason=reason,
                    matched_rule="prompt_injection_classifier",
                    notes=suspicious,
                )
            # alert mode falls through to drift handling but we surface the note.
            notes.append(f"CLASSIFIER ALERT: {', '.join(suspicious)}")

        if not drifted:
            return Decision(type=DecisionType.ALLOW, reason="; ".join(notes) or "tools list ok")

        if self.policy.pinning_on_drift == "block":
            return Decision(
                type=DecisionType.DENY,
                reason=f"tool description drift detected for: {', '.join(drifted)}",
                matched_rule="tool_description_pinning",
                notes=drifted,
            )
        return Decision(
            type=DecisionType.ALLOW,
            reason=f"DRIFT ALERT for: {', '.join(drifted)} (allowed; alert mode)"
            + (f"; {'; '.join(notes)}" if notes else ""),
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


def _redact_string(s: str, rules: list[RedactRule]) -> tuple[str, int]:
    """Apply regex substitutions with a per-call wall-clock budget.

    With the `regex` package, this uses native `timeout=` (kills runaway
    backtracking). With stdlib `re`, falls back to a chunked window so
    pathological patterns don't lock the proxy on long inputs.
    """
    total = 0
    out = s
    for r in rules:
        if _HAVE_REGEX_TIMEOUT:
            try:
                out, n = r.pattern.subn(
                    r.replacement, out, timeout=REGEX_TIMEOUT_SECONDS
                )
                total += n
            except _regex_engine.TimeoutError:
                # The pattern is pathological against this input. Replace the
                # whole string with the redaction marker to be safe — never
                # forward unredacted bytes that may contain a secret.
                out = r.replacement
                total += 1
        else:
            out, n = _chunked_subn(r, out)
            total += n
    return out, total


def _chunked_subn(rule: RedactRule, s: str) -> tuple[str, int]:
    """Stdlib-only: scan long strings in overlapping windows with a deadline."""
    from .limits import REDACT_WINDOW_BYTES

    if len(s) <= REDACT_WINDOW_BYTES:
        return rule.pattern.subn(rule.replacement, s)
    deadline = time.monotonic() + REGEX_TIMEOUT_SECONDS
    pieces: list[str] = []
    total = 0
    overlap = MAX_REGEX_PATTERN_LEN
    i = 0
    n = len(s)
    while i < n:
        if time.monotonic() > deadline:
            # Out of time; replace the rest with the marker rather than risk
            # forwarding a leak.
            pieces.append(rule.replacement)
            total += 1
            break
        end = min(i + REDACT_WINDOW_BYTES, n)
        chunk = s[i:end]
        replaced, m = rule.pattern.subn(rule.replacement, chunk)
        if i == 0:
            pieces.append(replaced)
        else:
            # Drop the leading `overlap` characters of the new chunk; they
            # were already covered by the previous window's tail.
            pieces.append(replaced[min(overlap, len(replaced)) :])
        total += m
        if end >= n:
            break
        i = end - overlap
    return "".join(pieces), total


def _redact_in_place(
    node: Any, rules: list[RedactRule], _depth: int = 0
) -> tuple[Any, int]:
    """Walk a JSON-ish structure iteratively; apply regex substitutions to
    every string leaf at any depth.

    Hardening:
      - Iterative (explicit stack) — handles arbitrarily deep trees without
        blowing the Python recursion limit.
      - Per-string regex timeout via the `regex` package (or chunked-window
        fallback) — handles arbitrarily long strings while bounding wall-
        clock time.
      - Total node budget — caps the *aggregate* work across the whole tree
        so adversarial fan-out (10k siblings of 10k siblings) can't DoS us.
    """
    # Build a deep-copied skeleton we can mutate as we descend, then rewire.
    # We don't deepcopy here because dict/list shells are cheap; we only
    # produce new strings.
    visited = 0
    # Sentinel containers so we have a single root we can swap.
    holder = {"root": node}
    # Stack entries: (parent_container, key_or_index)
    stack: list[tuple[Any, Any]] = [(holder, "root")]
    total_subs = 0
    while stack:
        if visited >= MAX_REDACT_NODES:
            # Stop walking; whatever wasn't visited stays as-is. Better than
            # an open-ended loop; the audit log captured the original frame.
            break
        parent, key = stack.pop()
        cur = parent[key]
        visited += 1
        if isinstance(cur, str):
            new_s, n = _redact_string(cur, rules)
            if n:
                parent[key] = new_s
                total_subs += n
        elif isinstance(cur, list):
            # Replace the list with a copy so we mutate independently of the
            # original payload (caller deep-copies the root, but lists nested
            # under it would still alias without this).
            new_list = list(cur)
            parent[key] = new_list
            for i in range(len(new_list)):
                stack.append((new_list, i))
        elif isinstance(cur, dict):
            new_d = dict(cur)
            parent[key] = new_d
            for k in list(new_d.keys()):
                stack.append((new_d, k))
        # Other JSON scalars (int, float, bool, None) are skipped.
    return holder["root"], total_subs
