"""Shared dataclasses used across the proxy."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Direction(str, Enum):
    CLIENT_TO_SERVER = "c2s"
    SERVER_TO_CLIENT = "s2c"


class FrameKind(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    INVALID = "invalid"


@dataclass
class MCPFrame:
    """A single parsed JSON-RPC message flowing through the proxy."""

    raw: bytes
    payload: dict[str, Any]
    kind: FrameKind
    direction: Direction
    method: str | None = None  # e.g. "tools/call", "tools/list", "initialize"
    tool_name: str | None = None  # for tools/call requests
    rpc_id: int | str | None = None


class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Decision:
    """Output of the policy engine for a single frame."""

    type: DecisionType
    reason: str = ""
    rewritten_payload: dict[str, Any] | None = None  # populated for REDACT
    matched_rule: str | None = None
    notes: list[str] = field(default_factory=list)
