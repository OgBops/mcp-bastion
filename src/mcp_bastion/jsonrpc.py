"""JSON-RPC 2.0 framing + MCP-specific method classification.

MCP uses JSON-RPC 2.0 over stdio (newline-delimited) and Streamable HTTP
(POST body or SSE event). This module:

- parses one frame at a time
- classifies it (request / response / notification)
- extracts MCP-relevant fields (method name, tool name for tools/call)
- serializes back to bytes for forwarding
"""

from __future__ import annotations

import json
from typing import Any

from .limits import MAX_FRAME_BYTES, MAX_JSON_DEPTH
from .types import Direction, FrameKind, MCPFrame

# MCP methods we care about for policy enforcement.
# https://modelcontextprotocol.io/specification/2025-11-25
MCP_REQUEST_METHODS = {
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "prompts/list",
    "prompts/get",
    "completion/complete",
    "logging/setLevel",
    "sampling/createMessage",
    "elicitation/create",
}

MCP_NOTIFICATION_METHODS = {
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/message",
    "notifications/resources/updated",
    "notifications/resources/list_changed",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
}


def parse_frame(raw: bytes, direction: Direction) -> MCPFrame:
    """Parse a single JSON-RPC frame. Never raises — returns INVALID on error.

    Hardening:
      - Refuses frames over MAX_FRAME_BYTES.
      - Caps JSON nesting depth to MAX_JSON_DEPTH (recursion DoS).
    """
    if len(raw) > MAX_FRAME_BYTES:
        return MCPFrame(raw=raw, payload={}, kind=FrameKind.INVALID, direction=direction)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return MCPFrame(raw=raw, payload={}, kind=FrameKind.INVALID, direction=direction)

    if _json_depth(payload) > MAX_JSON_DEPTH:
        return MCPFrame(raw=raw, payload={}, kind=FrameKind.INVALID, direction=direction)

    if not isinstance(payload, dict):
        return MCPFrame(raw=raw, payload={}, kind=FrameKind.INVALID, direction=direction)

    if payload.get("jsonrpc") != "2.0":
        return MCPFrame(
            raw=raw, payload=payload, kind=FrameKind.INVALID, direction=direction
        )

    has_method = "method" in payload
    has_id = "id" in payload
    has_result = "result" in payload
    has_error = "error" in payload

    method = payload.get("method") if has_method else None
    rpc_id = payload.get("id") if has_id else None

    if has_method and has_id:
        kind = FrameKind.REQUEST
    elif has_method and not has_id:
        kind = FrameKind.NOTIFICATION
    elif has_id and (has_result or has_error):
        kind = FrameKind.RESPONSE
    else:
        kind = FrameKind.INVALID

    tool_name = None
    if kind == FrameKind.REQUEST and method == "tools/call":
        params = payload.get("params") or {}
        if isinstance(params, dict):
            name = params.get("name")
            if isinstance(name, str):
                tool_name = name

    return MCPFrame(
        raw=raw,
        payload=payload,
        kind=kind,
        direction=direction,
        method=method,
        tool_name=tool_name,
        rpc_id=rpc_id,
    )


def serialize_frame(payload: dict[str, Any]) -> bytes:
    """Serialize back to newline-terminated UTF-8 (stdio convention)."""
    return (json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def make_error_response(
    rpc_id: int | str | None, code: int, message: str
) -> dict[str, Any]:
    """Build a JSON-RPC error response payload (for deny decisions)."""
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


# Standard JSON-RPC error codes + custom firewall codes
ERROR_FIREWALL_DENIED = -32001
ERROR_FIREWALL_APPROVAL_REQUIRED = -32002
ERROR_FIREWALL_DRIFT_BLOCKED = -32003


def _json_depth(node: Any, level: int = 0, cap: int = MAX_JSON_DEPTH + 1) -> int:
    """Iterative depth check that short-circuits at the cap.

    Avoids unbounded recursion (which itself would be a DoS) by tracking depth
    via an explicit stack and returning early as soon as we exceed the cap.
    """
    stack: list[tuple[Any, int]] = [(node, level)]
    max_depth = level
    while stack:
        cur, lvl = stack.pop()
        if lvl > max_depth:
            max_depth = lvl
        if max_depth >= cap:
            return max_depth
        if isinstance(cur, dict):
            for v in cur.values():
                stack.append((v, lvl + 1))
        elif isinstance(cur, list):
            for v in cur:
                stack.append((v, lvl + 1))
    return max_depth
