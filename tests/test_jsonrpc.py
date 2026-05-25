import json

from mcp_firewall.jsonrpc import parse_frame, serialize_frame, make_error_response
from mcp_firewall.types import Direction, FrameKind


def _b(payload: dict) -> bytes:
    return (json.dumps(payload) + "\n").encode("utf-8")


def test_parse_request_with_id():
    p = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    f = parse_frame(_b(p), Direction.CLIENT_TO_SERVER)
    assert f.kind == FrameKind.REQUEST
    assert f.method == "tools/list"
    assert f.rpc_id == 1
    assert f.tool_name is None


def test_parse_notification_no_id():
    p = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    f = parse_frame(_b(p), Direction.CLIENT_TO_SERVER)
    assert f.kind == FrameKind.NOTIFICATION
    assert f.method == "notifications/initialized"
    assert f.rpc_id is None


def test_parse_response_with_result():
    p = {"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}
    f = parse_frame(_b(p), Direction.SERVER_TO_CLIENT)
    assert f.kind == FrameKind.RESPONSE
    assert f.rpc_id == 7
    assert f.method is None


def test_parse_response_with_error():
    p = {"jsonrpc": "2.0", "id": 7, "error": {"code": -32600, "message": "bad"}}
    f = parse_frame(_b(p), Direction.SERVER_TO_CLIENT)
    assert f.kind == FrameKind.RESPONSE


def test_parse_tools_call_extracts_tool_name():
    p = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "filesystem.read_file", "arguments": {"path": "/tmp/x"}},
    }
    f = parse_frame(_b(p), Direction.CLIENT_TO_SERVER)
    assert f.kind == FrameKind.REQUEST
    assert f.method == "tools/call"
    assert f.tool_name == "filesystem.read_file"


def test_parse_invalid_json():
    f = parse_frame(b"not json\n", Direction.CLIENT_TO_SERVER)
    assert f.kind == FrameKind.INVALID


def test_parse_missing_jsonrpc():
    f = parse_frame(_b({"id": 1, "method": "x"}), Direction.CLIENT_TO_SERVER)
    assert f.kind == FrameKind.INVALID


def test_serialize_roundtrip():
    p = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    raw = serialize_frame(p)
    assert raw.endswith(b"\n")
    parsed = parse_frame(raw, Direction.CLIENT_TO_SERVER)
    assert parsed.method == "tools/list"


def test_make_error_response_shape():
    p = make_error_response(42, -32001, "denied")
    assert p == {
        "jsonrpc": "2.0",
        "id": 42,
        "error": {"code": -32001, "message": "denied"},
    }
