"""End-to-end stdio proxy smoke test.

Drives a fake MCP server (a Python subprocess that echoes a tools/list response
and a tools/call response) through the StdioProxy and verifies the policy
engine intercepts a denied tool.

We don't run the full asyncio CLI here — we exercise the policy engine + audit
log on real parsed frames the same way the proxy does, plus a subprocess
roundtrip to confirm the parsing pipeline isn't lying.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from mcp_firewall.audit import AuditLog
from mcp_firewall.jsonrpc import parse_frame, serialize_frame
from mcp_firewall.policy import Policy, PolicyEngine
from mcp_firewall.types import DecisionType, Direction


def test_proxy_pipeline_blocks_denied_tool(tmp_path: Path):
    policy = Policy.from_dict({"deny_tools": ["shell.*"]})
    audit = AuditLog(tmp_path / "audit.sqlite")
    engine = PolicyEngine(policy)
    engine.attach_pin_store(audit.conn)

    # Simulate a frame that the stdio proxy would receive on its way
    # client -> server, and run it through the same evaluate+append path.
    raw = serialize_frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "shell.exec", "arguments": {"cmd": "rm -rf /"}},
        }
    )
    frame = parse_frame(raw, Direction.CLIENT_TO_SERVER)
    decision = engine.evaluate(frame)
    audit.append(frame, decision)

    assert decision.type == DecisionType.DENY
    rows = audit.tail(5)
    assert rows[0]["decision_type"] == "deny"
    assert rows[0]["tool_name"] == "shell.exec"
    audit.close()


def test_proxy_pipeline_redacts(tmp_path: Path):
    policy = Policy.from_dict(
        {
            "redact_args": [
                {"pattern": r"sk-[A-Za-z0-9]{20,}", "replacement": "[REDACTED]"}
            ]
        }
    )
    audit = AuditLog(tmp_path / "audit.sqlite")
    engine = PolicyEngine(policy)
    engine.attach_pin_store(audit.conn)

    raw = serialize_frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "github.create_issue",
                "arguments": {"body": "key=sk-abcdefghijklmnopqrstuvwx end"},
            },
        }
    )
    frame = parse_frame(raw, Direction.CLIENT_TO_SERVER)
    decision = engine.evaluate(frame)
    row = audit.append(frame, decision)

    assert decision.type == DecisionType.REDACT
    assert decision.rewritten_payload is not None
    body = decision.rewritten_payload["params"]["arguments"]["body"]
    assert "sk-" not in body
    # Audit log should record the *forwarded* (redacted) payload, not the original.
    payload = json.loads(row.payload_json)
    assert "sk-" not in payload["params"]["arguments"]["body"]
    audit.close()


@pytest.mark.asyncio
async def test_subprocess_roundtrip():
    """Spawn a fake MCP server, send it a frame, read its reply.

    This proves the asyncio subprocess plumbing works; it does NOT exercise
    the StdioProxy class directly (which owns parent stdio and is awkward to
    drive from a test). The full proxy is exercised by the integration smoke
    in the README — this test guards the framing.
    """
    fake_server = (
        "import sys, json\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    resp = {'jsonrpc':'2.0','id':msg['id'],"
        "'result':{'tools':[{'name':'echo','description':'echoes input'}]}}\n"
        "    sys.stdout.write(json.dumps(resp)+'\\n')\n"
        "    sys.stdout.flush()\n"
    )
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        fake_server,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    assert proc.stdin and proc.stdout
    proc.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
    await proc.stdin.drain()
    proc.stdin.close()
    line = await proc.stdout.readline()
    parsed = parse_frame(line, Direction.SERVER_TO_CLIENT)
    assert parsed.kind.value == "response"
    await proc.wait()
