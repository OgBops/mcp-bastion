import json
import sqlite3

from mcp_bastion.jsonrpc import parse_frame
from mcp_bastion.policy import Policy, PolicyEngine
from mcp_bastion.types import DecisionType, Direction


def _frame(payload: dict, direction=Direction.CLIENT_TO_SERVER):
    return parse_frame((json.dumps(payload) + "\n").encode("utf-8"), direction)


def test_default_policy_allows():
    engine = PolicyEngine(Policy.from_dict({}))
    f = _frame({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    d = engine.evaluate(f)
    assert d.type == DecisionType.ALLOW


def test_deny_tool_by_glob():
    engine = PolicyEngine(Policy.from_dict({"deny_tools": ["shell.*"]}))
    f = _frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "shell.exec", "arguments": {"cmd": "ls"}},
        }
    )
    d = engine.evaluate(f)
    assert d.type == DecisionType.DENY
    assert d.matched_rule == "shell.*"


def test_deny_tool_does_not_match_unrelated():
    engine = PolicyEngine(Policy.from_dict({"deny_tools": ["shell.*"]}))
    f = _frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "filesystem.read_file", "arguments": {"path": "/tmp"}},
        }
    )
    assert engine.evaluate(f).type == DecisionType.ALLOW


def test_redact_arg_by_regex():
    policy = Policy.from_dict(
        {
            "redact_args": [
                {"pattern": r"sk-[A-Za-z0-9]{20,}", "replacement": "[REDACTED]"}
            ]
        }
    )
    engine = PolicyEngine(policy)
    f = _frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "github.create_issue",
                "arguments": {"body": "leaked sk-aaaaaaaaaaaaaaaaaaaaaaaa key"},
            },
        }
    )
    d = engine.evaluate(f)
    assert d.type == DecisionType.REDACT
    assert d.rewritten_payload is not None
    body = d.rewritten_payload["params"]["arguments"]["body"]
    assert "sk-" not in body
    assert "[REDACTED]" in body


def test_require_approval_takes_precedence_over_redact():
    """Approval is more important than redaction; we should not silently rewrite + run."""
    policy = Policy.from_dict(
        {
            "require_approval": ["filesystem.write_file"],
            "redact_args": [{"pattern": r"secret", "replacement": "***"}],
        }
    )
    engine = PolicyEngine(policy)
    f = _frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "filesystem.write_file",
                "arguments": {"content": "the secret data"},
            },
        }
    )
    d = engine.evaluate(f)
    assert d.type == DecisionType.REQUIRE_APPROVAL


def test_tool_description_pinning_first_sight_allows():
    policy = Policy.from_dict({"tool_description_pinning": {"enabled": True}})
    engine = PolicyEngine(policy)
    engine.attach_pin_store(sqlite3.connect(":memory:"))
    f = _frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "fs.read", "description": "Reads a file"}]},
        },
        direction=Direction.SERVER_TO_CLIENT,
    )
    d = engine.evaluate(f)
    assert d.type == DecisionType.ALLOW


def test_tool_description_pinning_drift_alerts_then_blocks():
    # alert mode
    policy = Policy.from_dict(
        {"tool_description_pinning": {"enabled": True, "on_drift": "alert"}}
    )
    engine = PolicyEngine(policy)
    engine.attach_pin_store(sqlite3.connect(":memory:"))
    first = _frame(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "fs.read", "description": "v1"}]},
        },
        direction=Direction.SERVER_TO_CLIENT,
    )
    engine.evaluate(first)
    second = _frame(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": [{"name": "fs.read", "description": "v2 changed"}]},
        },
        direction=Direction.SERVER_TO_CLIENT,
    )
    d = engine.evaluate(second)
    assert d.type == DecisionType.ALLOW
    assert "DRIFT ALERT" in d.reason

    # block mode
    policy_block = Policy.from_dict(
        {"tool_description_pinning": {"enabled": True, "on_drift": "block"}}
    )
    engine2 = PolicyEngine(policy_block)
    engine2.attach_pin_store(sqlite3.connect(":memory:"))
    engine2.evaluate(first)
    d2 = engine2.evaluate(second)
    assert d2.type == DecisionType.DENY
    assert d2.matched_rule == "tool_description_pinning"
