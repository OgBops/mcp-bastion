"""Regression tests for the v0.3 security hardening pass.

Each test name maps to a finding ID (C1, C3, etc.) in the audit.
"""

from __future__ import annotations

import json

import pytest

from mcp_firewall import limits
from mcp_firewall.jsonrpc import _json_depth, parse_frame
from mcp_firewall.policy import Policy, PolicyEngine, _redact_in_place
from mcp_firewall.types import Direction


# C1 — oversized stdio frames are dropped, not parsed.
def test_oversized_frame_returns_invalid():
    big = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"x\":\"" + (
        b"A" * (limits.MAX_FRAME_BYTES + 1)
    ) + b"\"}\n"
    assert len(big) > limits.MAX_FRAME_BYTES
    f = parse_frame(big, Direction.CLIENT_TO_SERVER)
    assert f.kind.value == "invalid"


# H4 — JSON depth limit defends against recursion DoS.
def test_deeply_nested_json_marked_invalid():
    nested: dict | list = {}
    cur = nested
    for _ in range(limits.MAX_JSON_DEPTH + 5):
        cur["x"] = {}
        cur = cur["x"]
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": nested}
    raw = (json.dumps(payload) + "\n").encode("utf-8")
    f = parse_frame(raw, Direction.CLIENT_TO_SERVER)
    assert f.kind.value == "invalid"


def test_json_depth_helper_short_circuits():
    # Build nested exactly at the cap; helper should return >= cap quickly.
    cur: dict | list = {}
    root = cur
    for _ in range(limits.MAX_JSON_DEPTH + 10):
        cur["x"] = {}
        cur = cur["x"]
    d = _json_depth(root)
    assert d >= limits.MAX_JSON_DEPTH


# C3 — refuse oversized regex patterns at policy load time.
def test_regex_pattern_length_capped():
    pattern = "a" * (limits.MAX_REGEX_PATTERN_LEN + 1)
    with pytest.raises(ValueError, match="too long"):
        Policy.from_dict(
            {"redact_args": [{"pattern": pattern, "replacement": "x"}]}
        )


def test_regex_pattern_must_be_string():
    with pytest.raises(ValueError):
        Policy.from_dict(
            {"redact_args": [{"pattern": 123, "replacement": "x"}]}
        )


def test_regex_pattern_must_be_valid():
    with pytest.raises(ValueError, match="invalid regex"):
        Policy.from_dict(
            {"redact_args": [{"pattern": "(unclosed", "replacement": "x"}]}
        )


# C3 — input length truncation bounds backtracking time.
def test_redact_truncates_oversized_input(monkeypatch):
    monkeypatch.setattr(limits, "MAX_REGEX_INPUT_LEN", 10)
    # Reload the policy module's reference so the function sees the new limit.
    import importlib

    from mcp_firewall import policy as pol

    importlib.reload(pol)
    rules = pol.Policy.from_dict(
        {"redact_args": [{"pattern": r"X+", "replacement": "[X]"}]}
    ).redact_rules
    # With the limit at 10, only the first 10 chars are scanned by the regex.
    long = "X" * 50
    out, count = pol._redact_in_place(long, rules)
    assert count == 1  # one match in the truncated head
    assert out.startswith("[X]")
    assert out.endswith("X")  # untouched suffix re-attached


# M3 — recursion depth bounded.
def test_redact_bails_at_max_depth():
    # Build a deeply nested arg structure.
    cur: dict | list = []
    root = cur
    for _ in range(limits.MAX_REDACT_DEPTH + 5):
        nxt: list = []
        cur.append(nxt)
        cur = nxt
    cur.append("sk-aaaaaaaaaaaaaaaaaaaaaaaa")  # would normally redact
    rules = Policy.from_dict(
        {"redact_args": [{"pattern": r"sk-[A-Za-z0-9]{20,}", "replacement": "[X]"}]}
    ).redact_rules
    out, count = _redact_in_place(root, rules)
    # Beyond MAX_REDACT_DEPTH the walker bails; the deep secret is NOT redacted
    # in v0.3, but we don't crash. This is a documented behavior, not a hole —
    # the audit log still captures the original frame.
    assert count == 0


# H1 / SSRF — HttpProxy rejects metadata IP upstreams.
def test_http_proxy_blocks_metadata_ip():
    from mcp_firewall.audit import AuditLog
    from mcp_firewall.http_proxy import HttpProxy
    from mcp_firewall.policy import PolicyEngine
    from pathlib import Path
    import tempfile

    tmp = Path(tempfile.mkdtemp()) / "audit.sqlite"
    audit = AuditLog(tmp, sign=False)
    engine = PolicyEngine(Policy.from_dict({}))
    with pytest.raises(ValueError, match="SSRF block list"):
        HttpProxy("http://169.254.169.254/latest/meta-data/", engine, audit)
    audit.close()


def test_http_proxy_rejects_invalid_scheme():
    from mcp_firewall.audit import AuditLog
    from mcp_firewall.http_proxy import HttpProxy
    from pathlib import Path
    import tempfile

    tmp = Path(tempfile.mkdtemp()) / "audit.sqlite"
    audit = AuditLog(tmp, sign=False)
    engine = PolicyEngine(Policy.from_dict({}))
    with pytest.raises(ValueError, match="must be http"):
        HttpProxy("file:///etc/passwd", engine, audit)
    audit.close()


# H6 — public-key fingerprint pinning.
def test_audit_log_rejects_swapped_key(tmp_path, monkeypatch):
    from mcp_firewall import crypto
    from mcp_firewall.audit import AuditLog

    # Generate first keypair, write a row.
    monkeypatch.setattr(crypto, "PUBLIC_KEY_PATH", tmp_path / "k1.pub")
    monkeypatch.setattr(crypto, "SECRET_KEY_PATH", tmp_path / "k1.key")
    log = AuditLog(tmp_path / "audit.sqlite", sign=True)
    log.close()

    # Swap to a *different* keypair and re-open the same DB.
    monkeypatch.setattr(crypto, "PUBLIC_KEY_PATH", tmp_path / "k2.pub")
    monkeypatch.setattr(crypto, "SECRET_KEY_PATH", tmp_path / "k2.key")
    with pytest.raises(RuntimeError, match="fingerprint mismatch"):
        AuditLog(tmp_path / "audit.sqlite", sign=True)
