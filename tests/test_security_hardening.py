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


# L1 — long strings are scanned end-to-end (no truncation), but with a
# wall-clock timeout that aborts catastrophic patterns.
def test_redact_handles_long_strings_end_to_end():
    from mcp_firewall import policy as pol

    rules = pol.Policy.from_dict(
        {"redact_args": [{"pattern": r"sk-[A-Za-z0-9]{20,}", "replacement": "[REDACTED]"}]}
    ).redact_rules
    # 200KB of filler with a secret near the END — past v0.3's truncation point.
    secret = "sk-" + "A" * 30
    payload = ("X" * 200_000) + " " + secret + " trailing"
    container = {"args": payload}
    out, count = pol._redact_in_place(container, rules)
    assert count == 1
    assert "sk-" not in out["args"]
    assert "[REDACTED]" in out["args"]


def test_redact_aborts_catastrophic_pattern():
    """An attacker-supplied pathological pattern times out instead of hanging."""
    from mcp_firewall import policy as pol

    # Classic ReDoS: (a+)+b against many a's
    rules = pol.Policy.from_dict(
        {"redact_args": [{"pattern": r"(a+)+b", "replacement": "[X]"}]}
    ).redact_rules
    payload = "a" * 60  # Long enough to cause catastrophic backtracking
    container = {"v": payload}
    import time

    t0 = time.monotonic()
    out, count = pol._redact_in_place(container, rules)
    elapsed = time.monotonic() - t0
    # Without timeout, this would hang for minutes. With timeout, well under 2s.
    assert elapsed < 2.0, f"redact took {elapsed:.1f}s — timeout not enforced"
    # Either the regex completed (no match) or the timeout marker landed.
    assert "v" in out


# L2 — iterative walker handles arbitrarily deep trees without recursion-
# limit failures, and successfully redacts secrets at the leaf.
def test_redact_handles_deep_tree():
    # 10,000 levels of nested lists — well past Python's 1000-frame default
    # recursion limit. Recursive walker would crash; iterative walker handles
    # it cleanly.
    cur: list = []
    root = {"r": cur}
    for _ in range(10_000):
        nxt: list = []
        cur.append(nxt)
        cur = nxt
    cur.append("sk-aaaaaaaaaaaaaaaaaaaaaaaa")
    rules = Policy.from_dict(
        {"redact_args": [{"pattern": r"sk-[A-Za-z0-9]{20,}", "replacement": "[X]"}]}
    ).redact_rules
    out, count = _redact_in_place(root, rules)
    assert count == 1, "deep secret should be redacted by iterative walker"
    # Walk back down to verify
    n = out["r"]
    for _ in range(10_000):
        n = n[0]
    assert n[0] == "[X]"


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
