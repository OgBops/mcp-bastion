"""Hard input-size limits to prevent resource exhaustion attacks.

These bound every untrusted input the proxy reads. They are deliberately
generous for normal MCP traffic but tight enough to make memory-exhaustion
DoS infeasible.

Override via environment variables for unusual workloads, e.g.:
    MCP_FIREWALL_MAX_FRAME_BYTES=4194304
"""

from __future__ import annotations

import os


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if not val:
        return default
    try:
        return max(1, int(val))
    except ValueError:
        return default


# A single newline-delimited JSON-RPC frame on stdio.
# The MCP spec doesn't mandate a max but real frames rarely exceed 64KB.
# 1MB gives generous headroom for tool outputs while bounding memory.
MAX_FRAME_BYTES: int = _env_int("MCP_FIREWALL_MAX_FRAME_BYTES", 1 * 1024 * 1024)

# An entire HTTP POST body (one JSON-RPC message or a small batch).
MAX_HTTP_BODY_BYTES: int = _env_int("MCP_FIREWALL_MAX_HTTP_BODY_BYTES", 4 * 1024 * 1024)

# JSON-RPC nesting depth. JSON-RPC structure is shallow; legitimate tool
# arguments rarely exceed 10 levels.
MAX_JSON_DEPTH: int = _env_int("MCP_FIREWALL_MAX_JSON_DEPTH", 64)

# Per-substitution regex match wall-clock budget. Compiled regexes from
# user policy could be catastrophic; a per-call budget caps the damage.
# Implemented via re.match timeouts in Python 3.12+; we also enforce a
# pre-compile complexity check.
REGEX_TIMEOUT_SECONDS: float = float(
    os.environ.get("MCP_FIREWALL_REGEX_TIMEOUT_SECONDS", "0.5")
)

# Max compiled regex pattern length to accept from policy YAML.
# A pathological pattern is short; legitimate ones are also short.
MAX_REGEX_PATTERN_LEN: int = _env_int("MCP_FIREWALL_MAX_REGEX_PATTERN_LEN", 1024)

# Max length of input we'll feed to a single regex. Patterns like (a+)+b
# are exponential in input length; capping the input bounds worst-case.
MAX_REGEX_INPUT_LEN: int = _env_int("MCP_FIREWALL_MAX_REGEX_INPUT_LEN", 64 * 1024)

# Max recursion depth for the redact walker.
MAX_REDACT_DEPTH: int = _env_int("MCP_FIREWALL_MAX_REDACT_DEPTH", 64)
