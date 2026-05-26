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

# Per-substitution regex wall-clock budget. The third-party `regex` module
# enforces this directly via its `timeout=` kwarg; with stdlib `re` we use
# chunked windows + per-window deadline checks.
REGEX_TIMEOUT_SECONDS: float = float(
    os.environ.get("MCP_FIREWALL_REGEX_TIMEOUT_SECONDS", "0.5")
)

# Max compiled regex pattern length to accept from policy YAML.
# A pathological pattern is short; legitimate ones are also short.
MAX_REGEX_PATTERN_LEN: int = _env_int("MCP_FIREWALL_MAX_REGEX_PATTERN_LEN", 1024)

# Stdlib-fallback only: chunked window size when scanning long strings.
# Adjacent windows overlap by MAX_REGEX_PATTERN_LEN to avoid splitting matches
# at boundaries. With the `regex` package we don't use this.
REDACT_WINDOW_BYTES: int = _env_int("MCP_FIREWALL_REDACT_WINDOW_BYTES", 64 * 1024)

# Bounded recursion is a worse trade-off than bounded *work*. v0.3.1 walks
# the JSON tree iteratively with a node-count cap.
MAX_REDACT_DEPTH: int = _env_int("MCP_FIREWALL_MAX_REDACT_DEPTH", 4096)

# Max total nodes the redact walker will visit per frame. This is the *real*
# DoS guard — a node-count budget bounds wall-clock time independently of
# tree shape.
MAX_REDACT_NODES: int = _env_int("MCP_FIREWALL_MAX_REDACT_NODES", 1_000_000)
