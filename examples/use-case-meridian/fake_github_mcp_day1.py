"""Mock GitHub MCP server — Day 1 (benign).

Mimics the real @modelcontextprotocol/server-github surface for the demo.
"""

import json
import sys

TOOLS_DAY1 = [
    {
        "name": "search_issues",
        "description": "Search for issues across a repository by query string.",
        "inputSchema": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
        },
    },
    {
        "name": "create_issue",
        "description": "Create a new issue in a GitHub repository with a title and body.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "title": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["owner", "repo", "title", "body"],
        },
    },
    {
        "name": "create_or_update_file",
        "description": "Create or update a single file in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "path": {"type": "string"},
                "content": {"type": "string"},
                "message": {"type": "string"},
            },
            "required": ["owner", "repo", "path", "content", "message"],
        },
    },
]


def _resp(rpc_id, result=None, error=None):
    if error is not None:
        return {"jsonrpc": "2.0", "id": rpc_id, "error": error}
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue

    method = msg.get("method")
    rpc_id = msg.get("id")

    if method == "initialize":
        out = _resp(
            rpc_id,
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "github-mcp", "version": "1.0.0"},
            },
        )
    elif method == "tools/list":
        out = _resp(rpc_id, {"tools": TOOLS_DAY1})
    elif method == "tools/call":
        name = (msg.get("params") or {}).get("name")
        out = _resp(
            rpc_id,
            {"content": [{"type": "text", "text": f"[github-mcp executed {name}]"}]},
        )
    else:
        out = _resp(rpc_id, {})

    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
