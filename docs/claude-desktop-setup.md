# Wiring mcp-firewall into Claude Desktop

This guide turns mcp-firewall into the **default** wrapper for all your MCP
servers in Claude Desktop. Once installed, every tool call from Claude flows
through the firewall — same flow as the Cloudflare/Snyk model: opt-in your
infra, opt-out only if you want raw traffic.

## Prerequisites

- Claude Desktop installed (https://claude.ai/download)
- Python 3.11+ on `PATH`
- mcp-firewall installed (`pip install -e ".[dev]"` from this repo)

## Step 1 — generate a policy

```bash
mkdir -p ~/.mcp-firewall
mcp-firewall init -o ~/.mcp-firewall/policy.yaml
```

Edit `~/.mcp-firewall/policy.yaml` to taste. The starter policy denies
`shell.*` and `*.delete_*`, redacts API keys + emails, and pins tool
descriptions on first sight.

## Step 2 — generate the wrapped MCP server config

For a filesystem MCP server scoped to `~/tmp`:

```bash
mcp-firewall wrap filesystem -- uvx mcp-server-filesystem ~/tmp
```

That prints something like:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-firewall",
      "args": [
        "up",
        "--policy",
        "/Users/you/.mcp-firewall/policy.yaml",
        "--upstream",
        "uvx mcp-server-filesystem /Users/you/tmp"
      ]
    }
  }
}
```

## Step 3 — paste into Claude Desktop's config

Open `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac).

Merge the `mcpServers` block. If you already have entries, replace each
upstream command with a wrapped version — the firewall is generic and works
for any MCP server (filesystem, github, slack, etc.):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-firewall",
      "args": [
        "up", "--policy", "/Users/you/.mcp-firewall/policy.yaml",
        "--upstream", "uvx mcp-server-filesystem /Users/you/tmp"
      ]
    },
    "github": {
      "command": "mcp-firewall",
      "args": [
        "up", "--policy", "/Users/you/.mcp-firewall/policy.yaml",
        "--upstream", "npx @modelcontextprotocol/server-github"
      ],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..." }
    }
  }
}
```

## Step 4 — restart Claude Desktop

Fully quit (⌘Q) and relaunch. Claude will re-spawn each MCP server through
mcp-firewall.

## Step 5 — verify

Ask Claude something that triggers a tool call (e.g. "list files in /tmp").
Then in a terminal:

```bash
mcp-firewall inspect-log --policy ~/.mcp-firewall/policy.yaml --verify --limit 20
```

You should see one row per JSON-RPC frame, with `chain: OK` and ML-DSA-44
signatures on each.

## Troubleshooting

**Claude Desktop can't find `mcp-firewall`** — Claude Desktop spawns child
processes with a minimal `PATH`. Use the absolute path of the binary in the
`command` field:

```bash
which mcp-firewall   # e.g. /Users/you/.venv/bin/mcp-firewall
```

Replace `"command": "mcp-firewall"` with `"command": "/Users/you/.venv/bin/mcp-firewall"`.

**Tool calls fail with `denied by mcp-firewall`** — that's working as
intended; review your policy. Either loosen the `deny_tools` glob or add an
explicit `require_approval` rule and approve the call out-of-band (v0.3 will
add an interactive approval channel).

**Audit log empty** — confirm Claude Desktop actually restarted (not just
hidden). The MCP server is spawned per-window; each new conversation
re-initializes the connection.

## Cursor + VS Code

Same JSON shape, different file paths:

- **Cursor:** `~/.cursor/mcp.json`
- **VS Code (workspace):** `.vscode/mcp.json`
- **VS Code (user):** `~/Library/Application Support/Code/User/mcp.json` (Mac)

Use the same `mcp-firewall wrap` command to generate the snippet for any client.
