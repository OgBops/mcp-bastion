# mcp-firewall

**Open-source security gateway for the Model Context Protocol.**

Sits between your LLM agent (Claude Desktop, Cursor, Codex, Claude Code) and the
MCP servers it talks to. Inspects every JSON-RPC frame. Enforces a policy. Logs
every tool call to a tamper-evident audit trail.

> ⚠️ Alpha. Breaking changes expected. Don't deploy in prod yet.

## Why

MCP shipped November 2024. Adoption is everywhere (ChatGPT, Gemini, Copilot,
Cursor, Claude). The official MCP Registry [delegates security scanning to
upstream package registries](https://modelcontextprotocol.io/registry/about),
and the spec authors themselves named ["gateway and proxy
patterns"](https://modelcontextprotocol.io/development/roadmap) as an open
enterprise problem on the 2026 roadmap.

This is the gateway.

## What it does (v0)

- **Proxies stdio MCP servers** — wraps `uvx mcp-server-filesystem`, `npx
  @modelcontextprotocol/server-github`, etc.
- **Proxies Streamable HTTP MCP servers** — reverse-proxies any HTTP MCP
  endpoint
- **Parses every JSON-RPC frame** in both directions
- **Enforces YAML policy**: deny tools by glob, redact arguments by regex,
  require human approval for destructive tool calls
- **Pins tool descriptions** — alerts/blocks if a tool's description changes
  after first sight (mitigates [tool poisoning
  attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks))
- **Tamper-evident audit log** — SQLite, hash-chained, append-only

## Install

```bash
pip install mcp-firewall          # not yet published — for now use editable install
# or, from source:
git clone https://github.com/your-org/mcp-firewall
cd mcp-firewall
pip install -e ".[dev]"
```

## 60-second demo

```bash
# 1. Generate a starter policy
mcp-firewall init > policy.yaml

# 2. Wrap a real MCP server
mcp-firewall up \
  --policy policy.yaml \
  --upstream "uvx mcp-server-filesystem /tmp"

# 3. In another shell, talk to it via stdio with the MCP inspector
npx @modelcontextprotocol/inspector mcp-firewall up --upstream "uvx mcp-server-filesystem /tmp"

# 4. Inspect the audit log
mcp-firewall inspect-log
```

## HTTP mode

```bash
mcp-firewall up \
  --policy policy.yaml \
  --listen 127.0.0.1:8080 \
  --upstream-url https://my-mcp-server.example.com/mcp
```

## Example policy

```yaml
version: 1

deny_tools:
  - "shell.*"
  - "*.delete_*"

redact_args:
  - pattern: 'sk-[A-Za-z0-9]{20,}'
    replacement: '[REDACTED_API_KEY]'

require_approval:
  - "filesystem.write_file"
  - "github.create_issue"

tool_description_pinning:
  enabled: true
  on_drift: alert  # alert | block

audit:
  path: ~/.mcp-firewall/audit.sqlite
```

## Architecture

```
LLM client  ─▶  mcp-firewall  ─▶  MCP server
              (parse → policy → audit)
```

See [`BUILD_PLAN.md`](BUILD_PLAN.md) for module-level detail and the v0
acceptance criteria.

## What it does NOT do (yet)

- Prompt-injection ML classifier (regex + drift detection only)
- Confused-deputy protection across multiple OAuth-authorized MCP servers
- SIEM forwarding (audit log is local SQLite)
- Multi-tenant SaaS (that's the commercial control plane, separate repo)

These are roadmap items; PRs welcome.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
