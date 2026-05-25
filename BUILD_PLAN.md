# mcp-firewall — v0 Build Plan

**Goal:** Ship an OSS MCP gateway proxy in 60 days that lands distribution
(stars + installs), validates the wedge with 3 design partners, and seeds the
threat-intel data flywheel that becomes the moat.

**Non-goal:** A perfect product. v0 is rough. Speed > polish.

---

## Why this repo exists

Per `mcp-firewall-memo.md` (in the parent Asterism repo): the MCP spec authors
themselves named "gateway and proxy patterns" as an open enterprise problem on
the 2026 roadmap. The official MCP Registry delegates security scanning to
upstream package registries. No dominant MCP-native security middleware exists
yet. The window is 18-30 months before Cloudflare/Palo Alto/Check Point absorb
it.

Strategy: **OSS data plane, commercial control plane.** Cloudflare/Snyk model.
This repo is the data plane.

---

## Architecture (v0)

```
┌──────────────────┐                        ┌──────────────────┐
│ MCP Client       │                        │ MCP Server       │
│ (Claude Desktop, │  stdio  / HTTP         │ (filesystem,     │
│  Cursor, Codex,  │ ◀────┐         ┌────▶ │  github, slack,  │
│  Claude Code)    │      │         │       │  custom...)      │
└──────────────────┘      ▼         ▼       └──────────────────┘
                    ┌──────────────────────┐
                    │  mcp-firewall proxy  │
                    │                      │
                    │  ┌────────────────┐  │
                    │  │ JSON-RPC parse │  │
                    │  └───────┬────────┘  │
                    │          ▼           │
                    │  ┌────────────────┐  │
                    │  │ Policy engine  │  │
                    │  └───────┬────────┘  │
                    │          ▼           │
                    │  ┌────────────────┐  │
                    │  │ Audit log      │  │
                    │  │ (SQLite, hash- │  │
                    │  │  chained)      │  │
                    │  └────────────────┘  │
                    └──────────────────────┘
```

The proxy is the **only** trusted intermediary. Everything else is data
flowing through it.

## Modules

| Module | Responsibility | LOC budget |
|---|---|---|
| `jsonrpc.py` | Parse / classify / serialize JSON-RPC 2.0 frames; recognize MCP method names | 150 |
| `policy.py` | Load YAML policy; evaluate against parsed frames; return Allow/Deny/Redact/Approve decisions | 250 |
| `audit.py` | SQLite-backed hash-chained append-only log; one row per intercepted frame | 150 |
| `stdio_proxy.py` | asyncio subprocess wrapper; bidirectional stream interception for stdio MCP | 200 |
| `http_proxy.py` | aiohttp reverse proxy for Streamable HTTP MCP | 250 |
| `cli.py` | `mcp-firewall up / init / inspect-log` commands | 150 |
| `__init__.py` + types | Shared dataclasses, `MCPFrame`, `Decision`, `PolicyResult` | 100 |
| **Total** | | **~1,250** |

Tests target ~600 LOC. Total v0 footprint: ~1,850 LOC.

## Policy schema (v0 surface)

```yaml
# policy.yaml
version: 1

# Block specific tool names by glob
deny_tools:
  - "shell.*"
  - "*.delete_*"

# Redact arguments matching regex before forwarding
redact_args:
  - pattern: 'sk-[A-Za-z0-9]{20,}'
    replacement: '[REDACTED_API_KEY]'
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}'
    replacement: '[REDACTED_EMAIL]'

# Tools that require human approval before execution
require_approval:
  - "filesystem.write_file"
  - "github.create_issue"
  - "slack.send_message"

# Detect tool-description drift (poisoning attacks)
tool_description_pinning:
  enabled: true
  on_drift: alert  # alert | block

# Audit log location
audit:
  path: ~/.mcp-firewall/audit.sqlite
```

## Acceptance criteria (v0 ships when)

- [x] Repo init with Apache 2.0 license, README, pyproject
- [ ] `pip install -e .` works on clean Python 3.11+ env
- [ ] `mcp-firewall init` creates a starter `policy.yaml`
- [ ] `mcp-firewall up --upstream "uvx mcp-server-filesystem ~/tmp"` proxies a real
      stdio MCP server end-to-end (Claude Desktop or `mcp inspector` can talk through it)
- [ ] `mcp-firewall up --listen :8080 --upstream-url https://example.com/mcp`
      proxies a Streamable HTTP MCP server end-to-end
- [ ] Every `tools/call` is logged to SQLite with hash-chained integrity
- [ ] At least one deny rule, one redact rule, and tool-description pinning
      demonstrably work in a smoke test
- [ ] `pytest` passes; one end-to-end test using a fixture MCP server
- [ ] README has 60-second install + run example

## Milestone schedule

| Day | Milestone |
|---|---|
| 1 (today) | Repo scaffold, jsonrpc.py, policy.py, audit.py, stdio_proxy.py, CLI, basic tests |
| 2-3 | http_proxy.py, end-to-end test against `mcp-server-filesystem` |
| 7 | Public GitHub repo, README polish, launch post on HN + MCP Discord |
| 14 | First 100 GitHub stars; iterate on issues |
| 30 | 1,000 stars target; first design partner deploying in staging |
| 60 | 3 paid design partners; commercial control plane scoped (separate repo) |

## What v0 is NOT

- Not a TLS-terminating gateway (we proxy whatever the upstream wants)
- Not a full SIEM (audit log is local SQLite; SIEM forwarders come in v0.2)
- Not authenticated multi-tenant SaaS (that's the control plane, separate repo)
- Not a prompt-injection ML classifier (regex + drift detection only in v0)
- Not a registry / package manager (we're a runtime proxy)

## Threat model (v0 mitigates)

| Threat | v0 mitigation |
|---|---|
| Tool poisoning / description drift | SHA256 pinning + alert/block on change |
| Token exfiltration via tool args | Regex-based redaction before forward |
| Unapproved destructive tool calls | `require_approval` blocks until ack |
| Audit log tampering | Hash chain — every row references prev row's hash |
| Prompt injection via tool output | Out of scope for v0 (needs classifier) |
| Confused deputy across servers | Out of scope for v0 (needs OAuth-aware policy) |
| SSRF via OAuth metadata discovery | Out of scope for v0 (HTTP transport hardening) |

## Repo layout

```
mcp-firewall/
├── BUILD_PLAN.md              # this file
├── README.md
├── LICENSE
├── pyproject.toml
├── .gitignore
├── src/mcp_firewall/
│   ├── __init__.py
│   ├── types.py
│   ├── jsonrpc.py
│   ├── policy.py
│   ├── audit.py
│   ├── stdio_proxy.py
│   ├── http_proxy.py
│   └── cli.py
├── tests/
│   ├── test_jsonrpc.py
│   ├── test_policy.py
│   ├── test_audit.py
│   └── test_e2e_stdio.py
└── examples/
    └── policy.yaml
```
