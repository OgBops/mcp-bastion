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

## What it does

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
- **Prompt-injection classifier** *(optional)* — fine-tuned DeBERTa scores
  every tool description and flags/blocks injection attempts
- **Post-quantum signed audit log** — every row signed with NIST [ML-DSA-44
  (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final), SQLite-backed,
  hash-chained, append-only
- **Nitro Enclave attestation** — when run inside an AWS Nitro Enclave, the
  proxy exposes `/attestation` so customers can cryptographically prove the
  exact binary inspecting their MCP traffic

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

## Optional features

### Prompt-injection classifier

```bash
pip install 'mcp-firewall[classifier]'  # adds transformers + torch (~2GB)
```

Then in policy.yaml:

```yaml
classifier:
  enabled: true
  threshold: 0.85
  on_match: block      # alert | block
  model: protectai/deberta-v3-base-prompt-injection-v2
```

The classifier lazy-loads on first use (~5s startup, ~50-100ms inference per
tool description). Recommended for high-trust environments where any
injection signal should block.

### Nitro Enclave attestation

```bash
docker build -t mcp-firewall:0.2.0 .
nitro-cli build-enclave --docker-uri mcp-firewall:0.2.0 --output-file mcp-firewall.eif
nitro-cli run-enclave --cpu-count 2 --memory 2048 --eif-path mcp-firewall.eif --enclave-cid 16
```

Customers verify the running binary with:

```bash
curl https://your-proxy/attestation?nonce=<random>
```

Outside an enclave, `/attestation` returns a structured "not in enclave"
response so the same code paths work everywhere.

## What it does NOT do (yet)

- Confused-deputy protection across multiple OAuth-authorized MCP servers
- SIEM forwarding (audit log is local SQLite)
- Multi-tenant SaaS (that's the commercial control plane, separate repo)
- Differential-privacy aggregation of threat intel across customers

These are roadmap items; PRs welcome.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
