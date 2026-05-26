# mcp-firewall

**Open-source security gateway for the Model Context Protocol.**

Sits between your LLM agent (Claude Desktop, Cursor, Codex, Claude Code) and the
MCP servers it talks to. Inspects every JSON-RPC frame. Enforces a policy.
Logs every tool call to a PQC-signed, tamper-evident audit trail.

> **Status: v0.3.1 alpha.** 47 tests passing, security-audited, all
> Critical/High findings patched. API surface stable enough for design
> partners; backwards-incompatible changes will bump the minor version.

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
  endpoint, with SSRF block-listing (cloud metadata + link-local).
- **Parses every JSON-RPC frame** in both directions; bounded inputs so
  oversized frames cannot OOM the proxy.
- **Enforces YAML policy**: deny tools by glob, redact arguments by regex
  (with backtracking-safe `regex` package + per-call timeout), require
  human approval for destructive tool calls.
- **Pins tool descriptions** — alerts/blocks if a tool's description changes
  after first sight (mitigates [tool poisoning
  attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)).
- **Prompt-injection classifier** *(optional)* — fine-tuned DeBERTa scores
  every tool description and flags/blocks injection attempts.
- **Post-quantum signed audit log** — every row signed with NIST [ML-DSA-44
  (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final), SQLite-backed,
  hash-chained, append-only. Public-key fingerprint pinned inside the DB.
- **External anchor file** — every Nth row also written to a sidecar
  JSONL with `O_APPEND|0600` so tail truncation is detectable offline.
- **OS-keychain key custody** — secret signing key lives in macOS
  Keychain / Linux Secret Service / Windows Credential Locker by default.
- **Scrubbed log output** — tool names appear in logs and JSON-RPC errors
  as `tool#<8 hex>`, not raw. Tools whose names embed secrets don't leak.
- **Nitro Enclave attestation** — when run inside an AWS Nitro Enclave, the
  proxy exposes `/attestation` so customers can cryptographically prove the
  exact binary inspecting their MCP traffic.

## Install

```bash
# pip install mcp-firewall          # PyPI publish pending; install from source for now
git clone https://github.com/your-org/mcp-firewall
cd mcp-firewall
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
mcp-firewall --version              # → mcp-firewall, version 0.3.1
```

Optional extras:

```bash
pip install -e ".[classifier]"    # adds transformers + torch (~2GB) for prompt-injection detection
```

## 60-second demo

```bash
# 1. Generate a starter policy
mcp-firewall init -o policy.yaml

# 2. Wrap a real MCP server (stdio mode)
mcp-firewall up \
  --policy policy.yaml \
  --upstream "uvx mcp-server-filesystem /tmp" \
  --verbose

# 3. In another shell, drive it with Anthropic's MCP Inspector
npx @modelcontextprotocol/inspector \
  mcp-firewall up --policy policy.yaml --upstream "uvx mcp-server-filesystem /tmp"

# 4. Inspect the PQC-signed audit log
mcp-firewall inspect-log --policy policy.yaml --verify
```

To wire it into Claude Desktop, Cursor, or VS Code, see
[`docs/claude-desktop-setup.md`](docs/claude-desktop-setup.md). For the
quick wrap snippet:

```bash
mcp-firewall wrap filesystem -- uvx mcp-server-filesystem /tmp
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
docker build -t mcp-firewall:0.3.1 .
nitro-cli build-enclave --docker-uri mcp-firewall:0.3.1 --output-file mcp-firewall.eif
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
- SIEM forwarding (audit log is local SQLite + JSONL anchor)
- Multi-tenant SaaS — the commercial control plane lives in a *separate*
  repo; see [`CONTROL_PLANE.md`](CONTROL_PLANE.md) for the spec.
- Differential-privacy aggregation of threat intel across customers (control plane)
- Cross-machine S3-Object-Lock anchoring of the audit log (control plane)

These are roadmap items; PRs welcome.

## Security

This is a security product, so we hold ourselves to a higher bar than
"works for the demo." Every Critical and High finding from the v0.3
self-audit is patched and has a regression test. See:

- [`SECURITY.md`](SECURITY.md) — threat model, vulnerability disclosure,
  hardening posture, deployment recommendations
- [`CHANGELOG.md`](CHANGELOG.md) — release-by-release security history
- `tests/test_security_hardening.py` + `tests/test_v031_followups.py` —
  one regression test per finding

To report a vulnerability, email `security@<your-domain>` (do **not**
open a public GitHub issue).

## License

Apache 2.0. See [`LICENSE`](LICENSE).
