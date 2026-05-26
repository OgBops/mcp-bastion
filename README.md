# mcp-bastion

**Open-source security gateway for the Model Context Protocol.**

Sits between your LLM agent (Claude Desktop, Cursor, Codex, Claude Code) and the
MCP servers it talks to. Inspects every JSON-RPC frame. Enforces a policy.
Logs every tool call to a PQC-signed, tamper-evident audit trail.

> **Status: v0.3.1 alpha.** 47 tests passing, security-audited, all
> Critical/High findings patched. API surface stable enough for design
> partners; backwards-incompatible changes will bump the minor version.

> **Note:** This project is independent and not affiliated with
> `ressl/mcp-firewall` or any other similarly-named project on PyPI or
> GitHub.

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

> PyPI publish is pending — install from source for now.

```bash
git clone https://github.com/OgBops/mcp-bastion.git
cd mcp-bastion
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
mcp-bastion --version
```

Expected output:

```
mcp-bastion, version 0.3.1
```

Optional: install the prompt-injection classifier (adds `transformers` + `torch`, ~2 GB):

```bash
pip install -e ".[classifier]"
```

## 60-second demo

**Step 1.** Generate a starter policy:

```bash
mcp-bastion init -o policy.yaml
```

**Step 2.** Wrap a real MCP server (stdio mode):

```bash
mcp-bastion up --policy policy.yaml --upstream "uvx mcp-server-filesystem /tmp" --verbose
```

**Step 3.** In another shell, drive it with Anthropic's MCP Inspector:

```bash
npx @modelcontextprotocol/inspector mcp-bastion up --policy policy.yaml --upstream "uvx mcp-server-filesystem /tmp"
```

**Step 4.** Inspect the PQC-signed audit log:

```bash
mcp-bastion inspect-log --policy policy.yaml --verify
```

### Try the realistic attack scenario

If you want to see `mcp-bastion` block a real-world attack class — a
malicious MCP server silently mutating a tool description weeks after
install — the repo ships a one-shot reproducer:

```bash
./examples/use-case-meridian/reproduce.sh
```

The full narrative is in [`docs/USE_CASE.md`](docs/USE_CASE.md).

### Wire it into Claude Desktop, Cursor, or VS Code

See [`docs/claude-desktop-setup.md`](docs/claude-desktop-setup.md). The
short version: generate a config snippet with

```bash
mcp-bastion wrap filesystem -- uvx mcp-server-filesystem /tmp
```

then paste the result into your client's MCP config file.

## HTTP mode

```bash
mcp-bastion up \
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
  path: ~/.mcp-bastion/audit.sqlite
```

## Architecture

```
LLM client  ─▶  mcp-bastion  ─▶  MCP server
              (parse → policy → audit)
```

See [`BUILD_PLAN.md`](BUILD_PLAN.md) for module-level detail and the v0
acceptance criteria.

## Optional features

### Prompt-injection classifier

```bash
pip install 'mcp-bastion[classifier]'  # adds transformers + torch (~2GB)
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
docker build -t mcp-bastion:0.3.1 .
nitro-cli build-enclave --docker-uri mcp-bastion:0.3.1 --output-file mcp-bastion.eif
nitro-cli run-enclave --cpu-count 2 --memory 2048 --eif-path mcp-bastion.eif --enclave-cid 16
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
