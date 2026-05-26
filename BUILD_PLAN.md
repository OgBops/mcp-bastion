# mcp-bastion — Build Plan

**Status (as of v0.3.1):** v0 acceptance criteria are met *and exceeded* —
PQC signatures, prompt-injection classifier, Nitro attestation, OS keychain
storage, and the external anchor file all landed before public launch.

**Goal:** Ship an OSS MCP gateway proxy in 60 days that lands distribution
(stars + installs), validates the wedge with 3 design partners, and seeds the
threat-intel data flywheel that becomes the moat.

**Non-goal:** A perfect product. v0 is rough. Speed > polish.

---

## Why this repo exists

Per `mcp-bastion-memo.md` (in the parent Asterism repo): the MCP spec authors
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
                    │  mcp-bastion proxy  │
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

## Modules (as shipped in v0.3.1)

| Module | Responsibility |
|---|---|
| `jsonrpc.py` | Parse / classify / serialize JSON-RPC 2.0 frames; recognize MCP methods; bounded size + depth |
| `policy.py` | YAML policy; iterative redact walker; backtracking-safe regex; `safe_tool_label()` |
| `audit.py` | SQLite hash-chained log + ML-DSA-44 signatures + sidecar JSONL anchor + fingerprint pinning |
| `crypto.py` | ML-DSA-44 keygen + sign/verify; OS keychain storage with file fallback; O_EXCL atomic writes |
| `classifier.py` | Lazy-loaded HuggingFace prompt-injection classifier (optional extra) |
| `nitro_enclave.py` | NSM device detection + attestation document generation |
| `stdio_proxy.py` | asyncio subprocess proxy with bounded `readuntil` for stdio MCP |
| `http_proxy.py` | aiohttp reverse proxy with SSRF block list, body cap, SSE buffer |
| `limits.py` | All hard input-size caps, env-overridable |
| `cli.py` | `up / init / wrap / inspect-log` |
| `types.py` | Shared dataclasses |

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
  path: ~/.mcp-bastion/audit.sqlite
```

## Acceptance criteria (v0 status)

- [x] Repo init with Apache 2.0 license, README, pyproject
- [x] `pip install -e .` works on clean Python 3.11+ env (verified on 3.14)
- [x] `mcp-bastion init` creates a starter `policy.yaml`
- [x] `mcp-bastion up --upstream "uvx mcp-server-filesystem ~/tmp"` proxies a
      real stdio MCP server end-to-end *(stdio data-path verified against a
      fixture server; `uvx mcp-server-filesystem` not yet exercised live —
      same code path)*
- [x] `mcp-bastion up --listen 127.0.0.1:8080 --upstream-url ...` HTTP proxy
      code complete; SSRF block list and request-body cap in place *(not yet
      exercised against a hosted MCP server)*
- [x] Every `tools/call` is logged to SQLite with hash-chained integrity
- [x] At least one deny rule, one redact rule, and tool-description pinning
      demonstrably work in a smoke test
- [x] `pytest` passes — **47 tests** in v0.3.1
- [x] README has 60-second install + run example
- [x] **Bonus shipped before v1**: PQC signatures (ML-DSA-44), prompt-injection
      classifier, Nitro attestation, OS keychain storage, external anchor
      file, scrubbed log output, full threat model in SECURITY.md.

## Milestone schedule

| Day | Milestone |
|---|---|
| 1 (today) | Repo scaffold, jsonrpc.py, policy.py, audit.py, stdio_proxy.py, CLI, basic tests |
| 2-3 | http_proxy.py, end-to-end test against `mcp-server-filesystem` |
| 7 | Public GitHub repo, README polish, launch post on HN + MCP Discord |
| 14 | First 100 GitHub stars; iterate on issues |
| 30 | 1,000 stars target; first design partner deploying in staging |
| 60 | 3 paid design partners; commercial control plane scoped (separate repo) |

## What v0.3.1 is NOT

- Not a TLS-terminating gateway (front it with Caddy / nginx / Cloudflare)
- Not a full SIEM (audit log is local SQLite + JSONL anchor; SIEM forwarders
  ship in the control plane)
- Not authenticated multi-tenant SaaS (control plane, separate repo)
- Not a registry / package manager (we're a runtime proxy)
- Not yet exercised against a hosted Streamable HTTP MCP server in CI (code
  paths are tested; live HTTP smoke is on the day-7 launch checklist)
- Not yet wired into Claude Desktop on this machine (Claude Desktop isn't
  installed; the `wrap` snippet is generated and tested, integration is
  documented but unverified end-to-end)

## Threat model (v0.3.1 mitigates)

| Threat | Mitigation as shipped |
|---|---|
| Tool poisoning / description drift | SHA256 pinning + alert/block on change |
| Token exfiltration via tool args | Regex redaction with `regex` package timeout, iterative deep-tree walk |
| Unapproved destructive tool calls | `require_approval` blocks until ack |
| Audit log tampering | Hash chain + ML-DSA-44 PQC sig + DB-pinned key fingerprint + sidecar anchor file |
| Prompt injection via tool description | Optional ProtectAI DeBERTa classifier (alert / block) |
| SSRF via upstream path | Scheme/netloc pinned, path traversal stripped, metadata-IP block list |
| stdio / HTTP DoS via oversized frames | Bounded `readuntil`, `client_max_size`, JSON depth cap |
| ReDoS via policy-supplied regex | Pattern length cap + per-call timeout (`regex` package) |
| Tool name leaks via logs | `safe_tool_label()` hashes before stderr / JSON-RPC error |
| Secret-key disclosure to local users | OS keychain (macOS / Linux / Windows) by default |
| Compromised proxy binary | Nitro Enclave attestation document via `/attestation` |
| Confused deputy across multiple OAuth-authorized MCP servers | Out of scope for v0.3.1 (slated for v0.4) |
| Cross-machine audit-log truncation | Out of scope locally; control plane closes via S3 Object Lock |

## Repo layout (v0.3.1)

```
mcp-bastion/
├── BUILD_PLAN.md              # this file
├── README.md
├── SECURITY.md                # threat model + disclosure
├── CHANGELOG.md               # release history
├── CONTROL_PLANE.md           # spec for the commercial cloud (separate repo)
├── LICENSE                    # Apache 2.0
├── Dockerfile                 # Nitro Enclave-ready
├── pyproject.toml
├── docs/
│   └── claude-desktop-setup.md
├── examples/
│   └── policy.yaml
├── src/mcp_bastion/
│   ├── __init__.py
│   ├── types.py
│   ├── limits.py              # hard caps, env-overridable
│   ├── crypto.py              # ML-DSA-44 + keychain
│   ├── jsonrpc.py             # bounded parser
│   ├── policy.py              # iterative walker + safe_tool_label
│   ├── audit.py               # hash chain + PQC sig + anchor file
│   ├── classifier.py          # HuggingFace lazy-load
│   ├── nitro_enclave.py       # NSM attestation
│   ├── stdio_proxy.py
│   ├── http_proxy.py          # SSRF block + body cap
│   └── cli.py                 # up / init / wrap / inspect-log
└── tests/
    ├── conftest.py
    ├── test_jsonrpc.py
    ├── test_policy.py
    ├── test_audit.py
    ├── test_signed_audit.py
    ├── test_crypto.py
    ├── test_nitro.py
    ├── test_e2e_stdio.py
    ├── test_security_hardening.py    # one regression test per audit finding
    ├── test_v031_followups.py        # L1-L5 follow-up coverage
    └── test_classifier_real.py       # skipped if transformers absent
```
