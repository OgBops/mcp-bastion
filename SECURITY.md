# Security Policy & Threat Model

This is a security product. The bar is "an exploit means the data path is
compromised." This document is what we promise, what we *don't* promise, how
we expect the product to be deployed, and how to report a vulnerability.

## Vulnerability disclosure

If you find a security issue, **please do not open a public GitHub issue.**
Email `security@<your-domain>` with:

- A description of the issue
- A proof of concept (or CVE-style reproducer)
- Your preferred name for the credit line
- Whether you want to coordinate a disclosure timeline

We'll acknowledge within 48 hours and aim to ship a fix within 7-30 days
depending on severity. Critical issues that put customer data at risk get
out-of-band patches.

## Threat model

### Trust boundaries

```
   ┌─────────────────────────────────────────────────────────────────┐
   │  Trust zone A: the operator's machine                           │
   │  ┌────────────────────┐   ┌──────────────────────────────────┐  │
   │  │  LLM client        │   │  upstream MCP server             │  │
   │  │  (UNTRUSTED — may  │   │  (UNTRUSTED — may be a malicious │  │
   │  │  be tricked by     │   │  server by adversary)            │  │
   │  │  prompt injection) │   │                                  │  │
   │  └────────────┬───────┘   └─────────────▲────────────────────┘  │
   │               │                          │                       │
   │  ┌────────────▼──────────────────────────┴────────────────────┐  │
   │  │  mcp-firewall (TRUSTED — this is the data plane)           │  │
   │  │                                                            │  │
   │  │  - Trusts the operator's policy.yaml  (TRUSTED INPUT)      │  │
   │  │  - Distrusts every byte from the LLM client and the MCP    │  │
   │  │    server                                                  │  │
   │  │  - Persists keys + audit log to filesystem (LOCAL TRUST)   │  │
   │  └────────────────────────────────────────────────────────────┘  │
   └─────────────────────────────────────────────────────────────────┘
```

### Attackers we defend against

| Attacker | Capability | Defense |
|---|---|---|
| **Malicious MCP server** | Crafts adversarial JSON-RPC frames, oversized payloads, deeply nested JSON, drift in tool descriptions | Bounded reads, JSON depth cap, tool-description SHA256 pinning, optional ML classifier |
| **Malicious LLM client** | Tries to flood the proxy or reach metadata endpoints | Bounded HTTP body, SSRF block list, hardened path-traversal handling |
| **Compromised tool description** | Embeds prompt-injection text in a tool spec | Pinning + ML classifier flag/block |
| **Local filesystem attacker (low-priv user)** | Tries to read the secret key or audit DB | Key dir 0700, secret 0600, audit DB 0600 |
| **Audit-log tamperer with full FS access** | Edits SQLite to backdate / delete entries | Hash chain + ML-DSA-44 PQC signatures + first-seen public key fingerprint pinning inside the DB |

### Attackers we explicitly do NOT defend against

| Attacker | Why we don't try |
|---|---|
| **Root on the host** | If they own the box, they own the proxy, the keys, and the audit log. Use a Nitro Enclave (`/attestation`) for hardware-rooted defense. |
| **A nation-state with a 0day in CPython / aiohttp** | Out of our control — keep deps current, run `pip-audit` in CI |
| **An attacker who exfiltrates secrets via the upstream MCP server's *legitimate* tool calls** | This is by design; the proxy redacts known patterns but cannot semantically distinguish "ls ~/.ssh" from "ls ~/Documents" without policy that says so |

## Hardening posture (v0.3+)

Implemented:
- **Bounded inputs** everywhere a malicious peer can send bytes:
  - stdio: `MAX_FRAME_BYTES` (default 1 MB) — `asyncio.StreamReader.readuntil`
    raises `LimitOverrunError` instead of OOMing
  - HTTP: `client_max_size = MAX_HTTP_BODY_BYTES` (default 4 MB)
  - JSON depth: `MAX_JSON_DEPTH` (default 64)
- **Regex DoS defense**:
  - Pattern length capped at `MAX_REGEX_PATTERN_LEN` (1 KB) at policy load
  - Input length to each substitution capped at `MAX_REGEX_INPUT_LEN` (64 KB)
  - Recursion depth in the redact walker capped at `MAX_REDACT_DEPTH` (64)
- **SSRF defense**:
  - Upstream URL pinned at startup (scheme + netloc never client-controlled)
  - Path traversal segments stripped from client requests
  - Block list for cloud metadata + link-local + IPv6 ULA
- **Crypto hardening**:
  - ML-DSA-44 (FIPS 204) signatures on every audit row
  - Atomic O_EXCL keypair generation (no TOCTOU)
  - First-seen public-key fingerprint pinned in the audit DB itself
  - Key directory 0700, secret 0600
- **HTTP listener defaults to 127.0.0.1**, with a stderr warning on 0.0.0.0
- **No `assert`-based runtime checks** — all enforcement is plain `if`

Configuration knobs (env vars; safe defaults):

```
MCP_FIREWALL_MAX_FRAME_BYTES=1048576
MCP_FIREWALL_MAX_HTTP_BODY_BYTES=4194304
MCP_FIREWALL_MAX_JSON_DEPTH=64
MCP_FIREWALL_MAX_REGEX_PATTERN_LEN=1024
MCP_FIREWALL_MAX_REGEX_INPUT_LEN=65536
MCP_FIREWALL_MAX_REDACT_DEPTH=64
MCP_FIREWALL_ALLOW_PRIVATE=0       # set to 1 to allow private/loopback upstreams (dev only)
```

## Deployment recommendations

### Local desktop (Claude Desktop / Cursor / VS Code)
- Install via venv; let the proxy own `~/.mcp-firewall/`
- Don't share the audit DB across users
- Audit log signature key never leaves the laptop

### Server / shared host
- Run as a dedicated unix user (`mcpf`) with no shell
- Mount `~/.mcp-firewall/` on a separate filesystem with quota
- Front the HTTP proxy with TLS (Caddy / nginx) and an auth proxy (Cloudflare
  Access, Tailscale, OIDC) — never expose the raw `--listen` to the internet
- Enable `--verbose` only if you've audited the policy for echo-of-secrets
  in `decision.reason`

### High-assurance (regulated industry)
- Build the Nitro Enclave image (`Dockerfile` + `nitro-cli build-enclave`)
- Customers query `GET /attestation?nonce=<random>` and verify against
  AWS Nitro root CA + your published PCRs
- Forward audit log to S3 with **Object Lock in compliance mode** for legal
  retention proofs (control-plane work; see `CONTROL_PLANE.md`)

## Known limits and trade-offs

1. **Truncating long arg strings to `MAX_REGEX_INPUT_LEN` before redaction**
   means a secret embedded past 64 KB of an arg is *not* redacted. The audit
   log still captures the original; pair this with content-aware tools (DLP,
   data classification) at the SIEM layer.

2. **The redact walker bails at `MAX_REDACT_DEPTH`** — secrets in deeply
   nested arg structures past 64 levels are NOT redacted in v0.3. The
   alternative was unbounded recursion, which is a worse trade.

3. **Verbose stderr logs may include `decision.reason`** which embeds tool
   names. If your tool naming convention includes secrets, *don't run with
   `--verbose` in production.*

4. **The hash chain detects truncation** via the public-key-fingerprint
   pin: if an attacker truncates the tail and re-signs forward with their
   own key, the pinned fingerprint won't match. But if they preserve the
   original key, only an external anchor (cloud control plane / S3 Object
   Lock) detects the truncation. v0.3 is local-only; the control plane
   closes that gap.

5. **No defense against root.** If `/dev/nsm` is unavailable (i.e., not
   inside a Nitro Enclave), an attacker with root on the host can read the
   secret key and forge audit rows. Use the enclave deployment shape for
   environments where root compromise is in scope.

## How we develop

- `pip-audit` runs in CI on every PR; clean tree as of v0.3.0 (no known
  CVEs in dependencies)
- 39 tests including a regression suite for every concrete finding from the
  v0.3 audit (`tests/test_security_hardening.py`)
- Each finding in this codebase is tagged in code comments by ID (C1, H4,
  M3, etc.) so reviewers can trace defenses back to the threat that motivated
  them
- We don't ship `--no-verify` shortcuts, `shell=True`, or `yaml.load`
  (we use `yaml.safe_load`)

## Audit history

| Date | Auditor | Findings | Status |
|---|---|---|---|
| 2026-05-26 | self-audit (pre-public-release) | 4 Critical, 6 High, 6 Medium, 3 Low | All Critical + High patched; Medium documented; Low triaged |

External audits welcome — see disclosure section above.
