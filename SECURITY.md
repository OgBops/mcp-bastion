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
   │  │  mcp-bastion (TRUSTED — this is the data plane)           │  │
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
MCP_BASTION_MAX_FRAME_BYTES=1048576
MCP_BASTION_MAX_HTTP_BODY_BYTES=4194304
MCP_BASTION_MAX_JSON_DEPTH=64
MCP_BASTION_MAX_REGEX_PATTERN_LEN=1024
MCP_BASTION_MAX_REGEX_INPUT_LEN=65536
MCP_BASTION_MAX_REDACT_DEPTH=64
MCP_BASTION_ALLOW_PRIVATE=0       # set to 1 to allow private/loopback upstreams (dev only)
```

## Deployment recommendations

### Local desktop (Claude Desktop / Cursor / VS Code)
- Install via venv; let the proxy own `~/.mcp-bastion/`
- Don't share the audit DB across users
- Audit log signature key never leaves the laptop

### Server / shared host
- Run as a dedicated unix user (`mcpf`) with no shell
- Mount `~/.mcp-bastion/` on a separate filesystem with quota
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

## Known limits and trade-offs (v0.3.1+)

The five trade-offs surfaced in the v0.3 audit have been closed:

1. ~~**Long-string truncation** — *fixed in v0.3.1.*~~ The redact walker now
   uses the `regex` package's `timeout=` API (with a chunked-window stdlib
   fallback). Strings of any length are scanned; runaway patterns abort
   within `REGEX_TIMEOUT_SECONDS` and the offending value is replaced with
   the redaction marker so no plaintext leaks.

2. ~~**Recursion-depth bail** — *fixed in v0.3.1.*~~ The redact walker is
   now iterative (explicit stack), bounded by a per-frame *node-count*
   budget (`MAX_REDACT_NODES = 1M`). Secrets at any tree depth are
   redacted; total work is bounded by node count, not tree shape.

3. ~~**Verbose logs echoed tool names** — *fixed in v0.3.1.*~~ All log
   output and outbound JSON-RPC error messages now use a stable hashed
   label (`tool#xxxxxxxx`, SHA256 first 8 hex chars) instead of the raw
   tool name. A tool whose name embeds a secret never appears in stderr or
   in a response to the client.

4. ~~**Truncation undetectable without external anchor** — *partially fixed
   in v0.3.1.*~~ Every Nth audit row is also written to a sidecar anchor
   file (`audit.anchor.jsonl`) on a separate path with `O_APPEND|0600` and
   per-row PQC signatures. `verify_anchor()` cross-checks the SQLite
   contents against the anchor — if the DB is truncated below an anchored
   seq, or any anchored hash doesn't match, we report it. Full
   tamper-proofing still requires an *out-of-process* anchor (S3 Object
   Lock, blockchain witness, control-plane); the local anchor closes the
   gap against in-process tampering and offline forensic review.

5. ~~**Root could read the secret key** — *partially fixed in v0.3.1.*~~ The
   secret key now lives in the **OS keychain** by default (macOS Keychain,
   Linux Secret Service, Windows Credential Locker via the `keyring`
   library). Root can still bypass — but every read leaves an OS-level
   audit trail. For environments where root compromise is in scope, use
   the **Nitro Enclave** deployment (`Dockerfile` + `nitro-cli build-enclave`)
   — keys generated inside an enclave never leave it, and a remote party
   verifies the enclave via `/attestation`. Set `MCP_BASTION_KEYRING=0`
   to force file storage (e.g., for Nitro Enclaves where no keychain
   exists).

## Residual limits (v0.3.1)

The defenses above raise the bar materially but do not make any of these
*impossible*:

- **A regex-timeout abort replaces the matched substring with the marker.**
  This is a safe default — we never forward unredacted bytes that may
  contain a secret — but it does mean a sufficiently malicious policy
  (which only an authenticated operator can write) plus a long input could
  cause data loss in non-secret payloads.

- **Local anchor file** is still on the same machine. An attacker with
  full FS access can rewrite both the DB and the anchor. The anchor's
  value is in offline forensics: an honest snapshot of the anchor file at
  time T proves what the DB looked like at T. Pair with the cloud control
  plane (`CONTROL_PLANE.md`) for cross-machine guarantees.

- **OS keychain bypass requires root or a debugger.** Every such bypass
  is logged by the OS keychain itself (macOS Keychain Access shows reads
  by app + signature). Don't rely on it as a single line of defense; pair
  with EDR / endpoint monitoring.

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
