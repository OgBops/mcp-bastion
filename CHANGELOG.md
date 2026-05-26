# Changelog

All notable changes to mcp-bastion.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Roadmap (v0.4 candidates)
- Confused-deputy protection for multi-MCP-server OAuth flows
- Out-of-band approval channel (replace error-on-approval-required with a
  callback)
- Tool input-schema pinning (currently we pin only on description)
- Cross-machine audit-log anchoring via the cloud control plane

---

## [0.3.1] — 2026-05-26

### Closed all five "known limits" from v0.3 SECURITY.md

- **L1 — long-string redaction.** Replaced input truncation (was: 64 KB cap)
  with the third-party `regex` package's `timeout=` API. Strings of any
  length are scanned end-to-end; runaway patterns abort within
  `REGEX_TIMEOUT_SECONDS` and the offending value is replaced with the
  redaction marker (no plaintext leaks). Stdlib fallback uses chunked
  windows when the `regex` package isn't available.
- **L2 — deep-tree redaction.** Replaced recursive walker with iterative
  explicit-stack walker bounded by `MAX_REDACT_NODES` (1M default).
  Tested against 10,000-deep nested lists; secret at the leaf is correctly
  redacted with no `RecursionError`.
- **L3 — log scrubbing.** Added `safe_tool_label()` (SHA256 first 8 hex,
  format `tool#xxxxxxxx`). All `decision.reason` strings, stderr logs, and
  outbound JSON-RPC errors now use the hashed label. A tool whose name
  embeds a secret never appears in any output channel.
- **L4 — external audit anchor.** Every Nth audit row now also writes a
  triple `(seq, entry_hash, signature)` to a sidecar JSONL file with
  `O_APPEND|0600`. New `verify_anchor()` cross-checks SQLite content
  against the anchor and detects (a) tail truncation and (b) hash
  substitution.
- **L5 — OS-keychain key custody.** `ensure_keypair()` stores the ML-DSA-44
  secret key in macOS Keychain / Linux Secret Service / Windows Credential
  Locker via the `keyring` library by default. Public key still on disk.
  Set `MCP_BASTION_KEYRING=0` to force file storage (Nitro Enclaves /
  headless servers).

### Added
- `regex>=2024.0` and `keyring>=24.0` to runtime dependencies.
- `MAX_REDACT_NODES`, `REDACT_WINDOW_BYTES` knobs in `limits.py`.
- `tests/test_v031_followups.py` — 7 tests covering L1–L5.

### Changed
- `MAX_REDACT_DEPTH` raised from 64 to 4096 (it now bounds work-via-stack,
  not recursion-via-Python).
- `safe_tool_label()` is now public; `policy.py` and the proxy modules use
  it consistently.

### Removed
- `MAX_REGEX_INPUT_LEN` (no longer needed; replaced by per-call timeout).

---

## [0.3.0] — 2026-05-26

### Security audit + hardening pass

Self-audit found 4 Critical, 6 High, 6 Medium, 3 Low. All Critical + High
fixed in this release; each carries a regression test in
`tests/test_security_hardening.py`.

### Added — input bounds
- `limits.py` — central, env-overridable size caps:
  - `MAX_FRAME_BYTES` (1 MB) — single stdio frame
  - `MAX_HTTP_BODY_BYTES` (4 MB) — single HTTP POST body
  - `MAX_JSON_DEPTH` (64) — JSON nesting limit
  - `MAX_REGEX_PATTERN_LEN` (1 KB) — refuse oversized policy patterns
- Bounded `asyncio.StreamReader` buffer + `readuntil` with
  `LimitOverrunError` handling in stdio proxy.
- `aiohttp.web.Application(client_max_size=...)` in HTTP proxy.

### Added — SSRF defense
- HTTP proxy validates upstream URL at construction: scheme must be http(s),
  hostname must not be on the cloud-metadata / link-local block list.
- Client-supplied path is sanitized (drop `..`, drop empty segments, reject
  `://`, `//`, `\`) before being appended to the operator-pinned base URL.
- `MCP_BASTION_ALLOW_PRIVATE=1` env var allows private upstreams for dev.

### Added — tamper-evident audit
- ML-DSA-44 (FIPS 204) signature on every audit row.
- `audit_meta` table pins the public-key fingerprint on first row; refuses
  to use the DB if the fingerprint differs at open time (defends against
  attacker swapping both the SQLite file and the keypair).
- `O_EXCL` atomic keypair generation defeats TOCTOU races.
- Key directory chmod 0700, secret key 0600, audit DB 0600.

### Added — HTTP listener defaults
- `--listen :8080` defaults to `127.0.0.1`; binding to `0.0.0.0` prints a
  warning to stderr.
- Port range validated [1, 65535].

### Added — SSE
- Per-connection buffer for SSE stream parsing — frames split across chunk
  boundaries are no longer dropped.

### Changed
- All `assert self._session is not None` runtime checks replaced with
  explicit `if`/return so `python -O` doesn't strip them.

### Added
- `SECURITY.md` — threat model, vulnerability disclosure policy,
  hardening posture, deployment shapes, audit history.

---

## [0.2.1] — 2026-05-25

### Added
- `mcp-bastion wrap <name> -- <upstream>` — generates a paste-ready JSON
  snippet for Claude Desktop, Cursor, and VS Code MCP configs.
- `docs/claude-desktop-setup.md` — end-to-end install guide.
- `tests/test_classifier_real.py` — real-model regression suite (downloads
  ProtectAI DeBERTa, scores benign + adversarial samples).
- `CONTROL_PLANE.md` — 600-line product spec for the commercial cloud
  (separate repo).

### Fixed
- Classifier now triggers on `tools/list` responses regardless of whether
  pinning is enabled (was a gating bug). Verified end-to-end: real DeBERTa
  scored 1.000 on 3 of 4 obvious prompt-injection tool descriptions, 0.000
  on benign ones.

---

## [0.2.0] — 2026-05-25

### Added
- **PQC ML-DSA-44 signed audit log.** Every audit row signed via the
  `pqcrypto` library; `verify_chain()` checks both the SHA256 hash chain
  and each signature. Keypair auto-generated at `~/.mcp-bastion/keys/`.
- **Prompt-injection classifier (optional).** Lazy-loads
  `protectai/deberta-v3-base-prompt-injection-v2` from HuggingFace; scores
  every tool description on `tools/list` responses; `alert` or `block`
  modes via policy YAML. Behind the `[classifier]` extras.
- **Nitro Enclave attestation.** New `nitro_enclave.py` detects `/dev/nsm`,
  generates an attestation document via `aws-nitro-enclaves-nsm-api` when
  inside an enclave; structured fallback otherwise. New `/attestation` and
  `/healthz` HTTP endpoints. Dockerfile suitable for `nitro-cli build-enclave`.

### Changed
- `Policy.from_dict()` accepts a `classifier:` block (`enabled`, `threshold`,
  `on_match`, `model`).

---

## [0.1.0] — 2026-05-25

### Initial scaffold
- `jsonrpc.py` — JSON-RPC 2.0 framing + MCP method classification.
- `policy.py` — deny / redact / require-approval / tool-description pinning.
- `audit.py` — SQLite hash-chained, tamper-evident log.
- `stdio_proxy.py` — asyncio bidirectional stdio interception.
- `http_proxy.py` — aiohttp reverse proxy for Streamable HTTP MCP.
- `cli.py` — `mcp-bastion up / init / inspect-log`.
- 22 tests; end-to-end smoke against a fake MCP server.
- Apache 2.0 license.
