# Control Plane — product spec

This document specifies the **commercial cloud product** that pairs with the
open-source `mcp-firewall` data-plane proxy. It belongs in a *separate
repository* (proposed: `mcp-firewall-cloud`), under a non-OSI source-available
license (Elastic v2 or BUSL).

> **Why a second repo:** the OSS data plane is the wedge — bottom-up adoption,
> permissive license, max distribution. The control plane is where revenue
> lives. Splitting them keeps the OSS contributors' contract clean and makes
> the commercial moat (multi-tenant aggregation, threat-intel network, audit
> retention, billing) clearly demarcated.

## Tenets

1. **The OSS proxy is fully usable without the control plane.** No coercion.
2. **Control-plane value compounds with adoption.** Threat intel + benchmarking
   improve with each customer.
3. **Customer data never leaves the customer's edge in plaintext.** Cloud
   ingest is event-shaped + differentially-private.
4. **Boring tech.** Postgres, S3, Cognito/SSO, no exotic stack.
5. **One-binary install for self-hosted on Day 1.** Many enterprise buyers
   require it before SaaS.

## Customer journey (commercial pitch)

| Stage | OSS data plane | Cloud control plane |
|---|---|---|
| 0 — try | `pip install mcp-firewall && mcp-firewall up` | — |
| 1 — adopt | Wrap MCP servers in Claude Desktop / Cursor / VS Code | Free tier: hosted policy management for 1 user |
| 2 — pilot | Same proxy, runs in staging | Team plan: shared policies, 30-day audit retention, SIEM forward |
| 3 — produce | Same proxy, runs in prod (optionally inside Nitro Enclave) | Enterprise: SSO/SAML, 7-year audit retention, threat-intel feed, design-partner support |

## Architecture

```
                        ┌──────────────────────────────────────────────┐
                        │  Cloud Control Plane (multi-tenant SaaS)     │
                        │                                              │
                        │  ┌──────────────┐   ┌──────────────────┐     │
                        │  │  Policy Mgmt │   │  Threat Intel    │     │
                        │  │  UI + API    │   │  Aggregator      │     │
                        │  └──────┬───────┘   └────────▲─────────┘     │
                        │         │                    │               │
                        │  ┌──────▼─────────┐   ┌──────┴─────────┐     │
                        │  │ Tenant Policy  │   │ Server Reputa- │     │
                        │  │ Postgres       │   │ tion Postgres  │     │
                        │  └────────────────┘   └────────────────┘     │
                        │                                              │
                        │  ┌────────────────────────────────────────┐  │
                        │  │ Audit Ingest API (S3 + DDB index)      │  │
                        │  └────────────────────────────────────────┘  │
                        └────────────▲─────────────────▲───────────────┘
                                     │ HTTPS+OAuth     │ HTTPS+OAuth
                                     │                 │
              ┌──────────────────────┴───┐         ┌───┴──────────────────┐
              │  Customer A edge         │         │  Customer B edge     │
              │  ┌───────────────────┐   │         │  ┌────────────────┐  │
              │  │ mcp-firewall OSS  │   │         │  │ mcp-firewall   │  │
              │  │ (proxy)           │   │         │  │ OSS (proxy)    │  │
              │  └───────┬───────────┘   │         │  └────────────────┘  │
              │          │ tail audit    │         │                      │
              │          │ + telemetry   │         │                      │
              │  ┌───────▼───────────┐   │         │                      │
              │  │ Edge Forwarder    │   │         │                      │
              │  │ (sidecar binary)  │   │         │                      │
              │  └───────────────────┘   │         │                      │
              └──────────────────────────┘         └──────────────────────┘
```

## Cloud services (Phase 1 — minimum viable)

### `policy-svc`
Hosted policy authoring, versioning, and distribution. Customers edit YAML in
a web UI; the service signs each version (Ed25519) and customer proxies pull
signed bundles via OAuth.

- **API:** `GET /v1/policies/{tenant_id}/current`, `PUT /v1/policies/{tenant_id}`,
  `GET /v1/policies/{tenant_id}/versions/{n}`
- **Storage:** Postgres `policies` table (tenant_id, version, yaml_text,
  signed_blob, signed_by, created_at)
- **Cache:** S3 (signed bundle), CloudFront in front
- **Auth:** OAuth 2.1 via Cognito or Auth0; per-tenant signing key in KMS

### `audit-ingest-svc`
Receives ML-DSA-signed audit rows from edge proxies. Verifies signatures
against the customer's published key. Stores the raw payload in S3 (tenant
prefix, object lock for retention) and indexes searchable fields in
DynamoDB.

- **API:** `POST /v1/audit/{tenant_id}/batch` (max 1MB per request, gzip)
- **Storage:**
  - S3: `s3://mcpf-audit/{tenant_id}/{yyyy}/{mm}/{dd}/{hour}/{seq}.jsonl.zst`
    with **Object Lock** in compliance mode for the retention period
  - DynamoDB index: `(tenant_id, ts)` for fast searches; partition by day
- **Retention:** 30 days (Team plan), 7 years (Enterprise plan with HIPAA
  attestation)
- **SIEM forward:** customer-configurable webhook + Kinesis Firehose
  destinations (Splunk HEC, Datadog, Sumo, Elastic)

### `threat-intel-svc`
The moat. Aggregates suspicious tool descriptions, server reputation
signals, and known-bad MCP server publishers across all customers.

- **Data flywheel:**
  1. Edge proxy detects something suspicious (drift, classifier hit, novel
     tool description from a server hash never seen before).
  2. Edge forwarder ships a **differentially private** event to ingest:
     SHA256 of tool description + classifier score + count, NOT the
     tool description plaintext.
  3. Aggregator decides: if N≥10 distinct customers see the same hash with
     score > threshold within 24h, the hash is published to the **threat
     intel feed**.
  4. All customer proxies subscribe to the feed; new feed entries become
     deny rules without any customer action.
- **API:** `GET /v1/intel/{tenant_id}/since?ts={ts}` returns delta of
  feed entries
- **Privacy:** differential privacy via the Google `differential-privacy`
  library; ε=1.0, δ=1e-9 default; never log per-customer events
  identifiably; aggregated counts only

### `reputation-svc`
Per-MCP-server reputation: known signers, known package hashes, known good
tool description SHA256s. Sourced from:
- Anthropic's official MCP Registry metadata
- npm/PyPI/Docker Hub package signatures
- Customer-attested "this server is trusted" declarations

API: `GET /v1/reputation/server/{server_id}` → score + provenance details.

### `attestation-verify-svc`
For customers running edge proxies inside Nitro Enclaves. Receives the
attestation document, validates against the AWS Nitro root CA, matches
PCRs against published `mcp-firewall` release artifacts, returns a signed
"verified" certificate the customer can present to auditors.

API: `POST /v1/attestation/verify` body=base64 attestation doc.

### `billing-svc`
Stripe integration. Per-seat pricing. Three plans:

| Plan | Price | Limits | Notes |
|---|---|---|---|
| Free | $0 | 1 user, local audit only, no cloud feed | Permanent |
| Team | $20/user/mo | Up to 25 users, 30-day audit retention, basic threat-intel feed | |
| Enterprise | Contact | SSO/SAML, 7y audit + Object Lock, full threat intel, attested execution support | $3k/mo+ floor |

## Edge Forwarder (lives in OSS data-plane repo as `mcp_firewall.cloud`)

A small module the proxy can opt into. Responsibilities:

1. **Pull** signed policy bundles from `policy-svc`. Verify signature against
   tenant's public key (configured once via `mcp-firewall login`). Hot-swap
   the in-memory `Policy` object on update.
2. **Push** audit rows to `audit-ingest-svc` in batches. Compress + sign each
   batch with the tenant's edge key.
3. **Push** differentially-private threat-intel events.
4. **Pull** threat-intel feed deltas; merge new deny rules into the live
   policy.

Failure modes are explicit: if `policy-svc` is unreachable, the proxy keeps
running with the last-known-good cached policy. If `audit-ingest-svc` is
unreachable, audit rows queue locally up to a configurable cap (default
1GB) and ship when connectivity returns.

## Phased rollout

| Phase | Weeks from v0.2 | Deliverables |
|---|---|---|
| P1 | 1-3 | `policy-svc` MVP + edge forwarder + login flow. No audit ingest yet. |
| P2 | 4-6 | `audit-ingest-svc` + S3 with Object Lock + DynamoDB index + SIEM webhook |
| P3 | 7-10 | `threat-intel-svc` aggregator + differentially-private events from edge |
| P4 | 11-14 | `attestation-verify-svc` + Nitro PCR catalog + first regulated customer |
| P5 | 15-18 | `billing-svc` + Stripe + first paid Team plan customer |
| P6 | 19-26 | Enterprise: SSO/SAML, audit Object Lock retention proofs, MSA/DPA |

## Stack choices (defended)

- **Python (FastAPI) + Postgres + Redis + S3 + DynamoDB + Kinesis Firehose**
  — boring, hireable, cheap to run.
- **Cognito or Auth0 for tenant SSO**, KMS for per-tenant signing keys.
- **Terraform + ECS Fargate** for deployment; one tenant-shared cluster, plus
  optional dedicated single-tenant deployments for Enterprise+regulated.
- **No Kafka in P1.** Kinesis Firehose covers SIEM forward; aggregation lives
  in scheduled Lambda batches. Add Kafka only if event volume blows past
  10k/s sustained.

## Why this is defensible

| Threat | Defense |
|---|---|
| Cloudflare ships a competing free tier | OSS data plane is already free; control plane competes on threat-intel quality + audit/compliance, not gateway features |
| Anthropic builds it into Claude Desktop | Anthropic ships clients, not multi-vendor cloud control planes; this works across Claude/Cursor/Codex/Copilot/Gemini equally |
| Palo Alto / Check Point / Cisco re-uses Lakera/Protect AI for MCP coverage | Their products are LLM-API-call focused; rebuilding for MCP semantics is a 12-month project. By then we have data flywheel. |
| A startup forks our OSS and undercuts us | Fine — they don't have the cross-customer threat intel; the edge of moat is the network effect, not the code |

## Customer-facing security commitments

- **Audit log immutability**: ML-DSA-44 signed at the edge + S3 Object Lock
  in compliance mode in the cloud. Even AWS root cannot retroactively edit.
- **Data minimization**: raw tool-call arguments are redacted at the edge
  per policy *before* leaving the customer's network. The cloud receives
  decisions + metadata, not plaintext.
- **Differential privacy on threat intel**: per-customer events are noised
  before aggregation. ε/δ parameters published per release.
- **Cryptographic key custody**: each customer's signing keys are generated
  in the customer's environment; the cloud never holds them.
- **TEE-attested edge** option: Enterprise customers can deploy the edge
  proxy in Nitro Enclaves for cryptographic execution integrity.

## Open questions (require founder decision)

1. **License**: Elastic v2 vs. BUSL vs. fully proprietary for the cloud repo?
   *Recommendation: BUSL with 4-year conversion to Apache 2.0, mirroring
   Sentry/Cockroach/HashiCorp.*
2. **Self-hosted Enterprise**: ship a single-binary helm-chart bundle on Day 1?
   *Recommendation: yes — many regulated buyers will not entertain SaaS.
   This means the cloud must be deployable on a customer's K8s.*
3. **Pricing anchor**: per-seat or per-MCP-server?
   *Recommendation: per-seat (Datadog model). Easier to forecast; avoids
   incentivizing customers to consolidate their MCP servers to game pricing.*
4. **Acquisition optionality**: keep the cloud closed-source from Day 1 to
   maximize value to acquirers, or open-core to maximize developer trust?
   *Recommendation: open-core (BUSL on the cloud repo). The core moat is
   the data, not the code; opening the code raises trust and adoption.*

---

**This spec is the bridge from "OSS proxy with 1,000 stars" to "category-defining
SaaS that gets acquired for $300-500M like Lakera/Protect AI did."** The next
six months of work, organized.
