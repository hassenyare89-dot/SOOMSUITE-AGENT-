# Architecture

## 1. Services and trust zones

```
                    Internet
                       │
          ┌────────────┴─────────────┐
          │  edge (TLS, WAF, CDN)    │
          ├──────────────┬───────────┤
   widget / WhatsApp /   │           │ operators (OIDC + MFA)
   ingest webhooks       │           │
   ┌──────▼───────┐      │    ┌──────▼────────┐        ┌───────────┐
   │ api-gateway- │      │    │ api-gateway-  │        │   web     │
   │ public       │      │    │ admin (BFF)   │◄───────│ (Next.js) │
   └──┬────┬───┬──┘      │    └──┬─────────┬──┘        └───────────┘
      │    │   │ ingest only     │         │
      │    │   └─────────────┐   │         │
 SAMIIR zone (samiir_net)    │   │    FATMA zone (fatma_net, private)
 ┌──────────────────────┐    │   │   ┌──────────────────────────────────┐
 │ samiir-agent         │    └───┼──►│ security-ingest ──► fatma-soc    │
 │  ├─► crm             │        │   │ scanner-controller ─(Temporal)─► │
 │  ├─► scheduling      │◄───────┘   │    scanner-worker / malware-worker│
 │  ├─► knowledge       │            │ approvals                         │
 │  ├─► notifications   │            └──────────────────────────────────┘
 │  └─► whatsapp        │                     │
 └──────────┬───────────┘                     │
            └──────────────► audit ◄──────────┘  (hash-chained, append-only)
```

| Service | Zone | Purpose | DB role |
|---|---|---|---|
| api-gateway-public | edge | Widget sessions, WhatsApp webhook pass-through, signed ingest webhooks | none (Redis only) |
| api-gateway-admin | edge | OIDC login (PKCE + MFA), server-side sessions, CSRF, role-gated proxy, SSE | `svc_gateway_admin` |
| samiir-agent | SAMIIR | Conversation runtime, ToolGateway, guardrails | `svc_samiir` |
| crm | SAMIIR | Companies, contacts, opportunities, pipeline, tasks | `svc_crm` |
| scheduling | SAMIIR | Appointment types, slots, bookings, Google/M365 calendars | `svc_scheduling` |
| knowledge | SAMIIR | Approved documents, versioning, embeddings, pricing | `svc_knowledge` |
| notifications | shared | Email/WhatsApp outbox with retries and templates | `svc_notifications` |
| whatsapp | SAMIIR | Meta Cloud API send/receive, signature verification | `svc_whatsapp` |
| fatma-soc | FATMA | Detection, risk scoring, incidents, defence recommendations, FATMA analyst | `svc_fatma` |
| security-ingest | FATMA | Webhook auth, normalization, redaction, raw storage, malware quarantine | `svc_security_ingest` |
| scanner-controller | FATMA | Asset verification, 7-gate scan authorization, Temporal workflow start | `svc_scanner_controller` |
| scanner-worker | FATMA (isolated) | ZAP (spider + passive) and Nuclei (safe tags) in a sandbox | none |
| malware-worker | FATMA (isolated) | ClamAV + YARA against quarantined samples, no egress | none |
| approvals | governance | Payload-hash-bound, signed, single-use approvals; pre-approval policy | `svc_approvals` |
| audit | governance | Per-tenant hash chain, SIEM forwarding, verification | `svc_audit` |

## 2. Isolation layers (defence in depth)

A SAMIIR compromise, whether prompt injection or an RCE in `samiir-agent`, must not reach FATMA
capabilities. Each layer below enforces that on its own:

1. **Network.** Compose uses segmented networks (`samiir_net`, `fatma_net`, `ingest_net`,
   `samiir_data`, `fatma_data`, `edge_cache`, `malware_net`, …). Kubernetes uses default-deny
   NetworkPolicies generated from the same caller table plus Istio `AuthorizationPolicy`.
   Verified empirically: `samiir-agent` cannot resolve `fatma-soc`, `scanner-controller`,
   `approvals` or `security-ingest`, and the public gateway has no route to Postgres.
2. **Service identity.** Every internal call carries `X-Service-Token`: an EdDSA JWT (kid =
   caller, `aud` = receiver, 60 s TTL, `jti` replay cache). Each service holds only its own
   private key. Receivers check `ACCEPTED_CALLERS` (`platform_core/security/service_acl.py`).
3. **Delegated principal with a ceiling.** The token carries the end-user principal (`prn`).
   Effective permissions = role permissions ∩ `CALLER_PERMISSION_CEILING[caller]`, so the public
   gateway can never borrow an admin's rights.
4. **Policy engine.** `PolicyEngine` (`platform_core/security/policy.py`) decides tenant scope
   (mismatch → 404), RBAC, MFA step-up for sensitive permissions, ABAC ownership and tool
   authorization. Tools come from a static `TOOL_REGISTRY` per agent. Import-time validation
   rejects any tool shared between agents or named with the other agent's prefixes.
5. **Database.** `FORCE ROW LEVEL SECURITY` on every tenant table using `app_current_tenant()`
   (a `set_config('app.tenant_id', …, true)` per transaction). There is a NOLOGIN role per
   service with table-level grants: `svc_samiir` has no grant on `incidents`, `security_events`
   or `scan_jobs`. Restrictive `agent_scope` policies keep `agent_runs`/`tool_calls` per agent.
   Cross-tenant lookups (widget key, webhook integration, login) go through `SECURITY DEFINER`
   functions owned by the `app_lookup` role.
6. **Model boundary.** The model sees tool results, not credentials or slot tokens. SAMIIR books
   by slot *number* and the server maps it to a signed slot token. Untrusted content is wrapped by
   `platform_core.security.untrusted` and labelled as data.
7. **Human approval.** Scans and defensive actions require an approval whose `payload_hash`
   (sha256 of canonical JSON) the approver echoes back. It is Ed25519-signed, single-use
   (atomic consume) and expires. Four-eyes is enforced by a DB `CHECK` for high-risk actions.
8. **Audit.** Every tool call, approval, transition and login emits an audit event. The audit
   service chains `entry_hash = sha256(prev_hash || canonical(entry))` under a per-tenant
   advisory lock. A trigger makes `audit_logs` append-only, and `/verify` recomputes the chain.

## 3. Key flows

### SAMIIR chat → booking
1. The widget obtains a session (`POST /v1/widget/session`): origin check against the widget's
   allowed origins, HttpOnly session cookie (`__Host-` over HTTPS), and an HMAC CSRF token.
2. The message goes through the bot checks (honeypot, timing, repeats) and rate limits, then to
   `samiir-agent /internal/chat` with a service token and anonymous visitor principal.
3. The runtime (OpenAI Agents SDK on the Responses API, or the deterministic fallback) calls tools
   via `ToolGateway`. Each call is policy-checked, pydantic-validated, persisted to `tool_calls`,
   audited and traced.
4. `search_knowledge` returns approved chunks only. `get_pricing` returns structured price rows
   from the knowledge service.
5. `check_availability` → numbered slots. `book_appointment(slot_number)` → scheduling. The
   EXCLUDE constraint prevents double booking. CRM moves the opportunity to
   `APPOINTMENT_BOOKED`. Notifications queues the email and/or WhatsApp confirmation.
6. The output guardrail checks every price, percentage, time and commitment against tool
   output before the reply is sent.

### FATMA detection → action
1. A vendor webhook reaches `/v1/ingest/{kind}/{key}`. Security-ingest verifies the HMAC or
   vendor token, then normalizes, redacts (secrets, cards, emails), stores the raw payload and
   inserts `security_events`.
2. fatma-soc runs per-event and windowed detectors, `score_signals` (0–100) and `classify`, then
   upserts the incident by correlation key. Risk never auto-decreases.
3. The analyst (deterministic or OpenAI) produces a structured `FatmaAnalysis`. Any "confirmed"
   wording is sanitized unless a human has confirmed the incident.
4. Recommended actions become `waf_actions` in `RECOMMENDED`. Execution requires a consumed
   approval matching the payload hash. Low-risk actions may be pre-approved per tenant policy.
   The sweeper reverts expired actions.

### Scan
Asset registration → DNS TXT / HTTP file verification → allowlist → scan request with ticket and
profile → `evaluate_gate` (checks 1–5, 7) → approval (check 6) consumed → Temporal
`ScanWorkflow` on queue `scanner` → the worker runs ZAP (spider + passive) and Nuclei (safe tags,
rate-limited) → parsed findings → `/findings/ingested` → incidents where warranted.

## 4. Data

PostgreSQL 16 with `pgvector` (1536-dim `text-embedding-3-small`, HNSW), `pgcrypto`, `btree_gist`
and `pg_trgm`. PII columns (email, phone, notes) use AES-256-GCM with the tenant id as associated
data, and HMAC blind indexes for lookup. Redis holds sessions, rate limits, replay caches and
idempotency keys. Object storage holds raw events and the encrypted malware quarantine.

## 5. Observability

OpenTelemetry traces, metrics and logs go to the collector (`infra/docker/otel/collector.yaml`).
Logs are structured JSON with redaction. Agent tracing to OpenAI is **off** by default.
