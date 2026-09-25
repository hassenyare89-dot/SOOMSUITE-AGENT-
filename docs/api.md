# API reference

OpenAPI is served at `/docs` on every service outside production. This page describes the
surface and the authentication model for each tier.

## Authentication schemes

| Tier | Scheme |
|---|---|
| Public widget | `POST /v1/widget/session` → HttpOnly `samiir_ws` session cookie (`__Host-` prefixed when served over HTTPS) + `csrf_token`. Later calls send `X-CSRF-Token`. Origin must be in the widget's allow-list. |
| WhatsApp webhook | `GET` verify-token handshake; `POST` requires `X-Hub-Signature-256` (HMAC-SHA256 of raw body with app secret). |
| Ingest webhooks | `X-Signature: t=<unix>,v1=<hmac>` over `"<t>." + body`, ±300 s, replay cache. Cloudflare Logpush / Firehose use a vendor token header (edge-IP-restricted). |
| Admin | OIDC session cookie (`admin_session`, `__Host-` prefixed over HTTPS) + `X-CSRF-Token` + same-origin `Origin` on writes. |
| Internal | `X-Service-Token` (EdDSA JWT, `aud` = receiver, 60 s, single-use `jti`) carrying the delegated principal. |

Errors use one envelope: `{"error": {"code": "not_found", "message": "..."}}` plus an
`X-Request-ID` response header. Codes: `bad_request` 400, `unauthenticated` 401, `forbidden` 403
(including MFA step-up: "step-up authentication required"), `not_found` 404 (also for other
tenants' resources), `conflict` 409, `payload_too_large` 413, `validation_failed` 422,
`rate_limited` 429, `upstream_unavailable` 503, and `approval_required` 202 (the action was
queued for human approval). Tool calls and notifications are idempotent on server-derived keys.

## Public gateway (`:8000`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/widget/config?key=` | Widget branding + greeting |
| POST | `/v1/widget/session` | Start a visitor session |
| POST | `/v1/widget/messages` | Send a message; returns SAMIIR reply, quick replies, slots |
| GET | `/v1/widget/messages` | Conversation history for this session |
| POST | `/v1/widget/contact` | Submit contact details (consent flags) |
| POST | `/v1/widget/escalate` | Request a human |
| GET/POST | `/v1/whatsapp/webhook` | Meta webhook (verify / events) |
| POST | `/v1/ingest/{kind}/{key}` | Security telemetry; `kind` ∈ `cloudflare, aws_waf, siem, app_log, proxy, auth, scanner, malware` |

## Admin gateway (`:8001`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/auth/login`, `/auth/callback` | OIDC code + PKCE |
| GET | `/auth/me` | Current user, roles, permissions, CSRF token |
| POST | `/auth/logout` | Revoke session |
| POST | `/auth/dev-login` | **Development only** |
| GET | `/v1/admin/stream` | SSE: incidents, approvals, conversations |
| GET/PATCH | `/v1/admin/identity/tenant` | Tenant settings (FATMA mode, detection thresholds) |
| GET/POST | `/v1/admin/identity/users`, `PUT …/{id}/roles`, `POST …/{id}/disable` | User admin |
| GET | `/v1/admin/identity/roles`, `/security-settings` | |
| GET/POST | `/v1/admin/identity/integrations`, `POST …/{id}/disable` | Integrations (secret refs only) |
| GET/POST | `/v1/admin/identity/widgets` | Widget keys and allowed origins |
| * | `/v1/admin/{service}/{path}` | Role-gated proxy to `/internal/{path}` of: `samiir`, `crm`, `scheduling`, `knowledge`, `notifications`, `whatsapp`, `fatma`, `ingest`, `scanner`, `approvals`, `audit` |

## Internal service endpoints (prefix `/internal`)

**samiir-agent:** `POST /chat`, `GET /chat/history`, `POST /chat/contact`, `POST /chat/escalate`,
`GET /widget/resolve`, `GET /conversations`, `GET /conversations/{id}`,
`POST /conversations/{id}/reply|status|summarize`, `GET /agent-runs`, `GET /agent/config`,
`POST /messages/status`.

**crm:** `GET|POST /companies`, `PATCH /companies/{id}`, `GET|POST /contacts`,
`GET|PATCH|DELETE /contacts/{id}`, `GET /contacts/{id}/delivery`, `GET|POST /opportunities`,
`PATCH /opportunities/{id}`, `POST /opportunities/{id}/stage`, `GET /pipeline`, `GET|POST /tasks`,
`PATCH /tasks/{id}`, `GET|POST /activities`, `POST /notes`, `GET /metrics`,
`POST /samiir/contacts`, `POST /samiir/qualify`, `POST /stage-events`.
Stages: `NEW_LEAD → QUALIFIED → APPOINTMENT_BOOKED → SECURITY_REVIEW → PROPOSAL → NEGOTIATION → WON | LOST`.

**scheduling:** `GET|POST /appointment-types`, `POST /availability`, `GET|POST /appointments`,
`POST /appointments/{id}/cancel|reschedule`.

**knowledge:** `GET|POST /documents`, `GET|PATCH /documents/{id}`, `GET /documents/{id}/versions`,
`POST /documents/{id}/submit|approve|archive`, `POST /search`, `GET /pricing`.

**notifications:** `GET|POST /notifications`, `POST /notifications/cancel|status`, `GET /templates`.

**whatsapp:** `GET|POST /webhook`, `POST /send`, `GET /status`.

**fatma-soc:** `GET /soc/overview`, `GET /metrics`, `GET /events`, `POST /events/ingested`,
`GET /incidents`, `GET /incidents/{id}`, `POST /incidents/{id}/status|assign|notes|analyze|confirm`,
`GET /findings`, `PATCH /findings/{id}`, `POST /findings/ingested`, `GET /assets`, `GET /malware`,
`GET|POST /actions`, `POST /actions/{id}/request-approval|execute|revert|dismiss`, `POST /ask`.

**security-ingest:** `POST /ingest/{kind}/{key}`, `POST /malware/submit`, `GET /malware`,
`GET /malware/{id}`, `POST /malware/{id}/destroy`.

**scanner-controller:** `GET|POST /assets`, `PATCH /assets/{id}`,
`POST /assets/{id}/verifications`, `POST /assets/{id}/verifications/{vid}/check`,
`POST /assets/{id}/allowlist`, `POST /scans/gate-check`, `GET|POST /scans`, `GET /scans/{id}`,
`POST /scans/{id}/start|cancel|retry`.

**approvals** (prefix `/internal/approvals`): `POST /` (create), `GET /{id}`, `POST /{id}/decide`
(body must echo `payload_hash`), `POST /{id}/consume`, `POST /{id}/cancel`, `POST /preapproved`,
`GET /policies`.

**audit** (prefix `/internal/audit`): `POST /events`, `GET /logs`, `GET /verify`.

## Example: approve and execute a defence action

```http
POST /v1/admin/fatma/actions/{id}/request-approval         → {"approval_id": "...", "payload_hash": "ab12…"}
POST /v1/admin/approvals/{approval_id}/decide               {"decision": "approve", "payload_hash": "ab12…", "comment": "…"}
POST /v1/admin/fatma/actions/{id}/execute                   → consumes approval; status ACTIVE; expires_at set
```
A different approver is required for high-risk actions (four eyes). Replaying `execute` fails
because the approval is already consumed.
