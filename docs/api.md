# API

All `/v1` calls use TLS and OIDC bearer tokens. Tenant identity comes exclusively from the validated token, never a client-selected header. `POST /v1/samiir/chat` requires `samiir:chat`; `POST /v1/fatma/events/{tenant}` requires a SOC role and exact tenant match. WhatsApp GET verifies the subscription token and POST validates `X-Hub-Signature-256` before parsing. Mutations use `Idempotency-Key`; production stores results in Redis/PostgreSQL with a tenant-scoped unique key.
