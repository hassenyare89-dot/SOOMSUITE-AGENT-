# SAMIIR + FATMA Secure AI Platform

A multi-tenant SaaS platform with two AI agents that are **architecturally isolated** from each other:

| | SAMIIR | FATMA |
|---|---|---|
| Purpose | Customer service, sales qualification, CRM, appointments | Defensive security operations (SOC) for verified tenant assets |
| Channels | Web chat widget, WhatsApp (Meta Cloud API), email confirmations | Admin console only (never public) |
| Answers from | Approved knowledge (pgvector RAG) + structured pricing/availability tools | Normalized, redacted security evidence |
| Can act | Create/qualify contacts, book appointments, send confirmations | **Recommend only.** Execution needs a human approval bound to the exact payload hash |
| Model default | `gpt-5.4-mini` (configurable) | `gpt-5.5` (configurable) |

Isolation is enforced by **separate services, service identities, credentials, database roles, tool
registries, RBAC, network segments, a policy engine, human approval and an immutable audit chain**,
not by prompts. The language model never decides whether it has permission; the policy engine does.

> This is a production-grade foundation, not a compliance certification. Before going live you still
> need a real OIDC provider, a managed secret store/KMS, an external penetration test, a restore
> drill in your account, and signed customer authorization for every scanned asset.

## Quick start (Docker Compose)

```bash
python3 scripts/bootstrap_dev.py          # writes .env + per-service Ed25519 keys under .secrets/ (git-ignored)
docker compose up -d --build              # 16 services + web; `migrate` runs Alembic, provisions DB roles, seeds demo data
open http://localhost:3000                # console (dev login enabled only when ENVIRONMENT=development)
open http://localhost:3000/widget/pk_demo_acme_widget_000001   # SAMIIR widget demo
open http://localhost:8025                # Mailpit: appointment confirmation emails
docker compose --profile scanners up -d   # optional: Temporal, ClamAV, scanner + malware workers
```

Demo users (development only, via the dev-login button): `admin`, `sales`, `support`, `analyst`,
`engineer`, `engineer2` for tenants `acme` and `globex`.

## Without Docker

```bash
python3.13 -m venv .venv && .venv/bin/pip install -e '.[dev,agents,temporal,email,dns]'
python scripts/bootstrap_dev.py
LOCAL_ADMIN_DATABASE_URL=postgresql://postgres@localhost:5432/postgres python scripts/run_local.py --reset
(cd apps/web && npm ci && ADMIN_GATEWAY_URL=http://localhost:8001 PUBLIC_GATEWAY_URL=http://localhost:8000 \
   NEXT_PUBLIC_DEV_LOGIN=true npm run dev)
```

Requires PostgreSQL 16+ with `pgvector`, and Redis 7+.

## Tests

```bash
export TEST_ADMIN_DATABASE_URL=postgresql+asyncpg://postgres@localhost:5432/platform_test
export TEST_DATABASE_URL=postgresql+asyncpg://platform_owner:owner@localhost:5432/platform_test
ruff check . && pytest -q                 # unit, integration (all 15 apps in-process), security/prompt-injection
(cd apps/web && npm run typecheck && npm run build)
```

The security suite drives an adversarial model runtime that *tries* to call forbidden tools,
leak other tenants' data, invent prices and claim confirmed breaches, and asserts the platform
blocks each attempt deterministically.

## Repository map

```
apps/web/                     Next.js 16 console (SAMIIR, FATMA, admin) + embeddable widget
packages/platform-core/       Shared runtime: config, DB/RLS sessions, policy engine, service auth,
                              crypto, audit client, redaction, SSRF guard, schemas, Temporal workflow types
packages/database/            Alembic migrations (schema, RLS, service roles, audit immutability)
services/
  api-gateway/                Public gateway (widget, WhatsApp + ingest webhooks) and admin BFF (OIDC)
  samiir-agent/ crm/ scheduling/ knowledge/ notifications/ whatsapp/        SAMIIR side
  fatma-soc/ security-ingest/ scanner-controller/ scanner-worker/           FATMA side
  approvals/ audit/           Shared governance services
infra/                        Dockerfiles, Helm chart, Terraform (AWS), OTel collector
scripts/                      bootstrap, local runner, DB provisioning, seed, restore verification
tests/                        unit / integration / security
docs/                         architecture, threat model, deployment, API, knowledge base, SOC runbook, IR
```

## Documentation

- [Architecture](docs/architecture.md): services, trust boundaries, isolation layers, data flows
- [Threat model](docs/threat-model.md): STRIDE per boundary, prompt-injection defences, residual risk
- [Deployment](docs/deployment.md): Compose, Kubernetes/Helm, Terraform, secrets, CI/CD, key rotation
- [API](docs/api.md): public, admin and internal endpoints; auth schemes; errors
- [Knowledge base](docs/knowledge-base.md): approval workflow, pricing data, RAG and grounding
- [SOC runbook](docs/soc-runbook.md): triage, scanning, defensive actions for FATMA operators
- [Incident response](docs/incident-response.md): response plan for incidents in the platform itself

## Non-negotiable invariants

1. SAMIIR and FATMA share **no tools, no credentials, no network path and no DB role**. The tool
   registries are validated at import time, so a shared tool fails startup.
2. Every tenant query runs under PostgreSQL `FORCE ROW LEVEL SECURITY`. A cross-tenant id returns 404.
3. Customer messages, retrieved documents, logs and scanner output are **untrusted data**. They are
   wrapped, never followed as instructions, and never widen permissions.
4. SAMIIR cannot state a price, discount, time or commitment that is not present in tool output.
   The grounding guardrail replaces such replies.
5. FATMA marks incidents `SUSPECTED`. Only a human security engineer, with a checklist, evidence
   references and a justification, can mark one `CONFIRMED` (enforced by a DB trigger too).
6. No scan runs without all seven gates. No defensive action runs without an approval whose hash
   matches the exact payload, and each approval is consumed once.
7. Secrets live only in the secret manager/environment. `.env.example` holds placeholders only.
   Meta, Cloudflare and OpenAI tokens are never placed in model context.
