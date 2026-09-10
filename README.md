# SAMIIR + FATMA Secure AI Platform

A security-first, multi-tenant SaaS foundation containing two deliberately isolated AI systems:

- **SAMIIR** — approved-knowledge customer support, CRM, WhatsApp, and scheduling.
- **FATMA** — private, defensive SOC analysis for verified tenant assets. It begins in recommend-only mode.

> This repository is an MVP foundation, not a claim of compliance. A production deployment requires a configured identity provider, managed secrets/KMS, mTLS, external penetration testing, backup restoration exercises, and tenant-specific authorization onboarding.

## Security invariants

1. Agent separation is enforced by identities, networks, permissions, and fixed tool registries—not prompts.
2. Tenant-bound queries run with PostgreSQL RLS context (`app.tenant_id`); cross-tenant resources return 404.
3. Public routes have no path to scanner workers. Scans require verified allowlisted assets, a ticket, immutable payload approval, and safe profile.
4. Model context contains approved knowledge or normalized/redacted evidence only.
5. A single alert is never sufficient to label a breach confirmed.

## Run locally

```bash
cp .env.example .env
# Set strong POSTGRES_PASSWORD and REDIS_PASSWORD values in .env
docker compose up --build postgres redis temporal gateway
curl http://localhost:8000/healthz
```

API docs are at `http://localhost:8000/docs` outside production. The authenticated endpoints expect an OIDC JWT containing `tenant_id` and `roles` claims.

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
```

## Repository map

- `apps/api`: FastAPI gateway, deterministic policy, agent orchestration, integrations.
- `apps/web`: responsive Next.js operations dashboard and SAMIIR widget shell.
- `services`: independently deployable capability boundaries.
- `packages/database`: Alembic schema, pgvector, indexes, and RLS.
- `infra`: local containers and production deployment foundations.
- `tests`: unit, integration, and adversarial security suites.
- `docs`: architecture, threat model, operations, and integration contracts.

## External configuration

Credentials are referenced through environment/secret-manager configuration only. OpenAI agent execution should use the current supported Responses API through the OpenAI Agents SDK. Meta webhook signatures use the raw request bytes and app secret. Scanner images are intentionally an opt-in Compose profile and must run in private, restricted worker nodes.
