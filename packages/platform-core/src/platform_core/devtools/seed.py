"""Idempotent demo seed for local development and integration tests."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import asyncpg

from platform_core.security.crypto import FieldEncryptor, sha256_hex

KNOWLEDGE = [
    ("company_profile", "About Acme Secure",
     "Acme Secure is a managed cybersecurity and IT services company founded in 2015. "
     "We help small and mid-sized businesses protect their websites, cloud workloads and "
     "employees. Our team operates a 24/7 security operations centre.", None),
    ("services", "Our services",
     "Acme Secure offers three services. Website Security Monitoring watches your website for "
     "attacks, malware and downtime around the clock. Vulnerability Assessment is a scheduled, "
     "authorised scan of your internet-facing systems with a written report and remediation "
     "guidance. Security Awareness Training teaches your staff to recognise phishing.", None),
    ("faq", "Frequently asked questions",
     "How long does onboarding take? Onboarding for Website Security Monitoring takes five "
     "business days after we receive DNS or CDN access.\n\nDo you need access to our servers? "
     "No. Monitoring works through your CDN or web application firewall logs.\n\n"
     "What are your support hours? Customer support is available Monday to Friday, 08:00 to "
     "18:00 UTC. Security incidents are handled 24/7.", None),
    ("refund_escalation_policies", "Refunds and escalations",
     "Refund requests and contract questions are always handled by our customer success team. "
     "The assistant will connect you with a person for these topics.", None),
    ("security_services", "Security services scope",
     "Vulnerability assessments are only performed on systems you own, after written "
     "authorisation and domain ownership verification. We never perform denial-of-service "
     "testing or destructive testing.", None),
    ("pricing", "Price list 2026",
     "Approved list prices for 2026.",
     {"currency": "USD", "items": [
         {"service": "Website Security Monitoring", "price": "499", "unit": "per month",
          "notes": "Up to 3 domains."},
         {"service": "Vulnerability Assessment", "price_from": "2500", "price_to": "7500",
          "unit": "per assessment", "notes": "Depends on the number of hosts."},
         {"service": "Security Awareness Training", "price": "15", "unit": "per user per month",
          "notes": "Minimum 20 users."}]}),
]

USERS = [
    ("admin", "Amina Admin", ["tenant_admin"]),
    ("admin2", "Omar Admin", ["tenant_admin"]),
    ("sales", "Sara Sales", ["sales_agent"]),
    ("support", "Sam Support", ["support_agent"]),
    ("analyst", "Hodan Analyst", ["security_analyst"]),
    ("engineer", "Fatima Engineer", ["security_engineer"]),
    ("engineer2", "Yusuf Engineer", ["security_engineer"]),
]


@dataclass
class SeedResult:
    tenants: dict[str, uuid.UUID] = field(default_factory=dict)
    users: dict[str, uuid.UUID] = field(default_factory=dict)
    widget_keys: dict[str, str] = field(default_factory=dict)
    assets: dict[str, uuid.UUID] = field(default_factory=dict)
    ingest_keys: dict[str, str] = field(default_factory=dict)


async def _tenant(conn: asyncpg.Connection, tid: uuid.UUID) -> None:
    await conn.execute("SELECT set_config('app.tenant_id', $1, false)", str(tid))


async def seed(admin_url: str, enc: FieldEncryptor, *, embed=None) -> SeedResult:  # noqa: ANN001
    if os.environ.get("ENVIRONMENT") in ("production", "staging"):
        raise RuntimeError("refusing to seed a production-like environment")
    if embed is None:
        from knowledge_service.embeddings import HashingEmbedder

        embed = HashingEmbedder()
    from knowledge_service.embeddings import chunk_text

    result = SeedResult()
    conn = await asyncpg.connect(admin_url.replace("postgresql+asyncpg://", "postgresql://"))
    try:
        for slug, name, key_suffix in (("acme", "Acme Secure", "acme"), ("globex", "Globex Ltd", "globex")):
            tid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{slug}.tenant.samiir-fatma")
            result.tenants[slug] = tid
            await _tenant(conn, tid)
            await conn.execute(
                "INSERT INTO tenants (id, name, slug, timezone, settings) VALUES ($1,$2,$3,'UTC',"
                "$4::jsonb) ON CONFLICT (id) DO NOTHING", tid, name, slug,
                '{"fatma_mode": "recommend_only", "appointment_rules": {"business_timezone": '
                '"UTC", "min_notice_minutes": 60}}')
            roles = {r["name"]: r["id"] for r in await conn.fetch("SELECT id, name FROM roles")}
            for handle, display, role_names in USERS:
                subject = f"dev|{slug}|{handle}"
                email = f"{handle}@{slug}.example"
                uid = await conn.fetchval(
                    "INSERT INTO users (tenant_id, external_subject, email_ciphertext, email_hash,"
                    " display_name) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id, external_subject)"
                    " DO UPDATE SET display_name = EXCLUDED.display_name RETURNING id",
                    tid, subject, enc.encrypt(email, tid), enc.blind_index(email, tid, "email"),
                    display)
                result.users[f"{slug}:{handle}"] = uid
                for rn in role_names:
                    await conn.execute(
                        "INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES ($1,$2,$3) "
                        "ON CONFLICT DO NOTHING", tid, uid, roles[rn])
            pk = f"pk_demo_{key_suffix}_widget_000001"
            result.widget_keys[slug] = pk
            await conn.execute(
                "INSERT INTO widget_sites (tenant_id, public_key, name, allowed_origins, greeting) "
                "VALUES ($1,$2,$3,$4,$5) ON CONFLICT (public_key) DO NOTHING", tid, pk,
                f"{name} website", ["http://localhost:3000", "http://localhost:8080"],
                f"Hi! I'm SAMIIR from {name}. How can I help?")
            admin_id = result.users[f"{slug}:admin"]
            approver = result.users[f"{slug}:admin2"]
            for category, title, content, structured in KNOWLEDGE:
                exists = await conn.fetchval(
                    "SELECT id FROM knowledge_documents WHERE title = $1 AND status = 'APPROVED'",
                    title)
                if exists:
                    continue
                import json

                doc_id = await conn.fetchval(
                    "INSERT INTO knowledge_documents (tenant_id, lineage_id, title, content, category,"
                    " source, visibility, version, status, structured_data, content_hash, created_by,"
                    " approved_by, approved_at, effective_date, review_date) VALUES ($1,$2,$3,$4,$5,"
                    " 'seed', 'public', 1, 'APPROVED', $6::jsonb, $7, $8, $9, now(), now() - interval "
                    "'1 day', now() + interval '180 days') RETURNING id",
                    tid, uuid.uuid4(), title, content, category,
                    json.dumps(structured) if structured else None, sha256_hex(content), admin_id,
                    approver)
                chunks = chunk_text(content)
                vectors = await embed.embed([f"{title}\n{c}" for c in chunks])
                for i, (c, v) in enumerate(zip(chunks, vectors, strict=True)):
                    await conn.execute(
                        "INSERT INTO knowledge_chunks (tenant_id, document_id, chunk_index, content,"
                        " embedding, embedding_model) VALUES ($1,$2,$3,$4,$5::vector,$6)",
                        tid, doc_id, i, c, str(v), embed.model_name)
            for code, type_name, minutes in (("consultation", "Free consultation (30 min)", 30),
                                             ("security_review", "Security review call (60 min)",
                                              60)):
                await conn.execute(
                    "INSERT INTO appointment_types (tenant_id, code, name, duration_minutes, "
                    "buffer_minutes, calendar_id) VALUES ($1,$2,$3,$4,10,'sales-calendar') "
                    "ON CONFLICT (tenant_id, code) DO NOTHING", tid, code, type_name, minutes)
            target = f"www.{slug}.example"
            aid = await conn.fetchval(
                "INSERT INTO assets (tenant_id, name, asset_type, canonical_target, criticality, "
                "verification_status, verified_until, customer_authorization_ref, "
                "customer_authorization_expires_at) VALUES ($1,$2,'website',$3,4,'VERIFIED',$4,"
                "'AUTH-DEMO-001',$4) ON CONFLICT (tenant_id, canonical_target) WHERE deleted_at IS NULL"
                " DO UPDATE SET name = EXCLUDED.name RETURNING id", tid, f"{name} website", target,
                datetime.now(UTC) + timedelta(days=90))
            result.assets[slug] = aid
            for kind, key_id in (("ingest.cloudflare", f"ing_{slug}_cloudflare"),
                                 ("ingest.siem", f"ing_{slug}_siem"),
                                 ("ingest.app_log", f"ing_{slug}_applog"),
                                 ("ingest.auth", f"ing_{slug}_auth")):
                await conn.execute(
                    "INSERT INTO integrations (tenant_id, kind, name, external_key, secret_ref, config)"
                    " VALUES ($1,$2,$3,$4,'env://INGEST_DEMO_SECRET',$5::jsonb) ON CONFLICT "
                    "(kind, external_key) WHERE external_key IS NOT NULL DO NOTHING",
                    tid, kind, f"Demo {kind}", key_id, f'{{"asset_id": "{aid}"}}')
                result.ingest_keys[f"{slug}:{kind}"] = key_id
        await conn.execute("SELECT set_config('app.tenant_id', '', false)")
    finally:
        await conn.close()
    return result
