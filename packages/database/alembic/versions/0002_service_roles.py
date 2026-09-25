"""Least-privilege database roles per service, agent-scoped RLS, lookup functions, RBAC seed.

Each service connects as its own NOLOGIN-by-default role (login and credentials are provisioned
out of band: IAM auth in production, ``scripts/provision_db_users.py`` in development). No
service role owns tables, has BYPASSRLS or DELETE on business tables.

Revision ID: 0002_service_roles
Revises: 0001_core_schema
Create Date: 2026-09-24
"""

import re

import sqlalchemy as sa
from alembic import op

from platform_core.db.sqlscript import execute_script

from platform_core.security.rbac import ROLE_PERMISSIONS, P

revision = "0002_service_roles"
down_revision = "0001_core_schema"
branch_labels = None
depends_on = None

SERVICE_ROLES = [
    "svc_gateway_admin", "svc_samiir", "svc_crm", "svc_scheduling", "svc_knowledge",
    "svc_notifications", "svc_whatsapp", "svc_fatma", "svc_security_ingest",
    "svc_scanner_controller", "svc_approvals", "svc_audit",
]
# Role names are interpolated into DDL (identifiers cannot be bound), so pin their shape.
assert all(re.fullmatch(r"svc_[a-z_]+", r) for r in SERVICE_ROLES)  # noqa: S101

R, RW, RWD, RI = "SELECT", "SELECT, INSERT, UPDATE", "SELECT, INSERT, UPDATE, DELETE", "SELECT, INSERT"

GRANTS: dict[str, dict[str, str]] = {
    "svc_gateway_admin": {
        "tenants": "SELECT, UPDATE", "users": RW, "user_roles": RWD, "roles": R,
        "permissions": R, "role_permissions": R, "integrations": RW, "widget_sites": RW,
    },
    "svc_samiir": {
        "tenants": R, "conversations": RW, "messages": RW, "agent_runs": RW, "tool_calls": RI,
    },
    "svc_crm": {
        "tenants": R, "users": R, "companies": RW, "contacts": RW, "opportunities": RW,
        "crm_activities": RI, "crm_notes": RW, "crm_tasks": RW, "conversations": R,
    },
    "svc_scheduling": {
        "tenants": R, "appointment_types": RW, "appointments": RW, "integrations": R,
    },
    "svc_knowledge": {"tenants": R, "knowledge_documents": RW, "knowledge_chunks": RWD},
    "svc_notifications": {"tenants": R, "users": R, "user_roles": R, "roles": R, "notifications": RW},
    "svc_whatsapp": {"tenants": R, "integrations": R},
    "svc_fatma": {
        "tenants": R, "users": R, "assets": R, "security_events": "SELECT, UPDATE",
        "incidents": RW, "incident_events": RI, "findings": "SELECT, UPDATE", "scan_jobs": R,
        "malware_results": R, "waf_actions": RW, "integrations": R, "agent_runs": RW,
        "tool_calls": RI,
    },
    "svc_security_ingest": {
        "tenants": R, "assets": R, "integrations": R, "security_events": RI,
        "malware_results": RW, "findings": RW,
    },
    "svc_scanner_controller": {
        "tenants": R, "assets": RW, "asset_verifications": RW, "scan_jobs": RW, "findings": RW,
    },
    "svc_approvals": {"tenants": R, "approval_requests": RW},
    "svc_audit": {"tenants": R, "audit_logs": RI},
}

LOOKUP_FUNCTIONS = r"""
CREATE FUNCTION app_resolve_widget(p_public_key text)
RETURNS TABLE (tenant_id uuid, site_id uuid, tenant_name text, allowed_origins text[],
               greeting text, theme jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
$$
  SELECT w.tenant_id, w.id, t.name, w.allowed_origins, w.greeting, w.theme
  FROM widget_sites w JOIN tenants t ON t.id = w.tenant_id
  WHERE w.public_key = p_public_key AND w.active AND t.status = 'active' AND t.deleted_at IS NULL
$$;

CREATE FUNCTION app_resolve_integration(p_kind text, p_external_key text)
RETURNS TABLE (tenant_id uuid, integration_id uuid, secret_ref text, config jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
$$
  SELECT i.tenant_id, i.id, i.secret_ref, i.config
  FROM integrations i JOIN tenants t ON t.id = i.tenant_id
  WHERE i.kind = p_kind AND i.external_key = p_external_key AND i.status = 'active'
    AND t.status = 'active' AND t.deleted_at IS NULL
$$;

CREATE FUNCTION app_login_lookup(p_subject text)
RETURNS TABLE (user_id uuid, tenant_id uuid, display_name text, status text, roles text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
$$
  SELECT u.id, u.tenant_id, u.display_name, u.status,
         coalesce(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}')
  FROM users u
  JOIN tenants t ON t.id = u.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL
  LEFT JOIN user_roles ur ON ur.user_id = u.id
  LEFT JOIN roles r ON r.id = ur.role_id
  WHERE u.external_subject = p_subject AND u.deleted_at IS NULL
  GROUP BY u.id
$$;

CREATE FUNCTION app_claim_due_notifications(p_limit integer)
RETURNS TABLE (tenant_id uuid, notification_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS
$$
  UPDATE notifications n SET status = 'SENDING', attempts = n.attempts + 1
  WHERE n.id IN (
    SELECT id FROM notifications
    WHERE status = 'SCHEDULED' AND scheduled_for <= now()
    ORDER BY scheduled_for
    LIMIT least(greatest(p_limit, 1), 500)
    FOR UPDATE SKIP LOCKED
  )
  RETURNING n.tenant_id, n.id
$$;

CREATE FUNCTION app_expire_approvals()
RETURNS integer
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp AS
$$
  WITH expired AS (
    UPDATE approval_requests SET status = 'EXPIRED'
    WHERE status IN ('PENDING','APPROVED') AND expires_at <= now()
    RETURNING 1
  ) SELECT count(*)::integer FROM expired
$$;

CREATE FUNCTION app_due_waf_expirations(p_limit integer)
RETURNS TABLE (tenant_id uuid, action_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
$$
  SELECT tenant_id, id FROM waf_actions
  WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at <= now()
  ORDER BY expires_at LIMIT least(greatest(p_limit, 1), 500)
$$;

CREATE FUNCTION app_active_tenants()
RETURNS TABLE (tenant_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
$$ SELECT id FROM tenants WHERE status = 'active' AND deleted_at IS NULL $$;
"""

LOOKUP_GRANTS = {
    "app_resolve_widget(text)": ["svc_samiir"],
    "app_resolve_integration(text, text)": ["svc_whatsapp", "svc_security_ingest"],
    "app_login_lookup(text)": ["svc_gateway_admin"],
    "app_claim_due_notifications(integer)": ["svc_notifications"],
    "app_expire_approvals()": ["svc_approvals"],
    "app_due_waf_expirations(integer)": ["svc_fatma"],
    "app_active_tenants()": ["svc_fatma", "svc_scanner_controller", "svc_audit",
                             "svc_notifications"],
}

# Tables the lookup role may read across tenants (only through the functions above).
LOOKUP_TABLE_ACCESS = {
    "widget_sites": "SELECT", "tenants": "SELECT", "integrations": "SELECT", "users": "SELECT",
    "user_roles": "SELECT", "roles": "SELECT", "notifications": "SELECT, UPDATE",
    "approval_requests": "SELECT, UPDATE", "waf_actions": "SELECT",
}


def upgrade() -> None:
    op.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
    for role in [*SERVICE_ROLES, "app_lookup"]:
        op.execute(
            # Identifiers cannot be bound parameters; role names are module constants.
            f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') "  # nosec B608
            f"THEN CREATE ROLE {role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS; "
            f"END IF; END $$"
        )
        op.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION app_current_tenant() TO {role}")
    op.execute("GRANT app_lookup TO CURRENT_USER")

    for role, tables in GRANTS.items():
        for table, privs in tables.items():
            op.execute(f"GRANT {privs} ON {table} TO {role}")

    # Agent isolation inside shared agent tables: each agent's service role only sees and
    # writes its own agent's rows, on top of tenant isolation.
    for role, agent in (("svc_samiir", "SAMIIR"), ("svc_fatma", "FATMA")):
        for table in ("agent_runs", "tool_calls"):
            op.execute(
                f"CREATE POLICY agent_scope_{role} ON {table} AS RESTRICTIVE TO {role} "
                f"USING (agent_name = '{agent}') WITH CHECK (agent_name = '{agent}')"
            )

    # The lookup role: owns the SECURITY DEFINER functions, sees specific tables unfiltered.
    for table, privs in LOOKUP_TABLE_ACCESS.items():
        op.execute(f"GRANT {privs} ON {table} TO app_lookup")
        op.execute(f"CREATE POLICY lookup_all ON {table} TO app_lookup USING (true) "
                   f"WITH CHECK (true)")
    execute_script(op, LOOKUP_FUNCTIONS)
    # ALTER OWNER requires the new owner to hold CREATE on the schema; revoke it right after.
    op.execute("GRANT CREATE ON SCHEMA public TO app_lookup")
    for fn in LOOKUP_GRANTS:
        op.execute(f"ALTER FUNCTION {fn} OWNER TO app_lookup")
    op.execute("REVOKE CREATE ON SCHEMA public FROM app_lookup")
    for fn, roles in LOOKUP_GRANTS.items():
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
        for role in roles:
            op.execute(f"GRANT EXECUTE ON FUNCTION {fn} TO {role}")

    # Seed the RBAC catalog from the code-reviewed mapping.
    bind = op.get_bind()
    for perm in P:
        bind.execute(sa.text("INSERT INTO permissions (name) VALUES (:p) ON CONFLICT DO NOTHING"),
                     {"p": perm.value})
    for role, perms in ROLE_PERMISSIONS.items():
        bind.execute(sa.text("INSERT INTO roles (name) VALUES (:r) ON CONFLICT DO NOTHING"),
                     {"r": role.value})
        for perm in perms:
            bind.execute(sa.text(
                "INSERT INTO role_permissions (role_id, permission_id) "
                "SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = :r AND p.name = :p "
                "ON CONFLICT DO NOTHING"), {"r": role.value, "p": perm.value})


def downgrade() -> None:
    for fn in LOOKUP_GRANTS:
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")
    for table in LOOKUP_TABLE_ACCESS:
        op.execute(f"DROP POLICY IF EXISTS lookup_all ON {table}")
    for role in ("svc_samiir", "svc_fatma"):
        for table in ("agent_runs", "tool_calls"):
            op.execute(f"DROP POLICY IF EXISTS agent_scope_{role} ON {table}")
    op.execute("DELETE FROM role_permissions")
    op.execute("DELETE FROM roles")
    op.execute("DELETE FROM permissions")
    for role in [*SERVICE_ROLES, "app_lookup"]:
        op.execute(f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN "  # nosec B608
                   f"EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}'; "
                   f"EXECUTE 'REVOKE ALL ON SCHEMA public FROM {role}'; END IF; END $$")
