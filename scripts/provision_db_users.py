"""Development/CI helper: give each NOLOGIN service role a login password.

Production uses IAM/cloud database authentication or Vault dynamic credentials instead.
Usage: ADMIN_DATABASE_URL=postgresql://... python scripts/provision_db_users.py
Passwords are read from DB_PASSWORD_<ROLE> environment variables (see .env.example).
"""

from __future__ import annotations

import asyncio
import os
import re
import sys

import asyncpg

ROLES = ["svc_gateway_admin", "svc_samiir", "svc_crm", "svc_scheduling", "svc_knowledge",
         "svc_notifications", "svc_whatsapp", "svc_fatma", "svc_security_ingest",
         "svc_scanner_controller", "svc_approvals", "svc_audit"]


async def provision(admin_url: str, passwords: dict[str, str]) -> None:
    conn = await asyncpg.connect(admin_url.replace("postgresql+asyncpg://", "postgresql://"))
    try:
        for role, password in passwords.items():
            if not re.fullmatch(r"svc_[a-z_]+", role):
                raise ValueError(f"unexpected role {role}")
            if len(password) < 16:
                raise ValueError(f"password for {role} is too short")
            await conn.execute(f"ALTER ROLE {role} LOGIN")
            # Role names are validated above; the password is passed as a quoted literal.
            quoted = await conn.fetchval("SELECT quote_literal($1)", password)
            await conn.execute(f"ALTER ROLE {role} PASSWORD {quoted}")
            await conn.execute(f"ALTER ROLE {role} CONNECTION LIMIT 50")
    finally:
        await conn.close()


def main() -> int:
    url = os.environ.get("ADMIN_DATABASE_URL")
    if not url:
        print("ADMIN_DATABASE_URL is required", file=sys.stderr)
        return 2
    passwords = {r: os.environ[f"DB_PASSWORD_{r.upper()}"] for r in ROLES
                 if os.environ.get(f"DB_PASSWORD_{r.upper()}")}
    missing = sorted(set(ROLES) - set(passwords))
    if missing:
        print(f"missing passwords for: {', '.join(missing)}", file=sys.stderr)
        return 2
    asyncio.run(provision(url, passwords))
    print(f"provisioned {len(passwords)} service roles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
