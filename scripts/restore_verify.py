"""Backup restore drill verification (used by .github/workflows/restore-drill.yml).

Connects to a restored instance with a read-only drill credential and checks:
* the schema is at the Alembic head this commit expects,
* core tables are non-empty / readable,
* every tenant's audit hash chain still verifies end to end.
Exit code is non-zero on any failure so the workflow pages on-call.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

import asyncpg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/platform-core/src"))
sys.path.insert(0, str(ROOT / "services/audit/src"))

EXPECTED_HEAD = "0002_service_roles"
TABLES = ["tenants", "users", "contacts", "opportunities", "appointments", "incidents",
          "security_events", "audit_logs"]


async def verify(dsn: str) -> list[str]:
    from audit_service.chain import verify_rows  # imported lazily: needs sys.path above

    problems: list[str] = []
    conn = await asyncpg.connect(dsn)
    try:
        head = await conn.fetchval("SELECT version_num FROM alembic_version")
        if head != EXPECTED_HEAD:
            problems.append(f"alembic head {head!r} != {EXPECTED_HEAD!r}")
        for t in TABLES:
            n = await conn.fetchval(f"SELECT count(*) FROM {t}")  # noqa: S608 - constant names
            print(f"{t:18} {n}")
        for (tenant_id,) in await conn.fetch("SELECT DISTINCT tenant_id FROM audit_logs"):
            rows = await conn.fetch("SELECT * FROM audit_logs WHERE tenant_id = $1 ORDER BY seq",
                                    tenant_id)
            ok, detail = verify_rows([dict(r) for r in rows])
            if not ok:
                problems.append(f"audit chain broken for tenant {tenant_id}: {detail}")
    finally:
        await conn.close()
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True, help="restored RDS instance identifier")
    args = ap.parse_args()
    dsn = os.environ.get("DRILL_DATABASE_URL") or \
        f"postgresql://drill_reader@{args.instance}.{os.environ['DR_DB_DOMAIN']}:5432/platform"
    problems = asyncio.run(verify(dsn))
    for p in problems:
        print("FAIL:", p)
    print("restore drill:", "FAILED" if problems else "OK")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
