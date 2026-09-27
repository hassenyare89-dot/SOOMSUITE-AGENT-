from __future__ import annotations

import asyncio
import os
import secrets
import subprocess
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

ADMIN_URL = os.environ.get("TEST_ADMIN_DATABASE_URL")  # superuser/owner connection for setup
OWNER_URL = os.environ.get("TEST_DATABASE_URL")        # schema owner (runs migrations)

ROLES = ["svc_gateway_admin", "svc_samiir", "svc_crm", "svc_scheduling", "svc_knowledge",
         "svc_notifications", "svc_whatsapp", "svc_fatma", "svc_security_ingest",
         "svc_scanner_controller", "svc_approvals", "svc_audit"]


def pytest_collection_modifyitems(config, items):  # noqa: ANN001
    if OWNER_URL and ADMIN_URL:
        return
    skip = pytest.mark.skip(reason="TEST_DATABASE_URL / TEST_ADMIN_DATABASE_URL not set")
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def migrated_db() -> dict[str, str]:
    """Reset the test database, run migrations as the owner and provision service logins."""
    import asyncpg

    async def reset() -> None:
        conn = await asyncpg.connect(ADMIN_URL.replace("+asyncpg", ""))
        await conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        owner = OWNER_URL.split("//", 1)[1].split(":", 1)[0]
        await conn.execute(f"CREATE SCHEMA public AUTHORIZATION {owner}")
        for ext in ("vector", "pgcrypto", "btree_gist", "pg_trgm"):
            await conn.execute(f"CREATE EXTENSION IF NOT EXISTS {ext}")
        await conn.close()

    asyncio.run(reset())
    env = {**os.environ, "MIGRATION_DATABASE_URL": OWNER_URL}
    subprocess.run([sys.executable, "-m", "alembic", "-c", "packages/database/alembic.ini",
                    "upgrade", "head"], cwd=ROOT, env=env, check=True, capture_output=True)
    passwords = {r: secrets.token_urlsafe(24) for r in ROLES}
    sys.path.insert(0, str(ROOT / "scripts"))
    from provision_db_users import provision

    asyncio.run(provision(ADMIN_URL, passwords))
    return passwords


@pytest.fixture(scope="session")
async def platform(migrated_db, tmp_path_factory):  # noqa: ANN001
    from harness import start_platform

    from platform_core.devtools.seed import seed

    async with AsyncExitStack() as stack:
        plat = await start_platform(stack, tmp_path_factory.mktemp("platform"), OWNER_URL,
                                    migrated_db)
        plat.seed = await seed(ADMIN_URL, plat.enc)
        yield plat
