"""Run the whole platform locally without Docker (PostgreSQL 16+ with pgvector and Redis
must be reachable). Intended for development and demos.

    python scripts/bootstrap_dev.py
    LOCAL_ADMIN_DATABASE_URL=postgresql://postgres@localhost:5432/postgres \\
        python scripts/run_local.py [--reset] [--no-seed]
    (cd apps/web && ADMIN_GATEWAY_URL=http://localhost:8001 PUBLIC_GATEWAY_URL=http://localhost:8000 \\
        NEXT_PUBLIC_DEV_LOGIN=true npm run dev)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import asyncpg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from topology import SERVICES  # noqa: E402


def load_env() -> dict[str, str]:
    env = {}
    for line in (ROOT / ".env").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k] = v.strip("'")
    return env


async def prepare(admin_url: str, env: dict[str, str], reset: bool) -> str:
    db = env.get("POSTGRES_DB", "platform")
    conn = await asyncpg.connect(admin_url)
    try:
        owner_pw = env["DB_OWNER_PASSWORD"]
        if not await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname='platform_owner'"):
            await conn.execute(f"CREATE ROLE platform_owner LOGIN CREATEROLE PASSWORD "
                               f"{await conn.fetchval('SELECT quote_literal($1)', owner_pw)}")
        if reset and await conn.fetchval("SELECT 1 FROM pg_database WHERE datname=$1", db):
            await conn.execute(f'DROP DATABASE "{db}" WITH (FORCE)')
        if not await conn.fetchval("SELECT 1 FROM pg_database WHERE datname=$1", db):
            await conn.execute(f'CREATE DATABASE "{db}" OWNER platform_owner')
    finally:
        await conn.close()
    db_admin = admin_url.rsplit("/", 1)[0] + f"/{db}"
    conn = await asyncpg.connect(db_admin)
    for ext in ("vector", "pgcrypto", "btree_gist", "pg_trgm"):
        await conn.execute(f"CREATE EXTENSION IF NOT EXISTS {ext}")
    await conn.close()
    return db_admin


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--no-seed", action="store_true")
    parser.add_argument("--db-host", default="localhost:5432")
    parser.add_argument("--redis", default="localhost:6379")
    args = parser.parse_args()
    env = load_env()
    admin_url = os.environ.get("LOCAL_ADMIN_DATABASE_URL", "postgresql://postgres@localhost:5432/postgres")
    db_admin = asyncio.run(prepare(admin_url, env, args.reset))
    db = env.get("POSTGRES_DB", "platform")
    owner_url = f"postgresql+asyncpg://platform_owner:{env['DB_OWNER_PASSWORD']}@{args.db_host}/{db}"
    subprocess.run([sys.executable, "-m", "alembic", "-c", "packages/database/alembic.ini", "upgrade",
                    "head"], cwd=ROOT, env={**os.environ, "MIGRATION_DATABASE_URL": owner_url},
                   check=True)
    from provision_db_users import ROLES, provision

    asyncio.run(provision(db_admin, {r: env[f"DB_PASSWORD_{r.upper()}"] for r in ROLES}))
    if not args.no_seed:
        import base64

        sys.path.insert(0, str(ROOT / "packages/platform-core/src"))
        from platform_core.devtools.seed import seed
        from platform_core.security.crypto import FieldEncryptor, Keyring

        enc = FieldEncryptor(Keyring.from_json(env["FIELD_ENCRYPTION_KEYRING"]),
                             base64.b64decode(env["BLIND_INDEX_KEY"]))
        result = asyncio.run(seed(db_admin, enc))
        print(f"seeded tenants: {', '.join(result.tenants)}; widget key (acme): "
              f"{result.widget_keys['acme']}")

    run_dir = ROOT / ".run"
    run_dir.mkdir(exist_ok=True)
    redis_pw = env.get("REDIS_PASSWORD", "")
    procs: list[subprocess.Popen] = []
    urls = {s.name: f"http://127.0.0.1:{s.port}" for s in SERVICES}
    for s in SERVICES:
        penv = {k: v for k, v in os.environ.items() if not k.startswith(("DB_", "POSTGRES"))}
        penv.update({
            "ENVIRONMENT": env.get("ENVIRONMENT", "development"),
            "LOG_LEVEL": env.get("LOG_LEVEL", "INFO"),
            "SERVICE_NAME": s.name,
            "SERVICE_PRIVATE_KEY_PATH": str(ROOT / f".secrets/service-keys/{s.name}.pem"),
            "SERVICE_TRUST_BUNDLE_PATH": str(ROOT / ".secrets/service-keys/trust.json"),
            "REDIS_URL": f"redis://:{redis_pw}@{args.redis}/0",
            "AUDIT_URL": urls["audit"] if s.name != "audit" else "",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "",
            "RAW_STORE_PATH": str(run_dir / "raw"), "QUARANTINE_PATH": str(run_dir / "quarantine"),
            "SMTP_HOST": "127.0.0.1", "SMTP_PORT": "1025",
            "ALLOWED_ORIGINS": f'["{env.get("WEB_ORIGIN", "http://localhost:3000")}"]',
            "COOKIE_SECURE": "false", "DEV_LOGIN_ENABLED": env.get("DEV_LOGIN_ENABLED", "false"),
            "POST_LOGIN_REDIRECT": env.get("WEB_ORIGIN", "http://localhost:3000") + "/",
            "OPENAI_MODEL": env.get("SAMIIR_OPENAI_MODEL" if s.name == "samiir-agent"
                                    else "FATMA_OPENAI_MODEL", ""),
        })
        if s.db_role:
            pw = env[f"DB_PASSWORD_{s.db_role.upper()}"]
            penv["DATABASE_URL"] = f"postgresql+asyncpg://{s.db_role}:{pw}@{args.db_host}/{db}"
        for var, target in s.downstream.items():
            penv[var] = urls[target]
        for secret in s.secrets:
            if env.get(secret):
                penv[secret] = env[secret]
        if not penv.get("OPENAI_MODEL"):
            penv.pop("OPENAI_MODEL")
        log = open(run_dir / f"{s.name}.log", "ab")  # noqa: SIM115
        cmd = [sys.executable, "-m", "uvicorn", "--factory", s.factory, "--host", "127.0.0.1",
               "--port", str(s.port), "--no-server-header", "--proxy-headers",
               "--forwarded-allow-ips", "127.0.0.1"]
        procs.append(subprocess.Popen(cmd, cwd=ROOT, env=penv, stdout=log, stderr=log))
        print(f"started {s.name:20s} :{s.port}  ({shlex.join(cmd[-8:-6])})")

    def stop(*_: object) -> None:
        for p in procs:
            p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print("logs in .run/*.log — public gateway http://localhost:8000, admin http://localhost:8001")
    while True:
        for p, s in zip(procs, SERVICES, strict=True):
            if p.poll() is not None:
                print(f"{s.name} exited with {p.returncode}; see .run/{s.name}.log")
                stop()
        time.sleep(2)


if __name__ == "__main__":
    main()
