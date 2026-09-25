"""Async engine and tenant-bound sessions.

Every tenant-scoped transaction runs ``set_config('app.tenant_id', …, true)`` (transaction
local) before any statement, so PostgreSQL row-level security filters every read and write.
Service roles do not own tables and do not have BYPASSRLS, so forgetting a WHERE clause
cannot leak cross-tenant rows.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


class Database:
    def __init__(self, url: str, *, pool_size: int = 10, statement_timeout_ms: int = 15_000,
                 application_name: str = "platform") -> None:
        self.engine: AsyncEngine = create_async_engine(
            url,
            pool_size=pool_size,
            max_overflow=pool_size,
            pool_pre_ping=True,
            pool_recycle=1800,
            connect_args={
                "server_settings": {
                    "application_name": application_name,
                    "statement_timeout": str(statement_timeout_ms),
                    "idle_in_transaction_session_timeout": "60000",
                },
            },
        )
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    @asynccontextmanager
    async def tenant_session(self, tenant_id: UUID, *, actor: str | None = None
                             ) -> AsyncIterator[AsyncSession]:
        """Transaction bound to one tenant. Commits on success, rolls back on error."""
        async with self.sessionmaker() as session, session.begin():
            await session.execute(
                text("SELECT set_config('app.tenant_id', :tid, true), "
                     "set_config('app.actor', :actor, true)"),
                {"tid": str(tenant_id), "actor": (actor or "")[:200]},
            )
            yield session

    @asynccontextmanager
    async def system_session(self) -> AsyncIterator[AsyncSession]:
        """Transaction without tenant context. RLS makes tenant tables invisible here; only
        SECURITY DEFINER lookup functions granted to the role are usable."""
        async with self.sessionmaker() as session, session.begin():
            yield session

    async def dispose(self) -> None:
        await self.engine.dispose()

    async def ping(self) -> bool:
        async with self.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
