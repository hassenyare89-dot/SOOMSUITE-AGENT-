"""The ORM mapping must match the migrated schema (tables, columns, types, nullability)."""

from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy.ext.asyncio import create_async_engine

from platform_core.db.models import Base

pytestmark = pytest.mark.db
IGNORED = {"add_index", "remove_index", "add_constraint", "remove_constraint",
           "add_fk", "remove_fk"}


async def test_models_match_migrations(migrated_db):
    from conftest import OWNER_URL

    engine = create_async_engine(OWNER_URL)
    async with engine.connect() as conn:
        def diff(sync_conn):  # noqa: ANN001, ANN202
            ctx = MigrationContext.configure(sync_conn, opts={"compare_type": True})
            return compare_metadata(ctx, Base.metadata)

        changes = await conn.run_sync(diff)
    await engine.dispose()
    flat = []
    for change in changes:
        items = change if isinstance(change, list) else [change]
        for item in items:
            if item[0] in IGNORED:
                continue
            if item[0] == "remove_table" and item[1].name == "alembic_version":
                continue
            if item[0] == "remove_column" and item[3].name == "tsv":  # generated column
                continue
            flat.append(item)
    assert not flat, flat
