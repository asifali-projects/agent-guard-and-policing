from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

os.environ.setdefault("AGENTGUARD_ENV", "test")

import asyncio

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from agentguard_api.config import get_settings

API_DIR = Path(__file__).resolve().parents[1]
asyncpg = pytest.importorskip("asyncpg")


@pytest.fixture
async def client():
    """App client with NO database — for health/meta tests only."""
    from agentguard_api.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# --- database-backed client -------------------------------------------------


def _admin_url(url: str) -> str:
    parts = urlsplit(url.replace("+asyncpg", ""))
    return urlunsplit(parts._replace(path="/postgres"))


async def _create_db(admin: str, name: str) -> None:
    conn = await asyncpg.connect(admin)
    try:
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()


async def _drop_db(admin: str, name: str) -> None:
    conn = await asyncpg.connect(admin)
    try:
        await conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1", name
        )
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def _database_url() -> str:
    base = get_settings().database_url
    admin = _admin_url(base)
    try:
        asyncio.run(_create_db(admin, "ag_probe_only__"))
    except Exception:
        pytest.skip("Postgres not reachable — run `docker compose up -d`")
    else:
        asyncio.run(_drop_db(admin, "ag_probe_only__"))

    name = f"ag_test_{uuid.uuid4().hex[:12]}"
    asyncio.run(_create_db(admin, name))

    url = urlunsplit(urlsplit(base)._replace(path=f"/{name}"))
    env = {**os.environ, "DATABASE_URL": url}
    for args in (["-m", "alembic", "upgrade", "head"], ["-m", "agentguard_api.rbac.seed"]):
        proc = subprocess.run(
            [sys.executable, *args], cwd=API_DIR, env=env, capture_output=True, text=True
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout

    yield url

    asyncio.run(_drop_db(admin, name))


@pytest_asyncio.fixture
async def api(_database_url: str):
    """App client wired to a migrated + seeded throwaway Postgres database."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    from agentguard_api import db as db_module
    from agentguard_api.db import get_session
    from agentguard_api.main import app

    engine = create_async_engine(_database_url, poolclass=NullPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def _override():
        async with maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            else:
                await session.commit()

    app.dependency_overrides[get_session] = _override
    # db.ping() (readiness) should also hit the test DB
    db_module._engine = engine
    db_module._sessionmaker = maker

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()
    await engine.dispose()
    db_module._engine = None
    db_module._sessionmaker = None
