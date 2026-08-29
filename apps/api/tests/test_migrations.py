"""Migration checks against a throwaway Postgres database.

Skipped automatically when Postgres is unreachable (e.g. `docker compose up`
was not run). CI provides a Postgres service so these always run there.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest

from agentguard_api.config import get_settings

API_DIR = Path(__file__).resolve().parents[1]
psycopg_asyncpg = pytest.importorskip("asyncpg")


def _split_db(url: str) -> tuple[str, str]:
    # strip the SQLAlchemy driver suffix for a raw asyncpg connection
    raw = url.replace("+asyncpg", "")
    parts = urlsplit(raw)
    db = parts.path.lstrip("/")
    admin = urlunsplit(parts._replace(path="/postgres"))
    return admin, db


async def _pg_reachable(admin_url: str) -> bool:
    try:
        conn = await psycopg_asyncpg.connect(admin_url)
        await conn.close()
        return True
    except Exception:
        return False


@pytest.fixture
async def throwaway_db_url() -> str:
    settings = get_settings()
    admin_url, _ = _split_db(settings.database_url)
    if not await _pg_reachable(admin_url):
        pytest.skip("Postgres not reachable — run `docker compose up -d`")

    name = f"ag_test_{uuid.uuid4().hex[:12]}"
    conn = await psycopg_asyncpg.connect(admin_url)
    await conn.execute(f'CREATE DATABASE "{name}"')
    await conn.close()

    parts = urlsplit(settings.database_url)
    yield urlunsplit(parts._replace(path=f"/{name}"))

    conn = await psycopg_asyncpg.connect(admin_url)
    await conn.execute(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1", name
    )
    await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
    await conn.close()


def _alembic(url: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DATABASE_URL": url}
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=API_DIR,
        env=env,
        capture_output=True,
        text=True,
    )


def test_upgrade_head_then_check_reports_no_drift(throwaway_db_url: str):
    up = _alembic(throwaway_db_url, "upgrade", "head")
    assert up.returncode == 0, up.stderr

    check = _alembic(throwaway_db_url, "check")
    assert check.returncode == 0, f"models diverge from migrations:\n{check.stdout}\n{check.stderr}"


def test_downgrade_base_is_clean(throwaway_db_url: str):
    assert _alembic(throwaway_db_url, "upgrade", "head").returncode == 0
    down = _alembic(throwaway_db_url, "downgrade", "base")
    assert down.returncode == 0, down.stderr
    # A second upgrade must still succeed (no leftover objects).
    assert _alembic(throwaway_db_url, "upgrade", "head").returncode == 0
