"""Liveness and readiness probes.

- ``/healthz`` — process is up. Never touches dependencies.
- ``/readyz``  — process can serve traffic: Postgres and Redis both reachable.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Response, status

from .. import __version__, cache, db

router = APIRouter(tags=["health"])


@router.get("/healthz", summary="Liveness probe")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/readyz", summary="Readiness probe")
async def readyz(response: Response) -> dict[str, object]:
    async def check(coro) -> bool:
        try:
            return await asyncio.wait_for(coro, timeout=2.0)
        except Exception:
            return False

    postgres_ok, redis_ok = await asyncio.gather(check(db.ping()), check(cache.ping()))
    checks = {"postgres": postgres_ok, "redis": redis_ok}
    ready = all(checks.values())

    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ready else "degraded", "checks": checks}
