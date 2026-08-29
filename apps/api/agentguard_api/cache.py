"""Redis client + a connectivity check for readiness probes."""

from __future__ import annotations

import redis.asyncio as redis

from .config import get_settings

_client: redis.Redis | None = None


def get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(get_settings().redis_url, decode_responses=True)
    return _client


async def ping() -> bool:
    """Return True if Redis answers PING."""
    return bool(await get_client().ping())


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
