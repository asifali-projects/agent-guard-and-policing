"""Fixed-window rate limiting backed by Redis (PRD §24 RATE_LIMIT)."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from agentguard_policy import RateLimitSpec

from ..cache import get_client


@dataclass(frozen=True)
class RateVerdict:
    allowed: bool
    remaining: int
    retry_after_seconds: int


def _bucket_key(
    org_id: uuid.UUID, agent_id: uuid.UUID, tool: str, spec: RateLimitSpec, now: float
) -> str:
    window = int(now // spec.window_seconds)
    if spec.scope == "agent":
        subject = f"a:{agent_id}"
    elif spec.scope == "tool":
        subject = f"t:{tool}"
    else:
        subject = f"a:{agent_id}:t:{tool}"
    return f"rl:{org_id}:{subject}:{spec.window_seconds}:{window}"


async def check_and_consume(
    *, org_id: uuid.UUID, agent_id: uuid.UUID, tool: str, spec: RateLimitSpec
) -> RateVerdict:
    now = time.time()
    key = _bucket_key(org_id, agent_id, tool, spec, now)
    redis = get_client()

    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, spec.window_seconds)

    retry_after = spec.window_seconds - int(now % spec.window_seconds)
    if count > spec.max:
        return RateVerdict(allowed=False, remaining=0, retry_after_seconds=retry_after)
    return RateVerdict(
        allowed=True, remaining=max(spec.max - count, 0), retry_after_seconds=retry_after
    )
