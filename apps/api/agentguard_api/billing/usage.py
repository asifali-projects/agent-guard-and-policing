"""Usage metering via Redis counters (PRD §65).

One INCR per metered event — cheap enough for the runtime hot path. A worker
flushes the monthly counters into `usage_records` for invoicing later; until
then the billing endpoint reads Redis directly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ..cache import get_client
from ..logging import get_logger

log = get_logger("billing.usage")

# PRD §65
METRICS = (
    "runtime_actions",
    "redteam_tests",
    "data_scans",
    "runtime_blocked",
)


def _period() -> str:
    return datetime.now(UTC).strftime("%Y-%m")


def _key(org_id: uuid.UUID, metric: str, period: str | None = None) -> str:
    return f"usage:{org_id}:{metric}:{period or _period()}"


async def increment(metric: str, organization_id: uuid.UUID, n: int = 1) -> None:
    try:
        key = _key(organization_id, metric)
        redis = get_client()
        await redis.incrby(key, n)
        # keep two periods of history, then let it expire
        await redis.expire(key, 60 * 60 * 24 * 70)
    except Exception as exc:
        log.warning("usage.increment_failed", metric=metric, error=str(exc))


async def current(organization_id: uuid.UUID) -> dict[str, int]:
    period = _period()
    out: dict[str, int] = {}
    try:
        redis = get_client()
        for metric in METRICS:
            raw = await redis.get(_key(organization_id, metric, period))
            out[metric] = int(raw) if raw else 0
    except Exception as exc:
        log.warning("usage.read_failed", error=str(exc))
        out = dict.fromkeys(METRICS, 0)
    return out
