"""Load + update the per-agent behavioural baseline."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import BehaviorProfile
from .anomaly import _max_volume

_DEST_CAP = 50
_CLASS_CAP = 8
_SEQ_CAP = 25


async def load_profile(session: AsyncSession, agent_id: uuid.UUID) -> BehaviorProfile | None:
    return await session.scalar(select(BehaviorProfile).where(BehaviorProfile.agent_id == agent_id))


def as_dict(p: BehaviorProfile | None) -> dict | None:
    if p is None:
        return None
    return {
        "total_calls": p.total_calls,
        "tool_counts": p.tool_counts,
        "tool_max_volume": p.tool_max_volume,
        "destinations": p.destinations,
        "classifications": p.classifications,
        "recent_sequence": p.recent_sequence,
    }


async def observe(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    agent_id: uuid.UUID,
    tool: str,
    parameters: dict,
    context: dict,
    classification: str | None,
    anomaly_score: int,
) -> None:
    p = await load_profile(session, agent_id)
    if p is None:
        p = BehaviorProfile(organization_id=organization_id, agent_id=agent_id)
        session.add(p)

    p.total_calls = (p.total_calls or 0) + 1
    counts = dict(p.tool_counts or {})
    counts[tool] = counts.get(tool, 0) + 1
    p.tool_counts = counts

    volume = _max_volume(parameters or {})
    if volume:
        maxes = dict(p.tool_max_volume or {})
        maxes[tool] = max(int(maxes.get(tool, 0)), volume)
        p.tool_max_volume = maxes

    dest = str((context or {}).get("destination") or (context or {}).get("destination_url") or "")
    if dest and dest not in (p.destinations or []):
        p.destinations = ([*(p.destinations or []), dest])[-_DEST_CAP:]

    if classification and classification not in (p.classifications or []):
        p.classifications = ([*(p.classifications or []), classification])[-_CLASS_CAP:]

    p.recent_sequence = ([*(p.recent_sequence or []), tool])[-_SEQ_CAP:]
    p.last_anomaly_score = anomaly_score
    p.last_evaluated_at = datetime.now(UTC)
    await session.flush()
