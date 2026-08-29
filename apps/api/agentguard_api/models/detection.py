"""Per-agent behavioral baseline (PRD §28).

Updated synchronously on every runtime evaluation (one indexed upsert). The
anomaly detector reads it; Step 8's heavier ClickHouse-backed baselines run in a
worker later.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin, org_column


class BehaviorProfile(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "behavior_profiles"

    organization_id: Mapped[uuid.UUID] = org_column()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), unique=True
    )
    total_calls: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # {tool: count}
    tool_counts: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # {tool: max record/count parameter seen}
    tool_max_volume: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # distinct destinations ever seen (capped)
    destinations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # data classifications ever seen
    classifications: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # last N tool names, most recent last
    recent_sequence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    last_anomaly_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    baseline_since: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
