"""Conversation persistence, quota, and audit for the AI Security Analyst."""

from __future__ import annotations

import time
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .. import audit_log
from ..auth.dependencies import Principal
from ..cache import get_client
from ..config import get_settings
from ..models import AnalystConversation, AnalystMessage
from ..models.enums import ActorType
from . import engine


class AnalystError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


async def _check_quota(org_id: uuid.UUID) -> None:
    quota = get_settings().analyst_hourly_quota
    if quota <= 0:
        return
    key = f"analyst:q:{org_id}:{int(time.time() // 3600)}"
    try:
        redis = get_client()
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, 3600)
    except Exception:
        return
    if count > quota:
        raise AnalystError(429, f"hourly analyst quota ({quota}) exceeded for this organization")


def _title(question: str) -> str:
    q = " ".join(question.split())
    return (q[:80] + "…") if len(q) > 80 else q


async def ask(
    db: AsyncSession, *, principal: Principal, question: str, conversation_id: uuid.UUID | None
) -> tuple[AnalystConversation, AnalystMessage]:
    settings = get_settings()
    if not settings.analyst_enabled:
        raise AnalystError(503, "the AI Security Analyst is disabled")
    org_id = principal.organization_id
    assert org_id is not None
    await _check_quota(org_id)

    history: list[dict] = []
    if conversation_id is not None:
        conv = await db.scalar(
            select(AnalystConversation)
            .where(
                AnalystConversation.id == conversation_id,
                AnalystConversation.organization_id == org_id,
            )
            .options(selectinload(AnalystConversation.messages))
        )
        if conv is None:
            raise AnalystError(404, "conversation not found")
        history = [
            {"role": m.role, "content": m.content}
            for m in sorted(conv.messages, key=lambda m: m.created_at)
        ][-12:]
    else:
        conv = AnalystConversation(
            organization_id=org_id, user_id=principal.user_id, title=_title(question)
        )
        db.add(conv)
        await db.flush()

    db.add(AnalystMessage(conversation_id=conv.id, role="user", content=question))
    await db.flush()

    result = await engine.answer(db, org_id=org_id, question=question, history=history)

    answer = AnalystMessage(
        conversation_id=conv.id,
        role="assistant",
        content=result.answer,
        tool_calls=result.tool_calls,
        citations=result.citations,
        engine=result.engine,
    )
    db.add(answer)
    await db.flush()

    await audit_log.record(
        db,
        organization_id=org_id,
        action="analyst.query",
        actor_type=ActorType.user,
        user_id=principal.user_id,
        actor_label=principal.actor_label,
        metadata={
            "conversation_id": str(conv.id),
            "engine": result.engine,
            "tools": [c["tool"] for c in result.tool_calls],
        },
    )
    await db.refresh(answer)
    return conv, answer


async def list_conversations(
    db: AsyncSession, org_id: uuid.UUID, limit: int = 50
) -> list[AnalystConversation]:
    return list(
        (
            await db.scalars(
                select(AnalystConversation)
                .where(AnalystConversation.organization_id == org_id)
                .order_by(AnalystConversation.updated_at.desc())
                .limit(limit)
            )
        ).all()
    )


async def get_conversation(
    db: AsyncSession, org_id: uuid.UUID, conversation_id: uuid.UUID
) -> AnalystConversation:
    conv = await db.scalar(
        select(AnalystConversation)
        .where(
            AnalystConversation.id == conversation_id,
            AnalystConversation.organization_id == org_id,
        )
        .options(selectinload(AnalystConversation.messages))
    )
    if conv is None:
        raise AnalystError(404, "conversation not found")
    return conv


def suggestions() -> list[str]:
    from .fallback import SUGGESTIONS

    return SUGGESTIONS
