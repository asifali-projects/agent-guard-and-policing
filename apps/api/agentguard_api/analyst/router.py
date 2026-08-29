"""AI Security Analyst endpoints — /v1/analyst/* (PRD §35)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException

from ..auth.dependencies import DbSession, Principal, require_permission
from ..models import AnalystConversation, AnalystMessage
from . import engine, service
from .schemas import (
    AskRequest,
    AskResponse,
    ConversationDetail,
    ConversationOut,
    MessageOut,
    SuggestionsResponse,
)

router = APIRouter(prefix="/v1/analyst", tags=["analyst"])

QueryDep = Annotated[Principal, Depends(require_permission("analyst.query"))]


def _msg_out(m: AnalystMessage) -> MessageOut:
    return MessageOut(
        id=m.id,
        role=m.role,
        content=m.content,
        tool_calls=list(m.tool_calls or []),
        citations=list(m.citations or []),
        engine=m.engine,
        created_at=m.created_at,
    )


def _conv_out(c: AnalystConversation) -> ConversationOut:
    return ConversationOut(id=c.id, title=c.title, created_at=c.created_at, updated_at=c.updated_at)


@router.get("/suggestions", response_model=SuggestionsResponse)
async def get_suggestions(principal: QueryDep) -> SuggestionsResponse:
    from ..config import get_settings

    return SuggestionsResponse(
        enabled=get_settings().analyst_enabled,
        engine=engine.engine_name(),
        suggestions=service.suggestions(),
    )


@router.post("/ask", response_model=AskResponse)
async def ask(body: AskRequest, db: DbSession, principal: QueryDep) -> AskResponse:
    try:
        conv, answer = await service.ask(
            db,
            principal=principal,
            question=body.question,
            conversation_id=body.conversation_id,
        )
    except service.AnalystError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    return AskResponse(conversation_id=conv.id, message=_msg_out(answer))


@router.get("/conversations", response_model=list[ConversationOut])
async def list_conversations(db: DbSession, principal: QueryDep) -> list[ConversationOut]:
    rows = await service.list_conversations(db, principal.organization_id)
    return [_conv_out(c) for c in rows]


@router.get("/conversations/{conversation_id}", response_model=ConversationDetail)
async def get_conversation(
    conversation_id: uuid.UUID, db: DbSession, principal: QueryDep
) -> ConversationDetail:
    try:
        conv = await service.get_conversation(db, principal.organization_id, conversation_id)
    except service.AnalystError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    return ConversationDetail(
        id=conv.id,
        title=conv.title,
        created_at=conv.created_at,
        updated_at=conv.updated_at,
        messages=[_msg_out(m) for m in conv.messages],
    )


@router.delete("/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(conversation_id: uuid.UUID, db: DbSession, principal: QueryDep):
    try:
        conv = await service.get_conversation(db, principal.organization_id, conversation_id)
    except service.AnalystError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    await db.delete(conv)
