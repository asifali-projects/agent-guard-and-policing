"""Request/response models + the internal analyst result type (PRD §35)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from pydantic import BaseModel, Field


@dataclass
class AnalystResult:
    answer: str
    engine: str  # "claude" | "fallback"
    citations: list[dict] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    conversation_id: uuid.UUID | None = None


class MessageOut(BaseModel):
    id: uuid.UUID
    role: str
    content: str
    tool_calls: list[dict]
    citations: list[dict]
    engine: str | None
    created_at: datetime


class AskResponse(BaseModel):
    conversation_id: uuid.UUID
    message: MessageOut


class ConversationOut(BaseModel):
    id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime


class ConversationDetail(ConversationOut):
    messages: list[MessageOut]


class SuggestionsResponse(BaseModel):
    enabled: bool
    engine: str
    suggestions: list[str]
