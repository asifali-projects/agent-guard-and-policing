"""Runtime API request/response models (PRD §42)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class RuntimeEvaluateRequest(BaseModel):
    agent_id: uuid.UUID
    tool: str = Field(min_length=1, max_length=200)
    action: str = Field(default="execute", max_length=60)
    parameters: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)
    # Opaque id supplied by the caller to correlate this decision end-to-end.
    request_id: str | None = Field(default=None, max_length=80)
    # If the caller already knows the sensitivity of the payload.
    data_classification: str | None = None


class RateLimitOut(BaseModel):
    max: int
    window_seconds: int
    scope: str
    remaining: int | None = None
    retry_after_seconds: int | None = None


class RuntimeEvaluateResponse(BaseModel):
    decision: str  # ALLOW | DENY | APPROVAL | REDACT | RATE_LIMIT  (PRD §24)
    risk_score: int
    request_id: str
    policy_id: str | None = None
    policy_keys: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)
    approval_request_id: uuid.UUID | None = None
    rate_limit: RateLimitOut | None = None
    fail_mode: str
    cache_hit: bool
    evaluated_in_ms: float
