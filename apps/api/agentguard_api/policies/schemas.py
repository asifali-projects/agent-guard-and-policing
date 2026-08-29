"""Policy management request/response models."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from ..models.enums import Environment, PolicyScopeType


class PolicyIn(BaseModel):
    key: str = Field(min_length=2, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=2, max_length=200)
    description: str | None = None
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=1000)
    spec: dict


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = None
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=1000)
    spec: dict | None = None


class PolicyOut(BaseModel):
    id: uuid.UUID
    key: str
    name: str
    description: str | None
    enabled: bool
    priority: int
    spec: dict
    version: int
    created_at: datetime
    updated_at: datetime


class BindingIn(BaseModel):
    scope_type: PolicyScopeType
    environment: Environment | None = None
    agent_id: uuid.UUID | None = None
    tool_id: uuid.UUID | None = None
    action: str | None = Field(default=None, max_length=120)


class BindingOut(BaseModel):
    id: uuid.UUID
    policy_id: uuid.UUID
    scope_type: PolicyScopeType
    environment: Environment | None
    agent_id: uuid.UUID | None
    tool_id: uuid.UUID | None
    action: str | None


class ValidateIn(BaseModel):
    spec: dict


class ValidateOut(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    rule_count: int = 0


class SimulateIn(BaseModel):
    agent_id: uuid.UUID
    tool: str
    action: str = "execute"
    parameters: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)
    data_classification: str | None = None


class SimulateOut(BaseModel):
    decision: str
    policy_keys: list[str]
    reasons: list[str]
    redactions: list[str]
    default_applied: bool
