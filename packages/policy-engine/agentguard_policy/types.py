"""Core value types for the policy engine."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Decision(StrEnum):
    """Final decision produced by the engine (PRD §24)."""

    allow = "allow"
    deny = "deny"
    approval = "approval"
    redact = "redact"
    rate_limit = "rate_limit"


class Effect(StrEnum):
    """The effect a single policy rule asserts when it matches."""

    allow = "allow"
    deny = "deny"
    approval = "approval"
    redact = "redact"
    rate_limit = "rate_limit"


# Decision precedence: earlier wins. A matching `deny` rule always beats a
# matching `allow` rule, etc. (PRD §23 shows deny / approval / allow ordering).
PRECEDENCE: tuple[Effect, ...] = (
    Effect.deny,
    Effect.approval,
    Effect.rate_limit,
    Effect.redact,
    Effect.allow,
)


class RateLimitSpec(BaseModel):
    max: int = Field(gt=0)
    window_seconds: int = Field(gt=0)
    scope: Literal["agent", "tool", "agent_tool"] = "agent_tool"


class EvaluationInput(BaseModel):
    """Everything the engine needs about one attempted tool call."""

    tool: str
    action: str = "execute"
    environment: str = "production"
    agent_id: str | None = None
    agent_trust_level: str | None = None
    parameters: dict = Field(default_factory=dict)
    context: dict = Field(default_factory=dict)
    data_classification: str | None = None


class MatchedRule(BaseModel):
    policy_key: str
    rule_index: int
    effect: Effect
    reason: str


class DecisionResult(BaseModel):
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    matched: list[MatchedRule] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)
    rate_limit: RateLimitSpec | None = None
    default_applied: bool = False

    @property
    def matched_policy_keys(self) -> list[str]:
        seen: list[str] = []
        for m in self.matched:
            if m.policy_key not in seen:
                seen.append(m.policy_key)
        return seen
