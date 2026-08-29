"""Policy specification model (stored in `policies.spec` as JSON)."""

from __future__ import annotations

import fnmatch

from pydantic import BaseModel, Field, model_validator

from .conditions import validate_condition
from .types import Effect, RateLimitSpec


class PolicyRule(BaseModel):
    effect: Effect
    # Tool / action patterns this rule applies to. Matched against the tool name
    # ("payment.create") and against "tool:action" ("payment.create:execute").
    # fnmatch globs allowed ("payment.*", "*").
    actions: list[str] = Field(default_factory=lambda: ["*"])
    when: dict | None = None
    redactions: list[str] = Field(default_factory=list)
    rate_limit: RateLimitSpec | None = None
    description: str | None = None

    @model_validator(mode="after")
    def _check(self) -> PolicyRule:
        validate_condition(self.when)
        if self.effect == Effect.rate_limit and self.rate_limit is None:
            raise ValueError("rate_limit rule requires a 'rate_limit' spec")
        if self.effect == Effect.redact and not self.redactions:
            raise ValueError("redact rule requires non-empty 'redactions'")
        return self

    def matches_action(self, tool: str, action: str) -> bool:
        target_full = f"{tool}:{action}"
        for pat in self.actions:
            if pat == "*" or fnmatch.fnmatch(tool, pat) or fnmatch.fnmatch(target_full, pat):
                return True
        return False


class PolicySpec(BaseModel):
    rules: list[PolicyRule] = Field(default_factory=list)
    default_effect: Effect | None = None

    @model_validator(mode="after")
    def _check_default(self) -> PolicySpec:
        if self.default_effect in (Effect.redact, Effect.rate_limit):
            raise ValueError("default_effect must be allow, deny, or approval")
        return self


class CompiledPolicy(BaseModel):
    """A policy bound at some scope, ready for evaluation."""

    key: str
    spec: PolicySpec
    priority: int = 100
    # 0 = organization, 1 = environment, 2 = agent, 3 = tool, 4 = action
    specificity: int = 0

    @property
    def sort_key(self) -> tuple[int, int]:
        # More specific first, then lower priority number first.
        return (-self.specificity, self.priority)
