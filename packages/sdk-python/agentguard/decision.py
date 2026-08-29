"""The decision object returned by the runtime API (PRD §24, §42)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL = "APPROVAL"
    REDACT = "REDACT"
    RATE_LIMIT = "RATE_LIMIT"


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    risk_score: int
    risk_severity: str
    request_id: str
    policy_id: str | None = None
    policy_keys: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    data_classification: str | None = None
    approval_request_id: str | None = None
    rate_limit: dict | None = None
    fail_mode: str = "fail_closed"
    cache_hit: bool = False
    evaluated_in_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @classmethod
    def from_api(cls, body: dict) -> DecisionResult:
        return cls(
            decision=Decision(body["decision"]),
            risk_score=body.get("risk_score", 0),
            risk_severity=body.get("risk_severity", "info"),
            request_id=body.get("request_id", ""),
            policy_id=body.get("policy_id"),
            policy_keys=body.get("policy_keys", []),
            reasons=body.get("reasons", []),
            redactions=body.get("redactions", []),
            data_classification=body.get("data_classification"),
            approval_request_id=body.get("approval_request_id"),
            rate_limit=body.get("rate_limit"),
            fail_mode=body.get("fail_mode", "fail_closed"),
            cache_hit=body.get("cache_hit", False),
            evaluated_in_ms=body.get("evaluated_in_ms", 0.0),
        )
