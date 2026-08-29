"""SDK exception hierarchy."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .decision import DecisionResult


class AgentGuardError(Exception):
    """Base class for every AgentGuard SDK error."""


class ConfigurationError(AgentGuardError):
    """Missing or invalid configuration (API key, base URL, agent)."""


class RuntimeUnavailable(AgentGuardError):
    """The runtime API could not be reached. Fail-safe behaviour applies."""


class BlockedError(AgentGuardError):
    """Base for decisions that prevent the tool call."""

    def __init__(self, message: str, result: DecisionResult) -> None:
        super().__init__(message)
        self.result = result


class PolicyDenied(BlockedError):
    """The action was denied (policy, DLP block, or critical risk)."""


class ApprovalRequired(BlockedError):
    """A human must approve this exact action before it can proceed."""

    @property
    def approval_request_id(self) -> str | None:
        return self.result.approval_request_id


class RateLimited(BlockedError):
    """The action exceeded its rate-limit budget."""

    @property
    def retry_after_seconds(self) -> int | None:
        return self.result.rate_limit.get("retry_after_seconds") if self.result.rate_limit else None
