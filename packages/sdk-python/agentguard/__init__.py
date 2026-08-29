"""AgentGuard SDK — runtime security for AI agents (PRD §37–38).

from agentguard import AgentGuard

guard = AgentGuard(api_key="ag_live_...", agent="FinanceAgent", environment="production")

@guard.tool
def send_email(to: str, subject: str, body: str) -> None:
    ...
"""

from .decision import Decision, DecisionResult
from .exceptions import (
    AgentGuardError,
    ApprovalRequired,
    ConfigurationError,
    PolicyDenied,
    RateLimited,
    RuntimeUnavailable,
)
from .guard import AgentGuard

__all__ = [
    "AgentGuard",
    "AgentGuardError",
    "ApprovalRequired",
    "ConfigurationError",
    "Decision",
    "DecisionResult",
    "PolicyDenied",
    "RateLimited",
    "RuntimeUnavailable",
]

__version__ = "0.0.0"
