"""SQLAlchemy models for the AgentGuard control plane (PRD §44).

Import this module (or ``target_metadata``) from Alembic so every table is
registered before autogenerate runs.
"""

from __future__ import annotations

from .agent import Agent, AgentIdentity, AgentVersion
from .approval import ApprovalDecision, ApprovalRequest
from .audit import AuditEvent
from .auth import ExternalIdentity, Session
from .base import Base
from .billing import Invoice, Plan, Subscription, UsageRecord
from .data_security import DataClassificationRule, DataPolicy
from .detection import BehaviorProfile
from .incident import Incident, IncidentEvent, Threat
from .integration import Integration, Webhook
from .mcp import McpServer, McpTool
from .organization import (
    ApiKey,
    Membership,
    Organization,
    Permission,
    Role,
    ServiceAccount,
    User,
)
from .policy import Policy, PolicyBinding, PolicyVersion
from .redteam import RedTeamAssessment, RedTeamFinding, RedTeamTest
from .tool import AgentTool, Tool, ToolVersion

target_metadata = Base.metadata

__all__ = [
    "Agent",
    "AgentIdentity",
    "AgentTool",
    "AgentVersion",
    "ApiKey",
    "ApprovalDecision",
    "ApprovalRequest",
    "AuditEvent",
    "Base",
    "BehaviorProfile",
    "DataClassificationRule",
    "DataPolicy",
    "ExternalIdentity",
    "Incident",
    "IncidentEvent",
    "Integration",
    "Invoice",
    "McpServer",
    "McpTool",
    "Membership",
    "Organization",
    "Permission",
    "Plan",
    "Policy",
    "PolicyBinding",
    "PolicyVersion",
    "RedTeamAssessment",
    "RedTeamFinding",
    "RedTeamTest",
    "Role",
    "ServiceAccount",
    "Session",
    "Subscription",
    "Threat",
    "Tool",
    "ToolVersion",
    "UsageRecord",
    "User",
    "Webhook",
    "target_metadata",
]
