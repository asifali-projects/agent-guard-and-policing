"""Shared enumerations.

Stored as VARCHAR (``native_enum=False``) so adding a value is a code change,
not a Postgres ``ALTER TYPE`` migration.
"""

from __future__ import annotations

from enum import StrEnum


class Environment(StrEnum):
    development = "development"
    staging = "staging"
    production = "production"


class MembershipRole(StrEnum):
    """PRD §50."""

    owner = "owner"
    admin = "admin"
    security_admin = "security_admin"
    security_analyst = "security_analyst"
    developer = "developer"
    auditor = "auditor"
    billing_admin = "billing_admin"


class AgentKind(StrEnum):
    """PRD §10 — what is being secured."""

    ai_agent = "ai_agent"
    mcp_server = "mcp_server"
    rag_application = "rag_application"
    coding_agent = "coding_agent"
    multi_agent_system = "multi_agent_system"


class Framework(StrEnum):
    """PRD §10 — framework selection."""

    openai = "openai"
    langgraph = "langgraph"
    langchain = "langchain"
    crewai = "crewai"
    semantic_kernel = "semantic_kernel"
    mcp = "mcp"
    custom = "custom"


class AgentStatus(StrEnum):
    healthy = "healthy"
    warning = "warning"
    high = "high"
    critical = "critical"
    paused = "paused"
    archived = "archived"


class TrustLevel(StrEnum):
    untrusted = "untrusted"
    low = "low"
    standard = "standard"
    high = "high"
    privileged = "privileged"


class PermissionScope(StrEnum):
    """PRD §15."""

    read = "read"
    write = "write"
    execute = "execute"
    admin = "admin"


class RiskSeverity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Decision(StrEnum):
    """Policy decision engine output — PRD §24."""

    allow = "allow"
    deny = "deny"
    approval = "approval"
    redact = "redact"
    rate_limit = "rate_limit"


class PolicyEffect(StrEnum):
    """PRD §23 — deny / approval / allow."""

    allow = "allow"
    deny = "deny"
    approval = "approval"


class PolicyScopeType(StrEnum):
    """Policy hierarchy — PRD §23."""

    organization = "organization"
    environment = "environment"
    agent = "agent"
    tool = "tool"
    action = "action"


class FailMode(StrEnum):
    """Behaviour when AgentGuard is unavailable — PRD §59."""

    fail_open = "fail_open"
    fail_closed = "fail_closed"
    fail_safe = "fail_safe"  # per-tool decision table


class DataClassification(StrEnum):
    """PRD §27."""

    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


class DlpAction(StrEnum):
    """PRD §27."""

    allow = "allow"
    redact = "redact"
    block = "block"
    approval = "approval"


class McpServerStatus(StrEnum):
    active = "active"
    review_required = "review_required"
    quarantined = "quarantined"
    disabled = "disabled"


class AssessmentProfile(StrEnum):
    """PRD §18."""

    quick = "quick"
    standard = "standard"
    deep = "deep"
    enterprise = "enterprise"
    custom = "custom"


class AssessmentStatus(StrEnum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class AttackCategory(StrEnum):
    """PRD §19."""

    prompt = "prompt"
    tool = "tool"
    data = "data"
    agent = "agent"
    mcp = "mcp"
    availability = "availability"


class FindingStatus(StrEnum):
    """PRD §22."""

    open = "open"
    triaged = "triaged"
    suppressed = "suppressed"
    false_positive = "false_positive"
    retest = "retest"
    resolved = "resolved"


class ThreatStatus(StrEnum):
    open = "open"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"


class IncidentStatus(StrEnum):
    """PRD §30."""

    detected = "detected"
    investigating = "investigating"
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    expired = "expired"


class ApprovalDecisionType(StrEnum):
    approved = "approved"
    rejected = "rejected"


class ApiKeyType(StrEnum):
    """PRD §52."""

    publishable = "publishable"
    secret = "secret"
    runtime = "runtime"
    cicd = "cicd"


class IntegrationCategory(StrEnum):
    """PRD §62."""

    identity = "identity"
    siem = "siem"
    devops = "devops"
    notifications = "notifications"
    ticketing = "ticketing"
    cloud = "cloud"


class PlanCode(StrEnum):
    """PRD §64."""

    community = "community"
    developer = "developer"
    team = "team"
    business = "business"
    enterprise = "enterprise"


class SubscriptionStatus(StrEnum):
    trialing = "trialing"
    active = "active"
    past_due = "past_due"
    canceled = "canceled"


class InvoiceStatus(StrEnum):
    draft = "draft"
    open = "open"
    paid = "paid"
    void = "void"


class UsageMetric(StrEnum):
    """PRD §65."""

    runtime_actions = "runtime_actions"
    redteam_tests = "redteam_tests"
    agents = "agents"
    mcp_servers = "mcp_servers"
    data_scans = "data_scans"
    users = "users"
    storage = "storage"


class ActorType(StrEnum):
    system = "system"
    user = "user"
    agent = "agent"
    service_account = "service_account"
