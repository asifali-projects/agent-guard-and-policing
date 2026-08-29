"""Permission vocabulary and built-in role grants (PRD §50)."""

from __future__ import annotations

from ..models.enums import MembershipRole

# code -> (category, description)
PERMISSIONS: dict[str, tuple[str, str]] = {
    "org.read": ("organization", "View organization details"),
    "org.manage": ("organization", "Edit organization settings, SSO, and lifecycle"),
    "org.billing": ("organization", "View and manage billing, plans, and invoices"),
    "member.read": ("organization", "List members and their roles"),
    "member.manage": ("organization", "Invite, remove, and change roles of members"),
    "apikey.read": ("developer", "List API keys and their metadata"),
    "apikey.manage": ("developer", "Create, rotate, and revoke API keys"),
    "agent.read": ("security", "View the agent inventory and agent detail"),
    "agent.manage": ("security", "Register, edit, pause, and archive agents"),
    "tool.read": ("security", "View the tool inventory"),
    "tool.manage": ("security", "Edit tool metadata and agent-tool grants"),
    "mcp.read": ("security", "View MCP servers and their scan results"),
    "mcp.manage": ("security", "Register MCP servers and trigger scans"),
    "policy.read": ("governance", "View policies and bindings"),
    "policy.manage": ("governance", "Create, edit, and bind policies"),
    "redteam.read": ("security", "View red-team assessments and tests"),
    "redteam.run": ("security", "Launch red-team assessments"),
    "finding.read": ("security", "View findings"),
    "finding.manage": ("security", "Triage, suppress, assign, and resolve findings"),
    "threat.read": ("security", "View detected threats"),
    "incident.read": ("security", "View incidents and their timelines"),
    "incident.manage": ("security", "Create, update, and respond to incidents"),
    "approval.read": ("security", "View approval requests"),
    "approval.decide": ("security", "Approve or reject approval requests"),
    "data.read": ("governance", "View data classifications and DLP policies"),
    "data.manage": ("governance", "Edit data classifications and DLP policies"),
    "audit.read": ("observability", "Read and export the audit log"),
    "analytics.read": ("observability", "View dashboards, risk, and the agent graph"),
    "integration.read": ("developer", "View integrations and webhooks"),
    "integration.manage": ("developer", "Connect and configure integrations and webhooks"),
    "runtime.evaluate": ("runtime", "Call the runtime decision endpoint"),
}

ALL_PERMISSIONS = frozenset(PERMISSIONS)
_READ_ONLY = frozenset(c for c in PERMISSIONS if c.endswith(".read"))

SYSTEM_ROLE_GRANTS: dict[MembershipRole, frozenset[str]] = {
    MembershipRole.owner: ALL_PERMISSIONS,
    MembershipRole.admin: ALL_PERMISSIONS - {"org.billing"},
    MembershipRole.security_admin: frozenset(
        {
            "org.read",
            "member.read",
            "agent.read",
            "agent.manage",
            "tool.read",
            "tool.manage",
            "mcp.read",
            "mcp.manage",
            "policy.read",
            "policy.manage",
            "redteam.read",
            "redteam.run",
            "finding.read",
            "finding.manage",
            "threat.read",
            "incident.read",
            "incident.manage",
            "approval.read",
            "approval.decide",
            "data.read",
            "data.manage",
            "audit.read",
            "analytics.read",
            "integration.read",
        }
    ),
    MembershipRole.security_analyst: _READ_ONLY | {"analytics.read", "audit.read"},
    MembershipRole.developer: frozenset(
        {
            "org.read",
            "agent.read",
            "agent.manage",
            "tool.read",
            "tool.manage",
            "mcp.read",
            "mcp.manage",
            "policy.read",
            "redteam.read",
            "redteam.run",
            "finding.read",
            "apikey.read",
            "apikey.manage",
            "integration.read",
            "integration.manage",
            "analytics.read",
            "runtime.evaluate",
        }
    ),
    MembershipRole.auditor: _READ_ONLY | {"audit.read", "analytics.read"},
    MembershipRole.billing_admin: frozenset({"org.read", "org.billing"}),
}


def permissions_for_role(role: MembershipRole) -> frozenset[str]:
    return SYSTEM_ROLE_GRANTS.get(role, frozenset())
