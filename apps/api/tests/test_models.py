"""Model-level checks that need no database."""

from agentguard_api.models import target_metadata

# PRD §44 — the tables the data model must provide.
EXPECTED_TABLES = {
    "organizations",
    "users",
    "memberships",
    "roles",
    "permissions",
    "role_permissions",
    "service_accounts",
    "api_keys",
    "agents",
    "agent_versions",
    "agent_identities",
    "tools",
    "tool_versions",
    "agent_tools",
    "mcp_servers",
    "mcp_tools",
    "policies",
    "policy_versions",
    "policy_bindings",
    "redteam_assessments",
    "redteam_tests",
    "redteam_findings",
    "threats",
    "incidents",
    "incident_events",
    "approval_requests",
    "approval_decisions",
    "data_classifications",
    "data_policies",
    "integrations",
    "webhooks",
    "plans",
    "subscriptions",
    "usage_records",
    "invoices",
    "audit_events",
}

# Aggregate-root tables that must carry a direct organization_id (PRD §49).
# Child tables (versions, join tables, event rows) inherit tenancy via their parent FK.
TENANT_ROOT_TABLES = {
    "agents",
    "tools",
    "mcp_servers",
    "policies",
    "policy_bindings",
    "redteam_assessments",
    "redteam_findings",
    "threats",
    "incidents",
    "approval_requests",
    "data_classifications",
    "data_policies",
    "integrations",
    "webhooks",
    "api_keys",
    "service_accounts",
    "subscriptions",
    "usage_records",
    "invoices",
    "audit_events",
    "memberships",
}


def test_all_prd_tables_present():
    missing = EXPECTED_TABLES - set(target_metadata.tables)
    assert not missing, f"missing tables: {sorted(missing)}"


def test_tenant_root_tables_carry_organization_id():
    for name in TENANT_ROOT_TABLES:
        table = target_metadata.tables[name]
        assert "organization_id" in table.c, f"{name} is missing organization_id"


def test_child_tables_reference_a_parent():
    # Every non-root table should have at least one foreign key (tenancy chain).
    roots = TENANT_ROOT_TABLES | {"organizations", "users", "permissions", "plans", "roles"}
    for name, table in target_metadata.tables.items():
        if name in roots:
            continue
        assert table.foreign_keys, f"{name} has no foreign key to anchor tenancy"


def test_every_table_has_primary_key():
    for name, table in target_metadata.tables.items():
        assert list(table.primary_key.columns), f"{name} has no primary key"


def test_constraint_naming_convention_applied():
    # A representative unique constraint should use the uq_ prefix.
    agents = target_metadata.tables["agents"]
    uniques = [c for c in agents.constraints if c.__class__.__name__ == "UniqueConstraint"]
    assert any(c.name and c.name.startswith("uq_agents_") for c in uniques)
