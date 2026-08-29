export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type DecisionStr = "ALLOW" | "DENY" | "APPROVAL" | "REDACT" | "RATE_LIMIT";

export type RegionCode = "us" | "eu" | "me" | "apac";

export interface Me {
  id: string;
  email: string;
  full_name: string | null;
  mfa_enabled: boolean;
  is_superuser: boolean;
  active_organization_id: string | null;
  active_region: RegionCode | null;
  region: RegionCode;
  permissions: string[];
  memberships: {
    organization_id: string;
    organization_name: string;
    role: string;
    region: RegionCode | null;
  }[];
}

export interface RegionInfo {
  code: RegionCode;
  name: string;
  api_url: string;
  web_url: string | null;
  current: boolean;
}
export interface RegionsResponse {
  current: RegionCode;
  regions: RegionInfo[];
}

export interface DashboardSummary {
  security_score: number;
  assets: { agents: number; mcp_servers: number; tools: number };
  threats: { critical: number; high: number; medium: number };
  runtime: { actions_24h: number; blocked_24h: number; approvals_pending: number };
  top_risky_agents: { id: string; name: string; risk_score: number | null; open_findings: number }[];
}

export interface Agent {
  id: string;
  name: string;
  kind: string;
  framework: string;
  model: string | null;
  environment: string;
  owner_team: string | null;
  description: string | null;
  status: string;
  risk_score: number | null;
  fail_mode: string;
  tags: string[];
  identity: string | null;
  created_at: string;
  updated_at: string;
}

export interface Tool {
  id: string;
  name: string;
  display_name: string | null;
  risk: Severity;
  permissions: string[];
  destination: string | null;
  owner_team: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  assessment_id: string | null;
  agent_id: string;
  tool_id: string | null;
  title: string;
  category: string;
  severity: Severity;
  risk_score: number | null;
  status: string;
  recommendation: string | null;
  owner_id: string | null;
  resolution_note: string | null;
  created_at: string;
  updated_at: string;
}

export interface Assessment {
  id: string;
  agent_id: string;
  environment: string;
  profile: string;
  status: string;
  trigger: string | null;
  model: string | null;
  summary: {
    total?: number;
    passed?: number;
    failed?: number;
    findings?: number;
    by_severity?: Record<string, number>;
  };
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface RedTeamTest {
  id: string;
  attack_id: string;
  category: string;
  technique: string;
  input_summary: string | null;
  expected_behavior: string | null;
  observed_behavior: string | null;
  severity: Severity;
  passed: boolean;
}

export interface Policy {
  id: string;
  key: string;
  name: string;
  description: string | null;
  enabled: boolean;
  priority: number;
  spec: unknown;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface Approval {
  id: string;
  request_id: string;
  agent_id: string;
  action: string;
  parameters: Record<string, unknown>;
  parameters_hash: string;
  risk_score: number | null;
  severity: Severity;
  reason: string | null;
  status: string;
  requested_at: string;
  expires_at: string | null;
  decided_at: string | null;
}

export interface AuditEvent {
  id: string;
  occurred_at: string;
  action: string;
  actor_type: string;
  actor_id: string | null;
  agent_id: string | null;
  tool: string | null;
  policy_key: string | null;
  decision: string | null;
  risk_score: number | null;
  request_id: string | null;
  entry_hash: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  key_type: string;
  environment: string;
  scopes: string[];
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  usage_count: number;
  created_at: string;
}

export interface Member {
  user_id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
}

export interface McpServer {
  id: string;
  name: string;
  url: string | null;
  version: string | null;
  status: string;
  risk: Severity;
  trusted: boolean;
  permissions: string[];
  external_dependencies: string[];
  last_scan_at: string | null;
  scan_summary: Record<string, unknown>;
}

export interface RiskAssessment {
  risk_score: number;
  severity: Severity;
  decision: string;
  factors: { name: string; score: number; weight: number; detail: string }[];
}
