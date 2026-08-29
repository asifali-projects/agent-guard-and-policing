/** The decision object returned by the runtime API (PRD §24, §42). */

export enum Decision {
  Allow = "ALLOW",
  Deny = "DENY",
  Approval = "APPROVAL",
  Redact = "REDACT",
  RateLimit = "RATE_LIMIT",
}

export interface RateLimit {
  max: number;
  window_seconds: number;
  scope: string;
  remaining?: number | null;
  retry_after_seconds?: number | null;
}

export interface DecisionResult {
  decision: Decision;
  riskScore: number;
  riskSeverity: string;
  requestId: string;
  policyId: string | null;
  policyKeys: string[];
  reasons: string[];
  redactions: string[];
  dataClassification: string | null;
  approvalRequestId: string | null;
  rateLimit: RateLimit | null;
  failMode: string;
  cacheHit: boolean;
  evaluatedInMs: number;
  /** Convenience: true only for an ALLOW decision. */
  allowed: boolean;
}

const asString = (v: unknown, fallback = ""): string => (typeof v === "string" ? v : fallback);
const asNumber = (v: unknown, fallback = 0): number => (typeof v === "number" ? v : fallback);
const asStringList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

export function decisionFromApi(raw: unknown): DecisionResult {
  const body = (raw ?? {}) as Record<string, unknown>;
  const decision = asString(body.decision, "DENY") as Decision;
  return {
    decision,
    riskScore: asNumber(body.risk_score),
    riskSeverity: asString(body.risk_severity, "info"),
    requestId: asString(body.request_id),
    policyId: (body.policy_id as string | null) ?? null,
    policyKeys: asStringList(body.policy_keys),
    reasons: asStringList(body.reasons),
    redactions: asStringList(body.redactions),
    dataClassification: (body.data_classification as string | null) ?? null,
    approvalRequestId: (body.approval_request_id as string | null) ?? null,
    rateLimit: (body.rate_limit as RateLimit | null) ?? null,
    failMode: asString(body.fail_mode, "fail_closed"),
    cacheHit: body.cache_hit === true,
    evaluatedInMs: asNumber(body.evaluated_in_ms),
    allowed: decision === Decision.Allow,
  };
}

export function unavailableResult(reason: string): DecisionResult {
  return {
    decision: Decision.Deny,
    riskScore: 100,
    riskSeverity: "critical",
    requestId: "",
    policyId: null,
    policyKeys: [],
    reasons: [`runtime unavailable: ${reason}`],
    redactions: [],
    dataClassification: null,
    approvalRequestId: null,
    rateLimit: null,
    failMode: "fail_closed",
    cacheHit: false,
    evaluatedInMs: 0,
    allowed: false,
  };
}
