/** SDK exception hierarchy — mirrors `agentguard.exceptions` in the Python SDK. */

import type { DecisionResult } from "./types.js";

export class AgentGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Missing or invalid configuration (API key, base URL, agent). */
export class ConfigurationError extends AgentGuardError {}

/** The runtime API could not be reached. Fail-safe behaviour applies. */
export class RuntimeUnavailable extends AgentGuardError {}

/** Base for decisions that prevent the tool call. Carries the full result. */
export class BlockedError extends AgentGuardError {
  readonly result: DecisionResult;
  constructor(message: string, result: DecisionResult) {
    super(message);
    this.result = result;
  }
}

/** The action was denied (policy, DLP block, or critical risk). */
export class PolicyDenied extends BlockedError {}

/** A human must approve this exact action before it can proceed. */
export class ApprovalRequired extends BlockedError {
  get approvalRequestId(): string | null {
    return this.result.approvalRequestId;
  }
}

/** The action exceeded its rate-limit budget. */
export class RateLimited extends BlockedError {
  get retryAfterSeconds(): number | null {
    return this.result.rateLimit?.retry_after_seconds ?? null;
  }
}
