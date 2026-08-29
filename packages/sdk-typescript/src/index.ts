/**
 * AgentGuard SDK — runtime security for AI agents (PRD §37–38).
 *
 * ```ts
 * import { AgentGuard } from "@agentguard/sdk";
 *
 * const guard = new AgentGuard({ apiKey: "ag_live_...", agent: "FinanceAgent", environment: "production" });
 *
 * const sendEmail = guard.tool(async ({ to, subject, body }: { to: string; subject: string; body: string }) => {
 *   // runs only if the runtime returns ALLOW; REDACT masks flagged args
 * });
 * ```
 */

export { AgentGuard } from "./guard.js";
export type { AgentGuardOptions, EvaluateOptions } from "./guard.js";
export { AgentGuardClient } from "./client.js";
export type { ClientOptions, EvaluateArgs, FetchLike } from "./client.js";
export {
  type AgentGuardConfig,
  type ConfigOverrides,
  type FailMode,
  DEFAULT_BASE_URL,
  configPath,
  resolveConfig,
  saveConfig,
} from "./config.js";
export {
  AgentGuardError,
  ApprovalRequired,
  BlockedError,
  ConfigurationError,
  PolicyDenied,
  RateLimited,
  RuntimeUnavailable,
} from "./errors.js";
export { Decision, type DecisionResult, type RateLimit, decisionFromApi } from "./types.js";
export { REDACTED, applyRedactions } from "./redact.js";

export const VERSION = "0.0.0";
