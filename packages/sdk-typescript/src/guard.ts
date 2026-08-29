/** The `AgentGuard` facade — identity, tool interception, enforcement (PRD §37). */

import { randomUUID } from "node:crypto";

import { AgentGuardClient, type FetchLike } from "./client.js";
import {
  type AgentGuardConfig,
  type ConfigOverrides,
  resolveConfig,
} from "./config.js";
import {
  ApprovalRequired,
  ConfigurationError,
  PolicyDenied,
  RateLimited,
  RuntimeUnavailable,
} from "./errors.js";
import { applyRedactions } from "./redact.js";
import { Decision, type DecisionResult, unavailableResult } from "./types.js";

export interface AgentGuardOptions extends ConfigOverrides {
  /** Inject a fetch implementation (tests, proxies). */
  fetch?: FetchLike;
  /** Register the agent automatically on first use. Default true. */
  autoRegister?: boolean;
}

export interface EvaluateOptions {
  action?: string;
  context?: Record<string, unknown>;
  requestId?: string;
  dataClassification?: string;
}

type Params = Record<string, unknown>;
// deliberately permissive: the wrapper forwards whatever the caller passes
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyFn = (...args: any[]) => unknown;

export class AgentGuard {
  readonly config: AgentGuardConfig;
  readonly client: AgentGuardClient;
  private agentIdCache: string | null = null;

  constructor(options: AgentGuardOptions = {}) {
    this.config = resolveConfig(options);
    this.client = new AgentGuardClient({
      apiKey: this.config.apiKey,
      baseUrl: this.config.baseUrl,
      timeoutMs: this.config.timeoutMs,
      fetch: options.fetch,
    });
  }

  /** Resolve (and, if needed, register) the agent id for the configured agent. */
  async agentId(): Promise<string> {
    if (this.agentIdCache === null) {
      if (!this.config.agent) {
        throw new ConfigurationError(
          "no agent — pass agent to AgentGuard() or set AGENTGUARD_AGENT",
        );
      }
      this.agentIdCache = await this.client.resolveAgentId({
        name: this.config.agent,
        environment: this.config.environment,
      });
    }
    return this.agentIdCache;
  }

  /** Pre-set the agent id (skips the identity lookup). */
  setAgentId(id: string): void {
    this.agentIdCache = id;
  }

  /** Ask the runtime what to do. Returns a decision; only throws
   * `RuntimeUnavailable` when fail_mode='closed' and the API is unreachable. */
  async evaluate(
    tool: string,
    parameters: Params = {},
    options: EvaluateOptions = {},
  ): Promise<DecisionResult> {
    const requestId = options.requestId ?? randomUUID();
    try {
      return await this.client.evaluate({
        agentId: await this.agentId(),
        tool,
        action: options.action ?? "execute",
        parameters,
        context: options.context ?? {},
        requestId,
        dataClassification: options.dataClassification,
      });
    } catch (err) {
      if (err instanceof RuntimeUnavailable) {
        if (this.config.failMode === "open") {
          const result = unavailableResult("fail-open");
          return {
            ...result,
            decision: Decision.Allow,
            riskScore: 0,
            riskSeverity: "info",
            reasons: ["runtime unavailable — fail-open"],
            failMode: "fail_open",
            allowed: true,
            requestId,
          };
        }
      }
      throw err;
    }
  }

  /** Evaluate and enforce. Resolves to `{ result, parameters }` on ALLOW /
   * REDACT (parameters may be a masked copy); rejects otherwise. */
  async check(
    tool: string,
    parameters: Params = {},
    options: EvaluateOptions = {},
  ): Promise<{ result: DecisionResult; parameters: Params }> {
    let result: DecisionResult;
    try {
      result = await this.evaluate(tool, parameters, options);
    } catch (err) {
      if (err instanceof RuntimeUnavailable) {
        throw new PolicyDenied(
          `runtime unavailable (fail-closed): ${err.message}`,
          unavailableResult(err.message),
        );
      }
      throw err;
    }

    switch (result.decision) {
      case Decision.Allow:
        return { result, parameters };
      case Decision.Redact:
        return { result, parameters: applyRedactions(parameters, result.redactions) };
      case Decision.Approval:
        throw new ApprovalRequired(result.reasons.join("; ") || "approval required", result);
      case Decision.RateLimit:
        throw new RateLimited(result.reasons.join("; ") || "rate limited", result);
      default:
        throw new PolicyDenied(result.reasons.join("; ") || "denied", result);
    }
  }

  /** Wrap a tool function so every call is enforced. The wrapped function is
   * async. It expects a single plain-object argument of named parameters
   * (the shape every major agent framework uses); on REDACT the masked copy is
   * passed through. Positional-arg tools are evaluated but not redacted. */
  tool<F extends AnyFn>(fn: F, options: { name?: string; action?: string } = {}): F {
    const toolName = options.name ?? (fn.name || "tool");
    const guard = this;
    const wrapped = async function (this: unknown, ...args: unknown[]) {
      const single =
        args.length === 1 && args[0] != null && typeof args[0] === "object" && !Array.isArray(args[0]);
      const params: Params = single ? (args[0] as Params) : { args };
      const { result, parameters } = await guard.check(toolName, params, {
        action: options.action,
      });
      const callArgs = single && result.decision === Decision.Redact ? [parameters] : args;
      return fn.apply(this, callArgs);
    };
    Object.defineProperty(wrapped, "name", { value: toolName });
    (wrapped as { agentGuardTool?: string }).agentGuardTool = toolName;
    return wrapped as unknown as F;
  }

  /** Register the agent and, if `target.tools` is a discoverable array, wrap it. */
  async protect<T extends { tools?: unknown[] }>(target: T): Promise<T> {
    await this.agentId();
    if (Array.isArray(target.tools)) {
      target.tools = target.tools.map((t) => (typeof t === "function" ? this.tool(t as AnyFn) : t));
    }
    (target as { agentguard?: AgentGuard }).agentguard = this;
    return target;
  }

  /** Block until an approval request is decided. Returns its final status. */
  async waitForApproval(
    approvalRequestId: string,
    options: { pollMs?: number; timeoutMs?: number } = {},
  ): Promise<string> {
    const pollMs = options.pollMs ?? 2000;
    const deadline = Date.now() + (options.timeoutMs ?? 300_000);
    while (Date.now() < deadline) {
      const row = (await this.client.get(`/v1/approvals/${approvalRequestId}`)) as {
        status: string;
      };
      if (row.status !== "pending") return row.status;
      await new Promise((r) => setTimeout(r, pollMs));
    }
    return "timeout";
  }
}
