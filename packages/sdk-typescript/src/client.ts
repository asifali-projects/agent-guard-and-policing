/** Thin fetch-based HTTP client for the AgentGuard API. */

import { AgentGuardError, RuntimeUnavailable } from "./errors.js";
import { type DecisionResult, decisionFromApi } from "./types.js";

const USER_AGENT = "agentguard-typescript/0.0.0";

export type FetchLike = typeof fetch;

export interface ClientOptions {
  apiKey: string;
  baseUrl: string;
  timeoutMs?: number;
  /** Inject a fetch implementation (tests, proxies). Defaults to global fetch. */
  fetch?: FetchLike;
}

export interface EvaluateArgs {
  agentId: string;
  tool: string;
  action?: string;
  parameters?: Record<string, unknown>;
  context?: Record<string, unknown>;
  requestId?: string;
  dataClassification?: string;
}

interface AgentRow {
  id: string;
  name: string;
  environment: string;
}

export class AgentGuardClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;
  private readonly fetchImpl: FetchLike;

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    if (!this.fetchImpl) {
      throw new AgentGuardError("no fetch implementation available (Node >= 18 or pass opts.fetch)");
    }
    this.headers = {
      Authorization: `Bearer ${opts.apiKey}`,
      "User-Agent": USER_AGENT,
    };
  }

  async evaluate(args: EvaluateArgs): Promise<DecisionResult> {
    const payload: Record<string, unknown> = {
      agent_id: args.agentId,
      tool: args.tool,
      action: args.action ?? "execute",
      parameters: args.parameters ?? {},
      context: args.context ?? {},
    };
    if (args.requestId) payload.request_id = args.requestId;
    if (args.dataClassification) payload.data_classification = args.dataClassification;

    const res = await this.send("POST", "/v1/runtime/evaluate", { body: payload });
    return decisionFromApi(await this.json(res));
  }

  async get(path: string, query?: Record<string, string | number | undefined>): Promise<unknown> {
    const res = await this.send("GET", path, { query });
    return this.json(res);
  }

  async post(path: string, body?: unknown): Promise<unknown> {
    const res = await this.send("POST", path, { body });
    return this.json(res);
  }

  async resolveAgentId(args: { name: string; environment: string }): Promise<string> {
    const agents = (await this.get("/v1/agents")) as AgentRow[];
    const match = agents.find((a) => a.name === args.name && a.environment === args.environment);
    if (match) return match.id;
    const created = (await this.post("/v1/agents", {
      name: args.name,
      environment: args.environment,
    })) as AgentRow;
    return created.id;
  }

  private async send(
    method: string,
    path: string,
    opts: { body?: unknown; query?: Record<string, string | number | undefined> },
  ): Promise<Response> {
    const url = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
    }
    const headers = { ...this.headers };
    let payload: string | undefined;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(opts.body);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(url, {
        method,
        headers,
        body: payload,
        signal: controller.signal,
      });
    } catch (err) {
      throw new RuntimeUnavailable(`${method} ${path} failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  private async json(res: Response): Promise<unknown> {
    if (res.status >= 400) {
      let detail: string = res.statusText;
      try {
        const parsed = (await res.json()) as { detail?: unknown };
        detail = typeof parsed.detail === "string" ? parsed.detail : JSON.stringify(parsed);
      } catch {
        /* keep statusText */
      }
      throw new AgentGuardError(`HTTP ${res.status}: ${detail}`);
    }
    if (res.status === 204) return null;
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }
}
