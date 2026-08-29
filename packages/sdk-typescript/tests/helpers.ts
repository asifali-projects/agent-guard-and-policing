import type { FetchLike } from "../src/client.js";

export const AGENT_ID = "11111111-1111-1111-1111-111111111111";

export interface FakeFetch {
  fn: FetchLike;
  calls: Array<Record<string, unknown>>;
}

/** A fetch stand-in for the AgentGuard API. `decisions` maps a tool name to a
 * partial runtime response that overrides the default ALLOW. */
export function makeFetch(decisions: Record<string, Record<string, unknown>> = {}): FakeFetch {
  const calls: Array<Record<string, unknown>> = [];
  const agent = { id: AGENT_ID, name: "TestAgent", environment: "production", status: "healthy" };

  const fn = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const path = url.pathname;
    const method = init?.method ?? "GET";
    const json = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });

    if (path === "/v1/agents" && method === "GET") return json([agent]);
    if (path === "/v1/agents" && method === "POST") return json(agent, 201);
    if (path === "/v1/runtime/evaluate") {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      calls.push(body);
      const base: Record<string, unknown> = {
        decision: "ALLOW",
        risk_score: 10,
        risk_severity: "low",
        request_id: body.request_id ?? "r",
        reasons: [],
        redactions: [],
        fail_mode: "fail_closed",
        cache_hit: false,
        evaluated_in_ms: 1.0,
      };
      return json({ ...base, ...(decisions[body.tool as string] ?? {}) });
    }
    if (path.startsWith("/v1/approvals/")) return json({ status: "approved" });
    return json({ detail: "not found" }, 404);
  }) as FetchLike;

  return { fn, calls };
}

export function throwingFetch(): FetchLike {
  return (async () => {
    throw new Error("ECONNREFUSED");
  }) as FetchLike;
}
