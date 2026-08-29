import assert from "node:assert/strict";
import { test } from "node:test";

import { AgentGuard } from "../src/guard.js";
import { ApprovalRequired, PolicyDenied, RateLimited } from "../src/errors.js";
import { Decision } from "../src/types.js";
import { REDACTED } from "../src/redact.js";
import { AGENT_ID, makeFetch, throwingFetch } from "./helpers.js";

function makeGuard(decisions: Record<string, Record<string, unknown>> = {}, opts = {}) {
  const fake = makeFetch(decisions);
  const guard = new AgentGuard({
    apiKey: "ag_dev_test_secret",
    baseUrl: "http://test",
    agent: "TestAgent",
    environment: "production",
    fetch: fake.fn,
    ...opts,
  });
  return { guard, calls: fake.calls };
}

test("ALLOW calls the wrapped function and forwards named params", async () => {
  const { guard, calls } = makeGuard();
  const add = guard.tool(async ({ a, b }: { a: number; b: number }) => a + b, { name: "add" });
  assert.equal(await add({ a: 2, b: 3 }), 5);
  assert.equal(calls[0]!.tool, "add");
  assert.deepEqual(calls[0]!.parameters, { a: 2, b: 3 });
});

test("DENY raises PolicyDenied with reasons", async () => {
  const { guard } = makeGuard({ wire_money: { decision: "DENY", reasons: ["policy FIN-1"] } });
  const wire = guard.tool(async (_: { amount: number }) => "sent", { name: "wire_money" });
  await assert.rejects(() => wire({ amount: 1000 }), (err: unknown) => {
    assert.ok(err instanceof PolicyDenied);
    assert.match(err.message, /FIN-1/);
    assert.equal(err.result.decision, Decision.Deny);
    return true;
  });
});

test("APPROVAL raises ApprovalRequired carrying the request id", async () => {
  const { guard } = makeGuard({
    pay: { decision: "APPROVAL", approval_request_id: "abc-123", reasons: ["needs sign-off"] },
  });
  const pay = guard.tool(async (_: { vendor: string }) => "paid", { name: "pay" });
  await assert.rejects(() => pay({ vendor: "acme" }), (err: unknown) => {
    assert.ok(err instanceof ApprovalRequired);
    assert.equal(err.approvalRequestId, "abc-123");
    return true;
  });
});

test("REDACT masks the flagged argument before the call", async () => {
  const { guard } = makeGuard({
    send_email: { decision: "REDACT", redactions: ["parameters.body"] },
  });
  const seen: Record<string, unknown> = {};
  const sendEmail = guard.tool(
    async (args: { to: string; body: string }) => {
      Object.assign(seen, args);
    },
    { name: "send_email" },
  );
  await sendEmail({ to: "x@y.com", body: "my SSN is 123-45-6789" });
  assert.equal(seen.to, "x@y.com");
  assert.equal(seen.body, REDACTED);
});

test("RATE_LIMIT raises RateLimited with retryAfterSeconds", async () => {
  const { guard } = makeGuard({
    search: { decision: "RATE_LIMIT", rate_limit: { retry_after_seconds: 42 } },
  });
  const search = guard.tool(async (_: { q: string }) => [], { name: "search" });
  await assert.rejects(() => search({ q: "hello" }), (err: unknown) => {
    assert.ok(err instanceof RateLimited);
    assert.equal(err.retryAfterSeconds, 42);
    return true;
  });
});

test("fail-closed converts an unreachable runtime into PolicyDenied", async () => {
  const guard = new AgentGuard({
    apiKey: "ag_dev_x_y",
    baseUrl: "http://test",
    agent: "TestAgent",
    fetch: throwingFetch(),
    failMode: "closed",
  });
  guard.setAgentId(AGENT_ID);
  const t = guard.tool(async () => "ran", { name: "t" });
  await assert.rejects(() => t({}), PolicyDenied);
});

test("fail-open runs the function when the runtime is down", async () => {
  const guard = new AgentGuard({
    apiKey: "ag_dev_x_y",
    baseUrl: "http://test",
    agent: "TestAgent",
    fetch: throwingFetch(),
    failMode: "open",
  });
  guard.setAgentId(AGENT_ID);
  const t = guard.tool(async () => "ran", { name: "t" });
  assert.equal(await t({}), "ran");
});

test("identity resolution reuses an existing agent", async () => {
  const { guard } = makeGuard();
  assert.equal(await guard.agentId(), AGENT_ID);
});

test("waitForApproval returns the decided status", async () => {
  const { guard } = makeGuard();
  assert.equal(await guard.waitForApproval("abc-123", { pollMs: 1 }), "approved");
});

test("check returns effective parameters without throwing on ALLOW", async () => {
  const { guard } = makeGuard();
  const { result, parameters } = await guard.check("noop", { x: 1 });
  assert.equal(result.decision, Decision.Allow);
  assert.deepEqual(parameters, { x: 1 });
});
