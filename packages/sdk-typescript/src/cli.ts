#!/usr/bin/env node
/** `agentguard` command-line interface (PRD §36). */

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";

import { AgentGuardClient } from "./client.js";
import { resolveConfig, saveConfig } from "./config.js";
import { AgentGuardError } from "./errors.js";
import { VERSION } from "./index.js";

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function makeClient(opts: { apiKey?: string; baseUrl?: string }): AgentGuardClient {
  const cfg = resolveConfig({ apiKey: opts.apiKey, baseUrl: opts.baseUrl });
  return new AgentGuardClient({ apiKey: cfg.apiKey, baseUrl: cfg.baseUrl, timeoutMs: cfg.timeoutMs });
}

function fail(message: string): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(1);
}

const HELP = `agentguard ${VERSION} — secure your AI agents from the command line

usage: agentguard [--api-key KEY] [--base-url URL] <command>

commands:
  login                    save an API key to ~/.agentguard/config.json
  whoami                   show the authenticated principal
  agents list              list the agent inventory
  policy validate <file>   validate a policy spec (JSON) without saving
  scan                     per-agent risk posture summary
  logs [--limit] [--decision]
  redteam run --agent NAME [--environment] [--profile] [--fail-on]
  mcp scan [--server NAME]
  deploy [--policies DIR] [--agent NAME]... [--environment] [--profile] [--fail-on] [--pr-comment FILE]
`;

async function main(argv: string[]): Promise<void> {
  const { values: globals, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: false,
    options: {
      "api-key": { type: "string" },
      "base-url": { type: "string" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean" },
    },
  });

  if (globals.version) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  const command = positionals[0];
  if (!command || globals.help) {
    process.stdout.write(HELP);
    return;
  }

  const gopts = { apiKey: globals["api-key"] as string, baseUrl: globals["base-url"] as string };
  const rest = positionals.slice(1);

  switch (command) {
    case "login":
      return login(gopts);
    case "whoami":
      return whoami(gopts);
    case "agents":
      if (rest[0] === "list") return agentsList(gopts);
      return fail("usage: agentguard agents list");
    case "policy":
      if (rest[0] === "validate" && rest[1]) return policyValidate(gopts, rest[1]);
      return fail("usage: agentguard policy validate <file>");
    case "scan":
      return scan(gopts);
    case "logs":
      return logs(gopts, argv);
    case "redteam":
      if (rest[0] === "run") return redteamRun(gopts, argv);
      return fail("usage: agentguard redteam run --agent NAME");
    case "mcp":
      if (rest[0] === "scan") return mcpScan(gopts, argv);
      return fail("usage: agentguard mcp scan [--server NAME]");
    case "deploy":
      return deploy(gopts, argv);
    default:
      return fail(`unknown command: ${command}`);
  }
}

async function login(gopts: { apiKey?: string; baseUrl?: string }): Promise<void> {
  let apiKey = gopts.apiKey ?? process.env.AGENTGUARD_API_KEY;
  if (!apiKey) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    apiKey = (await rl.question("AgentGuard API key (input is visible): ")).trim();
    rl.close();
  }
  if (!apiKey) fail("no API key provided");
  const cfg = resolveConfig({ apiKey, baseUrl: gopts.baseUrl });
  const client = new AgentGuardClient({ apiKey: cfg.apiKey, baseUrl: cfg.baseUrl });
  try {
    await client.get("/v1/agents");
  } catch (err) {
    fail(`credentials rejected: ${(err as Error).message}`);
  }
  const path = saveConfig({ api_key: apiKey, base_url: cfg.baseUrl });
  process.stdout.write(`saved ${path}\n`);
}

async function whoami(gopts: { apiKey?: string; baseUrl?: string }): Promise<void> {
  const client = makeClient(gopts);
  try {
    const me = (await client.get("/v1/auth/me")) as {
      email: string;
      active_organization_id: string | null;
    };
    process.stdout.write(`${me.email}  org=${me.active_organization_id}\n`);
  } catch {
    process.stdout.write("authenticated as an API key\n");
  }
}

async function agentsList(gopts: { apiKey?: string; baseUrl?: string }): Promise<void> {
  const rows = (await makeClient(gopts).get("/v1/agents")) as Array<{
    name: string;
    environment: string;
    status: string;
    risk_score: number | null;
  }>;
  if (rows.length === 0) {
    process.stdout.write("no agents\n");
    return;
  }
  const width = Math.max(...rows.map((r) => r.name.length));
  for (const r of rows) {
    process.stdout.write(
      `${r.name.padEnd(width)}  ${r.environment.padEnd(11)}  ${r.status.padEnd(9)}  ` +
        `risk=${r.risk_score ?? "-"}\n`,
    );
  }
}

async function policyValidate(
  gopts: { apiKey?: string; baseUrl?: string },
  file: string,
): Promise<void> {
  let spec = JSON.parse(readFileSync(file, "utf8"));
  if (spec && typeof spec === "object" && "spec" in spec) spec = spec.spec;
  const result = (await makeClient(gopts).post("/v1/policies/validate", { spec })) as {
    valid: boolean;
    rule_count: number;
    errors: string[];
  };
  if (result.valid) {
    process.stdout.write(`OK — ${result.rule_count} rule(s)\n`);
  } else {
    for (const e of result.errors) process.stderr.write(`error: ${e}\n`);
    process.exit(1);
  }
}

async function scan(gopts: { apiKey?: string; baseUrl?: string }): Promise<void> {
  const rows = (await makeClient(gopts).get("/v1/agents")) as Array<{
    name: string;
    risk_score: number | null;
  }>;
  if (rows.length === 0) {
    process.stdout.write("no agents to scan — run `agentguard login` and connect one\n");
    return;
  }
  const hot = rows.filter((r) => (r.risk_score ?? 0) >= 65);
  process.stdout.write(`${rows.length} agent(s) scanned; ${hot.length} at high/critical risk\n`);
  for (const r of [...rows].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))) {
    process.stdout.write(`  ${r.name.padEnd(24)} risk=${r.risk_score ?? "-"}\n`);
  }
}

async function logs(gopts: { apiKey?: string; baseUrl?: string }, argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: false,
    options: { limit: { type: "string" }, decision: { type: "string" } },
  });
  const query: Record<string, string | number | undefined> = {
    limit: values.limit ? Number(values.limit) : 20,
    decision: values.decision as string | undefined,
  };
  const rows = (await makeClient(gopts).get("/v1/audit/events", query)) as
    | { items: AuditRow[] }
    | AuditRow[];
  const items = Array.isArray(rows) ? rows : rows.items;
  for (const e of items) {
    process.stdout.write(
      `${e.occurred_at}  ${(e.action ?? "").padEnd(22)}  ${(e.decision ?? "-").padEnd(9)}  ` +
        `${e.actor_id ?? ""}\n`,
    );
  }
}

interface AuditRow {
  occurred_at: string;
  action: string | null;
  decision: string | null;
  actor_id: string | null;
}

async function redteamRun(
  gopts: { apiKey?: string; baseUrl?: string },
  argv: string[],
): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: false,
    options: {
      agent: { type: "string" },
      environment: { type: "string" },
      profile: { type: "string" },
      "fail-on": { type: "string" },
    },
  });
  const agent = (values.agent as string) ?? process.env.AGENTGUARD_AGENT;
  if (!agent) fail("--agent is required (or set AGENTGUARD_AGENT)");
  const environment = (values.environment as string) ?? "production";
  const profile = (values.profile as string) ?? "standard";
  const failOn = values["fail-on"] as string | undefined;

  const client = makeClient(gopts);
  const agentId = await client.resolveAgentId({ name: agent!, environment });
  const assessment = (await client.post("/v1/redteam/assessments", {
    agent_id: agentId,
    profile,
    environment,
  })) as { summary: Summary };
  const s = assessment.summary;
  process.stdout.write(`${agent}: ${s.passed}/${s.total} defended, ${s.failed} finding(s)\n`);
  for (const sev of ["critical", "high", "medium", "low"]) {
    const n = s.by_severity?.[sev] ?? 0;
    if (n) process.stdout.write(`  ${sev.padEnd(9)} ${n}\n`);
  }
  if (failOn) {
    const findings = (await client.get("/v1/redteam/findings", {
      agent_id: agentId,
      status: "open",
    })) as Array<{ severity: string; title: string }>;
    const threshold = SEVERITY_RANK[failOn] ?? 99;
    const blockers = findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 0) >= threshold);
    if (blockers.length > 0) {
      process.stderr.write(`\n${blockers.length} finding(s) at/above ${failOn} — failing.\n`);
      for (const f of blockers) process.stderr.write(`  [${f.severity}] ${f.title}\n`);
      process.exit(1);
    }
  }
}

interface Summary {
  passed: number;
  failed: number;
  total: number;
  by_severity?: Record<string, number>;
}

async function mcpScan(gopts: { apiKey?: string; baseUrl?: string }, argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: false,
    options: { server: { type: "string" } },
  });
  const client = makeClient(gopts);
  let servers = (await client.get("/v1/mcp/servers")) as Array<{ id: string; name: string }>;
  if (values.server) {
    servers = servers.filter((s) => s.name === values.server);
    if (servers.length === 0) fail(`no MCP server named ${String(values.server)}`);
  }
  if (servers.length === 0) {
    process.stdout.write("no MCP servers registered\n");
    return;
  }
  for (const s of servers) {
    const result = (await client.post(`/v1/mcp/servers/${s.id}/scan`)) as {
      severity: string;
      status: string;
      issues: string[];
    };
    const issues = result.issues.join(", ") || "clean";
    process.stdout.write(
      `${s.name.padEnd(24)} ${result.severity.padEnd(9)} ${result.status.padEnd(16)} ${issues}\n`,
    );
  }
}

async function deploy(gopts: { apiKey?: string; baseUrl?: string }, argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: false,
    options: {
      policies: { type: "string" },
      agent: { type: "string", multiple: true },
      environment: { type: "string" },
      profile: { type: "string" },
      "fail-on": { type: "string" },
      "pr-comment": { type: "string" },
    },
  });
  const environment = (values.environment as string) ?? "production";
  const profile = (values.profile as string) ?? "quick";
  const failOn = (values["fail-on"] as string) ?? "high";
  const threshold = SEVERITY_RANK[failOn] ?? 3;
  const client = makeClient(gopts);
  const lines: string[] = ["## AgentGuard Security", ""];
  let failed = false;

  if (values.policies) {
    let bad = 0;
    for (const name of readdirSync(values.policies as string).filter((f) => f.endsWith(".json"))) {
      let spec = JSON.parse(readFileSync(`${String(values.policies)}/${name}`, "utf8"));
      spec = spec?.spec ?? spec;
      const r = (await client.post("/v1/policies/validate", { spec })) as {
        valid: boolean;
        errors: string[];
      };
      if (!r.valid) {
        bad += 1;
        failed = true;
        lines.push(`- [invalid] \`${name}\` - ${r.errors.join("; ")}`);
      }
    }
    lines.push(`- Policies: ${bad === 0 ? "all valid" : `${bad} invalid`}`);
  }

  let targets = (values.agent as string[] | undefined) ?? [];
  if (targets.length === 0) {
    const agents = (await client.get("/v1/agents")) as Array<{ name: string; environment: string }>;
    targets = agents.filter((a) => a.environment === environment).map((a) => a.name);
  }
  for (const name of targets) {
    const agentId = await client.resolveAgentId({ name, environment });
    const assessment = (await client.post("/v1/redteam/assessments", {
      agent_id: agentId,
      profile,
      environment,
    })) as { summary: Summary };
    const s = assessment.summary;
    const blockers = Object.entries(s.by_severity ?? {}).reduce(
      (acc, [k, v]) => acc + ((SEVERITY_RANK[k] ?? 0) >= threshold ? v : 0),
      0,
    );
    if (blockers > 0) failed = true;
    lines.push(
      `- [${blockers ? "FAIL" : "ok"}] **${name}**: ${s.passed}/${s.total} defended, ${s.failed} finding(s)`,
    );
  }

  lines.push("", `**${failed ? "Deployment blocked" : "Checks passed"}** (fail-on: ${failOn})`);
  const summary = lines.join("\n");
  process.stdout.write(`${summary}\n`);
  if (values["pr-comment"]) writeFileSync(values["pr-comment"] as string, `${summary}\n`, "utf8");
  if (failed) process.exit(1);
}

main(process.argv.slice(2)).catch((err) => {
  if (err instanceof AgentGuardError) fail(err.message);
  throw err;
});
