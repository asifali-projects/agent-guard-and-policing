/** Resolve SDK configuration: explicit args → env vars → config file → default.
 *
 * Config file: `~/.agentguard/config.json` (or `$AGENTGUARD_CONFIG`)
 *
 *   { "api_key": "ag_live_...", "base_url": "https://api.agentguard.example",
 *     "agent": "FinanceAgent", "environment": "production" }
 */

import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { ConfigurationError } from "./errors.js";

export const DEFAULT_BASE_URL = "http://localhost:8010";

export type FailMode = "closed" | "open";

export interface AgentGuardConfig {
  apiKey: string;
  baseUrl: string;
  agent: string | null;
  environment: string;
  failMode: FailMode;
  timeoutMs: number;
}

export interface ConfigOverrides {
  apiKey?: string;
  baseUrl?: string;
  agent?: string | null;
  environment?: string;
  failMode?: FailMode;
  timeoutMs?: number;
  requireApiKey?: boolean;
}

export function configPath(): string {
  const override = process.env.AGENTGUARD_CONFIG;
  if (override) return override;
  return join(homedir(), ".agentguard", "config.json");
}

function loadFile(): Record<string, string> {
  try {
    const text = readFileSync(configPath(), "utf8");
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof v === "string") out[k] = v;
    }
    return out;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw new ConfigurationError(`could not read ${configPath()}: ${(err as Error).message}`);
  }
}

export function resolveConfig(overrides: ConfigOverrides = {}): AgentGuardConfig {
  const file = loadFile();
  const requireApiKey = overrides.requireApiKey ?? true;

  const apiKey = overrides.apiKey ?? process.env.AGENTGUARD_API_KEY ?? file.api_key ?? "";
  if (requireApiKey && !apiKey) {
    throw new ConfigurationError(
      "no API key — pass apiKey, set AGENTGUARD_API_KEY, or run `agentguard login`",
    );
  }

  const baseUrl = (
    overrides.baseUrl ??
    process.env.AGENTGUARD_BASE_URL ??
    file.base_url ??
    DEFAULT_BASE_URL
  ).replace(/\/+$/, "");

  const agent =
    overrides.agent ?? process.env.AGENTGUARD_AGENT ?? file.agent ?? null;

  const environment =
    overrides.environment ??
    process.env.AGENTGUARD_ENVIRONMENT ??
    file.environment ??
    "production";

  const failMode = (
    overrides.failMode ??
    (process.env.AGENTGUARD_FAIL_MODE as FailMode | undefined) ??
    (file.fail_mode as FailMode | undefined) ??
    "closed"
  ).toLowerCase() as FailMode;
  if (failMode !== "closed" && failMode !== "open") {
    throw new ConfigurationError("failMode must be 'closed' or 'open'");
  }

  const timeoutMs =
    overrides.timeoutMs ??
    (process.env.AGENTGUARD_TIMEOUT ? Number(process.env.AGENTGUARD_TIMEOUT) * 1000 : 5000);

  return { apiKey, baseUrl, agent, environment, failMode, timeoutMs };
}

export function saveConfig(data: Record<string, string | null | undefined>): string {
  const path = configPath();
  mkdirSync(dirname(path), { recursive: true });
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(data)) {
    if (v != null) clean[k] = v;
  }
  writeFileSync(path, `${JSON.stringify(clean, null, 2)}\n`, "utf8");
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best effort on platforms without POSIX perms */
  }
  return path;
}
