import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { DEFAULT_BASE_URL, resolveConfig, saveConfig } from "../src/config.js";
import { ConfigurationError } from "../src/errors.js";

const ENV_KEYS = [
  "AGENTGUARD_API_KEY",
  "AGENTGUARD_BASE_URL",
  "AGENTGUARD_AGENT",
  "AGENTGUARD_ENVIRONMENT",
  "AGENTGUARD_FAIL_MODE",
  "AGENTGUARD_TIMEOUT",
  "AGENTGUARD_CONFIG",
];

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = {};
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  process.env.AGENTGUARD_CONFIG = join(mkdtempSync(join(tmpdir(), "ag-")), "config.json");
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

test("explicit args win and defaults fill the rest", () => {
  const cfg = resolveConfig({ apiKey: "ag_live_1", agent: "Fin" });
  assert.equal(cfg.apiKey, "ag_live_1");
  assert.equal(cfg.agent, "Fin");
  assert.equal(cfg.baseUrl, DEFAULT_BASE_URL);
  assert.equal(cfg.environment, "production");
  assert.equal(cfg.failMode, "closed");
  assert.equal(cfg.timeoutMs, 5000);
});

test("env vars override the file and are overridden by args", () => {
  process.env.AGENTGUARD_API_KEY = "env-key";
  process.env.AGENTGUARD_BASE_URL = "https://env.example/";
  process.env.AGENTGUARD_TIMEOUT = "12";
  const cfg = resolveConfig();
  assert.equal(cfg.apiKey, "env-key");
  assert.equal(cfg.baseUrl, "https://env.example");
  assert.equal(cfg.timeoutMs, 12000);
});

test("missing API key throws ConfigurationError", () => {
  assert.throws(() => resolveConfig(), ConfigurationError);
  assert.doesNotThrow(() => resolveConfig({ requireApiKey: false }));
});

test("an invalid fail mode is rejected", () => {
  assert.throws(
    () => resolveConfig({ apiKey: "k", failMode: "halfway" as "open" }),
    ConfigurationError,
  );
});

test("saveConfig round-trips through resolveConfig", () => {
  const path = saveConfig({ api_key: "ag_saved", base_url: "https://saved.example" });
  assert.equal(path, process.env.AGENTGUARD_CONFIG);
  const cfg = resolveConfig();
  assert.equal(cfg.apiKey, "ag_saved");
  assert.equal(cfg.baseUrl, "https://saved.example");
});

test("a corrupt config file surfaces a ConfigurationError", () => {
  writeFileSync(process.env.AGENTGUARD_CONFIG as string, "{ not json");
  assert.throws(() => resolveConfig({ requireApiKey: false }), ConfigurationError);
});
