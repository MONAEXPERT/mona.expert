import assert from "node:assert/strict";
import test from "node:test";
import { createSafeEnv, getSentinelStatus, startSentinel, stopSentinel } from "../src/agents/sentinel.js";
import { listAgents } from "../src/agent-registry.js";
import { readFile, stat } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const SANDBOX = join(ROOT, "..", ".mona-agents", "sandbox", "sentinel");

test("sentinel agent is registered in the built-in catalog", async () => {
  const agents = await listAgents();
  const sentinel = agents.find((a) => a.id === "sentinel");
  assert.ok(sentinel, "sentinel agent should exist in registry");
  assert.equal(sentinel.permissions.api_keys.length, 0, "sentinel must declare zero local API keys");
  assert.equal(sentinel.permissions.shell, false, "sentinel must not allow shell");
  assert.equal(sentinel.safety.rating, "green");
});

test("createSafeEnv builds a locked-down sandbox with no secret material", async () => {
  const result = await createSafeEnv();
  assert.equal(result.ok, true);

  // Directory must be owner-only
  const dirStat = await stat(SANDBOX);
  const mode = dirStat.mode & 0o777;
  assert.equal(mode, 0o700, `sandbox dir mode should be 0700, got ${mode.toString(8)}`);

  // sandbox.json must be owner-only too
  const fileStat = await stat(join(SANDBOX, "sandbox.json"));
  const fileMode = fileStat.mode & 0o777;
  assert.equal(fileMode, 0o600, `sandbox.json mode should be 0600, got ${fileMode.toString(8)}`);

  // Manifest must declare the zero-secret policy
  const manifest = JSON.parse(await readFile(join(SANDBOX, "sandbox.json"), "utf8"));
  assert.equal(manifest.policy.localKeys, "none");
  assert.equal(manifest.policy.outbound, "wrapper-only");
  assert.equal(manifest.secretsStoredLocally, 0);

  // The manifest itself must not contain secret-looking fields
  const raw = await readFile(join(SANDBOX, "sandbox.json"), "utf8");
  assert.ok(!raw.toLowerCase().includes("password"));
  assert.ok(!raw.toLowerCase().includes("api_key"));
});

test("sentinel lifecycle: start → status → stop", async () => {
  const started = await startSentinel();
  assert.ok(started.ok);

  const status = await getSentinelStatus();
  assert.equal(status.running, true);
  assert.equal(status.safeEnv, true);
  assert.equal(status.localSecretsStored, 0, "invariant: no secrets stored locally");

  const stopped = stopSentinel();
  assert.equal(stopped.status, "stopped");

  const after = await getSentinelStatus();
  assert.equal(after.running, false);
  assert.equal(after.sessionActive, false, "session token must be wiped on stop");
});
