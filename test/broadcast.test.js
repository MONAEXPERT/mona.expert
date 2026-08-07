import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";

// ── Setup: ensure dashboard audit file exists ──
// broadcast.js has top-level await that reads .mona-dashboard/events.jsonl
// We create it empty so module import doesn't fail.
const rootDir = new URL("..", import.meta.url).pathname;
const auditDir = join(rootDir, ".mona-dashboard");
const auditFile = join(auditDir, "events.jsonl");

if (!existsSync(auditDir)) {
  mkdirSync(auditDir, { recursive: true });
}
if (!existsSync(auditFile)) {
  writeFileSync(auditFile, "", "utf8");
}

// Dynamic import triggers top-level module code (reads existing audit file)
const broadcast = await import("../src/broadcast.js");

test("broadcast functions exist", () => {
  assert.equal(typeof broadcast.broadcast, "function");
  assert.equal(typeof broadcast.broadcastBuild, "function");
  assert.equal(typeof broadcast.broadcastTest, "function");
  assert.equal(typeof broadcast.broadcastCommit, "function");
  assert.equal(typeof broadcast.broadcastAgent, "function");
});

test("broadcast returns audit record", async () => {
  const record = await broadcast.broadcast({
    type: "mona.expert.agent_event",
    summary: "test event",
    source: "test",
    severity: "info",
  });

  assert.ok(record);
  assert.ok(record.hash);
  assert.equal(typeof record.hash, "string");
  assert.equal(record.event.summary, "test event");
});

test("broadcastTest returns audit record", async () => {
  const record = await broadcast.broadcastTest({
    passed: 10,
    failed: 0,
    durationMs: 1000,
  });

  assert.ok(record);
  assert.ok(record.hash);
  assert.equal(record.event.data.passed, 10);
  assert.equal(record.event.data.failed, 0);
});

test("broadcastAgent returns audit record", async () => {
  const record = await broadcast.broadcastAgent({
    agent: "test-agent",
    status: "running",
    summary: "agent test",
  });

  assert.ok(record);
  assert.equal(record.event.data.agent, "test-agent");
  assert.equal(record.event.data.agentStatus, "running");
});

test("broadcastBuild returns audit record", async () => {
  const record = await broadcast.broadcastBuild({
    file: "test.js",
    action: "modified",
    summary: "testing",
  });

  assert.ok(record);
  assert.equal(record.event.data.file, "test.js");
  assert.equal(record.event.data.action, "modified");
});

test("broadcastCommit returns audit record", async () => {
  const record = await broadcast.broadcastCommit({
    message: "test commit",
    files: 3,
    hash: "abc123",
  });

  assert.ok(record);
  assert.ok(record.event.data.message.includes("test commit"));
});
