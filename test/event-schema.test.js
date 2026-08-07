import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  EVENT_SCHEMA_VERSION,
  createEvent,
  normalizeEvent,
  redactEventData,
  validateEvent
} from "../src/event-schema.js";
import {
  AUDIT_HASH_ALGORITHM,
  AUDIT_RECORD_SCHEMA_VERSION,
  appendAuditEvent,
  hashAuditEvent,
  readAuditLog,
  verifyAuditChain
} from "../src/audit-log.js";

test("normalizes v1 mona.expert events with defaults", () => {
  const event = createEvent({
    id: "evt_test_001",
    ts: "2026-07-03T19:00:42.985Z",
    type: "mona.expert.safety_run",
    summary: "Safety run: review",
    data: {
      decision: "review",
      riskScore: 28
    }
  });

  assert.equal(event.schemaVersion, EVENT_SCHEMA_VERSION);
  assert.equal(event.source, "mona.expert");
  assert.equal(event.project, "mona.expert");
  assert.equal(event.severity, "info");
  assert.deepEqual(event.data, {
    decision: "review",
    riskScore: 28
  });
});

test("accepts legacy agent field as actor and timestamp alias", () => {
  const event = createEvent({
    id: "evt_test_002",
    timestamp: "2026-07-03T19:00:42.985Z",
    type: "mona.expert.agent_event",
    agent: "Safety Gate Agent",
    decision: "review",
    summary: "Tool execution requires confirmation",
    data: {}
  });

  assert.equal(event.actor, "Safety Gate Agent");
  assert.equal(event.decision, "review");
  assert.equal(event.ts, "2026-07-03T19:00:42.985Z");
});

test("normalizes provenance and evidence fields with redaction", () => {
  const event = createEvent({
    id: "evt_test_003",
    ts: "2026-07-03T19:00:42.985Z",
    type: "mona.expert.tool_approval",
    origin: "wrapper",
    producer: "Evidence Agent",
    runId: "run_001",
    requestId: "req_001",
    parentEventId: "evt_parent_001",
    summary: "Approve tool with token=secret-token",
    evidence: {
      toolId: "read_file",
      command: "Bearer abc.def.ghi",
      approverEmail: "ada@example.com"
    },
    provenance: {
      receivedAt: "2026-07-03T19:00:43.000Z",
      hostname: "mona-local",
      processId: 1234,
      sessionToken: "secret-session-token"
    },
    data: {}
  });

  assert.equal(event.summary.includes("secret-token"), false);
  assert.equal(event.origin, "wrapper");
  assert.equal(event.producer, "Evidence Agent");
  assert.equal(event.runId, "run_001");
  assert.equal(event.requestId, "req_001");
  assert.equal(event.parentEventId, "evt_parent_001");
  assert.equal(event.evidence.command, "Bearer ...redacted");
  assert.equal(event.evidence.approverEmail, "[email redacted]");
  assert.equal(event.provenance.receivedAt, "2026-07-03T19:00:43.000Z");
  assert.equal(event.provenance.sessionToken, "...redacted");
});

test("reports useful validation errors for malformed events", () => {
  const result = validateEvent(
    normalizeEvent({
      id: "",
      ts: "not-a-date",
      type: "mona.expert.unknown",
      severity: "critical",
      summary: "",
      data: []
    })
  );

  assert.equal(result.ok, false);
  assert.ok(result.errors.includes("id must be a non-empty string"));
  assert.ok(result.errors.includes("ts must be an ISO-8601 UTC timestamp"));
  assert.ok(result.errors.some((error) => error.startsWith("type must be one of:")));
  assert.ok(result.errors.some((error) => error.startsWith("severity must be one of:")));
  assert.ok(result.errors.includes("summary must be a non-empty string"));
  assert.ok(result.errors.includes("data must be an object"));
});

test("redacts secrets and personal data recursively", () => {
  const redacted = redactEventData({
    inputPreview: "Email ada@example.com with password: hunter2 and Bearer abc.def",
    callback: "https://user:pass@example.com/path",
    nested: {
      apiKey: "abc123",
      authorization: "Bearer abc.def.ghi",
      notes: ["token=my-token", "plain value"]
    }
  });

  assert.equal(redacted.inputPreview.includes("ada@example.com"), false);
  assert.equal(redacted.inputPreview.includes("hunter2"), false);
  assert.equal(redacted.inputPreview.includes("abc.def"), false);
  assert.equal(redacted.callback, "https://[credentials redacted]@example.com/path");
  assert.equal(redacted.nested.apiKey, "...redacted");
  assert.equal(redacted.nested.authorization, "...redacted");
  assert.equal(redacted.nested.notes[0], "token=...redacted");
  assert.equal(redacted.nested.notes[1], "plain value");
});

test("appends normalized audit records and verifies hash chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mona-expert-audit-"));
  const filePath = join(dir, "events.jsonl");

  const first = await appendAuditEvent(filePath, {
    id: "evt_audit_001",
    ts: "2026-07-03T19:00:42.985Z",
    type: "mona.expert.server_ready",
    summary: "mona.expert server starting",
    data: { port: 4188 }
  });

  await appendAuditEvent(
    filePath,
    {
      id: "evt_audit_002",
      ts: "2026-07-03T19:01:42.985Z",
      type: "mona.expert.safety_run",
      summary: "Safety run: block",
      data: { decision: "block", token: "secret-token" }
    },
    { previousHash: first.hash }
  );

  const body = await readFile(filePath, "utf8");
  assert.equal(body.trim().split("\n").length, 2);
  assert.equal(body.includes("secret-token"), false);

  const records = await readAuditLog(filePath);
  assert.equal(records.length, 2);
  assert.equal(records[0].recordVersion, AUDIT_RECORD_SCHEMA_VERSION);
  assert.equal(records[0].hashAlgorithm, AUDIT_HASH_ALGORITHM);
  assert.equal(records[0].ok, true);
  assert.equal(records[1].event.data.token, "...redacted");
  assert.deepEqual(verifyAuditChain(records), { ok: true, errors: [] });
});

test("auto-links appended audit records to the last file hash", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mona-expert-audit-"));
  const filePath = join(dir, "events.jsonl");

  const first = await appendAuditEvent(filePath, {
    id: "evt_audit_003",
    ts: "2026-07-03T19:00:42.985Z",
    type: "mona.expert.server_ready",
    summary: "mona.expert server starting",
    data: { port: 4188 }
  });
  const second = await appendAuditEvent(filePath, {
    id: "evt_audit_004",
    ts: "2026-07-03T19:01:42.985Z",
    type: "mona.expert.safety_run",
    summary: "Safety run: review",
    data: { decision: "review" }
  });

  assert.equal(second.previousHash, first.hash);
  assert.deepEqual(verifyAuditChain(await readAuditLog(filePath)), { ok: true, errors: [] });
});

test("detects audit event tampering and malformed chain hashes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mona-expert-audit-"));
  const filePath = join(dir, "events.jsonl");

  const record = await appendAuditEvent(filePath, {
    id: "evt_audit_005",
    ts: "2026-07-03T19:00:42.985Z",
    type: "mona.expert.safety_run",
    summary: "Safety run: allow",
    data: { decision: "allow" }
  });

  const tampered = {
    ...record,
    event: {
      ...record.event,
      summary: "Safety run: block"
    }
  };
  const badHash = {
    ...record,
    hash: "not-a-sha256"
  };

  assert.deepEqual(hashAuditEvent(record.event, record.previousHash), record.hash);
  assert.equal(verifyAuditChain([tampered]).ok, false);
  assert.ok(
    verifyAuditChain([tampered]).errors.includes("record 0 hash does not match event payload")
  );
  assert.equal(verifyAuditChain([badHash]).ok, false);
  assert.ok(
    verifyAuditChain([badHash]).errors.includes("record 0 hash must be a lowercase sha256 hex digest")
  );
});
