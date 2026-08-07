import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  hashAuditEvent,
  createAuditRecord,
  parseAuditLine,
  verifyAuditChain,
  appendAuditEvent,
  readAuditLog,
  initAuditEncryption,
  isEncryptionEnabled,
  encryptRecord,
  decryptRecord,
  appendEncryptedAuditEvent,
  readEncryptedAuditLog,
} from "../src/audit-log.js";

const T = { type: "mona.expert.safety_run", summary: "test run" };
const S = { type: "mona.expert.server_ready", summary: "server started" };

test("hashAuditEvent produces consistent sha256", () => {
  const h1 = hashAuditEvent(T);
  const h2 = hashAuditEvent(T);
  assert.equal(h1, h2);
  assert.equal(h1.length, 64);
});

test("hashAuditEvent includes previous hash in chaining", () => {
  const a = hashAuditEvent(S, null);
  const b = hashAuditEvent(T, a);
  const c = hashAuditEvent(S, b);
  assert.notEqual(a, b);
  assert.notEqual(b, c);
});

test("createAuditRecord produces valid entry", () => {
  const record = createAuditRecord(T);
  assert.ok(record.hash);
  assert.equal(record.previousHash, null);
  assert.ok(record.recordedAt);
  assert.equal(record.event.summary, "test run");
  assert.equal(record.event.type, "mona.expert.safety_run");
  assert.equal(record.recordVersion, "mona.expert.audit.v1");
});

test("createAuditRecord chains hashes", () => {
  const a = createAuditRecord(S);
  const b = createAuditRecord(T, { previousHash: a.hash });
  assert.equal(b.previousHash, a.hash);
  assert.notEqual(b.hash, a.hash);
});

test("parseAuditLine parses valid audit line", () => {
  const record = createAuditRecord(T);
  const line = JSON.stringify(record) + "\n";
  const parsed = parseAuditLine(line);
  assert.equal(parsed.hash, record.hash);
  assert.equal(parsed.event.summary, "test run");
  assert.equal(parsed.ok, true);
});

test("parseAuditLine throws on invalid JSON", () => {
  assert.throws(() => parseAuditLine("{invalid"), SyntaxError);
});

test("verifyAuditChain accepts valid chain", () => {
  const a = createAuditRecord(S);
  const b = createAuditRecord(T, { previousHash: a.hash });
  const c = createAuditRecord(S, { previousHash: b.hash });
  const result = verifyAuditChain([a, b, c]);
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);
});

test("verifyAuditChain catches broken hash", () => {
  const a = createAuditRecord(S);
  const b = createAuditRecord(T, { previousHash: a.hash });
  const c = createAuditRecord(S, { previousHash: "0000wrong0000" });
  const result = verifyAuditChain([a, b, c]);
  assert.equal(result.ok, false);
  assert.ok(result.errors.length > 0);
});

test("verifyAuditChain accepts single record", () => {
  const a = createAuditRecord(S);
  const result = verifyAuditChain([a]);
  assert.equal(result.ok, true);
});

test("appendAuditEvent and readAuditLog round-trip", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "audit-test-"));
  const tmpFile = join(tmpDir, "test.audit.log");

  try {
    const r1 = await appendAuditEvent(tmpFile, S);
    const r2 = await appendAuditEvent(tmpFile, T);
    const r3 = await appendAuditEvent(tmpFile, S);

    assert.equal(r2.previousHash, r1.hash);
    assert.equal(r3.previousHash, r2.hash);

    const records = await readAuditLog(tmpFile);
    assert.equal(records.length, 3);
    assert.equal(records[0].event.summary, "server started");
    assert.equal(records[2].event.summary, "server started");

    const verification = verifyAuditChain(records);
    assert.equal(verification.ok, true);
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("encryptRecord and decryptRecord round-trip", async () => {
  const key = "abcdef0123456789abcdef0123456789"; // 32 hex = 16 bytes
  await initAuditEncryption(key);
  assert.ok(isEncryptionEnabled());

  const plaintext = JSON.stringify(S);
  const cipher = encryptRecord(plaintext);
  assert.ok(typeof cipher === "string");

  const parsed = JSON.parse(cipher);
  assert.ok(parsed.iv);
  assert.ok(parsed.tag);
  assert.ok(parsed.data);
  assert.equal(parsed.v, 1);

  const decrypted = decryptRecord(cipher);
  assert.equal(decrypted, plaintext);
});

test("encryptRecord with non-hex key uses derivation", async () => {
  await initAuditEncryption("my-weak-secret");
  assert.ok(isEncryptionEnabled());

  const plaintext = JSON.stringify(T);
  const cipher = encryptRecord(plaintext);
  const decrypted = decryptRecord(cipher);
  assert.equal(decrypted, plaintext);
});

test("appendEncryptedAuditEvent and readEncryptedAuditLog round-trip", async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), "audit-enc-test-"));
  const tmpFile = join(tmpDir, "test.enc.audit.log");

  try {
    await initAuditEncryption("test-encryption-secret");

    const result = await appendEncryptedAuditEvent(tmpFile, T);
    assert.ok(result.encryptedPath); // companion .enc path

    const records = await readEncryptedAuditLog(result.encryptedPath);
    assert.equal(records.length, 1);
    assert.equal(records[0].event.summary, "test run");
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
