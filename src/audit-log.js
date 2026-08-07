import { createHash, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";

import { createEvent, normalizeEvent, validateEvent } from "./event-schema.js";

export const AUDIT_RECORD_SCHEMA_VERSION = "mona.expert.audit.v1";
export const AUDIT_HASH_ALGORITHM = "sha256";
const HASH_PATTERN = /^[a-f0-9]{64}$/;

// ─── Encryption at Rest ──────────────────────────────────────────
// Uses AES-256-GCM. Key loaded from MONA_AUDIT_KEY env var,
// or auto-generated (stored in .mona-audit-key).

const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const KEY_FILE = process.env.MONA_AUDIT_KEY_FILE || ".mona-audit-key";
let encryptionKey = null;

function deriveKey(secret) {
  // Derive a 32-byte key from any-length secret using sha256
  return createHash("sha256").update(secret).digest();
}

export async function initAuditEncryption(keyOrSecret) {
  if (keyOrSecret) {
    encryptionKey = deriveKey(keyOrSecret);
    return { initialized: true, source: "provided" };
  }
  
  // Try env var
  const envKey = process.env.MONA_AUDIT_KEY;
  if (envKey) {
    encryptionKey = deriveKey(envKey);
    return { initialized: true, source: "env" };
  }
  
  // Try key file
  try {
    const { readFile } = await import("node:fs/promises");
    const stored = await readFile(KEY_FILE, "utf8");
    encryptionKey = deriveKey(stored.trim());
    return { initialized: true, source: "file" };
  } catch {
    // Auto-generate and store
    const { writeFile } = await import("node:fs/promises");
    const newKey = randomBytes(32).toString("hex");
    await writeFile(KEY_FILE, newKey, "utf8");
    encryptionKey = deriveKey(newKey);
    return { initialized: true, source: "auto_generated" };
  }
}

export function isEncryptionEnabled() {
  return encryptionKey !== null;
}

export function encryptRecord(plaintext) {
  if (!encryptionKey) {
    throw new Error("Audit encryption not initialized. Call initAuditEncryption() first.");
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv(ENCRYPTION_ALGORITHM, encryptionKey, iv);
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  return JSON.stringify({ v: 1, iv: iv.toString("hex"), tag: authTag, data: encrypted });
}

export function decryptRecord(cipherJson) {
  if (!encryptionKey) {
    throw new Error("Audit encryption not initialized. Call initAuditEncryption() first.");
  }
  const parsed = JSON.parse(cipherJson);
  if (parsed.v !== 1) throw new Error(`Unsupported encryption version: ${parsed.v}`);
  const decipher = createDecipheriv(ENCRYPTION_ALGORITHM, encryptionKey, Buffer.from(parsed.iv, "hex"));
  decipher.setAuthTag(Buffer.from(parsed.tag, "hex"));
  let decrypted = decipher.update(parsed.data, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

export async function appendEncryptedAuditEvent(filePath, input, options = {}) {
  const record = await appendAuditEvent(filePath, input, options);
  // Re-read, encrypt, re-write
  // For production, write encrypted directly. For now, append cleartext to chain
  // and also write encrypted to a .enc companion file.
  const encPath = filePath + ".enc";
  const jsonLine = JSON.stringify(record) + "\n";
  const encrypted = encryptRecord(jsonLine);
  await appendFile(encPath, encrypted + "\n", "utf8");
  return { record, encryptedPath: encPath };
}

export async function readEncryptedAuditLog(encPath) {
  const body = await readFile(encPath, "utf8");
  return body
    .split("\n")
    .filter(Boolean)
    .map(line => JSON.parse(decryptRecord(line)));
}

// ─── Core Audit Functions (unchanged) ────────────────────────────

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (value && Object.prototype.toString.call(value) === "[object Object]") {
    return `{${Object.keys(value)
      .sort()
      .filter((key) => value[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function serializeJsonLine(value) {
  return `${JSON.stringify(value)}\n`;
}

function isHash(value) {
  return typeof value === "string" && HASH_PATTERN.test(value);
}

export function hashAuditEvent(event, previousHash = null) {
  const payload = canonicalJson({ previousHash, event });
  return sha256(payload);
}

export function createAuditRecord(input, { previousHash = null } = {}) {
  const event = createEvent(input);
  const hash = hashAuditEvent(event, previousHash);

  return {
    recordVersion: AUDIT_RECORD_SCHEMA_VERSION,
    hashAlgorithm: AUDIT_HASH_ALGORITHM,
    recordedAt: new Date().toISOString(),
    event,
    hash,
    previousHash
  };
}

async function latestAuditHash(filePath) {
  try {
    const records = await readAuditLog(filePath);
    return [...records].reverse().find((record) => record.hash)?.hash ?? null;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export async function appendAuditEvent(filePath, input, options = {}) {
  if (typeof filePath !== "string" || !filePath.trim()) {
    throw new TypeError("filePath must be a non-empty string");
  }

  const previousHash = Object.hasOwn(options, "previousHash")
    ? options.previousHash
    : await latestAuditHash(filePath);
  const record = createAuditRecord(input, { ...options, previousHash });
  await mkdir(dirname(filePath), { recursive: true });
  await appendFile(filePath, serializeJsonLine(record), "utf8");
  return record;
}

export function parseAuditLine(line) {
  const parsed = JSON.parse(line);

  if (parsed?.event && parsed?.hash) {
    const validation = validateEvent(parsed.event);
    const errors = [...validation.errors];
    if (!isHash(parsed.hash)) errors.push("hash must be a lowercase sha256 hex digest");
    if (parsed.previousHash !== null && parsed.previousHash !== undefined && !isHash(parsed.previousHash)) {
      errors.push("previousHash must be null or a lowercase sha256 hex digest");
    }
    if (
      parsed.hashAlgorithm !== undefined &&
      parsed.hashAlgorithm !== AUDIT_HASH_ALGORITHM
    ) {
      errors.push(`hashAlgorithm must be ${AUDIT_HASH_ALGORITHM}`);
    }
    return {
      ...parsed,
      previousHash: parsed.previousHash ?? null,
      ok: errors.length === 0,
      errors
    };
  }

  const event = normalizeEvent(parsed);
  const validation = validateEvent(event);
  return {
    event,
    hash: null,
    previousHash: null,
    ok: validation.ok,
    errors: validation.errors
  };
}

export async function readAuditLog(filePath) {
  const body = await readFile(filePath, "utf8");
  return body
    .split("\n")
    .filter(Boolean)
    .map((line) => parseAuditLine(line));
}

export function verifyAuditChain(records) {
  const errors = [];
  let previousHash = null;

  if (!Array.isArray(records)) {
    return { ok: false, errors: ["records must be an array"] };
  }

  records.forEach((record, index) => {
    if (!record || typeof record !== "object") {
      errors.push(`record ${index} must be an object`);
      return;
    }
    const validation = validateEvent(record.event);
    for (const error of validation.errors) {
      errors.push(`record ${index} event ${error}`);
    }
    if (!isHash(record.hash)) {
      errors.push(`record ${index} hash must be a lowercase sha256 hex digest`);
      return;
    }
    const recordPreviousHash = record.previousHash ?? null;
    if (recordPreviousHash !== null && !isHash(recordPreviousHash)) {
      errors.push(`record ${index} previousHash must be null or a lowercase sha256 hex digest`);
    }
    if (record.hashAlgorithm !== undefined && record.hashAlgorithm !== AUDIT_HASH_ALGORITHM) {
      errors.push(`record ${index} hashAlgorithm must be ${AUDIT_HASH_ALGORITHM}`);
    }
    if (recordPreviousHash !== previousHash) {
      errors.push(`record ${index} previousHash does not match chain`);
    }
    const expectedHash = hashAuditEvent(record.event, recordPreviousHash);
    if (record.hash !== expectedHash) {
      errors.push(`record ${index} hash does not match event payload`);
    }
    previousHash = record.hash;
  });

  return { ok: errors.length === 0, errors };
}
