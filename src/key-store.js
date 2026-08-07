/**
 * mona.expert — API Key Store (MySQL-backed with in-memory fallback)
 *
 * Uses SHA-256 hashed keys for storage (bcrypt in production).
 * Supports key generation, revocation, rotation, usage tracking, and expiry.
 * When MySQL is unavailable, falls back to an in-memory Map for dev/test use.
 *
 * ```
 * import { generateApiKey, authenticateRequest } from "./key-store.js";
 * const key = await generateApiKey({ tenantId: "my-app" });
 * const auth = await authenticateRequest("Bearer " + key.raw);
 * ```
 */

import crypto from "node:crypto";

// ─── Graceful MySQL import ────────────────────────────

const { getPool } = await import("./db.js").catch(() => ({ getPool: null }));
let mysqlAvailable = false;

if (getPool) {
  try {
    mysqlAvailable = !!getPool();
  } catch {
    mysqlAvailable = false;
  }
}

// ─── In-memory fallback store ─────────────────────────

const keys = new Map();

function memGet(keyHash) {
  return keys.get(keyHash);
}

function memSet(keyHash, entry) {
  keys.set(keyHash, entry);
}

function memDelete(keyHash) {
  return keys.delete(keyHash);
}

function memList(tenantId) {
  const all = [...keys.values()];
  return tenantId ? all.filter((k) => k.tenantId === tenantId) : all;
}

// ─── Hashing ──────────────────────────────────────────

function hashKey(raw) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function generateRawKey(tenantId) {
  const prefix = tenantId ? `mk_${tenantId.slice(0, 12)}` : "mk_anon";
  return `${prefix}_${Date.now().toString(36)}_${crypto.randomBytes(20).toString("hex")}`;
}

function generateKeyId() {
  return `key_${crypto.randomBytes(8).toString("hex")}`;
}

// ─── Standard scopes ──────────────────────────────────

const VALID_SCOPES = new Set([
  "llm:write",
  "llm:read",
  "agents:manage",
  "agents:read",
  "keys:manage",
  "keys:read",
  "audit:read",
  "admin",
]);

function validateScopes(scopes) {
  if (!Array.isArray(scopes)) return ["llm:write"];
  const valid = scopes.filter((s) => VALID_SCOPES.has(s));
  return valid.length > 0 ? valid : ["llm:write"];
}

// ─── CRUD Operations ──────────────────────────────────

/**
 * Generate a new API key for a tenant.
 * Returns { raw, keyId, tenantId, label, scopes, expiresAt } where `raw` is the
 * plaintext key shown once. The store only keeps the SHA-256 hash.
 */
export async function generateApiKey({
  tenantId = "default",
  label = "default",
  scopes = ["llm:write"],
  expiresInDays = null,
  metadata = {},
} = {}) {
  const raw = generateRawKey(tenantId);
  const keyHash = hashKey(raw);
  const keyId = generateKeyId();
  const now = new Date();
  const expiresAt = expiresInDays && expiresInDays > 0
    ? new Date(now.getTime() + expiresInDays * 86400000)
    : null;
  const validScopes = validateScopes(scopes);

  if (mysqlAvailable) {
    const pool = getPool();
    await pool.execute(
      `INSERT INTO api_keys (key_id, key_hash, tenant_id, label, scopes, status, metadata, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
      [
        keyId, keyHash, tenantId, label,
        JSON.stringify(validScopes),
        JSON.stringify(metadata),
        expiresAt, now,
      ]
    );
  } else {
    memSet(keyHash, {
      keyId,
      keyHash,
      tenantId,
      label,
      scopes: validScopes,
      status: "active",
      metadata,
      expiresAt,
      createdAt: now,
    });
  }

  return {
    raw,
    keyId,
    tenantId,
    label,
    scopes: validScopes,
    expiresAt: expiresAt?.toISOString() || null,
  };
}

/**
 * Authenticate a request by its Bearer token (string like "Bearer <key>").
 * Returns { authenticated, tenantId, keyId, label, scopes } or an error.
 */
export async function authenticateRequest(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { authenticated: false, error: "Missing or invalid Authorization header" };
  }

  const raw = authHeader.slice(7).trim();
  if (!raw) {
    return { authenticated: false, error: "Empty API key" };
  }

  const keyHash = hashKey(raw);
  let key;

  if (mysqlAvailable) {
    const pool = getPool();
    const [rows] = await pool.execute(
      `SELECT key_id, tenant_id, label, scopes, status, expires_at
       FROM api_keys WHERE key_hash = ? LIMIT 1`,
      [keyHash]
    );
    if (rows.length === 0) {
      return { authenticated: false, error: "Invalid API key" };
    }
    key = rows[0];
  } else {
    key = memGet(keyHash);
    if (!key) {
      return { authenticated: false, error: "Invalid API key" };
    }
  }

  if (key.status === "revoked") {
    return { authenticated: false, error: "API key revoked" };
  }

  if (key.expires_at && new Date(key.expires_at) < new Date()) {
    return { authenticated: false, error: "API key expired" };
  }

  // Fire-and-forget last_used update
  if (mysqlAvailable) {
    getPool().execute(
      `UPDATE api_keys SET last_used = NOW() WHERE key_hash = ?`,
      [keyHash]
    ).catch(() => {});
  }

  const scopes = typeof key.scopes === "string"
    ? JSON.parse(key.scopes || "[]")
    : (key.scopes || []);

  return {
    authenticated: true,
    tenantId: key.tenant_id || key.tenantId,
    keyId: key.key_id || key.keyId,
    label: key.label,
    scopes,
  };
}

/**
 * Revoke an API key by raw token or key hash (prefixed with "hk:").
 */
export async function revokeApiKey(rawOrHash) {
  const keyHash = rawOrHash.startsWith("hk:") ? rawOrHash.slice(3) : hashKey(rawOrHash);

  if (mysqlAvailable) {
    const pool = getPool();
    const [result] = await pool.execute(
      `UPDATE api_keys SET status = 'revoked', updated_at = NOW() WHERE key_hash = ?`,
      [keyHash]
    );
    if (result.affectedRows === 0) {
      return { ok: false, error: "Key not found" };
    }
  } else {
    const key = memGet(keyHash);
    if (!key) return { ok: false, error: "Key not found" };
    key.status = "revoked";
  }

  return { ok: true };
}

/**
 * List API keys for a tenant, or all keys if no tenant specified.
 * Returns an array of { keyId, tenantId, label, scopes, status, ... }.
 */
export async function listApiKeys(tenantId = null) {
  if (mysqlAvailable) {
    const pool = getPool();
    let [rows] = tenantId
      ? await pool.execute(
          `SELECT key_id, tenant_id, label, scopes, status, last_used, created_at, expires_at, metadata
           FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC`,
          [tenantId]
        )
      : await pool.execute(
          `SELECT key_id, tenant_id, label, scopes, status, last_used, created_at, expires_at, metadata
           FROM api_keys ORDER BY created_at DESC`
        );

    return rows.map((r) => ({
      keyId: r.key_id,
      tenantId: r.tenant_id,
      label: r.label,
      scopes: JSON.parse(r.scopes || "[]"),
      status: r.status,
      lastUsed: r.last_used?.toISOString() || null,
      createdAt: r.created_at?.toISOString() || null,
      expiresAt: r.expires_at?.toISOString() || null,
      metadata: JSON.parse(r.metadata || "{}"),
    }));
  }

  return memList(tenantId).map((k) => ({
    keyId: k.keyId,
    tenantId: k.tenantId,
    label: k.label,
    scopes: k.scopes,
    status: k.status,
    lastUsed: null,
    createdAt: k.createdAt?.toISOString() || null,
    expiresAt: k.expiresAt?.toISOString() || null,
    metadata: k.metadata || {},
  }));
}

/**
 * Rotate an API key: revoke old, generate new with same config.
 */
export async function rotateApiKey(oldRawOrHash) {
  const keyHash = oldRawOrHash.startsWith("hk:") ? oldRawOrHash.slice(3) : hashKey(oldRawOrHash);
  let old;

  if (mysqlAvailable) {
    const pool = getPool();
    const [rows] = await pool.execute(
      `SELECT tenant_id, label, scopes, metadata FROM api_keys WHERE key_hash = ? LIMIT 1`,
      [keyHash]
    );
    if (rows.length === 0) return { ok: false, error: "Key not found" };
    old = rows[0];

    await pool.execute(
      `UPDATE api_keys SET status = 'revoked', updated_at = NOW() WHERE key_hash = ?`,
      [keyHash]
    );
  } else {
    old = memGet(keyHash);
    if (!old) return { ok: false, error: "Key not found" };
    old.status = "revoked";
  }

  return generateApiKey({
    tenantId: old.mysqlAvailable ? old.tenant_id : old.tenantId,
    label: old.label,
    scopes: typeof old.scopes === "string" ? JSON.parse(old.scopes || "[]") : old.scopes,
    metadata: typeof old.metadata === "string" ? JSON.parse(old.metadata || "{}") : (old.metadata || {}),
  });
}

/**
 * Delete expired/revoked keys older than the given days.
 * Returns count of deleted keys.
 */
export async function cleanExpiredKeys(olderThanDays = 30) {
  if (mysqlAvailable) {
    const pool = getPool();
    const cutoff = new Date(Date.now() - olderThanDays * 86400000);
    const [result] = await pool.execute(
      `DELETE FROM api_keys WHERE (status = 'revoked' OR (expires_at IS NOT NULL AND expires_at < NOW())) AND updated_at < ?`,
      [cutoff]
    );
    return { deleted: result.affectedRows };
  }

  const cutoff = new Date(Date.now() - olderThanDays * 86400000);
  let deleted = 0;
  for (const [hash, k] of keys) {
    const expired = k.expiresAt && k.expiresAt < new Date();
    const oldRevoked = k.status === "revoked" && k.updatedAt && k.updatedAt < cutoff;
    if (expired || oldRevoked) {
      memDelete(hash);
      deleted++;
    }
  }
  return { deleted };
}

/**
 * Validate a scope against a key's allowed scopes.
 */
export function hasScope(keyScopes, requiredScope) {
  if (keyScopes?.includes("admin")) return true;
  return keyScopes?.includes(requiredScope) ?? false;
}

export default {
  generateApiKey,
  authenticateRequest,
  revokeApiKey,
  listApiKeys,
  rotateApiKey,
  cleanExpiredKeys,
  hasScope,
};
