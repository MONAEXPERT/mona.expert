/**
 * mona.expert — API Key Authentication
 *
 * Legacy bridge + MySQL-backed API key management.
 *
 * Keeps backward compatibility with query-param style auth (?api_key=...)
 * while delegating all storage and verification to src/key-store.js.
 *
 * generateApiKey():  creates key → MySQL → returns raw key once
 * authenticateRequest(): verifies Bearer + query-param → checks hash in MySQL
 * revokeApiKey():     marks key revoked in MySQL
 * listApiKeys():      returns all keys for a tenant
 * rotateApiKey():     revokes old, issues new with same config
 */

import {
  generateApiKey as ksGenerate,
  authenticateRequest as ksAuthenticate,
  revokeApiKey as ksRevoke,
  listApiKeys as ksList,
  rotateApiKey as ksRotate,
  hasScope as ksHasScope,
} from "./key-store.js";

// ─── Scopes (re-exported) ─────────────────────────────

export const SCOPES = Object.freeze([
  "llm:write",
  "llm:read",
  "agents:manage",
  "agents:read",
  "keys:manage",
  "keys:read",
  "audit:read",
  "admin",
]);

export const DEFAULT_SCOPE = "llm:write";

export function hasScope(keyScopes, required) {
  return ksHasScope(keyScopes, required);
}

// ─── Key Generation ───────────────────────────────────

export async function generateApiKey({
  tenantId = "default",
  label = "default",
  scopes = ["llm:write"],
  expiresInDays = null,
  metadata = {},
}) {
  return ksGenerate({ tenantId, label, scopes, expiresInDays, metadata });
}

// ─── Authentication ───────────────────────────────────
// Supports both Authorization: Bearer <key> and ?api_key=<key>

export async function authenticateRequest(req) {
  // Try Bearer token first
  const authHeader = req.headers?.authorization || "";

  if (authHeader.startsWith("Bearer ")) {
    const result = await ksAuthenticate(authHeader);
    if (result.authenticated) return result;
  }

  // Fallback: query-param api_key (legacy support)
  const queryKey = req.query?.api_key || req.url?.split("?api_key=")[1]?.split("&")[0];
  if (queryKey) {
    const result = await ksAuthenticate(`Bearer ${queryKey}`);
    if (result.authenticated) return result;
  }

  // Check cookies (for dashboard/web UI)
  const cookieKey = req.cookies?.api_key;
  if (cookieKey) {
    const result = await ksAuthenticate(`Bearer ${cookieKey}`);
    if (result.authenticated) return result;
  }

  return { authenticated: false, error: "Authentication required" };
}

// ─── Management ───────────────────────────────────────

export async function revokeApiKey(rawKey) {
  return ksRevoke(rawKey);
}

export async function listApiKeys(tenantId = null) {
  return ksList(tenantId);
}

export async function rotateApiKey(rawKey) {
  return ksRotate(rawKey);
}

// ─── Express Middleware ───────────────────────────────

export function requireAuth(req, res, next) {
  authenticateRequest(req).then((auth) => {
    if (!auth.authenticated) {
      res.status(401).json({ error: auth.error || "Unauthorized" });
      return;
    }
    req.auth = auth;
    next();
  }).catch((err) => {
    res.status(500).json({ error: "Auth error", detail: err.message });
  });
}

export function requireScope(...required) {
  return (req, res, next) => {
    if (!req.auth) {
      res.status(401).json({ error: "Not authenticated" });
      return;
    }
    for (const scope of required) {
      if (!ksHasScope(req.auth.scopes, scope)) {
        res.status(403).json({ error: `Missing required scope: ${scope}` });
        return;
      }
    }
    next();
  };
}

export default {
  generateApiKey,
  authenticateRequest,
  revokeApiKey,
  listApiKeys,
  rotateApiKey,
  requireAuth,
  requireScope,
  hasScope,
  SCOPES,
  DEFAULT_SCOPE,
};
