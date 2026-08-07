/**
 * mona-expert Guardian Client
 *
 * Runs inside the local wrapper. Connects to the mona.expert website
 * for decentralized security checks. All LLM calls route through this.
 *
 * Architecture:
 *   User's App → mona-expert wrapper (local) → guardian.mona.expert (website) → verdict
 *                                                   ↓
 *   If ALLOW: wrapper calls LLM with user's own API key
 *   If BLOCK: wrapper returns rejection, audit logged both locally and remotely
 */

import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile, access, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { createHmac } from "node:crypto";

// ─── Config ───────────────────────────────────────────
const MONA_CONFIG_DIR = join(homedir(), ".mona-expert");
const MONA_CONFIG_FILE = join(MONA_CONFIG_DIR, "config.json");
const MONA_AUTH_FILE = join(MONA_CONFIG_DIR, "auth.json");

const DEFAULT_GUARDIAN_URL = "https://mona.expert";
const GUARDIAN_CHECK_PATH = "/api/v1/guard/check";
const GUARDIAN_CONNECT_PATH = "/api/v1/wrapper/connect";
const GUARDIAN_HEARTBEAT_PATH = "/api/v1/wrapper/heartbeat";

// ─── Config management ────────────────────────────────
async function ensureConfigDir() {
  try { await access(MONA_CONFIG_DIR); } catch { await mkdir(MONA_CONFIG_DIR, { recursive: true }); }
}

async function loadConfig() {
  try {
    const raw = await readFile(MONA_CONFIG_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return { guardianUrl: DEFAULT_GUARDIAN_URL, version: "0.10.0", connected: false };
  }
}

async function saveConfig(config) {
  await ensureConfigDir();
  await writeFile(MONA_CONFIG_FILE, JSON.stringify(config, null, 2), "utf8");
}

async function loadAuth() {
  try {
    const raw = await readFile(MONA_AUTH_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function saveAuth(auth) {
  await ensureConfigDir();
  await writeFile(MONA_AUTH_FILE, JSON.stringify(auth, null, 2), "utf8");
}

// ─── HMAC signing ─────────────────────────────────────
function signPayload(payload, secret) {
  const hmac = createHmac("sha256", secret);
  hmac.update(JSON.stringify(payload));
  return hmac.digest("hex");
}

// ─── HTTP helpers ─────────────────────────────────────
async function guardianPost(path, body, auth) {
  const config = await loadConfig();
  const url = `${config.guardianUrl}${path}`;

  const headers = {
    "Content-Type": "application/json",
    "User-Agent": `mona-expert/${config.version}`,
  };

  if (auth?.wrapperId) {
    headers["X-Wrapper-Id"] = auth.wrapperId;
    headers["X-Wrapper-Key"] = auth.wrapperKey;
  }

  if (auth?.apiKey) {
    headers["Authorization"] = `Bearer ${auth.apiKey}`;
  }

  // Sign the request body
  if (auth?.wrapperSecret) {
    const nonce = randomUUID();
    const timestamp = Math.floor(Date.now() / 1000);
    const payload = { ...body, _nonce: nonce, _timestamp: timestamp };
    const signature = signPayload(payload, auth.wrapperSecret);
    headers["X-Signature"] = signature;
    headers["X-Nonce"] = nonce;
    headers["X-Timestamp"] = String(timestamp);
    body = payload;
  }

  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });

  if (!response.ok) {
    const errBody = await response.text().catch(() => "");
    throw new Error(`Guardian HTTP ${response.status}: ${errBody.slice(0, 200)}`);
  }

  return response.json();
}

// ─── Public API ───────────────────────────────────────

/**
 * Connect this wrapper to a mona.expert account.
 * Called once during setup. Returns wrapper credentials.
 *
 * @param {string} apiKey - User's mona.expert API key (from website dashboard)
 * @param {object} opts
 * @param {string} opts.wrapperName - Friendly name for this wrapper instance
 * @param {string} opts.guardianUrl - Override guardian URL
 */
export async function connectWrapper(apiKey, opts = {}) {
  if (!apiKey) throw new Error("API key required — get it from https://mona.expert/dashboard");

  const config = await loadConfig();
  if (opts.guardianUrl) config.guardianUrl = opts.guardianUrl;

  // Machine fingerprint
  const hostname = (await import("node:os")).hostname();
  const machineId = createHash("sha256").update(`${hostname}-${process.pid}-${Date.now()}`).digest("hex").slice(0, 16);

  const result = await guardianPost(GUARDIAN_CONNECT_PATH, {
    machineId,
    wrapperName: opts.wrapperName || hostname,
    wrapperVersion: config.version,
    nodeVersion: process.version,
    platform: process.platform,
  }, { apiKey });

  if (!result.ok || !result.wrapper) {
    throw new Error(result.error || "Connection failed — check your API key");
  }

  const auth = {
    wrapperId: result.wrapper.id,
    wrapperKey: result.wrapper.key,
    wrapperSecret: result.wrapper.secret,
    apiKey,
    connectedAt: new Date().toISOString(),
    guardianUrl: config.guardianUrl,
  };

  await saveConfig({ ...config, connected: true, connectedAt: auth.connectedAt });
  await saveAuth(auth);
  return { ok: true, wrapper: result.wrapper };
}

/**
 * Run a security check through the mona.expert guardian.
 * This is the core function — every LLM call goes through this.
 *
 * @param {string} input - The prompt/input to check
 * @param {object} opts
 * @param {string[]} opts.requestedTools - Tools the agent wants to use
 * @param {string} opts.tenantId - Tenant context
 * @param {string} opts.mode - "strict" | "balanced" | "permissive"
 * @returns {object} Verdict with decision, riskScore, patterns
 */
export async function guardianCheck(input, opts = {}) {
  const auth = await loadAuth();
  if (!auth) {
    throw new Error(
      "Wrapper not connected. Run: npx mona-expert connect\n" +
      "Or get an API key at: https://mona.expert/dashboard"
    );
  }

  const result = await guardianPost(GUARDIAN_CHECK_PATH, {
    input,
    requestedTools: opts.requestedTools || [],
    tenantId: opts.tenantId || "default",
    mode: opts.mode || "balanced",
    timestamp: new Date().toISOString(),
  }, auth);

  return result;
}

/**
 * Send a heartbeat to the guardian to keep the connection alive.
 * Also reports local stats.
 */
export async function guardianHeartbeat(stats = {}) {
  const auth = await loadAuth();
  if (!auth) return { ok: false, reason: "not_connected" };

  try {
    return await guardianPost(GUARDIAN_HEARTBEAT_PATH, {
      ...stats,
      timestamp: new Date().toISOString(),
    }, auth);
  } catch {
    return { ok: false, reason: "guardian_unreachable" };
  }
}

/**
 * Get the current connection status.
 */
export async function getConnectionStatus() {
  const config = await loadConfig();
  const auth = await loadAuth();

  if (!auth) {
    return { connected: false, guardianUrl: config.guardianUrl, version: config.version };
  }

  return {
    connected: true,
    wrapperId: auth.wrapperId,
    guardianUrl: auth.guardianUrl,
    connectedAt: auth.connectedAt,
    version: config.version,
  };
}

/**
 * Disconnect this wrapper from the mona.expert account.
 */
export async function disconnectWrapper() {
  await saveConfig({ guardianUrl: DEFAULT_GUARDIAN_URL, version: "0.10.0", connected: false });
  try { await access(MONA_AUTH_FILE); await (await import("node:fs/promises")).unlink(MONA_AUTH_FILE); } catch {}
  return { ok: true };
}

export default {
  connect: connectWrapper,
  check: guardianCheck,
  heartbeat: guardianHeartbeat,
  status: getConnectionStatus,
  disconnect: disconnectWrapper,
};
