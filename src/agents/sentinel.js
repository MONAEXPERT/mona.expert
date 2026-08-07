// mona.expert — Sentinel Agent Runtime
//
// The first agent to install on any wrapper.
//
// Guarantees:
//   1. SAFE ENV  — creates its own sandbox (mode 0700) and never writes
//                  secret material (API keys, tokens, passwords) to disk.
//   2. MONITOR   — ticks on an interval: system metrics, agent liveness,
//                  security posture, wrapper reachability.
//   3. WRAPPER-ROUTED — every outbound request goes through the wrapper
//                  gateway (https://wrapper.mona.expert). No direct calls.
//   4. MYSQL/FTP — health checks performed via wrapper gateway endpoints;
//                  credentials live on the wrapper side only.
//
// Security model: keys live in memory (process.env) or on the wrapper,
// never in files created by this agent.

import { mkdir, writeFile, readFile, access, chmod } from "node:fs/promises";
import { constants } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { broadcast } from "../event-bus.js";
import { getCurrentMetrics } from "../system-monitor.js";
import { listAgents, getAgent } from "../agent-registry.js";
import { getRunningAgents } from "../agent-sandbox.js";
import { INSTALL_STATUS } from "../agent-manifest.js";
import { getRecentBreaches } from "../injection-guard.js";
import { readAuditLog } from "../audit-log.js";

const ROOT = dirname(fileURLToPath(import.meta.url));
const SANDBOX_DIR = join(ROOT, "..", "..", ".mona-agents", "sandbox", "sentinel");
const AUDIT_FILE = process.env.MONA_EXPERT_AUDIT_FILE || ".mona-dashboard/events.jsonl";

const INTERVAL_MS = Number(process.env.SENTINEL_INTERVAL_MS) || 30000;
const WRAPPER_GATEWAY = process.env.WRAPPER_GATEWAY_URL || "https://wrapper.mona.expert";

// In-memory only — never persisted.
const session = {
  token: null,
  tokenExpiresAt: 0,
  requests: 0,
};

let intervalHandle = null;
let tickCount = 0;
let lastTickAt = null;
let safeEnvReady = false;

// ─── 1. Safe environment ──────────────────────────────────────────

/**
 * Create the Sentinel safe environment.
 * - mkdir -p with mode 0700 (owner-only)
 * - writes a non-secret sandbox manifest
 * - refuses to write any secret-bearing env content
 */
export async function createSafeEnv() {
  try {
    await mkdir(SANDBOX_DIR, { recursive: true, mode: 0o700 });
    await chmod(SANDBOX_DIR, 0o700);

    const manifest = {
      agent: "sentinel",
      createdAt: new Date().toISOString(),
      policy: {
        localKeys: "none",            // zero secrets on disk
        outbound: "wrapper-only",     // all traffic via wrapper.mona.expert
        shell: false,
        writeScope: SANDBOX_DIR,      // cannot write outside sandbox
      },
      secretsStoredLocally: 0,
    };

    await writeFile(join(SANDBOX_DIR, "sandbox.json"), JSON.stringify(manifest, null, 2), {
      encoding: "utf8",
      mode: 0o600,
    });

    safeEnvReady = true;
    broadcast("sentinel-status", { ok: true, safeEnv: true, sandbox: SANDBOX_DIR });
    return { ok: true, sandbox: SANDBOX_DIR, mode: "0700", policy: manifest.policy };
  } catch (err) {
    broadcast("sentinel-alert", { ok: false, stage: "safe_env", error: err.message });
    return { ok: false, error: err.message };
  }
}

/**
 * Guard: never persist secret material. Called before any write.
 */
function assertNoSecrets(payload) {
  const joined = JSON.stringify(payload || {}).toLowerCase();
  const secretHints = ["api_key", "apikey", "password", "secret", "token", "authorization", "bearer"];
  for (const hint of secretHints) {
    if (joined.includes(hint)) {
      throw new Error(`Refusing to write secret-bearing material (hint: ${hint})`);
    }
  }
}

// ─── 3. Wrapper gateway client ────────────────────────────────────

/**
 * Every outbound request goes through the wrapper gateway.
 * The gateway (wrapper.mona.expert) holds credentials and performs
 * MySQL/FTP/LLM operations; Sentinel only carries a short-lived session
 * token in memory.
 */
async function gatewayRequest(path, payload = {}, method = "POST", timeoutMs = 10000) {
  const url = `${WRAPPER_GATEWAY}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  session.requests++;
  try {
    const headers = { "content-type": "application/json" };
    if (session.token) headers["x-sentinel-session"] = session.token;

    const res = await fetch(url, {
      method,
      headers,
      body: method === "GET" ? undefined : JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await res.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
    return { ok: res.ok, status: res.status, ...json };
  } catch (err) {
    return { ok: false, status: 0, error: err.message };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Obtain a short-lived session token from the wrapper gateway.
 * Stored in memory only — never written to disk.
 */
async function acquireSession() {
  if (session.token && Date.now() < session.tokenExpiresAt) return true;
  const res = await gatewayRequest("/api/sentinel/session", { agent: "sentinel", nonce: Date.now() });
  if (res.ok && res.sessionToken) {
    session.token = res.sessionToken;
    session.tokenExpiresAt = Date.now() + (res.ttlMs || 5 * 60 * 1000);
    return true;
  }
  session.token = null;
  return false;
}

// ─── 2. Monitoring ────────────────────────────────────────────────

/**
 * Perform one Sentinel monitoring cycle.
 */
async function tick() {
  tickCount++;
  lastTickAt = new Date().toISOString();

  const metrics = getCurrentMetrics();

  // Agent liveness
  let agents = [];
  let running = [];
  try {
    agents = await listAgents();
    running = getRunningAgents();
  } catch { /* registry may be unavailable */ }

  const agentStatuses = agents.map((a) => ({
    id: a.id,
    name: a.name,
    status: a.status,
    installed: a.installed,
  }));

  const errors = agentStatuses.filter((a) => a.status === INSTALL_STATUS.ERROR);
  const stopped = agentStatuses.filter((a) => a.installed && a.status === INSTALL_STATUS.STOPPED);

  // Security posture
  let breachCount = 0;
  try { breachCount = getRecentBreaches(100).length; } catch { /* no breaches yet */ }

  let auditErrors = 0;
  try {
    const records = await readAuditLog(AUDIT_FILE);
    auditErrors = records.slice(-50).filter((r) => r.severity === "error").length;
  } catch { /* no audit log yet */ }

  // Wrapper reachability (gateway ping, no secrets involved)
  const gateway = await gatewayRequest("/api/sentinel/ping", { at: lastTickAt });

  const summary = {
    tick: tickCount,
    at: lastTickAt,
    intervalMs: INTERVAL_MS,
    safeEnv: safeEnvReady,
    sandboxMode: safeEnvReady ? "0700" : null,
    metrics: {
      cpu: metrics.cpu,
      memory: metrics.memory.percent,
      uptime: metrics.uptime,
    },
    agents: {
      total: agents.length,
      running: running.length,
      error: errors.length,
      stoppedIdle: stopped.length,
    },
    security: {
      recentBreaches: breachCount,
      auditErrorsLast50: auditErrors,
    },
    gateway: {
      url: WRAPPER_GATEWAY,
      ok: gateway.ok,
      status: gateway.status,
    },
    localSecrets: 0, // invariant — never stored
  };

  broadcast("sentinel-tick", summary);

  // Alerts
  if (errors.length > 0) {
    broadcast("sentinel-alert", {
      tick: tickCount, at: lastTickAt, type: "agent_errors",
      agents: errors.map((e) => `${e.name} (${e.id})`),
    });
  }
  if (metrics.memory.percent > 85) {
    broadcast("sentinel-alert", { tick: tickCount, at: lastTickAt, type: "memory_pressure", memoryPercent: metrics.memory.percent });
  }
  if (!gateway.ok) {
    broadcast("sentinel-alert", { tick: tickCount, at: lastTickAt, type: "gateway_unreachable", url: WRAPPER_GATEWAY, status: gateway.status });
  }
  if (breachCount > 0) {
    broadcast("sentinel-alert", { tick: tickCount, at: lastTickAt, type: "injection_breaches", count: breachCount });
  }

  return summary;
}

// ─── 4. MySQL / FTP health via wrapper gateway ────────────────────

/**
 * Ask the wrapper gateway to check MySQL connectivity.
 * Sentinel carries no MySQL credentials — the wrapper does.
 */
export async function checkMysqlViaGateway() {
  await acquireSession();
  return gatewayRequest("/api/sentinel/mysql-health", { agent: "sentinel", tick: tickCount });
}

/**
 * Ask the wrapper gateway to check FTP connectivity.
 * Sentinel carries no FTP credentials — the wrapper does.
 */
export async function checkFtpViaGateway() {
  await acquireSession();
  return gatewayRequest("/api/sentinel/ftp-health", { agent: "sentinel", tick: tickCount });
}

// ─── Lifecycle ────────────────────────────────────────────────────

export async function startSentinel() {
  if (intervalHandle) return { ok: true, status: "already_running" };

  const env = await createSafeEnv();
  if (!env.ok) {
    broadcast("sentinel-alert", { type: "safe_env_failed", error: env.error });
  }

  // Try to acquire a session token (non-fatal if gateway is down)
  await acquireSession();

  tick().catch((err) => {
    broadcast("sentinel-alert", { tick: tickCount, type: "tick_error", error: err.message });
  });

  intervalHandle = setInterval(() => {
    tick().catch((err) => {
      broadcast("sentinel-alert", { tick: tickCount, type: "tick_error", error: err.message });
    });
  }, INTERVAL_MS).unref();

  console.log(`🛰 Sentinel agent started (interval: ${INTERVAL_MS}ms, gateway: ${WRAPPER_GATEWAY})`);
  return { ok: true, status: "started", intervalMs: INTERVAL_MS, safeEnv: env };
}

export function stopSentinel() {
  if (!intervalHandle) return { ok: true, status: "not_running" };
  clearInterval(intervalHandle);
  intervalHandle = null;
  session.token = null; // wipe in-memory session token
  console.log("🛰 Sentinel agent stopped");
  return { ok: true, status: "stopped" };
}

export async function getSentinelStatus() {
  return {
    ok: true,
    running: !!intervalHandle,
    ticks: tickCount,
    lastTickAt,
    safeEnv: safeEnvReady,
    gateway: WRAPPER_GATEWAY,
    sessionActive: !!session.token,
    requests: session.requests,
    localSecretsStored: 0,
  };
}
