import { createServer } from "node:http";
import { readFile, access } from "node:fs/promises";
import { constants } from "node:fs";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { appendAuditEvent, readAuditLog } from "./src/audit-log.js";
import { secureAction, analyzeInjections } from "./src/security-layer.js";
import { getRecentBreaches } from "./src/injection-guard.js";
import { createProxy } from "./src/llm-proxy.js";
import { startSystemMonitor, getCurrentMetrics } from "./src/system-monitor.js";
import { emitApiRequest } from "./src/agent-instrument.js";
import { authenticateRequest, generateApiKey, revokeApiKey, listApiKeys } from "./src/api-auth.js";
import { printEnvStatus } from "./src/env-check.js";
import {
  listAgents,
  getAgent,
  installAgent,
  uninstallAgent,
  getRegistrySummary,
  addCustomAgent,
} from "./src/agent-registry.js";
import {
  startAgent,
  stopAgent,
  getRunningAgents,
} from "./src/agent-sandbox.js";
import { validateManifest } from "./src/agent-manifest.js";
import { startHeartbeat, stopHeartbeat, getLatestHeartbeat } from "./src/agents/heartbeat.js";
import { startBoss, stopBoss, getBossStatus } from "./src/agents/boss.js";
import { startSentinel, stopSentinel, getSentinelStatus, checkMysqlViaGateway, checkFtpViaGateway } from "./src/agents/sentinel.js";
import { checkLicense } from "./src/license.js";

// ─── Load .env if present ─────────────────────────────
try {
  await access(".env", constants.F_OK);
  const envRaw = await readFile(".env", "utf8");
  for (const line of envRaw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();
    // Strip surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!process.env[key]) {
      process.env[key] = val;
    }
  }
  console.log("✔ .env loaded");
} catch {
  console.log("ℹ .env not found — using existing environment");
}

// ─── Startup Configuration Check ───────────────────────
console.log("mona.expert v0.10.0 — checking configuration…");
printEnvStatus();
console.log("");

// ─── License gate (machine-bound, fails closed) ──────────────
const license = checkLicense();
if (!license.ok) {
  console.error("🔒 License check FAILED:", license.reason);
  console.error("   See LICENSE and docs for commercial/on-prem licensing.");
  process.exit(1);
}
console.log("🔒 License OK — machine-bound, run authorized");
console.log("");

// Require API key auth in production mode (set AUTH_REQUIRED=1)
const AUTH_REQUIRED = process.env.AUTH_REQUIRED === "1";

function optionalAuth(req) {
  if (!AUTH_REQUIRED) return { authenticated: true, tenantId: "default", label: "local-dev", scopes: ["*"] };
  return authenticateRequest(req.headers.authorization);
}

// Lazy singleton — created on first use after .env is loaded
let llmProxy = null;
function getProxy() {
  if (!llmProxy) llmProxy = createProxy();
  return llmProxy;
}

const ROOT = fileURLToPath(new URL(".", import.meta.url));
const PUBLIC_DIR = join(ROOT, "public");
const AUDIT_DIR = join(ROOT, ".mona-dashboard");
const AUDIT_FILE = join(AUDIT_DIR, "events.jsonl");
const PORT = Number(process.env.MONA_EXPERT_PORT || 4188);
const auditClients = new Set();
let eventBusBroadcast = null;
// Lazy-import event bus broadcast for agent updates
async function agentBroadcast(type, payload) {
  if (!eventBusBroadcast) {
    try {
      const bus = await import("./src/event-bus.js");
      eventBusBroadcast = bus.broadcast;
    } catch { return; }
  }
  try { eventBusBroadcast(type, payload); } catch {}
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8"
};

async function previousAuditHash() {
  try {
    const records = await readAuditLog(AUDIT_FILE);
    return [...records].reverse().find((record) => record.hash)?.hash ?? null;
  } catch {
    return null;
  }
}

async function audit(type, summary, data = {}) {
  const record = await appendAuditEvent(AUDIT_FILE, {
    type,
    source: "mona.expert",
    project: "mona.expert",
    sessionId: "mona.expert-local",
    severity: type === "mona.expert.error" ? "error" : "info",
    summary,
    data
  }, { previousHash: await previousAuditHash() });
  broadcastAuditRecord(record);
  return record;
}

const MAX_BODY_BYTES = 100_000;

async function readJson(req) {
  let body = "";
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) {
      throw Object.assign(new Error("Request body too large"), { statusCode: 413 });
    }
    body += chunk;
  }
  return body ? JSON.parse(body) : {};
}

function sendJson(res, code, payload) {
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  res.end(JSON.stringify(payload));
}

function serializeSseEvent(name, payload) {
  return `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
}

// ─── Setup Helpers ────────────────────────────
function getEnvStatus() {
  const keys = ["SITE_URL", "WRAPPER_ID", "WRAPPER_SECRET", "SITE_CONNECTED", "SITE_USER_ID", "LLM_MODEL", "LLM_ENDPOINT"];
  const result = {};
  for (const k of keys) {
    result[k] = process.env[k] ? (k.includes("SECRET") || k.includes("KEY") ? "✓ set" : process.env[k]) : null;
  }
  return result;
}

async function doConnectSetup(res) {
  try {
    // Import and run mona-sync setup
    const { authenticate, setupRemote, syncOnce, collectMetrics, pushTelemetry, discoverLocalAgents, pushAgentInfo } = await import("./mona-sync.cjs");
    try {
      await authenticate();
      await setupRemote();
      await pushAgentInfo(discoverLocalAgents());
      // One-shot sync
      const metrics = collectMetrics();
      await pushTelemetry(metrics);
      sendJson(res, 200, { ok: true, message: "Connected and synced" });
    } catch (err) {
      sendJson(res, 200, { ok: false, message: err.message });
    }
  } catch (err) {
    sendJson(res, 200, { ok: false, message: "mona-sync module unavailable: " + err.message });
  }
}

function broadcastAuditRecord(record) {
  const message = serializeSseEvent("audit", record);
  for (const client of auditClients) {
    client.write(message);
  }
}

async function sendAuditSnapshot(res) {
  try {
    const records = await readAuditLog(AUDIT_FILE);
    res.write(serializeSseEvent("snapshot", {
      ok: true,
      records: records.slice(-50)
    }));
  } catch {
    res.write(serializeSseEvent("snapshot", {
      ok: true,
      records: []
    }));
  }
}

async function streamBreaches(req, res) {
  res.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-store",
    "connection": "keep-alive",
    "x-accel-buffering": "no"
  });
  res.write(serializeSseEvent("ready", { ok: true, at: new Date().toISOString(), type: "breach" }));
  res.write(serializeSseEvent("snapshot", { breaches: getRecentBreaches(50) }));

  auditClients.add(res);
  const heartbeat = setInterval(() => {
    res.write(serializeSseEvent("heartbeat", { at: new Date().toISOString() }));
  }, 25000);

  req.on("close", () => {
    clearInterval(heartbeat);
    auditClients.delete(res);
  });
}

async function streamAudit(req, res) {
  res.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-store",
    "connection": "keep-alive",
    "x-accel-buffering": "no"
  });
  res.write(serializeSseEvent("ready", { ok: true, at: new Date().toISOString() }));
  await sendAuditSnapshot(res);

  auditClients.add(res);
  const heartbeat = setInterval(() => {
    res.write(serializeSseEvent("heartbeat", { at: new Date().toISOString() }));
  }, 25000);

  req.on("close", () => {
    clearInterval(heartbeat);
    auditClients.delete(res);
  });
}

async function serveStatic(req, res) {
  const url = new URL(req.url, "http://localhost");
  // Alias /live → /live.html
  const pathname = url.pathname === "/" ? "/index.html" : url.pathname === "/live" ? "/live.html" : url.pathname;
  const filePath = resolve(PUBLIC_DIR, `.${pathname}`);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  try {
    const body = await readFile(filePath);
    res.writeHead(200, {
      "content-type": MIME[extname(filePath)] || "application/octet-stream",
      "cache-control": "no-store"
    });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
}

const server = createServer(async (req, res) => {
  req._start = Date.now();
  // Wrap res.end to capture status code and timing
  const origEnd = res.end.bind(res);
  res.end = function end(...args) {
    const elapsed = Date.now() - (req._start || Date.now());
    if (req._pathname && req._pathname.startsWith('/api/') && req._ended !== true) {
      emitApiRequest(req.method, req._pathname, res.statusCode || 200, elapsed);
    }
    req._ended = true;
    return origEnd(...args);
  };
  try {
    const url = new URL(req.url, "http://localhost");
    req._pathname = url.pathname;

    if (url.pathname === "/api/health") {
      sendJson(res, 200, { ok: true, name: "mona.expert", at: new Date().toISOString() });
      return;
    }

    if (url.pathname === "/api/heartbeat") {
      const hb = await getLatestHeartbeat();
      sendJson(res, 200, { ok: true, action: "heartbeat", ...hb });
      return;
    }

    if (url.pathname === "/api/boss") {
      const bs = await getBossStatus();
      sendJson(res, 200, { ok: true, action: "boss", ...bs });
      return;
    }

    if (url.pathname === "/api/sentinel") {
      const st = await getSentinelStatus();
      sendJson(res, 200, { ok: true, action: "sentinel", ...st });
      return;
    }

    if (url.pathname === "/api/sentinel/mysql-health" && req.method === "POST") {
      const result = await checkMysqlViaGateway();
      sendJson(res, 200, { ok: true, action: "sentinel", service: "mysql", result });
      return;
    }

    if (url.pathname === "/api/sentinel/ftp-health" && req.method === "POST") {
      const result = await checkFtpViaGateway();
      sendJson(res, 200, { ok: true, action: "sentinel", service: "ftp", result });
      return;
    }

    if (url.pathname === "/api/system/metrics") {
      sendJson(res, 200, { ok: true, ...getCurrentMetrics() });
      return;
    }

    if (url.pathname === "/api/system") {
      const cpus = os.cpus();
      sendJson(res, 200, {
        ok: true,
        hostname: os.hostname(),
        platform: os.platform(),
        release: os.release(),
        arch: os.arch(),
        uptime: os.uptime(),
        loadavg: os.loadavg(),
        totalmem: os.totalmem(),
        freemem: os.freemem(),
        cpus: cpus.length,
        cpuModel: cpus[0]?.model || "unknown",
        node: process.version,
        pid: process.pid,
        processUptime: process.uptime(),
        at: new Date().toISOString()
      });
      return;
    }

    // ─── Setup & Connection Status ─────────────────────
    if (url.pathname === "/api/setup/status") {
      try {
        // Read env connection state
        const wrapperId = process.env.WRAPPER_ID || null;
        const siteConnected = process.env.SITE_CONNECTED === "true";
        const siteUserId = process.env.SITE_USER_ID || null;
        const siteUrl = process.env.SITE_URL || "https://mona.expert";

        // Generate a connection code from wrapper ID
        const connectionCode = wrapperId ? wrapperId.substring(0, 4).toUpperCase() + "-" + wrapperId.substring(4, 8).toUpperCase() : "XXXX-XXXX";

        // Count running agents (sandboxed + built-in)
        let agentCount = 0;
        try {
          const { getRunningAgents } = await import("./src/agent-sandbox.js");
          const running = getRunningAgents();
          agentCount = Array.isArray(running) ? running.length : (running?.size || 0);
        } catch {}
        // Add built-in agents (heartbeat, boss) even though not sandboxed
        const hb = await getLatestHeartbeat().catch(() => ({}));
        const bs = await getBossStatus().catch(() => ({}));
        const st = await getSentinelStatus().catch(() => ({}));
        if (hb.running) agentCount++;
        if (bs.running) agentCount++;
        if (st.running) agentCount++;

        sendJson(res, 200, {
          ok: true,
          data: {
            serverRunning: true,
            serverUptime: Math.floor(process.uptime()),
            serverPid: process.pid,
            agentCount,
            siteConnected,
            siteUserId,
            siteUrl,
            paired: siteConnected,
            connectionCode,
            wrapperId,
            dotEnv: await getEnvStatus(),
          },
        });
      } catch (err) {
        sendJson(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    if (url.pathname === "/api/setup/connect" && req.method === "POST") {
      // Trigger mona-sync to connect/pair with remote
      doConnectSetup(res);
      return;
    }

    if (url.pathname === "/api/setup/sync") {
      // Returns live sync status (read from mona-sync state file)
      try {
        const syncState = await readFile(os.homedir() + "/.mona-sync-state.json", "utf8").then(JSON.parse).catch(() => ({}));
        sendJson(res, 200, {
          ok: true,
          lastSync: syncState.lastSyncTs || null,
          syncedEvents: Array.isArray(syncState.syncedHashes) ? syncState.syncedHashes.length : 0,
          monitoring: !!syncState.lastSyncTs,
        });
      } catch (err) {
        sendJson(res, 200, { ok: true, monitoring: false, lastSync: null, syncedEvents: 0 });
      }
      return;
    }

    if (req.method === "GET" && (url.pathname === "/api/audit" || url.pathname === "/api/audit-stream")) {
      if (url.pathname === "/api/audit") {
        try {
          const records = await readAuditLog(AUDIT_FILE);
          const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '10', 10), 1), 100);
          const filter = url.searchParams.get('filter') || '';
          let filtered = records.slice(-limit).reverse();
          if (filter) {
            filtered = filtered.filter(r => r.event?.event_type !== undefined);
          }
          sendJson(res, 200, { ok: true, count: filtered.length, records: filtered });
        } catch (e) {
          sendJson(res, 200, { ok: true, count: 0, records: [], note: e.message });
        }
        return;
      }
      await streamAudit(req, res);
      return;
    }

    if (url.pathname === "/api/live") {
      const { subscribe } = await import("./src/event-bus.js");
      res.writeHead(200, {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store",
        "connection": "keep-alive",
        "x-accel-buffering": "no"
      });
      res.write(serializeSseEvent("ready", { ok: true, at: new Date().toISOString(), type: "live-dashboard" }));
      const unsub = subscribe(res);
      const heartbeat = setInterval(() => {
        try { res.write(serializeSseEvent("heartbeat", { at: new Date().toISOString() })); } catch { clearInterval(heartbeat); }
      }, 25000);
      req.on("close", () => { clearInterval(heartbeat); unsub(); });
      return;
    }

    if (url.pathname === "/api/breach-stream") {
      await streamBreaches(req, res);
      return;
    }

    if (url.pathname === "/api/breaches") {
      sendJson(res, 200, { breaches: getRecentBreaches(Number(url.searchParams.get("limit")) || 50) });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/safety-run") {
      const body = await readJson(req);
      const result = secureAction(body);

      // If ALLOWed and has input, also run through the live LLM proxy
      let llmResponse = null;
      if (result.decision === "allow" && body.input) {
        try {
          llmResponse = await getProxy().process(body.input, {
            requestedTools: body.requestedTools || [],
            tools: body.tools || undefined,
            user: body.userId || "anonymous",
            tenantId: body.tenantId || "default",
            requireConsent: false
          });
        } catch (proxyErr) {
          llmResponse = { error: proxyErr.message, status: "proxy_error" };
        }
      }

      await audit("mona.expert.safety_run", `Safety run: ${result.decision}`, {
        inputPreview: body.input?.slice?.(0, 260) || "",
        mode: body.mode,
        decision: result.decision,
        hadLlmResponse: !!llmResponse,
        riskScore: result.riskScore,
        triggeredRules: result.triggeredRules.map((rule) => rule.id),
        toolPolicy: result.toolPolicy.map((item) => ({
          toolId: item.toolId,
          decision: item.decision,
          riskLevel: item.riskLevel,
          requiresHumanConfirmation: item.requiresHumanConfirmation,
          dryRunRecommended: item.dryRunRecommended
        }))
      });
      sendJson(res, 200, { ...result, llmResponse });
      return;
    }

    if (url.pathname === "/api/security-status") {
      const patterns = [
        { id: "direct_override", label: "Direct instruction override", weight: 85 },
        { id: "system_prompt_extraction", label: "System prompt extraction", weight: 87 },
        { id: "role_hijack", label: "Role hijack", weight: 80 },
        { id: "developer_mode", label: "Developer mode invocation", weight: 88 },
        { id: "safety_bypass", label: "Safety bypass attempt", weight: 82 },
        { id: "hidden_instruction", label: "Hidden instruction reveal", weight: 87 },
        { id: "prefix_injection", label: "Prefix injection", weight: 75 },
        { id: "context_pollution", label: "Context pollution", weight: 70 },
        { id: "token_manipulation", label: "Token/format manipulation", weight: 65 },
        { id: "delimiter_collapse", label: "Delimiter collapse attempt", weight: 73 },
        { id: "jailbreak_persona", label: "Jailbreak persona invoke", weight: 88 },
        { id: "coercion_token_system", label: "Coercion token threat", weight: 75 },
        { id: "roleplay_persona_bypass", label: "Role-play persona bypass", weight: 65 },
        { id: "identity_creator_override", label: "Creator identity override", weight: 78 },
        { id: "base64_injection", label: "Base64 encoded injection", weight: 85 },
        { id: "hex_encoded_injection", label: "Hex encoded injection", weight: 80 },
        { id: "homoglyph_attack", label: "Unicode homoglyph attack", weight: 75 },
        { id: "url_encoded_injection", label: "URL-encoded injection", weight: 78 },
        { id: "multilang_override", label: "Multi-language instruction override", weight: 82 },
        { id: "payload_splitting", label: "Payload splitting / concatenation", weight: 70 },
        { id: "chatgpt_legacy_bypass", label: "Legacy ChatGPT bypass invocation", weight: 85 }
      ];
      sendJson(res, 200, {
        guard: "injection-guard-v2", version: 2, status: "active", patterns,
        thresholds: { block: "score >= 80", review: "score >= 40", lowRisk: "score >= 10", breach: "auto on block" },
        guardrails: ["inputGuardrail", "outputGuardrail"],
        features: {
          decoder: { base64: true, hex: true, homoglyph: true, obfuscation: true, url: true },
          breachNotification: true,
          auditRestEncryption: true
        },
        lastChecked: new Date().toISOString()
      });
      return;
    }

    if (url.pathname === "/api/security-check" && req.method === "POST") {
      const body = await readJson(req);
      const result = secureAction({ input: body.input || "", mode: body.mode || "balanced", requestedTools: body.requestedTools || [] });
      sendJson(res, 200, {
        decision: result.decision, riskScore: result.riskScore,
        controls: result.controls, injectionGuard: result.injectionGuard,
        triggeredRules: (result.triggeredRules || []).map(r => ({ id: r.id, label: r.label, weight: r.weight })),
        canExecute: result.canExecute, requiresReview: result.requiresReview, blocked: result.blocked
      });
      return;
    }

    // B2C / B2B module APIs
    if (url.pathname === "/api/consent") {
      const { recordConsent, revokeConsent, checkConsent, getConsentReport, createAgreement, getAgreements } = await import("./src/consent-manager.js");
      if (req.method === "POST") {
        const body = await readJson(req);
        if (body.action === "record") sendJson(res, 200, recordConsent(body));
        else if (body.action === "revoke") sendJson(res, 200, revokeConsent(body.consentId));
        else if (body.action === "check") sendJson(res, 200, checkConsent(body));
        else if (body.action === "create-agreement") sendJson(res, 200, createAgreement(body));
        else sendJson(res, 400, { error: "Unknown action" });
      } else {
        sendJson(res, 200, getConsentReport({ tenantId: url.searchParams.get("tenantId") }));
      }
      return;
    }

    if (url.pathname === "/api/consent-report") {
      const { getConsentReport } = await import("./src/consent-manager.js");
      sendJson(res, 200, getConsentReport({ tenantId: url.searchParams.get("tenantId") }));
      return;
    }

    if (url.pathname === "/api/tenants") {
      const { registerTenant, getTenant, listTenants, isolateSession, authorizeTenantModel, trackTenantTokenUsage } = await import("./src/tenant-isolation.js");
      if (req.method === "POST") {
        const body = await readJson(req);
        if (body.action === "register") sendJson(res, 200, registerTenant(body));
        else if (body.action === "isolate") sendJson(res, 200, isolateSession(body));
        else if (body.action === "authorize-model") sendJson(res, 200, authorizeTenantModel(body));
        else if (body.action === "track-usage") sendJson(res, 200, trackTenantTokenUsage(body));
        else sendJson(res, 400, { error: "Unknown action" });
      } else {
        const tenantId = url.searchParams.get("tenantId");
        if (tenantId) sendJson(res, 200, getTenant(tenantId));
        else sendJson(res, 200, listTenants());
      }
      return;
    }

    if (url.pathname === "/api/keys") {
      const auth = optionalAuth(req);
      if (req.method === "POST") {
        const body = await readJson(req);
        if (body.action === "generate") {
          const result = generateApiKey({ tenantId: body.tenantId || auth.tenantId, label: body.label || "default", scopes: body.scopes });
          sendJson(res, 200, result);
        } else if (body.action === "revoke") {
          sendJson(res, 200, revokeApiKey(body.key));
        } else sendJson(res, 400, { error: "Unknown action: use generate or revoke" });
      } else {
        const tenantId = url.searchParams.get("tenantId") || auth.tenantId;
        sendJson(res, 200, listApiKeys(tenantId));
      }
      return;
    }

    if (url.pathname === "/api/cost") {
      const { calculateCost, checkRateLimit, getCostReport, getAllCostReports, createRateLimiter } = await import("./src/rate-limiter.js");
      if (req.method === "POST") {
        const body = await readJson(req);
        if (body.action === "calculate") sendJson(res, 200, calculateCost(body));
        else if (body.action === "check-limit") sendJson(res, 200, checkRateLimit(body));
        else if (body.action === "create-limiter") sendJson(res, 200, createRateLimiter(body));
        else sendJson(res, 400, { error: "Unknown action" });
      } else {
        const key = url.searchParams.get("key") || url.searchParams.get("plan");
        if (key) sendJson(res, 200, getCostReport(key));
        else sendJson(res, 200, getAllCostReports());
      }
      return;
    }

    if (url.pathname === "/api/llm" && req.method === "POST") {
      const body = await readJson(req);
      try {
        const result = await getProxy().process(body.input || "", {
          maxOutputTokens: body.maxTokens || 500,
          requestedTools: body.requestedTools || [],
          tools: body.tools || undefined,
          user: body.userId || "website",
          tenantId: body.tenantId || "default",
          requireConsent: body.requireConsent === true
        });
        await audit("mona.expert.agent_event", `Website API call: ${result.decision || "complete"}`, {
          endpoint: "/api/llm",
          decision: result.decision,
          blocked: result.blocked,
          requiresReview: result.requiresReview,
          requestedTools: body.requestedTools || []
        });
        sendJson(res, 200, { ok: !result.blocked, ...result });
      } catch (err) {
        await audit("mona.expert.error", `Website API call failed: ${err.message}`, { endpoint: "/api/llm" });
        sendJson(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    if (url.pathname === "/api/compliance-evidence") {
      const { getConsentReport } = await import("./src/consent-manager.js");
      const { listTenants } = await import("./src/tenant-isolation.js");
      const { getAllCostReports } = await import("./src/rate-limiter.js");
      sendJson(res, 200, {
        generatedAt: new Date().toISOString(),
        project: "mona.expert",
        version: "0.1.0",
        consents: getConsentReport(),
        tenants: listTenants(),
        costs: getAllCostReports(),
        evidence: {
          auditReady: true,
          chainOfCustody: true,
          tenantIsolation: true,
          consentTracking: true,
          rateLimiting: true,
          injectionGuard: true
        },
        standards: ["SOC2", "ISO 27001", "GDPR", "CCPA"]
      });
      return;
    }

    if (url.pathname === "/api/safety-run-stream" && req.method === "GET") {
      // SSE endpoint for streaming LLM responses through the proxy
      const input = url.searchParams.get("input") || "";
      if (!input) {
        res.writeHead(400);
        res.end("Missing ?input= parameter");
        return;
      }
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-store",
        "connection": "keep-alive",
        "x-accel-buffering": "no"
      });

      try {
        const stream = getProxy().processStream(input, { requireConsent: false });

        for await (const event of stream) {
          if (event.type === "error") {
            res.write(`event: error\ndata: ${JSON.stringify(event)}\n\n`);
            break;
          } else if (event.type === "token") {
            res.write(`event: token\ndata: ${JSON.stringify(event)}\n\n`);
          } else if (event.type === "meta") {
            res.write(`event: meta\ndata: ${JSON.stringify({ steps: event.steps, cost: event.cost })}\n\n`);
          } else if (event.type === "done") {
            res.write(`event: done\ndata: ${JSON.stringify(event)}\n\n`);
            break;
          }
        }
      } catch (err) {
        res.write(`event: error\ndata: ${JSON.stringify({ type: "error", reason: "SERVER_ERROR", details: { error: err.message } })}\n\n`);
      }
      res.end();
      return;
    }

    // ═══════════════════════════════════════════════
    // Agent Registry API
    // ═══════════════════════════════════════════════

    if (url.pathname === "/api/agents" && req.method === "GET") {
      const agents = await listAgents();
      sendJson(res, 200, { ok: true, agents, summary: await getRegistrySummary() });
      return;
    }

    if (url.pathname === "/api/agents/running" && req.method === "GET") {
      sendJson(res, 200, { ok: true, running: getRunningAgents() });
      return;
    }

    if (url.pathname === "/api/agents/custom" && req.method === "POST") {
      const body = await readJson(req);
      if (!body.manifest) {
        sendJson(res, 400, { ok: false, error: "Missing 'manifest' in request body" });
        return;
      }
      const validation = validateManifest(body.manifest);
      if (!validation.valid) {
        sendJson(res, 400, { ok: false, error: "Invalid manifest", details: validation.errors });
        return;
      }
      try {
        const agent = await addCustomAgent(body.manifest);
        await audit("mona.expert.agent_added", `Custom agent added: ${agent.name}`, { agentId: agent.id });
        sendJson(res, 201, { ok: true, agent });
      } catch (err) {
        sendJson(res, 409, { ok: false, error: err.message });
      }
      return;
    }

    // Agent-specific routes: /api/agents/:id/action
    const agentMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/(\w+)$/);
    if (agentMatch) {
      const [, agentId, action] = agentMatch;

      if (req.method !== "POST") {
        sendJson(res, 405, { ok: false, error: "Method not allowed" });
        return;
      }

      try {
        let result;
        const actionMap = {
          install: async () => {
            const agent = await getAgent(agentId);
            if (!agent) throw new Error(`Agent "${agentId}" not found`);
            const installPath = join(ROOT, ".mona-agents", "installed", agentId);
            result = await installAgent(agentId, installPath);
            await audit("mona.expert.agent_installed", `Agent installed: ${result.name}`, { agentId, installPath });
            await agentBroadcast("agents-update", { action: "installed", agentId, name: result.name });
            return { ok: true, agent: result };
          },
          uninstall: async () => {
            result = await uninstallAgent(agentId);
            await audit("mona.expert.agent_uninstalled", `Agent uninstalled: ${result.name}`, { agentId });
            await agentBroadcast("agents-update", { action: "uninstalled", agentId, name: result.name });
            return { ok: true, agent: result };
          },
          start: async () => {
            result = await startAgent(agentId);
            await audit("mona.expert.agent_started", `Agent started: ${agentId}`, { agentId });
            await agentBroadcast("agents-update", { action: "started", agentId });
            return { ok: true, ...result };
          },
          stop: async () => {
            result = await stopAgent(agentId);
            await audit("mona.expert.agent_stopped", `Agent stopped: ${agentId}`, { agentId });
            await agentBroadcast("agents-update", { action: "stopped", agentId });
            return { ok: true, ...result };
          },
        };

        const handler = actionMap[action];
        if (!handler) {
          sendJson(res, 400, { ok: false, error: `Unknown action "${action}". Valid: ${Object.keys(actionMap).join(", ")}` });
          return;
        }

        sendJson(res, 200, await handler());
      } catch (err) {
        sendJson(res, 400, { ok: false, error: err.message });
      }
      return;
    }

    // GET single agent
    if (url.pathname.startsWith("/api/agents/") && req.method === "GET") {
      const agentId = url.pathname.slice("/api/agents/".length);
      if (agentId && agentId !== "running" && agentId !== "custom") {
        const agent = await getAgent(agentId);
        if (!agent) {
          sendJson(res, 404, { ok: false, error: `Agent "${agentId}" not found` });
          return;
        }
        sendJson(res, 200, { ok: true, agent });
        return;
      }
    }

    // ─── Dashboard API (api.php proxy for local dev) ───
    if (url.pathname === "/api.php" || url.pathname.endsWith("/api.php")) {
      if (req.method !== "POST") {
        sendJson(res, 405, { status: "error", error: "Method not allowed" });
        return;
      }
      try {
        const action = url.searchParams.get("action");
        if (!action) {
          sendJson(res, 400, { status: "error", error: "Missing action" });
          return;
        }
        let body = {};
        try { body = await readJson(req); } catch { body = {}; }

        switch (action) {
          case "me": {
            sendJson(res, 200, {
              status: "ok",
              user: {
                id: 1,
                name: "Mona",
                email: "mona@localhost",
                role: "admin",
                created_at: new Date().toISOString(),
                provider_id: "local",
                provider_name: "Local Dev",
              },
            });
            return;
          }

          case "list_wrappers": {
            let wrappers = [];
            try {
              const { listAgents } = await import("./src/agent-registry.js");
              const agents = await listAgents();
              wrappers = (agents || []).map((a, i) => ({
                id: a.id || `wrapper_${i}`,
                name: a.name || a.id || `Wrapper ${i}`,
                status: a.installed ? "online" : "offline",
                version: a.version || "1.0.0",
                last_seen: new Date().toISOString(),
                cpu: "—",
                memory: "—",
              }));
            } catch { /* no agents yet */ }
            sendJson(res, 200, { status: "ok", wrappers });
            return;
          }

          case "get_latest_telemetry": {
            const metrics = getCurrentMetrics();
            const latest = {
              id: 1,
              created_at: new Date().toISOString(),
              wrapper_id: "local",
              details: JSON.stringify({
                hostname: os.hostname(),
                cpu: {
                  pct: metrics.cpu,
                  load_1m: metrics.loadavg[0],
                  cores: os.cpus().length,
                },
                memory: {
                  total_bytes: metrics.memory.totalBytes,
                  used_bytes: metrics.memory.usedBytes,
                  pct: metrics.memory.percent,
                },
                disk: {
                  total_gb: "—",
                  used_gb: "—",
                  pct: 0,
                },
                uptime: metrics.uptime,
              }),
            };
            sendJson(res, 200, { status: "ok", latest });
            return;
          }

          case "get_audit_stats": {
            let daily = {};
            let total = 0;
            let injections = 0;
            try {
              const log = await readAuditLog(AUDIT_FILE);
              for (const record of log) {
                if (!record?.event?.action) continue;
                total++;
                const day = (record.recordedAt || record.event.timestamp || "").slice(0, 10);
                if (day) {
                  daily[day] = (daily[day] || 0) + 1;
                }
                if (record.event.action.includes("injection") || record.event.action.includes("safety")) {
                  injections++;
                }
              }
            } catch { /* empty log */ }
            sendJson(res, 200, {
              status: "ok",
              daily,
              stats: {
                total_events: total,
                injection_blocks: injections,
                active_wrappers: 1,
                online_agents: 0,
              },
            });
            return;
          }

          case "get_audit_log": {
            let logEntries = [];
            try {
              const log = await readAuditLog(AUDIT_FILE);
              const limit = Number(body.limit) || 50;
              const offset = Number(body.offset) || 0;
              logEntries = log.slice(offset, offset + limit).map((r, i) => ({
                id: i + 1,
                event_type: r.event?.action?.includes("injection") || r.event?.action?.includes("safety") ? "security" :
                             r.event?.action?.includes("chat") || r.event?.action?.includes("llm") ? "llm" :
                             r.event?.action?.includes("wrapper") || r.event?.action?.includes("agent") ? "wrapper" :
                             r.event?.action?.includes("api") || r.event?.action?.includes("request") ? "api" :
                             "auth",
                action: r.event?.action || "unknown",
                status: r.event?.status || "success",
                created_at: r.recordedAt || r.event?.timestamp || new Date().toISOString(),
                details: JSON.stringify(r.event?.metadata || {}),
              }));
            } catch { /* empty */ }
            sendJson(res, 200, {
              status: "ok",
              log: logEntries,
              total: logEntries.length,
            });
            return;
          }

          default:
            sendJson(res, 400, { status: "error", error: `Unknown action: ${action}` });
        }
      } catch (err) {
        sendJson(res, 500, { status: "error", error: err.message });
      }
      return;
    }

    await serveStatic(req, res);
  } catch (error) {
    const status = error.statusCode || 500;
    await audit("mona.expert.error", `HTTP ${status}: ${error.message}`);
    sendJson(res, status, { ok: false, error: error.message });
  }
});

await audit("mona.expert.server_ready", "mona.expert server starting", { port: PORT, root: ROOT });

// Start system resource monitoring (broadcasts every 10s to SSE clients)
startSystemMonitor(10000);

// Auto-start heartbeat, boss and sentinel agents
(async () => {
  try {
    const hb = startHeartbeat();
    const boss = startBoss();
    const sentinel = await startSentinel();
    await audit("mona.expert.agent_event", `Heartbeat: ${hb.status}, Boss: ${boss.status}, Sentinel: ${sentinel.status}`, {
      agents: { heartbeat: hb, boss: boss, sentinel: sentinel },
    });
  } catch (err) {
    console.error("Failed to auto-start agents:", err.message);
  }
})();

// Auto-start mona-sync (non-blocking, runs as background sync every 120s)
(async () => {
  try {
    const { authenticate, setupRemote } = await import("./mona-sync.cjs");
    try {
      await authenticate();
      await setupRemote();
      console.log("✔ mona-sync: remote authenticated");
      // Schedule periodic sync (non-watch, just one-shot after auth since watch uses setInterval internally)
      setInterval(async () => {
        try {
          const { syncOnce, collectMetrics } = await import("./mona-sync.cjs");
          await syncOnce();
        } catch {}
      }, 120000);
      // Do first sync immediately
      const { syncOnce, collectMetrics } = await import("./mona-sync.cjs");
      await syncOnce();
    } catch (err) {
      console.warn("ℹ mona-sync: remote auth failed (" + err.message + ") — sync will be offline");
    }
  } catch (err) {
    // mona-sync.cjs may not exist or have import compatibility issues
    console.warn("ℹ mona-sync: module unavailable — " + err.message);
  }
})();

server.listen(PORT, "127.0.0.1", () => {
  console.log(`mona.expert running at http://127.0.0.1:${PORT}`);
  console.log(`Audit events: ${AUDIT_FILE}`);
});

// ─── Graceful Shutdown ────────────────────────────────
async function shutdown(signal) {
  console.log(`\n${signal} received — draining connections…`);

  // Stop all running agents
  stopHeartbeat();
  stopBoss();
  stopSentinel();
  try {
    const { stopAllAgents } = await import("./src/agent-sandbox.js");
    const stopped = await stopAllAgents();
    if (stopped.length > 0) {
      console.log(`Stopped ${stopped.length} sandboxed agent(s)`);
    }
  } catch { /* agent sandbox may not be loaded */ }
  // Close all SSE clients
  for (const client of auditClients) {
    try {
      client.write(serializeSseEvent("shutdown", { at: new Date().toISOString(), reason: signal }));
      client.end();
    } catch { /* already closed */ }
  }
  auditClients.clear();
  server.close(() => {
    console.log("mona.expert stopped.");
    process.exit(0);
  });
  // Force close after 5s
  setTimeout(() => {
    console.error("Forced shutdown after timeout.");
    process.exit(1);
  }, 5000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
