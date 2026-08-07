/**
 * mona.expert — Secure AI Agent Wrapper (mTLS Backend)
 * 
 * Internal service on 127.0.0.1:4189
 * Only accepts requests with a valid client certificate signed by our CA.
 * The website gateway is the only authorized client.
 */

import { createServer } from "node:https";
import { randomBytes } from "node:crypto";
import { readFile, access } from "node:fs/promises";
import { constants } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { appendAuditEvent, readAuditLog } from "./src/audit-log.js";
import { secureAction } from "./src/security-layer.js";
import { getRecentBreaches } from "./src/injection-guard.js";
import { createProxy } from "./src/llm-proxy.js";
import { authenticateRequest, generateApiKey, revokeApiKey, listApiKeys, requireAuth, requireScope } from "./src/api-auth.js";
import { connectDatabase, dbHealth, disconnectDatabase } from "./src/db.js";
import { createMessageRouter } from "./src/message-broker.js";
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

// ─── Config ───────────────────────────────────────────
console.log("mona.expert wrapper v0.10.0 — checking configuration…");
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

const ROOT = fileURLToPath(new URL(".", import.meta.url));
const AUDIT_DIR = join(ROOT, ".mona-dashboard");
const AUDIT_FILE = join(AUDIT_DIR, "events.jsonl");
const CERTS_DIR = join(ROOT, "certs");
const PORT = Number(process.env.WRAPPER_PORT || 4189);
const auditClients = new Set();
const sentinelSessions = new Map(); // in-memory session tokens (never persisted)
let eventBusBroadcast = null;

async function agentBroadcast(type, payload) {
  if (!eventBusBroadcast) {
    try {
      const bus = await import("./src/event-bus.js");
      eventBusBroadcast = bus.broadcast;
    } catch { return; }
  }
  try { eventBusBroadcast(type, payload); } catch {}
}

// ─── Lazy LLM proxy ───────────────────────────────────
let llmProxy = null;
function getProxy() {
  if (!llmProxy) llmProxy = createProxy();
  return llmProxy;
}

// ─── Audit helpers ────────────────────────────────────
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
    sessionId: "wrapper-internal",
    severity: type.includes("error") ? "error" : "info",
    summary,
    data
  }, { previousHash: await previousAuditHash() });
  broadcastAuditRecord(record);
  return record;
}

// ─── HTTP helpers ─────────────────────────────────────
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

function broadcastAuditRecord(record) {
  const message = serializeSseEvent("audit", record);
  for (const client of auditClients) {
    client.write(message);
  }
}

async function sendAuditSnapshot(res) {
  try {
    const records = await readAuditLog(AUDIT_FILE);
    res.write(serializeSseEvent("snapshot", { ok: true, records: records.slice(-50) }));
  } catch {
    res.write(serializeSseEvent("snapshot", { ok: true, records: [] }));
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
  req.on("close", () => { clearInterval(heartbeat); auditClients.delete(res); });
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
  req.on("close", () => { clearInterval(heartbeat); auditClients.delete(res); });
}

// ─── mTLS Server ──────────────────────────────────────
const wrapperServer = createServer({
  key: await readFile(join(CERTS_DIR, "wrapper-key.pem")),
  cert: await readFile(join(CERTS_DIR, "wrapper-cert.pem")),
  ca: await readFile(join(CERTS_DIR, "ca-cert.pem")),
  requestCert: true,
  rejectUnauthorized: true,  // Only clients with valid cert can connect
}, async (req, res) => {
  // Log which client certificate connected
  const clientCert = req.socket.getPeerCertificate();
  const clientCN = clientCert?.subject?.CN || "unknown";

  try {
    const url = new URL(req.url, "https://localhost");

    // ── Health check ──────────────────────────────────
    if (url.pathname === "/api/health") {
      sendJson(res, 200, {
        ok: true,
        name: "mona.expert-wrapper",
        version: "0.10.0",
        at: new Date().toISOString(),
        client: clientCN,
        tls: true,
        mtls: true
      });
      return;
    }

    // ── Audit stream (SSE) ────────────────────────────
    if (req.method === "GET" && url.pathname === "/api/audit-stream") {
      await streamAudit(req, res);
      return;
    }

    // ── Live event stream (SSE) ───────────────────────
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

    // ── Breach stream (SSE) ───────────────────────────
    if (url.pathname === "/api/breach-stream") {
      await streamBreaches(req, res);
      return;
    }

    // ── Breaches list ─────────────────────────────────
    if (url.pathname === "/api/breaches") {
      sendJson(res, 200, { breaches: getRecentBreaches(Number(url.searchParams.get("limit")) || 50) });
      return;
    }

    // ── Safety run ────────────────────────────────────
    if (req.method === "POST" && url.pathname === "/api/safety-run") {
      const body = await readJson(req);
      const result = secureAction(body);
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
      });
      sendJson(res, 200, { ...result, llmResponse });
      return;
    }

    // ── Security status ───────────────────────────────
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

    // ── Security check ────────────────────────────────
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

    // ── Consent ───────────────────────────────────────
    if (url.pathname === "/api/consent") {
      const { recordConsent, revokeConsent, checkConsent, getConsentReport, createAgreement } = await import("./src/consent-manager.js");
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

    // ── Tenants ───────────────────────────────────────
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

    // ── Message Broker ────────────────────────────────
    const broker = createMessageRouter();

    // ── Message Broker (MySQL required; graceful fallback) ─
    async function handleBrokerRoute(req, res) {
      const broker = createMessageRouter();
      try {
        if (req.method === "POST") {
          const body = await readJson(req);
          switch (body.action) {
            case "send": {
              const result = await broker.sendMessage({
                type: body.type || "direct",
                sourceAgent: body.sourceAgent,
                sourceTenant: body.sourceTenant || "default",
                targetAgent: body.targetAgent,
                payload: body.payload,
                ttlSeconds: body.ttlSeconds,
                priority: body.priority,
              });
              sendJson(res, 200, result);
              return;
            }
            case "poll": {
              const result = await broker.pollMessages(body.agentId, body.tenantId || "default", {
                limit: body.limit || 20,
              });
              sendJson(res, 200, { ok: true, messages: result });
              return;
            }
            case "ack": {
              const result = await broker.acknowledgeMessage(body.messageId, body.status);
              sendJson(res, 200, result);
              return;
            }
            case "broadcast": {
              const result = await broker.broadcastToTenant({
                sourceAgent: body.sourceAgent,
                sourceTenant: body.sourceTenant || "default",
                payload: body.payload,
                ttlSeconds: body.ttlSeconds,
              });
              sendJson(res, 200, result);
              return;
            }
            default:
              sendJson(res, 400, { ok: false, error: `Unknown message action: ${body.action}` });
              return;
          }
        } else {
          const result = await broker.getQueueStats(url.searchParams.get("tenantId"));
          sendJson(res, 200, result);
        }
      } catch (brokerErr) {
        sendJson(res, 503, { ok: false, error: "Message broker requires MySQL", detail: brokerErr.message });
      }
    }

    if (url.pathname.startsWith("/api/messages") && req.method !== "POST") {
      await handleBrokerRoute(req, res);
      return;
    } else if (url.pathname.startsWith("/api/messages") && req.method === "POST") {
      await handleBrokerRoute(req, res);
      return;
    }

    // ── Queue Maintenance ──────────────────────────────
    if (url.pathname === "/api/messages/clean" && req.method === "POST") {
      try {
        const broker = createMessageRouter();
        const result = await broker.cleanExpiredMessages();
        sendJson(res, 200, result);
      } catch (cleanErr) {
        sendJson(res, 503, { ok: false, error: "Message broker requires MySQL", detail: cleanErr.message });
      }
      return;
    }

    // ── API Keys (MySQL required; graceful fallback) ──
    if (url.pathname === "/api/keys") {
      try {
        if (req.method === "POST") {
          const body = await readJson(req);
          if (body.action === "generate") {
            const result = await generateApiKey({ tenantId: body.tenantId || "default", label: body.label || "default", scopes: body.scopes || ["llm:write"] });
            sendJson(res, 200, result);
          } else if (body.action === "revoke") {
            sendJson(res, 200, await revokeApiKey(body.key));
          } else if (body.action === "rotate") {
            const { rotateApiKey } = await import("./src/key-store.js");
            sendJson(res, 200, await rotateApiKey(body.key));
          } else sendJson(res, 400, { error: "Unknown action: use generate, revoke, or rotate" });
        } else {
          const tenantId = url.searchParams.get("tenantId") || "default";
          sendJson(res, 200, await listApiKeys(tenantId));
        }
      } catch (keyErr) {
        sendJson(res, 503, { ok: false, error: "API key management requires MySQL", detail: keyErr.message });
      }
      return;
    }

    // ── Cost / Rate limiting ──────────────────────────
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

    // ── LLM proxy ─────────────────────────────────────
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
        });
        sendJson(res, 200, { ok: !result.blocked, ...result });
      } catch (err) {
        await audit("mona.expert.error", `Website API call failed: ${err.message}`, { endpoint: "/api/llm" });
        sendJson(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    // ── Compliance evidence ───────────────────────────
    if (url.pathname === "/api/compliance-evidence") {
      const { getConsentReport } = await import("./src/consent-manager.js");
      const { listTenants } = await import("./src/tenant-isolation.js");
      const consentReport = getConsentReport({});
      const tenants = listTenants();
      sendJson(res, 200, {
        consentSummary: { totalRecords: consentReport.records?.length || 0 },
        tenantCount: tenants?.length || 0,
        auditChain: "SHA-256 linked, tamper-detectable",
        injectionGuardVersion: 2,
        at: new Date().toISOString()
      });
      return;
    }

    // ── Agents (multi-action POST) ────────────────────
    if (url.pathname === "/api/agents" && req.method === "POST") {
      try {
        const body = await readJson(req);
        const action = body.action;
        let result;

        const actionMap = {
          list: async () => {
            result = listAgents();
            return { ok: true, agents: result, summary: getRegistrySummary() };
          },
          running: async () => {
            result = getRunningAgents();
            return { ok: true, running: result };
          },
          custom: async () => {
            result = await addCustomAgent(body);
            await audit("mona.expert.agent_added", `Custom agent added: ${body.name}`, { name: body.name });
            return { ok: true, agent: result };
          },
          validate: async () => {
            const manifestResult = validateManifest(body.manifest);
            return { ok: true, ...manifestResult };
          },
          install: async () => {
            const agentId = body.agentId;
            if (!agentId) throw new Error("agentId required");
            const agent = await getAgent(agentId);
            if (!agent) throw new Error(`Agent "${agentId}" not found`);
            const installPath = join(ROOT, ".mona-agents", "installed", agentId);
            result = await installAgent(agentId, installPath);
            await audit("mona.expert.agent_installed", `Agent installed: ${result.name}`, { agentId, installPath });
            await agentBroadcast("agents-update", { action: "installed", agentId, name: result.name });
            return { ok: true, agent: result };
          },
          uninstall: async () => {
            const agentId = body.agentId;
            result = await uninstallAgent(agentId);
            await audit("mona.expert.agent_uninstalled", `Agent uninstalled: ${result.name}`, { agentId });
            await agentBroadcast("agents-update", { action: "uninstalled", agentId, name: result.name });
            return { ok: true, agent: result };
          },
          start: async () => {
            const agentId = body.agentId;
            result = await startAgent(agentId);
            await audit("mona.expert.agent_started", `Agent started: ${agentId}`, { agentId });
            await agentBroadcast("agents-update", { action: "started", agentId });
            return { ok: true, ...result };
          },
          stop: async () => {
            const agentId = body.agentId;
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

    // ── Single agent GET ──────────────────────────────
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

    // ── Sentinel gateway endpoints ────────────────────
    // These are the ONLY endpoints the Sentinel agent calls.
    // The wrapper holds all credentials; Sentinel never does.

    if (url.pathname === "/api/sentinel/session" && req.method === "POST") {
      // Issue a short-lived in-memory session token for Sentinel.
      const token = "stn_" + randomBytes(24).toString("hex");
      const ttlMs = 5 * 60 * 1000;
      sentinelSessions.set(token, { issuedAt: Date.now(), expiresAt: Date.now() + ttlMs });
      await audit("mona.expert.sentinel", "Sentinel session issued", { ttlMs });
      sendJson(res, 200, { ok: true, sessionToken: token, ttlMs });
      return;
    }

    if (url.pathname === "/api/sentinel/ping" && req.method === "POST") {
      sendJson(res, 200, { ok: true, pong: true, at: new Date().toISOString(), gateway: "wrapper" });
      return;
    }

    if (url.pathname === "/api/sentinel/mysql-health" && req.method === "POST") {
      const health = await dbHealth();
      await audit("mona.expert.sentinel", `MySQL health: ${health.ok ? "ok" : "failed"}`, { health });
      sendJson(res, 200, { ok: health.ok, service: "mysql", ...health });
      return;
    }

    if (url.pathname === "/api/sentinel/ftp-health" && req.method === "POST") {
      // FTP creds come from wrapper-side env only (never from the agent).
      const { Client } = await import("basic-ftp");
      const client = new Client();
      client.ftp.verbose = false;
      try {
        const host = process.env.FTP_HOST;
        if (!host) throw new Error("FTP_HOST not configured on wrapper");
        await client.access({
          host,
          port: Number(process.env.FTP_PORT) || 21,
          user: process.env.FTP_USER || "",
          password: process.env.FTP_PASSWORD || "",
          secure: process.env.FTP_SECURE === "true",
          timeout: 8000,
        });
        const result = { ok: true, service: "ftp", host, connected: true };
        await audit("mona.expert.sentinel", "FTP health: ok", { host });
        sendJson(res, 200, result);
      } catch (err) {
        await audit("mona.expert.sentinel", "FTP health: failed", { error: err.message });
        sendJson(res, 200, { ok: false, service: "ftp", connected: false, error: err.message });
      } finally {
        client.close();
      }
      return;
    }

    // ── Fallback ──────────────────────────────────────
    sendJson(res, 404, { ok: false, error: `Unknown endpoint: ${url.pathname}` });

  } catch (error) {
    const status = error.statusCode || 500;
    await audit("mona.expert.error", `HTTP ${status}: ${error.message}`);
    sendJson(res, status, { ok: false, error: error.message });
  }
});

// ─── Startup ──────────────────────────────────────────
// ─── Connect MySQL ────────────────────────────────────
let mysqlConnected = false;
try {
  await connectDatabase();
  mysqlConnected = true;
  console.log("✔ MySQL database connected");
} catch (err) {
  console.log("ℹ MySQL not available — running with in-memory/disk storage");
  console.log(`   ${err.message}`);
}

await audit("mona.expert.server_ready", "Wrapper backend starting (mTLS)", { port: PORT, mysqlConnected });

wrapperServer.listen(PORT, "127.0.0.1", () => {
  console.log(`🔒 Wrapper backend (mTLS) → https://127.0.0.1:${PORT}`);
  console.log(`   Client cert required — only the website gateway can connect`);
  console.log(`   Audit events: ${AUDIT_FILE}`);
});

// ─── Graceful Shutdown ────────────────────────────────
async function shutdown(signal) {
  console.log(`\n${signal} received — draining connections…`);
  try {
    const { stopAllAgents } = await import("./src/agent-sandbox.js");
    const stopped = await stopAllAgents();
    if (stopped.length > 0) console.log(`Stopped ${stopped.length} sandboxed agent(s)`);
  } catch {}
  for (const client of auditClients) {
    try {
      client.write(serializeSseEvent("shutdown", { at: new Date().toISOString(), reason: signal }));
      client.end();
    } catch {}
  }
  auditClients.clear();
  wrapperServer.close(async () => {
    await disconnectDatabase().catch(() => {});
    console.log("Wrapper backend stopped.");
    process.exit(0);
  });
  setTimeout(() => { console.error("Forced shutdown after timeout."); process.exit(1); }, 5000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
