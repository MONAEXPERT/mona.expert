// mona.expert — Boss Agent Runtime
// Supervisory coordination: monitors agents, cross-references logs, escalates anomalies

import { broadcast } from "../event-bus.js";
import { getCurrentMetrics } from "../system-monitor.js";
import { listAgents, getAgent, getRegistrySummary } from "../agent-registry.js";
import { getRunningAgents } from "../agent-sandbox.js";
import { INSTALL_STATUS } from "../agent-manifest.js";
import { readAuditLog } from "../audit-log.js";

const INTERVAL_MS = Number(process.env.BOSS_INTERVAL_MS) || 60000;
const HEARTBEAT_MISSED_THRESHOLD = 3;
const AUDIT_FILE = process.env.MONA_EXPERT_AUDIT_FILE || ".mona-dashboard/events.jsonl";

let intervalHandle = null;
let cycleCount = 0;
let lastCycleAt = null;
let heartbeatTickHistory = [];

/**
 * Cross-reference agent statuses and look for anomalies.
 */
async function crossReference() {
  const anomalies = [];
  const running = getRunningAgents();

  // Check for agents in ERROR state
  const allAgents = await listAgents();
  for (const agent of allAgents) {
    if (agent.status === INSTALL_STATUS.ERROR) {
      anomalies.push({
        level: "error",
        agentId: agent.id,
        name: agent.name,
        issue: `Agent in ERROR state`,
        suggestedAction: "Review agent logs and restart",
      });
    }
    // Check for installed but never started
    if (agent.installed && agent.status === INSTALL_STATUS.INSTALLED && agent.installedAt) {
      const installedMs = Date.now() - new Date(agent.installedAt).getTime();
      if (installedMs > 3600000) {
        anomalies.push({
          level: "info",
          agentId: agent.id,
          name: agent.name,
          issue: `Agent installed but never started (${Math.round(installedMs / 60000)}min idle)`,
          suggestedAction: "Consider starting or uninstalling",
        });
      }
    }
  }

  return anomalies;
}

/**
 * Check for recent audit log spikes (injection blocks, errors).
 */
async function checkAuditAlerts() {
  const alerts = [];
  try {
    const records = await readAuditLog(AUDIT_FILE);
    const recent = records.slice(-50);
    const injectionBlocks = recent.filter(r =>
      r.type?.includes("injection") || r.summary?.toLowerCase().includes("injection")
    ).length;
    const errors = recent.filter(r =>
      r.severity === "error"
    ).length;

    if (injectionBlocks > 5) {
      alerts.push({ level: "warn", type: "injection_spike", count: injectionBlocks });
    }
    if (errors > 3) {
      alerts.push({ level: "warn", type: "error_spike", count: errors });
    }
  } catch {
    // No audit log available
  }
  return alerts;
}

/**
 * Run one boss evaluation cycle.
 */
async function evaluate() {
  cycleCount++;
  lastCycleAt = new Date().toISOString();

  const metrics = getCurrentMetrics();
  const registrySummary = await getRegistrySummary();
  const running = getRunningAgents();
  const anomalies = await crossReference();
  const auditAlerts = await checkAuditAlerts();
  const allAlerts = [...anomalies, ...auditAlerts];

  const summary = {
    cycle: cycleCount,
    at: lastCycleAt,
    intervalMs: INTERVAL_MS,
    metrics: {
      cpu: metrics.cpu,
      memory: metrics.memory.percent,
      processUptime: Math.round(metrics.process.uptime),
    },
    registry: registrySummary,
    running: running.map(r => ({ agentId: r.agentId, status: r.status, uptime: r.startedAt })),
    anomalies: allAlerts.filter(a => a.level === "error" || a.level === "warn"),
    infos: allAlerts.filter(a => a.level === "info"),
    status: allAlerts.some(a => a.level === "error") ? "degraded" :
            allAlerts.some(a => a.level === "warn") ? "warning" : "healthy",
  };

  broadcast("boss-summary", summary);

  // Escalate on critical issues
  if (allAlerts.some(a => a.level === "error")) {
    broadcast("boss-escalation", {
      cycle: cycleCount,
      at: lastCycleAt,
      reason: "Critical anomalies detected",
      details: allAlerts.filter(a => a.level === "error"),
    });
  }

  return summary;
}

/**
 * Start the boss agent.
 */
export function startBoss() {
  if (intervalHandle) {
    return { ok: true, status: "already_running" };
  }

  // Evaluate immediately, then on interval
  evaluate().catch(err => {
    broadcast("boss-escalation", {
      cycle: cycleCount,
      at: new Date().toISOString(),
      reason: "Evaluation error",
      error: err.message,
    });
  });

  intervalHandle = setInterval(() => {
    evaluate().catch(err => {
      broadcast("boss-escalation", {
        cycle: cycleCount,
        at: new Date().toISOString(),
        reason: "Evaluation error",
        error: err.message,
      });
    });
  }, INTERVAL_MS).unref();

  console.log(`◆ Boss agent started (interval: ${INTERVAL_MS}ms)`);

  return { ok: true, status: "started", intervalMs: INTERVAL_MS };
}

/**
 * Stop the boss agent.
 */
export function stopBoss() {
  if (!intervalHandle) {
    return { ok: true, status: "not_running" };
  }
  clearInterval(intervalHandle);
  intervalHandle = null;
  console.log("◆ Boss agent stopped");
  return { ok: true, status: "stopped" };
}

/**
 * Get latest boss status.
 */
export async function getBossStatus() {
  if (!lastCycleAt) {
    return { ok: true, status: "not_started" };
  }
  return {
    ok: true,
    cycles: cycleCount,
    lastCycle: lastCycleAt,
    running: !!intervalHandle,
  };
}
