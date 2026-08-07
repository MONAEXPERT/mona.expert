// mona.expert — Heartbeat Agent Runtime
// Continuously monitors system health, agent liveness, service availability

import { broadcast } from "../event-bus.js";
import { getCurrentMetrics } from "../system-monitor.js";
import { listAgents, getAgent } from "../agent-registry.js";
import { INSTALL_STATUS } from "../agent-manifest.js";

const INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS) || 30000;
const ALERT_MISSED_TICKS = 3;

let intervalHandle = null;
let tickCount = 0;
let lastTickAt = null;

/**
 * Perform a single heartbeat check cycle.
 */
async function tick() {
  tickCount++;
  lastTickAt = new Date().toISOString();

  const metrics = getCurrentMetrics();

  // Check agent statuses
  let agents;
  try {
    agents = await listAgents();
  } catch {
    agents = [];
  }

  const agentStatuses = {};
  const errors = [];
  for (const agent of agents) {
    agentStatuses[agent.id] = {
      name: agent.name,
      status: agent.status,
      installed: agent.installed,
    };
    if (agent.status === INSTALL_STATUS.ERROR) {
      errors.push({ agentId: agent.id, name: agent.name, status: agent.status });
    }
  }

  // Ping health endpoint
  let endpointOk = false;
  let endpointLatency = -1;
  // Server is local; rely on in-process health as fallback
  endpointOk = metrics.process.pid > 0;

  // Build summary
  const summary = {
    tick: tickCount,
    at: lastTickAt,
    intervalMs: INTERVAL_MS,
    metrics: {
      cpu: metrics.cpu,
      memory: metrics.memory.percent,
      uptime: metrics.uptime,
    },
    agents: {
      total: agents.length,
      running: agents.filter(a => a.status === INSTALL_STATUS.RUNNING).length,
      error: errors.length,
    },
    endpoint: {
      ok: endpointOk,
      latencyMs: endpointLatency,
    },
  };

  // Broadcast tick
  broadcast("heartbeat-tick", summary);

  // Broadcast alert if errors
  if (errors.length > 0) {
    broadcast("heartbeat-alert", {
      tick: tickCount,
      at: lastTickAt,
      type: "agent_errors",
      errors: errors.map(e => `${e.name} (${e.agentId}): ${e.status}`),
    });
  }

  // Check memory pressure
  if (metrics.memory.percent > 85) {
    broadcast("heartbeat-alert", {
      tick: tickCount,
      at: lastTickAt,
      type: "memory_pressure",
      memoryPercent: metrics.memory.percent,
    });
  }

  return summary;
}

/**
 * Start the heartbeat agent.
 */
export function startHeartbeat() {
  if (intervalHandle) {
    return { ok: true, status: "already_running" };
  }

  // Tick immediately, then on interval
  tick().catch(err => {
    broadcast("heartbeat-alert", {
      tick: tickCount,
      at: new Date().toISOString(),
      type: "tick_error",
      error: err.message,
    });
  });

  intervalHandle = setInterval(() => {
    tick().catch(err => {
      broadcast("heartbeat-alert", {
        tick: tickCount,
        at: new Date().toISOString(),
        type: "tick_error",
        error: err.message,
      });
    });
  }, INTERVAL_MS).unref();

  console.log(`♥ Heartbeat agent started (interval: ${INTERVAL_MS}ms)`);

  return { ok: true, status: "started", intervalMs: INTERVAL_MS };
}

/**
 * Stop the heartbeat agent.
 */
export function stopHeartbeat() {
  if (!intervalHandle) {
    return { ok: true, status: "not_running" };
  }
  clearInterval(intervalHandle);
  intervalHandle = null;
  console.log("♥ Heartbeat agent stopped");
  return { ok: true, status: "stopped" };
}

/**
 * Get the latest heartbeat summary.
 */
export async function getLatestHeartbeat() {
  if (!lastTickAt) {
    return { ok: true, status: "not_started" };
  }
  return { ok: true, tick: tickCount, at: lastTickAt, running: !!intervalHandle };
}
