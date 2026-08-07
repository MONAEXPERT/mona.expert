// mona.expert — Deep Agent Instrumentation
// Broadcasts every agent lifecycle event, I/O action, and status change to the live dashboard
// Augments the existing agent-sandbox.js with real-time event hooks

import { broadcast } from "./event-bus.js";

/**
 * Broadcast when an agent starts — include PID, resource limits, sandbox info
 */
export function emitAgentStart(agentId, name, pid, sandboxPath, resourceLimits) {
  broadcast("agent-lifecycle", {
    action: "start",
    agentId,
    name,
    pid,
    sandboxPath,
    resourceLimits,
    startedAt: new Date().toISOString(),
  });
}

/**
 * Broadcast when an agent stops
 */
export function emitAgentStop(agentId, name, reason, runtimeMs) {
  broadcast("agent-lifecycle", {
    action: "stop",
    agentId,
    name,
    reason: reason || "shutdown",
    runtimeMs,
    stoppedAt: new Date().toISOString(),
  });
}

/**
 * Broadcast when an agent crashes or exits unexpectedly
 */
export function emitAgentCrash(agentId, name, exitCode, signal, stderrTail) {
  broadcast("agent-lifecycle", {
    action: "crash",
    agentId,
    name,
    exitCode,
    signal,
    stderrTail: stderrTail || null,
    crashedAt: new Date().toISOString(),
  });
}

/**
 * Broadcast agent I/O — every input received, output produced, injection blocked
 */
export function emitAgentIO(agentId, name, direction, content, meta = {}) {
  // Truncate content to avoid flooding the dashboard with large payloads
  const truncated = (content || "").slice(0, 500);
  broadcast("agent-io", {
    agentId,
    name,
    direction,          // "in" | "out" | "blocked" | "tool_call" | "tool_result"
    content: truncated,
    length: (content || "").length,
    ...meta,
    at: new Date().toISOString(),
  });
}

/**
 * Broadcast tool execution — which tool was called, with what args, result status
 */
export function emitToolCall(agentId, toolName, args, result, elapsedMs, status) {
  broadcast("agent-tool", {
    agentId,
    tool: toolName,
    args: JSON.stringify(args).slice(0, 300),
    result: JSON.stringify(result).slice(0, 300),
    elapsedMs,
    status: status || "success", // "success" | "error" | "blocked"
    at: new Date().toISOString(),
  });
}

/**
 * Broadcast when an agent's resource usage changes (CPU/memory spike)
 */
export function emitAgentResource(agentId, name, cpuPercent, memoryMb) {
  broadcast("agent-resource", {
    agentId,
    name,
    cpuPercent: Math.round(cpuPercent),
    memoryMb: Math.round(memoryMb),
    at: new Date().toISOString(),
  });
}

/**
 * Broadcast when the wrapper server receives an API request
 */
export function emitApiRequest(method, path, statusCode, elapsedMs, clientIp) {
  broadcast("api-request", {
    method,
    path,
    statusCode,
    elapsedMs,
    clientIp: clientIp || "unknown",
    at: new Date().toISOString(),
  });
}
