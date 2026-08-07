/**
 * mona.expert — Secure Message Broker
 *
 * Provides agent-to-agent, agent-to-wrapper, and cross-tenant messaging
 * with delivery guarantees, audit trail, injection guard pass-through,
 * and SSE event broadcast.
 *
 * Architecture:
 *   Agent A → sendToAgent(agentId, payload) → SQL queue → Agent B polls
 *   Agent → broadcast(event, payload) → SSE subscribers (dashboards)
 *   Cross-tenant → routed via tenant_id isolation checks
 */

import { getPool } from "./db.js";
import { broadcast } from "./event-bus.js";
import crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────

/**
 * @typedef {"direct"|"broadcast"|"tenant"|"system"} MessageType
 *
 * direct:    one agent → another agent
 * broadcast: one agent → all agents in same tenant
 * tenant:    wrapper → all agents in a tenant
 * system:    wrapper internal event (config changes, restart, etc.)
 */

/**
 * @typedef {"pending"|"delivered"|"failed"|"expired"} MessageStatus
 */

// ─── Queue Table Schema (run ONCE via migration) ──────

const QUEUE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS message_queue (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(64) UNIQUE NOT NULL,
    type ENUM('direct','broadcast','tenant','system') NOT NULL,
    source_agent VARCHAR(128),
    source_tenant VARCHAR(64) NOT NULL,
    target_agent VARCHAR(128),
    target_tenant VARCHAR(64),
    payload JSON NOT NULL,
    ttl_seconds INT DEFAULT 300,
    priority INT DEFAULT 0,
    status VARCHAR(32) DEFAULT 'pending',
    delivered_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    INDEX idx_status (status),
    INDEX idx_target (target_agent, status),
    INDEX idx_source (source_agent, created_at),
    INDEX idx_tenant (source_tenant, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
`;

let queueTableEnsured = false;

async function ensureQueueTable() {
  if (queueTableEnsured) return;
  const pool = getPool();
  try {
    await pool.execute(QUEUE_TABLE_SQL);
  } catch (err) {
    if (err.code !== "ER_TABLE_EXISTS_ERROR") throw err;
  }
  queueTableEnsured = true;
}

// ─── Message Helpers ──────────────────────────────────

function generateMessageId() {
  return `msg_${Date.now().toString(36)}_${crypto.randomBytes(8).toString("hex")}`;
}

// ─── Public API ───────────────────────────────────────

/**
 * Send a message from one agent to another (direct delivery).
 * Stores in the queue; target agent picks it up via poll or SSE push.
 */
export async function sendMessage({
  type = "direct",
  sourceAgent,
  sourceTenant = "default",
  targetAgent,
  targetTenant,
  payload,
  ttlSeconds = 300,
  priority = 0,
}) {
  await ensureQueueTable();

  // Cross-tenant isolation check
  if (targetTenant && targetTenant !== sourceTenant) {
    throw new Error(
      `Cross-tenant messaging blocked: ${sourceTenant} → ${targetTenant}. ` +
      "Use the wrapper's tenant bridge for cross-tenant messages."
    );
  }

  const pool = getPool();
  const messageId = generateMessageId();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

  await pool.execute(
    `INSERT INTO message_queue
     (message_id, type, source_agent, source_tenant, target_agent, target_tenant, payload, ttl_seconds, priority, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      messageId,
      type,
      sourceAgent || null,
      sourceTenant,
      targetAgent || null,
      targetTenant || sourceTenant,
      JSON.stringify(payload),
      ttlSeconds,
      priority,
      expiresAt,
      now,
    ]
  );

  // Broadcast notification via SSE so live dashboards see it
  broadcast("message", {
    messageId,
    type,
    sourceAgent,
    sourceTenant,
    targetAgent,
    summary: typeof payload === "object" ? payload.action || "message" : String(payload).slice(0, 80),
  });

  return { messageId, queued: true, expiresAt: expiresAt.toISOString() };
}

/**
 * Poll for pending messages targeting a specific agent.
 * Returns delivered messages (marked as delivered on return).
 */
export async function pollMessages(agentId, tenantId, { limit = 20, markDelivered = true } = {}) {
  await ensureQueueTable();

  const pool = getPool();

  const [rows] = await pool.execute(
    `SELECT id, message_id, type, source_agent, source_tenant, target_agent, payload, priority, created_at, expires_at
     FROM message_queue
     WHERE (target_agent = ? OR (type = 'broadcast' AND source_tenant = ?))
       AND status = 'pending'
       AND (expires_at IS NULL OR expires_at > NOW())
     ORDER BY priority DESC, created_at ASC
     LIMIT ?`,
    [agentId, tenantId, limit]
  );

  const messages = rows.map((row) => ({
    messageId: row.message_id,
    type: row.type,
    sourceAgent: row.source_agent,
    sourceTenant: row.source_tenant,
    targetAgent: row.target_agent,
    payload: typeof row.payload === "string" ? JSON.parse(row.payload) : row.payload,
    priority: row.priority,
    createdAt: row.created_at?.toISOString() || null,
    expiresAt: row.expires_at?.toISOString() || null,
  }));

  // Mark delivered
  if (markDelivered && messages.length > 0) {
    const ids = rows.map((r) => r.id);
    const placeholders = ids.map(() => "?").join(",");
    await pool.execute(
      `UPDATE message_queue SET status = 'delivered', delivered_at = NOW() WHERE id IN (${placeholders})`,
      ids
    );
  }

  return messages;
}

/**
 * Acknowledge a specific message as handled.
 */
export async function acknowledgeMessage(messageId, status = "delivered") {
  await ensureQueueTable();

  const pool = getPool();
  await pool.execute(
    `UPDATE message_queue SET status = ?, delivered_at = NOW() WHERE message_id = ?`,
    [status, messageId]
  );

  return { ok: true, messageId, status };
}

/**
 * Broadcast a message to all agents within a tenant, or globally.
 */
export async function broadcastToTenant({
  sourceAgent,
  sourceTenant = "default",
  payload,
  ttlSeconds = 120,
}) {
  return sendMessage({
    type: "broadcast",
    sourceAgent,
    sourceTenant,
    targetTenant: sourceTenant,
    payload,
    ttlSeconds,
  });
}

/**
 * Send a system event to all agents (config reload, restart warning, etc.)
 */
export async function systemBroadcast({
  event,
  payload = {},
  targetTenant = null,
}) {
  const pool = getPool();

  // For system events, store a broadcast message
  return sendMessage({
    type: "system",
    sourceAgent: "wrapper",
    sourceTenant: "*",
    targetTenant,
    payload: { event, ...payload },
    ttlSeconds: 60,
    priority: 100, // high priority
  });
}

/**
 * Get message queue statistics.
 */
export async function getQueueStats(tenantId = null) {
  await ensureQueueTable();

  const pool = getPool();

  let pendingQuery;
  let params = [];

  if (tenantId) {
    pendingQuery = `SELECT COUNT(*) AS count FROM message_queue WHERE status = 'pending' AND source_tenant = ?`;
    params = [tenantId];
  } else {
    pendingQuery = `SELECT COUNT(*) AS count FROM message_queue WHERE status = 'pending'`;
  }

  const [pending] = await pool.execute(pendingQuery, params);

  let expiredQuery;
  if (tenantId) {
    expiredQuery = `SELECT COUNT(*) AS count FROM message_queue WHERE status = 'pending' AND expires_at < NOW() AND source_tenant = ?`;
  } else {
    expiredQuery = `SELECT COUNT(*) AS count FROM message_queue WHERE status = 'pending' AND expires_at < NOW()`;
  }

  const [expired] = await pool.execute(expiredQuery, params);

  return {
    pending: pending[0].count,
    expired: expired[0].count,
  };
}

/**
 * Clean expired messages from the queue.
 */
export async function cleanExpiredMessages() {
  await ensureQueueTable();

  const pool = getPool();
  const [result] = await pool.execute(
    `DELETE FROM message_queue WHERE expires_at < NOW() OR (status != 'pending' AND created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR))`
  );

  return { cleaned: result.affectedRows };
}

/**
 * Wire the message broker routes into an HTTP router (Express-like).
 * Used by wrapper-server.js.
 */
export function createMessageRouter() {
  return {
    sendMessage,
    pollMessages,
    acknowledgeMessage,
    broadcastToTenant,
    systemBroadcast,
    getQueueStats,
    cleanExpiredMessages,
  };
}

export default {
  sendMessage,
  pollMessages,
  acknowledgeMessage,
  broadcastToTenant,
  systemBroadcast,
  getQueueStats,
  cleanExpiredMessages,
  createMessageRouter,
};
