// mona.expert — Live Broadcast Module
// Every action → audit log → dashboard SSE → visible IMMEDIATELY

import { appendAuditEvent, readAuditLog } from "./audit-log.js";
import { writeFileSync, existsSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const ROOT = dirname(fileURLToPath(import.meta.url)) + "/..";
const AUDIT_DIR = join(ROOT, ".mona-dashboard");
const AUDIT_FILE = join(AUDIT_DIR, "events.jsonl");

if (!existsSync(AUDIT_DIR)) mkdirSync(AUDIT_DIR, { recursive: true });

let lastHash = null;

// Load last hash once
try {
  const records = await readAuditLog(AUDIT_FILE);
  const last = [...records].reverse().find(r => r.hash);
  if (last) lastHash = last.hash;
} catch {}

export async function broadcast({ type, summary, data = {}, severity = "info", source = "agent-daemon" }) {
  const record = await appendAuditEvent(AUDIT_FILE, {
    type: "mona.expert.agent_event",
    source,
    project: "mona.expert",
    sessionId: "live-dashboard",
    severity,
    summary,
    data: { ...data, _broadcastAt: new Date().toISOString() }
  }, { previousHash: lastHash });
  
  lastHash = record.hash;
  
  // Also log to stdout for terminal visibility
  const ts = new Date().toISOString().slice(11, 19);
  const icon = severity === "error" ? "❌" : severity === "warn" ? "⚠️" : "✅";
  console.log(`  [${ts}] ${icon} ${source}: ${summary.slice(0, 100)}`);
  
  return record;
}

export async function broadcastBuild({ file, action, summary, details = {} }) {
  return broadcast({
    type: "mona.expert.agent_event",
    source: "builder",
    summary: `${action}: ${file} — ${summary}`,
    severity: action === "delete" ? "warn" : "info",
    data: { file, action, ...details }
  });
}

export async function broadcastTest({ passed, failed, durationMs }) {
  const status = failed === 0 ? "all_pass" : "failures";
  return broadcast({
    source: "tests",
    summary: `${passed}/${passed + failed} passed in ${(durationMs / 1000).toFixed(1)}s`,
    severity: failed === 0 ? "info" : "warn",
    data: { passed, failed, durationMs }
  });
}

export async function broadcastCommit({ message, files, hash }) {
  return broadcast({
    source: "git",
    summary: `Committed: ${message.slice(0, 60)} (${files} files)`,
    severity: "info",
    data: { message, files, hash }
  });
}

export async function broadcastAgent({ agent, status, summary, details = {} }) {
  return broadcast({
    source: "agent-daemon",
    summary: `${agent}: ${summary}`,
    data: { agent, agentStatus: status, ...details }
  });
}
