import { randomUUID } from "node:crypto";

export const EVENT_SCHEMA_VERSION = "mona.expert.event.v1";

export const EVENT_TYPES = [
  "mona.expert.agent_added",
  "mona.expert.agent_event",
  "mona.expert.agent_installed",
  "mona.expert.agent_started",
  "mona.expert.agent_stopped",
  "mona.expert.agent_uninstalled",
  "mona.expert.agent_workflow_created",
  "mona.expert.compliance_program_created",
  "mona.expert.error",
  "mona.expert.log_window_opened",
  "mona.expert.policy_decision",
  "mona.expert.project_created",
  "mona.expert.release_plan_created",
  "mona.expert.release_readiness",
  "mona.expert.safety_run",
  "mona.expert.sentinel",
  "mona.expert.server_ready",
  "mona.expert.subagents_started",
  "mona.expert.tool_approval"
];

export const EVENT_SEVERITIES = ["debug", "info", "warn", "error"];

const DEFAULT_SOURCE = "mona.expert";
const DEFAULT_PROJECT = "mona.expert";
const REDACTED = "...redacted";
const SECRET_KEY_PATTERN =
  /access[_-]?token|api[_-]?key|authorization|bearer|client[_-]?secret|cookie|credential|password|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|set-cookie|token/i;
const MAX_SUMMARY_LENGTH = 300;

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function isIsoTimestamp(value) {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function normalizeTimestamp(value) {
  if (value == null || value === "") return new Date().toISOString();
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "number" && Number.isFinite(value)) return new Date(value).toISOString();
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return new Date(parsed).toISOString();
  }
  return value;
}

function compactObject(value) {
  const compacted = {};
  for (const [key, item] of Object.entries(value)) {
    if (item !== undefined) compacted[key] = item;
  }
  return compacted;
}

function compactRedactedObject(value) {
  return compactObject(redactEventData(value));
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim().replace(/\s+/g, " ") : value;
}

export function redactEventData(value) {
  if (value == null) return value;
  if (typeof value === "string") {
    return value
      .replace(/sk-[A-Za-z0-9_-]{12,}/g, `sk-${REDACTED}`)
      .replace(/\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, REDACTED)
      .replace(/(Bearer\s+)[A-Za-z0-9._-]+/gi, `$1${REDACTED}`)
      .replace(/\b(api[_-]?key|authorization|client[_-]?secret|secret|password|token)(\s*[:=]\s*)(\S+)/gi, `$1$2${REDACTED}`)
      .replace(/(https?:\/\/)[^/@\s]+@/gi, `$1[credentials redacted]@`)
      .replace(/\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b/gi, "[email redacted]");
  }
  if (Array.isArray(value)) return value.map((item) => redactEventData(item));
  if (isPlainObject(value)) {
    const redacted = {};
    for (const [key, item] of Object.entries(value)) {
      redacted[key] = SECRET_KEY_PATTERN.test(key) ? "...redacted" : redactEventData(item);
    }
    return redacted;
  }
  return value;
}

export function normalizeEvent(input = {}) {
  if (!isPlainObject(input)) {
    return {
      schemaVersion: EVENT_SCHEMA_VERSION,
      id: `evt_${randomUUID()}`,
      ts: new Date().toISOString(),
      type: "",
      source: DEFAULT_SOURCE,
      project: DEFAULT_PROJECT,
      severity: "info",
      summary: "",
      data: {}
    };
  }

  const rawProvenance = isPlainObject(input.provenance) ? input.provenance : {};
  const provenance = compactRedactedObject({
    ...rawProvenance,
    origin: input.origin ?? input.provenance?.origin,
    producer: input.producer ?? input.provenance?.producer,
    runId: input.runId ?? input.provenance?.runId,
    requestId: input.requestId ?? input.provenance?.requestId,
    parentEventId: input.parentEventId ?? input.provenance?.parentEventId,
    hostname: input.hostname ?? input.provenance?.hostname,
    processId: input.processId ?? input.provenance?.processId,
    receivedAt: normalizeTimestamp(input.receivedAt ?? input.provenance?.receivedAt)
  });
  const evidence = input.evidence === undefined ? undefined : compactRedactedObject(input.evidence);

  return compactObject({
    schemaVersion: input.schemaVersion ?? EVENT_SCHEMA_VERSION,
    id: input.id ?? `evt_${randomUUID()}`,
    ts: normalizeTimestamp(input.ts ?? input.timestamp),
    type: input.type,
    source: input.source ?? DEFAULT_SOURCE,
    project: input.project ?? DEFAULT_PROJECT,
    sessionId: input.sessionId,
    correlationId: input.correlationId,
    runId: input.runId,
    requestId: input.requestId,
    parentEventId: input.parentEventId,
    actor: input.actor ?? input.agent,
    origin: input.origin,
    producer: input.producer,
    severity: input.severity ?? "info",
    decision: input.decision,
    summary: redactEventData(normalizeString(input.summary)),
    evidence: evidence && Object.keys(evidence).length ? evidence : undefined,
    provenance: Object.keys(provenance).length ? provenance : undefined,
    data: redactEventData(input.data ?? {})
  });
}

export function validateEvent(event) {
  const errors = [];

  if (!isPlainObject(event)) {
    return { ok: false, errors: ["event must be an object"] };
  }

  if (event.schemaVersion !== EVENT_SCHEMA_VERSION) {
    errors.push(`schemaVersion must be ${EVENT_SCHEMA_VERSION}`);
  }
  if (typeof event.id !== "string" || !event.id.trim()) {
    errors.push("id must be a non-empty string");
  }
  if (!isIsoTimestamp(event.ts)) {
    errors.push("ts must be an ISO-8601 UTC timestamp");
  }
  if (typeof event.type !== "string" || !EVENT_TYPES.includes(event.type)) {
    errors.push(`type must be one of: ${EVENT_TYPES.join(", ")}`);
  }
  if (typeof event.source !== "string" || !event.source.trim()) {
    errors.push("source must be a non-empty string");
  }
  if (typeof event.project !== "string" || !event.project.trim()) {
    errors.push("project must be a non-empty string");
  }
  if (typeof event.severity !== "string" || !EVENT_SEVERITIES.includes(event.severity)) {
    errors.push(`severity must be one of: ${EVENT_SEVERITIES.join(", ")}`);
  }
  if (typeof event.summary !== "string" || !event.summary.trim()) {
    errors.push("summary must be a non-empty string");
  } else if (event.summary.length > MAX_SUMMARY_LENGTH) {
    errors.push(`summary must be ${MAX_SUMMARY_LENGTH} characters or fewer`);
  }
  if (!isPlainObject(event.data)) {
    errors.push("data must be an object");
  }

  for (const key of [
    "sessionId",
    "correlationId",
    "runId",
    "requestId",
    "parentEventId",
    "actor",
    "origin",
    "producer",
    "decision"
  ]) {
    if (event[key] !== undefined && (typeof event[key] !== "string" || !event[key].trim())) {
      errors.push(`${key} must be a non-empty string when present`);
    }
  }
  for (const key of ["evidence", "provenance"]) {
    if (event[key] !== undefined && !isPlainObject(event[key])) {
      errors.push(`${key} must be an object when present`);
    }
  }
  if (event.provenance?.receivedAt !== undefined && !isIsoTimestamp(event.provenance.receivedAt)) {
    errors.push("provenance.receivedAt must be an ISO-8601 UTC timestamp when present");
  }

  return { ok: errors.length === 0, errors };
}

export function assertValidEvent(event) {
  const result = validateEvent(event);
  if (!result.ok) {
    throw new TypeError(`Invalid ${EVENT_SCHEMA_VERSION}: ${result.errors.join("; ")}`);
  }
  return event;
}

export function createEvent(input = {}) {
  const event = normalizeEvent(input);
  return assertValidEvent(event);
}
