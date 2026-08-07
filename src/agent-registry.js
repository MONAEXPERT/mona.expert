/**
 * agent-registry.js — Agent registry management
 *
 * Manages the catalog of known agents, their installation state,
 * and persists state to a JSON file.
 */

import { mkdir, readFile, writeFile, access } from "node:fs/promises";
import { constants } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { BUILTIN_AGENTS, INSTALL_STATUS, INSTALL_STATUS as STATUS, createAgentRecord } from "./agent-manifest.js";

const ROOT = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(ROOT, "..", ".mona-agents");
const STATE_FILE = join(DATA_DIR, "registry.json");
const AGENTS_DIR = join(DATA_DIR, "installed");

// In-memory registry
let _registry = null;
let _dirty = false;

/**
 * Ensure the data directory exists.
 */
async function ensureDataDir() {
  try {
    await access(DATA_DIR, constants.F_OK);
  } catch {
    await mkdir(DATA_DIR, { recursive: true });
  }
  try {
    await access(AGENTS_DIR, constants.F_OK);
  } catch {
    await mkdir(AGENTS_DIR, { recursive: true });
  }
}

/**
 * Load registry state from disk.
 */
async function loadRegistry() {
  if (_registry) return _registry;

  await ensureDataDir();

  try {
    const raw = await readFile(STATE_FILE, "utf8");
    _registry = JSON.parse(raw);
    _dirty = false;
  } catch {
    // First run — initialize with built-in agents
    _registry = {
      version: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      agents: BUILTIN_AGENTS.map((manifest) => createAgentRecord(manifest)),
      customAgents: [],
    };
    _dirty = true;
    await saveRegistry();
  }

  return _registry;
}

/**
 * Save registry state to disk if dirty.
 */
async function saveRegistry() {
  if (!_dirty) return;
  await ensureDataDir();
  _registry.updatedAt = new Date().toISOString();
  await writeFile(STATE_FILE, JSON.stringify(_registry, null, 2), "utf8");
  _dirty = false;
}

/**
 * Persist immediately (force save even if not dirty).
 */
async function flushRegistry() {
  _dirty = true;
  await saveRegistry();
}

/**
 * List all agents in the registry.
 */
export async function listAgents() {
  const reg = await loadRegistry();
  return [...reg.agents, ...reg.customAgents];
}

/**
 * Get a single agent by ID.
 */
export async function getAgent(agentId) {
  const agents = await listAgents();
  return agents.find((a) => a.id === agentId) || null;
}

/**
 * Get the installation path for an agent.
 */
export function getAgentInstallPath(agentId) {
  return join(AGENTS_DIR, agentId);
}

/**
 * Install an agent: set its status to installed, record the path and time.
 */
export async function installAgent(agentId, installPath) {
  const reg = await loadRegistry();

  const agent = reg.agents.find((a) => a.id === agentId)
    || reg.customAgents.find((a) => a.id === agentId);

  if (!agent) {
    throw new Error(`Agent '${agentId}' not found in registry`);
  }

  agent.installed = true;
  agent.installPath = installPath || getAgentInstallPath(agentId);
  agent.installedAt = new Date().toISOString();
  agent.status = INSTALL_STATUS.INSTALLED;

  _dirty = true;
  await saveRegistry();

  return agent;
}

/**
 * Uninstall an agent.
 */
export async function uninstallAgent(agentId) {
  const reg = await loadRegistry();

  const agent = reg.agents.find((a) => a.id === agentId)
    || reg.customAgents.find((a) => a.id === agentId);

  if (!agent) {
    throw new Error(`Agent '${agentId}' not found in registry`);
  }

  agent.installed = false;
  agent.installPath = null;
  agent.installedAt = null;
  agent.lastRunAt = null;
  agent.status = INSTALL_STATUS.NOT_INSTALLED;

  _dirty = true;
  await saveRegistry();

  return agent;
}

/**
 * Update an agent's runtime status.
 */
export async function setAgentStatus(agentId, status) {
  const reg = await loadRegistry();

  const agent = reg.agents.find((a) => a.id === agentId)
    || reg.customAgents.find((a) => a.id === agentId);

  if (!agent) {
    throw new Error(`Agent '${agentId}' not found in registry`);
  }

  agent.status = status;
  agent.lastRunAt = status === INSTALL_STATUS.RUNNING ? new Date().toISOString() : agent.lastRunAt;

  _dirty = true;
  await saveRegistry();

  return agent;
}

/**
 * Add a custom agent (user-defined) to the registry.
 */
export async function addCustomAgent(manifest) {
  const reg = await loadRegistry();

  // Check for duplicate IDs
  const all = [...reg.agents, ...reg.customAgents];
  if (all.some((a) => a.id === manifest.id)) {
    throw new Error(`Agent with id '${manifest.id}' already exists`);
  }

  const record = createAgentRecord(manifest);
  reg.customAgents.push(record);

  _dirty = true;
  await saveRegistry();

  return record;
}

/**
 * Remove a custom agent from the registry.
 */
export async function removeCustomAgent(agentId) {
  const reg = await loadRegistry();
  const idx = reg.customAgents.findIndex((a) => a.id === agentId);
  if (idx === -1) {
    throw new Error(`Custom agent '${agentId}' not found`);
  }
  const [removed] = reg.customAgents.splice(idx, 1);
  _dirty = true;
  await saveRegistry();
  return removed;
}

/**
 * Get installation state summary (counts).
 */
export async function getRegistrySummary() {
  const reg = await loadRegistry();
  const agents = [...reg.agents, ...reg.customAgents];
  return {
    total: agents.length,
    builtin: reg.agents.length,
    custom: reg.customAgents.length,
    installed: agents.filter((a) => a.installed).length,
    running: agents.filter((a) => a.status === STATUS.RUNNING).length,
  };
}

/**
 * Flush any pending changes to disk.
 * Call this before process exit.
 */
export async function shutdownRegistry() {
  await flushRegistry();
}
