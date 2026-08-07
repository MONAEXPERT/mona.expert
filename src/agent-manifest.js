/**
 * agent-manifest.js — Agent manifest schema & validation
 *
 * An agent manifest defines what an agent is, what permissions it needs,
 * how to run it, and its safety profile. Mona uses this to guide the
 * user through installation and to enforce containment.
 */

export const MANIFEST_VERSION = "1.0";

/**
 * Runtime type options
 */
export const RUNTIME_TYPES = {
  NODE: "node",
  PYTHON: "python",
  DOCKER: "docker",
  API_ENDPOINT: "api_endpoint",
  BINARY: "binary",
};

/**
 * Safety ratings
 */
export const SAFETY_RATINGS = {
  GREEN: "green",
  AMBER: "amber",
  RED: "red",
  UNKNOWN: "unknown",
};

/**
 * Provider types
 */
export const PROVIDER_TYPES = {
  OPEN_SOURCE: "open_source",
  SAAS: "saas",
  LOCAL: "local",
  COMMERCIAL: "commercial",
};

/**
 * Agent installation states
 */
export const INSTALL_STATUS = {
  NOT_INSTALLED: "not_installed",
  INSTALLING: "installing",
  INSTALLED: "installed",
  RUNNING: "running",
  STOPPED: "stopped",
  ERROR: "error",
};

/**
 * Built-in agents: the agents Mona ships with out of the box.
 * Users can add their own via the registry.
 */
export const BUILTIN_AGENTS = [
  {
    id: "openclaw",
    name: "OpenClaw",
    tagline: "Secure AI agent workspace companion",
    description: "OpenClaw is a secure AI agent wrapper and workspace companion. It helps you build, run, and contain AI agents — with built-in prompt injection resistance, memory, and tool orchestration.",
    version: "1.0.0",
    provider: { name: "OpenClaw", url: "https://openclaw.ai", type: PROVIDER_TYPES.OPEN_SOURCE },
    permissions: {
      files: { read: true, write: false },
      network: { outbound: true },
      shell: false,
      api_keys: [],
    },
    resource_limits: { max_memory_mb: 512, max_cpu_percent: 50, max_storage_mb: 200 },
    runtime: { type: RUNTIME_TYPES.NODE, entry: "openclaw", env: [] },
    safety: { rating: SAFETY_RATINGS.GREEN, injection_resistance: "high", audit_trail: true },
    tags: ["assistant", "workspace", "dev-tool"],
  },
  {
    id: "claude-code",
    name: "Claude Code",
    tagline: "Coding agent by Anthropic",
    description: "Claude Code is an AI coding assistant by Anthropic. It helps write, debug, and refactor code in your terminal. Mona wraps its I/O for injection security and audit tracking.",
    version: "1.0.0",
    provider: { name: "Anthropic", url: "https://anthropic.com", type: PROVIDER_TYPES.SAAS },
    permissions: {
      files: { read: true, write: true },
      network: { outbound: true },
      shell: true,
      api_keys: ["ANTHROPIC_API_KEY"],
    },
    resource_limits: { max_memory_mb: 1024, max_cpu_percent: 80, max_storage_mb: 500 },
    runtime: { type: RUNTIME_TYPES.NODE, entry: "claude", env: ["ANTHROPIC_API_KEY"] },
    safety: { rating: SAFETY_RATINGS.GREEN, injection_resistance: "medium", audit_trail: true },
    tags: ["coding", "dev-tool", "terminal"],
  },
  {
    id: "chatgpt",
    name: "ChatGPT",
    tagline: "OpenAI's general-purpose AI",
    description: "ChatGPT is OpenAI's conversational AI. Mona wraps it with an injection guard, consent layer, and audit trail — keeping your conversations safe and auditable.",
    version: "1.0.0",
    provider: { name: "OpenAI", url: "https://openai.com", type: PROVIDER_TYPES.SAAS },
    permissions: {
      files: { read: false, write: false },
      network: { outbound: true },
      shell: false,
      api_keys: ["OPENAI_API_KEY"],
    },
    resource_limits: { max_memory_mb: 256, max_cpu_percent: 30, max_storage_mb: 50 },
    runtime: { type: RUNTIME_TYPES.API_ENDPOINT, entry: "api.openai.com", env: ["OPENAI_API_KEY"] },
    safety: { rating: SAFETY_RATINGS.GREEN, injection_resistance: "medium", audit_trail: true },
    tags: ["chat", "general", "conversation"],
  },
  {
    id: "shell-agent",
    name: "Shell Agent",
    tagline: "Automated terminal assistant",
    description: "An automated shell assistant that can execute commands, manage files, and run scripts. Mona treats it as a high-permission agent with strict containment.",
    version: "1.0.0",
    provider: { name: "Local", url: "", type: PROVIDER_TYPES.LOCAL },
    permissions: {
      files: { read: true, write: true },
      network: { outbound: false },
      shell: true,
      api_keys: [],
    },
    resource_limits: { max_memory_mb: 256, max_cpu_percent: 50, max_storage_mb: 100 },
    runtime: { type: RUNTIME_TYPES.BINARY, entry: "", env: [] },
    safety: { rating: SAFETY_RATINGS.AMBER, injection_resistance: "low", audit_trail: true },
    tags: ["terminal", "automation", "high-permission"],
  },
  {
    id: "custom",
    name: "Custom Agent",
    tagline: "Define your own agent",
    description: "Bring your own AI agent. Define the runtime, permissions, and resource limits. Mona wraps and contains it regardless of origin.",
    version: "1.0.0",
    provider: { name: "User-defined", url: "", type: PROVIDER_TYPES.LOCAL },
    permissions: {
      files: { read: false, write: false },
      network: { outbound: false },
      shell: false,
      api_keys: [],
    },
    resource_limits: { max_memory_mb: 512, max_cpu_percent: 50, max_storage_mb: 200 },
    runtime: { type: RUNTIME_TYPES.NODE, entry: "", env: [] },
    safety: { rating: SAFETY_RATINGS.UNKNOWN, injection_resistance: "unknown", audit_trail: true },
    tags: ["custom", "bring-your-own"],
  },
  {
    id: "sentinel",
    name: "Sentinel Agent",
    tagline: "Safe-env monitor — zero local keys, all traffic via wrapper.mona.expert",
    description: "Sentinel is the first agent to install on any mona.expert wrapper. It creates its own locked-down safe environment (sandbox, 0700 perms, no secret material on disk), continuously monitors system health, agent liveness, security posture and wrapper reachability, and routes every outbound request through wrapper.mona.expert. MySQL and FTP access are performed exclusively through wrapper gateway endpoints — the agent never holds API keys locally.",
    version: "1.0.0",
    provider: { name: "mona.expert", url: "https://wrapper.mona.expert", type: PROVIDER_TYPES.LOCAL },
    permissions: {
      files: { read: true, write: true },
      network: { outbound: true },
      shell: false,
      api_keys: [],
    },
    resource_limits: { max_memory_mb: 128, max_cpu_percent: 15, max_storage_mb: 25 },
    runtime: { type: RUNTIME_TYPES.NODE, entry: "src/agents/sentinel.js", env: [] },
    safety: { rating: SAFETY_RATINGS.GREEN, injection_resistance: "high", audit_trail: true },
    tags: ["monitoring", "safe-env", "sentinel", "first-install"],
  },
  {
    id: "heartbeat",
    name: "Heartbeat Agent",
    tagline: "System health & agent liveness monitor",
    description: "Continuously monitors system health, agent liveness, and service availability. Broadcasts heartbeat ticks and alerts on anomalies.",
    version: "1.0.0",
    provider: { name: "mona.expert", url: "https://mona.expert", type: PROVIDER_TYPES.LOCAL },
    permissions: {
      files: { read: true, write: false },
      network: { outbound: false },
      shell: false,
      api_keys: [],
    },
    resource_limits: { max_memory_mb: 64, max_cpu_percent: 10, max_storage_mb: 10 },
    runtime: { type: RUNTIME_TYPES.NODE, entry: "src/agents/heartbeat.js", env: [] },
    safety: { rating: SAFETY_RATINGS.GREEN, injection_resistance: "high", audit_trail: true },
    tags: ["monitoring", "system", "heartbeat"],
  },
  {
    id: "boss",
    name: "Boss Agent",
    tagline: "Supervisory coordination & oversight",
    description: "Supervisory coordination agent that monitors all other agents, cross-references audit logs, and escalates anomalies to human operators.",
    version: "1.0.0",
    provider: { name: "mona.expert", url: "https://mona.expert", type: PROVIDER_TYPES.LOCAL },
    permissions: {
      files: { read: true, write: false },
      network: { outbound: false },
      shell: false,
      api_keys: [],
    },
    resource_limits: { max_memory_mb: 128, max_cpu_percent: 15, max_storage_mb: 50 },
    runtime: { type: RUNTIME_TYPES.NODE, entry: "src/agents/boss.js", env: [] },
    safety: { rating: SAFETY_RATINGS.GREEN, injection_resistance: "high", audit_trail: true },
    tags: ["supervisor", "oversight", "coordination"],
  },
];

/**
 * Validate that an object is a well-formed agent manifest.
 * Returns { valid: true } or { valid: false, errors: [...] }.
 */
export function validateManifest(manifest) {
  const errors = [];

  if (!manifest || typeof manifest !== "object") {
    return { valid: false, errors: ["Manifest must be an object"] };
  }

  if (!manifest.id || typeof manifest.id !== "string") {
    errors.push("Missing or invalid 'id' (string)");
  }

  if (!manifest.name || typeof manifest.name !== "string") {
    errors.push("Missing or invalid 'name' (string)");
  }

  if (!manifest.runtime || typeof manifest.runtime !== "object") {
    errors.push("Missing or invalid 'runtime' (object)");
  } else {
    if (!Object.values(RUNTIME_TYPES).includes(manifest.runtime.type)) {
      errors.push(`Invalid runtime type '${manifest.runtime.type}'. Expected: ${Object.values(RUNTIME_TYPES).join(", ")}`);
    }
  }

  if (!manifest.permissions || typeof manifest.permissions !== "object") {
    errors.push("Missing or invalid 'permissions' (object)");
  }

  if (!manifest.safety || typeof manifest.safety !== "object") {
    errors.push("Missing or invalid 'safety' (object)");
  }

  return {
    valid: errors.length === 0,
    errors: errors.length > 0 ? errors : undefined,
  };
}

/**
 * Create a full agent record from a manifest, merging in registry state defaults.
 */
export function createAgentRecord(manifest) {
  const validation = validateManifest(manifest);
  if (!validation.valid) {
    throw new Error(`Invalid manifest: ${validation.errors.join("; ")}`);
  }

  return {
    ...manifest,
    installed: false,
    installPath: null,
    status: INSTALL_STATUS.NOT_INSTALLED,
    installedAt: null,
    lastRunAt: null,
    manifestVersion: MANIFEST_VERSION,
    createdAt: new Date().toISOString(),
  };
}
