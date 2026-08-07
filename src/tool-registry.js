function enumWithIncludes(values) {
  const enumObject = { ...values };
  const allowedValues = Object.freeze(Object.values(values));
  Object.defineProperty(enumObject, "includes", {
    value: (value) => allowedValues.includes(value),
    enumerable: false
  });
  return Object.freeze(enumObject);
}

export const RISK_LEVELS = enumWithIncludes({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
});

export const DECISIONS = enumWithIncludes({
  ALLOW: "allow",
  REVIEW: "review",
  BLOCK: "block"
});

const RISK_POLICY = Object.freeze({
  [RISK_LEVELS.LOW]: {
    defaultDecision: DECISIONS.ALLOW,
    requiresHumanConfirmation: false,
    dryRunRecommended: false
  },
  [RISK_LEVELS.MEDIUM]: {
    defaultDecision: DECISIONS.REVIEW,
    requiresHumanConfirmation: true,
    dryRunRecommended: false
  },
  [RISK_LEVELS.HIGH]: {
    defaultDecision: DECISIONS.REVIEW,
    requiresHumanConfirmation: true,
    dryRunRecommended: true
  },
  [RISK_LEVELS.CRITICAL]: {
    defaultDecision: DECISIONS.BLOCK,
    requiresHumanConfirmation: true,
    dryRunRecommended: true
  }
});

const TOOL_ID_PATTERN = /^[a-z][a-z0-9_.:-]*$/;
const PERMISSION_PATTERN = /^[a-z][a-z0-9_.:-]*:[a-z][a-z0-9_.:-]*$/;

export const DEFAULT_TOOLS = Object.freeze([
  {
    id: "read_file",
    label: "Read file",
    description: "Read local project files without changing state.",
    riskLevel: RISK_LEVELS.LOW,
    permissions: ["filesystem:read"]
  },
  {
    id: "web_search",
    label: "Web search",
    description: "Fetch public web information.",
    riskLevel: RISK_LEVELS.LOW,
    permissions: ["network:read"]
  },
  {
    id: "write_file",
    label: "Write file",
    description: "Create or update local files.",
    riskLevel: RISK_LEVELS.MEDIUM,
    permissions: ["filesystem:write"]
  },
  {
    id: "shell",
    label: "Shell command",
    description: "Run local shell commands.",
    riskLevel: RISK_LEVELS.HIGH,
    permissions: ["process:execute"]
  },
  {
    id: "send_email",
    label: "Send email",
    description: "Send outbound email as the user.",
    riskLevel: RISK_LEVELS.HIGH,
    permissions: ["external:message"]
  },
  {
    id: "delete_file",
    label: "Delete file",
    description: "Remove local files or folders.",
    riskLevel: RISK_LEVELS.CRITICAL,
    permissions: ["filesystem:delete"],
    decision: DECISIONS.BLOCK
  }
]);

function assertKnownRiskLevel(riskLevel) {
  if (!Object.hasOwn(RISK_POLICY, riskLevel)) {
    throw new TypeError(`Unknown tool risk level: ${riskLevel}`);
  }
}

function cloneTool(tool) {
  return {
    ...tool,
    permissions: [...tool.permissions]
  };
}

function normalizePermissions(permissions) {
  if (permissions == null) return [];
  if (!Array.isArray(permissions)) {
    throw new TypeError("Tool permissions must be an array.");
  }

  return [...new Set(permissions.map((permission) => {
    const normalized = String(permission || "").trim();
    if (!PERMISSION_PATTERN.test(normalized)) {
      throw new TypeError(`Invalid tool permission: ${permission}`);
    }
    return normalized;
  }))];
}

function permissionGate(tool, allowedPermissions) {
  if (allowedPermissions == null) {
    return {
      ok: true,
      missingPermissions: []
    };
  }

  const allowed = new Set(normalizePermissions(allowedPermissions));
  const missingPermissions = tool.permissions.filter((permission) => !allowed.has(permission));
  return {
    ok: missingPermissions.length === 0,
    missingPermissions
  };
}

function normalizeTool(tool) {
  if (!tool || typeof tool !== "object") {
    throw new TypeError("Tool definition must be an object.");
  }

  const id = String(tool.id || "").trim();
  if (!id) throw new TypeError("Tool definition requires a non-empty id.");
  if (!TOOL_ID_PATTERN.test(id)) {
    throw new TypeError("Tool definition id must use lowercase letters, digits, _, ., :, or -.");
  }

  const riskLevel = tool.riskLevel || RISK_LEVELS.LOW;
  assertKnownRiskLevel(riskLevel);

  const policy = RISK_POLICY[riskLevel];
  const decision = tool.decision || policy.defaultDecision;
  if (!Object.values(DECISIONS).includes(decision)) {
    throw new TypeError(`Unknown tool decision: ${decision}`);
  }

  const permissions = normalizePermissions(tool.permissions);

  return Object.freeze({
    id,
    label: tool.label || id,
    description: tool.description || "",
    riskLevel,
    permissions: Object.freeze(permissions),
    decision,
    requiresHumanConfirmation: tool.requiresHumanConfirmation ?? policy.requiresHumanConfirmation,
    dryRunRecommended: tool.dryRunRecommended ?? policy.dryRunRecommended
  });
}

function reasonFor(tool, { confirmed, dryRunSatisfied, permissionAllowed }) {
  if (!tool) return "Tool is not registered.";
  if (tool.decision === DECISIONS.BLOCK) return "Tool policy blocks this request.";
  if (!permissionAllowed.ok) return `Permission gate denied: ${permissionAllowed.missingPermissions.join(", ")}.`;
  if (tool.requiresHumanConfirmation && !confirmed) return "Human confirmation is required before use.";
  if (tool.dryRunRecommended && !dryRunSatisfied) return "Dry-run is required before live execution.";
  return "Tool request satisfies registry policy.";
}

function decisionFor(tool, { confirmed, dryRunSatisfied, permissionAllowed }) {
  if (!tool || tool.decision === DECISIONS.BLOCK) return DECISIONS.BLOCK;
  if (!permissionAllowed.ok) return DECISIONS.BLOCK;
  if (tool.requiresHumanConfirmation && !confirmed) return DECISIONS.REVIEW;
  if (tool.dryRunRecommended && !dryRunSatisfied) return DECISIONS.REVIEW;
  return DECISIONS.ALLOW;
}

export function createToolRegistry(tools = DEFAULT_TOOLS) {
  const registry = new Map();

  function registerTool(tool) {
    const normalized = normalizeTool(tool);
    if (registry.has(normalized.id)) {
      throw new TypeError(`Duplicate tool id: ${normalized.id}`);
    }
    registry.set(normalized.id, normalized);
    return cloneTool(normalized);
  }

  for (const tool of tools) registerTool(tool);

  return {
    listTools() {
      return [...registry.values()].map(cloneTool);
    },

    getTool(id) {
      const tool = registry.get(String(id || "").trim());
      return tool ? cloneTool(tool) : null;
    },

    registerTool,

    evaluateRequest({
      toolId,
      confirmed = false,
      dryRun = false,
      dryRunCompleted = false,
      allowedPermissions
    } = {}) {
      const id = String(toolId || "").trim();
      const tool = registry.get(id);
      const isConfirmed = confirmed === true;
      const isDryRun = dryRun === true;
      const isDryRunCompleted = dryRunCompleted === true;
      const dryRunSatisfied = isDryRun || isDryRunCompleted || !tool?.dryRunRecommended;
      const permissionAllowed = tool
        ? permissionGate(tool, allowedPermissions)
        : { ok: false, missingPermissions: [] };
      const decision = decisionFor(tool, {
        confirmed: isConfirmed,
        dryRunSatisfied,
        permissionAllowed
      });

      return {
        ok: decision === DECISIONS.ALLOW,
        toolId: id,
        tool: tool ? cloneTool(tool) : null,
        riskLevel: tool?.riskLevel || RISK_LEVELS.CRITICAL,
        decision,
        requiresHumanConfirmation: tool?.requiresHumanConfirmation ?? true,
        humanConfirmationSatisfied: isConfirmed,
        dryRunRecommended: tool?.dryRunRecommended ?? true,
        dryRunRequested: isDryRun,
        dryRunCompleted: isDryRunCompleted,
        dryRunSatisfied,
        permissionGateSatisfied: permissionAllowed.ok,
        missingPermissions: permissionAllowed.missingPermissions,
        reason: reasonFor(tool, {
          confirmed: isConfirmed,
          dryRunSatisfied,
          permissionAllowed
        })
      };
    }
  };
}

export function evaluateToolRequest(request, tools = DEFAULT_TOOLS) {
  return createToolRegistry(tools).evaluateRequest(request);
}
