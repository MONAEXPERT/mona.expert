import { analyzeSafety } from "./safety-engine.js";
import { DECISIONS, evaluateToolRequest, RISK_LEVELS } from "./tool-registry.js";
import { inputGuardrail, outputGuardrail, analyzeInjections } from "./injection-guard.js";
import { broadcast } from "./event-bus.js";

function enumWithIncludes(values) {
  const enumObject = { ...values };
  const allowedValues = Object.freeze(Object.values(values));
  Object.defineProperty(enumObject, "includes", {
    value: (value) => allowedValues.includes(value),
    enumerable: false
  });
  return Object.freeze(enumObject);
}

export const ACTION_DECISIONS = enumWithIncludes({
  ALLOW: "allow",
  REVIEW: "review",
  BLOCK: "block"
});

const RISK_SCORE_FLOOR = Object.freeze({
  [RISK_LEVELS.LOW]: 5,
  [RISK_LEVELS.MEDIUM]: 28,
  [RISK_LEVELS.HIGH]: 45,
  [RISK_LEVELS.CRITICAL]: 80
});

function toolControls(toolPolicy) {
  return toolPolicy.flatMap((item) => {
    const controls = [];
    if (!item.permissionGateSatisfied) {
      controls.push(`Tool ${item.toolId} requires denied permissions: ${item.missingPermissions.join(", ")}.`);
    }
    if (item.requiresHumanConfirmation && !item.humanConfirmationSatisfied) {
      controls.push(`Tool ${item.toolId} requires human confirmation.`);
    }
    if (item.dryRunRecommended && !item.dryRunSatisfied) {
      controls.push(`Tool ${item.toolId} requires dry-run before live execution.`);
    }
    if (item.decision === DECISIONS.BLOCK) {
      controls.push(`Tool ${item.toolId} is blocked by registry policy.`);
    }
    return controls;
  });
}

export function secureAction(request = {}) {
  const {
    input = "",
    mode = "balanced",
    requestedTools = [],
    confirmedTools = [],
    dryRunTools = [],
    dryRunCompletedTools = [],
    allowedPermissions
  } = request;

  const base = analyzeSafety({ input, mode, requestedTools });
  const injectionResult = inputGuardrail(input);
  
  const toolPolicy = requestedTools.map((toolId) => evaluateToolRequest({
    toolId,
    confirmed: confirmedTools.includes(toolId),
    dryRun: dryRunTools.includes(toolId),
    dryRunCompleted: dryRunCompletedTools.includes(toolId),
    allowedPermissions
  }));

  const toolFloor = Math.max(0, ...toolPolicy.map((item) => RISK_SCORE_FLOOR[item.riskLevel] ?? 0));
  const hasBlockedTool = toolPolicy.some((item) => item.decision === DECISIONS.BLOCK);
  const hasReviewTool = toolPolicy.some((item) => item.decision === DECISIONS.REVIEW);

  // Injection guard overrides
  let decision = base.decision;
  if (injectionResult.blocked) decision = ACTION_DECISIONS.BLOCK;
  else if (injectionResult.needsReview && decision !== ACTION_DECISIONS.BLOCK) decision = ACTION_DECISIONS.REVIEW;
  if (hasBlockedTool) decision = ACTION_DECISIONS.BLOCK;
  else if (hasReviewTool && decision !== ACTION_DECISIONS.BLOCK) decision = ACTION_DECISIONS.REVIEW;

  // Broadcast detailed security decision
  broadcast("security-action", {
    decision,
    riskScore: Math.max(base.riskScore, toolFloor),
    injectionScore: injectionResult.analysis?.totalScore || 0,
    patternHits: injectionResult.analysis?.matchCount || 0,
    topHit: injectionResult.analysis?.evidence?.topHit?.patternId || null,
    controls: toolPolicy.filter(t => t.decision === DECISIONS.BLOCK).map(t => t.toolId),
    inputSample: (input || "").slice(0, 120),
    at: new Date().toISOString(),
  });

  // Broadcast per-tool evaluation details
  for (const tp of toolPolicy) {
    broadcast("tool-eval", {
      toolId: tp.toolId,
      decision: tp.decision,
      riskLevel: tp.riskLevel,
      missingPermissions: tp.missingPermissions,
      requiresConfirmation: tp.requiresHumanConfirmation,
      at: new Date().toISOString(),
    });
  }

  return {
    ...base,
    wrapper: "mona.expert",
    decision,
    riskScore: Math.max(base.riskScore, toolFloor),
    controls: [...new Set([...base.controls, ...toolControls(toolPolicy), ...injectionResult.blocked ? ["Blocked by injection guard"] : injectionResult.needsReview ? ["Review by injection guard"] : []])],
    toolPolicy,
    injectionGuard: injectionResult,
    canExecute: decision === ACTION_DECISIONS.ALLOW,
    requiresReview: decision === ACTION_DECISIONS.REVIEW,
    blocked: decision === ACTION_DECISIONS.BLOCK
  };
}

export async function wrapAction(request, action) {
  const result = secureAction(request);
  if (!result.canExecute) {
    return {
      executed: false,
      result: null,
      security: result
    };
  }

  const actionResult = typeof action === "function" ? await action(result) : null;
  const outputCheck = outputGuardrail(actionResult?.output || actionResult?.result || "");
  
  return {
    executed: !outputCheck.blocked,
    result: outputCheck.blocked ? null : actionResult,
    security: result,
    outputGuard: outputCheck,
    provenance: {
      secureActionAt: new Date().toISOString(),
      guardrails: ["injection-guard-v1", "output-guard-v1"],
      riskScore: result.riskScore,
      injectionScore: result.injectionGuard?.analysis?.totalScore || 0,
      outputBlocked: outputCheck.blocked
    }
  };
}

export { analyzeInjections };
