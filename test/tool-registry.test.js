import assert from "node:assert/strict";
import test from "node:test";

import {
  DECISIONS,
  RISK_LEVELS,
  createToolRegistry,
  evaluateToolRequest
} from "../src/tool-registry.js";

test("lists default tools with risk, permission, confirmation, and dry-run metadata", () => {
  const registry = createToolRegistry();
  const shell = registry.getTool("shell");

  assert.equal(shell.id, "shell");
  assert.equal(shell.riskLevel, RISK_LEVELS.HIGH);
  assert.equal(shell.decision, DECISIONS.REVIEW);
  assert.equal(shell.requiresHumanConfirmation, true);
  assert.equal(shell.dryRunRecommended, true);
  assert.deepEqual(shell.permissions, ["process:execute"]);
  assert.ok(registry.listTools().length >= 6);
});

test("allows low-risk tools without human confirmation", () => {
  const result = evaluateToolRequest({ toolId: "read_file" });

  assert.equal(result.ok, true);
  assert.equal(result.decision, DECISIONS.ALLOW);
  assert.equal(result.riskLevel, RISK_LEVELS.LOW);
  assert.equal(result.requiresHumanConfirmation, false);
  assert.equal(result.dryRunRecommended, false);
});

test("routes medium-risk write tools to review until confirmed", () => {
  const needsReview = evaluateToolRequest({ toolId: "write_file" });
  const confirmed = evaluateToolRequest({ toolId: "write_file", confirmed: true });

  assert.equal(needsReview.ok, false);
  assert.equal(needsReview.decision, DECISIONS.REVIEW);
  assert.equal(needsReview.requiresHumanConfirmation, true);
  assert.match(needsReview.reason, /Human confirmation/);

  assert.equal(confirmed.ok, true);
  assert.equal(confirmed.decision, DECISIONS.ALLOW);
  assert.equal(confirmed.humanConfirmationSatisfied, true);
});

test("recommends dry-run and review for high-risk tools before confirmation", () => {
  const result = evaluateToolRequest({ toolId: "shell" });

  assert.equal(result.ok, false);
  assert.equal(result.decision, DECISIONS.REVIEW);
  assert.equal(result.riskLevel, RISK_LEVELS.HIGH);
  assert.equal(result.requiresHumanConfirmation, true);
  assert.equal(result.dryRunRecommended, true);
  assert.equal(result.dryRunSatisfied, false);
});

test("keeps high-risk tools in review until confirmation and dry-run are satisfied", () => {
  const confirmedOnly = evaluateToolRequest({ toolId: "shell", confirmed: true });
  const dryRun = evaluateToolRequest({ toolId: "shell", confirmed: true, dryRun: true });
  const dryRunCompleted = evaluateToolRequest({
    toolId: "shell",
    confirmed: true,
    dryRunCompleted: true
  });

  assert.equal(confirmedOnly.ok, false);
  assert.equal(confirmedOnly.decision, DECISIONS.REVIEW);
  assert.match(confirmedOnly.reason, /Dry-run/);

  assert.equal(dryRun.ok, true);
  assert.equal(dryRun.dryRunRequested, true);
  assert.equal(dryRun.dryRunSatisfied, true);

  assert.equal(dryRunCompleted.ok, true);
  assert.equal(dryRunCompleted.dryRunCompleted, true);
  assert.equal(dryRunCompleted.dryRunSatisfied, true);
});

test("blocks tools outside the caller permission allowlist", () => {
  const denied = evaluateToolRequest({
    toolId: "write_file",
    confirmed: true,
    allowedPermissions: ["filesystem:read"]
  });
  const allowed = evaluateToolRequest({
    toolId: "write_file",
    confirmed: true,
    allowedPermissions: ["filesystem:write"]
  });

  assert.equal(denied.ok, false);
  assert.equal(denied.decision, DECISIONS.BLOCK);
  assert.equal(denied.permissionGateSatisfied, false);
  assert.deepEqual(denied.missingPermissions, ["filesystem:write"]);
  assert.match(denied.reason, /Permission gate denied/);

  assert.equal(allowed.ok, true);
  assert.equal(allowed.permissionGateSatisfied, true);
});

test("blocks explicitly blocked and unknown tools", () => {
  const blocked = evaluateToolRequest({ toolId: "delete_file", confirmed: true });
  const unknown = evaluateToolRequest({ toolId: "wire_money" });

  assert.equal(blocked.ok, false);
  assert.equal(blocked.decision, DECISIONS.BLOCK);
  assert.equal(blocked.requiresHumanConfirmation, true);
  assert.equal(blocked.dryRunRecommended, true);

  assert.equal(unknown.ok, false);
  assert.equal(unknown.decision, DECISIONS.BLOCK);
  assert.equal(unknown.tool, null);
  assert.equal(unknown.riskLevel, RISK_LEVELS.CRITICAL);
});

test("supports custom dependency-free tool registration", () => {
  const registry = createToolRegistry([]);
  const tool = registry.registerTool({
    id: "calendar_read",
    label: "Calendar read",
    riskLevel: RISK_LEVELS.LOW,
    permissions: ["calendar:read"]
  });

  assert.equal(tool.id, "calendar_read");
  assert.deepEqual(registry.getTool("calendar_read").permissions, ["calendar:read"]);
  assert.equal(registry.evaluateRequest({ toolId: "calendar_read" }).decision, DECISIONS.ALLOW);
});

test("rejects invalid risk levels", () => {
  assert.throws(
    () => createToolRegistry([{ id: "mystery", riskLevel: "extreme" }]),
    /Unknown tool risk level/
  );
});

test("rejects malformed tool permissions", () => {
  assert.throws(
    () => createToolRegistry([{ id: "mystery", permissions: ["filesystem"] }]),
    /Invalid tool permission/
  );
});
