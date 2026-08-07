import assert from "node:assert/strict";
import test from "node:test";

import {
  ACTION_DECISIONS,
  DECISIONS,
  EVENT_SCHEMA_VERSION,
  RISK_LEVELS,
  analyzeSafety,
  createEvent,
  createToolRegistry,
  secureAction,
  validateEvent
} from "../src/index.js";

test("package root exports release-critical APIs", () => {
  assert.equal(typeof analyzeSafety, "function");
  assert.equal(typeof secureAction, "function");
  assert.equal(typeof createEvent, "function");
  assert.equal(typeof validateEvent, "function");
  assert.equal(typeof createToolRegistry, "function");
  assert.equal(EVENT_SCHEMA_VERSION, "mona.expert.event.v1");
  assert.ok(DECISIONS.includes("review"));
  assert.ok(RISK_LEVELS.includes("high"));
  assert.ok(ACTION_DECISIONS.includes("block"));
});

test("package root APIs compose for an audited safety decision", () => {
  const decision = secureAction({
    input: "Email ada@example.com after checking local docs.",
    mode: "strict",
    requestedTools: ["read_file"]
  });

  const event = createEvent({
    id: "evt_package_surface_001",
    ts: "2026-07-03T19:00:42.985Z",
    type: "mona.expert.safety_run",
    summary: `Safety run: ${decision.decision}`,
    data: {
      decision: decision.decision,
      inputPreview: decision.sanitizedPrompt
    }
  });

  assert.equal(validateEvent(event).ok, true);
  assert.equal(event.data.inputPreview.includes("ada@example.com"), false);
});
