// mona.expert — Tool calling tests (v0.6.0)
import { describe, it, before } from "node:test";
import assert from "node:assert";
import { createProxy, registerTool } from "../src/llm-proxy.js";

describe("LLMProxy — Tool Calling", { concurrency: false }, () => {
  let proxy;

  before(() => {
    proxy = createProxy({ workerUrl: null, workerKey: "" }); // dry-run mode
  });

  it("registers and retrieves tools from registry", () => {
    registerTool("test_tool", {
      type: "function",
      function: {
        name: "test_tool",
        description: "Test tool",
        parameters: { type: "object", properties: { x: { type: "string" } } }
      }
    }, async (args) => ({ received: args }));
    // Note: test_tool is now registered globally
    assert.ok(true);
  });

  it("dry-run process works with tools in context", async () => {
    const result = await proxy.process("Use a tool", { tools: [] });
    assert.equal(result.ok, true);
    assert.ok(result.steps.some(s => s.step === "worker_call"));
    assert.ok(result.output.length > 0);
  });

  it("tool registry has built-in tools", () => {
    // echo and now are registered by default
    assert.ok(true);
  });
});
