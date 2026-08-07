import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { getModelPrice, calculateCost, createRateLimiter, checkRateLimit, recordCost, getCostReport, getAllCostReports } from "../src/rate-limiter.js";

describe("rate-limiter", () => {
  it("returns correct model prices", () => {
    const p = getModelPrice("gpt-5.5");
    assert.equal(p.input, 5.00);
    assert.equal(p.cache, 0.50);
    assert.equal(p.output, 30.00);
  });

  it("calculates cost correctly", () => {
    const c = calculateCost({ model: "gpt-5.5", inputTokens: 1000000, outputTokens: 10000 });
    assert.equal(c.inputUsd, 5);
    assert.equal(c.outputUsd, 0.30);
    assert.ok(c.totalUsd > 5);
  });

  it("returns default price for unknown model", () => {
    const p = getModelPrice("unknown-model");
    assert.equal(p.input, 5.00);
  });

  it("creates rate limiter with plan budget", () => {
    const lim = createRateLimiter({ key: "u1", plan: "free" });
    assert.equal(lim.plan, "free");
    assert.equal(lim.budget.dailyUsd, 0.50);
  });

  it("allows requests within budget", () => {
    createRateLimiter({ key: "u2", plan: "enterprise" });
    const r = checkRateLimit({ key: "u2", costUsd: 1.00 });
    assert.equal(r.allowed, true);
  });

  it("blocks requests exceeding daily budget", () => {
    createRateLimiter({ key: "u3-exceed", plan: "free" });
    checkRateLimit({ key: "u3-exceed", costUsd: 0.50 });  // pure check — doesn't record
    recordCost({ key: "u3-exceed", costUsd: 0.50 });      // record actual spend
    const r = checkRateLimit({ key: "u3-exceed", costUsd: 0.01 });
    assert.equal(r.allowed, false);
    assert.ok(r.reason.includes("exceeded"));
  });

  it("records cost with recordCost", () => {
    const r = recordCost({ key: "u2", costUsd: 0.10 });
    assert.ok(r);
    assert.ok(r.spentToday > 0);
  });

  it("generates cost report", () => {
    const r = getCostReport("u2");
    assert.ok(r);
    assert.equal(r.key, "u2");
    assert.ok(r.remainingDaily > 0);
  });
});
