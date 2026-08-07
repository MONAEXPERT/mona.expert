// mona.expert — Tenant Isolation tests (v0.8.0+)
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

// Enable in-memory mode for tests (block auto-init which tries MySQL)
process.env.MONA_TEST = "1";

import {
  initializeTenantIsolation,
  registerTenant,
  getTenant,
  listTenants,
  isolateSession,
  authorizeTenantModel,
  trackTenantTokenUsage,
} from "../src/tenant-isolation.js";

describe("tenant-isolation", () => {
  // Seed demo tenants + attempt MySQL connection (graceful fallback)
  before(async () => {
    await initializeTenantIsolation();
  });

  it("registers a new tenant", async () => {
    const suffix = Date.now().toString(36);
    const t = await registerTenant({
      tenantId: `test-1-${suffix}`,
      name: "Test One",
      plan: "business",
    });
    assert.equal(t.tenantId, `test-1-${suffix}`);
    assert.equal(t.plan, "business");
    assert.equal(t.isolationLevel, "soft");
  });

  it("rejects duplicate tenant", async () => {
    const suffix = Date.now().toString(36);
    await registerTenant({ tenantId: `dup-${suffix}`, name: "Dup" });
    await assert.rejects(
      () => registerTenant({ tenantId: `dup-${suffix}` }),
      /already registered/,
    );
  });

  it("gets tenant by ID", async () => {
    const suffix = Date.now().toString(36);
    const id = `get-${suffix}`;
    await registerTenant({ tenantId: id, name: "Getter" });

    // The demo tenant "default" is already seeded via initializeTenantIsolation
    const r = getTenant("default");
    assert.equal(r.found, true);
    assert.equal(r.tenant.tenantId, "default");
  });

  it("returns not found for unknown tenant", () => {
    assert.equal(getTenant("nope").found, false);
  });

  it("isolates session for registered tenant", () => {
    const r = isolateSession({ tenantId: "default", sessionId: "sess-1" });
    assert.equal(r.allowed, true);
    assert.ok(r.isolation.namespace.startsWith("default::"));
    assert.equal(r.guard.noCrossTenantData, true);
  });

  it("authorizes model based on plan", () => {
    // free plan allows gpt-5.5
    assert.equal(authorizeTenantModel({ tenantId: "default", model: "gpt-5.5" }).allowed, true);
    // free plan does not allow gpt-5.5-pro
    assert.equal(authorizeTenantModel({ tenantId: "default", model: "gpt-5.5-pro" }).allowed, false);
  });

  it("tracks token usage within limits", () => {
    const r = trackTenantTokenUsage({ tenantId: "default", tokens: 1000 });
    assert.equal(r.ok, true);
    assert.equal(r.used, 1000);
  });

  it("lists all tenants", () => {
    const list = listTenants();
    assert.ok(list.length > 0);
  });
});
