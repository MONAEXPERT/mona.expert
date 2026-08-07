// mona.expert — API Auth tests (v0.8.0+)
//
// key-store.js falls back to in-memory Map when MySQL is unavailable,
// so these tests work without a running database server.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

// Dynamic import so key-store can establish its in-memory fallback first.
// (Static imports would be fine too — the fallback is at module load time.)
import {
  generateApiKey,
  revokeApiKey,
  authenticateRequest,
  listApiKeys,
} from "../src/api-auth.js";

describe("api-auth", () => {
  it("generates an API key with raw and key id", async () => {
    const k = await generateApiKey({ tenantId: "test-tenant", label: "my-key" });
    assert.ok(k.raw);
    assert.ok(k.raw.startsWith("mk_"));
    assert.ok(k.keyId);
    assert.ok(k.keyId.startsWith("key_"));
    assert.equal(k.tenantId, "test-tenant");
    assert.equal(k.label, "my-key");
  });

  it("authenticates a valid key (via request-like object)", async () => {
    const k = await generateApiKey({ tenantId: "auth-test", label: "test" });
    const auth = await authenticateRequest({
      headers: { authorization: `Bearer ${k.raw}` },
    });
    assert.equal(auth.authenticated, true);
    assert.equal(auth.tenantId, "auth-test");
  });

  it("rejects missing auth header", async () => {
    const auth = await authenticateRequest({ headers: {} });
    assert.equal(auth.authenticated, false);
  });

  it("rejects invalid auth header format", async () => {
    const auth = await authenticateRequest({
      headers: { authorization: "Basic xyz" },
    });
    assert.equal(auth.authenticated, false);
  });

  it("rejects invalid key", async () => {
    const auth = await authenticateRequest({
      headers: { authorization: "Bearer invalid_key_xxx" },
    });
    assert.equal(auth.authenticated, false);
  });

  it("rejects revoked key", async () => {
    const k = await generateApiKey({ tenantId: "revoke-test", label: "will-revoke" });
    await revokeApiKey(k.raw);
    const auth = await authenticateRequest({
      headers: { authorization: `Bearer ${k.raw}` },
    });
    assert.equal(auth.authenticated, false);
  });

  it("lists keys for a tenant", async () => {
    await generateApiKey({ tenantId: "list-test", label: "key-a" });
    await generateApiKey({ tenantId: "list-test", label: "key-b" });
    const keys = await listApiKeys("list-test");
    assert.ok(keys.length >= 2);
    assert.ok(keys.every((k) => !k.raw)); // raw not exposed in list
  });
});
