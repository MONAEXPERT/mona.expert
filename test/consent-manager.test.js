import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { recordConsent, revokeConsent, checkConsent, getConsentReport, createAgreement, getAgreements } from "../src/consent-manager.js";

describe("consent-manager", () => {
  it("records consent with scopes", () => {
    const r = recordConsent({ userId: "u1", scopes: ["data_collection", "personalization"] });
    assert.ok(r.id.startsWith("consent-"));
    assert.equal(r.given, true);
    assert.deepEqual(r.scopes, ["data_collection", "personalization"]);
  });

  it("rejects invalid scopes", () => {
    assert.throws(() => recordConsent({ scopes: ["invalid_scope"] }));
  });

  it("checks consent by userId and scope", () => {
    recordConsent({ userId: "u2", scopes: ["audit_logging"] });
    const result = checkConsent({ userId: "u2", scope: "audit_logging" });
    assert.equal(result.allowed, true);
    assert.equal(result.reason, "Consent granted");
  });

  it("returns not allowed for unrecorded scope", () => {
    const result = checkConsent({ userId: "u2", scope: "model_training" });
    assert.equal(result.allowed, false);
    assert.equal(result.reason, "No consent recorded for this scope");
  });

  it("revokes consent", () => {
    const r = recordConsent({ userId: "u3", scopes: ["data_collection"] });
    const revoked = revokeConsent(r.id);
    assert.equal(revoked.given, false);
    assert.ok(revoked.revokedAt);
  });

  it("creates B2B data processing agreement", () => {
    const a = createAgreement({
      tenantId: "biz", companyName: "Biz Inc", contactEmail: "a@b.com",
      dataCategories: ["profiles"], processingPurposes: ["delivery"],
      retentionDays: 180, subProcessors: []
    });
    assert.ok(a.id.startsWith("dpa-"));
    assert.equal(a.status, "active");
    assert.equal(a.retentionDays, 180);
  });

  it("generates consent report", () => {
    const report = getConsentReport({ userId: "u1" });
    assert.ok(report.total >= 1);
    assert.ok(report.byScope.length > 0);
  });
});
