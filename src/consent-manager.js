// mona.expert — Consent Manager
// B2C: user consent records with scope, revocation, and proof
// B2B: data processing agreements, tenant consent, SLA evidence
// MySQL-backed with in-memory fallback

const { getPool } = await import("./db.js").catch(() => ({ getPool: null }));
let mysqlAvailable = false;

// In-memory stores (fallback)
let consents = [];
let agreements = [];

const CONSENT_SCOPES = Object.freeze([
  "data_collection",
  "personalization",
  "model_training",
  "third_party_sharing",
  "audit_logging",
  "analytics",
]);

// Try to connect MySQL and load existing records
export async function initializeConsentManager() {
  try {
    if (getPool && typeof getPool === "function") {
      const pool = getPool();
      if (pool) {
        // Ensure tables exist
        await pool.execute(`
          CREATE TABLE IF NOT EXISTS consent_records (
            id INT AUTO_INCREMENT PRIMARY KEY,
            consent_id VARCHAR(64) UNIQUE NOT NULL,
            user_id VARCHAR(128),
            tenant_id VARCHAR(64) DEFAULT 'default',
            scopes JSON NOT NULL,
            given BOOLEAN DEFAULT TRUE,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked_at TIMESTAMP NULL,
            ip_address VARCHAR(45),
            user_agent VARCHAR(512),
            provenance JSON,
            INDEX idx_tenant (tenant_id),
            INDEX idx_user (user_id)
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);
        await pool.execute(`
          CREATE TABLE IF NOT EXISTS data_agreements (
            id INT AUTO_INCREMENT PRIMARY KEY,
            agreement_id VARCHAR(64) UNIQUE NOT NULL,
            tenant_id VARCHAR(64) NOT NULL,
            company_name VARCHAR(255) NOT NULL,
            contact_email VARCHAR(255),
            data_categories JSON,
            processing_purposes JSON,
            retention_days INT DEFAULT 90,
            sub_processors JSON,
            status ENUM('active','expired','terminated') DEFAULT 'active',
            signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            version INT DEFAULT 1,
            sla JSON,
            provenance JSON,
            INDEX idx_tenant_agreement (tenant_id)
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);

        mysqlAvailable = true;

        // Load existing consents
        const [consentRows] = await pool.execute("SELECT * FROM consent_records");
        consents = consentRows.map(r => ({
          id: r.consent_id,
          userId: r.user_id,
          tenantId: r.tenant_id,
          scopes: typeof r.scopes === "string" ? JSON.parse(r.scopes) : r.scopes,
          given: !!r.given,
          recordedAt: r.recorded_at ? new Date(r.recorded_at).toISOString() : null,
          ip: r.ip_address,
          userAgent: r.user_agent,
          revokedAt: r.revoked_at ? new Date(r.revoked_at).toISOString() : null,
          provenance: r.provenance ? (typeof r.provenance === "string" ? JSON.parse(r.provenance) : r.provenance) : null,
        }));

        // Load existing agreements
        const [agreementRows] = await pool.execute("SELECT * FROM data_agreements");
        agreements = agreementRows.map(r => ({
          id: r.agreement_id,
          tenantId: r.tenant_id,
          companyName: r.company_name,
          contactEmail: r.contact_email,
          dataCategories: typeof r.data_categories === "string" ? JSON.parse(r.data_categories) : r.data_categories,
          processingPurposes: typeof r.processing_purposes === "string" ? JSON.parse(r.processing_purposes) : r.processing_purposes,
          retentionDays: r.retention_days,
          subProcessors: r.sub_processors ? (typeof r.sub_processors === "string" ? JSON.parse(r.sub_processors) : r.sub_processors) : [],
          status: r.status,
          signedAt: r.signed_at ? new Date(r.signed_at).toISOString() : null,
          version: r.version,
          sla: r.sla ? (typeof r.sla === "string" ? JSON.parse(r.sla) : r.sla) : null,
          provenance: r.provenance ? (typeof r.provenance === "string" ? JSON.parse(r.provenance) : r.provenance) : null,
        }));

        console.log(`[consent-manager] Loaded ${consents.length} consents, ${agreements.length} agreements from MySQL`);
      }
    }
  } catch (err) {
    console.log(`[consent-manager] MySQL unavailable — using in-memory fallback (${err.message})`);
    mysqlAvailable = false;
  }

  return { initialized: true, mysqlAvailable, scopes: CONSENT_SCOPES, consentCount: consents.length, agreementCount: agreements.length };
}

export function recordConsent({ userId, tenantId, scopes, given = true, ip, userAgent }) {
  const invalid = (scopes || []).filter(s => !CONSENT_SCOPES.includes(s));
  if (invalid.length > 0) {
    throw new Error(`Invalid consent scopes: ${invalid.join(", ")}`);
  }

  const record = {
    id: `consent-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    userId: userId || "anonymous",
    tenantId: tenantId || "default",
    scopes: scopes || [],
    given,
    recordedAt: new Date().toISOString(),
    ip: ip || null,
    userAgent: userAgent || null,
    revokedAt: null,
    provenance: { method: given ? "explicit_opt_in" : "explicit_opt_out", source: "consent-manager-v2" },
  };

  consents.push(record);

  // Persist to MySQL
  if (mysqlAvailable) {
    try {
      const pool = getPool();
      pool.execute(
        `INSERT INTO consent_records (consent_id, user_id, tenant_id, scopes, given, recorded_at, ip_address, user_agent, provenance)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          record.id, record.userId, record.tenantId,
          JSON.stringify(record.scopes), given,
          record.recordedAt, ip || null, userAgent || null,
          JSON.stringify(record.provenance),
        ]
      ).catch(err => console.error(`[consent-manager] DB write error: ${err.message}`));
    } catch {}
  }

  return record;
}

export function revokeConsent(consentId) {
  const record = consents.find(c => c.id === consentId);
  if (!record) throw new Error(`Consent ${consentId} not found`);

  record.given = false;
  record.revokedAt = new Date().toISOString();
  record.provenance.revoked = true;

  if (mysqlAvailable) {
    try {
      const pool = getPool();
      pool.execute(
        "UPDATE consent_records SET given = FALSE, revoked_at = ?, provenance = ? WHERE consent_id = ?",
        [record.revokedAt, JSON.stringify(record.provenance), consentId]
      ).catch(() => {});
    } catch {}
  }

  return record;
}

export function checkConsent({ userId, tenantId, scope }) {
  if (!CONSENT_SCOPES.includes(scope)) {
    return { allowed: false, reason: `Unknown scope: ${scope}` };
  }

  const records = consents.filter(c => {
    if (userId && c.userId !== userId) return false;
    if (tenantId && c.tenantId !== tenantId) return false;
    return c.scopes.includes(scope);
  });

  // Most recent non-revoked consent wins
  const active = records
    .filter(c => !c.revokedAt)
    .sort((a, b) => new Date(b.recordedAt) - new Date(a.recordedAt));

  if (active.length === 0) {
    return { allowed: false, reason: "No consent recorded for this scope", evidence: null };
  }

  return {
    allowed: active[0].given,
    reason: active[0].given ? "Consent granted" : "Consent revoked",
    evidence: active[0],
  };
}

// B2B: Data Processing Agreement
export function createAgreement({
  tenantId,
  companyName,
  contactEmail,
  dataCategories,
  processingPurposes,
  retentionDays = 90,
  subProcessors = [],
}) {
  const agreement = {
    id: `dpa-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    tenantId,
    companyName,
    contactEmail,
    dataCategories: dataCategories || [],
    processingPurposes: processingPurposes || [],
    retentionDays,
    subProcessors: subProcessors.map(s => ({
      name: s.name,
      purpose: s.purpose,
      country: s.country,
      dataCategories: s.dataCategories || [],
    })),
    status: "active",
    signedAt: new Date().toISOString(),
    version: 1,
    sla: { uptimePct: 99.9, responseTimeMs: 5000, supportHours: "24/7" },
    provenance: { createdBy: "consent-manager-v2", method: "b2b_dpa" },
  };

  agreements.push(agreement);

  // Persist to MySQL
  if (mysqlAvailable) {
    try {
      const pool = getPool();
      pool.execute(
        `INSERT INTO data_agreements (agreement_id, tenant_id, company_name, contact_email, data_categories, processing_purposes, retention_days, sub_processors, status, signed_at, version, sla, provenance)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          agreement.id, tenantId, companyName, contactEmail,
          JSON.stringify(dataCategories || []), JSON.stringify(processingPurposes || []),
          retentionDays, JSON.stringify(agreement.subProcessors),
          "active", agreement.signedAt, 1,
          JSON.stringify(agreement.sla), JSON.stringify(agreement.provenance),
        ]
      ).catch(err => console.error(`[consent-manager] DB write error: ${err.message}`));
    } catch {}
  }

  return agreement;
}

export function getConsentReport({ tenantId, userId } = {}) {
  let filtered = consents;
  if (tenantId) filtered = filtered.filter(c => c.tenantId === tenantId);
  if (userId) filtered = filtered.filter(c => c.userId === userId);

  const total = filtered.length;
  const active = filtered.filter(c => c.given && !c.revokedAt).length;
  const revoked = filtered.filter(c => c.revokedAt).length;

  return {
    total,
    active,
    revoked,
    byScope: CONSENT_SCOPES.map(scope => ({
      scope,
      count: filtered.filter(c => c.scopes.includes(scope) && c.given && !c.revokedAt).length,
    })),
    records: filtered.slice(-20),
  };
}

export function getAgreements({ tenantId, status } = {}) {
  let filtered = agreements;
  if (tenantId) filtered = filtered.filter(a => a.tenantId === tenantId);
  if (status) filtered = filtered.filter(a => a.status === status);
  return filtered;
}

// Auto-initialize with demo data if not in test mode
if (!process.env.MONA_TEST) {
  const result = await initializeConsentManager();

  // Pre-seed demo data only when MySQL is NOT available (DB already has seed data from schema.sql)
  if (!mysqlAvailable && consents.length === 0) {
    recordConsent({ userId: "demo-user", scopes: ["data_collection", "personalization"] });
    recordConsent({ userId: "demo-user", scopes: ["audit_logging"] });
    createAgreement({
      tenantId: "acme-corp",
      companyName: "Acme Corporation",
      contactEmail: "dpo@acme.com",
      dataCategories: ["user_profiles", "interaction_logs", "billing_data"],
      processingPurposes: ["service_delivery", "fraud_prevention", "compliance_reporting"],
      retentionDays: 365,
      subProcessors: [{ name: "CloudHost Inc", purpose: "Infrastructure", country: "DE", dataCategories: ["all"] }],
    });
  }
}
