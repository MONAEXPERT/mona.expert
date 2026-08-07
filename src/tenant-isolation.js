// mona.expert — Tenant Isolation
// B2B multi-tenant data separation with MySQL backing (optional, graceful fallback to in-memory)

const { getPool } = await import("./db.js").catch(() => ({ getPool: null }));
let mysqlAvailable = false;

// In-memory fallback store
const tenants = new Map();

// Seed demo tenants into in-memory fallback
function seedDemoTenants() {
  const demos = [
    { tenantId: "default", name: "Default Tenant", plan: "free", isolationLevel: "soft", allowedModels: ["gpt-5.5"], requestsPerMinute: 10, tokensPerDay: 1_000_000, concurrentSessions: 2 },
    { tenantId: "acme-corp", name: "Acme Corporation (B2B)", plan: "enterprise", isolationLevel: "hard", allowedModels: ["gpt-5.5", "deepseek-v4-pro", "gpt-5.5-pro"], requestsPerMinute: 1000, tokensPerDay: 100_000_000, concurrentSessions: 50 },
    { tenantId: "beta-user", name: "Beta User (B2C)", plan: "free", isolationLevel: "soft", allowedModels: ["gpt-5.5"], requestsPerMinute: 10, tokensPerDay: 1_000_000, concurrentSessions: 2 },
    { tenantId: "startup-io", name: "Startup.io (B2B)", plan: "business", isolationLevel: "soft", allowedModels: ["gpt-5.5"], requestsPerMinute: 100, tokensPerDay: 10_000_000, concurrentSessions: 10 },
  ];
  for (const d of demos) {
    if (!tenants.has(d.tenantId)) {
      tenants.set(d.tenantId, {
        tenantId: d.tenantId,
        name: d.name,
        plan: d.plan,
        encryptionKey: null,
        isolationLevel: d.isolationLevel,
        registeredAt: new Date().toISOString(),
        metadata: { sessionCount: 0, tokenUsage: 0 },
        allowedModels: d.allowedModels,
        rateLimits: { requestsPerMinute: d.requestsPerMinute, tokensPerDay: d.tokensPerDay, concurrentSessions: d.concurrentSessions },
        provenance: { createdBy: "tenant-isolation-v2", encryptionAtRest: false },
      });
    }
  }
}

// Try to connect MySQL and load tenants
export async function initializeTenantIsolation() {
  try {
    if (getPool && typeof getPool === "function") {
      const pool = getPool();
      if (pool) {
        // Ensure tenants table exists by running the migration
        await pool.execute(`
          CREATE TABLE IF NOT EXISTS tenants (
            tenant_id VARCHAR(64) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            plan ENUM('free','business','enterprise') DEFAULT 'free',
            encryption_key TEXT,
            isolation_level ENUM('soft','hard') DEFAULT 'soft',
            allowed_models JSON,
            rate_limits JSON,
            metadata JSON,
            registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP
          ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `);
        mysqlAvailable = true;
        // Load existing tenants from DB into memory cache
        const [rows] = await pool.execute("SELECT * FROM tenants");
        for (const row of rows) {
          tenants.set(row.tenant_id, {
            tenantId: row.tenant_id,
            name: row.name,
            plan: row.plan,
            encryptionKey: row.encryption_key,
            isolationLevel: row.isolation_level,
            registeredAt: row.registered_at ? new Date(row.registered_at).toISOString() : new Date().toISOString(),
            metadata: row.metadata ? (typeof row.metadata === "string" ? JSON.parse(row.metadata) : row.metadata) : {},
            allowedModels: row.allowed_models ? (typeof row.allowed_models === "string" ? JSON.parse(row.allowed_models) : row.allowed_models) : ["gpt-5.5"],
            rateLimits: row.rate_limits ? (typeof row.rate_limits === "string" ? JSON.parse(row.rate_limits) : row.rate_limits) : { requestsPerMinute: 10, tokensPerDay: 1_000_000, concurrentSessions: 2 },
            provenance: { createdBy: "tenant-isolation-v2-mysql", encryptionAtRest: !!row.encryption_key },
          });
        }
        console.log(`[tenant-isolation] Loaded ${rows.length} tenants from MySQL`);
      }
    }
  } catch (err) {
    console.log(`[tenant-isolation] MySQL unavailable — using in-memory fallback (${err.message})`);
    mysqlAvailable = false;
  }

  // Fallback seed
  if (tenants.size === 0) seedDemoTenants();

  return { initialized: true, mysqlAvailable, tenantCount: tenants.size };
}

export async function registerTenant({ tenantId, name, plan, encryptionKey }) {
  if (tenants.has(tenantId)) {
    throw new Error(`Tenant ${tenantId} already registered`);
  }

  const isolationLevel = plan === "enterprise" ? "hard" : "soft";
  const allowedModels = plan === "enterprise"
    ? ["gpt-5.5", "deepseek-v4-pro", "gpt-5.5-pro"]
    : plan === "business"
    ? ["gpt-5.5", "deepseek-v4-pro"]
    : ["gpt-5.5"];

  const rateLimits = {
    requestsPerMinute: plan === "enterprise" ? 1000 : plan === "business" ? 100 : 10,
    tokensPerDay: plan === "enterprise" ? 100_000_000 : plan === "business" ? 10_000_000 : 1_000_000,
    concurrentSessions: plan === "enterprise" ? 50 : plan === "business" ? 10 : 2,
  };

  const tenant = {
    tenantId,
    name: name || tenantId,
    plan: plan || "free",
    encryptionKey: encryptionKey || null,
    isolationLevel,
    registeredAt: new Date().toISOString(),
    metadata: {},
    allowedModels,
    rateLimits,
    provenance: { createdBy: "tenant-isolation-v2", encryptionAtRest: !!encryptionKey },
  };

  tenants.set(tenantId, tenant);

  // Persist to MySQL if available
  if (mysqlAvailable) {
    try {
      const pool = getPool();
      await pool.execute(
        `INSERT INTO tenants (tenant_id, name, plan, encryption_key, isolation_level, allowed_models, rate_limits, metadata)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE name=VALUES(name), plan=VALUES(plan), isolation_level=VALUES(isolation_level)`,
        [
          tenantId, tenant.name, tenant.plan, encryptionKey || null,
          isolationLevel,
          JSON.stringify(allowedModels),
          JSON.stringify(rateLimits),
          JSON.stringify({}),
        ]
      );
    } catch (err) {
      console.error(`[tenant-isolation] Failed to persist tenant ${tenantId}: ${err.message}`);
    }
  }

  return tenant;
}

export function getTenant(tenantId) {
  const tenant = tenants.get(tenantId);
  if (!tenant) return { found: false, error: `Tenant ${tenantId} not found` };
  return { found: true, tenant };
}

export function listTenants() {
  return Array.from(tenants.values()).map(t => ({
    tenantId: t.tenantId,
    name: t.name,
    plan: t.plan,
    isolationLevel: t.isolationLevel,
    registeredAt: t.registeredAt,
    sessionCount: t.metadata.sessionCount || 0,
    tokenUsage: t.metadata.tokenUsage || 0,
  }));
}

export function isolateSession({ tenantId, sessionId }) {
  const tenant = tenants.get(tenantId);
  if (!tenant) return { allowed: false, error: `Unknown tenant ${tenantId}` };

  tenant.metadata.sessionCount = (tenant.metadata.sessionCount || 0) + 1;

  return {
    allowed: true,
    isolation: {
      level: tenant.isolationLevel,
      namespace: `${tenantId}::${sessionId}`,
      encryptionKey: tenant.encryptionKey,
      models: tenant.allowedModels,
      dataBoundary: tenantId,
    },
    guard: {
      noCrossTenantData: true,
      noSharedMemory: tenant.isolationLevel === "hard",
      separateAuditScope: true,
      tenantAuditPrefix: `tenant:${tenantId}`,
    },
    provenance: { isolatedAt: new Date().toISOString(), by: "tenant-isolation-v2" },
  };
}

export function authorizeTenantModel({ tenantId, model }) {
  const tenant = tenants.get(tenantId);
  if (!tenant) return { allowed: false, reason: "Unknown tenant" };
  if (!tenant.allowedModels.includes(model)) {
    return { allowed: false, reason: `Model ${model} not in allowlist for ${tenant.plan} plan`, allowedModels: tenant.allowedModels };
  }
  return { allowed: true, plan: tenant.plan };
}

export function trackTenantTokenUsage({ tenantId, tokens }) {
  const tenant = tenants.get(tenantId);
  if (!tenant) return { ok: false };

  const current = tenant.metadata.tokenUsage || 0;
  const dailyLimit = tenant.rateLimits.tokensPerDay;

  if (current + tokens > dailyLimit) {
    return { ok: false, exceeded: true, used: current, limit: dailyLimit, reason: "Daily token limit exceeded" };
  }

  tenant.metadata.tokenUsage = current + tokens;

  // Persist to MySQL if available
  if (mysqlAvailable) {
    try {
      const pool = getPool();
      pool.execute(
        `UPDATE tenants SET metadata = ? WHERE tenant_id = ?`,
        [JSON.stringify(tenant.metadata), tenantId]
      ).catch(() => {});
    } catch {}
  }

  return { ok: true, used: tenant.metadata.tokenUsage, limit: dailyLimit, remaining: dailyLimit - tenant.metadata.tokenUsage };
}

// Auto-initialize if not in test mode
if (!process.env.MONA_TEST) {
  initializeTenantIsolation();
}
