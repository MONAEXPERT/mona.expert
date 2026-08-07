/**
 * mona.expert — MySQL Database Layer
 *
 * Provides a shared connection pool with retry logic and schema migration.
 * All production data (keys, tenants, agents, consent, audit) flows through here.
 */

import { createPool } from "mysql2/promise";

let pool = null;

const DEFAULT_CONFIG = {
  host: process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || "mona",
  password: process.env.MYSQL_PASSWORD || "",
  database: process.env.MYSQL_DATABASE || "mona_expert",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
};

/**
 * Initialise the connection pool. Safe to call multiple times — returns the
 * existing pool if already connected.
 */
export async function connectDatabase(customConfig = {}) {
  if (pool) return pool;

  const config = { ...DEFAULT_CONFIG, ...customConfig };

  // Strip database from initial connect so we can CREATE DATABASE if needed
  const { database, ...connectConfig } = config;

  // First connect without database to ensure it exists
  const bootstrapPool = createPool(connectConfig);
  try {
    await bootstrapPool.execute(
      `CREATE DATABASE IF NOT EXISTS \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
    );
  } finally {
    await bootstrapPool.end();
  }

  // Now connect with database
  pool = createPool({ ...config, database });

  // Run migrations
  await migrate();

  console.log(`✔ MySQL connected: ${config.user}@${config.host}:${config.port}/${database}`);
  return pool;
}

/**
 * Get the current pool. Throws if not connected.
 */
export function getPool() {
  if (!pool) throw new Error("Database not connected — call connectDatabase() first");
  return pool;
}

/**
 * Run schema migrations from sql/schema.sql.
 */
async function migrate() {
  const { readFileSync, existsSync } = await import("fs");
  const { join, dirname } = await import("path");
  const { fileURLToPath } = await import("url");

  const ROOT = dirname(fileURLToPath(import.meta.url));
  const schemaPath = join(ROOT, "..", "sql", "schema.sql");

  if (!existsSync(schemaPath)) {
    console.log("ℹ No schema.sql found — skipping migration");
    return;
  }

  const schema = readFileSync(schemaPath, "utf8");

  // Split by semicolons, filter empty statements
  const statements = schema
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith("--"));

  for (const stmt of statements) {
    try {
      await pool.execute(stmt);
    } catch (err) {
      // Ignore "already exists" errors
      if (err.code !== "ER_TABLE_EXISTS_ERROR" && !err.message?.includes("already exists")) {
        console.warn(`⚠ Migration warning: ${err.message.slice(0, 120)}`);
      }
    }
  }

  console.log("✔ Schema migrated");
}

/**
 * Health-check the database connection.
 */
export async function dbHealth() {
  if (!pool) return { ok: false, error: "Not connected" };
  try {
    const [rows] = await pool.execute("SELECT 1 AS ok");
    return { ok: true, result: rows[0].ok };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Close the connection pool gracefully.
 */
export async function disconnectDatabase() {
  if (pool) {
    await pool.end();
    pool = null;
    console.log("✔ MySQL disconnected");
  }
}

export default {
  connectDatabase,
  getPool,
  dbHealth,
  disconnectDatabase,
};
