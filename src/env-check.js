// mona.expert — Configuration validator
// Called at startup to fail fast on misconfigured env.

const REQUIRED = [
  { key: "OPENAI_API_KEY", label: "OpenAI API key (worker/guardian LLM)" },
];

const CONDITIONAL = [
  {
    key: "MONA_AUDIT_KEY",
    label: "Audit encryption key",
    note: "auto-generated if absent — see audit-log.js",
  },
  {
    key: "MONA_WORKER_MODEL",
    label: "Worker LLM model override",
    default: "openai/gpt-4o",
  },
  {
    key: "MONA_GUARDIAN_MODEL",
    label: "Guardian LLM model override",
    default: "openai/gpt-4o-mini",
  },
  {
    key: "MONA_DAILY_BUDGET",
    label: "Daily cost cap (USD)",
    default: "0",
  },
  {
    key: "MONA_ADMIN_KEY",
    label: "Admin API key for management endpoints",
    note: "if unset, key management endpoints are disabled",
  },
];

export function checkEnv() {
  const errors = [];
  const warnings = [];

  for (const { key, label } of REQUIRED) {
    if (!process.env[key]) {
      errors.push(`Missing required env ${key}: ${label}`);
    }
  }

  for (const { key, label, default: def, note } of CONDITIONAL) {
    const val = process.env[key];
    if (!val) {
      if (def !== undefined) {
        warnings.push(`${key} (${label}) not set — will use default: ${def}`);
      } else if (note) {
        warnings.push(`${key} (${label}) not set — ${note}`);
      }
    }
  }

  // Validate model strings if provided
  for (const key of ["MONA_WORKER_MODEL", "MONA_GUARDIAN_MODEL"]) {
    const val = process.env[key];
    if (val && !val.includes("/")) {
      warnings.push(
        `${key} = "${val}" — expected provider/model format (e.g. openai/gpt-4o)`
      );
    }
  }

  // Validate budget if set
  const budget = process.env.MONA_DAILY_BUDGET;
  if (budget && (isNaN(Number(budget)) || Number(budget) < 0)) {
    errors.push(
      `MONA_DAILY_BUDGET = "${budget}" — must be a non-negative number`
    );
  }

  return { ok: errors.length === 0, errors, warnings };
}

export function printEnvStatus() {
  const { ok, errors, warnings } = checkEnv();

  if (ok && warnings.length === 0) {
    console.log("  ✓ All env checks passed");
    return;
  }

  if (warnings.length > 0) {
    for (const w of warnings) {
      console.log(`  ⚠ ${w}`);
    }
  }

  if (errors.length > 0) {
    console.log(`  ✗ ${errors.length} error(s):`);
    for (const e of errors) {
      console.log(`    ${e}`);
    }
  }

  return { ok, errors, warnings };
}
