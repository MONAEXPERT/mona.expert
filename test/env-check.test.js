import assert from "node:assert/strict";
import test from "node:test";
import { checkEnv } from "../src/env-check.js";

test("reports missing OPENAI_API_KEY as error", () => {
  // Save original
  const orig = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;

  try {
    const result = checkEnv();
    assert.equal(result.ok, false);
    assert.ok(result.errors.length > 0);
    assert.ok(result.errors.some((e) => e.includes("OPENAI_API_KEY")));
  } finally {
    process.env.OPENAI_API_KEY = orig;
  }
});

test("reports warnings for optional but recommended settings", () => {
  // Save originals
  const origWorker = process.env.MONA_WORKER_MODEL;
  const origGuardian = process.env.MONA_GUARDIAN_MODEL;
  delete process.env.MONA_WORKER_MODEL;
  delete process.env.MONA_GUARDIAN_MODEL;

  try {
    const result = checkEnv();
    assert.ok(result.warnings.length > 0);
    assert.ok(
      result.warnings.some((w) => w.includes("MONA_WORKER_MODEL"))
    );
    assert.ok(
      result.warnings.some((w) => w.includes("MONA_GUARDIAN_MODEL"))
    );
  } finally {
    process.env.MONA_WORKER_MODEL = origWorker;
    process.env.MONA_GUARDIAN_MODEL = origGuardian;
  }
});

test("warns on malformed model names", () => {
  const orig = process.env.MONA_WORKER_MODEL;
  process.env.MONA_WORKER_MODEL = "gpt4";
  try {
    const result = checkEnv();
    assert.ok(
      result.warnings.some((w) => w.includes("expected provider/model format"))
    );
  } finally {
    process.env.MONA_WORKER_MODEL = orig;
  }
});

test("rejects negative MONA_DAILY_BUDGET", () => {
  const orig = process.env.MONA_DAILY_BUDGET;
  process.env.MONA_DAILY_BUDGET = "-5";
  try {
    const result = checkEnv();
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((e) => e.includes("MONA_DAILY_BUDGET")));
  } finally {
    process.env.MONA_DAILY_BUDGET = orig;
  }
});

test("passes with valid configuration", () => {
  const origKey = process.env.OPENAI_API_KEY;
  const origWorker = process.env.MONA_WORKER_MODEL;
  const origBudet = process.env.MONA_DAILY_BUDGET;

  process.env.OPENAI_API_KEY = "sk-test123";
  process.env.MONA_WORKER_MODEL = "openai/gpt-4o";
  process.env.MONA_DAILY_BUDGET = "1";

  try {
    const result = checkEnv();
    // OPENAI_API_KEY is set → no required errors
    assert.equal(result.ok, true);
  } finally {
    process.env.OPENAI_API_KEY = origKey;
    process.env.MONA_WORKER_MODEL = origWorker;
    process.env.MONA_DAILY_BUDGET = origBudet;
  }
});
