// mona.expert — Rate Limiter & Cost Controller
// B2C: per-user rate windows, cost budgets
// B2B: per-tenant SLAs, cost allocation, spend caps

const windows = new Map();  // key -> { timestamps[], budget }

const MODEL_RATES = {
  "gpt-4o":           { input: 2.50, cache: 1.25, output: 10.00 },
  "gpt-4o-mini":      { input: 0.15, cache: 0.075, output: 0.60 },
  "gpt-5.5":          { input: 5.00, cache: 0.50, output: 30.00 },
  "gpt-5.5-pro":      { input: 30.00, cache: 0, output: 180.00 },
  "deepseek-v4-pro":  { input: 1.74, cache: 0.145, output: 3.48 },
  "deepseek-v4-flash": { input: 0.14, cache: 0.028, output: 0.28 },
  "deepseek-chat":     { input: 0.28, cache: 0.028, output: 0.42 },
  "deepseek-reasoner": { input: 0.28, cache: 0.028, output: 0.42 }
};

const DEFAULT_BUDGETS = {
  "free":      { dailyUsd: 0.50, monthlyUsd: 5.00, alertAtUsd: 0.40 },
  "business":  { dailyUsd: 10.00, monthlyUsd: 100.00, alertAtUsd: 8.00 },
  "enterprise": { dailyUsd: 100.00, monthlyUsd: 2000.00, alertAtUsd: 80.00 }
};

export function getModelPrice(model) {
  return MODEL_RATES[model] || MODEL_RATES["gpt-5.5"];
}

export function calculateCost({ model, inputTokens, cachedInputTokens, outputTokens }) {
  const rates = getModelPrice(model);
  const inputUsd = (inputTokens || 0) / 1_000_000 * rates.input;
  const cacheUsd = (cachedInputTokens || 0) / 1_000_000 * rates.cache;
  const outputUsd = (outputTokens || 0) / 1_000_000 * rates.output;
  return {
    model,
    inputTokens: inputTokens || 0,
    cachedInputTokens: cachedInputTokens || 0,
    outputTokens: outputTokens || 0,
    inputUsd: +inputUsd.toFixed(8),
    cachedInputUsd: +cacheUsd.toFixed(8),
    outputUsd: +outputUsd.toFixed(8),
    totalUsd: +(inputUsd + cacheUsd + outputUsd).toFixed(8),
    rates
  };
}

export function createRateLimiter({ key, plan = "free", windowMs = 60000, maxRequests }) {
  const budgets = DEFAULT_BUDGETS[plan] || DEFAULT_BUDGETS.free;
  const config = {
    maxRequests: maxRequests || budgets.dailyUsd * 20,  // rough heuristic
    windowMs,
    plan,
    budget: { ...budgets },
    spentToday: 0,
    spentThisMonth: 0,
    resetAt: Date.now() + windowMs
  };
  windows.set(key, config);
  return config;
}

export function checkRateLimit({ key, costUsd = 0 }) {
  const limiter = windows.get(key);
  if (!limiter) {
    return { allowed: true, created: true, reason: "New rate limiter created" };
  }

  const now = Date.now();

  // Daily budget check (pure check — does NOT record cost)
  if (limiter.spentToday + costUsd > limiter.budget.dailyUsd) {
    return {
      allowed: false,
      reason: `Daily budget $${limiter.budget.dailyUsd.toFixed(2)} exceeded`,
      spent: +limiter.spentToday.toFixed(6),
      remaining: 0,
      limit: limiter.budget.dailyUsd,
      plan: limiter.plan,
      alert: true
    };
  }

  // Monthly budget check
  if (limiter.spentThisMonth + costUsd > limiter.budget.monthlyUsd) {
    return {
      allowed: false,
      reason: `Monthly budget $${limiter.budget.monthlyUsd.toFixed(2)} exceeded`,
      spent: +limiter.spentThisMonth.toFixed(6),
      remaining: 0,
      limit: limiter.budget.monthlyUsd,
      plan: limiter.plan,
      alert: true
    };
  }

  return {
    allowed: true,
    spent: +limiter.spentToday.toFixed(6),
    remaining: +(limiter.budget.dailyUsd - limiter.spentToday).toFixed(6),
    limit: limiter.budget.dailyUsd,
    plan: limiter.plan,
    alert: limiter.spentToday >= limiter.budget.alertAtUsd
  };
}

export function recordCost({ key, costUsd, tags = {} }) {
  const limiter = windows.get(key);
  if (!limiter) return null;
  limiter.spentToday += costUsd;
  limiter.spentThisMonth += costUsd;
  return {
    spentToday: +limiter.spentToday.toFixed(6),
    spentThisMonth: +limiter.spentThisMonth.toFixed(6),
    remainingDaily: +(limiter.budget.dailyUsd - limiter.spentToday).toFixed(6),
    remainingMonthly: +(limiter.budget.monthlyUsd - limiter.spentThisMonth).toFixed(6)
  };
}

export function getCostReport(key) {
  const limiter = windows.get(key);
  if (!limiter) return null;
  return {
    key,
    plan: limiter.plan,
    budget: limiter.budget,
    spentToday: +limiter.spentToday.toFixed(6),
    spentThisMonth: +limiter.spentThisMonth.toFixed(6),
    remainingDaily: +(limiter.budget.dailyUsd - limiter.spentToday).toFixed(6),
    remainingMonthly: +(limiter.budget.monthlyUsd - limiter.spentThisMonth).toFixed(6),
    usagePct: +(limiter.spentToday / limiter.budget.dailyUsd * 100).toFixed(1)
  };
}

export function getAllCostReports() {
  return Array.from(windows.entries()).map(([key, limiter]) => ({
    key,
    plan: limiter.plan,
    spentToday: +limiter.spentToday.toFixed(6),
    spentThisMonth: +limiter.spentThisMonth.toFixed(6),
    budget: limiter.budget
  }));
}

// Seed demo
if (!process.env.MONA_TEST) {
  createRateLimiter({ key: "acme-corp", plan: "enterprise" });
  createRateLimiter({ key: "beta-user", plan: "free" });
  createRateLimiter({ key: "startup-io", plan: "business" });
}
