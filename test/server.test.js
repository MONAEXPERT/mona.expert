import assert from "node:assert/strict";
import test from "node:test";
import { request } from "node:http";
import { spawn } from "node:child_process";

const PORT = 14190;
const BASE = `http://127.0.0.1:${PORT}`;
const ENV = {
  ...process.env,
  MONA_EXPERT_PORT: String(PORT),
  OPENAI_API_KEY: "sk-test-integration",
  MONA_WORKER_MODEL: "openai/gpt-4o",
  MONA_GUARDIAN_MODEL: "openai/gpt-4o-mini",
  MONA_DAILY_BUDGET: "5",
};

function fetchJson(method, path) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, BASE);
    const req = request(
      { method, hostname: u.hostname, port: u.port, path: u.pathname },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          resolve({ status: res.statusCode, headers: res.headers, json: JSON.parse(data) });
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}

function postJson(path, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, BASE);
    const payload = JSON.stringify(body);
    const req = request(
      {
        method: "POST",
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload)
        }
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          resolve({ status: res.statusCode, headers: res.headers, json: JSON.parse(data) });
        });
      }
    );
    req.on("error", reject);
    req.end(payload);
  });
}

function fetchText(method, path) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, BASE);
    const req = request(
      { method, hostname: u.hostname, port: u.port, path: u.pathname },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          resolve({ status: res.statusCode, headers: res.headers, text: data });
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}

function checkSseHeaders(path) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, BASE);
    const req = request(
      { method: "GET", hostname: u.hostname, port: u.port, path: u.pathname },
      (res) => {
        // SSE connections don't end — read headers, then abort
        resolve({ status: res.statusCode, headers: res.headers });
        res.destroy();
      }
    );
    req.on("error", reject);
    req.end();
  });
}

function waitForServer(retries = 30, delayMs = 400) {
  return new Promise((resolve, reject) => {
    let i = 0;
    const check = () => {
      i++;
      const req = request(`http://127.0.0.1:${PORT}/api/health`, (res) => {
        if (res.statusCode === 200) return resolve();
        if (i >= retries) return reject(new Error("timeout waiting for server"));
        res.resume();
        setTimeout(check, delayMs);
      });
      req.on("error", () => {
        if (i >= retries)
          return reject(new Error(`timeout: server not reachable at :${PORT}`));
        setTimeout(check, delayMs);
      });
      req.end();
    };
    check();
  });
}

test("server integration — meta endpoints", { timeout: 40000 }, async (t) => {
  const serverProcess = spawn("node", ["server.js"], {
    cwd: new URL("..", import.meta.url).pathname,
    env: ENV,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let output = "";
  serverProcess.stdout.on("data", (d) => (output += d.toString()));
  serverProcess.stderr.on("data", (d) => (output += d.toString()));

  t.after(() => serverProcess.kill("SIGTERM"));

  await waitForServer();

  // ── /api/health ──
  const health = await fetchJson("GET", "/api/health");
  assert.equal(health.status, 200);
  assert.equal(health.json.ok, true);
  assert.equal(health.json.name, "mona.expert");

  // ── / serves index.html ──
  const root = await fetchText("GET", "/");
  assert.equal(root.status, 200);
  assert.ok(root.text.includes("doctype"));

  // ── /api/security-status ──
  const status = await fetchJson("GET", "/api/security-status");
  assert.equal(status.status, 200);
  assert.ok(status.json.version);
  assert.ok(Array.isArray(status.json.patterns));

  // ── /dashboard.html ──
  const dash = await fetchText("GET", "/dashboard.html");
  assert.equal(dash.status, 200);
  assert.ok(dash.text.includes("mona.expert"));

  // ── /agents.html marketplace ──
  const agentsPage = await fetchText("GET", "/agents.html");
  assert.equal(agentsPage.status, 200);
  assert.ok(agentsPage.text.includes("Agent Marketplace"));

  // ── website wrapper API ──
  const llm = await postJson("/api/llm", {
    input: "Write one safe welcome sentence.",
    maxTokens: 40,
    requestedTools: []
  });
  assert.equal(llm.status, 200);
  assert.equal(typeof llm.json.ok, "boolean");
  assert.equal(typeof llm.json.decision, "string");

  // ── /api/agents ──
  const agents = await fetchJson("GET", "/api/agents");
  assert.equal(agents.status, 200);
  assert.equal(agents.json.ok, true);
  assert.ok(Array.isArray(agents.json.agents));
  assert.ok(agents.json.agents.some((agent) => agent.id === "openclaw"));
  assert.equal(typeof agents.json.summary?.total, "number");

  // ── /api/agents/running ──
  const runningAgents = await fetchJson("GET", "/api/agents/running");
  assert.equal(runningAgents.status, 200);
  assert.equal(runningAgents.json.ok, true);
  assert.ok(Array.isArray(runningAgents.json.running));

  // ── SSE endpoint starts correctly (check headers, don't read body) ──
  const sse = await checkSseHeaders("/api/live");
  assert.equal(sse.status, 200);
  assert.ok(sse.headers["content-type"].includes("text/event-stream"));

  // ── /api/cost with plan param (dashboard compatibility) ──
  const costViaPlan = await fetchJson("GET", "/api/cost?plan=default");
  assert.equal(costViaPlan.status, 200);
  assert.ok(Array.isArray(costViaPlan.json));

  // ── /api/cost with key param (native API) ──
  const costViaKey = await fetchJson("GET", "/api/cost?key=default");
  assert.equal(costViaKey.status, 200);
  assert.ok(Array.isArray(costViaKey.json));

  // ── 404 ──
  const nf = await fetchText("GET", "/api/nonexistent");
  assert.equal(nf.status, 404);

  // ── Startup includes env check ──
  assert.ok(output.includes("checking configuration"), "env check on startup");

  // ── .env loading log (loaded or not-found message) ──
  const envLoaded = output.includes(".env loaded") || output.includes(".env not found");
  assert.ok(envLoaded, ".env auto-load attempt logged");
});
