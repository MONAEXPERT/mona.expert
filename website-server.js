/**
 * mona.expert — Website Gateway
 * 
 * Public-facing server on 127.0.0.1:4188
 * Serves static HTML/CSS/JS and proxies all /api/* calls to the
 * mTLS-secured wrapper backend (127.0.0.1:4189) with client certificate auth.
 */

import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL(".", import.meta.url));
const PUBLIC_DIR = join(ROOT, "public");
const CERTS_DIR = join(ROOT, "certs");
const PORT = Number(process.env.MONA_EXPERT_PORT || 4188);
const WRAPPER_URL = process.env.WRAPPER_URL || "https://127.0.0.1:4189";

// ─── Load TLS client cert for mTLS to wrapper ─────────
const clientCert = await readFile(join(CERTS_DIR, "website-cert.pem"));
const clientKey = await readFile(join(CERTS_DIR, "website-key.pem"));
const caCert = await readFile(join(CERTS_DIR, "ca-cert.pem"));

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

// ─── Proxy helper: forward API calls to wrapper ───────
async function proxyToWrapper(req, res) {
  const targetUrl = new URL(req.url, WRAPPER_URL);

  const options = {
    hostname: targetUrl.hostname,
    port: targetUrl.port,
    path: targetUrl.pathname + targetUrl.search,
    method: req.method,
    headers: { ...req.headers },
    cert: clientCert,
    key: clientKey,
    ca: caCert,
    rejectUnauthorized: true,
  };

  // Remove hop-by-hop headers
  delete options.headers["host"];
  delete options.headers["connection"];
  delete options.headers["keep-alive"];
  delete options.headers["transfer-encoding"];

  const proxyReq = httpsRequest(options, (proxyRes) => {
    // Forward status and headers
    const headers = { ...proxyRes.headers };
    // Remove hop-by-hop response headers
    delete headers["connection"];
    delete headers["keep-alive"];
    delete headers["transfer-encoding"];

    res.writeHead(proxyRes.statusCode, headers);

    // Stream the response body
    proxyRes.pipe(res);
  });

  proxyReq.on("error", (err) => {
    console.error(`[gateway] Proxy error → wrapper: ${err.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({
        ok: false,
        error: "wrapper_unreachable",
        detail: err.message,
        hint: "Is the wrapper backend running on " + WRAPPER_URL + "?"
      }));
    }
  });

  // Pipe request body to wrapper
  req.pipe(proxyReq);
}

// ─── Static file serving ──────────────────────────────
async function serveStatic(req, res) {
  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname === "/" ? "/index.html" : url.pathname;

  // Don't serve static for API paths (should be caught earlier, but safety net)
  if (pathname.startsWith("/api/")) {
    res.writeHead(404, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ ok: false, error: "API endpoint not proxied" }));
    return;
  }

  const filePath = resolve(PUBLIC_DIR, `.${pathname}`);

  // Path traversal guard
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  try {
    const body = await readFile(filePath);
    const ext = extname(filePath);
    res.writeHead(200, {
      "content-type": MIME[ext] || "application/octet-stream",
      "cache-control": "no-store"
    });
    res.end(body);
  } catch {
    // SPA fallback: serve index.html for HTML requests
    if (!extname(pathname) || extname(pathname) === ".html") {
      try {
        const indexBody = await readFile(join(PUBLIC_DIR, "index.html"));
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(indexBody);
        return;
      } catch {}
    }
    res.writeHead(404);
    res.end("Not found");
  }
}

// ─── Server ───────────────────────────────────────────
const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");

  // Route all /api/* calls to the wrapper backend via mTLS
  if (url.pathname.startsWith("/api/")) {
    await proxyToWrapper(req, res);
    return;
  }

  // Everything else → static files
  await serveStatic(req, res);
});

// ─── Startup ──────────────────────────────────────────
server.listen(PORT, "127.0.0.1", () => {
  console.log(`🌐 Website gateway → http://127.0.0.1:${PORT}`);
  console.log(`   Static files: ${PUBLIC_DIR}`);
  console.log(`   API proxy → ${WRAPPER_URL} (mTLS)`);
  console.log(`   Client cert: website.mona.expert`);
});

// ─── Graceful shutdown ────────────────────────────────
async function shutdown(signal) {
  console.log(`\n${signal} received — shutting down gateway…`);
  server.close(() => {
    console.log("Website gateway stopped.");
    process.exit(0);
  });
  setTimeout(() => { process.exit(1); }, 5000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
