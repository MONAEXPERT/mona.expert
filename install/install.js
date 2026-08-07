#!/usr/bin/env node

/**
 * mona.expert — Cross-Platform Terminal Installer
 * =================================================
 *
 * A single-file interactive wizard that runs on Windows, macOS, and Linux.
 * It guides you through:
 *   1.   Account creation or login
 *   2.   Wrapper creation (via API)
 *   3.   Local .env configuration
 *   4.   npm dependency installation
 *   5.   Starting the wrapper server
 *
 * Usage:
 *   node install/install.js
 *
 * Requirements:
 *   Node.js >= 18 (checked automatically)
 *
 * ─── Multi-OS notes ──────────────────────────────
 *   Windows:  spawn / child_process work natively.
 *   macOS:    uses open(1) to launch browser for dashboards.
 *   Linux:    uses xdg-open or similar.
 *   Fallback: prints the URL so the user can click it manually.
 */

// ─── Module setup (ESM) ──────────────────────────
import { readFile, writeFile, access, constants } from "node:fs/promises";
import { createInterface } from "node:readline";
import { spawn, execSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve, dirname, basename, join } from "node:path";
import { createHash } from "node:crypto";
import { platform, release, arch, hostname, freemem, totalmem } from "node:os";
import http from "node:http";

const ROOT    = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ENV_FILE = join(ROOT, ".env");

// ─── Styling ────────────────────────────────────
const C = {
  reset: "\x1b[0m",
  bold:  "\x1b[1m",
  dim:   "\x1b[2m",
  red:   "\x1b[31m",
  green: "\x1b[32m",
  yellow:"\x1b[33m",
  blue:  "\x1b[34m",
  cyan:  "\x1b[36m",
  magenta:"\x1b[35m",
};

function bold(s)     { return `${C.bold}${s}${C.reset}`; }
function green(s)    { return `${C.green}${s}${C.reset}`; }
function red(s)      { return `${C.red}${s}${C.reset}`; }
function yellow(s)   { return `${C.yellow}${s}${C.reset}`; }
function cyan(s)     { return `${C.cyan}${s}${C.reset}`; }
function dim(s)      { return `${C.dim}${s}${C.reset}`; }
function ok(s)       { return green(`✔ ${s}`); }
function fail(s)     { return red(`✘ ${s}`); }
function warn(s)     { return yellow(`⚠ ${s}`); }
function info(s)     { return `${C.blue}ℹ${C.reset} ${s}`; }
function hr()        { console.log(dim("───────────────────────────────────────────────")); }

// ─── Terminal input helper ──────────────────────
const rl = createInterface({ input: process.stdin, output: process.stdout });
function ask(prompt) {
  return new Promise((r) => rl.question(prompt + " ", r));
}
async function password(prompt) {
  // Cross-platform masked input (stdin raw mode on Unix, fallback on Windows)
  const isWin = process.platform === "win32";
  if (!isWin) {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    return new Promise((r) => {
      let buf = "";
      const onData = (chunk) => {
        const c = chunk.toString();
        if (c === "\x03") { process.exit(1); }
        if (c === "\x0d" || c === "\x0a") {
          stdin.setRawMode(wasRaw);
          stdin.pause();
          stdin.removeListener("data", onData);
          process.stdout.write("\n");
          r(buf);
          return;
        }
        if (c === "\x7f" || c === "\b") {
          if (buf.length > 0) {
            buf = buf.slice(0, -1);
            process.stdout.write("\b \b");
          }
          return;
        }
        buf += c;
        process.stdout.write("*");
      };
      process.stdout.write(prompt);
      stdin.on("data", onData);
    });
  } else {
    // Windows: standard readline
    return new Promise((r) => rl.question(prompt, r));
  }
}

// ─── API client ─────────────────────────────────
const API_BASE = "https://mona.expert";
async function apiCall(action, body = {}) {
  const url = `${API_BASE}/api.php?action=${action}`;
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const urlObj = new URL(url);
    const opts = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
      rejectUnauthorized: true,
    };
    const req = http.request(opts, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error(`Ungültige API-Antwort: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error("API timeout")); });
    req.write(payload);
    req.end();
  });
}

// ─── Utilities ──────────────────────────────────
function genWrapperId() {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 8);
  return `mx-${ts}-${rand}`;
}

function detectOS() {
  const p = platform();
  if (p === "win32") return "Windows";
  if (p === "darwin") return "macOS";
  if (p === "linux") return "Linux";
  return p;
}

// ─── Banner ─────────────────────────────────────
function showBanner() {
  console.clear();
  console.log(`
  ${C.cyan}╔═══════════════════════════════════════╗${C.reset}
  ${C.cyan}║${C.reset}    ${C.bold}${C.magenta}mona.expert${C.reset} — Secure AI Wrapper  ${C.cyan}║${C.reset}
  ${C.cyan}║${C.reset}       ${dim}Terminal Installer v2.0${C.reset}      ${C.cyan}║${C.reset}
  ${C.cyan}╚═══════════════════════════════════════╝${C.reset}
  `);
  console.log(`  ${info("OS erkannt:")} ${bold(detectOS())} ${dim(`(${platform()} ${arch()})`)}`);
  console.log(`  ${info("Node.js:")}   ${bold(process.version)}`);
  console.log(`  ${info("Ziel:")}      ${dim(ROOT)}`);
  console.log("");
}

// ─── Step: Node.js check ────────────────────────
async function checkNodeVersion() {
  const v = process.version.replace("v", "").split(".").map(Number);
  if (v[0] < 18) {
    console.log(`  ${fail("Node.js ≥ 18 erforderlich (gefunden: " + process.version + ")")}`);
    console.log(`  ${info("Lade Node.js herunter:")} ${cyan("https://nodejs.org")}`);
    process.exit(1);
  }
  console.log(`  ${ok(`Node.js ${process.version}`)}`);
}

// ─── Step: Send Telemetry / Detect ──────────────
async function checkEnvironment() {
  console.log("");
  hr();
  console.log(`  ${bold("System-Prüfung")}`);
  const sysInfo = {
    os: platform(),
    os_release: release(),
    arch: arch(),
    hostname: hostname(),
    node: process.version,
    freemem: freemem(),
    totalmem: totalmem(),
  };
  console.log(`  ${ok("Betriebssystem:")} ${sysInfo.os} ${sysInfo.os_release} (${sysInfo.arch})`);
  console.log(`  ${ok("Rechner:")}       ${sysInfo.hostname}`);
  console.log(`  ${ok("RAM:")}          ${(sysInfo.totalmem / 1e9).toFixed(1)} GB`);
  console.log(`  ${info("Falls du Windows verwendest:")}`);
  console.log(`     ${dim("Stelle sicher, dass Node.js und Git Bash installiert sind.")}`);
  console.log(`     ${dim("Alternativ: Terminal als Administrator ausführen.")}`);
  return sysInfo;
}

// ─── Step: Account Setup ────────────────────────
async function accountSetup() {
  console.log("");
  hr();
  console.log(`  ${bold("🔑 Konto — Anmeldung")}`);
  console.log(`  ${dim("Du benötigst ein mona.expert-Konto.")}`);
  console.log(`  ${dim("Hast du bereits eines? Dann logge dich ein.")}`);
  console.log("");

  const hasAccount = (await ask(`  ${cyan("?")} Bereits registriert? ${dim("(j/N)")}`)).toLowerCase() === "j";

  let token, user;

  if (hasAccount) {
    console.log(`\n  ${bold("→ Anmelden")}`);
    const email    = await ask(`  ${cyan("?")} E-Mail:`);
    const password = await password(`  ${cyan("?")} Passwort:`);

    console.log(`  ${dim("→ Authentifiziere …")}`);
    const res = await apiCall("login", { email, password });
    if (res.status !== "ok") {
      console.log(`\n  ${fail(res.message || "Login fehlgeschlagen.")}`);
      console.log(`  ${info("Bitte erneut versuchen.")}\n`);
      return accountSetup();
    }
    token = res.token;
    user  = res.user || {};
    console.log(`  ${ok("Angemeldet als " + bold(email))}`);
    if (res.display_name) console.log(`  ${ok("Name: " + res.display_name)}`);

  } else {
    console.log(`\n  ${bold("→ Registrieren")}`);
    console.log(`  ${dim("Erstelle ein neues Konto. Es dauert nur einen Moment.")}\n`);
    const email    = await ask(`  ${cyan("?")} E-Mail:`);
    const name     = await ask(`  ${cyan("?")} Anzeigename ${dim("(optional)")}:`);
    const password = await password(`  ${cyan("?")} Passwort ${dim("(min. 6 Zeichen)")}:`);

    if (password.length < 6) {
      console.log(`\n  ${fail("Passwort zu kurz (min. 6 Zeichen).")}`);
      return accountSetup();
    }

    console.log(`  ${dim("→ Registriere …")}`);
    const res = await apiCall("register", { email, password, name });
    if (res.status !== "ok") {
      console.log(`\n  ${fail(res.message || "Registrierung fehlgeschlagen.")}`);
      if (res.message && res.message.includes("bereits registriert")) {
        console.log(`  ${info("Hast du schon ein Konto? Wähle 'j' bei der nächsten Frage.")}\n`);
        return accountSetup();
      }
      console.log(`  ${info("Bitte erneut versuchen.")}\n`);
      return accountSetup();
    }
    token = res.token;
    user  = res.user || {};
    console.log(`  ${ok("Konto erstellt! Willkommen, " + bold(user.display_name || email) + " 🎉")}`);
  }

  return { token, user, email: user.email };
}

// ─── Step: Wrapper erstellen ────────────────────
async function createWrapper(token) {
  console.log("");
  hr();
  console.log(`  ${bold("🤖 Wrapper — Erstellen & Verbinden")}`);
  console.log(`  ${dim("Ein Wrapper verbindet Deinen Rechner mit dem mona.expert-Dienst.")}`);
  console.log(`  ${dim("Du kannst pro Konto mehrere Wrapper erstellen.")}`);
  console.log("");

  const name = await ask(`  ${cyan("?")} Wrapper-Name ${dim("(z.B. Mein MacBook)")}:`) || hostname();

  console.log(`  ${dim("→ Erstelle Wrapper …")}`);
  const res = await apiCall("create_wrapper", { name }, { "X-Auth-Token": token });
  if (res.status !== "ok") {
    console.log(`\n  ${fail(res.message || "Wrapper-Erstellung fehlgeschlagen.")}`);
    process.exit(1);
  }

  const wrapperId = res.wrapper_id;
  const wrapperKey = res.key;

  console.log(`  ${ok("Wrapper erstellt: " + bold(name))}`);
  console.log(`  ${dim("Wrapper-ID: ")} ${wrapperId}`);
  console.log(`  ${dim("Wrapper-Key: ")} ${wrapperKey}`);
  console.log("");

  return { wrapperId, wrapperKey, name };
}

// ─── Step: Connect Wrapper to API ───────────────
async function connectWrapper(token, wrapperKey, wrapperId, wrapperVersion) {
  console.log(`  ${dim("→ Verbinde Wrapper mit Server …")}`);
  const res = await apiCall("connect_wrapper", {
    token: wrapperKey,
    wrapper_id: wrapperId,
    wrapper_version: wrapperVersion || "2.0.0",
    hostname: hostname(),
  });
  if (res.status !== "ok") {
    console.log(`  ${warn(res.message || "Wrapper-Verbindung fehlgeschlagen (kann später behoben werden).")}`);
  } else {
    console.log(`  ${ok("Wrapper verbunden als " + bold(res.wrapper_name || name))}`);
  }
  return res;
}

// ─── Step: .env konfigurieren ───────────────────
async function configureEnv(token, wrapperKey, wrapperId) {
  console.log("");
  hr();
  console.log(`  ${bold("⚙️  Konfiguration")}`);
  console.log(`  ${dim("Erstelle .env mit Deinen Zugangsdaten.")}`);
  console.log("");

  const envContent = `# mona.expert — Konfiguration
# Automatisch erstellt am ${new Date().toISOString()}

# Server
MONA_EXPERT_PORT=4188
WRAPPER_PORT=4189

# API Verbindung (mona.expert)
MONA_API_URL=https://mona.expert
MONA_API_KEY=${token}

# Wrapper
MONA_WRAPPER_ID=${wrapperId}
MONA_WRAPPER_KEY=${wrapperKey}
MONA_WRAPPER_NAME=${hostname()}

# MySQL (optional — für lokale Datenhaltung)
# DB_HOST=localhost
# DB_USER=
# DB_PASS=
# DB_NAME=mona_expert

# LLM Provider (optional)
# OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
`;

  // Try to merge with existing .env
  let existing = "";
  try {
    existing = await readFile(ENV_FILE, "utf8");
  } catch { /* no existing */ }

  if (existing) {
    console.log(`  ${info(".env existiert bereits — wird zusammengeführt.")}`);
    const existingLines = existing.split("\n");
    const newLines = envContent.split("\n");
    const merged = [...newLines];
    const existingVars = new Set();
    for (const l of existingLines) {
      const eq = l.indexOf("=");
      if (eq > 0 && !l.trim().startsWith("#")) {
        existingVars.add(l.slice(0, eq).trim());
      }
    }
    // Only add new vars that don't already exist
    console.log(`  ${ok(`Bestehende ${existingVars.size} Variablen behalten.`)}`);
    console.log(`  ${ok("Neue API/Wrapper-Variablen hinzugefügt.")}`);

    // Build merged output: keep ALL existing lines, but add missing key ones
    const existingKeys = existingLines.reduce((acc, l) => {
      const eq = l.indexOf("=");
      if (eq > 0) acc[l.slice(0, eq).trim()] = l;
      return acc;
    }, {});

    let mergedLines = [...existingLines];
    // Add MONA_API_KEY if missing
    if (!existingKeys["MONA_API_KEY"]) mergedLines.push(`\nMONA_API_KEY=${token}`);
    if (!existingKeys["MONA_WRAPPER_KEY"]) mergedLines.push(`MONA_WRAPPER_KEY=${wrapperKey}`);
    if (!existingKeys["MONA_WRAPPER_ID"]) mergedLines.push(`MONA_WRAPPER_ID=${wrapperId}`);
    if (!existingKeys["MONA_WRAPPER_NAME"]) mergedLines.push(`MONA_WRAPPER_NAME=${hostname()}`);

    await writeFile(ENV_FILE, mergedLines.join("\n") + "\n", "utf8");
  } else {
    await writeFile(ENV_FILE, envContent, "utf8");
    console.log(`  ${ok(".env wurde erstellt mit Deinen Zugangsdaten.")}`);
  }
}

// ─── Step: npm install ──────────────────────────
async function installDependencies() {
  console.log("");
  hr();
  console.log(`  ${bold("📦 Abhängigkeiten")}`);
  console.log(`  ${dim("Installiere npm-Pakete …")}`);
  console.log("");

  return new Promise((resolve, reject) => {
    const npm = process.platform === "win32" ? "npm.cmd" : "npm";
    const proc = spawn(npm, ["install", "--no-audit", "--no-fund"], {
      cwd: ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let output = "";
    proc.stdout.on("data", (d) => { output += d.toString(); });
    proc.stderr.on("data", (d) => { output += d.toString(); });

    proc.on("close", (code) => {
      if (code === 0) {
        console.log(`  ${ok("Abhängigkeiten installiert.")}`);
        resolve();
      } else {
        console.log(`  ${warn("npm install beendet mit Exit-Code " + code)}`);
        console.log(`  ${info("Du kannst später manuell 'npm install' ausführen.")}`);
        console.log(output.slice(0, 300));
        resolve();
      }
    });
    proc.on("error", (err) => {
      console.log(`  ${warn("npm install fehlgeschlagen: " + err.message)}`);
      console.log(`  ${info("Du kannst später manuell 'npm install' ausführen.")}`);
      resolve();
    });
  });
}

// ─── Step: Start wrapper ────────────────────────
async function startWrapper() {
  console.log("");
  hr();
  console.log(`  ${bold("🚀 Wrapper starten")}`);

  const startNow = (await ask(`\n  ${cyan("?")} Wrapper jetzt starten? ${dim("(j/N)")}`)).toLowerCase() === "j";
  if (!startNow) {
    console.log(`\n  ${info("Wrapper kann später gestartet werden:")}`);
    console.log(`  ${cyan("  node bin/mona-expert.js start")}`);
    console.log(`  ${cyan("  # oder: npm start")}`);
    console.log("");
    return false;
  }

  console.log(`  ${dim("→ Starte mona.expert Server auf Port 4188 …")}`);
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const proc = spawn(npm, ["start"], {
    cwd: ROOT,
    stdio: "inherit",
    detached: false,
    env: { ...process.env },
  });

  // Wait a bit to let it start
  await new Promise((r) => setTimeout(r, 3000));

  console.log(`\n  ${ok("Wrapper läuft! 🎉")}`);
  console.log(`  ${info("Öffne das Dashboard:")}  ${cyan("http://127.0.0.1:4188")}`);
  console.log(`  ${info("Dashboard auf mona.expert:")} ${cyan("https://mona.expert/dashboard.html")}`);

  // Open browser if possible
  openBrowser("http://127.0.0.1:4188");

  // Don't detach — user can Ctrl+C to stop
  return proc;
}

function openBrowser(url) {
  const p = platform();
  try {
    if (p === "darwin") {
      spawn("open", [url], { detached: true, stdio: "ignore" });
    } else if (p === "win32") {
      spawn("cmd", ["/c", "start", url], { detached: true, stdio: "ignore" });
    } else {
      spawn("xdg-open", [url], { detached: true, stdio: "ignore" });
    }
  } catch { /* browser not available */ }
}

// ─── Step: Summary ──────────────────────────────
function showSummary({ email, wrapperName, wrapperId, wrapperKey, token }) {
  console.log("");
  console.log(`  ${C.bold}${C.magenta}╔═══════════════════════════════════════╗${C.reset}`);
  console.log(`  ${C.bold}${C.magenta}║${C.reset}   ✅  Installation abgeschlossen!    ${C.bold}${C.magenta}║${C.reset}`);
  console.log(`  ${C.bold}${C.magenta}╚═══════════════════════════════════════╝${C.reset}`);
  console.log("");
  console.log(`  ${ok("Konto:")}        ${email || "—"}`);
  console.log(`  ${ok("Wrapper:")}      ${wrapperName || "—"}`);
  console.log(`  ${ok("Wrapper-ID:")}   ${dim(wrapperId || "—")}`);
  console.log(`  ${ok("API-Key:")}      ${dim((token || "").slice(0, 16) + "…")}`);
  console.log(`  ${ok("Status:")}       ${green("Verbunden")}`);
  console.log("");
  console.log(`  ${bold("Nächste Schritte:")}`);
  console.log(`  ${dim("→")} Dashboard: ${cyan("http://127.0.0.1:4188")}`);
  console.log(`  ${dim("→")} Web:       ${cyan("https://mona.expert/dashboard.html")}`);
  console.log(`  ${dim("→")} Hilfe:     ${cyan("https://mona.expert/api")}`);
  console.log("");
  console.log(`  ${dim("Viel Erfolg mit Deinem AI-Sicherheits-Wrapper! 🛡️")}`);
  console.log("");
}

// ─── Main ───────────────────────────────────────
async function main() {
  showBanner();

  await checkNodeVersion();
  const sysInfo = await checkEnvironment();

  // Account
  const { token, user } = await accountSetup();

  // Wrapper
  const { wrapperId, wrapperKey, name: wrapperName } = await createWrapper(token);

  // Connect
  await connectWrapper(token, wrapperKey, wrapperId);

  // .env
  await configureEnv(token, wrapperKey, wrapperId);

  // Dependencies
  await installDependencies();

  // Summary
  showSummary({
    email: user?.email || user?.display_name,
    wrapperName,
    wrapperId,
    wrapperKey,
    token,
  });

  // Optional: Start
  const proc = await startWrapper();

  rl.close();

  if (proc) {
    // Keep running
    await new Promise(() => {});
  }
}

main().catch((err) => {
  console.error(`\n${fail("Fehler: " + err.message)}`);
  process.exit(1);
});
