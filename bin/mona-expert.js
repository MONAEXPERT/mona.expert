#!/usr/bin/env node
/**
 * mona-expert — CLI
 * Secure AI Agent Wrapper
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { spawn, spawnSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const ENV_FILE = resolve(ROOT, '.env');
const PID_FILE = resolve(ROOT, '.mona-expert.pid');

function loadEnv() {
  if (!existsSync(ENV_FILE)) return {};
  const env = {};
  const lines = readFileSync(ENV_FILE, 'utf-8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    env[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return env;
}

function saveEnv(updates) {
  let existing = '';
  if (existsSync(ENV_FILE)) existing = readFileSync(ENV_FILE, 'utf-8');
  for (const [k, v] of Object.entries(updates)) {
    const re = new RegExp(`^${k}=.*$`, 'm');
    if (re.test(existing)) existing = existing.replace(re, `${k}=${v}`);
    else existing += `\n${k}=${v}`;
  }
  writeFileSync(ENV_FILE, existing.trim() + '\n');
  console.log(`  ✓ ${ENV_FILE} updated`);
}

function generateToken() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let token = 'mxn_';
  for (let i = 0; i < 40; i++) token += chars[Math.floor(Math.random() * chars.length)];
  return token;
}

function generateWrapperId() {
  const chars = 'abcdef0123456789';
  let id = 'w_';
  for (let i = 0; i < 16; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
}

function log(msg) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  appendFileSync(resolve(ROOT, 'wrapper.log'), `[${ts}] ${msg}\n`);
}

async function cmd(args) {
  const cmd = args[0] || 'help';

  switch (cmd) {
    case 'start': {
      const env = loadEnv();
      const port = parseInt(env.WRAPPER_PORT || args[1] || '4189', 10);
      const serverScript = resolve(ROOT, 'wrapper-server.js');
      if (!existsSync(serverScript)) {
        console.error(`❌ wrapper-server.js not found at ${serverScript}`);
        process.exit(1);
      }
      console.log(`🛡️  mona-expert wrapper starting on :${port}`);
      log(`Wrapper starting on port ${port}`);
      const child = spawn(process.execPath, [serverScript], {
        cwd: ROOT,
        env: { ...process.env, ...env, WRAPPER_PORT: String(port) },
        stdio: 'inherit',
      });
      writeFileSync(PID_FILE, String(child.pid));
      console.log(`  ✓ Wrapper process started (PID ${child.pid})`);
      console.log(`  ✓ Health: http://127.0.0.1:${port}/health`);
      log(`Wrapper started on port ${port} (PID ${child.pid})`);
      const stop = () => { try { child.kill('SIGINT'); } catch {} };
      process.on('SIGINT', stop);
      process.on('SIGTERM', stop);
      child.on('exit', (code) => process.exit(code ?? 0));
      break;
    }

    case 'setup': {
      console.log('\n⚙️  mona-expert setup\n');

      // Create directories
      for (const dir of ['.mona-agents', '.mona-data', 'certs']) {
        if (!existsSync(resolve(ROOT, dir))) {
          mkdirSync(resolve(ROOT, dir), { recursive: true });
          console.log(`  ✓ ${dir}/ created`);
        }
      }

      // Generate .env if missing
      const env = loadEnv();
      const updates = {};
      if (!env.WRAPPER_PORT) updates.WRAPPER_PORT = '4189';
      if (!env.WRAPPER_ID) updates.WRAPPER_ID = generateWrapperId();
      if (!env.WRAPPER_SECRET) updates.WRAPPER_SECRET = generateToken();
      if (!env.SITE_URL) updates.SITE_URL = 'https://mona.expert';
      if (!env.LLM_ENDPOINT) updates.LLM_ENDPOINT = '';
      if (!env.LLM_API_KEY) updates.LLM_API_KEY = '';

      if (Object.keys(updates).length) saveEnv(updates);
      const finalEnv = { ...env, ...updates };
      console.log(`  ✓ Wrapper ID: ${finalEnv.WRAPPER_ID}`);
      console.log(`  ✓ Website: ${finalEnv.SITE_URL || 'not set'}`);

      // Generate mTLS certs if missing (wrapper requires them to start)
      const certKey = resolve(ROOT, 'certs', 'wrapper-key.pem');
      if (!existsSync(certKey)) {
        const genScript = resolve(ROOT, 'bin', 'generate-certs.sh');
        if (existsSync(genScript)) {
          console.log('  → Generating mTLS certificates…');
          const r = spawnSync('bash', [genScript], { cwd: ROOT, stdio: 'ignore' });
          if (r.status === 0 && existsSync(certKey)) {
            console.log('  ✓ Certificates generated');
          } else {
            console.log('  ⚠ Certificate generation failed — run bin/generate-certs.sh manually (needs openssl)');
          }
        }
      } else {
        console.log('  ✓ Certificates present');
      }

      console.log(`  ✓ Setup complete\n`);
      log(`Setup complete — wrapper ${finalEnv.WRAPPER_ID}`);
      break;
    }

    case 'connect': {
      const token = args[1];
      if (!token) {
        console.error('❌ Usage: mona-expert connect <token>');
        console.error('   Get your token from: https://mona.expert/dashboard.html');
        process.exit(1);
      }

      const env = loadEnv();
      if (!env.WRAPPER_ID) {
        console.log('⚙️  Running setup first...');
        await cmd(['setup']);
      }

      const siteUrl = env.SITE_URL;
      console.log(`\n🔗 Connecting wrapper to ${siteUrl}...`);

      try {
        const fetch = (await import('node-fetch')).default;
        const res = await fetch(`${siteUrl}/api.php?action=connect_wrapper`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token,
            wrapper_id: env.WRAPPER_ID,
            wrapper_version: '1.0.0',
            hostname: require('os').hostname()
          })
        });
        const data = await res.json();
        if (data.status === 'ok') {
          saveEnv({ SITE_CONNECTED: 'true', SITE_USER_ID: String(data.user_id) });
          console.log(`  ✓ Connected to account #${data.user_id}`);
          console.log(`  ✓ Wrapper "${data.wrapper_name}" active`);
          console.log(`\n  📋 Dashboard: ${siteUrl}/dashboard.html`);
          log(`Connected to website — user #${data.user_id}, wrapper ${data.wrapper_name}`);
        } else {
          console.error(`❌ Connection failed: ${data.message || 'Unknown error'}`);
          log(`Connection failed: ${data.message}`);
          process.exit(1);
        }
      } catch (err) {
        console.error(`❌ Connection failed: ${err.message}`);
        log(`Connection error: ${err.message}`);
        process.exit(1);
      }
      break;
    }

    case 'status': {
      const env = loadEnv();
      const pid = existsSync(PID_FILE) ? readFileSync(PID_FILE, 'utf-8').trim() : null;
      const running = pid && existsSync(`/proc/${pid}`) ? true : false; // simple check

      console.log('\n🛡️  mona-expert status\n');
      console.log(`  Wrapper ID:  ${env.WRAPPER_ID || 'not set'}`);
      console.log(`  Port:        ${env.WRAPPER_PORT || 'not set'}`);
      console.log(`  Website:     ${env.SITE_URL || 'not set'}`);
      console.log(`  Connected:   ${env.SITE_CONNECTED === 'true' ? '✓ yes' : '✗ no'}`);
      console.log(`  PID:         ${pid || 'not running'}`);
      console.log(`  Agents:      ${existsSync(resolve(ROOT, '.mona-agents')) ? '✓ ready' : 'not initialized'}`);
      break;
    }

    case 'agent': {
      const action = args[1];
      const name = args[2];
      const env = loadEnv();

      if (!action || action === 'list') {
        console.log('\n📦 Installed agents:\n');
        const agentsDir = resolve(ROOT, '.mona-agents');
        if (existsSync(agentsDir)) {
          const files = (await import('fs')).readdirSync(agentsDir);
          if (files.length === 0) console.log('  (none installed)');
          else for (const f of files) console.log(`  • ${f.replace('.json', '')}`);
        } else {
          console.log('  (none installed)');
        }
        break;
      }

      console.log('Usage: mona-expert agent [list]');
      break;
    }

    case 'doctor': {
      console.log('\n🔍 mona-expert diagnostics\n');
      const checks = [
        ['Node.js >=20', !!(process.version.match(/^v(\d+)/) && parseInt(process.version.match(/^v(\d+)/)[1]) >= 20)],
        ['Package deps', existsSync(resolve(ROOT, 'package.json'))],
        ['.env exists', existsSync(ENV_FILE)],
        ['Wrapper ID set', !!loadEnv().WRAPPER_ID],
        ['Website configured', !!loadEnv().SITE_URL],
        ['Data dir ready', existsSync(resolve(ROOT, '.mona-data'))],
      ];
      for (const [label, ok] of checks) {
        console.log(`  ${ok ? '✓' : '✗'} ${label}`);
      }
      break;
    }

    case '-h':
    case '--help':
    case 'help':
    default:
      console.log(`
🛡️  mona-expert — Secure AI Agent Wrapper

USAGE
  mona-expert <command> [options]

COMMANDS
  start [port]        Start wrapper server
  setup               Initialize config and directories
  connect <token>     Connect wrapper to website account
  status              Show wrapper status
  agent list          List installed agents
  doctor              Run diagnostics
  help                Show this help

EXAMPLES
  mona-expert setup          First-time setup
  mona-expert start          Start on default port 4189
  mona-expert connect mxn_..   Link to website
`);
      break;
  }
}

// Minimal require shim for hostname
import { hostname } from 'os';
globalThis.require = (id) => {
  if (id === 'os') return { hostname };
  throw new Error(`require not available for: ${id}`);
};

cmd(process.argv.slice(2));
