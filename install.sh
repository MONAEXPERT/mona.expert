#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────
# mona.expert — Auto-Installer
#   Installs the wrapper, configures MySQL, generates TLS certs,
#   sets up Docker (optional), and creates the first API key.
#
# Usage:
#   # Easiest — one line, zero questions, auto-starts:
#   curl -fsSL https://mona.expert/download/install.sh | bash -s -- --start
#
#   # Interactive (asks for MySQL/LLM config):
#   ./install.sh
#
#   # Flags:
#   #   --yes | --quick   non-interactive, safe defaults (auto when piped)
#   #   --start           start wrapper + website after install
#   #   --docker          use Docker Compose for MySQL
#   #   --mysql-root-password=<pw>
# ────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Colors ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log()  { echo -e "${GREEN}✔${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
err()  { echo -e "${RED}✘${NC} $1"; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }
step() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

# ─── Parse args ────────────────────────────────────────────
USE_DOCKER=false
MYSQL_ROOT_PW=""
NONINTERACTIVE=false
AUTOSTART=false
for arg in "$@"; do
  case "$arg" in
    --docker) USE_DOCKER=true ;;
    --mysql-root-password=*) MYSQL_ROOT_PW="${arg#*=}" ;;
    --yes|-y|--quick) NONINTERACTIVE=true ;;
    --start) AUTOSTART=true ;;
  esac
done

# Auto-detect non-interactive: if stdin is not a TTY (e.g. curl | bash),
# never block on prompts — fall back to safe defaults so the one-liner works.
if [ ! -t 0 ]; then
  NONINTERACTIVE=true
fi

# ─── Detect OS ─────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
NODE_MIN="18.0.0"

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║     mona.expert — Auto-Installer      ║"
echo "  ║   Secure AI Agent Wrapper System      ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"
echo "  OS:   ${OS} ${ARCH}"
echo "  Mode: $(${USE_DOCKER} && echo 'Docker 🐳' || echo 'Native 🖥️')"
echo ""

# ─── Step 1: Node.js check ────────────────────────────────
step "Checking prerequisites"

if command -v node &>/dev/null; then
  NODE_VER="$(node --version)"
  log "Node.js ${NODE_VER}"
else
  err "Node.js not found. Please install Node.js ${NODE_MIN}+:"
  echo "  https://nodejs.org/en/download"
  exit 1
fi

# Compare semver
if [ "$(printf '%s\n' "${NODE_MIN}" "$(node --version | sed 's/v//')" | sort -V | head -1)" != "${NODE_MIN}" ]; then
  err "Node.js ${NODE_MIN}+ required (found: $(node --version))"
  exit 1
fi

# Check npm
if command -v npm &>/dev/null; then
  log "npm $(npm --version)"
else
  err "npm not found (should come with Node.js)"
  exit 1
fi

# Check git
if command -v git &>/dev/null; then
  log "git $(git --version | awk '{print $3}')"
else
  warn "git not found — will download source manually"
fi

# Check openssl
if command -v openssl &>/dev/null; then
  log "openssl $(openssl version | awk '{print $2}')"
else
  err "openssl required for certificate generation"
  exit 1
fi

# ─── Step 2: Clone / Download mona.expert ────────────────
step "Installing mona.expert"

INSTALL_DIR="${HOME}/mona.expert"

if [ -d "${INSTALL_DIR}" ]; then
  info "mona.expert already exists at ${INSTALL_DIR}"
  cd "${INSTALL_DIR}"
  if [ -d .git ]; then
    git pull --ff-only 2>/dev/null && log "Updated via git pull" || warn "Could not git pull"
  fi
else
  if command -v git &>/dev/null; then
    git clone --depth 1 git@github.com:MONAEXPERT/mo.git "${INSTALL_DIR}" 2>/dev/null \
      || git clone --depth 1 https://github.com/MONAEXPERT/mo.git "${INSTALL_DIR}" 2>/dev/null || {
      warn "Git clone failed — falling back to local copy"
      mkdir -p "${INSTALL_DIR}"
      cp -r "$(dirname "$0")"/* "${INSTALL_DIR}/" 2>/dev/null || true
    }
  else
    mkdir -p "${INSTALL_DIR}"
    cp -r "$(dirname "$0")"/* "${INSTALL_DIR}/" 2>/dev/null || true
  fi
  log "Installed to ${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"

# ─── Step 3: Install npm dependencies ─────────────────────
step "Installing npm dependencies"

if [ -f package.json ]; then
  npm install --no-audit --no-fund 2>&1 | tail -3
  log "npm dependencies installed"
else
  # Initialize project
  npm init -y 2>/dev/null
  npm install express mysql2 dotenv basic-ftp node-fetch uuid 2>&1 | tail -3
  log "Project initialized with dependencies"
fi

# ─── Step 4: Create .env ──────────────────────────────────
step "Configuring environment"

if [ ! -f .env ]; then
  if [ "${NONINTERACTIVE}" = true ]; then
    info "Non-interactive install — using safe defaults (edit .env later to customize)"
    MYSQL_HOST="127.0.0.1"; MYSQL_PORT="3306"; MYSQL_USER="mona"
    MYSQL_PASSWORD=""; MYSQL_DATABASE="mona_expert"
    OPENAI_KEY=""; ANTHROPIC_KEY=""; OLLAMA_URL=""
    info "Defaults: MySQL 127.0.0.1:3306 db=mona_expert (in-memory fallback if DB unset)"
  else
  # Interactive MySQL config
  echo ""
  echo "  ┌─ MySQL Configuration ─────────────────────┐"
  echo "  │ Leave blank for defaults or to skip MySQL │"
  echo "  └─────────────────────────────────────────┘"
  echo ""

  read -r -p "  MySQL host [127.0.0.1]: " MYSQL_HOST
  MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"

  read -r -p "  MySQL port [3306]: " MYSQL_PORT
  MYSQL_PORT="${MYSQL_PORT:-3306}"

  read -r -p "  MySQL user [mona]: " MYSQL_USER
  MYSQL_USER="${MYSQL_USER:-mona}"

  read -r -s -p "  MySQL password: " MYSQL_PASSWORD
  echo ""
  MYSQL_PASSWORD="${MYSQL_PASSWORD:-}"

  read -r -p "  MySQL database [mona_expert]: " MYSQL_DATABASE
  MYSQL_DATABASE="${MYSQL_DATABASE:-mona_expert}"

  # LLM provider config
  echo ""
  info "LLM Configuration (API keys for guardrails / LLM proxy)"
  echo ""

  read -r -p "  OpenAI API key (optional): " OPENAI_KEY
  read -r -p "  Anthropic API key (optional): " ANTHROPIC_KEY
  read -r -p "  Ollama base URL (optional, e.g. http://localhost:11434): " OLLAMA_URL
  fi

  cat > .env <<EOF
# mona.expert — Environment Configuration
# Generated by install.sh at $(date)

# ─── Server Ports ─────────────────────────
MONA_EXPERT_PORT=${MONA_EXPERT_PORT:-4188}
WRAPPER_PORT=${WRAPPER_PORT:-4189}
DASHBOARD_PORT=${DASHBOARD_PORT:-4177}

# ─── MySQL Database ───────────────────────
MYSQL_HOST=${MYSQL_HOST}
MYSQL_PORT=${MYSQL_PORT}
MYSQL_USER=${MYSQL_USER}
MYSQL_PASSWORD=${MYSQL_PASSWORD}
MYSQL_DATABASE=${MYSQL_DATABASE}

# ─── LLM Providers ────────────────────────
OPENAI_API_KEY=${OPENAI_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_KEY}
OLLAMA_BASE_URL=${OLLAMA_URL:-}

# ─── Agent Config ─────────────────────────
MONA_AGENTS_DIR=${INSTALL_DIR}/.mona-agents

# ─── TLS / Certs ──────────────────────────
CERTS_DIR=${INSTALL_DIR}/certs

# ─── Default Tenant ───────────────────────
DEFAULT_TENANT=default
EOF
  log ".env created"
else
  info ".env already exists — skipping"
fi

# Source .env
set -a; source .env 2>/dev/null; set +a

# ─── Step 5: MySQL Setup ─────────────────────────────────
step "Setting up MySQL"

if command -v mysql &>/dev/null && [ -n "${MYSQL_PASSWORD:-}" ]; then
  info "MySQL client found — creating database and running schema"

  # Try connecting with user-provided password
  MYSQL_CMD="mysql -h ${MYSQL_HOST} -P ${MYSQL_PORT} -u ${MYSQL_USER}"
  if [ -n "${MYSQL_PASSWORD}" ]; then
    MYSQL_CMD="${MYSQL_CMD} -p'${MYSQL_PASSWORD}'"
  fi

  if ${MYSQL_CMD} -e "SELECT 1" &>/dev/null; then
    log "MySQL connection verified"

    # Create database if not exists
    ${MYSQL_CMD} -e "CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null || warn "Could not create database (may already exist)"

    # Run schema
    if [ -f sql/schema.sql ]; then
      ${MYSQL_CMD} "${MYSQL_DATABASE}" < sql/schema.sql 2>/dev/null && log "Schema applied" || warn "Schema apply had warnings (likely idempotent)"
    fi

    # Create mona user if using root
    if [ "${MYSQL_USER}" = "root" ] || [ "${MYSQL_USER}" = "mona" ]; then
      ${MYSQL_CMD} -e "CREATE USER IF NOT EXISTS 'mona'@'%' IDENTIFIED BY '${MYSQL_PASSWORD}'; GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO 'mona'@'%'; FLUSH PRIVILEGES;" 2>/dev/null || warn "MySQL user setup had issues (may already exist)"
    fi

    log "MySQL setup complete"
  else
    warn "Could not connect to MySQL — will use in-memory storage"
    warn "Fix your .env or run MySQL manually, then restart"
  fi
else
  if [ "${USE_DOCKER}" = true ]; then
    info "Docker mode: MySQL will be managed by Docker Compose"
  else
    info "MySQL client not found — skipping database setup"
    info "Install mysql-client or use --docker for containerized MySQL"
  fi
fi

# ─── Step 6: Generate TLS Certificates ───────────────────
step "Generating TLS certificates"

CERTS_DIR="${INSTALL_DIR}/certs"
mkdir -p "${CERTS_DIR}"

if [ -f "${CERTS_DIR}/wrapper-key.pem" ] && [ -f "${CERTS_DIR}/website-cert.pem" ]; then
  info "Certificates exist — skipping generation"
else
  info "Creating Certificate Authority and server certificates…"

  # CA key + cert
  openssl genrsa -out "${CERTS_DIR}/ca-key.pem" 4096 2>/dev/null
  openssl req -x509 -new -nodes -key "${CERTS_DIR}/ca-key.pem" \
    -sha256 -days 3650 \
    -subj "/C=DE/O=mona.expert/CN=mona.expert CA" \
    -out "${CERTS_DIR}/ca-cert.pem"

  # Wrapper key + CSR + cert (signed by CA)
  openssl genrsa -out "${CERTS_DIR}/wrapper-key.pem" 2048 2>/dev/null
  openssl req -new -key "${CERTS_DIR}/wrapper-key.pem" \
    -subj "/C=DE/O=mona.expert/CN=wrapper.mona.expert" \
    -out "${CERTS_DIR}/wrapper-csr.pem"
  openssl x509 -req -in "${CERTS_DIR}/wrapper-csr.pem" \
    -CA "${CERTS_DIR}/ca-cert.pem" -CAkey "${CERTS_DIR}/ca-key.pem" \
    -CAcreateserial -out "${CERTS_DIR}/wrapper-cert.pem" -days 365 \
    -sha256

  # Website key + CSR + cert (signed by CA)
  openssl genrsa -out "${CERTS_DIR}/website-key.pem" 2048 2>/dev/null
  openssl req -new -key "${CERTS_DIR}/website-key.pem" \
    -subj "/C=DE/O=mona.expert/CN=website.mona.expert" \
    -out "${CERTS_DIR}/website-csr.pem"
  openssl x509 -req -in "${CERTS_DIR}/website-csr.pem" \
    -CA "${CERTS_DIR}/ca-cert.pem" -CAkey "${CERTS_DIR}/ca-key.pem" \
    -CAcreateserial -out "${CERTS_DIR}/website-cert.pem" -days 365 \
    -sha256

  # Clean up CSRs
  rm -f "${CERTS_DIR}/wrapper-csr.pem" "${CERTS_DIR}/website-csr.pem"

  # Secure permissions
  chmod 644 "${CERTS_DIR}/ca-cert.pem" "${CERTS_DIR}/wrapper-cert.pem" "${CERTS_DIR}/website-cert.pem"
  chmod 600 "${CERTS_DIR}/ca-key.pem" "${CERTS_DIR}/wrapper-key.pem" "${CERTS_DIR}/website-key.pem"

  log "Certificates generated in ${CERTS_DIR}"
fi

# ─── Step 7: Create systemd service (Linux only) ─────────
step "Setting up service"

if [ "$(uname -s)" = "Linux" ] && command -v systemctl &>/dev/null; then
  SERVICE_FILE="/etc/systemd/system/mona-expert.service"

  if [ ! -f "${SERVICE_FILE}" ]; then
    cat > /tmp/mona-expert.service <<EOF
[Unit]
Description=mona.expert — Secure AI Agent Wrapper
After=network.target mysql.service mariadb.service
Wants=mysql.service

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${INSTALL_DIR}
ExecStart=$(which node) ${INSTALL_DIR}/wrapper-server.js
ExecStartPost=$(which node) ${INSTALL_DIR}/website-server.js
Restart=on-failure
RestartSec=5
EnvironmentFile=${INSTALL_DIR}/.env

[Install]
WantedBy=multi-user.target
EOF

    warn "To install systemd service:"
    echo "  sudo cp /tmp/mona-expert.service ${SERVICE_FILE}"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable mona-expert"
    echo "  sudo systemctl start mona-expert"
  else
    info "systemd service already exists"
  fi
fi

# ─── Step 8: Generate first API key ──────────────────────
step "Generating first API key"

echo ""
echo "  ┌─ First API Key ──────────────────────────┐"
echo "  │ This key is for the default tenant.      │"
echo "  │ Save it — it will only be shown once!    │"
echo "  └─────────────────────────────────────────┘"
echo ""

NODE_SCRIPT=$(cat <<'NODESCRIPT'
const { generateApiKey } = await import("./src/api-auth.js");
try {
  const key = await generateApiKey({
    tenantId: process.env.DEFAULT_TENANT || "default",
    label: "installer-auto",
    scopes: ["admin"],
    metadata: { source: "install.sh", bootstrap: true }
  });
  console.log(JSON.stringify(key, null, 2));
} catch (err) {
  console.log(JSON.stringify({ error: err.message, hint: "MySQL may not be running — keys will work at runtime" }, null, 2));
}
process.exit(0);
NODESCRIPT
)

CD_DIR="${INSTALL_DIR}"
(cd "${CD_DIR}" && node --input-type=module -e "${NODE_SCRIPT}" 2>/dev/null) || {
  warn "Could not generate API key (MySQL not yet available at runtime)"
  warn "Run 'node bin/mona-expert.js keygen' after starting the service"
}

# ─── Step 9: Docker Compose (optional) ──────────────────
if [ "${USE_DOCKER}" = true ]; then
  step "Setting up Docker"

  if command -v docker &>/dev/null && command -v docker-compose &>/dev/null; then
    cp docker-compose.yml "${INSTALL_DIR}/docker-compose.yml" 2>/dev/null || true
    log "Docker Compose configuration ready at ${INSTALL_DIR}/docker-compose.yml"
    info "Run: cd ${INSTALL_DIR} && docker-compose up -d"
  else
    warn "Docker or docker-compose not found — install Docker first:"
    echo "  https://docs.docker.com/get-docker/"
  fi
fi

# ─── Step 9.5: Auto-start (optional) ─────────────────────
if [ "${AUTOSTART}" = true ]; then
  step "Starting mona.expert"
  nohup node "${INSTALL_DIR}/wrapper-server.js" > "${INSTALL_DIR}/wrapper.log" 2>&1 &
  WRAP_PID=$!
  nohup node "${INSTALL_DIR}/website-server.js" > "${INSTALL_DIR}/website.log" 2>&1 &
  SITE_PID=$!
  sleep 2
  if kill -0 "${WRAP_PID}" 2>/dev/null; then
    log "Wrapper running (pid ${WRAP_PID}) — logs: ${INSTALL_DIR}/wrapper.log"
  else
    warn "Wrapper did not stay up — check ${INSTALL_DIR}/wrapper.log"
  fi
  if kill -0 "${SITE_PID}" 2>/dev/null; then
    log "Website running (pid ${SITE_PID}) — http://127.0.0.1:${MONA_EXPERT_PORT:-4188}"
  else
    warn "Website did not stay up — check ${INSTALL_DIR}/website.log"
  fi
fi

# ─── Step 10: Done ───────────────────────────────────────
step "Installation Complete"

echo ""
echo "  ┌─────────────────────────────────────────┐"
echo "  │  mona.expert is installed!              │"
echo "  │                                         │"
echo "  │  Start the wrapper:                     │"
echo "  │    node ${INSTALL_DIR}/wrapper-server.js    │"
echo "  │                                         │"
echo "  │  Start the website:                     │"
echo "  │    node ${INSTALL_DIR}/website-server.js    │"
echo "  │                                         │"
echo "  │  Open in browser:                       │"
echo "  │    http://127.0.0.1:${MONA_EXPERT_PORT:-4188}                  │"
echo "  │                                         │"
echo "  │  Or use the CLI:                        │"
echo "  │    node ${INSTALL_DIR}/bin/mona-expert.js    │"
echo "  └─────────────────────────────────────────┘"
echo ""

if [ -f .env ]; then
  echo "  Configuration: ${INSTALL_DIR}/.env"
fi
echo ""
echo -e "${GREEN}🚀 All set. Run the wrapper and website to get started!${NC}"
echo ""
