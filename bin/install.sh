#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${MONA_EXPERT_PORT:-4188}"
START_SERVER=1

for arg in "$@"; do
  case "$arg" in
    --no-start) START_SERVER=0 ;;
    --port=*) PORT="${arg#--port=}" ;;
    -h|--help)
      cat <<USAGE
mona.expert smart installer

Usage:
  bash bin/install.sh [--no-start] [--port=4188]

What it does:
  - checks Node.js >=20
  - installs npm dependencies when package.json declares any
  - initializes local runtime folders and .env
  - verifies the CLI
  - starts mona.expert unless --no-start is used
USAGE
      exit 0
      ;;
  esac
done

echo "mona.expert installer"
echo "Project: $ROOT"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js >=20 is required: https://nodejs.org"
  exit 1
fi

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "Node.js >=20 is required; found $(node -v)"
  exit 1
fi
echo "Node $(node -v) ok"

HAS_DEPS="$(node -e 'const p=require("./package.json"); const d={...(p.dependencies||{}),...(p.optionalDependencies||{})}; process.stdout.write(Object.keys(d).length ? "1" : "0")')"
if [ "$HAS_DEPS" = "1" ]; then
  echo "Installing dependencies..."
  npm install
else
  echo "Dependencies: none"
fi

node bin/mona-expert.js setup
node bin/mona-expert.js doctor

echo ""
echo "Ready."
echo "Dashboard: http://127.0.0.1:$PORT"
echo "Agents:    http://127.0.0.1:$PORT/agents.html"

if [ "$START_SERVER" = "1" ]; then
  echo ""
  echo "Starting mona.expert. Press Ctrl+C to stop."
  MONA_EXPERT_PORT="$PORT" node bin/mona-expert.js start
else
  echo "Start later with: MONA_EXPERT_PORT=$PORT node bin/mona-expert.js start"
fi
