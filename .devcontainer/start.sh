#!/usr/bin/env bash
# Runs every time the codespace starts: launch the web app and the worker in the background.
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f .env.local ] || { echo "run .devcontainer/setup.sh first"; exit 0; }
set -a; . ./.env.local; set +a
# Keep APP_URL in sync if the codespace was renamed or rebuilt.
if [ -n "${CODESPACE_NAME:-}" ]; then
  export APP_URL="https://${CODESPACE_NAME}-8080.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
fi
npm run db:migrate >/tmp/soc-migrate.log 2>&1 || true
pkill -f "vite dev" 2>/dev/null; pkill -f "src/worker/main.ts" 2>/dev/null
nohup npm run dev >/tmp/soc-app.log 2>&1 &
nohup npm run worker >/tmp/soc-worker.log 2>&1 &
echo "FINPAY SOC starting on port 8080 (logs: /tmp/soc-app.log, /tmp/soc-worker.log)"
