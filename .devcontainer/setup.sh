#!/usr/bin/env bash
# Runs once when the codespace is created: install, configure, migrate, load demo data.
set -euo pipefail
cd "$(dirname "$0")/.."

npm install --no-audit --no-fund

if [ -n "${CODESPACE_NAME:-}" ]; then
  APP_URL="https://${CODESPACE_NAME}-8080.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
else
  APP_URL="http://localhost:8080"
fi

if [ ! -f .env.local ]; then
  cat > .env.local <<ENV
# Development settings for the codespace (not used in production).
NODE_ENV=development
APP_URL=${APP_URL}
APP_SECRET=$(openssl rand -hex 32)
DATABASE_URL=postgres://soc_app:devpassword@localhost:5432/soc
MIGRATION_DATABASE_URL=postgres://postgres:postgres@localhost:5432/soc
SOC_APP_DB_PASSWORD=devpassword
ORG_NAME=FINPAYTECH
BOOTSTRAP_ADMIN_EMAIL=masudn058@gmail.com
ALLOWED_EMAIL_DOMAINS=
REQUIRE_MFA=false
ALLOW_SIGNUP=true
TRUST_PROXY=true
ENV
fi

set -a; . ./.env.local; set +a
for i in $(seq 1 30); do (echo > /dev/tcp/localhost/5432) 2>/dev/null && break; sleep 1; done
npm run db:migrate
npm run db:seed-demo

echo
echo "Setup done. Preview: ${APP_URL}"
echo "Sign up with ${BOOTSTRAP_ADMIN_EMAIL} to become the first Security Administrator."
