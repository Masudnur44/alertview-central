#!/bin/sh
# Creates .env with strong random secrets. Run once on the server:  ./scripts/setup.sh
set -eu
cd "$(dirname "$0")/.."
[ -f .env ] && { echo ".env already exists — edit it instead."; exit 1; }
printf "Public domain for the SOC (e.g. soc.finpaytech.com): "; read -r DOMAIN
printf "First administrator email: "; read -r ADMIN
printf "Company email domain(s) allowed to request access (comma separated, blank = any): "; read -r DOMAINS
rand() { openssl rand -hex 32; }
sed -e "s|^SOC_DOMAIN=.*|SOC_DOMAIN=$DOMAIN|" \
    -e "s|^APP_URL=.*|APP_URL=https://$DOMAIN|" \
    -e "s|^APP_SECRET=.*|APP_SECRET=$(rand)|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand)|" \
    -e "s|^SOC_APP_DB_PASSWORD=.*|SOC_APP_DB_PASSWORD=$(rand)|" \
    -e "s|^BOOTSTRAP_ADMIN_EMAIL=.*|BOOTSTRAP_ADMIN_EMAIL=$ADMIN|" \
    -e "s|^ALLOWED_EMAIL_DOMAINS=.*|ALLOWED_EMAIL_DOMAINS=$DOMAINS|" \
    .env.example > .env
chmod 600 .env
echo "Wrote .env. Review SMTP / Google settings, then run:  docker compose up -d --build"
