# FINPAY SOC

Self-hosted Security Operations Center for FINPAYTECH: asset inventory, external attack-surface monitoring, event intake with detections mapped to MITRE ATT&CK, alert triage, incident response, vulnerability management, reports and a tamper-evident audit trail.

Everything runs on your own server with Docker. There are no third-party platform dependencies: the database, sign-in and scheduled jobs are all part of this repository.

```
                Internet
                   │  443 (Let's Encrypt via Caddy)
            ┌──────▼──────┐
            │    caddy    │  TLS, gzip, request size limits
            └──────┬──────┘
            ┌──────▼──────┐        ┌──────────────┐
 agents ───►│     app     │◄──────►│  PostgreSQL  │  row-level security,
 Wazuh  ───►│ (web + API) │        │      16      │  hash-chained audit log
            └─────────────┘        └──────▲───────┘
            ┌─────────────┐               │
            │   worker    │───────────────┘  checks · discovery · threat intel ·
            └─────────────┘                  notifications · retention
            ┌─────────────┐
            │   backup    │  nightly pg_dump → ./backups
            └─────────────┘
```

## What it does

| Area | Capabilities |
| --- | --- |
| **Access** | Built-in sign-in (password + authenticator-app 2FA, optional Google), admin approval for every new account, company-domain lock, 6 roles, account lockout, session management |
| **Assets** | Inventory with owner/criticality/tags; hosts reporting through agents are registered automatically; new subdomains discovered from certificate-transparency logs |
| **External surface** | Live uptime and response time, TLS certificate read from the server (expiry, trust, hostname), security headers, exposed risky ports (RDP, SMB, databases…), DNS name-server / MX changes. Alerts auto-resolve on recovery |
| **Detection** | Brute force, password spraying, login-after-brute-force, off-hours privileged logins, Office→script chains and encoded PowerShell, LOLBin downloads, new admin accounts, cleared logs, new services, known-malicious IPs, silent agents, Wazuh alerts. Thresholds tunable per rule |
| **Threat intel** | CISA KEV, abuse.ch Feodo, Spamhaus DROP, Tor exits — refreshed daily, matched on every event |
| **Response** | Alert queue with bulk triage, owners, related events; incidents with lifecycle, timeline/evidence, linked alerts and vulnerabilities |
| **Vulnerabilities** | Risk score (CVSS, KEV, exposure, criticality, live alerts), SLA due dates by severity |
| **Notifications** | Email (SMTP), Slack, Microsoft Teams, Telegram, signed webhooks — per-channel severity threshold, retries |
| **Reporting & audit** | Daily/weekly/monthly/quarterly metrics (MTTA, MTTR, MTTC, false-positive rate, coverage), CSV/print; every human change recorded with a diff in an append-only, hash-chained audit log |

## Quick start (server)

```sh
git clone <repo> finpay-soc && cd finpay-soc
./scripts/setup.sh                 # writes .env with random secrets
docker compose up -d --build       # db, migrations, app, worker, caddy, backups
```

Then open `https://<your domain>`, sign up with the `BOOTSTRAP_ADMIN_EMAIL` address, and set up two-factor. Full guide: **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

## Local development

Requirements: Node 22+, a PostgreSQL 16 database.

```sh
npm install
cp .env.example .env.local
# edit .env.local: APP_URL=http://localhost:8080, APP_SECRET=<openssl rand -hex 32>,
#   DATABASE_URL=postgres://soc_app:devpassword@localhost:5432/soc
#   MIGRATION_DATABASE_URL=postgres://<owner>:<pw>@localhost:5432/soc, SOC_APP_DB_PASSWORD=devpassword
set -a; . ./.env.local; set +a    # load the variables into this shell

npm run db:migrate                # schema + restricted soc_app role
npm run db:seed-demo              # optional demo data
npm run admin:create -- --email you@finpaytech.com
npm run dev                       # http://localhost:8080
npm run worker                    # second terminal (same variables loaded)
npm test                          # unit tests
```

## Project layout

```
src/routes/            pages (TanStack Start file routes) and API routes (src/routes/api/*)
src/lib/api/           server functions the pages call (auth, SOC data, administration)
src/server/            server-only code: auth, database, detection, monitoring, intel, notifications
src/worker/main.ts     background worker (scheduled jobs)
db/migrations/         SQL schema, row-level security, audit triggers (applied by scripts/migrate.ts)
db/seed/               demo data and its removal script
agents/                Linux and Windows agents, Wazuh integration
deploy/                Caddyfile, backup script
docs/                  deployment, security model
tests/unit/            unit tests (run with `npm run test:unit`)
```

## Documentation

- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — install, configure, go live, backups, upgrades, troubleshooting
- [docs/SECURITY.md](docs/SECURITY.md) — security model and design decisions
- [agents/README.md](agents/README.md) — connecting servers, laptops and Wazuh
- [AGENTS.md](AGENTS.md) — conventions for developers (and AI coding assistants)
- [roadmap.md](roadmap.md) — what is done and what is next
