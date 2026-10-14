# Deploying FINPAY SOC

This guide takes a fresh Linux server to a running SOC with HTTPS, then to production use with FINPAYTECH's real assets.

## 1. Server

| | Minimum | Recommended |
| --- | --- | --- |
| CPU / RAM | 2 vCPU / 4 GB | 4 vCPU / 8 GB |
| Disk | 40 GB SSD | 100 GB SSD (events are kept 90 days by default) |
| OS | Any Linux with Docker 24+ and Docker Compose v2 | Ubuntu 24.04 LTS |

Install Docker (Ubuntu):

```sh
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
```

**Firewall:** open only 22 (SSH, ideally restricted to your office/VPN IPs), 80 and 443. The database is never exposed — it is only reachable inside the Docker network.

```sh
sudo ufw allow from <office-ip> to any port 22 proto tcp
sudo ufw allow 80,443/tcp && sudo ufw enable
```

**DNS:** create an `A` record, e.g. `soc.finpaytech.com → <server IP>`. Caddy obtains the certificate automatically on first start.

## 2. Configure

```sh
git clone <your repository> /opt/finpay-soc && cd /opt/finpay-soc
./scripts/setup.sh
```

The script asks for the domain, the first administrator's email and the allowed company email domain(s), and writes `.env` with strong random secrets (`chmod 600`). Review `.env` afterwards:

| Setting | Meaning |
| --- | --- |
| `BOOTSTRAP_ADMIN_EMAIL` | Signs up (or uses Google) and is approved as Security Administrator automatically. Only works while no other active admin exists. |
| `ALLOWED_EMAIL_DOMAINS` | Only these domains can request access, e.g. `finpaytech.com`. Leave empty only for testing. |
| `REQUIRE_MFA` | `true` (default): every user must set up an authenticator app before seeing any data. |
| `ALLOW_SIGNUP` | `true`: people can request access (an admin must approve). `false`: invite-only via `admin:create`. |
| `SMTP_*` | Optional. Enables email alerts, email verification and self-service password reset. Works with Microsoft 365, Google Workspace, Amazon SES, Mailgun, etc. |
| `GOOGLE_CLIENT_ID/SECRET` | Optional Google sign-in (see §6). |
| `SEED_DEMO` | `true` loads the FINPAYTECH demo data on first start. Set to `false` for a clean production install. |

> Keep `APP_SECRET` safe and stable: it encrypts two-factor secrets and notification-channel tokens. If it changes, users must re-enrol 2FA and channels must be re-entered.

## 3. Start

```sh
docker compose up -d --build
docker compose ps            # db, app, worker, caddy, backup "running"; migrate "exited (0)"
docker compose logs -f app worker
curl https://soc.finpaytech.com/api/health      # {"ok":true,"db":"ok","worker":"ok"}
```

Open the site, choose **Request access**, sign up with the bootstrap email, sign in, and scan the QR code with an authenticator app. **Save the recovery codes.**

If you prefer not to use the bootstrap email (or locked yourself out), create/promote an admin from the server:

```sh
docker compose run --rm migrate node_modules/.bin/tsx scripts/create-admin.ts --email masud@finpaytech.com --name "Masud Nur"
```

## 4. Make it real (replace the demo)

1. **Remove the demo data** once you are ready (real data is untouched):
   ```sh
   docker compose run --rm migrate node_modules/.bin/tsx scripts/seed-demo.ts --remove
   ```
   and set `SEED_DEMO=false` in `.env`.
2. **Team:** colleagues click *Request access* with their company email; approve them under **Settings → Team & access** and give each the least role they need.
3. **Developer teams:** **Settings → Developer teams** — one team per group that fixes things (Web, Payments, IT Ops…), with their email addresses, Telegram group chat id and WhatsApp numbers. Developers who should sign in get the *Developer* role and a team under **Settings → Team & access**; everyone else just uses the secure link in the message.
4. **Assets:** add websites/APIs as `https://…` URLs, services as `host:port`, servers by name, and pick the owning team. Adding an asset starts monitoring it (only Security Admin/Manager/System Admin can add assets, so adding is the approval); use **Stop monitoring** on the asset to pause it. Only add systems FINPAYTECH owns or is authorized to test. Discovered subdomains are *not* scanned until you open them and press **Start monitoring**.
5. **Discovery:** **External Surface → Subdomain discovery → Add domain** `finpaytech.com`. New hostnames found in certificate-transparency logs appear as *NEW* assets with an alert.
6. **Event sources & agents:** **Settings → Event sources**, create one source per group (Linux servers, Windows laptops, Wazuh). Copy the key (shown once) and follow [agents/README.md](../agents/README.md).
7. **Notifications:** **Settings → Notifications** — add Email/Slack/Teams/Telegram/webhook channels and press **Send test**. Without a channel, nobody is told about critical alerts outside the console.
8. **Tune detections:** **Settings → Detection rules** — business hours, privileged-account pattern, thresholds, risky ports.
9. **Time zone & intervals:** **Settings → Platform & intel**.

### Sending issues to developers (email, Telegram, WhatsApp)

From an alert (or the Command Center) press **Send to developer**. The team gets the diagnosis — what is wrong, impact, where, when, evidence, likely causes, where to look, fix steps — with a deadline (critical 4h, high 24h, medium 3 days, low 7 days) and a secure link that needs no login. Progress shows under **Issues to devs**. When monitoring sees the problem is gone the issue is closed as *verified*; if it comes back within 30 days it is reopened and sent again.

- **Email** uses the SMTP settings.
- **Telegram:** create a bot with @BotFather, put the token in `TELEGRAM_BOT_TOKEN`, add the bot to the team's group and use the group's chat id (e.g. `-1001234567890`; forward a group message to @userinfobot to see it).
- **WhatsApp:** needs a WhatsApp Business Cloud API number from Meta (`WHATSAPP_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`). WhatsApp only delivers free text to people who messaged your number in the last 24 hours, so create and get approved a *utility* template with one body variable, e.g. "FINPAY SOC issue for your team: {{1}}", and set `WHATSAPP_TEMPLATE` to its name.
- Links expire after `ISSUE_LINK_DAYS` (default 14). **New link** on the issue revokes the old one.

## 5. Backups and restore

The `backup` service writes a compressed dump to `./backups` every 24 h and keeps `BACKUP_KEEP_DAYS` (14). **Copy `./backups` off the server** (e.g. nightly `rsync`/`rclone` to object storage) — a backup on the same disk is not a backup.

Restore:

```sh
docker compose stop app worker
docker compose exec -T db pg_restore -U soc_owner -d soc --clean --if-exists < backups/soc-YYYYMMDDTHHMMSSZ.dump
docker compose start app worker
```

Also back up `.env` (secrets) somewhere safe — without `APP_SECRET`, encrypted 2FA secrets in a restored database cannot be read.

## 6. Google sign-in (optional)

1. Google Cloud Console → *APIs & Services* → *OAuth consent screen* → Internal (Workspace) or External.
2. *Credentials* → *Create OAuth client ID* → Web application.
3. Authorised redirect URI: `https://soc.finpaytech.com/api/auth/google/callback`
4. Put the client ID and secret in `.env`, then `docker compose up -d`.

Google users still need admin approval and (with `REQUIRE_MFA=true`) still enrol the authenticator app — Google sign-in replaces the password, not the SOC's own second factor.

## 7. Upgrades

```sh
cd /opt/finpay-soc
git pull
docker compose up -d --build     # migrations run automatically before app/worker start
```

Migrations are forward-only SQL files in `db/migrations/`; each is applied once inside a transaction.

## 8. Operations

| Task | Command |
| --- | --- |
| Logs | `docker compose logs -f app worker caddy` |
| Health | `curl https://<domain>/api/health` |
| Run checks now | External Surface → *Run checks now* |
| Database shell | `docker compose exec db psql -U soc_owner soc` |
| Verify audit integrity | Settings → Audit trail → *Verify integrity* |
| Rotate an agent key | Settings → Event sources → *Rotate* (old key stops immediately) |

## 9. Troubleshooting

| Symptom | Fix |
| --- | --- |
| Banner "background worker has not reported" | `docker compose logs worker` — usually a bad `.env` value; the worker prints which. |
| Caddy cannot get a certificate | DNS must point at the server and ports 80/443 must be reachable from the internet. |
| Every external check says `blocked: resolves to a private/reserved address` | The asset resolves to an internal IP. External checks deliberately never touch internal networks; monitor internal hosts with agents instead. |
| Agent gets HTTP 401 | Key wrong or rotated; 403 = the source has an IP allow-list that does not include the agent's public IP. |
| Locked out after failed sign-ins | Wait 15 minutes, or an admin uses *Unlock* in Settings → Team. |
| Lost phone with 2FA | Use a recovery code; or an admin uses *Reset two-factor*. |

## Moving from the previous hosted prototype

Nothing needs migrating: the prototype's database only held sample data and test accounts. Users re-register on this platform (with approval), and the same FINPAYTECH sample data is available via `SEED_DEMO=true`. Once this server is live, disconnect the old project's GitHub integration so it stops syncing to the repository.
