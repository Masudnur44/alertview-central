# FINPAY SOC roadmap

## Done — v1.0 (self-hosted)
- [x] Fully self-hosted: plain PostgreSQL 16 + built-in auth; Docker Compose deployment with Caddy HTTPS, worker and nightly backups
- [x] Sign-in: password + mandatory TOTP 2FA + recovery codes, optional Google, admin approval, company-domain lock, lockout, session management, email verification & reset (with SMTP)
- [x] Authorization in server code **and** PostgreSQL row-level security (restricted `soc_app` role)
- [x] Append-only, hash-chained audit trail written by database triggers; integrity check and export
- [x] External surface: live TLS certificate inspection, uptime/latency, security headers, risky exposed ports, DNS NS/MX change detection, SSRF-safe probing, auto-resolve on recovery
- [x] Subdomain discovery from certificate-transparency logs
- [x] Detections: brute force, password spraying, success-after-brute-force, off-hours privileged login, suspicious process chains / encoded PowerShell, LOLBin downloads, new admin accounts, log cleared, new services, threat-intel IP match, silent sources, Wazuh alerts — all tunable
- [x] Threat intel: CISA KEV, Feodo Tracker, Spamhaus DROP, Tor exits
- [x] Notifications: email, Slack, Teams, Telegram, signed webhooks, with retries
- [x] Agents: Linux (Python), Windows (PowerShell), Wazuh integration; hashed per-source keys with rotation and IP allow-lists
- [x] Alert bulk triage, owners, context; incident owners/severity/print; vulnerability SLAs and editing; asset editing and detail; richer reports
- [x] Email notifications (was blocked on a sender domain — any SMTP account now works)

## Before go-live (FINPAYTECH tasks)
- [ ] Provision the server, DNS record and `.env` (docs/DEPLOYMENT.md)
- [ ] Remove demo data; add the real asset inventory and root domains
- [ ] Create event sources and roll agents to servers/laptops (or connect Wazuh)
- [ ] Add at least one notification channel and send a test
- [ ] Copy `./backups` off the server on a schedule

## Next
- [ ] Integration with the existing assessment platform (import findings as vulnerabilities via API)
- [ ] Paid threat-intel feeds (e.g. AbuseIPDB, VirusTotal) as optional enrichers
- [ ] Syslog receiver for firewalls/network devices
- [ ] WebAuthn / passkeys for administrators
- [ ] Scheduled PDF report emails to management
- [ ] Case assignment SLAs and on-call escalation
