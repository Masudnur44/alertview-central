# Security model

A SOC is a high-value target: it knows where everything is and what is vulnerable. These are the controls built into the platform and the reasoning behind them.

## Identity and sessions

- **Passwords:** scrypt (N=2¹⁵, r=8, p=1, 16-byte salt). Minimum 12 characters, 3 character classes, common words rejected. Unknown emails take the same time as wrong passwords (no account enumeration). Sign-up responds identically for new and existing addresses.
- **Two-factor:** RFC 6238 TOTP (any authenticator app). Codes are single-use (replay of the last accepted step is rejected), ±30 s drift allowed. Ten single-use recovery codes, stored as SHA-256 hashes. Secrets are encrypted at rest with AES-256-GCM (key derived from `APP_SECRET` via HKDF). `REQUIRE_MFA=true` blocks all data access until enrolment.
- **Approval:** new accounts start as `pending` with no role and can read nothing. Only a Security Administrator can approve and assign roles; admins cannot change their own access (there is always an admin).
- **Company domains:** `ALLOWED_EMAIL_DOMAINS` restricts who can request access, for passwords and Google alike (Google's `hd` hint is also sent).
- **Brute-force protection:** account locks for 15 minutes after 5 failures; per-IP and per-account rate limits on sign-in, sign-up, 2FA and reset requests.
- **Sessions:** 256-bit random tokens in an `HttpOnly`, `Secure`, `SameSite=Lax`, `__Host-` cookie. Only SHA-256(token) is stored. Idle timeout 12 h, absolute 7 days. The session id rotates when 2FA succeeds. Password change/reset and account disable revoke other sessions. Users can see and revoke their own sessions.
- **Google sign-in:** OIDC authorization-code flow with PKCE, `state` and `nonce` in a signed short-lived cookie; issuer, audience, expiry, nonce and `email_verified` are validated.

## Authorization — enforced twice

1. **Server functions** check a permission matrix (`src/lib/permissions.ts`) before doing anything.
2. **PostgreSQL row-level security** enforces the same rules. The app connects as `soc_app` (`NOSUPERUSER NOBYPASSRLS`, not the table owner) and every request runs in a transaction tagged with the signed-in user (`app.user_id`). A bug in one layer does not expose or modify data.

| Role | Can |
| --- | --- |
| Security Administrator | Everything: team, keys, channels, settings, deletes |
| Security Manager | Triage, incidents, vulnerabilities, tune detections, assets/domains, read audit |
| Security Analyst | Triage alerts, run incidents, manage vulnerabilities, run checks |
| System Administrator | Assets, domains, event sources, triage |
| Management | Read-only dashboards and reports |
| Auditor | Read-only plus the audit trail |

## Audit trail

- Database triggers record **every change made by a person** (who, when, from which IP, and a before/after diff with secrets redacted) — the browser cannot skip or forge entries; the actor is always taken from the session.
- Explicit entries for sign-ins, failures, 2FA events, key rotation, exports, report views, "run now" actions.
- **Append-only:** `UPDATE`/`DELETE`/`TRUNCATE` are revoked from the app role and blocked by triggers.
- **Tamper-evident:** each entry stores `SHA-256(previous hash | entry)`. *Verify integrity* recomputes the chain and reports the first altered entry — even edits made directly by a database superuser are detected.

## Event intake

- One key per source, format `soc_` + 160 random bits; only the SHA-256 is stored and the key is shown once. Keys can be rotated or disabled instantly, and restricted to source IP ranges.
- 1 MB body limit (2 MB at the proxy), 500 events per request, strict schema validation, per-source events-per-minute limit, per-IP auth-failure limit.
- Hosts are auto-registered as *internal* assets, never as external targets for probing.

## External probing (SSRF protection)

Nothing is probed without explicit authorization: every asset starts with monitoring off, and a Security Admin, Manager or System Admin must **approve its monitoring scope** (recorded with who and when, and enforced by a database trigger) before checks can run. Revoking approval switches monitoring off. The monitor resolves every hostname itself, refuses private, loopback, link-local, CGNAT, multicast, documentation and NAT64 ranges (v4 and v6), and then connects to that exact address — so DNS rebinding cannot redirect it to the internal network or a cloud metadata endpoint. Every redirect hop is re-validated. Only Security Admins, Managers and System Admins can add assets. Outbound webhooks must be HTTPS and pass the same check.

## Secrets at rest

| Secret | Storage |
| --- | --- |
| Passwords | scrypt hash |
| Session tokens, reset/verify tokens, ingest keys, recovery codes | SHA-256 only |
| TOTP seeds, notification channel configs (webhook URLs, bot tokens, emails) | AES-256-GCM, key from `APP_SECRET` |

## Web hardening

Content-Security-Policy, HSTS (2 years), `X-Frame-Options: DENY`, `nosniff`, strict referrer and permissions policies on every response; `no-store` on APIs; same-origin check on all server functions (CSRF); `noindex` everywhere. CSV exports neutralise spreadsheet formula injection.

## Deployment

- Database is not published outside the Docker network; the app and worker never receive the owner password.
- Containers run as a non-root user; Caddy terminates TLS and replaces any client-supplied `X-Forwarded-For`.
- Nightly backups; copy them off the host.

## Known limits / next steps

- The rate limiter is per-process memory — fine for the single-app deployment here; use Redis or Postgres if you scale to several app replicas.
- CSP allows inline scripts because the framework inlines hydration data; nonce-based CSP is a future improvement.
- WebAuthn/passkeys would be a stronger second factor than TOTP for administrators.
- Agents authenticate with a shared per-source key; per-host certificates (mTLS) would limit the blast radius of a stolen key.
