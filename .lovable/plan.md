# FINPAY SOC — Full Platform Build Plan

A dark "command center" security operations platform for FINPAYTECH, built in phases following the spec's MVP (section 35) and then expanding.

## Phase 1 — Foundation (this first build)
- Enable Lovable Cloud: secure sign-in (email/password + Google), team roles from the spec (Security Administrator, Analyst, Manager, System Administrator, Management, Auditor).
- Dark command-center design: near-black surfaces, cyan signal accent, severity colors (critical red, high orange, medium amber, low blue, info gray), monospaced data font.
- App shell with sidebar: Overview, Assets, External Surface, Alerts, Incidents, Vulnerabilities, Activity, Reports, Settings.
- Realistic FINPAYTECH sample data so every screen is populated on day one.

## Phase 2 — Core SOC screens
- **Overview dashboard**: overall status, open critical/high alerts, active incidents, assets online/offline, vulnerability counts, MTTD/MTTR, recent activity, "what happened while you were away".
- **Asset inventory**: domains, subdomains, websites, APIs, servers, IPs, endpoints; owner, criticality, status, last seen; new/changed asset flags.
- **Alerts**: queue with severity, source, asset, MITRE ATT&CK technique; acknowledge, assign, mark false positive, escalate to incident.
- **Incidents**: lifecycle (new → triage → contained → resolved → closed), timeline, linked alerts/assets, evidence notes, owner.
- **Vulnerabilities**: findings linked to assets, correlated with alerts, risk-based priority score.

## Phase 3 — Live monitoring
- **External surface checks** run on a schedule: website/API uptime, HTTP status, TLS certificate expiry and validity, security headers, DNS resolution. Results raise alerts automatically.
- **Event intake endpoint**: a secured URL where FINPAYTECH servers, endpoint agents and apps can send logs/events (logins, processes, errors). Protected by a per-source key.
- **Detection rules**: failed-login bursts, privileged account use off-hours, new exposed service, cert expiring, asset offline — each mapped to severity and ATT&CK.

## Phase 4 — Reporting, notifications, audit
- Daily/weekly/monthly reports with metrics (MTTD, MTTR, alert volume, false-positive rate, coverage).
- Email notifications for critical/high alerts.
- Full audit log of analyst actions for the Auditor role.

## Out of scope for now
- Installing agents on FINPAYTECH machines (the platform provides the intake endpoint; agents such as Wazuh/osquery are configured on your side).
- Paid threat-intelligence feeds and the integration with your existing assessment platform (a placeholder connection page will be ready for it).

## Technical details
- TanStack Start routes under a signed-in area; server functions for all data access with row-level security per role (roles in a separate table with a `has_role` check).
- Tables: assets, alerts, incidents, incident_events, vulnerabilities, detection_rules, event_sources, events, check_results, audit_log, user_roles, profiles. Seed data in the migration.
- Public endpoints under `/api/public/` for event intake (key-verified) and scheduled checks (triggered by a database cron job).
