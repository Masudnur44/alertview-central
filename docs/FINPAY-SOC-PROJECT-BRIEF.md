# FINPAY Security Operations Center

## Project Brief and Company Information Request

**Document status:** Planning and onboarding guide  
**Audience:** FINPAY leadership, IT, infrastructure, application, and security teams  
**System:** FINPAY SOC, self-hosted security operations platform

## 1. Executive Summary

FINPAY SOC is a self-hosted Security Operations Center (SOC) for monitoring FINPAY's technology environment. It provides one place to inventory assets, monitor the external attack surface, collect security events, detect suspicious activity, manage alerts and incidents, track vulnerabilities, notify responders, and preserve an auditable record of security actions.

The platform is designed to run inside infrastructure controlled by FINPAY. Its database, web application, background worker, authentication, monitoring jobs, and backups run as Docker services. External traffic is protected by HTTPS through Caddy, and PostgreSQL row-level security plus application permissions limit access to authorized users.

The current local installation is a demonstration environment containing sample data. It must be configured with FINPAY's real domain, users, assets, event sources, notification channels, and operational policies before it is used for production security monitoring.

## 2. What Is Being Created

The finished system will provide:

- A secure web console for FINPAY security and management users.
- A complete inventory of websites, APIs, servers, endpoints, network devices, databases, and other monitored assets.
- External attack-surface monitoring for authorized internet-facing systems.
- Internal event collection from Linux and Windows machines, Wazuh, applications, and other approved sources.
- Detection rules for brute force, password spraying, privileged logins, suspicious process chains, new administrators, cleared logs, new services, threat-intelligence matches, and silent event sources.
- Alert triage, ownership, investigation notes, and incident management.
- Vulnerability tracking with risk scoring and remediation deadlines.
- Notifications through email, Slack, Microsoft Teams, Telegram, or signed webhooks.
- Reports for security posture, alert handling, response performance, and audit activity.
- An append-only, hash-chained audit trail recording human changes and important security events.
- Scheduled background checks, threat-intelligence updates, notifications, retention, and backups.

## 3. What the SOC Does Not Do Automatically

The SOC does not automatically authorize monitoring of systems that FINPAY does not own or have permission to assess. FINPAY must approve the domains, IP addresses, applications, and networks placed under monitoring.

The SOC also does not replace:

- A firewall, endpoint protection platform, identity provider, vulnerability scanner, or SIEM that FINPAY already operates.
- A formal incident-response process or a human security team.
- Patch management, secure software development, access reviews, or backup testing.
- Legal, regulatory, privacy, or compliance decisions.

The platform consolidates security visibility and response work. It can receive events from existing tools and can complement them.

## 4. Platform Architecture

The production deployment contains these services:

| Service    | Purpose                                                                            |
| ---------- | ---------------------------------------------------------------------------------- |
| Caddy      | HTTPS termination, certificate management, compression, and request limits         |
| App        | Web console, authentication, API routes, server functions, and reporting           |
| PostgreSQL | Application data, row-level security, audit trail, and event history               |
| Worker     | Scheduled monitoring, discovery, threat intelligence, notifications, and retention |
| Migrate    | Applies forward-only database migrations and optional initial data                 |
| Backup     | Creates scheduled compressed database backups                                      |

Agents and integrations send approved security events to the app over HTTPS. The app stores only hashed event-source keys. Reusable secrets such as TOTP seeds and notification credentials are encrypted using the application secret.

## 5. Security Model

The production deployment should use the following controls:

- HTTPS with a real FINPAY-owned domain.
- Mandatory authenticator-app MFA for every user.
- FINPAY company-domain restriction for account requests.
- Approval and least-privilege role assignment for new users.
- Separate roles for administrators, managers, analysts, system administrators, management, and auditors.
- PostgreSQL row-level security in addition to application permission checks.
- No database owner password passed to the web app or worker.
- Per-source event keys that can be rotated or disabled.
- Private and reserved network targets blocked by external monitoring to prevent SSRF.
- Login throttling, account lockout, secure sessions, recovery codes, and session revocation.
- Append-only audit records with integrity verification.
- Nightly backups copied off the production server.
- Secrets stored in a protected server secret file or secret manager, never in email, tickets, chat, or source control.

FINPAY should provide access through narrowly scoped service accounts or agent installation permissions. Unrestricted root passwords, SSH private keys, personal passwords, and long-lived administrator tokens are not required.

## 6. Information FINPAY Must Provide

### 6.1 Company and ownership

- Legal or operating company name to display in the SOC.
- Official company email domain or domains.
- Initial Security Administrator email address.
- Confirmation that FINPAY authorizes monitoring of the submitted assets.
- Primary technical contact and escalation contact.
- Security, privacy, and compliance requirements that affect retention or access.

### 6.2 Production hosting

- Linux server hostname, public IP, provider, and region.
- Preferred deployment domain, for example `soc.finpaytech.com`.
- DNS administrator who can create the required DNS record.
- SSH access process or administrator who will perform deployment.
- Firewall or security-group process for ports 22, 80, and 443.
- Backup destination and retention requirements.
- Preferred timezone for reports, business hours, and scheduled checks.

FINPAY does not need to send server passwords in this document. Access can be performed by a FINPAY administrator while following the deployment guide.

### 6.3 Public websites and applications

Provide a spreadsheet or export with one row per asset:

| Field                   | Example                                      |
| ----------------------- | -------------------------------------------- |
| Name                    | Customer Portal                              |
| Hostname or URL         | `https://portal.finpaytech.com`              |
| Asset type              | Website, API, mobile backend, VPN, mail, DNS |
| Environment             | Production, staging, development             |
| Owner/team              | Customer Operations                          |
| Criticality             | Critical, high, medium, low                  |
| Internet-facing         | Yes or no                                    |
| Approved for monitoring | Yes or no                                    |
| Notes                   | Maintenance window or special behavior       |

Include known domains, subdomains, public IPs, APIs, VPN portals, mail systems, DNS providers, cloud-hosted services, payment services, and customer-facing applications. FINPAY may also provide approved root domains so the SOC can discover possible subdomains from certificate-transparency data. Discovered assets must be reviewed before being treated as confirmed FINPAY assets.

### 6.4 Internal infrastructure

Provide, where applicable:

- Server inventory and operating systems.
- Private IP ranges and network locations.
- Domain controllers and identity systems.
- Workstations or endpoint groups.
- Databases, storage systems, backup systems, and virtualization platforms.
- Firewalls, VPNs, routers, switches, and wireless controllers.
- Cloud accounts, subscriptions, projects, and important services.
- Asset owners, criticality, and maintenance windows.

Private assets are not probed as public targets. They are monitored through agents or approved integrations.

### 6.5 Event sources and integrations

For each source, provide:

- Source name and owner.
- Source type: Linux, Windows, Wazuh, application, firewall, cloud, or other.
- Approximate event volume.
- Network path to the SOC.
- Machines or systems included.
- Required deployment method: manual, Group Policy, Intune, RMM, or existing Wazuh.
- Any source IP restrictions required.

The SOC generates a separate source key inside the console. FINPAY should not reuse passwords or infrastructure credentials as event-source keys.

### 6.6 Notifications and response

Provide the chosen notification destinations and owners:

- Critical-alert email distribution list.
- Security operations or on-call mailbox.
- Slack or Teams security channel.
- Optional Telegram or signed webhook destination.
- Escalation contacts and response hours.
- Severity thresholds for each channel.

At least one notification channel must be tested before production acceptance.

### 6.7 Optional identity and email services

- SMTP provider and sending mailbox for verification, password resets, and alerts.
- Google Workspace OAuth client details if Google sign-in is required.
- Allowed Google Workspace domain and redirect URI approval.

Secrets for SMTP and OAuth must be entered directly into the protected production configuration.

## 7. Production Onboarding Plan

### Phase 1: Confirm scope

1. Confirm the FINPAY company domain and authorized asset scope.
2. Select the production server and deployment domain.
3. Define the initial administrator, technical owner, and escalation contacts.
4. Decide retention, timezone, business hours, and notification policy.

### Phase 2: Deploy the platform

1. Install Docker and Docker Compose on the approved Linux server.
2. Create the production `.env` with strong generated secrets.
3. Set `SEED_DEMO=false` for a clean production database.
4. Set `REQUIRE_MFA=true` and restrict `ALLOWED_EMAIL_DOMAINS` to FINPAY domains.
5. Configure DNS and allow HTTPS traffic.
6. Start the database, migrations, app, worker, Caddy, and backup services.
7. Confirm the health endpoint and review app and worker logs.

### Phase 3: Establish access

1. Create or approve the initial Security Administrator.
2. Enrol an authenticator app and save recovery codes securely.
3. Add other users only after assigning the least required role.
4. Confirm that management and auditor users have read-only access where required.

### Phase 4: Load FINPAY scope

1. Remove any demo data if it was loaded.
2. Add approved websites, APIs, domains, and public services.
3. Add internal assets and owners.
4. Add the approved root domains for discovery.
5. Review every discovered hostname before monitoring it.

### Phase 5: Connect event sources

1. Create event sources in the SOC.
2. Install Linux and Windows agents on an approved pilot group.
3. Connect Wazuh or other approved integrations.
4. Confirm heartbeats and event intake.
5. Expand deployment to the approved server and endpoint inventory.

### Phase 6: Tune and accept

1. Configure notification channels and send test notifications.
2. Set business hours, privileged-account patterns, thresholds, and risky ports.
3. Run an approved external check and confirm the result.
4. Generate a test alert and walk through triage and incident handling.
5. Verify the audit trail and backup creation.
6. Record unresolved gaps, owners, and deadlines.

## 8. Production Acceptance Criteria

The deployment is ready for production when:

- The approved FINPAY domain serves the SOC over valid HTTPS.
- The health endpoint reports the database and worker as healthy.
- Demo data is removed or explicitly approved for continued use.
- MFA is enabled and recovery codes are stored securely.
- Company-domain restrictions and user roles are verified.
- The approved public asset inventory is loaded.
- At least one Linux, Windows, Wazuh, or application source sends test events.
- At least one alert notification is received successfully.
- A test incident is created, assigned, updated, and closed.
- A backup exists and its off-server copy process is documented.
- Audit integrity verification succeeds.
- The monitoring scope has been approved by the FINPAY owner.

## 9. Company Handoff Checklist

FINPAY can return the following completed information:

- [ ] Company name and official email domain(s)
- [ ] Initial Security Administrator email
- [ ] Authorized production domain
- [ ] Production server and hosting owner
- [ ] DNS and firewall owner
- [ ] Backup destination and retention
- [ ] Timezone, business hours, and maintenance windows
- [ ] Public websites, APIs, domains, and IPs
- [ ] Internal server and endpoint inventory
- [ ] Cloud, firewall, Wazuh, and application integrations
- [ ] Agent deployment owner and rollout method
- [ ] Security notification destinations
- [ ] Incident escalation contacts
- [ ] SMTP decision
- [ ] Google sign-in decision
- [ ] Data retention and compliance requirements
- [ ] Written authorization to monitor the submitted scope

## 10. Information That Must Not Be Sent in This Document

Do not place any of the following in email, chat, spreadsheets, tickets, or source control:

- Passwords.
- SSH private keys.
- Personal access tokens.
- Database owner credentials.
- SMTP passwords.
- OAuth client secrets.
- Agent keys.
- Webhook signing secrets.
- TOTP recovery codes.

These values should be generated or entered directly on the production server using an approved secret-management process.

## 11. Reference Documents

- [Deployment guide](DEPLOYMENT.md)
- [Security model](SECURITY.md)
- [Agent and integration guide](../agents/README.md)
- [Developer and operations conventions](../AGENTS.md)
