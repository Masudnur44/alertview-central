// Developer-facing runbooks: for every detection, what it means, the usual causes,
// where to look and how to fix it. Used to build the issue brief sent to a team.
export type Runbook = {
  meaning: string;
  causes: string[];
  where: string[];
  fix: string[];
  verify: string;
  /** Who usually fixes this, used to suggest a team when an asset has none. */
  owner: "web" | "infra" | "security" | "app";
};

const R: Record<string, Runbook> = {
  asset_offline: {
    meaning: "The service does not answer from the internet, or answers with a server error (HTTP 5xx). Customers or partners cannot use it right now.",
    causes: ["Application process crashed or was not restarted after a deploy", "Server/VM/container is down or out of memory/disk", "Load balancer, reverse proxy or firewall rule changed", "DNS points to the wrong address", "Upstream dependency (database, payment provider) failing, causing 502/503/504"],
    where: ["Application logs around the 'first seen' time", "Service/container status (systemctl, docker ps, Kubernetes pods)", "Reverse proxy / load balancer logs and health checks", "Recent deploys or config changes at that time"],
    fix: ["Restore the service (restart / roll back the last deploy)", "Check disk, memory and CPU on the host", "Confirm DNS and firewall still route to the right place", "Once up, find the root cause before closing"],
    verify: "The SOC re-checks automatically; the issue is verified when the asset answers normally again.",
    owner: "infra",
  },
  flapping: {
    meaning: "The service keeps going down and coming back. Intermittent failures usually turn into a full outage.",
    causes: ["Memory leak or crash loop (process restarted by a supervisor)", "Unhealthy instance behind a load balancer", "Resource exhaustion at peak times (connections, threads, DB pool)", "Unstable network path or DNS"],
    where: ["Restart counts / crash logs", "Load balancer target health", "Resource graphs at the failure times listed below"],
    fix: ["Find which instance/process fails and why (OOM, exceptions)", "Increase resources or fix the leak", "Remove bad instances from rotation"],
    verify: "Verified when no further failures are seen for 24 hours.",
    owner: "infra",
  },
  latency_degradation: {
    meaning: "The service still works but is much slower than its normal baseline — a common early warning before timeouts and outages.",
    causes: ["Slow database queries or missing indexes", "Saturated server (CPU, memory, connection pool)", "A slow third-party dependency", "A recent deploy that added heavy work to the request path", "Traffic spike or abusive client (scraping, attack)"],
    where: ["APM / slow-query logs for the time window", "Server resource graphs", "Recent deploys", "Web server access logs for unusual clients"],
    fix: ["Identify the slow endpoint/query and optimise or cache it", "Scale up/out if resources are saturated", "Rate-limit abusive clients"],
    verify: "Verified when response time returns to its baseline.",
    owner: "app",
  },
  cert_expiring: {
    meaning: "The TLS (HTTPS) certificate expires soon. When it expires, browsers and API clients will refuse to connect.",
    causes: ["Automatic renewal (e.g. certbot / ACME) not configured or failing", "Certificate bought manually and renewal forgotten", "Renewed certificate not deployed to this server / load balancer"],
    where: ["Certificate details below (issuer, expiry)", "certbot/ACME logs or your CA account", "Where TLS terminates: web server, load balancer, CDN"],
    fix: ["Renew the certificate and deploy it where TLS terminates", "Set up automatic renewal and an expiry reminder", "Reload the web server so it serves the new certificate"],
    verify: "Verified automatically when the server presents a certificate valid for more than 14 days.",
    owner: "web",
  },
  cert_expiring_soon: {
    meaning: "The TLS certificate expires within 30 days. Not urgent yet — renewing now avoids an outage.",
    causes: ["Normal renewal window; check that automatic renewal is actually set up"],
    where: ["Certificate details below", "Renewal automation (certbot timer, cloud certificate manager)"],
    fix: ["Confirm auto-renewal works, or renew now"],
    verify: "Verified automatically when the certificate is renewed.",
    owner: "web",
  },
  cert_invalid: {
    meaning: "The certificate is not trusted (self-signed, wrong hostname, or incomplete chain). Users see a security warning and traffic could be intercepted.",
    causes: ["Self-signed or internal CA certificate on a public site", "Certificate issued for a different hostname", "Missing intermediate certificate in the chain"],
    where: ["Certificate subject/issuer and the error below", "Web server TLS configuration (certificate + chain file)"],
    fix: ["Install a certificate from a public CA for exactly this hostname", "Include the full chain (fullchain.pem)"],
    verify: "Verified automatically when the certificate is trusted.",
    owner: "web",
  },
  missing_security_headers: {
    meaning: "The site does not send standard browser security headers, which protect users against clickjacking, content sniffing and some injection attacks.",
    causes: ["Headers never configured on the web server / framework", "A proxy or CDN strips them"],
    where: ["Web server config (nginx/Apache/IIS) or application middleware", "Missing headers are listed below"],
    fix: ["Add Strict-Transport-Security, Content-Security-Policy, X-Frame-Options (or CSP frame-ancestors) and X-Content-Type-Options: nosniff", "Test CSP in report-only mode first if the site uses inline scripts"],
    verify: "Verified automatically when all headers are present.",
    owner: "web",
  },
  risky_port_open: {
    meaning: "A sensitive service (database, remote desktop, file sharing, admin API) is reachable from the whole internet. These are prime targets for attackers.",
    causes: ["Firewall / security group opened for testing and never closed", "Service bound to 0.0.0.0 instead of a private address", "Port forwarding on a router"],
    where: ["Cloud security groups / firewall rules for this host", "The service's listen address configuration"],
    fix: ["Close the port to the internet; allow only VPN or specific office IPs", "Bind the service to a private interface", "Check the service logs for unauthorised access while it was exposed"],
    verify: "Verified automatically when the port no longer answers from the internet.",
    owner: "infra",
  },
  dns_changed: {
    meaning: "The domain's name servers or mail servers changed. If nobody planned this, the domain may have been hijacked.",
    causes: ["Planned DNS provider or email migration", "Compromised registrar or DNS provider account"],
    where: ["Registrar and DNS provider account audit logs", "Old vs new records below"],
    fix: ["If unplanned: lock the registrar account, restore records, rotate credentials, enable registrar lock and 2FA"],
    verify: "Close as fixed once the change is confirmed as planned or reverted.",
    owner: "infra",
  },
  new_external_asset: {
    meaning: "A hostname under the company domain has a public certificate and is reachable, but it is not in the asset inventory.",
    causes: ["New service deployed without registering it", "Forgotten staging/test environment", "Shadow IT"],
    where: ["Who owns the hostname (DNS records, cloud account)", "Whether it should be public at all"],
    fix: ["Confirm the owner and register it with the right team, or take it offline", "Make sure staging/test sites are not exposing real data"],
    verify: "Close once the owner is confirmed or the host is removed.",
    owner: "infra",
  },
  brute_force: {
    meaning: "One address is repeatedly failing to log in — someone is guessing passwords.",
    causes: ["Automated password-guessing bot", "Misconfigured client with an old password (check if the IP is internal)"],
    where: ["Authentication logs for the source IP and target accounts", "Whether any login from that IP succeeded"],
    fix: ["Block the IP at the firewall/WAF", "Add rate limiting and account lockout", "Enforce MFA for the targeted accounts"],
    verify: "Verified when no further failures from that source are seen.",
    owner: "security",
  },
  password_spray: {
    meaning: "One address is trying a few passwords against many different accounts — a classic way to find weak passwords without locking accounts.",
    causes: ["Credential-stuffing or spraying campaign"],
    where: ["Login logs: accounts tried and any successes", "WAF/proxy logs for the source"],
    fix: ["Block the source", "Force resets for any account that logged in successfully", "Enforce MFA and breached-password checks"],
    verify: "Verified when the activity stops and no account was compromised.",
    owner: "security",
  },
  brute_force_success: {
    meaning: "After many failed attempts, a login from the same address SUCCEEDED. Treat the account as compromised.",
    causes: ["Password guessed or reused from a breach"],
    where: ["Everything the account did after the successful login", "Sessions/tokens issued to it"],
    fix: ["Disable the account / revoke sessions now", "Reset the password and enable MFA", "Review data accessed and changes made"],
    verify: "Close after the account is secured and activity reviewed.",
    owner: "security",
  },
  offhours_privileged_login: {
    meaning: "An administrator or service account logged in outside business hours.",
    causes: ["Legitimate emergency or maintenance work", "Stolen credentials used by an attacker"],
    where: ["Confirm with the account owner", "What was done in that session"],
    fix: ["If not legitimate: disable the account, rotate credentials, investigate the host"],
    verify: "Close once confirmed legitimate or contained.",
    owner: "security",
  },
  suspicious_process: {
    meaning: "A program started a script interpreter in a way typical of malware (e.g. Word launching PowerShell, or encoded PowerShell commands).",
    causes: ["Malicious document or download", "Unusual but legitimate admin script"],
    where: ["Command line below", "The file/email that triggered it", "Other activity on the host"],
    fix: ["Isolate the host if not explained", "Remove the malicious file, scan the machine, reset the user's credentials"],
    verify: "Close after the host is cleaned or the activity is confirmed legitimate.",
    owner: "security",
  },
  lolbin_download: {
    meaning: "A built-in Windows/Linux tool was used to download and run something from the internet — a common attacker technique.",
    causes: ["Malware stage-two download", "Admin installing software in an unusual way"],
    where: ["Command line and URL below", "What was downloaded and executed"],
    fix: ["Block the URL/domain", "Isolate and scan the host if not explained"],
    verify: "Close after investigation.",
    owner: "security",
  },
  new_admin_account: {
    meaning: "An account was created or added to an administrators group.",
    causes: ["Planned access change", "Attacker creating persistence"],
    where: ["Who made the change and whether a ticket exists"],
    fix: ["If unplanned: remove the account/membership, investigate who added it"],
    verify: "Close once confirmed or reverted.",
    owner: "security",
  },
  log_cleared: {
    meaning: "Security logs on a host were cleared. Attackers do this to hide their tracks.",
    causes: ["Attacker covering tracks", "Admin clearing logs (should not happen without a change ticket)"],
    where: ["Who cleared it (account below)", "Forwarded logs in the SOC before the clear"],
    fix: ["Treat the host as suspicious; investigate activity before the clear"],
    verify: "Close after investigation.",
    owner: "security",
  },
  new_service: {
    meaning: "A new system service was installed on a host.",
    causes: ["Software installation", "Malware persistence"],
    where: ["Service name and path below; check it is expected software"],
    fix: ["Remove the service and scan the host if not expected"],
    verify: "Close once confirmed.",
    owner: "security",
  },
  threat_intel_ip: {
    meaning: "A system communicated with an address listed in threat-intelligence feeds (botnet servers, criminal networks).",
    causes: ["Infected machine contacting its controller", "Attack traffic from a known-bad network"],
    where: ["The host and connection below", "Other traffic from/to that IP"],
    fix: ["Block the IP", "Investigate the host if it initiated the connection"],
    verify: "Close after the host is cleared.",
    owner: "security",
  },
  source_silent: {
    meaning: "A log source / agent stopped sending events. Either it broke or someone stopped it.",
    causes: ["Agent stopped or uninstalled", "Network/firewall change", "Server down", "Ingest key rotated"],
    where: ["Agent service status on the machines in this source", "Agent logs (journalctl -u finpay-soc-agent / Windows Application log)"],
    fix: ["Restart or reinstall the agent; check the key and network path"],
    verify: "Verified automatically when events arrive again.",
    owner: "infra",
  },
  auth_failure_surge: {
    meaning: "Failed logins on this host are far above normal. An attack may be starting even if no single source crossed the brute-force threshold.",
    causes: ["Distributed password guessing from many IPs", "Broken client/service account retrying with an old password"],
    where: ["Login failure logs grouped by source IP and account"],
    fix: ["Rate-limit/WAF the login endpoint", "Fix or rotate the broken service account if that is the cause"],
    verify: "Verified when failures return to normal.",
    owner: "security",
  },
  wazuh_alert: {
    meaning: "Wazuh reported a security event on this host.",
    causes: ["See the Wazuh rule description below"],
    where: ["Wazuh dashboard for the agent and rule", "Full log line below"],
    fix: ["Follow the Wazuh rule's recommendation; escalate if it indicates compromise"],
    verify: "Close after investigation.",
    owner: "security",
  },
};

const DEFAULT: Runbook = {
  meaning: "The SOC detected a problem on this system.",
  causes: ["See the description and evidence below"],
  where: ["Logs of the affected system around the first-seen time"],
  fix: ["Investigate and fix the cause, then mark the issue fixed"],
  verify: "The SOC analyst verifies the fix.",
  owner: "security",
};

export function runbookFor(ruleKey: string | null | undefined): Runbook {
  return (ruleKey && R[ruleKey]) || DEFAULT;
}

export const RUNBOOK_KEYS = Object.keys(R);
