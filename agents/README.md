# Connecting machines to FINPAY SOC

Create a source per group of machines under **Settings → Event sources** (e.g. "Linux servers", "Windows laptops"), copy its key, and install the matching agent. Each agent sends a heartbeat every few minutes; if a source goes quiet for 2 hours the SOC raises *Event source silent* (an attacker stopping the agent is itself a signal).

## Linux (`agents/linux`)

Python 3, no dependencies. Reads journald (or `/var/log/auth.log` / `/var/log/secure`).

```sh
sudo ./install.sh --url https://soc.finpaytech.com --key soc_xxxxxxxx
systemctl status finpay-soc-agent
```

Sends: SSH logins (success/failure/invalid users), sudo commands, sudo auth failures, new accounts, additions to `sudo`/`wheel`/`admin`/`docker` groups. Events are spooled to `/var/lib/finpay-soc-agent` while the SOC is unreachable. Config: `/etc/finpay-soc-agent.json` (root-only).

## Windows (`agents/windows`)

PowerShell 5.1+. In an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Url https://soc.finpaytech.com -Key soc_xxxxxxxx
```

Creates the scheduled task *FINPAY SOC Agent* (every minute, as SYSTEM), stores the key in `C:\ProgramData\FinpaySocAgent` (SYSTEM/Administrators only) and enables the needed audit policies. Sends: logons 4624/4625, account creation 4720, privileged group changes 4728/4732/4756, log cleared 1102, new services 7045, and suspicious process starts 4688 (script interpreters, LOLBins, anything launched by Office or a browser).

For many machines, deploy the same two files with Group Policy, Intune or your RMM tool.

## Wazuh (`agents/wazuh`)

If FINPAYTECH already runs Wazuh, forward its alerts instead of (or as well as) installing these agents:

```sh
cp custom-finpay-soc.py /var/ossec/integrations/custom-finpay-soc
chown root:wazuh /var/ossec/integrations/custom-finpay-soc && chmod 750 /var/ossec/integrations/custom-finpay-soc
```

Add to `/var/ossec/etc/ossec.conf` and restart the manager:

```xml
<integration>
  <name>custom-finpay-soc</name>
  <hook_url>https://soc.finpaytech.com/api/public/wazuh</hook_url>
  <api_key>soc_xxxxxxxx</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Wazuh level ≥ 7 becomes an alert (10+ high, 13+ critical); authentication events also feed the SOC's own brute-force detections.

## Anything else (applications, firewalls, cloud)

POST JSON to `/api/public/ingest` with header `x-soc-key`:

```json
{ "events": [
  { "event_type": "auth.login", "host": "payments-api", "username": "jdoe", "src_ip": "203.0.113.7", "outcome": "failure",
    "message": "invalid password", "occurred_at": "2026-10-12T08:15:00Z" }
] }
```

| Field | Notes |
| --- | --- |
| `event_type` | `auth.login`, `process.start`, `account.created`, `group.member_added`, `log.cleared`, `service.installed`, or your own (`app.payment_declined`, `network.connection`…) |
| `outcome` | `success`, `failure` or `unknown` |
| `raw` | Any extra JSON (`command_line`, `parent_image`… are used by detections) |

Limits: 500 events / 1 MB per request; per-source rate limit (`INGEST_RATE_PER_MINUTE`).
