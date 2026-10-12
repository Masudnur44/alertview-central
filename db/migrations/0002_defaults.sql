-- Built-in detection rules and default settings (production data, not demo data).
insert into public.detection_rules (key, name, description, severity, mitre_tactic, mitre_technique, params) values
('brute_force', 'Brute-force login', 'Many failed logins from one source IP in a short window', 'high', 'Credential Access', 'T1110 Brute Force', '{"threshold": 10, "window_minutes": 5}'),
('password_spray', 'Password spraying', 'One source IP failing logins against many different accounts', 'high', 'Credential Access', 'T1110.003 Password Spraying', '{"distinct_users": 5, "window_minutes": 10}'),
('brute_force_success', 'Successful login after brute force', 'A login succeeds from an IP that just produced many failures', 'critical', 'Credential Access', 'T1110 Brute Force', '{"failures": 5, "window_minutes": 30}'),
('offhours_privileged_login', 'Off-hours privileged login', 'Privileged account signs in outside business hours', 'critical', 'Privilege Escalation', 'T1078 Valid Accounts', '{"start_hour": 6, "end_hour": 22, "user_pattern": "admin|root|svc_|administrator"}'),
('suspicious_process', 'Suspicious process chain', 'Office or browser process spawning a script interpreter, or encoded PowerShell', 'high', 'Execution', 'T1059 Command and Scripting Interpreter', '{}'),
('lolbin_download', 'Living-off-the-land download', 'certutil/bitsadmin/mshta/regsvr32/curl used to fetch remote payloads', 'high', 'Command and Control', 'T1105 Ingress Tool Transfer', '{}'),
('new_admin_account', 'New privileged account', 'Account created or added to an administrators/sudo group', 'high', 'Persistence', 'T1136 Create Account', '{}'),
('log_cleared', 'Security log cleared', 'Audit or security log was cleared on a host', 'high', 'Defense Evasion', 'T1070.001 Clear Windows Event Logs', '{}'),
('new_service', 'New service installed', 'A new system service was installed on a host', 'medium', 'Persistence', 'T1543.003 Windows Service', '{}'),
('threat_intel_ip', 'Known-malicious IP', 'Event source IP matches a threat-intelligence blocklist', 'high', 'Command and Control', null, '{}'),
('source_silent', 'Event source went silent', 'A source that normally sends events has stopped reporting', 'medium', 'Defense Evasion', 'T1562.001 Disable or Modify Tools', '{"silent_hours": 2}'),
('asset_offline', 'Asset offline', 'Monitored internet-facing asset is unreachable or returning server errors', 'high', 'Impact', 'T1499 Endpoint Denial of Service', '{}'),
('cert_expiring', 'Certificate expiring', 'TLS certificate expires soon', 'medium', null, null, '{"warn_days": 14, "high_days": 3}'),
('cert_invalid', 'Invalid TLS certificate', 'Certificate is expired, self-signed, untrusted or does not match the hostname', 'high', 'Credential Access', 'T1557 Adversary-in-the-Middle', '{}'),
('missing_security_headers', 'Missing security headers', 'HSTS/CSP/X-Frame-Options/X-Content-Type-Options absent on a public site', 'low', null, null, '{}'),
('risky_port_open', 'Risky service exposed', 'Database, remote-desktop or admin port reachable from the internet', 'high', 'Initial Access', 'T1133 External Remote Services', '{"ports": [21, 23, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017]}'),
('new_external_asset', 'New internet-facing asset', 'Previously unknown subdomain found in certificate-transparency logs', 'high', 'Initial Access', 'T1190 Exploit Public-Facing Application', '{}'),
('dns_changed', 'DNS records changed', 'A monitored domain now resolves to different addresses or name servers', 'medium', 'Resource Development', 'T1584.002 DNS Server', '{}'),
('wazuh_alert', 'Wazuh alert', 'Alert forwarded from a Wazuh manager (level 10+ becomes high, 13+ critical)', 'high', null, null, '{"min_level": 7}');

insert into public.settings (key, value) values
('org_name', '"FINPAYTECH"'),
('timezone', '"Africa/Nairobi"'),
('check_interval_minutes', '60'),
('discovery_interval_hours', '24'),
('intel_interval_hours', '24'),
('event_retention_days', '90'),
('check_results_retention_days', '30');
