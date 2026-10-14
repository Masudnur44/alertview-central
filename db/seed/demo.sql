-- FINPAYTECH demo data. Everything here is tagged so db/seed/remove-demo.sql can
-- delete it cleanly once real assets and event sources are connected.
-- Runs as the database owner (bypasses RLS); safe to run once.
begin;

-- Developer teams (description starts with [demo] so remove-demo.sql can find them).
insert into public.teams (name, description) values
('Web Team','[demo] Public website and marketing pages'),
('Payments Engineering','[demo] Payment API, card gateway, settlement'),
('Customer Ops','[demo] Customer portal'),
('IT Operations','[demo] VPN, mail, AD, backups, office network'),
('DBA','[demo] Core databases'),
('Platform','[demo] Application servers and deployment'),
('NetSec','[demo] Firewalls and edge network'),
('Finance IT','[demo] Finance workstations'),
('Engineering IT','[demo] Engineering workstations')
on conflict do nothing;

insert into public.assets (name, asset_type, address, owner, criticality, status, exposure, is_new, tls_expires_at, last_seen, tags, discovered_via) values
('finpaytech.com','website','https://finpaytech.com','Web Team','high','online','external',false, now()+interval '74 days', now(), '{demo}', 'manual'),
('api.finpaytech.com','api','https://api.finpaytech.com','Payments Eng','critical','online','external',false, now()+interval '12 days', now(), '{demo}', 'manual'),
('portal.finpaytech.com','website','https://portal.finpaytech.com','Customer Ops','critical','online','external',false, now()+interval '140 days', now(), '{demo}', 'manual'),
('staging-api.finpaytech.com','api','https://staging-api.finpaytech.com','Payments Eng','medium','online','external',true, now()+interval '5 days', now(), '{demo}', 'ct_log'),
('vpn.finpaytech.com','service','vpn.finpaytech.com:443','IT Ops','high','online','external',false, now()+interval '200 days', now(), '{demo}', 'manual'),
('41.90.12.34','ip','41.90.12.34','IT Ops','high','online','external',false,null, now(), '{demo}', 'manual'),
('mail.finpaytech.com','service','mail.finpaytech.com:25','IT Ops','medium','online','external',false, now()+interval '60 days', now(), '{demo}', 'manual'),
('core-db-01','server','10.0.1.10','DBA','critical','online','internal',false,null, now(), '{demo}', 'agent'),
('app-srv-02','server','10.0.2.22','Platform','high','online','internal',false,null, now(), '{demo}', 'agent'),
('app-srv-03','server','10.0.2.23','Platform','high','offline','internal',false,null, now()-interval '3 hours', '{demo}', 'agent'),
('fw-edge-01','network','10.0.0.1','NetSec','critical','online','internal',false,null, now(), '{demo}', 'manual'),
('ad-dc-01','server','10.0.0.5','IT Ops','critical','online','internal',false,null, now(), '{demo}', 'agent'),
('WS-FIN-014','endpoint','10.0.8.14','Finance','medium','online','internal',false,null, now(), '{demo}', 'agent'),
('WS-ENG-031','endpoint','10.0.8.31','Engineering','medium','online','internal',true,null, now(), '{demo}', 'agent'),
('backup-nas','server','10.0.3.40','IT Ops','high','online','internal',false,null, now()-interval '20 minutes', '{demo}', 'manual');

update public.assets a set team_id = t.id from public.teams t
where 'demo' = any(a.tags) and t.name = case a.owner
  when 'Web Team' then 'Web Team' when 'Payments Eng' then 'Payments Engineering' when 'Customer Ops' then 'Customer Ops'
  when 'IT Ops' then 'IT Operations' when 'DBA' then 'DBA' when 'Platform' then 'Platform' when 'NetSec' then 'NetSec'
  when 'Finance' then 'Finance IT' when 'Engineering' then 'Engineering IT' end;

-- Demo assets are not probed by the real external checks (they are not FINPAYTECH's live hosts yet).
update public.assets set monitored = false where 'demo' = any(tags);

insert into public.incidents (ref, title, summary, severity, status, opened_at, triaged_at) values
('INC-DEMO-0001','Brute-force against customer portal','Sustained failed logins from a rotating IP pool targeting portal accounts.','high','triage', now()-interval '5 hours', now()-interval '4 hours'),
('INC-DEMO-0002','Unexpected admin login on core-db-01','Privileged account used at 02:14 local from a non-standard workstation.','critical','contained', now()-interval '1 day', now()-interval '23 hours');
update public.incidents set contained_at = now()-interval '22 hours' where ref = 'INC-DEMO-0002';

insert into public.alerts (title, description, severity, status, source, asset_id, rule_id, mitre_tactic, mitre_technique, detected_at, last_seen_at, acknowledged_at, incident_id, details)
select v.title, v.descr, v.sev::public.severity, v.status, v.src, a.id, r.id, v.tactic, v.tech,
  now() - (v.ago || ' minutes')::interval, now() - (v.ago || ' minutes')::interval,
  case when v.status <> 'new' then now() - ((v.ago - v.ack) || ' minutes')::interval end,
  (select id from public.incidents where ref = v.inc), '{"demo": true}'::jsonb
from (values
 ('Brute-force login attempts','312 failed logins in 10 min from 185.220.101.0/24','high','investigating','auth','portal.finpaytech.com','brute_force','Credential Access','T1110 Brute Force',40,6,'INC-DEMO-0001'),
 ('Privileged login outside business hours','svc_dbadmin logged in at 02:14','critical','escalated','endpoint','core-db-01','offhours_privileged_login','Privilege Escalation','T1078 Valid Accounts',1500,12,'INC-DEMO-0002'),
 ('TLS certificate expires in 12 days','api.finpaytech.com certificate near expiry','medium','new','external','api.finpaytech.com','cert_expiring',null,null,90,0,null),
 ('New internet-facing asset discovered','staging-api.finpaytech.com now publicly reachable','high','new','external','staging-api.finpaytech.com','new_external_asset','Initial Access','T1190 Exploit Public-Facing Application',180,0,null),
 ('Server offline','app-srv-03 stopped responding','high','acknowledged','infrastructure','app-srv-03','asset_offline','Impact','T1499 Endpoint DoS',190,9,null),
 ('Suspicious PowerShell execution','Encoded command spawned by winword.exe','high','new','endpoint','WS-FIN-014','suspicious_process','Execution','T1059.001 PowerShell',25,0,null),
 ('Missing security headers','CSP and HSTS absent on staging-api','low','new','external','staging-api.finpaytech.com','missing_security_headers',null,null,170,0,null),
 ('Spike in API 401 errors','4x baseline unauthorized responses','medium','new','application','api.finpaytech.com','password_spray','Credential Access','T1110.003 Password Spraying',60,0,null),
 ('New local admin account created','user "support2" added to Administrators','high','new','endpoint','WS-ENG-031','new_admin_account','Persistence','T1136 Create Account',15,0,null),
 ('Backup job failed','Nightly backup to backup-nas failed','medium','resolved','infrastructure','backup-nas',null,null,null,600,30,null),
 ('Port scan from external IP','Scan of 1,024 ports on 41.90.12.34','low','false_positive','external','41.90.12.34',null,'Discovery','T1046 Network Service Discovery',800,45,null)
) as v(title,descr,sev,status,src,asset,rule,tactic,tech,ago,ack,inc)
left join public.assets a on a.name = v.asset
left join public.detection_rules r on r.key = v.rule;

-- Two issues already handed to developers, so the hand-off pages have something to show.
insert into public.issues (title, severity, status, team_id, asset_id, alert_id, dedupe_key, brief, soc_note, created_at, due_at, acknowledged_at)
select v.title, v.sev::public.severity, v.status, t.id, a.id, al.id, v.dk,
  jsonb_build_object(
    'summary', v.title, 'meaning', v.meaning, 'impact', v.impact,
    'where', jsonb_build_array(jsonb_build_object('label','System','value',a.name), jsonb_build_object('label','Address','value',coalesce(a.address,'—'))),
    'when', jsonb_build_array(jsonb_build_object('label','First seen','value',to_char(now() - (v.ago || ' minutes')::interval, 'YYYY-MM-DD HH24:MI'))),
    'evidence', jsonb_build_array(jsonb_build_object('label','Detail','value',v.ev)),
    'checks', '[]'::jsonb, 'events', '[]'::jsonb,
    'causes', to_jsonb(v.causes), 'whereToLook', to_jsonb(v.look), 'fix', to_jsonb(v.fix),
    'verify', 'The SOC closes this automatically once the monitoring no longer sees the problem.', 'technique', null),
  v.note, now() - (v.ago || ' minutes')::interval, now() + (v.due || ' minutes')::interval,
  case when v.status <> 'open' then now() - ((v.ago - 20) || ' minutes')::interval end
from (values
 ('TLS certificate on api.finpaytech.com expires in 12 days','medium','in_progress','Payments Engineering','api.finpaytech.com','TLS certificate expires in 12 days','demo:cert-api',
  'The HTTPS certificate for the payment API is close to expiry.','When it expires, every client and partner calling the API gets a certificate error and payments stop.',
  'api cert expires in 12 days', array['Auto-renewal (certbot/ACME) failing','Certificate bought manually and not tracked'],
  array['Load balancer / nginx TLS config','certbot logs: /var/log/letsencrypt/'], array['Renew the certificate','Reload nginx','Confirm the new expiry date with openssl s_client'],
  'Please renew before the weekend.', 300, 3000),
 ('staging-api.finpaytech.com is publicly reachable with an exposed .git directory','high','open','Payments Engineering','staging-api.finpaytech.com','New internet-facing asset discovered','demo:staging-exposed',
  'A staging server is reachable from the internet and serves its .git folder.','Anyone can download the source code and any secrets committed to it.',
  'GET /.git/HEAD returns 200', array['Staging deployed without the firewall rule','Web root points at the repository folder'],
  array['Web server config for staging-api','Cloud security group / firewall'], array['Block /.git at the web server','Restrict staging to the VPN','Rotate any secrets in the repository history'],
  null, 180, -60)
) as v(title,sev,status,team,asset,alert_title,dk,meaning,impact,ev,causes,look,fix,note,ago,due)
join public.teams t on t.name = v.team
join public.assets a on a.name = v.asset
left join public.alerts al on al.title = v.alert_title and al.asset_id = a.id;

insert into public.issue_updates (issue_id, kind, body, author_label, created_at)
select i.id, u.kind, u.body, u.who, now() - (u.ago || ' minutes')::interval
from public.issues i join (values
 ('demo:cert-api','system','Issue sent to Payments Engineering','SOC',300),
 ('demo:cert-api','status','Status: open → acknowledged','Amina (Payments Engineering, via secure link)',280),
 ('demo:cert-api','status','Status: acknowledged → in_progress','Amina (Payments Engineering, via secure link)',120),
 ('demo:cert-api','comment','certbot renewal was failing because port 80 is closed on the LB. Switching to DNS challenge.','Amina (Payments Engineering, via secure link)',119),
 ('demo:staging-exposed','system','Issue sent to Payments Engineering','SOC',180)
) as u(dk,kind,body,who,ago) on u.dk = i.dedupe_key;

update public.alerts set resolved_at = acknowledged_at + interval '40 minutes'
where status in ('resolved','false_positive') and resolved_at is null and details ->> 'demo' = 'true';

insert into public.incident_events (incident_id, kind, body, created_at)
select i.id, e.kind, e.body, now() - (e.ago || ' minutes')::interval from public.incidents i
join (values
 ('INC-DEMO-0001','created','Incident opened from brute-force alert',300),
 ('INC-DEMO-0001','note','Source IPs belong to known Tor exit range. Rate limiting requested.',240),
 ('INC-DEMO-0002','created','Incident opened from privileged-login alert',1500),
 ('INC-DEMO-0002','action','Account svc_dbadmin disabled; host isolated.',1400),
 ('INC-DEMO-0002','status','Status changed to contained',1380)
) as e(ref,kind,body,ago) on e.ref = i.ref;

insert into public.vulnerabilities (title, cve, severity, cvss, asset_id, status, exploited_in_wild, internet_exposed, remediation)
select v.t, v.cve, v.s::public.severity, v.cvss, a.id, v.st, v.kev, v.ext, v.fix from (values
 ('OpenSSH regreSSHion RCE','CVE-2024-6387','critical',8.1,'vpn.finpaytech.com','open',true,true,'Upgrade OpenSSH to 9.8p1 or later; set LoginGraceTime 0 as a stop-gap.'),
 ('Outdated nginx with HTTP/2 DoS','CVE-2023-44487','high',7.5,'api.finpaytech.com','open',true,true,'Upgrade nginx to 1.25.3+ and limit concurrent HTTP/2 streams.'),
 ('PostgreSQL privilege escalation','CVE-2024-10979','high',8.8,'core-db-01','in_progress',false,false,'Apply PostgreSQL minor release 16.5 / 17.1.'),
 ('Windows SMB information disclosure','CVE-2024-43642','medium',7.5,'WS-FIN-014','open',false,false,'Install the latest Windows cumulative update.'),
 ('jQuery XSS in portal','CVE-2020-11023','medium',6.1,'portal.finpaytech.com','open',true,true,'Upgrade jQuery to 3.5.0+.'),
 ('Weak TLS ciphers enabled',null,'low',3.7,'mail.finpaytech.com','open',false,true,'Disable CBC and 3DES suites; require TLS 1.2+.'),
 ('Exposed .git directory',null,'high',7.5,'staging-api.finpaytech.com','open',false,true,'Block /.git at the web server and rotate any secrets in the repository history.')
) as v(t,cve,s,cvss,asset,st,kev,ext,fix) join public.assets a on a.name = v.asset;

insert into public.events (event_type, host, username, src_ip, outcome, message, occurred_at, raw)
select 'auth.login', 'portal.finpaytech.com', 'user'||g, ('185.220.101.'||(g%20))::inet, 'failure', 'Invalid password',
       now() - (g * 30 || ' minutes')::interval, '{"demo": true}'::jsonb
from generate_series(1,40) g;
insert into public.events (event_type, host, username, src_ip, outcome, message, occurred_at, raw)
select 'auth.login', h, u, ('10.0.8.'||(g%40))::inet, 'success', 'Interactive login', now() - (g * 17 || ' minutes')::interval, '{"demo": true}'::jsonb
from generate_series(1,60) g, (values ('app-srv-02','deploy'),('WS-FIN-014','jdoe')) as x(h,u);
insert into public.events (event_type, host, username, src_ip, outcome, message, occurred_at, raw) values
('auth.login','core-db-01','svc_dbadmin','10.0.8.31','success','Interactive admin login', now()-interval '25 hours', '{"demo": true}'),
('process.start','WS-FIN-014','jdoe',null,'success','winword.exe -> powershell.exe -enc ...', now()-interval '25 minutes', '{"demo": true}'),
('account.created','WS-ENG-031','support2',null,'success','Added to Administrators', now()-interval '15 minutes', '{"demo": true}');

insert into public.check_results (asset_id, check_type, ok, detail, response_ms, checked_at)
select a.id, 'http', a.status='online', case when a.status='online' then '200 OK' else 'timeout' end,
       (80 + random()*300)::int, now() - (g*15 || ' minutes')::interval
from public.assets a, generate_series(0,7) g where a.exposure='external' and 'demo' = any(a.tags);

update public.detection_rules r set hits = x.n, last_hit_at = now() - interval '15 minutes'
from (select rule_id, count(*) n from public.alerts where rule_id is not null group by rule_id) x where x.rule_id = r.id;

commit;
