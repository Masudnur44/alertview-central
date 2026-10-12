-- FINPAYTECH demo data. Everything here is tagged so db/seed/remove-demo.sql can
-- delete it cleanly once real assets and event sources are connected.
-- Runs as the database owner (bypasses RLS); safe to run once.
begin;

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
