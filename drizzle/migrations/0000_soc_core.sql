
create type public.app_role as enum ('security_admin','security_analyst','security_manager','system_admin','management','auditor');
create type public.severity as enum ('critical','high','medium','low','info');

create table public.profiles (
  id uuid primary key,
  display_name text,
  email text,
  created_at timestamptz not null default now()
);
grant select, update on public.profiles to authenticated;
grant all on public.profiles to service_role;
alter table public.profiles enable row level security;

create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  role app_role not null,
  unique (user_id, role)
);
grant select on public.user_roles to authenticated;
grant all on public.user_roles to service_role;
alter table public.user_roles enable row level security;

create or replace function public.has_role(_user_id uuid, _role app_role)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role = _role)
$$;
create or replace function public.is_soc_member(_user_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id)
$$;
create or replace function public.can_operate(_user_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id
    and role in ('security_admin','security_analyst','security_manager','system_admin'))
$$;

create policy "members read profiles" on public.profiles for select to authenticated using (public.is_soc_member(auth.uid()) or id = auth.uid());
create policy "own profile update" on public.profiles for update to authenticated using (id = auth.uid());
create policy "own roles read" on public.user_roles for select to authenticated using (user_id = auth.uid() or public.has_role(auth.uid(),'security_admin'));

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name, email)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email,'@',1)), new.email);
  if not exists (select 1 from public.user_roles) then
    insert into public.user_roles (user_id, role) values (new.id, 'security_admin');
  else
    insert into public.user_roles (user_id, role) values (new.id, 'security_analyst');
  end if;
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

create table public.assets (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  asset_type text not null,
  address text,
  environment text not null default 'production',
  owner text,
  criticality severity not null default 'medium',
  status text not null default 'online',
  exposure text not null default 'internal',
  monitored boolean not null default true,
  is_new boolean not null default false,
  tls_expires_at timestamptz,
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table public.alerts (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  severity severity not null,
  status text not null default 'new',
  source text not null,
  asset_id uuid references public.assets(id) on delete set null,
  mitre_tactic text,
  mitre_technique text,
  assignee uuid,
  incident_id uuid,
  detected_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  resolved_at timestamptz
);

create table public.incidents (
  id uuid primary key default gen_random_uuid(),
  ref text not null default ('INC-' || to_char(now(),'YYMMDD') || '-' || substr(gen_random_uuid()::text,1,4)),
  title text not null,
  summary text,
  severity severity not null,
  status text not null default 'new',
  owner uuid,
  opened_at timestamptz not null default now(),
  contained_at timestamptz,
  resolved_at timestamptz,
  closed_at timestamptz
);
alter table public.alerts add constraint alerts_incident_fk foreign key (incident_id) references public.incidents(id) on delete set null;

create table public.incident_events (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  kind text not null default 'note',
  body text not null,
  author uuid,
  created_at timestamptz not null default now()
);

create table public.vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  cve text,
  severity severity not null,
  cvss numeric(3,1),
  asset_id uuid references public.assets(id) on delete cascade,
  status text not null default 'open',
  exploited_in_wild boolean not null default false,
  internet_exposed boolean not null default false,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now()
);

create table public.detection_rules (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  severity severity not null,
  mitre_technique text,
  enabled boolean not null default true,
  hits integer not null default 0
);

create table public.event_sources (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  source_type text not null,
  api_key text not null default encode(gen_random_bytes(24),'hex'),
  last_event_at timestamptz,
  created_at timestamptz not null default now()
);

create table public.events (
  id uuid primary key default gen_random_uuid(),
  source_id uuid references public.event_sources(id) on delete set null,
  event_type text not null,
  host text,
  username text,
  src_ip text,
  outcome text,
  message text,
  raw jsonb,
  occurred_at timestamptz not null default now()
);
create index on public.events (occurred_at desc);
create index on public.events (event_type, src_ip, occurred_at);

create table public.check_results (
  id uuid primary key default gen_random_uuid(),
  asset_id uuid references public.assets(id) on delete cascade,
  check_type text not null,
  ok boolean not null,
  detail text,
  response_ms integer,
  checked_at timestamptz not null default now()
);
create index on public.check_results (checked_at desc);

create table public.audit_log (
  id uuid primary key default gen_random_uuid(),
  actor uuid,
  action text not null,
  target text,
  created_at timestamptz not null default now()
);

do $$ declare t text; begin
  foreach t in array array['assets','alerts','incidents','incident_events','vulnerabilities','detection_rules','events','check_results'] loop
    execute format('grant select, insert, update, delete on public.%I to authenticated', t);
    execute format('grant all on public.%I to service_role', t);
    execute format('alter table public.%I enable row level security', t);
    execute format('create policy "members read" on public.%I for select to authenticated using (public.is_soc_member(auth.uid()))', t);
    execute format('create policy "operators insert" on public.%I for insert to authenticated with check (public.can_operate(auth.uid()))', t);
    execute format('create policy "operators update" on public.%I for update to authenticated using (public.can_operate(auth.uid()))', t);
    execute format('create policy "admins delete" on public.%I for delete to authenticated using (public.has_role(auth.uid(),''security_admin''))', t);
  end loop;
end $$;

grant select, insert, update, delete on public.event_sources to authenticated;
grant all on public.event_sources to service_role;
alter table public.event_sources enable row level security;
create policy "admins manage sources" on public.event_sources for all to authenticated
  using (public.has_role(auth.uid(),'security_admin') or public.has_role(auth.uid(),'system_admin'))
  with check (public.has_role(auth.uid(),'security_admin') or public.has_role(auth.uid(),'system_admin'));

grant select, insert on public.audit_log to authenticated;
grant all on public.audit_log to service_role;
alter table public.audit_log enable row level security;
create policy "audit read" on public.audit_log for select to authenticated using (public.has_role(auth.uid(),'auditor') or public.has_role(auth.uid(),'security_admin') or public.has_role(auth.uid(),'security_manager'));
create policy "audit write own" on public.audit_log for insert to authenticated with check (actor = auth.uid() and public.is_soc_member(auth.uid()));

-- Seed data
insert into public.assets (name, asset_type, address, owner, criticality, status, exposure, is_new, tls_expires_at, last_seen) values
('finpaytech.com','website','https://finpaytech.com','Web Team','high','online','external',false, now()+interval '74 days', now()),
('api.finpaytech.com','api','https://api.finpaytech.com','Payments Eng','critical','online','external',false, now()+interval '12 days', now()),
('portal.finpaytech.com','website','https://portal.finpaytech.com','Customer Ops','critical','online','external',false, now()+interval '140 days', now()),
('staging-api.finpaytech.com','api','https://staging-api.finpaytech.com','Payments Eng','medium','online','external',true, now()+interval '5 days', now()),
('vpn.finpaytech.com','service','vpn.finpaytech.com:443','IT Ops','high','online','external',false, now()+interval '200 days', now()),
('41.90.12.34','ip','41.90.12.34','IT Ops','high','online','external',false,null, now()),
('mail.finpaytech.com','service','mail.finpaytech.com:25','IT Ops','medium','online','external',false, now()+interval '60 days', now()),
('core-db-01','server','10.0.1.10','DBA','critical','online','internal',false,null, now()),
('app-srv-02','server','10.0.2.22','Platform','high','online','internal',false,null, now()),
('app-srv-03','server','10.0.2.23','Platform','high','offline','internal',false,null, now()-interval '3 hours'),
('fw-edge-01','network','10.0.0.1','NetSec','critical','online','internal',false,null, now()),
('ad-dc-01','server','10.0.0.5','IT Ops','critical','online','internal',false,null, now()),
('WS-FIN-014','endpoint','10.0.8.14','Finance','medium','online','internal',false,null, now()),
('WS-ENG-031','endpoint','10.0.8.31','Engineering','medium','online','internal',true,null, now()),
('backup-nas','server','10.0.3.40','IT Ops','high','online','internal',false,null, now()-interval '20 minutes');

insert into public.incidents (ref, title, summary, severity, status, opened_at) values
('INC-2410-01','Brute-force against customer portal','Sustained failed logins from a rotating IP pool targeting portal accounts.','high','triage', now()-interval '5 hours'),
('INC-2410-02','Unexpected admin login on core-db-01','Privileged account used at 02:14 local from a non-standard workstation.','critical','contained', now()-interval '1 day');

insert into public.alerts (title, description, severity, status, source, asset_id, mitre_tactic, mitre_technique, detected_at, incident_id)
select v.title, v.descr, v.sev::severity, v.status, v.src, a.id, v.tactic, v.tech, now() - (v.ago || ' minutes')::interval,
  (select id from public.incidents where ref = v.inc)
from (values
 ('Brute-force login attempts','312 failed logins in 10 min from 185.220.101.0/24','high','investigating','auth','portal.finpaytech.com','Credential Access','T1110 Brute Force',40,'INC-2410-01'),
 ('Privileged login outside business hours','svc_dbadmin logged in at 02:14','critical','escalated','endpoint','core-db-01','Privilege Escalation','T1078 Valid Accounts',1500,'INC-2410-02'),
 ('TLS certificate expires in 12 days','api.finpaytech.com certificate near expiry','medium','new','external','api.finpaytech.com','—',null,90,null),
 ('New internet-facing asset discovered','staging-api.finpaytech.com now publicly reachable','high','new','external','staging-api.finpaytech.com','Initial Access','T1190 Exploit Public-Facing Application',180,null),
 ('Server offline','app-srv-03 stopped responding','high','acknowledged','infrastructure','app-srv-03','Impact','T1499 Endpoint DoS',190,null),
 ('Suspicious PowerShell execution','Encoded command spawned by winword.exe','high','new','endpoint','WS-FIN-014','Execution','T1059.001 PowerShell',25,null),
 ('Missing security headers','CSP and HSTS absent on staging-api','low','new','external','staging-api.finpaytech.com','—',null,170,null),
 ('Spike in API 401 errors','4x baseline unauthorized responses','medium','new','application','api.finpaytech.com','Credential Access','T1110.003 Password Spraying',60,null),
 ('New local admin account created','user "support2" added to Administrators','high','new','endpoint','WS-ENG-031','Persistence','T1136 Create Account',15,null),
 ('Backup job failed','Nightly backup to backup-nas failed','medium','resolved','infrastructure','backup-nas','—',null,600,null),
 ('Port scan from external IP','Scan of 1,024 ports on 41.90.12.34','low','false_positive','external','41.90.12.34','Discovery','T1046 Network Service Discovery',800,null)
) as v(title,descr,sev,status,src,asset,tactic,tech,ago,inc)
left join public.assets a on a.name = v.asset;

insert into public.incident_events (incident_id, kind, body, created_at)
select i.id, e.kind, e.body, now() - (e.ago || ' minutes')::interval from public.incidents i
join (values
 ('INC-2410-01','created','Incident opened from brute-force alert',300),
 ('INC-2410-01','note','Source IPs belong to known Tor exit range. Rate limiting requested.',240),
 ('INC-2410-02','created','Incident opened from privileged-login alert',1500),
 ('INC-2410-02','action','Account svc_dbadmin disabled; host isolated.',1400),
 ('INC-2410-02','status','Status changed to contained',1380)
) as e(ref,kind,body,ago) on e.ref = i.ref;

insert into public.vulnerabilities (title, cve, severity, cvss, asset_id, status, exploited_in_wild, internet_exposed)
select v.t, v.cve, v.s::severity, v.cvss, a.id, v.st, v.kev, v.ext from (values
 ('OpenSSH regreSSHion RCE','CVE-2024-6387','critical',8.1,'vpn.finpaytech.com','open',true,true),
 ('Outdated nginx with HTTP/2 DoS','CVE-2023-44487','high',7.5,'api.finpaytech.com','open',true,true),
 ('PostgreSQL privilege escalation','CVE-2024-10979','high',8.8,'core-db-01','in_progress',false,false),
 ('Windows SMB information disclosure','CVE-2024-43642','medium',7.5,'WS-FIN-014','open',false,false),
 ('jQuery XSS in portal','CVE-2020-11023','medium',6.1,'portal.finpaytech.com','open',true,true),
 ('Weak TLS ciphers enabled',null,'low',3.7,'mail.finpaytech.com','open',false,true),
 ('Exposed .git directory',null,'high',7.5,'staging-api.finpaytech.com','open',false,true)
) as v(t,cve,s,cvss,asset,st,kev,ext) join public.assets a on a.name = v.asset;

insert into public.detection_rules (name, description, severity, mitre_technique, hits) values
('Brute-force login','10+ failed logins from one IP in 5 minutes','high','T1110',14),
('Off-hours privileged login','Admin account login between 22:00 and 06:00','critical','T1078',3),
('New internet-facing asset','Previously unknown asset reachable from internet','high','T1190',2),
('Certificate expiring','TLS certificate expires within 14 days','medium',null,4),
('Asset offline','Monitored asset unreachable','high','T1499',6),
('Suspicious process','Office app spawning a script interpreter','high','T1059',5),
('New admin account','Account added to privileged group','high','T1136',2),
('Missing security headers','HSTS/CSP absent on public site','low',null,7);

insert into public.event_sources (name, source_type) values ('Linux servers (syslog)','server'), ('Windows endpoints','endpoint'), ('Payments API','application');

insert into public.events (event_type, host, username, src_ip, outcome, message, occurred_at)
select 'auth.login', 'portal.finpaytech.com', 'user'||g, '185.220.101.'||(g%20), 'failure', 'Invalid password', now() - (g || ' minutes')::interval from generate_series(1,40) g;
insert into public.events (event_type, host, username, src_ip, outcome, message, occurred_at) values
('auth.login','core-db-01','svc_dbadmin','10.0.8.31','success','Interactive admin login', now()-interval '25 hours'),
('process.start','WS-FIN-014','jdoe',null,'success','winword.exe -> powershell.exe -enc ...', now()-interval '25 minutes'),
('account.created','WS-ENG-031','support2',null,'success','Added to Administrators', now()-interval '15 minutes');

insert into public.check_results (asset_id, check_type, ok, detail, response_ms, checked_at)
select a.id, 'http', a.status='online', case when a.status='online' then '200 OK' else 'timeout' end, (80 + random()*300)::int, now() - (g*15 || ' minutes')::interval
from public.assets a, generate_series(0,7) g where a.exposure='external';
