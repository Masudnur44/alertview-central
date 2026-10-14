-- Ownership and hand-off: teams own assets, the SOC sends issues (with a diagnosis brief)
-- to the owning team, developers update them by secure link or with a developer login.

-- ---------------------------------------------------------------------------
-- Membership: developers are not SOC members (they never see the SOC console data)
-- ---------------------------------------------------------------------------
create or replace function app.is_member() returns boolean
language sql stable as $$
  select app.has_any_role('{security_admin,security_analyst,security_manager,system_admin,management,auditor}')
$$;

-- ---------------------------------------------------------------------------
-- Teams
-- ---------------------------------------------------------------------------
create table public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  emails text[] not null default '{}',
  telegram_chat_id text,
  whatsapp_numbers text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index teams_name_key on public.teams (lower(name));

alter table public.assets add column team_id uuid references public.teams(id) on delete set null;
alter table public.users add column team_id uuid references public.teams(id) on delete set null;
create index on public.assets (team_id);

create or replace function app.my_team() returns uuid
language sql stable security definer set search_path = public, app as $$
  select team_id from public.users where id = app.current_user_id() and status = 'active'
$$;

create or replace function app.is_developer() returns boolean
language sql stable as $$ select app.has_role('developer') $$;

-- ---------------------------------------------------------------------------
-- Issues: work handed to a team
-- ---------------------------------------------------------------------------
create sequence public.issue_seq;
create table public.issues (
  id uuid primary key default gen_random_uuid(),
  ref text not null unique default ('ISS-' || to_char(now(), 'YYYY') || '-' || lpad(nextval('public.issue_seq')::text, 4, '0')),
  title text not null,
  severity public.severity not null,
  status text not null default 'open' check (status in ('open','acknowledged','in_progress','fixed','verified','wont_fix')),
  team_id uuid references public.teams(id) on delete set null,
  asset_id uuid references public.assets(id) on delete set null,
  alert_id uuid references public.alerts(id) on delete set null,
  incident_id uuid references public.incidents(id) on delete set null,
  dedupe_key text,                     -- the alert condition; used to auto-verify and to reopen
  brief jsonb not null default '{}',   -- diagnosis snapshot sent to developers
  soc_note text,
  created_by uuid references public.users(id) on delete set null,
  created_at timestamptz not null default now(),
  due_at timestamptz,
  acknowledged_at timestamptz,
  fixed_at timestamptz,
  verified_at timestamptz,
  reopened_count int not null default 0,
  updated_at timestamptz not null default now()
);
create index on public.issues (team_id, status);
create index on public.issues (status, due_at);
create index on public.issues (dedupe_key);

create table public.issue_updates (
  id uuid primary key default gen_random_uuid(),
  issue_id uuid not null references public.issues(id) on delete cascade,
  kind text not null default 'comment' check (kind in ('comment','status','system','sent')),
  body text not null,
  author uuid references public.users(id) on delete set null,
  author_label text,                   -- e.g. "Payments team (secure link)" when posted without login
  created_at timestamptz not null default now()
);
create index on public.issue_updates (issue_id, created_at);

-- Secure links: only sha256(token) is stored; one active link per issue.
create table public.issue_links (
  id uuid primary key default gen_random_uuid(),
  issue_id uuid not null references public.issues(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_by uuid references public.users(id) on delete set null,
  created_at timestamptz not null default now()
);

-- Generic outbox for messages to teams (email / Telegram / WhatsApp), delivered by the worker.
create table public.outbox (
  id bigint generated always as identity primary key,
  channel text not null check (channel in ('email','telegram','whatsapp')),
  recipient text not null,
  subject text,
  body text not null,
  html text,
  link text,
  issue_id uuid references public.issues(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','sent','failed')),
  attempts int not null default 0,
  next_attempt_at timestamptz not null default now(),
  last_error text,
  created_at timestamptz not null default now(),
  sent_at timestamptz
);
create index on public.outbox (status, next_attempt_at);

-- SLA due dates and lifecycle timestamps
create or replace function app.issue_defaults() returns trigger
language plpgsql as $$
begin
  if tg_op = 'INSERT' and new.due_at is null then
    new.due_at := now() + case new.severity when 'critical' then interval '4 hours' when 'high' then interval '24 hours'
                               when 'medium' then interval '3 days' else interval '7 days' end;
  end if;
  if tg_op = 'UPDATE' and new.status is distinct from old.status then
    if new.status = 'acknowledged' and new.acknowledged_at is null then new.acknowledged_at := now(); end if;
    if new.status in ('in_progress','fixed','verified') and new.acknowledged_at is null then new.acknowledged_at := now(); end if;
    if new.status = 'fixed' then new.fixed_at := now(); end if;
    if new.status = 'verified' then new.verified_at := now(); if new.fixed_at is null then new.fixed_at := now(); end if; end if;
    if new.status in ('open','acknowledged','in_progress') and old.status in ('fixed','verified') then
      new.reopened_count := old.reopened_count + 1; new.fixed_at := null; new.verified_at := null;
    end if;
  end if;
  return new;
end $$;
create trigger issue_defaults before insert or update on public.issues for each row execute function app.issue_defaults();

do $$ declare t text; begin
  foreach t in array array['teams','issues'] loop
    execute format('create trigger touch_updated_at before update on public.%I for each row execute function app.touch_updated_at()', t);
  end loop;
  foreach t in array array['teams','issues','issue_updates'] loop
    execute format('create trigger audit_row after insert or update or delete on public.%I for each row execute function app.audit_row()', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- Privileges + RLS
-- ---------------------------------------------------------------------------
grant select, insert, update, delete on public.teams, public.issues, public.issue_updates, public.issue_links, public.outbox to soc_app;
grant usage, select on sequence public.issue_seq to soc_app;
grant execute on all functions in schema app to soc_app;

do $$ declare t text; begin
  foreach t in array array['teams','issues','issue_updates','issue_links','outbox'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('alter table public.%I force row level security', t);
    execute format('create policy system_all on public.%I for all to soc_app using (app.is_system()) with check (app.is_system())', t);
  end loop;
end $$;

-- Teams: every SOC member reads; developers read their own team; asset managers edit.
create policy members_read on public.teams for select to soc_app using (app.is_member() or id = app.my_team());
create policy managers_write on public.teams for all to soc_app
  using (app.has_any_role('{security_admin,security_manager,system_admin}'))
  with check (app.has_any_role('{security_admin,security_manager,system_admin}'));

-- Issues: SOC reads all, operators create/update; developers read/update their team's issues.
create policy members_read on public.issues for select to soc_app using (app.is_member());
create policy operators_write on public.issues for insert to soc_app with check (app.can_operate());
create policy operators_update on public.issues for update to soc_app using (app.can_operate()) with check (app.can_operate());
create policy admins_delete on public.issues for delete to soc_app using (app.has_role('security_admin'));
create policy team_read on public.issues for select to soc_app using (app.is_developer() and team_id = app.my_team());
create policy team_update on public.issues for update to soc_app
  using (app.is_developer() and team_id = app.my_team()) with check (app.is_developer() and team_id = app.my_team());

create policy members_read on public.issue_updates for select to soc_app using (app.is_member());
create policy operators_write on public.issue_updates for insert to soc_app with check (app.can_operate());
create policy team_read on public.issue_updates for select to soc_app
  using (app.is_developer() and exists (select 1 from public.issues i where i.id = issue_id and i.team_id = app.my_team()));
create policy team_write on public.issue_updates for insert to soc_app
  with check (app.is_developer() and exists (select 1 from public.issues i where i.id = issue_id and i.team_id = app.my_team()));

create policy operators_links on public.issue_links for all to soc_app using (app.can_operate()) with check (app.can_operate());
create policy admins_read on public.outbox for select to soc_app using (app.has_any_role('{security_admin,security_manager}'));
create policy operators_queue on public.outbox for insert to soc_app with check (app.can_operate());

-- Developers can read their own user row and team assets' names (for the issue view).
create policy team_assets on public.assets for select to soc_app using (app.is_developer() and team_id = app.my_team());

-- ---------------------------------------------------------------------------
-- Monitoring approval simplified: whoever adds an asset approves it.
-- Existing manually added external assets (not demo) are approved by the first admin and monitored.
-- ---------------------------------------------------------------------------
update public.assets a set monitoring_approved = true, monitoring_approved_at = now(),
  monitoring_approved_by = (select r.user_id from public.user_roles r join public.users u on u.id = r.user_id
                            where r.role = 'security_admin' and u.status = 'active' order by u.created_at limit 1),
  monitored = true
where a.discovered_via = 'manual' and a.exposure = 'external' and not ('demo' = any(a.tags)) and not a.monitoring_approved
  and exists (select 1 from public.user_roles r join public.users u on u.id = r.user_id where r.role = 'security_admin' and u.status = 'active');

-- New early-warning detections (raised by the worker before things break).
insert into public.detection_rules (key, name, description, severity, mitre_tactic, mitre_technique, params) values
('latency_degradation', 'Response time degrading', 'An external asset is answering much slower than its normal baseline — often the first sign of an outage', 'medium', 'Early warning', null, '{"factor": 2, "min_ms": 800}'),
('flapping', 'Service unstable (flapping)', 'Asset went down and came back several times in 24 hours — intermittent failures usually precede a full outage', 'medium', 'Early warning', null, '{"failures": 3, "hours": 24}'),
('cert_expiring_soon', 'Certificate renewal due', 'TLS certificate expires within 30 days — renew before it becomes urgent', 'low', 'Early warning', null, '{"days": 30}'),
('auth_failure_surge', 'Failed-login surge', 'Failed logins on a host are far above its normal rate — a brute-force or credential-stuffing campaign may be starting', 'medium', 'Early warning', 'T1110 Brute Force', '{"factor": 3, "min_failures": 20}')
on conflict (key) do nothing;
