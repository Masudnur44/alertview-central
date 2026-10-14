-- Explicit authorization gate for active external monitoring.
-- Existing assets remain unapproved until an authorized user reviews their scope.
alter table public.assets
  add column monitoring_approved boolean not null default false,
  add column monitoring_approved_by uuid references public.users(id) on delete set null,
  add column monitoring_approved_at timestamptz;

alter table public.assets
  add constraint assets_monitoring_approval_consistent
  check ((monitoring_approved and monitoring_approved_by is not null and monitoring_approved_at is not null)
      or (not monitoring_approved and monitoring_approved_by is null and monitoring_approved_at is null));

create or replace function app.enforce_monitoring_approval() returns trigger
language plpgsql as $$
begin
  if not new.monitoring_approved and new.monitored and tg_op = 'UPDATE' and old.monitoring_approved then
    new.monitored := false;
  elsif new.monitored and not new.monitoring_approved then
    raise exception 'asset monitoring requires explicit approval';
  end if;
  if not new.monitoring_approved then
    new.monitoring_approved_by := null;
    new.monitoring_approved_at := null;
  end if;
  return new;
end $$;

create trigger assets_monitoring_approval
before insert or update on public.assets
for each row execute function app.enforce_monitoring_approval();
