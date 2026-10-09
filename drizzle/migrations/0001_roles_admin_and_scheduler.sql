create extension if not exists pg_cron;
create extension if not exists pg_net;

create table public.scheduler_token (id int primary key default 1, token text not null default encode(extensions.gen_random_bytes(32),'hex'));
grant all on public.scheduler_token to service_role;
alter table public.scheduler_token enable row level security;
insert into public.scheduler_token (id) values (1);

grant insert, update, delete on public.user_roles to authenticated;
create policy "admins add roles" on public.user_roles for insert to authenticated with check (public.has_role(auth.uid(),'security_admin'));
create policy "admins change roles" on public.user_roles for update to authenticated using (public.has_role(auth.uid(),'security_admin')) with check (public.has_role(auth.uid(),'security_admin'));
create policy "admins remove roles" on public.user_roles for delete to authenticated using (public.has_role(auth.uid(),'security_admin') and user_id <> auth.uid());