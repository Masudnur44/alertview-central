-- Removes everything db/seed/demo.sql created. Real data is untouched.
begin;
delete from public.events where raw ->> 'demo' = 'true';
delete from public.alerts where details ->> 'demo' = 'true';
delete from public.incidents where ref like 'INC-DEMO-%';
delete from public.assets where 'demo' = any(tags);  -- cascades to vulnerabilities and check results
update public.detection_rules set hits = 0, last_hit_at = null;
commit;
