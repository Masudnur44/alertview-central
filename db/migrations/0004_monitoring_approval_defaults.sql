-- Follow-up to 0003: make "not monitored" the default so the approval gate holds everywhere.
--  * New assets (manual, discovered, agent-registered, demo seed) start unmonitored until approved.
--  * Assets that were monitored before 0003 but never approved are switched off now; otherwise
--    any later UPDATE on them (agent last_seen, edits) would be rejected by the approval trigger.
alter table public.assets alter column monitored set default false;

update public.assets set monitored = false where monitored and not monitoring_approved;
