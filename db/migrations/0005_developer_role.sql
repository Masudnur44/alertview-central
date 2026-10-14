-- Developers: log in to see and update only the issues handed to their team.
-- (Enum values must be committed before use, so this migration stands alone.)
alter type public.app_role add value if not exists 'developer';
