// Event intake + detection. Used by /api/public/ingest, the Wazuh endpoint and tests.
import type { Tx } from "./db.server";
import { loadRules, raiseAlert, type Rule } from "./alerts.server";
import { matchSingleEvent, type IncomingEvent } from "./detect-rules";
import net from "node:net";

type Stored = IncomingEvent & { ti_match: string | null };

async function settingString(tx: Tx, key: string, fallback: string): Promise<string> {
  const [row] = await tx`select value from settings where key = ${key}`;
  return typeof row?.value === "string" ? row.value : fallback;
}

/** Look up which source IPs appear in threat-intel feeds. */
export async function threatMatches(tx: Tx, ips: string[]): Promise<Map<string, string>> {
  const valid = [...new Set(ips.filter((ip) => net.isIP(ip)))];
  if (!valid.length) return new Map();
  const rows = await tx`
    select distinct on (ip) host(ip) as ip, ti.source
    from unnest(${valid}::inet[]) as ip
    join threat_indicators ti on ti.network is not null and ti.network >>= ip
    order by ip, ti.source`;
  return new Map(rows.map((r) => [String(r.ip), String(r.source)]));
}

/** Keep the inventory current: known hosts get last_seen, unknown agent hosts are registered. */
async function touchHosts(tx: Tx, hosts: string[], autoRegister: boolean): Promise<Map<string, string>> {
  const names = [...new Set(hosts.filter(Boolean).map((h) => h.toLowerCase()))].slice(0, 500);
  if (!names.length) return new Map();
  if (autoRegister) {
    await tx`
      insert into assets (name, asset_type, exposure, status, discovered_via, is_new, last_seen, monitored)
      select h, 'server', 'internal', 'online', 'agent', true, now(), false from unnest(${names}::text[]) h
      on conflict (lower(name)) do nothing`;
  }
  const rows = await tx`
    update assets set last_seen = now(), status = case when exposure = 'internal' then 'online' else status end
    where lower(name) = any(${names}) returning id, lower(name) as name`;
  return new Map(rows.map((r) => [r.name as string, r.id as string]));
}

export type IngestOptions = { sourceId: string | null; autoRegisterHosts?: boolean };

export async function ingestEvents(tx: Tx, events: IncomingEvent[], opts: IngestOptions): Promise<{ accepted: number; alerts: number }> {
  const rules = await loadRules(tx);
  const tz = await settingString(tx, "timezone", "Africa/Nairobi");
  const ti = await threatMatches(tx, events.map((e) => e.src_ip ?? "").filter(Boolean));
  const stored: Stored[] = events.map((e) => ({ ...e, src_ip: e.src_ip && net.isIP(e.src_ip) ? e.src_ip : null, ti_match: e.src_ip ? ti.get(e.src_ip) ?? null : null }));

  const rows = stored.map((e) => ({
    source_id: opts.sourceId,
    event_type: e.event_type.toLowerCase(),
    host: e.host ?? null,
    username: e.username ?? null,
    src_ip: e.src_ip ?? null,
    outcome: e.outcome ?? null,
    message: e.message ?? null,
    raw: e.raw ? JSON.stringify(e.raw) : null,
    ti_match: e.ti_match,
    occurred_at: e.occurred_at ?? new Date().toISOString(),
  }));
  await tx`
    insert into events (source_id, event_type, host, username, src_ip, outcome, message, raw, ti_match, occurred_at)
    select * from unnest(
      ${rows.map((r) => r.source_id)}::uuid[], ${rows.map((r) => r.event_type)}::text[], ${rows.map((r) => r.host)}::text[],
      ${rows.map((r) => r.username)}::text[], ${rows.map((r) => r.src_ip)}::inet[], ${rows.map((r) => r.outcome)}::text[],
      ${rows.map((r) => r.message)}::text[], ${rows.map((r) => r.raw)}::jsonb[], ${rows.map((r) => r.ti_match)}::text[],
      ${rows.map((r) => r.occurred_at)}::timestamptz[])`;

  if (opts.sourceId) {
    await tx`update event_sources set last_event_at = now(), event_count = event_count + ${rows.length} where id = ${opts.sourceId}`;
  }
  const assetIds = await touchHosts(tx, stored.map((e) => e.host ?? ""), opts.autoRegisterHosts ?? false);
  const alerts = await detect(tx, stored, rules, tz, assetIds);
  return { accepted: rows.length, alerts };
}

async function detect(tx: Tx, events: Stored[], rules: Map<string, Rule>, tz: string, assetIds: Map<string, string>): Promise<number> {
  let opened = 0;
  const assetOf = (host?: string | null) => (host ? assetIds.get(host.toLowerCase()) ?? null : null);
  const params = Object.fromEntries([...rules.values()].map((r) => [r.key, r.params]));
  const num = (key: string, p: string, d: number) => Number((rules.get(key)?.params as Record<string, unknown> | undefined)?.[p] ?? d);

  // 1) Single-event rules
  for (const e of events) {
    for (const m of matchSingleEvent(e, params, tz)) {
      if (await raiseAlert(tx, rules, { rule: m.rule, title: m.title, description: m.description, source: sourceFor(e), assetId: assetOf(e.host), dedupeKey: m.dedupeKey, severity: m.severity, details: { username: e.username, src_ip: e.src_ip, host: e.host } })) opened++;
    }
  }

  // 2) Threat-intel hits
  const tiIps = new Map<string, Stored>();
  for (const e of events) if (e.ti_match && e.src_ip) tiIps.set(e.src_ip, e);
  for (const [ip, e] of tiIps) {
    const tor = e.ti_match === "tor_exit";
    if (await raiseAlert(tx, rules, {
      rule: "threat_intel_ip",
      title: tor ? `Activity from Tor exit node ${ip}` : `Activity from known-malicious IP ${ip}`,
      description: `${e.event_type} on ${e.host ?? "unknown host"} from ${ip}, listed by ${e.ti_match}.`,
      severity: tor ? "medium" : undefined,
      source: sourceFor(e), assetId: assetOf(e.host), dedupeKey: `ti:${ip}`, details: { feed: e.ti_match, src_ip: ip },
    })) opened++;
  }

  // 3) Aggregates over recent history (the batch is already stored)
  const failIps = [...new Set(events.filter((e) => e.event_type.toLowerCase() === "auth.login" && e.outcome === "failure" && e.src_ip).map((e) => e.src_ip!))];
  if (failIps.length) {
    const bfWin = num("brute_force", "window_minutes", 5);
    const spWin = num("password_spray", "window_minutes", 10);
    const stats = await tx`
      select host(src_ip) as ip,
             count(*) filter (where occurred_at > now() - make_interval(mins => ${bfWin}))::int as fails,
             count(distinct lower(username)) filter (where occurred_at > now() - make_interval(mins => ${spWin}))::int as users,
             (array_agg(host order by occurred_at desc))[1] as host
      from events
      where event_type = 'auth.login' and outcome = 'failure' and src_ip = any(${failIps}::inet[])
        and occurred_at > now() - make_interval(mins => ${Math.max(bfWin, spWin)})
      group by src_ip`;
    for (const s of stats) {
      if (s.fails >= num("brute_force", "threshold", 10) &&
        (await raiseAlert(tx, rules, { rule: "brute_force", title: `Brute-force login attempts from ${s.ip}`, description: `${s.fails} failed logins in ${bfWin} minutes on ${s.host ?? "unknown host"}.`, source: "auth", assetId: assetOf(s.host), dedupeKey: `bf:${s.ip}`, details: { src_ip: s.ip, failures: s.fails } }))) opened++;
      if (s.users >= num("password_spray", "distinct_users", 5) &&
        (await raiseAlert(tx, rules, { rule: "password_spray", title: `Password spraying from ${s.ip}`, description: `${s.users} different accounts failed from one address in ${spWin} minutes.`, source: "auth", assetId: assetOf(s.host), dedupeKey: `spray:${s.ip}`, details: { src_ip: s.ip, accounts: s.users } }))) opened++;
    }
  }

  const successes = events.filter((e) => e.event_type.toLowerCase() === "auth.login" && e.outcome === "success" && e.src_ip);
  if (successes.length) {
    const win = num("brute_force_success", "window_minutes", 30);
    const rows = await tx`
      select host(src_ip) as ip, count(*)::int as fails from events
      where event_type = 'auth.login' and outcome = 'failure' and src_ip = any(${[...new Set(successes.map((e) => e.src_ip!))]}::inet[])
        and occurred_at > now() - make_interval(mins => ${win})
      group by src_ip`;
    const fails = new Map(rows.map((r) => [r.ip as string, r.fails as number]));
    for (const e of successes) {
      const n = fails.get(e.src_ip!) ?? 0;
      if (n >= num("brute_force_success", "failures", 5) &&
        (await raiseAlert(tx, rules, { rule: "brute_force_success", title: `Successful login after brute force: ${e.username ?? "unknown"} from ${e.src_ip}`, description: `${n} failures from ${e.src_ip} in ${win} minutes, then a successful login to ${e.host ?? "unknown host"}. Treat the account as compromised until verified.`, source: "auth", assetId: assetOf(e.host), dedupeKey: `bfs:${e.src_ip}:${(e.username ?? "").toLowerCase()}`, details: { src_ip: e.src_ip, username: e.username, failures: n } }))) opened++;
    }
  }
  return opened;
}

function sourceFor(e: IncomingEvent): string {
  const t = e.event_type.toLowerCase();
  if (t.startsWith("auth.")) return "auth";
  if (t.startsWith("wazuh.")) return "wazuh";
  if (t.startsWith("app.")) return "application";
  if (t.startsWith("network.")) return "network";
  return "endpoint";
}

/** Sources that normally report but have gone quiet — an agent may have been stopped. */
export async function checkSilentSources(tx: Tx): Promise<number> {
  const rules = await loadRules(tx);
  const hours = Number((rules.get("source_silent")?.params as Record<string, unknown> | undefined)?.silent_hours ?? 2);
  const rows = await tx`
    select id, name, last_event_at from event_sources
    where enabled and event_count > 0 and last_event_at < now() - make_interval(hours => ${hours})`;
  let opened = 0;
  for (const s of rows) {
    if (await raiseAlert(tx, rules, { rule: "source_silent", title: `Event source silent: ${s.name}`, description: `No events since ${s.last_event_at}. The agent or log forwarder may be stopped, blocked or tampered with.`, source: "platform", dedupeKey: `silent:${s.id}` })) opened++;
  }
  // Clear alerts for sources that are reporting again.
  await tx`
    update alerts a set status = 'resolved', details = coalesce(a.details, '{}'::jsonb) || '{"auto_resolved":"source reporting again"}'
    from event_sources s
    where a.dedupe_key = 'silent:' || s.id::text and a.status in ('new','acknowledged') and s.last_event_at > now() - make_interval(hours => ${hours})`;
  return opened;
}
