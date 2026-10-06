import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";

type Admin = SupabaseClient<Database>;
type Sev = Database["public"]["Enums"]["severity"];

async function raise(db: Admin, a: { title: string; description: string; severity: Sev; source: string; asset_id?: string | null; rule: string; technique?: string; tactic?: string }) {
  // dedupe: skip if an open alert with same title/asset exists in last 24h
  const since = new Date(Date.now() - 864e5).toISOString();
  let q = db.from("alerts").select("id").eq("title", a.title).gte("detected_at", since).not("status", "in", "(resolved,false_positive,closed)");
  q = a.asset_id ? q.eq("asset_id", a.asset_id) : q.is("asset_id", null);
  const { data } = await q.limit(1);
  if (data?.length) return false;
  const { data: rule } = await db.from("detection_rules").select("id,hits,enabled").eq("name", a.rule).maybeSingle();
  if (rule && !rule.enabled) return false;
  await db.from("alerts").insert({
    title: a.title, description: a.description, severity: a.severity, source: a.source,
    asset_id: a.asset_id ?? null, mitre_technique: a.technique ?? null, mitre_tactic: a.tactic ?? null,
  });
  if (rule) await db.from("detection_rules").update({ hits: rule.hits + 1 }).eq("id", rule.id);
  return true;
}

export async function runChecks(db: Admin) {
  const { data: assets } = await db.from("assets").select("*").eq("exposure", "external").eq("monitored", true);
  let alerts = 0, checked = 0;
  for (const a of assets ?? []) {
    if (!a.address?.startsWith("http")) continue;
    checked++;
    const t0 = Date.now();
    let ok = false, detail = "", headers: Headers | null = null;
    try {
      const r = await fetch(a.address, { method: "GET", redirect: "follow", signal: AbortSignal.timeout(10000) });
      ok = r.status < 500;
      detail = `${r.status} ${r.statusText}`;
      headers = r.headers;
    } catch (e) {
      detail = (e as Error).name === "TimeoutError" ? "timeout" : "unreachable";
    }
    const ms = Date.now() - t0;
    await db.from("check_results").insert({ asset_id: a.id, check_type: "http", ok, detail, response_ms: ok ? ms : null });
    await db.from("assets").update(ok ? { status: "online", last_seen: new Date().toISOString() } : { status: "offline" }).eq("id", a.id);
    if (!ok && (await raise(db, { title: `Asset offline: ${a.name}`, description: `External check failed (${detail})`, severity: "high", source: "external", asset_id: a.id, rule: "Asset offline", technique: "T1499 Endpoint DoS", tactic: "Impact" }))) alerts++;
    if (headers) {
      const missing = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"].filter((h) => !headers!.has(h));
      await db.from("check_results").insert({ asset_id: a.id, check_type: "headers", ok: missing.length === 0, detail: missing.length ? `Missing: ${missing.join(", ")}` : "All present" });
      if (missing.length && (await raise(db, { title: `Missing security headers: ${a.name}`, description: missing.join(", "), severity: "low", source: "external", asset_id: a.id, rule: "Missing security headers" }))) alerts++;
    }
    if (a.tls_expires_at) {
      const days = Math.round((new Date(a.tls_expires_at).getTime() - Date.now()) / 864e5);
      if (days < 14 && (await raise(db, { title: `TLS certificate expires in ${days} days`, description: `${a.name} certificate near expiry`, severity: days < 3 ? "high" : "medium", source: "external", asset_id: a.id, rule: "Certificate expiring" }))) alerts++;
    }
  }
  return { checked, alerts };
}

type Ev = { event_type: string; host?: string | null; username?: string | null; src_ip?: string | null; outcome?: string | null; message?: string | null; occurred_at?: string };

export async function detect(db: Admin, events: Ev[]) {
  let alerts = 0;
  const { data: assets } = await db.from("assets").select("id,name");
  const assetId = (h?: string | null) => assets?.find((a) => a.name === h)?.id ?? null;
  for (const e of events) {
    if (e.event_type === "auth.login" && e.outcome === "failure" && e.src_ip) {
      const since = new Date(Date.now() - 5 * 60000).toISOString();
      const { count } = await db.from("events").select("id", { count: "exact", head: true }).eq("event_type", "auth.login").eq("outcome", "failure").eq("src_ip", e.src_ip).gte("occurred_at", since);
      if ((count ?? 0) >= 10 && (await raise(db, { title: `Brute-force login attempts from ${e.src_ip}`, description: `${count} failed logins in 5 minutes on ${e.host ?? "unknown"}`, severity: "high", source: "auth", asset_id: assetId(e.host), rule: "Brute-force login", technique: "T1110 Brute Force", tactic: "Credential Access" }))) alerts++;
    }
    if (e.event_type === "auth.login" && e.outcome === "success" && e.username && /admin|root|svc_/i.test(e.username)) {
      const h = new Date(e.occurred_at ?? Date.now()).getUTCHours() + 3; // EAT
      const hr = h % 24;
      if ((hr >= 22 || hr < 6) && (await raise(db, { title: `Privileged login outside business hours: ${e.username}`, description: `${e.username} on ${e.host} from ${e.src_ip ?? "?"}`, severity: "critical", source: "auth", asset_id: assetId(e.host), rule: "Off-hours privileged login", technique: "T1078 Valid Accounts", tactic: "Privilege Escalation" }))) alerts++;
    }
    if (e.event_type === "process.start" && /(winword|excel|outlook).*(powershell|cmd|wscript|mshta)/i.test(e.message ?? "")) {
      if (await raise(db, { title: `Suspicious process on ${e.host}`, description: e.message ?? "", severity: "high", source: "endpoint", asset_id: assetId(e.host), rule: "Suspicious process", technique: "T1059 Command and Scripting Interpreter", tactic: "Execution" })) alerts++;
    }
    if (e.event_type === "account.created" && /admin/i.test(e.message ?? "")) {
      if (await raise(db, { title: `New privileged account on ${e.host}: ${e.username}`, description: e.message ?? "", severity: "high", source: "endpoint", asset_id: assetId(e.host), rule: "New admin account", technique: "T1136 Create Account", tactic: "Persistence" })) alerts++;
    }
  }
  return alerts;
}
