// Event intake: per-source keys (stored hashed), optional IP allow-lists, rate limits, size limits.
import net from "node:net";
import { z } from "zod";
import { asSystem } from "./db.server";
import { env } from "./env.server";
import { sha256 } from "./crypto.server";
import { rateLimit } from "./ratelimit.server";
import { ingestEvents } from "./detect.server";
import { loadRules, raiseAlert } from "./alerts.server";
import { wazuhSeverity, wazuhToEvent, type WazuhAlert } from "./detect-rules";

const MAX_BODY = 1_000_000; // 1 MB

const Event = z.object({
  event_type: z.string().min(1).max(64).regex(/^[a-z0-9_.-]+$/i),
  host: z.string().max(255).optional().nullable(),
  username: z.string().max(128).optional().nullable(),
  src_ip: z.string().max(64).optional().nullable(),
  outcome: z.enum(["success", "failure", "unknown"]).optional().nullable(),
  message: z.string().max(4000).optional().nullable(),
  occurred_at: z.string().datetime({ offset: true }).optional(),
  raw: z.record(z.string(), z.unknown()).optional(),
});
const Body = z.union([Event, z.object({ events: z.array(Event).min(1).max(500) })]);

type Source = { id: string; name: string; source_type: string; allowed_cidrs: string[] };

function json(status: number, body: unknown, extra: Record<string, string> = {}) {
  return Response.json(body, { status, headers: { "cache-control": "no-store", ...extra } });
}

function clientIpFrom(request: Request): string | null {
  if (env().TRUST_PROXY) {
    const fwd = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
    if (fwd && net.isIP(fwd)) return fwd;
    const real = request.headers.get("x-real-ip");
    if (real && net.isIP(real)) return real;
  }
  return null;
}

async function authenticate(request: Request): Promise<{ source: Source; ip: string | null } | Response> {
  const auth = request.headers.get("authorization");
  const key = request.headers.get("x-soc-key") ?? (auth?.startsWith("Bearer ") ? auth.slice(7) : null);
  const ip = clientIpFrom(request);
  if (!rateLimit(`ingest-auth:${ip ?? "unknown"}`, 120, 60_000).ok) return json(429, { error: "too many requests" });
  if (!key || key.length < 20 || key.length > 100) return json(401, { error: "missing or invalid key" });
  const [source] = await asSystem((tx) => tx<Source[]>`
    select id, name, source_type, allowed_cidrs::text[] as allowed_cidrs from event_sources where key_hash = ${sha256(key)} and enabled`);
  if (!source) return json(401, { error: "missing or invalid key" });
  if (source.allowed_cidrs.length) {
    const allowed = ip ? await asSystem((tx) => tx`select ${ip}::inet <<= any(${source.allowed_cidrs}::cidr[]) as ok`) : [];
    if (!allowed[0]?.ok) return json(403, { error: "source address not allowed for this key" });
  }
  return { source, ip };
}

async function readJson(request: Request): Promise<unknown | Response> {
  const len = Number(request.headers.get("content-length") ?? 0);
  if (len > MAX_BODY) return json(413, { error: "payload too large (max 1 MB)" });
  const text = await request.text();
  if (text.length > MAX_BODY) return json(413, { error: "payload too large (max 1 MB)" });
  try {
    return JSON.parse(text);
  } catch {
    return json(400, { error: "body must be JSON" });
  }
}

export async function handleIngest(request: Request): Promise<Response> {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const parsed = Body.safeParse(body);
  if (!parsed.success) return json(400, { error: "invalid payload", issues: parsed.error.issues.slice(0, 5).map((i) => `${i.path.join(".")}: ${i.message}`) });
  const events = "events" in parsed.data ? parsed.data.events : [parsed.data];
  const limit = rateLimit(`ingest:${auth.source.id}`, env().INGEST_RATE_PER_MINUTE, 60_000);
  if (!limit.ok) return json(429, { error: "rate limit exceeded for this source" }, { "retry-after": String(limit.retryAfter) });
  // Count events, not requests, against the per-minute budget.
  for (let i = 1; i < events.length; i++) rateLimit(`ingest:${auth.source.id}`, env().INGEST_RATE_PER_MINUTE, 60_000);

  const result = await asSystem(
    (tx) => ingestEvents(tx, events, { sourceId: auth.source.id, autoRegisterHosts: ["server", "endpoint", "wazuh"].includes(auth.source.source_type) }),
    auth.ip,
  );
  return json(200, result);
}

/** Wazuh integration: accepts a Wazuh alert (or {alerts:[...]}) from the custom integration script. */
export async function handleWazuh(request: Request): Promise<Response> {
  const auth = await authenticate(request);
  if (auth instanceof Response) return auth;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const alerts = (Array.isArray((body as { alerts?: unknown }).alerts) ? (body as { alerts: WazuhAlert[] }).alerts : [body as WazuhAlert]).slice(0, 200);
  if (!alerts.every((a) => a && typeof a === "object" && a.rule)) return json(400, { error: "expected a Wazuh alert object" });
  if (!rateLimit(`ingest:${auth.source.id}`, env().INGEST_RATE_PER_MINUTE, 60_000).ok) return json(429, { error: "rate limit exceeded" });

  const result = await asSystem(async (tx) => {
    const ingested = await ingestEvents(tx, alerts.map(wazuhToEvent), { sourceId: auth.source.id, autoRegisterHosts: true });
    const rules = await loadRules(tx);
    const minLevel = Number((rules.get("wazuh_alert")?.params as { min_level?: number } | undefined)?.min_level ?? 7);
    let opened = 0;
    for (const a of alerts) {
      const level = Number(a.rule?.level ?? 0);
      if (level < minLevel) continue;
      const host = a.agent?.name ?? "unknown agent";
      const [asset] = await tx`select id from assets where lower(name) = lower(${host})`;
      if (await raiseAlert(tx, rules, {
        rule: "wazuh_alert",
        title: `${a.rule?.description ?? "Wazuh alert"} on ${host}`,
        description: a.full_log?.slice(0, 2000),
        severity: wazuhSeverity(level),
        source: "wazuh",
        assetId: asset?.id ?? null,
        dedupeKey: `wazuh:${a.rule?.id ?? "x"}:${host.toLowerCase()}`,
        technique: a.rule?.mitre?.id?.length ? `${a.rule.mitre.id[0]} ${a.rule.mitre.technique?.[0] ?? ""}`.trim() : null,
        tactic: a.rule?.mitre?.tactic?.[0] ?? null,
        details: { wazuh_rule: a.rule?.id, level, agent: a.agent, groups: a.rule?.groups },
      })) opened++;
    }
    return { accepted: ingested.accepted, alerts: ingested.alerts + opened };
  }, auth.ip);
  return json(200, result);
}
