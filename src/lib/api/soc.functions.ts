// SOC data server functions. Every handler authenticates, checks the permission
// matrix, then runs as the signed-in user so row-level security and audit apply.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import type { Alert, Asset, CheckResult, Incident, IncidentEvent, SocEvent, Vulnerability } from "@/lib/types";

const uuid = z.string().uuid();
const severity = z.enum(["critical", "high", "medium", "low", "info"]);

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------
export const getOverview = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("view");
  return run(async (tx) => {
    const alerts = await tx<Alert[]>`
      select a.id, a.title, a.severity, a.status, a.source, a.detected_at, a.acknowledged_at, a.resolved_at, s.name as asset_name
      from alerts a left join assets s on s.id = a.asset_id
      where a.detected_at > now() - interval '30 days' or a.status not in ('resolved','false_positive','closed')
      order by a.detected_at desc limit 2000`;
    const assets = await tx`select id, status, exposure, is_new, tls_expires_at from assets where status <> 'retired'`;
    const incidents = await tx<Incident[]>`select id, ref, title, severity, status, opened_at from incidents order by opened_at desc limit 200`;
    const vulns = await tx`select id, severity, status, exploited_in_wild, due_at from vulnerabilities`;
    const hourly = await tx`
      select date_trunc('hour', occurred_at) as h, count(*)::int as events, count(*) filter (where outcome = 'failure')::int as failures,
             count(*) filter (where ti_match is not null)::int as ti
      from events where occurred_at > now() - interval '24 hours' group by 1 order by 1`;
    const [sources] = await tx`select count(*)::int as total, count(*) filter (where last_event_at > now() - interval '1 hour')::int as live from event_sources where enabled`;
    const [worker] = await tx`select value as heartbeat from settings where key = 'worker_heartbeat'`;
    return { alerts, assets, incidents, vulns, hourly, sources, workerHeartbeat: (worker?.heartbeat as string | undefined) ?? null };
  });
});

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------
export const listAssets = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("view");
  return run((tx) => tx<Asset[]>`
    select a.*,
      (select count(*)::int from alerts x where x.asset_id = a.id and x.status not in ('resolved','false_positive','closed')) as open_alerts,
      (select count(*)::int from vulnerabilities v where v.asset_id = a.id and v.status not in ('fixed','risk_accepted')) as open_vulns
    from assets a
    order by case a.criticality when 'critical' then 0 when 'high' then 1 when 'medium' then 2 when 'low' then 3 else 4 end, a.name`);
});

const AssetInput = z.object({
  id: uuid.optional(),
  name: z.string().trim().min(1).max(255),
  asset_type: z.enum(["domain", "website", "api", "service", "ip", "server", "endpoint", "network", "cloud", "other"]),
  address: z.string().trim().max(500).optional().nullable(),
  environment: z.string().trim().max(40).default("production"),
  owner: z.string().trim().max(120).optional().nullable(),
  criticality: severity,
  exposure: z.enum(["internal", "external"]),
  monitored: z.boolean().default(true),
  tags: z.array(z.string().trim().max(40)).max(20).default([]),
  notes: z.string().max(4000).optional().nullable(),
  status: z.enum(["online", "offline", "degraded", "unknown", "retired"]).optional(),
  is_new: z.boolean().optional(),
});

export const saveAsset = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => AssetInput.parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("assets.manage");
    if (data.exposure === "external" && data.address && /^https?:\/\//i.test(data.address)) {
      try {
        const u = new URL(data.address);
        if (!["http:", "https:"].includes(u.protocol)) throw new Error();
      } catch {
        throw new Error("Address must be a valid http(s) URL, host, host:port or IP.");
      }
    }
    return run(async (tx) => {
      if (data.id) {
        const [row] = await tx`
          update assets set name = ${data.name}, asset_type = ${data.asset_type}, address = ${data.address ?? null}, environment = ${data.environment},
            owner = ${data.owner ?? null}, criticality = ${data.criticality}, exposure = ${data.exposure}, monitored = ${data.monitored},
            tags = ${data.tags}, notes = ${data.notes ?? null},
            status = coalesce(${data.status ?? null}, status), is_new = coalesce(${data.is_new ?? null}, is_new)
          where id = ${data.id} returning id`;
        if (!row) throw new Error("Asset not found or you cannot edit it.");
        return { id: row.id as string };
      }
      const [row] = await tx`
        insert into assets (name, asset_type, address, environment, owner, criticality, exposure, monitored, tags, notes, discovered_via, status)
        values (${data.name}, ${data.asset_type}, ${data.address ?? null}, ${data.environment}, ${data.owner ?? null}, ${data.criticality},
                ${data.exposure}, ${data.monitored}, ${data.tags}, ${data.notes ?? null}, 'manual', 'unknown')
        returning id`;
      return { id: row!.id as string };
    }).catch((e: Error) => {
      if (/assets_name_key/.test(e.message)) throw new Error("An asset with this name already exists.");
      throw e;
    });
  });

export const deleteAsset = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("data.delete");
    await run((tx) => tx`delete from assets where id = ${data.id}`);
    return { ok: true };
  });

export const getAsset = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ id: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("view");
    return run(async (tx) => {
      const [asset] = await tx<Asset[]>`select * from assets where id = ${data.id}`;
      if (!asset) throw new Error("Asset not found");
      const checks = await tx<CheckResult[]>`select id, asset_id, check_type, ok, detail, response_ms, checked_at from check_results where asset_id = ${data.id} order by checked_at desc limit 200`;
      const alerts = await tx<Alert[]>`select id, title, severity, status, detected_at, mitre_technique from alerts where asset_id = ${data.id} order by detected_at desc limit 50`;
      const vulns = await tx<Vulnerability[]>`select id, title, cve, severity, status, cvss, exploited_in_wild from vulnerabilities where asset_id = ${data.id} order by cvss desc nulls last`;
      const events = await tx<SocEvent[]>`select id::text, event_type, username, host(src_ip) as src_ip, outcome, message, occurred_at from events where lower(host) = lower(${asset.name}) order by occurred_at desc limit 50`;
      return { asset, checks, alerts, vulns, events };
    });
  });

// ---------------------------------------------------------------------------
// External surface
// ---------------------------------------------------------------------------
export const getSurface = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("view");
  return run(async (tx) => {
    const assets = await tx<Asset[]>`select * from assets where exposure = 'external' and status <> 'retired' order by name`;
    const history = await tx<CheckResult[]>`
      select id::text, asset_id, check_type, ok, detail, response_ms, checked_at from (
        select c.*, row_number() over (partition by asset_id, check_type order by checked_at desc) rn
        from check_results c where checked_at > now() - interval '7 days') x
      where rn <= 24 order by checked_at desc`;
    const domains = await tx`select id, domain::text as domain, discover_subdomains, last_discovery_at from monitored_domains order by domain`;
    const jobs = await tx`select distinct on (job) job, started_at, finished_at, ok, detail from job_runs where job in ('checks','discovery') order by job, started_at desc`;
    return { assets, history, domains, jobs };
  });
});

export const runChecksNow = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ assetIds: z.array(uuid).max(200).optional() }).parse(d ?? {}))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("checks.run");
    await run((tx) => tx`select app.audit('checks.run_now', 'assets', null, ${tx.json({ assets: data.assetIds ?? "all" })})`);
    if (data.assetIds?.length) {
      const { runChecks } = await import("@/server/monitor/checks.server");
      return runChecks({ assetIds: data.assetIds });
    }
    const { runJob } = await import("@/server/jobs.server");
    return (await runJob("checks")) as { checked: number; alerts: number; failed: number };
  });

export const saveDomain = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ domain: z.string().trim().toLowerCase().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/, "Enter a domain like finpaytech.com"), discover: z.boolean().default(true) }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("domains.manage");
    await run((tx) => tx`insert into monitored_domains (domain, discover_subdomains) values (${data.domain}, ${data.discover})
                         on conflict (domain) do update set discover_subdomains = excluded.discover_subdomains`);
    return { ok: true };
  });

export const removeDomain = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("domains.manage");
    await run((tx) => tx`delete from monitored_domains where id = ${data.id}`);
    return { ok: true };
  });

export const runDiscoveryNow = createServerFn({ method: "POST" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("domains.manage");
  await run((tx) => tx`select app.audit('discovery.run_now')`);
  const { runJob } = await import("@/server/jobs.server");
  return (await runJob("discovery")) as { domains: number; found: number; added: number; errors: string[] };
});

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
export const listAlerts = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ status: z.string().max(30).default("open"), severity: z.string().max(10).default("all"), q: z.string().max(200).default("") }).parse(d ?? {}))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("view");
    return run((tx) => tx<Alert[]>`
      select a.*, s.name as asset_name, r.name as rule_name, u.display_name as assignee_name, i.ref as incident_ref
      from alerts a
      left join assets s on s.id = a.asset_id
      left join detection_rules r on r.id = a.rule_id
      left join users u on u.id = a.assignee
      left join incidents i on i.id = a.incident_id
      where true
        ${data.status === "open" ? tx`and a.status not in ('resolved','false_positive','closed')`
          : data.status === "all" ? tx`` : tx`and a.status = ${data.status}`}
        ${data.severity === "all" ? tx`` : tx`and a.severity = ${data.severity}::severity`}
        ${data.q ? tx`and (a.title ilike ${"%" + data.q + "%"} or a.description ilike ${"%" + data.q + "%"} or s.name ilike ${"%" + data.q + "%"})` : tx``}
      order by case when a.status in ('resolved','false_positive','closed') then 1 else 0 end,
               app.severity_rank(a.severity) desc, a.last_seen_at desc
      limit 500`);
  });

export const getAlertContext = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ id: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("view");
    return run(async (tx) => {
      const [a] = await tx`select a.*, s.name as asset_name from alerts a left join assets s on s.id = a.asset_id where a.id = ${data.id}`;
      if (!a) throw new Error("Alert not found");
      const d = (a.details ?? {}) as { src_ip?: string; host?: string; username?: string };
      const host = a.asset_name ?? d.host ?? null;
      // Events around the alert from the same host, source IP or account.
      const events = await tx<SocEvent[]>`
        select e.id::text, e.event_type, e.host, e.username, host(e.src_ip) as src_ip, e.outcome, e.message, e.ti_match, e.occurred_at, null as source_name
        from events e
        where e.occurred_at between ${a.detected_at}::timestamptz - interval '2 hours' and ${a.last_seen_at}::timestamptz + interval '30 minutes'
          and (${host}::text is not null and lower(e.host) = lower(${host})
               or ${d.src_ip ?? null}::text is not null and e.src_ip = ${d.src_ip ?? null}::inet
               or ${d.username ?? null}::text is not null and lower(e.username) = lower(${d.username ?? null}))
        order by e.occurred_at desc limit 100`;
      const related = await tx<Alert[]>`
        select id, title, severity, status, detected_at from alerts
        where id <> ${data.id} and (asset_id = ${a.asset_id} or (${d.src_ip ?? null}::text is not null and details->>'src_ip' = ${d.src_ip ?? null}))
          and detected_at > now() - interval '14 days' order by detected_at desc limit 20`;
      const intel = d.src_ip ? await tx`select source, description from threat_indicators where network >>= ${d.src_ip}::inet limit 5` : [];
      return { events, related, intel };
    });
  });

export const updateAlerts = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({
    ids: z.array(uuid).min(1).max(200),
    status: z.enum(["new", "acknowledged", "investigating", "resolved", "false_positive", "closed"]).optional(),
    assignee: uuid.nullable().optional(),
  }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("alerts.triage");
    return run(async (tx) => {
      const rows = await tx`
        update alerts set
          status = coalesce(${data.status ?? null}, status),
          assignee = case when ${data.assignee !== undefined} then ${data.assignee ?? null}::uuid else assignee end
        where id = any(${data.ids}::uuid[]) returning id`;
      if (data.status === "new") {
        await tx`update alerts set resolved_at = null where id = any(${data.ids}::uuid[])`;
      }
      if (data.status === "acknowledged") {
        await tx`update alerts set assignee = coalesce(assignee, ${s.user.id}) where id = any(${data.ids}::uuid[])`;
      }
      return { updated: rows.length };
    });
  });

export const escalateAlerts = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ ids: z.array(uuid).min(1).max(100), incidentId: uuid.optional(), title: z.string().trim().max(200).optional() }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("incidents.manage");
    return run(async (tx) => {
      const alerts = await tx`select id, title, description, severity from alerts where id = any(${data.ids}::uuid[]) order by app.severity_rank(severity) desc`;
      if (!alerts.length) throw new Error("No alerts found");
      let incidentId = data.incidentId;
      let ref: string;
      if (!incidentId) {
        const lead = alerts[0]!;
        const [inc] = await tx`
          insert into incidents (title, summary, severity, owner, status)
          values (${data.title || lead.title}, ${lead.description}, ${lead.severity}, ${s.user.id}, 'triage') returning id, ref`;
        incidentId = inc!.id as string;
        ref = inc!.ref as string;
        await tx`insert into incident_events (incident_id, kind, body, author) values (${incidentId}, 'created', ${`Incident opened from ${alerts.length} alert(s): ${alerts.map((a) => a.title).join("; ")}`}, ${s.user.id})`;
      } else {
        const [inc] = await tx`select ref from incidents where id = ${incidentId}`;
        if (!inc) throw new Error("Incident not found");
        ref = inc.ref as string;
        await tx`insert into incident_events (incident_id, kind, body, author) values (${incidentId}, 'alert_linked', ${`Linked: ${alerts.map((a) => a.title).join("; ")}`}, ${s.user.id})`;
        // Raise incident severity if a more severe alert joins.
        await tx`update incidents set severity = ${alerts[0]!.severity} where id = ${incidentId} and app.severity_rank(severity) < app.severity_rank(${alerts[0]!.severity}::severity)`;
      }
      await tx`update alerts set status = 'escalated', incident_id = ${incidentId}, assignee = coalesce(assignee, ${s.user.id}) where id = any(${data.ids}::uuid[])`;
      return { incidentId, ref };
    });
  });

export const listTeam = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("view");
  return run((tx) => tx<{ id: string; display_name: string; email: string }[]>`
    select u.id, u.display_name, u.email from users u
    where u.status = 'active' and exists (select 1 from user_roles r where r.user_id = u.id and r.role in ('security_admin','security_analyst','security_manager','system_admin'))
    order by u.display_name`);
});

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------
export const listIncidents = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("view");
  return run((tx) => tx<Incident[]>`
    select i.*, u.display_name as owner_name, (select count(*)::int from alerts a where a.incident_id = i.id) as alert_count
    from incidents i left join users u on u.id = i.owner
    order by case when i.status in ('resolved','closed') then 1 else 0 end, i.opened_at desc limit 500`);
});

export const getIncident = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ id: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("view");
    return run(async (tx) => {
      const [incident] = await tx<Incident[]>`select i.*, u.display_name as owner_name from incidents i left join users u on u.id = i.owner where i.id = ${data.id}`;
      if (!incident) throw new Error("Incident not found");
      const events = await tx<IncidentEvent[]>`
        select e.id, e.kind, e.body, e.created_at, u.display_name as author_name
        from incident_events e left join users u on u.id = e.author where e.incident_id = ${data.id} order by e.created_at desc`;
      const alerts = await tx<Alert[]>`
        select a.id, a.title, a.severity, a.status, a.mitre_technique, a.mitre_tactic, a.detected_at, s.name as asset_name, a.asset_id
        from alerts a left join assets s on s.id = a.asset_id where a.incident_id = ${data.id} order by a.detected_at`;
      const vulns = await tx<Vulnerability[]>`
        select v.id, v.title, v.cve, v.severity, v.status, s.name as asset_name from vulnerabilities v join assets s on s.id = v.asset_id
        where v.asset_id in (select asset_id from alerts where incident_id = ${data.id} and asset_id is not null) and v.status not in ('fixed','risk_accepted')`;
      return { incident, events, alerts, vulns };
    });
  });

export const createIncident = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ title: z.string().trim().min(3).max(200), summary: z.string().max(4000).optional(), severity }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("incidents.manage");
    return run(async (tx) => {
      const [inc] = await tx`insert into incidents (title, summary, severity, owner) values (${data.title}, ${data.summary ?? null}, ${data.severity}, ${s.user.id}) returning id, ref`;
      await tx`insert into incident_events (incident_id, kind, body, author) values (${inc!.id}, 'created', 'Incident opened manually', ${s.user.id})`;
      return { id: inc!.id as string, ref: inc!.ref as string };
    });
  });

export const updateIncident = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({
    id: uuid,
    status: z.enum(["new", "triage", "contained", "resolved", "closed"]).optional(),
    severity: severity.optional(),
    owner: uuid.nullable().optional(),
    summary: z.string().max(4000).optional(),
  }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("incidents.manage");
    return run(async (tx) => {
      const [before] = await tx`select status, owner, severity from incidents where id = ${data.id}`;
      if (!before) throw new Error("Incident not found");
      if (data.status === "closed" && before.status !== "resolved") throw new Error("Resolve the incident before closing it.");
      await tx`
        update incidents set status = coalesce(${data.status ?? null}, status), severity = coalesce(${data.severity ?? null}::severity, severity),
          owner = case when ${data.owner !== undefined} then ${data.owner ?? null}::uuid else owner end,
          summary = coalesce(${data.summary ?? null}, summary)
        where id = ${data.id}`;
      if (data.status && data.status !== before.status) {
        await tx`insert into incident_events (incident_id, kind, body, author) values (${data.id}, 'status', ${`Status changed from ${before.status} to ${data.status}`}, ${s.user.id})`;
        if (data.status === "resolved" || data.status === "closed") {
          await tx`update alerts set status = 'resolved' where incident_id = ${data.id} and status not in ('resolved','false_positive','closed')`;
        }
      }
      if (data.owner !== undefined && data.owner !== before.owner) {
        const [u] = data.owner ? await tx`select display_name from users where id = ${data.owner}` : [];
        await tx`insert into incident_events (incident_id, kind, body, author) values (${data.id}, 'owner', ${`Owner set to ${u?.display_name ?? "nobody"}`}, ${s.user.id})`;
      }
      return { ok: true };
    });
  });

export const addIncidentEvent = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid, kind: z.enum(["note", "action", "evidence"]), body: z.string().trim().min(1).max(10000) }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("incidents.manage");
    await run((tx) => tx`insert into incident_events (incident_id, kind, body, author) values (${data.id}, ${data.kind}, ${data.body}, ${s.user.id})`);
    return { ok: true };
  });

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------
export const listVulns = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("view");
  return run((tx) => tx<Vulnerability[]>`
    select v.*, v.cvss::float8 as cvss, s.name as asset_name, s.criticality as asset_criticality,
      (select count(*)::int from alerts a where a.asset_id = v.asset_id and a.status not in ('resolved','false_positive','closed')) as open_alerts
    from vulnerabilities v left join assets s on s.id = v.asset_id`);
});

const VulnInput = z.object({
  id: uuid.optional(),
  title: z.string().trim().min(3).max(300),
  cve: z.string().trim().toUpperCase().regex(/^CVE-\d{4}-\d{4,}$/, "CVE format: CVE-2024-12345").optional().nullable().or(z.literal("").transform(() => null)),
  description: z.string().max(4000).optional().nullable(),
  remediation: z.string().max(4000).optional().nullable(),
  severity,
  cvss: z.number().min(0).max(10).optional().nullable(),
  asset_id: uuid.nullable(),
  internet_exposed: z.boolean().default(false),
  status: z.enum(["open", "in_progress", "risk_accepted", "fixed"]).default("open"),
});

export const saveVuln = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => VulnInput.parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("vulns.manage");
    return run(async (tx) => {
      if (data.id) {
        await tx`update vulnerabilities set title = ${data.title}, cve = ${data.cve ?? null}, description = ${data.description ?? null},
                   remediation = ${data.remediation ?? null}, severity = ${data.severity}, cvss = ${data.cvss ?? null}, asset_id = ${data.asset_id},
                   internet_exposed = ${data.internet_exposed}, status = ${data.status}, last_seen = now() where id = ${data.id}`;
        return { id: data.id };
      }
      const [row] = await tx`
        insert into vulnerabilities (title, cve, description, remediation, severity, cvss, asset_id, internet_exposed, status)
        values (${data.title}, ${data.cve ?? null}, ${data.description ?? null}, ${data.remediation ?? null}, ${data.severity}, ${data.cvss ?? null},
                ${data.asset_id}, ${data.internet_exposed}, ${data.status}) returning id`;
      return { id: row!.id as string };
    });
  });

export const setVulnStatus = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid, status: z.enum(["open", "in_progress", "risk_accepted", "fixed"]) }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("vulns.manage");
    await run((tx) => tx`update vulnerabilities set status = ${data.status}, fixed_at = case when ${data.status} = 'fixed' then coalesce(fixed_at, now()) else null end where id = ${data.id}`);
    return { ok: true };
  });

// ---------------------------------------------------------------------------
// Activity
// ---------------------------------------------------------------------------
export const listEvents = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({
    q: z.string().max(200).default(""),
    type: z.string().max(64).default(""),
    outcome: z.enum(["", "success", "failure", "unknown"]).default(""),
    tiOnly: z.boolean().default(false),
    before: z.string().max(40).optional(),
  }).parse(d ?? {}))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("view");
    return run(async (tx) => {
      const like = `%${data.q}%`;
      const rows = await tx<SocEvent[]>`
        select e.id::text, e.event_type, e.host, e.username, host(e.src_ip) as src_ip, e.outcome, e.message, e.ti_match, e.occurred_at, s.name as source_name
        from events e left join event_sources s on s.id = e.source_id
        where true
          ${data.q ? tx`and (e.host ilike ${like} or e.username ilike ${like} or host(e.src_ip) like ${like} or e.message ilike ${like})` : tx``}
          ${data.type ? tx`and e.event_type = ${data.type}` : tx``}
          ${data.outcome ? tx`and e.outcome = ${data.outcome}` : tx``}
          ${data.tiOnly ? tx`and e.ti_match is not null` : tx``}
          ${data.before ? tx`and e.occurred_at < ${data.before}::timestamptz` : tx``}
        order by e.occurred_at desc limit 300`;
      const types = await tx`select distinct event_type from events where occurred_at > now() - interval '7 days' order by 1 limit 100`;
      return { rows, types: types.map((t) => t.event_type as string) };
    });
  });

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------
export const getReport = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ days: z.number().int().min(1).max(366) }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("view");
    return run(async (tx) => {
      const since = () => tx`now() - make_interval(days => ${data.days})`;
      const [m] = await tx`
        select count(*)::int as alerts,
          count(*) filter (where status = 'false_positive')::int as false_positives,
          round(avg(extract(epoch from acknowledged_at - detected_at) / 60) filter (where acknowledged_at is not null))::int as mtta_min,
          round(avg(extract(epoch from resolved_at - detected_at) / 60) filter (where resolved_at is not null))::int as mttr_min
        from alerts where detected_at > ${since()}`;
      const [inc] = await tx`
        select count(*)::int as opened, count(*) filter (where status in ('resolved','closed'))::int as closed,
          round((avg(extract(epoch from contained_at - opened_at)) filter (where contained_at is not null) / 3600)::numeric, 1)::float8 as mttc_hours
        from incidents where opened_at > ${since()}`;
      const bySeverity = await tx`select severity::text as s, count(*)::int as n from alerts where detected_at > ${since()} group by 1`;
      const bySource = await tx`select source as s, count(*)::int as n from alerts where detected_at > ${since()} group by 1 order by 2 desc`;
      const byTechnique = await tx`select coalesce(mitre_technique, 'unmapped') as s, count(*)::int as n from alerts where detected_at > ${since()} group by 1 order by 2 desc limit 10`;
      const topAssets = await tx`select s.name as s, count(*)::int as n from alerts a join assets s on s.id = a.asset_id where a.detected_at > ${since()} group by 1 order by 2 desc limit 10`;
      const daily = await tx`select date_trunc('day', detected_at)::date::text as d, count(*)::int as n from alerts where detected_at > ${since()} group by 1 order by 1`;
      const [cov] = await tx`select count(*)::int as total, count(*) filter (where monitored)::int as monitored,
                               count(*) filter (where exposure = 'external')::int as external from assets where status <> 'retired'`;
      const [vul] = await tx`select count(*) filter (where status not in ('fixed','risk_accepted'))::int as open,
          count(*) filter (where severity = 'critical' and status not in ('fixed','risk_accepted'))::int as critical_open,
          count(*) filter (where status not in ('fixed','risk_accepted') and due_at < now())::int as overdue,
          count(*) filter (where status = 'fixed' and fixed_at > ${since()})::int as fixed_in_period
        from vulnerabilities`;
      const [ev] = await tx`select count(*)::int as events, count(*) filter (where ti_match is not null)::int as ti_hits from events where occurred_at > ${since()}`;
      await tx`select app.audit('report.viewed', 'report', ${String(data.days)})`;
      return { metrics: m, incidents: inc, bySeverity, bySource, byTechnique, topAssets, daily, coverage: cov, vulns: vul, events: ev };
    });
  });
