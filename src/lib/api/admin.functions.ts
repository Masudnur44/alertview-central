// Administration: team & access, event sources, detection rules, notification channels,
// threat intel, platform settings and the audit trail.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import type { TeamMember } from "@/lib/types";

const uuid = z.string().uuid();
const severity = z.enum(["critical", "high", "medium", "low", "info"]);
const role = z.enum(["security_admin", "security_analyst", "security_manager", "system_admin", "management", "auditor"]);

// ---------------------------------------------------------------------------
// Team & access
// ---------------------------------------------------------------------------
export const listUsers = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("users.manage");
  return run((tx) => tx<TeamMember[]>`
    select u.id, u.email::text, u.display_name, u.status, u.email_verified, u.mfa_enabled, u.last_login_at, u.created_at, u.approved_at,
           coalesce(array_agg(r.role::text order by r.role) filter (where r.role is not null), '{}') as roles
    from users u left join user_roles r on r.user_id = u.id
    group by u.id order by (u.status = 'pending') desc, u.created_at`);
});

export const setUserAccess = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid, status: z.enum(["active", "disabled"]).optional(), roles: z.array(role).max(6).optional() }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("users.manage");
    if (data.id === s.user.id) throw new Error("You cannot change your own access. Ask another Security Administrator.");
    return run(async (tx) => {
      if (data.roles) {
        if (data.status === "active" && !data.roles.length) throw new Error("Give the user at least one role before approving.");
        await tx`delete from user_roles where user_id = ${data.id} and not (role = any(${data.roles}::app_role[]))`;
        for (const r of data.roles) {
          await tx`insert into user_roles (user_id, role, granted_by) values (${data.id}, ${r}, ${s.user.id}) on conflict do nothing`;
        }
      }
      if (data.status) {
        const [before] = await tx`select status from users where id = ${data.id}`;
        if (!before) throw new Error("User not found");
        await tx`update users set status = ${data.status},
                   approved_by = case when ${data.status} = 'active' and approved_at is null then ${s.user.id}::uuid else approved_by end,
                   approved_at = case when ${data.status} = 'active' and approved_at is null then now() else approved_at end
                 where id = ${data.id}`;
        if (data.status === "disabled") await tx`delete from sessions where user_id = ${data.id}`;
      }
      return { ok: true };
    });
  });

export const adminUserAction = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid, action: z.enum(["reset_link", "revoke_sessions", "reset_mfa", "unlock"]) }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("users.manage");
    if (data.id === s.user.id && data.action !== "revoke_sessions") throw new Error("Use your Account page for your own account.");
    const { adminResetLink } = await import("@/server/auth.server");
    return run(async (tx) => {
      const [u] = await tx`select id from users where id = ${data.id}`;
      if (!u) throw new Error("User not found");
      switch (data.action) {
        case "reset_link": {
          const link = await adminResetLink(tx, data.id);
          await tx`select app.audit('user.reset_link_issued', 'users', ${data.id})`;
          return { link };
        }
        case "revoke_sessions":
          await tx`delete from sessions where user_id = ${data.id}`;
          await tx`select app.audit('user.sessions_revoked', 'users', ${data.id})`;
          return { ok: true };
        case "reset_mfa":
          await tx`update users set mfa_enabled = false, mfa_secret = null, mfa_recovery_codes = '{}' where id = ${data.id}`;
          await tx`delete from sessions where user_id = ${data.id}`;
          return { ok: true };
        case "unlock":
          await tx`update users set failed_logins = 0, locked_until = null where id = ${data.id}`;
          await tx`select app.audit('user.unlocked', 'users', ${data.id})`;
          return { ok: true };
      }
    });
  });

// ---------------------------------------------------------------------------
// Event sources
// ---------------------------------------------------------------------------
export const listSources = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("sources.manage");
  return run((tx) => tx`
    select id, name, source_type, key_prefix, enabled, allowed_cidrs::text[] as allowed_cidrs, event_count::text, last_event_at, created_at
    from event_sources order by created_at`);
});

const cidr = z.string().trim().regex(/^[0-9a-f.:]+(\/\d{1,3})?$/i, "Use CIDR notation like 41.90.12.0/24");

export const createSource = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({
    name: z.string().trim().min(2).max(120),
    source_type: z.enum(["server", "endpoint", "application", "network", "wazuh", "cloud", "other"]),
    allowed_cidrs: z.array(cidr).max(50).default([]),
  }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("sources.manage");
    const { newIngestKey } = await import("@/server/crypto.server");
    const k = newIngestKey();
    await run(async (tx) => {
      await tx`insert into event_sources (name, source_type, key_hash, key_prefix, allowed_cidrs, created_by)
               values (${data.name}, ${data.source_type}, ${k.hash}, ${k.prefix}, ${data.allowed_cidrs}::cidr[], ${s.user.id})`;
    });
    // The full key is returned exactly once and never stored.
    return { key: k.key };
  });

export const updateSource = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid, enabled: z.boolean().optional(), rotate: z.boolean().optional(), allowed_cidrs: z.array(cidr).max(50).optional(), remove: z.boolean().optional() }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("sources.manage");
    const { newIngestKey } = await import("@/server/crypto.server");
    return run(async (tx) => {
      if (data.remove) {
        await tx`delete from event_sources where id = ${data.id}`;
        return { key: null };
      }
      let key: string | null = null;
      if (data.rotate) {
        const k = newIngestKey();
        key = k.key;
        await tx`update event_sources set key_hash = ${k.hash}, key_prefix = ${k.prefix} where id = ${data.id}`;
        await tx`select app.audit('source.key_rotated', 'event_sources', ${data.id})`;
      }
      if (data.enabled !== undefined) await tx`update event_sources set enabled = ${data.enabled} where id = ${data.id}`;
      if (data.allowed_cidrs) await tx`update event_sources set allowed_cidrs = ${data.allowed_cidrs}::cidr[] where id = ${data.id}`;
      return { key };
    });
  });

// ---------------------------------------------------------------------------
// Detection rules
// ---------------------------------------------------------------------------
export const listRules = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("view");
  return run((tx) => tx`
    select id, key, name, description, severity, mitre_tactic, mitre_technique, params, enabled, hits, last_hit_at
    from detection_rules order by app.severity_rank(severity) desc, name`);
});

export const updateRule = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({
    id: uuid,
    enabled: z.boolean().optional(),
    severity: severity.optional(),
    params: z.record(z.string(), z.union([z.number(), z.string().max(300), z.array(z.number().int().min(1).max(65535)).max(100)])).optional(),
  }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("rules.manage");
    if (data.params) {
      const pattern = data.params.user_pattern;
      if (typeof pattern === "string") {
        try { new RegExp(pattern); } catch { throw new Error("User pattern is not a valid regular expression."); }
      }
    }
    await run((tx) => tx`
      update detection_rules set enabled = coalesce(${data.enabled ?? null}, enabled), severity = coalesce(${data.severity ?? null}::severity, severity),
        params = case when ${data.params ? true : false} then params || ${tx.json((data.params ?? {}) as never)} else params end
      where id = ${data.id}`);
    return { ok: true };
  });

// ---------------------------------------------------------------------------
// Notification channels
// ---------------------------------------------------------------------------
const ChannelConfig = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("email"), to: z.array(z.string().email()).min(1).max(20) }),
  z.object({ kind: z.literal("slack"), webhook_url: z.string().url().startsWith("https://") }),
  z.object({ kind: z.literal("teams"), webhook_url: z.string().url().startsWith("https://") }),
  z.object({ kind: z.literal("telegram"), bot_token: z.string().regex(/^\d+:[A-Za-z0-9_-]{30,}$/, "Bot token looks wrong"), chat_id: z.string().regex(/^-?\d+$|^@\w+$/) }),
  z.object({ kind: z.literal("webhook"), url: z.string().url().startsWith("https://"), secret: z.string().min(16).max(200).optional() }),
]);

export const listChannels = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("channels.manage");
  const { openConfig, describeConfig } = await import("@/server/notify.server");
  const rows = await run((tx) => tx`
    select c.id, c.name, c.kind, c.config, c.min_severity, c.enabled, c.last_sent_at, c.last_error,
      (select count(*)::int from notifications n where n.channel_id = c.id and n.status = 'sent' and n.sent_at > now() - interval '7 days') as sent_7d,
      (select count(*)::int from notifications n where n.channel_id = c.id and n.status = 'failed') as failed
    from notification_channels c order by c.created_at`);
  return rows.map(({ config, ...r }) => {
    let target = "unreadable (APP_SECRET changed?)";
    try { target = describeConfig(openConfig(config)); } catch { /* keep message */ }
    return { ...r, target };
  });
});

export const saveChannel = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid.optional(), name: z.string().trim().min(2).max(80), min_severity: severity, enabled: z.boolean().default(true), config: ChannelConfig.optional() }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("channels.manage");
    const { sealConfig } = await import("@/server/notify.server");
    if (!data.id && !data.config) throw new Error("Channel settings are required.");
    return run(async (tx) => {
      if (data.id) {
        await tx`update notification_channels set name = ${data.name}, min_severity = ${data.min_severity}, enabled = ${data.enabled},
                   config = coalesce(${data.config ? tx.json(sealConfig(data.config) as never) : null}::jsonb, config),
                   kind = coalesce(${data.config?.kind ?? null}, kind)
                 where id = ${data.id}`;
        return { id: data.id };
      }
      const [row] = await tx`insert into notification_channels (name, kind, config, min_severity, enabled)
                             values (${data.name}, ${data.config!.kind}, ${tx.json(sealConfig(data.config!) as never)}, ${data.min_severity}, ${data.enabled}) returning id`;
      return { id: row!.id as string };
    });
  });

export const deleteChannel = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("channels.manage");
    await run((tx) => tx`delete from notification_channels where id = ${data.id}`);
    return { ok: true };
  });

export const testChannel = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("channels.manage");
    const { openConfig, deliver } = await import("@/server/notify.server");
    const [row] = await run((tx) => tx`select config from notification_channels where id = ${data.id}`);
    if (!row) throw new Error("Channel not found");
    await deliver(openConfig(row.config), {
      id: "00000000-0000-0000-0000-000000000000",
      title: "Test notification from FINPAY SOC",
      description: `Sent by ${s.user.displayName}. If you can read this, the channel works.`,
      severity: "info",
      source: "platform",
      asset: null,
      technique: null,
      detected_at: new Date().toISOString(),
    });
    await run((tx) => tx`select app.audit('channel.tested', 'notification_channels', ${data.id})`);
    return { ok: true };
  });

// ---------------------------------------------------------------------------
// Threat intel + jobs + platform settings
// ---------------------------------------------------------------------------
export const getPlatformStatus = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("view");
  const { FEEDS } = await import("@/server/intel.server");
  const { smtpConfigured, googleConfigured, env } = await import("@/server/env.server");
  const data = await run(async (tx) => {
    const intel = await tx`select source, count(*)::int as n, max(last_seen) as refreshed from threat_indicators group by source`;
    const jobs = await tx`select distinct on (job) job, started_at, finished_at, ok, detail from job_runs order by job, started_at desc`;
    const settings = await tx`select key, value from settings where key not in ('worker_heartbeat')`;
    const [hb] = await tx`select value from settings where key = 'worker_heartbeat'`;
    return { intel, jobs, settings: Object.fromEntries(settings.map((r) => [r.key, r.value])), workerHeartbeat: (hb?.value as string | undefined) ?? null };
  });
  const e = env();
  return {
    ...data,
    feeds: FEEDS.map((f) => ({ source: f.source, label: f.label })),
    config: {
      smtp: smtpConfigured(), google: googleConfigured(), requireMfa: e.REQUIRE_MFA, allowedDomains: e.ALLOWED_EMAIL_DOMAINS,
      allowSignup: e.ALLOW_SIGNUP, appUrl: e.APP_URL, allowPrivateTargets: e.ALLOW_PRIVATE_TARGETS,
    },
  };
});

export const refreshIntelNow = createServerFn({ method: "POST" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("intel.manage");
  await run((tx) => tx`select app.audit('intel.refresh_now')`);
  const { runJob } = await import("@/server/jobs.server");
  return (await runJob("intel")) as Record<string, number | string>;
});

const SettingsInput = z.object({
  org_name: z.string().trim().min(1).max(80).optional(),
  timezone: z.string().refine((tz) => { try { new Intl.DateTimeFormat("en", { timeZone: tz }); return true; } catch { return false; } }, "Unknown time zone").optional(),
  check_interval_minutes: z.number().int().min(5).max(1440).optional(),
  discovery_interval_hours: z.number().int().min(1).max(168).optional(),
  intel_interval_hours: z.number().int().min(1).max(168).optional(),
  event_retention_days: z.number().int().min(7).max(3650).optional(),
  check_results_retention_days: z.number().int().min(7).max(3650).optional(),
});

export const updateSettings = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => SettingsInput.parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("settings.manage");
    await run(async (tx) => {
      for (const [key, value] of Object.entries(data)) {
        if (value === undefined) continue;
        await tx`insert into settings (key, value, updated_by) values (${key}, ${tx.json(value as never)}, ${s.user.id})
                 on conflict (key) do update set value = excluded.value, updated_by = excluded.updated_by, updated_at = now()`;
      }
    });
    return { ok: true };
  });

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------
export const listAudit = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ q: z.string().max(200).default(""), before: z.number().int().optional() }).parse(d ?? {}))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("audit.view");
    return run((tx) => tx`
      select id::int, at, actor_email, action, target_type, target_id, detail, ip
      from audit_log
      where true
        ${data.q ? tx`and (action ilike ${"%" + data.q + "%"} or actor_email ilike ${"%" + data.q + "%"} or target_id ilike ${"%" + data.q + "%"})` : tx``}
        ${data.before ? tx`and id < ${data.before}` : tx``}
      order by id desc limit 200`);
  });

export const verifyAuditChain = createServerFn({ method: "POST" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("audit.view");
  return run(async (tx) => {
    const [r] = await tx`select app.audit_verify() as broken, (select count(*)::int from audit_log) as total`;
    await tx`select app.audit('audit.chain_verified', null, null, ${tx.json({ intact: r!.broken === null })})`;
    return { intact: r!.broken === null, brokenAt: r!.broken as string | null, total: r!.total as number };
  });
});

export const exportAudit = createServerFn({ method: "POST" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("audit.view");
  return run(async (tx) => {
    await tx`select app.audit('audit.exported')`;
    return tx`select id::int, at, actor_email, action, target_type, target_id, detail::text, ip, hash from audit_log order by id desc limit 50000`;
  });
});
