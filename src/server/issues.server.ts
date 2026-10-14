// Issues: hand a problem to the team that owns it, with a diagnosis brief so the developer
// does not have to search for what is wrong, where, and how to fix it.
import type { Tx } from "./db.server";
import { env } from "./env.server";
import { randomToken, sha256 } from "./crypto.server";
import { escapeHtml } from "./mail.server";
import { runbookFor } from "./runbooks";
import type { Severity } from "./alerts.server";

export type { Brief } from "@/lib/types";
import type { Brief, DevIssue } from "@/lib/types";

const fmt = (d: string | Date | null | undefined) => (d ? new Date(d).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "—");

function impactText(sev: string, criticality: string | null, exposure: string | null): string {
  const exposed = exposure === "external" ? "internet-facing" : "internal";
  const crit = criticality ?? "unknown";
  if (sev === "critical") return `Critical: active compromise or outage risk on a ${crit}-criticality ${exposed} system. Act now.`;
  if (sev === "high") return `High: likely customer impact or serious security exposure on a ${crit}-criticality ${exposed} system. Fix today.`;
  if (sev === "medium") return `Medium: degraded service or a weakness on a ${crit}-criticality ${exposed} system. Fix within days, before it gets worse.`;
  return `Low: hygiene / early warning on a ${crit}-criticality ${exposed} system. Schedule a fix.`;
}

/** Collects everything known about an alert into a self-contained brief. */
export async function buildBrief(tx: Tx, alertId: string, note?: string | null): Promise<{ brief: Brief; alert: Record<string, any> }> {
  const [a] = await tx`
    select a.*, r.key as rule_key, r.name as rule_name,
           s.name as asset_name, s.address, s.environment, s.criticality as asset_criticality, s.exposure, s.tls_expires_at, s.tls_issuer,
           s.tls_subject, s.http_status, s.response_ms, s.open_ports, s.dns, s.last_seen, s.last_checked_at, s.status as asset_status,
           t.name as team_name
    from alerts a
    left join detection_rules r on r.id = a.rule_id
    left join assets s on s.id = a.asset_id
    left join teams t on t.id = s.team_id
    where a.id = ${alertId}`;
  if (!a) throw new Error("Alert not found");
  const rb = runbookFor(a.rule_key);
  const d = (a.details ?? {}) as Record<string, unknown>;

  const where = [
    { label: "System", value: a.asset_name ?? (d.host as string) ?? "—" },
    { label: "Address", value: a.address ?? "—" },
    { label: "Environment", value: a.environment ?? "—" },
    { label: "Owner team", value: a.team_name ?? "not assigned" },
  ];
  if (d.src_ip) where.push({ label: "Source IP", value: String(d.src_ip) });
  if (d.username) where.push({ label: "Account", value: String(d.username) });
  if (d.port) where.push({ label: "Port", value: String(d.port) });

  const evidence: { label: string; value: string }[] = [{ label: "Detection", value: `${a.rule_name ?? a.source}: ${a.description ?? a.title}` }];
  let checks: Brief["checks"] = [];
  let lastGood: string | null = null;
  if (a.asset_id) {
    const rows = await tx`
      select checked_at, ok, detail, response_ms from check_results
      where asset_id = ${a.asset_id} and check_type = 'availability' order by checked_at desc limit 12`;
    checks = rows.map((r) => ({ at: r.checked_at, ok: r.ok, detail: r.detail ?? "", ms: r.response_ms }));
    const [good] = await tx`select max(checked_at) as at from check_results where asset_id = ${a.asset_id} and check_type = 'availability' and ok`;
    lastGood = good?.at ?? null;
    const latest = await tx`
      select distinct on (check_type) check_type, ok, detail from check_results
      where asset_id = ${a.asset_id} and check_type in ('tls','headers','ports') order by check_type, checked_at desc`;
    for (const r of latest) evidence.push({ label: `Latest ${r.check_type} check`, value: `${r.ok ? "OK" : "PROBLEM"} — ${r.detail ?? ""}` });
    if (a.http_status) evidence.push({ label: "Last HTTP status", value: String(a.http_status) });
    if (a.response_ms) evidence.push({ label: "Last response time", value: `${a.response_ms} ms` });
    const [lat] = await tx`
      select round(avg(response_ms) filter (where checked_at > now() - interval '1 hour'))::int as recent,
             round(percentile_cont(0.5) within group (order by response_ms) filter (where checked_at > now() - interval '7 days'))::int as baseline
      from check_results where asset_id = ${a.asset_id} and check_type = 'availability' and ok and response_ms is not null`;
    if (lat?.baseline) evidence.push({ label: "Response time (last hour vs 7-day normal)", value: `${lat.recent ?? "—"} ms vs ${lat.baseline} ms` });
    if (a.tls_expires_at) evidence.push({ label: "TLS certificate", value: `${a.tls_subject ?? ""} by ${a.tls_issuer ?? "?"}, expires ${fmt(a.tls_expires_at)}` });
    if (a.open_ports?.length) evidence.push({ label: "Open ports seen from internet", value: (a.open_ports as number[]).join(", ") });
    if (a.dns?.ns?.length) evidence.push({ label: "Name servers", value: (a.dns.ns as string[]).join(", ") });
  }
  for (const [k, v] of Object.entries(d)) {
    if (["demo", "auto_resolved"].includes(k) || v == null || typeof v === "object") continue;
    if (!where.some((w) => w.value === String(v))) evidence.push({ label: k.replace(/_/g, " "), value: String(v) });
  }

  const host = a.asset_name ?? (d.host as string | undefined) ?? null;
  const events = await tx`
    select occurred_at, event_type, username, host(src_ip) as ip, outcome, message from events
    where occurred_at between ${a.detected_at}::timestamptz - interval '1 hour' and ${a.last_seen_at}::timestamptz + interval '15 minutes'
      and ((${host}::text is not null and lower(host) = lower(${host}))
           or (${(d.src_ip as string) ?? null}::text is not null and src_ip = ${(d.src_ip as string) ?? null}::inet))
    order by occurred_at desc limit 8`;

  const when = [
    { label: "First seen", value: fmt(a.detected_at) },
    { label: "Last seen", value: fmt(a.last_seen_at) },
    { label: "Occurrences", value: String(a.event_count) },
  ];
  if (lastGood) when.push({ label: "Last time it was healthy", value: fmt(lastGood) });

  const brief: Brief = {
    summary: `${a.title}${a.asset_name ? ` (${a.asset_name})` : ""}`,
    meaning: rb.meaning,
    impact: impactText(a.severity, a.asset_criticality, a.exposure),
    where,
    when,
    evidence,
    checks,
    events: events.map((e) => ({ at: e.occurred_at, type: e.event_type, user: e.username, ip: e.ip, outcome: e.outcome, message: e.message ? String(e.message).slice(0, 300) : null })),
    causes: rb.causes,
    whereToLook: rb.where,
    fix: rb.fix,
    verify: rb.verify,
    technique: a.mitre_technique ?? null,
  };
  if (note) brief.evidence.unshift({ label: "Note from SOC", value: note });
  return { brief, alert: a };
}

export function issueLinkUrl(token: string) {
  return `${env().APP_URL}/fix/${token}`;
}

/** Creates a fresh secure link (revoking older ones) and returns its URL. */
export async function newIssueLink(tx: Tx, issueId: string, userId: string | null, days = Number(process.env.ISSUE_LINK_DAYS ?? 14)): Promise<string> {
  const token = randomToken(32);
  await tx`update issue_links set revoked_at = now() where issue_id = ${issueId} and revoked_at is null`;
  await tx`insert into issue_links (issue_id, token_hash, expires_at, created_by)
           values (${issueId}, ${sha256(token)}, now() + make_interval(days => ${days}), ${userId})`;
  return issueLinkUrl(token);
}

export type IssueInput = {
  alertId?: string | null;
  teamId?: string | null;
  title?: string | null;
  severity?: Severity | null;
  note?: string | null;
  assetId?: string | null;
};

/** Creates an issue (with brief + secure link) and queues messages to the team. Runs as the signed-in user. */
export async function createIssue(tx: Tx, input: IssueInput, userId: string): Promise<{ id: string; ref: string; link: string; queued: number }> {
  let brief: Brief;
  let alert: Record<string, any> | null = null;
  if (input.alertId) {
    ({ brief, alert } = await buildBrief(tx, input.alertId, input.note));
  } else {
    if (!input.title) throw new Error("A title is required.");
    brief = {
      summary: input.title, meaning: input.note ?? "", impact: impactText(input.severity ?? "medium", null, null),
      where: [], when: [{ label: "Reported", value: fmt(new Date()) }], evidence: input.note ? [{ label: "Note from SOC", value: input.note }] : [],
      checks: [], events: [], causes: [], whereToLook: [], fix: [], verify: "The SOC analyst verifies the fix.", technique: null,
    };
  }
  let teamId = input.teamId ?? null;
  const assetId = input.assetId ?? alert?.asset_id ?? null;
  if (!teamId && assetId) {
    const [t] = await tx`select team_id from assets where id = ${assetId}`;
    teamId = t?.team_id ?? null;
  }
  if (!teamId) throw new Error("Choose the team that should fix this (or assign a team to the asset).");

  const [issue] = await tx`
    insert into issues (title, severity, team_id, asset_id, alert_id, incident_id, dedupe_key, brief, soc_note, created_by)
    values (${input.title || alert?.title}, ${input.severity ?? alert?.severity ?? "medium"}, ${teamId}, ${assetId},
            ${alert?.id ?? null}, ${alert?.incident_id ?? null}, ${alert?.dedupe_key ?? null}, ${tx.json(brief as never)}, ${input.note ?? null}, ${userId})
    returning id, ref`;
  const link = await newIssueLink(tx, issue!.id, userId);
  if (alert && ["new", "acknowledged"].includes(alert.status)) {
    await tx`update alerts set status = 'investigating', assignee = coalesce(assignee, ${userId}) where id = ${alert.id}`;
  }
  const queued = await queueIssueMessages(tx, issue!.id, "new", link);
  await tx`insert into issue_updates (issue_id, kind, body, author) values (${issue!.id}, 'sent', ${`Sent to the team (${queued} message${queued === 1 ? "" : "s"} queued).`}, ${userId})`;
  return { id: issue!.id, ref: issue!.ref, link, queued };
}

/** Queues email / Telegram / WhatsApp messages for the issue's team. */
export async function queueIssueMessages(tx: Tx, issueId: string, kind: "new" | "reopened" | "reminder", link: string | null): Promise<number> {
  const [i] = await tx`
    select i.ref, i.title, i.severity, i.due_at, i.brief, t.name as team, t.emails, t.telegram_chat_id, t.whatsapp_numbers
    from issues i left join teams t on t.id = i.team_id where i.id = ${issueId}`;
  if (!i) return 0;
  const brief = i.brief as Brief;
  const head = kind === "reopened" ? `REOPENED — the problem came back: ${i.title}` : kind === "reminder" ? `Reminder — overdue: ${i.title}` : i.title;
  const subject = `[${String(i.severity).toUpperCase()}] ${i.ref}: ${head}`;
  const due = `Fix by: ${fmt(i.due_at)}`;
  const linkLine = link ? `Open the issue (no login needed): ${link}` : `Open it in the SOC: ${env().APP_URL}/my-issues`;
  const short = [`${subject}`, brief.impact, due, linkLine].join("\n");
  const text = [
    subject, "", `What is wrong: ${brief.meaning}`, `Impact: ${brief.impact}`, due, "",
    "Where:", ...brief.where.map((w) => `  - ${w.label}: ${w.value}`), "",
    "Evidence:", ...brief.evidence.slice(0, 10).map((e) => `  - ${e.label}: ${e.value}`), "",
    "Likely causes:", ...brief.causes.map((c) => `  - ${c}`), "",
    "How to fix:", ...brief.fix.map((f, n) => `  ${n + 1}. ${f}`), "",
    linkLine, "", "Please acknowledge the issue on the link, post updates, and mark it fixed when done.",
  ].join("\n");
  const html = renderBriefHtml(subject, brief, link ?? `${env().APP_URL}/my-issues`, due);

  let n = 0;
  for (const email of (i.emails as string[]) ?? []) {
    await tx`insert into outbox (channel, recipient, subject, body, html, link, issue_id) values ('email', ${email}, ${subject}, ${text}, ${html}, ${link}, ${issueId})`;
    n++;
  }
  if (i.telegram_chat_id) {
    await tx`insert into outbox (channel, recipient, subject, body, link, issue_id) values ('telegram', ${i.telegram_chat_id}, ${subject}, ${short}, ${link}, ${issueId})`;
    n++;
  }
  for (const num of (i.whatsapp_numbers as string[]) ?? []) {
    await tx`insert into outbox (channel, recipient, subject, body, link, issue_id) values ('whatsapp', ${num}, ${subject}, ${short}, ${link}, ${issueId})`;
    n++;
  }
  return n;
}

export function renderBriefHtml(subject: string, b: Brief, link: string, due: string): string {
  const e = escapeHtml;
  const list = (items: string[], ordered = false) =>
    items.length ? `<${ordered ? "ol" : "ul"} style="margin:4px 0 12px;padding-left:20px">${items.map((x) => `<li>${e(x)}</li>`).join("")}</${ordered ? "ol" : "ul"}>` : "";
  const table = (rows: { label: string; value: string }[]) =>
    rows.length ? `<table style="border-collapse:collapse;margin:4px 0 12px;font-size:13px">${rows.map((r) => `<tr><td style="padding:2px 12px 2px 0;color:#555;vertical-align:top">${e(r.label)}</td><td style="padding:2px 0">${e(r.value)}</td></tr>`).join("")}</table>` : "";
  return `<div style="font-family:system-ui,sans-serif;max-width:680px;margin:auto;color:#111;font-size:14px">
<h2 style="font-size:18px;margin:0 0 8px">${e(subject)}</h2>
<p style="margin:0 0 4px"><b>What is wrong:</b> ${e(b.meaning)}</p>
<p style="margin:0 0 4px"><b>Impact:</b> ${e(b.impact)}</p>
<p style="margin:0 0 12px"><b>${e(due)}</b></p>
<p><a href="${e(link)}" style="display:inline-block;background:#0ea5b7;color:#00161a;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:600">Open the issue</a></p>
<h3 style="font-size:15px;margin:16px 0 4px">Where</h3>${table(b.where)}
<h3 style="font-size:15px;margin:16px 0 4px">When</h3>${table(b.when)}
<h3 style="font-size:15px;margin:16px 0 4px">Evidence</h3>${table(b.evidence.slice(0, 12))}
<h3 style="font-size:15px;margin:16px 0 4px">Likely causes</h3>${list(b.causes)}
<h3 style="font-size:15px;margin:16px 0 4px">Where to look</h3>${list(b.whereToLook)}
<h3 style="font-size:15px;margin:16px 0 4px">How to fix</h3>${list(b.fix, true)}
<p style="color:#555">${e(b.verify)}</p>
<p style="color:#888;font-size:12px">${e(env().ORG_NAME)} Security Operations · this link is private to your team</p></div>`;
}

/** The alert condition cleared on its own (e.g. site back up): verify open issues for it. */
export async function verifyIssuesForCondition(tx: Tx, dedupeKey: string): Promise<void> {
  const rows = await tx`
    update issues set status = 'verified'
    where dedupe_key = ${dedupeKey} and status in ('open','acknowledged','in_progress','fixed') returning id`;
  for (const r of rows) {
    await tx`insert into issue_updates (issue_id, kind, body, author_label) values (${r.id}, 'system', 'SOC monitoring confirms the problem is gone — verified.', 'SOC monitoring')`;
  }
}

/** The same problem came back after being fixed: reopen and tell the team again. */
export async function reopenIssuesForCondition(tx: Tx, dedupeKey: string, alertId: string): Promise<void> {
  const rows = await tx`
    update issues set status = 'open', alert_id = ${alertId}
    where dedupe_key = ${dedupeKey} and status in ('fixed','verified') and coalesce(verified_at, fixed_at) > now() - interval '30 days'
    returning id`;
  for (const r of rows) {
    await tx`insert into issue_updates (issue_id, kind, body, author_label) values (${r.id}, 'system', 'The problem was detected again after it was fixed — reopened.', 'SOC monitoring')`;
    await queueIssueMessages(tx, r.id, "reopened", await newIssueLink(tx, r.id, null));
  }
}

/** Resolves a secure link token to its issue id (null if invalid/expired/revoked). */
export async function issueIdForToken(tx: Tx, token: string): Promise<string | null> {
  if (!/^[A-Za-z0-9_-]{30,60}$/.test(token)) return null;
  const [l] = await tx`
    update issue_links set last_used_at = now()
    where token_hash = ${sha256(token)} and revoked_at is null and expires_at > now() returning issue_id`;
  return l?.issue_id ?? null;
}

/** Issue as shown to developers (brief + timeline). */
export async function loadIssueView(tx: Tx, id: string): Promise<DevIssue | null> {
  const [i] = await tx`
    select i.id, i.ref, i.title, i.severity, i.status, i.due_at, i.created_at, i.brief, t.name as team_name, a.name as asset_name
    from issues i left join teams t on t.id = i.team_id left join assets a on a.id = i.asset_id where i.id = ${id}`;
  if (!i) return null;
  const updates = await tx`
    select x.kind, x.body, x.created_at, coalesce(u.display_name, x.author_label, 'SOC') as author
    from issue_updates x left join users u on u.id = x.author where x.issue_id = ${id} order by x.created_at`;
  return { ...(i as unknown as DevIssue), updates: updates as unknown as DevIssue["updates"] };
}

