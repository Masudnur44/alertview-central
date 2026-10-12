// Raising alerts: one open alert per dedupe key, rule enable/disable respected,
// hit counters maintained. New alerts queue notifications via a database trigger.
import type { Tx } from "./db.server";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Rule = {
  id: string;
  key: string;
  name: string;
  severity: Severity;
  enabled: boolean;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  params: Record<string, unknown>;
};

export async function loadRules(tx: Tx): Promise<Map<string, Rule>> {
  const rows = await tx<Rule[]>`select id, key, name, severity, enabled, mitre_tactic, mitre_technique, params from detection_rules`;
  return new Map(rows.map((r) => [r.key, r]));
}

export type RaiseInput = {
  rule: string;                 // detection_rules.key
  title: string;
  description?: string;
  severity?: Severity;          // defaults to the rule's severity
  source: string;
  assetId?: string | null;
  dedupeKey: string;
  details?: Record<string, unknown>;
  technique?: string | null;
  tactic?: string | null;
};

/** Returns true when a new alert was opened, false when it was merged into an open one or the rule is off. */
export async function raiseAlert(tx: Tx, rules: Map<string, Rule>, a: RaiseInput): Promise<boolean> {
  const rule = rules.get(a.rule);
  if (rule && !rule.enabled) return false;
  const [row] = await tx`
    insert into alerts (title, description, severity, source, asset_id, rule_id, mitre_tactic, mitre_technique, dedupe_key, details)
    values (${a.title}, ${a.description ?? null}, ${a.severity ?? rule?.severity ?? "medium"}, ${a.source}, ${a.assetId ?? null},
            ${rule?.id ?? null}, ${a.tactic ?? rule?.mitre_tactic ?? null}, ${a.technique ?? rule?.mitre_technique ?? null},
            ${a.dedupeKey}, ${a.details ? tx.json(a.details as never) : null})
    on conflict (dedupe_key) where dedupe_key is not null and status not in ('resolved','false_positive','closed')
    do update set event_count = alerts.event_count + 1, last_seen_at = now(),
                  description = coalesce(excluded.description, alerts.description)
    returning (xmax = 0) as inserted`;
  const inserted = Boolean(row?.inserted);
  if (inserted && rule) {
    await tx`update detection_rules set hits = hits + 1, last_hit_at = now() where id = ${rule.id}`;
  }
  return inserted;
}

/** Close an open, untouched alert when its condition clears (e.g. asset back online). */
export async function autoResolve(tx: Tx, dedupeKey: string, reason: string) {
  await tx`
    update alerts set status = 'resolved',
      details = coalesce(details, '{}'::jsonb) || ${tx.json({ auto_resolved: reason })}
    where dedupe_key = ${dedupeKey} and status in ('new','acknowledged')`;
}
