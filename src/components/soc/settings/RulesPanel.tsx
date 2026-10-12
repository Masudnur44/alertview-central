import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Panel, SeverityBadge, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { listRules, updateRule } from "@/lib/api/admin.functions";
import { useCan } from "@/lib/session";
import type { Severity } from "@/lib/types";

type Rule = { id: string; key: string; name: string; description: string | null; severity: Severity; mitre_technique: string | null; params: Record<string, unknown>; enabled: boolean; hits: number; last_hit_at: string | null };

export function RulesPanel() {
  const qc = useQueryClient();
  const canEdit = useCan("rules.manage");
  const { data = [] } = useQuery({ queryKey: ["rules"], queryFn: () => listRules() as Promise<Rule[]> });
  const [open, setOpen] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: (v: { id: string; enabled?: boolean; severity?: Severity; params?: Record<string, number | string | number[]> }) => updateRule({ data: v }),
    onSuccess: () => { toast.success("Rule updated"); qc.invalidateQueries({ queryKey: ["rules"] }); },
  });
  return (
    <Panel title="Detection rules">
      {!canEdit && <p className="mb-2 text-xs text-muted-foreground">Read-only: Security Administrators and Managers can tune rules.</p>}
      <ul className="divide-y">
        {data.map((r) => (
          <li key={r.id} className="py-3">
            <div className="flex flex-wrap items-center gap-4">
              <SeverityBadge s={r.severity} />
              <button className="min-w-48 flex-1 text-left" onClick={() => setOpen(open === r.id ? null : r.id)}>
                <p className="text-sm font-medium">{r.name}</p>
                <p className="text-xs text-muted-foreground">{r.description}</p>
              </button>
              <span className="data text-xs text-primary">{r.mitre_technique}</span>
              <span className="data w-28 text-right text-xs text-muted-foreground">{r.hits} hits{r.last_hit_at ? ` · ${ago(r.last_hit_at)}` : ""}</span>
              <Switch checked={r.enabled} disabled={!canEdit} onCheckedChange={(v) => update.mutate({ id: r.id, enabled: v })} />
            </div>
            {open === r.id && <RuleEditor rule={r} canEdit={canEdit} onSave={(v) => update.mutate({ id: r.id, ...v })} />}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

const LABELS: Record<string, string> = {
  threshold: "Failures to trigger", window_minutes: "Window (minutes)", distinct_users: "Distinct accounts", failures: "Prior failures",
  start_hour: "Business hours start (0-23)", end_hour: "Business hours end (0-23)", user_pattern: "Privileged account pattern (regex)",
  warn_days: "Warn when fewer days left", high_days: "High severity when fewer days left", ports: "Risky ports (comma separated)",
  silent_hours: "Silent after (hours)", min_level: "Minimum Wazuh level",
};

function RuleEditor({ rule, canEdit, onSave }: { rule: Rule; canEdit: boolean; onSave: (v: { severity?: Severity; params?: Record<string, number | string | number[]> }) => void }) {
  const [sev, setSev] = useState<Severity>(rule.severity);
  const [params, setParams] = useState<Record<string, string>>(() =>
    Object.fromEntries(Object.entries(rule.params).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : String(v)])));
  function save() {
    const out: Record<string, number | string | number[]> = {};
    for (const [k, v] of Object.entries(params)) {
      const orig = rule.params[k];
      out[k] = Array.isArray(orig) ? v.split(/[\s,]+/).filter(Boolean).map(Number).filter((n) => Number.isInteger(n)) : typeof orig === "number" ? Number(v) : v;
    }
    onSave({ severity: sev, params: out });
  }
  return (
    <div className="mt-3 grid gap-3 rounded border bg-muted/30 p-3 sm:grid-cols-2">
      <label className="text-xs text-muted-foreground">Severity
        <select disabled={!canEdit} className="mt-1 h-8 w-full rounded border bg-background px-2 text-sm" value={sev} onChange={(e) => setSev(e.target.value as Severity)}>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </label>
      {Object.keys(params).map((k) => (
        <label key={k} className="text-xs text-muted-foreground">{LABELS[k] ?? k}
          <Input disabled={!canEdit} className="mt-1 h-8" value={params[k]} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />
        </label>
      ))}
      {canEdit && <div className="sm:col-span-2"><Button size="sm" onClick={save}>Save tuning</Button></div>}
    </div>
  );
}
