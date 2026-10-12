import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { CheckCircle2, RefreshCw, XCircle } from "lucide-react";
import { Panel, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getPlatformStatus, refreshIntelNow, updateSettings } from "@/lib/api/admin.functions";
import { useCan } from "@/lib/session";

export function PlatformPanel() {
  const qc = useQueryClient();
  const canIntel = useCan("intel.manage");
  const canSettings = useCan("settings.manage");
  const { data } = useQuery({ queryKey: ["platform"], queryFn: () => getPlatformStatus(), refetchInterval: 30000 });
  const intel = useMutation({
    mutationFn: () => refreshIntelNow(),
    onSuccess: (r) => {
      Object.entries(r).forEach(([k, v]) => (typeof v === "number" ? toast.success(`${k}: ${v.toLocaleString()} indicators`) : toast.error(`${k}: ${v}`)));
      qc.invalidateQueries({ queryKey: ["platform"] });
    },
  });
  if (!data) return <p className="text-sm text-muted-foreground">Loading…</p>;
  const hbAge = data.workerHeartbeat ? (Date.now() - new Date(data.workerHeartbeat).getTime()) / 60000 : null;
  const ok = (b: boolean) => (b ? <CheckCircle2 className="inline h-4 w-4 text-ok" /> : <XCircle className="inline h-4 w-4 text-muted-foreground" />);
  return (
    <div className="space-y-4">
      <Panel title="Platform health">
        <dl className="data grid gap-2 text-xs sm:grid-cols-2">
          <div className="flex justify-between"><dt className="text-muted-foreground">Background worker</dt><dd className={hbAge != null && hbAge < 10 ? "text-ok" : "text-sev-high"}>{hbAge == null ? "never reported" : `heartbeat ${Math.round(hbAge)} min ago`}</dd></div>
          <div className="flex justify-between"><dt className="text-muted-foreground">Public URL</dt><dd>{data.config.appUrl}</dd></div>
          <div className="flex justify-between"><dt className="text-muted-foreground">Email (SMTP)</dt><dd>{ok(data.config.smtp)}</dd></div>
          <div className="flex justify-between"><dt className="text-muted-foreground">Google sign-in</dt><dd>{ok(data.config.google)}</dd></div>
          <div className="flex justify-between"><dt className="text-muted-foreground">Two-factor mandatory</dt><dd>{ok(data.config.requireMfa)}</dd></div>
          <div className="flex justify-between"><dt className="text-muted-foreground">Self sign-up</dt><dd>{data.config.allowSignup ? "on (admin approval)" : "off"}</dd></div>
          <div className="flex justify-between"><dt className="text-muted-foreground">Allowed email domains</dt><dd>{data.config.allowedDomains.join(", ") || "any (set ALLOWED_EMAIL_DOMAINS)"}</dd></div>
          <div className="flex justify-between"><dt className="text-muted-foreground">Probe private addresses</dt><dd className={data.config.allowPrivateTargets ? "text-sev-medium" : ""}>{data.config.allowPrivateTargets ? "allowed" : "blocked"}</dd></div>
        </dl>
        <p className="mt-3 text-xs text-muted-foreground">These are set in the server's <code>.env</code> file; see the deployment guide.</p>
      </Panel>
      <Panel title="Scheduled jobs">
        <ul className="data divide-y text-xs">
          {data.jobs.map((j) => (
            <li key={j.job} className="flex flex-wrap gap-3 py-2">
              <span className="w-28 text-primary">{j.job}</span>
              <span className={j.ok === false ? "text-sev-high" : j.ok ? "text-ok" : "text-muted-foreground"}>{j.ok === false ? "failed" : j.ok ? "ok" : "running"}</span>
              <span className="text-muted-foreground">{ago(j.started_at)}</span>
              <span className="flex-1 truncate text-muted-foreground" title={JSON.stringify(j.detail)}>{JSON.stringify(j.detail)}</span>
            </li>
          ))}
          {!data.jobs.length && <li className="py-2 text-muted-foreground">No jobs have run yet.</li>}
        </ul>
      </Panel>
      <Panel title="Threat intelligence feeds" action={canIntel && <Button size="sm" variant="outline" onClick={() => intel.mutate()} disabled={intel.isPending}><RefreshCw className={`mr-1 h-3.5 w-3.5 ${intel.isPending ? "animate-spin" : ""}`} />Refresh now</Button>}>
        <ul className="divide-y text-sm">
          {data.feeds.map((f) => {
            const row = data.intel.find((i) => i.source === f.source);
            return (
              <li key={f.source} className="flex justify-between py-2">
                <span>{f.label}</span>
                <span className="data text-xs text-muted-foreground">{row ? `${Number(row.n).toLocaleString()} indicators · ${ago(row.refreshed)}` : "not loaded yet"}</span>
              </li>
            );
          })}
        </ul>
        <p className="mt-2 text-xs text-muted-foreground">Event source IPs are matched against these lists on arrival; CVEs on the CISA list mark vulnerabilities as known-exploited.</p>
      </Panel>
      <SettingsForm settings={data.settings} canEdit={canSettings} />
    </div>
  );
}

const FIELDS: { key: string; label: string; type: "text" | "number" }[] = [
  { key: "org_name", label: "Organisation name", type: "text" },
  { key: "timezone", label: "Time zone (business hours, reports)", type: "text" },
  { key: "check_interval_minutes", label: "External checks every (minutes)", type: "number" },
  { key: "discovery_interval_hours", label: "Subdomain discovery every (hours)", type: "number" },
  { key: "intel_interval_hours", label: "Threat-intel refresh every (hours)", type: "number" },
  { key: "event_retention_days", label: "Keep raw events (days)", type: "number" },
  { key: "check_results_retention_days", label: "Keep check history (days)", type: "number" },
];

function SettingsForm({ settings, canEdit }: { settings: Record<string, unknown>; canEdit: boolean }) {
  const qc = useQueryClient();
  const [f, setF] = useState<Record<string, string>>({});
  useEffect(() => setF(Object.fromEntries(FIELDS.map((x) => [x.key, String(settings[x.key] ?? "")]))), [settings]);
  const save = useMutation({
    mutationFn: () => updateSettings({ data: Object.fromEntries(FIELDS.map((x) => [x.key, x.type === "number" ? Number(f[x.key]) : f[x.key]])) }),
    onSuccess: () => { toast.success("Settings saved"); qc.invalidateQueries({ queryKey: ["platform"] }); },
  });
  return (
    <Panel title="Platform settings">
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        {FIELDS.map((x) => (
          <label key={x.key} className="text-xs text-muted-foreground">{x.label}
            <Input disabled={!canEdit} type={x.type} className="mt-1 h-8" value={f[x.key] ?? ""} onChange={(e) => setF({ ...f, [x.key]: e.target.value })} />
          </label>
        ))}
        {canEdit && <div className="sm:col-span-2"><Button disabled={save.isPending}>Save settings</Button></div>}
      </form>
    </Panel>
  );
}
