import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
import { PageHeader, Panel, SeverityBadge, StatusPill, Table, Th, Td, ago, SEVERITIES } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { escalateAlerts, getAlertBrief, getAlertContext, listAlerts, listTeam, updateAlerts } from "@/lib/api/soc.functions";
import { BriefView } from "@/components/soc/BriefView";
import { SendToDevDialog } from "@/components/soc/SendToDevDialog";
import { Send } from "lucide-react";
import { useCan, useMe } from "@/lib/session";
import type { Alert } from "@/lib/types";

export const Route = createFileRoute("/_authenticated/alerts")({
  validateSearch: z.object({ focus: z.string().uuid().optional(), q: z.string().max(200).optional() }),
  head: () => ({ meta: [{ title: "Alerts — FINPAY SOC" }, { name: "description", content: "Security alert queue." }] }),
  component: Alerts,
});

const STATUSES = ["open", "new", "acknowledged", "investigating", "escalated", "resolved", "false_positive", "all"];

function Alerts() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { focus, q: initialQ } = Route.useSearch();
  const canTriage = useCan("alerts.triage");
  const canEscalate = useCan("incidents.manage");
  const [sev, setSev] = useState("all");
  const [st, setSt] = useState(focus ? "all" : "open");
  const canSend = useCan("issues.send");
  const [q, setQ] = useState(initialQ ?? "");
  const [sendFor, setSendFor] = useState<Alert | null>(null);
  const [sel, setSel] = useState<string | null>(focus ?? null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const filters = { status: st, severity: sev, q };
  const { data = [], isLoading } = useQuery({ queryKey: ["alerts", filters], queryFn: () => listAlerts({ data: filters }), refetchInterval: 20000 });
  const cur = data.find((a) => a.id === sel) ?? null;
  useEffect(() => { setChecked(new Set()); }, [st, sev, q]);

  const refresh = () => { qc.invalidateQueries({ queryKey: ["alerts"] }); qc.invalidateQueries({ queryKey: ["overview"] }); };
  const update = useMutation({
    mutationFn: (v: { ids: string[]; status?: "new" | "acknowledged" | "investigating" | "resolved" | "false_positive" | "closed"; assignee?: string | null }) => updateAlerts({ data: v }),
    onSuccess: (r) => { toast.success(`${r.updated} alert(s) updated`); setChecked(new Set()); refresh(); },
  });
  const escalate = useMutation({
    mutationFn: (ids: string[]) => escalateAlerts({ data: { ids } }),
    onSuccess: (r) => { toast.success(`Incident ${r.ref} opened`); refresh(); navigate({ to: "/incidents/$id", params: { id: r.incidentId } }); },
  });

  const ids = [...checked];
  const allChecked = data.length > 0 && data.every((a) => checked.has(a.id));
  return (
    <div>
      <PageHeader title="Alerts" sub={`${data.length} shown · repeats of an open alert are merged and counted`} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Input placeholder="Search title, asset…" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 max-w-56" />
        {["all", ...SEVERITIES].map((s) => (
          <button key={s} onClick={() => setSev(s)} className={`data rounded border px-2.5 py-1 text-xs capitalize ${sev === s ? "border-primary text-primary" : "text-muted-foreground"}`}>{s}</button>
        ))}
        <span className="mx-2 h-5 w-px bg-border" />
        {STATUSES.map((s) => (
          <button key={s} onClick={() => setSt(s)} className={`data rounded border px-2.5 py-1 text-xs ${st === s ? "border-primary text-primary" : "text-muted-foreground"}`}>{s.replace("_", " ")}</button>
        ))}
      </div>
      {canTriage && ids.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-primary/40 bg-primary/5 p-2">
          <span className="data px-2 text-xs">{ids.length} selected</span>
          <Button size="sm" variant="outline" onClick={() => update.mutate({ ids, status: "acknowledged" })}>Acknowledge</Button>
          <Button size="sm" variant="outline" onClick={() => update.mutate({ ids, status: "resolved" })}>Resolve</Button>
          <Button size="sm" variant="outline" onClick={() => update.mutate({ ids, status: "false_positive" })}>False positive</Button>
          {canEscalate && <Button size="sm" variant="destructive" onClick={() => escalate.mutate(ids)}>Escalate as one incident</Button>}
        </div>
      )}
      <div className="grid gap-4 xl:grid-cols-[1fr_400px]">
        <Table>
          <thead><tr>
            {canTriage && <Th><Checkbox checked={allChecked} onCheckedChange={(v) => setChecked(v ? new Set(data.map((a) => a.id)) : new Set())} aria-label="Select all" /></Th>}
            <Th>Sev</Th><Th>Alert</Th><Th>Asset</Th><Th>Source</Th><Th>Status</Th><Th>Owner</Th><Th>Last seen</Th>
          </tr></thead>
          <tbody>
            {data.map((a) => (
              <tr key={a.id} onClick={() => setSel(a.id)} className={`cursor-pointer ${sel === a.id ? "bg-accent/60" : ""}`}>
                {canTriage && <Td><span onClick={(e) => e.stopPropagation()}><Checkbox checked={checked.has(a.id)} onCheckedChange={(v) => { const n = new Set(checked); if (v) n.add(a.id); else n.delete(a.id); setChecked(n); }} /></span></Td>}
                <Td><SeverityBadge s={a.severity} /></Td>
                <Td className="font-medium">{a.title}{a.event_count > 1 && <span className="data ml-2 rounded bg-muted px-1 text-[10px] text-muted-foreground">×{a.event_count}</span>}</Td>
                <Td className="data text-xs text-muted-foreground">{a.asset_name ?? "—"}</Td>
                <Td className="data text-xs">{a.source}</Td>
                <Td><StatusPill status={a.status} /></Td>
                <Td className="text-xs text-muted-foreground">{a.assignee_name ?? "—"}</Td>
                <Td className="data text-xs text-muted-foreground">{ago(a.last_seen_at)}</Td>
              </tr>
            ))}
            {!isLoading && !data.length && <tr><Td className="text-muted-foreground">No alerts match these filters.</Td></tr>}
          </tbody>
        </Table>
        <aside className="h-fit rounded-lg border bg-card p-5 xl:sticky xl:top-4">
          {!cur ? <p className="text-sm text-muted-foreground">Select an alert to triage.</p> : (
            <AlertDetail a={cur} canTriage={canTriage} canEscalate={canEscalate} canSend={canSend} onSend={() => setSendFor(cur)}
              onUpdate={(v) => update.mutate({ ids: [cur.id], ...v })}
              onEscalate={() => escalate.mutate([cur.id])}
              onOpenIncident={() => navigate({ to: "/incidents/$id", params: { id: cur.incident_id! } })} />
          )}
        </aside>
      </div>
      <SendToDevDialog alertId={sendFor?.id ?? null} title={sendFor?.title} open={!!sendFor} onOpenChange={(v) => !v && setSendFor(null)} />
    </div>
  );
}

function AlertDetail({ a, canTriage, canEscalate, canSend, onSend, onUpdate, onEscalate, onOpenIncident }: {
  a: Alert; canTriage: boolean; canEscalate: boolean; canSend: boolean; onSend: () => void;
  onUpdate: (v: { status?: "acknowledged" | "investigating" | "resolved" | "false_positive" | "new"; assignee?: string | null }) => void;
  onEscalate: () => void; onOpenIncident: () => void;
}) {
  const me = useMe();
  const { data: ctx } = useQuery({ queryKey: ["alert-ctx", a.id], queryFn: () => getAlertContext({ data: { id: a.id } }) });
  const { data: diag } = useQuery({ queryKey: ["brief", a.id], queryFn: () => getAlertBrief({ data: { id: a.id } }) });
  const { data: team = [] } = useQuery({ queryKey: ["team"], queryFn: () => listTeam(), staleTime: 300_000, enabled: canTriage });
  const closed = ["resolved", "false_positive", "closed"].includes(a.status);
  const details = (a.details ?? {}) as Record<string, unknown>;
  return (
    <div>
      <div className="flex items-center gap-2"><SeverityBadge s={a.severity} /><StatusPill status={a.status} /></div>
      <h2 className="mt-3 text-lg font-semibold">{a.title}</h2>
      <p className="mt-2 whitespace-pre-wrap break-words text-sm text-muted-foreground">{a.description}</p>
      <dl className="data mt-4 space-y-1.5 text-xs">
        {[
          ["Asset", a.asset_name], ["Rule", a.rule_name], ["Tactic", a.mitre_tactic], ["Technique", a.mitre_technique],
          ["Occurrences", String(a.event_count)], ["First seen", new Date(a.detected_at).toLocaleString()], ["Last seen", new Date(a.last_seen_at).toLocaleString()],
          ["Incident", a.incident_ref], ["Source IP", details.src_ip as string | undefined], ["Account", details.username as string | undefined],
        ].filter(([, v]) => v).map(([k, v]) => (
          <div key={k} className="flex justify-between gap-4"><dt className="text-muted-foreground">{k}</dt><dd className={`truncate text-right ${k === "Technique" ? "text-primary" : ""}`}>{v}</dd></div>
        ))}
        {typeof details.auto_resolved === "string" && <p className="text-ok">Auto-resolved: {details.auto_resolved}</p>}
      </dl>
      {canTriage && (
        <>
          <label className="mt-4 block text-xs text-muted-foreground">Owner
            <select className="data mt-1 h-8 w-full rounded border bg-background px-2 text-xs" value={a.assignee ?? ""} onChange={(e) => onUpdate({ assignee: e.target.value || null })}>
              <option value="">Unassigned</option>
              {team.map((u) => <option key={u.id} value={u.id}>{u.display_name}{u.id === me.id ? " (me)" : ""}</option>)}
            </select>
          </label>
          <div className="mt-4 grid grid-cols-2 gap-2">
            {closed ? <Button variant="outline" size="sm" className="col-span-2" onClick={() => onUpdate({ status: "new" })}>Reopen</Button> : (
              <>
                <Button variant="outline" size="sm" onClick={() => onUpdate({ status: "acknowledged" })} disabled={a.status !== "new"}>Acknowledge</Button>
                <Button variant="outline" size="sm" onClick={() => onUpdate({ status: "investigating" })}>Investigate</Button>
                <Button variant="outline" size="sm" onClick={() => onUpdate({ status: "resolved" })}>Resolve</Button>
                <Button variant="outline" size="sm" onClick={() => onUpdate({ status: "false_positive" })}>False positive</Button>
              </>
            )}
            {a.incident_id
              ? <Button size="sm" className="col-span-2" onClick={onOpenIncident}>Open incident {a.incident_ref}</Button>
              : canEscalate && !closed && <Button size="sm" variant="destructive" className="col-span-2" onClick={onEscalate}>Escalate to incident</Button>}
          </div>
        </>
      )}
      {canSend && !closed && (
        <div className="mt-3">
          <Button size="sm" className="w-full" onClick={onSend}><Send className="mr-2 h-3.5 w-3.5" />Send to developer{diag?.suggestedTeam ? ` · ${diag.suggestedTeam.name}` : ""}</Button>
          {diag?.issues?.length ? <p className="data mt-1 text-[11px] text-primary">Already with devs: {diag.issues.map((i) => `${i.ref} (${i.status})`).join(", ")}</p> : null}
        </div>
      )}
      <Panel title="Diagnosis" className="mt-4">
        {diag ? <BriefView brief={diag.brief} /> : <p className="text-xs text-muted-foreground">Analysing…</p>}
      </Panel>
      {ctx && ctx.intel.length > 0 && (
        <Panel title="Threat intelligence" className="mt-5">
          <ul className="data space-y-1 text-xs">{ctx.intel.map((i, n) => <li key={n}><span className="text-sev-high">{String(i.source)}</span> {String(i.description ?? "")}</li>)}</ul>
        </Panel>
      )}
      <Panel title={`Related events (${ctx?.events.length ?? "…"})`} className="mt-4">
        <ul className="data max-h-64 space-y-1 overflow-y-auto text-[11px]">
          {ctx?.events.map((e) => (
            <li key={e.id} className="flex gap-2">
              <span className="w-16 shrink-0 text-muted-foreground">{new Date(e.occurred_at).toLocaleTimeString()}</span>
              <span className="text-primary">{e.event_type}</span>
              <span className={e.outcome === "failure" ? "text-sev-high" : ""}>{e.username ?? ""}</span>
              <span className="truncate text-muted-foreground">{e.src_ip ?? ""} {e.message ?? ""}</span>
            </li>
          ))}
          {ctx && !ctx.events.length && <li className="text-muted-foreground">No raw events linked to this alert.</li>}
        </ul>
      </Panel>
      {ctx && ctx.related.length > 0 && (
        <Panel title="Related alerts (14 days)" className="mt-4">
          <ul className="space-y-1.5 text-xs">{ctx.related.map((r) => <li key={r.id} className="flex items-center gap-2"><SeverityBadge s={r.severity} /><span className="flex-1 truncate">{r.title}</span><StatusPill status={r.status} /></li>)}</ul>
        </Panel>
      )}
    </div>
  );
}
