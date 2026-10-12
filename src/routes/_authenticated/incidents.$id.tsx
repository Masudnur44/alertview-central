import { createFileRoute, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Printer } from "lucide-react";
import { Panel, SeverityBadge, StatusPill, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { addIncidentEvent, getIncident, listTeam, updateIncident } from "@/lib/api/soc.functions";
import { useCan } from "@/lib/session";
import type { Severity } from "@/lib/types";

export const Route = createFileRoute("/_authenticated/incidents/$id")({
  head: () => ({ meta: [{ title: "Incident — FINPAY SOC" }] }),
  component: Incident,
});

const FLOW = ["new", "triage", "contained", "resolved", "closed"] as const;
type Stage = (typeof FLOW)[number];

function Incident() {
  const { id } = Route.useParams();
  const qc = useQueryClient();
  const canManage = useCan("incidents.manage");
  const [note, setNote] = useState("");
  const [kind, setKind] = useState<"note" | "action" | "evidence">("note");
  const { data } = useQuery({ queryKey: ["incident", id], queryFn: () => getIncident({ data: { id } }), refetchInterval: 30000 });
  const { data: team = [] } = useQuery({ queryKey: ["team"], queryFn: () => listTeam(), staleTime: 300_000, enabled: canManage });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["incident", id] }); qc.invalidateQueries({ queryKey: ["incidents"] }); };
  const update = useMutation({
    mutationFn: (v: { status?: Stage; owner?: string | null; severity?: Severity }) => updateIncident({ data: { id, ...v } }),
    onSuccess: refresh,
  });
  const add = useMutation({
    mutationFn: () => addIncidentEvent({ data: { id, kind, body: note } }),
    onSuccess: () => { setNote(""); refresh(); },
  });
  if (!data) return <p className="text-sm text-muted-foreground">Loading…</p>;
  const inc = data.incident;
  const minutes = (a?: string | null) => (a ? Math.round((new Date(a).getTime() - new Date(inc.opened_at).getTime()) / 60000) : null);
  const ttc = minutes(inc.contained_at);
  const ttr = minutes(inc.resolved_at);

  return (
    <div>
      <div className="flex items-center justify-between print:hidden">
        <Link to="/incidents" className="text-xs text-muted-foreground hover:text-foreground">← Incidents</Link>
        <Button size="sm" variant="ghost" onClick={() => window.print()}><Printer className="mr-1 h-4 w-4" />Print / PDF</Button>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <span className="data text-primary">{inc.ref}</span>
        <SeverityBadge s={inc.severity} />
        <StatusPill status={inc.status} />
        <span className="data text-xs text-muted-foreground">opened {new Date(inc.opened_at).toLocaleString()}</span>
        {ttc != null && <span className="data text-xs text-muted-foreground">· contained in {ttc} min</span>}
        {ttr != null && <span className="data text-xs text-muted-foreground">· resolved in {ttr} min</span>}
      </div>
      <h1 className="mt-2 text-2xl font-semibold">{inc.title}</h1>
      <p className="mt-1 max-w-3xl whitespace-pre-wrap text-sm text-muted-foreground">{inc.summary}</p>

      {canManage && (
        <div className="mt-4 flex flex-wrap gap-3 print:hidden">
          <label className="text-xs text-muted-foreground">Owner
            <select className="data ml-2 h-8 rounded border bg-background px-2 text-xs" value={inc.owner ?? ""} onChange={(e) => update.mutate({ owner: e.target.value || null })}>
              <option value="">Unassigned</option>
              {team.map((u) => <option key={u.id} value={u.id}>{u.display_name}</option>)}
            </select>
          </label>
          <label className="text-xs text-muted-foreground">Severity
            <select className="data ml-2 h-8 rounded border bg-background px-2 text-xs" value={inc.severity} onChange={(e) => update.mutate({ severity: e.target.value as Severity })}>
              {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
        </div>
      )}

      <div className="mt-6 flex flex-wrap gap-1">
        {FLOW.map((s, i) => {
          const reached = FLOW.indexOf(inc.status as Stage) >= i;
          return (
            <button key={s} disabled={!canManage || update.isPending} onClick={() => update.mutate({ status: s })}
              className={`data min-w-24 flex-1 rounded border px-3 py-2 text-xs uppercase tracking-widest disabled:cursor-default ${reached ? "border-primary/60 bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}>
              {s}
            </button>
          );
        })}
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-[1fr_360px]">
        <Panel title="Timeline & evidence">
          {canManage && (
            <div className="mb-4 space-y-2 print:hidden">
              <Textarea placeholder="Add finding, action taken, or evidence (log excerpt, hash, IP)…" value={note} onChange={(e) => setNote(e.target.value)} />
              <div className="flex gap-2">
                <select value={kind} onChange={(e) => setKind(e.target.value as typeof kind)} className="h-9 rounded-md border bg-background px-2 text-sm">
                  <option value="note">Note</option><option value="action">Action</option><option value="evidence">Evidence</option>
                </select>
                <Button size="sm" onClick={() => add.mutate()} disabled={!note.trim() || add.isPending}>Add to timeline</Button>
              </div>
            </div>
          )}
          <ol className="relative space-y-4 border-l pl-5">
            {data.events.map((e) => (
              <li key={e.id}>
                <span className="absolute -left-1 mt-1.5 h-2 w-2 rounded-full bg-primary" />
                <p className="data text-[10px] uppercase tracking-widest text-muted-foreground">{e.kind} · {e.author_name ?? "system"} · {new Date(e.created_at).toLocaleString()}</p>
                <p className={`mt-0.5 whitespace-pre-wrap break-words text-sm ${e.kind === "evidence" ? "data rounded bg-muted p-2 text-xs" : ""}`}>{e.body}</p>
              </li>
            ))}
          </ol>
        </Panel>
        <div className="space-y-4">
          <Panel title="Linked alerts">
            <ul className="space-y-2">
              {data.alerts.map((a) => (
                <li key={a.id} className="rounded border p-2.5">
                  <div className="flex items-center gap-2"><SeverityBadge s={a.severity} /><StatusPill status={a.status} /></div>
                  <p className="mt-1 text-sm">{a.title}</p>
                  <p className="data mt-1 text-[11px] text-primary">{a.mitre_technique}</p>
                  <p className="data text-[11px] text-muted-foreground">{ago(a.detected_at)}</p>
                </li>
              ))}
              {!data.alerts.length && <p className="text-sm text-muted-foreground">None</p>}
            </ul>
          </Panel>
          <Panel title="Affected assets">
            <ul className="data space-y-1 text-sm">
              {[...new Set(data.alerts.map((a) => a.asset_name).filter(Boolean))].map((n) => <li key={n}>{n}</li>)}
            </ul>
          </Panel>
          {data.vulns.length > 0 && (
            <Panel title="Open vulnerabilities on these assets">
              <ul className="space-y-1.5 text-xs">
                {data.vulns.map((v) => <li key={v.id} className="flex items-center gap-2"><SeverityBadge s={v.severity} /><span className="flex-1 truncate">{v.title}</span><span className="data text-muted-foreground">{v.cve}</span></li>)}
              </ul>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
