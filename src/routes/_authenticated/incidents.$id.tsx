import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Panel, SeverityBadge, StatusPill, ago, type Severity } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { audit } from "@/lib/soc";

export const Route = createFileRoute("/_authenticated/incidents/$id")({
  head: () => ({ meta: [{ title: "Incident — FINPAY SOC" }] }),
  component: Incident,
});

const FLOW = ["new", "triage", "contained", "resolved", "closed"];
const STAMP: Record<string, string> = { contained: "contained_at", resolved: "resolved_at", closed: "closed_at" };

function Incident() {
  const { id } = Route.useParams();
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const [kind, setKind] = useState("note");
  const { data } = useQuery({
    queryKey: ["incident", id],
    queryFn: async () => {
      const [i, ev, al] = await Promise.all([
        supabase.from("incidents").select("*").eq("id", id).single(),
        supabase.from("incident_events").select("*").eq("incident_id", id).order("created_at", { ascending: false }),
        supabase.from("alerts").select("*, assets(name, address)").eq("incident_id", id),
      ]);
      return { inc: i.data, events: ev.data ?? [], alerts: al.data ?? [] };
    },
  });
  if (!data?.inc) return <p className="text-sm text-muted-foreground">Loading…</p>;
  const inc = data.inc;
  const refresh = () => { qc.invalidateQueries({ queryKey: ["incident", id] }); qc.invalidateQueries({ queryKey: ["incidents"] }); };

  async function move(status: string) {
    const stamp = STAMP[status];
    const patch = { status, ...(stamp ? { [stamp]: new Date().toISOString() } : {}) } as { status: string; contained_at?: string; resolved_at?: string; closed_at?: string };
    const { error } = await supabase.from("incidents").update(patch).eq("id", id);
    if (error) { toast.error(error.message); return; }
    await supabase.from("incident_events").insert({ incident_id: id, kind: "status", body: `Status changed to ${status}` });
    await audit(`incident.${status}`, inc.ref);
    refresh();
  }
  async function addNote() {
    const { data: u } = await supabase.auth.getUser();
    const { error } = await supabase.from("incident_events").insert({ incident_id: id, kind, body: note, author: u.user?.id ?? null });
    if (error) { toast.error(error.message); return; }
    setNote("");
    refresh();
  }

  return (
    <div>
      <Link to="/incidents" className="text-xs text-muted-foreground hover:text-foreground">← Incidents</Link>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <span className="data text-primary">{inc.ref}</span>
        <SeverityBadge s={inc.severity as Severity} />
        <StatusPill status={inc.status} />
      </div>
      <h1 className="mt-2 text-2xl font-semibold">{inc.title}</h1>
      <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{inc.summary}</p>

      <div className="mt-6 flex flex-wrap gap-1">
        {FLOW.map((s, i) => {
          const reached = FLOW.indexOf(inc.status) >= i;
          return (
            <button key={s} onClick={() => move(s)}
              className={`data flex-1 rounded border px-3 py-2 text-xs uppercase tracking-widest ${reached ? "border-primary/60 bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}>
              {s}
            </button>
          );
        })}
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-[1fr_360px]">
        <Panel title="Timeline & evidence">
          <div className="mb-4 space-y-2">
            <Textarea placeholder="Add finding, action taken, or evidence (log excerpt, hash, IP)…" value={note} onChange={(e) => setNote(e.target.value)} />
            <div className="flex gap-2">
              <select value={kind} onChange={(e) => setKind(e.target.value)} className="h-9 rounded-md border bg-background px-2 text-sm">
                <option value="note">Note</option><option value="action">Action</option><option value="evidence">Evidence</option>
              </select>
              <Button size="sm" onClick={addNote} disabled={!note.trim()}>Add to timeline</Button>
            </div>
          </div>
          <ol className="relative space-y-4 border-l pl-5">
            {data.events.map((e) => (
              <li key={e.id}>
                <span className="absolute -left-1 mt-1.5 h-2 w-2 rounded-full bg-primary" />
                <p className="data text-[10px] uppercase tracking-widest text-muted-foreground">{e.kind} · {ago(e.created_at)}</p>
                <p className={`mt-0.5 text-sm ${e.kind === "evidence" ? "data rounded bg-muted p-2 text-xs" : ""}`}>{e.body}</p>
              </li>
            ))}
          </ol>
        </Panel>
        <div className="space-y-4">
          <Panel title="Linked alerts">
            <ul className="space-y-2">
              {data.alerts.map((a) => (
                <li key={a.id} className="rounded border p-2.5">
                  <SeverityBadge s={a.severity as Severity} />
                  <p className="mt-1 text-sm">{a.title}</p>
                  <p className="data mt-1 text-[11px] text-primary">{a.mitre_technique}</p>
                </li>
              ))}
              {!data.alerts.length && <p className="text-sm text-muted-foreground">None</p>}
            </ul>
          </Panel>
          <Panel title="Affected assets">
            <ul className="data space-y-1 text-sm">
              {[...new Set(data.alerts.map((a) => a.assets?.name).filter(Boolean))].map((n) => <li key={n}>{n}</li>)}
            </ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}
