import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader, SeverityBadge, StatusPill, Table, Th, Td, ago, SEVERITIES, type Severity } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { audit } from "@/lib/soc";

export const Route = createFileRoute("/_authenticated/alerts")({
  head: () => ({ meta: [{ title: "Alerts — FINPAY SOC" }, { name: "description", content: "Security alert queue." }] }),
  component: Alerts,
});

const STATUSES = ["open", "new", "acknowledged", "investigating", "escalated", "resolved", "false_positive", "all"];

function Alerts() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [sev, setSev] = useState<string>("all");
  const [st, setSt] = useState("open");
  const [sel, setSel] = useState<string | null>(null);
  const { data = [] } = useQuery({
    queryKey: ["alerts"],
    refetchInterval: 20000,
    queryFn: async () => (await supabase.from("alerts").select("*, assets(name)").order("detected_at", { ascending: false })).data ?? [],
  });
  const rows = data.filter((a) => (sev === "all" || a.severity === sev) &&
    (st === "all" || (st === "open" ? !["resolved", "false_positive"].includes(a.status) : a.status === st)));
  const cur = data.find((a) => a.id === sel);

  async function setStatus(id: string, status: string) {
    const patch: Record<string, string> = { status };
    if (status === "acknowledged") patch.acknowledged_at = new Date().toISOString();
    if (status === "resolved" || status === "false_positive") patch.resolved_at = new Date().toISOString();
    const { error } = await supabase.from("alerts").update(patch).eq("id", id);
    if (error) return toast.error(error.message);
    await audit(`alert.${status}`, id);
    qc.invalidateQueries({ queryKey: ["alerts"] });
  }
  async function escalate(a: (typeof data)[number]) {
    const { data: inc, error } = await supabase.from("incidents").insert({ title: a.title, summary: a.description, severity: a.severity }).select().single();
    if (error || !inc) return toast.error(error?.message ?? "Failed");
    await supabase.from("alerts").update({ status: "escalated", incident_id: inc.id, acknowledged_at: a.acknowledged_at ?? new Date().toISOString() }).eq("id", a.id);
    await supabase.from("incident_events").insert({ incident_id: inc.id, kind: "created", body: `Incident opened from alert: ${a.title}` });
    await audit("alert.escalate", a.id);
    toast.success(`Incident ${inc.ref} opened`);
    navigate({ to: "/incidents/$id", params: { id: inc.id } });
  }

  return (
    <div>
      <PageHeader title="Alerts" sub={`${rows.length} shown`} />
      <div className="mb-4 flex flex-wrap gap-2">
        {["all", ...SEVERITIES].map((s) => (
          <button key={s} onClick={() => setSev(s)} className={`data rounded border px-2.5 py-1 text-xs capitalize ${sev === s ? "border-primary text-primary" : "text-muted-foreground"}`}>{s}</button>
        ))}
        <span className="mx-2 w-px bg-border" />
        {STATUSES.map((s) => (
          <button key={s} onClick={() => setSt(s)} className={`data rounded border px-2.5 py-1 text-xs ${st === s ? "border-primary text-primary" : "text-muted-foreground"}`}>{s.replace("_", " ")}</button>
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
        <Table>
          <thead><tr><Th>Sev</Th><Th>Alert</Th><Th>Asset</Th><Th>Source</Th><Th>Status</Th><Th>Detected</Th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id} onClick={() => setSel(a.id)} className={`cursor-pointer ${sel === a.id ? "bg-accent/60" : ""}`}>
                <Td><SeverityBadge s={a.severity as Severity} /></Td>
                <Td className="font-medium">{a.title}</Td>
                <Td className="data text-xs text-muted-foreground">{a.assets?.name ?? "—"}</Td>
                <Td className="data text-xs">{a.source}</Td>
                <Td><StatusPill status={a.status} /></Td>
                <Td className="data text-xs text-muted-foreground">{ago(a.detected_at)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
        <aside className="rounded-lg border bg-card p-5">
          {!cur ? <p className="text-sm text-muted-foreground">Select an alert to triage.</p> : (
            <div>
              <SeverityBadge s={cur.severity as Severity} />
              <h2 className="mt-3 text-lg font-semibold">{cur.title}</h2>
              <p className="mt-2 text-sm text-muted-foreground">{cur.description}</p>
              <dl className="data mt-4 space-y-1.5 text-xs">
                <div className="flex justify-between"><dt className="text-muted-foreground">Asset</dt><dd>{cur.assets?.name ?? "—"}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Tactic</dt><dd>{cur.mitre_tactic ?? "—"}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Technique</dt><dd className="text-primary">{cur.mitre_technique ?? "—"}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Status</dt><dd><StatusPill status={cur.status} /></dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Detected</dt><dd>{new Date(cur.detected_at).toLocaleString()}</dd></div>
              </dl>
              <div className="mt-5 grid grid-cols-2 gap-2">
                <Button variant="outline" size="sm" onClick={() => setStatus(cur.id, "acknowledged")}>Acknowledge</Button>
                <Button variant="outline" size="sm" onClick={() => setStatus(cur.id, "investigating")}>Investigate</Button>
                <Button variant="outline" size="sm" onClick={() => setStatus(cur.id, "resolved")}>Resolve</Button>
                <Button variant="outline" size="sm" onClick={() => setStatus(cur.id, "false_positive")}>False positive</Button>
                {cur.incident_id
                  ? <Button size="sm" className="col-span-2" onClick={() => navigate({ to: "/incidents/$id", params: { id: cur.incident_id! } })}>Open incident</Button>
                  : <Button size="sm" variant="destructive" className="col-span-2" onClick={() => escalate(cur)}>Escalate to incident</Button>}
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
