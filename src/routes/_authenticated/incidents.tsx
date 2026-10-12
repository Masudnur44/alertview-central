import { createFileRoute, Link, Outlet, useMatchRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { PageHeader, SeverityBadge, StatusPill, Table, Th, Td, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { createIncident, listIncidents } from "@/lib/api/soc.functions";
import { useCan } from "@/lib/session";
import type { Severity } from "@/lib/types";

export const Route = createFileRoute("/_authenticated/incidents")({
  head: () => ({ meta: [{ title: "Incidents — FINPAY SOC" }, { name: "description", content: "Security incident management." }] }),
  component: Incidents,
});

const STAGES = ["new", "triage", "contained", "resolved", "closed"];

function Incidents() {
  const match = useMatchRoute();
  const canManage = useCan("incidents.manage");
  const [open, setOpen] = useState(false);
  const { data = [] } = useQuery({ queryKey: ["incidents"], queryFn: () => listIncidents(), refetchInterval: 30000 });
  if (match({ to: "/incidents/$id" })) return <Outlet />;
  const active = data.filter((i) => !["resolved", "closed"].includes(i.status));
  return (
    <div>
      <PageHeader title="Incidents" sub="Escalate alerts from the Alerts queue, or open one manually"
        action={canManage && <Button onClick={() => setOpen(true)}>New incident</Button>} />
      <div className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-5">
        {STAGES.map((s) => (
          <div key={s} className="rounded-lg border bg-card p-3">
            <p className="data text-[10px] uppercase tracking-widest text-muted-foreground">{s}</p>
            <p className="data mt-1 text-2xl font-bold">{data.filter((i) => i.status === s).length}</p>
          </div>
        ))}
      </div>
      <Table>
        <thead><tr><Th>Ref</Th><Th>Title</Th><Th>Sev</Th><Th>Status</Th><Th>Owner</Th><Th>Alerts</Th><Th>Opened</Th><Th>Age</Th></tr></thead>
        <tbody>
          {data.map((i) => (
            <tr key={i.id} className={["resolved", "closed"].includes(i.status) ? "opacity-60" : ""}>
              <Td><Link to="/incidents/$id" params={{ id: i.id }} className="data text-primary">{i.ref}</Link></Td>
              <Td><Link to="/incidents/$id" params={{ id: i.id }}>{i.title}</Link></Td>
              <Td><SeverityBadge s={i.severity} /></Td>
              <Td><StatusPill status={i.status} /></Td>
              <Td className="text-xs text-muted-foreground">{i.owner_name ?? "—"}</Td>
              <Td className="data">{i.alert_count ?? 0}</Td>
              <Td className="data text-xs text-muted-foreground">{new Date(i.opened_at).toLocaleDateString()}</Td>
              <Td className="data text-xs text-muted-foreground">{ago(i.closed_at ?? i.resolved_at ?? i.opened_at)}</Td>
            </tr>
          ))}
          {!data.length && <tr><Td className="text-muted-foreground">No incidents.</Td></tr>}
        </tbody>
      </Table>
      {active.length > 0 && <p className="mt-3 text-xs text-muted-foreground">{active.length} active incident(s).</p>}
      <NewIncident open={open} onOpenChange={setOpen} />
    </div>
  );
}

function NewIncident({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const navigate = useNavigate();
  const [f, setF] = useState<{ title: string; summary: string; severity: Severity }>({ title: "", summary: "", severity: "high" });
  const create = useMutation({
    mutationFn: () => createIncident({ data: f }),
    onSuccess: (r) => { toast.success(`Incident ${r.ref} opened`); onOpenChange(false); navigate({ to: "/incidents/$id", params: { id: r.id } }); },
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader><DialogTitle>Open incident</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <Input placeholder="Title" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} />
          <Textarea placeholder="What happened, what is affected, how it was reported" rows={4} value={f.summary} onChange={(e) => setF({ ...f, summary: e.target.value })} />
          <select className="h-9 w-full rounded-md border bg-background px-2 text-sm" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value as Severity })}>
            {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <Button className="w-full" disabled={f.title.trim().length < 3 || create.isPending} onClick={() => create.mutate()}>Open incident</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
