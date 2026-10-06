import { createFileRoute, Link, Outlet, useMatchRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader, SeverityBadge, StatusPill, Table, Th, Td, ago, type Severity } from "@/components/soc/ui";

export const Route = createFileRoute("/_authenticated/incidents")({
  head: () => ({ meta: [{ title: "Incidents — FINPAY SOC" }, { name: "description", content: "Security incident management." }] }),
  component: Incidents,
});

const STAGES = ["new", "triage", "contained", "resolved", "closed"];

function Incidents() {
  const match = useMatchRoute();
  const { data = [] } = useQuery({
    queryKey: ["incidents"],
    queryFn: async () => (await supabase.from("incidents").select("*, alerts(id)").order("opened_at", { ascending: false })).data ?? [],
  });
  if (match({ to: "/incidents/$id" })) return <Outlet />;
  return (
    <div>
      <PageHeader title="Incidents" sub="Escalate alerts from the Alerts queue to open an incident" />
      <div className="mb-6 grid grid-cols-5 gap-2">
        {STAGES.map((s) => (
          <div key={s} className="rounded-lg border bg-card p-3">
            <p className="data text-[10px] uppercase tracking-widest text-muted-foreground">{s}</p>
            <p className="data mt-1 text-2xl font-bold">{data.filter((i) => i.status === s).length}</p>
          </div>
        ))}
      </div>
      <Table>
        <thead><tr><Th>Ref</Th><Th>Title</Th><Th>Sev</Th><Th>Status</Th><Th>Alerts</Th><Th>Opened</Th></tr></thead>
        <tbody>
          {data.map((i) => (
            <tr key={i.id}>
              <Td><Link to="/incidents/$id" params={{ id: i.id }} className="data text-primary">{i.ref}</Link></Td>
              <Td><Link to="/incidents/$id" params={{ id: i.id }}>{i.title}</Link></Td>
              <Td><SeverityBadge s={i.severity as Severity} /></Td>
              <Td><StatusPill status={i.status} /></Td>
              <Td className="data">{i.alerts?.length ?? 0}</Td>
              <Td className="data text-xs text-muted-foreground">{ago(i.opened_at)}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}
