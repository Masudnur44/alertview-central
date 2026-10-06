import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader, SeverityBadge, StatusPill, Stat, Table, Th, Td, ago, type Severity } from "@/components/soc/ui";
import { riskScore, audit } from "@/lib/soc";

export const Route = createFileRoute("/_authenticated/vulnerabilities")({
  head: () => ({ meta: [{ title: "Vulnerabilities — FINPAY SOC" }, { name: "description", content: "Risk-prioritized vulnerabilities correlated with alerts." }] }),
  component: Vulns,
});

function Vulns() {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["vulns"],
    queryFn: async () => {
      const [v, a] = await Promise.all([
        supabase.from("vulnerabilities").select("*, assets(id,name,criticality)"),
        supabase.from("alerts").select("asset_id,status").not("status", "in", "(resolved,false_positive)"),
      ]);
      return { vulns: v.data ?? [], alerts: a.data ?? [] };
    },
  });
  const rows = (data?.vulns ?? []).map((v) => {
    const targeted = (data?.alerts ?? []).filter((a) => a.asset_id === v.asset_id).length;
    const base = riskScore({ ...v, criticality: v.assets?.criticality });
    return { ...v, targeted, risk: Math.min(100, base + (targeted ? 10 : 0)) };
  }).sort((a, b) => b.risk - a.risk);
  const open = rows.filter((r) => r.status !== "fixed");

  async function setStatus(id: string, status: string) {
    const { error } = await supabase.from("vulnerabilities").update({ status }).eq("id", id);
    if (error) return toast.error(error.message);
    await audit(`vuln.${status}`, id);
    qc.invalidateQueries({ queryKey: ["vulns"] });
  }

  return (
    <div>
      <PageHeader title="Vulnerabilities" sub="Ranked by risk: severity, active exploitation, exposure, asset criticality and live alert activity" />
      <div className="mb-6 grid gap-4 md:grid-cols-4">
        <Stat label="Open" value={open.length} />
        <Stat label="Critical" value={open.filter((v) => v.severity === "critical").length} tone="text-sev-critical" />
        <Stat label="Known exploited" value={open.filter((v) => v.exploited_in_wild).length} tone="text-sev-high" />
        <Stat label="Under active targeting" value={open.filter((v) => v.targeted).length} tone="text-sev-high" hint="Asset also has open alerts" />
      </div>
      <Table>
        <thead><tr><Th>Risk</Th><Th>Finding</Th><Th>Sev</Th><Th>Asset</Th><Th>Signals</Th><Th>Status</Th><Th>First seen</Th></tr></thead>
        <tbody>
          {rows.map((v) => (
            <tr key={v.id}>
              <Td><span className={`data text-lg font-bold ${v.risk >= 85 ? "text-sev-critical" : v.risk >= 65 ? "text-sev-high" : "text-sev-medium"}`}>{v.risk}</span></Td>
              <Td><div className="font-medium">{v.title}</div><div className="data text-xs text-muted-foreground">{v.cve ?? "—"} · CVSS {v.cvss ?? "—"}</div></Td>
              <Td><SeverityBadge s={v.severity as Severity} /></Td>
              <Td className="data text-xs">{v.assets?.name}</Td>
              <Td className="data space-x-1 text-[10px]">
                {v.exploited_in_wild && <span className="rounded bg-sev-critical/15 px-1 text-sev-critical">KEV</span>}
                {v.internet_exposed && <span className="rounded bg-sev-medium/15 px-1 text-sev-medium">EXPOSED</span>}
                {v.targeted > 0 && <span className="rounded bg-sev-high/15 px-1 text-sev-high">TARGETED</span>}
              </Td>
              <Td>
                <select value={v.status} onChange={(e) => setStatus(v.id, e.target.value)} className="data h-7 rounded border bg-background px-1 text-xs">
                  {["open", "in_progress", "fixed", "accepted"].map((s) => <option key={s}>{s}</option>)}
                </select>
                <div className="mt-1"><StatusPill status={v.status} /></div>
              </Td>
              <Td className="data text-xs text-muted-foreground">{ago(v.first_seen)}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}
