import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Download } from "lucide-react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader, Panel, Stat, SEVERITIES } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/_authenticated/reports")({
  head: () => ({ meta: [{ title: "Reports — FINPAY SOC" }, { name: "description", content: "Daily, weekly and monthly security reports and metrics." }] }),
  component: Reports,
});

const PERIODS = { daily: 1, weekly: 7, monthly: 30 } as const;

function Reports() {
  const [p, setP] = useState<keyof typeof PERIODS>("weekly");
  const since = new Date(Date.now() - PERIODS[p] * 864e5).toISOString();
  const { data } = useQuery({
    queryKey: ["report", p],
    queryFn: async () => {
      const [al, inc, as, v] = await Promise.all([
        supabase.from("alerts").select("*").gte("detected_at", since),
        supabase.from("incidents").select("*").gte("opened_at", since),
        supabase.from("assets").select("id,monitored,asset_type"),
        supabase.from("vulnerabilities").select("severity,status"),
      ]);
      return { alerts: al.data ?? [], incidents: inc.data ?? [], assets: as.data ?? [], vulns: v.data ?? [] };
    },
  });
  if (!data) return null;
  const mins = (xs: number[]) => (xs.length ? Math.round(xs.reduce((a, b) => a + b, 0) / xs.length / 60000) : null);
  const mtta = mins(data.alerts.filter((a) => a.acknowledged_at).map((a) => +new Date(a.acknowledged_at!) - +new Date(a.detected_at)));
  const mttr = mins(data.alerts.filter((a) => a.resolved_at).map((a) => +new Date(a.resolved_at!) - +new Date(a.detected_at)));
  const fp = data.alerts.length ? Math.round((data.alerts.filter((a) => a.status === "false_positive").length / data.alerts.length) * 100) : 0;
  const closed = data.incidents.filter((i) => ["resolved", "closed"].includes(i.status)).length;
  const cov = data.assets.length ? Math.round((data.assets.filter((a) => a.monitored).length / data.assets.length) * 100) : 0;
  const bySev = SEVERITIES.map((s) => ({ s, n: data.alerts.filter((a) => a.severity === s).length }));
  const bySrc = Object.entries(data.alerts.reduce<Record<string, number>>((m, a) => ((m[a.source] = (m[a.source] ?? 0) + 1), m), {})).map(([s, n]) => ({ s, n }));

  function exportCsv() {
    const lines = [["metric", "value"], ["period", p], ["alerts", data!.alerts.length], ["incidents", data!.incidents.length], ["mtta_min", mtta ?? ""], ["mttr_min", mttr ?? ""], ["false_positive_pct", fp], ["incidents_closed", closed], ["asset_coverage_pct", cov],
      ["critical_vulns_open", data!.vulns.filter((v) => v.severity === "critical" && v.status !== "fixed").length]];
    const blob = new Blob([lines.map((l) => l.join(",")).join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `finpay-soc-${p}-report.csv`;
    a.click();
  }

  return (
    <div>
      <PageHeader title="Security Reports" sub={`${p.charAt(0).toUpperCase() + p.slice(1)} report · since ${new Date(since).toLocaleString()}`}
        action={<div className="flex gap-2">
          {(Object.keys(PERIODS) as (keyof typeof PERIODS)[]).map((k) => (
            <Button key={k} variant={p === k ? "default" : "outline"} size="sm" onClick={() => setP(k)} className="capitalize">{k}</Button>
          ))}
          <Button size="sm" variant="outline" onClick={exportCsv}><Download className="mr-1 h-4 w-4" />CSV</Button>
        </div>} />
      <div className="grid gap-4 md:grid-cols-4">
        <Stat label="Alert volume" value={data.alerts.length} />
        <Stat label="Mean time to acknowledge" value={mtta != null ? `${mtta}m` : "—"} />
        <Stat label="Mean time to resolve" value={mttr != null ? `${mttr}m` : "—"} />
        <Stat label="False-positive rate" value={`${fp}%`} />
        <Stat label="Incidents opened" value={data.incidents.length} />
        <Stat label="Incident closure" value={data.incidents.length ? `${Math.round((closed / data.incidents.length) * 100)}%` : "—"} />
        <Stat label="Asset coverage" value={`${cov}%`} tone="text-ok" />
        <Stat label="Critical vulns open" value={data.vulns.filter((v) => v.severity === "critical" && v.status !== "fixed").length} tone="text-sev-critical" />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Panel title="Alerts by severity"><Chart data={bySev} /></Panel>
        <Panel title="Alerts by source"><Chart data={bySrc} /></Panel>
      </div>
    </div>
  );
}

function Chart({ data }: { data: { s: string; n: number }[] }) {
  return (
    <div className="h-56">
      <ResponsiveContainer>
        <BarChart data={data}>
          <XAxis dataKey="s" tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} />
          <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} width={28} allowDecimals={false} />
          <Tooltip contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", fontSize: 12 }} cursor={{ fill: "var(--accent)" }} />
          <Bar dataKey="n" fill="var(--chart-1)" radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
