import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Download, Printer } from "lucide-react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { PageHeader, Panel, Stat, SEVERITIES } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { getReport } from "@/lib/api/soc.functions";
import { downloadCsv } from "@/lib/risk";

export const Route = createFileRoute("/_authenticated/reports")({
  head: () => ({ meta: [{ title: "Reports — FINPAY SOC" }, { name: "description", content: "Daily, weekly and monthly security reports and metrics." }] }),
  component: Reports,
});

const PERIODS = { daily: 1, weekly: 7, monthly: 30, quarterly: 90 } as const;

function Reports() {
  const [p, setP] = useState<keyof typeof PERIODS>("weekly");
  const { data } = useQuery({ queryKey: ["report", p], queryFn: () => getReport({ data: { days: PERIODS[p] } }) });
  const since = new Date(Date.now() - PERIODS[p] * 864e5);
  if (!data) return <p className="data text-sm text-muted-foreground">Building report…</p>;
  const m = data.metrics;
  const fp = m.alerts ? Math.round((m.false_positives / m.alerts) * 100) : 0;
  const cov = data.coverage.total ? Math.round((data.coverage.monitored / data.coverage.total) * 100) : 0;
  const bySev = SEVERITIES.map((s) => ({ s, n: data.bySeverity.find((r) => r.s === s)?.n ?? 0 }));

  function exportCsv() {
    downloadCsv(`finpay-soc-${p}-report-${new Date().toISOString().slice(0, 10)}.csv`, [
      ["metric", "value"], ["period", p], ["from", since.toISOString()], ["to", new Date().toISOString()],
      ["alerts", m.alerts], ["mtta_minutes", m.mtta_min], ["mttr_minutes", m.mttr_min], ["false_positive_pct", fp],
      ["incidents_opened", data!.incidents.opened], ["incidents_closed", data!.incidents.closed], ["mean_time_to_contain_hours", data!.incidents.mttc_hours],
      ["events_ingested", data!.events.events], ["threat_intel_hits", data!.events.ti_hits],
      ["asset_coverage_pct", cov], ["external_assets", data!.coverage.external],
      ["vulns_open", data!.vulns.open], ["vulns_critical_open", data!.vulns.critical_open], ["vulns_overdue", data!.vulns.overdue], ["vulns_fixed_in_period", data!.vulns.fixed_in_period],
      [], ["severity", "alerts"], ...bySev.map((r) => [r.s, r.n]),
      [], ["source", "alerts"], ...data!.bySource.map((r) => [r.s, r.n]),
      [], ["attack_technique", "alerts"], ...data!.byTechnique.map((r) => [r.s, r.n]),
      [], ["asset", "alerts"], ...data!.topAssets.map((r) => [r.s, r.n]),
    ]);
  }

  return (
    <div>
      <PageHeader title="Security Reports" sub={`${p.charAt(0).toUpperCase() + p.slice(1)} report · ${since.toLocaleString()} → now`}
        action={<div className="flex flex-wrap gap-2 print:hidden">
          {(Object.keys(PERIODS) as (keyof typeof PERIODS)[]).map((k) => (
            <Button key={k} variant={p === k ? "default" : "outline"} size="sm" onClick={() => setP(k)} className="capitalize">{k}</Button>
          ))}
          <Button size="sm" variant="outline" onClick={exportCsv}><Download className="mr-1 h-4 w-4" />CSV</Button>
          <Button size="sm" variant="outline" onClick={() => window.print()}><Printer className="mr-1 h-4 w-4" />Print / PDF</Button>
        </div>} />
      <div className="grid gap-4 md:grid-cols-4">
        <Stat label="Alert volume" value={m.alerts} />
        <Stat label="Mean time to acknowledge" value={m.mtta_min != null ? `${m.mtta_min}m` : "—"} />
        <Stat label="Mean time to resolve" value={m.mttr_min != null ? `${m.mttr_min}m` : "—"} />
        <Stat label="False-positive rate" value={`${fp}%`} hint="High rates mean rules need tuning" />
        <Stat label="Incidents opened" value={data.incidents.opened} />
        <Stat label="Incidents closed" value={data.incidents.closed} hint={data.incidents.mttc_hours != null ? `Mean time to contain ${data.incidents.mttc_hours}h` : undefined} />
        <Stat label="Events ingested" value={Number(data.events.events).toLocaleString()} hint={`${data.events.ti_hits} threat-intel hits`} />
        <Stat label="Asset coverage" value={`${cov}%`} tone="text-ok" hint={`${data.coverage.monitored}/${data.coverage.total} monitored`} />
        <Stat label="Open vulnerabilities" value={data.vulns.open} />
        <Stat label="Critical vulns open" value={data.vulns.critical_open} tone="text-sev-critical" />
        <Stat label="Past SLA" value={data.vulns.overdue} tone="text-sev-medium" />
        <Stat label="Fixed this period" value={data.vulns.fixed_in_period} tone="text-ok" />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Panel title="Alerts per day"><Chart data={data.daily.map((d) => ({ s: d.d.slice(5), n: d.n }))} /></Panel>
        <Panel title="Alerts by severity"><Chart data={bySev} /></Panel>
        <Panel title="Alerts by source"><Chart data={data.bySource} /></Panel>
        <Panel title="Top ATT&CK techniques">
          <ul className="data space-y-1.5 text-xs">{data.byTechnique.map((r) => <li key={r.s} className="flex justify-between"><span className="truncate">{r.s}</span><span className="text-primary">{r.n}</span></li>)}</ul>
        </Panel>
        <Panel title="Most-alerted assets">
          <ul className="data space-y-1.5 text-xs">{data.topAssets.map((r) => <li key={r.s} className="flex justify-between"><span className="truncate">{r.s}</span><span className="text-sev-high">{r.n}</span></li>)}
            {!data.topAssets.length && <li className="text-muted-foreground">No alerts linked to assets in this period.</li>}</ul>
        </Panel>
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
