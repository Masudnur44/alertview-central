import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { supabase } from "@/integrations/supabase/client";
import { Panel, PageHeader, Stat, SeverityBadge, StatusPill, ago, SEVERITIES, sevText, type Severity } from "@/components/soc/ui";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({ meta: [{ title: "Overview — FINPAY SOC" }, { name: "description", content: "FINPAYTECH security posture at a glance." }] }),
  component: Dashboard,
});

function useOverview() {
  return useQuery({
    queryKey: ["overview"],
    refetchInterval: 30000,
    queryFn: async () => {
      const [alerts, assets, incidents, vulns, events] = await Promise.all([
        supabase.from("alerts").select("id,title,severity,status,detected_at,acknowledged_at,resolved_at,source").order("detected_at", { ascending: false }),
        supabase.from("assets").select("id,name,status,exposure,is_new,tls_expires_at"),
        supabase.from("incidents").select("id,ref,title,severity,status,opened_at").order("opened_at", { ascending: false }),
        supabase.from("vulnerabilities").select("id,severity,status,exploited_in_wild"),
        supabase.from("events").select("id,event_type,outcome,occurred_at").gte("occurred_at", new Date(Date.now() - 864e5).toISOString()),
      ]);
      return { alerts: alerts.data ?? [], assets: assets.data ?? [], incidents: incidents.data ?? [], vulns: vulns.data ?? [], events: events.data ?? [] };
    },
  });
}

function Dashboard() {
  const { data } = useOverview();
  if (!data) return <p className="data text-sm text-muted-foreground">Loading telemetry…</p>;
  const open = data.alerts.filter((a) => !["resolved", "false_positive", "closed"].includes(a.status));
  const crit = open.filter((a) => a.severity === "critical").length;
  const high = open.filter((a) => a.severity === "high").length;
  const offline = data.assets.filter((a) => a.status === "offline").length;
  const activeInc = data.incidents.filter((i) => i.status !== "closed" && i.status !== "resolved");
  const openVulns = data.vulns.filter((v) => v.status !== "fixed");
  const posture = crit > 0 ? { l: "ELEVATED", c: "text-sev-critical" } : high > 2 ? { l: "GUARDED", c: "text-sev-high" } : { l: "NORMAL", c: "text-ok" };
  const certs = data.assets.filter((a) => a.tls_expires_at && new Date(a.tls_expires_at).getTime() - Date.now() < 30 * 864e5);
  const ackd = data.alerts.filter((a) => a.acknowledged_at);
  const mttr = ackd.length ? Math.round(ackd.reduce((s, a) => s + (new Date(a.acknowledged_at!).getTime() - new Date(a.detected_at).getTime()), 0) / ackd.length / 60000) : null;

  const buckets = Array.from({ length: 24 }, (_, i) => {
    const h = new Date(Date.now() - (23 - i) * 36e5);
    return { h: `${h.getHours()}:00`, events: 0, failures: 0 };
  });
  data.events.forEach((e) => {
    const idx = 23 - Math.floor((Date.now() - new Date(e.occurred_at).getTime()) / 36e5);
    if (idx >= 0 && idx < 24) { buckets[idx].events++; if (e.outcome === "failure") buckets[idx].failures++; }
  });

  return (
    <div>
      <PageHeader title="Security Overview" sub="Continuous visibility across FINPAYTECH" />
      <div className="mb-4 grid gap-4 md:grid-cols-[1.2fr_repeat(4,1fr)]">
        <div className="rounded-lg border bg-card p-4 glow">
          <p className="data text-[10px] uppercase tracking-[0.2em] text-muted-foreground">Overall posture</p>
          <p className={`data mt-2 text-3xl font-bold ${posture.c}`}>{posture.l}</p>
          <p className="mt-1 text-xs text-muted-foreground">{open.length} open alerts · {activeInc.length} active incidents</p>
        </div>
        <Stat label="Critical alerts" value={crit} tone="text-sev-critical" />
        <Stat label="High alerts" value={high} tone="text-sev-high" />
        <Stat label="Assets offline" value={`${offline}/${data.assets.length}`} tone={offline ? "text-sev-high" : "text-ok"} />
        <Stat label="Mean time to ack" value={mttr != null ? `${mttr}m` : "—"} hint="MTTA across acknowledged alerts" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Event volume · 24h" className="lg:col-span-2">
          <div className="h-56">
            <ResponsiveContainer>
              <AreaChart data={buckets}>
                <XAxis dataKey="h" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} interval={3} />
                <YAxis tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} width={28} />
                <Tooltip contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", fontSize: 12 }} />
                <Area dataKey="events" stroke="var(--chart-1)" fill="var(--chart-1)" fillOpacity={0.15} />
                <Area dataKey="failures" stroke="var(--chart-3)" fill="var(--chart-3)" fillOpacity={0.2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Open alerts by severity">
          <div className="space-y-3">
            {SEVERITIES.map((s) => {
              const n = open.filter((a) => a.severity === s).length;
              return (
                <div key={s}>
                  <div className="flex justify-between text-xs"><span className="capitalize">{s}</span><span className={`data ${sevText[s]}`}>{n}</span></div>
                  <div className="mt-1 h-1.5 rounded bg-muted"><div className={`h-full rounded bg-current ${sevText[s]}`} style={{ width: `${open.length ? (n / open.length) * 100 : 0}%` }} /></div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel title="Needs immediate attention" className="lg:col-span-2" action={<Link to="/alerts" className="text-xs text-primary">All alerts →</Link>}>
          <ul className="divide-y">
            {open.sort((a, b) => SEVERITIES.indexOf(a.severity as Severity) - SEVERITIES.indexOf(b.severity as Severity)).slice(0, 6).map((a) => (
              <li key={a.id} className="flex items-center gap-3 py-2.5">
                <SeverityBadge s={a.severity as Severity} />
                <span className="flex-1 truncate text-sm">{a.title}</span>
                <span className="data text-xs text-muted-foreground">{a.source}</span>
                <span className="data w-24 text-right text-xs text-muted-foreground">{ago(a.detected_at)}</span>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Active incidents" action={<Link to="/incidents" className="text-xs text-primary">View →</Link>}>
          <ul className="space-y-3">
            {activeInc.map((i) => (
              <li key={i.id}>
                <Link to="/incidents/$id" params={{ id: i.id }} className="block rounded border p-3 hover:border-primary/50">
                  <div className="flex items-center justify-between"><span className="data text-xs text-primary">{i.ref}</span><SeverityBadge s={i.severity as Severity} /></div>
                  <p className="mt-1 text-sm">{i.title}</p>
                  <div className="mt-1"><StatusPill status={i.status} /></div>
                </Link>
              </li>
            ))}
            {!activeInc.length && <p className="text-sm text-muted-foreground">No active incidents.</p>}
          </ul>
        </Panel>

        <Panel title="External environment">
          <dl className="data space-y-2 text-sm">
            <Row k="Internet-facing assets" v={data.assets.filter((a) => a.exposure === "external").length} />
            <Row k="Newly discovered" v={data.assets.filter((a) => a.is_new).length} warn />
            <Row k="Certs expiring <30d" v={certs.length} warn />
          </dl>
        </Panel>
        <Panel title="Vulnerability status">
          <dl className="data space-y-2 text-sm">
            <Row k="Open findings" v={openVulns.length} />
            <Row k="Critical" v={openVulns.filter((v) => v.severity === "critical").length} warn />
            <Row k="Known exploited" v={openVulns.filter((v) => v.exploited_in_wild).length} warn />
          </dl>
        </Panel>
        <Panel title="While you were away · 24h">
          <dl className="data space-y-2 text-sm">
            <Row k="New alerts" v={data.alerts.filter((a) => Date.now() - new Date(a.detected_at).getTime() < 864e5).length} />
            <Row k="Events ingested" v={data.events.length} />
            <Row k="Failed logins" v={data.events.filter((e) => e.outcome === "failure").length} warn />
          </dl>
        </Panel>
      </div>
    </div>
  );
}

function Row({ k, v, warn }: { k: string; v: number; warn?: boolean }) {
  return <div className="flex justify-between"><dt className="text-muted-foreground">{k}</dt><dd className={warn && v ? "text-sev-high" : ""}>{v}</dd></div>;
}
