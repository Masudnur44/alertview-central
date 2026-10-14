import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Activity, AlertOctagon, CircleCheck, Clock, Gauge, Radio, Send, ShieldAlert, TrendingUp, Users } from "lucide-react";
import { Panel, SeverityBadge, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { SendToDevDialog } from "@/components/soc/SendToDevDialog";
import { getCommandCenter } from "@/lib/api/soc.functions";
import { useCan } from "@/lib/session";
import type { Severity } from "@/lib/types";

export const Route = createFileRoute("/_authenticated/command")({
  head: () => ({ meta: [{ title: "Command Center — FINPAY SOC" }, { name: "description", content: "Live health, early warnings and hand-offs." }] }),
  component: Command,
});

type Tile = {
  id: string; name: string; address: string | null; status: string; criticality: Severity; exposure: string; monitored: boolean; is_new: boolean;
  response_ms: number | null; http_status: number | null; tls_expires_at: string | null; last_checked_at: string | null; last_seen: string | null;
  team_name: string | null; team_id: string | null; open_alerts: number; worst_rank: number | null; open_issues: number; recent: boolean[];
};

function tileState(t: Tile): { tone: string; label: string } {
  if (t.status === "offline" || (t.worst_rank ?? 0) >= 5) return { tone: "border-sev-critical/60 bg-sev-critical/10", label: t.status === "offline" ? "DOWN" : "CRITICAL" };
  if ((t.worst_rank ?? 0) >= 4) return { tone: "border-sev-high/60 bg-sev-high/10", label: "PROBLEM" };
  if (t.status === "degraded" || (t.worst_rank ?? 0) >= 2) return { tone: "border-sev-medium/50 bg-sev-medium/10", label: "WARNING" };
  if (t.status === "unknown" || !t.last_checked_at && t.exposure === "external") return { tone: "border-border bg-muted/30", label: "NO DATA" };
  return { tone: "border-ok/30 bg-ok/5", label: "OK" };
}

function Command() {
  const canSend = useCan("issues.send");
  const { data, dataUpdatedAt, isFetching } = useQuery({ queryKey: ["command"], queryFn: () => getCommandCenter(), refetchInterval: 15000 });
  const [team, setTeam] = useState<string>("all");
  const [send, setSend] = useState<{ id: string; title: string } | null>(null);

  const board = (data?.board ?? []) as Tile[];
  const teams = useMemo(() => [...new Set(board.map((b) => b.team_name ?? "Unassigned"))].sort(), [board]);
  const shown = team === "all" ? board : board.filter((b) => (b.team_name ?? "Unassigned") === team);
  if (!data) return <p className="data text-sm text-muted-foreground">Connecting to telemetry…</p>;

  const down = board.filter((b) => b.status === "offline").length;
  const crit = data.attention.filter((a) => a.severity === "critical").length;
  const high = data.attention.filter((a) => a.severity === "high").length;
  const overdue = data.issues.filter((i) => i.overdue).length;
  const unacked = data.attention.filter((a) => !a.acknowledged_at && ["critical", "high"].includes(String(a.severity))).length;
  const workerAge = data.workerHeartbeat ? (Date.now() - new Date(data.workerHeartbeat).getTime()) / 60000 : null;
  const state = down || crit ? { l: "INCIDENT", c: "text-sev-critical border-sev-critical/50 bg-sev-critical/10" }
    : high || data.warnings.length ? { l: "DEGRADED", c: "text-sev-medium border-sev-medium/50 bg-sev-medium/10" }
    : { l: "OPERATIONAL", c: "text-ok border-ok/40 bg-ok/10" };

  return (
    <div>
      {/* Status strip */}
      <div className="mb-4 flex flex-wrap items-stretch gap-2">
        <div className={`data flex items-center gap-3 rounded-lg border px-4 py-3 ${state.c}`}>
          <span className="pulse-dot h-2.5 w-2.5 rounded-full bg-current" />
          <div><p className="text-[10px] uppercase tracking-[0.25em] opacity-80">FINPAYTECH status</p><p className="text-xl font-bold">{state.l}</p></div>
        </div>
        {[
          { icon: AlertOctagon, label: "Down now", v: down, bad: down > 0 },
          { icon: ShieldAlert, label: "Critical / high open", v: `${crit} / ${high}`, bad: crit + high > 0 },
          { icon: Clock, label: "Not acknowledged", v: unacked, bad: unacked > 0 },
          { icon: TrendingUp, label: "Early warnings", v: data.warnings.length, bad: data.warnings.length > 0, warn: true },
          { icon: Send, label: "Dev issues overdue", v: overdue, bad: overdue > 0 },
          { icon: Activity, label: "Events / hour", v: Number(data.ingest?.events_hour ?? 0).toLocaleString() },
          { icon: Radio, label: "Sources live", v: `${data.ingest?.sources_live ?? 0}/${data.ingest?.sources_total ?? 0}`, bad: (data.ingest?.sources_total ?? 0) > (data.ingest?.sources_live ?? 0), warn: true },
        ].map((k) => (
          <div key={k.label} className="min-w-32 flex-1 rounded-lg border bg-card px-3 py-2">
            <p className="data flex items-center gap-1.5 text-[10px] uppercase tracking-[0.15em] text-muted-foreground"><k.icon className="h-3 w-3" />{k.label}</p>
            <p className={`data mt-1 text-2xl font-bold ${k.bad ? (k.warn ? "text-sev-medium" : "text-sev-critical") : ""}`}>{k.v}</p>
          </div>
        ))}
      </div>
      <p className="data mb-4 flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
        <span>Updated {new Date(dataUpdatedAt).toLocaleTimeString()} · refreshes every 15 s{isFetching ? " · refreshing…" : ""}</span>
        {(workerAge == null || workerAge > 10) && <span className="text-sev-high">Background worker not reporting — checks and notifications are paused</span>}
      </p>

      <div className="grid gap-4 xl:grid-cols-3">
        {/* Needs attention */}
        <Panel title={`Needs attention now (${data.attention.length})`} className="xl:col-span-2" action={<Link to="/alerts" className="text-xs text-primary">Alert queue →</Link>}>
          <ul className="divide-y">
            {data.attention.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 py-2">
                <SeverityBadge s={a.severity as Severity} />
                <Link to="/alerts" search={{ focus: a.id }} className="min-w-48 flex-1 truncate text-sm hover:text-primary">{a.title}</Link>
                <span className="data text-xs text-muted-foreground">{a.asset_name ?? "—"}</span>
                <span className="data w-28 truncate text-xs" title="Owner team">{a.team_name ?? <span className="text-sev-medium">no owner</span>}</span>
                <span className={`data w-24 text-right text-xs ${!a.acknowledged_at ? "text-sev-high" : "text-muted-foreground"}`} title={a.acknowledged_at ? "acknowledged" : "not acknowledged"}>
                  {ago(a.detected_at)}
                </span>
                {a.issue_ref
                  ? <Link to="/issues" search={{ ref: a.issue_ref }} className="data w-28 text-right text-xs text-primary">{a.issue_ref}</Link>
                  : canSend ? <Button size="sm" variant="outline" className="h-7 w-28" onClick={() => setSend({ id: a.id, title: a.title })}><Send className="mr-1 h-3 w-3" />To dev</Button> : <span className="w-28" />}
              </li>
            ))}
            {!data.attention.length && <li className="flex items-center gap-2 py-6 text-sm text-ok"><CircleCheck className="h-4 w-4" /> Nothing needs attention right now.</li>}
          </ul>
        </Panel>

        {/* Early warnings */}
        <Panel title="Before it breaks" action={<span className="data text-[10px] text-muted-foreground">early warnings</span>}>
          <ul className="space-y-2">
            {data.warnings.map((w) => (
              <li key={w.id} className="rounded border border-sev-medium/30 bg-sev-medium/5 p-2.5">
                <div className="flex items-center gap-2"><Gauge className="h-3.5 w-3.5 text-sev-medium" /><span className="flex-1 text-sm">{w.title}</span></div>
                <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{w.description}</p>
                <div className="mt-1.5 flex items-center justify-between">
                  <span className="data text-[10px] text-muted-foreground">{ago(w.detected_at)}</span>
                  {w.issue_ref ? <span className="data text-[11px] text-primary">{w.issue_ref}</span>
                    : canSend && <button onClick={() => setSend({ id: w.id, title: w.title })} className="data text-[11px] text-primary hover:underline">Send to dev →</button>}
                </div>
              </li>
            ))}
            {!data.warnings.length && <li className="text-sm text-muted-foreground">No early-warning signals. Latency, stability, certificates and login rates look normal.</li>}
            {data.slaSoon.map((v) => (
              <li key={v.id} className="rounded border p-2 text-xs">
                <span className="text-sev-high">Vulnerability fix due {ago(v.due_at)}</span> · {v.title} <span className="text-muted-foreground">({v.asset_name})</span>
              </li>
            ))}
          </ul>
        </Panel>

        {/* Health board */}
        <Panel title={`Health board · ${shown.length} systems`} className="xl:col-span-3"
          action={<div className="flex flex-wrap gap-1">{["all", ...teams].map((t) => (
            <button key={t} onClick={() => setTeam(t)} className={`data rounded border px-2 py-0.5 text-[10px] ${team === t ? "border-primary text-primary" : "text-muted-foreground"}`}>{t}</button>
          ))}</div>}>
          <div className="grid grid-cols-[repeat(auto-fill,minmax(210px,1fr))] gap-2">
            {shown.map((t) => {
              const st = tileState(t);
              const days = t.tls_expires_at ? Math.floor((new Date(t.tls_expires_at).getTime() - Date.now()) / 864e5) : null;
              return (
                <Link key={t.id} to="/alerts" search={{ q: t.name }} className={`block rounded-lg border p-2.5 transition hover:border-primary/60 ${st.tone}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium" title={t.address ?? t.name}>{t.name}</span>
                    <span className="data text-[10px] font-bold">{st.label}</span>
                  </div>
                  <p className="data mt-0.5 truncate text-[10px] text-muted-foreground">{t.team_name ?? "no owner team"} · {t.exposure}</p>
                  <div className="mt-2 flex h-3 items-end gap-0.5">
                    {(t.recent ?? []).map((ok, i) => <span key={i} className={`h-full w-1.5 rounded-sm ${ok ? "bg-ok/70" : "bg-sev-critical"}`} />)}
                    {!t.recent?.length && <span className="data text-[10px] text-muted-foreground">{t.exposure === "internal" ? `agent seen ${ago(t.last_seen)}` : t.monitored ? "waiting for first check" : "not monitored"}</span>}
                  </div>
                  <div className="data mt-1.5 flex flex-wrap gap-x-3 text-[10px] text-muted-foreground">
                    {t.response_ms != null && <span className={t.response_ms > 1500 ? "text-sev-medium" : ""}>{t.response_ms} ms</span>}
                    {days != null && <span className={days < 14 ? "text-sev-high" : days < 30 ? "text-sev-medium" : ""}>TLS {days}d</span>}
                    {t.open_alerts > 0 && <span className="text-sev-high">{t.open_alerts} alert{t.open_alerts > 1 ? "s" : ""}</span>}
                    {t.open_issues > 0 && <span className="text-primary">{t.open_issues} with devs</span>}
                  </div>
                </Link>
              );
            })}
            {!shown.length && <p className="text-sm text-muted-foreground">No monitored systems yet. Add assets and turn monitoring on.</p>}
          </div>
        </Panel>

        {/* Issues with developers */}
        <Panel title="With developers" action={<Link to="/issues" className="text-xs text-primary">All issues →</Link>}>
          <ul className="divide-y">
            {data.issues.map((i) => (
              <li key={i.id} className="py-2">
                <div className="flex items-center gap-2">
                  <SeverityBadge s={i.severity as Severity} />
                  <Link to="/issues" search={{ ref: i.ref }} className="data text-xs text-primary">{i.ref}</Link>
                  <span className="data ml-auto text-[10px] uppercase">{String(i.status).replace("_", " ")}</span>
                </div>
                <p className="mt-0.5 truncate text-sm">{i.title}</p>
                <p className={`data text-[10px] ${i.overdue ? "text-sev-critical" : "text-muted-foreground"}`}>{i.team_name ?? "—"} · {i.overdue ? "OVERDUE" : "due"} {ago(i.due_at)}</p>
              </li>
            ))}
            {!data.issues.length && <li className="py-2 text-sm text-muted-foreground">Nothing is waiting on a developer.</li>}
          </ul>
        </Panel>

        {/* Team load */}
        <Panel title="Teams" action={<Users className="h-4 w-4 text-muted-foreground" />}>
          <table className="data w-full text-xs">
            <thead><tr className="text-[10px] uppercase tracking-wider text-muted-foreground"><th className="text-left">Team</th><th>Open</th><th>Overdue</th><th title="Not acknowledged after 1 hour">Silent</th><th title="Mean time to fix, 30 days">MTTR</th></tr></thead>
            <tbody>
              {data.teams.map((t) => (
                <tr key={t.id} className="border-t">
                  <td className="py-1.5"><Link to="/issues" search={{ team: t.id }} className="hover:text-primary">{t.name}</Link></td>
                  <td className="text-center">{t.open}</td>
                  <td className={`text-center ${t.overdue ? "text-sev-critical" : ""}`}>{t.overdue}</td>
                  <td className={`text-center ${t.unacknowledged ? "text-sev-high" : ""}`}>{t.unacknowledged}</td>
                  <td className="text-center">{t.mttr_hours != null ? `${t.mttr_hours}h` : "—"}</td>
                </tr>
              ))}
              {!data.teams.length && <tr><td className="py-2 text-muted-foreground" colSpan={5}>Add teams in Settings → Teams so issues reach the right developers.</td></tr>}
            </tbody>
          </table>
        </Panel>

        {/* What changed */}
        <Panel title="Last 2 hours">
          <ul className="data max-h-80 space-y-1.5 overflow-y-auto text-[11px]">
            {data.changes.map((c, i) => (
              <li key={i} className="flex gap-2">
                <span className="w-14 shrink-0 text-muted-foreground">{new Date(c.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                <span className={c.kind === "resolved" ? "text-ok" : c.kind === "issue" ? "text-primary" : c.severity === "critical" || c.severity === "high" ? "text-sev-high" : ""}>
                  {c.kind === "resolved" ? "✓ " : c.kind === "issue" ? "↳ " : "● "}{c.text}
                </span>
              </li>
            ))}
            {!data.changes.length && <li className="text-muted-foreground">Quiet: no changes in the last 2 hours.</li>}
          </ul>
        </Panel>
      </div>
      <SendToDevDialog alertId={send?.id ?? null} title={send?.title} open={!!send} onOpenChange={(v) => !v && setSend(null)} />
    </div>
  );
}
