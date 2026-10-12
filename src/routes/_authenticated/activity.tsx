import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { PageHeader, Table, Th, Td, ago } from "@/components/soc/ui";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { listEvents } from "@/lib/api/soc.functions";

export const Route = createFileRoute("/_authenticated/activity")({
  head: () => ({ meta: [{ title: "Activity — FINPAY SOC" }, { name: "description", content: "Raw security event stream." }] }),
  component: Activity,
});

function Activity() {
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [type, setType] = useState("");
  const [outcome, setOutcome] = useState<"" | "success" | "failure" | "unknown">("");
  const [tiOnly, setTiOnly] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(q), 350);
    return () => clearTimeout(t);
  }, [q]);
  const filters = { q: debounced, type, outcome, tiOnly };
  const { data, isFetching } = useQuery({ queryKey: ["events", filters], queryFn: () => listEvents({ data: filters }), refetchInterval: 10000 });
  const rows = data?.rows ?? [];
  return (
    <div>
      <PageHeader title="Activity Stream" sub="Events from agents, log forwarders, Wazuh and applications · auto-refreshing · newest 300 shown" />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Input placeholder="Search host, user, IP, message…" value={q} className="max-w-sm"
          onChange={(e) => setQ(e.target.value)} />
        <select className="data h-9 rounded-md border bg-background px-2 text-xs" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">All event types</option>
          {data?.types.map((t) => <option key={t}>{t}</option>)}
        </select>
        <select className="data h-9 rounded-md border bg-background px-2 text-xs" value={outcome} onChange={(e) => setOutcome(e.target.value as typeof outcome)}>
          <option value="">Any outcome</option><option value="failure">failure</option><option value="success">success</option><option value="unknown">unknown</option>
        </select>
        <label className="flex items-center gap-2 text-xs text-muted-foreground"><Switch checked={tiOnly} onCheckedChange={setTiOnly} /> Threat-intel hits only</label>
        {isFetching && <span className="data text-[10px] text-muted-foreground">refreshing…</span>}
      </div>
      <Table>
        <thead><tr><Th>Time</Th><Th>Type</Th><Th>Host</Th><Th>User</Th><Th>Source IP</Th><Th>Outcome</Th><Th>Message</Th><Th>Source</Th></tr></thead>
        <tbody className="data text-xs">
          {rows.map((e) => (
            <tr key={e.id}>
              <Td className="text-xs text-muted-foreground" ><span title={new Date(e.occurred_at).toLocaleString()}>{ago(e.occurred_at)}</span></Td>
              <Td className="text-xs text-primary">{e.event_type}</Td>
              <Td className="text-xs">{e.host}</Td>
              <Td className="text-xs">{e.username}</Td>
              <Td className="text-xs">{e.src_ip}{e.ti_match && <span className="ml-1 rounded bg-sev-high/15 px-1 text-[10px] text-sev-high" title="Listed in a threat-intelligence feed">{e.ti_match}</span>}</Td>
              <Td className={`text-xs ${e.outcome === "failure" ? "text-sev-high" : e.outcome === "success" ? "text-ok" : "text-muted-foreground"}`}>{e.outcome}</Td>
              <Td className="max-w-md truncate text-xs text-muted-foreground"><span title={e.message ?? ""}>{e.message}</span></Td>
              <Td className="text-xs text-muted-foreground">{e.source_name ?? "—"}</Td>
            </tr>
          ))}
          {data && !rows.length && <tr><Td className="text-muted-foreground">No events. Connect an agent from Settings → Event sources.</Td></tr>}
        </tbody>
      </Table>
    </div>
  );
}
