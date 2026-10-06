import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader, Table, Th, Td, ago } from "@/components/soc/ui";
import { Input } from "@/components/ui/input";

export const Route = createFileRoute("/_authenticated/activity")({
  head: () => ({ meta: [{ title: "Activity — FINPAY SOC" }, { name: "description", content: "Raw security event stream." }] }),
  component: Activity,
});

function Activity() {
  const [q, setQ] = useState("");
  const { data = [] } = useQuery({
    queryKey: ["events"],
    refetchInterval: 10000,
    queryFn: async () => (await supabase.from("events").select("*").order("occurred_at", { ascending: false }).limit(300)).data ?? [],
  });
  const rows = data.filter((e) => JSON.stringify(e).toLowerCase().includes(q.toLowerCase()));
  return (
    <div>
      <PageHeader title="Activity Stream" sub="Events received from servers, endpoints and applications · auto-refreshing" />
      <Input placeholder="Search host, user, IP, message…" value={q} onChange={(e) => setQ(e.target.value)} className="mb-4 max-w-sm" />
      <Table>
        <thead><tr><Th>Time</Th><Th>Type</Th><Th>Host</Th><Th>User</Th><Th>Source IP</Th><Th>Outcome</Th><Th>Message</Th></tr></thead>
        <tbody className="data text-xs">
          {rows.map((e) => (
            <tr key={e.id}>
              <Td className="text-xs text-muted-foreground">{ago(e.occurred_at)}</Td>
              <Td className="text-xs text-primary">{e.event_type}</Td>
              <Td className="text-xs">{e.host}</Td>
              <Td className="text-xs">{e.username}</Td>
              <Td className="text-xs">{e.src_ip}</Td>
              <Td className={`text-xs ${e.outcome === "failure" ? "text-sev-high" : "text-ok"}`}>{e.outcome}</Td>
              <Td className="max-w-md truncate text-xs text-muted-foreground">{e.message}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}
