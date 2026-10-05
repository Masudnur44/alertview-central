import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { RefreshCw } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader, Panel, StatusPill, Table, Th, Td, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { runExternalChecks } from "@/lib/checks.functions";
import { useServerFn } from "@tanstack/react-start";

export const Route = createFileRoute("/_authenticated/surface")({
  head: () => ({ meta: [{ title: "External Surface — FINPAY SOC" }, { name: "description", content: "Internet-facing exposure monitoring." }] }),
  component: Surface,
});

function Surface() {
  const qc = useQueryClient();
  const run = useServerFn(runExternalChecks);
  const [busy, setBusy] = useState(false);
  const { data } = useQuery({
    queryKey: ["surface"],
    queryFn: async () => {
      const [a, c] = await Promise.all([
        supabase.from("assets").select("*").eq("exposure", "external").order("name"),
        supabase.from("check_results").select("*").order("checked_at", { ascending: false }).limit(300),
      ]);
      return { assets: a.data ?? [], checks: c.data ?? [] };
    },
  });
  async function runNow() {
    setBusy(true);
    try {
      const r = await run();
      toast.success(`Checked ${r.checked} assets · ${r.alerts} new alerts`);
      qc.invalidateQueries();
    } catch (e) { toast.error((e as Error).message); }
    setBusy(false);
  }
  const assets = data?.assets ?? [];
  const checks = data?.checks ?? [];
  return (
    <div>
      <PageHeader title="External Attack Surface" sub="Uptime, TLS and security headers for internet-facing assets · checked hourly"
        action={<Button onClick={runNow} disabled={busy}><RefreshCw className={`mr-2 h-4 w-4 ${busy ? "animate-spin" : ""}`} />Run checks now</Button>} />
      <Table>
        <thead><tr><Th>Asset</Th><Th>Status</Th><Th>Last check</Th><Th>Response</Th><Th>TLS expiry</Th><Th>History</Th></tr></thead>
        <tbody>
          {assets.map((a) => {
            const hist = checks.filter((c) => c.asset_id === a.id && c.check_type === "http").slice(0, 16).reverse();
            const last = hist[hist.length - 1];
            const days = a.tls_expires_at ? Math.round((new Date(a.tls_expires_at).getTime() - Date.now()) / 864e5) : null;
            const hdr = checks.find((c) => c.asset_id === a.id && c.check_type === "headers");
            return (
              <tr key={a.id}>
                <Td><div className="font-medium">{a.name}</div><div className="data text-xs text-muted-foreground">{a.address}</div>
                  {hdr && !hdr.ok && <div className="data mt-1 text-[11px] text-sev-low">{hdr.detail}</div>}</Td>
                <Td><StatusPill status={a.status} /></Td>
                <Td className="data text-xs text-muted-foreground">{ago(last?.checked_at)}</Td>
                <Td className="data text-xs">{last?.response_ms ? `${last.response_ms}ms` : "—"} <span className="text-muted-foreground">{last?.detail}</span></Td>
                <Td className={`data text-xs ${days != null && days < 14 ? "text-sev-high" : days != null && days < 30 ? "text-sev-medium" : ""}`}>{days != null ? `${days}d` : "—"}</Td>
                <Td><div className="flex gap-0.5">{hist.map((c) => <span key={c.id} title={c.detail ?? ""} className={`h-5 w-1.5 rounded-sm ${c.ok ? "bg-ok/70" : "bg-sev-critical"}`} />)}</div></Td>
              </tr>
            );
          })}
        </tbody>
      </Table>
      <Panel title="What is checked" className="mt-6">
        <p className="text-sm text-muted-foreground">HTTP reachability and status code, response time, HSTS / CSP / X-Frame-Options / X-Content-Type-Options headers, and certificate expiry (recorded on each asset). Failures raise alerts automatically: asset offline (high), certificate under 14 days (medium), missing security headers (low).</p>
      </Panel>
    </div>
  );
}
