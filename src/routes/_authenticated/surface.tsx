import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Globe, RefreshCw, Search, Trash2 } from "lucide-react";
import { PageHeader, Panel, StatusPill, Table, Th, Td, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getSurface, removeDomain, runChecksNow, runDiscoveryNow, saveDomain } from "@/lib/api/soc.functions";
import { useCan } from "@/lib/session";

export const Route = createFileRoute("/_authenticated/surface")({
  head: () => ({ meta: [{ title: "External Surface — FINPAY SOC" }, { name: "description", content: "Internet-facing exposure monitoring." }] }),
  component: Surface,
});

const RISKY: Record<number, string> = { 21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker", 3306: "MySQL", 3389: "RDP", 5432: "Postgres", 5900: "VNC", 6379: "Redis", 9200: "Elastic", 11211: "Memcached", 27017: "MongoDB" };

function Surface() {
  const qc = useQueryClient();
  const canRun = useCan("checks.run");
  const canDomains = useCan("domains.manage");
  const [domain, setDomain] = useState("");
  const { data } = useQuery({ queryKey: ["surface"], queryFn: () => getSurface(), refetchInterval: 60000 });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["surface"] }); qc.invalidateQueries({ queryKey: ["overview"] }); qc.invalidateQueries({ queryKey: ["alerts"] }); };

  const run = useMutation({
    mutationFn: (assetIds?: string[]) => runChecksNow({ data: { assetIds } }),
    onSuccess: (r) => { toast.success(`Checked ${r.checked} assets · ${r.alerts} new alerts${r.failed ? ` · ${r.failed} errors` : ""}`); refresh(); },
  });
  const discover = useMutation({
    mutationFn: () => runDiscoveryNow(),
    onSuccess: (r) => {
      toast.success(`Searched ${r.domains} domains · ${r.found} hostnames seen · ${r.added} new assets`);
      r.errors.forEach((e) => toast.error(e));
      refresh();
    },
  });
  const addDomain = useMutation({
    mutationFn: () => saveDomain({ data: { domain, discover: true } }),
    onSuccess: () => { setDomain(""); refresh(); },
  });
  const delDomain = useMutation({ mutationFn: (id: string) => removeDomain({ data: { id } }), onSuccess: refresh });

  const assets = data?.assets ?? [];
  const history = data?.history ?? [];
  const lastJob = (job: string) => data?.jobs.find((j) => j.job === job);
  const checksJob = lastJob("checks");

  return (
    <div>
      <PageHeader title="External Attack Surface"
        sub={`Availability, TLS, security headers, exposed services and DNS for internet-facing assets · last full run ${ago(checksJob?.started_at)}`}
        action={canRun && <Button onClick={() => run.mutate(undefined)} disabled={run.isPending}><RefreshCw className={`mr-2 h-4 w-4 ${run.isPending ? "animate-spin" : ""}`} />Run checks now</Button>} />

      <Table>
        <thead><tr><Th>Asset</Th><Th>Status</Th><Th>Response</Th><Th>TLS</Th><Th>Exposed services</Th><Th>History (24 checks)</Th><Th></Th></tr></thead>
        <tbody>
          {assets.map((a) => {
            const hist = history.filter((c) => c.asset_id === a.id && c.check_type === "availability").slice(0, 24).reverse();
            const hdr = history.find((c) => c.asset_id === a.id && c.check_type === "headers");
            const tls = history.find((c) => c.asset_id === a.id && c.check_type === "tls");
            const days = a.tls_expires_at ? Math.floor((new Date(a.tls_expires_at).getTime() - Date.now()) / 864e5) : null;
            const risky = a.open_ports.filter((p) => RISKY[p]);
            return (
              <tr key={a.id}>
                <Td>
                  <div className="font-medium">{a.name}{a.is_new && <span className="data ml-1 rounded bg-primary/15 px-1 text-[10px] text-primary">NEW</span>}{!a.monitored && <span className="data ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">NOT MONITORED</span>}</div>
                  <div className="data text-xs text-muted-foreground">{a.address}</div>
                  {hdr && !hdr.ok && <div className="data mt-1 text-[11px] text-sev-low">{hdr.detail}</div>}
                </Td>
                <Td><StatusPill status={a.status} /><div className="data mt-1 text-[11px] text-muted-foreground">{ago(a.last_checked_at)}</div></Td>
                <Td className="data text-xs">{a.response_ms ? `${a.response_ms} ms` : "—"}{a.http_status ? <span className="text-muted-foreground"> · {a.http_status}</span> : null}</Td>
                <Td className="data text-xs">
                  <span className={days != null && days < 14 ? "text-sev-high" : days != null && days < 30 ? "text-sev-medium" : ""}>{days != null ? `${days}d left` : "—"}</span>
                  {a.tls_issuer && <div className="text-[11px] text-muted-foreground">{a.tls_issuer}</div>}
                  {tls && !tls.ok && /untrusted/.test(tls.detail ?? "") && <div className="text-[11px] text-sev-high">{tls.detail}</div>}
                </Td>
                <Td className="data text-xs">
                  {risky.map((p) => <span key={p} className="mr-1 rounded bg-sev-high/15 px-1 text-sev-high">{p} {RISKY[p]}</span>)}
                  {!risky.length && <span className="text-muted-foreground">{a.open_ports.length ? a.open_ports.join(", ") : "—"}</span>}
                </Td>
                <Td><div className="flex gap-0.5">{hist.map((c) => <span key={c.id} title={`${new Date(c.checked_at).toLocaleString()} — ${c.detail ?? ""}`} className={`h-5 w-1.5 rounded-sm ${c.ok ? "bg-ok/70" : "bg-sev-critical"}`} />)}</div></Td>
                <Td>{canRun && a.monitored && <Button size="sm" variant="ghost" title="Check now" onClick={() => run.mutate([a.id])} disabled={run.isPending}><RefreshCw className="h-3.5 w-3.5" /></Button>}</Td>
              </tr>
            );
          })}
          {!assets.length && <tr><Td className="text-muted-foreground">No internet-facing assets yet. Add them on the Assets page or let discovery find them.</Td></tr>}
        </tbody>
      </Table>

      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Panel title="Subdomain discovery" action={canDomains && <Button size="sm" variant="outline" onClick={() => discover.mutate()} disabled={discover.isPending || !data?.domains.length}><Search className={`mr-1 h-3.5 w-3.5 ${discover.isPending ? "animate-pulse" : ""}`} />Discover now</Button>}>
          <p className="mb-3 text-sm text-muted-foreground">Root domains are searched daily in public certificate-transparency logs. Any live hostname not in the inventory is added and raises a “new internet-facing asset” alert — shadow IT and forgotten staging sites show up here.</p>
          <ul className="divide-y">
            {data?.domains.map((d) => (
              <li key={d.id} className="flex items-center gap-3 py-2 text-sm">
                <Globe className="h-4 w-4 text-primary" />
                <span className="data flex-1">{d.domain}</span>
                <span className="data text-xs text-muted-foreground">{d.last_discovery_at ? `searched ${ago(d.last_discovery_at)}` : "not searched yet"}</span>
                {canDomains && <button onClick={() => delDomain.mutate(d.id)} className="text-muted-foreground hover:text-sev-critical" title="Remove"><Trash2 className="h-3.5 w-3.5" /></button>}
              </li>
            ))}
            {!data?.domains.length && <li className="py-2 text-sm text-muted-foreground">No root domains yet.</li>}
          </ul>
          {canDomains && (
            <form className="mt-3 flex gap-2" onSubmit={(e) => { e.preventDefault(); addDomain.mutate(); }}>
              <Input placeholder="finpaytech.com" value={domain} onChange={(e) => setDomain(e.target.value)} className="max-w-xs" />
              <Button disabled={!domain || addDomain.isPending}>Add domain</Button>
            </form>
          )}
        </Panel>
        <Panel title="What is checked">
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li><span className="text-foreground">Availability</span> — HTTP status and response time for web assets; TLS handshake or TCP connect for services. Down → <b>high</b> alert, auto-resolved on recovery.</li>
            <li><span className="text-foreground">TLS certificates</span> — read live from the server: expiry (&lt;14 days medium, &lt;3 days high), untrusted, self-signed or wrong hostname (high).</li>
            <li><span className="text-foreground">Security headers</span> — HSTS, CSP, X-Frame-Options, X-Content-Type-Options (low).</li>
            <li><span className="text-foreground">Exposed services</span> — RDP, SMB, databases, Redis, Docker API and other risky ports reachable from the internet (high).</li>
            <li><span className="text-foreground">DNS</span> — name-server and mail-exchanger changes (medium; possible hijack).</li>
            <li className="text-xs">Checks never probe private or reserved addresses, so the scanner cannot be turned against the internal network.</li>
          </ul>
        </Panel>
      </div>
    </div>
  );
}
