import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Download, Pencil, Trash2 } from "lucide-react";
import { PageHeader, Panel, SeverityBadge, StatusPill, Table, Th, Td, ago } from "@/components/soc/ui";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { AssetDialog, ASSET_TYPES } from "@/components/soc/AssetDialog";
import { deleteAsset, getAsset, listAssets } from "@/lib/api/soc.functions";
import { useCan } from "@/lib/session";
import { downloadCsv } from "@/lib/risk";
import type { Asset } from "@/lib/types";

export const Route = createFileRoute("/_authenticated/assets")({
  head: () => ({ meta: [{ title: "Assets — FINPAY SOC" }, { name: "description", content: "FINPAYTECH asset inventory." }] }),
  component: Assets,
});

function Assets() {
  const canManage = useCan("assets.manage");
  const [q, setQ] = useState("");
  const [type, setType] = useState("all");
  const [exposure, setExposure] = useState("all");
  const [editing, setEditing] = useState<Asset | null>(null);
  const [dialog, setDialog] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const { data = [], isLoading } = useQuery({ queryKey: ["assets"], queryFn: () => listAssets(), refetchInterval: 60000 });
  const rows = data.filter((a) => (type === "all" || a.asset_type === type) && (exposure === "all" || a.exposure === exposure) &&
    `${a.name} ${a.address ?? ""} ${a.owner ?? ""} ${a.tags.join(" ")}`.toLowerCase().includes(q.toLowerCase()));

  function exportCsv() {
    downloadCsv(`finpay-assets-${new Date().toISOString().slice(0, 10)}.csv`, [
      ["name", "type", "address", "exposure", "criticality", "owner", "environment", "status", "monitored", "tags", "tls_expires_at", "open_ports", "last_seen"],
      ...rows.map((a) => [a.name, a.asset_type, a.address, a.exposure, a.criticality, a.owner, a.environment, a.status, a.monitored ? "yes" : "no", a.tags.join(" "), a.tls_expires_at, a.open_ports.join(" "), a.last_seen]),
    ]);
  }

  return (
    <div>
      <PageHeader title="Asset Inventory"
        sub={`${data.length} assets · ${data.filter((a) => a.monitored).length} monitored · ${data.filter((a) => a.is_new).length} awaiting review`}
        action={<div className="flex gap-2">
          <Button variant="outline" onClick={exportCsv}><Download className="mr-1 h-4 w-4" />CSV</Button>
          {canManage && <Button onClick={() => { setEditing(null); setDialog(true); }}>Add asset</Button>}
        </div>} />
      <div className="mb-4 flex flex-wrap gap-2">
        <Input placeholder="Search name, address, owner, tag…" value={q} onChange={(e) => setQ(e.target.value)} className="max-w-xs" />
        {["all", ...ASSET_TYPES].map((t) => (
          <button key={t} onClick={() => setType(t)} className={`data rounded border px-2.5 text-xs capitalize ${type === t ? "border-primary text-primary" : "text-muted-foreground"}`}>{t}</button>
        ))}
        <span className="mx-1 w-px bg-border" />
        {["all", "external", "internal"].map((t) => (
          <button key={t} onClick={() => setExposure(t)} className={`data rounded border px-2.5 text-xs capitalize ${exposure === t ? "border-primary text-primary" : "text-muted-foreground"}`}>{t}</button>
        ))}
      </div>
      {isLoading ? <p className="data text-sm text-muted-foreground">Loading inventory…</p> : (
        <Table>
          <thead><tr><Th>Asset</Th><Th>Type</Th><Th>Address</Th><Th>Exposure</Th><Th>Criticality</Th><Th>Owner</Th><Th>Risk</Th><Th>Status</Th><Th>Last seen</Th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id} className="cursor-pointer" onClick={() => setDetail(a.id)}>
                <Td className="font-medium">
                  {a.name}
                  {a.is_new && <span className="data ml-1 rounded bg-primary/15 px-1 text-[10px] text-primary">NEW</span>}
                  {a.tags.includes("demo") && <span className="data ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">DEMO</span>}
                </Td>
                <Td className="data text-xs capitalize text-muted-foreground">{a.asset_type}</Td>
                <Td className="data max-w-56 truncate text-xs">{a.address}</Td>
                <Td className={`data text-xs ${a.exposure === "external" ? "text-sev-medium" : "text-muted-foreground"}`}>{a.exposure}</Td>
                <Td><SeverityBadge s={a.criticality} /></Td>
                <Td className="text-muted-foreground">{a.owner}</Td>
                <Td className="data text-xs">
                  {a.open_alerts ? <span className="text-sev-high">{a.open_alerts} alerts </span> : null}
                  {a.open_vulns ? <span className="text-sev-medium">{a.open_vulns} vulns</span> : null}
                  {!a.open_alerts && !a.open_vulns && <span className="text-muted-foreground">—</span>}
                </Td>
                <Td><StatusPill status={a.status} /></Td>
                <Td className="data text-xs text-muted-foreground">{ago(a.last_seen)}</Td>
              </tr>
            ))}
            {!rows.length && <tr><Td className="text-muted-foreground">No assets match.</Td></tr>}
          </tbody>
        </Table>
      )}
      <AssetDialog open={dialog} onOpenChange={setDialog} asset={editing} />
      <AssetSheet id={detail} onClose={() => setDetail(null)} onEdit={(a) => { setEditing(a); setDialog(true); }} />
    </div>
  );
}

function AssetSheet({ id, onClose, onEdit }: { id: string | null; onClose: () => void; onEdit: (a: Asset) => void }) {
  const qc = useQueryClient();
  const canManage = useCan("assets.manage");
  const canDelete = useCan("data.delete");
  const { data } = useQuery({ queryKey: ["asset", id], queryFn: () => getAsset({ data: { id: id! } }), enabled: !!id });
  const del = useMutation({
    mutationFn: () => deleteAsset({ data: { id: id! } }),
    onSuccess: () => { toast.success("Asset deleted"); onClose(); qc.invalidateQueries({ queryKey: ["assets"] }); },
  });
  const a = data?.asset;
  return (
    <Sheet open={!!id} onOpenChange={(v) => !v && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        {!a ? <p className="text-sm text-muted-foreground">Loading…</p> : (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2">{a.name} <StatusPill status={a.status} /></SheetTitle>
            </SheetHeader>
            <div className="mt-2 flex flex-wrap gap-2">
              <SeverityBadge s={a.criticality} />
              {a.tags.map((t) => <span key={t} className="data rounded bg-muted px-1.5 text-[10px]">{t}</span>)}
            </div>
            {a.notes && <p className="mt-3 text-sm text-muted-foreground">{a.notes}</p>}
            <dl className="data mt-4 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
              {[
                ["Address", a.address], ["Type", a.asset_type], ["Exposure", a.exposure], ["Owner", a.owner], ["Environment", a.environment],
                ["Discovered via", a.discovered_via], ["HTTP status", a.http_status], ["Response", a.response_ms ? `${a.response_ms} ms` : null],
                ["TLS issuer", a.tls_issuer], ["TLS expires", a.tls_expires_at ? new Date(a.tls_expires_at).toLocaleDateString() : null],
                ["Open ports", a.open_ports.join(", ") || null], ["Name servers", a.dns?.ns?.join(", ") || null],
                ["Last checked", ago(a.last_checked_at)], ["Last seen", ago(a.last_seen)],
              ].map(([k, v]) => (
                <div key={String(k)} className="contents"><dt className="text-muted-foreground">{k}</dt><dd className="truncate">{v ?? "—"}</dd></div>
              ))}
            </dl>
            <div className="mt-4 flex gap-2">
              {canManage && <Button size="sm" variant="outline" onClick={() => onEdit(a)}><Pencil className="mr-1 h-3.5 w-3.5" />Edit</Button>}
              {canDelete && <Button size="sm" variant="ghost" className="text-sev-critical" onClick={() => { if (confirm(`Delete ${a.name}? Its check history and vulnerabilities are deleted too.`)) del.mutate(); }}><Trash2 className="mr-1 h-3.5 w-3.5" />Delete</Button>}
            </div>
            <Panel title="Open alerts" className="mt-5">
              <ul className="space-y-2 text-sm">
                {data.alerts.filter((x) => !["resolved", "false_positive", "closed"].includes(x.status)).map((x) => (
                  <li key={x.id} className="flex items-center gap-2"><SeverityBadge s={x.severity} /><span className="flex-1 truncate">{x.title}</span><span className="data text-xs text-muted-foreground">{ago(x.detected_at)}</span></li>
                ))}
                {!data.alerts.some((x) => !["resolved", "false_positive", "closed"].includes(x.status)) && <li className="text-muted-foreground">None</li>}
              </ul>
            </Panel>
            <Panel title="Vulnerabilities" className="mt-4">
              <ul className="space-y-2 text-sm">
                {data.vulns.map((v) => <li key={v.id} className="flex items-center gap-2"><SeverityBadge s={v.severity} /><span className="flex-1 truncate">{v.title}</span><StatusPill status={v.status} /></li>)}
                {!data.vulns.length && <li className="text-muted-foreground">None recorded</li>}
              </ul>
            </Panel>
            <Panel title="Recent checks" className="mt-4">
              <ul className="data space-y-1 text-xs">
                {data.checks.slice(0, 20).map((c) => (
                  <li key={c.id} className="flex gap-2"><span className={c.ok ? "text-ok" : "text-sev-high"}>{c.ok ? "OK " : "FAIL"}</span><span className="w-20 text-muted-foreground">{c.check_type}</span><span className="flex-1 truncate">{c.detail}</span><span className="text-muted-foreground">{ago(c.checked_at)}</span></li>
                ))}
                {!data.checks.length && <li className="text-muted-foreground">{a.exposure === "external" ? "Not checked yet" : "Internal assets are tracked through agents, not external checks"}</li>}
              </ul>
            </Panel>
            {data.events.length > 0 && (
              <Panel title="Recent activity" className="mt-4">
                <ul className="data space-y-1 text-xs">
                  {data.events.slice(0, 20).map((e) => (
                    <li key={e.id} className="flex gap-2"><span className="text-primary">{e.event_type}</span><span>{e.username}</span><span className={e.outcome === "failure" ? "text-sev-high" : "text-muted-foreground"}>{e.outcome}</span><span className="ml-auto text-muted-foreground">{ago(e.occurred_at)}</span></li>
                  ))}
                </ul>
              </Panel>
            )}
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
