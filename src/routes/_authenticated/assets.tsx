import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader, SeverityBadge, StatusPill, Table, Th, Td, ago, type Severity } from "@/components/soc/ui";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { audit } from "@/lib/soc";

export const Route = createFileRoute("/_authenticated/assets")({
  head: () => ({ meta: [{ title: "Assets — FINPAY SOC" }, { name: "description", content: "FINPAYTECH asset inventory." }] }),
  component: Assets,
});

const TYPES = ["all", "website", "api", "service", "ip", "server", "endpoint", "network"];

function Assets() {
  const [q, setQ] = useState("");
  const [type, setType] = useState("all");
  const { data = [] } = useQuery({
    queryKey: ["assets"],
    queryFn: async () => (await supabase.from("assets").select("*").order("criticality")).data ?? [],
  });
  const rows = data.filter((a) => (type === "all" || a.asset_type === type) && (a.name + (a.address ?? "") + (a.owner ?? "")).toLowerCase().includes(q.toLowerCase()));
  return (
    <div>
      <PageHeader title="Asset Inventory" sub={`${data.length} assets · ${data.filter((a) => a.monitored).length} monitored`} action={<AddAsset />} />
      <div className="mb-4 flex flex-wrap gap-2">
        <Input placeholder="Search name, address, owner…" value={q} onChange={(e) => setQ(e.target.value)} className="max-w-xs" />
        {TYPES.map((t) => (
          <button key={t} onClick={() => setType(t)} className={`data rounded border px-2.5 text-xs capitalize ${type === t ? "border-primary text-primary" : "text-muted-foreground"}`}>{t}</button>
        ))}
      </div>
      <Table>
        <thead><tr><Th>Asset</Th><Th>Type</Th><Th>Address</Th><Th>Exposure</Th><Th>Criticality</Th><Th>Owner</Th><Th>Status</Th><Th>Last seen</Th></tr></thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.id}>
              <Td className="font-medium">{a.name} {a.is_new && <span className="data ml-1 rounded bg-primary/15 px-1 text-[10px] text-primary">NEW</span>}</Td>
              <Td className="data text-xs capitalize text-muted-foreground">{a.asset_type}</Td>
              <Td className="data text-xs">{a.address}</Td>
              <Td className={`data text-xs ${a.exposure === "external" ? "text-sev-medium" : "text-muted-foreground"}`}>{a.exposure}</Td>
              <Td><SeverityBadge s={a.criticality as Severity} /></Td>
              <Td className="text-muted-foreground">{a.owner}</Td>
              <Td><StatusPill status={a.status} /></Td>
              <Td className="data text-xs text-muted-foreground">{ago(a.last_seen)}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function AddAsset() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ name: "", asset_type: "website", address: "", owner: "", exposure: "external", criticality: "medium" });
  async function save() {
    const { error } = await supabase.from("assets").insert({ ...f, criticality: f.criticality as Severity, is_new: true });
    if (error) { toast.error(error.message); return; }
    await audit("asset.create", f.name);
    toast.success("Asset added");
    setOpen(false);
    qc.invalidateQueries({ queryKey: ["assets"] });
  }
  const sel = "h-9 w-full rounded-md border bg-background px-2 text-sm";
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild><Button>Add asset</Button></DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Register asset</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <Input placeholder="Name (e.g. pay.finpaytech.com)" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
          <Input placeholder="Address / URL (https:// for web checks)" value={f.address} onChange={(e) => setF({ ...f, address: e.target.value })} />
          <Input placeholder="Owner" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} />
          <div className="grid grid-cols-3 gap-2">
            <select className={sel} value={f.asset_type} onChange={(e) => setF({ ...f, asset_type: e.target.value })}>{TYPES.slice(1).map((t) => <option key={t}>{t}</option>)}</select>
            <select className={sel} value={f.exposure} onChange={(e) => setF({ ...f, exposure: e.target.value })}><option>external</option><option>internal</option></select>
            <select className={sel} value={f.criticality} onChange={(e) => setF({ ...f, criticality: e.target.value })}>{["critical", "high", "medium", "low"].map((t) => <option key={t}>{t}</option>)}</select>
          </div>
          <Button className="w-full" onClick={save} disabled={!f.name}>Save</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
