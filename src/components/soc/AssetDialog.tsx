import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { listTeams, saveAsset } from "@/lib/api/soc.functions";
import type { Asset } from "@/lib/types";

export const ASSET_TYPES = ["website", "api", "domain", "service", "ip", "server", "endpoint", "network", "cloud", "other"] as const;
export const selectCls = "h-9 w-full rounded-md border bg-background px-2 text-sm";

type Form = {
  id?: string;
  name: string;
  asset_type: (typeof ASSET_TYPES)[number];
  address: string;
  owner: string;
  exposure: "internal" | "external";
  criticality: "critical" | "high" | "medium" | "low";
  environment: string;
  monitored: boolean;
  team_id: string;
  tags: string;
  notes: string;
  is_new?: boolean;
};

function toForm(a?: Asset | null): Form {
  return a
    ? { id: a.id, name: a.name, asset_type: a.asset_type as Form["asset_type"], address: a.address ?? "", owner: a.owner ?? "", exposure: a.exposure,
        criticality: (a.criticality === "info" ? "low" : a.criticality) as Form["criticality"], environment: a.environment, monitored: a.monitored, team_id: a.team_id ?? "",
        tags: a.tags.join(", "), notes: a.notes ?? "", is_new: a.is_new }
    : { name: "", asset_type: "website", address: "", owner: "", exposure: "external", criticality: "low", environment: "production", monitored: true, team_id: "", tags: "", notes: "" };
}

export function AssetDialog({ open, onOpenChange, asset }: { open: boolean; onOpenChange: (v: boolean) => void; asset?: Asset | null }) {
  const qc = useQueryClient();
  const [f, setF] = useState<Form>(() => toForm(asset));
  const [lastId, setLastId] = useState(asset?.id);
  if (asset?.id !== lastId) {
    setLastId(asset?.id);
    setF(toForm(asset));
  }
  const { data: teams = [] } = useQuery({ queryKey: ["teams"], queryFn: () => listTeams(), enabled: open });
  const save = useMutation({
    mutationFn: () => saveAsset({ data: {
      ...f, team_id: f.team_id || null, address: f.address || null, owner: f.owner || null, notes: f.notes || null,
      tags: f.tags.split(",").map((t) => t.trim()).filter(Boolean),
      is_new: f.id ? false : undefined,
    } }),
    onSuccess: () => {
      toast.success(f.id ? "Asset updated" : f.monitored ? "Asset added — monitoring starts on the next run" : "Asset added (not monitored)");
      onOpenChange(false);
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["surface"] });
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const web = ["website", "api"].includes(f.asset_type);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto">
        <DialogHeader><DialogTitle>{f.id ? "Edit asset" : "Register asset"}</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <Input placeholder="Name (e.g. pay.finpaytech.com)" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
          <Input placeholder={web ? "URL, e.g. https://pay.finpaytech.com" : "Address: host, host:port or IP"} value={f.address} onChange={(e) => setF({ ...f, address: e.target.value })} />
          <div className="grid grid-cols-2 gap-2">
            <label className="text-xs text-muted-foreground">Developer team (receives its issues)
              <select className={selectCls} value={f.team_id} onChange={(e) => setF({ ...f, team_id: e.target.value })}>
                <option value="">— none —</option>
                {teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </label>
            <label className="text-xs text-muted-foreground">Owner (person)
              <Input placeholder="e.g. J. Otieno" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} />
            </label>
          </div>
          <div className="grid grid-cols-1 gap-2">
            <Input placeholder="Environment" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })} />
          </div>
          <div className="grid grid-cols-3 gap-2">
            <label className="text-xs text-muted-foreground">Type
              <select className={selectCls} value={f.asset_type} onChange={(e) => setF({ ...f, asset_type: e.target.value as Form["asset_type"] })}>{ASSET_TYPES.map((t) => <option key={t}>{t}</option>)}</select>
            </label>
            <label className="text-xs text-muted-foreground">Exposure
              <select className={selectCls} value={f.exposure} onChange={(e) => setF({ ...f, exposure: e.target.value as Form["exposure"] })}><option>external</option><option>internal</option></select>
            </label>
            <label className="text-xs text-muted-foreground">Criticality
              <select className={selectCls} value={f.criticality} onChange={(e) => setF({ ...f, criticality: e.target.value as Form["criticality"] })}>{["critical", "high", "medium", "low"].map((t) => <option key={t}>{t}</option>)}</select>
            </label>
          </div>
          <Input placeholder="Tags (comma separated): pci, payments" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} />
          <Textarea placeholder="Notes" value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} rows={3} />
          <label className="flex items-center justify-between gap-3 rounded border p-3 text-sm">
            <span>
              Monitor this asset{f.exposure === "external" ? " (uptime, TLS, headers, ports, DNS)" : ""}
              <span className="mt-1 block text-xs text-muted-foreground">Only add systems FINPAY owns or is authorised to test — adding it here is your approval to scan it.</span>
            </span>
            <Switch checked={f.monitored} onCheckedChange={(v) => setF({ ...f, monitored: v })} />
          </label>
          <Button className="w-full" onClick={() => save.mutate()} disabled={!f.name || save.isPending}>Save</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
