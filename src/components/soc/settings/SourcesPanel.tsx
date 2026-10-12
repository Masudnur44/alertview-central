import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Copy, KeyRound } from "lucide-react";
import { Panel, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { createSource, listSources, updateSource } from "@/lib/api/admin.functions";

const TYPES = ["server", "endpoint", "application", "network", "wazuh", "cloud", "other"] as const;

export function SourcesPanel() {
  const qc = useQueryClient();
  const { data = [] } = useQuery({ queryKey: ["sources"], queryFn: () => listSources() });
  const [name, setName] = useState("");
  const [type, setType] = useState<(typeof TYPES)[number]>("server");
  const [cidrs, setCidrs] = useState("");
  const [shownKey, setShownKey] = useState<{ key: string; type: string } | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["sources"] });
  const create = useMutation({
    mutationFn: () => createSource({ data: { name, source_type: type, allowed_cidrs: cidrs.split(/[\s,]+/).filter(Boolean) } }),
    onSuccess: (r) => { setShownKey({ key: r.key, type }); setName(""); setCidrs(""); refresh(); },
  });
  const update = useMutation({
    mutationFn: (v: { id: string; enabled?: boolean; rotate?: boolean; remove?: boolean }) => updateSource({ data: v }),
    onSuccess: (r, v) => { if (r.key) setShownKey({ key: r.key, type: data.find((s) => s.id === v.id)?.source_type ?? "server" }); refresh(); },
  });
  const origin = typeof window !== "undefined" ? window.location.origin : "";

  return (
    <div className="space-y-4">
      <Panel title="Event sources · log intake">
        <p className="mb-4 text-sm text-muted-foreground">Each agent, log forwarder or application gets its own key. Keys are stored hashed and shown only once — rotate a key if it may have leaked, and restrict it to the sender's IP range where you can.</p>
        <ul className="divide-y">
          {data.map((s) => (
            <li key={s.id} className="flex flex-wrap items-center gap-3 py-2.5">
              <div className="min-w-48 flex-1">
                <p className="text-sm">{s.name} <span className="data ml-1 text-[10px] uppercase text-muted-foreground">{s.source_type}</span></p>
                <p className="data text-xs text-muted-foreground">{s.key_prefix}… · {Number(s.event_count).toLocaleString()} events · {s.last_event_at ? `last ${ago(s.last_event_at)}` : "no events yet"}{s.allowed_cidrs.length ? ` · only from ${s.allowed_cidrs.join(", ")}` : ""}</p>
              </div>
              <Switch checked={s.enabled} onCheckedChange={(v) => update.mutate({ id: s.id, enabled: v })} title="Accept events" />
              <Button size="sm" variant="ghost" onClick={() => confirm("Rotate key? The old key stops working immediately.") && update.mutate({ id: s.id, rotate: true })}><KeyRound className="mr-1 h-3.5 w-3.5" />Rotate</Button>
              <Button size="sm" variant="ghost" className="text-muted-foreground" onClick={() => confirm(`Delete source "${s.name}"? Its events are kept.`) && update.mutate({ id: s.id, remove: true })}>Delete</Button>
            </li>
          ))}
          {!data.length && <li className="py-2 text-sm text-muted-foreground">No sources yet. Create one per agent group (e.g. “Linux servers”, “Windows laptops”, “Wazuh manager”).</li>}
        </ul>
        <form className="mt-4 flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
          <Input placeholder="Source name" value={name} onChange={(e) => setName(e.target.value)} className="max-w-56" />
          <select className="h-9 rounded-md border bg-background px-2 text-sm" value={type} onChange={(e) => setType(e.target.value as typeof type)}>{TYPES.map((t) => <option key={t}>{t}</option>)}</select>
          <Input placeholder="Allowed IPs/CIDRs (optional)" value={cidrs} onChange={(e) => setCidrs(e.target.value)} className="max-w-64" />
          <Button disabled={name.trim().length < 2 || create.isPending}>Create source & key</Button>
        </form>
      </Panel>
      <Panel title="Connecting machines">
        <SetupGuide origin={origin} keyValue="<SOURCE_KEY>" />
      </Panel>
      <Dialog open={!!shownKey} onOpenChange={(v) => !v && setShownKey(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader><DialogTitle>Copy this key now</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">It will not be shown again. Store it in the agent configuration only.</p>
          <div className="flex items-center gap-2">
            <code className="data flex-1 break-all rounded bg-muted p-2 text-xs">{shownKey?.key}</code>
            <Button size="sm" variant="outline" onClick={() => { navigator.clipboard.writeText(shownKey!.key); toast.success("Copied"); }}><Copy className="h-4 w-4" /></Button>
          </div>
          {shownKey && <SetupGuide origin={origin} keyValue={shownKey.key} initial={shownKey.type === "wazuh" ? "wazuh" : shownKey.type === "endpoint" ? "windows" : "linux"} />}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function SetupGuide({ origin, keyValue, initial = "linux" }: { origin: string; keyValue: string; initial?: string }) {
  const block = (s: string) => <pre className="data mt-2 overflow-x-auto whitespace-pre rounded bg-muted p-3 text-[11px] leading-relaxed">{s}</pre>;
  return (
    <Tabs defaultValue={initial}>
      <TabsList>
        <TabsTrigger value="linux">Linux</TabsTrigger>
        <TabsTrigger value="windows">Windows</TabsTrigger>
        <TabsTrigger value="wazuh">Wazuh</TabsTrigger>
        <TabsTrigger value="api">API / apps</TabsTrigger>
      </TabsList>
      <TabsContent value="linux" className="text-sm text-muted-foreground">
        Python 3 agent (no dependencies): ships SSH/sudo logins, account and group changes from journald or /var/log/auth.log. Copy <code>agents/linux/</code> from the SOC repository to the server, then:
        {block(`sudo ./install.sh --url ${origin} --key ${keyValue}\n# status / logs\nsystemctl status finpay-soc-agent\njournalctl -u finpay-soc-agent -f`)}
      </TabsContent>
      <TabsContent value="windows" className="text-sm text-muted-foreground">
        PowerShell agent: forwards logons (4624/4625), new accounts (4720), admin group changes (4728/4732/4756), cleared logs (1102), new services (7045) and process starts (4688). Run as Administrator:
        {block(`powershell -ExecutionPolicy Bypass -File .\\install.ps1 -Url ${origin} -Key ${keyValue}`)}
        Enable "Audit Process Creation" with command line in Group Policy for process detections.
      </TabsContent>
      <TabsContent value="wazuh" className="text-sm text-muted-foreground">
        Already running Wazuh? Forward its alerts. Copy <code>agents/wazuh/custom-finpay-soc.py</code> to <code>/var/ossec/integrations/custom-finpay-soc</code> on the manager and add to <code>ossec.conf</code>:
        {block(`<integration>\n  <name>custom-finpay-soc</name>\n  <hook_url>${origin}/api/public/wazuh</hook_url>\n  <api_key>${keyValue}</api_key>\n  <level>7</level>\n  <alert_format>json</alert_format>\n</integration>`)}
      </TabsContent>
      <TabsContent value="api" className="text-sm text-muted-foreground">
        Any system can POST JSON (one event or {"{"}"events": [...]{"}"}, max 500 per request). Event types the detections understand: <code>auth.login</code>, <code>process.start</code>, <code>account.created</code>, <code>group.member_added</code>, <code>log.cleared</code>, <code>service.installed</code>.
        {block(`curl -X POST ${origin}/api/public/ingest \\\n  -H "content-type: application/json" -H "x-soc-key: ${keyValue}" \\\n  -d '{"event_type":"auth.login","host":"app-srv-02","username":"jdoe","src_ip":"203.0.113.7","outcome":"failure"}'`)}
      </TabsContent>
    </Tabs>
  );
}
