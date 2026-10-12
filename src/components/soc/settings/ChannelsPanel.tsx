import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Panel, SeverityBadge, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { deleteChannel, listChannels, saveChannel, testChannel } from "@/lib/api/admin.functions";
import type { Severity } from "@/lib/types";

type Kind = "email" | "slack" | "teams" | "telegram" | "webhook";
const KINDS: { value: Kind; label: string; help: string }[] = [
  { value: "email", label: "Email", help: "Needs SMTP settings in the server .env. Comma-separate several addresses." },
  { value: "slack", label: "Slack", help: "Slack → Apps → Incoming Webhooks → add to a channel, paste the https://hooks.slack.com/... URL." },
  { value: "teams", label: "Microsoft Teams", help: "Teams channel → Workflows → “Post to a channel when a webhook request is received”, paste the URL." },
  { value: "telegram", label: "Telegram", help: "Create a bot with @BotFather, add it to your group, then use the bot token and the group chat id." },
  { value: "webhook", label: "Webhook", help: "POSTs JSON to your URL. With a secret, requests carry x-soc-signature: sha256=HMAC(timestamp.body)." },
];

export function ChannelsPanel() {
  const qc = useQueryClient();
  const { data = [] } = useQuery({ queryKey: ["channels"], queryFn: () => listChannels() });
  const refresh = () => qc.invalidateQueries({ queryKey: ["channels"] });
  const [kind, setKind] = useState<Kind>("email");
  const [name, setName] = useState("");
  const [minSev, setMinSev] = useState<Severity>("high");
  const [target, setTarget] = useState("");
  const [extra, setExtra] = useState("");

  const config = () => {
    switch (kind) {
      case "email": return { kind, to: target.split(/[\s,;]+/).filter(Boolean) };
      case "slack": case "teams": return { kind, webhook_url: target.trim() };
      case "telegram": return { kind, bot_token: target.trim(), chat_id: extra.trim() };
      case "webhook": return { kind, url: target.trim(), secret: extra.trim() || undefined };
    }
  };
  const create = useMutation({
    mutationFn: () => saveChannel({ data: { name, min_severity: minSev, enabled: true, config: config() } }),
    onSuccess: () => { toast.success("Channel added — send a test to confirm it works"); setName(""); setTarget(""); setExtra(""); refresh(); },
  });
  const toggle = useMutation({
    mutationFn: (v: { id: string; name: string; min_severity: Severity; enabled: boolean }) => saveChannel({ data: v }),
    onSuccess: refresh,
  });
  const del = useMutation({ mutationFn: (id: string) => deleteChannel({ data: { id } }), onSuccess: refresh });
  const test = useMutation({ mutationFn: (id: string) => testChannel({ data: { id } }), onSuccess: () => { toast.success("Test sent"); refresh(); } });
  const k = KINDS.find((x) => x.value === kind)!;

  return (
    <div className="space-y-4">
      <Panel title="Alert notification channels">
        <p className="mb-3 text-sm text-muted-foreground">Every new alert at or above a channel's minimum severity is delivered by the worker, with retries. Repeats of an open alert are merged and do not notify again.</p>
        <ul className="divide-y">
          {data.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center gap-3 py-2.5">
              <div className="min-w-48 flex-1">
                <p className="text-sm">{c.name} <span className="data ml-1 text-[10px] uppercase text-muted-foreground">{c.kind}</span></p>
                <p className="data text-xs text-muted-foreground">{c.target} · {c.sent_7d} sent in 7d{c.last_sent_at ? ` · last ${ago(c.last_sent_at)}` : ""}</p>
                {c.last_error && <p className="data text-xs text-sev-high">Last error: {c.last_error}</p>}
              </div>
              <span className="text-xs text-muted-foreground">≥</span><SeverityBadge s={c.min_severity as Severity} />
              <Switch checked={c.enabled} onCheckedChange={(v) => toggle.mutate({ id: c.id, name: c.name, min_severity: c.min_severity as Severity, enabled: v })} />
              <Button size="sm" variant="outline" onClick={() => test.mutate(c.id)} disabled={test.isPending}>Send test</Button>
              <Button size="sm" variant="ghost" className="text-muted-foreground" onClick={() => confirm(`Delete channel "${c.name}"?`) && del.mutate(c.id)}>Delete</Button>
            </li>
          ))}
          {!data.length && <li className="py-2 text-sm text-sev-medium">No channels yet — nobody is told about critical alerts outside the console.</li>}
        </ul>
      </Panel>
      <Panel title="Add channel">
        <form className="grid gap-3 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
          <select className="h-9 rounded-md border bg-background px-2 text-sm" value={kind} onChange={(e) => { setKind(e.target.value as Kind); setTarget(""); setExtra(""); }}>
            {KINDS.map((x) => <option key={x.value} value={x.value}>{x.label}</option>)}
          </select>
          <Input placeholder="Name, e.g. SOC on-call" value={name} onChange={(e) => setName(e.target.value)} />
          <Input className="sm:col-span-2" placeholder={kind === "email" ? "soc@finpaytech.com, ciso@finpaytech.com" : kind === "telegram" ? "Bot token 123456:ABC…" : "https://…"} value={target} onChange={(e) => setTarget(e.target.value)} />
          {(kind === "telegram" || kind === "webhook") && <Input placeholder={kind === "telegram" ? "Chat id, e.g. -1001234567890" : "Signing secret (optional, 16+ chars)"} value={extra} onChange={(e) => setExtra(e.target.value)} />}
          <select className="h-9 rounded-md border bg-background px-2 text-sm" value={minSev} onChange={(e) => setMinSev(e.target.value as Severity)}>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>Notify for {s} and above</option>)}
          </select>
          <p className="text-xs text-muted-foreground sm:col-span-2">{k.help}</p>
          <div className="sm:col-span-2"><Button disabled={name.trim().length < 2 || !target || create.isPending}>Add channel</Button></div>
        </form>
      </Panel>
    </div>
  );
}
