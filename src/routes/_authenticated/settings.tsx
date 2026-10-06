import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader, Panel, SeverityBadge, ago, type Severity } from "@/components/soc/ui";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { audit } from "@/lib/soc";

export const Route = createFileRoute("/_authenticated/settings")({
  head: () => ({ meta: [{ title: "Settings — FINPAY SOC" }, { name: "description", content: "Detection rules, event sources and audit log." }] }),
  component: Settings,
});

function Settings() {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const { data } = useQuery({
    queryKey: ["settings"],
    queryFn: async () => {
      const { data: u } = await supabase.auth.getUser();
      const [rules, sources, logs, roles] = await Promise.all([
        supabase.from("detection_rules").select("*").order("severity"),
        supabase.from("event_sources").select("*").order("created_at"),
        supabase.from("audit_log").select("*").order("created_at", { ascending: false }).limit(50),
        supabase.from("user_roles").select("role").eq("user_id", u.user!.id),
      ]);
      return { rules: rules.data ?? [], sources: sources.data, logs: logs.data, roles: (roles.data ?? []).map((r) => r.role) };
    },
  });
  if (!data) return null;
  const origin = typeof window !== "undefined" ? window.location.origin : "";

  async function toggle(id: string, enabled: boolean) {
    const { error } = await supabase.from("detection_rules").update({ enabled }).eq("id", id);
    if (error) return toast.error(error.message);
    await audit(`rule.${enabled ? "enable" : "disable"}`, id);
    qc.invalidateQueries({ queryKey: ["settings"] });
  }
  async function addSource() {
    const { error } = await supabase.from("event_sources").insert({ name, source_type: "custom" });
    if (error) return toast.error(error.message);
    await audit("source.create", name);
    setName("");
    qc.invalidateQueries({ queryKey: ["settings"] });
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" sub={`Your role: ${data.roles.join(", ").replace(/_/g, " ") || "none"}`} />
      <Panel title="Detection rules">
        <ul className="divide-y">
          {data.rules.map((r) => (
            <li key={r.id} className="flex items-center gap-4 py-3">
              <SeverityBadge s={r.severity as Severity} />
              <div className="flex-1">
                <p className="text-sm font-medium">{r.name}</p>
                <p className="text-xs text-muted-foreground">{r.description}</p>
              </div>
              <span className="data text-xs text-primary">{r.mitre_technique}</span>
              <span className="data w-16 text-right text-xs text-muted-foreground">{r.hits} hits</span>
              <Switch checked={r.enabled} onCheckedChange={(v) => toggle(r.id, v)} />
            </li>
          ))}
        </ul>
      </Panel>

      <Panel title="Event sources · log intake">
        {data.sources ? (
          <>
            <p className="mb-3 text-sm text-muted-foreground">Point servers, endpoint agents or applications at the intake URL with the source key in the <code className="data text-primary">x-soc-key</code> header.</p>
            <pre className="data mb-4 overflow-x-auto rounded bg-muted p-3 text-xs">{`curl -X POST ${origin}/api/public/ingest \\
  -H "content-type: application/json" -H "x-soc-key: <SOURCE_KEY>" \\
  -d '{"event_type":"auth.login","host":"app-srv-02","username":"jdoe","src_ip":"1.2.3.4","outcome":"failure"}'`}</pre>
            <ul className="divide-y">
              {data.sources.map((s) => (
                <li key={s.id} className="flex flex-wrap items-center gap-4 py-2.5">
                  <span className="flex-1 text-sm">{s.name}</span>
                  <code className="data rounded bg-muted px-2 py-1 text-[11px]">{s.api_key}</code>
                  <span className="data w-28 text-right text-xs text-muted-foreground">{s.last_event_at ? ago(s.last_event_at) : "no events"}</span>
                </li>
              ))}
            </ul>
            <div className="mt-3 flex gap-2">
              <Input placeholder="New source name" value={name} onChange={(e) => setName(e.target.value)} className="max-w-xs" />
              <Button onClick={addSource} disabled={!name}>Add source</Button>
            </div>
          </>
        ) : <p className="text-sm text-muted-foreground">Only Security or System Administrators can manage event sources.</p>}
      </Panel>

      <Panel title="Audit log">
        {data.logs?.length ? (
          <ul className="data divide-y text-xs">
            {data.logs.map((l) => (
              <li key={l.id} className="flex gap-4 py-2"><span className="w-28 text-muted-foreground">{ago(l.created_at)}</span><span className="text-primary">{l.action}</span><span className="truncate text-muted-foreground">{l.target}</span></li>
            ))}
          </ul>
        ) : <p className="text-sm text-muted-foreground">No entries, or your role cannot view the audit log.</p>}
      </Panel>
    </div>
  );
}
