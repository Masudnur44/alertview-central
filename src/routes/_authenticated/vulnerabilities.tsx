import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Download } from "lucide-react";
import { PageHeader, SeverityBadge, Stat, Table, Th, Td, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { listAssets, listVulns, saveVuln, setVulnStatus } from "@/lib/api/soc.functions";
import { downloadCsv, riskScore } from "@/lib/risk";
import { useCan } from "@/lib/session";
import type { Severity, Vulnerability } from "@/lib/types";

export const Route = createFileRoute("/_authenticated/vulnerabilities")({
  head: () => ({ meta: [{ title: "Vulnerabilities — FINPAY SOC" }, { name: "description", content: "Risk-prioritized vulnerabilities correlated with alerts." }] }),
  component: Vulns,
});

const STATUS = ["open", "in_progress", "risk_accepted", "fixed"] as const;

function Vulns() {
  const qc = useQueryClient();
  const canManage = useCan("vulns.manage");
  const [show, setShow] = useState<"open" | "all">("open");
  const [editing, setEditing] = useState<Vulnerability | null | undefined>(undefined);
  const { data = [] } = useQuery({ queryKey: ["vulns"], queryFn: () => listVulns() });
  const rows = data.map((v) => {
    const overdue = !!v.due_at && new Date(v.due_at).getTime() < Date.now() && !["fixed", "risk_accepted"].includes(v.status);
    return { ...v, overdue, risk: riskScore({ ...v, criticality: v.asset_criticality, overdue }) };
  }).sort((a, b) => b.risk - a.risk);
  const open = rows.filter((r) => !["fixed", "risk_accepted"].includes(r.status));
  const shown = show === "open" ? open : rows;
  const status = useMutation({
    mutationFn: (v: { id: string; status: (typeof STATUS)[number] }) => setVulnStatus({ data: v }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vulns"] }),
  });

  return (
    <div>
      <PageHeader title="Vulnerabilities" sub="Ranked by risk: severity, known exploitation (CISA KEV), internet exposure, asset criticality, live alerts and SLA"
        action={<div className="flex gap-2">
          <Button variant="outline" onClick={() => downloadCsv("finpay-vulnerabilities.csv", [["risk", "title", "cve", "severity", "cvss", "asset", "status", "kev", "exposed", "due", "first_seen"], ...rows.map((v) => [v.risk, v.title, v.cve, v.severity, v.cvss, v.asset_name, v.status, v.exploited_in_wild ? "yes" : "", v.internet_exposed ? "yes" : "", v.due_at?.slice(0, 10), v.first_seen.slice(0, 10)])])}><Download className="mr-1 h-4 w-4" />CSV</Button>
          {canManage && <Button onClick={() => setEditing(null)}>Add finding</Button>}
        </div>} />
      <div className="mb-6 grid gap-4 md:grid-cols-5">
        <Stat label="Open" value={open.length} />
        <Stat label="Critical" value={open.filter((v) => v.severity === "critical").length} tone="text-sev-critical" />
        <Stat label="Known exploited" value={open.filter((v) => v.exploited_in_wild).length} tone="text-sev-high" hint="On the CISA KEV list" />
        <Stat label="Under active targeting" value={open.filter((v) => v.open_alerts).length} tone="text-sev-high" hint="Asset also has open alerts" />
        <Stat label="Past SLA" value={open.filter((v) => v.overdue).length} tone="text-sev-medium" hint="7/30/90/180 days by severity" />
      </div>
      <div className="mb-3 flex gap-2">
        {(["open", "all"] as const).map((s) => <button key={s} onClick={() => setShow(s)} className={`data rounded border px-2.5 py-1 text-xs ${show === s ? "border-primary text-primary" : "text-muted-foreground"}`}>{s}</button>)}
      </div>
      <Table>
        <thead><tr><Th>Risk</Th><Th>Finding</Th><Th>Sev</Th><Th>Asset</Th><Th>Signals</Th><Th>Due</Th><Th>Status</Th></tr></thead>
        <tbody>
          {shown.map((v) => (
            <tr key={v.id}>
              <Td><span className={`data text-lg font-bold ${v.risk >= 85 ? "text-sev-critical" : v.risk >= 65 ? "text-sev-high" : "text-sev-medium"}`}>{v.risk}</span></Td>
              <Td>
                <button className="text-left font-medium hover:text-primary" onClick={() => canManage && setEditing(v)}>{v.title}</button>
                <div className="data text-xs text-muted-foreground">{v.cve ?? "—"} · CVSS {v.cvss ?? "—"} · found {ago(v.first_seen)}</div>
                {v.remediation && <div className="mt-1 max-w-lg text-xs text-muted-foreground">Fix: {v.remediation}</div>}
              </Td>
              <Td><SeverityBadge s={v.severity} /></Td>
              <Td className="data text-xs">{v.asset_name}</Td>
              <Td className="data space-x-1 text-[10px]">
                {v.exploited_in_wild && <span className="rounded bg-sev-critical/15 px-1 text-sev-critical">KEV</span>}
                {v.internet_exposed && <span className="rounded bg-sev-medium/15 px-1 text-sev-medium">EXPOSED</span>}
                {v.open_alerts > 0 && <span className="rounded bg-sev-high/15 px-1 text-sev-high">TARGETED</span>}
              </Td>
              <Td className={`data text-xs ${v.overdue ? "text-sev-high" : "text-muted-foreground"}`}>{v.due_at ? new Date(v.due_at).toLocaleDateString() : "—"}{v.overdue && " · overdue"}</Td>
              <Td>
                {canManage ? (
                  <select value={v.status} onChange={(e) => status.mutate({ id: v.id, status: e.target.value as (typeof STATUS)[number] })} className="data h-7 rounded border bg-background px-1 text-xs">
                    {STATUS.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
                  </select>
                ) : <span className="data text-xs">{v.status.replace("_", " ")}</span>}
              </Td>
            </tr>
          ))}
          {!shown.length && <tr><Td className="text-muted-foreground">No findings.</Td></tr>}
        </tbody>
      </Table>
      {editing !== undefined && <VulnDialog vuln={editing} onClose={() => setEditing(undefined)} />}
    </div>
  );
}

function VulnDialog({ vuln, onClose }: { vuln: Vulnerability | null; onClose: () => void }) {
  const qc = useQueryClient();
  const { data: assets = [] } = useQuery({ queryKey: ["assets"], queryFn: () => listAssets() });
  const [f, setF] = useState({
    title: vuln?.title ?? "", cve: vuln?.cve ?? "", description: vuln?.description ?? "", remediation: vuln?.remediation ?? "",
    severity: (vuln?.severity ?? "high") as Severity, cvss: vuln?.cvss?.toString() ?? "", asset_id: vuln?.asset_id ?? "",
    internet_exposed: vuln?.internet_exposed ?? false, status: (vuln?.status ?? "open") as (typeof STATUS)[number],
  });
  const save = useMutation({
    mutationFn: () => saveVuln({ data: { ...f, id: vuln?.id, cve: f.cve || null, cvss: f.cvss ? Number(f.cvss) : null, asset_id: f.asset_id || null } }),
    onSuccess: () => { toast.success("Saved"); qc.invalidateQueries({ queryKey: ["vulns"] }); onClose(); },
  });
  const sel = "h-9 w-full rounded-md border bg-background px-2 text-sm";
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto">
        <DialogHeader><DialogTitle>{vuln ? "Edit finding" : "Add vulnerability finding"}</DialogTitle></DialogHeader>
        <div className="space-y-3">
          <Input placeholder="Title" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} />
          <div className="grid grid-cols-3 gap-2">
            <Input placeholder="CVE-2024-12345" value={f.cve} onChange={(e) => setF({ ...f, cve: e.target.value })} />
            <Input placeholder="CVSS" type="number" step="0.1" min="0" max="10" value={f.cvss} onChange={(e) => setF({ ...f, cvss: e.target.value })} />
            <select className={sel} value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value as Severity })}>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select>
          </div>
          <select className={sel} value={f.asset_id} onChange={(e) => setF({ ...f, asset_id: e.target.value })}>
            <option value="">— Asset —</option>
            {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
          <Textarea placeholder="Description" rows={3} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
          <Textarea placeholder="Remediation" rows={2} value={f.remediation} onChange={(e) => setF({ ...f, remediation: e.target.value })} />
          <label className="flex items-center justify-between rounded border p-3 text-sm">Reachable from the internet <Switch checked={f.internet_exposed} onCheckedChange={(v) => setF({ ...f, internet_exposed: v })} /></label>
          <p className="text-xs text-muted-foreground">If the CVE is on the CISA Known Exploited list it is flagged automatically, and an SLA due date is set from the severity.</p>
          <Button className="w-full" disabled={f.title.trim().length < 3 || save.isPending} onClick={() => save.mutate()}>Save</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
