import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Download, ShieldCheck } from "lucide-react";
import { Panel } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { exportAudit, listAudit, verifyAuditChain } from "@/lib/api/admin.functions";
import { downloadCsv } from "@/lib/risk";

export function AuditPanel() {
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  useEffect(() => { const t = setTimeout(() => setDebounced(q), 350); return () => clearTimeout(t); }, [q]);
  const { data = [] } = useQuery({ queryKey: ["audit", debounced], queryFn: () => listAudit({ data: { q: debounced } }) });
  const verify = useMutation({
    mutationFn: () => verifyAuditChain(),
    onSuccess: (r) => (r.intact ? toast.success(`Audit chain intact (${r.total} entries)`) : toast.error(`Audit chain BROKEN at entry #${r.brokenAt} — the log may have been tampered with`, { duration: 20000 })),
  });
  const exp = useMutation({
    mutationFn: () => exportAudit(),
    onSuccess: (rows) => downloadCsv(`finpay-soc-audit-${new Date().toISOString().slice(0, 10)}.csv`, [
      ["id", "at", "actor", "action", "target_type", "target_id", "detail", "ip", "hash"],
      ...rows.map((r) => [r.id, r.at, r.actor_email, r.action, r.target_type, r.target_id, r.detail, r.ip, r.hash]),
    ]),
  });
  return (
    <Panel title="Audit trail" action={<div className="flex gap-2">
      <Button size="sm" variant="outline" onClick={() => verify.mutate()} disabled={verify.isPending}><ShieldCheck className="mr-1 h-3.5 w-3.5" />Verify integrity</Button>
      <Button size="sm" variant="outline" onClick={() => exp.mutate()} disabled={exp.isPending}><Download className="mr-1 h-3.5 w-3.5" />Export</Button>
    </div>}>
      <p className="mb-3 text-xs text-muted-foreground">Append-only and hash-chained in the database: entries cannot be edited or deleted through the application, and “Verify integrity” detects any tampering. Every change made by a person is recorded with a before/after diff.</p>
      <Input placeholder="Filter by action, person or target…" value={q} onChange={(e) => setQ(e.target.value)} className="mb-3 max-w-sm" />
      <ul className="data divide-y text-xs">
        {data.map((l) => (
          <li key={l.id} className="py-2">
            <div className="flex flex-wrap gap-x-4">
              <span className="w-40 text-muted-foreground">{new Date(l.at).toLocaleString()}</span>
              <span className="w-56 truncate">{l.actor_email ?? "system"}</span>
              <span className="text-primary">{l.action}</span>
              <span className="truncate text-muted-foreground">{l.target_id}</span>
              {l.ip && <span className="text-muted-foreground">{l.ip}</span>}
            </div>
            {l.detail && <details className="mt-1"><summary className="cursor-pointer text-muted-foreground">details</summary><pre className="mt-1 overflow-x-auto rounded bg-muted p-2 text-[11px]">{JSON.stringify(l.detail, null, 2)}</pre></details>}
          </li>
        ))}
        {!data.length && <li className="py-2 text-muted-foreground">No entries.</li>}
      </ul>
    </Panel>
  );
}
