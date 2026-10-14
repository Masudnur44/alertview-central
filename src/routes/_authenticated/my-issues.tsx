import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { PageHeader, Panel, SeverityBadge, Table, Th, Td, ago } from "@/components/soc/ui";
import { DevIssuePanel, DEV_STATUS_LABEL } from "@/components/soc/DevIssuePanel";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { devUpdateIssue, getMyIssue, myIssues } from "@/lib/api/dev.functions";
import type { Severity } from "@/lib/types";

export const Route = createFileRoute("/_authenticated/my-issues")({
  head: () => ({ meta: [{ title: "My issues — FINPAY SOC" }] }),
  component: MyIssues,
});

function MyIssues() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const { data = [], isLoading } = useQuery({ queryKey: ["my-issues"], queryFn: () => myIssues(), refetchInterval: 30000 });
  const { data: issue } = useQuery({ queryKey: ["my-issue", selected], queryFn: () => getMyIssue({ data: { id: selected! } }), enabled: !!selected });
  const update = useMutation({
    mutationFn: (u: { status?: "acknowledged" | "in_progress" | "fixed"; comment?: string }) => devUpdateIssue({ data: { id: selected!, ...u } }),
    onSuccess: () => { toast.success("Update sent to the SOC"); qc.invalidateQueries({ queryKey: ["my-issues"] }); qc.invalidateQueries({ queryKey: ["my-issue", selected] }); },
    onError: (e: Error) => toast.error(e.message),
  });
  const active = data.filter((i) => ["open", "acknowledged", "in_progress"].includes(i.status));

  return (
    <div>
      <PageHeader title="My issues" sub="Problems the SOC found in your team's systems — with the diagnosis and where to look" />
      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        {[
          ["To do", active.length, ""],
          ["Overdue", data.filter((i) => i.overdue).length, "text-sev-critical"],
          ["New (not acknowledged)", data.filter((i) => i.status === "open").length, "text-sev-high"],
        ].map(([l, v, c]) => (
          <div key={String(l)} className="rounded-lg border bg-card p-3">
            <div className="data text-[11px] uppercase tracking-wider text-muted-foreground">{l}</div>
            <div className={`mt-1 text-2xl font-semibold ${c}`}>{v}</div>
          </div>
        ))}
      </div>
      <Panel>
        <Table>
          <thead><tr><Th>Ref</Th><Th>Severity</Th><Th>Problem</Th><Th>System</Th><Th>Status</Th><Th>Due</Th></tr></thead>
          <tbody>
            {data.map((i) => (
              <tr key={i.id} className="cursor-pointer hover:bg-muted/40" onClick={() => setSelected(i.id)}>
                <Td className="data text-primary">{i.ref}</Td>
                <Td><SeverityBadge s={i.severity as Severity} /></Td>
                <Td>{i.title}</Td>
                <Td className="data">{i.asset_name ?? "—"}</Td>
                <Td className="text-xs">{DEV_STATUS_LABEL[i.status] ?? i.status}</Td>
                <Td className={`data text-xs ${i.overdue ? "text-sev-critical" : "text-muted-foreground"}`}>
                  {i.due_at ? (i.overdue ? `overdue ${ago(i.due_at)}` : new Date(i.due_at).toLocaleString()) : "—"}
                </Td>
              </tr>
            ))}
            {!data.length && !isLoading && (
              <tr><Td className="text-muted-foreground">Nothing assigned to your team. If you expected something, ask the SOC to add you to your team.</Td></tr>
            )}
          </tbody>
        </Table>
      </Panel>
      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
          <SheetHeader><SheetTitle>Issue</SheetTitle></SheetHeader>
          <div className="px-4 pb-6">
            {issue ? <DevIssuePanel issue={issue} busy={update.isPending} onUpdate={(u) => update.mutateAsync({ status: u.status, comment: u.comment })} />
              : <p className="text-sm text-muted-foreground">Loading…</p>}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
