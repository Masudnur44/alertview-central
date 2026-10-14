import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
import { Copy, Link2, RefreshCw, Send } from "lucide-react";
import { PageHeader, Panel, SeverityBadge, Table, Th, Td, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { BriefView } from "@/components/soc/BriefView";
import { createIssue, getIssue, listIssues, listTeams, updateIssue } from "@/lib/api/soc.functions";
import { useCan } from "@/lib/session";
import type { Brief, Severity } from "@/lib/types";

export const Route = createFileRoute("/_authenticated/issues")({
  validateSearch: z.object({ ref: z.string().max(30).optional(), team: z.string().max(40).optional() }),
  head: () => ({ meta: [{ title: "Issues to developers — FINPAY SOC" }] }),
  component: Issues,
});

const STATUS_LABEL: Record<string, string> = {
  open: "Sent, not acknowledged", acknowledged: "Acknowledged", in_progress: "Being fixed", fixed: "Dev says fixed", verified: "Verified fixed", wont_fix: "Won't fix",
};
const STATUS_TONE: Record<string, string> = {
  open: "text-sev-high", acknowledged: "text-sev-medium", in_progress: "text-primary", fixed: "text-ok", verified: "text-ok", wont_fix: "text-muted-foreground",
};

function Issues() {
  const search = Route.useSearch();
  const canSend = useCan("issues.send");
  const [status, setStatus] = useState("active");
  const [teamId, setTeamId] = useState(search.team ?? "");
  const [selected, setSelected] = useState<string | null>(null);
  const [manual, setManual] = useState(false);
  const { data: teams = [] } = useQuery({ queryKey: ["teams"], queryFn: () => listTeams() });
  const { data = [] } = useQuery({ queryKey: ["issues", status, teamId], queryFn: () => listIssues({ data: { status, teamId } }), refetchInterval: 20000 });
  useEffect(() => {
    if (search.ref) {
      const hit = data.find((i) => i.ref === search.ref);
      if (hit) setSelected(hit.id);
      else if (status !== "all") setStatus("all");
    }
  }, [search.ref, data, status]);

  const open = data.filter((i) => ["open", "acknowledged", "in_progress"].includes(i.status));
  return (
    <div>
      <PageHeader title="Issues sent to developers" sub="Every problem handed to a team, with its diagnosis, owner, deadline and progress"
        action={canSend && <Button onClick={() => setManual(true)}><Send className="mr-2 h-4 w-4" />New issue</Button>} />
      <div className="mb-4 grid gap-3 sm:grid-cols-4">
        {[
          ["Open with devs", open.length, ""],
          ["Overdue", data.filter((i) => i.overdue).length, "text-sev-critical"],
          ["Not acknowledged", data.filter((i) => i.status === "open").length, "text-sev-high"],
          ["Waiting for verification", data.filter((i) => i.status === "fixed").length, "text-primary"],
        ].map(([l, v, c]) => (
          <div key={String(l)} className="rounded-lg border bg-card p-3">
            <p className="data text-[10px] uppercase tracking-[0.15em] text-muted-foreground">{l}</p>
            <p className={`data mt-1 text-2xl font-bold ${c}`}>{v}</p>
          </div>
        ))}
      </div>
      <div className="mb-3 flex flex-wrap gap-2">
        {["active", "open", "acknowledged", "in_progress", "fixed", "verified", "wont_fix", "all"].map((s) => (
          <button key={s} onClick={() => setStatus(s)} className={`data rounded border px-2.5 py-1 text-xs ${status === s ? "border-primary text-primary" : "text-muted-foreground"}`}>{s.replace("_", " ")}</button>
        ))}
        <select className="data h-7 rounded border bg-background px-2 text-xs" value={teamId} onChange={(e) => setTeamId(e.target.value)}>
          <option value="">All teams</option>
          {teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
      </div>
      <Table>
        <thead><tr><Th>Ref</Th><Th>Sev</Th><Th>Problem</Th><Th>Team</Th><Th>Status</Th><Th>Due</Th><Th>Last update</Th></tr></thead>
        <tbody>
          {data.map((i) => (
            <tr key={i.id} className="cursor-pointer" onClick={() => setSelected(i.id)}>
              <Td className="data text-xs text-primary">{i.ref}{i.reopened_count > 0 && <span className="ml-1 text-sev-high" title="Came back after being fixed">↻{i.reopened_count}</span>}</Td>
              <Td><SeverityBadge s={i.severity} /></Td>
              <Td><div className="font-medium">{i.title}</div><div className="data text-xs text-muted-foreground">{i.asset_name ?? ""}</div></Td>
              <Td className="text-xs">{i.team_name ?? "—"}</Td>
              <Td className={`data text-xs ${STATUS_TONE[i.status]}`}>{STATUS_LABEL[i.status] ?? i.status}</Td>
              <Td className={`data text-xs ${i.overdue ? "font-bold text-sev-critical" : "text-muted-foreground"}`}>{i.overdue ? "OVERDUE " : ""}{ago(i.due_at)}</Td>
              <Td className="data text-xs text-muted-foreground">{ago(i.last_update)}</Td>
            </tr>
          ))}
          {!data.length && <tr><Td className="text-muted-foreground">No issues. Use “Send to developer” on any alert or early warning.</Td></tr>}
        </tbody>
      </Table>
      <IssueSheet id={selected} onClose={() => setSelected(null)} teams={teams} />
      <ManualIssue open={manual} onOpenChange={setManual} teams={teams} />
    </div>
  );
}

function IssueSheet({ id, onClose, teams }: { id: string | null; onClose: () => void; teams: { id: string; name: string }[] }) {
  const qc = useQueryClient();
  const canSend = useCan("issues.send");
  const [comment, setComment] = useState("");
  const [link, setLink] = useState<string | null>(null);
  const { data } = useQuery({ queryKey: ["issue", id], queryFn: () => getIssue({ data: { id: id! } }), enabled: !!id, refetchInterval: 15000 });
  useEffect(() => setLink(null), [id]);
  const upd = useMutation({
    mutationFn: (v: { status?: "open" | "acknowledged" | "in_progress" | "fixed" | "verified" | "wont_fix"; teamId?: string; comment?: string; resend?: boolean; newLink?: boolean }) => updateIssue({ data: { id: id!, ...v } }),
    onSuccess: (r, v) => {
      if (r.link) setLink(r.link);
      if (v.resend) toast.success("Sent to the team again");
      setComment("");
      qc.invalidateQueries({ queryKey: ["issue", id] });
      qc.invalidateQueries({ queryKey: ["issues"] });
      qc.invalidateQueries({ queryKey: ["command"] });
    },
  });
  const i = data?.issue;
  return (
    <Sheet open={!!id} onOpenChange={(v) => !v && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
        {!i ? <p className="text-sm text-muted-foreground">Loading…</p> : (
          <>
            <SheetHeader>
              <SheetTitle className="flex flex-wrap items-center gap-2"><span className="data text-primary">{i.ref}</span><SeverityBadge s={i.severity as Severity} /> {i.title}</SheetTitle>
            </SheetHeader>
            <p className={`data mt-1 text-xs ${STATUS_TONE[i.status]}`}>{STATUS_LABEL[i.status]} · team {i.team_name ?? "—"} · due {new Date(i.due_at).toLocaleString()}{i.reopened_count ? ` · reopened ${i.reopened_count}×` : ""}</p>
            {canSend && (
              <div className="mt-3 flex flex-wrap gap-2">
                {i.status === "fixed" && <Button size="sm" onClick={() => upd.mutate({ status: "verified" })}>Confirm fixed</Button>}
                {i.status === "fixed" && <Button size="sm" variant="outline" onClick={() => upd.mutate({ status: "open", comment: "Not fixed yet — still seeing the problem.", resend: true })}>Not fixed — send back</Button>}
                {!["verified", "wont_fix"].includes(i.status) && <Button size="sm" variant="outline" onClick={() => upd.mutate({ resend: true })}><RefreshCw className="mr-1 h-3.5 w-3.5" />Remind team</Button>}
                <Button size="sm" variant="outline" onClick={() => upd.mutate({ newLink: true })}><Link2 className="mr-1 h-3.5 w-3.5" />New secure link</Button>
                <select className="data h-8 rounded border bg-background px-2 text-xs" value={i.team_id ?? ""} onChange={(e) => e.target.value && upd.mutate({ teamId: e.target.value })}>
                  {teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                </select>
                {!["verified", "wont_fix"].includes(i.status) && <Button size="sm" variant="ghost" className="text-muted-foreground" onClick={() => upd.mutate({ status: "wont_fix" })}>Close as won't fix</Button>}
                {["verified", "wont_fix"].includes(i.status) && <Button size="sm" variant="outline" onClick={() => upd.mutate({ status: "open", resend: true })}>Reopen</Button>}
              </div>
            )}
            {link && (
              <div className="mt-3 flex gap-2">
                <code className="data flex-1 break-all rounded bg-muted p-2 text-[11px]">{link}</code>
                <Button size="sm" variant="outline" onClick={() => { navigator.clipboard.writeText(link); toast.success("Copied"); }}><Copy className="h-4 w-4" /></Button>
              </div>
            )}
            {data.link && !link && <p className="data mt-2 text-[11px] text-muted-foreground">Secure link active until {new Date(data.link.expires_at).toLocaleDateString()}{data.link.last_used_at ? ` · last opened ${ago(data.link.last_used_at)}` : " · not opened yet"}</p>}

            <Panel title="Timeline" className="mt-4">
              <ol className="relative space-y-3 border-l pl-4">
                {data.updates.map((u) => (
                  <li key={u.id}>
                    <span className="absolute -left-1 mt-1.5 h-2 w-2 rounded-full bg-primary" />
                    <p className="data text-[10px] uppercase tracking-wider text-muted-foreground">{u.kind} · {u.author} · {new Date(u.created_at).toLocaleString()}</p>
                    <p className="whitespace-pre-wrap text-sm">{u.body}</p>
                  </li>
                ))}
              </ol>
              {canSend && (
                <div className="mt-3 flex gap-2">
                  <Input placeholder="Add a note for the team…" value={comment} onChange={(e) => setComment(e.target.value)} />
                  <Button size="sm" disabled={!comment.trim()} onClick={() => upd.mutate({ comment })}>Add</Button>
                </div>
              )}
            </Panel>
            {data.messages.length > 0 && (
              <Panel title="Messages to the team" className="mt-4">
                <ul className="data space-y-1 text-[11px]">
                  {data.messages.map((m, n) => (
                    <li key={n} className="flex gap-2"><span className="w-16">{m.channel}</span><span className="flex-1 truncate">{m.recipient}</span>
                      <span className={m.status === "sent" ? "text-ok" : m.status === "failed" ? "text-sev-critical" : "text-muted-foreground"}>{m.status}</span>
                      {m.last_error && <span className="truncate text-sev-high" title={m.last_error}>{m.last_error}</span>}</li>
                  ))}
                </ul>
              </Panel>
            )}
            <Panel title="Diagnosis sent to the developer" className="mt-4"><BriefView brief={i.brief as Brief} /></Panel>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function ManualIssue({ open, onOpenChange, teams }: { open: boolean; onOpenChange: (v: boolean) => void; teams: { id: string; name: string }[] }) {
  const qc = useQueryClient();
  const [f, setF] = useState<{ title: string; teamId: string; severity: Severity; note: string }>({ title: "", teamId: "", severity: "medium", note: "" });
  const [done, setDone] = useState<{ ref: string; link: string } | null>(null);
  const create = useMutation({
    mutationFn: () => createIssue({ data: { title: f.title, teamId: f.teamId, severity: f.severity, note: f.note || undefined } }),
    onSuccess: (r) => { setDone(r); qc.invalidateQueries({ queryKey: ["issues"] }); },
  });
  return (
    <Dialog open={open} onOpenChange={(v) => { onOpenChange(v); if (!v) setDone(null); }}>
      <DialogContent>
        <DialogHeader><DialogTitle>New issue for a team</DialogTitle></DialogHeader>
        {done ? (
          <div className="space-y-2 text-sm">
            <p><span className="data text-primary">{done.ref}</span> sent.</p>
            <code className="data block break-all rounded bg-muted p-2 text-[11px]">{done.link}</code>
          </div>
        ) : (
          <div className="space-y-3">
            <Input placeholder="What needs fixing" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} />
            <div className="grid grid-cols-2 gap-2">
              <select className="h-9 rounded-md border bg-background px-2 text-sm" value={f.teamId} onChange={(e) => setF({ ...f, teamId: e.target.value })}>
                <option value="">— team —</option>{teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
              <select className="h-9 rounded-md border bg-background px-2 text-sm" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value as Severity })}>
                {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <Textarea rows={5} placeholder="Details: what you saw, where, how to reproduce, what you already checked" value={f.note} onChange={(e) => setF({ ...f, note: e.target.value })} />
            <Button className="w-full" disabled={f.title.trim().length < 3 || !f.teamId || create.isPending} onClick={() => create.mutate()}>Send to team</Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
