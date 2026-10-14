// What a developer sees for one issue: the diagnosis, the deadline, the history and
// three buttons (acknowledge / working on it / fixed). Shared by "My issues" and the
// secure no-login link page.
import { useState } from "react";
import { CheckCircle2, Clock, Hammer, Eye } from "lucide-react";
import { BriefView } from "@/components/soc/BriefView";
import { SeverityBadge, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { DevIssue, Severity } from "@/lib/types";

export const DEV_STATUS_LABEL: Record<string, string> = {
  open: "New — please acknowledge", acknowledged: "Acknowledged", in_progress: "Being fixed",
  fixed: "Marked fixed — SOC is verifying", verified: "Verified fixed", wont_fix: "Closed (won't fix)",
};

type Update = { status?: "acknowledged" | "in_progress" | "fixed"; comment?: string; name?: string };

export function DevIssuePanel({ issue, onUpdate, askName, busy }: {
  issue: DevIssue;
  onUpdate: (u: Update) => Promise<unknown>;
  askName?: boolean;
  busy?: boolean;
}) {
  const [comment, setComment] = useState("");
  const [name, setName] = useState(() => {
    try { return (askName && localStorage.getItem("finpay-dev-name")) || ""; } catch { return ""; }
  });
  const closed = ["verified", "wont_fix"].includes(issue.status);
  const overdue = !closed && issue.status !== "fixed" && issue.due_at && new Date(issue.due_at) < new Date();

  async function send(status?: Update["status"]) {
    if (askName && name.trim().length < 2) return alertName();
    if (!status && !comment.trim()) return;
    if (askName) { try { localStorage.setItem("finpay-dev-name", name.trim()); } catch { /* ignore */ } }
    await onUpdate({ status, comment: comment.trim() || undefined, name: name.trim() || undefined });
    setComment("");
  }
  function alertName() {
    document.getElementById("dev-name")?.focus();
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="data text-xs text-primary">{issue.ref}</span>
        <SeverityBadge s={issue.severity as Severity} />
        <span className="data rounded border px-1.5 py-0.5 text-[11px]">{DEV_STATUS_LABEL[issue.status] ?? issue.status}</span>
        {issue.team_name && <span className="data text-[11px] text-muted-foreground">team: {issue.team_name}</span>}
      </div>
      <h2 className="mt-2 text-lg font-semibold">{issue.title}</h2>
      {issue.due_at && !closed && (
        <p className={`data mt-1 flex items-center gap-1.5 text-xs ${overdue ? "text-sev-critical" : "text-muted-foreground"}`}>
          <Clock className="h-3.5 w-3.5" />
          {overdue ? "OVERDUE — was due " : "Fix by "}{new Date(issue.due_at).toLocaleString()}{overdue ? ` (${ago(issue.due_at)})` : ""}
        </p>
      )}

      {!closed && (
        <div className="mt-4 rounded-lg border bg-card p-3">
          {askName && (
            <div className="mb-2">
              <label htmlFor="dev-name" className="text-xs text-muted-foreground">Your name (shown to the SOC)</label>
              <Input id="dev-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="e.g. Amina — backend" className="mt-1" />
            </div>
          )}
          <Textarea value={comment} onChange={(e) => setComment(e.target.value)} maxLength={4000} rows={3}
            placeholder="What did you find / what did you change? (optional)" />
          <div className="mt-2 flex flex-wrap gap-2">
            {issue.status === "open" && (
              <Button variant="outline" disabled={busy} onClick={() => send("acknowledged")}><Eye className="mr-2 h-4 w-4" />Got it</Button>
            )}
            {issue.status !== "in_progress" && issue.status !== "fixed" && (
              <Button variant="outline" disabled={busy} onClick={() => send("in_progress")}><Hammer className="mr-2 h-4 w-4" />Working on it</Button>
            )}
            {issue.status !== "fixed" && (
              <Button disabled={busy} onClick={() => send("fixed")}><CheckCircle2 className="mr-2 h-4 w-4" />It's fixed</Button>
            )}
            <Button variant="ghost" disabled={busy || !comment.trim()} onClick={() => send()}>Add comment only</Button>
          </div>
          <p className="mt-2 text-[11px] text-muted-foreground">
            When you mark it fixed, the monitoring re-checks it. If the problem is really gone the SOC closes it; if it comes back it is reopened and sent to you again.
          </p>
        </div>
      )}

      <div className="mt-5 rounded-lg border p-3">
        <BriefView brief={issue.brief} />
      </div>

      <h3 className="data mt-5 text-[11px] font-bold uppercase tracking-[0.15em] text-muted-foreground">History</h3>
      <ul className="mt-2 space-y-2">
        {issue.updates.map((u, i) => (
          <li key={i} className="rounded border p-2 text-xs">
            <div className="data flex justify-between text-[11px] text-muted-foreground">
              <span>{u.author} · {u.kind}</span><span>{new Date(u.created_at).toLocaleString()}</span>
            </div>
            <p className="mt-1 whitespace-pre-wrap">{u.body}</p>
          </li>
        ))}
        {!issue.updates.length && <li className="text-xs text-muted-foreground">No updates yet.</li>}
      </ul>
    </div>
  );
}
