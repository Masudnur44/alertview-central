import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Copy, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { BriefView } from "@/components/soc/BriefView";
import { createIssue, getAlertBrief, listTeams } from "@/lib/api/soc.functions";

/** One click from an alert to a developer: pick the team, add a note, send the generated brief. */
export function SendToDevDialog({ alertId, title, open, onOpenChange }: { alertId: string | null; title?: string; open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const { data: teams = [] } = useQuery({ queryKey: ["teams"], queryFn: () => listTeams(), enabled: open, staleTime: 60_000 });
  const { data: brief } = useQuery({ queryKey: ["brief", alertId], queryFn: () => getAlertBrief({ data: { id: alertId! } }), enabled: open && !!alertId });
  const [teamId, setTeamId] = useState("");
  const [note, setNote] = useState("");
  const [sent, setSent] = useState<{ ref: string; link: string; queued: number } | null>(null);
  useEffect(() => {
    if (open) { setSent(null); setNote(""); }
  }, [open, alertId]);
  useEffect(() => {
    if (brief?.suggestedTeam && !teamId) setTeamId(brief.suggestedTeam.id);
  }, [brief, teamId]);

  const send = useMutation({
    mutationFn: () => createIssue({ data: { alertId: alertId!, teamId: teamId || undefined, note: note || undefined } }),
    onSuccess: (r) => {
      setSent(r);
      toast.success(`${r.ref} sent to the team`);
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["issues"] });
      qc.invalidateQueries({ queryKey: ["command"] });
    },
  });
  const existing = brief?.issues?.filter((i) => !["verified", "wont_fix"].includes(String(i.status))) ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
        <DialogHeader><DialogTitle>Send to developer{title ? `: ${title}` : ""}</DialogTitle></DialogHeader>
        {sent ? (
          <div className="space-y-3 text-sm">
            <p><span className="data text-primary">{sent.ref}</span> created and {sent.queued ? `${sent.queued} message(s) queued to the team.` : "saved — this team has no email/Telegram/WhatsApp contacts yet, so send the link yourself."}</p>
            <p className="text-xs text-muted-foreground">Secure link for the developer (no login needed, expires in 14 days):</p>
            <div className="flex gap-2">
              <code className="data flex-1 break-all rounded bg-muted p-2 text-[11px]">{sent.link}</code>
              <Button size="sm" variant="outline" onClick={() => { navigator.clipboard.writeText(sent.link); toast.success("Link copied"); }}><Copy className="h-4 w-4" /></Button>
            </div>
            <Button className="w-full" variant="outline" onClick={() => onOpenChange(false)}>Done</Button>
          </div>
        ) : (
          <div className="space-y-3">
            {existing.length > 0 && (
              <p className="rounded border border-sev-medium/40 bg-sev-medium/10 p-2 text-xs text-sev-medium">
                Already sent: {existing.map((i) => `${i.ref} (${i.status})`).join(", ")}. Sending again creates a separate issue.
              </p>
            )}
            <label className="block text-xs text-muted-foreground">Team that should fix it
              <select className="mt-1 h-9 w-full rounded-md border bg-background px-2 text-sm text-foreground" value={teamId} onChange={(e) => setTeamId(e.target.value)}>
                <option value="">— choose team —</option>
                {teams.map((t) => <option key={t.id} value={t.id}>{t.name}{brief?.suggestedTeam?.id === t.id ? " (owns this asset)" : ""}</option>)}
              </select>
            </label>
            {!teams.length && <p className="text-xs text-sev-medium">No teams yet — add them in Settings → Teams.</p>}
            <Textarea placeholder="Note for the developer (optional): what you already checked, urgency, who to call…" rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
            <div className="rounded border bg-muted/20 p-3">
              <p className="data mb-2 text-[10px] uppercase tracking-widest text-muted-foreground">What the developer will receive</p>
              {brief ? <BriefView brief={brief.brief} compact /> : <p className="text-xs text-muted-foreground">Building diagnosis…</p>}
            </div>
            <Button className="w-full" disabled={!teamId || send.isPending} onClick={() => send.mutate()}><Send className="mr-2 h-4 w-4" />Send to team</Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
