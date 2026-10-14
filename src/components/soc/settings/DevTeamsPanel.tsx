// Developer teams: who owns which systems and where their issues are delivered
// (email addresses, a Telegram group, WhatsApp numbers).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Mail, MessageCircle, Plus, Send, Trash2 } from "lucide-react";
import { Panel } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { deleteTeam, saveTeam } from "@/lib/api/admin.functions";
import { listTeams, type TeamRow } from "@/lib/api/soc.functions";

const split = (s: string) => s.split(/[,;\n]/).map((x) => x.trim()).filter(Boolean);

export function DevTeamsPanel() {
  const qc = useQueryClient();
  const { data = [] } = useQuery({ queryKey: ["teams"], queryFn: () => listTeams() });
  const [editing, setEditing] = useState<TeamRow | "new" | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => deleteTeam({ data: { id } }),
    onSuccess: () => { toast.success("Team deleted"); qc.invalidateQueries({ queryKey: ["teams"] }); },
    onError: (e: Error) => toast.error(e.message),
  });
  return (
    <Panel title="Developer teams" action={<Button size="sm" onClick={() => setEditing("new")}><Plus className="mr-1 h-4 w-4" />Add team</Button>}>
      <p className="mb-3 text-xs text-muted-foreground">
        Each asset belongs to a team. When you send an issue, it goes to that team's email addresses, Telegram group and WhatsApp numbers, with a secure link to the diagnosis. Developers with an account (role "Developer") see their team's issues under "My issues".
      </p>
      <ul className="divide-y">
        {data.map((t) => (
          <li key={t.id} className="flex flex-wrap items-center gap-3 py-3">
            <div className="min-w-56 flex-1">
              <p className="text-sm font-medium">{t.name}</p>
              {t.description && <p className="text-xs text-muted-foreground">{t.description}</p>}
              <p className="data mt-1 flex flex-wrap gap-3 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1"><Mail className="h-3 w-3" />{t.emails.length || "no"} email</span>
                <span className={`flex items-center gap-1 ${t.telegram_chat_id ? "" : "opacity-50"}`}><Send className="h-3 w-3" />{t.telegram_chat_id ? "Telegram" : "no Telegram"}</span>
                <span className={`flex items-center gap-1 ${t.whatsapp_numbers.length ? "" : "opacity-50"}`}><MessageCircle className="h-3 w-3" />{t.whatsapp_numbers.length} WhatsApp</span>
                <span>{t.assets} assets · {t.members} dev accounts · {t.open_issues} open issues</span>
              </p>
              {!t.emails.length && !t.telegram_chat_id && !t.whatsapp_numbers.length && (
                <p className="data mt-1 text-[11px] text-sev-high">No delivery channel — issues will only be visible in the app and by secure link.</p>
              )}
            </div>
            <Button size="sm" variant="outline" onClick={() => setEditing(t)}>Edit</Button>
            <Button size="sm" variant="ghost" onClick={() => confirm(`Delete team ${t.name}? Its assets and users become unassigned.`) && del.mutate(t.id)}>
              <Trash2 className="h-4 w-4" />
            </Button>
          </li>
        ))}
        {!data.length && <li className="py-3 text-sm text-muted-foreground">No teams yet. Add your first team (e.g. "Payments Engineering").</li>}
      </ul>
      {editing && <TeamDialog team={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
    </Panel>
  );
}

function TeamDialog({ team, onClose }: { team: TeamRow | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(team?.name ?? "");
  const [description, setDescription] = useState(team?.description ?? "");
  const [emails, setEmails] = useState((team?.emails ?? []).join(", "));
  const [telegram, setTelegram] = useState(team?.telegram_chat_id ?? "");
  const [whatsapp, setWhatsapp] = useState((team?.whatsapp_numbers ?? []).join(", "));
  const save = useMutation({
    mutationFn: () => saveTeam({ data: { id: team?.id, name, description: description || null, emails: split(emails), telegram_chat_id: telegram || null, whatsapp_numbers: split(whatsapp) } }),
    onSuccess: () => { toast.success("Team saved"); qc.invalidateQueries({ queryKey: ["teams"] }); onClose(); },
    onError: (e: Error) => toast.error(e.message.length > 200 ? "Check the email addresses, Telegram chat id and phone numbers." : e.message),
  });
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader><DialogTitle>{team ? `Edit ${team.name}` : "New team"}</DialogTitle></DialogHeader>
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Name"><Input value={name} onChange={(e) => setName(e.target.value)} required maxLength={80} placeholder="Payments Engineering" /></Field>
          <Field label="What they own"><Input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} placeholder="Card gateway, settlement API" /></Field>
          <Field label="Emails (comma separated)"><Input value={emails} onChange={(e) => setEmails(e.target.value)} placeholder="payments-dev@finpay.example, lead@finpay.example" /></Field>
          <Field label="Telegram group chat id" hint="Add the SOC bot to the group, then use the group's id (e.g. -1001234567890).">
            <Input value={telegram} onChange={(e) => setTelegram(e.target.value)} placeholder="-1001234567890" />
          </Field>
          <Field label="WhatsApp numbers (comma separated)" hint="International format. Needs WhatsApp Business API settings on the server.">
            <Input value={whatsapp} onChange={(e) => setWhatsapp(e.target.value)} placeholder="+254700000000" />
          </Field>
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={save.isPending}>Save</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs text-muted-foreground">{label}</span>
      <div className="mt-1">{children}</div>
      {hint && <span className="mt-1 block text-[11px] text-muted-foreground">{hint}</span>}
    </label>
  );
}
