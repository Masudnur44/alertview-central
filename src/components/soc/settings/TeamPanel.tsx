import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Panel, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { adminUserAction, listUsers, setUserAccess } from "@/lib/api/admin.functions";
import { ROLES, roleLabel, type Role } from "@/lib/permissions";
import { useMe } from "@/lib/session";
import type { TeamMember } from "@/lib/types";

export function TeamPanel() {
  const qc = useQueryClient();
  const me = useMe();
  const { data = [] } = useQuery({ queryKey: ["users"], queryFn: () => listUsers() });
  const refresh = () => qc.invalidateQueries({ queryKey: ["users"] });
  const access = useMutation({
    mutationFn: (v: { id: string; status?: "active" | "disabled"; roles?: Role[] }) => setUserAccess({ data: v }),
    onSuccess: () => { toast.success("Access updated"); refresh(); },
  });
  const action = useMutation({
    mutationFn: (v: { id: string; action: "reset_link" | "revoke_sessions" | "reset_mfa" | "unlock" }) => adminUserAction({ data: v }),
    onSuccess: (r) => {
      if (r && "link" in r && r.link) {
        navigator.clipboard?.writeText(r.link).catch(() => {});
        toast.success("Reset link copied to clipboard (valid 24h). Send it to the user privately.", { duration: 10000 });
        prompt("Password reset link (valid 24 hours):", r.link);
      } else toast.success("Done");
      refresh();
    },
  });
  const pending = data.filter((u) => u.status === "pending");
  return (
    <div className="space-y-4">
      {pending.length > 0 && (
        <Panel title={`Access requests (${pending.length})`}>
          <ul className="divide-y">{pending.map((u) => <PendingRow key={u.id} u={u} onApprove={(roles) => access.mutate({ id: u.id, status: "active", roles })} onReject={() => access.mutate({ id: u.id, status: "disabled" })} />)}</ul>
        </Panel>
      )}
      <Panel title="Team">
        <ul className="divide-y">
          {data.filter((u) => u.status !== "pending").map((u) => (
            <li key={u.id} className="flex flex-wrap items-center gap-3 py-3">
              <div className="min-w-48 flex-1">
                <p className="text-sm">{u.display_name} {u.id === me.id && <span className="data text-[10px] text-primary">YOU</span>}</p>
                <p className="data text-xs text-muted-foreground">{u.email} · last sign-in {ago(u.last_login_at)}</p>
                <p className="data mt-1 flex gap-2 text-[10px]">
                  <span className={u.status === "active" ? "text-ok" : "text-sev-high"}>{u.status.toUpperCase()}</span>
                  <span className={u.mfa_enabled ? "text-ok" : "text-sev-medium"}>{u.mfa_enabled ? "2FA ON" : "NO 2FA"}</span>
                </p>
              </div>
              <RolePicker value={u.roles as Role[]} disabled={u.id === me.id} onChange={(roles) => access.mutate({ id: u.id, roles })} />
              {u.id !== me.id && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild><Button size="sm" variant="ghost">Actions</Button></DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    {u.status === "active"
                      ? <DropdownMenuItem onClick={() => confirm(`Disable ${u.email}? They are signed out immediately.`) && access.mutate({ id: u.id, status: "disabled" })}>Disable account</DropdownMenuItem>
                      : <DropdownMenuItem onClick={() => access.mutate({ id: u.id, status: "active" })}>Re-enable account</DropdownMenuItem>}
                    <DropdownMenuItem onClick={() => action.mutate({ id: u.id, action: "reset_link" })}>Create password-reset link</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => action.mutate({ id: u.id, action: "revoke_sessions" })}>Sign out everywhere</DropdownMenuItem>
                    <DropdownMenuItem onClick={() => action.mutate({ id: u.id, action: "unlock" })}>Unlock (after failed sign-ins)</DropdownMenuItem>
                    {u.mfa_enabled && <DropdownMenuItem onClick={() => confirm("Reset two-factor? The user must enrol again at next sign-in.") && action.mutate({ id: u.id, action: "reset_mfa" })}>Reset two-factor</DropdownMenuItem>}
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-muted-foreground">You can't change your own access, so there is always at least one Security Administrator. Every change here is written to the audit trail.</p>
      </Panel>
    </div>
  );
}

function PendingRow({ u, onApprove, onReject }: { u: TeamMember; onApprove: (roles: Role[]) => void; onReject: () => void }) {
  const [roles, setRoles] = useState<Role[]>(["security_analyst"]);
  return (
    <li className="flex flex-wrap items-center gap-3 py-3">
      <div className="min-w-48 flex-1">
        <p className="text-sm">{u.display_name}</p>
        <p className="data text-xs text-muted-foreground">{u.email} · requested {ago(u.created_at)} {u.email_verified ? "· email confirmed" : "· email not confirmed"}</p>
      </div>
      <RolePicker value={roles} onChange={setRoles} />
      <Button size="sm" onClick={() => onApprove(roles)} disabled={!roles.length}>Approve</Button>
      <Button size="sm" variant="ghost" onClick={onReject}>Reject</Button>
    </li>
  );
}

function RolePicker({ value, onChange, disabled }: { value: Role[]; onChange: (r: Role[]) => void; disabled?: boolean }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild disabled={disabled}>
        <Button size="sm" variant="outline" className="data max-w-72 justify-start truncate text-xs">{value.length ? value.map(roleLabel).join(", ") : "No role"}</Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        {ROLES.map((r) => (
          <DropdownMenuItem key={r.value} onSelect={(e) => e.preventDefault()} onClick={() => onChange(value.includes(r.value) ? value.filter((x) => x !== r.value) : [...value, r.value])}>
            <Checkbox checked={value.includes(r.value)} className="mr-2" />
            <div><p className="text-sm">{r.label}</p><p className="text-xs text-muted-foreground">{r.blurb}</p></div>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
