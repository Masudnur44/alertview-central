import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import type { Database } from "@/integrations/supabase/types";
import { Panel } from "@/components/soc/ui";
import { audit } from "@/lib/soc";

type Role = Database["public"]["Enums"]["app_role"];
const ROLES: Role[] = ["security_admin", "security_analyst", "security_manager", "system_admin", "management", "auditor"];
const label = (r: string) => r.replace(/_/g, " ");

export function RoleManager({ me }: { me: string }) {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["team-roles"],
    queryFn: async () => {
      const [p, r] = await Promise.all([
        supabase.from("profiles").select("id,display_name,email").order("created_at"),
        supabase.from("user_roles").select("id,user_id,role"),
      ]);
      return (p.data ?? []).map((u) => ({ ...u, role: r.data?.find((x) => x.user_id === u.id) }));
    },
  });

  async function change(userId: string, rowId: string | undefined, role: Role) {
    const { error } = rowId
      ? await supabase.from("user_roles").update({ role }).eq("id", rowId)
      : await supabase.from("user_roles").insert({ user_id: userId, role });
    if (error) { toast.error(error.message); return; }
    await audit(`role.set.${role}`, userId);
    toast.success("Role updated");
    qc.invalidateQueries({ queryKey: ["team-roles"] });
  }

  return (
    <Panel title="Team & roles">
      <ul className="divide-y">
        {data?.map((u) => (
          <li key={u.id} className="flex flex-wrap items-center gap-4 py-2.5">
            <div className="flex-1">
              <p className="text-sm">{u.display_name}</p>
              <p className="data text-xs text-muted-foreground">{u.email}</p>
            </div>
            <select
              className="data rounded border bg-background px-2 py-1 text-xs capitalize"
              value={u.role?.role ?? ""}
              disabled={u.id === me}
              onChange={(e) => change(u.id, u.role?.id, e.target.value as Role)}
            >
              {!u.role && <option value="">no role</option>}
              {ROLES.map((r) => <option key={r} value={r}>{label(r)}</option>)}
            </select>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-xs text-muted-foreground">You can't change your own role, so there's always at least one Security Administrator.</p>
    </Panel>
  );
}
