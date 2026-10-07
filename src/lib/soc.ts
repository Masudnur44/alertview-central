import { supabase } from "@/integrations/supabase/client";

export async function audit(action: string, target?: string) {
  const { data } = await supabase.auth.getUser();
  if (!data.user) return;
  await supabase.from("audit_log").insert({ actor: data.user.id, action, target: target ?? null });
}

export function riskScore(v: { cvss: number | null; exploited_in_wild: boolean; internet_exposed: boolean; criticality?: string | null }) {
  let s = Number(v.cvss ?? 5) * 10;
  if (v.exploited_in_wild) s += 25;
  if (v.internet_exposed) s += 15;
  if (v.criticality === "critical") s += 15;
  else if (v.criticality === "high") s += 8;
  return Math.min(100, Math.round(s));
}
