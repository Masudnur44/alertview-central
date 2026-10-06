import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export const runExternalChecks = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data: ok } = await context.supabase.rpc("can_operate", { _user_id: context.userId });
    if (!ok) throw new Error("Your role cannot run checks");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { runChecks } = await import("./monitor.server");
    return runChecks(supabaseAdmin);
  });
