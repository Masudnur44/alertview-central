import { createFileRoute } from "@tanstack/react-router";
import { authenticateCronRequest } from "@/integrations/supabase/cron-auth";

export const Route = createFileRoute("/api/public/checks")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const provided = request.headers.get("x-scheduler-token");
        let allowed = false;
        if (provided && provided.length >= 32) {
          const { data } = await supabaseAdmin.from("scheduler_token").select("token").eq("id", 1).maybeSingle();
          allowed = !!data && data.token === provided;
        }
        if (!allowed) {
          const denied = await authenticateCronRequest(request);
          if (denied) return denied;
        }
        const { runChecks } = await import("@/lib/monitor.server");
        return Response.json(await runChecks(supabaseAdmin));
      },
    },
  },
});
