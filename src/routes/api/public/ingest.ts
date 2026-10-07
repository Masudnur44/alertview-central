import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

const Event = z.object({
  event_type: z.string().min(1).max(64),
  host: z.string().max(255).optional().nullable(),
  username: z.string().max(128).optional().nullable(),
  src_ip: z.string().max(64).optional().nullable(),
  outcome: z.enum(["success", "failure", "unknown"]).optional().nullable(),
  message: z.string().max(4000).optional().nullable(),
  occurred_at: z.string().datetime().optional(),
  raw: z.record(z.string(), z.unknown()).optional(),
});
const Body = z.union([Event, z.object({ events: z.array(Event).min(1).max(500) })]);

export const Route = createFileRoute("/api/public/ingest")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const key = request.headers.get("x-soc-key");
        if (!key || key.length < 20) return new Response("Unauthorized", { status: 401 });
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { data: src } = await supabaseAdmin.from("event_sources").select("id").eq("api_key", key).maybeSingle();
        if (!src) return new Response("Unauthorized", { status: 401 });
        let parsed;
        try { parsed = Body.parse(await request.json()); } catch { return new Response("Invalid payload", { status: 400 }); }
        const events = "events" in parsed ? parsed.events : [parsed];
        const rows = events.map((e) => ({
          event_type: e.event_type, host: e.host ?? null, username: e.username ?? null, src_ip: e.src_ip ?? null,
          outcome: e.outcome ?? null, message: e.message ?? null, raw: (e.raw ?? null) as never,
          source_id: src.id, occurred_at: e.occurred_at ?? new Date().toISOString(),
        }));
        const { error } = await supabaseAdmin.from("events").insert(rows);
        if (error) return new Response("Storage error", { status: 500 });
        await supabaseAdmin.from("event_sources").update({ last_event_at: new Date().toISOString() }).eq("id", src.id);
        const { detect } = await import("@/lib/monitor.server");
        const alerts = await detect(supabaseAdmin, rows);
        return Response.json({ accepted: rows.length, alerts });
      },
    },
  },
});
