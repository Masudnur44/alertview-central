import { createFileRoute } from "@tanstack/react-router";

// Liveness/readiness for Docker and uptime monitors. Reveals no data.
export const Route = createFileRoute("/api/health")({
  server: {
    handlers: {
      GET: async () => {
        const { asSystem } = await import("@/server/db.server");
        try {
          const [row] = await asSystem((tx) => tx`select now() as now, (select value from settings where key = 'worker_heartbeat') as hb`);
          const hb = row?.hb ? new Date(String(row.hb)).getTime() : 0;
          const workerOk = Date.now() - hb < 10 * 60_000;
          return Response.json({ ok: true, db: "ok", worker: workerOk ? "ok" : "stale" }, { headers: { "cache-control": "no-store" } });
        } catch {
          return Response.json({ ok: false, db: "unreachable" }, { status: 503 });
        }
      },
    },
  },
});
