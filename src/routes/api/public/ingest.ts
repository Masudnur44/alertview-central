import { createFileRoute } from "@tanstack/react-router";

// Event intake for agents, log forwarders and applications.
//   POST /api/public/ingest   header: x-soc-key: <source key>
//   body: one event, or {"events": [...]} (max 500, max 1 MB)
export const Route = createFileRoute("/api/public/ingest")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleIngest } = await import("@/server/ingest.server");
        return handleIngest(request);
      },
    },
  },
});
