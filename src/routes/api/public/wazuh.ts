import { createFileRoute } from "@tanstack/react-router";

// Wazuh manager integration (see agents/wazuh/custom-finpay-soc.py).
export const Route = createFileRoute("/api/public/wazuh")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleWazuh } = await import("@/server/ingest.server");
        return handleWazuh(request);
      },
    },
  },
});
