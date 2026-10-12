import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/auth/google/callback")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { googleCallback } = await import("@/server/google.server");
        const { clientIp } = await import("@/server/auth.server");
        return googleCallback(request, clientIp());
      },
    },
  },
});
