import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/auth/google/start")({
  server: {
    handlers: {
      GET: async () => {
        const { googleStart } = await import("@/server/google.server");
        return googleStart();
      },
    },
  },
});
