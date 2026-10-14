import { createFileRoute, redirect } from "@tanstack/react-router";

// The SOC is an internal tool: no public marketing page. Send visitors to the console
// (which itself redirects to sign-in when needed).
export const Route = createFileRoute("/")({
  beforeLoad: () => {
    throw redirect({ to: "/command" });
  },
});
