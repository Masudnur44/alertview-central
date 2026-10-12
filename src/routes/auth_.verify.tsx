import { createFileRoute, Link } from "@tanstack/react-router";
import { z } from "zod";
import { verifyEmail } from "@/lib/api/auth.functions";
import { AuthCard } from "@/components/soc/AuthCard";

export const Route = createFileRoute("/auth_/verify")({
  validateSearch: z.object({ token: z.string().max(100).default("") }),
  head: () => ({ meta: [{ title: "Confirm email — FINPAY SOC" }, { name: "referrer", content: "no-referrer" }] }),
  ssr: false,
  loaderDeps: ({ search }) => ({ token: search.token }),
  loader: async ({ deps }) => (deps.token ? verifyEmail({ data: { token: deps.token } }) : { ok: false }),
  component: Verify,
});

function Verify() {
  const { ok } = Route.useLoaderData();
  return (
    <AuthCard title={ok ? "Email confirmed" : "Link not valid"}
      sub={ok ? "Thanks. A security administrator will approve your access; you can sign in to check your status." : "This confirmation link is invalid or has expired. Sign in to request a new one."}>
      <Link to="/auth" className="mt-6 inline-block text-sm text-primary">Go to sign in →</Link>
    </AuthCard>
  );
}
