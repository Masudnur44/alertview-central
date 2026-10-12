import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router";
import { Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getSession, signOut } from "@/lib/api/auth.functions";
import { AuthCard } from "@/components/soc/AuthCard";

export const Route = createFileRoute("/pending")({
  head: () => ({ meta: [{ title: "Awaiting approval — FINPAY SOC" }] }),
  ssr: false,
  beforeLoad: async () => {
    const s = await getSession();
    if (!s) throw redirect({ to: "/auth" });
    if (s.needsMfa) throw redirect({ to: "/auth/mfa" });
    if (s.user.status === "active") throw redirect({ to: "/dashboard" });
    return { session: s };
  },
  component: Pending,
});

function Pending() {
  const { session } = Route.useRouteContext();
  const navigate = useNavigate();
  const disabled = session.user.status === "disabled";
  return (
    <AuthCard title={disabled ? "Access disabled" : "Awaiting approval"}
      sub={disabled ? "Your account has been disabled. Contact your security administrator." : `Signed in as ${session.user.email}. A Security Administrator must approve your account and assign a role before you can see SOC data.`}>
      <div className="mt-6 flex items-center gap-2 rounded border p-3 text-xs text-muted-foreground">
        <Clock className="h-4 w-4 text-primary" /> Approval requests appear under Settings → Team for administrators.
      </div>
      <div className="mt-6 flex gap-2">
        <Button variant="outline" onClick={() => window.location.reload()}>Check again</Button>
        <Button variant="ghost" onClick={async () => { await signOut(); navigate({ to: "/auth" }); }}>Sign out</Button>
      </div>
    </AuthCard>
  );
}
