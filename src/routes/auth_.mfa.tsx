import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { getSession, signOut, verifyMfa } from "@/lib/api/auth.functions";
import { AuthCard } from "@/components/soc/AuthCard";

export const Route = createFileRoute("/auth_/mfa")({
  head: () => ({ meta: [{ title: "Two-factor — FINPAY SOC" }] }),
  ssr: false,
  beforeLoad: async () => {
    const s = await getSession();
    if (!s) throw redirect({ to: "/auth" });
    if (!s.needsMfa) throw redirect({ to: "/dashboard" });
  },
  component: Mfa,
});

function Mfa() {
  const navigate = useNavigate();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [recovery, setRecovery] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await verifyMfa({ data: { code } });
      navigate({ to: "/dashboard", replace: true });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Invalid code");
      setCode("");
    }
    setBusy(false);
  }

  return (
    <AuthCard title="Two-factor verification" sub={recovery ? "Enter one of your saved recovery codes." : "Enter the 6-digit code from your authenticator app."}>
      <form onSubmit={submit} className="mt-6 space-y-3">
        <Input autoFocus required value={code} onChange={(e) => setCode(e.target.value)}
          inputMode={recovery ? "text" : "numeric"} autoComplete="one-time-code" maxLength={recovery ? 11 : 6}
          placeholder={recovery ? "xxxxx-xxxxx" : "123456"} className="data text-center text-lg tracking-[0.4em]" />
        <Button className="w-full" disabled={busy || code.length < 6}>Verify</Button>
      </form>
      <div className="mt-6 flex justify-between text-sm text-muted-foreground">
        <button type="button" className="hover:text-foreground" onClick={() => { setRecovery(!recovery); setCode(""); }}>
          {recovery ? "Use authenticator code" : "Use a recovery code"}
        </button>
        <button type="button" className="hover:text-foreground" onClick={async () => { await signOut(); navigate({ to: "/auth" }); }}>Cancel</button>
      </div>
    </AuthCard>
  );
}
