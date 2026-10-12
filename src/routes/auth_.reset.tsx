import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { resetPassword } from "@/lib/api/auth.functions";
import { AuthCard } from "@/components/soc/AuthCard";

export const Route = createFileRoute("/auth_/reset")({
  validateSearch: z.object({ token: z.string().max(100).default("") }),
  head: () => ({ meta: [{ title: "Choose a new password — FINPAY SOC" }, { name: "referrer", content: "no-referrer" }] }),
  ssr: false,
  component: Reset,
});

function Reset() {
  const { token } = Route.useSearch();
  const navigate = useNavigate();
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (pw !== pw2) return toast.error("Passwords do not match");
    setBusy(true);
    try {
      await resetPassword({ data: { token, password: pw } });
      toast.success("Password changed. Sign in with your new password.");
      navigate({ to: "/auth", replace: true });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Reset failed");
    }
    setBusy(false);
  }
  return (
    <AuthCard title="Choose a new password" sub="At least 12 characters, mixing upper/lower case, digits or symbols.">
      <form onSubmit={submit} className="mt-6 space-y-3">
        <Input type="password" required minLength={12} placeholder="New password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" />
        <Input type="password" required minLength={12} placeholder="Repeat new password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" />
        <Button className="w-full" disabled={busy || !token}>Set password</Button>
      </form>
    </AuthCard>
  );
}
