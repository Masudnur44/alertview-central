import { createFileRoute, redirect, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
import { Input } from "@/components/ui/input";
import { AuthCard } from "@/components/soc/AuthCard";
import { Button } from "@/components/ui/button";
import { getAuthConfig, getSession, requestReset, signIn, signUp } from "@/lib/api/auth.functions";

export const Route = createFileRoute("/auth")({
  validateSearch: z.object({ error: z.string().max(300).optional(), mode: z.enum(["in", "up", "forgot"]).optional() }),
  head: () => ({ meta: [{ title: "Sign in — FINPAY SOC" }, { name: "description", content: "Sign in to the FINPAY Security Operations Center." }] }),
  ssr: false,
  beforeLoad: async () => {
    const s = await getSession();
    if (s && !s.needsMfa) throw redirect({ to: s.user.status === "active" ? "/dashboard" : "/pending" });
  },
  loader: () => getAuthConfig(),
  component: AuthPage,
});

function AuthPage() {
  const cfg = Route.useLoaderData();
  const search = Route.useSearch();
  const navigate = useNavigate();
  const [mode, setMode] = useState<"in" | "up" | "forgot">(search.mode ?? "in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(search.error ?? null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      if (mode === "in") {
        const r = await signIn({ data: { email, password } });
        if (r.next === "verify_email") setNotice("Confirm your email address first — check your inbox for the link.");
        else navigate({ to: r.next === "mfa" ? "/auth/mfa" : r.next === "pending" ? "/pending" : "/dashboard", replace: true });
      } else if (mode === "up") {
        const r = await signUp({ data: { name, email, password } });
        setMode("in");
        setPassword("");
        setNotice(r.next === "verify_email"
          ? "Check your email to confirm your address. A security administrator will then approve your access."
          : "Access requested. Sign in to check your status — a security administrator must approve new accounts.");
      } else {
        await requestReset({ data: { email } });
        setMode("in");
        setNotice("If that account exists, a reset link is on its way.");
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Request failed");
    }
    setBusy(false);
  }

  const title = mode === "in" ? "Analyst sign in" : mode === "up" ? "Request access" : "Reset password";
  return (
    <AuthCard title={title} sub={mode === "up" && cfg.domains.length ? `Use your ${cfg.domains.join(" / ")} email address.` : undefined}>
      {notice && <p className="mt-4 rounded border border-primary/30 bg-primary/10 p-3 text-sm">{notice}</p>}
      <form onSubmit={submit} className="mt-6 space-y-3">
        {mode === "up" && <Input placeholder="Full name" required value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />}
        <Input type="email" required placeholder="Work email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
        {mode !== "forgot" && (
          <Input type="password" required minLength={mode === "up" ? 12 : 1} placeholder={mode === "up" ? "Password (12+ characters)" : "Password"}
            value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === "up" ? "new-password" : "current-password"} />
        )}
        <Button className="w-full" disabled={busy}>{mode === "in" ? "Sign in" : mode === "up" ? "Request access" : "Send reset link"}</Button>
      </form>
      {cfg.google && mode !== "forgot" && (
        <Button variant="outline" className="mt-3 w-full" asChild>
          <a href="/api/auth/google/start">Continue with Google</a>
        </Button>
      )}
      <div className="mt-6 flex flex-col gap-2 text-center text-sm text-muted-foreground">
        {mode === "in" && cfg.signup && <button type="button" className="hover:text-foreground" onClick={() => setMode("up")}>No account? Request access</button>}
        {mode === "in" && cfg.passwordReset && <button type="button" className="hover:text-foreground" onClick={() => setMode("forgot")}>Forgot password?</button>}
        {mode !== "in" && <button type="button" className="hover:text-foreground" onClick={() => setMode("in")}>Back to sign in</button>}
      </div>
    </AuthCard>
  );
}
