import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { PageHeader, Panel, ago } from "@/components/soc/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { beginMfa, changePassword, confirmMfa, disableMfa, mySessions, revokeSession, updateProfile } from "@/lib/api/auth.functions";
import { useMe } from "@/lib/session";
import { roleLabel } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/account")({
  validateSearch: z.object({ setup: z.enum(["mfa"]).optional() }),
  head: () => ({ meta: [{ title: "Account — FINPAY SOC" }] }),
  component: Account,
});

function Account() {
  const me = useMe();
  const { setup } = Route.useSearch();
  return (
    <div className="max-w-3xl space-y-6">
      <PageHeader title="Your account" sub={`${me.email} · ${me.roles.map(roleLabel).join(", ")}`} />
      {setup === "mfa" && !me.mfaEnabled && (
        <div className="flex items-start gap-3 rounded-lg border border-sev-high/40 bg-sev-high/10 p-4 text-sm">
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-sev-high" />
          <p>Two-factor authentication is required on this platform. Set it up below to continue to the SOC.</p>
        </div>
      )}
      <MfaPanel />
      <ProfilePanel />
      <PasswordPanel />
      <SessionsPanel />
    </div>
  );
}

function MfaPanel() {
  const me = useMe();
  const router = useRouter();
  const [enroll, setEnroll] = useState<{ secret: string; svg: string } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [pw, setPw] = useState("");
  const start = useMutation({ mutationFn: () => beginMfa(), onSuccess: (r) => setEnroll(r) });
  const confirm = useMutation({
    mutationFn: () => confirmMfa({ data: { code } }),
    onSuccess: (r) => { setCodes(r.recoveryCodes); setEnroll(null); toast.success("Two-factor enabled"); },
  });
  const disable = useMutation({ mutationFn: () => disableMfa({ data: { password: pw } }), onSuccess: () => { toast.success("Two-factor disabled"); router.invalidate(); } });

  if (codes) {
    return (
      <Panel title="Save your recovery codes">
        <p className="text-sm text-muted-foreground">Each code works once if you lose your phone. Store them in your password manager — they will not be shown again.</p>
        <pre className="data mt-3 grid grid-cols-2 gap-1 rounded bg-muted p-3 text-sm">{codes.map((c) => <span key={c}>{c}</span>)}</pre>
        <div className="mt-3 flex gap-2">
          <Button variant="outline" onClick={() => { navigator.clipboard.writeText(codes.join("\n")); toast.success("Copied"); }}>Copy</Button>
          <Button onClick={() => { setCodes(null); router.invalidate(); router.navigate({ to: "/dashboard" }); }}>I saved them — continue</Button>
        </div>
      </Panel>
    );
  }

  return (
    <Panel title="Two-factor authentication">
      {me.mfaEnabled ? (
        <div className="space-y-3">
          <p className="flex items-center gap-2 text-sm text-ok"><ShieldCheck className="h-4 w-4" /> Enabled — an authenticator code is required at every sign-in.</p>
          <details className="text-sm text-muted-foreground">
            <summary className="cursor-pointer">Turn off two-factor</summary>
            <div className="mt-2 flex gap-2">
              <Input type="password" placeholder="Current password" value={pw} onChange={(e) => setPw(e.target.value)} className="max-w-xs" />
              <Button variant="outline" onClick={() => disable.mutate()} disabled={!pw || disable.isPending}>Disable</Button>
            </div>
          </details>
        </div>
      ) : enroll ? (
        <div className="grid gap-4 sm:grid-cols-[180px_1fr]">
          {/* QR is generated server-side from our own data; safe to inline. */}
          <div className="rounded bg-white p-2" dangerouslySetInnerHTML={{ __html: enroll.svg }} />
          <div className="space-y-3 text-sm">
            <p>Scan with Google Authenticator, Microsoft Authenticator, 1Password or similar. Or enter this key manually:</p>
            <code className="data block break-all rounded bg-muted p-2 text-xs">{enroll.secret.match(/.{1,4}/g)?.join(" ")}</code>
            <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); confirm.mutate(); }}>
              <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} className="data max-w-40 tracking-widest" />
              <Button disabled={code.length !== 6 || confirm.isPending}>Verify & enable</Button>
            </form>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">Protect your account with an authenticator app. Strongly recommended for everyone with SOC access.</p>
          <Button onClick={() => start.mutate()} disabled={start.isPending}>Set up two-factor</Button>
        </div>
      )}
    </Panel>
  );
}

function ProfilePanel() {
  const me = useMe();
  const router = useRouter();
  const [name, setName] = useState(me.displayName);
  const save = useMutation({ mutationFn: () => updateProfile({ data: { displayName: name } }), onSuccess: () => { toast.success("Saved"); router.invalidate(); } });
  return (
    <Panel title="Profile">
      <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <Input value={name} onChange={(e) => setName(e.target.value)} className="max-w-sm" />
        <Button variant="outline" disabled={!name.trim() || name === me.displayName}>Save name</Button>
      </form>
    </Panel>
  );
}

function PasswordPanel() {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const save = useMutation({
    mutationFn: () => changePassword({ data: { current: cur, next } }),
    onSuccess: () => { toast.success("Password changed. Other sessions were signed out."); setCur(""); setNext(""); },
  });
  return (
    <Panel title="Password">
      <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <Input type="password" placeholder="Current password" value={cur} onChange={(e) => setCur(e.target.value)} className="max-w-56" autoComplete="current-password" />
        <Input type="password" placeholder="New password (12+)" minLength={12} value={next} onChange={(e) => setNext(e.target.value)} className="max-w-56" autoComplete="new-password" />
        <Button variant="outline" disabled={next.length < 12 || save.isPending}>Change password</Button>
      </form>
      <p className="mt-2 text-xs text-muted-foreground">Signed in with Google only? Leave “current password” empty to set one.</p>
    </Panel>
  );
}

function SessionsPanel() {
  const qc = useQueryClient();
  const { data = [] } = useQuery({ queryKey: ["my-sessions"], queryFn: () => mySessions() });
  const revoke = useMutation({ mutationFn: (handle: string) => revokeSession({ data: { handle } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["my-sessions"] }) });
  return (
    <Panel title="Active sessions">
      <ul className="divide-y text-sm">
        {data.map((s) => (
          <li key={s.handle} className="flex flex-wrap items-center gap-3 py-2">
            <span className="data w-32 text-xs">{s.ip ?? "unknown IP"}</span>
            <span className="flex-1 truncate text-xs text-muted-foreground" title={s.user_agent ?? ""}>{s.user_agent ?? "unknown device"}</span>
            <span className="data text-xs text-muted-foreground">active {ago(s.last_seen_at)}</span>
            {s.current ? <span className="data text-xs text-ok">this device</span> : <Button size="sm" variant="ghost" onClick={() => revoke.mutate(s.handle)}>Sign out</Button>}
          </li>
        ))}
      </ul>
    </Panel>
  );
}
