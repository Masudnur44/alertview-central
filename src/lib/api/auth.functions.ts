// Sign-in, sign-up, two-factor and account server functions.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const email = z.string().trim().email().max(254);
const password = z.string().min(1).max(256);

export type ClientSession = {
  user: { id: string; email: string; displayName: string; status: string; roles: string[]; mfaEnabled: boolean };
  needsMfa: boolean;
  mustEnrollMfa: boolean;
} | null;

export const getSession = createServerFn({ method: "GET" }).handler(async (): Promise<ClientSession> => {
  const { currentSession } = await import("@/server/auth.server");
  const s = await currentSession();
  if (!s) return null;
  return { user: s.user, needsMfa: s.needsMfa, mustEnrollMfa: s.mustEnrollMfa };
});

export const getAuthConfig = createServerFn({ method: "GET" }).handler(async () => {
  const { env, googleConfigured, smtpConfigured } = await import("@/server/env.server");
  const e = env();
  return {
    google: googleConfigured(),
    signup: e.ALLOW_SIGNUP,
    passwordReset: smtpConfigured(),
    domains: e.ALLOWED_EMAIL_DOMAINS,
    requireMfa: e.REQUIRE_MFA,
    org: e.ORG_NAME,
  };
});

export const signIn = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ email, password }).parse(d))
  .handler(async ({ data }) => {
    const { signInWithPassword } = await import("@/server/auth.server");
    return signInWithPassword(data.email, data.password);
  });

export const signUp = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ name: z.string().trim().min(1).max(120), email, password }).parse(d))
  .handler(async ({ data }) => {
    const { signUpWithPassword } = await import("@/server/auth.server");
    return signUpWithPassword(data);
  });

export const signOut = createServerFn({ method: "POST" }).handler(async () => {
  const { signOut } = await import("@/server/auth.server");
  await signOut();
  return { ok: true };
});

export const verifyMfa = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ code: z.string().trim().min(6).max(20) }).parse(d))
  .handler(async ({ data }) => {
    const { verifyMfaCode } = await import("@/server/auth.server");
    await verifyMfaCode(data.code);
    return { ok: true };
  });

export const requestReset = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ email }).parse(d))
  .handler(async ({ data }) => {
    const { requestPasswordReset } = await import("@/server/auth.server");
    await requestPasswordReset(data.email);
    return { ok: true };
  });

export const resetPassword = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ token: z.string().min(20).max(100), password }).parse(d))
  .handler(async ({ data }) => {
    const { resetPassword } = await import("@/server/auth.server");
    await resetPassword(data.token, data.password);
    return { ok: true };
  });

export const verifyEmail = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ token: z.string().min(20).max(100) }).parse(d))
  .handler(async ({ data }) => {
    const { verifyEmail } = await import("@/server/auth.server");
    return { ok: await verifyEmail(data.token) };
  });

// ---------------------------------------------------------------------------
// Account (signed-in user)
// ---------------------------------------------------------------------------
export const beginMfa = createServerFn({ method: "POST" }).handler(async () => {
  const { requireSession, beginMfaEnrollment } = await import("@/server/auth.server");
  const s = await requireSession({ allowMfaEnrollment: true });
  const { secret, uri } = await beginMfaEnrollment(s);
  const QRCode = await import("qrcode");
  const svg = await QRCode.toString(uri, { type: "svg", margin: 1, color: { dark: "#000000", light: "#ffffff" } });
  return { secret, uri, svg };
});

export const confirmMfa = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ code: z.string().trim().length(6) }).parse(d))
  .handler(async ({ data }) => {
    const { requireSession, confirmMfaEnrollment } = await import("@/server/auth.server");
    const s = await requireSession({ allowMfaEnrollment: true });
    return { recoveryCodes: await confirmMfaEnrollment(s, data.code) };
  });

export const disableMfa = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ password }).parse(d))
  .handler(async ({ data }) => {
    const { requireSession, disableMfa } = await import("@/server/auth.server");
    await disableMfa(await requireSession(), data.password);
    return { ok: true };
  });

export const changePassword = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ current: z.string().max(256), next: password }).parse(d))
  .handler(async ({ data }) => {
    const { requireSession, changePassword } = await import("@/server/auth.server");
    await changePassword(await requireSession({ allowMfaEnrollment: true }), data.current, data.next);
    return { ok: true };
  });

export const mySessions = createServerFn({ method: "GET" }).handler(async () => {
  const { requireSession } = await import("@/server/auth.server");
  const { asSystem } = await import("@/server/db.server");
  const { plain } = await import("@/server/api.server");
  const s = await requireSession({ allowMfaEnrollment: true });
  const rows = await asSystem((tx) => tx`
    select id, ip, user_agent, created_at, last_seen_at, (id = ${s.sessionId}) as current
    from sessions where user_id = ${s.user.id} and expires_at > now() order by last_seen_at desc`);
  // Never send session hashes to the browser; use a short handle instead.
  return plain(rows.map((r) => ({ handle: String(r.id).slice(0, 16), ip: r.ip, user_agent: r.user_agent, created_at: r.created_at, last_seen_at: r.last_seen_at, current: r.current })));
});

export const revokeSession = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ handle: z.string().length(16).regex(/^[0-9a-f]+$/) }).parse(d))
  .handler(async ({ data }) => {
    const { requireSession } = await import("@/server/auth.server");
    const { asSystem } = await import("@/server/db.server");
    const s = await requireSession({ allowMfaEnrollment: true });
    await asSystem(async (tx) => {
      await tx`delete from sessions where user_id = ${s.user.id} and id like ${data.handle + "%"} and id <> ${s.sessionId}`;
      await tx`insert into audit_log (actor, action, target_type, target_id) values (${s.user.id}, 'auth.session_revoked', 'users', ${s.user.id})`;
    });
    return { ok: true };
  });

export const updateProfile = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ displayName: z.string().trim().min(1).max(120) }).parse(d))
  .handler(async ({ data }) => {
    const { requireSession, withUser } = await import("@/server/auth.server");
    const s = await requireSession({ allowMfaEnrollment: true });
    await withUser(s, (tx) => tx`update users set display_name = ${data.displayName} where id = ${s.user.id}`);
    return { ok: true };
  });
