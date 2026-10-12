// Built-in authentication: password + TOTP 2FA, optional Google sign-in, admin approval.
import { deleteCookie, getCookie, getRequestHeader, getRequestIP, setCookie } from "@tanstack/react-start/server";
import { asSystem, asUser, audit, type Tx } from "./db.server";
import { env, secureCookies, smtpConfigured } from "./env.server";
import {
  decrypt, encrypt, hashPassword, newRecoveryCodes, newTotpSecret, passwordProblems, randomToken, sha256, totpUri,
  verifyPassword, verifyTotp,
} from "./crypto.server";
import { rateLimit } from "./ratelimit.server";
import { sendMail, simpleHtml } from "./mail.server";
import type { Role } from "@/lib/permissions";

export class AuthError extends Error {}

export type SessionUser = {
  id: string;
  email: string;
  displayName: string;
  status: "pending" | "active" | "disabled";
  roles: Role[];
  mfaEnabled: boolean;
};

export type SessionInfo = {
  user: SessionUser;
  sessionId: string;
  mfaPassed: boolean;
  /** Signed in with password but has not entered the 2FA code yet. */
  needsMfa: boolean;
  /** 2FA is mandatory and this user has not set it up yet. */
  mustEnrollMfa: boolean;
};

const LOCK_AFTER = 5;
const LOCK_MINUTES = 15;

export const cookieName = () => (secureCookies() ? "__Host-soc_session" : "soc_session");

export function clientIp(): string | null {
  try {
    return getRequestIP({ xForwardedFor: env().TRUST_PROXY }) ?? null;
  } catch {
    return null;
  }
}

function userAgent(): string | null {
  try {
    return getRequestHeader("user-agent")?.slice(0, 300) ?? null;
  } catch {
    return null;
  }
}

function setSessionCookie(token: string) {
  setCookie(cookieName(), token, {
    httpOnly: true,
    secure: secureCookies(),
    sameSite: "lax",
    path: "/",
    maxAge: env().SESSION_MAX_DAYS * 86400,
  });
}

export function clearSessionCookie() {
  deleteCookie(cookieName(), { path: "/", secure: secureCookies(), httpOnly: true, sameSite: "lax" });
}

export function emailDomainAllowed(email: string): boolean {
  const allowed = env().ALLOWED_EMAIL_DOMAINS;
  if (isBootstrapEmail(email)) return true;
  if (!allowed.length) return true;
  const domain = email.split("@")[1]?.toLowerCase() ?? "";
  return allowed.some((d) => domain === d || domain.endsWith(`.${d}`));
}

function isBootstrapEmail(email: string) {
  const b = env().BOOTSTRAP_ADMIN_EMAIL;
  return Boolean(b && b.toLowerCase() === email.toLowerCase());
}

/** The configured bootstrap address becomes the first Security Administrator. */
async function maybeBootstrapAdmin(tx: Tx, userId: string, email: string): Promise<boolean> {
  if (!isBootstrapEmail(email)) return false;
  const [existing] = await tx`
    select 1 from user_roles r join users u on u.id = r.user_id
    where r.role = 'security_admin' and u.status = 'active' and u.id <> ${userId} limit 1`;
  if (existing) return false;
  await tx`update users set status = 'active', email_verified = true, approved_at = now() where id = ${userId}`;
  await tx`insert into user_roles (user_id, role) values (${userId}, 'security_admin') on conflict do nothing`;
  await audit(tx, "auth.bootstrap_admin", { type: "users", id: userId }, { email });
  return true;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
async function createSession(tx: Tx, userId: string, mfaPassed: boolean): Promise<string> {
  const token = randomToken(32);
  await tx`
    insert into sessions (id, user_id, mfa_passed, ip, user_agent, expires_at)
    values (${sha256(token)}, ${userId}, ${mfaPassed}, ${clientIp()}, ${userAgent()}, now() + make_interval(days => ${env().SESSION_MAX_DAYS}))`;
  return token;
}

export async function currentSession(): Promise<SessionInfo | null> {
  const token = getCookie(cookieName());
  if (!token || token.length > 100) return null;
  const id = sha256(token);
  const idleHours = env().SESSION_IDLE_HOURS;
  const row = await asSystem(async (tx) => {
    const [s] = await tx`
      select s.id, s.user_id, s.mfa_passed, s.last_seen_at, s.expires_at,
             u.email, u.display_name, u.status, u.mfa_enabled,
             coalesce(array_agg(r.role::text) filter (where r.role is not null), '{}') as roles
      from sessions s
      join users u on u.id = s.user_id
      left join user_roles r on r.user_id = u.id
      where s.id = ${id}
        and s.expires_at > now()
        and s.last_seen_at > now() - make_interval(hours => ${idleHours})
      group by s.id, u.id`;
    if (!s) return null;
    if (Date.now() - new Date(s.last_seen_at).getTime() > 5 * 60_000) {
      await tx`update sessions set last_seen_at = now() where id = ${id}`;
    }
    return s;
  });
  if (!row || row.status === "disabled") return null;
  const user: SessionUser = {
    id: row.user_id,
    email: row.email,
    displayName: row.display_name,
    status: row.status,
    roles: row.status === "active" ? (row.roles as Role[]) : [],
    mfaEnabled: row.mfa_enabled,
  };
  return {
    user,
    sessionId: row.id,
    mfaPassed: row.mfa_passed,
    needsMfa: user.mfaEnabled && !row.mfa_passed,
    mustEnrollMfa: env().REQUIRE_MFA && !user.mfaEnabled && user.status === "active",
  };
}

/** Use in every protected server function. */
export async function requireSession(opts: { allowPending?: boolean; allowMfaEnrollment?: boolean } = {}): Promise<SessionInfo> {
  const s = await currentSession();
  if (!s) throw new AuthError("UNAUTHENTICATED");
  if (s.needsMfa) throw new AuthError("MFA_REQUIRED");
  if (s.user.status !== "active" && !opts.allowPending) throw new AuthError("PENDING_APPROVAL");
  if (s.mustEnrollMfa && !opts.allowMfaEnrollment) throw new AuthError("MFA_ENROLLMENT_REQUIRED");
  return s;
}

export async function signOut() {
  const token = getCookie(cookieName());
  if (token) {
    await asSystem(async (tx) => {
      const [s] = await tx`delete from sessions where id = ${sha256(token)} returning user_id`;
      if (s) await tx`insert into audit_log (actor, action, target_type, target_id) values (${s.user_id}, 'auth.sign_out', 'users', ${s.user_id})`;
    });
  }
  clearSessionCookie();
}

// ---------------------------------------------------------------------------
// Password sign-in / sign-up
// ---------------------------------------------------------------------------
export type SignInResult = { next: "dashboard" | "mfa" | "pending" | "verify_email" };
export type SignUpResult = { next: "requested" | "verify_email" };

export async function signInWithPassword(emailRaw: string, password: string): Promise<SignInResult> {
  const email = emailRaw.trim().toLowerCase();
  const ip = clientIp() ?? "unknown";
  if (!rateLimit(`login-ip:${ip}`, 30, 10 * 60_000).ok || !rateLimit(`login-email:${email}`, 10, 10 * 60_000).ok) {
    throw new AuthError("Too many sign-in attempts. Wait a few minutes and try again.");
  }
  // Failures are recorded and committed before the error is raised (a throw inside the
  // transaction would roll back the lockout counter and the audit entry).
  const outcome = await asSystem(async (tx): Promise<SignInResult | { error: string }> => {
    const [u] = await tx`select id, password_hash, status, email_verified, mfa_enabled, locked_until from users where email = ${email}`;
    const ok = await verifyPassword(password, u?.password_hash);
    if (!u || !ok) {
      if (u) {
        await tx`
          update users set failed_logins = failed_logins + 1,
            locked_until = case when failed_logins + 1 >= ${LOCK_AFTER} then now() + make_interval(mins => ${LOCK_MINUTES}) else locked_until end
          where id = ${u.id}`;
        await tx`insert into audit_log (actor, action, target_type, target_id, detail) values (${u.id}, 'auth.sign_in_failed', 'users', ${u.id}, ${tx.json({ reason: "bad_password" })})`;
      }
      return { error: "Incorrect email or password." };
    }
    if (u.locked_until && new Date(u.locked_until).getTime() > Date.now()) {
      return { error: `Account temporarily locked after repeated failures. Try again in ${LOCK_MINUTES} minutes.` };
    }
    if (u.status === "disabled") return { error: "This account has been disabled. Contact your security administrator." };
    if (smtpConfigured() && !u.email_verified) return { next: "verify_email" };

    await tx`update users set failed_logins = 0, locked_until = null, last_login_at = now() where id = ${u.id}`;
    const token = await createSession(tx, u.id, false);
    setSessionCookie(token);
    await tx`insert into audit_log (actor, action, target_type, target_id) values (${u.id}, 'auth.sign_in', 'users', ${u.id})`;
    if (u.mfa_enabled) return { next: "mfa" };
    return { next: u.status === "active" ? "dashboard" : "pending" };
  }, ip);
  if ("error" in outcome) throw new AuthError(outcome.error);
  return outcome;
}

export async function signUpWithPassword(input: { name: string; email: string; password: string }): Promise<SignUpResult> {
  const e = env();
  const email = input.email.trim().toLowerCase();
  if (!e.ALLOW_SIGNUP && !isBootstrapEmail(email)) throw new AuthError("Self sign-up is disabled. Ask an administrator to invite you.");
  if (!emailDomainAllowed(email)) throw new AuthError(`Use your company email address (${e.ALLOWED_EMAIL_DOMAINS.join(", ")}).`);
  const problem = passwordProblems(input.password, email);
  if (problem) throw new AuthError(problem);
  const ip = clientIp() ?? "unknown";
  if (!rateLimit(`signup-ip:${ip}`, 5, 60 * 60_000).ok) throw new AuthError("Too many sign-ups from this network. Try later.");

  const hash = await hashPassword(input.password);
  const result = await asSystem(async (tx) => {
    const [exists] = await tx`select id from users where email = ${email}`;
    // Same response whether or not the address exists, so the form cannot be used to discover accounts.
    if (exists) return { userId: null as string | null, admin: false };
    const [u] = await tx`
      insert into users (email, display_name, password_hash)
      values (${email}, ${input.name.trim().slice(0, 120) || email.split("@")[0]!}, ${hash}) returning id`;
    await tx`insert into audit_log (actor, action, target_type, target_id) values (${u!.id}, 'auth.sign_up', 'users', ${u!.id})`;
    const admin = await maybeBootstrapAdmin(tx, u!.id, email);
    return { userId: u!.id as string, admin };
  }, ip);

  if (smtpConfigured()) {
    if (result.userId && !result.admin) await sendVerification(result.userId, email).catch((err) => console.error("verification email failed", err));
    return { next: result.admin ? "requested" : "verify_email" };
  }
  return { next: "requested" };
}

// ---------------------------------------------------------------------------
// Email verification + password reset
// ---------------------------------------------------------------------------
async function issueToken(tx: Tx, userId: string, purpose: "verify_email" | "reset_password", hours: number) {
  const token = randomToken(32);
  await tx`delete from one_time_tokens where user_id = ${userId} and purpose = ${purpose}`;
  await tx`insert into one_time_tokens (id, user_id, purpose, expires_at) values (${sha256(token)}, ${userId}, ${purpose}, now() + make_interval(hours => ${hours}))`;
  return token;
}

async function sendVerification(userId: string, email: string) {
  const token = await asSystem((tx) => issueToken(tx, userId, "verify_email", 48));
  const link = `${env().APP_URL}/auth/verify?token=${token}`;
  await sendMail({
    to: email,
    subject: `Confirm your ${env().ORG_NAME} SOC account`,
    text: `Confirm your email address: ${link}\n\nAfter confirming, a security administrator must approve your access.`,
    html: simpleHtml("Confirm your email", ["Confirm your email address to continue. A security administrator must then approve your access."], { href: link, label: "Confirm email" }),
  });
}

export async function verifyEmail(token: string): Promise<boolean> {
  return asSystem(async (tx) => {
    const [t] = await tx`
      update one_time_tokens set used_at = now()
      where id = ${sha256(token)} and purpose = 'verify_email' and used_at is null and expires_at > now()
      returning user_id`;
    if (!t) return false;
    const [u] = await tx`update users set email_verified = true where id = ${t.user_id} returning email`;
    await maybeBootstrapAdmin(tx, t.user_id, u!.email);
    await tx`insert into audit_log (actor, action, target_type, target_id) values (${t.user_id}, 'auth.email_verified', 'users', ${t.user_id})`;
    return true;
  });
}

export async function requestPasswordReset(emailRaw: string): Promise<void> {
  const email = emailRaw.trim().toLowerCase();
  if (!rateLimit(`reset:${email}`, 3, 60 * 60_000).ok || !smtpConfigured()) return;
  const found = await asSystem(async (tx) => {
    const [u] = await tx`select id from users where email = ${email} and status <> 'disabled' and password_hash is not null`;
    return u ? { id: u.id as string, token: await issueToken(tx, u.id, "reset_password", 1) } : null;
  });
  if (!found) return;
  const link = `${env().APP_URL}/auth/reset?token=${found.token}`;
  await sendMail({
    to: email,
    subject: "Reset your SOC password",
    text: `Reset your password (valid for 1 hour): ${link}\nIf you did not ask for this, tell your security team.`,
    html: simpleHtml("Reset your password", ["This link is valid for 1 hour. If you did not ask for it, tell your security team."], { href: link, label: "Choose a new password" }),
  });
}

/** Admin-issued reset link, for servers without email configured. */
export async function adminResetLink(tx: Tx, userId: string): Promise<string> {
  const token = await issueToken(tx, userId, "reset_password", 24);
  return `${env().APP_URL}/auth/reset?token=${token}`;
}

export async function resetPassword(token: string, password: string): Promise<void> {
  await asSystem(async (tx) => {
    const [t] = await tx`select user_id from one_time_tokens where id = ${sha256(token)} and purpose = 'reset_password' and used_at is null and expires_at > now()`;
    if (!t) throw new AuthError("This reset link is invalid or has expired.");
    const [u] = await tx`select email from users where id = ${t.user_id}`;
    const problem = passwordProblems(password, u!.email);
    if (problem) throw new AuthError(problem);
    await tx`update one_time_tokens set used_at = now() where id = ${sha256(token)}`;
    await tx`update users set password_hash = ${await hashPassword(password)}, failed_logins = 0, locked_until = null, email_verified = true where id = ${t.user_id}`;
    await tx`delete from sessions where user_id = ${t.user_id}`;
    await tx`insert into audit_log (actor, action, target_type, target_id) values (${t.user_id}, 'auth.password_reset', 'users', ${t.user_id})`;
  });
}

export async function changePassword(session: SessionInfo, current: string, next: string): Promise<void> {
  await asSystem(async (tx) => {
    const [u] = await tx`select password_hash, email from users where id = ${session.user.id}`;
    if (u!.password_hash && !(await verifyPassword(current, u!.password_hash))) throw new AuthError("Current password is incorrect.");
    const problem = passwordProblems(next, u!.email);
    if (problem) throw new AuthError(problem);
    await tx`update users set password_hash = ${await hashPassword(next)} where id = ${session.user.id}`;
    await tx`delete from sessions where user_id = ${session.user.id} and id <> ${session.sessionId}`;
    await tx`insert into audit_log (actor, action, target_type, target_id) values (${session.user.id}, 'auth.password_changed', 'users', ${session.user.id})`;
  });
}

// ---------------------------------------------------------------------------
// TOTP two-factor
// ---------------------------------------------------------------------------
export async function verifyMfaCode(code: string): Promise<void> {
  const s = await currentSession();
  if (!s) throw new AuthError("UNAUTHENTICATED");
  if (!rateLimit(`mfa:${s.user.id}`, 8, 10 * 60_000).ok) throw new AuthError("Too many attempts. Wait 10 minutes.");
  const failed = await asSystem(async (tx): Promise<string | null> => {
    const [u] = await tx`select mfa_secret, mfa_last_step, mfa_recovery_codes from users where id = ${s.user.id}`;
    if (!u?.mfa_secret) return "Two-factor is not set up for this account.";
    const secret = decrypt(u.mfa_secret, env().APP_SECRET, "totp");
    const step = verifyTotp(secret, code, u.mfa_last_step == null ? null : Number(u.mfa_last_step));
    if (step != null) {
      await tx`update users set mfa_last_step = ${step} where id = ${s.user.id}`;
    } else {
      const hashed = sha256(code.trim().toLowerCase());
      if (!(u.mfa_recovery_codes as string[]).includes(hashed)) {
        await tx`insert into audit_log (actor, action, target_type, target_id) values (${s.user.id}, 'auth.mfa_failed', 'users', ${s.user.id})`;
        return "That code is not valid.";
      }
      await tx`update users set mfa_recovery_codes = array_remove(mfa_recovery_codes, ${hashed}) where id = ${s.user.id}`;
      await tx`insert into audit_log (actor, action, target_type, target_id) values (${s.user.id}, 'auth.recovery_code_used', 'users', ${s.user.id})`;
    }
    // Rotate the session id once the second factor passes.
    await tx`delete from sessions where id = ${s.sessionId}`;
    setSessionCookie(await createSession(tx, s.user.id, true));
    await tx`insert into audit_log (actor, action, target_type, target_id) values (${s.user.id}, 'auth.mfa_passed', 'users', ${s.user.id})`;
    return null;
  });
  if (failed) throw new AuthError(failed);
}

export async function beginMfaEnrollment(s: SessionInfo): Promise<{ secret: string; uri: string }> {
  if (s.user.mfaEnabled) throw new AuthError("Two-factor is already enabled.");
  const secret = newTotpSecret();
  await asSystem((tx) => tx`update users set mfa_secret = ${encrypt(secret, env().APP_SECRET, "totp")}, mfa_last_step = null where id = ${s.user.id} and not mfa_enabled`);
  return { secret, uri: totpUri(secret, s.user.email, `${env().ORG_NAME} SOC`) };
}

export async function confirmMfaEnrollment(s: SessionInfo, code: string): Promise<string[]> {
  return asSystem(async (tx) => {
    const [u] = await tx`select mfa_secret, mfa_enabled from users where id = ${s.user.id}`;
    if (!u?.mfa_secret || u.mfa_enabled) throw new AuthError("Start two-factor setup again.");
    const step = verifyTotp(decrypt(u.mfa_secret, env().APP_SECRET, "totp"), code, null);
    if (step == null) throw new AuthError("That code is not valid. Check the time on your phone and try again.");
    const codes = newRecoveryCodes();
    await tx`update users set mfa_enabled = true, mfa_last_step = ${step}, mfa_recovery_codes = ${codes.map((c) => sha256(c))} where id = ${s.user.id}`;
    await tx`update sessions set mfa_passed = true where id = ${s.sessionId}`;
    await tx`delete from sessions where user_id = ${s.user.id} and id <> ${s.sessionId}`;
    await tx`insert into audit_log (actor, action, target_type, target_id) values (${s.user.id}, 'auth.mfa_enabled', 'users', ${s.user.id})`;
    return codes;
  });
}

export async function disableMfa(s: SessionInfo, password: string): Promise<void> {
  if (env().REQUIRE_MFA) throw new AuthError("Two-factor is mandatory on this platform.");
  await asSystem(async (tx) => {
    const [u] = await tx`select password_hash from users where id = ${s.user.id}`;
    if (!(await verifyPassword(password, u?.password_hash))) throw new AuthError("Password is incorrect.");
    await tx`update users set mfa_enabled = false, mfa_secret = null, mfa_recovery_codes = '{}' where id = ${s.user.id}`;
    await tx`insert into audit_log (actor, action, target_type, target_id) values (${s.user.id}, 'auth.mfa_disabled', 'users', ${s.user.id})`;
  });
}

// ---------------------------------------------------------------------------
// Google sign-in (OpenID Connect, authorization code + PKCE)
// ---------------------------------------------------------------------------
export function googleRedirectUri() {
  return `${env().APP_URL}/api/auth/google/callback`;
}

/** Called after the callback route has exchanged the code and validated the ID token. */
export async function signInWithGoogleIdentity(claims: { sub: string; email: string; name?: string; email_verified?: boolean }, ip: string | null) {
  const email = claims.email.toLowerCase();
  if (!claims.email_verified) throw new AuthError("Your Google email address is not verified.");
  if (!emailDomainAllowed(email)) throw new AuthError(`Use your company Google account (${env().ALLOWED_EMAIL_DOMAINS.join(", ")}).`);
  return asSystem(async (tx) => {
    let [u] = await tx`select id, status, mfa_enabled, google_sub from users where google_sub = ${claims.sub} or email = ${email} order by (google_sub = ${claims.sub}) desc limit 1`;
    if (u && u.google_sub && u.google_sub !== claims.sub) throw new AuthError("This email is linked to a different Google account.");
    if (!u) {
      if (!env().ALLOW_SIGNUP && !isBootstrapEmail(email)) throw new AuthError("Self sign-up is disabled. Ask an administrator to invite you.");
      [u] = await tx`
        insert into users (email, display_name, google_sub, email_verified)
        values (${email}, ${(claims.name ?? email.split("@")[0]!).slice(0, 120)}, ${claims.sub}, true)
        returning id, status, mfa_enabled`;
      await tx`insert into audit_log (actor, action, target_type, target_id, detail) values (${u!.id}, 'auth.sign_up', 'users', ${u!.id}, ${tx.json({ via: "google" })})`;
      if (await maybeBootstrapAdmin(tx, u!.id, email)) u!.status = "active";
    } else if (!u.google_sub) {
      await tx`update users set google_sub = ${claims.sub}, email_verified = true where id = ${u.id}`;
    }
    if (u!.status === "disabled") throw new AuthError("This account has been disabled.");
    await tx`update users set last_login_at = now(), failed_logins = 0 where id = ${u!.id}`;
    const token = await createSession(tx, u!.id, false);
    await tx`insert into audit_log (actor, action, target_type, target_id, detail) values (${u!.id}, 'auth.sign_in', 'users', ${u!.id}, ${tx.json({ via: "google" })})`;
    return { token, next: u!.mfa_enabled ? "mfa" : u!.status === "active" ? "dashboard" : "pending" };
  }, ip);
}

export function sessionCookieHeader(token: string): string {
  const parts = [`${cookieName()}=${token}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${env().SESSION_MAX_DAYS * 86400}`];
  if (secureCookies()) parts.push("Secure");
  return parts.join("; ");
}

/** Convenience for server functions: run a callback as the signed-in user. */
export function withUser<T>(s: SessionInfo, fn: (tx: Tx) => Promise<T>) {
  return asUser({ userId: s.user.id, ip: clientIp() }, fn);
}
