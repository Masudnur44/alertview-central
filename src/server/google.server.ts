// Google sign-in (OpenID Connect authorization-code flow with PKCE, state and nonce).
import { createHash } from "node:crypto";
import { env } from "./env.server";
import { randomToken, sign, unsign } from "./crypto.server";
import { AuthError, googleRedirectUri, sessionCookieHeader, signInWithGoogleIdentity } from "./auth.server";

const COOKIE = "soc_oauth";

function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}

function stateCookie(value: string, maxAge: number) {
  const secure = env().APP_URL.startsWith("https://") ? "; Secure" : "";
  return `${COOKIE}=${encodeURIComponent(value)}; Path=/api/auth/google; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function redirect(location: string, cookies: string[] = []) {
  const headers = new Headers({ location, "cache-control": "no-store" });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 302, headers });
}

export function googleStart(): Response {
  const e = env();
  if (!e.GOOGLE_CLIENT_ID || !e.GOOGLE_CLIENT_SECRET) return redirect("/auth?error=" + encodeURIComponent("Google sign-in is not configured."));
  const state = randomToken(24);
  const nonce = randomToken(24);
  const verifier = randomToken(48);
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const params = new URLSearchParams({
    client_id: e.GOOGLE_CLIENT_ID,
    redirect_uri: googleRedirectUri(),
    response_type: "code",
    scope: "openid email profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  });
  if (e.ALLOWED_EMAIL_DOMAINS.length === 1) params.set("hd", e.ALLOWED_EMAIL_DOMAINS[0]!);
  const payload = Buffer.from(JSON.stringify({ state, nonce, verifier, exp: Date.now() + 600_000 })).toString("base64url");
  return redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, [stateCookie(sign(payload, e.APP_SECRET), 600)]);
}

export async function googleCallback(request: Request, ip: string | null): Promise<Response> {
  const e = env();
  const clear = stateCookie("", 0);
  const fail = (msg: string) => redirect(`/auth?error=${encodeURIComponent(msg)}`, [clear]);
  try {
    const url = new URL(request.url);
    if (url.searchParams.get("error")) return fail("Google sign-in was cancelled.");
    const raw = readCookie(request, COOKIE);
    const payload = raw ? unsign(raw, e.APP_SECRET) : null;
    if (!payload) return fail("Sign-in session expired. Try again.");
    const st = JSON.parse(Buffer.from(payload, "base64url").toString()) as { state: string; nonce: string; verifier: string; exp: number };
    if (st.exp < Date.now() || st.state !== url.searchParams.get("state")) return fail("Sign-in session expired. Try again.");
    const code = url.searchParams.get("code");
    if (!code) return fail("Google did not return an authorization code.");

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code, client_id: e.GOOGLE_CLIENT_ID!, client_secret: e.GOOGLE_CLIENT_SECRET!, redirect_uri: googleRedirectUri(),
        grant_type: "authorization_code", code_verifier: st.verifier,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!tokenRes.ok) return fail("Google rejected the sign-in.");
    const { id_token } = (await tokenRes.json()) as { id_token?: string };
    if (!id_token) return fail("Google did not return an identity token.");

    // The ID token came straight from Google's token endpoint over TLS, so per OpenID
    // Connect Core §3.1.3.7 its claims are validated without re-checking the signature.
    const claims = JSON.parse(Buffer.from(id_token.split(".")[1] ?? "", "base64url").toString()) as {
      iss?: string; aud?: string; exp?: number; nonce?: string; sub?: string; email?: string; email_verified?: boolean; name?: string; hd?: string;
    };
    if (!["accounts.google.com", "https://accounts.google.com"].includes(claims.iss ?? "")) return fail("Unexpected token issuer.");
    if (claims.aud !== e.GOOGLE_CLIENT_ID || !claims.exp || claims.exp * 1000 < Date.now() || claims.nonce !== st.nonce) return fail("Invalid identity token.");
    if (!claims.sub || !claims.email) return fail("Google did not share an email address.");

    const result = await signInWithGoogleIdentity({ sub: claims.sub, email: claims.email, name: claims.name, email_verified: claims.email_verified }, ip);
    const next = result.next === "mfa" ? "/auth/mfa" : result.next === "pending" ? "/pending" : "/dashboard";
    return redirect(next, [clear, sessionCookieHeader(result.token)]);
  } catch (err) {
    if (err instanceof AuthError) return fail(err.message);
    console.error("google callback failed", err);
    return fail("Google sign-in failed.");
  }
}
