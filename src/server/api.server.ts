// Guard for server functions: authenticate, authorize, then run as that user.
import { AuthError, requireSession, withUser, type SessionInfo } from "./auth.server";
import type { Tx } from "./db.server";
import { can, type Permission } from "@/lib/permissions";

/** Strip driver-specific wrappers so results serialize cleanly to the browser. */
export function plain<T>(value: T): T {
  return value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T);
}

export async function guard(perm: Permission, opts: { allowMfaEnrollment?: boolean } = {}) {
  const s = await requireSession(opts);
  if (!can(s.user.roles, perm)) throw new AuthError("FORBIDDEN: your role does not allow this action.");
  return {
    s,
    run: async <T>(fn: (tx: Tx) => Promise<T>): Promise<T> => plain(await withUser(s, fn)),
  };
}

export type Guarded = { s: SessionInfo; run: <T>(fn: (tx: Tx) => Promise<T>) => Promise<T> };
