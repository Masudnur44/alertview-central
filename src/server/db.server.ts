// PostgreSQL access. Every unit of work runs in a transaction that tells the database
// who is acting, so row-level security and the audit triggers see the right identity.
import postgres from "postgres";
import { env } from "./env.server";

export type Sql = postgres.Sql;
export type Tx = postgres.TransactionSql;

let client: Sql | undefined;

export function db(): Sql {
  if (!client) {
    client = postgres(env().DATABASE_URL, {
      max: Number(process.env.DB_POOL_SIZE ?? 10),
      idle_timeout: 30,
      connect_timeout: 10,
      onnotice: () => {},
      // Hand timestamps to the UI as ISO strings (stable across server/client serialization).
      transform: { value: { from: (v: unknown) => (v instanceof Date ? v.toISOString() : v) } },
    });
  }
  return client;
}

export type Actor = { userId: string; ip?: string | null };

/** Run as a signed-in user: RLS policies and the audit trail apply to this user. */
export function asUser<T>(actor: Actor, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return db().begin(async (tx) => {
    await tx`select set_config('app.user_id', ${actor.userId}, true), set_config('app.client_ip', ${actor.ip ?? ""}, true)`;
    return fn(tx);
  }) as Promise<T>;
}

/** Run as the platform itself (worker, ingest, sign-in flows). */
export function asSystem<T>(fn: (tx: Tx) => Promise<T>, ip?: string | null): Promise<T> {
  return db().begin(async (tx) => {
    await tx`select set_config('app.system', 'on', true), set_config('app.client_ip', ${ip ?? ""}, true)`;
    return fn(tx);
  }) as Promise<T>;
}

/** Record an explicit audit entry (logins, exports, key creation...). */
export async function audit(tx: Tx, action: string, target?: { type?: string; id?: string | null }, detail?: Record<string, unknown>) {
  await tx`select app.audit(${action}, ${target?.type ?? null}, ${target?.id ?? null}, ${detail ? tx.json(detail as never) : null})`;
}

export async function closeDb() {
  await client?.end({ timeout: 5 });
  client = undefined;
}
