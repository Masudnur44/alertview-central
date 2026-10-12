// Applies db/migrations/*.sql in order, once each, inside a transaction per file.
// Uses MIGRATION_DATABASE_URL (the database owner). If SOC_APP_DB_PASSWORD is set,
// also enables login for the restricted soc_app role the app and worker use.
//
//   npm run db:migrate
import fs from "node:fs";
import path from "node:path";
import postgres from "postgres";

const url = process.env.MIGRATION_DATABASE_URL;
if (!url) {
  console.error("MIGRATION_DATABASE_URL is not set");
  process.exit(1);
}
const sql = postgres(url, { max: 1, onnotice: () => {} });
const dir = path.resolve(process.cwd(), "db/migrations");

async function main() {
  await sql`create table if not exists schema_migrations (name text primary key, applied_at timestamptz not null default now())`;
  // Serialise concurrent starts (app + worker both run migrations on boot).
  await sql`select pg_advisory_lock(727274)`;
  try {
    const done = new Set((await sql`select name from schema_migrations`).map((r) => r.name as string));
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
    for (const f of files) {
      if (done.has(f)) continue;
      process.stdout.write(`applying ${f} ... `);
      await sql.begin(async (tx) => {
        await tx.unsafe(fs.readFileSync(path.join(dir, f), "utf8"));
        await tx`insert into schema_migrations (name) values (${f})`;
      });
      console.log("ok");
    }
    const pw = process.env.SOC_APP_DB_PASSWORD;
    if (pw) {
      await sql.unsafe(`alter role soc_app login password '${pw.replace(/'/g, "''")}'`);
    }
    console.log(`database up to date (${files.length} migrations)`);
  } finally {
    await sql`select pg_advisory_unlock(727274)`;
    await sql.end();
  }
}

main().catch(async (e) => {
  console.error(e);
  await sql.end({ timeout: 1 });
  process.exit(1);
});
