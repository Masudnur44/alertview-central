// Loads (or removes) the FINPAYTECH demo data.
//   npm run db:seed-demo            load demo assets, alerts, incidents, vulnerabilities, events
//   npm run db:seed-demo -- --remove   delete all demo rows, keep real data
import fs from "node:fs";
import path from "node:path";
import postgres from "postgres";

const url = process.env.MIGRATION_DATABASE_URL;
if (!url) {
  console.error("MIGRATION_DATABASE_URL is not set");
  process.exit(1);
}
const remove = process.argv.includes("--remove");
const sql = postgres(url, { max: 1, onnotice: () => {} });

async function main() {
  if (!remove) {
    const [existing] = await sql`select count(*)::int as n from assets where 'demo' = any(tags)`;
    if (existing!.n > 0) {
      console.log("demo data already loaded");
      return;
    }
  }
  const file = path.resolve(process.cwd(), remove ? "db/seed/remove-demo.sql" : "db/seed/demo.sql");
  await sql.unsafe(fs.readFileSync(file, "utf8"));
  console.log(remove ? "demo data removed" : "demo data loaded");
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => sql.end());
