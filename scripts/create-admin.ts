// Creates or promotes a Security Administrator from the server's command line.
//   npm run admin:create -- --email masud@finpaytech.com --name "Masud Nur"
// Prints a one-time password if the account is new (change it after first sign-in).
import postgres from "postgres";
import { hashPassword, randomToken } from "../src/server/crypto.server";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}

const url = process.env.MIGRATION_DATABASE_URL;
const email = arg("email")?.toLowerCase();
const name = arg("name") ?? email?.split("@")[0];
if (!url || !email) {
  console.error("usage: MIGRATION_DATABASE_URL=... npm run admin:create -- --email you@company.com [--name \"Full Name\"]");
  process.exit(1);
}
const sql = postgres(url, { max: 1, onnotice: () => {} });

async function main() {
  const [existing] = await sql`select id from users where email = ${email!}`;
  let password: string | null = null;
  let id: string;
  if (existing) {
    id = existing.id;
    await sql`update users set status = 'active', email_verified = true, approved_at = coalesce(approved_at, now()), locked_until = null, failed_logins = 0 where id = ${id}`;
  } else {
    password = `${randomToken(12)}-A1!`;
    const [u] = await sql`insert into users (email, display_name, password_hash, status, email_verified, approved_at)
                          values (${email!}, ${name!}, ${await hashPassword(password)}, 'active', true, now()) returning id`;
    id = u!.id;
  }
  await sql`insert into user_roles (user_id, role) values (${id}, 'security_admin') on conflict do nothing`;
  await sql`insert into audit_log (action, target_type, target_id, detail) values ('cli.admin_created', 'users', ${id}, ${sql.json({ email: email! })})`;
  console.log(`${email} is now an active Security Administrator.`);
  if (password) console.log(`One-time password: ${password}\nSign in, then set up two-factor and change this password in Account.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => sql.end());
