# FINPAY SOC — conventions for developers and AI coding assistants

Read this before changing code. `roadmap.md` lists open work; `docs/SECURITY.md` explains the security model you must preserve.

## Architecture
- TanStack Start (React 19, Vite) + Tailwind v4 + shadcn/ui. Built with Nitro's `node-server` preset into `.output/`.
- PostgreSQL 16 accessed with `postgres` (postgres.js). No ORM. Schema lives in `db/migrations/*.sql` (forward-only, applied by `scripts/migrate.ts`).
- Server-only code is in `src/server/*.server.ts`. Pages never touch the database: they call server functions in `src/lib/api/*.functions.ts`.
- The worker (`src/worker/main.ts`, run with `tsx`) runs scheduled jobs from `src/server/jobs.server.ts`. Exactly one worker.

## Rules
1. **Every server function** starts with `const { guard } = await import("@/server/api.server"); const { run } = await guard("<permission>");` and does its queries inside `run(tx => ...)`. Never use `asSystem` for user-initiated reads/writes — RLS and the audit trail depend on the user context.
2. **Import server modules dynamically inside handlers** (`await import("@/server/...")`), never at the top of `*.functions.ts` or route files — those files are also bundled for the browser.
3. **Permissions** are defined once in `src/lib/permissions.ts`. If you add one, add the matching RLS policy in a new migration.
4. **Schema changes** = a new numbered file in `db/migrations/`. Never edit an applied migration. New tables: enable + force RLS, add the `system_all` policy and member policies, add the `audit_row` trigger if humans edit it.
5. **Alerts** are raised only through `raiseAlert()` (`src/server/alerts.server.ts`) with a stable `dedupeKey`, so repeats merge into one open alert and notifications fire once.
6. **Outbound requests to user-supplied addresses** must go through `src/server/monitor/net.server.ts` (`resolveTarget`/`httpProbe`) — it blocks private networks (SSRF).
7. **Secrets** are never stored in plain text: hash tokens/keys with `sha256`, encrypt reusable secrets with `encrypt()` from `crypto.server.ts`.
8. Inet columns: select them with `host(col)` (not `::text`, which appends `/32`).
9. Throwing inside `asSystem`/`asUser` rolls the transaction back — return a result and throw afterwards if a write (e.g. a failed-login counter) must persist.

## Commands
`npm run dev` · `npm run build` · `npm start` · `npm run worker` · `npm run db:migrate` · `npm run db:seed-demo [-- --remove]` · `npm run admin:create -- --email x` · `npm test` · `npm run typecheck`

## Design
Dark command-center theme; Space Grotesk headings, JetBrains Mono (`.data` class) for data; severity tokens `text-sev-critical|high|medium|low|info`, `text-ok`. Shared pieces in `src/components/soc/ui.tsx`.
