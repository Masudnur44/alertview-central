// Developer side of issues: the "My issues" view for developer accounts, and the
// secure no-login link (/fix/<token>) that can be sent to any developer.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const uuid = z.string().uuid();
const DevStatus = z.enum(["acknowledged", "in_progress", "fixed"]);
const token = z.string().min(30).max(60).regex(/^[A-Za-z0-9_-]+$/);

export type { DevIssue } from "@/lib/types";

// ----- Developer accounts --------------------------------------------------
export const myIssues = createServerFn({ method: "GET" }).handler(async () => {
  const { guard } = await import("@/server/api.server");
  const { run } = await guard("dev.issues");
  return run((tx) => tx`
    select i.id, i.ref, i.title, i.severity, i.status, i.due_at, i.created_at, a.name as asset_name,
           (i.status in ('open','acknowledged','in_progress') and i.due_at < now()) as overdue
    from issues i left join assets a on a.id = i.asset_id
    order by (i.status in ('open','acknowledged','in_progress')) desc, (i.due_at < now()) desc, i.created_at desc limit 300`);
});

export const getMyIssue = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ id: uuid }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run } = await guard("dev.issues");
    const issue = await run(async (tx) => (await import("@/server/issues.server")).loadIssueView(tx, data.id));
    if (!issue) throw new Error("Issue not found");
    return issue;
  });

export const devUpdateIssue = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ id: uuid, status: DevStatus.optional(), comment: z.string().trim().max(4000).optional() }).parse(d))
  .handler(async ({ data }) => {
    const { guard } = await import("@/server/api.server");
    const { run, s } = await guard("dev.issues");
    return run(async (tx) => {
      const [before] = await tx`select status from issues where id = ${data.id}`;
      if (!before) throw new Error("Issue not found");
      if (["verified", "wont_fix"].includes(before.status)) throw new Error("This issue is closed.");
      if (data.status && data.status !== before.status) {
        await tx`update issues set status = ${data.status} where id = ${data.id}`;
        await tx`insert into issue_updates (issue_id, kind, body, author) values (${data.id}, 'status', ${`Status: ${before.status} → ${data.status}`}, ${s.user.id})`;
      }
      if (data.comment) await tx`insert into issue_updates (issue_id, kind, body, author) values (${data.id}, 'comment', ${data.comment}, ${s.user.id})`;
      return { ok: true };
    });
  });

// ----- Secure link (no login) ----------------------------------------------
export const getIssueByLink = createServerFn({ method: "GET" })
  .inputValidator((d: unknown) => z.object({ token }).parse(d))
  .handler(async ({ data }) => {
    const { asSystem } = await import("@/server/db.server");
    const { issueIdForToken } = await import("@/server/issues.server");
    const { rateLimit } = await import("@/server/ratelimit.server");
    const { clientIp } = await import("@/server/auth.server");
    const { plain } = await import("@/server/api.server");
    if (!rateLimit(`issue-link:${clientIp() ?? "?"}`, 60, 60_000).ok) throw new Error("Too many requests. Wait a minute.");
    return plain(await asSystem(async (tx) => {
      const id = await issueIdForToken(tx, data.token);
      if (!id) return null;
      const issue = await (await import("@/server/issues.server")).loadIssueView(tx, id);
      return issue ? { ...issue, id: "" } : null; // never expose internal ids on the public page
    }));
  });

export const updateIssueByLink = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({
    token,
    name: z.string().trim().min(2).max(80),
    status: DevStatus.optional(),
    comment: z.string().trim().max(4000).optional(),
  }).parse(d))
  .handler(async ({ data }) => {
    const { asSystem } = await import("@/server/db.server");
    const { issueIdForToken } = await import("@/server/issues.server");
    const { rateLimit } = await import("@/server/ratelimit.server");
    const { clientIp } = await import("@/server/auth.server");
    if (!rateLimit(`issue-link-post:${clientIp() ?? "?"}`, 20, 60_000).ok) throw new Error("Too many updates. Wait a minute.");
    return asSystem(async (tx) => {
      const id = await issueIdForToken(tx, data.token);
      if (!id) throw new Error("This link is invalid or has expired. Ask the SOC for a new one.");
      const [before] = await tx`select i.status, t.name as team from issues i left join teams t on t.id = i.team_id where i.id = ${id}`;
      if (["verified", "wont_fix"].includes(before!.status)) throw new Error("This issue is already closed.");
      const label = `${data.name} (${before!.team ?? "team"}, via secure link)`;
      if (data.status && data.status !== before!.status) {
        await tx`update issues set status = ${data.status} where id = ${id}`;
        await tx`insert into issue_updates (issue_id, kind, body, author_label) values (${id}, 'status', ${`Status: ${before!.status} → ${data.status}`}, ${label})`;
      }
      if (data.comment) await tx`insert into issue_updates (issue_id, kind, body, author_label) values (${id}, 'comment', ${data.comment}, ${label})`;
      await tx`select app.audit('issue.updated_via_link', 'issues', ${id}, ${tx.json({ by: label, status: data.status ?? null })})`;
      return { ok: true };
    }, clientIp());
  });
