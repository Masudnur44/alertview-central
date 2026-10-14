// Background jobs, shared by the worker (on a schedule) and the app ("run now" buttons).
import { asSystem, db } from "./db.server";
import { runChecks } from "./monitor/checks.server";
import { runDiscovery } from "./monitor/discovery.server";
import { refreshAllFeeds } from "./intel.server";
import { checkSilentSources } from "./detect.server";
import { jobResultOk } from "./monitor/policy";

export type JobName = "checks" | "discovery" | "intel" | "silent_sources" | "retention";

const running = new Set<JobName>();

async function retention() {
  return asSystem(async (tx) => {
    const settings = Object.fromEntries((await tx`select key, value from settings where key in ('event_retention_days','check_results_retention_days')`).map((r) => [r.key, Number(r.value)]));
    const ev = await tx`delete from events where occurred_at < now() - make_interval(days => ${settings.event_retention_days || 90})`;
    const cr = await tx`delete from check_results where checked_at < now() - make_interval(days => ${settings.check_results_retention_days || 30})`;
    const se = await tx`delete from sessions where expires_at < now()`;
    const tk = await tx`delete from one_time_tokens where expires_at < now() - interval '1 day'`;
    const jr = await tx`delete from job_runs where started_at < now() - interval '30 days'`;
    const nt = await tx`delete from notifications where created_at < now() - interval '90 days' and status <> 'pending'`;
    return { events: ev.count, check_results: cr.count, sessions: se.count, tokens: tk.count, job_runs: jr.count, notifications: nt.count };
  });
}

const RUNNERS: Record<JobName, () => Promise<unknown>> = {
  checks: () => runChecks(),
  discovery: () => runDiscovery(),
  intel: () => refreshAllFeeds(),
  silent_sources: () => asSystem((tx) => checkSilentSources(tx)).then((alerts) => ({ alerts })),
  retention,
};

/** Runs a job once, recording it in job_runs. Concurrent runs of the same job in this process are skipped. */
export async function runJob(name: JobName): Promise<unknown> {
  if (running.has(name)) return { skipped: "already running" };
  running.add(name);
  let connection: Awaited<ReturnType<typeof db>["reserve"]> | undefined;
  let locked = false;
  let runId: number | undefined;
  try {
    connection = await db().reserve();
    const [lock] = await connection`select pg_try_advisory_lock(hashtextextended(${`finpay-soc:${name}`}, 0)) as locked`;
    if (!lock?.locked) return { skipped: "already running" };
    locked = true;
    const [run] = await asSystem((tx) => tx`insert into job_runs (job) values (${name}) returning id`);
    runId = run!.id as number;
    const detail = await RUNNERS[name]();
    await asSystem((tx) => tx`update job_runs set finished_at = now(), ok = ${jobResultOk(detail)}, detail = ${tx.json((detail ?? {}) as never)} where id = ${runId}`);
    return detail;
  } catch (e) {
    if (runId !== undefined) {
      await asSystem((tx) => tx`update job_runs set finished_at = now(), ok = false, detail = ${tx.json({ error: (e as Error).message })} where id = ${runId}`);
    }
    throw e;
  } finally {
    if (connection) {
      if (locked) await connection`select pg_advisory_unlock(hashtextextended(${`finpay-soc:${name}`}, 0))`;
      connection.release();
    }
    running.delete(name);
  }
}
