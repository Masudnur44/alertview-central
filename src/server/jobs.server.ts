// Background jobs, shared by the worker (on a schedule) and the app ("run now" buttons).
import { asSystem } from "./db.server";
import { runChecks } from "./monitor/checks.server";
import { runDiscovery } from "./monitor/discovery.server";
import { refreshAllFeeds } from "./intel.server";
import { checkSilentSources } from "./detect.server";

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
  const [run] = await asSystem((tx) => tx`insert into job_runs (job) values (${name}) returning id`);
  try {
    const detail = await RUNNERS[name]();
    await asSystem((tx) => tx`update job_runs set finished_at = now(), ok = true, detail = ${tx.json((detail ?? {}) as never)} where id = ${run!.id}`);
    return detail;
  } catch (e) {
    await asSystem((tx) => tx`update job_runs set finished_at = now(), ok = false, detail = ${tx.json({ error: (e as Error).message })} where id = ${run!.id}`);
    throw e;
  } finally {
    running.delete(name);
  }
}
