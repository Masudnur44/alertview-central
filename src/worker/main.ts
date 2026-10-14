// FINPAY SOC worker: scheduled checks, discovery, threat-intel refresh, notification
// delivery, silent-source detection and data retention. Run exactly one worker.
import { asSystem, closeDb } from "@/server/db.server";
import { env } from "@/server/env.server";
import { runJob, type JobName } from "@/server/jobs.server";
import { deliverOutbox, deliverPending } from "@/server/notify.server";

type Schedule = { job: JobName; everyMinutes: (s: Record<string, number>) => number };

const SCHEDULE: Schedule[] = [
  { job: "checks", everyMinutes: (s) => s.check_interval_minutes || 60 },
  { job: "discovery", everyMinutes: (s) => (s.discovery_interval_hours || 24) * 60 },
  { job: "intel", everyMinutes: (s) => (s.intel_interval_hours || 24) * 60 },
  { job: "silent_sources", everyMinutes: () => 15 },
  { job: "early_warning", everyMinutes: () => 15 },
  { job: "retention", everyMinutes: () => 360 },
];

let stopping = false;

async function settings(): Promise<Record<string, number>> {
  const rows = await asSystem((tx) => tx`select key, value from settings`);
  return Object.fromEntries(rows.filter((r) => typeof r.value === "number").map((r) => [r.key, r.value as number]));
}

async function lastRun(job: JobName): Promise<number> {
  const [r] = await asSystem((tx) => tx`select max(started_at) as at from job_runs where job = ${job}`);
  return r?.at ? new Date(r.at).getTime() : 0;
}

async function tick() {
  const s = await settings();
  for (const { job, everyMinutes } of SCHEDULE) {
    if (stopping) return;
    if (Date.now() - (await lastRun(job)) >= everyMinutes(s) * 60_000) {
      const t0 = Date.now();
      try {
        const detail = await runJob(job);
        console.log(`[worker] ${job} done in ${Date.now() - t0}ms`, JSON.stringify(detail));
      } catch (e) {
        console.error(`[worker] ${job} failed`, e);
      }
    }
  }
  await asSystem((tx) => tx`insert into settings (key, value) values ('worker_heartbeat', to_jsonb(now()))
                            on conflict (key) do update set value = excluded.value, updated_at = now()`);
}

async function notificationsLoop() {
  while (!stopping) {
    try {
      const r = await deliverPending();
      if (r.sent || r.failed) console.log(`[worker] notifications sent=${r.sent} failed=${r.failed}`);
      const o = await deliverOutbox();
      if (o.sent || o.failed) console.log(`[worker] team messages sent=${o.sent} failed=${o.failed}`);
    } catch (e) {
      console.error("[worker] notification delivery failed", e);
    }
    await sleep(15_000);
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  env(); // fail fast on bad configuration
  console.log("[worker] FINPAY SOC worker started");
  for (const sig of ["SIGINT", "SIGTERM"] as const) {
    process.on(sig, () => {
      console.log(`[worker] ${sig} received, finishing current work`);
      stopping = true;
    });
  }
  void notificationsLoop();
  while (!stopping) {
    try {
      await tick();
    } catch (e) {
      console.error("[worker] tick failed", e);
    }
    for (let i = 0; i < 6 && !stopping; i++) await sleep(10_000);
  }
  await closeDb();
  process.exit(0);
}

void main();
