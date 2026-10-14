// Early warnings: signals that usually come BEFORE an outage or a breach.
//   * response time degrading vs the asset's own 7-day baseline
//   * flapping (repeated short outages)
//   * certificate renewal due within 30 days
//   * failed-login surge on a host vs its normal rate
// Each warning auto-resolves (and verifies any issue sent to a team) when the signal clears.
import { asSystem } from "../db.server";
import { autoResolve, loadRules, raiseAlert, type Rule } from "../alerts.server";

const p = (rules: Map<string, Rule>, key: string, name: string, d: number) =>
  Number((rules.get(key)?.params as Record<string, unknown> | undefined)?.[name] ?? d);

export async function runEarlyWarnings(): Promise<{ warnings: number }> {
  return asSystem(async (tx) => {
    const rules = await loadRules(tx);
    let warnings = 0;
    const raise = async (...args: Parameters<typeof raiseAlert>) => { if (await raiseAlert(...args)) warnings++; };

    // 1) Latency degradation
    const factor = p(rules, "latency_degradation", "factor", 2);
    const minMs = p(rules, "latency_degradation", "min_ms", 800);
    const latency = await tx`
      select a.id, a.name,
        avg(c.response_ms) filter (where c.checked_at > now() - interval '1 hour')::int as recent,
        count(*) filter (where c.checked_at > now() - interval '1 hour')::int as recent_n,
        percentile_cont(0.5) within group (order by c.response_ms) filter (where c.checked_at <= now() - interval '1 hour')::int as baseline,
        count(*) filter (where c.checked_at <= now() - interval '1 hour')::int as baseline_n
      from assets a join check_results c on c.asset_id = a.id
      where a.monitored and c.check_type = 'availability' and c.ok and c.response_ms is not null and c.checked_at > now() - interval '7 days'
      group by a.id`;
    for (const r of latency) {
      const key = `slow:${r.id}`;
      if (r.recent_n >= 1 && r.baseline_n >= 3 && r.recent > minMs && r.recent > r.baseline * factor) {
        await raise(tx, rules, {
          rule: "latency_degradation",
          title: `Slowing down: ${r.name} (${r.recent} ms, normally ${r.baseline} ms)`,
          description: `Average response time in the last hour is ${(r.recent / Math.max(r.baseline, 1)).toFixed(1)}× the 7-day normal. Slow responses usually precede timeouts and outages.`,
          source: "early_warning", assetId: r.id, dedupeKey: key, details: { recent_ms: r.recent, baseline_ms: r.baseline },
        });
      } else if (r.recent_n >= 1 && r.recent <= r.baseline * 1.3) {
        await autoResolve(tx, key, "response time back to normal");
      }
    }

    // 2) Flapping: several failures in the window but currently online
    const failures = p(rules, "flapping", "failures", 3);
    const hours = p(rules, "flapping", "hours", 24);
    const flaps = await tx`
      select a.id, a.name, a.status, count(*) filter (where not c.ok)::int as fails,
             max(c.checked_at) filter (where not c.ok) as last_fail
      from assets a join check_results c on c.asset_id = a.id
      where a.monitored and c.check_type = 'availability' and c.checked_at > now() - make_interval(hours => ${hours})
      group by a.id`;
    for (const r of flaps) {
      const key = `flap:${r.id}`;
      if (r.fails >= failures && r.status === "online") {
        await raise(tx, rules, {
          rule: "flapping",
          title: `Unstable: ${r.name} failed ${r.fails} times in ${hours}h`,
          description: `The service keeps dropping and recovering (last failure ${new Date(r.last_fail).toISOString()}). Intermittent failures usually turn into a full outage.`,
          source: "early_warning", assetId: r.id, dedupeKey: key, details: { failures: r.fails, hours },
        });
      } else if (r.fails === 0) {
        await autoResolve(tx, key, `no failures in ${hours}h`);
      }
    }

    // 3) Certificate renewal due (the 14-day rule covers the urgent case)
    const days = p(rules, "cert_expiring_soon", "days", 30);
    const certs = await tx`select id, name, tls_expires_at, tls_issuer from assets where monitored and tls_expires_at is not null`;
    for (const r of certs) {
      const left = Math.floor((new Date(r.tls_expires_at).getTime() - Date.now()) / 864e5);
      const key = `cert-soon:${r.id}`;
      if (left >= 14 && left < days) {
        await raise(tx, rules, {
          rule: "cert_expiring_soon",
          title: `Renew certificate soon: ${r.name} (${left} days left)`,
          description: `Certificate from ${r.tls_issuer ?? "unknown issuer"} expires ${new Date(r.tls_expires_at).toDateString()}. Renew or confirm auto-renewal now to avoid an outage.`,
          source: "early_warning", assetId: r.id, dedupeKey: key,
        });
      } else if (left >= days) {
        await autoResolve(tx, key, "certificate renewed");
      }
    }

    // 4) Failed-login surge per host vs its own normal hourly rate
    const sFactor = p(rules, "auth_failure_surge", "factor", 3);
    const sMin = p(rules, "auth_failure_surge", "min_failures", 20);
    const surges = await tx`
      select e.host,
        count(*) filter (where e.occurred_at > now() - interval '1 hour')::int as last_hour,
        (count(*) filter (where e.occurred_at <= now() - interval '1 hour') / 167.0)::float8 as hourly_avg,
        count(distinct host(e.src_ip)) filter (where e.occurred_at > now() - interval '1 hour')::int as sources
      from events e
      where e.event_type = 'auth.login' and e.outcome = 'failure' and e.host is not null and e.occurred_at > now() - interval '7 days'
      group by e.host`;
    for (const r of surges) {
      const key = `authsurge:${String(r.host).toLowerCase()}`;
      if (r.last_hour >= sMin && r.last_hour > Math.max(1, r.hourly_avg) * sFactor) {
        const [asset] = await tx`select id from assets where lower(name) = lower(${r.host})`;
        await raise(tx, rules, {
          rule: "auth_failure_surge",
          title: `Failed-login surge on ${r.host}: ${r.last_hour} in the last hour`,
          description: `Normal is about ${r.hourly_avg.toFixed(1)} per hour; ${r.sources} different source addresses. A password-guessing campaign may be starting.`,
          source: "early_warning", assetId: asset?.id ?? null, dedupeKey: key, details: { host: r.host, last_hour: r.last_hour, normal_per_hour: Number(r.hourly_avg.toFixed(1)), sources: r.sources },
        });
      } else if (r.last_hour < sMin / 2) {
        await autoResolve(tx, key, "failed logins back to normal");
      }
    }
    return { warnings };
  });
}
