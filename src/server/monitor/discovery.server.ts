// New-asset discovery from public certificate-transparency logs (crt.sh).
// Any certificate issued for *.yourdomain reveals a hostname; unknown, resolvable
// hostnames are added to the inventory and raise a "new internet-facing asset" alert.
import { asSystem } from "../db.server";
import { env } from "../env.server";
import { loadRules, raiseAlert } from "../alerts.server";
import { resolveTarget } from "./net.server";

export function hostnamesFromCt(entries: { name_value?: string; common_name?: string }[], root: string): string[] {
  const out = new Set<string>();
  const r = root.toLowerCase();
  for (const e of entries) {
    for (const raw of `${e.name_value ?? ""}\n${e.common_name ?? ""}`.split(/\s+/)) {
      const h = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (!h || h.includes("*") || h.includes("@")) continue;
      if (!/^[a-z0-9.-]+$/.test(h)) continue;
      if (h === r || h.endsWith(`.${r}`)) out.add(h);
    }
  }
  return [...out].sort();
}

async function fetchCt(domain: string): Promise<{ name_value?: string; common_name?: string }[]> {
  const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired`, {
    headers: { "user-agent": "FINPAY-SOC-Discovery/1.0" },
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) throw new Error(`crt.sh answered ${res.status}`);
  return (await res.json()) as { name_value?: string; common_name?: string }[];
}

export async function runDiscovery(): Promise<{ domains: number; found: number; added: number; errors: string[] }> {
  const domains = await asSystem((tx) => tx`select id, domain::text as domain from monitored_domains where discover_subdomains`);
  let found = 0, added = 0;
  const errors: string[] = [];
  for (const d of domains) {
    let hosts: string[];
    try {
      hosts = hostnamesFromCt(await fetchCt(d.domain), d.domain);
    } catch (e) {
      errors.push(`${d.domain}: ${(e as Error).message}`);
      continue;
    }
    found += hosts.length;
    const known = new Set((await asSystem((tx) => tx`select lower(name) as n from assets`)).map((r) => r.n as string));
    const candidates = hosts.filter((h) => !known.has(h)).slice(0, 200);
    for (const host of candidates) {
      try {
        await resolveTarget(host, env().ALLOW_PRIVATE_TARGETS); // only live, public hostnames
      } catch {
        continue;
      }
      const inserted = await asSystem(async (tx) => {
        const [a] = await tx`
          insert into assets (name, asset_type, address, exposure, status, is_new, discovered_via, criticality, monitored, notes)
          values (${host}, 'website', ${`https://${host}`}, 'external', 'unknown', true, 'ct_log', 'medium', false,
                  ${`Discovered in certificate-transparency logs for ${d.domain}. Confirm the owner and criticality, then approve its monitoring scope.`})
          on conflict (lower(name)) do nothing returning id`;
        if (!a) return false;
        const rules = await loadRules(tx);
        await raiseAlert(tx, rules, {
          rule: "new_external_asset",
          title: `New internet-facing asset discovered: ${host}`,
          description: `${host} has a public TLS certificate and resolves on the internet, but was not in the asset inventory. Confirm it is approved, owned and patched.`,
          source: "external", assetId: a.id, dedupeKey: `new-asset:${host}`,
        });
        return true;
      });
      if (inserted) added++;
    }
    await asSystem((tx) => tx`update monitored_domains set last_discovery_at = now() where id = ${d.id}`);
  }
  return { domains: domains.length, found, added, errors };
}
