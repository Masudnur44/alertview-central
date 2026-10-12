// Free threat-intelligence feeds, refreshed by the worker.
//   * CISA Known Exploited Vulnerabilities → flags vulnerabilities as exploited in the wild
//   * abuse.ch Feodo Tracker               → botnet command-and-control IPs
//   * Spamhaus DROP                        → hijacked / criminal network ranges
//   * Tor Project exit list                → anonymised traffic (reported as medium)
import { asSystem } from "./db.server";

type Indicator = { kind: "ip" | "cidr" | "cve"; value: string; network: string | null; description: string | null };

export const FEEDS: { source: string; label: string; url: string; parse: (body: string) => Indicator[] }[] = [
  {
    source: "cisa_kev",
    label: "CISA Known Exploited Vulnerabilities",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    parse: (body) =>
      ((JSON.parse(body) as { vulnerabilities?: { cveID: string; vulnerabilityName?: string }[] }).vulnerabilities ?? [])
        .filter((v) => /^CVE-\d{4}-\d+$/i.test(v.cveID))
        .map((v) => ({ kind: "cve", value: v.cveID.toUpperCase(), network: null, description: v.vulnerabilityName ?? null })),
  },
  {
    source: "feodo",
    label: "abuse.ch Feodo Tracker (botnet C2)",
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    parse: (body) =>
      (JSON.parse(body) as { ip_address: string; malware?: string }[])
        .filter((r) => isIPv4(r.ip_address))
        .map((r) => ({ kind: "ip", value: r.ip_address, network: `${r.ip_address}/32`, description: r.malware ? `${r.malware} C2` : "Botnet C2" })),
  },
  {
    source: "spamhaus_drop",
    label: "Spamhaus DROP",
    url: "https://www.spamhaus.org/drop/drop_v4.json",
    parse: (body) =>
      body.split("\n").map((l) => l.trim()).filter(Boolean)
        .map((l) => { try { return JSON.parse(l) as { cidr?: string; sblid?: string }; } catch { return {}; } })
        .filter((r): r is { cidr: string; sblid?: string } => typeof r.cidr === "string" && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(r.cidr))
        .map((r) => ({ kind: "cidr", value: r.cidr, network: r.cidr, description: r.sblid ? `Spamhaus ${r.sblid}` : "Spamhaus DROP" })),
  },
  {
    source: "tor_exit",
    label: "Tor exit nodes",
    url: "https://check.torproject.org/torbulkexitlist",
    parse: (body) =>
      body.split("\n").map((l) => l.trim()).filter(isIPv4)
        .map((ip) => ({ kind: "ip", value: ip, network: `${ip}/32`, description: "Tor exit node" })),
  },
];

function isIPv4(s: string): boolean {
  return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s);
}

export async function refreshFeed(feed: (typeof FEEDS)[number]): Promise<number> {
  const res = await fetch(feed.url, { headers: { "user-agent": "FINPAY-SOC-Intel/1.0" }, signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`${feed.source}: HTTP ${res.status}`);
  const items = feed.parse(await res.text());
  if (!items.length) throw new Error(`${feed.source}: feed was empty, keeping previous data`);
  return asSystem(async (tx) => {
    const [clock] = await tx`select now() as started`;
    const started = clock!.started as string;
    for (let i = 0; i < items.length; i += 2000) {
      const chunk = items.slice(i, i + 2000);
      await tx`
        insert into threat_indicators (kind, value, network, source, description)
        select * from unnest(${chunk.map((c) => c.kind)}::text[], ${chunk.map((c) => c.value)}::text[],
                             ${chunk.map((c) => c.network)}::cidr[], ${chunk.map(() => feed.source)}::text[], ${chunk.map((c) => c.description)}::text[])
        on conflict (kind, value, source) do update set last_seen = now(), description = excluded.description`;
    }
    // Indicators that dropped off the feed are removed.
    await tx`delete from threat_indicators where source = ${feed.source} and last_seen < ${started}`;
    if (feed.source === "cisa_kev") {
      await tx`update vulnerabilities v set exploited_in_wild = true
               where not exploited_in_wild and v.cve is not null
                 and exists (select 1 from threat_indicators t where t.kind = 'cve' and t.source = 'cisa_kev' and t.value = upper(v.cve))`;
    }
    return items.length;
  });
}

export async function refreshAllFeeds(): Promise<Record<string, number | string>> {
  const out: Record<string, number | string> = {};
  for (const feed of FEEDS) {
    try {
      out[feed.source] = await refreshFeed(feed);
    } catch (e) {
      out[feed.source] = `error: ${(e as Error).message}`;
    }
  }
  return out;
}
