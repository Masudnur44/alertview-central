// External attack-surface checks: availability, TLS, security headers, exposed ports, DNS.
import net from "node:net";
import { asSystem, type Tx } from "../db.server";
import { env } from "../env.server";
import { autoResolve, loadRules, raiseAlert, type RaiseInput, type Rule } from "../alerts.server";
import { dnsSnapshot, httpProbe, missingSecurityHeaders, parseTarget, portProbe, tlsProbe, type CertInfo, type DnsSnapshot } from "./net.server";

const TLS_PORTS = new Set([443, 465, 636, 853, 990, 993, 995, 5986, 8443]);

type Asset = {
  id: string;
  name: string;
  asset_type: string;
  address: string | null;
  exposure: string;
  status: string;
  dns: DnsSnapshot | null;
  open_ports: number[];
};

type Outcome = {
  online: boolean | null;     // null = not checkable (blocked/invalid)
  detail: string;
  httpStatus?: number | null;
  ms?: number | null;
  cert?: CertInfo | null;
  openPorts?: number[];
  dns?: DnsSnapshot | null;
};

async function pool<T>(items: T[], size: number, fn: (item: T) => Promise<void>) {
  const queue = [...items];
  await Promise.all(Array.from({ length: Math.min(size, queue.length) }, async () => {
    while (queue.length) await fn(queue.shift()!);
  }));
}

export async function runChecks(opts: { assetIds?: string[] } = {}): Promise<{ checked: number; alerts: number; failed: number }> {
  const e = env();
  const { assets, rules } = await asSystem(async (tx) => ({
    assets: await tx<Asset[]>`
      select id, name, asset_type, address, exposure, status, dns, open_ports from assets
      where monitored and exposure = 'external' and status <> 'retired'
        ${opts.assetIds?.length ? tx`and id = any(${opts.assetIds}::uuid[])` : tx``}`,
    rules: await loadRules(tx),
  }));
  let alerts = 0, failed = 0;
  await pool(assets, e.CHECK_CONCURRENCY, async (asset) => {
    try {
      const outcome = await probe(asset, rules, e.ALLOW_PRIVATE_TARGETS);
      alerts += await asSystem((tx) => record(tx, asset, outcome, rules));
    } catch (err) {
      failed++;
      console.error(`check failed for ${asset.name}`, err);
    }
  });
  return { checked: assets.length, alerts, failed };
}

async function probe(asset: Asset, rules: Map<string, Rule>, allowPrivate: boolean): Promise<Outcome> {
  const target = parseTarget(asset.address ?? asset.name);
  if (!target) return { online: null, detail: "address not recognised" };
  const out: Outcome = { online: null, detail: "" };

  if (target.url) {
    const r = await httpProbe(target.url.toString(), { allowPrivate });
    if (r.error?.startsWith("blocked")) return { online: null, detail: r.error };
    out.online = r.ok;
    out.httpStatus = r.status;
    out.ms = r.ms;
    out.cert = r.cert;
    out.detail = r.error ?? `${r.status} ${r.statusText}`.trim();
    (out as Outcome & { headers?: Record<string, string> }).headers = r.ok ? r.headers : undefined;
  } else if (target.port) {
    const t0 = Date.now();
    if (TLS_PORTS.has(target.port)) {
      const c = await tlsProbe(target.host, target.port, { allowPrivate });
      if ("error" in c) {
        if (c.error.includes("private/reserved")) return { online: null, detail: `blocked: ${c.error}` };
        out.online = false;
        out.detail = c.error;
      } else {
        out.online = true;
        out.cert = c;
        out.detail = `TLS ${c.protocol ?? ""} handshake ok`.trim();
      }
    } else {
      const p = await portProbe(target.host, [target.port], { allowPrivate });
      if (p.error?.includes("private/reserved")) return { online: null, detail: `blocked: ${p.error}` };
      out.online = p.open.includes(target.port);
      out.detail = out.online ? `port ${target.port} open` : p.error ?? `port ${target.port} closed`;
    }
    out.ms = Date.now() - t0;
  }

  // Exposed-service scan (also gives liveness for bare IPs and domains).
  const risky = ((rules.get("risky_port_open")?.params as { ports?: number[] } | undefined)?.ports ?? []).filter((p) => Number.isInteger(p));
  const ports = [...new Set([...risky, 22, 80, 443])];
  const scan = await portProbe(target.host, ports, { allowPrivate });
  if (scan.error?.includes("private/reserved")) return { online: null, detail: `blocked: ${scan.error}` };
  out.openPorts = scan.open;
  if (out.online === null) {
    out.online = scan.open.length > 0;
    out.detail = scan.error ?? (scan.open.length ? `reachable on ${scan.open.join(", ")}` : "no common ports answered");
  }

  if (!net.isIP(target.host)) {
    const snap = await dnsSnapshot(target.host);
    // A failed lookup returns empty lists; keep the previous snapshot rather than recording "no records".
    out.dns = Object.values(snap).some((v) => v.length) ? snap : null;
  }
  return out;
}

async function record(tx: Tx, asset: Asset, o: Outcome, rules: Map<string, Rule>): Promise<number> {
  let opened = 0;
  const raise = async (a: RaiseInput) => {
    if (await raiseAlert(tx, rules, a)) opened++;
  };

  await tx`insert into check_results (asset_id, check_type, ok, detail, response_ms, data)
           values (${asset.id}, 'availability', ${o.online === true}, ${o.detail}, ${o.ms ?? null},
                   ${tx.json({ http_status: o.httpStatus ?? null, open_ports: o.openPorts ?? [] })})`;

  if (o.online === null) {
    await tx`update assets set status = 'unknown', last_checked_at = now() where id = ${asset.id}`;
    return 0;
  }

  await tx`
    update assets set
      status = ${o.online ? "online" : "offline"},
      last_checked_at = now(),
      last_seen = case when ${o.online} then now() else last_seen end,
      http_status = ${o.httpStatus ?? null},
      response_ms = ${o.ms ?? null},
      open_ports = ${o.openPorts ?? []}::int[],
      dns = coalesce(${o.dns ? tx.json(o.dns as never) : null}::jsonb, dns),
      tls_expires_at = coalesce(${o.cert?.validTo ?? null}::timestamptz, tls_expires_at),
      tls_issuer = coalesce(${o.cert?.issuer ?? null}, tls_issuer),
      tls_subject = coalesce(${o.cert?.subject ?? null}, tls_subject)
    where id = ${asset.id}`;

  // Availability
  const offlineKey = `offline:${asset.id}`;
  if (!o.online) {
    await raise({ rule: "asset_offline", title: `Asset offline: ${asset.name}`, description: `External check failed: ${o.detail}`, source: "external", assetId: asset.id, dedupeKey: offlineKey });
  } else {
    await autoResolve(tx, offlineKey, "asset reachable again");
  }

  // TLS certificate
  if (o.cert) {
    const c = o.cert;
    await tx`insert into check_results (asset_id, check_type, ok, detail, data)
             values (${asset.id}, 'tls', ${c.authorized && (c.daysLeft ?? 0) > 14},
                     ${c.authorized ? `valid, ${c.daysLeft} days left (${c.issuer ?? "unknown issuer"})` : `untrusted: ${c.authError}`},
                     ${tx.json(c as never)})`;
    const p = (rules.get("cert_expiring")?.params ?? {}) as { warn_days?: number; high_days?: number };
    if (c.daysLeft != null && c.daysLeft < (p.warn_days ?? 14)) {
      await raise({
        rule: "cert_expiring",
        title: c.daysLeft < 0 ? `TLS certificate expired: ${asset.name}` : `TLS certificate expires in ${c.daysLeft} days: ${asset.name}`,
        description: `Certificate for ${c.subject ?? asset.name} issued by ${c.issuer ?? "unknown"} expires ${c.validTo}.`,
        severity: c.daysLeft < (p.high_days ?? 3) ? "high" : undefined,
        source: "external", assetId: asset.id, dedupeKey: `cert-exp:${asset.id}`,
      });
    } else if (c.daysLeft != null) {
      await autoResolve(tx, `cert-exp:${asset.id}`, "certificate renewed");
    }
    if (!c.authorized && c.authError && !/CERT_HAS_EXPIRED/.test(c.authError)) {
      await raise({
        rule: "cert_invalid",
        title: `Untrusted TLS certificate: ${asset.name}`,
        description: `${c.authError}${c.selfSigned ? " (self-signed)" : ""}. Visitors see a browser warning and traffic can be intercepted.`,
        source: "external", assetId: asset.id, dedupeKey: `cert-bad:${asset.id}`,
      });
    } else if (c.authorized) {
      await autoResolve(tx, `cert-bad:${asset.id}`, "certificate trusted again");
    }
  }

  // Security headers (web assets only)
  const headers = (o as Outcome & { headers?: Record<string, string> }).headers;
  if (headers) {
    const missing = missingSecurityHeaders(headers, (asset.address ?? "").startsWith("https"));
    await tx`insert into check_results (asset_id, check_type, ok, detail) values (${asset.id}, 'headers', ${missing.length === 0}, ${missing.length ? `Missing: ${missing.join(", ")}` : "All present"})`;
    if (missing.length) {
      await raise({ rule: "missing_security_headers", title: `Missing security headers: ${asset.name}`, description: missing.join(", "), source: "external", assetId: asset.id, dedupeKey: `hdr:${asset.id}` });
    } else {
      await autoResolve(tx, `hdr:${asset.id}`, "headers present");
    }
  }

  // Risky exposed services
  const risky = new Set(((rules.get("risky_port_open")?.params as { ports?: number[] } | undefined)?.ports ?? []));
  const exposed = (o.openPorts ?? []).filter((p) => risky.has(p));
  await tx`insert into check_results (asset_id, check_type, ok, detail, data) values (${asset.id}, 'ports', ${exposed.length === 0},
           ${o.openPorts?.length ? `open: ${o.openPorts.join(", ")}` : "no common ports open"}, ${tx.json({ open: o.openPorts ?? [] })})`;
  for (const port of exposed) {
    await raise({ rule: "risky_port_open", title: `Port ${port} (${portName(port)}) exposed on ${asset.name}`, description: `${portName(port)} is reachable from the internet. Restrict it to VPN or trusted addresses.`, source: "external", assetId: asset.id, dedupeKey: `port:${asset.id}:${port}`, details: { port } });
  }
  for (const port of asset.open_ports ?? []) {
    if (risky.has(port) && !exposed.includes(port)) await autoResolve(tx, `port:${asset.id}:${port}`, "port closed");
  }

  // DNS changes (name servers and mail exchangers; A records churn too much behind CDNs)
  if (o.dns && asset.dns) {
    const changed = (["ns", "mx"] as const).filter((k) =>
      (asset.dns![k] ?? []).length > 0 && o.dns![k].length > 0 && JSON.stringify(asset.dns![k]) !== JSON.stringify(o.dns![k]));
    if (changed.length) {
      await raise({
        rule: "dns_changed",
        title: `DNS ${changed.map((c) => c.toUpperCase()).join("/")} records changed: ${asset.name}`,
        description: changed.map((k) => `${k.toUpperCase()}: ${asset.dns![k].join(", ") || "none"} → ${o.dns![k].join(", ") || "none"}`).join("; "),
        source: "external", assetId: asset.id, dedupeKey: `dns:${asset.id}:${changed.join("-")}:${changed.map((k) => o.dns![k].join(",")).join("|")}`,
      });
    }
  }
  return opened;
}

const PORT_NAMES: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 1521: "Oracle DB", 2375: "Docker API", 3306: "MySQL",
  3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
};
export const portName = (p: number) => PORT_NAMES[p] ?? `port ${p}`;
