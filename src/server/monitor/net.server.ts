// Network probes for external-surface monitoring, with SSRF protection.
//
// Every probe resolves the hostname itself, refuses private/reserved addresses
// (unless ALLOW_PRIVATE_TARGETS is set), and then connects to that exact address,
// so a DNS answer cannot be swapped between the check and the connection.
import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import https from "node:https";
import http from "node:http";
import type { DetailedPeerCertificate, PeerCertificate, TLSSocket } from "node:tls";

// ---------------------------------------------------------------------------
// Address classification
// ---------------------------------------------------------------------------
function v4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

const V4_BLOCKED: [string, number][] = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

export function isPrivateAddress(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const n = v4ToInt(ip);
    return V4_BLOCKED.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      return (n & mask) === (v4ToInt(base) & mask);
    });
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateAddress(mapped[1]!);
    if (lower === "::" || lower === "::1") return true;
    const first = parseInt(lower.split(":")[0] || "0", 16);
    if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
    if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link local
    if ((first & 0xff00) === 0xff00) return true; // multicast
    if (lower.startsWith("2001:db8")) return true; // documentation
    if (lower.startsWith("64:ff9b:")) return true; // NAT64 can reach internal v4
    return false;
  }
  return true; // not an IP at all: treat as unsafe
}

export class BlockedTargetError extends Error {}

export async function resolveTarget(host: string, allowPrivate: boolean): Promise<string[]> {
  const bare = host.replace(/^\[|\]$/g, "");
  let addrs: string[];
  if (net.isIP(bare)) {
    addrs = [bare];
  } else {
    const results = await Promise.allSettled([dns.resolve4(bare), dns.resolve6(bare)]);
    addrs = results.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
    if (!addrs.length) {
      // Fall back to the system resolver (handles /etc/hosts and search domains).
      addrs = (await dns.lookup(bare, { all: true })).map((a) => a.address);
    }
  }
  if (!addrs.length) throw new Error("does not resolve");
  if (!allowPrivate) {
    const bad = addrs.filter(isPrivateAddress);
    if (bad.length) throw new BlockedTargetError(`resolves to a private/reserved address (${bad.join(", ")})`);
  }
  return addrs;
}

// ---------------------------------------------------------------------------
// Target parsing: "https://x/y", "host:port", "1.2.3.4", "host"
// ---------------------------------------------------------------------------
export type Target = { host: string; port: number | null; url: URL | null };

export function parseTarget(address: string): Target | null {
  const a = address.trim();
  if (!a) return null;
  if (/^https?:\/\//i.test(a)) {
    try {
      const url = new URL(a);
      return { host: url.hostname, port: url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80, url };
    } catch {
      return null;
    }
  }
  const v6 = a.match(/^\[([0-9a-f:]+)\](?::(\d+))?$/i);
  if (v6) return { host: v6[1]!, port: v6[2] ? Number(v6[2]) : null, url: null };
  const m = a.match(/^([a-z0-9.-]+)(?::(\d{1,5}))?$/i);
  if (!m) return net.isIP(a) ? { host: a, port: null, url: null } : null;
  return { host: m[1]!.toLowerCase(), port: m[2] ? Number(m[2]) : null, url: null };
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------
export type CertInfo = {
  subject: string | null;
  issuer: string | null;
  validTo: string | null;
  daysLeft: number | null;
  altNames: string[];
  authorized: boolean;
  authError: string | null;
  selfSigned: boolean;
  protocol: string | null;
};

function describeCert(sock: TLSSocket, cert: PeerCertificate): CertInfo {
  const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : null;
  const pick = (o: unknown) => {
    const rec = (o ?? {}) as Record<string, string | string[]>;
    const v = rec.CN ?? rec.O;
    return Array.isArray(v) ? v[0] ?? null : v ?? null;
  };
  const subject = pick(cert.subject);
  const issuer = pick(cert.issuer);
  return {
    subject,
    issuer,
    validTo,
    daysLeft: validTo ? Math.floor((new Date(validTo).getTime() - Date.now()) / 864e5) : null,
    altNames: (cert.subjectaltname ?? "").split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter(Boolean),
    authorized: sock.authorized,
    authError: sock.authorizationError ? String(sock.authorizationError) : null,
    selfSigned: Boolean(cert.fingerprint256 && (cert as DetailedPeerCertificate).issuerCertificate?.fingerprint256 === cert.fingerprint256),
    protocol: sock.getProtocol?.() ?? null,
  };
}

export type HttpResult = {
  ok: boolean;
  status: number | null;
  statusText: string;
  ms: number;
  finalUrl: string;
  headers: Record<string, string>;
  cert: CertInfo | null;
  error: string | null;
};

type Pinned = { address: string; family: number };

function requestOnce(url: URL, pinned: Pinned, timeoutMs: number): Promise<{ status: number; statusText: string; headers: Record<string, string>; cert: CertInfo | null; location: string | null }> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const mod = isHttps ? https : http;
    const req = mod.request(
      {
        method: "GET",
        host: url.hostname,
        servername: net.isIP(url.hostname) ? undefined : url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        headers: { "user-agent": "FINPAY-SOC-Monitor/1.0", accept: "*/*" },
        timeout: timeoutMs,
        // Connect to the address we already validated, not whatever DNS says now.
        lookup: (_h: string, opts: unknown, cb: (...a: unknown[]) => void) => {
          if (opts && typeof opts === "object" && (opts as { all?: boolean }).all) cb(null, [pinned]);
          else cb(null, pinned.address, pinned.family);
        },
        rejectUnauthorized: false, // we inspect and report certificate problems ourselves
        agent: false,
      } as https.RequestOptions,
      (res) => {
        let cert: CertInfo | null = null;
        if (isHttps) {
          const sock = res.socket as TLSSocket;
          const peer = sock.getPeerCertificate?.(true);
          if (peer && Object.keys(peer).length) cert = describeCert(sock, peer);
        }
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) if (v != null) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
        res.resume(); // discard body
        res.on("end", () => resolve({ status: res.statusCode ?? 0, statusText: res.statusMessage ?? "", headers, cert, location: headers.location ?? null }));
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })));
    req.on("error", reject);
    req.end();
  });
}

/** GET a URL, following up to 5 redirects; every hop is re-validated against the SSRF rules. */
export async function httpProbe(start: string, opts: { allowPrivate: boolean; timeoutMs?: number }): Promise<HttpResult> {
  const t0 = Date.now();
  let url = new URL(start);
  let firstCert: CertInfo | null = null;
  try {
    for (let hop = 0; hop < 6; hop++) {
      if (!["http:", "https:"].includes(url.protocol)) throw new BlockedTargetError(`unsupported protocol ${url.protocol}`);
      const [address] = await resolveTarget(url.hostname, opts.allowPrivate);
      const r = await requestOnce(url, { address: address!, family: net.isIPv6(address!) ? 6 : 4 }, opts.timeoutMs ?? 10_000);
      if (hop === 0) firstCert = r.cert;
      if (r.status >= 300 && r.status < 400 && r.location && hop < 5) {
        url = new URL(r.location, url);
        continue;
      }
      return {
        ok: r.status > 0 && r.status < 500,
        status: r.status,
        statusText: r.statusText,
        ms: Date.now() - t0,
        finalUrl: url.toString(),
        headers: r.headers,
        cert: firstCert ?? r.cert,
        error: null,
      };
    }
    throw new Error("too many redirects");
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    const reason =
      e instanceof BlockedTargetError ? `blocked: ${err.message}`
      : err.code === "ETIMEDOUT" || err.message === "timeout" ? "timeout"
      : err.code === "ECONNREFUSED" ? "connection refused"
      : err.code === "ENOTFOUND" || err.message === "does not resolve" ? "does not resolve"
      : err.code ?? err.message;
    return { ok: false, status: null, statusText: "", ms: Date.now() - t0, finalUrl: url.toString(), headers: {}, cert: firstCert, error: reason };
  }
}

/** TLS handshake against host:port to read the certificate (for non-HTTP services such as VPN or mail). */
export async function tlsProbe(host: string, port: number, opts: { allowPrivate: boolean; timeoutMs?: number }): Promise<CertInfo | { error: string }> {
  try {
    const [address] = await resolveTarget(host, opts.allowPrivate);
    return await new Promise((resolve) => {
      const sock = tls.connect({ host: address!, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: opts.timeoutMs ?? 8000 });
      sock.once("secureConnect", () => {
        const info = describeCert(sock, sock.getPeerCertificate(true));
        if (!net.isIP(host)) {
          const hostErr = tls.checkServerIdentity(host, sock.getPeerCertificate());
          if (hostErr && info.authorized) {
            info.authorized = false;
            info.authError = hostErr.message;
          }
        }
        sock.end();
        resolve(info);
      });
      sock.once("timeout", () => { sock.destroy(); resolve({ error: "timeout" }); });
      sock.once("error", (e: NodeJS.ErrnoException) => resolve({ error: e.code ?? e.message }));
    });
  } catch (e) {
    return { error: (e as Error).message };
  }
}

/** TCP connect scan of a short list of ports. Returns the ports that accepted a connection. */
export async function portProbe(host: string, ports: number[], opts: { allowPrivate: boolean; timeoutMs?: number }): Promise<{ open: number[]; address: string | null; error?: string }> {
  let address: string;
  try {
    [address] = (await resolveTarget(host, opts.allowPrivate)) as [string];
  } catch (e) {
    return { open: [], address: null, error: (e as Error).message };
  }
  const check = (port: number) =>
    new Promise<number | null>((resolve) => {
      const s = net.connect({ host: address, port });
      const done = (v: number | null) => { s.destroy(); resolve(v); };
      s.setTimeout(opts.timeoutMs ?? 2500, () => done(null));
      s.once("connect", () => done(port));
      s.once("error", () => done(null));
    });
  const open: number[] = [];
  for (let i = 0; i < ports.length; i += 8) {
    const batch = await Promise.all(ports.slice(i, i + 8).map(check));
    open.push(...batch.filter((p): p is number => p != null));
  }
  return { open: open.sort((a, b) => a - b), address };
}

export type DnsSnapshot = { a: string[]; aaaa: string[]; ns: string[]; mx: string[]; cname: string[] };

export async function dnsSnapshot(host: string): Promise<DnsSnapshot> {
  const get = async <T,>(p: Promise<T[]>, map: (v: T) => string) => {
    try {
      return (await p).map(map).map((s) => s.toLowerCase().replace(/\.$/, "")).sort();
    } catch {
      return [];
    }
  };
  const [a, aaaa, ns, mx, cname] = await Promise.all([
    get(dns.resolve4(host), String),
    get(dns.resolve6(host), String),
    get(dns.resolveNs(host), String),
    get(dns.resolveMx(host), (m) => m.exchange),
    get(dns.resolveCname(host), String),
  ]);
  return { a, aaaa, ns, mx, cname };
}

export const SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"] as const;

export function missingSecurityHeaders(headers: Record<string, string>, isHttps: boolean): string[] {
  return SECURITY_HEADERS.filter((h) => {
    if (h === "strict-transport-security" && !isHttps) return false;
    if (h === "x-frame-options" && /frame-ancestors/i.test(headers["content-security-policy"] ?? "")) return false;
    return !headers[h];
  });
}
