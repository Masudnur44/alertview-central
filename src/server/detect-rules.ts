// Pure, per-event detection logic (no database) so it can be unit-tested.
// Aggregate rules (brute force, spraying) live in detect.server.ts.

export type IncomingEvent = {
  event_type: string;
  host?: string | null;
  username?: string | null;
  src_ip?: string | null;
  outcome?: string | null;
  message?: string | null;
  occurred_at?: string;
  raw?: Record<string, unknown> | null;
};

export type SingleMatch = {
  rule: string;
  title: string;
  description: string;
  dedupeKey: string;
  severity?: "critical" | "high" | "medium" | "low";
};

const OFFICE_PARENT = /(winword|excel|powerpnt|outlook|onenote|msaccess|mspub|acrord32|acrobat|chrome|msedge|firefox)(\.exe)?/i;
const SCRIPT_CHILD = /(^|[\\/\s"'>])(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|bash|sh)(\.exe)?(?=$|[\s"'])/i;
const ENCODED_PS = /powershell(\.exe)?[^\n]*\s-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/i;
const PS_DOWNLOAD_CRADLE = /(iex|invoke-expression)[\s(]+.*(downloadstring|invoke-webrequest|iwr|net\.webclient)/i;
const LOLBIN = [
  /certutil(\.exe)?\s.*-(urlcache|verifyctl)\b.*https?:\/\//i,
  /bitsadmin(\.exe)?\s.*\/transfer\b/i,
  /mshta(\.exe)?\s+["']?(https?:|javascript:|vbscript:)/i,
  /regsvr32(\.exe)?\s.*\/i:\s*https?:\/\//i,
  /rundll32(\.exe)?\s.*javascript:/i,
  /(curl|wget)\s.*https?:\/\/\S+\s*\|\s*(ba)?sh\b/i,
];
const ADMIN_GROUP = /\b(administrators|domain admins|enterprise admins|schema admins|sudo|wheel|admin)\b/i;

export function commandLine(e: IncomingEvent): string {
  const raw = e.raw ?? {};
  const fromRaw = [raw.command_line, raw.CommandLine, raw.cmdline, raw.parent_image, raw.ParentImage, raw.image, raw.Image]
    .filter((v) => typeof v === "string")
    .join(" ");
  return `${e.message ?? ""} ${fromRaw}`.trim();
}

export function hourIn(timeZone: string, iso?: string): number {
  const d = iso ? new Date(iso) : new Date();
  const h = new Intl.DateTimeFormat("en-GB", { hour: "numeric", hourCycle: "h23", timeZone }).format(d);
  return Number(h) % 24;
}

export function isOffHours(hour: number, startHour: number, endHour: number): boolean {
  // Business hours are [start, end). Supports windows that cross midnight.
  return startHour <= endHour ? hour < startHour || hour >= endHour : hour >= endHour && hour < startHour;
}

type Params = Record<string, unknown>;

export function matchSingleEvent(e: IncomingEvent, params: Record<string, Params>, timeZone: string): SingleMatch[] {
  const out: SingleMatch[] = [];
  const host = e.host ?? "unknown host";
  const type = e.event_type.toLowerCase();

  if (type === "auth.login" && e.outcome === "success" && e.username) {
    const p = params.offhours_privileged_login ?? {};
    const pattern = new RegExp(String(p.user_pattern ?? "admin|root|svc_|administrator"), "i");
    const hour = hourIn(timeZone, e.occurred_at);
    if (pattern.test(e.username) && isOffHours(hour, Number(p.start_hour ?? 6), Number(p.end_hour ?? 22))) {
      out.push({
        rule: "offhours_privileged_login",
        title: `Privileged login outside business hours: ${e.username}`,
        description: `${e.username} signed in to ${host} at ${String(hour).padStart(2, "0")}:00 local time from ${e.src_ip ?? "an unknown address"}.`,
        dedupeKey: `offhours:${host}:${e.username}`,
      });
    }
  }

  if (type === "process.start") {
    const cmd = commandLine(e);
    const parentChild = OFFICE_PARENT.test(cmd) && SCRIPT_CHILD.test(cmd.replace(OFFICE_PARENT, ""));
    if (parentChild || ENCODED_PS.test(cmd) || PS_DOWNLOAD_CRADLE.test(cmd)) {
      out.push({
        rule: "suspicious_process",
        title: `Suspicious process on ${host}`,
        description: cmd.slice(0, 1000),
        dedupeKey: `proc:${host}:${(e.username ?? "").toLowerCase()}`,
      });
    }
    if (LOLBIN.some((re) => re.test(cmd))) {
      out.push({
        rule: "lolbin_download",
        title: `Living-off-the-land download on ${host}`,
        description: cmd.slice(0, 1000),
        dedupeKey: `lolbin:${host}`,
      });
    }
  }

  if ((type === "account.created" || type === "group.member_added") && ADMIN_GROUP.test(`${e.message ?? ""} ${JSON.stringify(e.raw ?? {})}`)) {
    out.push({
      rule: "new_admin_account",
      title: `New privileged account on ${host}: ${e.username ?? "unknown"}`,
      description: e.message ?? "Account added to a privileged group",
      dedupeKey: `admin-acct:${host}:${(e.username ?? "").toLowerCase()}`,
    });
  }

  if (type === "log.cleared") {
    out.push({
      rule: "log_cleared",
      title: `Security log cleared on ${host}`,
      description: `${e.username ?? "Someone"} cleared the log. ${e.message ?? ""}`.trim(),
      dedupeKey: `logclear:${host}`,
    });
  }

  if (type === "service.installed") {
    out.push({
      rule: "new_service",
      title: `New service installed on ${host}`,
      description: e.message ?? "A new service was installed",
      dedupeKey: `service:${host}:${(e.message ?? "").slice(0, 80)}`,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Wazuh alert mapping
// ---------------------------------------------------------------------------
export type WazuhAlert = {
  id?: string;
  timestamp?: string;
  rule?: { id?: string | number; level?: number; description?: string; groups?: string[]; mitre?: { id?: string[]; tactic?: string[]; technique?: string[] } };
  agent?: { id?: string; name?: string; ip?: string };
  data?: Record<string, unknown>;
  full_log?: string;
};

export function wazuhSeverity(level: number): "critical" | "high" | "medium" | "low" | "info" {
  if (level >= 13) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  if (level >= 4) return "low";
  return "info";
}

export function wazuhToEvent(a: WazuhAlert): IncomingEvent {
  const d = a.data ?? {};
  const str = (v: unknown) => (typeof v === "string" && v ? v : null);
  const groups = a.rule?.groups ?? [];
  const isAuth = groups.some((g) => /authentication/.test(g));
  return {
    event_type: isAuth ? "auth.login" : "wazuh.alert",
    host: a.agent?.name ?? null,
    username: str(d.dstuser) ?? str(d.srcuser) ?? str((d.win as { eventdata?: { targetUserName?: string } } | undefined)?.eventdata?.targetUserName),
    src_ip: str(d.srcip),
    outcome: groups.some((g) => /authentication_fail|authentication_failures|invalid_login/.test(g)) ? "failure"
      : groups.some((g) => /authentication_success/.test(g)) ? "success" : null,
    message: `${a.rule?.description ?? "Wazuh alert"}${a.full_log ? ` — ${a.full_log.slice(0, 1500)}` : ""}`,
    occurred_at: a.timestamp ? new Date(a.timestamp).toISOString() : undefined,
    raw: a as Record<string, unknown>,
  };
}
