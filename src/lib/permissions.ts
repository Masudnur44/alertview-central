// Who may do what. Shared by server (enforcement) and UI (hiding controls).
// The database enforces the same rules again with row-level security.
export type Role = "security_admin" | "security_analyst" | "security_manager" | "system_admin" | "management" | "auditor" | "developer";

export const ROLES: { value: Role; label: string; blurb: string }[] = [
  { value: "security_admin", label: "Security Administrator", blurb: "Full control, users, keys, channels" },
  { value: "security_manager", label: "Security Manager", blurb: "Triage, tune detections, read audit" },
  { value: "security_analyst", label: "Security Analyst", blurb: "Triage alerts, run incidents" },
  { value: "system_admin", label: "System Administrator", blurb: "Assets, event sources, checks" },
  { value: "management", label: "Management", blurb: "Read-only dashboards and reports" },
  { value: "auditor", label: "Auditor", blurb: "Read-only plus the audit trail" },
  { value: "developer", label: "Developer", blurb: "Sees and updates only their team's issues" },
];

const ALL: Role[] = ROLES.map((r) => r.value).filter((r) => r !== "developer");
const OPS: Role[] = ["security_admin", "security_analyst", "security_manager", "system_admin"];

export const PERMISSIONS = {
  view: ALL,
  "alerts.triage": OPS,
  "incidents.manage": OPS,
  "vulns.manage": OPS,
  "checks.run": OPS,
  "issues.send": OPS,
  "dev.issues": ["developer"],
  "teams.manage": ["security_admin", "security_manager", "system_admin"],
  "assets.manage": ["security_admin", "security_manager", "system_admin"],
  "domains.manage": ["security_admin", "security_manager", "system_admin"],
  "rules.manage": ["security_admin", "security_manager"],
  "intel.manage": ["security_admin", "security_manager"],
  "sources.manage": ["security_admin", "system_admin"],
  "channels.manage": ["security_admin"],
  "users.manage": ["security_admin"],
  "settings.manage": ["security_admin"],
  "data.delete": ["security_admin"],
  "audit.view": ["security_admin", "security_manager", "auditor"],
} satisfies Record<string, Role[]>;

export type Permission = keyof typeof PERMISSIONS;

export function can(roles: readonly string[] | undefined, perm: Permission): boolean {
  if (!roles?.length) return false;
  return (PERMISSIONS[perm] as readonly string[]).some((r) => roles.includes(r));
}

export function roleLabel(role: string): string {
  return ROLES.find((r) => r.value === role)?.label ?? role;
}
