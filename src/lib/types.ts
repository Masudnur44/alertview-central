// Row shapes returned by the server functions (timestamps are ISO strings).
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Asset = {
  id: string;
  name: string;
  asset_type: string;
  address: string | null;
  environment: string;
  owner: string | null;
  criticality: Severity;
  status: string;
  exposure: "internal" | "external";
  monitored: boolean;
  monitoring_approved: boolean;
  team_id: string | null;
  is_new: boolean;
  discovered_via: string | null;
  tags: string[];
  notes: string | null;
  tls_expires_at: string | null;
  tls_issuer: string | null;
  tls_subject: string | null;
  http_status: number | null;
  response_ms: number | null;
  open_ports: number[];
  dns: { a: string[]; aaaa: string[]; ns: string[]; mx: string[]; cname: string[] } | null;
  last_checked_at: string | null;
  last_seen: string | null;
  created_at: string;
  open_alerts?: number;
  open_vulns?: number;
};

export type Alert = {
  id: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: string;
  source: string;
  asset_id: string | null;
  asset_name: string | null;
  rule_id: string | null;
  rule_name: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  assignee: string | null;
  assignee_name: string | null;
  incident_id: string | null;
  incident_ref: string | null;
  event_count: number;
  details: Record<string, unknown> | null;
  detected_at: string;
  last_seen_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
};

export type Incident = {
  id: string;
  ref: string;
  title: string;
  summary: string | null;
  severity: Severity;
  status: string;
  owner: string | null;
  owner_name: string | null;
  opened_at: string;
  triaged_at: string | null;
  contained_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  alert_count?: number;
};

export type IncidentEvent = { id: string; kind: string; body: string; author_name: string | null; created_at: string };

export type Vulnerability = {
  id: string;
  title: string;
  cve: string | null;
  description: string | null;
  remediation: string | null;
  severity: Severity;
  cvss: number | null;
  asset_id: string | null;
  asset_name: string | null;
  asset_criticality: Severity | null;
  status: string;
  exploited_in_wild: boolean;
  internet_exposed: boolean;
  due_at: string | null;
  first_seen: string;
  fixed_at: string | null;
  open_alerts: number;
};

export type SocEvent = {
  id: string;
  event_type: string;
  host: string | null;
  username: string | null;
  src_ip: string | null;
  outcome: string | null;
  message: string | null;
  ti_match: string | null;
  source_name: string | null;
  occurred_at: string;
};

export type CheckResult = { id: string; asset_id: string; check_type: string; ok: boolean; detail: string | null; response_ms: number | null; checked_at: string };

export type TeamMember = {
  id: string;
  email: string;
  display_name: string;
  status: "pending" | "active" | "disabled";
  email_verified: boolean;
  mfa_enabled: boolean;
  roles: string[];
  last_login_at: string | null;
  created_at: string;
  approved_at: string | null;
  team_id: string | null;
};

/** Diagnosis brief handed to developers. */
export type Brief = {
  summary: string;
  meaning: string;
  impact: string;
  where: { label: string; value: string }[];
  when: { label: string; value: string }[];
  evidence: { label: string; value: string }[];
  checks: { at: string; ok: boolean; detail: string; ms: number | null }[];
  events: { at: string; type: string; user: string | null; ip: string | null; outcome: string | null; message: string | null }[];
  causes: string[];
  whereToLook: string[];
  fix: string[];
  verify: string;
  technique: string | null;
};

export type DevIssue = {
  id: string; ref: string; title: string; severity: string; status: string; due_at: string | null; created_at: string;
  team_name: string | null; asset_name: string | null; brief: Brief;
  updates: { kind: string; body: string; author: string; created_at: string }[];
};
