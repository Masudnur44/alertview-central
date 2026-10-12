// Vulnerability risk score (0-100): severity/CVSS, active exploitation, exposure,
// asset criticality and live alert activity on the same asset.
export function riskScore(v: {
  cvss: number | null;
  severity?: string;
  exploited_in_wild: boolean;
  internet_exposed: boolean;
  criticality?: string | null;
  open_alerts?: number;
  overdue?: boolean;
}) {
  const fallback = { critical: 9, high: 7.5, medium: 5, low: 3, info: 1 }[v.severity ?? "medium"] ?? 5;
  let s = Number(v.cvss ?? fallback) * 10;
  if (v.exploited_in_wild) s += 25;
  if (v.internet_exposed) s += 15;
  if (v.criticality === "critical") s += 15;
  else if (v.criticality === "high") s += 8;
  if (v.open_alerts) s += 10;
  if (v.overdue) s += 5;
  return Math.min(100, Math.round(s));
}

export function downloadCsv(filename: string, rows: (string | number | null | undefined)[][]) {
  const esc = (v: string | number | null | undefined) => {
    const s = v == null ? "" : String(v);
    // Neutralise spreadsheet formula injection and quote when needed.
    const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
    return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  const blob = new Blob([rows.map((r) => r.map(esc).join(",")).join("\n")], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
