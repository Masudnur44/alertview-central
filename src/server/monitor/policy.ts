export type MonitoringAsset = {
  monitoring_approved: boolean;
  monitored: boolean;
  exposure: string;
  status: string;
};

export function isMonitoringEligible(asset: MonitoringAsset): boolean {
  return asset.monitoring_approved && asset.monitored && asset.exposure === "external" && asset.status !== "retired";
}

export type CheckFailure = { assetId: string; name: string; error: string };

export type CheckRunSummary = {
  checked: number;
  alerts: number;
  failed: number;
  failures: CheckFailure[];
};

export function jobResultOk(detail: unknown): boolean {
  if (!detail || typeof detail !== "object") return true;
  const result = detail as { failed?: unknown };
  return typeof result.failed !== "number" || result.failed === 0;
}
