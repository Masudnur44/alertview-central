import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { can } from "../../src/lib/permissions";
import { jobResultOk, isMonitoringEligible } from "../../src/server/monitor/policy";
import { notificationRetry } from "../../src/server/notify.server";

const migration = fs.readFileSync(path.resolve(process.cwd(), "db/migrations/0003_monitoring_approval.sql"), "utf8");

test("monitoring eligibility requires approval, monitoring, external scope, and a live asset", () => {
  const base = { monitoring_approved: true, monitored: true, exposure: "external", status: "unknown" };
  assert.equal(isMonitoringEligible(base), true);
  assert.equal(isMonitoringEligible({ ...base, monitoring_approved: false }), false);
  assert.equal(isMonitoringEligible({ ...base, monitored: false }), false);
  assert.equal(isMonitoringEligible({ ...base, exposure: "internal" }), false);
  assert.equal(isMonitoringEligible({ ...base, status: "retired" }), false);
});

test("asset management permission excludes read-only roles", () => {
  assert.equal(can(["security_admin"], "assets.manage"), true);
  assert.equal(can(["system_admin"], "assets.manage"), true);
  assert.equal(can(["management"], "assets.manage"), false);
  assert.equal(can(["auditor"], "assets.manage"), false);
});

test("job results distinguish success from partial and complete check failure", () => {
  assert.equal(jobResultOk({ checked: 2, failed: 0, failures: [] }), true);
  assert.equal(jobResultOk({ checked: 2, failed: 1, failures: [{ assetId: "a", name: "A", error: "timeout" }] }), false);
  assert.equal(jobResultOk({ checked: 0, failed: 2, failures: [] }), false);
});

test("notification retries use bounded backoff and eventually stop", () => {
  assert.deepEqual(notificationRetry(1), { giveUp: false, delayMinutes: 1 });
  assert.deepEqual(notificationRetry(3), { giveUp: false, delayMinutes: 15 });
  assert.deepEqual(notificationRetry(5), { giveUp: false, delayMinutes: 180 });
  assert.deepEqual(notificationRetry(6), { giveUp: true, delayMinutes: 180 });
});

test("approval migration defaults assets to unapproved and enforces the monitoring gate", () => {
  assert.match(migration, /monitoring_approved boolean not null default false/);
  assert.match(migration, /assets_monitoring_approval_consistent/);
  assert.match(migration, /asset monitoring requires explicit approval/);
  assert.match(migration, /new\.monitored := false/);
});
