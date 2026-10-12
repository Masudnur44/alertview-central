import { test } from "node:test";
import assert from "node:assert/strict";
import { FEEDS } from "../../src/server/intel.server";
import { hostnamesFromCt } from "../../src/server/monitor/discovery.server";
import { can } from "../../src/lib/permissions";

const feed = (s: string) => FEEDS.find((f) => f.source === s)!;

test("threat-intel feed parsers", () => {
  assert.deepEqual(feed("cisa_kev").parse(JSON.stringify({ vulnerabilities: [{ cveID: "CVE-2024-6387", vulnerabilityName: "OpenSSH" }, { cveID: "bogus" }] })).map((i) => i.value), ["CVE-2024-6387"]);
  assert.deepEqual(feed("feodo").parse(JSON.stringify([{ ip_address: "45.9.148.3", malware: "QakBot" }, { ip_address: "x" }])).map((i) => i.network), ["45.9.148.3/32"]);
  assert.deepEqual(feed("spamhaus_drop").parse('{"cidr":"1.10.16.0/20","sblid":"SBL256894"}\n{"type":"metadata","timestamp":1}\n').map((i) => i.value), ["1.10.16.0/20"]);
  assert.deepEqual(feed("tor_exit").parse("1.2.3.4\nnot-ip\n5.6.7.8\n").map((i) => i.value), ["1.2.3.4", "5.6.7.8"]);
});

test("certificate-transparency hostnames are normalised and scoped to the root domain", () => {
  const hosts = hostnamesFromCt([
    { name_value: "*.finpaytech.com\nfinpaytech.com", common_name: "finpaytech.com" },
    { name_value: "staging-api.finpaytech.com\nPortal.FinpayTech.com." },
    { name_value: "evil-finpaytech.com\nfinpaytech.com.attacker.net\nuser@finpaytech.com" },
  ], "finpaytech.com");
  assert.deepEqual(hosts, ["finpaytech.com", "portal.finpaytech.com", "staging-api.finpaytech.com"]);
});

test("permission matrix", () => {
  assert.equal(can(["security_analyst"], "alerts.triage"), true);
  assert.equal(can(["security_analyst"], "assets.manage"), false);
  assert.equal(can(["security_analyst"], "rules.manage"), false);
  assert.equal(can(["management"], "alerts.triage"), false);
  assert.equal(can(["management"], "view"), true);
  assert.equal(can(["auditor"], "audit.view"), true);
  assert.equal(can(["system_admin"], "sources.manage"), true);
  assert.equal(can(["system_admin"], "users.manage"), false);
  assert.equal(can([], "view"), false);
});
