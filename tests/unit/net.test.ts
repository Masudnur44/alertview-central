import { test } from "node:test";
import assert from "node:assert/strict";
import { isPrivateAddress, missingSecurityHeaders, parseTarget } from "../../src/server/monitor/net.server";

test("private, reserved and metadata addresses are blocked", () => {
  for (const ip of ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
    "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "not-an-ip"]) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
  for (const ip of ["8.8.8.8", "41.90.12.34", "172.32.0.1", "2606:4700::1111"]) assert.equal(isPrivateAddress(ip), false, ip);
});

test("asset addresses are parsed into probe targets", () => {
  assert.deepEqual({ ...parseTarget("https://api.finpaytech.com/health")!, url: undefined }, { host: "api.finpaytech.com", port: 443, url: undefined });
  assert.deepEqual(parseTarget("vpn.finpaytech.com:443"), { host: "vpn.finpaytech.com", port: 443, url: null });
  assert.deepEqual(parseTarget("41.90.12.34"), { host: "41.90.12.34", port: null, url: null });
  assert.deepEqual(parseTarget("[2606:4700::1]:22"), { host: "2606:4700::1", port: 22, url: null });
  assert.equal(parseTarget("not a host"), null);
});

test("security header check", () => {
  assert.deepEqual(missingSecurityHeaders({}, true), ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"]);
  assert.deepEqual(missingSecurityHeaders({}, false), ["content-security-policy", "x-frame-options", "x-content-type-options"]);
  assert.deepEqual(missingSecurityHeaders({ "content-security-policy": "frame-ancestors 'none'", "x-content-type-options": "nosniff", "strict-transport-security": "max-age=1" }, true), []);
});
