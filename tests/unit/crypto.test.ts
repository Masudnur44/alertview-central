import { test } from "node:test";
import assert from "node:assert/strict";
import * as c from "../../src/server/crypto.server";

test("TOTP matches RFC 6238 test vectors", () => {
  const secret = c.base32Encode(Buffer.from("12345678901234567890"));
  assert.equal(c.totpAt(secret, Math.floor(59 / 30)), "287082");
  assert.equal(c.totpAt(secret, Math.floor(1111111109 / 30)), "081804");
  assert.equal(c.totpAt(secret, Math.floor(2000000000 / 30)), "279037");
});

test("TOTP verification allows ±1 step and blocks replay", () => {
  const s = c.newTotpSecret();
  const now = Date.now();
  const step = Math.floor(now / 30000);
  assert.equal(c.verifyTotp(s, c.totpAt(s, step - 1), null, now), step - 1);
  assert.equal(c.verifyTotp(s, c.totpAt(s, step), step, now), null);
  assert.equal(c.verifyTotp(s, c.totpAt(s, step - 3), null, now), null);
  assert.equal(c.verifyTotp(s, "12ab56", null, now), null);
});

test("scrypt password hashing", async () => {
  const h = await c.hashPassword("Correct-Horse-9-Battery");
  assert.match(h, /^scrypt\$32768\$8\$1\$/);
  assert.equal(await c.verifyPassword("Correct-Horse-9-Battery", h), true);
  assert.equal(await c.verifyPassword("wrong", h), false);
  assert.equal(await c.verifyPassword("anything", null), false);
});

test("password policy", () => {
  assert.ok(c.passwordProblems("short"));
  assert.ok(c.passwordProblems("alllowercaseletters"));
  assert.ok(c.passwordProblems("Masud-Strong-2026", "masud@finpaytech.com"));
  assert.ok(c.passwordProblems("Finpay-Rocks-2026"));
  assert.equal(c.passwordProblems("Blue-Ocean-Tiger-77", "amina@finpaytech.com"), null);
});

test("AES-GCM sealing and signing", () => {
  const secret = "k".repeat(40);
  const sealed = c.encrypt("webhook-token", secret, "channel");
  assert.equal(c.decrypt(sealed, secret, "channel"), "webhook-token");
  assert.throws(() => c.decrypt(sealed, secret, "totp"));
  assert.throws(() => c.decrypt(sealed, "z".repeat(40), "channel"));
  assert.equal(c.unsign(c.sign("state", secret), secret), "state");
  assert.equal(c.unsign(c.sign("state", secret) + "x", secret), null);
});

test("ingest keys are random and only the hash is meant to be stored", () => {
  const a = c.newIngestKey();
  const b = c.newIngestKey();
  assert.match(a.key, /^soc_[0-9a-f]{40}$/);
  assert.notEqual(a.key, b.key);
  assert.equal(a.hash, c.sha256(a.key));
  assert.equal(a.prefix, a.key.slice(0, 10));
});
