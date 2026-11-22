import { test } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { FetchError } from "../src/crl-fetch.ts";
import { CrlCache, checkRevocation, skipRevocationCheck } from "../src/revocation.ts";
import type { CachedCrl } from "../src/revocation.ts";

const fixtures = new URL("./fixtures/", import.meta.url);
const file = (name: string) => readFileSync(new URL(name, fixtures));
const cert = (name: string) => new X509Certificate(file(name));

const rootCrl = file("root.crl");
const ca = cert("ca-cert.pem");
const crlLeaf = cert("crl-leaf-cert.pem");
const revokedLeaf = cert("revoked-leaf-cert.pem");
const now = new Date("2030-01-01T00:00:00Z");
const DAY = 24 * 60 * 60 * 1000;

// A fake download that returns `body` (or throws it) and counts calls.
function fakeFetch(body: Buffer | Error = rootCrl) {
  const fake = {
    calls: [] as string[],
    fetchCrl: async (url: string) => {
      fake.calls.push(url);
      if (body instanceof Error) throw body;
      return body;
    },
  };
  return fake;
}

test("a certificate not on the CRL passes", async () => {
  const fake = fakeFetch();
  const result = await checkRevocation(crlLeaf, ca, now, fake, new CrlCache());
  assert.deepEqual(result, { id: "revoked", status: "pass", message: "Not on the CA's revocation list" });
  assert.deepEqual(fake.calls, ["http://crl.test.example/root.crl"]);
});

test("a certificate on the CRL fails with the revocation date", async () => {
  const result = await checkRevocation(revokedLeaf, ca, now, fakeFetch(), new CrlCache());
  assert.equal(result.status, "fail");
  assert.match(result.message ?? "", /^The CA revoked this certificate on \d{4}-\d{2}-\d{2}$/);
});

const tampered = Buffer.from(rootCrl);
tampered[tampered.length - 1]! ^= 0x01;

const skips: [string, () => ReturnType<typeof checkRevocation>, string][] = [
  ["self-signed", () => checkRevocation(cert("test-cert.pem"), undefined, now, fakeFetch(), new CrlCache()), "certificate is self-signed"],
  ["no CRL URL", () => checkRevocation(cert("leaf-cert.pem"), ca, now, fakeFetch(), new CrlCache()), "the certificate lists no CRL (the CA may only offer OCSP)"],
  ["no issuer", () => checkRevocation(crlLeaf, undefined, now, fakeFetch(), new CrlCache()), "the issuer certificate isn't available"],
  ["HTTP error", () => checkRevocation(crlLeaf, ca, now, fakeFetch(new FetchError("HTTP 404")), new CrlCache()), "couldn't download the CRL (HTTP 404)"],
  ["other download error", () => checkRevocation(crlLeaf, ca, now, fakeFetch(new Error("boom")), new CrlCache()), "couldn't download the CRL"],
  ["unreadable CRL", () => checkRevocation(crlLeaf, ca, now, fakeFetch(Buffer.from([0x30, 0x00])), new CrlCache()), "couldn't read the CRL"],
  ["tampered CRL", () => checkRevocation(crlLeaf, ca, now, fakeFetch(tampered), new CrlCache()), "the CRL's signature doesn't match the issuer"],
  ["wrong issuer key", () => checkRevocation(crlLeaf, cert("intermediate-cert.pem"), now, fakeFetch(), new CrlCache()), "the CRL's signature doesn't match the issuer"],
  ["CRL from another CA", () => checkRevocation(crlLeaf, cert("yr1-cert.pem"), now, fakeFetch(file("yr1.crl")), new CrlCache()), "the CRL's signature doesn't match the issuer"],
  ["malformed CRL extension in the certificate", () => checkRevocation(cert("bad-crl-ext-cert.pem"), ca, now, fakeFetch(), new CrlCache()), "couldn't read the certificate's CRL details"],
  ["CRL for a different URL (another shard)", () => checkRevocation(crlLeaf, ca, now, fakeFetch(file("other-shard.crl")), new CrlCache()), "the downloaded CRL is for a different URL"],
  ["CRL with an unknown critical extension", () => checkRevocation(crlLeaf, ca, now, fakeFetch(file("unknown-critical.crl")), new CrlCache()), "the CRL uses features this check doesn't support"],
  ["out-of-date CRL", () => checkRevocation(crlLeaf, ca, new Date("2200-01-01"), fakeFetch(), new CrlCache()), "the CRL is out of date"],
];

for (const [name, run, reason] of skips) {
  test(`revocation is skipped, never passed: ${name}`, async () => {
    assert.deepEqual(await run(), { id: "revoked", status: "skip", message: `Skipped: ${reason}` });
  });
}

test("skipRevocationCheck gives a skip row", () => {
  assert.deepEqual(skipRevocationCheck("domain not found"), { id: "revoked", status: "skip", message: "Skipped: domain not found" });
});

test("a CRL is downloaded once and then reused", async () => {
  const fake = fakeFetch();
  const cache = new CrlCache();
  await checkRevocation(crlLeaf, ca, now, fake, cache);
  const second = await checkRevocation(revokedLeaf, ca, now, fake, cache);
  assert.equal(second.status, "fail");
  assert.equal(fake.calls.length, 1);
});

test("failures aren't cached", async () => {
  const cache = new CrlCache();
  for (const body of [new FetchError("HTTP 500"), tampered, Buffer.from([0x30, 0x00]), file("other-shard.crl")]) {
    const fake = fakeFetch(body);
    await checkRevocation(crlLeaf, ca, now, fake, cache);
    await checkRevocation(crlLeaf, ca, now, fake, cache);
    assert.equal(fake.calls.length, 2);
  }
  assert.equal(cache.size, 0);
});

test("a cached CRL is kept at most 24 hours", async () => {
  const fake = fakeFetch();
  const cache = new CrlCache();
  await checkRevocation(crlLeaf, ca, now, fake, cache);
  await checkRevocation(crlLeaf, ca, new Date(now.getTime() + DAY - 1), fake, cache);
  assert.equal(fake.calls.length, 1);
  await checkRevocation(crlLeaf, ca, new Date(now.getTime() + DAY + 1), fake, cache);
  assert.equal(fake.calls.length, 2);
});

function entry(expires: Date, issuerFingerprint = "A"): CachedCrl {
  return { revoked: new Map(), issuerFingerprint, expires };
}

test("CrlCache drops an expired entry when it's looked up", () => {
  const cache = new CrlCache();
  cache.set("a", entry(new Date(now.getTime() + 1000)));
  assert.ok(cache.get("a", "A", now));
  assert.equal(cache.get("a", "A", new Date(now.getTime() + 1000)), undefined);
  assert.equal(cache.size, 0);
});

test("CrlCache drops the oldest entry when full", () => {
  const cache = new CrlCache(2);
  const later = new Date(now.getTime() + DAY);
  cache.set("a", entry(later));
  cache.set("b", entry(later));
  cache.set("a", entry(later)); // set again: a becomes the newest
  cache.set("c", entry(later));
  assert.equal(cache.size, 2);
  assert.equal(cache.get("b", "A", now), undefined);
  assert.ok(cache.get("a", "A", now));
  assert.ok(cache.get("c", "A", now));
});

test("CrlCache keeps 50 entries by default", () => {
  const cache = new CrlCache();
  for (let i = 0; i < 51; i++) cache.set(`u${i}`, entry(new Date(now.getTime() + DAY)));
  assert.equal(cache.size, 50);
  assert.equal(cache.get("u0", "A", now), undefined);
});

test("CrlCache ignores an entry from a different issuer", () => {
  const cache = new CrlCache();
  cache.set("a", entry(new Date(now.getTime() + DAY), "A"));
  assert.equal(cache.get("a", "B", now), undefined);
});
