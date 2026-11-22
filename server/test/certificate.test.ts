import { test } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { checkCertificate, skipCertificateChecks, summarizeCertificate } from "../src/certificate.ts";

// leaf-cert.pem: test.example and *.wild.example, signed by the test CA (see fixtures/make-ca-signed-certs.sh).
// test-cert.pem: self-signed for test.example, with no subject alternative names.
const fixtures = new URL("./fixtures/", import.meta.url);
const leaf = new X509Certificate(readFileSync(new URL("leaf-cert.pem", fixtures)));
const selfSigned = new X509Certificate(readFileSync(new URL("test-cert.pem", fixtures)));

const DAY_MS = 24 * 60 * 60 * 1000;
const midLife = new Date(leaf.validFromDate.getTime() + 365 * DAY_MS);

function check(id: string, cert: X509Certificate, host = "test.example", now = midLife) {
  const result = checkCertificate(cert, host, now).find((c) => c.id === id);
  assert.ok(result, `no ${id} row`);
  return result;
}

test("a valid CA-signed certificate passes every check", () => {
  const checks = checkCertificate(leaf, "test.example", midLife);
  assert.deepEqual(
    checks.map((c) => `${c.id}:${c.status}`),
    ["expired:pass", "wrong_host:pass", "self_signed:pass"],
  );
});

test("expired: fails after validTo", () => {
  const result = check("expired", leaf, "test.example", new Date(leaf.validToDate.getTime() + DAY_MS));
  assert.equal(result.status, "fail");
  assert.equal(result.message, `Expired ${leaf.validToDate.toISOString().slice(0, 10)}`);
});

test("expired: fails before validFrom", () => {
  const result = check("expired", leaf, "test.example", new Date(leaf.validFromDate.getTime() - DAY_MS));
  assert.equal(result.status, "fail");
  assert.match(result.message ?? "", /^Not valid until /);
});

test("expired: warns with under 14 days left", () => {
  const result = check("expired", leaf, "test.example", new Date(leaf.validToDate.getTime() - 9.5 * DAY_MS));
  assert.equal(result.status, "warn");
  assert.match(result.message ?? "", /^Expires in 9 days /);
});

test("expired: warns on the last day", () => {
  const result = check("expired", leaf, "test.example", new Date(leaf.validToDate.getTime() - 60_000));
  assert.equal(result.status, "warn");
  assert.match(result.message ?? "", /^Expires in less than a day /);
});

test("expired: passes with 14 days left", () => {
  const result = check("expired", leaf, "test.example", new Date(leaf.validToDate.getTime() - 14 * DAY_MS));
  assert.equal(result.status, "pass");
});

test("wrong_host: a wildcard covers one label only", () => {
  assert.equal(check("wrong_host", leaf, "a.wild.example").status, "pass");
  assert.equal(check("wrong_host", leaf, "a.b.wild.example").status, "fail");
  assert.equal(check("wrong_host", leaf, "wild.example").status, "fail");
});

test("wrong_host: lists the names the certificate does cover", () => {
  const result = check("wrong_host", leaf, "other.example");
  assert.equal(result.status, "fail");
  assert.equal(result.message, "The certificate is for test.example and *.wild.example, not other.example.");
});

test("wrong_host: explains a wildcard that covers one level too few", () => {
  const result = check("wrong_host", leaf, "a.b.wild.example");
  assert.equal(
    result.message,
    "The certificate is for test.example and *.wild.example, not a.b.wild.example. " +
      "A wildcard (*) covers one level only, e.g. www.wild.example, not a.b.wild.example.",
  );
});

test("wrong_host: the Common Name alone doesn't count, as in browsers", () => {
  const result = check("wrong_host", selfSigned, "test.example");
  assert.equal(result.status, "fail");
  assert.equal(result.message, "The certificate doesn't list any domain names");
});

test("self_signed: fails for a self-signed certificate", () => {
  assert.equal(check("self_signed", selfSigned).status, "fail");
  assert.equal(check("self_signed", leaf).message, "Issued by TLS Check Test CA");
});

test("skipCertificateChecks gives a skip row per check", () => {
  assert.deepEqual(skipCertificateChecks("TLS handshake failed"), [
    { id: "expired", status: "skip", message: "Skipped: TLS handshake failed" },
    { id: "wrong_host", status: "skip", message: "Skipped: TLS handshake failed" },
    { id: "self_signed", status: "skip", message: "Skipped: TLS handshake failed" },
  ]);
});

test("summarizeCertificate returns the leaf's details", () => {
  const summary = summarizeCertificate(leaf, []);
  assert.equal(summary.subject, "CN=test.example");
  assert.equal(summary.issuer, "CN=TLS Check Test CA");
  assert.deepEqual(summary.altNames, ["test.example", "*.wild.example"]);
  assert.equal(summary.validTo, leaf.validToDate.toISOString());
  assert.equal(summary.publicKey, "EC P-256");
  assert.equal(summary.signatureAlgorithm, "ecdsa-with-SHA256");
  assert.equal(summary.fingerprint256, leaf.fingerprint256);
});
