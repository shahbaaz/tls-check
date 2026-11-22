import { test } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { checkCertificate, skipCertificateChecks, summarizeCertificate } from "../src/certificate.ts";

// leaf-cert.pem: test.example and *.wild.example, signed by the test CA (see fixtures/make-ca-signed-certs.sh).
// test-cert.pem: self-signed for test.example, with no subject alternative names.
// no-san-cert.pem: subject O=TLS Check Test (no CN), SAN with an IP address only.
// no-subject-cert.pem: empty subject, SAN test.example.
const fixtures = new URL("./fixtures/", import.meta.url);
const leaf = new X509Certificate(readFileSync(new URL("leaf-cert.pem", fixtures)));
const selfSigned = new X509Certificate(readFileSync(new URL("test-cert.pem", fixtures)));
const noSan = new X509Certificate(readFileSync(new URL("no-san-cert.pem", fixtures)));
const noSubject = new X509Certificate(readFileSync(new URL("no-subject-cert.pem", fixtures)));

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
    [
      "expired:pass",
      "wrong_host:pass",
      "self_signed:pass",
      "no_alt_names:pass",
      "no_subject:pass",
      "no_common_name:pass",
    ],
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

test("wrong_host: skips when there are no domain names to match", () => {
  // test-cert.pem has CN=test.example but no SAN: the Common Name alone doesn't count, as in browsers.
  for (const cert of [noSan, selfSigned]) {
    assert.deepEqual(check("wrong_host", cert), {
      id: "wrong_host",
      status: "skip",
      message: "Skipped: no domain names to match",
    });
  }
});

test("no_alt_names: passes and counts the domain names", () => {
  assert.equal(check("no_alt_names", leaf).message, "Lists 2 domain names");
  assert.equal(check("no_alt_names", noSubject).message, "Lists 1 domain name");
});

test("no_alt_names: fails when the SAN has only an IP address", () => {
  const result = check("no_alt_names", noSan);
  assert.equal(result.status, "fail");
  assert.equal(result.message, "Browsers only trust the names listed in the SAN, and this certificate lists none");
});

test("no_alt_names: fails when there is no SAN at all", () => {
  assert.equal(check("no_alt_names", selfSigned).status, "fail");
});

test("no_subject and no_common_name pass with a note for an empty Subject", () => {
  assert.deepEqual(check("no_subject", noSubject), {
    id: "no_subject",
    status: "pass",
    message: "No Subject (fine: browsers use the SAN)",
  });
  assert.deepEqual(check("no_common_name", noSubject), {
    id: "no_common_name",
    status: "pass",
    message: "No Common Name (fine: browsers use the SAN)",
  });
});

test("no_common_name passes with a note when the Subject has no CN", () => {
  assert.equal(check("no_subject", noSan).message, "O=TLS Check Test");
  assert.equal(check("no_common_name", noSan).message, "No Common Name (fine: browsers use the SAN)");
});

test("no_subject and no_common_name show the names when present", () => {
  assert.equal(check("no_subject", leaf).message, "CN=test.example");
  assert.equal(check("no_common_name", leaf).message, "test.example");
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
    { id: "no_alt_names", status: "skip", message: "Skipped: TLS handshake failed" },
    { id: "no_subject", status: "skip", message: "Skipped: TLS handshake failed" },
    { id: "no_common_name", status: "skip", message: "Skipped: TLS handshake failed" },
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

test("summarizeCertificate gives an empty subject instead of throwing", () => {
  assert.equal(summarizeCertificate(noSubject, []).subject, "");
});
