import { test } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { crlUrl, issuerAndSerial, parseCrl, verifyCrl } from "../src/crl.ts";
import { DerError } from "../src/der.ts";

const fixtures = new URL("./fixtures/", import.meta.url);
const file = (name: string) => readFileSync(new URL(name, fixtures));
const cert = (name: string) => new X509Certificate(file(name));

const rootCrl = file("root.crl");
const ca = cert("ca-cert.pem");
const crlLeaf = cert("crl-leaf-cert.pem");
const revokedLeaf = cert("revoked-leaf-cert.pem");

test("parseCrl lists the revoked serial numbers", () => {
  const crl = parseCrl(rootCrl);
  assert.equal(crl.revoked.size, 1);
  assert.ok(crl.revoked.has(issuerAndSerial(revokedLeaf).serial));
  assert.ok(!crl.revoked.has(issuerAndSerial(crlLeaf).serial));
  assert.ok(crl.revoked.get(issuerAndSerial(revokedLeaf).serial) instanceof Date);
  assert.ok(crl.nextUpdate && crl.nextUpdate > new Date("2100-01-01"));
  assert.ok(crl.thisUpdate < new Date());
  assert.ok(crl.issuer.equals(issuerAndSerial(revokedLeaf).issuer));
});

test("issuerAndSerial matches what Node reports for the serial", () => {
  assert.equal(issuerAndSerial(revokedLeaf).serial, revokedLeaf.serialNumber.replace(/^(00)+(?=.)/, ""));
});

test("verifyCrl accepts the issuer's signature", () => {
  assert.equal(verifyCrl(parseCrl(rootCrl), ca), true);
});

test("verifyCrl rejects another key", () => {
  assert.equal(verifyCrl(parseCrl(rootCrl), cert("intermediate-cert.pem")), false);
});

test("verifyCrl rejects a tampered CRL", () => {
  const tampered = Buffer.from(rootCrl);
  tampered[tampered.length - 1]! ^= 0x01;
  assert.equal(verifyCrl(parseCrl(tampered), ca), false);
});

test("a real Let's Encrypt CRL parses and verifies", () => {
  const crl = parseCrl(file("yr1.crl"));
  assert.ok(crl.revoked.size > 0);
  assert.equal(verifyCrl(crl, cert("yr1-cert.pem")), true);
});

test("parseCrl throws DerError on malformed input", () => {
  assert.throws(() => parseCrl(Buffer.from([0x30, 0x00])), DerError);
  assert.throws(() => parseCrl(rootCrl.subarray(0, 100)), DerError);
  assert.throws(() => parseCrl(Buffer.alloc(0)), DerError);
});

test("crlUrl finds the CRL Distribution Points URL", () => {
  assert.equal(crlUrl(crlLeaf), "http://crl.test.example/root.crl");
});

test("crlUrl is undefined without the extension", () => {
  assert.equal(crlUrl(cert("leaf-cert.pem")), undefined);
});
