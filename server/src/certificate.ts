import type { X509Certificate } from "node:crypto";
import { fail, pass, skip, warn } from "./check-result.ts";
import type { CertificateSummary, CheckResult } from "./types.ts";

const DAY_MS = 24 * 60 * 60 * 1000;
// Certificates are getting shorter-lived and renew with about a third of their life left,
// so under 14 days left means renewal is overdue.
const EXPIRY_WARNING_DAYS = 14;

export const certificateCheckIds = ["expired", "wrong_host", "self_signed"];

// Runs every check on the leaf certificate. Each one runs on its own, so one problem doesn't hide another.
export function checkCertificate(cert: X509Certificate, host: string, now: Date): CheckResult[] {
  return [checkExpiry(cert, now), checkHost(cert, host), checkSelfSigned(cert)];
}

// Used when no certificate was collected; reason says why, e.g. "TLS handshake failed".
export function skipCertificateChecks(reason: string): CheckResult[] {
  return certificateCheckIds.map((id) => skip(id, reason));
}

function checkExpiry(cert: X509Certificate, now: Date): CheckResult {
  const validFrom = cert.validFromDate;
  const validTo = cert.validToDate;
  if (now < validFrom) return fail("expired", `Not valid until ${day(validFrom)}`);
  if (now > validTo) return fail("expired", `Expired ${day(validTo)}`);
  const daysLeft = Math.floor((validTo.getTime() - now.getTime()) / DAY_MS);
  if (daysLeft < EXPIRY_WARNING_DAYS) {
    const when = daysLeft === 0 ? "in less than a day" : `in ${daysLeft} day${daysLeft === 1 ? "" : "s"}`;
    return warn("expired", `Expires ${when} (${day(validTo)})`);
  }
  return pass("expired", `Valid until ${day(validTo)}`);
}

function checkHost(cert: X509Certificate, host: string): CheckResult {
  // Match the way browsers do: only subject alternative names count (not the Common Name),
  // and a wildcard covers one whole label ("*.example.com", not "w*.example.com").
  const matched = cert.checkHost(host, { subject: "never", partialWildcards: false });
  if (matched !== undefined) return pass("wrong_host", matched === host ? `Covers ${host}` : `Covers ${host} (via ${matched})`);
  const names = altNames(cert);
  if (names.length === 0) return fail("wrong_host", `Not valid for ${host}: the certificate lists no domain names`);
  const shown = names.slice(0, 5).join(", ") + (names.length > 5 ? ` and ${names.length - 5} more` : "");
  return fail("wrong_host", `Not valid for ${host}: it covers ${shown}`);
}

function checkSelfSigned(cert: X509Certificate): CheckResult {
  // Self-signed: the certificate names itself as issuer and its own key signed it.
  if (cert.checkIssued(cert) && cert.verify(cert.publicKey)) {
    return fail("self_signed", "Self-signed: no trusted authority vouches for this certificate");
  }
  return pass("self_signed", `Issued by ${commonName(cert.issuer) ?? oneLine(cert.issuer)}`);
}

export function summarizeCertificate(cert: X509Certificate): CertificateSummary {
  return {
    subject: oneLine(cert.subject),
    issuer: oneLine(cert.issuer),
    validFrom: cert.validFromDate.toISOString(),
    validTo: cert.validToDate.toISOString(),
    altNames: altNames(cert),
    publicKey: describeKey(cert),
    signatureAlgorithm: cert.signatureAlgorithm ?? "Unknown",
    serialNumber: cert.serialNumber,
    fingerprint256: cert.fingerprint256,
    chain: [],
  };
}

// Node gives names one field per line ("C=US\nCN=example.com").
function oneLine(name: string): string {
  return name.split("\n").filter(Boolean).join(", ");
}

// The CN field of a name, e.g. "COMODO RSA Domain Validation Secure Server CA".
function commonName(name: string): string | undefined {
  return name.split("\n").find((field) => field.startsWith("CN="))?.slice(3) || undefined;
}

const curveNames: Record<string, string> = { prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521" };

// e.g. "RSA 2048", "EC P-256", "Ed25519"
function describeKey(cert: X509Certificate): string {
  const key = cert.publicKey;
  const details = key.asymmetricKeyDetails ?? {};
  switch (key.asymmetricKeyType) {
    case "rsa":
    case "rsa-pss":
      return `RSA ${details.modulusLength ?? ""}`.trim();
    case "ec":
      return `EC ${curveNames[details.namedCurve ?? ""] ?? details.namedCurve ?? ""}`.trim();
    case "ed25519":
      return "Ed25519";
    case "ed448":
      return "Ed448";
    default:
      return key.asymmetricKeyType?.toUpperCase() ?? "Unknown";
  }
}

// "DNS:a.example, DNS:b.example, IP Address:1.2.3.4" -> ["a.example", "b.example", "IP Address:1.2.3.4"]
function altNames(cert: X509Certificate): string[] {
  if (!cert.subjectAltName) return [];
  return cert.subjectAltName.split(", ").map((name) => name.replace(/^DNS:/, ""));
}

function day(date: Date): string {
  return date.toISOString().slice(0, 10);
}
