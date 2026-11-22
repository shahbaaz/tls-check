import { X509Certificate } from "node:crypto";
import tls from "node:tls";
import { commonName, isSelfSigned, oneLine } from "./certificate.ts";
import { fail, pass, skip } from "./check-result.ts";
import type { ChainCertificate, CheckResult } from "./types.ts";

export const chainCheckIds = ["incomplete_chain", "untrusted_root"];

// Real chains are 2–4 certificates long; stop well before a loop or a huge list could cost much.
const MAX_DEPTH = 10;

export interface TrustStore {
  roots: X509Certificate[];
}

export function trustStore(pems: readonly string[]): TrustStore {
  return { roots: pems.map((pem) => new X509Certificate(pem)) };
}

// Node's bundled Mozilla root list, parsed once at startup.
export const defaultTrustStore = trustStore(tls.rootCertificates);

interface Link {
  certificate: X509Certificate;
  source: ChainCertificate["source"];
}

// How far the path from the leaf got:
//   trusted        reached a root in the trust store
//   untrusted_root ended at a self-signed certificate that isn't in the trust store
//   incomplete     a certificate's issuer wasn't sent and isn't a trusted root
interface Path {
  end: "trusted" | "untrusted_root" | "incomplete";
  links: Link[]; // the certificates above the leaf, in order
  last: X509Certificate; // where the path stopped
}

// Builds the path from the leaf to a root ourselves, instead of relying on Node's
// authorizationError, which reports one problem only. At each step a trusted root wins,
// so a server that also sends an old cross-signed root still chains to the trusted one.
export function buildPath(leaf: X509Certificate, sent: X509Certificate[], store: TrustStore): Path {
  const links: Link[] = [];
  let current = leaf;
  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    // A trusted root is accepted as it is: it's in the store, so its CA flag isn't checked.
    // When the server sends a trusted root too, this finds the store's copy of it first.
    const root = store.roots.find((r) => r.fingerprint256 !== current.fingerprint256 && signedBy(current, r));
    if (root) {
      links.push({ certificate: root, source: "trust_store" });
      return { end: "trusted", links, last: root };
    }
    if (isSelfSigned(current)) return { end: "untrusted_root", links, last: current };
    // A certificate the server sent only counts as an issuer if it's a CA.
    const used = new Set([leaf, ...links.map((l) => l.certificate)].map((c) => c.fingerprint256));
    const next = sent.find((c) => c.ca && !used.has(c.fingerprint256) && signedBy(current, c));
    if (!next) break;
    links.push({ certificate: next, source: "server" });
    current = next;
  }
  return { end: "incomplete", links, last: current };
}

// checkIssued compares names (cheap), so verify (a signature check) only runs on likely issuers.
function signedBy(cert: X509Certificate, issuer: X509Certificate): boolean {
  return cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
}

export function checkChain(leaf: X509Certificate, path: Path): CheckResult[] {
  if (isSelfSigned(leaf)) return chainCheckIds.map((id) => skip(id, "certificate is self-signed"));
  if (path.end === "incomplete") {
    const missing = name(path.last.issuer);
    return [
      fail(
        "incomplete_chain",
        `The server didn't send the intermediate certificate ${missing}. Some browsers fetch it themselves, so the site may work in one browser and fail in others.`,
      ),
      skip("untrusted_root", "chain is incomplete"),
    ];
  }
  const complete = pass("incomplete_chain", "The server sent the full chain");
  if (path.end === "untrusted_root") {
    return [complete, fail("untrusted_root", `Ends at ${name(path.last.subject)}, which isn't a trusted root`)];
  }
  return [complete, pass("untrusted_root", `Chains to ${name(path.last.subject)}, a trusted root`)];
}

// Used when no certificate was collected; reason says why, e.g. "TLS handshake failed".
export function skipChainChecks(reason: string): CheckResult[] {
  return chainCheckIds.map((id) => skip(id, reason));
}

export function summarizeChain(path: Path): ChainCertificate[] {
  return path.links.map(({ certificate, source }) => ({
    subject: oneLine(certificate.subject),
    issuer: oneLine(certificate.issuer),
    validFrom: certificate.validFromDate.toISOString(),
    validTo: certificate.validToDate.toISOString(),
    fingerprint256: certificate.fingerprint256,
    source,
  }));
}

// e.g. "YR1", or the whole name when it has no CN.
function name(distinguishedName: string): string {
  return commonName(distinguishedName) ?? oneLine(distinguishedName);
}
