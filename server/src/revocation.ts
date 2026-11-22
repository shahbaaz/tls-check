import type { X509Certificate } from "node:crypto";
import { isSelfSigned } from "./certificate.ts";
import { fail, pass, skip } from "./check-result.ts";
import { crlUrl, issuerAndSerial, parseCrl, verifyCrl } from "./crl.ts";
import { DerError } from "./der.ts";
import { FetchError, defaultFetchOptions, fetchCrl } from "./crl-fetch.ts";
import type { CheckResult } from "./types.ts";

const ID = "revoked";
const MAX_CACHE_MS = 24 * 60 * 60 * 1000;

// A downloaded, verified CRL, reduced to what later checks need.
export interface CachedCrl {
  revoked: Map<string, Date>; // serial number -> revocation date
  issuerFingerprint: string; // the certificate whose key verified it
  expires: Date; // nextUpdate, at most 24 hours after download
}

// CRLs in memory, keyed by URL. No timer: expired entries are dropped when looked up,
// and the oldest entry goes when the cache is full. A Map keeps insertion order, so
// its first key is the oldest.
export class CrlCache {
  #entries = new Map<string, CachedCrl>();
  #maxEntries: number;

  constructor(maxEntries = 50) {
    this.#maxEntries = maxEntries;
  }

  get(url: string, issuerFingerprint: string, now: Date): CachedCrl | undefined {
    const entry = this.#entries.get(url);
    if (!entry) return undefined;
    if (entry.expires <= now) {
      this.#entries.delete(url);
      return undefined;
    }
    return entry.issuerFingerprint === issuerFingerprint ? entry : undefined;
  }

  set(url: string, entry: CachedCrl): void {
    this.#entries.delete(url);
    this.#entries.set(url, entry);
    for (const oldest of this.#entries.keys()) {
      if (this.#entries.size <= this.#maxEntries) break;
      this.#entries.delete(oldest);
    }
  }

  get size(): number {
    return this.#entries.size;
  }
}

// Tests replace the download so they never touch the network.
export interface RevocationOptions {
  fetchCrl: (url: string) => Promise<Buffer>;
}

export const defaultRevocationOptions: RevocationOptions = {
  fetchCrl: (url) => fetchCrl(url, defaultFetchOptions),
};

// Looks the leaf up in its CA's CRL. Anything that stops a trustworthy answer is a skip, never a pass.
export async function checkRevocation(
  leaf: X509Certificate,
  issuer: X509Certificate | undefined,
  now: Date,
  options: RevocationOptions,
  cache: CrlCache,
): Promise<CheckResult> {
  if (isSelfSigned(leaf)) return skipRevocationCheck("certificate is self-signed");
  // Node accepts certificates whose extension contents are malformed (OpenSSL doesn't decode them all).
  let url: string | undefined;
  let leafId: ReturnType<typeof issuerAndSerial>;
  try {
    url = crlUrl(leaf);
    leafId = issuerAndSerial(leaf);
  } catch (err) {
    if (!(err instanceof DerError)) throw err;
    return skipRevocationCheck("couldn't read the certificate's CRL details");
  }
  if (!url) return skipRevocationCheck("the certificate lists no CRL (the CA may only offer OCSP)");
  // The CRL is only trustworthy once the issuer's key has verified it.
  if (!issuer) return skipRevocationCheck("the issuer certificate isn't available");

  let crl = cache.get(url, issuer.fingerprint256, now);
  if (!crl) {
    const result = await download(url, leafId.issuer, issuer, now, options);
    if ("skip" in result) return skipRevocationCheck(result.skip);
    crl = result;
    cache.set(url, crl);
  }

  const revokedOn = crl.revoked.get(leafId.serial);
  if (revokedOn) return fail(ID, `The CA revoked this certificate on ${revokedOn.toISOString().slice(0, 10)}`);
  return pass(ID, "Not on the CA's revocation list");
}

// Downloads, reads and verifies a CRL. Nothing here is cached unless it all succeeds.
async function download(
  url: string,
  leafIssuer: Buffer,
  issuer: X509Certificate,
  now: Date,
  options: RevocationOptions,
): Promise<CachedCrl | { skip: string }> {
  let der: Buffer;
  try {
    der = await options.fetchCrl(url);
  } catch (err) {
    return { skip: err instanceof FetchError ? `couldn't download the CRL (${err.message})` : "couldn't download the CRL" };
  }
  let crl: ReturnType<typeof parseCrl>;
  try {
    crl = parseCrl(der);
  } catch {
    return { skip: "couldn't read the CRL" };
  }
  // Over plain HTTP anyone in between could swap the list, so it must be the leaf's issuer's, signed by its key.
  if (!crl.issuer.equals(leafIssuer) || !verifyCrl(crl, issuer)) {
    return { skip: "the CRL's signature doesn't match the issuer" };
  }
  // A CA's list split into parts: each part names its own URL and they're all validly signed, so a
  // swapped-in part would hide the revocation.
  if (crl.scope && !crl.scope.includes(url)) return { skip: "the downloaded CRL is for a different URL" };
  if (crl.unsupported) return { skip: "the CRL uses features this check doesn't support" };
  if (!crl.nextUpdate || crl.nextUpdate <= now) return { skip: "the CRL is out of date" };
  const expires = new Date(Math.min(crl.nextUpdate.getTime(), now.getTime() + MAX_CACHE_MS));
  return { revoked: crl.revoked, issuerFingerprint: issuer.fingerprint256, expires };
}

// Used when no certificate was collected; reason says why, e.g. "TLS handshake failed".
export function skipRevocationCheck(reason: string): CheckResult {
  return skip(ID, reason);
}
