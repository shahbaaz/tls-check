import { verify } from "node:crypto";
import type { X509Certificate } from "node:crypto";
import { DerError, children, integerKey, readOid, readTime, readTlv } from "./der.ts";
import type { Tlv } from "./der.ts";

// A certificate revocation list (RFC 5280, section 5), reduced to what the revoked check uses.
export interface Crl {
  issuer: Buffer; // DER of the issuer's name
  thisUpdate: Date;
  nextUpdate: Date | undefined;
  revoked: Map<string, Date>; // serial number (integerKey) -> revocation date
  signedPart: Buffer; // DER of tbsCertList, the part the signature covers
  signatureAlgorithm: string; // OID
  signature: Buffer;
  // The URLs in the Issuing Distribution Point: a CA that splits its list into parts (shards)
  // names the part's own URL here. undefined when the CRL has no such extension.
  scope: string[] | undefined;
  // The CRL uses something this check doesn't handle (a delta CRL, a list limited to CA
  // certificates or some reasons, an unknown critical extension), so it can't give a clear answer.
  unsupported: boolean;
}

const CRL_DISTRIBUTION_POINTS = "2.5.29.31";
const ISSUING_DISTRIBUTION_POINT = "2.5.29.28";
const TIME_TAGS = new Set([0x17, 0x18]); // UTCTime, GeneralizedTime
const URI_TAG = 0x86; // GeneralName uniformResourceIdentifier [6]

// Hash for each signature algorithm we accept; null = the algorithm has its own (Ed25519).
const HASHES: Record<string, string | null> = {
  "1.2.840.113549.1.1.11": "sha256", // sha256WithRSAEncryption
  "1.2.840.113549.1.1.12": "sha384",
  "1.2.840.113549.1.1.13": "sha512",
  "1.2.840.10045.4.3.2": "sha256", // ecdsa-with-SHA256
  "1.2.840.10045.4.3.3": "sha384",
  "1.2.840.10045.4.3.4": "sha512",
  "1.3.101.112": null, // Ed25519
};

// CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue BIT STRING }
export function parseCrl(der: Buffer): Crl {
  const outer = readTlv(der);
  const parts = sequence(outer, 3);
  const tbs = field(parts, 0, 0x30);
  const algorithm = field(parts, 1, 0x30);
  const signatureValue = field(parts, 2, 0x03);
  if (signatureValue.value.length < 1) throw new DerError("bad signature");

  // TBSCertList ::= SEQUENCE { version INTEGER OPTIONAL, signature, issuer, thisUpdate,
  //   nextUpdate OPTIONAL, revokedCertificates SEQUENCE OPTIONAL, [0] crlExtensions OPTIONAL }
  const fields = sequence(tbs, 3);
  let i = fields[0]?.tag === 0x02 ? 1 : 0; // skip the version
  i++; // the signature algorithm again (the outer one is the one used)
  const issuer = field(fields, i++, 0x30);
  const thisUpdate = readTime(field(fields, i++));
  let nextUpdate: Date | undefined;
  if (fields[i] && TIME_TAGS.has(fields[i]!.tag)) nextUpdate = readTime(fields[i++]!);

  const revoked = new Map<string, Date>();
  if (fields[i]?.tag === 0x30) {
    // Each entry: SEQUENCE { userCertificate INTEGER, revocationDate Time, crlEntryExtensions OPTIONAL }
    for (const entry of children(fields[i]!)) {
      const [serial, date] = sequence(entry, 2);
      revoked.set(integerKey(serial!), readTime(date!));
    }
    i++;
  }

  // crlExtensions [0] EXPLICIT SEQUENCE OF Extension
  let scope: string[] | undefined;
  let unsupported = false;
  if (fields[i]?.tag === 0xa0) {
    for (const extension of sequence(field(children(fields[i]!), 0), 0)) {
      const { id, critical, value } = readExtension(extension);
      if (id === ISSUING_DISTRIBUTION_POINT) {
        // IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0], onlyContainsUserCerts [1], ... }
        // Anything past those two narrows the list in ways this check doesn't follow.
        const parts = sequence(readTlv(value), 0);
        scope = parts.filter((p) => p.tag === 0xa0).flatMap(uris);
        if (parts.some((p) => p.tag !== 0xa0 && p.tag !== 0x81)) unsupported = true;
      } else if (critical) {
        unsupported = true; // RFC 5280: a CRL with an unknown critical extension must not be used
      }
    }
  }

  return {
    issuer: issuer.bytes,
    thisUpdate,
    nextUpdate,
    revoked,
    signedPart: tbs.bytes,
    signatureAlgorithm: readOid(field(sequence(algorithm, 1), 0)),
    signature: signatureValue.value.subarray(1), // drop the "unused bits" byte
    scope,
    unsupported,
  };
}

// Checks only the signature; whether the CRL is for the right issuer is up to the caller.
export function verifyCrl(crl: Crl, issuer: X509Certificate): boolean {
  const hash = HASHES[crl.signatureAlgorithm];
  if (hash === undefined) return false;
  try {
    return verify(hash, crl.signedPart, issuer.publicKey, crl.signature);
  } catch {
    return false;
  }
}

// The first http:// URL in the certificate's CRL Distribution Points extension.
export function crlUrl(cert: X509Certificate): string | undefined {
  for (const extension of extensions(cert)) {
    const { id, value } = readExtension(extension);
    if (id === CRL_DISTRIBUTION_POINTS) return uris(readTlv(value)).find((uri) => uri.startsWith("http://"));
  }
  return undefined;
}

// The leaf's issuer name (DER) and serial number, read from the certificate itself
// so they compare exactly with what the CRL holds.
export function issuerAndSerial(cert: X509Certificate): { issuer: Buffer; serial: string } {
  const fields = tbsFields(cert);
  const i = fields[0]?.tag === 0xa0 ? 1 : 0; // skip the [0] version
  return { serial: integerKey(field(fields, i, 0x02)), issuer: field(fields, i + 2, 0x30).bytes };
}

// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... }, signatureAlgorithm, signature }
function tbsFields(cert: X509Certificate): Tlv[] {
  return sequence(field(sequence(readTlv(cert.raw), 3), 0), 6);
}

function extensions(cert: X509Certificate): Tlv[] {
  const wrapper = tbsFields(cert).find((f) => f.tag === 0xa3); // [3] EXPLICIT Extensions
  return wrapper ? sequence(field(children(wrapper), 0), 0) : [];
}

// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
function readExtension(extension: Tlv): { id: string; critical: boolean; value: Buffer } {
  const parts = sequence(extension, 2);
  const flag = parts.length > 2 ? field(parts, 1, 0x01) : undefined;
  return {
    id: readOid(field(parts, 0)),
    critical: flag !== undefined && flag.value[0] !== 0,
    value: field(parts, parts.length - 1, 0x04).value,
  };
}

// Every URI anywhere inside a DistributionPoints structure.
function uris(tlv: Tlv): string[] {
  if (tlv.tag === URI_TAG) return [tlv.value.toString("latin1")];
  if ((tlv.tag & 0x20) === 0) return []; // primitive: nothing inside
  return children(tlv).flatMap(uris);
}

// The children of a SEQUENCE, with at least `min` of them.
function sequence(tlv: Tlv, min: number): Tlv[] {
  if (tlv.tag !== 0x30) throw new DerError("expected a SEQUENCE");
  const items = children(tlv);
  if (items.length < min) throw new DerError("SEQUENCE too short");
  return items;
}

function field(fields: Tlv[], index: number, tag?: number): Tlv {
  const item = fields[index];
  if (!item || (tag !== undefined && item.tag !== tag)) throw new DerError("unexpected structure");
  return item;
}
