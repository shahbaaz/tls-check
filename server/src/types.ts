// API contract for POST /api/check (see SPEC.md). The client imports these types too.

export type Verdict = "secure" | "not_secure" | "unknown";

// warn = a problem coming up that doesn't make the site insecure yet; skip = couldn't check
export type CheckStatus = "pass" | "warn" | "fail" | "skip";

export interface CheckResult {
  // "dns", "port_443", "tls_handshake", "expired", "wrong_host", "self_signed",
  // "no_alt_names", "no_subject", "no_common_name", "incomplete_chain", "untrusted_root"
  id: string;
  status: CheckStatus;
  message?: string;
}

// Details of the certificate the server sent for the domain (the leaf).
export interface CertificateSummary {
  subject: string; // e.g. "CN=*.badssl.com, O=BadSSL"
  issuer: string;
  validFrom: string; // ISO 8601
  validTo: string; // ISO 8601
  altNames: string[]; // subject alternative names, e.g. ["*.badssl.com", "badssl.com"]
  publicKey: string; // key type and size, e.g. "RSA 2048", "EC P-256"
  signatureAlgorithm: string; // how the issuer signed it, e.g. "sha256WithRSAEncryption"
  serialNumber: string;
  fingerprint256: string;
  chain: ChainCertificate[]; // the certificates above the leaf, up to the root
}

// One certificate in the chain above the leaf, in order from the leaf's issuer up to the root.
export interface ChainCertificate {
  subject: string;
  issuer: string;
  validFrom: string; // ISO 8601
  validTo: string; // ISO 8601
  fingerprint256: string;
  // server = sent by the server; trust_store = a trusted root (Node adds it even when the server didn't send it)
  source: "server" | "trust_store";
}

export interface CheckResponse {
  host: string;
  verdict: Verdict;
  checks: CheckResult[];
  // null when no certificate was collected (e.g. DNS, port 443 or the TLS handshake failed)
  certificate: CertificateSummary | null;
}

export interface ErrorResponse {
  error: string;
}
