// API contract for POST /api/check (see SPEC.md). The client imports these types too.

export type Verdict = "secure" | "not_secure" | "unknown";

// skip = couldn't check
export type CheckStatus = "pass" | "fail" | "skip";

export interface CheckResult {
  id: string; // e.g. "dns", "port_443", "tls_handshake"
  status: CheckStatus;
  message?: string;
}

export interface CertificateSummary {
  subject: string;
  issuer: string;
  validTo: string;
  chain: unknown[];
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
