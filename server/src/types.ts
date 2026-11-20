// API contract for POST /api/check (see SPEC.md). The client imports these types too.

export type Verdict = "secure" | "not_secure" | "unknown";

// skip = couldn't check
export type CheckStatus = "pass" | "fail" | "skip";

export interface CheckResult {
  id: string;
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
  // null when no certificate was collected (stub, or the site has no https)
  certificate: CertificateSummary | null;
}

export interface ErrorResponse {
  error: string;
}
