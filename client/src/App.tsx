import { useState } from "react";
import type { SubmitEvent } from "react";
import type { CertificateSummary, CheckResponse, CheckResult, CheckStatus, ErrorResponse } from "../../server/src/types.ts";

type RequestState =
  | { kind: "idle" }
  | { kind: "loading"; domain: string }
  | { kind: "error"; message: string }
  | { kind: "done"; result: CheckResponse };

const checkLabels: Record<string, string> = {
  // Name what each row looks at; the status and message say how it went.
  dns: "Domain lookup",
  port_443: "HTTPS port (443)",
  tls_handshake: "Secure connection",
  expired: "Expiry date",
  wrong_host: "Domain name match",
  self_signed: "Certificate issuer",
};

const statusLabels: Record<CheckStatus, string> = {
  pass: "OK",
  warn: "Warning",
  fail: "Problem",
  skip: "Couldn't check",
};

const statusIcons: Record<CheckStatus, string> = { pass: "✓", warn: "!", fail: "✗", skip: "–" };

export function App() {
  const [domain, setDomain] = useState("");
  const [request, setRequest] = useState<RequestState>({ kind: "idle" });

  async function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setRequest({ kind: "loading", domain: domain.trim() });
    setRequest(await runCheck(domain));
  }

  const loading = request.kind === "loading";
  return (
    <main>
      <h1>TLS Check</h1>
      <form onSubmit={onSubmit}>
        <label htmlFor="domain">Domain</label>
        <div className="input-row">
          <div className="input-group">
            <span className="prefix">https://</span>
            <input
              id="domain"
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <button type="submit" disabled={loading}>
            {loading && <span className="spinner" aria-hidden="true" />}
            {loading ? "Checking" : "Check"}
          </button>
        </div>
      </form>

      {request.kind === "loading" && (
        <p className="loading" role="status">
          <span className="spinner" aria-hidden="true" />
          Checking {request.domain}… this can take up to 10 seconds.
        </p>
      )}
      {request.kind === "error" && <p role="alert">{request.message}</p>}
      {request.kind === "done" && <Results result={request.result} />}
    </main>
  );
}

async function runCheck(domain: string): Promise<RequestState> {
  try {
    const res = await fetch("/api/check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ host: domain }),
    });
    if (res.ok) return { kind: "done", result: (await res.json()) as CheckResponse };
    // 429 is sent by Nginx's per-IP rate limit
    if (res.status === 429) return { kind: "error", message: "Too many checks. Wait a minute and try again." };
    const body = (await res.json().catch(() => null)) as ErrorResponse | null;
    return { kind: "error", message: body?.error ?? `Request failed (${res.status})` };
  } catch {
    return { kind: "error", message: "Couldn't reach the server" };
  }
}

function Results({ result }: { result: CheckResponse }) {
  return (
    <section className="results" aria-live="polite">
      <Verdict result={result} />
      <ul className="checks">
        {result.checks.map((check) => (
          <CheckRow key={check.id} check={check} />
        ))}
      </ul>
      {result.certificate && <CertificateDetails certificate={result.certificate} />}
    </section>
  );
}

function Verdict({ result }: { result: CheckResponse }) {
  const count = (status: CheckStatus) => result.checks.filter((c) => c.status === status).length;
  const problems = count("fail");
  const warnings = count("warn");
  const warningText = warnings ? `${warnings} warning${warnings === 1 ? "" : "s"}` : "";

  if (result.verdict === "not_secure") {
    const extra = warningText ? `, ${warningText}` : "";
    return (
      <h2 className="verdict verdict-not_secure">
        Not secure: {problems} problem{problems === 1 ? "" : "s"} found{extra}
      </h2>
    );
  }
  if (result.verdict === "secure") {
    return <h2 className="verdict verdict-secure">Secure{warningText ? ` (${warningText})` : ""}</h2>;
  }
  return (
    <>
      <h2 className="verdict verdict-unknown">No problems found so far{warningText ? ` (${warningText})` : ""}</h2>
      <p className="note">The trust chain isn't checked yet, so this isn't a full verdict.</p>
    </>
  );
}

function CheckRow({ check }: { check: CheckResult }) {
  return (
    <li className={`check check-${check.status}`}>
      <span className="icon" aria-hidden="true">
        {statusIcons[check.status]}
      </span>
      <span className="check-body">
        <span className="check-label">
          {checkLabels[check.id] ?? check.id} <span className="status">{statusLabels[check.status]}</span>
        </span>
        {check.message && <span className="check-message">{check.message}</span>}
      </span>
    </li>
  );
}

function CertificateDetails({ certificate }: { certificate: CertificateSummary }) {
  const rows: [string, string, string?][] = [
    ["Subject", certificate.subject],
    ["Issuer", certificate.issuer],
    ["Valid from", formatDate(certificate.validFrom)],
    ["Valid to", formatDate(certificate.validTo)],
    ["Domain names", certificate.altNames.join(", ") || "None"],
    ["Public key", certificate.publicKey],
    ["Signature algorithm", certificate.signatureAlgorithm],
    ["Serial number", certificate.serialNumber, "minor"],
    ["SHA-256 fingerprint", certificate.fingerprint256, "minor"],
  ];
  return (
    <section className="certificate">
      <h3>Certificate</h3>
      <dl>
        {rows.map(([term, value, className]) => (
          <div key={term} className={className}>
            <dt>{term}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function formatDate(iso: string): string {
  return new Date(iso).toUTCString();
}
