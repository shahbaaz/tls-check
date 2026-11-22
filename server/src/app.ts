import express from "express";
import type { ErrorRequestHandler } from "express";
import { checkCertificate, skipCertificateChecks, summarizeCertificate } from "./certificate.ts";
import { buildPath, checkChain, defaultTrustStore, skipChainChecks, summarizeChain } from "./chain.ts";
import type { TrustStore } from "./chain.ts";
import { checkConnection, defaultConnectionOptions } from "./connection.ts";
import type { ConnectionOptions } from "./connection.ts";
import { cleanHost } from "./host.ts";
import { CrlCache, checkRevocation, defaultRevocationOptions, skipRevocationCheck } from "./revocation.ts";
import type { RevocationOptions } from "./revocation.ts";
import type { CheckResponse, CheckResult, ErrorResponse, Verdict } from "./types.ts";

// Tests pass their own connection options and CRL download to avoid real DNS and network
// calls, and their own trust store so the test CA counts as a trusted root.
export function createApp(
  connectionOptions: ConnectionOptions = defaultConnectionOptions,
  store: TrustStore = defaultTrustStore,
  revocation: RevocationOptions = defaultRevocationOptions,
) {
  const app = express();
  const crlCache = new CrlCache();
  app.use(express.json({ limit: "1kb" }));

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true });
  });

  app.post("/api/check", async (req, res) => {
    const input: unknown = req.body?.host;
    if (typeof input !== "string" || input.trim() === "") {
      const body: ErrorResponse = { error: "host is required" };
      res.status(400).json(body);
      return;
    }
    const cleaned = cleanHost(input);
    if (!cleaned.ok) {
      const body: ErrorResponse = { error: cleaned.error };
      res.status(400).json(body);
      return;
    }

    const connection = await checkConnection(cleaned.host, connectionOptions);
    if (connection.kind === "blocked") {
      const body: ErrorResponse = { error: "This domain points to a private or internal address, so it can't be checked" };
      res.status(400).json(body);
      return;
    }

    let body: CheckResponse;
    if (connection.kind === "connected") {
      const { certificate, chain } = connection;
      const path = buildPath(certificate, chain, store);
      const now = new Date();
      const issuer = path.links[0]?.certificate;
      const checks = [
        ...connection.checks,
        ...checkCertificate(certificate, cleaned.host, now),
        ...checkChain(certificate, path),
        await checkRevocation(certificate, issuer, now, revocation, crlCache),
      ];
      const summary = summarizeCertificate(certificate, summarizeChain(path));
      body = { host: cleaned.host, verdict: verdict(checks), checks, certificate: summary };
    } else {
      const { reason } = connection;
      const checks = [
        ...connection.checks,
        ...skipCertificateChecks(reason),
        ...skipChainChecks(reason),
        skipRevocationCheck(reason),
      ];
      body = { host: cleaned.host, verdict: verdict(checks), checks, certificate: null };
    }
    res.json(body);
  });

  // Return JSON errors (e.g. malformed request bodies) instead of Express's HTML page.
  const onError: ErrorRequestHandler = (err, _req, res, _next) => {
    const status: number = typeof err?.status === "number" ? err.status : 500;
    if (status >= 500) console.error(err); // shows up in journalctl
    const body: ErrorResponse = {
      error: status < 500 ? "Invalid request" : "Internal server error",
    };
    res.status(status).json(body);
  };
  app.use(onError);

  return app;
}

// Any failure makes the site not secure; warnings don't change the verdict.
// Without a failure, a check that couldn't run leaves the verdict unknown, except revocation:
// browsers also let a site through when they can't check it.
function verdict(checks: CheckResult[]): Verdict {
  if (checks.some((c) => c.status === "fail")) return "not_secure";
  if (checks.some((c) => c.status === "skip" && c.id !== "revoked")) return "unknown";
  return "secure";
}
