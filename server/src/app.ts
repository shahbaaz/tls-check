import express from "express";
import type { ErrorRequestHandler } from "express";
import { checkConnection, defaultConnectionOptions } from "./connection.ts";
import type { ConnectionOptions } from "./connection.ts";
import { cleanHost } from "./host.ts";
import type { CheckResponse, ErrorResponse } from "./types.ts";

// Tests pass their own connection options to avoid real DNS and network calls.
export function createApp(connectionOptions: ConnectionOptions = defaultConnectionOptions) {
  const app = express();
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

    const { checks } = connection;
    const body: CheckResponse = {
      host: cleaned.host,
      // Certificate checks come in later milestones, so passing connection checks alone give "unknown".
      verdict: checks.some((c) => c.status === "fail") ? "not_secure" : "unknown",
      checks,
      certificate: null,
    };
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
