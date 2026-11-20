import express from "express";
import type { ErrorRequestHandler } from "express";
import type { CheckResponse, ErrorResponse } from "./types.ts";

export function createApp() {
  const app = express();
  app.use(express.json({ limit: "1kb" }));

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true });
  });

  // Stub for milestone 1: returns a fixed reply in the final response shape.
  app.post("/api/check", (req, res) => {
    const host: unknown = req.body?.host;
    if (typeof host !== "string" || host.trim() === "") {
      const body: ErrorResponse = { error: "host is required" };
      res.status(400).json(body);
      return;
    }

    const body: CheckResponse = {
      host: host.trim().toLowerCase(),
      verdict: "unknown",
      checks: [],
      certificate: null,
    };
    res.json(body);
  });

  // Return JSON errors (e.g. malformed request bodies) instead of Express's HTML page.
  const onError: ErrorRequestHandler = (err, _req, res, _next) => {
    const status: number = typeof err?.status === "number" ? err.status : 500;
    const body: ErrorResponse = {
      error: status < 500 ? "Invalid request" : "Internal server error",
    };
    res.status(status).json(body);
  };
  app.use(onError);

  return app;
}
