import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/app.ts";

// Fake DNS so the route tests never touch the network.
const notFound = Object.assign(new Error("not found"), { code: "ENOTFOUND" });
const connectionOptions = {
  resolve: async (host: string) => {
    if (host === "internal.example") return ["10.0.0.1"];
    throw notFound;
  },
  isBlocked: (address: string) => address === "10.0.0.1",
  port: 443,
  timeoutMs: 300,
};

let server: Server;
let baseUrl: string;

before(async () => {
  server = createApp(connectionOptions).listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

function postCheck(body: string) {
  return fetch(`${baseUrl}/api/check`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
}

test("GET /api/health returns ok", async () => {
  const res = await fetch(`${baseUrl}/api/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
});

test("POST /api/check cleans the host and reports connection checks", async () => {
  const res = await postCheck(JSON.stringify({ host: " https://Missing.example/path " }));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    host: "missing.example",
    verdict: "not_secure",
    checks: [
      { id: "dns", status: "fail", message: "Domain not found" },
      { id: "port_443", status: "skip", message: "Skipped: domain not found" },
      { id: "tls_handshake", status: "skip", message: "Skipped: domain not found" },
    ],
    certificate: null,
  });
});

test("POST /api/check with an IP address returns 400", async () => {
  const res = await postCheck(JSON.stringify({ host: "127.0.0.1" }));
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "Enter a domain name, not an IP address" });
});

test("POST /api/check refuses a domain that points to a private address", async () => {
  const res = await postCheck(JSON.stringify({ host: "internal.example" }));
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /private or internal address/);
});

test("POST /api/check without a host returns 400", async () => {
  const res = await postCheck(JSON.stringify({}));
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "host is required" });
});

test("POST /api/check with malformed JSON returns a JSON 400", async () => {
  const res = await postCheck("{not json");
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "Invalid request" });
});
