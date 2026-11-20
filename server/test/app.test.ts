import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/app.ts";

let server: Server;
let baseUrl: string;

before(async () => {
  server = createApp().listen(0, "127.0.0.1");
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

test("POST /api/check returns the stub reply", async () => {
  const res = await postCheck(JSON.stringify({ host: " Example.com " }));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), {
    host: "example.com",
    verdict: "unknown",
    checks: [],
    certificate: null,
  });
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
