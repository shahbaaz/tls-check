import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { once } from "node:events";
import net from "node:net";
import tls from "node:tls";
import type { AddressInfo } from "node:net";
import { checkConnection } from "../src/connection.ts";
import type { ConnectionOptions } from "../src/connection.ts";

// Local servers on 127.0.0.1 stand in for real sites, so these tests need no internet.
const fixtures = new URL("./fixtures/", import.meta.url);
const key = readFileSync(new URL("test-key.pem", fixtures));
const cert = readFileSync(new URL("test-cert.pem", fixtures));

function options(port: number, overrides: Partial<ConnectionOptions> = {}): ConnectionOptions {
  return {
    resolve: async () => ["127.0.0.1"],
    isBlocked: () => false,
    port,
    timeoutMs: 300,
    ...overrides,
  };
}

async function listen(server: net.Server): Promise<number> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return (server.address() as AddressInfo).port;
}

function statuses(result: Awaited<ReturnType<typeof checkConnection>>) {
  assert.equal(result.kind, "checked");
  return result.kind === "checked" ? result.checks.map((c) => `${c.id}:${c.status}`) : [];
}

test("all three checks pass against a TLS server, and SNI is sent", async (t) => {
  let sni: string | undefined;
  const context = tls.createSecureContext({ key, cert });
  const server = tls.createServer({
    key,
    cert,
    SNICallback: (name, done) => {
      sni = name; // runs during the handshake
      done(null, context);
    },
  });
  t.after(() => server.close());
  const result = await checkConnection("test.example", options(await listen(server)));
  assert.deepEqual(statuses(result), ["dns:pass", "port_443:pass", "tls_handshake:pass"]);
  assert.equal(sni, "test.example");
});

test("DNS failure fails dns and skips the rest", async () => {
  const notFound = Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  const result = await checkConnection("missing.example", options(1, { resolve: async () => Promise.reject(notFound) }));
  assert.deepEqual(statuses(result), ["dns:fail", "port_443:skip", "tls_handshake:skip"]);
  assert.equal(result.kind === "checked" && result.checks[0]?.message, "Domain not found");
});

test("a temporary DNS failure says so in every row", async () => {
  const again = Object.assign(new Error("try again"), { code: "EAI_AGAIN" });
  const result = await checkConnection("flaky.example", options(1, { resolve: async () => Promise.reject(again) }));
  assert.deepEqual(result.kind === "checked" && result.checks.map((c) => c.message), [
    "DNS lookup failed (EAI_AGAIN)",
    "Skipped: DNS lookup failed",
    "Skipped: DNS lookup failed",
  ]);
});

test("a blocked address is refused before connecting", async () => {
  const result = await checkConnection("internal.example", options(1, { isBlocked: () => true }));
  assert.deepEqual(result, { kind: "blocked" });
});

test("a mix of public and blocked addresses is refused", async () => {
  const result = await checkConnection(
    "mixed.example",
    options(1, { resolve: async () => ["1.1.1.1", "127.0.0.1"], isBlocked: (a) => a === "127.0.0.1" }),
  );
  assert.deepEqual(result, { kind: "blocked" });
});

test("a refused connection fails port_443", async () => {
  const server = net.createServer();
  const port = await listen(server);
  server.close(); // nothing listens on this port now
  await once(server, "close");
  const result = await checkConnection("closed.example", options(port));
  assert.deepEqual(statuses(result), ["dns:pass", "port_443:fail", "tls_handshake:skip"]);
  assert.equal(result.kind === "checked" && result.checks[1]?.message, "Connection refused on port 443");
});

test("a server that doesn't speak TLS fails tls_handshake", async (t) => {
  const server = net.createServer((socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"));
  t.after(() => server.close());
  const result = await checkConnection("plain.example", options(await listen(server)));
  assert.deepEqual(statuses(result), ["dns:pass", "port_443:pass", "tls_handshake:fail"]);
});

test("a server that never answers the handshake times out", async (t) => {
  const sockets: net.Socket[] = [];
  const server = net.createServer((socket) => sockets.push(socket));
  t.after(() => {
    for (const s of sockets) s.destroy();
    server.close();
  });
  const result = await checkConnection("silent.example", options(await listen(server)));
  assert.deepEqual(statuses(result), ["dns:pass", "port_443:pass", "tls_handshake:fail"]);
  assert.match(result.kind === "checked" ? (result.checks[2]?.message ?? "") : "", /no reply within/);
});
