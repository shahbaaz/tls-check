import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { FetchError, fetchCrl } from "../src/crl-fetch.ts";
import type { FetchOptions } from "../src/crl-fetch.ts";

let server: http.Server;
let port: number;
let requests: { url: string | undefined; host: string | undefined }[] = [];

before(async () => {
  server = http.createServer((req, res) => {
    requests.push({ url: req.url, host: req.headers.host });
    switch (req.url) {
      case "/ok.crl":
        res.end(Buffer.alloc(10, 1));
        return;
      case "/redirect.crl":
        res.writeHead(302, { location: "/ok.crl" }).end();
        return;
      case "/big.crl":
        res.end(Buffer.alloc(2000, 1));
        return;
      case "/big-header.crl":
        res.writeHead(200, { "content-length": "2000" }).flushHeaders(); // and never send the body
        return;
      case "/drip.crl": {
        res.writeHead(200);
        const timer = setInterval(() => res.write("x"), 50);
        res.on("close", () => clearInterval(timer));
        return;
      }
      default: // /silent.crl: never answer
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  port = (server.address() as AddressInfo).port;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

// The fetcher only uses one port (80 in production); here it's the test server's.
const options = (): FetchOptions => ({
  resolve: async () => ["127.0.0.1"],
  isBlocked: () => false,
  timeoutMs: 300,
  maxBytes: 1000,
  port,
});

const url = (path: string) => `http://crl.test.example:${port}${path}`;

// The fetcher must leave nothing open after it gives up.
async function assertNoOpenConnections() {
  for (let i = 0; i < 20; i++) {
    const count = await new Promise<number>((resolve, reject) =>
      server.getConnections((err, n) => (err ? reject(err) : resolve(n))),
    );
    if (count === 0) return;
    await sleep(10);
  }
  assert.fail("a connection was left open");
}

async function rejectsWith(promise: Promise<unknown>, message: RegExp) {
  await assert.rejects(promise, (err: unknown) => {
    assert.ok(err instanceof FetchError, `expected FetchError, got ${String(err)}`);
    assert.match(err.message, message);
    return true;
  });
}

test("fetchCrl downloads the body and sends the URL's host", async () => {
  requests = [];
  const body = await fetchCrl(url("/ok.crl"), options());
  assert.deepEqual(body, Buffer.alloc(10, 1));
  assert.deepEqual(requests, [{ url: "/ok.crl", host: `crl.test.example:${port}` }]);
  await assertNoOpenConnections();
});

test("fetchCrl doesn't follow redirects", async () => {
  requests = [];
  await rejectsWith(fetchCrl(url("/redirect.crl"), options()), /^HTTP 302$/);
  assert.equal(requests.length, 1);
  await assertNoOpenConnections();
});

test("fetchCrl stops at the size limit", async () => {
  await rejectsWith(fetchCrl(url("/big.crl"), options()), /^larger than 1000 bytes$/);
  await assertNoOpenConnections();
});

test("fetchCrl rejects a Content-Length over the limit without reading the body", async () => {
  await rejectsWith(fetchCrl(url("/big-header.crl"), options()), /^larger than 1000 bytes$/);
  await assertNoOpenConnections();
});

test("fetchCrl gives up when the server doesn't answer", async () => {
  const started = Date.now();
  await rejectsWith(fetchCrl(url("/silent.crl"), options()), /^no answer within 0.3 s$/);
  assert.ok(Date.now() - started < 1000);
  await assertNoOpenConnections();
});

test("fetchCrl's time limit covers the whole download, not just the wait for data", async () => {
  const started = Date.now();
  await rejectsWith(fetchCrl(url("/drip.crl"), options()), /^no answer within 0.3 s$/);
  assert.ok(Date.now() - started < 1000);
  await assertNoOpenConnections();
});

test("fetchCrl refuses a host with a private address without connecting", async () => {
  requests = [];
  const blocked = { ...options(), isBlocked: (address: string) => address === "127.0.0.1" };
  await rejectsWith(fetchCrl(url("/ok.crl"), blocked), /^private address$/);
  await rejectsWith(fetchCrl(`http://127.0.0.1:${port}/ok.crl`, blocked), /^private address$/);
  assert.equal(requests.length, 0);
});

test("fetchCrl refuses when any of the host's addresses is private", async () => {
  const mixed = { ...options(), resolve: async () => ["127.0.0.1", "10.0.0.1"], isBlocked: (a: string) => a === "10.0.0.1" };
  await rejectsWith(fetchCrl(url("/ok.crl"), mixed), /^private address$/);
});

test("fetchCrl only fetches http:// URLs", async () => {
  await rejectsWith(fetchCrl(`https://crl.test.example:${port}/ok.crl`, options()), /^not an http:\/\/ URL$/);
  await rejectsWith(fetchCrl("ftp://crl.test.example/ok.crl", options()), /^not an http:\/\/ URL$/);
  await rejectsWith(fetchCrl("not a url", options()), /^not an http:\/\/ URL$/);
});

test("fetchCrl reports a failed DNS lookup", async () => {
  const failing = { ...options(), resolve: async () => Promise.reject(new Error("ENOTFOUND")) };
  await rejectsWith(fetchCrl(url("/ok.crl"), failing), /^CRL host not found$/);
});

test("fetchCrl only connects to the allowed port", async () => {
  requests = [];
  await rejectsWith(fetchCrl(`http://crl.test.example:${port + 1}/ok.crl`, options()), new RegExp(`^only port ${port} is allowed$`));
  await rejectsWith(fetchCrl("http://crl.test.example/ok.crl", options()), new RegExp(`^only port ${port} is allowed$`));
  assert.equal(requests.length, 0);
});

test("fetchCrl allows port 80 by default", async () => {
  const blocked = { ...options(), port: 80, isBlocked: () => true };
  // Reaching the address check means the port was accepted.
  await rejectsWith(fetchCrl("http://crl.test.example/ok.crl", blocked), /^private address$/);
  await rejectsWith(fetchCrl("http://crl.test.example:80/ok.crl", blocked), /^private address$/);
  await rejectsWith(fetchCrl("http://crl.test.example:8080/ok.crl", blocked), /^only port 80 is allowed$/);
});
