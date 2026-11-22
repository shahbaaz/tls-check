import { after, before, test } from "node:test";
import type { TestContext } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import tls from "node:tls";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/app.ts";
import { trustStore } from "../src/chain.ts";
import type { CheckResponse } from "../src/types.ts";

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
      { id: "expired", status: "skip", message: "Skipped: domain not found" },
      { id: "wrong_host", status: "skip", message: "Skipped: domain not found" },
      { id: "self_signed", status: "skip", message: "Skipped: domain not found" },
      { id: "no_alt_names", status: "skip", message: "Skipped: domain not found" },
      { id: "no_subject", status: "skip", message: "Skipped: domain not found" },
      { id: "no_common_name", status: "skip", message: "Skipped: domain not found" },
      { id: "incomplete_chain", status: "skip", message: "Skipped: domain not found" },
      { id: "untrusted_root", status: "skip", message: "Skipped: domain not found" },
      { id: "revoked", status: "skip", message: "Skipped: domain not found" },
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

const fixtures = new URL("./fixtures/", import.meta.url);
const noNetwork = async (): Promise<Buffer> => {
  throw new Error("no network in tests");
};

// Starts a local TLS server serving the given fixture certificate(s) as test.example, and an app
// that trusts the test CA, then runs a check against it. fetchCrl stands in for the CRL download.
async function checkFixture(t: TestContext, keyFile: string, certFiles: string[], fetchCrl = noNetwork) {
  const pem = (file: string) => readFileSync(new URL(file, fixtures), "utf8");
  const tlsServer = tls.createServer({ key: pem(keyFile), cert: certFiles.map(pem).join("") });
  tlsServer.listen(0, "127.0.0.1");
  await once(tlsServer, "listening");
  const options = {
    resolve: async () => ["127.0.0.1"],
    isBlocked: () => false,
    port: (tlsServer.address() as AddressInfo).port,
    timeoutMs: 300,
  };
  const app = createApp(options, trustStore([pem("ca-cert.pem")]), { fetchCrl }).listen(0, "127.0.0.1");
  await once(app, "listening");
  t.after(() => {
    app.closeAllConnections();
    app.close();
    tlsServer.close();
  });

  const res = await fetch(`http://127.0.0.1:${(app.address() as AddressInfo).port}/api/check`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ host: "test.example" }),
  });
  return (await res.json()) as CheckResponse;
}

function statuses(body: CheckResponse) {
  return body.checks.map((c) => `${c.id}:${c.status}`);
}

const connectionPasses = ["dns:pass", "port_443:pass", "tls_handshake:pass"];

test("POST /api/check runs every check against a TLS server", async (t) => {
  const body = await checkFixture(t, "leaf-key.pem", ["leaf-cert.pem"]);
  assert.deepEqual(statuses(body), [
    ...connectionPasses,
    "expired:pass",
    "wrong_host:pass",
    "self_signed:pass",
    "no_alt_names:pass",
    "no_subject:pass",
    "no_common_name:pass",
    "incomplete_chain:pass",
    "untrusted_root:pass",
    "revoked:skip", // this certificate lists no CRL; a skipped revocation check leaves the verdict alone
  ]);
  assert.equal(body.verdict, "secure");
  assert.equal(body.certificate?.subject, "CN=test.example");
  assert.deepEqual(body.certificate?.altNames, ["test.example", "*.wild.example"]);
  assert.deepEqual(
    body.certificate?.chain.map((c) => [c.subject, c.source]),
    [["CN=TLS Check Test CA", "trust_store"]],
  );
});

test("POST /api/check collects the intermediate the server sends", async (t) => {
  const body = await checkFixture(t, "chain-leaf-key.pem", ["chain-leaf-cert.pem", "intermediate-cert.pem"]);
  assert.equal(body.verdict, "secure");
  assert.deepEqual(
    body.certificate?.chain.map((c) => [c.subject, c.source]),
    [
      ["CN=TLS Check Test Intermediate", "server"],
      ["CN=TLS Check Test CA", "trust_store"],
    ],
  );
});

test("POST /api/check reports a missing intermediate as not secure", async (t) => {
  const body = await checkFixture(t, "chain-leaf-key.pem", ["chain-leaf-cert.pem"]);
  assert.deepEqual(statuses(body).slice(-3), ["incomplete_chain:fail", "untrusted_root:skip", "revoked:skip"]);
  assert.equal(body.verdict, "not_secure");
  assert.deepEqual(body.certificate?.chain, []);
});

test("POST /api/check reports a self-signed certificate as not secure", async (t) => {
  const body = await checkFixture(t, "test-key.pem", ["test-cert.pem"]);
  const results = statuses(body);
  assert.ok(results.includes("self_signed:fail"));
  assert.deepEqual(results.slice(-3), ["incomplete_chain:skip", "untrusted_root:skip", "revoked:skip"]);
  assert.equal(body.verdict, "not_secure");
});

test("POST /api/check reports a certificate with no domain names as not secure", async (t) => {
  const body = await checkFixture(t, "no-san-key.pem", ["no-san-cert.pem"]);
  const results = statuses(body);
  assert.ok(results.includes("wrong_host:skip"));
  assert.ok(results.includes("no_alt_names:fail"));
  assert.equal(body.verdict, "not_secure");
});

test("POST /api/check accepts a certificate with an empty Subject", async (t) => {
  const body = await checkFixture(t, "no-subject-key.pem", ["no-subject-cert.pem"]);
  assert.equal(body.verdict, "secure");
  assert.equal(body.certificate?.subject, "");
});

const serveRootCrl = async () => readFileSync(new URL("root.crl", fixtures));

test("POST /api/check passes a certificate that isn't on its CRL", async (t) => {
  const body = await checkFixture(t, "crl-leaf-key.pem", ["crl-leaf-cert.pem"], serveRootCrl);
  assert.equal(statuses(body).at(-1), "revoked:pass");
  assert.equal(body.verdict, "secure");
});

test("POST /api/check reports a revoked certificate as not secure", async (t) => {
  const body = await checkFixture(t, "revoked-leaf-key.pem", ["revoked-leaf-cert.pem"], serveRootCrl);
  assert.equal(statuses(body).at(-1), "revoked:fail");
  assert.equal(body.verdict, "not_secure");
});

test("POST /api/check stays secure when the CRL can't be downloaded", async (t) => {
  const body = await checkFixture(t, "crl-leaf-key.pem", ["crl-leaf-cert.pem"]);
  assert.equal(statuses(body).at(-1), "revoked:skip");
  assert.equal(body.verdict, "secure");
});
