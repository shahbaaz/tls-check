import { test } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { buildPath, checkChain, defaultTrustStore, skipChainChecks, summarizeChain, trustStore } from "../src/chain.ts";

// See fixtures/make-ca-signed-certs.sh: root -> intermediate -> chainLeaf, root -> leaf,
// leaf -> signedByLeaf (its issuer isn't a CA). selfSigned is test-cert.pem.
const fixtures = new URL("./fixtures/", import.meta.url);
const pem = (file: string) => readFileSync(new URL(file, fixtures), "utf8");
const root = new X509Certificate(pem("ca-cert.pem"));
const intermediate = new X509Certificate(pem("intermediate-cert.pem"));
const chainLeaf = new X509Certificate(pem("chain-leaf-cert.pem"));
const leaf = new X509Certificate(pem("leaf-cert.pem"));
const signedByLeaf = new X509Certificate(pem("signed-by-leaf-cert.pem"));
const selfSigned = new X509Certificate(pem("test-cert.pem"));

const store = trustStore([pem("ca-cert.pem")]);
const emptyStore = trustStore([]);

function run(cert: X509Certificate, sent: X509Certificate[], withStore = store) {
  const path = buildPath(cert, sent, withStore);
  return { path, checks: checkChain(cert, path) };
}

function statuses(checks: { id: string; status: string }[]) {
  return checks.map((c) => `${c.id}:${c.status}`);
}

test("a full chain to a trusted root passes both checks", () => {
  const { path, checks } = run(chainLeaf, [intermediate]);
  assert.equal(path.end, "trusted");
  assert.deepEqual(statuses(checks), ["incomplete_chain:pass", "untrusted_root:pass"]);
  assert.equal(checks[1]?.message, "Chains to TLS Check Test CA, a trusted root");
  assert.deepEqual(
    summarizeChain(path).map((c) => [c.subject, c.source]),
    [
      ["CN=TLS Check Test Intermediate", "server"],
      ["CN=TLS Check Test CA", "trust_store"],
    ],
  );
});

test("a leaf issued by a trusted root needs no intermediate", () => {
  const { checks } = run(leaf, []);
  assert.deepEqual(statuses(checks), ["incomplete_chain:pass", "untrusted_root:pass"]);
});

test("certificates sent out of order, or with the root, still chain", () => {
  const { path, checks } = run(chainLeaf, [root, intermediate]);
  assert.deepEqual(statuses(checks), ["incomplete_chain:pass", "untrusted_root:pass"]);
  // The root the server sent is the one in the trust store, so it's listed once, as a trusted root.
  assert.deepEqual(
    path.links.map((l) => l.source),
    ["server", "trust_store"],
  );
});

test("a missing intermediate fails incomplete_chain and skips untrusted_root", () => {
  const { path, checks } = run(chainLeaf, []);
  assert.equal(path.end, "incomplete");
  assert.deepEqual(statuses(checks), ["incomplete_chain:fail", "untrusted_root:skip"]);
  assert.match(checks[0]?.message ?? "", /^The server didn't send the intermediate certificate TLS Check Test Intermediate\./);
  assert.equal(checks[1]?.message, "Skipped: chain is incomplete");
});

test("an untrusted root sent by the server fails untrusted_root", () => {
  const { path, checks } = run(chainLeaf, [intermediate, root], emptyStore);
  assert.equal(path.end, "untrusted_root");
  assert.deepEqual(statuses(checks), ["incomplete_chain:pass", "untrusted_root:fail"]);
  assert.equal(checks[1]?.message, "Ends at TLS Check Test CA, which isn't a trusted root");
  assert.deepEqual(
    summarizeChain(path).map((c) => c.source),
    ["server", "server"],
  );
});

test("a certificate that isn't a CA doesn't count as an issuer", () => {
  // leaf really did sign signedByLeaf, but leaf has CA:FALSE, so the chain stops there.
  const { path, checks } = run(signedByLeaf, [leaf]);
  assert.equal(path.end, "incomplete");
  assert.deepEqual(path.links, []);
  assert.deepEqual(statuses(checks), ["incomplete_chain:fail", "untrusted_root:skip"]);
});

test("a self-signed leaf skips both checks", () => {
  const { checks } = run(selfSigned, []);
  assert.deepEqual(checks, [
    { id: "incomplete_chain", status: "skip", message: "Skipped: certificate is self-signed" },
    { id: "untrusted_root", status: "skip", message: "Skipped: certificate is self-signed" },
  ]);
});

test("skipChainChecks gives a skip row per check", () => {
  assert.deepEqual(statuses(skipChainChecks("TLS handshake failed")), ["incomplete_chain:skip", "untrusted_root:skip"]);
});

test("the default trust store loads Node's bundled roots", () => {
  assert.ok(defaultTrustStore.roots.length > 100);
});
