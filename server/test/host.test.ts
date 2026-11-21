import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanHost } from "../src/host.ts";

const accepted: [string, string][] = [
  ["example.com", "example.com"],
  ["  Example.COM  ", "example.com"],
  ["https://www.example.com/path?q=1#top", "www.example.com"],
  ["http://example.com", "example.com"],
  ["example.com:443", "example.com"],
  ["example.com.", "example.com"],
  ["expired.badssl.com", "expired.badssl.com"],
  ["bücher.de", "xn--bcher-kva.de"],
];

for (const [input, expected] of accepted) {
  test(`accepts ${JSON.stringify(input)}`, () => {
    assert.deepEqual(cleanHost(input), { ok: true, host: expected });
  });
}

const rejected: [string, string][] = [
  ["", "Enter a domain name"],
  ["ftp://example.com", "Only http:// and https:// addresses can be checked"],
  ["example.com:8443", "Only port 443 can be checked"],
  ["127.0.0.1", "Enter a domain name, not an IP address"],
  ["0x7f.1", "Enter a domain name, not an IP address"],
  ["[::1]", "Enter a domain name, not an IP address"],
  ["localhost", "Enter a valid domain name"],
  ["exa mple.com", "Enter a valid domain name"],
  ["under_score.com", "Enter a valid domain name"],
  ["-bad.com", "Enter a valid domain name"],
  ["a..com", "Enter a valid domain name"],
  ["user:pass@example.com", "Enter a valid domain name"],
  [`${"a".repeat(64)}.com`, "Enter a valid domain name"],
];

for (const [input, error] of rejected) {
  test(`rejects ${JSON.stringify(input)}`, () => {
    assert.deepEqual(cleanHost(input), { ok: false, error });
  });
}
