import { test } from "node:test";
import assert from "node:assert/strict";
import { isBlockedAddress } from "../src/blocklist.ts";

const blocked = [
  "127.0.0.1",
  "10.1.2.3",
  "172.16.0.1",
  "192.168.1.1",
  "169.254.169.254", // cloud metadata
  "100.64.0.1",
  "0.0.0.0",
  "::1",
  "::ffff:127.0.0.1",
  "::127.0.0.1", // IPv4-compatible IPv6 (deprecated)
  "::10.0.0.1",
  "fd00::1",
  "fe80::1",
];
const allowed = ["1.1.1.1", "93.184.215.14", "2606:4700:4700::1111"];

for (const address of blocked) {
  test(`blocks ${address}`, () => assert.equal(isBlockedAddress(address), true));
}
for (const address of allowed) {
  test(`allows ${address}`, () => assert.equal(isBlockedAddress(address), false));
}
