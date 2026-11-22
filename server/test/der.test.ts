import { test } from "node:test";
import assert from "node:assert/strict";
import { DerError, children, integerKey, readOid, readTime, readTlv } from "../src/der.ts";

const hex = (s: string) => Buffer.from(s.replace(/\s/g, ""), "hex");
const ascii = (tag: number, text: string) => Buffer.concat([Buffer.from([tag, text.length]), Buffer.from(text)]);

test("readTlv reads a short element and children reads inside it", () => {
  const tlv = readTlv(hex("30 03 02 01 05"));
  assert.equal(tlv.tag, 0x30);
  assert.deepEqual(tlv.value, hex("02 01 05"));
  assert.deepEqual(tlv.bytes, hex("30 03 02 01 05"));
  assert.equal(tlv.end, 5);
  const inner = children(tlv);
  assert.equal(inner.length, 1);
  assert.equal(inner[0]?.tag, 0x02);
  assert.deepEqual(inner[0]?.value, hex("05"));
});

test("readTlv reads a long-form length", () => {
  const tlv = readTlv(Buffer.concat([hex("04 82 01 00"), Buffer.alloc(256, 7)]));
  assert.equal(tlv.value.length, 256);
  assert.equal(tlv.end, 260);
});

test("readTlv reads at an offset", () => {
  const tlv = readTlv(hex("ff 02 01 09"), 1);
  assert.equal(tlv.tag, 0x02);
  assert.equal(tlv.end, 4);
});

test("readTlv throws DerError on malformed input", () => {
  for (const bad of ["", "30", "30 05 02 01", "30 80 00 00", "30 85 00 00 00 00 01 00", "1f 01 00"]) {
    assert.throws(() => readTlv(hex(bad)), DerError, bad);
  }
});

test("children throws DerError when an inner element runs past the end", () => {
  assert.throws(() => children(readTlv(hex("30 02 02 05"))), DerError);
});

test("readOid gives the dotted form", () => {
  assert.equal(readOid(readTlv(hex("06 03 55 1d 1f"))), "2.5.29.31");
  assert.equal(readOid(readTlv(hex("06 08 2a 86 48 ce 3d 04 03 02"))), "1.2.840.10045.4.3.2");
});

test("readTime reads UTCTime and GeneralizedTime", () => {
  assert.equal(readTime(readTlv(ascii(0x17, "261122120000Z"))).toISOString(), "2026-11-22T12:00:00.000Z");
  assert.equal(readTime(readTlv(ascii(0x17, "491231235959Z"))).getUTCFullYear(), 2049);
  assert.equal(readTime(readTlv(ascii(0x17, "500101000000Z"))).getUTCFullYear(), 1950);
  assert.equal(readTime(readTlv(ascii(0x18, "21261122120000Z"))).getUTCFullYear(), 2126);
  assert.throws(() => readTime(readTlv(ascii(0x17, "2611221200"))), DerError);
  assert.throws(() => readTime(readTlv(hex("02 01 05"))), DerError);
});

test("integerKey ignores leading zero bytes", () => {
  assert.equal(integerKey(readTlv(hex("02 02 00 8f"))), "8F");
  assert.equal(integerKey(readTlv(hex("02 01 8f"))), "8F");
  assert.equal(integerKey(readTlv(hex("02 01 00"))), "0");
  assert.equal(integerKey(readTlv(hex("02 03 01 0a ff"))), "010AFF");
});
