// A minimal reader for DER, the binary encoding of certificates and CRLs. Each element is
// tag, length, value (TLV). Only what the revocation check needs: no writing, single-byte tags.

export class DerError extends Error {}

export interface Tlv {
  tag: number;
  value: Buffer; // the contents
  bytes: Buffer; // the whole element, header included (what signatures and name comparisons use)
}

// Lengths above 4 bytes would mean a 4 GB element; nothing we read comes close.
const MAX_LENGTH_BYTES = 4;

export function readTlv(buf: Buffer, offset = 0): Tlv & { end: number } {
  if (offset + 2 > buf.length) throw new DerError("truncated element");
  const tag = buf[offset]!;
  // Low 5 bits all set means a multi-byte tag, which certificates and CRLs don't use.
  if ((tag & 0x1f) === 0x1f) throw new DerError("multi-byte tags aren't supported");
  const first = buf[offset + 1]!;
  let length: number;
  let headerLength: number;
  if (first < 0x80) {
    length = first;
    headerLength = 2;
  } else {
    // Long form: the low bits say how many length bytes follow. 0x80 alone is BER's indefinite length.
    const count = first & 0x7f;
    if (count === 0) throw new DerError("indefinite length isn't allowed in DER");
    if (count > MAX_LENGTH_BYTES) throw new DerError("element too long");
    if (offset + 2 + count > buf.length) throw new DerError("truncated length");
    length = buf.readUIntBE(offset + 2, count);
    headerLength = 2 + count;
  }
  const start = offset + headerLength;
  const end = start + length;
  if (end > buf.length) throw new DerError("truncated element");
  return { tag, value: buf.subarray(start, end), bytes: buf.subarray(offset, end), end };
}

export function children(tlv: Tlv): Tlv[] {
  const items: Tlv[] = [];
  let offset = 0;
  while (offset < tlv.value.length) {
    const { end, ...item } = readTlv(tlv.value, offset);
    items.push(item);
    offset = end;
  }
  return items;
}

export function readOid(tlv: Tlv): string {
  if (tlv.tag !== 0x06 || tlv.value.length === 0) throw new DerError("not an object identifier");
  // Each number is base 128, high bit set on every byte but the last. The first number packs two (40 * a + b).
  const numbers: number[] = [];
  let current = 0;
  for (const byte of tlv.value) {
    current = current * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      numbers.push(current);
      current = 0;
    }
  }
  const [first = 0, ...rest] = numbers;
  const a = first < 80 ? Math.floor(first / 40) : 2;
  return [a, first - 40 * a, ...rest].join(".");
}

// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ); RFC 5280 requires the Z form.
export function readTime(tlv: Tlv): Date {
  const text = tlv.value.toString("latin1");
  let match: RegExpMatchArray | null;
  let year: number;
  if (tlv.tag === 0x17 && (match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text))) {
    const yy = Number(match[1]);
    year = yy < 50 ? 2000 + yy : 1900 + yy;
  } else if (tlv.tag === 0x18 && (match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text))) {
    year = Number(match[1]);
  } else {
    throw new DerError("not a valid time");
  }
  const [month, day, hour, minute, second] = match.slice(2).map(Number) as [number, number, number, number, number];
  return new Date(Date.UTC(year, month - 1, day, hour, minute, second));
}

// A serial number as uppercase hex without leading zero bytes, so "00 8F" and "8F" match.
export function integerKey(tlv: Tlv): string {
  if (tlv.tag !== 0x02) throw new DerError("not an integer");
  let start = 0;
  while (start < tlv.value.length - 1 && tlv.value[start] === 0) start++;
  const key = tlv.value.subarray(start).toString("hex").toUpperCase();
  return key === "00" || key === "" ? "0" : key;
}
