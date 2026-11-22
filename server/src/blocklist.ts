import { BlockList } from "node:net";
import { networkInterfaces } from "node:os";

// Addresses the public server must never connect to (SSRF protection).
// BlockList applies the IPv4 rules to IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) too.
const BLOCKED_RANGES: [string, number, "ipv4" | "ipv6"][] = [
  ["0.0.0.0", 8, "ipv4"], // "this network"
  ["10.0.0.0", 8, "ipv4"], // private
  ["100.64.0.0", 10, "ipv4"], // carrier-grade NAT
  ["127.0.0.0", 8, "ipv4"], // loopback
  ["169.254.0.0", 16, "ipv4"], // link-local, cloud metadata
  ["172.16.0.0", 12, "ipv4"], // private
  ["192.0.0.0", 24, "ipv4"], // IETF protocol assignments
  ["192.0.2.0", 24, "ipv4"], // documentation
  ["192.168.0.0", 16, "ipv4"], // private
  ["198.18.0.0", 15, "ipv4"], // benchmarking
  ["198.51.100.0", 24, "ipv4"], // documentation
  ["203.0.113.0", 24, "ipv4"], // documentation
  ["224.0.0.0", 4, "ipv4"], // multicast
  ["240.0.0.0", 4, "ipv4"], // reserved, broadcast
  ["::", 96, "ipv6"], // unspecified, loopback, IPv4-compatible (deprecated, can wrap a private IPv4 address)
  ["64:ff9b::", 96, "ipv6"], // NAT64, can wrap a private IPv4 address
  ["100::", 64, "ipv6"], // discard
  ["2001::", 32, "ipv6"], // Teredo
  ["2001:db8::", 32, "ipv6"], // documentation
  ["2002::", 16, "ipv6"], // 6to4, can wrap a private IPv4 address
  ["fc00::", 7, "ipv6"], // unique local (private)
  ["fe80::", 10, "ipv6"], // link-local
  ["ff00::", 8, "ipv6"], // multicast
];

function buildBlockList(): BlockList {
  const list = new BlockList();
  for (const [network, prefix, type] of BLOCKED_RANGES) list.addSubnet(network, prefix, type);
  // The server's own addresses, including the droplet's public IP.
  for (const addresses of Object.values(networkInterfaces())) {
    for (const { address, family } of addresses ?? []) {
      list.addAddress(address.split("%")[0] ?? address, family === "IPv6" ? "ipv6" : "ipv4");
    }
  }
  return list;
}

const blockList = buildBlockList();

export function isBlockedAddress(address: string): boolean {
  return blockList.check(address, address.includes(":") ? "ipv6" : "ipv4");
}
