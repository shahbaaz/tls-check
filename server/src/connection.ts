import { lookup } from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { isBlockedAddress } from "./blocklist.ts";
import type { CheckResult } from "./types.ts";

export interface ConnectionOptions {
  resolve: (host: string) => Promise<string[]>;
  isBlocked: (address: string) => boolean;
  port: number;
  timeoutMs: number;
}

export const defaultConnectionOptions: ConnectionOptions = {
  resolve: async (host) => (await lookup(host, { all: true, order: "ipv4first" })).map((a) => a.address),
  isBlocked: isBlockedAddress,
  port: 443,
  timeoutMs: 5000,
};

export type ConnectionResult =
  | { kind: "blocked" } // resolves to a private or internal address: refuse to connect
  | { kind: "checked"; checks: CheckResult[] };

// Runs the dns, port_443 and tls_handshake checks. A failed check makes the later ones "skip".
export async function checkConnection(
  host: string,
  options: ConnectionOptions = defaultConnectionOptions,
): Promise<ConnectionResult> {
  let addresses: string[];
  try {
    addresses = await options.resolve(host);
  } catch (err) {
    const message = dnsMessage(err);
    const reason = message === "Domain not found" ? "domain not found" : "DNS lookup failed";
    return checked(fail("dns", message), skip("port_443", reason), skip("tls_handshake", reason));
  }
  const address = addresses[0];
  if (address === undefined) {
    return checked(fail("dns", "Domain not found"), skip("port_443", "domain not found"), skip("tls_handshake", "domain not found"));
  }
  // Check every address, not just the one we use, so a mixed public/private answer is refused.
  if (addresses.some(options.isBlocked)) return { kind: "blocked" };
  const dns = pass("dns", `Resolves to ${address}`);

  let socket: net.Socket;
  try {
    socket = await openSocket(address, options.port, options.timeoutMs);
  } catch (err) {
    return checked(dns, fail("port_443", portMessage(err, options.timeoutMs)), skip("tls_handshake", "port 443 didn't answer"));
  }
  const port = pass("port_443", "Port 443 is open");

  // Connect to the address we checked (not the name again) so DNS can't change in between.
  // servername sends SNI so the server picks the certificate for this domain.
  try {
    const tlsSocket = await handshake(socket, host, options.timeoutMs);
    const protocol = tlsSocket.getProtocol();
    tlsSocket.destroy();
    return checked(dns, port, pass("tls_handshake", `Handshake completed${protocol ? ` (${protocol})` : ""}`));
  } catch (err) {
    return checked(dns, port, fail("tls_handshake", `TLS handshake failed: ${errorText(err)}`));
  }
}

function openSocket(address: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: address, port });
    socket.setTimeout(timeoutMs);
    const onTimeout = () => {
      socket.destroy();
      reject(new ConnectTimeout());
    };
    const onError = (err: Error) => {
      socket.destroy();
      reject(err);
    };
    socket.once("timeout", onTimeout);
    socket.once("error", onError);
    socket.once("connect", () => {
      socket.setTimeout(0);
      socket.off("timeout", onTimeout);
      socket.off("error", onError);
      resolve(socket);
    });
  });
}

function handshake(socket: net.Socket, servername: string, timeoutMs: number): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    // rejectUnauthorized: false, so certificate problems don't stop the connection;
    // each certificate check runs on its own later.
    const tlsSocket = tls.connect({ socket, servername, rejectUnauthorized: false });
    const timer = setTimeout(() => {
      tlsSocket.destroy();
      reject(new Error(`no reply within ${timeoutMs / 1000} s`));
    }, timeoutMs);
    tlsSocket.on("error", (err) => {
      clearTimeout(timer);
      tlsSocket.destroy();
      reject(err);
    });
    tlsSocket.once("secureConnect", () => {
      clearTimeout(timer);
      resolve(tlsSocket);
    });
  });
}

class ConnectTimeout extends Error {}

function dnsMessage(err: unknown): string {
  const code = errorCode(err);
  if (code === "ENOTFOUND" || code === "ENODATA") return "Domain not found";
  return `DNS lookup failed${code ? ` (${code})` : ""}`;
}

function portMessage(err: unknown, timeoutMs: number): string {
  if (err instanceof ConnectTimeout) return `No answer on port 443 within ${timeoutMs / 1000} s`;
  if (errorCode(err) === "ECONNREFUSED") return "Connection refused on port 443";
  return `Couldn't connect to port 443 (${errorText(err)})`;
}

function errorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : undefined;
}

function errorText(err: unknown): string {
  return errorCode(err) ?? (err instanceof Error ? err.message : String(err));
}

function checked(...checks: CheckResult[]): ConnectionResult {
  return { kind: "checked", checks };
}

function pass(id: string, message: string): CheckResult {
  return { id, status: "pass", message };
}

function fail(id: string, message: string): CheckResult {
  return { id, status: "fail", message };
}

function skip(id: string, reason: string): CheckResult {
  return { id, status: "skip", message: `Skipped: ${reason}` };
}
