import http from "node:http";
import net from "node:net";
import { isBlockedAddress } from "./blocklist.ts";
import { defaultConnectionOptions } from "./connection.ts";

// Downloads a CRL. The URL comes from the certificate, which anyone can make, so this guards
// against the public server being used to reach internal addresses (SSRF), and against
// slow or huge downloads.

// The message is the short reason shown to the user, e.g. "HTTP 404".
export class FetchError extends Error {}

export interface FetchOptions {
  resolve: (host: string) => Promise<string[]>;
  isBlocked: (address: string) => boolean;
  timeoutMs: number; // for the whole download, not just until the first byte
  maxBytes: number;
  port: number; // the only port connected to: CRLs are served on 80
}

export const defaultFetchOptions: FetchOptions = {
  resolve: defaultConnectionOptions.resolve,
  isBlocked: isBlockedAddress,
  timeoutMs: 5000,
  maxBytes: 1_000_000,
  port: 80,
};

export async function fetchCrl(url: string, options: FetchOptions = defaultFetchOptions): Promise<Buffer> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new FetchError("not an http:// URL");
  }
  if (parsed.protocol !== "http:") throw new FetchError("not an http:// URL");
  // URL drops a default :80, leaving port empty. Other ports could aim the server at any service.
  if (Number(parsed.port || 80) !== options.port) throw new FetchError(`only port ${options.port} is allowed`);

  // URL keeps IPv6 literals in brackets.
  const hostname = parsed.hostname.replace(/^\[(.*)\]$/, "$1");
  let addresses: string[];
  if (net.isIP(hostname)) {
    addresses = [hostname];
  } else {
    try {
      addresses = await options.resolve(hostname);
    } catch {
      throw new FetchError("CRL host not found");
    }
  }
  const address = addresses[0];
  if (address === undefined) throw new FetchError("CRL host not found");
  // Every address, as for the checked domain: a mixed public/private answer is refused.
  if (addresses.some(options.isBlocked)) throw new FetchError("private address");

  return download(parsed, address, options);
}

function download(url: URL, address: string, { timeoutMs, maxBytes, port }: FetchOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    // Connect to the address we checked, not the name again, so DNS can't change in between.
    // agent: false so the connection is closed afterwards rather than kept for reuse.
    const req = http.get({
      host: address,
      port,
      path: url.pathname + url.search,
      headers: { host: url.host },
      agent: false,
    });
    const tooLarge = `larger than ${maxBytes % 1_000_000 === 0 ? `${maxBytes / 1_000_000} MB` : `${maxBytes} bytes`}`;
    let settled = false;
    const finish = (error: FetchError | undefined, body?: Buffer) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy(); // closes the connection whatever state it's in
      if (error) reject(error);
      else resolve(body!);
    };
    const timer = setTimeout(() => finish(new FetchError(`no answer within ${timeoutMs / 1000} s`)), timeoutMs);

    req.on("error", (err) => finish(new FetchError(`couldn't connect (${errorCode(err)})`)));
    req.on("response", (res) => {
      // Anything but 200 fails, so redirects (which could point anywhere) are never followed.
      if (res.statusCode !== 200) return finish(new FetchError(`HTTP ${res.statusCode}`));
      if (Number(res.headers["content-length"]) > maxBytes) return finish(new FetchError(tooLarge));
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxBytes) return finish(new FetchError(tooLarge));
        chunks.push(chunk);
      });
      res.on("end", () => finish(undefined, Buffer.concat(chunks)));
      res.on("error", (err) => finish(new FetchError(`download failed (${errorCode(err)})`)));
    });
  });
}

function errorCode(err: Error): string {
  const code = (err as { code?: unknown }).code;
  return typeof code === "string" ? code : err.message;
}
