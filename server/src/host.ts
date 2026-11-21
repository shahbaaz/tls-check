import { isIP } from "node:net";

export type HostResult = { ok: true; host: string } | { ok: false; error: string };

// One DNS label: letters, digits and hyphens, 1-63 characters, no hyphen at either end.
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

// Turns user input ("Example.com", "https://example.com/path?q=1") into a bare domain.
export function cleanHost(input: string): HostResult {
  let text = input.trim();
  if (text === "") return invalid("Enter a domain name");

  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(text);
  if (scheme && !/^https?$/i.test(scheme[1] ?? "")) {
    return invalid("Only http:// and https:// addresses can be checked");
  }
  if (!scheme) text = `https://${text}`;

  // The URL parser lowercases, converts Unicode names to punycode and drops path, query and fragment.
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return invalid("Enter a valid domain name");
  }
  if (url.username || url.password) return invalid("Enter a valid domain name");
  if (url.port !== "" && url.port !== "443") return invalid("Only port 443 can be checked");

  let host = url.hostname;
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.startsWith("[") || isIP(host)) {
    return invalid("Enter a domain name, not an IP address");
  }

  const labels = host.split(".");
  const tld = labels.at(-1) ?? "";
  if (host.length > 253 || labels.length < 2 || !labels.every((l) => LABEL.test(l)) || /^\d+$/.test(tld)) {
    return invalid("Enter a valid domain name");
  }
  return { ok: true, host };
}

function invalid(error: string): HostResult {
  return { ok: false, error };
}
