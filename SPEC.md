### TLS Check

Find out what exactly is wrong about your website's certificate

Input:
Users can enter their website address in a text box and submit

Output:
If no https, then website is not secure
If https, then Certificate details with final verdict about security

- Expired
- Wrong host
- Self signed
- Untrusted root
- Revoked
- No Common Name
- No Subject
- Incomplete Chain

Test:
https://badssl.com/ (Certificate issues urls)

---

## Decisions

### Product

- **Show a list of problems, not one verdict.** Every check runs on its own and the page shows each one as pass / fail / couldn't check. An overall verdict sits on top, e.g. "Not secure: 2 problems found".
- **Input:** `https://` is shown as fixed text in front of the text box, so the user types only the domain (`example.com`, `www.example.com`).
  - Clean up the input: trim, lowercase, and strip `https://`, `http://`, paths and query strings if the user pastes a full URL anyway.
  - Port is always 443. Reject IP addresses and anything that isn't a valid domain name.
- **"No https" covers three cases:**
  - **Domain not found:** the DNS lookup fails.
  - **Nothing answers on port 443:** the connection is refused or times out (5 s timeout). Reported as not secure.
  - **Not speaking TLS:** port 443 is open but the TLS handshake fails. Reported as not secure.
  - (Later) A site has HTTPS but plain HTTP doesn't redirect to it: a warning, not a failure.
- **Expiry:** fails when the certificate has expired or isn't valid yet. Under 14 days left is a **warning**, not a failure: certificates are getting shorter-lived and renew with about a third of their life left, so 14 days means renewal is overdue.
- **Wrong host:** matched the way browsers do: only subject alternative names count (not the Common Name), and a wildcard covers one whole label.
- **Domain names (SAN):** a certificate whose subject alternative names list no domain names fails: browsers stopped falling back to the Common Name in 2017. IP-address entries don't count. Wrong host is then skipped rather than counting the same problem twice.
- **No Common Name / no Subject:** not a problem today: browsers use only the SAN, and CAs are dropping the Common Name. Shown as a pass with a note, never a failure.
- **Self-signed:** the leaf certificate is signed by its own key. Both chain checks are skipped for a self-signed certificate rather than counting the same problem twice.
- **Chain path:** built by the server itself from the leaf up, not taken from Node's validation error (which reports only one problem). At each step a root in the trust store wins; otherwise the issuer must be a certificate the server sent that is a CA and whose key signed the certificate below it.
- **Incomplete chain:** the server doesn't send the intermediate certificate(s). Some browsers fetch the missing piece themselves, so the site "works in Chrome" but fails in other clients. We don't fetch it (the URL comes from the certificate, so fetching it is an SSRF risk), so untrusted root is skipped for an incomplete chain.
- **Untrusted root:** the chain ends at a self-signed root that isn't in the trust store.
- **Revocation:** checked with the CRL (the CA's list of revoked serial numbers) only; OCSP is dropped (Let's Encrypt has shut it down and browsers barely use it). The leaf fails if its serial number is on the list.
  - "Couldn't check" (skip) when: the certificate has no CRL URL (e.g. OCSP-only CAs), the chain has no issuer to verify the list with, the download fails, the signature doesn't verify, or the list is past its `nextUpdate`. Never a pass.
  - Fetched safely, since the URL comes from the certificate: `http:` on port 80 only, resolve the name and block private addresses, connect to that IP, 5 s timeout, 1 MB cap, no redirects. On any failure the connection is destroyed.
  - The DER is parsed by hand and the list's signature verified with the issuer's key from the chain path (an unverified list over plain HTTP could hide a revocation).
  - Cached in memory: only the revoked serials, keyed by URL, until `nextUpdate` (at most 24 h). At most 50 lists; the oldest is dropped first. Expired entries are dropped when looked up; failures aren't cached.
- **Trust store:** use Node's bundled Mozilla root list (`tls.rootCertificates`). It's the default and the same on the laptop and the droplet. "Untrusted root" means the chain doesn't end at a root on this list.

### How a check works (server side)

1. Clean up and validate the input domain.
2. DNS lookup. If it fails, report "Domain not found".
3. **Block private and internal IP addresses**, so the public server can't be used to probe the droplet's own network.
4. Connect to the checked IP address (not the name again, so DNS can't change in between), sending the domain as SNI. Connect to port 443 over TLS with validation errors _not_ stopping the connection (`rejectUnauthorized: false`), and collect the full certificate chain.
5. Run each check separately against the collected chain and return the list.

### API

`POST /api/check` with `{ "host": "expired.badssl.com" }`

```json
{
  "host": "expired.badssl.com",
  "verdict": "not_secure",
  "checks": [
    { "id": "expired", "status": "fail", "message": "Expired 2015-04-12" },
    { "id": "wrong_host", "status": "pass" }
  ],
  "certificate": {
    "subject": "...",
    "issuer": "...",
    "validTo": "...",
    "chain": []
  }
}
```

- `verdict`: `secure` | `not_secure` | `unknown`. Any `fail` gives `not_secure`; otherwise any `skip` gives `unknown`; otherwise `secure`. Warnings, and a skipped `revoked` check, don't change the verdict (browsers also let the site through when they can't check).
- `status`: `pass` | `warn` | `fail` | `skip` (skip = couldn't check)
- Connection checks come first: `dns`, `port_443`, `tls_handshake`. Then the certificate checks: `expired`, `wrong_host`, `self_signed`, `no_alt_names`, `no_subject`, `no_common_name`. Then the chain checks: `incomplete_chain`, `untrusted_root`. Then `revoked`. When a connection check fails, every later check is `skip`.
- `certificate` describes the leaf: `subject`, `issuer`, `validFrom`, `validTo`, `altNames`, `publicKey`, `signatureAlgorithm`, `serialNumber`, `fingerprint256` and `chain`: the certificates above the leaf up to the root, each with `subject`, `issuer`, `validFrom`, `validTo`, `fingerprint256` and `source` (`server`, or `trust_store` for a trusted root, which Node adds even when the server didn't send it). It is `null` when no certificate was collected (DNS, port 443 or the TLS handshake failed).
- Invalid input, or a domain that resolves to a private or internal address, returns `400` with `{ "error": "..." }`.
- Nginx rate-limits `/api/` per client IP; over the limit returns `429`.
- `GET /api/health` returns `{ "ok": true }` for deploy checks.

## Tech stack

| Area            | Choice                                                                                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Runtime         | Node 26 LTS. The server's TypeScript runs directly with Node's type stripping, so the server has no build step (`tsc` is only used for type checking). |
| Package manager | npm workspaces (`server/`, `client/`). No pnpm, no Nx for now.                                                                                         |
| Server          | Express + TypeScript, using Node's built-in `tls`, `dns` and `crypto` modules (no TLS libraries).                                                      |
| Client          | Vite + React + TypeScript, a single page. In development, Vite passes `/api` requests to the server.                                                   |
| Tests           | Node's built-in test runner (`node --test`).                                                                                                           |

## CI/CD: GitHub Actions

Code is pushed to GitHub. The first deploy is done by hand so each step is understood, then automated.

- **CI** (every push and pull request): install, type-check, test, build.
- **CD** (pushes to `main`, after CI passes): connect to the droplet over SSH, pull, install, build, restart the service, then check that `https://tls.shahbaaz.dev/api/health` responds.
- Deploys use a separate, limited user on the droplet with its own SSH key, kept in GitHub's encrypted secrets. Not root and not a personal key.

## Milestones

1. [x] **Skeleton, deployed:** a form that calls `POST /api/check` and gets a stub reply, live at `tls.shahbaaz.dev` behind Nginx, systemd and Certbot.
2. [x] **Connection checks:** domain not found, nothing on port 443, not speaking TLS.
3. [x] **Certificate details plus easy checks:** expired (warning under 14 days left), wrong host, self-signed. The page shows the results as a list.
4. [x] **Chain checks:** untrusted root, incomplete chain.
5. [ ] **Name and revocation checks:**
   - [x] **Part 1, name checks:** no domain names in the SAN (fails), no Common Name and no Subject (pass with a note).
   - [ ] **Part 2, revocation:** revoked, from the CRL only (no OCSP). "Couldn't check" doesn't change the verdict.
   - Also later: expired intermediate certificates.
6. [ ] **GitHub Actions:** CI first, then CD.
