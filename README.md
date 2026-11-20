# tls.shahbaaz.dev

Find out exactly what's wrong with a website's TLS certificate. Enter a domain and get every problem as a pass / fail list, with an overall verdict on top.

**Status:** early development. The app runs end to end, but `POST /api/check` returns a stub reply. See the milestones in [SPEC.md](SPEC.md).

## What it checks

- Expired
- Wrong host
- Self-signed
- Untrusted root (the chain doesn't end at a root in Node's bundled Mozilla list)
- Incomplete chain (the server doesn't send its intermediate certificates)
- Revoked (OCSP/CRL; "couldn't check" if the CA can't be reached)
- No Common Name, no Subject

It also reports sites with no https: the domain isn't found, nothing answers on port 443, or the TLS handshake fails.

## Requirements

- Node 26 or later
- npm

## Getting started

```bash
npm install
npm run dev:server   # terminal 1: API on http://127.0.0.1:3000
npm run dev:client   # terminal 2: open the URL Vite prints
```

## Commands

| Command | What it does |
|---|---|
| `npm run dev:server` | Start the API and restart it when files change |
| `npm run dev:client` | Start the Vite dev server, which passes `/api` to the API |
| `npm run typecheck` | Type-check the server and client |
| `npm test` | Run the server tests |
| `npm run build` | Build the client into `client/dist/` |

Run one test file with `node --test server/test/app.test.ts`, and add `--test-name-pattern="health"` to run tests by name.

## How it works

- **`server/`:** Express + TypeScript. Node runs the TypeScript directly (type stripping), so the server has no build step. Certificates are inspected with Node's built-in `tls`, `dns` and `crypto` modules.
- **`client/`:** Vite + React + TypeScript, a single page.

The server looks up the domain first and refuses private and internal IP addresses, so it can't be used to probe its own network. It then connects without stopping on validation errors and runs each check separately against the certificate chain, so one problem doesn't hide the others.

## API

`POST /api/check` with `{ "host": "expired.badssl.com" }`

```json
{
  "host": "expired.badssl.com",
  "verdict": "not_secure",
  "checks": [
    { "id": "expired", "status": "fail", "message": "Expired 2015-04-12" },
    { "id": "wrong_host", "status": "pass" }
  ],
  "certificate": { "subject": "...", "issuer": "...", "validTo": "...", "chain": [] }
}
```

- `verdict`: `secure`, `not_secure` or `unknown`
- `status`: `pass`, `fail` or `skip` (couldn't check)
- Invalid input returns `400` with `{ "error": "..." }`.

`GET /api/health` returns `{ "ok": true }`.

## Deployment

A DigitalOcean droplet. Nginx serves the client build and passes `/api/` to Node on `127.0.0.1:3000`, systemd keeps Node running, and Certbot provides the certificate. GitHub Actions will run CI and deploy over SSH.

## Testing against real sites

[badssl.com](https://badssl.com/) has a subdomain for each kind of certificate problem, such as `expired.badssl.com`, `wrong.host.badssl.com` and `self-signed.badssl.com`.

## License

[MIT](LICENSE)
