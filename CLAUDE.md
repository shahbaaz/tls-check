# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

**`SPEC.md` is the source of truth** for requirements and decisions: product behavior, the API, the tech stack, CI/CD and the milestones. Milestones 1–3 are live; see SPEC.md for what's next.

This is the owner's personal learning project. They want to talk through decisions before any files are created or changed, so wait for an explicit go-ahead before building.

Build in SPEC.md milestone order; revocation comes last.

## What it is

**TLS Check** (deployed at tls.shahbaaz.dev): the user types a domain name, and the tool reports every problem with that site's TLS certificate as a pass/fail list, with an overall verdict on top.

## Stack (details in SPEC.md)

- Node 26 LTS. Server TypeScript runs directly with Node's type stripping: no server build step, `tsc` is used only for type checking. So use only TypeScript syntax that can be stripped (no enums, namespaces or parameter properties), and import files with explicit `.ts` extensions.
- npm workspaces: `server/` (Express) and `client/` (Vite + React). Don't use pnpm or Nx.
- Tests use Node's built-in runner (`node --test`).
- Deployed to a DigitalOcean droplet: Nginx serves the client build and passes `/api/` to Node on `127.0.0.1:3000`, and systemd keeps Node running. GitHub Actions runs CI and deploys over SSH.

## Commands

Run from the repo root:

- `npm install`
- `npm run dev`: runs the server (Express on `127.0.0.1:3000`, restarts on change) and the client (Vite, passes `/api` to the server) together. `npm run dev:server` and `npm run dev:client` run one each.
- `npm run typecheck`: `tsc` for both workspaces. It also rejects syntax Node can't strip (`erasableSyntaxOnly`).
- `npm test`: server tests.
- `npm run build`: client build into `client/dist/`.
- Single test file: `node --test server/test/app.test.ts`. Single test by name: add `--test-name-pattern="health"`.

## Layout

- `server/src/app.ts` builds the Express app (`createApp()`); `server/src/index.ts` only starts it. Tests start `createApp()` on a random port and call it with `fetch`.
- `server/src/connection.ts` runs the connection checks and returns the leaf certificate and the chain; `server/src/certificate.ts` runs the certificate checks on the leaf; `server/src/chain.ts` builds the path to a root and runs the chain checks.
- Test certificates live in `server/test/fixtures/`; `make-ca-signed-certs.sh` there remakes the CA-signed ones (a test root, an intermediate and leaves). Tests pass their own trust store to `createApp()` so the test root counts as trusted.
- `server/src/types.ts` holds the API response types. The client imports them with `import type`, so the server and client agree on the shape.

## Key design points

- Certificate inspection runs **server-side** with Node's `tls`, `dns` and `crypto` modules, not third-party TLS libraries.
- Connect with `rejectUnauthorized: false` and run each check separately against the collected chain. Node reports only one validation error per connection, so relying on it would hide the other problems.
- Trust store: Node's bundled Mozilla roots (`tls.rootCertificates`).
- Revocation checks that can't reach the CA report `skip` ("couldn't check"), never `pass`.
- Resolve DNS first and block private and internal IP addresses before connecting, to prevent SSRF from the public server.
- Input is a bare domain only: strip scheme, path and query; reject IP addresses; the port is always 443.
- Before any certificate checks, three connection failures are reported as not secure: DNS lookup fails, nothing answers on 443 (refused or 5 s timeout), or the TLS handshake fails.

## Testing

Use badssl.com subdomains as reference cases, one per check (e.g. `expired.badssl.com`, `wrong.host.badssl.com`, `self-signed.badssl.com`, `untrusted-root.badssl.com`, `incomplete-chain.badssl.com`, `revoked.badssl.com`). Check that a host still behaves as advertised before relying on it.
