# Deployment security

This document describes the security boundaries of the self-hosted AgentGov
server, what it stores, how to expose it safely, and what has and has not
been tested. Read it before you make the server reachable from another
machine.

## What was and was not tested

Tested by automated tests on Windows, with SQLite in a temporary directory
(`go test ./internal/server/... ./internal/storage/...`):

- first-run setup: token printed once, stored hashed, single use, one-hour
  expiry, no default credentials;
- sign-in: argon2id hashes, generic error, per-address rate limit, lockout
  with backoff;
- sessions: cookie attributes, hashed storage, idle and absolute expiry,
  sign-out;
- CSRF: missing token, wrong token, token of another session, foreign
  `Origin`, cross-site `Sec-Fetch-Site`;
- API tokens: shown once, stored as SHA-256, forged, truncated, expired, and
  revoked tokens rejected with one identical answer, tokens refused on every
  endpoint except upload and version;
- authorization: members of one project cannot read or change another
  project's data by guessing IDs; role limits for viewer, reviewer, owner;
- upload validation: size limit, content type, malformed JSON, unknown
  fields, enumerations, control IDs, timestamps, item counts, string lengths;
- injection: SQL metacharacters in names, IDs, filters, and credentials;
  script markup in stored fields returned as inert JSON;
- response headers, dashboard file serving, path traversal in asset paths;
- refusal to listen on a non-loopback address; graceful shutdown;
- migrations: repeated runs, reopening an existing database, refusal of a
  newer schema; audit hash chain detects edited and deleted entries;
- concurrent uploads.

Not tested:

- the Docker image, `deploy/compose.yaml`, and its hardening options (no
  Docker host was available);
- PostgreSQL: the code compiles and shares its queries with SQLite, but it
  has never run against a PostgreSQL server. Treat it as experimental;
- `deploy/Caddyfile.example` and any other reverse proxy;
- the Go race detector (it needs cgo, which the build machine does not have);
- Linux and macOS (the code has no platform-specific parts, but the tests ran
  on Windows only);
- load, soak, and fuzz testing. CPU, memory, and disk sizing is not yet
  benchmarked;
- an independent security review or penetration test.

## Trust boundaries

```text
 CI runner / developer              browser
        | upload (Bearer token)        | session cookie + CSRF token
        v                              v
  +------------------- TLS reverse proxy (you operate it) -------------------+
        |                              |
        v           plain HTTP on loopback only
  +------------------------ agentgov serve ------------------------+
  |  authentication -> authorization -> validation -> storage      |
  +----------------------------------------------------------------+
        |
        v
   SQLite file (or PostgreSQL, experimental)   ->   backups (you protect them)
```

| Boundary | Threat | What the server does | What you must do |
| --- | --- | --- | --- |
| Network to server | Eavesdropping, token theft | Listens on loopback by default; refuses other addresses without an explicit setting; warns in the log when public. | Terminate TLS at a reverse proxy. Open only 443 (and 80 for redirects). |
| Upload | Hostile or oversized documents | Requires a project token; limits size; rejects unknown fields and invalid values; rate-limits per token; never executes or renders content. | Keep tokens in a secret store. Give each pipeline its own token. |
| Browser | XSS, CSRF, clickjacking | Returns stored text as JSON only with `nosniff`; strict Content-Security-Policy; `SameSite=Strict` `HttpOnly` cookie; CSRF token and same-origin check; `X-Frame-Options: DENY`. | Serve the dashboard from its own host name. Do not share the host name with other applications. |
| Users and projects | Reading another project's data | One authorization function checks every project-scoped request; unknown and forbidden objects both return 404. | Grant the lowest role that works. Review members regularly. |
| Server to outside | Server-side request forgery | The server makes no outbound request. No endpoint accepts a URL to fetch. | Nothing. You may also block outbound traffic for the container. |
| Database and backups | Theft of stored data | Stores password hashes (argon2id) and token hashes (SHA-256), never the secrets. | Restrict file permissions. Encrypt the disk and the backups. |
| Host | Compromise of the server process | Compose example: non-root, read-only root file system, no capabilities, no Docker socket, resource limits. | Patch the host. Do not add mounts or privileges. |

Out of scope: a hostile administrator, a compromised host, and a compromised
reverse proxy. Each of them can read everything the server stores.

## What is stored

Stored:

- accounts: user name, argon2id password hash with a per-user salt, role;
- sessions: SHA-256 of the session ID, CSRF token, timestamps;
- projects and memberships;
- API tokens: SHA-256 of the token, a display prefix, name, scope, expiry;
- scans: the uploaded scan result document and an index of its agents,
  findings, and control results. A scan result holds file paths, line numbers,
  finding titles and descriptions, agent names, owners, and tool names;
- audit events: who did what and when, the client address for sign-in, and a
  hash chain.

Not stored:

- source code or file contents (the CLI does not upload them);
- secret values found by the scanner (the CLI reports the location and
  redacts the value);
- passwords, session IDs, API tokens, or the bootstrap token in readable
  form.

The server trusts the CLI to redact. It does not inspect uploads for secrets.
Anyone with a project token can upload arbitrary text into that project, so a
token in the wrong hands can store unwanted content there. Scan metadata is
still sensitive: it shows where an organization's agents are weak. Protect
the database and backups accordingly.

## Authentication and sessions

- First administrator: created with a one-time bootstrap token (32 random
  bytes) printed to the console. The token expires after one hour or on first
  use. Whoever can read the console on first start can become administrator,
  so complete setup promptly and restrict access to the logs.
- Passwords: at least 12 characters, hashed with argon2id (time 2, memory
  64 MiB, 2 threads).
- Sessions: random opaque ID in a cookie with `HttpOnly`, `SameSite=Strict`,
  `Path=/`, and `Secure` when the request arrived over HTTPS. Lifetime 12
  hours, idle limit 2 hours.
- CSRF: every cookie-authenticated `POST` and `DELETE` needs the
  `X-CSRF-Token` header and must be same-origin. A client that sends neither
  `Origin` nor `Sec-Fetch-Site` is treated as a non-browser client; it still
  needs the cookie and the CSRF token.
- Rate limits: held in process memory. They reset on restart and are not
  shared between instances. Add a limit at the reverse proxy if you run more
  than one instance or expect targeted attacks.
- Not available yet: password change, password reset, account disable,
  multi-factor authentication, and single sign-on. Until then, limit the
  number of accounts and reach the dashboard through a network you control,
  for example a VPN.

## Roles

| Role | Scope | May do |
| --- | --- | --- |
| administrator | Global | Everything: users, projects, members, tokens, all audit events, metrics. |
| owner | One project | Read the project; read its audit events; manage its tokens and members. |
| reviewer | One project | Read the project; read its audit events. |
| viewer | One project | Read the project. |
| API token | One project | Upload scans. Check its own validity. Nothing else. |

## TLS

The server does not terminate TLS. Never expose port 8080 to a network.

- Run a reverse proxy on the same host and forward to `127.0.0.1:8080`.
  `deploy/Caddyfile.example` is a starting point (not yet verified).
- Set `AGENTGOV_TRUSTED_PROXIES` to the proxy address. The server then
  honors `X-Forwarded-Proto` (to mark the cookie `Secure`) and
  `X-Forwarded-For` (for rate limits and audit entries) from that address
  only. Never list an address that clients can connect from directly.
- The proxy must pass the original `Host` header. The same-origin check
  compares `Origin` with `Host`.
- Add `Strict-Transport-Security` at the proxy.
- The CLI refuses to send a token over plain HTTP to a host that is not
  local, unless you pass `--upload-allow-http`.

## Firewall

| Port | Open to | Purpose |
| --- | --- | --- |
| 443/tcp | Users and CI runners that need the server | HTTPS at the reverse proxy |
| 80/tcp | Same, optional | Redirect to HTTPS and certificate issuance |
| 8080/tcp | Nobody. Loopback only | The AgentGov server |
| 5432/tcp | Nobody | PostgreSQL stays on the internal Compose network |

Restrict 443 to known networks when you can. The server needs no outbound
access.

## Hardening checklist

- [ ] The server listens on `127.0.0.1:8080`, or the container port is
      published on `127.0.0.1` only.
- [ ] A reverse proxy terminates TLS; port 8080 is closed in the firewall.
- [ ] `AGENTGOV_TRUSTED_PROXIES` holds the proxy address and nothing else.
- [ ] First-run setup is complete; the console output with the bootstrap
      token is no longer needed.
- [ ] The administrator uses a long, unique passphrase.
- [ ] Each pipeline has its own project token with an expiry; tokens live in
      a secret store, not in the repository.
- [ ] Unused tokens are revoked; members are reviewed.
- [ ] The data directory is readable only by the service account.
- [ ] The disk and the backups are encrypted; a restore has been tested.
- [ ] `/metrics` is not reachable through the proxy.
- [ ] The container keeps `read_only`, `cap_drop: ALL`,
      `no-new-privileges`, and the non-root user; no Docker socket and no
      host directory is mounted.
- [ ] `deploy/.env` is not committed and holds no reused password.
- [ ] Logs go to a place with access control and retention.
- [ ] Someone reviews `GET /api/v1/audit-events` for unexpected sign-ins,
      tokens, and uploads.
- [ ] An upgrade plan exists: back up, upgrade, check `/readyz`.

## Secrets management

- The server reads no secret from the environment in the SQLite setup.
- `POSTGRES_PASSWORD` (PostgreSQL profile only) has no default. Compose stops
  when it is empty. Keep `deploy/.env` readable by the operator only, or use
  your platform's secret mechanism.
- Upload tokens belong in the CI system's secret store. Pass the token to the
  CLI through an environment variable, never on the command line.

## Audit log integrity

Each audit entry stores the hash of the previous entry and its own hash
(`sha256(previous hash || canonical entry)`). The storage layer can verify
the whole chain. Verification detects an edited entry, an entry removed from
the middle, and reordered entries. It cannot detect removal of the newest
entries, and someone who can write to the database can rebuild the whole
chain. For stronger assurance, copy the latest hash to a system the server
cannot write to. No CLI command runs the verification yet.

## Residual risks

- A stolen session cookie or upload token is valid until it expires or is
  revoked. Transport security is your main protection.
- Accounts cannot be disabled or have their passwords reset through the API
  yet.
- In-memory rate limits reset on restart.
- The audit chain does not protect against an attacker with database write
  access.
- Deployment files and PostgreSQL support are unverified, as listed above.

Report vulnerabilities through the process in `SECURITY.md`.
