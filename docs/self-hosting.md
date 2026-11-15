# Self-hosting the AgentGov server

The AgentGov server stores the scan results that the CLI uploads and serves
them to the dashboard. It is optional: the CLI works without it.

## What was tested

| Part | Status |
| --- | --- |
| Server API and SQLite storage | Tested by the automated test suite on Windows (`go test ./internal/server/... ./internal/storage/...`), and by a manual run of the setup, sign-in, project, token, upload, and health `curl` commands in this guide against a local server. |
| Docker image and `deploy/compose.yaml` | Not yet verified on a Docker host. |
| PostgreSQL (`deploy/compose.postgres.yaml`) | Experimental and untested. The code compiles and shares its queries with SQLite. It has never run against a PostgreSQL server. |
| Caddy reverse proxy (`deploy/Caddyfile.example`) | Not yet verified. |
| CPU, memory, and disk sizing | Not yet benchmarked. This guide gives no sizing numbers. |

Use the SQLite path for anything you depend on until the other paths are
verified.

## How it works

- One process serves the API and the dashboard on one port.
- Data lives in one SQLite file, `agentgov.db`, with write-ahead logging.
- The server listens on `127.0.0.1:8080` by default. It refuses to start on
  any other address unless you set `AGENTGOV_ALLOW_PUBLIC=true`.
- The server speaks plain HTTP. For access from other machines, put a reverse
  proxy that terminates TLS in front of it.
- There is no default user and no default password.
- The server stores scan metadata and the uploaded scan result. It does not
  receive source files. The CLI redacts secrets before upload; the server does
  not inspect uploads for secrets.
- The server never fetches a URL that a client supplies.

## Configuration

`agentgov serve` reads these environment variables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `AGENTGOV_LISTEN` | `127.0.0.1:8080` | Listen address. |
| `AGENTGOV_ALLOW_PUBLIC` | `false` | Must be `true` to listen on an address that is not loopback. |
| `AGENTGOV_DATA_DIR` | `./data` | Directory of the SQLite file when no database URL is set. |
| `AGENTGOV_DATABASE_URL` | SQLite in the data directory | `sqlite:///path/agentgov.db`, a file path, or `postgres://...` (experimental). |
| `AGENTGOV_TRUSTED_PROXIES` | empty | Comma-separated addresses or CIDR ranges of reverse proxies whose `X-Forwarded-*` headers the server honors. |
| `AGENTGOV_MAX_UPLOAD_BYTES` | `5242880` | Largest accepted scan upload (5 MiB). |

Fixed limits: sessions end 12 hours after sign-in or after 2 hours without a
request; a token may upload 60 scans per minute; sign-in allows 20 attempts
per client address per minute and locks a user name and address pair after 5
failures, starting at 30 seconds and doubling up to 15 minutes. These limits
are held in memory and reset when the server restarts.

## Quick start without Docker

Linux or macOS:

```sh
export AGENTGOV_DATA_DIR="$HOME/agentgov-data"
agentgov serve
```

Windows PowerShell:

```powershell
$env:AGENTGOV_DATA_DIR = "$HOME\agentgov-data"
agentgov serve
```

The server creates the database, applies migrations, and prints the first-run
bootstrap token to the console. Continue with [First-run setup](#first-run-setup).

## Docker Compose

Not yet verified on a Docker host. Report what you find.

```sh
cp deploy/env.example deploy/.env        # review the values
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml logs agentgov   # shows the bootstrap token
```

The Compose file:

- publishes the port on `127.0.0.1:8080` of the host only;
- keeps data in the named volume `agentgov-data`, mounted at `/data`;
- runs as a non-root user with a read-only root file system, no Linux
  capabilities, and `no-new-privileges`;
- mounts no host directory and no Docker socket;
- restarts the container unless you stop it, and checks `/readyz` with
  `agentgov healthcheck`.

Inside the container the server listens on `0.0.0.0:8080`, which is why the
Compose file sets `AGENTGOV_ALLOW_PUBLIC=true`. The host port mapping is what
keeps the service local. Do not change the mapping to `0.0.0.0:8080:8080`.

### PostgreSQL profile (experimental, untested)

```sh
# set POSTGRES_PASSWORD in deploy/.env first; Compose stops when it is empty
docker compose -f deploy/compose.yaml -f deploy/compose.postgres.yaml up -d --build
```

PostgreSQL has no published port and sits on an internal network. Test this
profile yourself before you store anything you need.

## Reverse proxy and HTTPS

Not yet verified. `deploy/Caddyfile.example` is a starting point.

1. Keep the server on `127.0.0.1:8080`.
2. Run the proxy on the same host. Let it listen on 443 and forward to
   `127.0.0.1:8080`. It must pass the original `Host` header and set
   `X-Forwarded-For` and `X-Forwarded-Proto`.
3. Set `AGENTGOV_TRUSTED_PROXIES` to the address the server sees the proxy
   connect from. Without Docker that is `127.0.0.1`. With Docker Compose it is
   the gateway of the Compose network:

   ```sh
   docker network inspect agentgov_default --format '{{(index .IPAM.Config 0).Gateway}}'
   ```

4. Open only ports 80 and 443 in the firewall. Never open 8080.
5. Sign in through the HTTPS address and confirm that the `agentgov_session`
   cookie has the `Secure` flag.

See `docs/deployment-security.md` for the full checklist.

## First-run setup

When no user exists, the server prints a one-time bootstrap token:

```text
AgentGov Auditor: first-run setup
    Bootstrap token: <43 characters>
```

The token is valid for one hour and for one use. Only its hash is stored.
When it expires, restart the server to print a new one.

Create the first administrator. The password needs at least 12 characters.

```sh
curl -s -X POST http://127.0.0.1:8080/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"bootstrap_token":"PASTE_TOKEN","username":"admin","password":"CHOOSE_A_LONG_PASSPHRASE"}'
```

The dashboard setup screen sends the same request.

## Create a project and an upload token

Use the dashboard, or the API as shown here. Sign in and keep the session
cookie in a file:

```sh
curl -s -c cookies.txt -X POST http://127.0.0.1:8080/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_PASSPHRASE"}'
```

The response holds `csrf_token`. Every `POST` and `DELETE` with the cookie
must send it in the `X-CSRF-Token` header.

```sh
CSRF="PASTE_CSRF_TOKEN"

curl -s -b cookies.txt -X POST http://127.0.0.1:8080/api/v1/projects \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
  -d '{"slug":"payments","name":"Payments"}'

# use the "id" from the response (prj_...)
curl -s -b cookies.txt -X POST http://127.0.0.1:8080/api/v1/projects/PROJECT_ID/tokens \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
  -d '{"name":"ci","expires_in_days":90}'
```

The token (`agt_<prefix>_<secret>`) appears once, in this response. The server
keeps only its SHA-256 hash. Store the token in your CI secret store. Delete
`cookies.txt` when you finish.

A token can upload scans to its own project and can check its own validity.
It cannot read data and cannot call any other endpoint.

## Upload a scan

```sh
export AGENTGOV_TOKEN="agt_..."
agentgov scan . --upload-url http://127.0.0.1:8080 --upload-token-env AGENTGOV_TOKEN
```

PowerShell:

```powershell
$env:AGENTGOV_TOKEN = "agt_..."
agentgov scan . --upload-url http://127.0.0.1:8080 --upload-token-env AGENTGOV_TOKEN
```

The CLI sends `POST /api/v1/scans` with the scan result as JSON. The project
comes from the token. Uploading the same result twice stores it once.

To upload an existing JSON report by hand:

```sh
curl -s -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "Authorization: Bearer $AGENTGOV_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @agentgov-results.json
```

To check that a token and URL work without uploading:

```sh
curl -s -H "Authorization: Bearer $AGENTGOV_TOKEN" http://127.0.0.1:8080/api/v1/version
```

A valid token returns its project ID. An invalid, expired, or revoked token
returns `401`.

## Health checks

| Endpoint | Meaning |
| --- | --- |
| `GET /healthz` | The process runs. No database access, no detail. |
| `GET /readyz` | The database responds and all migrations are applied. |
| `GET /api/v1/version` | Version, and whether first-run setup is still required. |

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

```powershell
Invoke-RestMethod http://127.0.0.1:8080/healthz
Invoke-RestMethod http://127.0.0.1:8080/readyz
```

`GET /metrics` returns Prometheus counters for requests, uploads, and
authentication failures. It answers only an administrator session or a direct
caller on the server's own loopback address. It holds no scan detail. In a
container, scrape it with an administrator session, because a request through
the published port does not arrive from loopback.

## Logs

The server writes structured logs to standard error: request ID, method,
route pattern, status, duration, client address, and actor ID. It does not
log tokens, cookies, passwords, `Authorization` headers, or request bodies.

```sh
docker compose -f deploy/compose.yaml logs -f agentgov
```

The bootstrap token is printed to the console once, outside the structured
log. Treat the first-start console output as sensitive until setup is done.

Security-relevant actions are also recorded in the audit log inside the
database (`GET /api/v1/audit-events`). Each entry carries the hash of the
previous one, so an edited or removed entry breaks the chain.

## Backup

Back up the SQLite database. It holds everything, including password hashes
and token hashes. Encrypt backups and restrict who can read them.

Without Docker, while the server runs (needs the `sqlite3` tool):

```sh
sqlite3 "$AGENTGOV_DATA_DIR/agentgov.db" "VACUUM INTO '/backups/agentgov-$(date +%F).db'"
```

`VACUUM INTO` writes a consistent copy. Do not copy `agentgov.db` alone while
the server runs: recent changes may still be in `agentgov.db-wal`.

With Docker Compose (not yet verified), stop the service and archive the
volume:

```sh
docker compose -f deploy/compose.yaml stop agentgov
docker run --rm -v agentgov_agentgov-data:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/agentgov-data-$(date +%F).tgz -C /data .
docker compose -f deploy/compose.yaml start agentgov
```

For PostgreSQL use `pg_dump`.

The storage layer also has a per-project JSON export and a `VACUUM INTO`
helper. No CLI command exposes them yet.

## Restore

1. Stop the server.
2. Replace `agentgov.db` with the backup copy. Remove `agentgov.db-wal` and
   `agentgov.db-shm` if they exist.
3. Start the server. It applies any migration the backup lacks.
4. Check `GET /readyz`, then sign in and confirm the data.

With Docker Compose, restore into the volume the same way you archived it:

```sh
docker compose -f deploy/compose.yaml stop agentgov
docker run --rm -v agentgov_agentgov-data:/data -v "$PWD":/backup alpine \
  sh -c "rm -rf /data/* && tar xzf /backup/agentgov-data-DATE.tgz -C /data && chown -R 65532:65532 /data"
docker compose -f deploy/compose.yaml start agentgov
```

## Upgrade

1. Take a backup.
2. Install the new binary, or rebuild the image:
   `docker compose -f deploy/compose.yaml up -d --build`.
3. Start the server. Migrations run automatically, each in a transaction,
   and are recorded in the `schema_migrations` table.
4. Check `GET /readyz` and `GET /api/v1/version`.

## Rollback

Migrations only move forward. An older binary refuses to start on a database
that a newer binary migrated; the error says the database schema is newer
than the binary. To roll back:

1. Stop the server.
2. Restore the backup you took before the upgrade.
3. Start the old binary or image.

Scans uploaded after that backup are lost. Upload them again from CI if you
need them.

## Retention

The server keeps every scan until you delete data. The storage layer has a
retention function that deletes scans older than a number of days per project
and keeps the latest scan of each agent. No CLI command or schedule exposes it
yet. Until then, plan disk space for the full history: each scan stores its
result document, up to the upload limit.

## Token rotation

1. Create a new token for the project.
2. Update the secret in CI.
3. Run one upload to confirm that the new token works.
4. Revoke the old token:

```sh
curl -s -b cookies.txt -X DELETE \
  http://127.0.0.1:8080/api/v1/projects/PROJECT_ID/tokens/TOKEN_ID \
  -H "X-CSRF-Token: $CSRF"
```

Revocation takes effect at once. Give tokens an expiry (`expires_in_days`) and
rotate them before it. Revoke a token immediately when it may have leaked,
then review `GET /api/v1/audit-events?project=PROJECT_ID` for uploads you do
not recognize.

## Data deletion

- Everything: stop the server and delete the data directory, or remove the
  volume with `docker compose -f deploy/compose.yaml down -v`. Delete the
  backups as well.
- One project: the storage layer can delete a project with its scans, agents,
  tokens, and memberships. No API endpoint or CLI command exposes this yet.
- Audit events are kept when a project is deleted.

## Known gaps

- No password change, password reset, or account disable endpoint yet.
- No endpoint to delete a project or to run retention.
- No OIDC or single sign-on. Local accounts only.
- Rate limits are per process and in memory.
- Docker, PostgreSQL, and Caddy files are not yet verified.

## Troubleshooting

| Symptom | Cause and action |
| --- | --- |
| `refusing to listen on a non-loopback address without AllowPublic` | The listen address is reachable from other hosts. Use `127.0.0.1:8080`, or set `AGENTGOV_ALLOW_PUBLIC=true` behind a TLS proxy and a firewall. |
| `database schema is newer than this binary` | The database was migrated by a newer version. Run that version, or restore an older backup. |
| No bootstrap token in the log | A user already exists. Sign in with it. |
| `bootstrap_expired` | The token is older than one hour. Restart the server for a new one. |
| `setup_complete` | Setup was already done. Sign in. |
| `401 invalid_token` on upload | The token is wrong, expired, or revoked, or the `Authorization: Bearer` header is missing. All cases return the same answer by design. |
| `400 invalid_payload` on upload | The JSON is not a schema version 1 scan result, or it has unknown fields. The message names the field. Use the CLI version that matches the server. |
| `413 payload_too_large` | The result exceeds `AGENTGOV_MAX_UPLOAD_BYTES`. |
| `415 unsupported_media_type` | Send `Content-Type: application/json`. |
| `429 rate_limited` | Too many sign-in attempts or uploads. Wait for the time in `Retry-After`. |
| `403 csrf_failed` | The `X-CSRF-Token` header is missing or stale. Read it again from `GET /api/v1/session`. |
| `403 cross_origin` | The request came from another origin. Use the dashboard on the server's own host name. Behind a proxy, the proxy must pass the original `Host` header. |
| The session cookie has no `Secure` flag behind HTTPS | The server does not trust the proxy. Set `AGENTGOV_TRUSTED_PROXIES` to the address the proxy connects from. |
| `404` for a project or scan that exists | Your account is not a member of that project. The server does not reveal that the object exists. |
| The page says the dashboard bundle is not included | The binary was built without the dashboard. The API still works. |
