# Getting Started (Developers)

## Prerequisites

- Linux x86_64 with Docker Engine 24+ and the Compose plugin
- Go 1.27.1 (see `go.mod`); install into `~/.local/go` and add `~/.local/go/bin:~/go/bin` to `PATH`
- Node.js 24 and npm
- `make`, `openssl`, `jq`

## First run

```bash
make tools        # golangci-lint and govulncheck at pinned versions
make web-install  # web dependencies from the lockfile
make up           # creates deploy/.env, builds the image, starts Alice and PostgreSQL
make setup-token  # prints the one-time setup code for the wizard
```

Open https://localhost (accept the temporary certificate warning). Alice opens the setup wizard at
`/setup`; enter the code printed by `make setup-token`. If port 443 is in use, set `ALICE_PORT=8443` in
`deploy/.env` and run `make up` again, then open https://localhost:8443.

`make up` is the development equivalent of `docker compose up`. It generates `deploy/.env` with random
database passwords on first use and keeps an existing file (adding any password that is missing).

The setup code works only while no administrator exists. `make setup-token` always issues a new code and
invalidates the previous one. After the first administrator is created, sign in with the username,
password and the 6-digit code from your authenticator app.

Upgrading a Phase 0 development stack: the database now needs the `alice_app` role, which PostgreSQL only
creates when its data volume is new. Run `make reset` once (this deletes the development database).

## Everyday commands

| Command | What it does |
|---|---|
| `make test` | Go unit tests with the race detector |
| `make test-integration` | Go integration tests (starts PostgreSQL in Docker) |
| `make web-test` | Web unit tests (Vitest) |
| `make up` / `make down` | Start / stop the release build of the stack (data is kept) |
| `make reset` | Delete the development database and keys and start again (asks nothing; development only) |
| `make setup-token` | Print a new one-time setup code for the wizard |
| `make e2e-up` | Start the **e2e build** of the stack (adds test-only `/test/*` endpoints) |
| `make e2e` | Browser tests against the e2e build (run `make e2e-up` first) |
| `make lint` / `make web-lint` | Linters |
| `make i18n-check` | English and Turkish catalogs have the same keys and placeholders |
| `make authz-doc` | Regenerate `docs/authz-matrix.md` from the route table |
| `make hardening-check` | Verify container hardening of the running stack (`docker inspect`) |
| `make vuln` / `make secrets-scan` / `make fs-scan` / `make image-scan` | Vulnerability and secret scanning |
| `make ci` | The full pipeline, as run in GitHub Actions |
| `make logs` | Follow the Alice logs |

### Operator commands inside the container

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec alice /usr/local/bin/alice setup-token --reset
docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec alice /usr/local/bin/alice audit verify
docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec alice /usr/local/bin/alice admin reset-mfa <username>
```

- `setup-token --reset` prints a new setup code to the terminal only (it is never written to a file); it
  refuses once an administrator exists.
- `audit verify` recomputes the audit log hash chain; exit code 0 means intact, 1 means the output names
  the first broken entry.
- `admin reset-mfa <username>` removes a user's authenticator app (for example the only administrator lost
  their phone and their recovery codes). The user sets up a new app at their next sign-in. The action is
  recorded in the audit log with the actor `cli`.

### The e2e build

`make e2e-up` builds the image with the Go build tag `e2e` (`deploy/docker-compose.e2e.yml`). Only that
build serves `GET/POST /test/clock` (read or move the server clock forward), `POST /test/reset` (empty
all tables) and `POST /test/setup-token` (issue a setup code). Release images are built without the tag;
a unit test in `cmd/alice` fails if the release build ever contains a test endpoint or the demo clock.
The e2e build reports its version with a `+e2e` suffix and logs a warning at startup. Never run it
for real data.

## Configuration

Alice reads these environment variables (`internal/platform/config`):

| Variable | Default | Meaning |
|---|---|---|
| `ALICE_DATABASE_URL` | none (required) | PostgreSQL URL for the application role `alice_app`. Contains the password; never logged. |
| `ALICE_MIGRATE_DATABASE_URL` | empty | PostgreSQL URL for the owner role that runs migrations. If empty, `ALICE_DATABASE_URL` is used for both and Alice logs a warning, because the audit log is then protected by triggers only. |
| `ALICE_LISTEN_ADDR` | `:8443` | Public HTTPS listener |
| `ALICE_HEALTH_ADDR` | `127.0.0.1:8081` | Container-local plain HTTP listener for `/livez` and `/healthz` |
| `ALICE_KEYS_DIR` | `/opt/alice/keys` | Directory for the HTTPS certificate and the master key (`master.key`, mode 0400) |
| `ALICE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `ALICE_TLS_HOSTS` | empty | Extra host names or IPs for the temporary certificate, comma-separated |
| `ALICE_TRUSTED_PROXIES` | empty | Comma-separated IPs or CIDRs of reverse proxies whose `X-Forwarded-For` is believed. Empty means the header is ignored. |

The compose stack reads `deploy/.env`:

| Variable | Default | Meaning |
|---|---|---|
| `ALICE_DB_PASSWORD` | generated | Password of the owner role `alice` (migrations) |
| `ALICE_APP_DB_PASSWORD` | generated | Password of the application role `alice_app`, created by `deploy/postgres/initdb` on a new volume |
| `ALICE_PORT` | `443` | Host port published for the HTTPS listener (container port 8443) |
| `ALICE_TLS_HOSTS` | empty | Passed through to Alice |

## Notes

- The database connection uses `sslmode=disable` because PostgreSQL is only reachable on the
  internal Docker network `backend`, which has no route outside the host.
- Two database roles: migrations run as the owner `alice`; the running application uses `alice_app`,
  which may only read and append to `audit_log` (no update, delete or truncate). In this development
  stack the owner `alice` is the PostgreSQL superuser and its URL (`ALICE_MIGRATE_DATABASE_URL`) is in the
  `alice` container's environment, so someone with access to that container could bypass the audit
  log triggers. This is a known limitation until Phase 8 (non-superuser owner role and a one-shot
  migration container).
- The `alice` container has core dumps disabled (`ulimits: core: 0`), so a crash never writes key
  material to disk; `make hardening-check` verifies it.
- **The master key.** On the very first start Alice creates `master.key` in the keys directory. It
  encrypts TOTP secrets and, later, all stored credentials. If the database already holds encrypted data
  and the file is missing, has other contents, or is readable by other users, Alice refuses to start
  and says why; it never creates a new key over existing data. Deleting the `alice-keys` volume without
  also deleting the database therefore stops Alice until you restore the file (or `make reset`).
- Passwords, database passwords and secrets never appear in logs: the logger redacts fields such as
  `password`, `token` and `secret`.
- Alice creates a temporary self-signed certificate (valid 90 days, checked on every start and renewed
  when it is expired or within 7 days of expiry; restart the container to renew it). A certificate you
  place in the keys directory yourself is never modified.
- **Deleting `deploy/.env` requires `make reset`.** PostgreSQL keeps the passwords it was first
  initialised with in the `pgdata` volume, so new random passwords in a regenerated `.env` will not match.
- Translations: shared strings live in `locales/common/{en,tr}.json`, UI-only strings in
  `web/src/locales/{en,tr}.json`. Add every key to both languages; `make i18n-check` enforces it.
- The web build is written to `internal/webui/dist/app` (git-ignored) and embedded into the binary.

## Troubleshooting

Every API error carries a stable `ALC-<AREA>-<NNNN>` code. Meaning, likely cause and remedy for each
code are in [docs/troubleshooting.md](../troubleshooting.md). Add a section there whenever you add an
error code; a unit test fails if one is missing.
