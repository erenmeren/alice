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
```

Open https://localhost (accept the temporary certificate warning). If port 443 is in use, set
`ALICE_PORT=8443` in `deploy/.env` and run `make up` again, then open https://localhost:8443.

`make up` is the Phase 0 equivalent of `docker compose up`. It generates `deploy/.env` with a random
database password on first use and keeps an existing file.

## Everyday commands

| Command | What it does |
|---|---|
| `make test` | Go unit tests with the race detector |
| `make test-integration` | Go integration tests (starts PostgreSQL in Docker) |
| `make web-test` | Web unit tests (Vitest) |
| `make e2e` | Browser tests against the running stack (run `make up` first) |
| `make lint` / `make web-lint` | Linters |
| `make i18n-check` | English and Turkish catalogs have the same keys and placeholders |
| `make hardening-check` | Verify container hardening of the running stack (`docker inspect`) |
| `make vuln` / `make secrets-scan` / `make fs-scan` / `make image-scan` | Vulnerability and secret scanning |
| `make ci` | The full pipeline, as run in GitHub Actions |
| `make logs` / `make down` | Follow logs / stop the stack (data is kept) |

## Configuration

Alice reads these environment variables (`internal/platform/config`):

| Variable | Default | Meaning |
|---|---|---|
| `ALICE_DATABASE_URL` | none (required) | PostgreSQL connection URL. Contains the password; never logged. |
| `ALICE_LISTEN_ADDR` | `:8443` | Public HTTPS listener |
| `ALICE_HEALTH_ADDR` | `127.0.0.1:8081` | Container-local plain HTTP listener for `/livez` and `/healthz` |
| `ALICE_KEYS_DIR` | `/opt/alice/keys` | Directory for the HTTPS certificate and, from Phase 1, the master key |
| `ALICE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `ALICE_TLS_HOSTS` | empty | Extra host names or IPs for the temporary certificate, comma-separated |

The compose stack reads `deploy/.env`:

| Variable | Default | Meaning |
|---|---|---|
| `ALICE_DB_PASSWORD` | generated | PostgreSQL password; compose builds `ALICE_DATABASE_URL` from it |
| `ALICE_PORT` | `443` | Host port published for the HTTPS listener (container port 8443) |
| `ALICE_TLS_HOSTS` | empty | Passed through to Alice |

## Notes

- The database connection uses `sslmode=disable` because PostgreSQL is only reachable on the
  internal Docker network `backend`, which has no route outside the host.
- In Phase 0 the DB password lives inside `ALICE_DATABASE_URL` and TLS files in the keys directory;
  secret-file packaging arrives in Phase 8.
- Alice creates a temporary self-signed certificate (valid 90 days, checked on every start and renewed
  when it is expired or within 7 days of expiry; restart the container to renew it, runtime renewal is planned for a later phase). A certificate you place in the keys directory yourself is never modified.
- **Deleting `deploy/.env` requires `down -v`.** PostgreSQL keeps the password it was first
  initialised with in the `pgdata` volume, so a new random password in a regenerated `.env` will not
  match. Reset with `docker compose -p alice -f deploy/docker-compose.yml --env-file deploy/.env down -v`
  (run it before deleting the file), which also removes the generated certificate volume.
- Translations: shared strings live in `locales/common/{en,tr}.json`, UI-only strings in
  `web/src/locales/{en,tr}.json`. Add every key to both languages; `make i18n-check` enforces it.
- The web build is written to `internal/webui/dist/app` (git-ignored) and embedded into the binary.

## Troubleshooting

Every API error carries a stable `ALC-<AREA>-<NNNN>` code. Meaning, likely cause and remedy for each
code are in [docs/troubleshooting.md](../troubleshooting.md). Add a section there whenever you add an
error code; a unit test fails if one is missing.
