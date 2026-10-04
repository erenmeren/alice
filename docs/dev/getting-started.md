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

Always build the image through `make up`, `make e2e-up` or `make image`: they pass the build time
(`ALICE_BUILD_TIME`), which is the lowest time the license clock ever uses when its time record is lost
(spec §16.5, L-53). A plain `docker compose build` without `ALICE_BUILD_TIME` builds an image without one;
Alice then starts with the warning "this build has no build time, …". To build with Compose directly, run
`ALICE_BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) docker compose -f deploy/docker-compose.yml --env-file deploy/.env build`.

`make image` (and `make image-scan`, which builds and scans it) tags the image `alice:ci` only; `make
IMAGE_TAG=<version> image` chooses another tag. It refuses `IMAGE_TAG=dev` and never writes `alice:dev`, the tag
the `make up` stack runs, so `make image` and `make ci` never change the image of your running stack. `make up`
is the only target that builds `alice:dev`; the e2e stack runs `alice:e2e`.

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
| `make reset` | Delete the development database, keys and license state (a new Installation ID) and start again (asks nothing; development only) |
| `make setup-token` | Print a new one-time setup code for the wizard |
| `make e2e-up` | Start the **e2e build** of the stack (adds test-only `/test/*` endpoints) |
| `make e2e` | Browser tests against the e2e build (run `make e2e-up` first) |
| `make e2e-down` | Stop the e2e stack and delete its volumes (never touches the `make up` stack) |
| `make helper` | Build the static `alice-helper` for linux/amd64 and linux/arm64 into `bin/` with `bin/alice-helper.sha256` |
| `make fuzz-ssh` | Fuzz the `authorized_keys` and `sshd -T` parsers for 60 s each |
| `make test-ssh` | Run the real-OpenSSH suite (`TestRealOpenSSH`) and the real-Nginx suite (`TestRealNginx`: discovery, deployment, rollback and recovery through Alice's Nginx provider against each distribution's real Nginx) on Ubuntu 22.04, Debian 12 and Rocky 9 (needs Docker and a host that can reach containers at their bridge addresses, as Linux Docker can; builds three images on first run). It first runs `make helper`: the Nginx suite installs that release-built helper through the setup script, which checks it against the checksums linked into the test. `TestRealNginx` runs only with `ALICE_REAL_MATRIX=1`, which this target sets (`make coverage` skips it). Each line fails unless its test passed (no match or a skip fails it). `ALICE_SSH_IMAGES=ubuntu22 make test-ssh` limits it to one distribution |
| `make coverage` | Every Go test with the integration tag under coverage; enforces `coverage-floors.json` |
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

`make e2e-up` builds the image with the Go build tags `e2e testlicense` (`deploy/docker-compose.e2e.yml`). Only
that build serves `GET/POST /test/clock` (read the clock, move it forward or back by `advance_seconds`, at most
10 years either way, or jump only the wall clock with `"wall_only": true`; the license evaluation and the email
sender run right after every move), `POST /test/reset` (empty all tables, the license time record and the
mailbox, then create a new installation), `POST /test/setup-token`, `POST /test/license` (a license for this
installation signed with the test key, which only this build trusts; fields `valid_days`, `max_targets`,
`valid_from`, `replaces`, …), `GET /test/mail` (emails the build would have sent), `POST /test/license/tamper`
(damage the newest stored license file so the "changed outside Alice" banner appears), `POST /test/jobs/drain`
(run due jobs now: it claims jobs for 20 s, at most 20 per call, and lets the last one run until 50 s, so give the
request a 60 s timeout; a client that gives up does not cancel the running job; the answer is `{"ran": n}`, plus
`"cut_off": true` exactly when the budget ended before the running job returned, which is then retried like any
interrupted job; one drain runs at a time, a second one meanwhile answers 409 "a drain is already running", the only answer the
Playwright helper waits out; a cut-off the test did not ask for fails the test, also inside a retried step) and `POST /test/scheduler/run` with `{"task": "<job type>"}` (run one periodic task now,
for example `deployment.recovery_sweep`; 404 for a name that is not a scheduled task). The e2e build starts no job
workers: queued jobs (connection tests, discovery, key removals, certificate deployments and their recoveries, and
the jobs the scheduler enqueues) run only when a test calls `/test/jobs/drain`, so every job state is reproducible.
The scheduler still ticks on the wall clock, except for `deployment.recovery_sweep`, which the e2e build never
ticks (the demo clock is an offset of the wall clock, so a real-minute sweep would change deployments between test
steps): a test moves the clock (`/test/clock`) and calls `/test/scheduler/run`. The other periodic tasks keep their
Phase 1–3 behaviour: `discovery.schedule` and `notify.send` tick every real minute (a moved clock can make a
discovery job due; it runs only at the next drain), the license evaluation, audit verification and cleanup hourly. Release images are built
without the tags; unit tests in `cmd/alice` fail if the release build has a test endpoint, the demo clock, the
test key or the test signer. The e2e build reports its version with a `+e2e` suffix and logs a warning at
startup. A build with `testlicense` but without `e2e` logs "test license key trusted" and reports `+testlicense`.
Never run either for real data.

The e2e stack is a separate compose project, `alice-e2e` (its own database, volumes and networks), because every
Playwright run empties its database; it never touches the `make up` stack. It also starts the SSH test target
`sshtarget` (internal network only, no published port). `make e2e-hardening-check` checks it, `make e2e-down`
removes it with its volumes. `sshtarget` is an Ubuntu 22.04 SSH server that Alice reaches as `sshtarget`, port 22,
with the helper copied to `/opt/alice-bundle/alice-helper` (built like `make helper`, so its checksum is the one the
e2e image embeds). The Playwright tests prepare it with
`docker compose -p alice-e2e … exec -T sshtarget /usr/local/sbin/alice-e2e-prepare` (the setup script on stdin) and
change its host key with `/usr/local/sbin/alice-e2e-rotate-hostkey` (it keeps the previous keys, which
`/usr/local/sbin/alice-e2e-restore-hostkey` puts back); their helper `targetExec` refuses the project
`alice`, and no test touches any other container.

From Phase 4 `sshtarget` also runs Ubuntu's Nginx (`test/images/e2e-target/nginx-www.conf`) on port 443, which
Alice reaches as `sshtarget:443` on the internal network: `www.example.test` (a fixed certificate and key pair in
`/etc/nginx/ssl`, a supported location) and `files.example.test` (files chosen by `$ssl_server_name`, deliberately
unsupported), plus `s1.example.test` … `s5.example.test` (five more supported websites, each with its own files,
for a deployment to several websites at once). Prepare it with the setup script of the `nginx` profile. A throwaway test CA
(`/opt/alice-test-ca`) and the website pairs are created when the container starts, so no key is
committed or in an image layer. Commands for tests (as root, through `docker compose -p alice-e2e … exec -T
sshtarget`):

| Command | What it does |
|---|---|
| `alice-e2e-newcert <name>[,<name>…] [--broken]` | Prints a fresh certificate for `<name>` (several names separated by commas: one certificate for all, the first is the CN) from the test CA (leaf and CA) and its key between `-----ALICE CERT-----`, `-----ALICE KEY-----` and `-----ALICE END-----` markers; `--broken` prints an unrelated key |
| `alice-e2e-served <name>` | The SHA-256 fingerprint (64 lower-case hex digits) of the certificate Nginx serves for `<name>` |
| `alice-e2e-test-mode ok\|fail-once\|fail` | Makes the next (`fail-once`) or every (`fail`) `nginx -t` fail. `fail-once` is consumed by ANY `nginx -t`, including the one a connection test runs (`nginx-test`), so arm it right before the deployment. `nginx -T` is never faulted: under `fail`, discovery still reports the configuration valid |
| `alice-e2e-reload-mode ok\|fail-once\|fail\|noop\|drop-once` | Makes the next or every `systemctl reload nginx` fail, or succeed without reloading (`noop`: Nginx keeps serving the old certificate); `drop-once` first ends Alice's SSH session (as a dropped network would) and then reloads, so the deployment is interrupted and the recovery sweep finishes it |
| `alice-e2e-pki sign <name>[,<name>…]` | Signs the certificate signing request on stdin with the test CA for the given names (the request's own names are ignored) and prints the certificate and the CA certificate |
| `alice-e2e-config-mode broken\|ok` | Adds (or removes) a configuration file with a syntax error: `nginx -T` and `nginx -t` fail, the running Nginx keeps serving |
| `alice-e2e-nginx-reset` | Fresh pairs for every website, no faults, no broken configuration file, Nginx reloaded. `POST /test/reset` resets only Alice: it does not touch the target's Nginx files, fault modes, helper journals or sudoers, so call this between tests |

How the target differs from a real server: the container has no systemd, so `/usr/bin/systemctl` is a test
shim that handles exactly `reload nginx` (runs `nginx -s reload`, as `nginx.service` does) and
`is-active --quiet nginx` (true while an `nginx` process runs) and refuses anything else; `/usr/sbin/nginx` is a
wrapper that passes every call to the distribution's binary (diverted to `/usr/lib/alice-e2e/nginx`) except a
faulted `nginx -t`, so the master process shows that path in `ps`. alice-helper is unchanged and runs the same
fixed paths as on a real server. Both shims exist only in this image; `make e2e-hardening-check` checks that the
Alice image has neither them nor the test CA, that the target's keys are root-only and that its image holds no
test key. The e2e stack publishes its own host port, `ALICE_E2E_PORT`
(default 9443; open https://localhost:9443), never `ALICE_PORT`, so it runs beside the `make up` stack. It is
bound to 127.0.0.1 only, because the e2e build answers the unauthenticated `/test/*` endpoints (`make
e2e-hardening-check` fails on any other binding); the
Playwright tests use the same port (`ALICE_BASE_URL` overrides the whole address). `make ci` runs `make e2e-down`
at the end, also when an e2e stage fails. `make up` rebuilds the Go layer on every run because the build time is passed to the image (it is the
floor of the license clock, L-53).

#### net::ERR_NETWORK_CHANGED ("Alice cannot be reached" in a browser test)

Chromium on Linux watches the host's IP addresses over netlink. When any interface gains or loses an
address, it aborts every in-flight request with `net::ERR_NETWORK_CHANGED`, including requests to
`localhost`. A test then fails at the next step, typically in `enrollTotp` ("Set up your authenticator app"
never appears), and the SPA shows "Alice cannot be reached". The suite itself causes no such change. On a
developer laptop two things cause them: a Wi-Fi IPv6 address whose router-advertised lifetime runs out
before the next advertisement (the address is removed and added again), and containers that another
process starts or stops (each adds or removes a veth with an IPv6 link-local address), for example the
Go integration tests (`make coverage`, `make test-ssh`, `go test -tags integration`; they use Testcontainers). Chromium 153 has no switch to turn
this off. So avoid running those tests in parallel with `make e2e`.

As a mitigation (not a fix), the suite allows one retry, only for this cause, locally and in CI: the
`networkChangeGuard` fixture in `web/e2e/helpers.ts` records requests Chromium aborted with
`net::ERR_NETWORK_CHANGED`. A test whose failed attempt saw such an abort runs once more and is
reported as flaky, with the annotation "retried after network change". The retry of any other failure
fails at once with "not retried: …", so the original error stays the result. CI applies the same gate, so a
real flake fails the run instead of passing on a second attempt; a retried test is reported as flaky with the
annotation there too.

Playwright keeps a trace of a failed test (`web/test-results/`, and `web/playwright-report/`). The traces of
the certificate journeys contain the private keys those tests generated and pasted into the upload form:
throwaway test keys of the throwaway test CA, created at run time inside the e2e target and worthless outside
that container's life. They are still key material: do not attach those traces to an issue or share them
outside the team, and never commit `web/test-results/` or `web/playwright-report/`.

The release key gate `make release-keycheck` fails until the vendor's public key is committed to
`internal/license/keys/production.json` (see `docs/vendor/licensing-vendor.md`); it is not part of `make ci`.
`make coverage` runs every Go test with the integration tag under coverage and enforces `coverage-floors.json`.

## Configuration

Alice reads these environment variables (`internal/platform/config`):

| Variable | Default | Meaning |
|---|---|---|
| `ALICE_DATABASE_URL` | none (required) | PostgreSQL URL for the application role `alice_app`. Contains the password; never logged. |
| `ALICE_MIGRATE_DATABASE_URL` | empty | PostgreSQL URL for the owner role that runs migrations. If empty, `ALICE_DATABASE_URL` is used for both and Alice logs a warning, because the audit log is then protected by triggers only. |
| `ALICE_LISTEN_ADDR` | `:8443` | Public HTTPS listener |
| `ALICE_HEALTH_ADDR` | `127.0.0.1:8081` | Container-local plain HTTP listener for `/livez` and `/healthz` |
| `ALICE_KEYS_DIR` | `/opt/alice/keys` | Directory for the HTTPS certificate and the master key (`master.key`, mode 0400) |
| `ALICE_STATE_DIR` | `/opt/alice/state` | Directory for the license time record (`hwm.dat`); the `alice-state` volume |
| `ALICE_SMTP_HOST`, `_PORT`, `_FROM`, `_USERNAME`, `_PASSWORD_FILE`, `_TLS`, `_CA_FILE` | empty | Email for license warnings; see `docs/operator-guide.md#email` |
| `ALICE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `ALICE_TLS_HOSTS` | empty | Extra host names or IPs for the temporary certificate, comma-separated |
| `ALICE_TRUSTED_PROXIES` | empty | Comma-separated IPs or CIDRs of reverse proxies whose `X-Forwarded-For` is believed. Empty means the header is ignored. |

The compose stack reads `deploy/.env`:

| Variable | Default | Meaning |
|---|---|---|
| `ALICE_DB_PASSWORD` | generated | Password of the owner role `alice` (migrations) |
| `ALICE_APP_DB_PASSWORD` | generated | Password of the application role `alice_app`, created by `deploy/postgres/initdb` on a new volume |
| `ALICE_PORT` | `443` | Host port published for the HTTPS listener (container port 8443) |
| `ALICE_E2E_PORT` | `9443` | Host port of the e2e stack (`make e2e-up`, project `alice-e2e`); must differ from `ALICE_PORT` |
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
