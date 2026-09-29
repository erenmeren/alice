# Phase 0: Skeleton and CI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A runnable Alice skeleton: one Go binary that serves `/livez`, `/healthz`, a small JSON API and an embedded React (Mantine) UI in English and Turkish over HTTPS, packaged with PostgreSQL in Docker Compose, with a CI pipeline that lints, tests and scans everything.

**Architecture:** `cmd/alice` is the composition root. It loads env config, connects to PostgreSQL with retry, runs embedded goose migrations under an advisory lock, creates a temporary self-signed TLS certificate, and serves two listeners: public HTTPS (`:8443`) and an internal plain-HTTP health listener (`127.0.0.1:8081`) used by the container healthcheck. The React SPA is built by Vite into `internal/webui/dist/app` and embedded with `go:embed`. The server injects a per-request CSP nonce so Mantine's style tag is allowed without `unsafe-inline`. Shared translation catalogs in `locales/` are used by both the backend (error messages) and the SPA.

**Tech Stack:** Go 1.27.1, stdlib `net/http`, pgx v5, goose v3, golang.org/x/text, google/uuid, testify, testcontainers-go; React 18 + TypeScript + Vite, Mantine 8, i18next/react-i18next, TanStack Query 5, Vitest + Testing Library, Playwright; Docker Compose, PostgreSQL 16, distroless static image; golangci-lint v2 (gosec, forbidigo), govulncheck, gitleaks, Trivy.

**Spec:** `docs/superpowers/specs/2026-09-29-alice-v1-design.md` and `docs/superpowers/specs/alice-v1/` (especially `02-architecture.md` §5, §9.1, §9.3, §10; `04-security.md` SEC-023, SEC-030..035; `06-quality.md` §26.2). Decisions in `alice-v1/00-decisions.md` win on conflict.

## Global Constraints

- Go module path is `alice`. Go toolchain `go 1.27.1` pinned in `go.mod`.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `tr.json` files.
- Commit messages use Conventional Commits (`feat:`, `fix:`, `test:`, `build:`, `ci:`, `docs:`, `chore:`) and end with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Tests: Go stdlib `testing` plus `github.com/stretchr/testify/require` and `assert` only (no `suite`, no `mock`). Integration tests use build tag `integration`.
- Runtime Go dependencies allowed in this phase: `github.com/jackc/pgx/v5`, `github.com/pressly/goose/v3`, `golang.org/x/text`, `github.com/google/uuid`. Anything else needs a written justification in the commit message.
- Module import rules from spec §5.4 are enforced by `internal/archtest` (Task 10). `internal/platform/...` never imports another `alice/...` package outside `internal/platform/...`.
- Never call `strings.ToUpper`, `strings.ToLower` or `strings.Title` (forbidigo enforces it; Turkish dotted/dotless i). Use `strings.EqualFold` for identifiers and `golang.org/x/text/cases` for user text.
- Never set `InsecureSkipVerify`.
- No secret value (database password, keys) may appear in logs, error messages or HTTP responses.
- HTTP server timeouts (SEC-023): `ReadHeaderTimeout` 10 s, `ReadTimeout` 30 s, `WriteTimeout` 60 s, `IdleTimeout` 120 s.
- TLS (SEC-031): minimum TLS 1.2; TLS 1.2 suites only ECDHE + AES-GCM or ChaCha20-Poly1305; curves X25519MLKEM768, X25519, P-256.
- Security headers on every response (SEC-032): `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
- SPA CSP (SEC-033 as amended in Task 14): `default-src 'none'; script-src 'self'; style-src 'self' 'nonce-<n>'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. API/other responses: `default-src 'none'; frame-ancestors 'none'`.
- API JSON: `snake_case` fields, `Content-Type: application/json; charset=utf-8`, `Cache-Control: no-store`.
- Error body shape (spec §9.3): `{"error":{"code","reason","message_key","message","request_id","retryable"}}`, codes `ALC-<AREA>-<NNNN>`.
- Container: runs as UID/GID `10001:10001`, read-only root filesystem, all capabilities dropped, `no-new-privileges`, PostgreSQL has no published port.
- Frontend never uses `dangerouslySetInnerHTML`; Vite `assetsInlineLimit: 0` (no inline assets).
- If a GitHub Action major version used below is deprecated when you implement, bump it to the current major and say so in the commit message.

## Review Focus

1. **Mantine under strict CSP.** If the nonce is wrong or missing, the browser silently blocks Mantine's `<style>` tag and the UI renders unstyled. Expected: no CSP violation in the browser console. The E2E test in Task 13 fails on any "Content Security Policy" console error.
2. **Expired temporary certificate after a long uptime.** A container restarted after 90 days must not serve an expired self-signed certificate. Expected: Alice's own temporary certificate is regenerated when it is expired or within 7 days of expiry, and a user-supplied certificate is never overwritten. Tests in Task 5.
3. **Database password leakage.** `ALICE_DATABASE_URL` contains the DB password. Expected: it never appears in logs, `fmt` output of the config, connection errors or `/healthz` responses. Tests in Tasks 3, 4 and 6.
4. **Database not ready at startup.** After a host reboot, PostgreSQL may start after Alice. Expected: Alice retries for up to 60 s and then exits with a clear message instead of crashing immediately. Test in Task 4.
5. **Turkish browser on first visit / unknown API paths.** A browser sending `tr-TR` must get Turkish on first load. An unknown `/api/...` path must return a JSON error (not the SPA HTML), and a deep link like `/users/5` must return the SPA. Tests in Tasks 6 and 9.

---

## File Structure

```
go.mod, go.sum                      module "alice", Go 1.27.1
Makefile                            developer entry points (help, web, build, test, lint, up, e2e, ci, ...)
.gitignore, .dockerignore, .gitleaks.toml, .golangci.yml
cmd/alice/main.go                   CLI: serve, migrate, healthcheck, version
cmd/alice/main_test.go
internal/platform/clock/            Clock interface, Real, Fake
internal/platform/config/           env config + redaction
internal/platform/db/               pgx pool open with retry, goose migrate, health checker
internal/platform/tlscert/          temporary self-signed certificate management
internal/version/                   build info injected by -ldflags
internal/i18n/                      catalog loading, flattening, negotiation, interpolation
internal/api/                       HTTP handlers, middleware, error mapping, SPA serving
internal/webui/                     go:embed of the Vite build (dist/app)
internal/archtest/                  import-rule enforcement test
migrations/                         goose SQL files + embed.go
locales/manifest.json               supported languages
locales/common/{en,tr}.json         shared catalog (errors, app name)
locales/embed.go                    go:embed of manifest + common
tools/i18n-check/                   key/placeholder parity checker
api/openapi.yaml                    OpenAPI 3.1 skeleton + consistency test in internal/api
web/                                Vite React app (package.json, vite.config.ts, src/, e2e/)
deploy/Dockerfile, deploy/docker-compose.yml
deploy/dev/init-env.sh, deploy/dev/check-hardening.sh
.github/workflows/ci.yml
docs/dev/getting-started.md
```

---

### Task 1: Toolchain and repository bootstrap

**Files:**
- Create: `go.mod`, `.gitignore`, `.dockerignore`, `Makefile`, `internal/version/version.go`, `internal/version/version_test.go`

**Interfaces:**
- Produces: `version.Info{Version, Commit, BuildTime string}` with JSON tags `version`, `commit`, `build_time`; `version.Get() Info`; package vars `Version`, `Commit`, `BuildTime` set via `-ldflags -X alice/internal/version.<Var>=...`.

- [ ] **Step 1: Install Go 1.27.1 into the user's home (no sudo)**

```bash
curl -fsSLo /tmp/go1.27.1.tgz https://go.dev/dl/go1.27.1.linux-amd64.tar.gz
rm -rf "$HOME/.local/go" && mkdir -p "$HOME/.local" && tar -C "$HOME/.local" -xzf /tmp/go1.27.1.tgz
grep -q '.local/go/bin' "$HOME/.bashrc" || echo 'export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"' >> "$HOME/.bashrc"
export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"
go version
```
Expected: `go version go1.27.1 linux/amd64`. In every later shell command in this plan, make sure `PATH` includes `$HOME/.local/go/bin:$HOME/go/bin`.

- [ ] **Step 2: Initialize the module and ignore files**

```bash
cd /home/meren/projects/alice-secrets
go mod init alice
go mod edit -go=1.27.1 -toolchain=go1.27.1
```

`.gitignore`:
```gitignore
# Go
/bin/
/coverage.out
# Web
/web/node_modules/
/web/test-results/
/web/playwright-report/
/internal/webui/dist/app/
# Local environment
/deploy/.env
.DS_Store
```

`.dockerignore`:
```
.git
web/node_modules
web/test-results
web/playwright-report
internal/webui/dist/app
deploy/.env
bin
```

- [ ] **Step 3: Write the failing version test**

`internal/version/version_test.go`:
```go
package version_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/version"
)

func TestGetReturnsBuildInfoWithSnakeCaseJSON(t *testing.T) {
	version.Version, version.Commit, version.BuildTime = "1.2.3", "abc123", "2026-09-29T10:00:00Z"
	t.Cleanup(func() { version.Version, version.Commit, version.BuildTime = "dev", "unknown", "unknown" })

	b, err := json.Marshal(version.Get())
	require.NoError(t, err)
	assert.JSONEq(t, `{"version":"1.2.3","commit":"abc123","build_time":"2026-09-29T10:00:00Z"}`, string(b))
}
```

- [ ] **Step 4: Run it and see it fail**

Run: `go get github.com/stretchr/testify@latest && go test ./internal/version/`
Expected: FAIL, `undefined: version.Get` (package has no non-test files).

- [ ] **Step 5: Implement**

`internal/version/version.go`:
```go
// Package version exposes build information injected at link time.
package version

// These are overridden with -ldflags "-X alice/internal/version.Version=..." at build time.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Info is the build information returned by the API.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Get returns the current build information.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildTime: BuildTime}
}
```

- [ ] **Step 6: Makefile skeleton** (recipe lines must start with a real TAB character)

`Makefile`:
```make
SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w -X alice/internal/version.Version=$(VERSION) -X alice/internal/version.Commit=$(COMMIT) -X alice/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

.PHONY: test
test: ## Run Go unit tests with the race detector
	go test -race -count=1 ./...
```

- [ ] **Step 7: Run tests and help**

Run: `go mod tidy && go test ./internal/version/ && make help`
Expected: `ok  alice/internal/version`, and `help` lists `help` and `test`.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum .gitignore .dockerignore Makefile internal/version
git commit -m "build: bootstrap Go module, Makefile and version package

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Clock

**Files:**
- Create: `internal/platform/clock/clock.go`, `internal/platform/clock/clock_test.go`

**Interfaces:**
- Produces: `clock.Clock` interface `{ Now() time.Time }`; `clock.Real{}`; `clock.NewFake(t time.Time) *clock.Fake` with `Now()`, `Set(time.Time)`, `Advance(time.Duration)`. All returned times are UTC.

- [ ] **Step 1: Write the failing test**

`internal/platform/clock/clock_test.go`:
```go
package clock_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

func TestRealReturnsUTC(t *testing.T) {
	var c clock.Clock = clock.Real{}
	assert.Equal(t, time.UTC, c.Now().Location())
}

func TestFakeSetAndAdvance(t *testing.T) {
	start := time.Date(2026, 9, 29, 12, 0, 0, 0, time.FixedZone("TRT", 3*3600))
	f := clock.NewFake(start)
	var c clock.Clock = f

	assert.True(t, c.Now().Equal(start))
	assert.Equal(t, time.UTC, c.Now().Location())

	f.Advance(90 * time.Minute)
	assert.True(t, c.Now().Equal(start.Add(90*time.Minute)))

	later := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Set(later)
	assert.True(t, c.Now().Equal(later))
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `go test ./internal/platform/clock/`
Expected: FAIL, `undefined: clock.Real`.

- [ ] **Step 3: Implement**

`internal/platform/clock/clock.go`:
```go
// Package clock abstracts time so that time-dependent logic (licenses,
// sessions, certificate expiry) can be tested deterministically.
package clock

import (
	"sync"
	"time"
)

// Clock returns the current time in UTC.
type Clock interface {
	Now() time.Time
}

// Real is the production clock.
type Real struct{}

// Now returns the current wall-clock time in UTC.
func (Real) Now() time.Time { return time.Now().UTC() }

// Fake is a manually controlled clock for tests. It is safe for concurrent use.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake set to t.
func NewFake(t time.Time) *Fake { return &Fake{now: t.UTC()} }

// Now returns the fake's current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Set moves the fake to t.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}

// Advance moves the fake forward (or backward for negative d).
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
```

- [ ] **Step 4: Run and pass**

Run: `go test -race ./internal/platform/clock/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/clock
git commit -m "feat: add fakeable clock

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Configuration with secret redaction

**Files:**
- Create: `internal/platform/config/config.go`, `internal/platform/config/config_test.go`

**Interfaces:**
- Produces:
  - `config.Config{DatabaseURL string; ListenAddr string; HealthAddr string; KeysDir string; LogLevel slog.Level; TLSHosts []string}`
  - `config.Load(getenv func(string) string) (config.Config, error)`
  - `(Config) RequireDatabase() error`
  - `(Config) LogValue() slog.Value`, `String() string`, `GoString() string` (all redact the DB password)
- Env vars: `ALICE_DATABASE_URL` (no default), `ALICE_LISTEN_ADDR` (default `:8443`), `ALICE_HEALTH_ADDR` (default `127.0.0.1:8081`), `ALICE_KEYS_DIR` (default `/var/lib/alice/keys`), `ALICE_LOG_LEVEL` (default `info`; one of debug/info/warn/error, case-insensitive), `ALICE_TLS_HOSTS` (optional comma-separated extra hostnames/IPs).

- [ ] **Step 1: Write the failing tests**

`internal/platform/config/config_test.go`:
```go
package config_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/config"
)

const dbURL = "postgres://alice:s3cret-pw@postgres:5432/alice?sslmode=disable"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALICE_DATABASE_URL": dbURL}))
	require.NoError(t, err)
	assert.Equal(t, dbURL, c.DatabaseURL)
	assert.Equal(t, ":8443", c.ListenAddr)
	assert.Equal(t, "127.0.0.1:8081", c.HealthAddr)
	assert.Equal(t, "/var/lib/alice/keys", c.KeysDir)
	assert.Equal(t, slog.LevelInfo, c.LogLevel)
	assert.Empty(t, c.TLSHosts)
}

func TestLoadOverrides(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"ALICE_LISTEN_ADDR": ":9443",
		"ALICE_HEALTH_ADDR": "127.0.0.1:9081",
		"ALICE_KEYS_DIR":    "/tmp/keys",
		"ALICE_LOG_LEVEL":   "DEBUG",
		"ALICE_TLS_HOSTS":   " alice.example.com , 10.0.0.5,, ",
	}))
	require.NoError(t, err)
	assert.Equal(t, ":9443", c.ListenAddr)
	assert.Equal(t, "127.0.0.1:9081", c.HealthAddr)
	assert.Equal(t, "/tmp/keys", c.KeysDir)
	assert.Equal(t, slog.LevelDebug, c.LogLevel)
	assert.Equal(t, []string{"alice.example.com", "10.0.0.5"}, c.TLSHosts)
}

func TestLoadRejectsUnknownLogLevel(t *testing.T) {
	_, err := config.Load(env(map[string]string{"ALICE_LOG_LEVEL": "loud"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ALICE_LOG_LEVEL")
}

func TestRequireDatabase(t *testing.T) {
	c, err := config.Load(env(nil))
	require.NoError(t, err)
	err = c.RequireDatabase()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ALICE_DATABASE_URL")

	c.DatabaseURL = dbURL
	assert.NoError(t, c.RequireDatabase())
}

func TestConfigNeverRevealsDatabasePassword(t *testing.T) {
	c, err := config.Load(env(map[string]string{"ALICE_DATABASE_URL": dbURL}))
	require.NoError(t, err)

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("config loaded", "config", c)
	for _, out := range []string{buf.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), c.String()} {
		assert.NotContains(t, out, "s3cret-pw")
	}
	assert.Contains(t, buf.String(), "postgres:5432")
}

func TestRedactionOfUnparseableURL(t *testing.T) {
	c := config.Config{DatabaseURL: "::not a url s3cret-pw"}
	assert.NotContains(t, c.String(), "s3cret-pw")
}
```

- [ ] **Step 2: Run and see it fail**

Run: `go test ./internal/platform/config/`
Expected: FAIL, `undefined: config.Load`.

- [ ] **Step 3: Implement**

`internal/platform/config/config.go`:
```go
// Package config loads Alice's process configuration from environment variables.
// Values that contain secrets are never rendered in logs or formatted output.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// Config is the process configuration.
type Config struct {
	DatabaseURL string
	ListenAddr  string
	HealthAddr  string
	KeysDir     string
	LogLevel    slog.Level
	TLSHosts    []string
}

// Load reads configuration using getenv (os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		DatabaseURL: getenv("ALICE_DATABASE_URL"),
		ListenAddr:  withDefault(getenv("ALICE_LISTEN_ADDR"), ":8443"),
		HealthAddr:  withDefault(getenv("ALICE_HEALTH_ADDR"), "127.0.0.1:8081"),
		KeysDir:     withDefault(getenv("ALICE_KEYS_DIR"), "/var/lib/alice/keys"),
		LogLevel:    slog.LevelInfo,
	}
	if lvl := strings.TrimSpace(getenv("ALICE_LOG_LEVEL")); lvl != "" {
		// slog.Level.UnmarshalText is case-insensitive.
		if err := c.LogLevel.UnmarshalText([]byte(lvl)); err != nil {
			return Config{}, fmt.Errorf("ALICE_LOG_LEVEL must be one of debug, info, warn, error (got %q)", lvl)
		}
	}
	for _, h := range strings.Split(getenv("ALICE_TLS_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.TLSHosts = append(c.TLSHosts, h)
		}
	}
	return c, nil
}

// RequireDatabase reports a user-friendly error when no database is configured.
func (c Config) RequireDatabase() error {
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return errors.New("ALICE_DATABASE_URL is not set; set it in deploy/.env (see docs/dev/getting-started.md)")
	}
	return nil
}

// LogValue implements slog.LogValuer so the database password is never logged.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("database_url", redactURL(c.DatabaseURL)),
		slog.String("listen_addr", c.ListenAddr),
		slog.String("health_addr", c.HealthAddr),
		slog.String("keys_dir", c.KeysDir),
		slog.String("log_level", c.LogLevel.String()),
		slog.Any("tls_hosts", c.TLSHosts),
	)
}

// String renders the configuration with secrets redacted.
func (c Config) String() string {
	return fmt.Sprintf("Config{DatabaseURL:%s ListenAddr:%s HealthAddr:%s KeysDir:%s LogLevel:%s TLSHosts:%v}",
		redactURL(c.DatabaseURL), c.ListenAddr, c.HealthAddr, c.KeysDir, c.LogLevel, c.TLSHosts)
}

// GoString makes %#v safe as well.
func (c Config) GoString() string { return c.String() }

func redactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	return u.Redacted()
}

func withDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}
```

- [ ] **Step 4: Run and pass**

Run: `go test -race ./internal/platform/config/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/config
git commit -m "feat: load configuration from environment with secret redaction

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Database pool, migrations and health checker

**Files:**
- Create: `internal/platform/db/db.go`, `internal/platform/db/db_test.go`, `internal/platform/db/db_integration_test.go`, `migrations/embed.go`, `migrations/00001_init.sql`
- Modify: `Makefile` (add `test-integration`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `db.ErrUnreachable`, `db.ErrMigrationsPending` (sentinel errors)
  - `db.Open(ctx context.Context, url string) (*pgxpool.Pool, error)`: retries every 500 ms until `ctx` is done
  - `db.Migrate(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) error`: goose Up under a Postgres session advisory lock
  - `db.NewHealthChecker(pool *pgxpool.Pool, fsys fs.FS) (*db.HealthChecker, error)`; `(*HealthChecker) Check(ctx context.Context) error` returns nil, `ErrUnreachable` or `ErrMigrationsPending`
  - `migrations.FS embed.FS` (files at the FS root, e.g. `00001_init.sql`)

- [ ] **Step 1: Add dependencies**

```bash
go get github.com/jackc/pgx/v5@latest github.com/pressly/goose/v3@latest
go get github.com/testcontainers/testcontainers-go@latest github.com/testcontainers/testcontainers-go/modules/postgres@latest
```

- [ ] **Step 2: Write the initial migration and embed**

`migrations/00001_init.sql`:
```sql
-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

-- Key/value application settings. Later phases add secret settings in a sibling table.
CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE settings;
```

`migrations/embed.go`:
```go
// Package migrations embeds the goose SQL migrations.
package migrations

import "embed"

// FS holds the migration files at its root.
//
//go:embed *.sql
var FS embed.FS
```

- [ ] **Step 3: Write the failing unit test (no container needed)**

`internal/platform/db/db_test.go`:
```go
package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/db"
)

func TestOpenGivesUpWhenDatabaseUnreachableWithoutLeakingPassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	pool, err := db.Open(ctx, "postgres://alice:s3cret-pw@127.0.0.1:1/alice?sslmode=disable")
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.True(t, errors.Is(err, db.ErrUnreachable))
	assert.NotContains(t, err.Error(), "s3cret-pw")
	assert.Contains(t, err.Error(), "127.0.0.1:1")
	assert.Less(t, time.Since(start), 4*time.Second)
}

func TestOpenRejectsInvalidURLWithoutEchoingIt(t *testing.T) {
	_, err := db.Open(context.Background(), "postgres://alice:s3cret-pw@host:notaport/alice")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cret-pw")
	assert.Contains(t, err.Error(), "ALICE_DATABASE_URL")
}
```

- [ ] **Step 4: Write the failing integration test**

`internal/platform/db/db_integration_test.go`:
```go
//go:build integration

package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"alice/internal/platform/db"
	"alice/migrations"
)

func startPostgres(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("alice"),
		postgres.WithUsername("alice"),
		postgres.WithPassword("s3cret-pw"),
		postgres.BasicWaitStrategies(),
	)
	testcontainers.CleanupContainer(t, ctr)
	require.NoError(t, err)
	url, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	return url
}

func TestMigrateAndHealth(t *testing.T) {
	url := startPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	hc, err := db.NewHealthChecker(pool, migrations.FS)
	require.NoError(t, err)
	assert.True(t, errors.Is(hc.Check(ctx), db.ErrMigrationsPending), "fresh database must report pending migrations")

	require.NoError(t, db.Migrate(ctx, pool, migrations.FS))
	require.NoError(t, db.Migrate(ctx, pool, migrations.FS), "migrate must be idempotent")
	assert.NoError(t, hc.Check(ctx))

	var n int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM settings").Scan(&n))
	assert.Equal(t, 0, n)
}

func TestConcurrentMigrateIsSerialized(t *testing.T) {
	url := startPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	defer pool.Close()

	errs := make(chan error, 3)
	for range 3 {
		go func() { errs <- db.Migrate(ctx, pool, migrations.FS) }()
	}
	for range 3 {
		assert.NoError(t, <-errs)
	}
}

func TestHealthReportsUnreachableAfterPoolClosed(t *testing.T) {
	url := startPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, url)
	require.NoError(t, err)
	require.NoError(t, db.Migrate(ctx, pool, migrations.FS))
	hc, err := db.NewHealthChecker(pool, migrations.FS)
	require.NoError(t, err)

	pool.Close()
	assert.True(t, errors.Is(hc.Check(ctx), db.ErrUnreachable))
}
```

- [ ] **Step 5: Run and see both fail**

Run: `go test ./internal/platform/db/ && go test -tags integration ./internal/platform/db/`
Expected: FAIL, `undefined: db.Open`.

- [ ] **Step 6: Implement**

`internal/platform/db/db.go`:
```go
// Package db opens the PostgreSQL pool, applies embedded migrations and reports health.
package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

var (
	// ErrUnreachable means the database cannot be reached.
	ErrUnreachable = errors.New("database is not reachable")
	// ErrMigrationsPending means the schema is older than this binary expects.
	ErrMigrationsPending = errors.New("database migrations are pending")
)

const retryInterval = 500 * time.Millisecond

// Open creates a pool and waits until the database answers a ping or ctx ends.
// Errors never include the connection string, because it contains the password.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("the database URL is not valid; check ALICE_DATABASE_URL")
	}
	cfg.MaxConns = 20
	where := fmt.Sprintf("%s:%d", cfg.ConnConfig.Host, cfg.ConnConfig.Port)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not prepare the database connection to %s: %w", where, ErrUnreachable)
	}
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = pool.Ping(pingCtx)
		cancel()
		if err == nil {
			return pool, nil
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, fmt.Errorf("could not connect to the database at %s: %w", where, ErrUnreachable)
		case <-time.After(retryInterval):
		}
	}
}

// Migrate applies all pending migrations. A Postgres advisory lock serializes
// concurrent callers (for example two containers starting during an update).
func Migrate(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) error {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create migration lock: %w", err)
	}
	p, err := newProvider(pool, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return err
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// HealthChecker reports whether the database is reachable and fully migrated.
type HealthChecker struct {
	pool     *pgxpool.Pool
	provider *goose.Provider
}

// NewHealthChecker builds a checker for the given migrations.
func NewHealthChecker(pool *pgxpool.Pool, fsys fs.FS) (*HealthChecker, error) {
	p, err := newProvider(pool, fsys)
	if err != nil {
		return nil, err
	}
	return &HealthChecker{pool: pool, provider: p}, nil
}

// Check returns nil, ErrUnreachable or ErrMigrationsPending.
func (h *HealthChecker) Check(ctx context.Context) error {
	if err := h.pool.Ping(ctx); err != nil {
		return ErrUnreachable
	}
	pending, err := h.provider.HasPending(ctx)
	if err != nil {
		return ErrUnreachable
	}
	if pending {
		return ErrMigrationsPending
	}
	return nil
}

func newProvider(pool *pgxpool.Pool, fsys fs.FS, opts ...goose.ProviderOption) (*goose.Provider, error) {
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(pool), fsys, opts...)
	if err != nil {
		return nil, fmt.Errorf("load migrations: %w", err)
	}
	return p, nil
}
```

If the installed goose version lacks `Provider.HasPending`, replace that call with: current, err := `h.provider.GetDBVersion(ctx)`; compare with the highest `Version` in `h.provider.ListSources()`; pending when current < highest. Keep the same return values.

- [ ] **Step 7: Add the Makefile target**

Append to `Makefile`:
```make
.PHONY: test-integration
test-integration: ## Run integration tests (needs Docker)
	go test -race -count=1 -tags integration ./...
```

- [ ] **Step 8: Run and pass**

Run: `go mod tidy && go test -race ./internal/platform/db/ && make test-integration`
Expected: all `ok` (the integration run pulls `postgres:16-alpine` the first time).

- [ ] **Step 9: Commit**

```bash
git add go.mod go.sum migrations internal/platform/db Makefile
git commit -m "feat: add database pool with retry, embedded migrations and health checker

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Temporary self-signed TLS certificate

**Files:**
- Create: `internal/platform/tlscert/tlscert.go`, `internal/platform/tlscert/tlscert_test.go`

**Interfaces:**
- Produces:
  - `tlscert.Organization` = `"Alice temporary certificate"` (marks certificates Alice generated)
  - `tlscert.EnsureSelfSigned(dir string, hosts []string, now time.Time) (tls.Certificate, error)`: uses `dir/tls.crt` and `dir/tls.key`
  - `tlscert.ServerConfig(cert tls.Certificate) *tls.Config` (SEC-031 settings)

Behavior rules: (a) neither file exists → generate ECDSA P-256, valid from `now-1h` to `now+90d`, SANs from `hosts` (IPs vs DNS names split, duplicates removed); (b) both exist and the certificate is Alice-generated and `now >= NotAfter-7d` → regenerate; (c) both exist otherwise → load and return unchanged; (d) exactly one exists → error, touch nothing; (e) key file mode 0600, certificate 0644, directory created 0700; writes are atomic (temp file + rename).

- [ ] **Step 1: Write the failing tests**

`internal/platform/tlscert/tlscert_test.go`:
```go
package tlscert_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/tlscert"
)

var t0 = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func leaf(t *testing.T, c tls.Certificate) *x509.Certificate {
	t.Helper()
	l, err := x509.ParseCertificate(c.Certificate[0])
	require.NoError(t, err)
	return l
}

func TestGeneratesCertificateWithHostsAndSafePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	c, err := tlscert.EnsureSelfSigned(dir, []string{"localhost", "127.0.0.1", "alice.example.com", "localhost"}, t0)
	require.NoError(t, err)

	l := leaf(t, c)
	assert.Equal(t, []string{"localhost", "alice.example.com"}, l.DNSNames)
	require.Len(t, l.IPAddresses, 1)
	assert.True(t, l.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
	assert.Equal(t, []string{tlscert.Organization}, l.Subject.Organization)
	assert.Equal(t, t0.Add(90*24*time.Hour), l.NotAfter)
	assert.Equal(t, x509.ECDSA, l.PublicKeyAlgorithm)

	st, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), st.Mode().Perm())
	st, err = os.Stat(filepath.Join(dir, "tls.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}

func TestReusesValidCertificate(t *testing.T) {
	dir := t.TempDir()
	first, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.NoError(t, err)
	second, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0.Add(30*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, leaf(t, first).SerialNumber, leaf(t, second).SerialNumber)
}

func TestRegeneratesOwnCertificateNearExpiry(t *testing.T) {
	dir := t.TempDir()
	first, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.NoError(t, err)
	later := t0.Add(84 * 24 * time.Hour) // 6 days before expiry
	second, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, later)
	require.NoError(t, err)
	assert.NotEqual(t, leaf(t, first).SerialNumber, leaf(t, second).SerialNumber)
	assert.Equal(t, later.Add(90*24*time.Hour), leaf(t, second).NotAfter)
}

func TestNeverOverwritesUserCertificateEvenWhenExpired(t *testing.T) {
	dir := t.TempDir()
	// Simulate a user-supplied certificate: generate one, then re-sign it without the Alice marker.
	userCert, userKey := writeForeignCertificate(t, dir, t0.Add(-100*24*time.Hour), t0.Add(-1*time.Hour))
	c, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.NoError(t, err)
	assert.Equal(t, userCert, readFile(t, filepath.Join(dir, "tls.crt")))
	assert.Equal(t, userKey, readFile(t, filepath.Join(dir, "tls.key")))
	assert.NotEqual(t, []string{tlscert.Organization}, leaf(t, c).Subject.Organization)
}

func TestRefusesWhenOnlyOneFileExists(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("x"), 0o644))
	_, err := tlscert.EnsureSelfSigned(dir, []string{"localhost"}, t0)
	require.Error(t, err)
	_, statErr := os.Stat(filepath.Join(dir, "tls.key"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestServerConfig(t *testing.T) {
	c, err := tlscert.EnsureSelfSigned(t.TempDir(), []string{"localhost"}, t0)
	require.NoError(t, err)
	cfg := tlscert.ServerConfig(c)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Equal(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}, cfg.CurvePreferences)
	for _, id := range cfg.CipherSuites {
		name := tls.CipherSuiteName(id)
		assert.Regexp(t, `^TLS_ECDHE_(ECDSA|RSA)_WITH_(AES_\d+_GCM_SHA\d+|CHACHA20_POLY1305_SHA256)$`, name)
	}
	assert.Len(t, cfg.Certificates, 1)
}
```

Add the helpers at the end of the same test file:
```go
func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}

// writeForeignCertificate writes a self-signed certificate that Alice did not generate.
func writeForeignCertificate(t *testing.T, dir string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	certPEM, keyPEM = tlscert.GenerateForTest(t, "Customer Corp", notBefore, notAfter)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600))
	return certPEM, keyPEM
}
```

`GenerateForTest` lives in an `export_test.go`-style file so it never ships. Create `internal/platform/tlscert/export_test.go`:
```go
package tlscert

import (
	"testing"
	"time"
)

// GenerateForTest exposes certificate generation with a custom organization to tests.
func GenerateForTest(t *testing.T, org string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	c, k, err := generate(org, []string{"localhost"}, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}
```
Note: `export_test.go` is `package tlscert` while the other test file is `package tlscert_test`; both compile together in `go test`, which makes `tlscert.GenerateForTest` visible to the external test package.

- [ ] **Step 2: Run and see it fail**

Run: `go test ./internal/platform/tlscert/`
Expected: FAIL, `undefined: tlscert.EnsureSelfSigned`.

- [ ] **Step 3: Implement**

`internal/platform/tlscert/tlscert.go`:
```go
// Package tlscert manages Alice's temporary self-signed HTTPS certificate.
// A certificate supplied by the customer is never modified.
package tlscert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Organization marks certificates that Alice generated itself.
const Organization = "Alice temporary certificate"

const (
	validity    = 90 * 24 * time.Hour
	renewBefore = 7 * 24 * time.Hour
)

// EnsureSelfSigned returns the certificate in dir, creating or renewing
// Alice's own temporary certificate when needed.
func EnsureSelfSigned(dir string, hosts []string, now time.Time) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	certExists, keyExists := exists(certPath), exists(keyPath)

	switch {
	case certExists && keyExists:
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("the HTTPS certificate in %s could not be loaded: %w", dir, err)
		}
		l, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("the HTTPS certificate in %s is not valid: %w", dir, err)
		}
		if !slices.Contains(l.Subject.Organization, Organization) || now.Before(l.NotAfter.Add(-renewBefore)) {
			return c, nil
		}
	case certExists != keyExists:
		return tls.Certificate{}, fmt.Errorf("only one of tls.crt and tls.key exists in %s; add the missing file or remove both so Alice can create a temporary certificate", dir)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create key directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("secure key directory: %w", err)
	}
	certPEM, keyPEM, err := generate(Organization, hosts, now.Add(-time.Hour), now.Add(validity))
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ServerConfig returns the TLS settings required by SEC-031.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{ // TLS 1.2 only; TLS 1.3 suites are not configurable and are all acceptable.
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		Certificates: []tls.Certificate{cert},
	}
}

func generate(org string, hosts []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{org}, CommonName: "Alice"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := bytes.NewReader(data).WriteTo(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return !errors.Is(err, os.ErrNotExist)
}
```

- [ ] **Step 4: Run and pass**

Run: `go test -race ./internal/platform/tlscert/`
Expected: `ok`. If `tls.X25519MLKEM768` does not exist in the toolchain, the build fails; it exists since Go 1.24, so this indicates a wrong toolchain.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/tlscert
git commit -m "feat: manage temporary self-signed HTTPS certificate

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Shared locales and the i18n catalog

**Files:**
- Create: `locales/manifest.json`, `locales/common/en.json`, `locales/common/tr.json`, `locales/embed.go`, `internal/i18n/i18n.go`, `internal/i18n/i18n_test.go`

**Interfaces:**
- Produces:
  - `locales.FS embed.FS` containing `manifest.json` and `common/*.json`
  - `i18n.Locale{Code, Name, Direction string}` (JSON `code`, `name`, `direction`)
  - `i18n.Load(fsys fs.FS) (*i18n.Catalog, error)`: reads `manifest.json` and `common/<code>.json`
  - `(*Catalog) Locales() []Locale`, `Default() string`, `Negotiate(acceptLanguage string) string`, `T(lang, key string, params map[string]string) string`
  - `i18n.Flatten(data []byte) (map[string]string, error)`: nested JSON → dot keys; non-string leaves are errors
- Locale keys defined here and used later: `app.name`; `errors.system.not_found.{title,cause,action}`; `errors.system.unavailable.{title,cause,action}`; `errors.internal.unexpected.{title,cause,action}`.

- [ ] **Step 1: Write the locale files**

`locales/manifest.json`:
```json
{
  "default": "en",
  "locales": [
    { "code": "en", "name": "English", "direction": "ltr" },
    { "code": "tr", "name": "Türkçe", "direction": "ltr" }
  ]
}
```

`locales/common/en.json`:
```json
{
  "app": { "name": "Alice" },
  "errors": {
    "system": {
      "not_found": {
        "title": "This page or item does not exist.",
        "cause": "The address may be mistyped, or the item was removed.",
        "action": "Check the address, or go back to the home page."
      },
      "unavailable": {
        "title": "Alice is temporarily unavailable.",
        "cause": "Alice cannot reach its database, or it is still starting.",
        "action": "Wait a minute and try again. If this continues, ask your administrator to check the Alice service."
      }
    },
    "internal": {
      "unexpected": {
        "title": "Something went wrong on our side.",
        "cause": "Alice hit an unexpected problem while handling your request.",
        "action": "Try again. If it happens again, give your administrator the request ID shown here."
      }
    }
  }
}
```

`locales/common/tr.json`:
```json
{
  "app": { "name": "Alice" },
  "errors": {
    "system": {
      "not_found": {
        "title": "Bu sayfa veya öğe bulunamadı.",
        "cause": "Adres yanlış yazılmış olabilir ya da öğe kaldırılmış olabilir.",
        "action": "Adresi kontrol edin veya ana sayfaya dönün."
      },
      "unavailable": {
        "title": "Alice şu anda geçici olarak kullanılamıyor.",
        "cause": "Alice veritabanına ulaşamıyor ya da hâlâ başlatılıyor.",
        "action": "Bir dakika bekleyip tekrar deneyin. Sorun sürerse yöneticinizden Alice hizmetini kontrol etmesini isteyin."
      }
    },
    "internal": {
      "unexpected": {
        "title": "Bizim tarafımızda bir sorun oluştu.",
        "cause": "Alice isteğinizi işlerken beklenmeyen bir sorunla karşılaştı.",
        "action": "Tekrar deneyin. Yine olursa burada gösterilen istek kimliğini yöneticinize iletin."
      }
    }
  }
}
```

`locales/embed.go`:
```go
// Package locales embeds the translation catalogs shared by the backend and the web UI.
package locales

import "embed"

// FS contains manifest.json and common/<code>.json.
//
//go:embed manifest.json common/*.json
var FS embed.FS
```

- [ ] **Step 2: Write the failing tests**

`internal/i18n/i18n_test.go`:
```go
package i18n_test

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/locales"
)

func fixture() fstest.MapFS {
	return fstest.MapFS{
		"manifest.json": {Data: []byte(`{"default":"en","locales":[{"code":"tr","name":"Türkçe","direction":"ltr"},{"code":"en","name":"English","direction":"ltr"}]}`)},
		"common/en.json": {Data: []byte(`{"greet":{"hello":"Hello {{name}}"},"only_en":"English only"}`)},
		"common/tr.json": {Data: []byte(`{"greet":{"hello":"Merhaba {{name}}"}}`)},
	}
}

func TestTranslateWithParamsAndFallback(t *testing.T) {
	c, err := i18n.Load(fixture())
	require.NoError(t, err)
	assert.Equal(t, "Merhaba İzmir", c.T("tr", "greet.hello", map[string]string{"name": "İzmir"}))
	assert.Equal(t, "Hello Ada", c.T("en", "greet.hello", map[string]string{"name": "Ada"}))
	assert.Equal(t, "English only", c.T("tr", "only_en", nil), "missing Turkish key falls back to English")
	assert.Equal(t, "missing.key", c.T("tr", "missing.key", nil), "unknown key returns the key")
	assert.Equal(t, "Hello Ada", c.T("de", "greet.hello", map[string]string{"name": "Ada"}), "unknown language uses default")
}

func TestNegotiate(t *testing.T) {
	c, err := i18n.Load(fixture())
	require.NoError(t, err)
	assert.Equal(t, "en", c.Default())
	cases := map[string]string{
		"":                          "en",
		"tr-TR,tr;q=0.9,en;q=0.8":   "tr",
		"TR":                        "tr",
		"de-DE,de;q=0.9":            "en",
		"de-DE,tr;q=0.5":            "tr",
		"en-GB":                     "en",
		"this is ;;; not a header": "en",
	}
	for header, want := range cases {
		assert.Equal(t, want, c.Negotiate(header), "header %q", header)
	}
}

func TestLocalesKeepManifestOrder(t *testing.T) {
	c, err := i18n.Load(fixture())
	require.NoError(t, err)
	require.Len(t, c.Locales(), 2)
	assert.Equal(t, "tr", c.Locales()[0].Code)
	assert.Equal(t, "Türkçe", c.Locales()[0].Name)
}

func TestLoadErrors(t *testing.T) {
	bad := fixture()
	bad["common/tr.json"] = &fstest.MapFile{Data: []byte(`{"greet":{"hello":3}}`)}
	_, err := i18n.Load(bad)
	assert.ErrorContains(t, err, "greet.hello")

	missing := fixture()
	delete(missing, "common/tr.json")
	_, err = i18n.Load(missing)
	assert.ErrorContains(t, err, "common/tr.json")

	noDefault := fixture()
	noDefault["manifest.json"] = &fstest.MapFile{Data: []byte(`{"default":"fr","locales":[{"code":"en","name":"English","direction":"ltr"}]}`)}
	_, err = i18n.Load(noDefault)
	assert.ErrorContains(t, err, "default")
}

func TestFlatten(t *testing.T) {
	m, err := i18n.Flatten([]byte(`{"a":{"b":"x","c":{"d":"y"}},"e":"z"}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a.b": "x", "a.c.d": "y", "e": "z"}, m)
}

func TestRealCatalogLoads(t *testing.T) {
	c, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	assert.Equal(t, "Alice", c.T("tr", "app.name", nil))
	assert.NotEqual(t, "errors.system.not_found.title", c.T("tr", "errors.system.not_found.title", nil))
}
```

- [ ] **Step 3: Run and see it fail**

Run: `go get golang.org/x/text@latest && go test ./internal/i18n/`
Expected: FAIL, `undefined: i18n.Load`.

- [ ] **Step 4: Implement**

`internal/i18n/i18n.go`:
```go
// Package i18n loads translation catalogs and renders messages by key.
// The backend returns stable keys; this package only produces fallback text
// (API error messages and, in later phases, emails).
package i18n

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"golang.org/x/text/language"
)

// Locale describes one supported language.
type Locale struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Direction string `json:"direction"`
}

type manifest struct {
	Default string   `json:"default"`
	Locales []Locale `json:"locales"`
}

// Catalog holds flattened messages for every supported locale.
type Catalog struct {
	def     string
	locales []Locale
	msgs    map[string]map[string]string
	codes   []string // matcher order: default first
	matcher language.Matcher
}

// Load reads manifest.json and common/<code>.json from fsys.
func Load(fsys fs.FS) (*Catalog, error) {
	raw, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		return nil, fmt.Errorf("read locale manifest: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse locale manifest: %w", err)
	}
	if len(m.Locales) == 0 {
		return nil, errors.New("locale manifest lists no locales")
	}
	c := &Catalog{def: m.Default, locales: m.Locales, msgs: map[string]map[string]string{}}
	var tags []language.Tag
	for _, l := range m.Locales {
		tag, err := language.Parse(l.Code)
		if err != nil {
			return nil, fmt.Errorf("locale code %q: %w", l.Code, err)
		}
		path := "common/" + l.Code + ".json"
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		flat, err := Flatten(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		c.msgs[l.Code] = flat
		if l.Code == m.Default {
			tags = append([]language.Tag{tag}, tags...)
			c.codes = append([]string{l.Code}, c.codes...)
		} else {
			tags = append(tags, tag)
			c.codes = append(c.codes, l.Code)
		}
	}
	if _, ok := c.msgs[m.Default]; !ok {
		return nil, fmt.Errorf("default locale %q is not listed in the manifest", m.Default)
	}
	c.matcher = language.NewMatcher(tags)
	return c, nil
}

// Locales returns the supported locales in manifest order.
func (c *Catalog) Locales() []Locale { return append([]Locale(nil), c.locales...) }

// Default returns the default locale code.
func (c *Catalog) Default() string { return c.def }

// Negotiate picks the best supported locale for an Accept-Language header.
func (c *Catalog) Negotiate(acceptLanguage string) string {
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return c.def
	}
	_, idx, conf := c.matcher.Match(tags...)
	if conf == language.No {
		return c.def
	}
	return c.codes[idx]
}

// T renders key in lang, falling back to the default locale and then to the key itself.
// Placeholders use the i18next syntax {{name}}.
func (c *Catalog) T(lang, key string, params map[string]string) string {
	s, ok := c.msgs[lang][key]
	if !ok {
		s, ok = c.msgs[c.def][key]
	}
	if !ok {
		return key
	}
	for k, v := range params {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

// Flatten converts nested JSON objects into dot-separated keys.
func Flatten(data []byte) (map[string]string, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	out := map[string]string{}
	if err := flattenInto(out, "", root); err != nil {
		return nil, err
	}
	return out, nil
}

func flattenInto(out map[string]string, prefix string, node map[string]any) error {
	for k, v := range node {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case string:
			out[key] = t
		case map[string]any:
			if err := flattenInto(out, key, t); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: value must be a string or an object", key)
		}
	}
	return nil
}
```

- [ ] **Step 5: Run and pass**

Run: `go mod tidy && go test -race ./internal/i18n/`
Expected: `ok`. If `"TR"` does not negotiate to `tr`, the matcher is being fed lowercase-sensitive input; `language.ParseAcceptLanguage` is case-insensitive, so check the tag list ordering instead of adding casing code.

- [ ] **Step 6: Commit**

```bash
git add locales internal/i18n go.mod go.sum
git commit -m "feat: add shared EN/TR locale catalogs and i18n package

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: i18n parity checker tool

**Files:**
- Create: `tools/i18n-check/check.go`, `tools/i18n-check/main.go`, `tools/i18n-check/check_test.go`
- Modify: `Makefile` (add `i18n-check`)

**Interfaces:**
- Consumes: `i18n.Flatten` (Task 6).
- Produces: `go run ./tools/i18n-check <dir> [<dir>...]`. Each dir contains `en.json` (the source) and other `<code>.json` files. Exit 1 and print one line per problem when a key is missing or extra, a value is empty, or the `{{placeholder}}` sets differ.

- [ ] **Step 1: Write the failing test**

`tools/i18n-check/check_test.go`:
```go
package main

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDirFindsAllProblemKinds(t *testing.T) {
	fsys := fstest.MapFS{
		"en.json": {Data: []byte(`{"a":"Hello {{name}}","b":"Bye","c":"Count {{n}}","d":""}`)},
		"tr.json": {Data: []byte(`{"a":"Merhaba {{isim}}","c":"Sayı {{n}}","d":"x","extra":"fazla"}`)},
	}
	problems, err := CheckDir(fsys, "en")
	require.NoError(t, err)
	assert.Equal(t, []Problem{
		{File: "en.json", Key: "d", Msg: "value is empty"},
		{File: "tr.json", Key: "a", Msg: "placeholders differ: en has [name], tr has [isim]"},
		{File: "tr.json", Key: "b", Msg: "missing key"},
		{File: "tr.json", Key: "extra", Msg: "key not present in en.json"},
	}, problems)
}

func TestCheckDirCleanCatalog(t *testing.T) {
	fsys := fstest.MapFS{
		"en.json": {Data: []byte(`{"a":{"b":"Hi {{ name }}"}}`)},
		"tr.json": {Data: []byte(`{"a":{"b":"Selam {{name}}"}}`)},
	}
	problems, err := CheckDir(fsys, "en")
	require.NoError(t, err)
	assert.Empty(t, problems)
}

func TestCheckDirRequiresSourceFile(t *testing.T) {
	_, err := CheckDir(fstest.MapFS{"tr.json": {Data: []byte(`{}`)}}, "en")
	assert.ErrorContains(t, err, "en.json")
}
```

- [ ] **Step 2: Run and see it fail**

Run: `go test ./tools/i18n-check/`
Expected: FAIL, `undefined: CheckDir`.

- [ ] **Step 3: Implement**

`tools/i18n-check/check.go`:
```go
package main

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strings"

	"alice/internal/i18n"
)

// Problem is one catalog inconsistency.
type Problem struct {
	File, Key, Msg string
}

var placeholderRE = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.]+)\s*\}\}`)

// CheckDir compares every <code>.json in fsys against <base>.json.
func CheckDir(fsys fs.FS, base string) ([]Problem, error) {
	baseFile := base + ".json"
	baseMsgs, err := load(fsys, baseFile)
	if err != nil {
		return nil, err
	}
	var problems []Problem
	for k, v := range baseMsgs {
		if strings.TrimSpace(v) == "" {
			problems = append(problems, Problem{baseFile, k, "value is empty"})
		}
	}
	files, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if f == baseFile {
			continue
		}
		code := strings.TrimSuffix(f, ".json")
		msgs, err := load(fsys, f)
		if err != nil {
			return nil, err
		}
		for k, bv := range baseMsgs {
			v, ok := msgs[k]
			switch {
			case !ok:
				problems = append(problems, Problem{f, k, "missing key"})
			case strings.TrimSpace(v) == "":
				problems = append(problems, Problem{f, k, "value is empty"})
			case !slices.Equal(placeholders(bv), placeholders(v)):
				problems = append(problems, Problem{f, k, fmt.Sprintf("placeholders differ: %s has %v, %s has %v", base, placeholders(bv), code, placeholders(v))})
			}
		}
		for k := range msgs {
			if _, ok := baseMsgs[k]; !ok {
				problems = append(problems, Problem{f, k, "key not present in " + baseFile})
			}
		}
	}
	sort.Slice(problems, func(i, j int) bool {
		if problems[i].File != problems[j].File {
			return problems[i].File < problems[j].File
		}
		return problems[i].Key < problems[j].Key
	})
	return problems, nil
}

func load(fsys fs.FS, name string) (map[string]string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	m, err := i18n.Flatten(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return m, nil
}

func placeholders(s string) []string {
	var out []string
	for _, m := range placeholderRE.FindAllStringSubmatch(s, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}
```

`tools/i18n-check/main.go`:
```go
// Command i18n-check verifies that every translation file has exactly the
// keys and placeholders of en.json. Usage: i18n-check <dir> [<dir>...]
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: i18n-check <dir> [<dir>...]")
		os.Exit(2)
	}
	failed := false
	for _, dir := range os.Args[1:] {
		problems, err := CheckDir(os.DirFS(dir), "en")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", dir, err)
			failed = true
			continue
		}
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "%s/%s: %s: %s\n", dir, p.File, p.Key, p.Msg)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("i18n-check: all catalogs are consistent")
}
```

- [ ] **Step 4: Makefile target**

Append:
```make
.PHONY: i18n-check
i18n-check: ## Verify EN/TR translation catalogs have identical keys and placeholders
	go run ./tools/i18n-check locales/common web/src/locales
```
`web/src/locales` is created in Task 9; until then run the tool on `locales/common` only.

- [ ] **Step 5: Run and pass**

Run: `go test -race ./tools/i18n-check/ && go run ./tools/i18n-check locales/common`
Expected: `ok`, then `i18n-check: all catalogs are consistent`.

- [ ] **Step 6: Commit**

```bash
git add tools/i18n-check Makefile
git commit -m "feat: add translation catalog parity checker

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: HTTP API, middleware, errors and SPA serving

**Files:**
- Create: `internal/api/server.go`, `internal/api/middleware.go`, `internal/api/errors.go`, `internal/api/spa.go`, `internal/api/server_test.go`, `internal/api/errors_test.go`

**Interfaces:**
- Consumes: `i18n.Catalog` (Task 6), `version.Info` (Task 1), `db.ErrUnreachable` and `db.ErrMigrationsPending` (Task 4, only to label health failures in logs).
- Produces:
  - `api.HealthChecker` interface `{ Check(ctx context.Context) error }` (satisfied by `*db.HealthChecker`)
  - `api.Deps{Health HealthChecker; Catalog *i18n.Catalog; Version version.Info; UI fs.FS; Log *slog.Logger}`
  - `api.NewHandler(d Deps) http.Handler`: public handler (`GET /livez`, `GET /healthz`, `GET /api/v1/version`, `GET /api/v1/i18n/locales`, JSON 404 for other `/api/`, SPA for everything else)
  - `api.NewHealthHandler(d Deps) http.Handler`: internal listener (`/livez`, `/healthz` only)
  - `api.ErrorCode{Code, Reason string; Status int; Retryable bool}`; `api.ErrNotFound` (`ALC-SYS-0001`, `system.not_found`, 404), `api.ErrUnavailable` (`ALC-SYS-0002`, `system.unavailable`, 503, retryable), `api.ErrUnexpected` (`ALC-SYS-0003`, `internal.unexpected`, 500); `api.AllErrorCodes() []ErrorCode`
  - `api.RequestID(ctx context.Context) string`
  - Index placeholder string `__CSP_NONCE__` (Task 9 puts it in `web/index.html`)

- [ ] **Step 1: Add dependency**

Run: `go get github.com/google/uuid@latest`

- [ ] **Step 2: Write the failing server tests**

`internal/api/server_test.go`:
```go
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/version"
	"alice/locales"
)

type fakeHealth struct{ err error }

func (f fakeHealth) Check(context.Context) error { return f.err }

const indexHTML = `<!doctype html><html><head><meta name="csp-nonce" content="__CSP_NONCE__"></head><body><div id="root"></div></body></html>`

func testDeps(t *testing.T, health error) Deps {
	t.Helper()
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	return Deps{
		Health:  fakeHealth{err: health},
		Catalog: cat,
		Version: version.Info{Version: "1.2.3", Commit: "abc", BuildTime: "t"},
		UI: fstest.MapFS{
			"index.html":         {Data: []byte(indexHTML)},
			"assets/app-1a2b.js": {Data: []byte("console.log(1)")},
			"favicon.svg":        {Data: []byte("<svg/>")},
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func do(h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type errBody struct {
	Error struct {
		Code, Reason, MessageKey, Message, RequestID string
		Retryable                                    bool
	} `json:"error"`
}

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) errBody {
	t.Helper()
	var raw map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	e := raw["error"]
	var b errBody
	b.Error.Code, _ = e["code"].(string)
	b.Error.Reason, _ = e["reason"].(string)
	b.Error.MessageKey, _ = e["message_key"].(string)
	b.Error.Message, _ = e["message"].(string)
	b.Error.RequestID, _ = e["request_id"].(string)
	b.Error.Retryable, _ = e["retryable"].(bool)
	return b
}

func TestLivez(t *testing.T) {
	rec := do(NewHandler(testDeps(t, nil)), http.MethodGet, "/livez", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestHealthzOK(t *testing.T) {
	rec := do(NewHandler(testDeps(t, nil)), http.MethodGet, "/healthz", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestHealthzUnavailableHidesCause(t *testing.T) {
	rec := do(NewHandler(testDeps(t, errors.New("dial tcp postgres: password s3cret-pw rejected"))), http.MethodGet, "/healthz", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotContains(t, rec.Body.String(), "s3cret-pw")
	b := decodeErr(t, rec)
	assert.Equal(t, "ALC-SYS-0002", b.Error.Code)
	assert.True(t, b.Error.Retryable)
}

func TestVersionAndLocales(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	rec := do(h, http.MethodGet, "/api/v1/version", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"version":"1.2.3","commit":"abc","build_time":"t"}`, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))

	rec = do(h, http.MethodGet, "/api/v1/i18n/locales", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"default":"en","locales":[{"code":"en","name":"English","direction":"ltr"},{"code":"tr","name":"Türkçe","direction":"ltr"}]}`, rec.Body.String())
}

func TestUnknownAPIPathIsJSON404InRequestLanguage(t *testing.T) {
	rec := do(NewHandler(testDeps(t, nil)), http.MethodGet, "/api/v1/nope", map[string]string{"Accept-Language": "tr-TR"})
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	b := decodeErr(t, rec)
	assert.Equal(t, "ALC-SYS-0001", b.Error.Code)
	assert.Equal(t, "system.not_found", b.Error.Reason)
	assert.Equal(t, "errors.system.not_found", b.Error.MessageKey)
	assert.Contains(t, b.Error.Message, "bulunamadı")
	assert.Equal(t, rec.Header().Get("X-Request-Id"), b.Error.RequestID)
	assert.NotEmpty(t, b.Error.RequestID)
}

func TestWrongMethodOnAPIRouteIsJSONNotSPA(t *testing.T) {
	// "/api/" is more specific than "/", so a POST to a GET-only API route gets the JSON 404.
	rec := do(NewHandler(testDeps(t, nil)), http.MethodPost, "/api/v1/version", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "ALC-SYS-0001", decodeErr(t, rec).Error.Code)
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for _, p := range []string{"/livez", "/", "/api/v1/nope", "/assets/app-1a2b.js"} {
		rec := do(h, http.MethodGet, p, nil)
		hdr := rec.Header()
		assert.Equal(t, "max-age=31536000; includeSubDomains", hdr.Get("Strict-Transport-Security"), p)
		assert.Equal(t, "nosniff", hdr.Get("X-Content-Type-Options"), p)
		assert.Equal(t, "DENY", hdr.Get("X-Frame-Options"), p)
		assert.Equal(t, "no-referrer", hdr.Get("Referrer-Policy"), p)
		assert.Equal(t, "same-origin", hdr.Get("Cross-Origin-Opener-Policy"), p)
		assert.Equal(t, "same-origin", hdr.Get("Cross-Origin-Resource-Policy"), p)
		assert.Equal(t, "camera=(), microphone=(), geolocation=()", hdr.Get("Permissions-Policy"), p)
		assert.NotEmpty(t, hdr.Get("Content-Security-Policy"), p)
		assert.NotEmpty(t, hdr.Get("X-Request-Id"), p)
	}
}

var nonceRE = regexp.MustCompile(`content="([A-Za-z0-9+/=]{20,})"`)

func TestIndexGetsFreshNonceMatchingCSP(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	var nonces []string
	for range 2 {
		rec := do(h, http.MethodGet, "/", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.NotContains(t, rec.Body.String(), "__CSP_NONCE__")
		m := nonceRE.FindStringSubmatch(rec.Body.String())
		require.Len(t, m, 2)
		csp := rec.Header().Get("Content-Security-Policy")
		assert.Equal(t, "default-src 'none'; script-src 'self'; style-src 'self' 'nonce-"+m[1]+"'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", csp)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
		nonces = append(nonces, m[1])
	}
	assert.NotEqual(t, nonces[0], nonces[1])
}

func TestClientSideRoutesServeIndex(t *testing.T) {
	rec := do(NewHandler(testDeps(t, nil)), http.MethodGet, "/users/5", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `<div id="root">`)
}

func TestAssetsAreCachedAndMissingAssetsAre404(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	rec := do(h, http.MethodGet, "/assets/app-1a2b.js", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "public, max-age=31536000, immutable", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "console.log(1)", rec.Body.String())

	rec = do(h, http.MethodGet, "/favicon.svg", nil)
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))

	rec = do(h, http.MethodGet, "/assets/missing.js", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPathTraversalNeverEscapesUI(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for _, p := range []string{"/../../etc/passwd", "/..%2f..%2fetc%2fpasswd", "/assets/../../go.mod"} {
		rec := do(h, http.MethodGet, p, nil)
		assert.NotContains(t, rec.Body.String(), "root:", p)
		assert.NotContains(t, rec.Body.String(), "module alice", p)
	}
}

func TestUINotBuiltShowsHelpfulPage(t *testing.T) {
	d := testDeps(t, nil)
	d.UI = fstest.MapFS{}
	rec := do(NewHandler(d), http.MethodGet, "/", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "make web")
}

func TestPanicBecomesUnexpectedError(t *testing.T) {
	s := &server{deps: testDeps(t, nil)}
	h := s.requestID(s.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom s3cret-pw") })))
	rec := do(h, http.MethodGet, "/x", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "s3cret-pw")
	assert.Equal(t, "ALC-SYS-0003", decodeErr(t, rec).Error.Code)
}

func TestHealthHandlerExposesOnlyProbes(t *testing.T) {
	h := NewHealthHandler(testDeps(t, nil))
	assert.Equal(t, http.StatusOK, do(h, http.MethodGet, "/healthz", nil).Code)
	assert.Equal(t, http.StatusOK, do(h, http.MethodGet, "/livez", nil).Code)
	assert.Equal(t, http.StatusNotFound, do(h, http.MethodGet, "/api/v1/version", nil).Code)
	assert.False(t, strings.Contains(do(h, http.MethodGet, "/", nil).Body.String(), "root"))
}
```

`internal/api/errors_test.go`:
```go
package api

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/locales"
)

var codeRE = regexp.MustCompile(`^ALC-[A-Z]{2,5}-\d{4}$`)

func TestEveryErrorCodeIsWellFormedUniqueAndTranslated(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, ec := range AllErrorCodes() {
		assert.Regexp(t, codeRE, ec.Code)
		assert.False(t, seen[ec.Code], "duplicate code %s", ec.Code)
		seen[ec.Code] = true
		for _, lang := range []string{"en", "tr"} {
			for _, part := range []string{"title", "cause", "action"} {
				key := "errors." + ec.Reason + "." + part
				assert.NotEqual(t, key, cat.T(lang, key, nil), "missing %s in %s", key, lang)
			}
		}
	}
}
```

- [ ] **Step 3: Run and see it fail**

Run: `go test ./internal/api/`
Expected: FAIL, `undefined: Deps`.

- [ ] **Step 4: Implement errors**

`internal/api/errors.go`:
```go
package api

import (
	"encoding/json"
	"net/http"
)

// ErrorCode is a stable, documented API error. Codes are never reused.
type ErrorCode struct {
	Code      string
	Reason    string
	Status    int
	Retryable bool
}

var (
	ErrNotFound    = ErrorCode{Code: "ALC-SYS-0001", Reason: "system.not_found", Status: http.StatusNotFound}
	ErrUnavailable = ErrorCode{Code: "ALC-SYS-0002", Reason: "system.unavailable", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrUnexpected  = ErrorCode{Code: "ALC-SYS-0003", Reason: "internal.unexpected", Status: http.StatusInternalServerError}
)

// AllErrorCodes lists every registered code; tests check format, uniqueness and translations.
func AllErrorCodes() []ErrorCode {
	return []ErrorCode{ErrNotFound, ErrUnavailable, ErrUnexpected}
}

type errorPayload struct {
	Code       string `json:"code"`
	Reason     string `json:"reason"`
	MessageKey string `json:"message_key"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
	Retryable  bool   `json:"retryable"`
}

func (s *server) writeError(w http.ResponseWriter, r *http.Request, ec ErrorCode) {
	lang := s.deps.Catalog.Negotiate(r.Header.Get("Accept-Language"))
	key := "errors." + ec.Reason
	msg := s.deps.Catalog.T(lang, key+".title", nil) + " " + s.deps.Catalog.T(lang, key+".action", nil)
	writeJSON(w, ec.Status, map[string]errorPayload{"error": {
		Code:       ec.Code,
		Reason:     ec.Reason,
		MessageKey: key,
		Message:    msg,
		RequestID:  RequestID(r.Context()),
		Retryable:  ec.Retryable,
	}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 5: Implement middleware**

`internal/api/middleware.go`:
```go
package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type ctxKey int

const requestIDKey ctxKey = iota

// RequestID returns the request ID assigned by the middleware, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// requestID assigns a server-generated ID. Client-supplied IDs are ignored so
// they cannot be used to forge audit correlations.
func (s *server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.Must(uuid.NewV7()).String()
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

const apiCSP = "default-src 'none'; frame-ancestors 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", apiCSP) // the SPA handler replaces this for index.html
		next.ServeHTTP(w, r)
	})
}

func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				// The panic value is not logged: it may contain request data or secrets.
				s.deps.Log.Error("request handler panicked", "request_id", RequestID(r.Context()), "path", r.URL.Path)
				s.writeError(w, r, ErrUnexpected)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 6: Implement the SPA handler**

`internal/api/spa.go`:
```go
package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

const noncePlaceholder = "__CSP_NONCE__"

const spaCSPTemplate = "default-src 'none'; script-src 'self'; style-src 'self' 'nonce-%NONCE%'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

const notBuiltPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Alice</title></head>
<body><h1>The Alice web interface is not built.</h1><p>Developers: run <code>make web</code> and rebuild the binary.</p></body></html>`

func (s *server) spa() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name != "" && name != "index.html" && fs.ValidPath(name) {
			if st, err := fs.Stat(s.deps.UI, name); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				http.ServeFileFS(w, r, s.deps.UI, name)
				return
			}
			if strings.HasPrefix(name, "assets/") || path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
		}
		s.serveIndex(w)
	})
}

func (s *server) serveIndex(w http.ResponseWriter) {
	index, err := fs.ReadFile(s.deps.UI, "index.html")
	if errors.Is(err, fs.ErrNotExist) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(notBuiltPage))
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce := newNonce()
	w.Header().Set("Content-Security-Policy", strings.Replace(spaCSPTemplate, "%NONCE%", nonce, 1))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(bytes.ReplaceAll(index, []byte(noncePlaceholder), []byte(nonce)))
}

func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}
```

- [ ] **Step 7: Implement the server**

`internal/api/server.go`:
```go
// Package api is Alice's HTTP layer. It holds no business logic and no SQL.
package api

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"

	"alice/internal/i18n"
	"alice/internal/platform/db"
	"alice/internal/version"
)

// HealthChecker reports whether dependencies (the database) are ready.
type HealthChecker interface {
	Check(ctx context.Context) error
}

// Deps are the handler's dependencies, wired in cmd/alice.
type Deps struct {
	Health  HealthChecker
	Catalog *i18n.Catalog
	Version version.Info
	UI      fs.FS
	Log     *slog.Logger
}

type server struct{ deps Deps }

// NewHandler returns the public HTTPS handler.
func NewHandler(d Deps) http.Handler {
	s := &server{deps: d}
	mux := http.NewServeMux()
	s.probes(mux)
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.deps.Version)
	})
	mux.HandleFunc("GET /api/v1/i18n/locales", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"default": s.deps.Catalog.Default(), "locales": s.deps.Catalog.Locales()})
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { s.writeError(w, r, ErrNotFound) })
	mux.Handle("/", s.spa())
	return s.requestID(securityHeaders(s.recoverer(mux)))
}

// NewHealthHandler returns the handler for the internal, container-local health listener.
func NewHealthHandler(d Deps) http.Handler {
	s := &server{deps: d}
	mux := http.NewServeMux()
	s.probes(mux)
	return s.requestID(securityHeaders(s.recoverer(mux)))
}

func (s *server) probes(mux *http.ServeMux) {
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.deps.Health.Check(r.Context()); err != nil {
			s.deps.Log.Warn("health check failed", "request_id", RequestID(r.Context()), "reason", healthReason(err))
			s.writeError(w, r, ErrUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

// healthReason maps an error to a fixed label so no driver text (which could
// include connection details) ever reaches the logs.
func healthReason(err error) string {
	switch {
	case errors.Is(err, db.ErrUnreachable):
		return "database_unreachable"
	case errors.Is(err, db.ErrMigrationsPending):
		return "migrations_pending"
	default:
		return "unknown"
	}
}
```

- [ ] **Step 8: Run and pass**

Run: `go mod tidy && go test -race ./internal/api/`
Expected: `ok`.

- [ ] **Step 9: Commit**

```bash
git add internal/api go.mod go.sum
git commit -m "feat: add HTTP API skeleton with security headers, errors and SPA serving

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Web UI (Vite, React, Mantine, EN/TR) and embedding

**Files:**
- Create: `web/package.json` (via npm), `web/go.mod` (Go-exclusion marker), `web/public/favicon.svg`, `web/postcss.config.cjs`, `web/tsconfig.json`, `web/vite.config.ts`, `web/eslint.config.js`, `web/index.html`, `web/src/main.tsx`, `web/src/App.tsx`, `web/src/LanguageSwitcher.tsx`, `web/src/i18n.ts`, `web/src/csp.ts`, `web/src/api.ts`, `web/src/theme.ts`, `web/src/locales/en.json`, `web/src/locales/tr.json`, `web/src/test/setup.ts`, `web/src/test/render.tsx`, `web/src/App.test.tsx`, `web/src/i18n.test.ts`, `internal/webui/embed.go`, `internal/webui/dist/.gitkeep`
- Modify: `Makefile` (add `web-install`, `web`, `build`, `web-test`, `web-lint`)

**Interfaces:**
- Consumes: `GET /api/v1/version` (Task 8), `locales/common/*.json`, `locales/manifest.json` (Task 6), placeholder `__CSP_NONCE__` (Task 8).
- Produces: build output in `internal/webui/dist/app/`; `webui.UI() fs.FS` rooted at that directory; UI strings `home.title`, `home.subtitle`, `home.serverChecking`, `home.serverVersion`, `home.serverUnreachable`, `language.label`; element `data-testid="server-status"`; `<html lang>` follows the active language; language stored in `localStorage` key `alice.lang`.

- [ ] **Step 1: Create the project and install dependencies**

```bash
cd /home/meren/projects/alice-secrets
mkdir -p web/public internal/webui/dist && touch internal/webui/dist/.gitkeep
# A nested go.mod keeps web/ (and node_modules, which may contain .go files) out of `go ./...`.
printf '// Keeps the Go toolchain out of web/; this is not a real Go module.\nmodule alice/web-nogo\n' > web/go.mod
cd web
npm init -y
npm pkg set name=alice-web private=true type=module
npm pkg delete main keywords author license description scripts.test
npm install react@18 react-dom@18 @mantine/core@8 @mantine/hooks@8 @tanstack/react-query@5 i18next react-i18next
npm install -D typescript vite @vitejs/plugin-react @types/react@18 @types/react-dom@18 vitest jsdom @testing-library/react @testing-library/user-event @testing-library/jest-dom eslint @eslint/js typescript-eslint eslint-plugin-react-hooks globals @playwright/test postcss postcss-preset-mantine
npm pkg set scripts.dev="vite" scripts.build="tsc --noEmit && vite build" scripts.test="vitest run" scripts.lint="eslint ." scripts.e2e="playwright test"
```

- [ ] **Step 2: Configuration files**

`web/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "skipLibCheck": true,
    "noEmit": true,
    "types": ["vitest/globals", "@testing-library/jest-dom"],
    "paths": { "@locales/*": ["../locales/*"] }
  },
  "include": ["src", "e2e", "vite.config.ts", "playwright.config.ts"]
}
```

`web/vite.config.ts`:
```ts
/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const locales = fileURLToPath(new URL('../locales', import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@locales': locales } },
  server: { fs: { allow: ['..'] } },
  build: {
    outDir: '../internal/webui/dist/app',
    emptyOutDir: true,
    assetsInlineLimit: 0, // CSP: no data: fonts or inline assets
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
```

`web/postcss.config.cjs`:
```js
module.exports = { plugins: { 'postcss-preset-mantine': {} } };
```

`web/eslint.config.js`:
```js
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default tseslint.config(
  { ignores: ['node_modules', 'playwright-report', 'test-results'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'no-restricted-syntax': [
        'error',
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: 'dangerouslySetInnerHTML is forbidden (XSS, SEC-035).' },
        { selector: "CallExpression[callee.property.name=/^to(Upper|Lower)Case$/]", message: 'Use toLocaleUpperCase/toLocaleLowerCase with the active locale for user-visible text (Turkish dotted/dotless i).' },
      ],
    },
  },
);
```

`web/index.html`:
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="csp-nonce" content="__CSP_NONCE__" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <title>Alice</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 3: Web-only translations**

`web/public/favicon.svg` (served at `/favicon.svg`; prevents a browser request for a missing `/favicon.ico`, which would log a console error):
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#4c6ef5"/><path d="M16 6l9 20h-4l-1.8-4.2h-6.4L11 26H7zm0 7.5l-2.1 5h4.2z" fill="#fff"/></svg>
```

`web/src/locales/en.json`:
```json
{
  "home": {
    "title": "Welcome to Alice",
    "subtitle": "Alice keeps track of your TLS certificates and SSH keys. The setup wizard arrives in the next version.",
    "serverChecking": "Checking the server…",
    "serverVersion": "Server version: {{version}}",
    "serverUnreachable": "The server cannot be reached right now. Try reloading the page in a minute."
  },
  "language": { "label": "Language" }
}
```

`web/src/locales/tr.json`:
```json
{
  "home": {
    "title": "Alice'e hoş geldiniz",
    "subtitle": "Alice, TLS sertifikalarınızı ve SSH anahtarlarınızı takip eder. Kurulum sihirbazı bir sonraki sürümde gelecek.",
    "serverChecking": "Sunucu kontrol ediliyor…",
    "serverVersion": "Sunucu sürümü: {{version}}",
    "serverUnreachable": "Sunucuya şu anda ulaşılamıyor. Bir dakika sonra sayfayı yenilemeyi deneyin."
  },
  "language": { "label": "Dil" }
}
```

- [ ] **Step 4: Write the failing tests**

`web/src/test/setup.ts`:
```ts
import '@testing-library/jest-dom/vitest';

// jsdom lacks these browser APIs that Mantine uses.
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
```

`web/src/test/render.tsx`:
```tsx
import { render } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import type { ReactElement } from 'react';
import { createI18n } from '../i18n';

export async function renderApp(ui: ReactElement, languages: readonly string[] = ['en-US']) {
  const i18n = await createI18n(languages);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const result = render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <MantineProvider>{ui}</MantineProvider>
      </QueryClientProvider>
    </I18nextProvider>,
  );
  return { ...result, i18n };
}
```

`web/src/i18n.test.ts`:
```ts
import { pickLanguage } from './i18n';

describe('pickLanguage', () => {
  beforeEach(() => localStorage.clear());

  it('uses a stored supported language first', () => {
    expect(pickLanguage('tr', ['en-US'])).toBe('tr');
  });
  it('ignores an unsupported stored value', () => {
    expect(pickLanguage('xx', ['tr-TR'])).toBe('tr');
  });
  it('matches the browser language by its base code', () => {
    expect(pickLanguage(null, ['de-DE', 'tr-TR'])).toBe('tr');
    expect(pickLanguage(null, ['TR'])).toBe('tr');
  });
  it('falls back to English', () => {
    expect(pickLanguage(null, ['de-DE'])).toBe('en');
    expect(pickLanguage(null, [])).toBe('en');
  });
});
```

`web/src/App.test.tsx`:
```tsx
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from './App';
import { renderApp } from './test/render';

function mockVersion(ok = true) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      ok
        ? new Response(JSON.stringify({ version: '1.2.3', commit: 'abc', build_time: 't' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        : new Response('{}', { status: 503 }),
    ),
  );
}

describe('App', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.lang = 'en';
  });
  afterEach(() => vi.unstubAllGlobals());

  it('renders the English home page with the server version', async () => {
    mockVersion();
    await renderApp(<App />);
    expect(screen.getByRole('heading', { name: 'Welcome to Alice' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('Server version: 1.2.3'));
  });

  it('starts in Turkish for a Turkish browser', async () => {
    mockVersion();
    await renderApp(<App />, ['tr-TR']);
    expect(screen.getByRole('heading', { name: "Alice'e hoş geldiniz" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('tr');
  });

  it('switches language, updates <html lang> and remembers the choice', async () => {
    mockVersion();
    await renderApp(<App />);
    await userEvent.click(screen.getByText('Türkçe'));
    expect(await screen.findByRole('heading', { name: "Alice'e hoş geldiniz" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('tr');
    expect(localStorage.getItem('alice.lang')).toBe('tr');
  });

  it('explains when the server is unreachable', async () => {
    mockVersion(false);
    await renderApp(<App />);
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('cannot be reached'));
  });
});
```

- [ ] **Step 5: Run and see them fail**

Run: `cd web && npx vitest run`
Expected: FAIL, cannot resolve `./i18n` / `./App`.

- [ ] **Step 6: Implement the app**

`web/src/csp.ts`:
```ts
// The server replaces __CSP_NONCE__ in index.html with a per-request nonce.
// Mantine adds it to the <style> tag it injects, so CSP needs no 'unsafe-inline'.
export function readCspNonce(): string {
  return document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content') ?? '';
}
```

`web/src/i18n.ts`:
```ts
import i18next, { type i18n as I18n } from 'i18next';
import { initReactI18next } from 'react-i18next';
import commonEn from '@locales/common/en.json';
import commonTr from '@locales/common/tr.json';
import manifest from '@locales/manifest.json';
import webEn from './locales/en.json';
import webTr from './locales/tr.json';

export type Lang = 'en' | 'tr';
export const LANGUAGES: { code: Lang; name: string }[] = manifest.locales.map((l) => ({
  code: l.code as Lang,
  name: l.name,
}));

const STORAGE_KEY = 'alice.lang';

function isSupported(code: string): code is Lang {
  return LANGUAGES.some((l) => l.code === code);
}

// Language tags are ASCII protocol data, so invariant lowercasing is correct here.
function baseCode(tag: string): string {
  return tag.split('-')[0].toLocaleLowerCase('en-US');
}

export function pickLanguage(stored: string | null, browser: readonly string[]): Lang {
  if (stored && isSupported(stored)) return stored;
  for (const tag of browser) {
    const base = baseCode(tag);
    if (isSupported(base)) return base;
  }
  return 'en';
}

function readStored(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export async function createI18n(browserLanguages: readonly string[]): Promise<I18n> {
  const lng = pickLanguage(readStored(), browserLanguages);
  const instance = i18next.createInstance();
  await instance.use(initReactI18next).init({
    resources: {
      en: { web: webEn, common: commonEn },
      tr: { web: webTr, common: commonTr },
    },
    lng,
    fallbackLng: 'en',
    ns: ['web', 'common'],
    defaultNS: 'web',
    fallbackNS: 'common',
    interpolation: { escapeValue: false }, // React escapes output
  });
  document.documentElement.lang = lng;
  return instance;
}

export async function setLanguage(i18n: I18n, lang: Lang): Promise<void> {
  await i18n.changeLanguage(lang);
  document.documentElement.lang = lang;
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Storage can be blocked (private mode); the choice then lasts for this page only.
  }
}
```

`web/src/api.ts`:
```ts
export interface VersionInfo {
  version: string;
  commit: string;
  build_time: string;
}

export async function fetchVersion(): Promise<VersionInfo> {
  const res = await fetch('/api/v1/version', { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`version request failed with status ${res.status}`);
  return (await res.json()) as VersionInfo;
}
```

`web/src/theme.ts`:
```ts
import { createTheme } from '@mantine/core';

export const theme = createTheme({
  primaryColor: 'indigo',
  defaultRadius: 'md',
});
```

`web/src/LanguageSwitcher.tsx`:
```tsx
import { SegmentedControl } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { LANGUAGES, setLanguage, type Lang } from './i18n';

export function LanguageSwitcher() {
  const { t, i18n } = useTranslation();
  return (
    <SegmentedControl
      aria-label={t('language.label')}
      value={i18n.language}
      onChange={(value) => void setLanguage(i18n, value as Lang)}
      data={LANGUAGES.map((l) => ({ value: l.code, label: l.name }))}
    />
  );
}
```

`web/src/App.tsx`:
```tsx
import { AppShell, Container, Group, Stack, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { fetchVersion } from './api';
import { LanguageSwitcher } from './LanguageSwitcher';

export function App() {
  const { t } = useTranslation();
  const version = useQuery({ queryKey: ['version'], queryFn: fetchVersion });

  let status = t('home.serverChecking');
  if (version.isSuccess) status = t('home.serverVersion', { version: version.data.version });
  if (version.isError) status = t('home.serverUnreachable');

  return (
    <AppShell header={{ height: 60 }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Text fw={700} size="xl">
            {t('app.name', { ns: 'common' })}
          </Text>
          <LanguageSwitcher />
        </Group>
      </AppShell.Header>
      <AppShell.Main>
        <Container size="sm">
          <Stack gap="sm" mt="xl">
            <Title order={1}>{t('home.title')}</Title>
            <Text>{t('home.subtitle')}</Text>
            <Text size="sm" c="dimmed" data-testid="server-status" aria-live="polite">
              {status}
            </Text>
          </Stack>
        </Container>
      </AppShell.Main>
    </AppShell>
  );
}
```

`web/src/main.tsx`:
```tsx
import '@mantine/core/styles.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import { App } from './App';
import { createI18n } from './i18n';
import { readCspNonce } from './csp';
import { theme } from './theme';

const queryClient = new QueryClient();

createI18n(navigator.languages).then((i18n) => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={queryClient}>
          <MantineProvider theme={theme} getStyleNonce={readCspNonce} defaultColorScheme="light">
            <App />
          </MantineProvider>
        </QueryClientProvider>
      </I18nextProvider>
    </StrictMode>,
  );
});
```

- [ ] **Step 7: Run tests, lint and build**

Run: `cd web && npx vitest run && npx eslint . && npm run build && ls ../internal/webui/dist/app`
Expected: 8 tests pass, no lint errors, `index.html` and `assets/` exist. Check that no inline script was emitted: `grep -c '<script type="module" crossorigin src=' ../internal/webui/dist/app/index.html` prints `1` and `grep -c '<script>' ../internal/webui/dist/app/index.html` prints `0`.

- [ ] **Step 8: Go embed package**

`internal/webui/embed.go`:
```go
// Package webui embeds the built web UI. Build it with `make web`; without a
// build the server shows a "not built" page instead of failing.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// UI returns the built SPA rooted at its index.html.
func UI() fs.FS {
	sub, err := fs.Sub(dist, "dist/app")
	if err != nil {
		panic(err) // only possible if the embed pattern is wrong
	}
	return sub
}
```

- [ ] **Step 9: Makefile targets**

Append:
```make
.PHONY: web-install
web-install: ## Install web dependencies from the lockfile
	cd web && npm ci

.PHONY: web
web: ## Build the web UI into internal/webui/dist/app
	cd web && npm run build

.PHONY: web-test
web-test: ## Run web unit tests
	cd web && npm test

.PHONY: web-lint
web-lint: ## Lint the web UI
	cd web && npm run lint

.PHONY: build
build: web ## Build the alice binary with the embedded UI into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/alice ./cmd/alice
```

- [ ] **Step 10: Run the full i18n check now that both dirs exist**

Run: `cd /home/meren/projects/alice-secrets && make i18n-check && go build ./...`
Expected: `i18n-check: all catalogs are consistent`; build succeeds (cmd/alice does not exist yet; `./...` builds the packages).

- [ ] **Step 11: Commit**

```bash
git add web internal/webui Makefile
git commit -m "feat: add React/Mantine web UI with EN/TR switcher and embed it

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Command entry point and architecture test

**Files:**
- Create: `cmd/alice/main.go`, `cmd/alice/main_test.go`, `internal/archtest/arch_test.go`, `internal/archtest/doc.go`

**Interfaces:**
- Consumes: `config.Load`, `db.Open`, `db.Migrate`, `db.NewHealthChecker`, `tlscert.EnsureSelfSigned`, `tlscert.ServerConfig`, `i18n.Load`, `api.NewHandler`, `api.NewHealthHandler`, `api.Deps`, `webui.UI`, `version.Get`, `migrations.FS`, `locales.FS`, `clock.Real`.
- Produces: `alice serve` (default), `alice migrate`, `alice healthcheck` (exit 0 when `http://$ALICE_HEALTH_ADDR/healthz` returns 200 within 3 s, else 1), `alice version`, `alice help`; unknown command exits 2. Function `run(args []string, getenv func(string) string, stdout, stderr io.Writer) int`.

- [ ] **Step 1: Write the failing CLI test**

`cmd/alice/main_test.go`:
```go
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestVersionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"version"}, env(nil), &out, &errOut)
	assert.Equal(t, 0, code)
	assert.Contains(t, out.String(), "alice dev")
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"frobnicate"}, env(nil), &out, &errOut)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut.String(), "unknown command")
	assert.Contains(t, errOut.String(), "serve")
}

func TestMigrateNeedsDatabaseURL(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"migrate"}, env(nil), &out, &errOut)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut.String(), "ALICE_DATABASE_URL")
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": strings.TrimPrefix(ok.URL, "http://")}), &out, &errOut))
	assert.Equal(t, 1, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": strings.TrimPrefix(bad.URL, "http://")}), &out, &errOut))
	assert.Equal(t, 1, run([]string{"healthcheck"}, env(map[string]string{"ALICE_HEALTH_ADDR": "127.0.0.1:1"}), &out, &errOut))
}
```

- [ ] **Step 2: Run and see it fail**

Run: `go test ./cmd/alice/`
Expected: FAIL, `undefined: run`.

- [ ] **Step 3: Implement**

`cmd/alice/main.go`:
```go
// Command alice is the Alice server and operator CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"alice/internal/api"
	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/db"
	"alice/internal/platform/tlscert"
	"alice/internal/version"
	"alice/internal/webui"
	"alice/locales"
	"alice/migrations"
)

const usage = `Usage: alice <command>

Commands:
  serve        Start the Alice server (default)
  migrate      Apply database migrations and exit
  healthcheck  Exit 0 if the local server reports healthy (used by Docker)
  version      Print version information
  help         Show this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "configuration error:", err)
		return 1
	}
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))

	switch cmd {
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := serve(ctx, cfg, log); err != nil {
			log.Error("alice stopped with an error", "error", err.Error())
			return 1
		}
		return 0
	case "migrate":
		if err := migrate(cfg); err != nil {
			fmt.Fprintln(stderr, "migration failed:", err)
			return 1
		}
		fmt.Fprintln(stdout, "database is up to date")
		return 0
	case "healthcheck":
		return healthcheck(cfg)
	case "version":
		v := version.Get()
		fmt.Fprintf(stdout, "alice %s (commit %s, built %s)\n", v.Version, v.Commit, v.BuildTime)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

func migrate(cfg config.Config) error {
	if err := cfg.RequireDatabase(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	return db.Migrate(ctx, pool, migrations.FS)
}

func serve(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if err := cfg.RequireDatabase(); err != nil {
		return err
	}
	log.Info("starting alice", "version", version.Get().Version, "config", cfg)

	openCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	pool, err := db.Open(openCtx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool, migrations.FS); err != nil {
		return err
	}
	health, err := db.NewHealthChecker(pool, migrations.FS)
	if err != nil {
		return err
	}
	catalog, err := i18n.Load(locales.FS)
	if err != nil {
		return err
	}
	hosts := append([]string{"localhost", "127.0.0.1"}, cfg.TLSHosts...)
	if h, err := os.Hostname(); err == nil {
		hosts = append(hosts, h)
	}
	cert, err := tlscert.EnsureSelfSigned(cfg.KeysDir, hosts, clock.Real{}.Now())
	if err != nil {
		return err
	}

	deps := api.Deps{Health: health, Catalog: catalog, Version: version.Get(), UI: webui.UI(), Log: log}
	errLog := slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	public := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.NewHandler(deps),
		TLSConfig:         tlscert.ServerConfig(cert),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          errLog,
	}
	internal := &http.Server{
		Addr:              cfg.HealthAddr,
		Handler:           api.NewHealthHandler(deps),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ErrorLog:          errLog,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- ignoreClosed(public.ListenAndServeTLS("", "")) }()
	go func() { errCh <- ignoreClosed(internal.ListenAndServe()) }()
	log.Info("alice is ready", "https", cfg.ListenAddr, "health", cfg.HealthAddr)

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case runErr = <-errCh:
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()
	_ = public.Shutdown(shutdownCtx)
	_ = internal.Shutdown(shutdownCtx)
	return runErr
}

func healthcheck(cfg config.Config) int {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.HealthAddr+"/healthz", nil)
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: address comes from local configuration, not user input
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
```

- [ ] **Step 4: Run and pass**

Run: `go test -race ./cmd/alice/`
Expected: `ok`.

- [ ] **Step 5: Write the architecture test**

`internal/archtest/doc.go`:
```go
// Package archtest enforces the module import rules from the design spec (§5.4).
package archtest
```

`internal/archtest/arch_test.go`:
```go
package archtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Allowed internal imports per package. A key or entry ending in "/..." covers
// the package and everything below it; other entries are exact. A package may
// always import packages inside its own rule subtree.
var rules = map[string][]string{
	"alice/internal/platform/...":  {},
	"alice/internal/version/...":   {},
	"alice/internal/webui/...":     {},
	"alice/internal/archtest/...":  {},
	"alice/internal/i18n/...":      {platform},
	"alice/internal/rbac/...":      {platform},
	"alice/internal/secrets/...":   {platform},
	"alice/internal/audit/...":     {platform},
	"alice/internal/license/...":   {platform, "alice/internal/secrets/...", "alice/internal/audit/..."},
	"alice/internal/notify/...":    {platform, "alice/internal/i18n/...", "alice/internal/secrets/..."},
	"alice/internal/auth/...":      {platform, "alice/internal/rbac/...", "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/notify/..."},
	"alice/internal/providers":     {platform, "alice/internal/secrets/..."},
	"alice/internal/providers/...": {platform, "alice/internal/providers", "alice/internal/providers/linuxssh/..."},
	"alice/internal/inventory/...": {platform, "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/rbac/...", "alice/internal/providers"},
	"alice/internal/jobs/...":      {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/inventory/...", "alice/internal/providers", "alice/internal/notify/..."},
	"alice/internal/api/...": {platform, "alice/internal/i18n/...", "alice/internal/version/...", "alice/internal/rbac/...",
		"alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/notify/...",
		"alice/internal/auth/...", "alice/internal/inventory/...", "alice/internal/jobs/...", "alice/internal/providers"},
}

const platform = "alice/internal/platform/..."

func covers(pattern, pkg string) bool {
	if base, ok := strings.CutSuffix(pattern, "/..."); ok {
		return pkg == base || strings.HasPrefix(pkg, base+"/")
	}
	return pkg == pattern
}

// ruleFor returns the most specific rule key: exact keys win, then the longest subtree.
func ruleFor(pkg string) (string, bool) {
	if _, ok := rules[pkg]; ok {
		return pkg, true
	}
	best := ""
	for k := range rules {
		if covers(k, pkg) && len(k) > len(best) {
			best = k
		}
	}
	return best, best != ""
}

type goPackage struct {
	ImportPath string
	Imports    []string
}

func TestImportRules(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-json", "./internal/...")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, stderr.String())

	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p goPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else {
			require.NoError(t, err)
		}
		key, ok := ruleFor(p.ImportPath)
		if !ok {
			t.Errorf("%s has no import rule; add it to internal/archtest", p.ImportPath)
			continue
		}
		for _, imp := range p.Imports {
			if !strings.HasPrefix(imp, "alice/") || covers(key, imp) {
				continue
			}
			allowed := false
			for _, a := range rules[key] {
				if covers(a, imp) {
					allowed = true
					break
				}
			}
			if !allowed {
				t.Errorf("%s must not import %s (rule %q)", p.ImportPath, imp, key)
			}
		}
	}
}

func TestRuleMatching(t *testing.T) {
	k, _ := ruleFor("alice/internal/providers")
	require.Equal(t, "alice/internal/providers", k)
	k, _ = ruleFor("alice/internal/providers/nginx")
	require.Equal(t, "alice/internal/providers/...", k)
	k, _ = ruleFor("alice/internal/platform/db")
	require.Equal(t, "alice/internal/platform/...", k)
	_, ok := ruleFor("alice/internal/platformx")
	require.False(t, ok)
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "go.mod not found")
		dir = parent
	}
}
```

- [ ] **Step 6: Prove the architecture test catches a violation, then pass**

Temporarily add `import _ "alice/internal/i18n"` to `internal/platform/clock/clock.go`, run `go test ./internal/archtest/`, and confirm it FAILS with `alice/internal/platform/clock must not import alice/internal/i18n`. Remove the import. (If the import creates a cycle error instead, use `internal/version/version.go` importing `alice/internal/i18n` for the check.)

Run: `go test -race ./internal/archtest/ ./cmd/alice/`
Expected: `ok` for both.

- [ ] **Step 7: Build and smoke-run the binary locally**

```bash
make build && ./bin/alice version && ./bin/alice help
```
Expected: version line with the git commit; help lists five commands.

- [ ] **Step 8: Commit**

```bash
git add cmd/alice internal/archtest
git commit -m "feat: add alice CLI entry point and enforce module import rules

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: OpenAPI skeleton with route consistency test

**Files:**
- Create: `api/openapi.yaml`, `api/embed.go`, `internal/api/openapi_test.go`

**Interfaces:**
- Consumes: `api.NewHandler` (Task 8).
- Produces: `api/openapi.yaml` (OpenAPI 3.1) documenting `/livez`, `/healthz`, `/api/v1/version`, `/api/v1/i18n/locales` and the shared `Error` schema; `apispec.YAML []byte` (package `alice/api`, name `apispec`).

- [ ] **Step 1: Write the spec and embed it**

`api/openapi.yaml`:
```yaml
openapi: 3.1.0
info:
  title: Alice API
  version: 0.1.0
  description: Self-hosted SSH key and TLS certificate management. All timestamps are UTC RFC 3339.
servers:
  - url: /
paths:
  /livez:
    get:
      operationId: getLivez
      summary: Process liveness (no dependencies checked)
      x-permission: public
      responses:
        "200": { $ref: "#/components/responses/StatusOK" }
  /healthz:
    get:
      operationId: getHealthz
      summary: Readiness (database reachable and migrations current)
      x-permission: public
      responses:
        "200": { $ref: "#/components/responses/StatusOK" }
        "503": { $ref: "#/components/responses/Error" }
  /api/v1/version:
    get:
      operationId: getVersion
      summary: Build information
      x-permission: public
      responses:
        "200":
          description: Build information
          content:
            application/json:
              schema: { $ref: "#/components/schemas/VersionInfo" }
  /api/v1/i18n/locales:
    get:
      operationId: listLocales
      summary: Supported UI languages
      x-permission: public
      responses:
        "200":
          description: Supported locales
          content:
            application/json:
              schema: { $ref: "#/components/schemas/LocaleList" }
components:
  responses:
    StatusOK:
      description: OK
      content:
        application/json:
          schema:
            type: object
            required: [status]
            properties:
              status: { type: string, const: ok }
    Error:
      description: Error
      content:
        application/json:
          schema: { $ref: "#/components/schemas/Error" }
  schemas:
    VersionInfo:
      type: object
      required: [version, commit, build_time]
      properties:
        version: { type: string }
        commit: { type: string }
        build_time: { type: string }
    Locale:
      type: object
      required: [code, name, direction]
      properties:
        code: { type: string, examples: [tr] }
        name: { type: string, examples: [Türkçe] }
        direction: { type: string, enum: [ltr, rtl] }
    LocaleList:
      type: object
      required: [default, locales]
      properties:
        default: { type: string }
        locales:
          type: array
          items: { $ref: "#/components/schemas/Locale" }
    Error:
      type: object
      required: [error]
      properties:
        error:
          type: object
          required: [code, reason, message_key, message, request_id, retryable]
          properties:
            code: { type: string, pattern: "^ALC-[A-Z]{2,5}-[0-9]{4}$", examples: [ALC-SYS-0001] }
            reason: { type: string, examples: [system.not_found] }
            message_key: { type: string }
            message: { type: string }
            request_id: { type: string }
            retryable: { type: boolean }
```

`api/embed.go`:
```go
// Package apispec embeds the OpenAPI document, the source of truth for the HTTP API.
package apispec

import _ "embed"

// YAML is the OpenAPI 3.1 document.
//
//go:embed openapi.yaml
var YAML []byte
```

- [ ] **Step 2: Write the failing consistency test**

The test does not add a YAML dependency: it reads the path keys with a line scanner (paths are the two-space-indented keys under `paths:`), which is enough for this check.

`internal/api/openapi_test.go`:
```go
package api

import (
	"bufio"
	"bytes"
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	apispec "alice/api"
)

var pathKeyRE = regexp.MustCompile(`^  (/[^:]*):\s*$`)

func specPaths() []string {
	var paths []string
	inPaths := false
	sc := bufio.NewScanner(bytes.NewReader(apispec.YAML))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && len(line) > 0 && line[0] != ' ':
			inPaths = false
		case inPaths:
			if m := pathKeyRE.FindStringSubmatch(line); m != nil {
				paths = append(paths, m[1])
			}
		}
	}
	return paths
}

// Every documented GET path must be served (not fall through to the SPA or the API 404).
func TestEveryDocumentedPathIsServed(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	paths := specPaths()
	assert.ElementsMatch(t, []string{"/livez", "/healthz", "/api/v1/version", "/api/v1/i18n/locales"}, paths)
	for _, p := range paths {
		rec := do(h, http.MethodGet, p, nil)
		assert.Equal(t, http.StatusOK, rec.Code, p)
		assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"), p)
	}
}

// Every operation must declare x-permission; Phase 1 turns this into the RBAC route table.
func TestEveryOperationDeclaresPermission(t *testing.T) {
	ops := regexp.MustCompile(`(?m)^    (get|post|put|patch|delete):`).FindAllIndex(apispec.YAML, -1)
	perms := regexp.MustCompile(`(?m)^      x-permission: \S+`).FindAllIndex(apispec.YAML, -1)
	assert.Equal(t, len(ops), len(perms))
}
```

Only the test file imports `alice/api`; the architecture test checks non-test imports, so no rule change is needed.

- [ ] **Step 3: Run and pass**

Run: `go test -race ./internal/api/ ./internal/archtest/`
Expected: `ok`. (Writing `openapi_test.go` before `api/embed.go` fails with `package alice/api is not in std`; that is the red step.)

- [ ] **Step 4: Commit**

```bash
git add api internal/api/openapi_test.go
git commit -m "feat: add OpenAPI skeleton and route consistency tests

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Container image, Docker Compose and hardening check

**Files:**
- Create: `deploy/Dockerfile`, `deploy/docker-compose.yml`, `deploy/dev/init-env.sh`, `deploy/dev/check-hardening.sh`
- Modify: `Makefile` (add `image`, `up`, `down`, `logs`, `hardening-check`)

**Interfaces:**
- Consumes: `alice serve`, `alice healthcheck` (Task 10).
- Produces: `make up` → stack running with HTTPS on `https://localhost:${ALICE_HTTPS_PORT:-443}`; `deploy/.env` with `ALICE_DB_PASSWORD` and `ALICE_HTTPS_PORT`; `make hardening-check` exits 0 only if the container settings match the Global Constraints.

- [ ] **Step 1: Dockerfile**

`deploy/Dockerfile`:
```dockerfile
# syntax=docker/dockerfile:1

FROM node:24-alpine AS web
WORKDIR /src
COPY locales/ locales/
COPY web/package.json web/package-lock.json web/
RUN cd web && npm ci
COPY web/ web/
RUN mkdir -p internal/webui/dist && cd web && npm run build

FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/webui/dist/app internal/webui/dist/app
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X alice/internal/version.Version=${VERSION} -X alice/internal/version.Commit=${COMMIT} -X alice/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/alice ./cmd/alice \
 && mkdir -p /out/keys && chmod 0700 /out/keys

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/alice /usr/local/bin/alice
COPY --from=build --chown=10001:10001 /out/keys /var/lib/alice/keys
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/alice"]
CMD ["serve"]
```

- [ ] **Step 2: Compose file**

`deploy/docker-compose.yml`:
```yaml
name: alice

services:
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: alice
      POSTGRES_USER: alice
      POSTGRES_PASSWORD: ${ALICE_DB_PASSWORD:?run make up or deploy/dev/init-env.sh first}
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks: [backend]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U alice -d alice"]
      interval: 5s
      timeout: 3s
      retries: 20
    logging: &logging
      driver: json-file
      options: { max-size: "10m", max-file: "5" }

  alice:
    image: alice:${ALICE_VERSION:-dev}
    build:
      context: ..
      dockerfile: deploy/Dockerfile
      args:
        VERSION: ${ALICE_VERSION:-dev}
    restart: unless-stopped
    depends_on:
      postgres: { condition: service_healthy }
    environment:
      ALICE_DATABASE_URL: postgres://alice:${ALICE_DB_PASSWORD}@postgres:5432/alice?sslmode=disable
      ALICE_TLS_HOSTS: ${ALICE_TLS_HOSTS:-}
    ports:
      - "${ALICE_HTTPS_PORT:-443}:8443"
    volumes:
      - alice-keys:/var/lib/alice/keys
    networks: [frontend, backend]
    user: "10001:10001"
    read_only: true
    tmpfs: ["/tmp:size=16m"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 512m
    healthcheck:
      test: ["CMD", "/usr/local/bin/alice", "healthcheck"]
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 20s
    logging: *logging

networks:
  frontend: {}
  backend:
    internal: true

volumes:
  pgdata: {}
  alice-keys: {}
```

The database connection uses `sslmode=disable` because it never leaves the internal Docker network `backend`, which has no route to the host or outside. Record this in the getting-started doc (Task 15).

- [ ] **Step 3: Environment bootstrap and hardening check scripts**

`deploy/dev/init-env.sh`:
```bash
#!/usr/bin/env bash
# Creates deploy/.env with a random database password if it does not exist yet.
set -euo pipefail
env_file="$(dirname "$0")/../.env"
if [[ -f "$env_file" ]]; then
  echo "deploy/.env already exists; keeping it."
  exit 0
fi
umask 077
password="$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)"
cat > "$env_file" <<EOF
ALICE_DB_PASSWORD=${password}
ALICE_HTTPS_PORT=443
EOF
echo "Created deploy/.env (mode 600)."
```

`deploy/dev/check-hardening.sh`:
```bash
#!/usr/bin/env bash
# Verifies the running containers match the hardening rules in the design spec.
set -euo pipefail
cd "$(dirname "$0")/.."
compose=(docker compose -f docker-compose.yml --env-file .env)
alice="$("${compose[@]}" ps -q alice)"
pg="$("${compose[@]}" ps -q postgres)"
[[ -n "$alice" && -n "$pg" ]] || { echo "FAIL: stack is not running (run make up)"; exit 1; }

fail=0
check() {
  if [[ "$2" == "$3" ]]; then echo "ok:   $1"; else echo "FAIL: $1 (got '$2', want '$3')"; fail=1; fi
}
check "alice runs as UID 10001" "$(docker inspect -f '{{.Config.User}}' "$alice")" "10001:10001"
check "alice root filesystem is read-only" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$alice")" "true"
check "alice drops all capabilities" "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$alice")" '["ALL"]'
check "alice has no-new-privileges" "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$alice")" '["no-new-privileges:true"]'
check "alice is healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$alice")" "healthy"
check "postgres publishes no ports" "$(docker port "$pg" | wc -l | tr -d ' ')" "0"
check "backend network is internal" "$(docker network inspect -f '{{.Internal}}' alice_backend)" "true"
exit "$fail"
```

```bash
chmod +x deploy/dev/init-env.sh deploy/dev/check-hardening.sh
```

- [ ] **Step 4: Makefile targets**

Append:
```make
COMPOSE := docker compose -f deploy/docker-compose.yml --env-file deploy/.env

.PHONY: image
image: ## Build the alice container image
	docker build -f deploy/Dockerfile --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t alice:$(VERSION) -t alice:dev .

.PHONY: up
up: ## Build and start Alice with PostgreSQL (https://localhost)
	./deploy/dev/init-env.sh
	$(COMPOSE) up -d --build --wait

.PHONY: down
down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) down

.PHONY: logs
logs: ## Follow the alice container logs
	$(COMPOSE) logs -f alice

.PHONY: hardening-check
hardening-check: ## Verify container hardening of the running stack
	./deploy/dev/check-hardening.sh
```

- [ ] **Step 5: Bring the stack up and verify**

```bash
make up
curl -sk https://localhost/livez
curl -sk https://localhost/healthz
curl -sk -o /dev/null -w '%{http_code}\n' https://localhost/
curl -sk https://localhost/api/v1/nope
make hardening-check
docker compose -f deploy/docker-compose.yml --env-file deploy/.env logs alice | grep -c "$(grep ALICE_DB_PASSWORD deploy/.env | cut -d= -f2)" || true
```
Expected: `{"status":"ok"}` twice; `200`; a JSON error with `ALC-SYS-0001`; every hardening line `ok:`; the last command prints `0` (the password never appears in logs). If port 443 is taken on the development machine, set `ALICE_HTTPS_PORT=8443` in `deploy/.env` and use `https://localhost:8443`.

- [ ] **Step 6: Restart resilience check**

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env restart alice
sleep 15 && curl -sk https://localhost/healthz
```
Expected: `{"status":"ok"}`, and the certificate serial is unchanged: `echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -serial` gives the same value before and after the restart.

- [ ] **Step 7: Commit**

```bash
git add deploy Makefile
git commit -m "build: add container image, compose stack and hardening check

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: Playwright end-to-end smoke tests

**Files:**
- Create: `web/playwright.config.ts`, `web/e2e/smoke.spec.ts`
- Modify: `Makefile` (add `e2e`)

**Interfaces:**
- Consumes: running stack from `make up` (Task 12). Base URL from `ALICE_BASE_URL` (default `https://localhost`).

- [ ] **Step 1: Configuration**

`web/playwright.config.ts`:
```ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.ALICE_BASE_URL ?? 'https://localhost',
    ignoreHTTPSErrors: true, // the Phase 0 stack uses a temporary self-signed certificate
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
```

- [ ] **Step 2: Tests**

`web/e2e/smoke.spec.ts`:
```ts
import { test, expect, type Page } from '@playwright/test';

function collectProblems(page: Page): string[] {
  const problems: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error') problems.push(m.text());
  });
  page.on('pageerror', (e) => problems.push(e.message));
  return problems;
}

test('home page loads in English, switches to Turkish, and violates no CSP rule', async ({ page }) => {
  const problems = collectProblems(page);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Welcome to Alice' })).toBeVisible();
  await expect(page.getByTestId('server-status')).toContainText('Server version');

  await page.getByText('Türkçe').click();
  await expect(page.getByRole('heading', { name: "Alice'e hoş geldiniz" })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'tr');
  await expect(page.getByTestId('server-status')).toContainText('Sunucu sürümü');

  await page.reload();
  await expect(page.getByRole('heading', { name: "Alice'e hoş geldiniz" })).toBeVisible();

  expect(problems.filter((p) => /Content Security Policy/i.test(p))).toEqual([]);
  expect(problems).toEqual([]);
});

test.describe('Turkish browser', () => {
  test.use({ locale: 'tr-TR' });
  test('first visit is in Turkish', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: "Alice'e hoş geldiniz" })).toBeVisible();
  });
});

test('deep links load the app and unknown API paths return JSON errors', async ({ page, request }) => {
  await page.goto('/users/5');
  await expect(page.getByRole('heading', { name: 'Welcome to Alice' })).toBeVisible();

  const res = await request.get('/api/v1/nope', { headers: { 'Accept-Language': 'tr' } });
  expect(res.status()).toBe(404);
  const body = await res.json();
  expect(body.error.code).toBe('ALC-SYS-0001');
  expect(body.error.message).toContain('bulunamadı');
});

test('security headers are present', async ({ request }) => {
  const res = await request.get('/');
  const h = res.headers();
  expect(h['content-security-policy']).toMatch(/style-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
  expect(h['strict-transport-security']).toBe('max-age=31536000; includeSubDomains');
  expect(h['x-frame-options']).toBe('DENY');
});
```

- [ ] **Step 3: Makefile target**

Append:
```make
.PHONY: e2e
e2e: ## Run Playwright tests against the running stack (make up first)
	cd web && npx playwright install chromium && npx playwright test
```

- [ ] **Step 4: Run**

Run: `make up && make e2e`
Expected: 5 tests pass. If the CSP test fails with "Refused to apply inline style", the nonce is not reaching Mantine: confirm `index.html` in `internal/webui/dist/app` still contains `__CSP_NONCE__`, that the served page contains a real nonce, and that `MantineProvider` receives `getStyleNonce`.

- [ ] **Step 5: Commit**

```bash
git add web/playwright.config.ts web/e2e Makefile
git commit -m "test: add Playwright smoke tests for EN/TR, CSP and routing

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 14: Linting, security scanning and CI pipeline

**Files:**
- Create: `.golangci.yml`, `.gitleaks.toml`, `.github/workflows/ci.yml`
- Modify: `Makefile` (add `tools`, `lint`, `vuln`, `secrets-scan`, `image-scan`, `ci`)

**Interfaces:**
- Produces: `make ci` runs, in order: `lint`, `test`, `test-integration`, `i18n-check`, `web-lint`, `web-test`, `vuln`, `secrets-scan`, `up`, `hardening-check`, `e2e`, `image-scan`. GitHub Actions runs the same stages on every push and pull request.

- [ ] **Step 1: Linter configuration**

`.golangci.yml`:
```yaml
version: "2"
linters:
  default: standard
  enable:
    - gosec
    - forbidigo
    - errorlint
    - bodyclose
    - misspell
    - noctx
  settings:
    forbidigo:
      forbid:
        - pattern: ^strings\.(ToUpper|ToLower|Title)$
          msg: "Turkish dotted/dotless i: use strings.EqualFold for identifiers or golang.org/x/text/cases for user-visible text."
        - pattern: ^fmt\.Print(f|ln)?$
          msg: "Use the structured logger (log/slog) or write to an explicit io.Writer."
  exclusions:
    presets: [std-error-handling, common-false-positives]
    rules:
      - path: _test\.go
        linters: [gosec, noctx]
formatters:
  enable:
    - gofmt
    - goimports
  settings:
    goimports:
      local-prefixes: [alice]
```

`.gitleaks.toml`:
```toml
[extend]
useDefault = true

[allowlist]
description = "Test fixtures use obviously fake secrets"
regexes = ['''s3cret-pw''']
paths = ['''web/package-lock\.json''']
```

- [ ] **Step 2: Pin tool versions and add Makefile targets**

Find the latest releases and write the exact versions into the Makefile variables below:
```bash
curl -s https://api.github.com/repos/golangci/golangci-lint/releases/latest | jq -r .tag_name
curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name
curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .tag_name
curl -s 'https://proxy.golang.org/golang.org/x/vuln/@latest' | jq -r .Version
```

Append to `Makefile` (replace each `vX.Y.Z` with the tag printed above; trivy and gitleaks image tags drop the leading `v`):
```make
GOLANGCI_LINT_VERSION ?= vX.Y.Z
GOVULNCHECK_VERSION   ?= vX.Y.Z
GITLEAKS_VERSION      ?= X.Y.Z
TRIVY_VERSION         ?= X.Y.Z

.PHONY: tools
tools: ## Install pinned Go developer tools into $(HOME)/go/bin
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: lint
lint: ## Run golangci-lint (gosec, forbidigo, ...)
	golangci-lint run ./...

.PHONY: vuln
vuln: ## Check Go dependencies and code for known vulnerabilities
	govulncheck ./...
	cd web && npm audit --omit=dev --audit-level=high

.PHONY: secrets-scan
secrets-scan: ## Scan git history for committed secrets
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$(CURDIR):/repo" ghcr.io/gitleaks/gitleaks:v$(GITLEAKS_VERSION) git /repo --config /repo/.gitleaks.toml --redact

.PHONY: image-scan
image-scan: image ## Scan the container image for HIGH/CRITICAL vulnerabilities
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:$(TRIVY_VERSION) image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed alice:dev

.PHONY: ci
ci: lint test test-integration i18n-check web-lint web-test vuln secrets-scan up hardening-check e2e image-scan ## Run the full CI pipeline locally
```

- [ ] **Step 3: Run the linters and fix findings**

Run: `make tools && make lint`
Expected: no issues. Typical fixes: add `//nolint:gosec // <reason>` only where the reason is real (the healthcheck URL already has one); convert `fmt.Fprint*` to explicit writers (they are allowed; only `fmt.Print*` to stdout is forbidden). Do not disable a linter to get green.

Then: `make vuln && make secrets-scan && make image-scan`
Expected: all exit 0. If Trivy reports a HIGH in the distroless base, rebuild with `docker pull gcr.io/distroless/static-debian12` first; if it persists and is unfixed upstream, it is already ignored by `--ignore-unfixed`; a fixed one must be resolved by updating the base image.

- [ ] **Step 4: GitHub Actions workflow**

`.github/workflows/ci.yml`:
```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version-file: go.mod }
      - run: make tools
      - run: make lint
      - run: make test
      - run: make test-integration
      - run: make i18n-check
      - run: govulncheck ./...

  web:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 24, cache: npm, cache-dependency-path: web/package-lock.json }
      - run: make web-install
      - run: make web-lint
      - run: make web-test
      - run: make web
      - run: cd web && npm audit --omit=dev --audit-level=high

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: make secrets-scan

  stack:
    runs-on: ubuntu-latest
    needs: [go, web]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 24, cache: npm, cache-dependency-path: web/package-lock.json }
      - run: make web-install
      - run: ./deploy/dev/init-env.sh && sed -i 's/^ALICE_HTTPS_PORT=.*/ALICE_HTTPS_PORT=8443/' deploy/.env
      - run: make up
      - run: make hardening-check
      - run: cd web && npx playwright install --with-deps chromium && ALICE_BASE_URL=https://localhost:8443 npx playwright test
      - run: make image-scan
      - if: failure()
        run: docker compose -f deploy/docker-compose.yml --env-file deploy/.env logs
      - if: failure()
        uses: actions/upload-artifact@v4
        with: { name: playwright-report, path: web/playwright-report }
```

- [ ] **Step 5: Run the whole pipeline locally**

Run: `make ci`
Expected: every stage exits 0.

- [ ] **Step 6: Commit**

```bash
git add .golangci.yml .gitleaks.toml .github Makefile
git commit -m "ci: add linting, vulnerability and secret scanning, and CI workflow

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 15: Developer guide and spec alignment

**Files:**
- Create: `docs/dev/getting-started.md`
- Modify: `docs/superpowers/specs/alice-v1/04-security.md` (SEC-033, SEC-041), `docs/superpowers/specs/alice-v1/02-architecture.md` (§5.2 dependency budget, §9.2 cookie name), `docs/superpowers/specs/alice-v1/00-decisions.md` (append R34)

- [ ] **Step 1: Write the developer guide**

`docs/dev/getting-started.md`:
````markdown
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
`ALICE_HTTPS_PORT=8443` in `deploy/.env` and run `make up` again.

## Everyday commands

| Command | What it does |
|---|---|
| `make test` | Go unit tests with the race detector |
| `make test-integration` | Go integration tests (starts PostgreSQL in Docker) |
| `make web-test` | Web unit tests (Vitest) |
| `make e2e` | Browser tests against the running stack |
| `make lint` / `make web-lint` | Linters |
| `make i18n-check` | English and Turkish catalogs have the same keys and placeholders |
| `make ci` | The full pipeline, as run in GitHub Actions |
| `make logs` / `make down` | Follow logs / stop the stack (data is kept) |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ALICE_DATABASE_URL` | none (required) | PostgreSQL connection URL. Contains the password; never logged. |
| `ALICE_LISTEN_ADDR` | `:8443` | Public HTTPS listener |
| `ALICE_HEALTH_ADDR` | `127.0.0.1:8081` | Container-local plain HTTP listener for `/livez` and `/healthz` |
| `ALICE_KEYS_DIR` | `/var/lib/alice/keys` | Directory for the HTTPS certificate and, from Phase 1, the master key |
| `ALICE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `ALICE_TLS_HOSTS` | empty | Extra host names or IPs for the temporary certificate, comma-separated |

## Notes

- The database connection uses `sslmode=disable` because PostgreSQL is only reachable on the
  internal Docker network `backend`, which has no route outside the host.
- Alice creates a temporary self-signed certificate (valid 90 days, renewed automatically 7 days
  before expiry). A certificate you place in the keys directory yourself is never modified.
- Translations: shared strings live in `locales/common/{en,tr}.json`, UI-only strings in
  `web/src/locales/{en,tr}.json`. Add every key to both languages; `make i18n-check` enforces it.
````

- [ ] **Step 2: Align the spec with implementation decisions**

In `docs/superpowers/specs/alice-v1/04-security.md`, replace the SEC-033 bullet with:
```markdown
- **SEC-033** CSP for the web UI: `default-src 'none'; script-src 'self'; style-src 'self' 'nonce-<per-request>'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. The server injects a fresh 128-bit nonce into `index.html` for each request; Mantine applies it to the one `<style>` element it creates. No `unsafe-inline`/`unsafe-eval`; the build emits no inline scripts. API responses use `default-src 'none'; frame-ancestors 'none'`. [T]
```

Replace the SEC-041 bullet with:
```markdown
- **SEC-041** AAD binds each ciphertext to its location. Payload layer: `table || '/' || row_id || '/' || column`. DEK-wrap layer: the same string plus `'/' || key_version`. Master-key rotation re-wraps only DEKs (recomputing the DEK-wrap AAD with the new version) and never touches payload ciphertext; moving ciphertext between rows or columns fails to decrypt. [T]
```

In `docs/superpowers/specs/alice-v1/02-architecture.md` §5.2, change the dependency-budget sentence to start: `Runtime Go dependency budget: pgx, goose, golang.org/x/text, google/uuid, x/crypto, x/oauth2, go-oidc, Azure SDK modules, oapi-codegen runtime, pquerna/otp, go-pkcs12.` In §7.2 change the AAD sentence to reference SEC-041. In §9.2 change the cookie name `alice_session` to `__Host-alice_session`.

Append to `docs/superpowers/specs/alice-v1/00-decisions.md`:
```markdown
- R34 (Phase 0) CSP uses a per-request style nonce for Mantine's style element (SEC-033 amended). AAD scheme fixed in SEC-041. Health probes are also served on a container-local plain-HTTP listener `127.0.0.1:8081` for the Docker healthcheck. TLS curve preferences include X25519MLKEM768 ahead of X25519 and P-256. `google/uuid` and `golang.org/x/text` join the dependency budget. Session cookie name is `__Host-alice_session`. Web build output goes to `internal/webui/dist/app` so no Go package lives inside `web/`.
```

- [ ] **Step 3: Final verification**

Run: `make ci`
Expected: all stages pass. Then execute the owner verification from spec §26.2 on a clean checkout: `git clone . /tmp/alice-verify && cd /tmp/alice-verify && make web-install && make up`, open https://localhost, switch to Türkçe and back, then `make down`.

- [ ] **Step 4: Commit**

```bash
git add docs
git commit -m "docs: add developer guide and align spec with Phase 0 decisions

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Phase 0 Done When

- `make ci` passes locally (and in GitHub Actions once a remote exists).
- `make up` on a clean checkout serves https://localhost with the Alice page in English, the language switch shows Turkish, and the page shows the server version.
- `make hardening-check` passes; the DB password never appears in logs.
- The known limitations below are recorded for the owner report.

## Known Limitations (carried to later phases)

- PostgreSQL runs with a writable root filesystem and default capabilities (only `no-new-privileges`); separate owner/app DB roles arrive with the audit log in Phase 1.
- `/api/v1/version` and `/api/v1/i18n/locales` are unauthenticated; Phase 1 puts every route behind the RBAC route table.
- The `/test/*` endpoints and demo clock do not exist yet, so the "absent from release build" check starts in Phase 2.
- No GitHub remote exists yet; CI runs locally through `make ci` until the owner creates a repository.
