## 5. Architecture

### 5.1 Component diagram

```
                     Browser (React SPA, EN/TR)
                              | HTTPS :443 (TLS terminated by alice)
 +----------------------------v-----------------------------------------+
 | container: alice  (single Go binary, non-root, read-only FS)         |
 |                                                                      |
 |  api  (net/http, middleware: TLS, rate limit, session/token, CSRF,   |
 |        authz, request-id, i18n error mapping) + embedded SPA (embed) |
 |    |                                                                 |
 |    +--> auth --> rbac      +--> inventory ----+                      |
 |    +--> license            +--> jobs (queue, scheduler, workers)     |
 |    +--> audit              |        |                                |
 |    +--> notify (SMTP,      |        v                                |
 |         syslog)            |    providers (registry)                 |
 |                            |     +-- linuxssh (connector)            |
 |            secrets <-------+     +-- nginx  (uses linuxssh)          |
 |     (envelope enc.,              +-- azurekv                         |
 |      master.key file)                |               |               |
 +------|-------------------------------|---------------|---------------+
        | pgx (internal docker network) | SSH :22       | HTTPS (Azure)
 +------v-----------+            Linux/Nginx hosts   Azure Key Vault
 | container:       |
 | postgres         |   volumes: /opt/alice/keys (master.key, ssh key, tls)
 | (no published    |            /opt/alice/backups   pgdata
 |  port)           |
 +------------------+
```

Single process; the same binary provides `alice serve` (API + workers + scheduler, default), `alice migrate`, `alice healthcheck`, and the operator subcommands exposed through the `alicectl` wrapper (`docker compose exec alice alice "$@"`): `backup`, `backup list`, `backup verify [--deep]`, `restore`, `selfcheck`, `audit verify`, `setup-token --reset`, `support-bundle` (secrets redacted), plus the host-root, audited `alice admin reset-mfa`. Restore is CLI-only. Health probes: `GET /livez` (process is up, no dependencies) and `GET /healthz` (database reachable, migrations current). The container runs as UID 10001. There is no separate worker container in v1; workers are goroutines in the same process, bounded by config.

### 5.2 Technology choices

| Concern | Choice | Rationale |
|---|---|---|
| Language | Go 1.23+ (toolchain pinned in `go.mod`) | Static binary, stdlib `crypto/ssh`-adjacent ecosystem, `crypto/x509`, `embed`, small CVE surface. |
| HTTP router | stdlib `net/http` `ServeMux` (method + path patterns, Go 1.22+) | Zero dependency; patterns like `GET /api/v1/targets/{id}` suffice. Middleware is plain `func(http.Handler) http.Handler`. |
| DB driver | `github.com/jackc/pgx/v5` (+ `pgxpool`) | De facto standard, native Postgres types, `LISTEN/NOTIFY`, batch support. |
| Queries | **sqlc** (generated, type-safe) over hand-written SQL files in `internal/<module>/queries/*.sql` | SQL stays reviewable (audit-friendly), compile-time checked against migrations, generated code has no runtime dependency beyond pgx. Chosen over an ORM (magic, extra deps) and over fully hand-written scanning (boilerplate, runtime typo risk). Generated code is committed; CI fails on drift. |
| Migrations | **goose** v3, SQL files embedded with `embed`, run by `alice migrate` and at startup under a Postgres advisory lock | Simple sequential SQL, embeddable, supports Go migrations for data backfills. Forward-only in production; the update script restores the pre-update backup on failure instead of running down-migrations. |
| SSH | `golang.org/x/crypto/ssh` | Standard; host-key callback and custom auth fully controllable. |
| Azure | `azidentity`, `azcertificates`, `azkeys`, `azsecrets` (official SDK) | Official, supports SP secret/cert and Managed Identity. |
| Passwords / crypto | `golang.org/x/crypto/argon2`; stdlib AES-GCM, Ed25519, X25519 (`crypto/ecdh`), HKDF | No third-party crypto. Backup files use age-style hybrid encryption (see 7.2). |
| PFX / PKCS#12 | `software.sslmate.com/src/go-pkcs12` | Parsing uploaded PFX bundles and exportable KV certificates. |
| TOTP | `github.com/pquerna/otp` | Small, maintained RFC 6238/4226 implementation (decided). |
| OIDC (Phase 7) | `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2` | Mature, PKCE, discovery, JWKS handling. Delivered in Phase 7; Phase 1 is local auth + TOTP only. |
| Config/logging | stdlib `log/slog` (JSON), env + YAML-free flags; settings in DB | No config framework. |
| OpenAPI | Hand-maintained `api/openapi.yaml` (source of truth) + `oapi-codegen` for Go server types and request validation; `openapi-typescript` for the SPA client types | Spec-first keeps the contract reviewable; both generators are build-time only. |
| Frontend | React 18 + TypeScript + Vite, `react-router`, **TanStack Query**, `react-i18next` + `i18next`, **Mantine** (built-in accessibility, single UI dependency) | Small, well-known; TanStack Query handles caching/polling of job status. |
| Tests | stdlib `testing`, `testcontainers-go` (Postgres, nginx+sshd), Playwright (E2E) | Matches decisions.md test strategy. |

Runtime Go dependency budget: pgx, goose, `golang.org/x/text`, `google/uuid`, x/crypto, x/oauth2, go-oidc, Azure SDK modules, oapi-codegen runtime, `pquerna/otp`, `go-pkcs12`. Anything else needs a written justification in the PR. `go mod vendor` is used for release builds so air-gapped/reproducible builds work.

Phase 1 defers sqlc, oapi-codegen and openapi-typescript (R35): queries are hand-written, parameterized pgx calls inside each module, and the hand-maintained `api/openapi.yaml` is kept consistent with the route table by tests (paths, methods and `x-permission`).

### 5.3 Repository layout

```
alice/
  cmd/
    alice/            main: serve, migrate, healthcheck, backup [list|verify], restore, selfcheck, audit verify, setup-token, support-bundle, admin reset-mfa, version
    alice-helper/     static Go binary installed root-owned on targets (nginx/linux sudoers profiles); see 6.6
    licensectl/       vendor-only CLI: keygen, issue, inspect, verify (never shipped to customers)
  internal/
    api/              HTTP handlers, middleware, error mapping, OpenAPI glue
    webui/            embedded SPA build output (dist/app), so no Go package lives inside web/
    archtest/         import-boundary tests (custom test instead of depguard)
    auth/             local login, Argon2id, TOTP, recovery codes, sessions, OIDC (Phase 7), API tokens, rate limiter
    rbac/             roles, permissions, policy checks (pure functions)
    audit/            append-only log writer, hash chain, verifier, syslog forwarder
    secrets/          envelope encryption, master key loading, key rotation, backup crypto
    inventory/        targets, certificates, ssh keys, locations, bindings (business logic + queries)
    jobs/             queue, scheduler, worker pool, job handlers registry, recovery
    providers/        Provider interface, registry, shared types
      linuxssh/       SSH connector, host key pinning, alice-helper command surface, authorized_keys ops
      nginx/          nginx provider (composes linuxssh)
      azurekv/        Azure Key Vault provider
      fake/           in-memory provider for tests
    license/          verify, state machine (evaluation/active/grace/lock), clock guard, limits
    notify/           SMTP mailer, templates (i18n keys), syslog/webhook sinks
    i18n/             server-side key catalog + Accept-Language negotiation, email template rendering
    platform/         cross-cutting leaf helpers: clock (fakeable), ids, config, db pool, logging
    version/
  api/openapi.yaml
  locales/common/     shared catalog (en.json, tr.json) consumed by web and backend; CI parity check
  migrations/         goose SQL files (embedded via migrations/embed.go)
  web/                Vite React app (Mantine); web/src/locales/{en,tr}.json; build output goes to `internal/webui/dist/app` and is embedded into alice by `internal/webui`
  deploy/             docker-compose.yml, Dockerfile, install.sh, alice-update.sh, alicectl, systemd unit, air-gap bundler
  docs/               spec, admin guide, runbooks, SECURITY-REPORT.md, threat model
  test/               integration (testcontainers), e2e (Playwright), security (authz matrix, leak tests)
  tools/              lint config, sqlc.yaml, oapi-codegen config
```

### 5.4 Module responsibilities and import rules

| Module | Responsibility | May import (internal) |
|---|---|---|
| `platform` | clock, config, db, logging, id generation | none |
| `i18n` | message keys, locale negotiation | `platform` |
| `rbac` | permission model | `platform` |
| `secrets` | encrypt/decrypt, master key, DEK wrapping, backup crypto | `platform` |
| `audit` | append events, verify chain, forward | `platform` |
| `license` | license verification and state, limit checks | `platform`, `secrets` (HMAC key for high-water mark), `audit` |
| `notify` | send mail/syslog | `platform`, `i18n`, `secrets` (SMTP password) |
| `auth` | identities, sessions, MFA, tokens | `platform`, `rbac`, `secrets`, `audit`, `notify` |
| `providers` (+ sub-packages) | talk to external systems; no DB access | `platform`, `secrets` (via a `CredentialResolver` passed in, not imported by sub-packages) |
| `inventory` | domain data, orchestrates providers via interface | `platform`, `secrets`, `audit`, `license`, `rbac`, `providers` (interface only) |
| `jobs` | queue, scheduler, handlers | `platform`, `audit`, `license`, `inventory`, `providers`, `notify` |
| `authz` (R49) | the value types of scoped access and the checks other modules run in their own transactions (the service a new row goes to, whether a service trusts another) | `platform` |
| `authz/services` (R49) | services, environments, policy history, trusts, assignment, the owning and visible-from resolvers | `platform`, `authz`, `audit` |
| `api` | HTTP only, thin | everything except `providers/<impl>` |
| `cmd/*` | wiring (composition root); the only place that imports `providers/nginx` etc. to register them | all |

Rules, enforced in CI by `depguard`/`go-arch-lint`:
1. Dependencies point downward only; no cycles. `platform` is a leaf.
2. `providers/*` never import `inventory`, `jobs`, `auth`, or the DB. They are pure adapters: input config in, results out.
3. `api` contains no business logic and no SQL; it calls module services and maps errors.
4. Only `secrets` decrypts secrets; other modules get plaintext via short-lived `secrets.Open(ctx, ref)` calls and must zero buffers after use. No module logs values of type `secrets.Plaintext` (type implements `fmt.Formatter` returning `[redacted]`).
5. Every state-changing service method takes an `audit.Actor` and writes an audit event in the same transaction where possible.
6. `license` checks are invoked from `inventory` (target add) and `jobs` (scheduled-job gate), never duplicated in `api`.

## 6. Provider Plugin Interface

Providers are compile-time Go packages. No `plugin` package, no runtime loading.

### 6.1 Core types

```go
package providers

type Kind string // "linuxssh", "nginx", "azurekv"

type Capability string
const (
    CapTestConnection     Capability = "test_connection"
    CapDiscoverCerts      Capability = "discover_certificates"
    CapDiscoverSSHKeys    Capability = "discover_ssh_keys"
    CapDiscoverKVKeys     Capability = "discover_kv_keys"
    CapDiscoverKVSecrets  Capability = "discover_kv_secret_metadata"
    CapDeployCertificate  Capability = "deploy_certificate"
    CapImportCertificate  Capability = "import_certificate"     // upload cert into a vault
    CapAuthorizedKeys     Capability = "authorized_keys"         // list/add/remove
    CapVerifyDeployment   Capability = "verify_deployment"
)

type Provider interface {
    Kind() Kind
    DisplayNameKey() string                 // i18n key, e.g. "provider.nginx.name"
    Capabilities() CapabilitySet            // static
    ConfigSchema() ConfigSchema             // describes target config (non-secret) fields
    CredentialSchema() CredentialSchema     // describes secret fields (never echoed back)
    ValidateConfig(cfg TargetConfig) []FieldError // syntax/semantic validation, no network
    Open(ctx context.Context, t TargetRef, cred CredentialSource, env Env) (Session, error)
}

type CapabilitySet map[Capability]struct{}
func (c CapabilitySet) Has(x Capability) bool

// Env carries injected dependencies so providers stay pure.
type Env struct {
    Clock     platform.Clock
    HostKeys  HostKeyStore     // read/write pinned host keys (implemented by inventory)
    Log       *slog.Logger     // pre-wrapped with redaction
    Now       func() time.Time
}

// Session is one connection scope. Methods return ErrUnsupported when the capability is absent.
type Session interface {
    Close() error
    TestConnection(ctx context.Context) (ConnectionReport, error)

    Discover(ctx context.Context, req DiscoverRequest) (DiscoveryResult, error)

    DeployCertificate(ctx context.Context, op DeployRequest, log StepLogger) (DeployOutcome, error)
    RollbackDeployment(ctx context.Context, op RollbackRequest, log StepLogger) error
    VerifyDeployment(ctx context.Context, req VerifyRequest) (VerifyResult, error)

    ListAuthorizedKeys(ctx context.Context) ([]AuthorizedKeyEntry, error)
    AddAuthorizedKey(ctx context.Context, req AuthKeyChange, log StepLogger) (AuthKeyResult, error)
    RemoveAuthorizedKey(ctx context.Context, req AuthKeyChange, log StepLogger) (AuthKeyResult, error)

    ImportCertificate(ctx context.Context, req ImportCertRequest, log StepLogger) (ImportResult, error)
}
```

`Session` is a wide interface for simplicity; every provider embeds `providers.UnsupportedSession` which returns `ErrUnsupported` for all methods, so a provider implements only what it advertises. The job layer checks `Capabilities()` first and the API hides unavailable actions using the same set (exposed on the target as `capabilities`).

`TargetConfig` is `map[string]any` validated by the provider; `ConfigSchema` is a small declarative struct (field name, type `string|int|bool|enum|path|host`, required, default, `LabelKey`, `HelpKey`, validation regex/range) used by both the server validator and the frontend form generator, so field labels are translatable and forms stay data-driven. Secrets are separate (`CredentialSchema`) and stored only via the `credentials` table.

### 6.2 Discovery result types

```go
type DiscoveryResult struct {
    Certificates []DiscoveredCertificate
    SSHKeys      []DiscoveredSSHKey
    KVKeys       []DiscoveredKVKey
    KVSecrets    []DiscoveredKVSecret   // metadata only
    HostKeys     []DiscoveredHostKey    // server host keys (linuxssh)
    Warnings     []Warning              // stable code + i18n key + params, e.g. AuthorizedKeysCommand detected
    Partial      bool                   // true if some sources failed; never treated as "deleted"
}

type DiscoveredCertificate struct {
    Location   CertLocation      // {Kind: "file"|"kv", Path or KVName+Version, ServerNames []string, ConfigRef string}
    PEMChain   []byte            // public material only
    Fingerprint string           // SHA-256 of leaf DER, hex
    Subject, Issuer string; SANs []string
    NotBefore, NotAfter time.Time
    KeyAlgorithm string; KeyBits int
    HasPrivateKeyAtLocation bool // known but private key file is NOT read
}
type DiscoveredSSHKey struct {
    OSUser, FilePath string; LineNo int
    PublicKey string; Fingerprint string   // SHA256:...
    KeyType string; Bits int; Comment string; Options string
}
type DiscoveredKVKey struct {
    Name, Version string; KeyType string; Bits int; Curve string
    Enabled bool; NotBefore, Expires *time.Time; Managed bool
}
type DiscoveredKVSecret struct {
    Name string; Enabled bool; Expires *time.Time; ContentType string; BackingCertificate string
}
```

Discovery is read-only and reconciled by `inventory` (upsert by fingerprint/location; items not seen in a complete, non-`Partial` scan are marked `missing`, never deleted).

### 6.3 Deploy and rollback contract

```go
type DeployRequest struct {
    OperationID uuid.UUID          // idempotency key = deployment id
    Attempt     int
    Target      CertLocation       // destination (paths / KV name)
    Certificate PEMBundle          // leaf + chain
    PrivateKey  SecretBytes        // zeroed by caller after return; nil for KV import of public-only
    Options     DeployOptions      // reload command id, verify SNI/port, file modes
}
type DeployOutcome struct {
    Changed  bool                  // false when already in desired state (idempotent no-op)
    Backup   BackupRef             // opaque provider-defined handle persisted in deployments.rollback_info
    Verified bool
}
type RollbackRequest struct { OperationID uuid.UUID; Backup BackupRef }

type StepLogger interface {
    Step(name string, status StepStatus, detail StepDetail) // status: started|ok|failed|skipped; detail is redacted, i18n key + params
}
```

Contract every implementation must honor:
1. **Idempotent**: calling `DeployCertificate` twice with the same `OperationID` and content yields the same end state; if desired fingerprint is already live and verified, return `Changed=false`.
2. **Step-logged**: each externally visible action emits `Step` before and after (`backup`, `write_files`, `config_test`, `reload`, `verify_handshake`, `restore`). The job layer persists each step to `deployment_steps` immediately (one row insert/update per step) so a crash leaves an exact trace.
3. **Rollback-capable**: `BackupRef` is serializable JSON persisted *before* the first mutating step. `RollbackDeployment` is itself idempotent and safe to call when nothing changed. On any failure inside `DeployCertificate`, the provider first attempts its own inline rollback; the job layer calls `RollbackDeployment` again if the result is uncertain (crash, timeout).
4. **Context-aware**: honors cancellation; after cancellation of a mutating phase it still performs rollback using a fresh short-deadline context supplied by `Env`.
5. **No secrets in errors or step details**; providers return `*providers.Error{Code, MessageKey, Params, Retryable, Cause}`.
6. **Never widens scope**: a provider only touches paths/resources named in the request.

Nginx deploy steps (implemented once in `nginx`, every remote action is an `alice-helper` subcommand): `backup` (helper `backup`: root-only copy under `/var/lib/alice-helper/backups/<opid>/`, sha256 recorded) -> `write_files` (helper `install-cert`: temp file + `fsync` + `rename`, key mode 0600, owner/SELinux context preserved) -> `config_test` (`nginx-test`) -> `reload` (`nginx-reload`) -> `verify_handshake` (TLS connect to host:port with SNI from `server_name`, compare presented leaf fingerprint) -> on any failure `restore` (helper `restore`) -> `config_test` -> `reload`. Discovery warns on TLS in `stream{}` blocks, which v1 does not support.

### 6.4 Registry

```go
type Registry struct{ /* map[Kind]Provider, immutable after Freeze() */ }
func (r *Registry) Register(p Provider)           // panics on duplicate Kind or schema errors
func (r *Registry) Freeze()
func (r *Registry) Get(k Kind) (Provider, bool)
func (r *Registry) List() []Descriptor            // for API /providers (kind, capabilities, schemas)
```

Registration happens explicitly in `cmd/alice/providers.go` (`reg.Register(linuxssh.New(...))`, no `init()` magic) so the shipped set is visible in one file and unit-testable. A startup self-check validates each provider's schemas and that every capability has the corresponding method overridden (via a conformance test suite `providers/providertest`).

Target `type` in the DB maps to provider kind: `linux` -> `linuxssh`, `nginx` -> `nginx`, `azure_key_vault` -> `azurekv`.

### 6.5 Adding a new provider (checklist)

1. Create `internal/providers/<name>/`; implement `Provider` and a `Session` embedding `providers.UnsupportedSession`.
2. Declare `Capabilities()`, `ConfigSchema()`, `CredentialSchema()`; write `ValidateConfig`.
3. Return only `*providers.Error` with stable `ALC-<AREA>-<NNNN>` codes (9.3); add all message keys to `en.json` and `tr.json` (CI key-parity check).
4. Emit step logs for every mutating operation; persist a `BackupRef` before mutating.
5. Run the shared `providertest` conformance suite (idempotency, rollback after injected failure, context cancellation, no-secret-in-output scan).
6. Add integration tests against a real or containerized counterpart (or recorded mock for cloud APIs).
7. Add target type to the DB `targets.type` check constraint (migration) and to the license counting set (explicit decision, default: counted).
8. Register in `cmd/alice/providers.go`; update OpenAPI enum for target type; add docs page and least-privilege table.
9. Security review: outbound endpoints, credential handling, command surface (helper subcommands / allowlist entries), threat-model delta.

### 6.6 The `linuxssh` connector

`linuxssh` exposes an internal (non-`Provider`) type used by both `linuxssh` and `nginx`:

```go
type Conn struct{ /* *ssh.Client, helper command set, target id */ }
func Dial(ctx, TargetRef, CredentialSource, Env) (*Conn, error)
func (c *Conn) Run(ctx context.Context, cmd HelperCommand) (Result, error)
func (c *Conn) ReadCert(ctx, path string) ([]byte, error)                        // helper `read-cert`: CERTIFICATE blocks only
func (c *Conn) InstallFile(ctx, path string, kind FileKind, data []byte, op uuid.UUID) error // helper `install-cert`, atomic
```

**Composition.** The `nginx` provider holds a `*linuxssh.Connector` constructor and opens a `Conn` for every session. `nginx.Session` implements certificate discovery/deploy on top of `Conn`; it does not open its own sockets. `nginx` also delegates `TestConnection`, host-key handling, and (optionally) authorized-keys operations to the connector, so an Nginx target can also show its SSH keys with no duplicated code. Both provider kinds share the same target-level SSH settings (host, port, username, credential).

**Host-key pinning.** `ssh.ClientConfig.HostKeyCallback` is a custom function backed by `HostKeyStore` (table `host_keys`):
- No pinned key for the target: the connection is aborted with `ssh.host_key_unconfirmed`; the fingerprint(s) are returned to the UI. Only an explicit user confirmation (audited) pins them (TOFU with human confirmation). Background jobs can never pin.
- Pinned key matches: proceed. Algorithm restricted to pinned key types (`HostKeyAlgorithms` set from the pinned entries).
- Mismatch: connection aborted, target flagged `host_key_changed`, all operations on that target are blocked (job handlers check the flag before dialing), an alert is raised and audited. Unblocking requires an Admin to review and explicitly re-pin, with MFA step-up.

**Remote command surface (R13, R21).** Alice never sends free-form shell strings. The only remote command surface is the root-owned `alice-helper`, a static Go binary built from this repository and installed on each target by the admin through the setup snippet (Alice cannot update it; a protocol version mismatch shows "helper outdated"). `HelperCommand` is a value constructed only through package constructors, each mapping to `sudo -n /usr/local/libexec/alice-helper <subcommand> <validated args>`; the exact subcommand set, argument validation and exit codes are defined in the integrations section (12.3). The subcommands used are `version` (unprivileged), `nginx-dump`, `nginx-test`, `nginx-reload`, `sshd-dump`, `hostkeys`, `stat`, `read-cert`, `install-cert`, `backup`, `restore`, `cleanup`, `authkeys-list`, `authkeys-read`, `authkeys-write`. Two sudoers profiles exist: `nginx` (all subcommands) and `linux` (SSH-key subcommands, `sshd-dump`, `hostkeys` only), so a generic Linux target never gains nginx capabilities. `cat /etc/os-release` is the only non-helper command.

Arguments are passed with strict single-quote escaping from a validated vocabulary (`[A-Za-z0-9._/@:+-]`); anything else is rejected before execution. Output size and runtime are capped (default 8 MiB, 30 s; `nginx-dump` up to 20 MB). The host side is a second, independent layer: sudoers lists only the helper subcommands and the helper treats all arguments as hostile (path validation, allowed roots, no private key output), so a bug in Alice does not grant more than the helper allows. The connector refuses to remove its own public key (fingerprint compare with the platform key) in `RemoveAuthorizedKey`, independent of the caller.

## 7. Data Model

Conventions: PostgreSQL 16; primary keys `uuid` (UUIDv7 generated by the app for index locality) unless noted; all timestamps `timestamptz` in UTC; `created_at`, `updated_at` on mutable tables; no soft delete except where stated. Secret columns are `bytea` and only ever written through `secrets`. Enumerations use `text` + `CHECK` (easier migrations than PG enums).

### 7.1 Identity and access

**users**: `id`, `username citext UNIQUE`, `email citext`, `display_name`, `auth_source text CHECK IN ('local','oidc')`, `oidc_issuer`, `oidc_subject` (UNIQUE `(oidc_issuer, oidc_subject)` where not null; both added with OIDC in Phase 7, R35), `password_hash text` (Argon2id encoded string, null for OIDC), `role text CHECK IN ('admin','operator','auditor')`, `role_source text CHECK IN ('manual','oidc_mapping')`, `locale text default 'en'`, `timezone text NULL`, `is_break_glass bool`, `disabled_at`, `failed_logins int`, `locked_until`, `password_changed_at`, `last_login_at`. Constraint: local users must have `password_hash`; the last enabled local Admin cannot be disabled, deleted or demoted (break-glass), enforced in the service layer (Phase 1: the change locks the rows of all enabled local Admins with `SELECT … FOR UPDATE` under READ COMMITTED before counting them, so two concurrent demotions cannot both succeed; R35). OIDC users get MFA from the IdP (documented customer requirement); the setting `sso.allow_admin_role` defaults to OFF, so SSO-mapped roles are capped at Operator/Auditor until an Admin enables it.

**user_mfa**: `user_id PK/FK`, `totp_secret_ct bytea`, `totp_nonce bytea`, `totp_wrapped_dek bytea`, `totp_key_version int`, `enrolled_at`, `last_used_step bigint` (replay prevention). **recovery_codes**: `id`, `user_id FK`, `code_hash` (Argon2id), `used_at`; index `(user_id) WHERE used_at IS NULL`.

**sessions**: `id_hash bytea PK` (SHA-256 of the cookie value), `user_id FK`, `kind` (`pending` after the password step, `full` after MFA; R35), `created_at`, `last_seen_at`, `expires_at` (absolute 12h), `idle_expires_at` (30 min sliding), `ip inet`, `user_agent`, `mfa_verified_at`, `stepup_until`, `revoked_at`. Index `(user_id)`, `(expires_at)` for cleanup. The CSRF token is HMAC-SHA256 of the session token under the HKDF key `alice/csrf/v1`, so it is not stored.

**api_tokens**: `id`, `user_id FK`, `name`, `token_hash bytea UNIQUE` (SHA-256 of high-entropy token; prefix `alice_` + 32 random bytes), `token_prefix` (first 12 chars for display, R35), `scopes text[]` (exactly one of `read`, `operate` in v1; R35), `expires_at NOT NULL`, `last_used_at`, `revoked_at`. Token role is the intersection of scopes and the owner's current role.

**oidc_providers**: `id`, `name`, `issuer_url`, `client_id`, `client_secret_ct/nonce/wrapped_dek/key_version`, `scopes`, `enabled` (Phase 7). **oidc_group_mappings**: `id`, `provider_id FK`, `group_claim_value`, `role`, `priority`; UNIQUE `(provider_id, group_claim_value)`.

**login_attempts**: `id`, `ip inet`, `username_norm`, `at`, `success bool`; indexes `(ip, at)`, `(username_norm, at)`; pruned by a job (used for progressive delay/lockout). Deferred (R35): Phase 1 keeps the lockout state in `users.failed_logins` and `users.locked_until`.

**setup_sessions** (R35): `id_hash bytea PK` (SHA-256 of the `__Host-alice_setup` cookie value), `created_at`, `idle_expires_at` (60 min sliding), and the pending administrator (`pending_username`, `pending_display_name`, `pending_email`, `pending_password_hash`, TOTP secret in envelope columns) until the first TOTP code is verified and the administrator is created. The setup-code hash, default language, backup key and completion time live in `settings` (`setup.token_hash`, `locale.default`, `backup.key`, `setup.completed_at`).

**Services and scoped access** (R49, migration `00026`; design `docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md` §4): **environments** (`key` unique and fixed, `name`, `sort`, `version`; seeded production, staging, test, development); **services** (`name citext` unique, `description`, `environment_id`, `is_default` with exactly one Default service, `policy_version`, `version`); **service_policies** (append-only history, version 1 `{"schema":1}`); **service_trusts** (directed `source_service_id` → `target_service_id`: the target accepts the source's certificates and keys); and, unused until their phase, **directory_groups**, **user_directory_groups**, **role_bindings** (a role on a service or an environment, for a user or a directory group), **service_owners**. Owning service: `service_id NOT NULL` on `targets`, `certificates`, `csr_requests`, `ssh_keys`, `acme_certificates`, `discovery_scopes` (column default `default_service_id()`, the Default service; the application names it on every insert); `jobs.service_id` and `alerts.service_id` (nullable, `ON DELETE SET NULL`: platform work has none); `certificate_incidents.service_ids`, `rotation_policies.approved_service_ids`, `api_tokens.service_ids`; `certificate_locations.binding_attention_code` (a Key Vault binding's website held for `service.untrusted`). `users.role` is nullable from 00026 and NULL means no global role from Phase 2 (R53, migration `00028`: the break-glass account keeps one; `role_bindings` with a `user_id` are read with every session and token and indexed by service and environment); `auth_source` admits `automation`.

**Deployment targets groundwork** (R59, migration `00031`; roadmap `docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md` §5): `targets.type` adds `windows`, `f5_bigip`, `kubernetes`; `credentials.purpose` adds `f5_device` (kind `f5_password`) and `kubernetes_cluster` (`k8s_token`, `k8s_client_cert`), both with `target_id` set like `azure_vault`; `certificate_locations.kind` adds `win_sslbinding`, `f5_clientssl`, `k8s_tls_secret` with `locator jsonb` (the identity, unique per `(target_id, kind, locator)`, NULL for `server_file`), `details jsonb` (`{}` for a file) and `verify_address` (NULL for a file); a location of another kind has its locator's canonical text in `cert_path` and empty key columns; `deployments.location_kind`; `deployment_backups` (`deployment_id` PK, `location_id`, `leaf_sha256`, `spki_sha256`, envelope columns, `created_at`; insert and delete only, never while the deployment is unfinished); `host_keys.key_type` `tls-spki` for an API target's server identity.

**Windows servers** (R60, no migration; design `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`, rulings `docs/superpowers/rulings/windows-iis.md`): provider `windows` (`internal/providers/windows`, registered for `targets.type` `windows`; capabilities `test_connection`, `discover_certificates` in W1). Packages: `winproto` (protocol 1 shared with the helper, standard library and `helperproto` only), `winhelper` (the helper's platform-neutral decisions behind a `Host` interface: command split, elevation gate, budget, dump assembly and bounds, appcmd XML, probe), `wintest` (the emulated host: an SSH server on `linuxsshtest` with Windows OpenSSH's first-command behaviour, modelled stores, http.sys table and IIS sites answered by `winhelper`, and real TLS listeners per binding), and `cmd/alice-winhelper` (the `GOOS=windows` helper: the real `Host` over httpapi.dll, crypt32, ncrypt, token APIs and appcmd). The provider dials through `linuxssh`'s pool and host-key pinning but takes one fresh connection per helper call (`Pool.AcquireFresh`) and sends lines built by `linuxssh.ForcedCommand`. A scan: `win-facts` (OS, IIS, elevation, stores; into `providers.OSRelease` and `WindowsFacts`), then `iis-dump` (http.sys SSL bindings, each bound certificate once with chain and key facts, IIS sites from `appcmd list site /config /xml`, warning facts); `convert.go` matches IIS site bindings to http.sys entries and returns one `CertLocation` of kind `win_sslbinding` per entry (and per IIS https binding without one, `cert_missing`), with the locator, the IIS sites as servers, the supported rule and problems, and the certificate by its DER hash. Inventory stores the certificate half only (`HasCertificateLocations`; no SSH half, `IsServer` is false), links the certificate by fingerprint and marks nothing missing on a cut scan (`locations_dropped`). Windows-only files are `_windows.go`; their tests run on the real-Windows workflow (`.github/workflows/windows.yml`).

### 7.2 Secrets and credentials

Envelope columns (shared shape, used wherever a secret is stored): `ciphertext bytea`, `nonce bytea` (12 bytes), `wrapped_dek bytea` (DEK sealed with the master key: AES-256-GCM, its own nonce prepended), `key_version int` (identifies which master key wrapped the DEK). AAD binds each ciphertext to its location (SEC-041): the payload layer uses `table || '/' || row id || '/' || column` and the DEK-wrap layer appends `'/' || key_version`, preventing ciphertext swapping between rows or columns.

**credentials**: `id`, `target_id FK NULL` (unique per target purpose), `kind text CHECK IN ('ssh_private_key','ssh_password_unused','azure_sp_secret','azure_sp_cert','azure_managed_identity')`, `public_info jsonb` (non-secret: e.g. client_id, tenant, SSH key fingerprint), `ciphertext`, `nonce`, `wrapped_dek`, `key_version`, `created_at`, `rotated_at`. The application never reads back plaintext to the API. (Phase 3, R37: a `purpose` column; the platform SSH key is the row with `purpose = 'platform_ssh'`; `target_id` arrives with target-bound credentials in Phase 5; append-only for `alice_app`.)

**managed_private_keys**: `id`, `owner_type text` (`certificate`|`ssh_key`|`csr`), `owner_id`, envelope columns, `created_by`, `download_count`. Stores private keys generated or uploaded into Alice (TLS keys, generated SSH keys, CSR keys).

**master_key_versions**: `version int PK`, `key_check bytea` (GCM-sealed known constant under that key for startup verification), `created_at`, `retired_at`. The key material lives only in files: `master.key` (current) and `master.<version>.key` for retired versions kept until rewrapping completes. The directory defaults to `/opt/alice/keys` and its path is configurable (e.g. a separate mount); the docs require full-disk encryption (boot passphrase, TPM and PKCS#11 are v2; the residual risk is stated as High in `SECURITY-REPORT.md`).

**Backup encryption (R4).** The wizard generates an X25519 backup key pair. The public key is stored on the host (`/opt/alice/keys/backup.pub`; Phase 1 stores the public key and the wrapped private key in the `settings` row `backup.key` and writes no host file, and the Phase 8 backup job reads `backup.key` or creates the file from it; R35); the private key is stored only wrapped by the recovery passphrase (Argon2id + AES-256-GCM) and is embedded in every backup file. Unattended daily backups encrypt to the public key (age-style hybrid, chunked AEAD stream), so the host never holds the passphrase or a passphrase-derived key. Restore needs the file and the passphrase only. The backup contains the DB dump and the master key material.

**Master-key rotation** (admin CLI/API action `alice keys rotate-master`, dry-run available, requires MFA step-up and a fresh backup):
1. Generate new 32-byte key, write `master.<n+1>.key` (0400), insert `master_key_versions(n+1)`.
2. Rewrap job iterates every envelope row in batches: decrypt `wrapped_dek` with version `k`, re-wrap with `n+1`, update `wrapped_dek` and `key_version` in one statement guarded by `WHERE key_version = k`. Ciphertext and nonce are untouched (only DEKs move), so the job is cheap, resumable, and idempotent.
3. When no row has `key_version < n+1`, mark old versions `retired_at`, and delete their files after the next successful backup. The backup stores the current and any not-yet-retired keys.
4. The high-water-mark MAC key and hash-chain-independent data derive from the master key via HKDF with fixed labels and are re-derived per version.
A DEK-only design also lets a compromised-data-key incident be limited to one row.

### 7.3 Inventory

**targets**: `id`, `name` (UNIQUE), `type text CHECK IN ('nginx','linux','azure_key_vault')`, `config jsonb` (validated by provider; non-secret), `credential_id FK`, `status text CHECK IN ('pending_host_key','ok','unreachable','host_key_changed','auth_failed','disabled')`, `last_success_at`, `last_error_code`, `discovery_interval_seconds`, `capabilities text[]` (cached), `counts_toward_license bool DEFAULT true`, `created_by`, `deleted_at`. **License counting query**: `SELECT count(*) FROM targets WHERE deleted_at IS NULL AND counts_toward_license`; the limit check runs in the same transaction as the insert with `SELECT ... FOR UPDATE` on the `license` singleton row to prevent race over-provisioning. Partial UNIQUE index on `(type, lower(config->>'host'), (config->>'port'))` WHERE `deleted_at IS NULL` prevents duplicates. Deleting a target is soft delete (frees a license slot) and never touches the remote system.

**host_keys**: `id`, `target_id FK`, `key_type`, `public_key bytea`, `fingerprint_sha256 text`, `confirmed_by FK users`, `confirmed_at`, `status CHECK IN ('pinned','superseded','rejected')`; UNIQUE `(target_id, fingerprint_sha256)`; partial UNIQUE `(target_id, key_type) WHERE status='pinned'`. (Phase 3, R37: status `observed` for a presented key that is not trusted yet; one pinned key per target; target status `checking`.)

**certificates**: `id`, `fingerprint_sha256 text NOT NULL UNIQUE` (leaf DER hash; the same certificate discovered on many servers is one row), `subject_cn`, `subject`, `issuer`, `serial`, `sans text[]` (GIN index), `not_before`, `not_after` (index for expiry queries), `key_algorithm`, `key_bits`, `pem_chain text` (public), `source text CHECK IN ('discovered','uploaded','csr','azure_kv')`, `private_key_id FK managed_private_keys NULL`, `status CHECK IN ('active','superseded','revoked_external')`, `superseded_by FK certificates`, `kv_current_version`, `kv_updated_at`, `thumbprint` (Azure KV certificates only), `first_seen_at`, `last_seen_at`. Constraint: private key never stored for `discovered` unless later uploaded by an admin.

**certificate_locations**: `id`, `certificate_id FK`, `target_id FK`, `kind CHECK IN ('nginx_file','kv_certificate')`, `cert_path`, `key_path`, `chain_path`, `kv_name`, `kv_version`, `server_names text[]`, `listen text`, `binding_id FK bindings NULL` (a location belongs to at most one binding), `seen_at`, `missing_since`. UNIQUE `(target_id, kind, coalesce(cert_path,''), coalesce(kv_name,''))`. Index `(certificate_id)`, `(target_id)`, `(binding_id)`.

**bindings**: `id`, `kv_target_id FK`, `kv_cert_name`, `auto_deploy bool DEFAULT false` (Admin-only toggle, audited), `include_root bool DEFAULT false`, `last_deployed_version`, `last_result`, `created_by`, `created_at`. **certificate_versions**: `id`, `certificate_id FK`, `kv_version_id`, `thumbprint`, `not_before`, `not_after`, `enabled`, `policy jsonb`, `detected_at`; UNIQUE `(certificate_id, kv_version_id)`. Azure change detection compares the tuple (current version id, X.509 thumbprint), with `Updated` only as a pre-filter; the `certificates` row therefore carries `kv_current_version`, `kv_updated_at` and `thumbprint` for `source='azure_kv'`.

**csr_requests**: `id`, `private_key_id FK`, `subject`, `sans text[]`, `csr_pem`, `status CHECK IN ('pending','completed','cancelled')`, `certificate_id FK NULL`.

**ssh_keys**: `id`, `fingerprint_sha256 text UNIQUE`, `key_type`, `bits`, `public_key text`, `comment`, `managed bool DEFAULT false` (true only if generated by Alice), `private_key_id FK managed_private_keys NULL`, `label`, `created_at`, `retired_at`. Public keys are not secrets; the same key on many hosts is one row.

**ssh_key_locations**: `id`, `ssh_key_id FK`, `target_id FK`, `os_user`, `file_path`, `options text`, `first_seen_at`, `last_seen_at`, `missing_since`, `removed_by_alice_at`, `is_alice_connection_key bool` (protected: service layer and DB trigger forbid removal operations referencing it), `rotation_policy_id FK NULL`. UNIQUE `(ssh_key_id, target_id, os_user, file_path)`.

**rotation_policies**: `id`, `name`, `enabled bool DEFAULT false`, `schedule_cron`, `overlap_days int DEFAULT 7 CHECK (overlap_days >= 0)`, `key_type`, `key_bits`, `scope jsonb` (target ids / os users; managed keys only), `notify_before_hours int`, `created_by`. Only Admin may write.

### 7.4 Operations

**deployments**: `id`, `certificate_id FK`, `location_id FK`, `target_id FK`, `trigger CHECK IN ('manual','kv_renewal','retry')`, `requested_by FK NULL`, `status CHECK IN ('pending','running','verifying','succeeded','failed','rolled_back','rollback_failed','needs_attention')`, `rollback_info jsonb` (provider `BackupRef`, written before the first mutation), `previous_fingerprint`, `error_code`, `job_id FK`, `started_at`, `finished_at`. Partial UNIQUE `(location_id) WHERE status IN ('pending','running','verifying')` = at most one active deployment per location. (R48, migration `00023`: `rollback_leaf_sha256`, `rollback_spki_sha256`, the certificate the replaced file held, recorded with the send values; phase `restore_forbidden`: a rollback the guard refused.)

**deployment_steps**: `id`, `deployment_id FK ON DELETE CASCADE`, `n`, `name`, `status CHECK IN ('started','ok','failed','skipped')`, `at`, `duration_ms`, `detail_key`, `params jsonb` (redacted); UNIQUE `(deployment_id, n)`.

**rotations**: `id`, `policy_id FK`, `ssh_key_location_id FK` (old), `new_ssh_key_id FK`, `status CHECK IN ('planned','dry_run_notified','adding_new','verifying_new','overlap','removing_old','completed','aborted','needs_attention')`, `planned_for`, `overlap_until`, `rollback_info jsonb`, `old_key_removal_allowed bool DEFAULT false` (set true only after the new key is verified on every affected location), `started_at`, `finished_at`, `job_id`. State machine ensures `removing_old` cannot be reached unless `old_key_removal_allowed`; DB `CHECK (status <> 'removing_old' OR old_key_removal_allowed)`. **rotation_steps**: `id`, `rotation_id FK ON DELETE CASCADE`, `n`, `name`, `status`, `at`, `location_ref`, `backup_op_id`, `detail_key`, `params jsonb`.

**target_locks**: `target_id PK/FK`, `job_id FK`, `operation text`, `locked_by`, `heartbeat_at`, `lease_until`. One row = the one active operation on that target; stale leases (3 missed 15 s heartbeats) are reclaimed by crash recovery (8.8).

**jobs**: see 8.1. **job_attempts**: `id`, `job_id FK`, `attempt`, `started_at`, `finished_at`, `error_code`, `worker_id`.

**alerts**: `id`, `kind` (`cert_expiring`, `host_key_changed`, `kv_key_expiring`, `license_expiring`, `clock_anomaly`, `discovery_failed`, `backup_stale` (no successful backup for 48 h), ...), `subject_type`, `subject_id`, `severity`, `first_raised_at`, `resolved_at`, `last_notified_at`, `params jsonb`. UNIQUE `(kind, subject_type, subject_id) WHERE resolved_at IS NULL` for dedupe.

**certificate_incidents** (R46, migration `00021`): `id`, `certificate_id FK`, `public_key_sha256`, `acme_certificate_id FK NULL`, `state CHECK IN ('awaiting_replacement','ordering','deploying','revoking','needs_attention','completed','closed')`, `revoke_mode CHECK IN ('after_verified','now')`, `revocation CHECK IN ('pending','revoked','failed','not_possible')`, `order_id FK NULL`, `replacement_certificate_id FK NULL`, `attention_code`, `revoke_attempts`, `next_attempt_at`, `revoked_at`, `started_by`, `closed_by`, `created_at`, `updated_at`, `finished_at`; one open incident per certificate; frozen once finished (Z1023). **certificate_incident_locations**: `incident_id FK`, `location_id FK`, `status CHECK IN ('pending','deploying','verified','unverified','failed','skipped')`, `deployment_id FK NULL`, `error_code`, `attempts`, `updated_at`. **certificates** gains `revoked_at`, `revocation_reason`, `revoked_by`, `compromised_at`, `compromised_by` (final once set, Z1022); **discovery_certificates** gains `public_key_sha256`.

### 7.5 Audit

**audit_log** (append-only): `seq bigint PK` (assigned by `audit.Append` as max+1 under the advisory lock, so the sequence is gapless and any gap is tampering; R35), `at timestamptz`, `actor_type CHECK IN ('user','api_token','system','oidc')`, `actor_id uuid NULL`, `actor_name text` (denormalized), `ip inet`, `action text` (e.g. `target.create`), `object_type`, `object_id`, `result CHECK IN ('success','failure','denied')`, `details jsonb` (redacted; secrets impossible by construction: details are built from allowlisted fields; Phase 1 enforces this with a case-insensitive key-segment denylist, R35), `request_id`, `prev_hash bytea`, `hash bytea`.
- `hash = SHA-256(prev_hash || canonical_json(seq, at, actor, ip, action, object, result, details, request_id))`. First row `prev_hash = 32 zero bytes`.
- Written by a single `audit.Append` function that takes `pg_advisory_xact_lock(<audit key>)`, reads the last hash, computes, inserts (serializes chain writes; throughput is ample at this scale).
- **Append-only enforcement**: the app connects as role `alice_app` with `INSERT, SELECT` only on `audit_log` (no UPDATE/DELETE/TRUNCATE); table owned by migration role `alice_owner` (Phase 1 development stack: the PostgreSQL superuser `alice`, until Phase 8; R35); additionally `BEFORE UPDATE OR DELETE OR TRUNCATE` triggers raise an exception, so it holds even if privileges are misconfigured. There is no audit pruning in v1 (deferred to v2).
- **Verification**: `alicectl audit verify` and a daily job recompute the chain from the last verified position (stored in `settings`) and alert on mismatch. External anchors: the wizard strongly recommends syslog/SIEM forwarding, each daily head hash is sent to syslog/SIEM, and the dashboard shows the daily audit head hash so it can be recorded offline; deletion of the tail is then detectable.

### 7.6 License, settings, misc

**license** (singleton, `id smallint PK CHECK (id=1)`): `installation_id text` (format `ALICE-XXXX-XXXX-XXXX-XXXX` with check digit; generated at install, preserved by restore), `installed_at` (installation timestamp stored with the installation ID; the 30-day evaluation runs from it and a restore does not reset it), `current_license_id`, `replaces` (set by a correction license; may carry an earlier `issued_at`), `issued_at`, `raw_file bytea` (the signed JSON as uploaded), `customer`, `max_targets`, `features text[]`, `valid_from`, `valid_until`, `state CHECK IN ('evaluation','active','grace','locked')` (cached; recomputed by the license module from instant-based UTC rules, not authoritative over the file: ACTIVE while now < valid_until, GRACE while valid_until <= now < valid_until + 168 h, LOCKED after; evaluation ends directly in LOCKED with no grace; expiry warnings at 60/30/14/7/1 days are computed from `valid_until`, and 7/3/1 days before evaluation end), `time_high_water_ct/nonce/mac` (encrypted+MAC'd high-water mark), `clock_jump_pending_since` (a suspicious forward jump, i.e. wall clock advanced more than 48 h beyond monotonic uptime since the last hourly tick, only triggers GRACE/LOCK transitions after 24 h of monotonic uptime at the new time), `updated_at`. **license_history**: `id`, `at`, `event CHECK IN ('installed','renewed','state_change','clock_anomaly','rejected')`, `license_id`, `from_state`, `to_state`, `details jsonb`. (Phase 2, R36: the singleton **license** row keeps only `installation_id`, `installed_at`, the cached `state` (which also has `evaluation_expired`), the held `clock_jump` and `updated_at`; the uploaded files live verbatim in **license_files** (`id`, `seq`, `sha256`, `raw_file`, `uploaded_at`, `uploaded_by`; append-only for the application) and are re-verified at every evaluation, parsed values are never stored; the time high-water mark is kept in `settings` (`time.hwm`) and a state file per §16.5, not in license columns; **license_history** has the extra event `notice` and a `notice` column, unique per `(license_id, notice)`, for exactly-once warnings, grace days, lock, clock and tamper notices; **notifications_outbox** queues emails.)

**settings**: `key text PK`, `value jsonb`, `secret bool`, `updated_by`, `updated_at`; secret values use envelope columns in a sibling table `setting_secrets(key FK, ciphertext, nonce, wrapped_dek, key_version)` (e.g. SMTP password). Keys: `smtp.*`, `syslog.*`, `discovery.default_interval`, `kv.poll_interval`, `session.*`, `locale.default`, `alerts.thresholds_days` (default 60,30,14,7,1; Admin-configurable), `sso.allow_admin_role` (default false). Auditors can read license status but not settings; Operators can read target metadata but never credentials.

**notifications_outbox**: `id`, `kind`, `to_address`, `template_key`, `params jsonb`, `locale`, `status`, `attempts`, `next_attempt_at`, `sent_at`; drained by the job system so mail failures never block operations.

**schema_migrations**: managed by goose (`goose_db_version`).

Index/constraint summary: unique cert fingerprint, unique SSH key fingerprint, one active deployment per location, one pinned host key per target and type, one open alert per subject, audit append-only triggers, CHECK forbidding early old-key removal, and FK `ON DELETE RESTRICT` everywhere except child step/attempt tables.

## 8. Jobs and Background Processing

### 8.1 Queue

**jobs**: `id`, `type text`, `payload jsonb` (ids and options only, never secrets), `target_id NULL`, `dedupe_key text NULL`, `status CHECK IN ('queued','running','succeeded','failed','cancelled','dead')`, `priority smallint DEFAULT 5`, `run_at timestamptz`, `attempts int`, `max_attempts int`, `locked_by text`, `locked_until timestamptz` (lease), `heartbeat_at`, `last_error_code`, `created_by NULL`, `kind CHECK IN ('scheduled','user','system')`. Indexes: `(status, run_at, priority) WHERE status='queued'`; UNIQUE `(dedupe_key) WHERE status IN ('queued','running')`.

Claim query (executed by each worker loop):

```sql
UPDATE jobs SET status='running', locked_by=$1, locked_until=now()+interval '45 seconds',
       attempts=attempts+1, heartbeat_at=now()
WHERE id = (
  SELECT id FROM jobs
  WHERE status='queued' AND run_at <= now()
    AND (target_id IS NULL OR NOT EXISTS (
          SELECT 1 FROM jobs r WHERE r.target_id = jobs.target_id AND r.status='running'))
  ORDER BY priority, run_at
  FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING *;
```

The handler additionally takes the target's `target_locks` row (lease-based, 7.4) before its first external action. Workers wake on `LISTEN alice_jobs` (sent by enqueue) with a 5 s poll fallback. (Phase 3, R37: times are bind parameters from the injected clock, the `target_locks` row is inserted in the claim transaction, workers poll every second, and `jobs` has `class`, `payload_mac`, `result`, `created_by_role`, `confirmed_by`, `confirmed_at`, `started_at`, `finished_at` and the status `blocked_license`.)

### 8.2 Job types

| Type | Kind | Purpose |
|---|---|---|
| `target.test_connection` | user | check credentials, host key, capabilities |
| `target.discover` | scheduled/user | run provider `Discover`, reconcile inventory |
| `kv.poll` | scheduled (15 min default) | list KV certificate versions, detect renewals, enqueue deploys for bound locations with `auto_deploy` |
| `certificate.deploy` | user/system | one deployment (per location) |
| `certificate.import_to_kv` | user | import uploaded cert to a vault |
| `sshkey.add` / `sshkey.remove` | user | authorized_keys change |
| `rotation.plan` | scheduled | evaluate policies, create dry-run + notification |
| `rotation.advance` | scheduled/system | move a rotation through add -> verify -> overlap -> remove |
| `alerts.evaluate` | scheduled (hourly) | expiry thresholds, emit alerts + emails (runs in lock mode too, email only) |
| `notify.send` | system | drain outbox with backoff |
| `audit.verify` | scheduled (daily) | hash chain verification |
| `license.evaluate` | scheduled (hourly) | update state, high-water mark, expiry warnings |
| `backup.auto` | scheduled (daily) | backup encrypted to the backup public key, keep 14; raises `backup_stale` after 48 h without success |
| `maintenance.cleanup` | scheduled | prune sessions, login_attempts, old jobs (90 days) |
| `secrets.rewrap` | user | master-key rotation rewrap |
| `incident.advance` | scheduled (30 s) | advance every open key-compromise incident: follow its order, request and follow the replacement's deployments, revoke at the CA (R46; ClassAlways, the gate is asked before each change) |

### 8.3 Scheduler

A single scheduler goroutine per process holds a Postgres advisory lock (`pg_try_advisory_lock`) so only one instance schedules even if two processes run briefly (e.g. during update). It evaluates a static cron table plus per-target discovery intervals every 30 s and inserts jobs with a `dedupe_key` such as `target.discover:<target_id>:<slot>`, so missed or duplicate ticks are harmless. After downtime it enqueues at most one catch-up job per schedule (no backlog storm).

### 8.4 Retries and backoff

Handlers return a classified error: `Retryable`, `Permanent`, or `NeedsAttention`. Retryable failures re-queue with exponential backoff and jitter: `min(30s * 2^(attempt-1), 30m) +- 20%`; default `max_attempts`: discovery 5, deploy 3, notify 10, poll 3. Exhausted jobs move to `dead` and raise an alert. `Permanent` (auth failed, host key changed) never retries and marks the target status. Deployments and rotations retry only until their first mutating step; after a mutation the handler either completes or rolls back and reports `failed`/`rolled_back` (no blind retry of a partially applied state).

**ACME renewal failures (R45, owner decision 2026-10-20).** An ACME order is not retried by the runner (one attempt per job); the renewal planner decides the next one. Its failures are classified `transient` (outage) or `permanent` (needs a person) from the RFC 8555 problem type, the HTTP status and the cause (`acme.FailureClass`); five permanent failures stop automatic renewal, transient ones never do while the certificate is valid (five of any class after it expired), the wait after a transient failure shrinks as the end nears (24 h, 12 h within 7 days, 6 h within 3, 2 h in the last day), and a certificate stopped with a transient last failure is ordered again by itself until it expires. Rulings: `docs/superpowers/rulings/acme-renewal-recovery.md`. The CA's `Retry-After` (R47) is not part of that backoff: it is stored as `acme_certificates.ca_not_before` (migration `00022`, bounded at seven days when recorded, cleared only by a successful order), and no order of the certificate starts before it (`renew.Decide` takes the latest of the backoff, the CA's time and the spacing; `startOrderTx` refuses a person's order with `ALC-ACM-0005`); a wait past the middle of the renewal window e-mails the Administrators at once (`acme.renewal_ca_wait`). Rulings: `docs/superpowers/rulings/acme-ca-retry-after.md`.

**ACME renewal information (R50, owner decision 2026-10-20).** The planner renews at a time chosen once, uniformly at random, inside the CA's suggested window (RFC 9773) and never later than the local rule (`renew.ChooseARIRenewAt`); it is stored as `acme_certificates.ari_renew_at` (migration `00024`) in the certificate's transaction, kept while it lies inside the window, chosen again when the window moves or shrinks past it, and cleared with the window on a new issuance or when the CA drops `renewalInfo`. Without a window the local rule decides as before. An issue order of a certificate with a current certificate that shares a name sends RFC 9773 `replaces` (the predecessor's ARI identifier; the one newOrder is signed by Alice, `internal/acme/jws.go`) when the CA advertises `renewalInfo` and the predecessor is this account's (`acme_orders.account_url`); the order records `replaces` and `replaces_outcome`. `alreadyReplaced` takes over Alice's own earlier order replacing it (pending or ready) or orders once more without the field; a CA that refuses the field gets the order once more without it; `acme.already_replaced` (`ALC-ACM-0041`) is transient. Rulings: `docs/superpowers/rulings/acme-ari.md`.

### 8.5 Concurrency limits

- Global workers: default 8 (config `jobs.workers`).
- Per target: 1 running job at a time (enforced in the claim query above) and per-target SSH connection cap 2.
- Per provider kind: `azurekv` max 4 concurrent calls per vault, with SDK retry respecting `Retry-After`.
- Per certificate location: unique-active-deployment index.
- User-initiated jobs have `priority 1`, scheduled `5`, so interactive actions overtake bulk discovery.

### 8.6 Lock mode and license gating

Every scheduled job type is tagged `gated`. `license.Gate(ctx, jobType)` is called by (a) the scheduler before enqueue and (b) the worker right after claim (covers jobs enqueued before lock). In lock mode `gated` jobs are marked `cancelled` with `last_error_code='license.locked'`. Not gated: `notify.send`, `alerts.evaluate` (expiry emails continue, with an added "license expired" note), `license.evaluate`, `backup.auto`, `audit.verify`, `maintenance.cleanup`. Gated: `target.discover`, `kv.poll`, `rotation.*`, `certificate.deploy` (system-triggered), `sshkey.*`. User-initiated deploy/add/remove are refused at the API with `license.locked` (no external changes in lock mode). Evaluation-expired state behaves as lock. On license renewal (R29): recurring read-only jobs (discovery, KV polling, expiry checks) auto-resume on the scheduler's next tick; external-change work that was refused or cancelled during lock (deploys, rotation removals) is not started automatically but listed for Admin confirmation; an overdue old-key removal re-verifies the new key and sends a fresh dry-run notice before it runs. A renewal with a smaller `max_targets` than the current target count keeps existing targets working with a persistent banner and only blocks adding targets.

**Continuity window (R44, owner decision 2026-10-20).** A fourth class, `continuity`, is the automatic upkeep of what is already managed: `acme.renew` (the renewal planner's order of an issued certificate), `certificate.deploy_auto` (a deployment the ACME or Key Vault planner queues to a location the certificate is already bound to), `kv.poll`, and the periodic `acme.schedule`, `acme.auto_deploy`, `kv.schedule` and `kv.auto_deploy`. The gate allows it wherever it allows changes and, in addition, in a licensed lock for 45 days after the lock begins (`ContinuityEndsAt` = `LocksAt` + 45 days; the evaluation has none). The runner claims `continuity` jobs while the gate allows them; once an evaluation finds the window ended, it holds queued continuity work that changes something (`blocked_license`, confirmed by an Admin after renewal as in R29) and cancels a queued poll. The same handler serves `acme.issue` and `acme.renew` (it asks the gate for its job's class before each publication and before finalize), and `certificate.deploy` and `certificate.deploy_auto` (they share the dedupe key namespace); the ACME sweep resumes an interrupted renewal order under `continuity`. A Key Vault poll in the window does not hold the versions it detects (the hold rule asks for `continuity`), so the automatic deployment deploys them. A person's request is never `continuity`: no API route may declare it.

### 8.7 In-flight operations at lock time

Lock is evaluated at claim and between phases. A `deployment` or `rotation` already past its first mutating step is not cancelled: the handler checks `Gate` only at safe boundaries (before a new mutating phase begins). Concretely: a deployment finishes verify or rolls back (it always ends in `succeeded`, `rolled_back`, or `needs_attention`); a rotation in `adding_new`/`verifying_new` completes or aborts, and a rotation never proceeds to `removing_old` while locked (removal step re-checks the gate and the `old_key_removal_allowed` flag); an overlap that ends during lock stays in `overlap` with a `needs_attention` note until a valid license is installed and an Admin confirms, as in 8.6.

### 8.8 Crash recovery

- **Leases**: workers heartbeat every 15 s extending `locked_until` (and the `target_locks` lease; stale after 3 missed heartbeats). A reaper (each worker loop, every 60 s) finds `running` jobs with `locked_until < now()` and re-queues them (`attempts` preserved) with `last_error_code='job.lease_expired'`.
- **Idempotent resume**: `certificate.deploy` re-run loads the `deployments` row. If `rollback_info` exists and status is `running`/`verifying`, the handler first asks the provider to `VerifyDeployment` for the *desired* fingerprint: if live and healthy, mark `succeeded`; otherwise call `RollbackDeployment` with the persisted `BackupRef`, then mark `rolled_back` (or `rollback_failed`/`needs_attention` with a high-severity alert and instructions on where backups live on the host). It does not redeploy automatically after a crash; the user or the next KV poll triggers a fresh deployment.
- **Rotations** are a persisted state machine; each step is idempotent (adding a key already present is a no-op checked by fingerprint; removal only if old key still present and `old_key_removal_allowed`). After a crash the handler resumes from `status`. Since removal is last and gated, the worst case is an extra valid key remaining, never lockout.
- **Startup**: on boot, before workers start, a recovery pass releases expired leases, and any deployment/rotation in a non-terminal state without a live lease is enqueued for the resume logic above.
- **Graceful shutdown** (`SIGTERM`, update): stop claiming, let running jobs finish up to 60 s, then release leases of unfinished jobs (they resume after restart).
- **Postgres outage**: workers stop on connection loss; on recovery leases have expired and the same reaper handles it.

## 9. API

### 9.1 Conventions

- Base path `/api/v1`, JSON only (`application/json; charset=utf-8`), UTC RFC 3339 timestamps, UUID ids, `snake_case` fields. Versioned by path; breaking changes -> `/api/v2`.
- Resource-oriented: `GET /targets`, `POST /targets`, `GET /targets/{id}`, `PATCH /targets/{id}`, `DELETE /targets/{id}`. Actions that are not CRUD use `POST /targets/{id}/actions/discover`; long operations return `202 Accepted` with `{ "job_id": ..., "status_url": "/api/v1/jobs/{id}" }`.
- `Idempotency-Key` header supported on `POST` for deploy and rotation actions (stored 24 h).
- Optimistic concurrency via `ETag`/`If-Match` on `PATCH` for settings, targets, policies.
- Every response carries `X-Request-Id`; the same id appears in the error body and audit log.
- Security headers: HSTS, CSP (`default-src 'self'`), `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API responses.

### 9.2 Authentication and CSRF

- **Browser sessions**: cookie `__Host-alice_session` (`HttpOnly; Secure; SameSite=Strict; Path=/`), random 256-bit value, stored hashed in `sessions`. Idle 30 min, absolute 12 h. Login is two-step: `POST /auth/login` (password) returns `mfa_required` with a short-lived pending token; `POST /auth/mfa/verify` completes the session. OIDC (delivered in Phase 7): `GET /auth/oidc/{provider}/start` and `/callback` with PKCE, state, nonce; MFA is delegated to the IdP for OIDC users.
- **CSRF**: double-submit-style synchronizer token: `GET /auth/session` returns a `csrf_token`; state-changing requests must send it in `X-CSRF-Token` (compared with the value bound to the session, constant time; the token is HMAC-SHA256 of the session token under `alice/csrf/v1`, R35). `Origin`/`Sec-Fetch-Site` checked as defense in depth. Requests authenticated with an API token are exempt from CSRF (no ambient credentials).
- **API tokens**: `Authorization: Bearer alice_...`; one scope per token, `read` or `operate` (R35); effective permission = scopes intersected with the owner's role. Tokens cannot perform MFA step-up operations (private key download, user/license/backup/settings admin), so those are session-only; no API token can retrieve private key material in v1.
- **Step-up**: sensitive endpoints require `stepup_until > now()`; otherwise `403 auth.stepup_required`; `POST /auth/stepup` re-verifies TOTP (or password + TOTP) and opens a 5-minute window.
- **Rate limiting**: in-memory (single-host v1) token bucket per IP and per token on all routes (default 300 requests/min), stricter login limits (5 failures -> progressive delay, 10 failures -> 15 min lockout); `429` with `Retry-After` and `rate.limited` error.
- **Authorization**: every route is registered with a required permission in one table (`route -> rbac.Permission`); a startup test fails if a route lacks an entry, and the QA role x endpoint matrix is generated from that same table.

### 9.3 Error format

```json
{
  "error": {
    "code": "ALC-TGT-0004",
    "reason": "target.host_key_changed",
    "message_key": "errors.target.host_key_changed",
    "message": "The server's identity has changed, so Alice stopped to keep your systems safe. Ask your security team to confirm the change, then review it here.",
    "params": { "target_name": "web-01" },
    "details": [ { "field": "config.port", "code": "validation.out_of_range", "message_key": "validation.out_of_range", "params": { "min": 1, "max": 65535 } } ],
    "request_id": "01J...",
    "retryable": false,
    "help_url": "/help/errors/ALC-TGT-0004"
  }
}
```

Rules:
- `code` has the format `ALC-<AREA>-<NNNN>` (e.g. `ALC-TGT-0004`; areas such as `AUTH`, `TGT`, `SSH`, `NGX`, `AKV`, `CRT`, `KEY`, `LIC`, `BAK`, `SYS`), is stable, never reused, and documented in the error table of `docs/troubleshooting.md` (generated from the code registry; CI fails if a code lacks documentation or locale keys). Clients switch on `code`. `reason` is the stable dotted symbolic name (`domain.reason`, e.g. `license.locked`) used in code, logs and locale keys; the dotted names used elsewhere in this document are `reason` values.
- `message_key` + `params` let the SPA render the localized text from its own locale files; `message` is the server-rendered fallback in the request locale (`Accept-Language` or user `locale`), always safe for end users: no stack traces, SQL, file paths of the Alice host, hostnames of internals beyond what the user already sees, and never secret material. Params are allowlisted primitives and redacted by type.
- Internal errors: `500` with `code=internal.unexpected`, generic message, and `request_id` only; detail is in server logs (also redacted). Provider/SDK errors are translated into stable codes (`azure.auth_failed`, `ssh.connection_refused`, `nginx.config_test_failed`), never passed through raw. The raw provider text may be stored in the job attempt (redacted, admin-only "technical details" panel).
- Each error has three user-facing pieces in locale files: what happened, why it matters/likely cause, what to do next (`errors.<reason>.title|cause|action`).
- HTTP status use: `400` malformed, `401` unauthenticated, `403` forbidden/step-up/license-locked (`license.locked`), `404`, `409` conflict (duplicate, active deployment, license target limit -> `license.target_limit_reached`), `412` ETag mismatch, `422` validation, `429` rate limit, `5xx` internal/upstream (`502 upstream.unreachable`).

### 9.4 Pagination, filtering, sorting

Cursor pagination for large lists (`audit`, `jobs`, `certificates`): `?limit=50&cursor=<opaque>` (max 200), response `{ "items": [...], "next_cursor": "..." | null, "total_estimate": 1234 }`. Offset pagination is not offered. Filters use explicit query params (`?expires_before=2026-12-31&target_id=...&status=...&q=...`), sort via `?sort=not_after` / `-not_after` from a per-endpoint allowlist. Exports (`GET /audit/export?format=csv|json`, inventory export) stream and are audited.

### 9.5 OpenAPI

`api/openapi.yaml` (OpenAPI 3.1) is the source of truth. `oapi-codegen` generates the Go server interface and models and validates requests against the schema at runtime (unknown fields rejected); `openapi-typescript` generates the SPA's types; CI fails if generated code is stale, if a route lacks an operation, or if an operation lacks a `x-permission` extension and error responses referencing the shared `Error` schema. The spec is served at `GET /api/v1/openapi.yaml` (authenticated) and rendered in docs; no third-party API-explorer is embedded in the binary.

### 9.6 Endpoint groups

| Group | Examples |
|---|---|
| `setup` (only before wizard completion, then disabled) | `POST /setup/admin`, `/setup/recovery-passphrase` (also generates the backup key pair), `/setup/tls`, `/setup/smtp`, `/setup/license`, `GET /setup/status`; exception that stays available afterwards (Admin only): `GET /setup/alice-helper` (helper binary + per-profile sudoers snippet) |
| `auth` | `/auth/login`, `/auth/mfa/verify`, `/auth/logout`, `/auth/session`, `/auth/stepup`, `/auth/oidc/...`, `/auth/password` |
| `users`, `roles`, `sso` | `/users`, `/users/{id}/actions/reset-mfa`, `/users/{id}/actions/reset-password`, `/users/{id}/actions/revoke-sessions`, `/sso/providers`, `/sso/group-mappings` (Admin; Phase 7) |
| `tokens` | `/tokens` (own tokens; create returns the secret once) |
| `targets` | CRUD, `/targets/{id}/actions/test`, `/actions/discover`, `/host-keys` (list, confirm pin, re-pin) |
| `providers` | `GET /providers` (kinds, capabilities, config schemas for form generation) |
| `certificates` | list/get, `/certificates/upload`, `/certificates/csr`, `/{id}/locations`, `/{id}/deploy`, `/{id}/private-key/download` (Admin, reason, step-up), bindings `/locations/{id}/binding` |
| `deployments` | list/get with steps, `/deployments/{id}/actions/retry|rollback` |
| `incidents` (R46) | `POST /certificates/{id}/incidents`, `GET /incidents`, `GET /incidents/{id}`, `/incidents/{id}/retry|revoke-now|replacement|close`, `GET /certificate-impact/{id}`, `GET /certificates/capabilities`, `POST /acme/certificates/{id}/revoke` |
| `ssh-keys` | list/get, `/ssh-keys/generate`, `/{id}/deploy`, `/locations/{id}/remove`, `/ssh-keys/platform-key` (public key for the wizard) |
| `rotation` | `/rotation/policies` CRUD, `/rotation/runs`, `/rotation/runs/{id}/actions/approve|abort|dry-run` |
| `keyvault` | vault-specific views: `/targets/{id}/kv/keys`, `/kv/secrets` (metadata), `/kv/certificates` |
| `jobs` | `/jobs`, `/jobs/{id}`, `/jobs/{id}/actions/cancel` |
| `alerts`, `dashboard` | `/alerts`, `/dashboard/summary` (includes the daily audit head hash), `/dashboard/expiring` |
| `audit` | `/audit` (list, Admin+Auditor), `/audit/export`, `/audit/verify` |
| `license` | `GET /license` (Admin + Auditor), `POST /license` (upload, Admin), `GET /license/installation-id` |
| `settings` | `/settings/smtp` (+ test mail), `/settings/syslog`, `/settings/general` |
| `backup` | `POST /backup` (streams encrypted file), `GET /backups`; restore is CLI-only (no web restore) |
| `system` | `/livez`, `/healthz`, `/version`, `/i18n/locales` |
| `services` (R49) | `/services` (CRUD, `/{id}/policy` (read; `PUT` saves a new version, R55), `/{id}/policy/versions`, `/{id}/owners` (read; `PUT` replaces the team, R56), `/{id}/actions/assign?dry_run=`), `/environments` (CRUD), `/service-trusts` (list, create, delete), `/role-bindings` (list, create, delete) and `/users/{id}/access` (R53), `/directory-groups` (list, create, delete) and
`/automation-accounts` (list, create, change; `/{id}/tokens` list, create, delete) (R54); every route of the table also declares a scope class (platform, resource, list, create, cross, any, self, none) and every route naming a resource a resolver |

Lock mode: all groups remain routable for reads; mutating endpoints outside {`auth`, `license`, `backup`, `audit export`, `inventory export`, `settings/smtp`, `tokens`} return `403 license.locked`.

## 10. Internationalization

### 10.1 Principles

- The backend never emits final user text as the only carrier of meaning: every error, validation message, warning, alert, job step, and email carries a stable **key** plus `params`. A server-rendered fallback `message` exists only for API consumers and logs (English default or `Accept-Language`).
- Keys are namespaced dot paths: `errors.<reason>.title|cause|action`, `validation.*`, `steps.<provider>.<step>`, `alerts.<kind>.subject|body`, `emails.<template>.*`, `enum.<domain>.<value>` (statuses, roles), `provider.<kind>.name|fields.<field>.label|help`.
- Audit log and stored data hold codes and ids, not localized text (localized at display time); audit `details` use keys + params so a Turkish auditor and an English admin read the same record in their language.

### 10.2 Frontend

- Locale files: `web/src/locales/en.json` and `tr.json` (nested JSON, i18next format, ICU-style plurals through i18next plural suffixes `_one/_other`; Turkish has no grammatical plural after numerals but keys remain identical). English is the source language and the fallback.
- Loaded via `i18next` with `react-i18next`; each locale file is a lazily loaded chunk except the active language. The user's `locale` (stored in `users.locale`) wins over browser language; the login screen uses browser language then the `locale.default` setting.
- The SPA translates `error.message_key` with `params`; if the key is missing it shows the server `message`, and in development builds a missing key throws in tests (CI parity check below).
- Backend-owned catalogs used for emails and fallback messages live in `internal/i18n/locales/{en,tr}.json` and are embedded; common keys (errors, enums, alerts, emails) live once in the shared catalog `/locales/common/{en,tr}.json`, consumed by both the SPA and the backend, so they cannot drift; a CI parity check (`tools/i18n-sync`) fails if any key is missing in `en` or `tr`.
- Providers register their schema label keys in the same catalog; the form generator resolves `LabelKey`/`HelpKey`.

### 10.3 Adding a language

1. Copy `web/src/locales/en.json` to `<code>.json` (BCP 47, e.g. `de`, `pt-BR`) and the backend catalog file likewise; translate values only.
2. Add the code, native name, and `direction` to `web/src/locales/manifest.json` (also served at `GET /api/v1/i18n/locales`).
3. Run `npm run i18n:check`: fails on missing/extra keys, unbalanced `{{placeholders}}`, and untranslated values identical to English where not allow-listed.
4. Add a Playwright smoke test run for the language; no Go code changes are needed because email templates are keyed catalogs. Right-to-left languages require a frontend layout review (not supported in v1; `direction` reserved).

### 10.4 Date, time, and number formatting

- Stored and transmitted in UTC RFC 3339; formatted in the browser with `Intl.DateTimeFormat` / `Intl.NumberFormat` using the active locale and the user's chosen time zone (default: browser zone; setting per user: `users.timezone`). No hand-rolled date formatting. Certificate expiry additionally shows relative time ("in 12 days") via `Intl.RelativeTimeFormat`.
- Emails render dates server-side with `golang.org/x/text` (`message.Printer`, `language.Tag`) and the recipient's locale and time zone, always including the zone abbreviation.
- Numbers: never format inside translation strings; pass raw numbers and let `Intl.NumberFormat` handle decimal separators (`1.234,5` in tr vs `1,234.5` in en). Key sizes (`2048`), ports, and serial numbers are technical identifiers and are rendered unformatted (no thousands separators) via a dedicated `<Technical>` component.
- Fingerprints, hostnames, file paths, commands, and cert subjects are never translated or case-transformed.

### 10.5 Turkish pitfalls

- **Dotted/dotless i**: `"i".toUpperCase()` is `"I"` in English but `"İ"` in Turkish, and `"I".toLowerCase()` is `"ı"`. Rules: (a) never use `toUpperCase()/toLowerCase()`, `strings.ToUpper/ToLower`, or CSS `text-transform` on user-visible text without locale awareness. Frontend uses `toLocaleUpperCase(locale)` / `toLocaleLowerCase(locale)` via a `useLocaleCase()` helper; Go uses `golang.org/x/text/cases` with `language.Turkish` (`cases.Upper(tag)`), or `unicode/utf8`-safe helpers. (b) CSS `text-transform: uppercase` respects `lang` attribute, so `<html lang>` is set to the active locale on every switch. (c) **Identifiers and protocol data are case-folded with locale-invariant operations** (`strings.ToLower` with `unicode` invariant, `strings.EqualFold` for ASCII hostnames/usernames/emails); using Turkish casing there causes the "Turkish I bug" (`TITLE` != `title`, `FILE` -> `fıle`). Database usernames use `citext` (locale-independent for ASCII) and are normalized with NFC plus invariant lowercase.
- **Sorting and search**: string sorting uses `Intl.Collator(locale)` in the UI (`ç, ğ, ı, ö, ş, ü` order) and `collate "tr-TR-x-icu"` is *not* used for identifiers; server-side list sorting for display text is done client-side for small lists and by stable technical keys server-side. Search is case- and diacritic-insensitive via a normalizing function that maps `İ/I/ı/i` all to `i` for the search index only (`unaccent`-style), so "istanbul", "İstanbul" and "ISTANBUL" all match.
- **Text expansion and grammar**: Turkish is agglutinative; never assemble sentences from fragments (`"Delete " + name`) and avoid suffixes attached to variables (e.g. `{{name}}'yi`). Use complete-sentence keys with placeholders, and rephrase so the variable is not inflected ("Silinecek sunucu: {{name}}"). Allow about 30% width growth in layouts.
- **Diacritics in inputs**: accept and preserve `ç ğ ı İ ö ş ü` in names/labels (UTF-8 everywhere; DB encoding UTF8; PDF/CSV exports write UTF-8 with BOM for Excel compatibility).
- **Mail**: subject and body via the recipient's locale; SMTP `Content-Type: text/plain; charset=utf-8`, subject RFC 2047 encoded.
- **Tests**: the E2E suite runs in EN and TR; unit tests include the strings `"ISTANBUL"`, `"İzmir"`, `"ığdır"` through every case/search helper, and a lint rule (`no-restricted-syntax`, `forbidigo` for `strings.ToUpper|ToLower` in `internal/api` and user-facing packages) flags unsafe casing calls.
