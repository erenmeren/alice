# LDAP and Active Directory Sign-in Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** People can sign in to Alice with a directory password over `ldaps://`: a read-only service account finds the user, Alice binds as that user, groups map to roles, users are created at first sign-in, Alice's own TOTP is asked for by default.

**Architecture:** A new package family next to the OIDC one: `internal/auth/ldap/ldapx` (pure helpers: escaping, transliteration, name and id derivation), `internal/auth/ldap` (directory settings, group mappings, secrets, the network client, the sign-in orchestration), and new methods in `internal/auth` (`SignInLDAP`, `StepUpLDAP`, `RefuseLDAP`) that create or update the user and the session in one transaction. The API gets a parallel route family; the web app gets a **Sign in to** selector and a **Directories** settings tab. Local accounts, OIDC and manual user creation stay exactly as they are.

**Tech Stack:** Go 1.27, `pgx/v5`, `github.com/go-ldap/ldap/v3` (new, MIT, pure Go; the product builds with `CGO_ENABLED=0`), React 18 + Mantine 8 + TanStack Query, testcontainers with a real OpenLDAP.

**Spec:** `docs/superpowers/specs/2026-10-15-ldap-directory-signin-design.md`

## Global Constraints

- Work on branch `ldap-signin`. Merge into `main` locally (fast-forward) at the end. Push only when the owner says so. Stage files by explicit path only (never `git add -A`: the working tree has untracked files that are not ours).
- Product binaries are built with `CGO_ENABLED=0`; the new dependency must be pure Go. No LDAP code outside `internal/auth/...`, `internal/api/...`, `cmd/alice`, and tests.
- Lint rules in `.golangci.yml`: no `strings.ToLower/ToUpper/Title` (use `strings.EqualFold`, `golang.org/x/text/cases`, or SQL `lower()`/citext), no `fmt.Print*`, no `time.Now` (use the injected `clock.Clock`), `noctx` (use `DialContext` and context variants), `gosec`. A `//nolint` needs the rule and a reason.
- Audit: events are appended last in a transaction (after row locks). Detail keys must not contain the segments `password, passphrase, secret, private, token, code, totp, otp, key, dek, credential, cookie, session` (except keys ending `_id`, `_prefix`, `_count`, and `error_code`/`reason_code`): write `bind_set: true`, `unique_id`, `reason`. Every new audit action needs a label `audit.actions.<action with dots as underscores>` in BOTH `web/src/locales/en.json` and `tr.json` (a test reads every Go source). `audit_log.actor_type` stays `user|api_token|system|oidc`: directory events use `ActorUser` for a known user and `ActorSystem` for an unknown one (no migration for a new actor type).
- Secrets: the service account password is stored with `secrets.Keyring.PutSetting` under `ldap.directory.<uuid>.bind_password`, written in the same transaction as the row and the audit event, never returned by any API, held in `secrets.Plaintext` and zeroed after use (every handler path: `defer req.zero()`; the zeroing tests in `internal/api` apply).
- Outbound connections dial through `netaddr.DialContext` (config field `Dial` like the OIDC service; nil means `netaddr.DialContext`). TLS: `ldaps://` only, verify certificate and host name (system roots plus optional PEM, reuse the OIDC PEM validation by moving `validCAPEM` to a shared place), no referrals, size and time limits.
- Directory network I/O happens BEFORE any database transaction that holds row or audit locks (as OIDC does: exchange first, `SignIn...` after). Never hold a DB transaction across an LDAP call.
- API: every route goes through `register` with permission `rbac.SSOManage` (reuse: browser-only, step-up required) or `rbac.Public`, a `limit` class and, for state-changing admin routes, `lic: license.ClassAlways`. New error codes `ALC-LDAP-0001...` are added to `AllErrorCodes()`, to `locales/common/{en,tr}.json` (`errors.ldap.<reason>.title/.cause/.action`), and to `docs/troubleshooting.md` as `## ALC-LDAP-NNNN: <title>` sections (read `TestTroubleshootingQuotesTheRealTitles` and `TestPhase7CodesHaveTroubleshootingSections` first and satisfy them). `api/openapi.yaml` and `internal/api/authz_test.go` (`make authz-doc`) are updated with every route.
- Tests: coverage floors in `coverage-floors.json` are never lowered; new packages get a floor at the measured value rounded down; web thresholds in `web/vite.config.ts` are never lowered. New container images in Go literals must carry `tag@sha256:<index digest>` (`tools/pincheck`). `make i18n-check` requires identical keys and placeholders in `en` and `tr`.
- Docs: `docs/admin-guide.md`, `docs/troubleshooting.md`, `docs/security-overview.md`, `docs/README.md`, `docs/dev/dependency-updates.md`, `CHANGELOG.md`; `make docs-check` must pass (commands named exist, anchors resolve).
- Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit ...`.

## Rulings (decisions this plan makes where the spec leaves room)

1. **Seven tasks, not five.** The spec's five delivery steps are split further (pure helpers apart from the service; API apart from the interface), because each stays reviewable.
2. **E-mail rule:** like OIDC, a directory first sign-in or an e-mail change is refused when a local user already has that address (`localEmailInUse`), reason `email_in_use`. A directory user without an e-mail attribute gets an empty e-mail and is fine. Collisions with OIDC users or between directories are allowed (names differ, ids differ).
3. **Unique id storage:** always the lower-case hex of the raw attribute bytes (objectGUID is 16 binary bytes; entryUUID is an ASCII string, its bytes are hexed too), 2 to 254 hex characters. It is the identity: matched by `(ldap_directory_id, ldap_unique_id)` only.
4. **User name:** the sign-in name attribute value goes through an explicit transliteration table (Turkish `ç ğ ı İ ö ş ü Ç Ğ Ö Ş Ü` and the common Latin accents), then the same character filter as `claims.Username` (`a-z 0-9 . _ - @`, lower-cased through `x/text/cases`, not `strings.ToLower`), fallback `ldap-` plus 12 hex characters of the unique id; clashes get `-2`, `-3` through the existing `freeUsername` loop. The display name is the display-name attribute as is (cut to 100 runes).
5. **Rate limits (spec L3):** per address the existing `limitLogin` bucket (10 a minute). New in-memory limiter per `(directory, login name)`: 5 attempts per 15 minutes, counted for unknown names too, refunded on success, listed in `ResetLimits`. Below a typical AD lockout threshold of 5-10 in 30 minutes only on the conservative side; the number is a constant with a comment.
6. **Step-up (spec L2):** `StepUpLDAP` always repeats the bind with the directory password; when the directory has `mfa_required` it also needs the TOTP. The window is 5 minutes as for the others.
7. **MFA per directory:** `mfa_required` is read at every sign-in. On: pending session through the existing `/auth/mfa/enroll|verify` routes. Off: a full session at once (`startFullSession`). A user's stored TOTP stays untouched when the setting flips.
8. **Roles:** reuse `claims.ResolveRole` and `claims.ValidateMapping` for group to role (exact, case-sensitive group value; the DN or the name exactly as the group search returns it, the setting says which attribute: `group_name_attribute`, default `cn`, or the DN when empty). The switch "SSO users may be Admin" (`sso.allow_admin_role`) applies to directory users: `capRole` and `DemoteSSOAdmins` cover `auth_source IN ('oidc','ldap')`.
9. **`role_source`** gets the value `ldap_mapping`.
10. **Directory I/O limits:** dial 10 s, operation 15 s, the whole sign-in 30 s; search size limit 2 for the user lookup (exactly one entry required), 1000 for groups; referrals off.
11. **At most 3 directories**, unique name (case-insensitive), a directory with users cannot be deleted or have its unique id attribute or address list changed (switch it off).
12. **Permission:** reuse `sso.manage`. A separate permission would only add matrix rows.

## Review Focus

- A sign-in must never reach the directory with an empty password; filters and DNs are escaped everywhere a value is inserted; the user lookup needs exactly one entry. Pinned in Tasks 2 and 3.
- The directory call must not hold a transaction; the provisioning transaction is short. Pinned in Task 4.
- Unknown user, wrong password, no mapped group and a disabled directory user produce the same visible answer; audit carries the reason. Pinned in Tasks 4 and 5.
- A directory user can never be joined to a local account, never gets a password, API token or manual role change; MFA reset works, password reset does not. Pinned in Task 4.
- The service account password never appears in an API response, an audit record, a log or an error. Pinned in Tasks 3, 5 and 7.
- Local sign-in is unchanged and cannot match a directory user. Pinned in Task 4.
- Rate limiting protects directory accounts from lockout through Alice, including for unknown names. Pinned in Task 5.

---

## File Structure

| Path | Responsibility |
|---|---|
| `migrations/00015_ldap.sql` | tables, constraints, secret key pattern, grants, down guards |
| `internal/auth/ldap/ldapx/` | pure helpers: `EscapeFilter`, `EscapeDN`, `Transliterate`, `Username`, `UniqueID`, `FilterTemplate` |
| `internal/auth/ldap/` | `Service`, directories and mappings CRUD, secrets, `client.go` (network), `signin.go` (orchestration), `test.go` (connection and sign-in tests) |
| `internal/auth/ldap_users.go` | `SignInLDAP`, `StepUpLDAP`, `RefuseLDAP`, provisioning |
| `internal/auth/*.go` | generalise the places that special-case `oidc` |
| `internal/api/ldap_handlers.go`, `ldap_dto.go`, `errors.go`, `server.go` | routes, DTOs, codes, limiter |
| `api/openapi.yaml`, `internal/api/authz_test.go`, `docs/authz-matrix.md` | contract |
| `locales/common/*.json`, `web/src/locales/*.json` | texts and audit labels |
| `web/src/api/ldap.ts`, `web/src/components/directories/*`, `web/src/pages/{LoginPage,SettingsPage,UsersPage,AccountPage}.tsx` | UI |
| `test/images/openldap/`, `deploy/docker-compose.e2e.yml`, `web/e2e/ldap.spec.ts` | e2e |
| `docs/*` | documents |

---

### Task 1: Schema

**Files:** Create `migrations/00015_ldap.sql`; Modify `cmd/alice/testapi_e2e.go` (reset SQL), `migrations/down_integration_test.go` if it lists versions; Test `migrations/ldap_integration_test.go`.

**Interfaces (SQL):**
- `ldap_directories(id uuid PK, name text, addresses text[] (1..3 entries, each `^ldaps://[^/\s?#]+$`), user_base_dn text, user_filter text (contains `{login}` exactly once), login_attribute text, unique_id_attribute text, display_name_attribute text, email_attribute text, bind_dn text, group_base_dn text, group_filter text (only `{dn}` and `{login}` placeholders), group_name_attribute text, ca_pem text, mfa_required boolean default true, enabled boolean default false, version int, created_by uuid, created_at, updated_at)` with format CHECKs mirroring `oidc_providers`, `UNIQUE (lower(name))`, at most 3 rows (enforced in the service, with a trigger-free count check inside a lock).
- `ldap_group_mappings(id, directory_id REFERENCES ldap_directories ON DELETE CASCADE, group_value text (1..256, btrim, no control characters), role IN ('admin','operator','auditor'), UNIQUE (directory_id, group_value))`.
- `users`: `auth_source` CHECK gains `'ldap'`; `role_source` CHECK gains `'ldap_mapping'`; new `ldap_directory_id uuid REFERENCES ldap_directories`, `ldap_unique_id text CHECK (length 2..254 and hex)`; constraints `users_ldap_identity` ((auth_source='ldap') = (both IS NOT NULL)) and `users_ldap_not_local` (ldap users: `password_hash IS NULL AND NOT is_break_glass AND role_source='ldap_mapping'`); unique partial index `users_ldap_identity_unique ON users (ldap_directory_id, ldap_unique_id) WHERE ldap_directory_id IS NOT NULL`.
- `setting_secrets_key_check` replaced by the current alternation plus `|ldap\.directory\.<uuid-regex>\.bind_password` (copy the form of 00012; verify the real constraint names against a migrated database first: `users_auth_source_check`, `users_role_source_check`).
- Grants to `alice_app` on the new tables. Down: refuses with a new SQLSTATE `Z1021` while any directory, `ldap` user or `ldap.directory.%` secret exists (guard in `StatementBegin/End`, as 00011/00012 do), then drops in reverse and restores the previous CHECKs.

- [ ] **Step 1: Write the failing tests** (`integration` tag, `pgtest`): constraints reject a local user with `ldap_directory_id`; an `ldap` user needs both id columns and no password and `ldap_mapping`; the unique index refuses the same `(directory, unique id)` twice but allows the same unique id in two directories; address CHECK refuses `ldap://` and `ldaps://host/path`; `user_filter` without `{login}` refused; group filter with an unknown placeholder refused; the secret key pattern accepts only `ldap.directory.<uuid>.bind_password`; deleting a directory with mappings cascades them; Down is refused while a directory exists and works on an empty schema (follow `down_integration_test.go`); the e2e reset truncates the new tables (add them to the TRUNCATE list and test the list contains every table that references `users`: if an existing test checks this, extend it).
- [ ] **Step 2: Run to verify failure:** `go test -tags integration ./migrations/ -count=1` → FAIL.
- [ ] **Step 3: Write the migration** in the style of `00011`/`00012` (header, guards, grants, no clock defaults).
- [ ] **Step 4: Run to verify it passes:** `go test -tags integration ./migrations/ ./internal/platform/db/ -race -count=1`.
- [ ] **Step 5: Commit** (`feat(auth): schema for LDAP directories, mappings and directory users`).

---

### Task 2: Pure helpers `ldapx`

**Files:** Create `internal/auth/ldap/ldapx/{escape.go,translit.go,names.go,filter.go}`; Modify `internal/archtest/arch_test.go` (an exact rule like `auth/oidc/claims`: platform and `rbac` only, `pureDeniedURL` std denials); `coverage-floors.json`; Test next to each file plus `fuzz_test.go`.

**Interfaces:**

```go
func EscapeFilter(s string) string                 // RFC 4515: ( ) * \ NUL and non-UTF-8 bytes as \xx
func EscapeDN(s string) string                     // RFC 4514 attribute value escaping
func ExpandFilter(tmpl string, vals map[string]string) (string, error) // only {login} and {dn}; every value EscapeFilter'ed; unknown placeholder -> error; the template must be a balanced RFC 4515 filter
func Transliterate(s string) string                // explicit table, never strings.ToLower
func Username(login, uniqueID string) string       // transliterate, fold with x/text/cases, keep a-z0-9._-@, fallback "ldap-"+first 12 hex of uniqueID
func UniqueID(raw []byte) (string, error)          // lower-case hex, 1..127 bytes
func ValidLoginName(s string) bool                 // 1..256 runes, no control characters, no NUL
```

- [ ] **Step 1: Write the failing tests:** escaping with the RFC examples and hostile strings (`*)(uid=*))(|(uid=*`, NUL, invalid UTF-8, leading `#`/space, trailing space, `,+"\<>;=`); `ExpandFilter` never lets a value change the filter structure (property test: parse the result with go-ldap's `ldap.CompileFilter` and compare the number of top-level conditions); unknown placeholder and unbalanced template refused; Turkish table (`ÇİĞDEM` ⇒ `cigdem`, `Şeref Üstün` handling of space, dotted/dotless i both ways), a name that becomes empty falls back to `ldap-<hex>`; `UniqueID` of 16 bytes and of an ASCII uuid; fuzz targets `FuzzEscapeFilter` (result contains no unescaped special byte), `FuzzUsername` (result matches `^[a-z0-9._@-]{1,64}$` or the fallback), `FuzzExpandFilter` (never panics, CompileFilter succeeds or an error is returned).
- [ ] **Step 2-5:** fail → implement → pass (`go test ./internal/auth/ldap/ldapx/ -race -count=1` and 20 s per fuzz target; `go test ./internal/archtest/`; `golangci-lint run ./internal/auth/ldap/...`) → commit (`feat(auth): pure helpers for LDAP filters, names and ids`). Add the `go get github.com/go-ldap/ldap/v3@<latest tag verified>` here (needed by the test) with `go mod tidy`, `go mod verify`, and the section in `docs/dev/dependency-updates.md` (modules, versions, licences read from the module graph, why).

---

### Task 3: The `ldap` service: settings, mappings, secrets, client, tests

**Files:** Create `internal/auth/ldap/{service.go,directories.go,mappings.go,client.go,test.go,errors.go}`; Test `internal/auth/ldap/*_integration_test.go` with an OpenLDAP container helper `internal/testutil/fakeldap/` (rule in archtest like `fakeidp`); Modify `coverage-floors.json`, `internal/auth/oidc/providers.go` (move `validCAPEM` to a shared internal package, e.g. `internal/platform/pemca`, with the OIDC package using it: behavior unchanged, its tests untouched).

**Interfaces:**

```go
type Config struct {
	Pool    *pgxpool.Pool
	Keyring *secrets.Keyring
	Audit   *audit.Log
	Clock   clock.Clock
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error) // nil: netaddr.DialContext
	Log     *slog.Logger
}
func New(Config) *Service

type Directory struct{ /* all columns; BindPasswordSet bool; Version int */ }
type DirectoryInput struct{ /* writable fields */; BindPassword secrets.Plaintext }
type DirectoryPatch struct{ /* opt-style pointers */ }

const MaxDirectories = 3
func (s *Service) CreateDirectory(ctx, a audit.Actor, in DirectoryInput) (Directory, error)
func (s *Service) UpdateDirectory(ctx, a audit.Actor, id uuid.UUID, version int, p DirectoryPatch) (Directory, error) // new addresses or bind DN or unique id attribute need BindPassword again; refused while users exist for unique id attribute and addresses (ErrDirectoryInUse)
func (s *Service) DeleteDirectory(ctx, a, id) error // ErrDirectoryInUse when users exist (FK 23503); deletes the secret in the same transaction
func (s *Service) Directories(ctx) ([]Directory, error); (s *Service) Directory(ctx, id) (Directory, error)
func (s *Service) PublicDirectories(ctx) ([]PublicDirectory, error) // enabled ones: id, name
func (s *Service) CreateMapping / DeleteMapping / Mappings (same shape as oidc.mappings.go; Admin mapping refused while the switch is off: reuse the switch lock)

// Network layer, used by sign-in and by the tests
type Entry struct{ DN string; Attrs map[string][][]byte }
type Client interface {
	Authenticate(ctx, d Directory, bindPassword secrets.Plaintext, login string, password secrets.Plaintext) (Entry, error)
	Groups(ctx, d Directory, bindPassword secrets.Plaintext, user Entry, login string) ([]string, error)
}
func (s *Service) client() Client // the real one; a test seam via Config.NewClient func() Client

type Identity struct{ UniqueID, Login, DisplayName, Email string; Groups []string }
func (s *Service) Verify(ctx, directoryID uuid.UUID, login string, password secrets.Plaintext) (Identity, Directory, error)
// Verify: loads the directory and the bind secret, refuses an empty password and an invalid login name BEFORE any network traffic, does service bind + search (exactly one entry) + user bind + group search; maps failures to *LoginError{Reason} with the closed set bad_credentials, ambiguous_user, directory_unreachable, directory_misconfigured, provider_disabled, login_invalid.
func (s *Service) TestConnection(ctx, a audit.Actor, id uuid.UUID) error // service bind and one search; audits ldap.directory_tested {result, reason}
func (s *Service) TestSignIn(ctx, a audit.Actor, id uuid.UUID, login string, password secrets.Plaintext) (TestResult, error) // returns groups found and the role the mappings would give (or none); nothing stored; audits ldap.signin_tested {result, reason, role}
```

Client details: `ldap.DialURL` is not used; connect through `s.dial` with `ldap.NewConn`/`DialWithDialer`-style options so the SSRF-guarded dial is used; TLS config built from system roots plus the optional PEM, `ServerName` from the address, minimum TLS 1.2; timeouts per ruling 10; referrals off; user lookup `SearchRequest` with `SizeLimit: 2`, `TimeLimit`, `DerefAliases: NeverDerefAliases`, attributes limited to the configured ones; a result with 0 entries is `bad_credentials` (same visible answer), 2+ is `ambiguous_user`; after the user bind returns an `InvalidCredentials` result code map to `bad_credentials`; any other bind error to `directory_unreachable` or `directory_misconfigured` (a constraint violation / unwilling to perform from an empty password never happens because empty passwords are refused earlier); the service account bind failing is `directory_misconfigured` (logged once, not shown); the passwords are `Plaintext` and zeroed.

- [ ] **Step 1: Write the failing tests.** Container helper `fakeldap.Start(t)` starts OpenLDAP (image pinned `tag@sha256:index-digest`: pull it, resolve the digest, record it; check how `tools/pincheck` wants it; osixia/openldap:1.5.0 was used for the AD guide and works, but a maintained alternative is acceptable if you verify it) with the memberof overlay, users `ada` (uid, `cn=Ada Lovelace`), `çiğdem` (a Turkish-named user), a group `alice-ops` with `member` entries, a nested group, a user in no group, a user with the same `uid` twice (ambiguous), and a service account; TLS with a generated CA and certificate (the helper returns the CA PEM). Tests: `TestVerifyHappyPath` (identity, groups, unique id = hex of entryUUID); `TestEmptyPasswordNeverReachesTheDirectory` (a recording dial counts connections: zero); `TestInvalidLoginNameRefused`; `TestWrongPasswordAndUnknownUserLookTheSame` (same `LoginError.Reason`, comparable duration within a loose bound); `TestAmbiguousUserRefused`; `TestFilterInjectionDoesNotMatchOtherUsers` (login `*` and `ada)(uid=*` find no user); `TestGroupSearchTemplateWithDNAndNested`; `TestTLSWrongAuthorityIsRefused`, `TestTLSWrongHostNameIsRefused`, `TestPlainLDAPAddressIsRejectedByTheDatabaseAndTheService`; `TestDialIsTheInjectedOne` (SSRF guard seam: a dial that refuses link-local addresses); `TestReferralsAreNotFollowed` (a referral entry from a test server); `TestTimeouts` (a listener that accepts and never answers: error within the limit); `TestResponseSizeLimit`; `TestServiceAccountFailureIsMisconfiguredNotBadCredentials`; CRUD tests mirroring `providers_integration_test.go` (create disabled by default, name uniqueness, version/ETag conflict, at most 3, bind password stored encrypted and `BindPasswordSet`, never returned, deleted with the directory, changing addresses needs the password again, in-use rules via a seeded directory user); mapping tests mirroring OIDC (Admin refused while the switch is off with audit `ldap.mapping.denied`); `TestPasswordNeverInAuditOrErrors` (distinctive password through every failure path; scan audit rows and error strings); `TestTestSignInShowsGroupsAndRole`; `TestTestConnectionAudited`.
- [ ] **Steps 2-5:** fail → implement → pass (`go test -tags integration ./internal/auth/ldap/... ./internal/auth/oidc/... -race -count=1`; coverage floor for `auth/ldap` and `auth/ldap/ldapx`; lint) → commit in 2-3 commits (`refactor: share the PEM authority validation`, `feat(auth): LDAP directory service, client and tests`).

---

### Task 4: Sign-in, provisioning, step-up; generalise the SSO special cases

**Files:** Create `internal/auth/ldap_users.go`; Modify `internal/auth/{login.go,account.go,mfa.go,tokens.go,users.go,store.go,sessions.go,oidc_users.go}` as listed below; Test `internal/auth/ldap_users_integration_test.go` and updates to the existing tests.

**Interfaces:**

```go
type LDAPIdentity struct{ DirectoryID uuid.UUID; UniqueID, Login, DisplayName, Email string }
// SignInLDAP: one db.InTx: advisory lock on (directory, unique id); capRole; lockLDAPUser (match by directory+unique id only); not found -> localEmailInUse check (ErrLDAPEmailInUse), defaultLocale, provision (username by ldapx.Username + freeUsername loop, auth_source 'ldap', password_hash NULL, role_source 'ldap_mapping', ldap ids); found -> disabled -> ErrLDAPUserDisabled; email changed -> same check; UPDATE role, email, display_name, last_login_at; user.role_synced event; then, depending on mfaRequired: pending session (kind 'pending', PendingLifetime) + LoginResult{Status: StatusMFARequired|StatusMFAEnrollmentRequired} or a full session via startFullSession. Audit rows appended last.
func (s *Service) SignInLDAP(ctx, id LDAPIdentity, role rbac.Role, mfaRequired bool, m Meta) (LoginResult, error)
func (s *Service) StepUpLDAP(ctx, p Principal, id LDAPIdentity, role rbac.Role, mfaCode string, mfaRequired bool, m Meta) (SessionResult, error) // same user (directory + unique id) else ErrLDAPOtherUser; role resync; TOTP checked when required; rotateSession with a 5 minute window; audits auth.stepup {method: ldap}
func (s *Service) RefuseLDAP(ctx, directoryID uuid.UUID, login, reason string, m Meta) error // audits auth.ldap.denied {directory_id, reason, login_name}; ends sessions and tokens of the known user for reasons no_access and provider_disabled (copy RefuseOIDC and share the session-ending helper)
```

Generalisations (each with tests): `capRole` and `DemoteSSOAdmins` cover `auth_source IN ('oidc','ldap')`; `userColumns`/`User`/`Principal` carry `LDAPDirectoryID`; `ChangePassword` and `ResetPassword` refuse `ldap` users with `ErrSSOUser`-equivalent (add `ErrDirectoryUser` mapped to the same ALC-USR-0003 family or a new `ALC-USR-0004`: decide in the task and keep one message: "This change is not possible for a directory user"); `UpdateUser` role change refused for `ldap`; `CreateToken` already refuses non-local: keep and test; `ResetMFA`/`resetMFA` and the CLI `ResetMFAByUsername` allowed for `ldap` users; `RegenerateRecoveryCodes` allowed for `ldap` users; `StepUp` (TOTP path) refuses `ldap` users with a pointer to `StepUpLDAP` (the API picks the path by `AuthSource`); `lockAdmins` unchanged (local admins only); `Login` unchanged and tested to never match an `ldap` user.

- [ ] **Step 1: Write the failing tests** (`pgtest`, fake clock, the `ldap.Service` with a fake `Client`, no container needed here): first sign-in creates the user (username from the Turkish table, `-2` on a clash with a local user, display name, role from mapping, no password, `role_source=ldap_mapping`), second sign-in updates role and e-mail and emits `user.role_synced` only on change; same unique id with a changed login name is the same user; two directories with the same unique id are two users; `ErrLDAPEmailInUse` when a local user has the e-mail (and empty e-mail is fine); disabled user refused; Admin role capped to Operator when the switch is off; MFA on: pending session and `StatusMFAEnrollmentRequired` for a user without TOTP, `StatusMFARequired` with TOTP, and the existing `VerifyMFA` completes it into a full session; MFA off: full session at once and no pending session row; flipping `mfa_required` leaves the TOTP row; the TOTP failure counters apply; `StepUpLDAP` (bind repeated, TOTP when required, other-user refused, window 5 minutes, role resync, a user removed from every mapped group is refused and sessions end); `RefuseLDAP` audits with the reason and ends sessions for `no_access`; no password or secret in audit rows; a directory sign-in transaction does not call the directory (the fake client is called before the transaction: assert by making the fake client check that no advisory lock is held, or by structure: `SignInLDAP` takes an identity, not a callback); every generalised check (password change/reset, role update, token creation refused for `ldap` users; MFA reset and recovery codes allowed); local `Login` with a directory user's name returns the same failure as an unknown name and never opens a session; concurrent first sign-ins of one identity create one user (race test like `oidc_username_race_integration_test.go`).
- [ ] **Steps 2-5:** fail → implement → pass (`go test -tags integration ./internal/auth/... -race -count=1`; coverage floor of `auth` not lowered; lint) → commit in 2 commits (`refactor(auth): treat directory users like SSO users where the rule is the same`, `feat(auth): sign in, step up and refuse for directory users`).

---

### Task 5: API

**Files:** Create `internal/api/{ldap_handlers.go,ldap_dto.go}`; Modify `internal/api/{server.go,errors.go,auth_handlers.go,dto.go,guard.go}` (limiter, `ResetLimits`, `LDAPService` interface in `Deps`), `cmd/alice/{services.go,main.go}` (wiring), `api/openapi.yaml`, `internal/api/authz_test.go` (+ `make authz-doc`), `locales/common/{en,tr}.json`, `docs/troubleshooting.md`; Test `internal/api/ldap_integration_test.go`.

**Interfaces (routes):**
- Public: `GET /api/v1/auth/ldap/directories` (enabled directories: id, name; `Public`, anonymous limiter); `POST /api/v1/auth/ldap/{id}/login` (`Public`, `limitLogin` plus the new per-(directory, login) limiter; body `{username, password}`, limits as the local login, `maxLoginPassword` runes; response and cookies exactly like `/auth/login` (`{status, csrf_token}`, pending cookie, or a full session cookie when MFA is off)); `POST /api/v1/auth/ldap/stepup` (`rbac.Session`, `limitMFA`; body `{password, code?}`).
- Admin (`rbac.SSOManage`, `lic: license.ClassAlways` for writes): `GET|POST /api/v1/ldap/directories`, `GET|PATCH|DELETE /api/v1/ldap/directories/{id}` (ETag/If-Match as OIDC), `GET|POST /api/v1/ldap/group-mappings`, `DELETE /api/v1/ldap/group-mappings/{id}?directory_id=`, `POST /api/v1/ldap/directories/{id}/actions/test-connection` and `.../actions/test-signin` (own `limitDirectoryTest` bucket 5 a minute per user, in `ResetLimits`). The "SSO users may be Admin" settings routes stay and now also describe directory users.
- DTOs: `directoryDTO` never contains the password (`bind_password_set: true`), request bodies use `secretField` with `defer req.zero()`; the sign-in routes use the generic refusal: every failure except rate limit and malformed input returns the same `401 ALC-LDAP-0001` ("The user name or password is wrong, or you have no access"), with the audit reason; `provider_disabled` and `directory_unreachable` return their own codes (`ALC-LDAP-0002` directory unavailable, 503) because they do not reveal user existence.
- Error codes (add to `AllErrorCodes()`, both locales, troubleshooting sections): `ALC-LDAP-0001` sign-in refused (generic, 401), `0002` directory unavailable (503), `0003` directory in use (409), `0004` validation/connection test failure details (422), `0005` e-mail in use (403), `0006` user disabled (403), `0007` too many directories (409), `0008` admin mapping disabled (409; or reuse `ALC-SSO-0002`: decide and record), `0009` directory sign-in test failed (422). Keep one source of truth in the table; map service errors through `errorMap`/`classify` like OIDC.
- The login handler calls `ldap.Service.Verify` first (network, no transaction), then `auth.SignInLDAP`; failures call `RefuseLDAP` then the generic error. The per-(directory, lower(login)) limiter lives in the `server` struct (`ratelimit.New(clock, 5, 15*time.Minute)`), is consulted before any directory traffic, counts unknown names equally, `Refund` on success; added to `ResetLimits`.
- The user DTO's `auth_source` enum and `openapi.yaml` gain `ldap`, plus `ldap_directory_id`.

- [ ] **Step 1: Write the failing tests** (integration, real DB, fake `ldap.Client` through `Config`): each route's permission (anonymous, session without step-up, operator refused, admin with step-up allowed) per the authz test table; ETag/If-Match; the password never in any response, header or audit row (distinctive value, all routes, including 4xx/5xx); `defer zero` tests (the existing zeroing test pattern); sign-in happy path with MFA on (pending cookie then `/auth/mfa/enroll|verify` finishes it) and off (full cookie); the generic refusal for unknown user, wrong password, no mapped group (same body and status, different audit reason); `directory_unreachable` gives 503 and no user data; rate limits: 11th request from one address refused; 6th attempt for one (directory, login) within 15 minutes refused even for an unknown name and even with the right password afterwards (until the window passes: fake clock); refund on success; `ResetLimits` clears the new limiters; the public directory list shows only enabled directories and no addresses; `POST .../stepup` for a directory user (password re-bind + TOTP) and for a local user returns the right error; OpenAPI consistency tests pass (`go test ./internal/api -run 'OpenAPI|Authz|ErrorCode|Troubleshooting' -count=1`) and `make authz-doc` produces the committed matrix; fuzz target for the sign-in body decoder if the SSO ones have one (`make fuzz-api` pattern).
- [ ] **Steps 2-5:** fail → implement → pass (`go test -tags integration ./internal/api/... ./cmd/alice/... -race -count=1`; `make authz-doc` then no diff; coverage floor for `api` not lowered) → commit (`feat(api): directory sign-in, directory settings and tests`).

---

### Task 6: Web interface

**Files:** Create `web/src/api/ldap.ts`, `web/src/components/directories/{DirectoriesSettings,DirectoryDialog,DirectoryMappings,TestSignInDialog}.tsx` (+ `*.module.css`, tests); Modify `web/src/pages/{LoginPage,SettingsPage,UsersPage,AccountPage}.tsx`, `web/src/api/{types.ts,queryKeys.ts,sso.ts}`, `web/src/components/stepup/*` (directory step-up asks for the directory password), `web/src/locales/{en,tr}.json` (texts and audit labels), `web/src/test/{fixtures.ts,handlers}`; Test per component; `web/e2e/ldap.spec.ts` is Task 7.

**Behavior:**
- Sign-in page: when at least one directory is enabled, a **Sign in to** select above the password form (*Local* default, then each directory by name); the chosen route posts to `/auth/ldap/{id}/login`; the result flows into the existing MFA/enrolment phases of `LoginPage`; a full-session result goes straight in. Refusal messages use the generic `errors.ldap.*` texts. The select is hidden when no directory is enabled.
- Settings: a **Directories** tab (icon from `icons.ts`) with a table of directories (name, addresses, MFA, enabled, version), the add/edit dialog (all fields of Task 3 with defaults and two ready-made presets that only fill fields: *Active Directory* (`sAMAccountName`, `objectGUID`, group filter with `1.2.840.113556.1.4.1941`) and *OpenLDAP* (`uid`, `entryUUID`, `(member={dn})`)), the password field kept in component state and cleared on submit (`gcTime: 0`), writes through `useStepUp().run`, field errors via `fieldErrorsOf`; mappings table (group, role; the Admin confirm dialog like SSO); **Test connection**; **Test sign-in** dialog (user, password: shows the groups found and the role that would be given; the password field cleared and never stored); a delete dialog that explains "switch it off".
- People & access: `auth_source==='ldap'` shows the badge **Directory** and the directory name (same read-with-`retry:false` pattern as SSO); no role select; no **Set a new password**; **Reset two-factor sign-in** stays; Account page shows a note that the directory manages the password and keeps Alice's TOTP controls; API tokens page shows the same "no tokens for directory users" note.
- Step-up: for a directory user the dialog asks for the directory password (and the code when the directory requires it) and calls `POST /auth/ldap/stepup`.
- i18n: every new key in `en` and `tr` with identical placeholders (`make i18n-check`); audit labels for every new action: `ldap.directory_created|changed|deleted|tested`, `ldap.signin_tested`, `ldap.mapping_created|deleted|denied`, `auth.ldap.denied`, `ldap.admin...` as emitted (grep the Go sources and run `npm test` to learn the exact list).

- [ ] **Step 1: Write the failing tests** (vitest + MSW, no unhandled requests): login select visible only with an enabled directory; posting to the right route; MFA phases reused; generic error text; settings tab renders and the dialog validates; password never in the DOM after submit and cleared on close; the presets only fill fields; test sign-in shows groups and role and clears the password; people page badge and hidden controls; account note; step-up dialog asks for the password; locale parity; audit label test; coverage thresholds not lowered (raise them if the measured value allows).
- [ ] **Steps 2-5:** fail → implement → pass (`make web-lint`, `cd web && npm test`, `make i18n-check`, `make web-coverage`) → commit (`feat(web): directory sign-in selector, directories settings and people page`).

---

### Task 7: End-to-end, documents, security review

**Files:** Create `test/images/openldap/` (Dockerfile pinned, bootstrap LDIF, TLS material generated at build or start), `web/e2e/ldap.spec.ts`; Modify `deploy/docker-compose.e2e.yml`, `deploy/dev/check-hardening.sh` expectations if needed, `Makefile` (a `fuzz-ldap` target in the `fuzz-nightly` list), `docs/*`, `CHANGELOG.md`, `docs/superpowers/specs/alice-v1/00-decisions.md` and `01-product.md` (a short ruling that LDAP sign-in is now delivered), `tools/docscheck/required.txt` (pin the security sentences), `docs/security/reviews/ldap-signin.md`.

- [ ] **Step 1: e2e.** An OpenLDAP service in the e2e compose (read-only, non-root where the image allows it, `cap_drop: ALL`, `no-new-privileges`, a healthcheck, `depends_on ... service_healthy`), passes `make e2e-hardening-check`. Playwright tests: an admin adds a directory (Active Directory preset values adapted to the test directory), runs Test connection and Test sign-in, maps a group to Operator, switches it on; a directory user signs in (MFA on: enrolment, then the app), a second sign-in with the TOTP; a user in no mapped group is refused with the generic message; a wrong password gets the same message; removing the user from the group in LDAP and signing in again is refused and the open session ends; the local administrator still signs in with the directory disabled and unreachable; the audit log shows `ldap.*` entries with no password; the rate limit message after repeated failures.
- [ ] **Step 2: Documents** (verify every statement against the code): `docs/admin-guide.md`: a new section "LDAP and Active Directory" after "Single sign-on" (setting up a directory with the two presets, the service account (read-only, what it needs), `ldaps://` and the authority field, the user and group filters and the AD nested-group template, the sign-in name and unique id attributes, MFA per directory and what turning it off means, group to role mapping and the Admin switch, Test connection and Test sign-in, how directory users appear on People & access, what happens when a user is disabled or removed from a group (open session rules), refused sign-ins and the audit reasons, rate limits and why, break-glass), and fix the "Active Directory" sentence that says direct sign-in is planned (it now points to the new section while keeping the OIDC routes as the alternative); `docs/troubleshooting.md` sections for the new codes plus a "Directory sign-in refused" walk-through (service account bind failing, certificate errors, filters matching nothing or two entries, groups empty, nested groups, clock/time, firewall to port 636); `docs/security-overview.md` (the directory password passes through Alice, LDAPS to the directory in the port table (636), service account secret storage, MFA responsibility is Alice's by default for directories, rate limits); `docs/README.md` link; `docs/dev/dependency-updates.md` (done in Task 2: check); `CHANGELOG.md`. State clearly what was not run: a real AD or Samba AD.
- [ ] **Step 3: Security review** document `docs/security/reviews/ldap-signin.md`: threat list (LDAP injection, anonymous bind trap, user enumeration, lockout through Alice, password handling in memory and logs, TLS downgrade and certificate checks, SSRF through the address field (the guarded dial), referral following, service account over-privilege, group manipulation by directory admins, session lifetime after directory changes, MFA bypass by flipping the setting, identity confusion (name vs unique id), local account takeover by name or e-mail) each with the control and the test that pins it.
- [ ] **Step 4: Final verification:** `gofmt -l cmd internal` (empty); `go vet ./...`; `golangci-lint run` (0 issues, with the project's tag sets as `make lint` does); `go test -race ./...`; `make coverage` (floors); `make web-lint web-coverage i18n-check docs-check matrix-check`; `make e2e-up e2e-hardening-check e2e` then `make e2e-down`; `make vuln` (the new module must be clean: record the result); `make release-symcheck`; `make build` (CGO off, no testify linked). Report exact output; list what could not run and why.
- [ ] **Step 5: Commit** (`docs(auth): LDAP and Active Directory sign-in guide, security review and e2e`), then the final whole-branch review (most capable model, with the Review Focus list and the security review document as input) and one fix wave, then a fast-forward of `main`.

---

## Self-Review

- **Spec coverage:** directory settings, tables and secret (Task 1, 3); `ldaps://` client with verification, limits, referrals off, exact-one lookup (Task 3); escaping (Task 2); sign-in flow steps 1-9 (Tasks 4, 5: limits first and empty-password refusal in Tasks 3 and 5, MFA per directory in Task 4, step-up in Task 4); first-sign-in provisioning, names, unique id (Tasks 2, 4); roles and the Admin switch (Tasks 3, 4); administrator interface incl. tests (Tasks 3, 5, 6); audit (Tasks 3, 4, 5, 6); documents and security notes (Task 7); tests (every task, e2e in Task 7); open items L1 (documented as not run), L2 and L3 (rulings 6 and 5).
- **Placeholders:** none; names, files and tests are specific. Where the plan says "decide and record" (ALC code reuse in Tasks 4 and 5) the options are listed and the implementer must write the decision in the commit and the report.
- **Types:** `Directory`, `DirectoryInput`, `DirectoryPatch`, `Identity`, `Entry`, `Client`, `LDAPIdentity`, `LoginResult`, `SignInLDAP`, `StepUpLDAP`, `RefuseLDAP`, `ldapx.*` are defined before use.
- **Review Focus** lines each map to named tests.
