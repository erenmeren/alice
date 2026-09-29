# Alice — Agreed Design Decisions (source of truth for all spec authors)

Working product name: **Alice** (self-hosted SSH key & TLS certificate management platform; alternative to ManageEngine Key Manager Plus). Sold by a solo vendor with limited software background under annual licenses. All technical content in English.

## Product decisions (approved by the owner)
- Customers: mixed. Regulated Turkish enterprises (often air-gapped, KVKK/BDDK expectations) AND internet-connected mid-size companies/MSPs.
- Scale target v1: hundreds of servers, thousands of certificates. Single-host deployment.
- License metric: number of **managed targets** (Nginx servers + generic Linux SSH hosts + Azure Key Vaults). Certificates/keys are NOT counted. Exceeding the limit only blocks adding new targets; never locks.
- License `features` field exists for future editions (not used in v1).
- v1 has NO license server. Vendor signs licenses offline with `licensectl` CLI (Ed25519 private key held only by vendor). Format is designed so a v2 license server can distribute the same signed files. Server unreachability must never cause lock (v2).
- SSH key lifecycle: inventory + generate + deploy public key + remove + **scheduled automatic rotation** (v1). Rotation rules: only platform-managed keys; add-new-verify-then-remove-old with configurable overlap (default 7 days); policies disabled by default, admin-only; dry-run preview + notification before each run; paused in license lock; incomplete rotation never removes old key.
- Generic (non-Nginx) Linux hosts can be added as SSH targets; they count toward the license limit.
- Certificate sourcing: manual upload + in-platform CSR generation + **Azure Key Vault as source of truth** (KV self-renews self-signed / DigiCert / GlobalSign integrated CA certs); platform detects new KV cert versions and auto-deploys to bound Nginx servers. ACME/Let's Encrypt deferred to v2.
- Authentication: local accounts with **mandatory TOTP** + **OIDC SSO** (Entra ID, AD FS, Keycloak) with group→role mapping. Wizard-created admin is always local + MFA (break-glass). LDAP deferred to v2.
- UI languages: English + Turkish from v1, JSON translation files (`locales/en.json`, `locales/tr.json`), new languages by adding a file. UI and errors written for non-technical users.

## Architecture (approved)
- Go backend single binary `alice` (REST API + OpenAPI, serves embedded React/TypeScript SPA built with Vite, react-i18next, runs background jobs). Terminates HTTPS itself (port 443).
- PostgreSQL (bundled in Docker Compose, internal network only). Job queue in PostgreSQL (`FOR UPDATE SKIP LOCKED`). 2 containers: `alice`, `postgres`.
- Modules: `auth`, `rbac`, `audit`, `secrets`, `inventory`, `jobs`, `providers`, `license`, `notify`, `i18n` (UI), `api`.
- Providers are compile-time Go plugins implementing a common interface with capability discovery (`Discover`, `DeployCertificate`, `ListAuthorizedKeys`, `AddAuthorizedKey`, `RemoveAuthorizedKey`, `TestConnection`, ...). v1 providers: `azurekv`, `nginx` (built on `linuxssh` connector), `linuxssh`. No runtime code loading (security).
- Why Go: small static binary, small CVE surface, strong crypto/ssh/x509 stdlib, official Azure SDK, compiled code makes license-check removal harder than interpreted languages.

## Data model (approved, simplified)
users, sessions, roles (+TOTP, OIDC mapping), api_tokens (hashed), targets (type nginx|linux|azure_key_vault; license counts these), credentials (always encrypted), certificates + certificate_locations (target, file path or KV name, nginx server_name), ssh_keys + ssh_key_locations (server, OS user, managed flag, rotation policy), deployments, rotations (steps + rollback info), jobs, audit_log (append-only, hash chain), license (+ status history), settings, host_keys (pinned).

## Secrets protection (approved)
- Envelope encryption: random master key generated at install in `/opt/alice/keys/master.key` (file, not DB, readable only by app). Per-secret random DEK, AES-256-GCM; DEK wrapped by master key.
- Private keys never in logs/errors/API responses; download is an explicit admin action with mandatory reason + MFA re-prompt, audited.
- Recovery passphrase set in wizard. `alice backup` = single encrypted file (DB dump + master key) encrypted with passphrase (Argon2id + AES-256-GCM). `alice restore` needs file + passphrase. Lost passphrase = unrecoverable backups (by design; vendor cannot recover).
- Platform generates its own Ed25519 SSH key at install; wizard shows public key + one-line command to authorize it. Host key TOFU with explicit user confirmation; changed host key blocks all operations on that target + alert.

## Integrations (approved boundaries)
### Azure Key Vault only (v1)
- Certificates: list, versions, expiry, policy, detect KV auto-renewals, import uploaded certs.
- Keys: inventory (type, size, expiry, enabled), alerts. No key rotation in v1.
- Secrets: metadata only (name, expiry); contents never read except cert-backing secret needed to deploy private key to Nginx.
- Auth: Service Principal (client secret, or certificate — recommended), Managed Identity when running on Azure VM.
- Least privilege table: monitor-only = Key Vault Reader; deploy to Nginx = + Key Vault Secrets User; upload/import = + Key Vault Certificates Officer. Legacy access policy model also supported.
- Change detection by polling (default every 15 min). No Event Grid (requires inbound internet).
- Private endpoint vaults work if network-reachable. Azure public cloud only.
- Deferred: Managed HSM, KV key rotation, App Gateway/Front Door/App Service binding, Gov/China clouds, subscription-wide auto-discovery of vaults (v1 adds vaults one by one).
### Nginx over SSH (v1)
- Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 8+, standard nginx package.
- Key auth; dedicated service user with restricted sudoers (only allowed commands); no root login.
- Discovery: `nginx -T`, parse `ssl_certificate` paths + `server_name`, read cert files. Private key files NOT read during discovery.
- Deploy: backup existing files → atomic write new cert+key (key 0600) → `nginx -t` → `systemctl reload nginx` → TLS handshake verification that the new cert is served → on any failure restore backup, `nginx -t`, reload.
- Never edits nginx config files; only cert/key files.
- Deferred: nginx in containers, k8s ingress-nginx, Nginx Plus API, Apache/IIS/HAProxy, Windows.
### Linux SSH keys
- Scan `authorized_keys` under `/root`, `/home/*`, plus custom `AuthorizedKeysFile` from sshd_config; inventory host keys. Detect `AuthorizedKeysCommand` and warn/skip management.
- Platform must refuse to remove its own connection key.

## Licensing (approved)
- License file: JSON payload (license_id, customer, installation_id, issued_at, valid_from, valid_until, max_targets, features, format version) signed with Ed25519; public key embedded in binary.
- Activation: wizard shows Installation ID → customer emails it → vendor runs `licensectl issue --installation <ID> --customer "X" --targets 100` → valid 12 months from issuance → customer uploads file. Renewal is identical; takes effect immediately.
- License bound to installation ID; restore from backup preserves installation ID.
- Evaluation mode: 30 days, max 5 targets, no license needed.
- Timeline: warnings to admins (banner + email) at 60/30/14/7/1 days before expiry. Expiry day + 7 grace days: red banner to all users, everything works. After grace: LOCK mode.
- Lock mode: scheduled jobs stop (discovery, auto-deploy, rotation); in-flight operations complete or roll back safely; rotations never remove old keys; no data deletion, no cert revocation, no external changes. Still available: login, license upload, backup/restore, audit log + inventory export. **Certificate expiry alert emails continue** with a "license expired" note (owner decided yes).
- Clock tampering: store high-water mark of observed time hourly (encrypted+MAC'd with master-key-derived key); if system clock < high-water mark, use high-water mark for license math + warn admin. Also use max notBefore of discovered certificates as a lower bound of real time. Forward clock jump: warn first, no immediate lock; vendor can issue a correction license.

## Security (approved)
- Roles: Admin (everything), Operator (view, discovery, deploy, add/remove keys), Auditor (read-only + audit log view/export). Private key download: Admin only + reason. Targets/credentials/rotation policy/users/SSO/license/backup/settings: Admin only. Operator cannot see audit log.
- Passwords Argon2id, min 12 chars, local breached-password list check. TOTP mandatory for local accounts + recovery codes.
- Sessions: HttpOnly, Secure, SameSite=Strict; idle 30 min, absolute 12h; CSRF protection. MFA step-up for sensitive ops.
- Rate limiting: login per IP + per account progressive delay + temporary lockout; general API limit.
- Personal API tokens: scoped, expiring, hash-only storage.
- Audit: who/when/IP/what/result, hash chain tamper detection, optional syslog/SIEM forwarding.
- Secure defaults: HTTPS only, DB not exposed, non-root container, read-only FS, no telemetry.
- Threat model: STRIDE. Top scenarios: platform compromise (holds access to all servers), DB/backup theft, malicious/compromised operator, MITM, license bypass, supply chain.
- Process: gosec, govulncheck, Trivy (deps+images), gitleaks in CI; security review at each phase; release checklist; `SECURITY-REPORT.md` with known & residual risks.

## Operations (approved)
- Install: `tar xzf alice-1.0.0.tar.gz && cd alice && sudo ./install.sh` → browser wizard. Air-gapped: package bundles container images as tar.
- Wizard: language → admin + TOTP → recovery passphrase → HTTPS cert (temporary self-signed or upload) → SMTP (optional) → license (upload or evaluation) → first target.
- Update: `sudo ./alice-update.sh alice-1.1.0.tar.gz` → auto backup → load image → migrations → health check → auto rollback on failure.
- Backups: daily automatic, keep 14, encrypted with recovery passphrase; manual `alice backup`. CI runs backup→wipe→restore→verify every release.
- Tests: TDD unit tests (fake clock for license), integration tests with real PostgreSQL + dockerized Nginx + SSH server, mocked Key Vault by default + optional real Azure suite, Playwright E2E in EN+TR, security tests (role×endpoint authz matrix, secret-leak-to-log tests, rate limit tests).
- Development phases:
  0 Skeleton & CI — compose up works, empty UI EN/TR, CI green
  1 Core: auth, MFA, RBAC, audit, secret store — wizard admin, TOTP login, 3 roles differ, audit chain verifies
  2 Licensing + licensectl — issue/upload; fake clock shows warnings/grace/lock
  3 Provider framework + Linux/SSH targets — add host, confirm host key, SSH keys in inventory
  4 Nginx cert discovery & deploy — list certs; deploy; auto-rollback on bad cert
  5 Azure Key Vault — add vault; certs/keys visible; KV renewal auto-deploys to Nginx
  6 SSH key lifecycle & rotation — generate/deploy/remove; rotation with overlap
  7 Alerts & dashboard — expiry emails, dashboard, filters
  8 Packaging & release — install.sh, update, backup/restore test, docs, security report, release checklist

## Team roles (virtual agents; coordinator = main session, final decisions & integration)
Product Manager, Security Architect, Backend Engineer, Frontend Engineer, Azure/Nginx Integration Engineer, QA Engineer, DevOps/Release Engineer, Technical Writer.

## Coordinator rulings (after section drafts)
- R1 Evaluation end (day 30): no grace; enters Lock mode directly. Warnings at 7/3/1 days before. Data preserved.
- R2 Certificate expiry alert thresholds: default 60/30/14/7/1 days, configurable by Admin.
- R3 Operator: can view targets (metadata) but never credentials. Auditor: can view license status, cannot view settings.
- R4 Unattended backups: hybrid (age-style) encryption. Wizard generates an X25519 backup key pair; public key stored on host; private key stored ONLY wrapped by the recovery passphrase (Argon2id) and embedded in each backup file. Daily backups encrypt to the public key, so the host never stores the passphrase or a passphrase-derived key. Restore = file + passphrase.
- R5 Approved: `install.sh --restore-mode`; `install.sh --uninstall` (never deletes data/backups unless `--purge` with typed confirmation). Restore is CLI-only (no web UI restore button).
- R6 Approved `alicectl` subcommands: backup, backup list, backup verify [--deep], restore, selfcheck, audit verify, setup-token --reset, support-bundle (secrets redacted). Cut: maintenance.
- R7 Approved: correction license (`replaces` field, may have earlier issued_at), Installation ID format `ALICE-XXXX-XXXX-XXXX-XXXX` with check digit, error code format `ALC-<AREA>-<NNNN>`, signed release tarball + SBOM, container UID 10001, 48h no-successful-backup alarm. Dropped: Turkish quick-start doc (docs are English-only).
- R8 Vendor licensectl signing key: passphrase-protected, offline, 2 USB copies + paper backup; documented in Security section.
- R9 Lock mode refuses all user-initiated external changes (deploy, add/remove key, import) with `license.locked`; only safe completion/rollback of in-flight ops runs.
- R10 Break-glass: last enabled local Admin cannot be disabled/deleted/demoted. OIDC users: MFA delegated to IdP (documented requirement for customers).
- R11 Accepted extra tables/columns from architecture draft (alerts, notifications_outbox, login_attempts, oidc_providers, job_attempts, managed_private_keys, targets.counts_toward_license, users.timezone).
- R12 Shared locale catalog with CI parity check (every key present in en and tr).
- R13 Remote command surface = the root-owned `alice-helper` script defined in the integrations section; architecture allowlist is aligned to it (helper wins).
- R14 Frontend UI kit: Mantine (built-in accessibility, one dependency). TOTP: pquerna/otp.
- R15 Master key: v1 supports configurable master key path (e.g. separate mount); docs REQUIRE full-disk encryption; boot passphrase / TPM / PKCS#11 deferred to v2; residual risk High stated in SECURITY-REPORT.md.
- R16 Audit: wizard strongly recommends syslog/SIEM forwarding; dashboard shows daily audit head hash for offline recording. Audit pruning deferred to v2 (no pruning in v1).
- R17 Clock: forward-jump handling (24h of uptime before a forward-jump-induced lock takes effect) and build-time floor accepted.
- R18 `alice admin reset-mfa` (host-root CLI, audited) accepted. WebAuthn and dual-approval private key download deferred to v2.
- R19 OIDC: setting "SSO users may be Admin" defaults to OFF (SSO max role Operator/Auditor) — secure default; Admin can enable.
- R20 Release public key fingerprint published on vendor website and in license delivery email. SSRF blocking and optional `from=` restriction kept. In-memory rate limiting accepted for single-host v1.
- R21 `alice-helper` is a static Go binary built from this repo, root-owned on targets, two sudoers profiles (`nginx`, `linux`); installed/updated by admin via setup snippet (Alice cannot self-update it).
- R22 Azure roles: keep Key Vault Secrets User for deploy (coordinator verified on learn.microsoft.com that Key Vault Certificate User also includes secrets/getSecret, so it is not narrower); docs recommend scoping the Secrets User assignment to individual cert-backing secrets. Key Vault Reader sufficiency for data-plane listing is confirmed by the real-Azure test suite in Phase 5.
- R23 Change detection via (current version id, X.509 thumbprint) with Updated as pre-filter. PFX: software.sslmate.com/src/go-pkcs12. nginx stream{} TLS unsupported in v1 (warn). No private-key retrieval via API tokens in v1.
- R24 Accept extra integration tables (bindings, certificate_versions, deployment_steps, rotation_steps, target_locks, kv version/thumbprint columns); rotation overlap that ends during lock stays in OVERLAP until valid license.
- R25 License timing is instant-based (UTC timestamps, no calendar/timezone ambiguity): ACTIVE while now < valid_until; GRACE while valid_until <= now < valid_until + 168h; LOCK after. Warnings at 60/30/14/7/1 days remaining computed from valid_until.
- R26 Forward clock jump: "suspicious" = wall clock advanced > 48h more than monotonic uptime since the last hourly HWM tick. A suspicious jump raises an admin warning; the new time is only allowed to trigger GRACE/LOCK transitions after 24h of monotonic uptime at the new time; after that it is accepted.
- R27 Evaluation: 30 days from installation (installation timestamp stored with installation ID); restore does not reset it; ends in LOCK without grace.
- R28 Certificate notBefore evidence is NOT used in license math (a far-future notBefore on a hostile target must never lock the platform). It only raises an admin warning "system clock appears to be behind". Overrides earlier notBefore lower-bound wording.
- R29 After renewal: recurring read-only jobs (discovery, KV polling, expiry checks) auto-resume; pending external-change jobs (deploys, rotation removals) require Admin confirmation; overdue old-key removal re-verifies the new key and sends a fresh dry-run notice first.
- R30 Smaller renewal below current target count: existing targets keep working with a persistent banner; only adding targets is blocked; no end date.
- R31 OIDC SSO is delivered in Phase 7 ("Alerts, dashboard and SSO"). Phase 1 is local auth + TOTP only.
- R32 Performance targets accepted: dashboard API p95 < 500 ms, list pages p95 < 300 ms at 5,000 certificates / 500 targets. Owner usability check at each phase end.
- R33 Accepted QA/infra assumptions: rate limits (5 failures → progressive delay, 10 → 15 min lockout, 300 req/min API), per-target locks with leases, /livez + /healthz, app DB role INSERT+SELECT only on audit_log, chunked AEAD backup format, mandatory policy on route registration, test-only "demo clock" build (never shipped; CI verifies absence in release), UI copy-paste fingerprint verification command.
