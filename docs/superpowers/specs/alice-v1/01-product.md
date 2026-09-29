## 1. Product Summary

Alice is a self-hosted platform that keeps track of two things every IT team struggles to keep under control: SSH keys and TLS certificates. It scans servers and Azure Key Vaults, shows every key and certificate in one place, warns before certificates expire, deploys renewed certificates to Nginx servers automatically and safely, and rotates SSH keys on a schedule. It runs on the customer's own server (two containers, one installer), keeps all secrets encrypted, and records every action in a tamper-evident audit log. The interface is available in English and Turkish and is written for non-technical users.

### Target customers

| Segment | Typical situation | What they need from Alice |
|---|---|---|
| Regulated Turkish enterprises (banks, insurers, public-sector suppliers) | Often air-gapped, subject to KVKK/BDDK expectations, audit pressure | Offline install and licensing, audit trail, role separation, no telemetry, Turkish UI |
| Internet-connected mid-size companies | Hundreds of Nginx/Linux servers, some Azure Key Vault, small ops team | Expiry visibility, safe automatic deployment, fewer outage incidents |
| Managed service providers (MSPs) | Many customer servers, staff turnover | Central SSH key inventory and rotation, clear roles, per-target licensing that scales with use |

v1 sizing target: hundreds of servers and thousands of certificates on a single host.

### Value proposition versus ManageEngine Key Manager Plus

| Area | Alice | Key Manager Plus (positioning) |
|---|---|---|
| Install | One tarball, `sudo ./install.sh`, browser wizard; 2 containers | Heavier Windows/Linux installer, more components to size and maintain |
| Licensing | Annual license file signed offline; counted by managed targets only (certificates and keys are unlimited); exceeding the limit only blocks adding targets | Edition- and key-count-based pricing tiers |
| Air-gap | First-class: images bundled in the package, offline license issuing, no phone-home, no telemetry | Possible but not the primary design |
| Language | English and Turkish from v1; new languages by adding one JSON file | English-centric |
| Safety of deployment | Backup, atomic write, `nginx -t`, reload, TLS handshake verification, automatic rollback | Broader coverage, less focus on verified rollback |
| Security posture | Small static Go binary, envelope encryption, mandatory MFA, hash-chained audit log, published `SECURITY-REPORT.md` | Mature product, larger surface |
| Scope | Deliberately narrow: SSH keys, Nginx certificates, Azure Key Vault | Very broad (many platforms, features) |

Alice does not try to match breadth. It wins on simplicity, predictable cost, air-gap suitability, Turkish language support, and verified safe deployment.

---

## 2. Personas and User Scenarios

### 2.1 Personas

**Admin (Aylin, IT infrastructure lead)**
- Installs and owns the platform; sets up SMTP, SSO, backups, and the license.
- Adds targets and credentials, defines rotation policies, manages users and roles.
- Is the only person who can download a private key (with a reason and MFA re-prompt).
- Success: the platform runs unattended, no surprise outages, license never lapses unnoticed.
- Role: Admin (everything).

**Operator (Emre, systems engineer / on-call)**
- Works daily with certificates and keys: checks what is expiring, runs discovery, deploys certificates, adds or removes SSH keys.
- Can view targets (metadata only) but never credentials; does not manage users, licensing, or policies, and does not see the audit log.
- Success: finds expiring certificates early and renews them with one safe action.
- Role: Operator (view, discovery, deploy, add/remove keys).

**Auditor (Deniz, internal audit / compliance officer)**
- Needs evidence: who has access to which servers, which keys are old, who did what and when.
- Reads inventory, license status, and the audit log, exports inventory and the audit log; changes nothing and cannot view settings.
- Success: produces an audit report without asking engineers for screenshots, and can prove the log was not altered.
- Role: Auditor (read-only plus audit log view/export).

### 2.2 User scenarios

Each scenario lists the persona, the story, and acceptance criteria (AC).

**S1. First-time setup (Admin)**
As an Admin, I install Alice and finish the wizard so I can add my first server the same day.
- AC1: `tar xzf`, `sudo ./install.sh`, then the browser wizard completes with steps: language, admin + TOTP, recovery passphrase, HTTPS certificate, SMTP (optional), license (upload or evaluation), first target.
- AC2: The wizard-created admin is a local account with MFA enabled and cannot be created without TOTP enrollment.
- AC3: The wizard shows Alice's own SSH public key and a one-line command to authorize it on the first server.
- AC4: Choosing "evaluation" needs no license file: 30 days from installation, up to 5 targets. Warnings appear 7, 3, and 1 days before the end; the end of evaluation enters lock mode directly (no grace period), and data is preserved. Restoring a backup does not reset the evaluation period.
- AC5: On an air-gapped host the same steps work with no internet access.
- AC6: The wizard generates a backup key pair and enables unattended daily backups without storing the recovery passphrase on the host, and strongly recommends configuring syslog/SIEM forwarding.

**S2. Operator sees certificates expiring in 30 days**
As an Operator, I open the dashboard and see which certificates expire within 30 days so I can act before an outage.
- AC1: The dashboard lists certificates expiring within 30 days, sorted by soonest expiry, with target, file path or Key Vault name, and Nginx `server_name`.
- AC2: Filters work by expiry window, target, and source (Nginx, Key Vault, uploaded).
- AC3: Expired certificates are visually distinct from soon-to-expire ones.
- AC4: If SMTP is configured, an expiry alert email is sent for the same certificates.
- AC5: Text and errors are available in English and Turkish.

**S3. Discover certificates on an Nginx server (Operator/Admin)**
As an Operator, I run discovery on an Nginx target to find all certificates it serves.
- AC1: Discovery runs `nginx -T`, reads `ssl_certificate` paths and `server_name`, and reads the certificate files. All remote commands go through the root-owned `alice-helper` static binary installed on the target by the Admin (sudoers profile `nginx`).
- AC2: Private key files are not read during discovery.
- AC3: Alice never edits nginx configuration files.
- AC4: Discovered certificates appear in inventory with their locations; a repeated run updates rather than duplicates them.
- AC5: If the server uses an unsupported layout (for example nginx in a container, or TLS configured only in a `stream {}` block), the UI says so in plain language and makes no changes.

**S4. Manual certificate deploy with automatic rollback (Operator)**
As an Operator, I deploy an uploaded or CSR-generated certificate to an Nginx server and trust that a bad certificate cannot break the site.
- AC1: Sequence is: back up existing files, atomically write new cert and key (key mode 0600), `nginx -t`, `systemctl reload nginx`, TLS handshake check that the new certificate is served.
- AC2: If any step fails, the backup is restored, `nginx -t` is run again, nginx is reloaded, and the deployment is marked failed with a plain-language reason and an error code (`ALC-<AREA>-<NNNN>`).
- AC3: A deliberately mismatched certificate and key in an integration test leaves the server serving the original certificate.
- AC4: The deployment and its result are recorded in the audit log.

**S5. Key Vault renewed certificate auto-deploys to Nginx (Admin configures, Operator benefits)**
As an Admin, I bind a Key Vault certificate to Nginx servers so that when Key Vault renews it, the new version reaches the servers without manual work.
- AC1: Alice polls the vault (default every 15 minutes) and detects a new certificate version.
- AC2: For each bound Nginx location it runs the S4 deploy sequence, using the cert-backing secret to obtain the private key.
- AC3: A failure on one server rolls back that server only and raises an alert; other servers are not affected.
- AC4: The vault is added with a Service Principal (client secret or certificate) or Managed Identity; the UI shows which Azure roles are needed for monitor-only, deploy, and import.
- AC5: Nothing is deployed while the license is in lock mode; after renewal, deploys that were pending during lock wait for Admin confirmation.
- AC6: A new version is detected by its version id and X.509 thumbprint (the vault's Updated timestamp is only a pre-filter). Whether the Key Vault Reader role alone is enough for data-plane listing of certificates and keys is (verify), to be confirmed by the real-Azure test suite in Phase 5. Key Vault Secrets User is required for deploy, and the docs recommend scoping it to the individual cert-backing secrets.

**S6. SSH key rotation with overlap (Admin configures policy)**
As an Admin, I enable a rotation policy for platform-managed SSH keys so that old keys are retired safely.
- AC1: Policies are disabled by default, admin-only, and apply only to platform-managed keys.
- AC2: Before each run the Admin can view a dry-run preview, and a notification is sent.
- AC3: Rotation adds the new key, verifies login with it, keeps the old key for the overlap period (default 7 days, configurable), then removes the old key.
- AC4: If any step fails, the old key is never removed and the rotation is reported as incomplete.
- AC5: Alice refuses to remove its own connection key.
- AC6: Rotation is paused in lock mode; an old-key removal that falls due during lock stays in the overlap state until a valid license is uploaded, then the new key is re-verified and a fresh dry-run notice is sent before removal.

**S7. Add and remove an SSH key on a server (Operator)**
As an Operator, I add or remove an authorized key on a Linux target.
- AC1: Discovery scans `authorized_keys` under `/root`, `/home/*`, and custom `AuthorizedKeysFile` paths from `sshd_config`.
- AC2: If `AuthorizedKeysCommand` is set, the UI warns and skips management for that host.
- AC3: Add and remove actions show the target, OS user, and key fingerprint for confirmation and are audited.
- AC4: A changed host key blocks all operations on the target and triggers an alert; a new host key needs explicit user confirmation (trust on first use).

**S8. License expires, grace, lock, renewal (Admin)**
As an Admin, I am warned early and, if I miss the date, nothing breaks abruptly.
- AC1: Banner and email to admins at 60, 30, 14, 7, and 1 days before `valid_until`.
- AC2: The license is active while the current time is before `valid_until` (UTC instant). From `valid_until` for the next 168 hours is the grace period: red banner to all users; all features still work.
- AC3: After grace, lock mode: scheduled jobs stop (discovery, auto-deploy, rotation); user-initiated external changes (deploy, add/remove key, import) are refused with `license.locked`; in-flight operations complete or roll back safely; no data deleted, no certificates revoked, no other external changes.
- AC4: In lock mode login, license upload, backup/restore, audit log view and export, and inventory export still work.
- AC5: Certificate expiry alert emails continue in lock mode with a "license expired" note.
- AC6: Uploading a renewed license file (issued by the vendor from the customer's Installation ID) takes effect immediately. Recurring read-only jobs (discovery, Key Vault polling, expiry checks) resume without restart; pending external-change jobs wait for Admin confirmation.
- AC7: Exceeding `max_targets` only blocks adding new targets; it never locks. A renewal with a smaller limit than the current target count keeps existing targets working with a persistent banner and only blocks adding targets.
- AC8: Setting the system clock backwards does not extend the license; the admin sees a warning. A suspicious forward jump (more than 48 hours beyond elapsed uptime) raises a warning and cannot trigger grace or lock until 24 hours of uptime at the new time. Certificate `notBefore` dates are never used in license calculations; they only raise a "system clock appears to be behind" warning.

**S9. Restore from backup after server loss (Admin)**
As an Admin, I rebuild the platform on a new server from the latest backup.
- AC1: Automatic daily backups are kept (last 14), encrypted to the wizard-generated backup public key (the host never stores the passphrase); `alicectl backup` creates one on demand.
- AC2: On a fresh install, `alicectl restore` with the backup file and recovery passphrase restores the database and master key.
- AC3: After restore, existing credentials and private keys decrypt correctly, the audit chain verifies, and the Installation ID is unchanged so the existing license remains valid.
- AC4: With a wrong or lost passphrase the restore fails with a clear message; the vendor cannot recover the backup.
- AC5: CI runs backup, wipe, restore, verify for every release. Restore is a command-line action only (no web restore button).

**S10. Auditor produces evidence (Auditor)**
As an Auditor, I review access and activity without being able to change anything.
- AC1: Auditor can view inventory (targets, certificates, SSH keys, key locations) and the audit log; every mutating action is unavailable.
- AC2: Audit entries show who, when, IP, what, and result; the UI shows whether the hash chain verifies.
- AC3: Audit log and inventory can be exported.
- AC4: Optional syslog/SIEM forwarding is delivering events when configured by the Admin.
- AC5: Operators cannot open the audit log.
- AC6: The dashboard shows the daily audit head hash so it can be recorded offline.

**S11. Sign in with SSO or local account (all roles)**
As a user, I sign in through my company identity provider, while the Admin keeps a local break-glass account.
- AC1: OIDC works with Entra ID, AD FS, and Keycloak (delivered in Phase 7; Phase 1 has local accounts with TOTP only); IdP groups map to Admin, Operator, or Auditor. By default SSO users can be at most Operator or Auditor; an Admin can enable "SSO users may be Admin". MFA for SSO users is delegated to the identity provider.
- AC2: Local accounts require TOTP and have recovery codes; the last enabled local Admin cannot be disabled, deleted, or demoted; passwords are at least 12 characters and checked against a local breached-password list.
- AC3: Sessions expire after 30 minutes idle or 12 hours absolute; sensitive actions ask for MFA again.
- AC4: Repeated failed logins cause progressive delay and temporary lockout, per IP and per account.

**S12. Update to a new version (Admin)**
As an Admin, I upgrade with confidence that a failed update rolls itself back.
- AC1: `sudo ./alice-update.sh alice-1.1.0.tar.gz` runs: automatic backup, load image, migrations, health check.
- AC2: If the health check fails, the previous version and data are restored automatically.
- AC3: The update works offline using the images bundled in the tarball.

---

## 3. Scope: v1 vs Later

### 3.1 v1 features

| Area | Feature |
|---|---|
| Install and ops | Single-host Docker Compose (`alice`, `postgres`); `install.sh` with browser wizard; offline/air-gap package; `alice-update.sh` with auto-rollback; daily encrypted backups (keep 14), `alicectl backup`/`alicectl restore`; `install.sh --restore-mode` |
| Authentication | Local accounts with mandatory TOTP and recovery codes; OIDC SSO (Entra ID, AD FS, Keycloak) with group-to-role mapping; wizard admin is local + MFA |
| Authorization | Three roles (Admin, Operator, Auditor); personal API tokens (scoped, expiring, hashed) |
| Audit | Append-only hash-chained audit log; view and export; optional syslog/SIEM forwarding |
| Secrets | Envelope encryption (AES-256-GCM, master key file); private key download by Admin only with reason and MFA re-prompt; Alice's own Ed25519 SSH key |
| Licensing | Offline signed license per installation; managed-target metric; 30-day evaluation (5 targets); warnings, 7-day grace, lock mode; clock-tampering protection; `licensectl` vendor CLI |
| Targets | Nginx servers (Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 8+), generic Linux SSH hosts, Azure Key Vaults; host key pinning with TOFU confirmation; remote actions via the root-owned `alice-helper` static binary (sudoers profiles `nginx` and `linux`) |
| Certificates | Inventory; Nginx discovery; manual upload; in-platform CSR generation; deploy to Nginx with verify and auto-rollback; Azure Key Vault as source of truth with auto-deploy on renewal |
| Azure Key Vault | Certificates (list, versions, expiry, policy, renewal detection, import); keys inventory and alerts; secrets metadata only; Service Principal or Managed Identity; polling (default 15 min); Azure public cloud |
| SSH keys | Inventory (`authorized_keys`, host keys); generate; deploy public key; remove; scheduled rotation with overlap, dry-run, and notification |
| Alerts | Certificate and key expiry emails (default thresholds 60/30/14/7/1 days, Admin-configurable), license warnings, rotation and deployment failure alerts, host key change alerts |
| Dashboard | Expiry overview, filters, license status banner |
| UI | English and Turkish via JSON locale files; plain-language messages |

### 3.2 Deferred items

| Item | Target | Reason for deferral |
|---|---|---|
| ACME / Let's Encrypt | v2 | Needs inbound challenges or DNS integrations; air-gapped customers cannot use it; Key Vault and CSR paths cover v1 sourcing |
| LDAP authentication | v2 | Local + MFA and OIDC SSO cover the target IdPs; LDAP adds a separate auth path to secure and test |
| License server | v2 | Offline signed files suit air-gapped customers and a solo vendor; file format is already designed to be distributed by a server later |
| Editions | v2 | `features` field is present in the license but unused; one product tier keeps pricing and support simple |
| Azure Managed HSM | Later | Different API and permission model; small share of v1 customers |
| Key Vault key rotation | Later | Higher risk (breaks dependent applications); v1 gives inventory and alerts only |
| Containers / k8s nginx, ingress-nginx, Nginx Plus API | Later | Different deployment mechanics and reload semantics than host-based nginx over SSH |
| Apache, IIS, HAProxy, Windows targets | Later | Each needs its own provider and test matrix; the provider interface allows adding them |
| App Gateway, Front Door, App Service binding | Later | Azure-side deployment targets outside the Key Vault-to-Nginx flow |
| Gov and China Azure clouds | Later | Separate endpoints and test environments; public cloud only in v1 |
| Subscription-wide Key Vault discovery | Later | Requires broader Azure permissions than least privilege; vaults are added one by one in v1 |
| HA and external database | v2 | v1 targets a single host; the bundled PostgreSQL keeps install and backup simple |
| WebAuthn, dual-approval private key download, boot passphrase/TPM/PKCS#11 master key protection, audit log pruning | v2 | Local TOTP plus IdP MFA, full-disk encryption (required by the docs), and a configurable master key path cover v1; the master key residual risk is stated in `SECURITY-REPORT.md` |
| Runtime-loaded provider plugins | Not planned | Providers are compile-time for security |

---

## 4. Release Plan

### 4.1 v1.0 (phases 0 to 8)

| Phase | Deliverable | Exit criterion |
|---|---|---|
| 0 | Skeleton and CI | `compose up` works, empty UI in EN/TR, CI green |
| 1 | Core: auth, MFA, RBAC, audit, secret store | Wizard admin, TOTP login, three roles behave differently, audit chain verifies |
| 2 | Licensing and `licensectl` | Issue and upload work; fake clock shows warnings, grace, lock |
| 3 | Provider framework and Linux/SSH targets | Add host, confirm host key, SSH keys appear in inventory |
| 4 | Nginx certificate discovery and deploy | Certificates listed; deploy works; bad certificate auto-rolls back |
| 5 | Azure Key Vault | Add vault; certificates and keys visible; KV renewal auto-deploys to Nginx |
| 6 | SSH key lifecycle and rotation | Generate, deploy, remove; rotation with overlap |
| 7 | Alerts, dashboard and SSO | Expiry emails, dashboard, filters, OIDC sign-in with group-to-role mapping |
| 8 | Packaging and release | `install.sh`, update, backup/restore test, docs, security report, release checklist |

### 4.2 v1.x candidates

- Additional UI languages (a new JSON file each), based on customer requests.
- Nginx and Key Vault fixes and compatibility additions found in customer environments.
- Further Nginx layout variants supported by discovery, within the host-based scope.

### 4.3 v2 candidates

- License server distributing the same signed license files; unreachability never locks.
- ACME / Let's Encrypt as a certificate source.
- LDAP authentication.
- Editions using the license `features` field.
- High availability and external database.
- Providers for containers/k8s nginx, Apache, IIS, HAProxy; Managed HSM; Key Vault key rotation; App Gateway/Front Door/App Service; Gov/China clouds; subscription-wide vault discovery (prioritized by customer demand).
