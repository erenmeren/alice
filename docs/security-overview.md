# Security Overview

This document is for security teams, auditors and procurement reviews. It describes how Alice is built and
protected, what it stores and where, and what risks remain. It can be attached to a security questionnaire. The
release's own security report, `SECURITY-REPORT.md` in the release package, carries the scan results, the residual
risks in full and the sign-off of each release.

## Architecture and data flow

Alice runs on one Linux server, in two containers started by Docker Compose: the Alice application (web interface,
API, background jobs) and its PostgreSQL database. A third container of the same image runs only for maintenance
commands (backup, restore, database update).

```
   People (browser)                        Identity provider (optional, OIDC)
        |  HTTPS 443  (TB0)                       ^  HTTPS  (TB4)
        v                                         |
 +----------------------------------------------------------------------+
 | Alice application container (TB1)                                    |
 |  user 10001, read-only file system, no capabilities                  |
 |  web UI and API | sign-in, MFA, roles | envelope encryption |        |
 |  audit log | background jobs | license | backup | audit forwarding   |
 +------+-------------------+----------------+----------------+---------+
        | PostgreSQL         | keys, state,   | SSH 22 (TB3)   | HTTPS 443, SMTP, syslog (TB4)
        | internal network   | backups        v                v
        v (TB2)              | (TB5)    Managed Linux and   Azure Key Vault, mail server,
 +-------------+             |          Nginx servers       syslog server / SIEM
 | PostgreSQL  |             v
 | no host port|      /opt/alice/{keys,state,backups} on the host disk
 +-------------+
                       Operator media (TB6): release packages, license files, backup copies
```

Data flows:

- People use the web interface over HTTPS; scripts use the API with personal API tokens ([api.md](api.md)).
- Alice connects out to the servers it manages over SSH, with its own key; on each server a small root-owned helper
  program, allowed through a narrow sudoers rule, does the privileged file work
  ([nginx-host-preparation.md](nginx-host-preparation.md)).
- Alice reads certificates from Azure Key Vault over HTTPS when vaults are configured ([azure-setup.md](azure-setup.md)).
- Alice sends e-mail through the customer's mail server and, when configured, the audit log to the customer's
  syslog server.
- Nothing flows to the vendor. Alice has **no telemetry** and makes no outbound connection other than the ones
  listed above that the customer configures.

## Trust boundaries

| Boundary | Between | Protection |
|---|---|---|
| TB0 | Browser and Alice | HTTPS (TLS 1.2 or newer), HSTS, a strict Content Security Policy, `SameSite=Strict` session cookies, a CSRF token and a same-origin check on every change, rate limits on sign-in and bad credentials. |
| TB1 | Alice process and its database and key volume | The application uses a database role that can only add and read audit entries; database triggers block changes of the audit log; the master key is a file only the container user can read. |
| TB2 | Database | Only on an internal Docker network, no published port, passwords from files (SCRAM-SHA-256), separate roles for the application and for schema changes, neither a superuser. |
| TB3 | Alice and managed servers | SSH host keys pinned on first contact and confirmed by an administrator; data from servers is treated as untrusted; a server-side helper with a fixed command set; addresses checked on every connection (no link-local or metadata addresses). |
| TB4 | Alice and cloud and customer services | TLS with certificate verification against the system authorities (plus a customer CA where configured); the same address rule. |
| TB5 | Containers and host | Non-root containers, read-only root file systems, no capabilities, `no-new-privileges`; the host scripts never act on files inside the directories containers can write. |
| TB6 | Offline media | Release packages signed (Ed25519) and verified before use; license files signed by the vendor; backups encrypted and origin-authenticated against anyone without the recovery passphrase (not against a passphrase holder: KI-14). |

## What Alice stores, and where

| Data | Where | Protection |
|---|---|---|
| Users, roles, password hashes (Argon2id), authenticator secrets, recovery codes, sessions, API token hashes | Database | Authenticator secrets encrypted with envelope encryption; passwords and tokens stored only as hashes. |
| Managed private keys (TLS keys, generated SSH keys), Alice's own SSH key, Key Vault credentials, SMTP password, identity-provider client secrets | Database | Envelope encryption under the master key. |
| Inventory: servers, certificates, SSH public keys, deployments, rotations | Database | Database access control. |
| Audit log | Database | Hash chain; insert and read only for the application. |
| License, installation record, time record | Database and `/opt/alice/state/hwm.dat` | Vendor signature (license); MAC under a key derived from the master key (installation and time record). |
| Master key | `/opt/alice/keys/master.key` | Mode 0400, owned by the container user, in a 0700 directory; full-disk encryption of the host is required. |
| HTTPS certificate and key | `/opt/alice/keys/tls.crt`, `tls.key` | Key mode 0400. |
| Database passwords | `/opt/alice/secrets/` | Root-only directory, read by the containers as Docker secrets; never in an environment variable or a log. |
| Backups | `/opt/alice/backups/` | Encrypted files, mode 0600 ([backup-restore.md](backup-restore.md)). |

Logs contain no secrets: passwords, keys, tokens and the recovery passphrase are never written to a log, an audit
entry, a job parameter or an error message, and the test suite checks this with planted values.

## Encryption

- **Envelope encryption.** Every stored secret is encrypted with its own random 256-bit data key (AES-256-GCM), and
  the data key is encrypted with the 256-bit master key (AES-256-GCM). The master key is a file on the host
  (`/opt/alice/keys/master.key`), created by the installer from the operating system's random source. Anyone who can
  read both the database and this file can decrypt the secrets; this is why the host disk must be encrypted and root
  access limited. Hardware key storage (TPM, HSM) is not part of version 1.
- **Passwords** are hashed with Argon2id.
- **Backups** use a hybrid scheme:
  - The installation has a backup key pair (X25519) and a second, installation-only sender key pair (X25519),
    created when the administrator sets the recovery passphrase.
  - The backup private key exists only inside each backup file, sealed with a key derived from the recovery
    passphrase (Argon2id, 64 MiB, 3 passes, 4 lanes; AES-256-GCM). The sender private key is kept in the database
    under the master key. The passphrase itself is never stored.
  - Each file is encrypted with a file key derived (HKDF-SHA256) from two X25519 agreements: a fresh ephemeral key
    and the installation's sender key, each with the backup public key. A file is therefore bound to the installation
    that made it **against anyone who does not know the recovery passphrase**: a file built from another backup's
    public parts does not open. This does not authenticate a file against a passphrase holder. X25519 agreement is
    symmetric, so whoever can unwrap the backup private key (the passphrase and any one backup file) computes the same
    second agreement and can build a file the passphrase opens, with a master key, database and audit chain of their
    choosing; the restore's checks then verify against that file's own contents (`SECURITY-REPORT.md` KI-14).
    Authenticating the author against a passphrase holder would need a signature by a key the passphrase does not
    reveal, checked against a trust root kept outside the installation and its backups (for example a public key the
    operator records separately and enters at restore). Version 1 has no such trust root: the recovery passphrase is
    as sensitive as the master key.
  - The content is compressed and sealed in 64 KiB chunks with AES-256-GCM; each chunk's authentication covers the
    file header and a final-chunk marker, so changed, reordered, cut or extended files are refused before the current
    data is touched.
  - The passphrase is normalised to Unicode NFKC, at least 16 characters long, and must be rated good or strong.
- **Transport.** HTTPS (TLS 1.2 or newer) for the web interface and the API; SSH to managed servers; TLS to Azure, the
  mail server and the syslog server (plain TCP or UDP to the syslog server only when chosen explicitly).

## Authentication and MFA

- Local accounts sign in with a password (at least 12 characters, checked against a list of 100,000 leaked passwords)
  and a time-based authenticator code (TOTP); MFA cannot be switched off. Ten single-use recovery codes replace a
  lost phone.
- Wrong passwords slow the account down after 5 attempts and block it for 15 minutes after 10.
- Sessions end after 30 minutes without activity and always after 12 hours.
- Sensitive actions (user and settings administration, license upload, private-key download, backups, re-pinning a
  server's host key, credentials) need a confirmation within the last 5 minutes: a fresh authenticator code, or for
  single sign-on users a fresh sign-in at the identity provider.
- Single sign-on (OpenID Connect: Entra ID, AD FS, Keycloak and others): MFA is then the identity provider's
  responsibility; the "SSO users may be Admin" setting is off by default; a local break-glass administrator always
  remains.
- API tokens are personal, scoped (`read` or `operate`), valid for at most 365 days and stored as hashes. They never
  reach the actions that need a confirmation (above), and single sign-on users cannot create them.

The full description is in [admin-guide.md](admin-guide.md#users-and-roles).

## Roles

Three roles: **Administrator**, **Operator** and **Auditor**. Every route of the API is mapped to one permission, and
every permission to the roles and token scopes that may use it; a route without a permission does not exist (a test
checks every route against every role and token). The full matrix is in [authz-matrix.md](authz-matrix.md).

## Audit log

- Every sign-in, failure, refused request and change is recorded with actor, address, object and result.
- Each entry carries the SHA-256 hash of the previous entry and its own content: changing or deleting an entry breaks
  the chain. The application's database role can only add and read entries, and triggers refuse changes for every
  role.
- Alice checks the whole chain every day and on demand (**Verify integrity**, `alicectl audit verify`). The newest
  verified hash is shown on the dashboard for recording outside Alice.
- **Forwarding** sends every entry, in order, to the customer's syslog server or SIEM (RFC 5424, over TLS by
  default), with its sequence number, hash and previous hash, so the receiver holds an independent copy and can check
  the chain. Delivery is at most once: a lost connection can lose a message, and the receiver sees the gap in the
  sequence numbers ([admin-guide.md](admin-guide.md#audit-forwarding)).
- A restore from a backup is itself recorded, naming the replaced history (its last entry), so a rollback of the
  audit log is visible.
- Exports (CSV and JSON) carry the verification result; the JSON export can be re-checked outside Alice
  ([operator-guide.md](operator-guide.md#checking-an-audit-export-outside-alice)).

## Network ports

| Direction | Port | Purpose |
|---|---|---|
| In | TCP 443 (installer option `--port`) | Web interface and API (the container listens on 8443) |
| Internal | TCP 5432 | Database, on Docker's internal network only; not published on the host |
| Internal | TCP 8081 | Health endpoint inside the container (127.0.0.1), for Docker's health check |
| Out | TCP 22 | Managed Linux and Nginx servers |
| Out | TCP 443 | Azure (`login.microsoftonline.com`, `*.vault.azure.net`) when Key Vault is used; the identity provider when single sign-on is used |
| Out | the mail server's port (25, 465 or 587) | E-mail, when configured |
| Out | TCP 6514 by default (or the port chosen) | Audit forwarding, when configured |

## Container hardening

| Container | Hardening |
|---|---|
| Alice | Runs as user 10001; read-only root file system; `/tmp` as a small memory file system without execution; all Linux capabilities dropped; `no-new-privileges`; core dumps off; limits of 2 CPUs, 1 GiB memory and 512 processes; image based on distroless `static` (no shell); never pulled from a registry (images are loaded from the signed package). |
| Database | PostgreSQL 16 pinned by digest; runs as user 70; read-only root file system; capabilities dropped; `no-new-privileges`; no published port; SCRAM-SHA-256 passwords. |
| Maintenance (migrate, admin) | Same image and hardening as Alice; started only for a command and removed afterwards. |

The schema is changed by a separate owner role (`alice_owner`) in a one-shot container, never by the running
application; neither role is a superuser.

## Supply chain

- **Signed releases.** The package lists every file with its SHA-256 checksum in `SHA256SUMS`, signed with the
  vendor's Ed25519 release key (`SHA256SUMS.sig`); the package file's checksum is signed the same way. The release
  key is separate from the license signing key, its fingerprint is published by the vendor, and the installer asks
  the operator to compare it ([install-guide.md](install-guide.md#3-check-the-package-before-you-extract-it)).
  Updates are accepted only when signed by a key the installation already trusts.
- **SBOM.** CycloneDX software bills of materials for the Alice image, the database image and the source are in the
  package (`sbom/`).
- **Pinned inputs.** Go modules (`go.sum`), npm packages (lockfile), base images and build tools are pinned by version
  or digest; a check refuses unpinned inputs.
- **Scanners.** The release gates run govulncheck, osv-scanner, npm audit, Trivy (source and images), gitleaks, gosec
  (through golangci-lint), ShellCheck and actionlint; the results of each release are in `SECURITY-REPORT.md`.
- **Builds.** Go builds are made reproducible (`-trimpath`, pinned toolchain, no CGO). The release key is meant to
  sign only on an offline machine; that signing ceremony is an owner step of each release and is recorded in the
  release checklist.

## Threat model summary

The design follows a STRIDE analysis per component. The main scenarios:

| Scenario | Main mitigations | Remaining exposure |
|---|---|---|
| Takeover of the Alice platform | MFA, roles, confirmation for sensitive actions, narrow helper on servers, audit log with external forwarding | Alice holds access to every managed server: a full compromise reaches them all (within the helper's command set). |
| Theft of the database or a backup | Envelope encryption; backups sealed with the recovery passphrase | A thief with the database **and** the master key file, or a backup **and** the passphrase, reads the secrets. |
| A forged or altered backup restored | Backups origin-authenticated against anyone without the passphrase, authenticated chunks, verification before the switch, the restore recorded in the audit chain | Anyone with the passphrase and one backup file can forge a backup that restores (KI-14); an administrator with the passphrase can restore an older genuine backup; the audit log shows both. |
| Malicious operator | Operators cannot download private keys, read the audit log or change servers and policies; every action audited | Operators can deploy certificates and add or remove keys on existing servers. |
| Man in the middle | TLS everywhere; SSH host key pinning; certificate verification | First contact with a new server relies on the administrator comparing its fingerprint (trust on first use). |
| Tampered update | Signed packages verified with the installed keys; the package copied before use; automatic backup and rollback | Trust in the first installation rests on the operator comparing the published fingerprint. |
| Supply-chain compromise | Pinned and scanned dependencies, SBOM, offline signing | A compromised dependency that no scanner knows. |

Out of scope for version 1: an administrator misusing the rights the role grants; physical access with live-memory
access; side channels; a compromise of the customer's identity provider beyond group mapping.

## Residual risks

The full table, with severities and customer guidance, is in `SECURITY-REPORT.md` of each release. In short:

- **Keys on one host.** The master key is a file on the Alice server; disk encryption and root access control are
  the customer's protection. No hardware key storage in version 1.
- **Blast radius.** Alice can reach every managed server through its key and helper.
- **The recovery passphrase and the master key cannot be changed in version 1.** An exposed passphrase opens every
  backup copy made before and after; protect the copies.
- **Audit log limits.** The chain proves that entries were not changed or removed in between; someone with control
  of the whole server can cut the newest entries or replace the database with an older copy. Forwarding to a syslog
  server and recording the dashboard's head hash outside Alice make this visible. Forwarding is at most once.
- **License clock heuristics** can be bypassed by someone in full control of the host; this harms no paying customer.
- **Trust on first use** for new servers' host keys and for the first package's release key, mitigated by the
  administrator's fingerprint comparison.
- **Results that need the vendor or a customer environment** (installation on each supported operating system,
  among them Rocky 9 with SELinux enforcing; the image-ID check on a fresh Docker engine; an external penetration
  test) are owner steps of the release: until the release checklist records them, treat them as not verified.

## Control mapping (KVKK and BDDK orientation)

This table maps common control areas of Turkish personal-data (KVKK) and banking-regulator (BDDK) information-system
requirements to Alice features and to the evidence an auditor can collect. It is an orientation for your own
assessment, not a legal opinion or a certification.

| Control area | Alice feature | Evidence |
|---|---|---|
| Access control and least privilege | Three roles, per-route permissions, scoped API tokens | [authz-matrix.md](authz-matrix.md); **Users** page; audit entries of role changes |
| Strong authentication | Mandatory MFA for local accounts, MFA at the identity provider for single sign-on, confirmation for sensitive actions | Admin settings; audit entries of sign-ins and confirmations |
| Session management | 30-minute idle and 12-hour absolute limits; sessions ended on disable | [admin-guide.md](admin-guide.md#staying-signed-in) |
| Logging and monitoring | Hash-chained audit log, daily verification, syslog/SIEM forwarding | Audit export with verification result; SIEM records; dashboard head hash |
| Integrity of records | Hash chain, insert-only database role, triggers | `alicectl audit verify` output; export re-checked outside Alice |
| Encryption of data at rest | Envelope encryption (AES-256-GCM) of secrets; encrypted backups | This document; `SECURITY-REPORT.md` |
| Encryption in transit | HTTPS, SSH, TLS to services | Port table above; TLS scan results in `SECURITY-REPORT.md` |
| Key management | Master key on the host, recovery passphrase never stored | [operator-guide.md](operator-guide.md#master-key) |
| Backup and continuity | Daily encrypted backups, off-host copies, restore drills | Backup list; [backup-restore.md](backup-restore.md) drill log |
| Change management | Signed updates, automatic backup and rollback, update logs | `update-<time>.log`; audit entries; [upgrade.md](upgrade.md) |
| Vulnerability management | Scanners per release, SBOM, patch policy below | `SECURITY-REPORT.md`; `sbom/` |
| Data location and sovereignty | Self-hosted, no telemetry, no vendor connection | Network port table; firewall rules |
| Privileged access to systems | Narrow server-side helper and sudoers rule, SSH key rotation | [nginx-host-preparation.md](nginx-host-preparation.md); rotation history |

## Vulnerability reporting and patch policy

- Report a suspected vulnerability to the security contact your vendor publishes (its `SECURITY.md` and
  `security.txt`), encrypted with the vendor's published PGP key where offered. The vendor acknowledges within 3
  business days and triages within 7 days. Coordinated disclosure: 90 days by default, with credit to the reporter.
- Severity follows CVSS. Target fix times: Critical within 14 days, High within 30 days, Medium in the next minor
  release. Critical fixes ship as patch releases through the normal update ([upgrade.md](upgrade.md)).
- Advisories are signed files listing the affected versions, impact, fixed version, workaround and CVE; they are
  e-mailed to registered security contacts and posted on the vendor's site. Each release's notes have a
  "Security fixes" section.
