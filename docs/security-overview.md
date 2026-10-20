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
- When an administrator sets up a certificate authority (ACME), Alice talks to that authority over HTTPS, calls the
  customer's DNS hook over HTTPS, and for the web proof checks `http://<name>/.well-known/acme-challenge/…` on port
  80 itself; nothing is contacted before an administrator acts
  ([admin-guide.md](admin-guide.md#certificate-authorities-acme)).
- When an administrator adds a network discovery scan scope and an operator or administrator (or the scope's
  schedule) starts a scan, Alice opens TLS connections to the listed addresses and ports, reads the certificates the
  servers present and closes the connections; nothing is scanned before that
  ([admin-guide.md](admin-guide.md#network-discovery)).
- When an administrator sets up directory sign-in (LDAP or Active Directory), Alice connects to the directory over
  `ldaps://` (port 636 by default) to find the person with a read-only service account, to check the person's password
  by binding as them and to read their groups; nothing is contacted before an administrator adds a directory and tests
  it or switches its sign-in on ([admin-guide.md](admin-guide.md#ldap-and-active-directory)).
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
| Managed private keys (TLS keys, generated SSH keys), Alice's own SSH key, Key Vault credentials, SMTP password, identity-provider client secrets, directory service account passwords, ACME account keys, external account binding keys, DNS hook secrets | Database | Envelope encryption under the master key, each value bound to its row. |
| Inventory: servers, certificates, SSH public keys, deployments, rotations | Database | Database access control. |
| Network discovery: scan scopes, and the public certificates and chains that scanned servers presented, with the address, port and TLS version where each was found | Database | Database access control. Public data only: no private key and no secret is read or stored. It is a map of the customer's network, so API tokens need the operate scope to read it. |
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
- Wrong passwords slow the account down after 5 attempts and block it for 15 minutes after 10; a block ends with a fresh count, so the limit is 10 evaluated guesses per 15 minutes.
- Sessions end after 30 minutes without activity and always after 12 hours.
- Sensitive actions (user and settings administration, license upload, private-key download, backups, re-pinning a
  server's host key, credentials) need a confirmation within the last 5 minutes: a fresh authenticator code, or for
  single sign-on users a fresh sign-in at the identity provider, and for directory users the directory password again
  (plus the authenticator code when they have one).
- Single sign-on (OpenID Connect: Entra ID, AD FS, Keycloak and others): MFA is then the identity provider's
  responsibility; the "SSO users may be Admin" setting is off by default; a local break-glass administrator always
  remains.
- Directory sign-in (LDAP or Active Directory over `ldaps://`): **the directory password passes through Alice**,
  unlike single sign-on. Alice uses it for one bind as the person, never stores, logs or audits it, and clears its own
  copies after use (a copy inside the LDAP library cannot be cleared). TLS is mandatory and verified (system
  authorities or the directory's own authority, host name checked), referrals are not followed, responses are size
  limited, and every typed name is escaped before it goes into a filter. **MFA stays Alice's job by default**: each
  directory asks for Alice's authenticator code after the password unless an administrator switches that off for the
  directory. The service account (read-only by requirement) has its password stored with envelope encryption under the
  master key. Every refused sign-in gets the same answer after at least 1.5 seconds; three failed attempts per sign-in
  name and per directory account within 30 minutes pause that name or account in Alice for 45 minutes (attempts still
  running count; a locked account is never bound to), so the guesses Alice sends stay below a typical directory
  lockout threshold, on top of the sign-in limit of 10 a minute per address. The "SSO users may be Admin"
  setting applies to directory users, and the local break-glass administrator always remains.
- API tokens are personal, scoped (`read` or `operate`), valid for at most 365 days and stored as hashes. They never
  reach the actions that need a confirmation (above), and single sign-on and directory users cannot create them.

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
  verified hash is shown on the Overview (tab **Assurance**) for recording outside Alice.
- **Forwarding** sends every entry, in order, to the customer's syslog server or SIEM (RFC 5424, over TLS by
  default), with its sequence number, hash and previous hash, so the receiver holds an independent copy of the hashes
  and can check that the entries link up; it cannot recompute a hash from the message, which leaves out some hashed
  fields (actor ID, client address, request ID) and cuts long details ([admin-guide.md](admin-guide.md#audit-forwarding)).
  Delivery is at most once: a lost connection can lose a message, and the receiver sees the gap in the
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
| Out | HTTPS (443 or the port in the address) | A certificate authority's ACME directory and the addresses its answers name, and the DNS hook, when an administrator set them up; never through a proxy, never following a redirect |
| Out | TCP 80 (HTTP) | Each name proved by the ACME web proof (HTTP-01), to check the proof file before the authority does; only for certificates that use that proof |
| Out | TCP, the ports of a scan scope (443 and the like) | Network discovery: a TLS handshake to each address and port of a scope an administrator wrote, inside the networks an administrator allowed; nothing before an administrator adds a scope; never through a proxy |
| Out | TCP 636 by default (or the port in the address) | The LDAP directory or Active Directory domain controllers over `ldaps://`, when directory sign-in is set up; TLS verified, no plain `ldap://`, no StartTLS, no referrals |
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
| Malicious operator | Operators cannot download private keys, read the audit log or change servers and policies; they cannot add certificate authorities or names to be certified, or switch automatic deployment on; every action audited | Operators can deploy certificates, add or remove keys on existing servers, and order or renew certificates for names an administrator approved. |
| Abuse of the certificate authority or hook settings (server-side request forgery) | Only administrators set the addresses; https only; the address rule refuses link-local and metadata addresses on every connection; no redirect, no proxy, 1 MiB answers; answer text never stored | An administrator can point Alice at any https address it can reach, private ones included. |
| Abuse of network discovery (server-side request forgery, scanning from Alice's position, a hostile server answering a scan) | Nothing is scanned without an administrator's scope; an empty list of allowed scan networks (the default) allows nothing, and changing it needs a fresh code and is audited; the policy is checked on the socket at connect time, so names that resolve to a refused address and DNS rebinding do not help; built-in refusals for loopback, link-local and cloud metadata, multicast, reserved, carrier-grade NAT, Alice's own addresses, the default gateway and the database; the global exclusions no scope can override; no proxy, no redirect; the probe sends no application byte; limits on addresses, rate, connections, time, chain size and new certificates; parsers fuzzed | An administrator can scan any network the allowed list holds, from the Alice server; Docker host addresses outside the container's view must be added to the exclusions by hand; scans can trip intrusion detection. |
| Abuse of directory sign-in (password guessing through Alice, LDAP injection, a spoofed directory, a hostile directory answer) | Limits before any directory traffic (10 sign-ins a minute per address; 3 failures per name and per account at a directory lock them in Alice for 45 minutes, attempts in flight included); one generic answer held to at least 1.5 seconds; empty passwords refused before a bind; every typed value escaped and filter templates checked when saved; `ldaps://` only with the certificate and host name verified; exactly one entry required; identity by the directory's unique ID, never by name or e-mail; no referrals, response and value limits, timeouts; Alice's authenticator code by default | The password passes through Alice; anyone can lock a person's directory sign-in in Alice for 45 minutes; a directory administrator controls roles through groups; an administrator who switches MFA off for a directory leaves its users with one factor. |
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
- **Certificate authorities.** Alice's ACME account can request certificates for the names an administrator allowed;
  Alice revokes the certificates it ordered (and, in a key compromise incident, only after replacing them everywhere);
  a certificate from another source is revoked at the authority that issued it. Behaviour against real public or company authorities, real DNS
  and real renewal information was tested during development only against a simulated authority; check it with your
  authority (for example its staging service) before relying on it.
- **Network discovery trusts nothing it finds.** To see expired, self-signed and wrongly chained certificates, the scan
  probe does not verify the certificate a server presents: the server is exactly the thing being examined. This is
  one function (`tlsprobe.CapturePresentedChain`); a source test fails if the setting appears anywhere else in Alice
  besides the three older places that compare a served certificate with a pinned one. The probe sends nothing after
  the handshake, returns only certificates and never a "valid" or "trusted" verdict, and no screen calls a found
  certificate trusted. Scanning was tested only against simulated servers and on loopback, not on real networks; read
  [the review](security/reviews/network-discovery.md).
- **The recovery passphrase and the master key cannot be changed in version 1.** An exposed passphrase opens every
  backup copy made before and after; protect the copies.
- **Audit log limits.** The chain proves that entries were not changed or removed in between; someone with control
  of the whole server can cut the newest entries or replace the database with an older copy. Forwarding to a syslog
  server and recording the Overview's head hash outside Alice make this visible. Forwarding is at most once.
- **License clock heuristics** can be bypassed by someone in full control of the host; this harms no paying customer.
- **Directory sign-in.** The directory password passes through Alice, and a directory administrator controls group
  membership and so roles in Alice. Anyone who reaches the sign-in page can lock a person's directory sign-in in Alice
  for 45 minutes with three wrong passwords (the same trade-off as Active Directory's own lockout; only a restart of
  Alice clears it); there is no overall limit on parallel directory sign-ins. Directory sign-in was tested against
  OpenLDAP only, not against a real Active Directory or Samba AD; read
  [the review](security/reviews/ldap-signin.md).
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
| Access control and least privilege | Three roles, per-route permissions, scoped API tokens | [authz-matrix.md](authz-matrix.md); **People & access** page; audit entries of role changes |
| Strong authentication | Mandatory MFA for local accounts, MFA at the identity provider for single sign-on, Alice's authenticator code for directory users unless switched off per directory, confirmation for sensitive actions | Admin settings; audit entries of sign-ins and confirmations |
| Session management | 30-minute idle and 12-hour absolute limits; sessions ended on disable | [admin-guide.md](admin-guide.md#staying-signed-in) |
| Logging and monitoring | Hash-chained audit log, daily verification, syslog/SIEM forwarding | Audit export with verification result; SIEM records; the Overview's head hash |
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
