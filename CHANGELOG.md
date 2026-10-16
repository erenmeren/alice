# Changelog

## Unreleased — LDAP and Active Directory sign-in

**Added**
- People can sign in with the password of an LDAP directory or of Active Directory: the sign-in page gains **Sign in
  to** (**Local account** stays the default, then each directory that allows sign-in). Alice finds the person with a
  read-only service account, checks the password by binding as the person over `ldaps://`, reads their groups and
  gives the highest mapped role. People are created at their first sign-in; their identity is the directory's unique
  ID (`objectGUID`, `entryUUID`), never the name or the e-mail. User names come from the sign-in name through a
  transliteration table (`çağla` becomes `cagla`; a taken name gets `-2`).
- Alice's own authenticator code is asked after the directory password, per directory and **on by default**; the
  first sign-in sets up the authenticator and recovery codes. **Confirm it's you** asks a directory user for the
  directory password again and the code.
- **Settings → Directories** (Administrators, with a fresh confirmation): up to 3 directories with the presets
  **Active Directory** and **OpenLDAP**, addresses, base DNs, filters (the AD template for nested groups),
  attributes, the service account, an optional certificate authority, **Test connection**, **Test sign-in** (groups
  found and the role they give, nothing stored), group mappings and **Allow sign-in with this directory**.
- **People & access** shows directory users with the badge **Directory** and the directory's name; **Reset two-factor
  sign-in** works for them; no password, no API tokens, no role change by hand (`ALC-USR-0003`).
- Error codes `ALC-LDAP-0001` to `ALC-LDAP-0008` ([docs/troubleshooting.md](docs/troubleshooting.md)); `ALC-SSO-0002`,
  `ALC-SSO-0003` and `ALC-USR-0003` now also name directory users.
- API: `GET /api/v1/auth/ldap/directories`, `POST /api/v1/auth/ldap/{id}/login`, `POST /api/v1/auth/ldap/stepup`, and
  10 routes under `/api/v1/ldap/` (permission `sso.manage`; see `docs/authz-matrix.md`). New audit actions
  `ldap.directory_created|changed|deleted|tested`, `ldap.signin_tested`, `ldap.mapping_created|deleted`,
  `ldap.mapping.denied` and `auth.ldap.denied`.
- `make fuzz-ldap` (part of the nightly and release fuzzing); an OpenLDAP service in the e2e stack (test builds only)
  and `web/e2e/ldap.spec.ts`.

**Security**
- The directory password passes through Alice (unlike single sign-on). It is used for one bind, never stored, logged
  or audited, and Alice clears its own copies; TLS is mandatory and verified (`ldaps://` only, no StartTLS, no
  referrals). The service account password is stored encrypted with the master key and never returned.
- Every refused directory sign-in gets the same answer and takes at least 1.5 seconds; the audit log records the
  reason, and the typed name only when the directory found the entry.
- Alice stops after three failed attempts per sign-in name and per directory account (its unique ID) within 30
  minutes and pauses that name or account for 45 minutes; attempts still running count, and a locked account is never
  bound to. So the guesses Alice sends stay below a typical directory lockout threshold. The price: anyone can lock a
  person's directory sign-in in Alice for 45 minutes; only a restart clears it.
- "SSO users may be Admin" applies to directory users. The local break-glass administrator is unchanged.

**Upgrade notes**
- Migration `00015` adds `ldap_directories`, `ldap_group_mappings` and the directory columns of `users`. It was edited
  while the feature was built: **a development database already at version 15 must be migrated down to 14 and up
  again** (or `make reset`). Released installations are not affected.
- New Go modules `github.com/go-ldap/ldap/v3` v3.4.15 and `github.com/go-asn1-ber/asn1-ber` v1.5.8, and the indirect
  `github.com/Azure/go-ntlmssp` v0.1.1 (all MIT) ([docs/dev/dependency-updates.md](docs/dev/dependency-updates.md)).
- Firewalls: Alice needs outbound TCP 636 (or the port in the address) to the domain controllers or directory servers.
- **Not run against a real Active Directory or Samba AD**: everything was tested against OpenLDAP. The AD preset, the
  nested-group template and AD's answers for disabled and locked accounts follow AD's documentation. Guide:
  [docs/admin-guide.md](docs/admin-guide.md#ldap-and-active-directory); review:
  `docs/security/reviews/ldap-signin.md`; design: `docs/superpowers/specs/2026-10-15-ldap-directory-signin-design.md`.

## Unreleased — Network certificate discovery

**Added**
- Alice finds the certificates that servers on your network present, including the ones it does not manage. An
  administrator writes a **scan scope** (addresses, ranges and host names, ports, optional server names, exclusions, a
  pace and an optional schedule with a daily time window); an operator or administrator chooses **Scan now**, or the
  scope's schedule does. Alice opens a TLS connection to each place, records the certificate chain the server
  presents and closes the connection. It sends nothing else and changes nothing on the scanned servers.
- New page **Network discovery** (`/discovery`, every role; auditors read only) with **Results** (one row per
  certificate: **Unmanaged**, **Managed** or **Known**, self-signed, expiry, the places it was found on, a detail
  panel, **Add as server** for administrators, CSV export), **Scopes** (with a live size of the scope as you type, the
  allowed scan networks, the global exclusions and the retention) and **Scans**.
- **Certificates** gets the link "Found on the network, not managed (n)". The **Overview** shows, once a scope exists,
  a separate line for unmanaged certificates expiring within 30 days (not counted with the managed ones).
- Optional expiry e-mails for unmanaged certificates found by a scope (**E-mail before certificates found by this
  scope expire**, off by default) at the usual thresholds.
- Error codes `ALC-DSC-0001` to `ALC-DSC-0013` ([docs/troubleshooting.md](docs/troubleshooting.md)).
- API: 17 routes under `/api/v1/discovery/` (permissions `discovery.view`, `discovery.operate`, `discovery.manage`; see
  `docs/authz-matrix.md`).
- Background jobs `netdisco.scan`, `netdisco.schedule` and `netdisco.retention`; `make fuzz-discovery` and
  `make fuzz-tlsprobe` (part of the nightly and release fuzzing); `make perf` also runs `TestPerfNetdiscoScan`.
- Test tool `alice-fakefleet` (test builds only): a fleet of TLS servers of every kind for the discovery journeys.

**Security**
- Nothing is scanned until an administrator adds a scope **and** lists the networks Alice may scan (**Allowed scan
  networks**; empty by default, which allows nothing). Changing either needs a fresh authenticator code and is
  recorded in the audit log; neither can be changed with an API token. Reading the results needs the operate scope for
  a token (the results are a map of your network).
- Alice never scans loopback, link-local and cloud metadata addresses, multicast and reserved ranges, carrier-grade
  NAT (`100.64.0.0/10`), its own addresses, its default gateways or its database server, whatever the settings; the
  rule is checked at the moment of connecting (names that resolve to a refused address and DNS rebinding do not help)
  and uses no proxy.
- To see expired and self-signed certificates the scan does not verify what a server presents. This is one function,
  guarded by a source test; Alice never calls a found certificate trusted and does not check its name.
- Discovery never counts toward the license. While the license is locked no scan starts; cancelling and reading work.

**Upgrade notes**
- Migration `00014` adds the discovery tables and the alert kind `discovered_certificate_expiry`. It was edited
  while the feature was built: **a development database that is already at version 14 must be migrated down to 13 and
  up again** (or `make reset`). Released installations are not affected.
- A restore ends scans that were running and switches off every scan scope that has a schedule; switch them on again
  when the restored installation replaces the original.
- Add the addresses of the Docker host to **Never scan these** when it lies inside an allowed network: Alice sees
  only its container's addresses. Scans can trip intrusion detection; tell the people who run it before the first
  scan.
- No new Go module or npm package; `THIRD_PARTY_NOTICES.md` is unchanged.
- Not verified on a real network (middleboxes, intrusion detection, load balancers that route by name, IPv6 at
  scale); performance was measured on one machine with simulated servers. Limits of this version (no STARTTLS, no SSL
  3.0, no name check, a malformed certificate is shown as unreadable without the certificate):
  [docs/admin-guide.md](docs/admin-guide.md#limits-of-this-version). Rulings:
  `docs/superpowers/rulings/network-discovery.md`; review: `docs/security/reviews/network-discovery.md`.

## Unreleased — Certificates from certificate authorities (ACME)

**Added**
- Alice gets, renews and deploys certificates from a certificate authority that speaks ACME (RFC 8555): Let's
  Encrypt, ZeroSSL, or your own (step-ca, EJBCA, an ACME gateway). **Settings → Certificate authorities**
  (administrators): authorities with an optional CA bundle and external account binding, one account per authority
  (terms shown before you accept them, account key rotation and deactivation), DNS hooks, and per authority and hook
  the domain endings Alice may request (an empty list allows nothing).
- New page **Issued certificates** (`/acme`, every role): the list, a status page per certificate (renewal, orders,
  current certificate, websites), the **Get a certificate** wizard (administrators), **Test run** (checks the names
  without issuing anything), **Get certificate now** / **Order now**, **Deploy now**, connecting websites, **Renew
  now** and **Release** (administrators).
- Proof of the names by a DNS hook (DNS-01; a small HTTPS service of yours, also for wildcards) or by a file on an
  Nginx server (HTTP-01; the server's administrator publishes one directory with three Nginx lines; Alice never edits
  the Nginx configuration).
- Automatic renewal (default 30 days before expiry, or at a third of the lifetime, earlier when the authority's
  renewal information suggests it), with growing waits after failures, an e-mail after 3 failures and a stop after 5.
  Automatic deployment through the existing verified deployment (same checks, same automatic undo), in groups of 5,
  stopped after 3 failures; certificates with an incomplete chain or received before the license allowed changes
  again are held for an administrator.
- Error codes `ALC-ACM-0001` to `ALC-ACM-0036` and `ALC-SSH-0013` ([docs/troubleshooting.md](docs/troubleshooting.md)).
- API: 29 routes under `/api/v1/acme/` (permissions `acme.view`, `acme.operate`, `acme.manage`, `acme.preview`; see
  `docs/authz-matrix.md`); certificates gain the source `acme`, deployments the trigger `acme_renewal`.
- `make fuzz-acme` (`fuzz-acme-docs`, `fuzz-acme-order`), part of the nightly and release fuzzing.

**Security**
- Nothing is contacted until an administrator sets up an authority. Every connection to an authority or a hook is
  https only (also for the addresses the authority's answers name), follows no redirect, ignores proxy settings, reads
  at most 1 MiB and uses Alice's address rule (no link-local or metadata addresses). The web proof's own check is plain
  HTTP to port 80 of the name. The new outbound connections are in `docs/security-overview.md`.
- Account keys, external account keys and hook secrets are stored encrypted with the master key, are write-only, and
  never appear in an API answer, log, audit entry, task or e-mail (a leak test checks this with planted values).
- Only administrators, with a fresh code and never with an API token, add authorities, hooks and names, and switch
  automatic deployment on. Operators can test, order, deploy and connect websites with automatic deployment off.
- While the license is locked no authority, hook or server is contacted for certificates.

**Upgrade notes**
- Migration `00013` adds the ACME tables and extends the certificate source and deployment trigger values (its Down
  turns `acme` certificates into `uploaded` and `acme_renewal` deployments into `retry`).
- `alice-helper` 1.6.0 (protocol 7) adds `acme-challenge-put` and `acme-challenge-rm` and two sudoers lines in the
  `nginx` profile. Servers with helper 1.5.0 (protocol 6) keep working for everything else; only the HTTP-01 proof on
  a server needs the new helper and setup commands ([docs/nginx-host-preparation.md](docs/nginx-host-preparation.md)).
- A restore switches automatic renewal off on every certificate from a certificate authority; switch it on again on
  each certificate's page when the restored installation is the one in use.
- No new Go module or npm package; `THIRD_PARTY_NOTICES.md` is unchanged.
- Not verified against a real certificate authority, real DNS or real renewal information: try it with **Let's
  Encrypt (staging, for tests)** first. Limits of this version (no revocation, no HTTPS proxy, no built-in DNS
  providers, no TLS-ALPN-01): [docs/admin-guide.md](docs/admin-guide.md#certificate-authorities-acme). Rulings:
  `docs/superpowers/rulings/acme-issuance.md`; review: `docs/security/reviews/acme-issuance.md`.

## Unreleased — Phase 9: the Clarity design

**Changed**
- The web interface follows the Clarity product design (`alice-design/`): warm neutral surfaces, a forest accent,
  the bundled Geist fonts and Lucide icons, grouped navigation (Inventory, Operations, Administration), page headers,
  resource tables, status badges, fact lists, operation timelines and attention items.
- Light, dark and system color modes and a compact table density (per computer, on **Your account** or with the
  moon/sun button in the top bar); the language stays per account (the **TR**/**EN** button in the top bar, or the
  language select on **Your account**).
- Page names: Dashboard → **Overview**, Users → **People & access**, Audit log → **Audit trail**, My account →
  **Your account**, Deployment history → **Deployments**. The Overview has Operations and Assurance tabs: audit
  integrity, recovery readiness (backups), the license and the newest audit entries are on **Assurance**, which
  administrators and auditors see; operators see the license state through the banners. The "Welcome, <name>"
  heading is gone; the signed-in name is in the sidebar.
- The expiry horizon on the Overview draws four exclusive bars (expired, 1–7, 8–30, 31–60 days); the count links stay
  cumulative and open exactly the rows they count.
- Sign-in uses the design's split layout; the first-run wizard shows a progress rail. Every setup check is unchanged.
- New page **Key rotations** (`/rotations`): running rotations and every policy (read-only). On **SSH keys**, its tab
  is **Rotation policies**.
- A page palette (Ctrl+K, ⌘K on a Mac) lists the pages your role may open; the bell shows the attention items.
- Error messages show their `ALC-*` code.
- **Your account** shows single sign-on users no password form and no **Create new recovery codes** (the server
  always refused both for them) and says that their identity provider manages them.
- **Deployments** marks a success that was not verified ("Verification: Skipped" or "Not done") instead of showing it
  like a verified one; lists say how many rows are shown ("N shown") and never a total.
- The License page shows the grace period in red, as its banner does; an intact audit verification says which entry
  it verified through.

**Accessibility**
- Status is shown with text and an icon besides color; a 3 px focus ring on every control; one heading level 1 per
  page and one navigation landmark.
- The wizard moves focus to each new step's title and announces "Step n of 7"; sign-in moves focus to the
  enrollment and recovery-code steps; Escape closes the phone menu and returns to its button.
- Dark mode is checked for contrast (every text and background pair at 4.5:1 or more, controls at 3:1).

**Upgrade notes**
- No API, permission or data change. Bookmarks keep working (`/rotation/runs/<id>` is unchanged).
- The browser stores `alice.colorScheme` and `alice.density` in local storage.
- `THIRD_PARTY_NOTICES.md` lists the bundled fonts (SIL OFL 1.1) and icons (ISC AND MIT: Lucide, with the
  Feather-derived icons under MIT).
- Where the product differs from the design, and why: [docs/design-gaps.md](docs/design-gaps.md).

## Unreleased — External code review fixes (2026-10-12)

**Behaviour changes**
- `PUT /settings/smtp`, `/settings/notifications` and `/settings/general` answer 422 for a missing required key
  and save nothing (they used to apply the zero value: an omitted `username` disabled SMTP authentication and
  deleted the stored password). A JSON `null` is 400.
- An SMTP host written as a bracketed IPv6 literal is refused (422); write IPv6 without brackets.
- The `Bearer` scheme of the `Authorization` header is matched case-insensitively (RFC 7235).
- A wrong method on an `/api/*` path answers 405 `ALC-SYS-0009` with an `Allow` header; unknown paths still 404.
- An SSO callback with no stored state is audited at most once a minute per client address.
- CSV exports also guard a cell that starts with a line feed.
- A bad backup key is recorded once per episode instead of every 5 minutes; other backup failures retry after
  5 minutes, doubling up to 1 hour. After a fix, the next automatic backup can wait up to an hour.
- Uptime comes from CLOCK_BOOTTIME on Linux: a suspended host no longer looks like a clock that stood still.

**Fixes**: SSO first sign-in with a user name taken by a concurrent sign-in (was a 500); e-mail is no longer sent
inside an open database transaction; the temporary HTTPS certificate is written crash-safely; the rate limiter
evicts least-recently-used buckets in batches; transaction rollback and the leadership check are bounded in time;
nginx `include` patterns match like glob(3); Key Vault listings survive one unreadable certificate; licensectl
month arithmetic clamps at month end. The backup documentation now states exactly what the sender key does and
does not authenticate (KI-14). Details and rulings: `docs/superpowers/rulings/review-fixes.md`.

## Unreleased — Phase 8: Packaging and release

**Upgrade notes**
- Production installations use `deploy/release/docker-compose.yml` through `install.sh`; the development stack
  (`make up`) is unchanged except a new volume for backups (`alice-backups`, mounted at `/opt/alice/backups`).
- The production database owner is no longer a superuser and the `alice` container holds no owner credential:
  migrations run in the one-shot `migrate` service, restores in `alice-admin` (`ALICE_MIGRATE=external`).
- Migration `00012` adds the backup sender key's storage. An Alice binary refuses a database whose schema is newer
  than its own migrations.
- New settings: the daily backup (time, zone, retention), audit forwarding. Backups need the recovery passphrase
  (set in the wizard); installations without it show "Finish setting up".
- The recovery passphrase must now be rated "good" or better (a "fair" one is refused, `ALC-SET-0010`).
- Development installations whose recovery passphrase was set before Phase 8 hold a version 1 backup key and make no
  backup until the wizard is run again on a fresh database (R43 row 41).
- No helper change: `alice-helper` stays at protocol 6 (1.5.0); the release bundle ships it in `helper/`.

### Added
- `install.sh` (preflight, signature and image checks, offline image load, hardened two-container stack, setup code),
  `alice-update.sh` (signed packages only, automatic pre-update backup, migrations, selfcheck, automatic return to
  the previous version), `alicectl` (backup, backup list, backup verify [--deep], restore, selfcheck, audit verify,
  setup-token --reset, support-bundle), `install.sh --restore-mode`, `--uninstall [--purge]`.
- Encrypted backups (X25519 to the installation's backup key, authenticated by the installation's sender key, AES-256-GCM
  chunks, the private key inside the file under the recovery passphrase; container format 2), daily at 02:30 with 14 kept,
  a failure e-mail and a 48-hour alarm; restore into a fresh database with one swap point.
- Wizard steps "HTTPS certificate" and "Mail server", Back on the steps after the administrator, resume after a reload;
  the dashboard's "Finish setting up" checklist and backup card; Settings → Backups, HTTPS certificate, Audit forwarding.
- Audit forwarding to syslog (RFC 5424 over TLS) in chain order with each hash.
- Release bundle with SBOMs, third-party notices (Alice's programs, and the contents of both container images with the
  license texts they carry and a written offer of the GPL/LGPL sources, `licenses/IMAGE_NOTICES.md`) and Ed25519 signatures; `make reproducible-check`, `make release-gates`,
  `make nightly`; ZAP, testssl, real-systemd, three-browser, mutation and osv-scanner gates; the §23–§25 traceability
  (`make matrix-check`, in `make lint` with `-strict`; status `partial` for rows proven only in part).
- Documents: install guide, backup and restore, upgrade, security overview, API, index; `SECURITY-REPORT.md`; the
  release checklist.
- Codes `ALC-BAK-0001..0004`, `ALC-TLS-0001..0005`, `ALC-AUD-0002..0004`, `ALC-SET-0010`; permission `backup.manage`.

### Changed
- The API's Content-Security-Policy also sets `base-uri 'none'` and `form-action 'none'`.
- After setup completion the public setup status answers only `completed` and the default language; an anonymous
  visitor of a completed installation is sent to the sign-in page.

### Security
- P1-01 closed in production (non-superuser owner, no owner credential in the application container); PostgreSQL
  read-only, non-root, no published port; secrets as files; the temporary HTTPS certificate renewed without a restart.
- Backups are origin-authenticated against anyone without the recovery passphrase: a file built from another
  installation's public keys does not open with the passphrase (R43 row 41; a passphrase holder can still forge one,
  KI-14); a restore keeps the newer license time record.

## Unreleased — Phase 7: Alerts, dashboard and SSO

**Upgrade notes**
- Migration `00011` runs at start (alert ledger, settings secrets, saved views, identity providers, SSO users, sign-in
  states). Once a sent notice, a settings secret, a saved view, a provider or an SSO user exists, it refuses to go
  down (`Z1015`).
- **Mail settings move to Settings → Email.** At the first start, `ALICE_SMTP_*` (with `ALICE_SMTP_PASSWORD_FILE` and
  `ALICE_SMTP_CA_FILE`) are imported once; afterwards they are ignored with a warning in the log — remove them from
  `deploy/.env`. The password is stored encrypted in the database. A user name without a readable password is not
  imported (enter the settings in the web UI); an unreadable password or CA file stops the start.
- **Alert recipients**: every e-mail Alice sends to administrators now goes to the recipients of Settings →
  Recipients (by default every administrator with an e-mail address, as before).
- The first expiry check after the upgrade sends one notice for each certificate in use, Key Vault certificate, key
  and client secret that has already reached a threshold (only the most urgent one), at most 20 per kind plus a
  summary.
- Single sign-on needs Alice's address (Settings → General); new identity providers are created switched off.
- No helper change: `alice-helper` stays at protocol 6 (1.5.0).

### Added
- Dashboard: certificates expired and within 7, 30 and 60 days (each count equals the list its link opens), Key
  Vault keys and secrets expiring within 30 days, expiring soon (expired ones marked), failed deployments of the last
  7 days, servers and vaults by status, license, upcoming rotations, needs attention, and the audit log's last
  verified head for offline recording (administrators and auditors).
- Expiry e-mails for certificates in use, Key Vault certificates, keys and client secrets at 60/30/14/7/1 days
  (editable) and once expired; exactly once per threshold; the license note in lock; the check `alerts.scan` every
  15 minutes.
- Settings: Email (test e-mail, trust this certificate, CA bundle), Recipients, Alerts, General (Alice's address,
  retired-key retention).
- Retries of e-mail for 24 hours and the "E-mails could not be sent" banner; the sign-in lockout e-mail.
- Filters in the address, saved views and CSV export (formula-safe, audited before the first byte) for certificates
  and SSH keys; certificate filters for 7, 14 and 90 days and Key Vault.
- Single sign-on with OpenID Connect (Entra ID, AD FS, Keycloak): group mappings, "SSO users may be Admin" (off by
  default), step-up at the identity provider, break-glass with the local administrator.
- Codes `ALC-NTF-0002..0009`, `ALC-SSO-0001..0016`, `ALC-RPT-0001..0004`, `ALC-USR-0003`, `ALC-SYS-0009`;
  permission `sso.manage`; `make perf` (R32); e2e-only fakes `fakesmtp` and `fakeidp` and the endpoint
  `POST /test/seed/dashboard`.
- Guides: "Dashboard", "Alerts and e-mail", "Mail server", "Single sign-on", "Saved views and export" in
  `docs/admin-guide.md`; "Email" rewritten in `docs/operator-guide.md`.

### Changed
- The Home page is the Dashboard. The outbox retries for 24 hours instead of 10 attempts. Key Vault polls read stored
  versions in one batch. The retention of retired SSH private keys is a setting (30 days by default).
- A HEAD request to an audited export (`/certificates/export`, `/ssh-keys/export`, `/audit/export`) is refused with
  405 (`ALC-SYS-0009`) before anything runs.
- Users and sessions carry `auth_source` and `sso_provider_id`.

### Fixed
- A lock sweep recorded at a later time (the clock was set back) no longer counts as recent, so queued work is still
  held in lock (`internal/jobs`).
- The monitored-items query reads live locations through the certificate index (the expiring list at 5,000
  certificates went from about 650 ms to about 45 ms).

### Security
- SMTP passwords and OIDC client secrets only as envelopes (`setting_secrets`); PKCE S256, single-use state and nonce
  bound to the browser; users matched by provider and subject, never linked to local accounts; every SMTP and OIDC
  connection through the address rule. A refused SSO user loses their sessions.
- SSO users cannot create API tokens (`ALC-USR-0003`), so no credential Alice issued outlives de-provisioning at the
  identity provider. An SSO sign-in opens the 5-minute step-up window only when the ID token's `auth_time` is at most
  5 minutes old; otherwise (a silent sign-in at the provider, or no `auth_time`) the first stepped-up action needs the
  step-up at the provider.
- A stored SMTP password or client secret is never sent to a new destination: a new mail server host or port, or a
  new issuer, needs the secret again (422). The identity provider client keeps no idle connection. The e-mail Subject
  is capped at 200 characters and folded so no header line exceeds 998 octets.
- Mail server certificates are trusted only by the system, the configured CA bundle or a pin an administrator chose
  after a failed test within the hour; no plaintext SMTP.

### Known issues
- No Microsoft Graph lookup: Entra ID users in more than 200 groups are refused unless the token carries only the
  application's groups.
- A group removed at the identity provider keeps an open session until it ends (up to 12 hours).
- Starting a single sign-on shares the sign-in limit of 10 a minute per address: behind one NAT address, the 11th
  person starting SSO within a minute gets `ALC-SYS-0005`.
- The full list is in `docs/security/reviews/phase-7.md` ("Known limitations").

## Unreleased — Phase 6: SSH key lifecycle and rotation

**Upgrade notes**
- Migration `00010` (generated keys, download counter and destruction of private keys, rotation policies, runs,
  places and steps, and the database guards of the rotation) runs at start. Once a generated key, a policy or a run
  exists, it refuses to go down.
- **After the upgrade every server refuses key deploys (`ALC-KEY-0014`) and is skipped by rotations
  (`connection_files_unknown`) until it has been scanned again**: Alice needs the list of key files of the account it
  connects with, which scans of earlier versions did not record. Connected servers are scanned once per discovery
  interval (one day unless it was changed); choose **Scan for SSH keys** (on an Nginx server, **Discover**) to do it
  at once. A server with more than 200 accounts, or whose `alice-svc` is not in
  `/etc/passwd`, keeps refusing.
- **Scheduled rotations need working email delivery**: a scheduled run starts only after its preview email was accepted
  by the mail server for at least one administrator before the planned start (otherwise `ALC-ROT-0017`). **Run now**
  does not need email.
- No helper change: `alice-helper` stays at protocol 6 (1.5.0).

### Added
- **Generate key** (administrators and operators): Ed25519 (recommended), RSA 3072, RSA 4096 or ECDSA P-256. The
  private key is stored only encrypted with the master key.
- **Deploy to a server**: adds a generated key to a user's key file (optionally with allowed source addresses and
  `restrict`, comment `alice:<name>:<date>`), then proves it with a test sign-in as that user with only the new key;
  a key the server refuses is removed again. Alice never touches the account it connects with or any of its files,
  never removes a line that was there before, and refuses files the last scan did not list.
- **Download private key** (administrators, browser session, fresh authenticator code, a reason): an OpenSSH file,
  optionally protected with a passphrase; recorded in the audit log and counted before the file is sent; 5 per minute
  per person; possible during a license lock.
- **Rotation policies** (administrators; off when created; every N days, overlap 7 days by default, notice 24 hours by
  default), **Preview next run** (emailed), scheduled runs that start only as previewed, **Run now** with the previewed
  plan, and a run page with **Continue**, **Finish now**, **Keep the old key on these servers** and **Stop and undo**.
  A run adds the new key next to the old one, signs in with it, keeps both through the overlap, signs in again and only
  then removes the old key; any failure before that undoes the run's own additions and never touches the old key.
- License lock: scheduled runs are not planned or started; a started run pauses (its overlap and decision time stop),
  and after the renewal continues only when an administrator chooses **Continue**. **Stop and undo** works in lock.
- Retired keys: the old key of a completed rotation is retired once unused; its private key is destroyed after 30
  days (hourly task `sshkey.destroy_retired`).
- Emails for previews, overlaps, decisions, completed, undone, paused and needs-attention runs, and late answers.
- Periodic tasks `rotation.plan`, `rotation.sweep` (every minute) and `sshkey.destroy_retired` (hourly); job types
  `sshkey.add` and `rotation.location`.
- Error codes `ALC-KEY-0006..0018`, `ALC-ROT-0001..0025`, `ALC-NTF-0001`; permissions `sshkeys.download`,
  `rotation.manage`, `rotation.operate`; audit actions `sshkey.*` and `rotation.*` for every step.
- API: `POST /api/v1/ssh-keys/generate`, `…/{id}/actions/deploy`, `…/{id}/actions/download-private-key`,
  `GET /api/v1/targets/{id}/key-files`, `/api/v1/rotation/policies` (with `actions/enable`, `disable`, `preview`,
  `run`) and `/api/v1/rotation/runs` (with `actions/continue`, `finish-now`, `keep-old`, `abort`).
- e2e build only: `POST /test/rotation/overlap` sets a policy's overlap in minutes.
- Guides: "SSH keys and rotation" in `docs/operator-guide.md`, "Generated keys and rotation" in
  `docs/admin-guide.md`, the rotation entries of `docs/troubleshooting.md`.

### Changed
- Scans record each user's candidate key files and whether the list is complete (`facts.key_files`).
- The SSH key list shows keys generated in Alice also when they are not used anywhere yet.
- Jobs name the SSH key and the rotation run they work on (`ssh_key_id`, `rotation_id`).
- The import history of a vault shows an error line with **Try again** for a vault whose imports could not be read,
  instead of dropping its rows; the add-vault dialog shows both the missing-role text and the failed-check text when
  both apply.
- OpenAPI: the 412 of `PATCH /bindings/{id}` says that a missing `If-Match` is answered first.

### Security
- The old-key rule: Alice removes an old key from a file only after the run reached the removal, every place of the
  run in that file was verified, a sign-in with the new key as that user succeeded at most 15 minutes before, the
  license allows changes and the run is not paused, and the key is not Alice's own. The service checks it and the
  database refuses any removal that does not meet it; the database also refuses run and place changes that are not
  steps of the state machine, a finished run's changes, and Alice's own key in a policy or a run.
- S-09: the private key leaves Alice only in the download response, after its audit row is committed; it is in no log,
  error, job, audit entry, rotation record or email (secret-leak suite with generated keys).
- A deploy owns a line only when it proved the line absent before its first send or the helper said it wrote it.

### Known issues
- Real OpenSSH was exercised only in three test containers (Ubuntu 22.04, Debian 12, Rocky 9); nothing was run
  against customer servers.
- Files shared by several users are skipped by rotations; servers where Alice cannot test a sign-in keep both keys
  unless the run is stopped; there are no weekday schedules and no partial rotations; the 30-day retention and the
  email recipients (every administrator) become settings in a later release; a certificate's private key cannot be
  downloaded yet.
- Backups taken before a private key was destroyed still contain it, encrypted.
- The full list is in `docs/security/reviews/phase-6.md` ("Known limitations").

## Unreleased — Phase 5: Azure Key Vault

**Upgrade notes**
- Migrations `00008` (Key Vault tables, connections, imports) and `00009` (a version's chain flag) run at start.
  Once a vault exists, `00008` refuses to go down.
- Alice now connects to Azure (`login.microsoftonline.com` and each vault's `<name>.vault.azure.net`, TCP 443)
  when a vault is added; allow both outbound. Do not set `AZURE_REGIONAL_AUTHORITY_NAME`, `MSAL_FORCE_REGION` or
  `AZURE_SDK_GO_LOGGING` for the Alice container: with any of them Alice refuses to sign in to Azure
  (`ALC-AKV-0011`). Proxy variables are ignored for Azure.
- API clients that deploy a vault version Alice knows to have an incomplete chain must send
  `confirm_incomplete_chain` (Administrator); otherwise the request is refused with 409 `ALC-CRT-0011`.

### Added
- **Key Vaults**: add an Azure Key Vault (administrators, with a fresh authenticator code) by name or address, signing
  in with a certificate (recommended), a client secret or the managed identity of the Azure virtual machine Alice
  runs on. Alice checks the sign-in and the certificate list before it stores anything; the **Access check** shows,
  per feature (monitor, deploy, import), what the identity may do and the Azure role that is missing, with the
  `az` commands to grant it. Each vault counts as one license target.
- The vault's certificates (versions, expiry, thumbprints, exportable key or **Monitor only**), keys (type, size)
  and secrets (metadata only; values are never read), checked every 15 minutes by default (5 to 1440 minutes) and
  with **Check now**; statuses **Connected**, **Partly working**, **Credentials refused**, **Cannot reach Azure**.
- **Connect websites**: a vault certificate follows up to 200 Nginx websites. **Automatic deployment** (off by
  default; administrators) deploys a new current version found after it was switched on, through the Phase 4
  deployment engine with a first step **Read the certificate from Key Vault** (the exact version, before anything
  is sent to the server): five at a time per connection, one hour between attempts on a website, stopped after
  three failures with one email. **Deploy now** deploys any version Alice has read.
- Versions that appear while the license is locked, or with an incomplete chain, are **Held** for an administrator,
  who deploys or releases them.
- **Import into Key Vault** (administrators): copies a certificate Alice holds with its key into a vault, sent once
  and never again by itself; an import whose answer was lost reads **Not confirmed yet** until a check settles it.
- Emails to administrators for repeated sign-in failures, removed certificates, versions not deployed
  automatically, stopped automatic deployments and failed or unknown imports (at most 20 of a kind per vault and
  run, then a summary).
- Error codes `ALC-AKV-0001..0041`; audit actions `vault.*`, `kv.*` and `binding.*`; every read of a certificate's
  secret is audited (`kv.secret_read`). Jobs name their deployment or import (`deployment_id`, `import_id`).
- `GET /api/v1/certificate-locations` lists websites across servers.
- Guides: `docs/azure-setup.md` for Azure administrators (identity, roles, access policies, network), the Key
  Vaults chapter of `docs/operator-guide.md`, Key Vaults in `docs/admin-guide.md`, `docs/licensing.md` and
  `docs/troubleshooting.md`.
- Developer targets: `make test-azure` and `make record-azure` (optional, against a real vault, never in `make ci`);
  the e2e stack runs a fake Azure service (`fakeazure`). `make coverage` enforces floors for
  `internal/platform/azureid` (100), `internal/providers/azurekv` (98) and `internal/jobs/kvjobs` (100), and raised
  ones for `internal/api` (94), `internal/certs` (98) and `internal/inventory` (89).

### Changed
- A new permission, `credentials.manage` (Administrator with a fresh authenticator code, never an API token), gates
  adding a vault, replacing its credentials, automatic deployment, releasing a held version and importing.
- Lock mode also stops vault checks, adding vaults, connecting websites, **Deploy now** of vault versions and
  imports; switching automatic deployment off and deleting a connection stay possible.
- The scrolling part of every table is a keyboard stop (a named group) with a visible focus ring, and field errors
  are drawn with a higher contrast.
- "Busy reading other PFX files" (`ALC-CRT-0015`) now says to try again, since a Key Vault deployment can meet it
  too.

### Known issues
- Nothing was tested against real Azure: the fake service follows the public REST reference. Whether `Key Vault
  Reader` alone is enough to monitor a vault is expected but not confirmed.
- Public Azure cloud only; no HTTPS proxy or custom CA for Azure; managed identity only on Azure virtual machines;
  no deployment windows; no reminder email before a client secret or sign-in certificate expires.
- The full list is in `docs/security/reviews/phase-5.md` ("Known limitations" and "Not verified against Azure").

## Unreleased — Audit remediation

Fixes for the independent audit of 2026-10-04; the full record is `docs/security/reviews/audit-remediation.md`.

**Upgrade notes**
- **Update `alice-helper` on every managed server first, then Alice.** This release needs helper protocol 6
  (`alice-helper` 1.5.0); the new helper also works with the previous Alice. Copy the `alice-helper` of this release
  next to the setup commands from **Servers** and run them again on each server (the sudoers file does not change).
  A server whose helper is older shows "The alice-helper on this server is outdated." (`ALC-SSH-0005`) and Alice does
  nothing on it, deployment recovery included, until it is updated.
- **Set a new password** and **Sign out everywhere** now also revoke the person's API tokens: scripts of a person
  whose password an administrator resets need new tokens.
- **The 30-minute idle timeout now works:** a page left open is signed out 30 minutes after the last click, key,
  wheel or touch, although it keeps refreshing.
- Migration `00007` (applied at start) makes the installation record's protection read-only for the application
  role. A development database that was never started since before Phase 2 reads as tampered: `make reset`.
- The CSV audit export has a new first line; readers that expect the column names on line 1 must skip it.
- Behind a reverse proxy, set `ALICE_TRUSTED_PROXIES` (now passed to the container) to the proxy's address only;
  otherwise every client shares the proxy's address for the request limits.
- A new installation needs an empty state volume: a time record left by an earlier installation ends the new
  installation's evaluation.

### Security
- Idle timeout: only a person's activity extends a session (a change, or a page request the web marks after real
  input); background refreshes no longer keep an unattended browser signed in.
- License gate: Alice counts the time between its license checks itself, stops changes at the lock time without
  waiting for the next check, and pauses changes ("Alice could not check its license since …", `ALC-LIC-0009`) when
  no check has succeeded for 3 hours; the check runs in every Alice process and is retried within minutes. Queued
  work waits and resumes by itself; deployment recovery and rollback keep running.
- SSH key inventory: accounts with dots, capitals or a final `$` in their names (`john.doe`, `Deploy2`, `host$`) and
  homes with a trailing `/` are listed; every `/etc/passwd` entry Alice cannot list is shown as a server warning
  with its user ID, and the server's account list then counts as incomplete (also for a NUL byte in `/etc/passwd`,
  any non-local account source, systemd user records and an unreadable `nsswitch.conf`). The last-root-key guard
  covers every account with user ID 0.
- API tokens are revoked by an administrator's **Set a new password**, **Sign out everywhere** and **Disable**, one
  audit entry per token; a token or recovery codes can no longer be created by a session that is being signed out.
- Server addresses are checked again each time Alice connects (SSH and its own website check): a name that
  resolves to a link-local (cloud metadata), multicast, unspecified or reserved address is refused
  (`ALC-SSH-0012`).
- Requests with credentials Alice does not accept are limited per client address before the database is asked;
  stale session cookies are deleted; the public `/healthz` is limited.
- Text PostgreSQL cannot store (NUL, invalid UTF-8 in queries, `\u0000` in JSON) is refused before any handler
  (`ALC-SYS-0004`); list cursors are bounded; certificates dated outside the years 1 to 9999 are refused; an answer
  that cannot be encoded is a complete 500, never a cut-off 200.
- Parallel sign-in attempts for an existing and for an unknown user name now queue and do the same work, so their
  timing no longer tells the names apart; a small residual (a millisecond-scale database write for a real account,
  weaker legacy password hashes) is recorded in R39 item 12.
- Resetting the setup code wins against an administrator creation in progress; the master key file's directory is
  synced when the key is created.
- An installation record without its protection is never trusted, and more traces show that an installation
  existed; refusal entries are written even when the client has gone.

### Changed
- `alice-helper` 1.5.0 (protocol 6) is required; a discovery reads the key files in one pass.
- Repeated refusals of the same person, permission and request are recorded once per 10 minutes, with a later
  entry that counts the rest (`suppressed_count`; all sessions of a person together, all their tokens together).
- One audit log check or export runs at a time (`ALC-AUD-0001`, try again later); an export may take up to 10
  minutes; the CSV export starts with `# alice audit export: intact=… checked=… head_seq=… head_hash=…`.
- The public `/healthz` answers at most 60 requests a minute per address; the internal health listener and `/livez`
  are not limited.
- A signed license in a newer format asks to update Alice (`ALC-LIC-0006`) also when it has new fields; an unsigned
  or edited one is "not a valid license".
- Discarding a waiting job is possible in every license state.
- `make up` and the other development-stack targets read `deploy/docker-compose.override.yml`; `ALICE_TRUSTED_PROXIES`
  and `ALICE_LOG_LEVEL` reach Alice.
- The web interface: an error page instead of a blank screen, English when the Turkish texts cannot load, all
  waiting jobs (**Show more**), the step-up dialog closes when the session ends, and the audit log shows each entry's
  object and details.

### Added
- Error codes `ALC-LIC-0009` (license could not be checked), `ALC-SSH-0012` (address not allowed) and
  `ALC-AUD-0001` (audit check or export already running).
- Server warnings for accounts Alice could not list (by name, user or group ID, or home directory, each naming the
  user ID) and for a NUL byte in `/etc/passwd`.
- `make image-check` (the release image and its binary checked without network), build-tag checks in
  `release-symcheck` and `internal/archtest`, `tools/pincheck` (actions by commit, images by digest), Dependabot,
  `npm ci --ignore-scripts`, `go mod verify`, Vitest coverage thresholds and coverage floors for more Go packages;
  CI runs on every branch and pull request.

### Known issues
- Accounts with user IDs 1–999, `nologin` shells or no home are not inventoried; some servers keep an incomplete
  account list for good (directory services, systemd-homed, unsupported names).
- Clients behind one address (NAT, a reverse proxy without `ALICE_TRUSTED_PROXIES`, rootless Docker) share the
  limit for unaccepted credentials.
- A server name that later resolves to 127.0.0.1 is still connected to.
- The lockout of an account also blocks its step-up and password change; the CI workflow has never run on GitHub;
  the npm lockfile is not scanned for secrets.
- The full list is in `docs/security/reviews/audit-remediation.md` ("Known limitations").

## Unreleased — Phase 4: Nginx certificates

### Added
- **Nginx servers**: add a server as **Nginx server** (prepared with the `nginx` setup commands). **Discover** reads
  its SSH keys and its websites together: every `ssl_certificate`/`ssl_certificate_key` pair Nginx uses, with the
  certificate, its expiry, the file's owner and mode, and a plain reason for each place Alice cannot manage.
- **Certificates**: one list of the certificates found on servers and the ones you added, with filters, details,
  chain check and where each is used.
- Certificate upload as PEM text or PFX file (administrators and operators), checked before anything is stored;
  private keys are stored encrypted and never shown again.
- Signing requests: Alice creates the key (ECDSA P-256, RSA 3072 or RSA 4096) and the request; you add the signed
  certificate when it arrives.
- **Deploy certificate**: to one website from the server's page, or to up to 20 websites that use a certificate from
  its page. The helper backs up the current files, writes the new key and certificate, runs `nginx -t`, reloads Nginx
  and puts everything back when a step fails; Alice checks the website before and after, from its own network or
  from the server itself.
- **Deployment history** with every step, the result, the verification, and the backup folder on the server.
- Interrupted deployments are finished or undone automatically from the helper's journal on the server, also while
  the license is expired; administrators get emails for failed deployments, deployments that need manual action and
  deployments Alice cannot finish.
- **Verification settings** per website (administrators): the port and name Alice checks, or no check.
- Helper protocol 5 (`alice-helper` 1.4.0): `nginx-dump`, `nginx-test`, `nginx-deploy`, `nginx-restore`,
  `nginx-status`, `nginx-fence` (sudo, with narrow sudoers lines) and `tls-probe` (no sudo). `nginx-fence` lets
  Alice prove that an interrupted deployment it has no journal for can never be applied later.
- Error codes `ALC-NGX-0001..0010`, `ALC-CRT-0001..0017`, `ALC-DEP-0001..0024` and the audit actions
  `certificate.*`, `csr.*`, `location.*` and `deployment.*`.
- Uploading a certificate Alice already holds with an incomplete chain, now with its complete chain, completes the
  stored chain (`certificate.chain_completed`); any other repeated upload is still refused (`ALC-CRT-0008`).
- Developer targets: `make fuzz-nginx`, `make fuzz-certs`; `make test-ssh` also runs a real-Nginx matrix on Ubuntu
  22.04, Debian 12 and Rocky 9 and is part of `make ci` and of a new CI job; `go run ./tools/testcerts` writes a test
  certificate pack.
- Guides: certificates and deployments in `docs/operator-guide.md`, verification settings and deployment emails in
  `docs/admin-guide.md`, the Nginx profile, backups and manual restore in `docs/nginx-host-preparation.md`.

### Changed
- Every server needs the new helper (protocol 5): copy the `alice-helper` of this release next to the setup commands
  and run them again on each server (Alice reports older helpers with `ALC-SSH-0005` and does nothing on them until
  then; see "Updating the helper" in `docs/nginx-host-preparation.md`). The `nginx` sudoers lines changed with it
  (new `nginx-fence` line).
- The helper refuses a deployment while the website's previous change is still being finished, when Nginx is not
  running (`ALC-NGX-0010`), and for a certificate or key file whose real name (after links) has characters it does
  not accept (shown as **Not supported**). When the unfinished change is one Alice no longer follows (for example
  after a deployment whose outcome was not confirmed), a new deployment of that website undoes it once and deploys
  again (`ALC-DEP-0024` with its own email when only the undo succeeded, `ALC-DEP-0023` when it cannot undo it).
- Too many authentication failures on a server count as a refused sign-in (`ALC-SSH-0002`).
- A connection lost while signing in to a server is now "cannot be reached" (`ALC-SSH-0001`, retried), not "sign-in
  refused"; an SSH-key scan is bounded (users, files, keys, warnings, 10 minutes of reading; a cut scan says so) and
  a discovery job stops after 20 minutes.
- SSH keys: keys of accounts deleted from a server are now marked **No longer found** when the server's account list
  is complete (no LDAP or SSSD accounts, not more accounts than Alice lists); every uid-0 account and accounts with an empty shell field are
  scanned; the root last-key guard covers every uid-0 account; the **SSH keys** list marks keys that are no longer
  found.
- Lock mode also refuses certificate uploads, signing requests, deployments and verification settings; deployments
  waiting in the queue are held for an administrator. A held deployment an administrator discards ends
  **cancelled** (`ALC-DEP-0022`) without a failure email.
- A scan never changes the chain of a certificate you uploaded or whose key Alice holds; uploading the key of a
  certificate found on a server stores your chain (the certificate is then listed as uploaded); a certificate found
  only on servers keeps the leaf and its ordered chain, without other certificates of the file.
- Alice creates at most two signing-request keys at once (`ALC-CRT-0016`, try again) and keeps at most 1000 open
  signing requests for the whole installation (`ALC-CRT-0017`).
- `make coverage` enforces floors for `internal/api`, `internal/certs`, `internal/providers/nginx` and its parser;
  several existing floors were raised.

### Known issues
- A website whose `listen` names a host name resolving to another address of the server cannot be verified;
  deployments to it are refused unless an administrator turns the check off.
- Configuration files that users other than root can change make their websites (or the whole server) unmanaged.
- No private-key download, and no retry or undo button on a deployment (deploy again, or deploy the earlier
  certificate).
- Real systemd is not part of the automated tests yet.
- The full list is in `docs/security/reviews/phase-4.md` ("Known limitations").

## Unreleased — Phase 3: Servers and SSH key inventory

### Added
- **Servers**: add a Linux server over SSH, confirm its host-key fingerprint before Alice trusts it, test the
  connection, scan it, remove it. Servers count toward the license; the limit and lock mode are enforced when a
  server is added.
- `alice-helper`, a small static program installed root-owned on each server (`make helper`), and a generated
  setup script with two restricted sudoers profiles (`linux`, `nginx`) that checks the helper's SHA-256 checksum
  before installing it. Alice runs nothing else as root.
- Host-key pinning: a changed host key stops all work on that server, emails administrators once and needs an
  administrator with a recent authenticator code and a reason to accept the new key.
- **SSH keys**: inventory of every `authorized_keys` entry (users, files, options, comments) with filters and
  findings (weak keys, root keys without `from=`, forced commands, duplicates, certificate authorities, hardware
  security keys); servers that use `AuthorizedKeysCommand` are detected and not changed.
- Removing a key from one place (administrators and operators); Alice's own key is always refused, and root's last
  key needs an administrator's confirmation.
- Alice's own Ed25519 SSH key, created at first start and stored encrypted in the database; shown with the setup
  commands on **Servers** and in the wizard's new **Connect your servers** step.
- A durable job queue in PostgreSQL with leases, retries, crash recovery and one job per server at a time; work
  paused by an expired license waits for an administrator after renewal.
- Daily audit chain verification and hourly clean-up of expired sessions and old jobs; emails to administrators for
  a broken audit chain, a job that stopped after its last attempt and a job changed in the database.
- Developer targets: `make helper`, `make fuzz-ssh`, `make test-ssh` (real OpenSSH on Ubuntu 22.04, Debian 12,
  Rocky 9); the e2e stack runs as the separate compose project `alice-e2e` with an SSH test server.
- The re-pin dialog offers **The server still shows the previous fingerprint**: an administrator can end a host-key
  block from the UI when the previous fingerprint is still right (audited `hostkey.change_dismissed`).
- A server that cannot be reached is tested again once per discovery interval and scanned as soon as the test
  succeeds; a successful scan or key removal also brings it back to **Connected** (`target.status_changed` reasons
  `discovery_ok`, `removal_ok`).
- Audit action `job.cancelled_license` for a read-only job the license lock cancelled; `job.dead` carries
  `shutdown=true`, and sends no email, when Alice's own shutdown cut off the last attempt.
- `ALC-SSH-0011`: a versioned build without the helper checksums answers this code on **Prepare a server for Alice**
  instead of a generic error, and logs a warning at startup.

### Changed
- Every state-changing API route belongs to exactly one license lock group; `GET /api/v1/license/status` answers
  `ALC-SYS-0002` until the first license evaluation has finished.
- A changed installation record is audited once per occurrence (`license.installation_tampered`), and restoring it
  is audited too (`license.installation_restored`).
- On a new installation the audit log now starts with `platform_key.created`.
- Builds other than development builds (version `dev`) need the helper checksums: `make build` and the image build
  embed them, and a build without them offers no setup commands.
- Helper protocol 3 (helper 1.2.0): `authkeys-write` takes `--content-sha256` and refuses incomplete content
  (`CONTENT_MISMATCH`), so a dropped connection never leaves a truncated `authorized_keys`. The sudoers line changed
  with it: run the setup commands again with the new `alice-helper` on servers prepared with an earlier build
  (Alice reports them with `ALC-SSH-0005`, helper outdated).
- The setup commands check and install a root-private copy of `./alice-helper`, create `alice-svc` without
  `/etc/skel` files and empty its home on every run; keep the helper in a directory only you can write.
- The helper lists key files as unsupported when another user could redirect them: an absolute `AuthorizedKeysFile`
  directory that is reached through a symlink or not controlled by root (for example a user-owned `/srv/keys/%u`),
  and every file of an account with a directory above its home that is not root's or is writable by others
  (root-owned symlinks such as `/home -> /data/home` work; a `..` in such a link does not). It answers
  `HOME_NOT_WRITABLE` when a user's `.ssh` cannot be created, removes lock files unused for 30 days, and reading or
  writing a key file may take up to 60 seconds.
- **Test connection** always opens a new SSH connection; removing a server closes the connections Alice kept open to
  it.
- Scheduled work runs at most once per discovery interval per server, whatever its outcome; a failed scheduled
  re-test ends without a dead-job email (becoming unreachable sends no email of its own; a scan, or a test a person started, that fails on its last attempt still sends the `job.dead` email); a confirmed server
  left at **Checking…** by a restart or the license lock is tested again by the scheduler.
- A new server that cannot be reached before its fingerprint is confirmed stays "Waiting for fingerprint
  confirmation"; confirm, re-pin and dismissal always start a new connection test.
- A job whose lease cannot be renewed is stopped and handed back before the lease runs out; a key removal applied
  while its server was deleted is still recorded, and a removal retry that finds its server deleted is recorded as
  failed and stops for a person.
- The database checks server addresses, ports and fingerprint formats; local-use NAT64 addresses
  (`64:ff9b:1::/48`) that translate to link-local, multicast or broadcast addresses are refused.
- Web: progress waits through network errors, a stopped task says so, the setup wizard no longer reports success
  after a failed first check, and several Turkish texts were corrected.
- Development: `make image` builds `alice:ci` (never the `alice:dev` tag of the `make up` stack); the e2e stack
  publishes `ALICE_E2E_PORT` (default 9443) so it runs beside the `make up` stack; `make ci` removes it at the end.

### Known issues
- Accounts that exist only in LDAP or SSSD are not inventoried.
- Keys of an account deleted from a server (or switched to a `nologin` shell) stay listed as found and cannot be
  removed through Alice; see `docs/operator-guide.md`.
- Replacing Alice's own SSH key needs the vendor; there is no command for it.
- The full list is in `docs/security/reviews/phase-3.md` ("Known limitations").

## Unreleased — Phase 2: Licensing

### Added
- Signed licenses per installation (Ed25519 over RFC 8785 canonical JSON), limited by managed targets; the
  Installation ID (`ALICE-XXXX-XXXX-XXXX-XXXX`, with a check character) is created at first start and kept by
  restores.
- 30-day evaluation (5 targets) from the installation date; the setup wizard's new license step (upload a license or
  start the evaluation).
- **License** page: Installation ID with Copy, state, "Valid until <date>, N targets", target usage, uploaded
  licenses, history; upload with a server check, a confirmation dialog and step-up.
- License banners on every page (evaluation, warnings 60/30/14/7/1 days, grace, lock, clock problems, damaged
  license data, pending license, target limit) and warning emails to administrators, each sent once (SMTP from
  `ALICE_SMTP_*`, TLS only).
- Lock mode after the 7-day grace period (directly after the evaluation): automatic work that changes servers
  pauses; changes to servers are refused (`ALC-LIC-0001`); sign-in, license upload, backups, audit, exports, user
  administration and tokens keep working. Nothing is deleted.
- Clock protection: a server clock set back never extends a license; a forward jump of more than 48 hours waits
  24 hours before it can start the grace period or the lock.
- The installation record (Installation ID and evaluation start) is protected by a key derived from the master key:
  a changed or deleted record never starts a new evaluation (audited as `license.installation_tampered`).
- `licensectl` (vendor only, never shipped): `keygen`, `issue`, `inspect`, `verify`, `keyset`, `ledger-verify`,
  with an encrypted key file and a signed issuance ledger.
- CLI: `alice license status`, `alice license keys`.
- Coverage floors enforced by `make coverage` (`coverage-floors.json`).
- Guides: `docs/licensing.md`; vendor guide `docs/vendor/licensing-vendor.md` (not shipped).

### Changed
- Finishing setup now needs a license choice (`ALC-SET-0009`).
- New volume `alice-state` at `/opt/alice/state` (back it up with the others).
- The permission `setup.finish` was removed (unused).
- `make ci` runs `make coverage` instead of `make test-integration`.

### Known issues
- Until the vendor's public key is built in, release builds accept no license (evaluation only), and
  `make release-keycheck` fails.
- Nothing in this release changes servers yet, so lock mode only shows its banners; the refusal of changes becomes
  visible with targets in the next release.
- Certificate expiry emails with the "license expired" note arrive with alerts in a later release.
- The full list is in `docs/security/reviews/phase-2.md` ("Known limitations").

## Unreleased — Phase 1: Core

### Added
- Setup wizard: one-time setup code, language, administrator account with mandatory authenticator app and
  10 recovery codes, recovery passphrase (generates the backup key pair).
- Local sign-in with Argon2id passwords (12–128 characters, 100,000-entry leaked-password list), mandatory TOTP,
  recovery codes, progressive delay and 15-minute lockout, step-up confirmation for sensitive changes.
- Sessions (`__Host-alice_session`, 30 minutes idle, 12 hours absolute) with CSRF protection and rate limits.
- Roles Administrator, Operator and Auditor enforced on every API route from one permission table
  (`docs/authz-matrix.md`).
- User management, personal API tokens (read or operate scope, at most 365 days).
- Tamper-evident audit log with viewer, CSV/JSON export and integrity verification (`alice audit verify`).
- Envelope encryption (AES-256-GCM, per-secret key) with a master key file; the application database role cannot
  change or delete audit entries.
- CLI: `alice setup-token --reset`, `alice audit verify`, `alice admin reset-mfa <username>`,
  `alice admin unlock <username>` (ends a sign-in block; `make unlock ACCOUNT=<username>`).
- Guides: `docs/first-run.md`, `docs/admin-guide.md`, `docs/operator-guide.md`.

### Changed
- `/api/v1/version` now requires sign-in.
- Database errors for a wrong password or a missing database stop startup immediately with a clear message.
- Development stack: separate `alice_app` database role; run `make reset` once after upgrading from Phase 0.

### Known issues
- The setup code comes from `alice setup-token --reset` (`make setup-token`); the installer prints it from a later
  release.
- The wizard ends after the recovery passphrase; HTTPS certificate upload, email, license and first target steps
  are added later. (Phase 2 adds the license step.)
- Account blocks and audit-integrity problems are recorded in the audit log but not emailed or sent to syslog, and
  there is no automatic daily integrity check yet.
- People created by an administrator are not forced to change their initial password.
- API tokens with "read and operate" access can do nothing more than read-only tokens until targets exist.
- In the development stack the database owner used for migrations is the PostgreSQL superuser, and its password is
  in the `alice` container (see `docs/operator-guide.md`).
- The full list, with the security review, is in `docs/security/reviews/phase-1.md` ("Known limitations").
