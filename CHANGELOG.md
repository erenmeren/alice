# Changelog

## Unreleased — Windows servers (Centralized Certificate Store, R68)

**Added**
- Windows servers whose IIS reads its certificates from a Centralized Certificate Store (CCS) in a local folder: each
  PFX file of the folder (`<host>.pfx`, `_.<domain>.pfx` for a wildcard) is a location of its own, listed under
  **Websites on this server** with the IIS sites that IIS serves from it (the exact file first, else the nearest
  wildcard file). An IIS site whose host has no file is shown with the hint to place the first file; a file no IIS site
  uses can be deployed and is checked by reading it back.
- **CCS password** panel on a Windows server's page: an Administrator enters the store's private-key password once
  (with step-up; 12 to 128 printable ASCII characters, no spaces). It is sealed on the Alice server, goes to the
  server's helper only on standard input while a file is read or written, and is never shown again; the panel shows
  the date it was set. API `PUT /api/v1/targets/{id}/ccs-password`; `ccs_password_set_at` on a Windows server; audit
  `target.ccs_password_set`.
- A deployment to a CCS file writes the certificate into the file in place: a temporary file in the same folder, then
  Windows' `ReplaceFile` with a backup `<file>.alice-<8 hex>.bak` beside it; the helper then tells IIS to read the file
  again and reads it back. The IIS sites that use the file are checked by their host names; when the check fails, the
  backup is put back. The deployment's steps are **Import the chain**, **Write the file** and **Verify**. A file
  replaced outside Alice is drifted and can be repaired; ACME renewals and Key Vault versions reach CCS files like any
  location. The daily cleanup removes the backups and temporary files after at most 7 days. Each write is event 1004 in
  the server's Application log.
- Codes `ALC-WIN-0015` to `ALC-WIN-0020` (the store turned off, its folder changed, a password that does not open the
  file, no password, a password Alice cannot use, a file no longer in the folder; see
  [troubleshooting.md](docs/troubleshooting.md)). The e-mails of a failed rollback, an unknown outcome and an unverified
  restore of a CCS file name the file, its backup and IIS Manager. English and Turkish.

**Changed**
- `alice-helper.exe` 1.1.0 adds `ccs-dump` and `ccs-deploy` (protocol 1). Alice manages CCS files only with a 1.1.0
  helper; a 1.0.0 helper keeps every other feature and is never sent a CCS command. Update the helpers first, then
  Alice.
- The http.sys entry that sends IIS to the store stays not supported (it names no certificate); its text and the
  server warning now point to the CCS files and the password panel.

**Not in this release**
- A CCS folder on a share of another server, creating a CCS file that does not exist yet, removing the CCS password,
  and a store whose password does not follow the rule above.

Rulings: `docs/superpowers/rulings/windows-iis.md` "W5 (R68)". Migration `00036` (the location kind `win_ccs_file` and
the credential purpose `win_ccs`).

## Unreleased — Fixes batch 2 (R67)

**Changed**
- An automatic deployment that was still queued when its service's policy forbade automatic deployment now ends with
  `service.auto_deploy_forbidden` before anything is sent, instead of going ahead; deployments a person asked for are
  unchanged.

**Fixed**
- The vendor console's pages print dates in UTC on every page.

## Unreleased — Canary deployment (R65)

**Added**
- **Canary deployment**: a service's policy (**Policy** tab, **Canary deployment**) can deploy its certificates to a few
  websites first (a number or a percentage, and websites that always go first), observe them for a hold of 1 minute to
  24 hours with checks every 15 seconds to 10 minutes, and only then deploy to the rest. Each check is the TLS check of a
  deployment plus, optionally, an HTTPS request to a path of the website (for example `/healthz`) with the expected
  statuses, sent only to the website's own address. Failed checks in a row (2 by default), a failed first-wave
  deployment, or no passing check until shortly after the hold put every first-wave website back to its previous
  certificate; the others are never touched. Applies to deployments from a certificate's page, Key Vault and ACME
  **Deploy now**, and the automatic deployments of ACME renewals and Key Vault versions.
- The deployment's page shows the **Canary deployment** panel: the state and why it ended, the time left, both waves
  with each website's deployment and the latest check, **Continue now** (with a fresh confirmation) and **Abort**. The
  history marks **Canary · wave 1** and **Canary · wave 2**, and a first-wave deployment **Under observation**.
- **Deploy to all at once** in the deploy dialogs skips the canary for one deployment with a fresh confirmation, unless
  the service's policy forbids it. API tokens can neither skip nor continue a canary.
- API: `GET /api/v1/deployment-rollouts/{id}`, `POST …/actions/continue`, `POST …/actions/abort`; `canary_override` on
  the three deploy routes; `rollout` in deploy answers and deployments, `canary` in a deployment's detail;
  `rollout_id` filter of the deployment list. New codes `ALC-DEP-0031` to `ALC-DEP-0035` and `ALC-SVC-0020` (see
  [troubleshooting.md](docs/troubleshooting.md)).
- E-mail "Canary deployment of <certificate> stopped before its second wave" when a canary a person asked for reaches
  its hold's end while the licence does not allow changes.

**Changed**
- A deployment can be in the new state **Under observation** (`holding`, status `running`) while its canary observes it.
- The service policy key `canary` is no longer refused as "not available yet".

**Security**
- The canary's check dials only a managed website's own address through the same address rule as every connection to a
  managed server, compares the served certificate before it sends anything, and follows no redirect and no proxy
  (STRIDE CN-1..CN-5, SEC-110, KI-44).

Rulings: `docs/superpowers/rulings/canary-deployment.md`. Migration `00035_canary_deployment.sql`; codes
`ALC-DEP-0031`..`ALC-DEP-0035`, `ALC-SVC-0020`; KI-44.

## Unreleased — Fixes batch 1 (R66)

**Added**
- The revocation check of a certificate found by network discovery, in its details.

**Changed**
- A deployment to a disabled server is refused with `ALC-TGT-0006` (it was `ALC-DEP-0011`); a key compromise incident's
  place on a disabled server fails at once with that reason instead of after 30 engine runs as busy.

**Fixed**
- The websites panel of an ACME certificate names a Windows binding as a binding, and the help for adding websites and
  the Key Vault texts say that Windows (IIS) is deployable too.
- The release package checks that each helper checksum file lists exactly its binaries, each once and well formed.

## Unreleased — Hardening batch 1 (R64)

**Added**
- **Incidents** in the navigation: every key compromise incident of your services, newest first, with a filter (all,
  open, needs attention, completed, closed) and paging. An incident opened from the list goes back to it.
- E-mails when a key compromise incident needs attention and when it completes, to the certificate's service
  recipients (the Administrators when nobody else is named), once per change and also while the licence is locked.
- Revocation checks: Alice asks the authority that issued each certificate (OCSP, then CRL) whether it was revoked,
  about once a day per certificate, and certificates found by network discovery too. A revocation the authority signed
  marks the certificate revoked for good (never deployed again, an issued certificate renewed at once) and is e-mailed
  once; a suspension is shown and e-mailed but not marked; unknown and unreachable answers are only shown. The
  certificate's page shows the last check; the switch is in **Settings**, **General**. New codes `ALC-CRT-0020` to
  `ALC-CRT-0026` (see [troubleshooting.md](docs/troubleshooting.md)).

**Changed**
- `alice-helper` 1.11.0 (protocol 11, same sudoers file) reads a first certificate labelled `TRUSTED CERTIFICATE` or
  `X509 CERTIFICATE`, as Nginx does; before, such a file showed its intermediate as the website's certificate. The
  rollback guard reads the same leaf.
- A person of a website's service may release its own websites from a Key Vault binding of another service.
- The incident list API takes `state` and `cursor` and answers `next_cursor`.

**Fixed**
- An incident's Windows store notice is recorded once per incident and certificate, so two cleanup jobs at once, or a
  pruned outbox, never send it twice.
- A refusal of a disabled server is stored with its own code (`target.disabled`) where the incident engine stores it,
  locked against the API catalogue with the key deploy job's reasons.

**Update note.** After an update the revocation check is off; switch it on in Settings, General, once the Alice host may
reach your certificate authorities over HTTP and HTTPS. Update the helpers to 1.11.0.

Rulings: `docs/superpowers/rulings/hardening-2026-10-24.md`. Migrations `00033_incident_notices.sql`,
`00034_revocation_checks.sql`; codes `ALC-CRT-0020`..`ALC-CRT-0026`; KI-43.

## Unreleased — Windows servers (CI and release, R63)

**Added**
- The release package carries the Windows helper: `helper/alice-winhelper-windows-amd64.exe`,
  `helper/alice-winhelper-windows-arm64.exe` and their checksum file `helper/alice-winhelper.sha256`, all listed in the
  signed `SHA256SUMS`. Take `alice-helper.exe` from there (see
  [windows-host-preparation.md](docs/windows-host-preparation.md)); `make release` builds them, and the stage refuses a
  missing or changed helper.
- Every change to the Windows helper or provider, every night and every release tag run the helper's real-host tests on
  Windows Server 2022 and 2025; each run builds the helper the package ships on both images and compares it byte for
  byte with the Linux release build, and the setup script test installs those bytes (the other real tests run the
  same source built by the test); one check,
  `windows-required`, reports the result (how to require it: `docs/dev/windows-ci.md` in the source repository). `release.yml`
  stages a tag only after that check passed.

**Changed**
- `alice-helper.exe` 1.0.0, the first released Windows helper. It adds nothing over 0.3.0: a 0.3.0 helper keeps every
  feature, a 0.2.0 helper still deploys (no cleanup). Update the helpers first, then Alice.
- The setup script names the package's `helper\` folder when the helper is missing or does not match.

**Fixed**
- The websites of an issued certificate (ACME) speak of a Windows binding as a binding, not as a certificate file
  (`location_kind` on the ACME binding).

Rulings: `docs/superpowers/rulings/windows-iis.md` "W4 (R63)". No migration, no new error code.

## Unreleased — Windows servers (drift and cleanup, R62)

**Added**
- Windows servers (drift and cleanup): a Windows binding bound to an ACME or Key Vault certificate is watched like a
  certificate file. When another tool points it to another certificate, Alice shows it as drifted and, in automatic
  mode, deploys the right certificate again (a binding that keeps changing back is left alone, as for a file). When
  the certificate is removed from its store or Windows can no longer use its key, Alice reports it with that cause
  once and does not try to repair it (`ALC-WIN-0013`). Drift e-mails speak of bindings and the certificate store, and
  mention Windows' `IIS-AutoCertRebind` task when the server runs it.
- A daily cleanup removes from a Windows server the certificates Alice imported, with their private keys, once
  nothing uses them: no binding of any application, not the Remote Desktop or a WinRM listener, no unfinished change
  of the helper, no deployment that may still roll back to them, and not before 7 days unused (or once expired). A
  certificate replaced after a key-compromise incident is removed at once; when a compromised certificate stays in a
  store (Alice did not import it, or something still uses it), its owners get one notice naming the store and
  thumbprint. Intermediate certificates are never removed. Each removal is in the audit log
  (`windows.certificate_removed`) and the server's Application log (event 1003). The helper also removes its own old
  journals.
- A server setting **Remove certificates Alice imported once nothing uses them** (on by default), and the label
  **Imported by Alice** on the certificates of a binding. Code `ALC-WIN-0014` (Alice could not tell whether the
  cleanup finished; the next run settles it). English and Turkish.

**Changed**
- `alice-helper.exe` 0.3.0: copy it from this release to each Windows server (see
  [windows-host-preparation.md](docs/windows-host-preparation.md)); a 0.2.0 helper keeps deploying, but Alice cleans up
  nothing on it until it is updated. Migration `00032` adds the cleanup setting to servers (on for every server).
  Rulings: `docs/superpowers/rulings/windows-iis.md` "W3 (R62)".

## Unreleased — Windows servers (deployment, R61)

**Added**
- Windows servers (deployment): certificates deploy to the HTTPS bindings of http.sys on a Windows server, manually
  and by ACME and Key Vault bindings. Alice's helper imports the intermediates into the machine's `CA` store and the
  certificate with a private key that cannot be exported into the binding's own store (`My` or `Web Hosting`), points
  the binding to it in one change that keeps every other setting of the binding, and reads it back. A journal on the
  server lets Alice finish or undo an interrupted deployment; each change is logged in the Application event log
  (source `Alice Helper`, events 1001 and 1002).
- Verification as for Nginx (Installed, Served, Trusted), with a fresh connection per check; for a binding Alice cannot
  reach, the helper checks it from the server. When Windows sends another chain than Alice deployed, the deployment
  page says so. A failed check puts the previous certificate back, never a revoked or compromised one (checked on the
  server too).
- **Websites on this server** groups a Windows server's bindings by the certificate they serve; the deploy dialog can
  select every binding of one certificate. Deployment pages, notices and e-mails show the Windows steps (import the
  chain, import the certificate, bind) and name the previous certificate by store and thumbprint.
- Codes `ALC-WIN-0004` to `ALC-WIN-0012` (binding changed or not found, server busy, a file or store error on the
  server, an unusable key, a missing previous certificate, a binding Alice does not deploy to, a refusal of the
  helper), with troubleshooting entries. English and Turkish.

**Changed**
- `alice-helper.exe` 0.2.0: copy it from this release to each Windows server (see
  [windows-host-preparation.md](docs/windows-host-preparation.md)); Alice names an older helper outdated before
  changing anything. Alice's own TLS check no longer offers session tickets (for every server type: it never resumed
  a session). No migration. Rulings: `docs/superpowers/rulings/windows-iis.md` "W2 (R61)".

## Unreleased — Windows servers (discovery, R60)

**Added**
- Windows servers (discovery): **Add server → Server type Windows server** adds a Windows Server 2019, 2022 or 2025
  machine, with or without IIS, signed in over Windows OpenSSH with Alice's own key as a local account (`alice`) or a
  domain account (`CORP\alice-svc`). A PowerShell setup script, shown for review, prepares the server once: OpenSSH
  Server, the account, the key, an sshd block that runs only `alice-helper.exe` for the account, the helper after
  checking its SHA-256, and a firewall rule ([windows-host-preparation.md](docs/windows-host-preparation.md)).
- Alice lists every HTTPS binding of http.sys (the Windows HTTP server of IIS, WinRM, SSTP and others) under
  **Websites on this server**, with the IIS sites that use it (column **IIS site**) and the certificate bound there,
  linked to the certificate inventory by its fingerprint. Bindings of other applications, Centralized Certificate
  Store bindings and bindings in other stores are listed as not supported, with the reason; a certificate missing from
  its store, a missing key or a key Windows cannot use are shown as problems. The server shows its Windows and IIS
  facts and warnings (shared IIS configuration, the AutoCertRebind task, expired certificates in the store).
- Codes `ALC-WIN-0001` (the helper is missing or sshd does not run it), `ALC-WIN-0002` (the helper is outdated) and
  `ALC-WIN-0003` (the account does not get an administrator token), with troubleshooting entries. English and Turkish.
- `make winhelper` builds `alice-helper.exe` for Windows x64 and ARM64 reproducibly; its checksums are built into Alice
  and the setup script. A real-Windows test workflow runs on Windows Server 2022 and 2025.

**Changed**
- On a Windows server Alice only reads in this release: deployment, drift and cleanup follow in a later release (the
  deploy controls are shown disabled). No migration. `internal/api/nul.go` was renamed so the repository checks out on
  Windows. Rulings: `docs/superpowers/rulings/windows-iis.md`.

## Unreleased — Groundwork for Windows, F5 BIG-IP and Kubernetes targets (R59)

**Added**
- The groundwork the Windows server, F5 BIG-IP and Kubernetes targets share (phase G of the deployment targets roadmap):
  certificate locations of other kinds than a file (an http.sys binding, a client SSL profile entry, a TLS Secret),
  identified by a locator; a probe address per such location (the address Alice checks, for example a load balancer's
  internal address); Alice-held backups for a target that keeps no copy of what it replaces, sealed and deleted 7 days
  after the deployment is final; the sign-in secrets of API targets; TLS server identities pinned like SSH host keys.
  No such target can be added yet: each comes with its own phase.
- API: a website location gains `kind`, `locator`, `details` and `verify_address`; `PATCH /api/v1/locations/{id}` takes
  `verify_address` for a location that is not a certificate file. Deployment steps may be named `import_chain`,
  `import_certificate`, `bind`, `upload`, `install`, `commit`, `sync`, `save` and `write_secret` (labelled in English
  and Turkish).

**Changed**
- Nothing changes for Nginx, Apache, HAProxy and Key Vault: their locations are certificate files, which keep no
  locator and no probe address. Migration `00031` (its Down refuses while data of the new targets exists). Rulings:
  `docs/superpowers/rulings/deployment-targets-groundwork.md`.

## Unreleased — Built-in DNS providers for the DNS proof (Cloudflare, Azure DNS, Amazon Route 53)

**Added**
- Alice can publish the DNS proof record itself through **Cloudflare** (an API token), **Azure DNS** (a service
  principal with a client secret or a certificate, or the managed identity of the machine Alice runs on) and **Amazon
  Route 53** (an access key, optionally assuming a role), besides a DNS hook (R57). **Settings → Certificate
  authorities → DNS publishing → Add DNS provider**; a certificate chooses a provider like a hook. Alice finds the zone
  of each name (the longest public zone that holds it), keeps every other value of the record, waits until Route 53
  reports the change on all its servers, and removes only its own value afterwards, also through a provider that was
  removed since.
- The credentials are encrypted and write-only like the hook secret; an empty field on a change keeps them. Alice
  reaches only the providers' own API hosts.
- Codes `ALC-ACM-0042` (no zone of the provider holds the name), `ALC-ACM-0043` (the provider refused the credentials;
  automatic renewal stops) and `ALC-ACM-0044` (the provider failed or could not be reached; automatic renewal retries
  an outage), with troubleshooting entries.
- API: `/api/v1/acme/hooks` takes `kind` (`webhook`, `cloudflare`, `azure_dns`, `route53`, fixed at creation) and the
  provider's settings and credentials, and shows `kind` and `settings`.

**Changed**
- The section **DNS hooks** is now **DNS publishing**, and the proof method reads **DNS proof (DNS record)**. Existing
  hooks are unchanged (migration `00030`; a downgrade below it is refused while a provider exists). Rulings:
  `docs/superpowers/rulings/acme-dns-providers.md`.

## Unreleased — Let's Encrypt staging acceptance harness

**Added**
- `make le-staging` (with `make le-staging-build`): an acceptance run of Alice's real ACME code against the Let's
  Encrypt staging service, for a domain the owner controls. It covers the account (reused between runs), an order with
  the web proof (HTTP-01, served by the harness or through a webroot) or the DNS proof (DNS-01 through the DNS hook, or
  by hand; optionally with a wildcard), finalize, the chain checked against the staging roots fetched from
  letsencrypt.org, renewal information (ARI), a renewal with `replaces`, revocation and the clean-up. It prints PASS or
  FAIL per step. It honours the CA's `Retry-After`, revokes what an interrupted run left behind, skips without its
  `ALICE_LE_*` variables and refuses the production service unless `ALICE_LE_ALLOW_PRODUCTION=yes`. Runbook:
  `docs/dev/le-staging-acceptance.md`. The harness (`test/lestaging`) is tested against the fake CA in `make test`; DNS
  providers plug in through `RegisterDNSProvider`. Nothing in `make ci` contacts Let's Encrypt.

## Unreleased — Service owners and e-mails routed by service (scoped access, phase 4)

**Added**
- Each service has **owners** (R56): people and directory groups responsible for it, listed on its page's
  **Overview** and changed by an Administrator of all services with **Edit owners** (a fresh confirmation code; audited
  as **Service owners changed**). Being an owner gives no access; Alice warns about an owner who receives e-mails but
  cannot open the service.
- The e-mails about a service's servers, Key Vaults, certificates, ACME certificates, deployments, website drift, SSH
  key rotations and stopped tasks go to its owners (an enabled person with an address; the enabled members of an owner
  group seen at their last sign-in, with an address) and to the extra addresses of its policy, besides the recipients of
  **Settings → Recipients**, whom a service's policy may leave out of its own e-mails. An e-mail about several services
  goes to the recipients of each. The "and N more" expiry e-mail counts, for each recipient, only the notices that
  concern them.
- API: `GET /api/v1/services/{id}/owners` (everyone who sees the service), `PUT /api/v1/services/{id}/owners`
  (`services.manage`, never a token; the service's version in the body); code `ALC-SVC-0019` (an automation account
  cannot own a service).

**Changed**
- With only the Default service, no owners and the default policy, every e-mail goes to exactly today's recipients.
  The e-mails about Alice itself (the license, backups, the sign-in block, the audit chain, a tampered task, the test
  e-mail) always go to the recipients of **Settings → Recipients** only. A service e-mail that would reach nobody goes to
  those recipients. A rotation notice delivered to an owner lets the scheduled run start. `ALC-SVC-0010` now also
  answers a change of owners based on an older state of the service. No migration (`00026` holds the owners). Rulings:
  `docs/superpowers/rulings/scoped-access.md` ("Phase 4").

## Unreleased — Groups, automation accounts and tokens limited to services (scoped access, phase 3)

**Added**
- A role on a service or an environment can be given to a group of a single sign-on provider or a directory (R54).
  **People & access**, **Groups** lists the groups added, with the people Alice saw in them at their last sign-in and
  the group values seen at sign-ins, adds and removes groups and their roles (a fresh confirmation code; audited). A
  person's **Access** shows the rights they have through groups.
- A single sign-on or directory user without a group mapped to a role on all services signs in when a role on a service
  reaches them, their own or a group's, and then reaches only those services. Without either the sign-in is refused as
  before. Leaving the group takes effect at the next sign-in or confirmation.
- **Automation accounts** on **People & access**: accounts for pipelines and scripts that never sign in and only hold API
  tokens, made by an Administrator. Their role on all services is none, Operator or Auditor; they may hold any role on
  services or environments. An Administrator creates and revokes their tokens; disabling an account revokes its tokens.
- **Limit to services** on **API tokens** (and on an automation account's tokens): the token then acts only on those
  services, never on People & access, settings, the license, backups or the audit log, even an Administrator's.
- API: `GET/POST /api/v1/directory-groups`, `DELETE /api/v1/directory-groups/{id}`, `GET/POST /api/v1/automation-accounts`,
  `PATCH /api/v1/automation-accounts/{id}`, `GET/POST /api/v1/automation-accounts/{id}/tokens`,
  `DELETE /api/v1/automation-accounts/{id}/tokens/{token_id}` (`access.manage`); `directory_group_id` on
  `POST /api/v1/role-bindings`; `group_bindings` in `GET /api/v1/users/{id}/access`; `service_ids` on tokens; codes
  `ALC-ACC-0002`, `ALC-ACC-0003`, `ALC-ACC-0006`, `ALC-ACC-0007`, `ALC-ACC-0008`, `ALC-TOK-0002`.

**Changed**
- Alice keeps the groups of single sign-on and directory users from their last sign-in (at most 1000; more are dropped
  and recorded). A refused sign-in for no access also forgets them. `GET /api/v1/users` lists people only.
- Migration `00029`: no session, authenticator or recovery code can ever be stored for an automation account; the groups
  seen at sign-in are indexed by value. Rulings: `docs/superpowers/rulings/scoped-access.md` ("Phase 3").

## Unreleased — Service policy (scoped access, phase 5)

**Added**
- Each service has a versioned policy (R55), on its page's new **Policy** tab: the domains its certificates may carry
  (names, wildcards at any depth, IP addresses and CIDR blocks), how certificates may enter it (ACME, upload, signing
  request), the certificate authorities, proof methods and key types of its ACME certificates and their default renewal
  window, whether automatic deployment is allowed, the default revocation of a key-compromise incident, and who else
  receives its e-mails (saved now, used once e-mails are routed by service). **Versions** lists every version with what
  changed and who saved it.
- A new ACME certificate or a change of its names or settings, a signing request, an upload and a move into the service
  outside the policy are refused before anything is stored, ordered or generated. While automatic deployment is
  forbidden it cannot be switched on, and the automatic deployments already on wait with a mark on each website until it
  is allowed again.
- An Administrator of the service changes the policy with a fresh confirmation code; the domains are an Administrator
  of all services' only. API: `PUT /api/v1/services/{id}/policy` (permission `services.policy`, never a token; the
  version read in the body); codes `ALC-SVC-0008` to `ALC-SVC-0011` and `ALC-SVC-0013` to `ALC-SVC-0015`. Audit
  entries **Service policy changed** (with the changed parts) and the automatic deployment holds.

**Changed**
- Nothing changes for a service without rules: every service starts with the empty policy. No migration. Rulings:
  `docs/superpowers/rulings/scoped-access.md` ("Phase 5").

## Unreleased — Roles on services (scoped access, phase 2)

**Added**
- A person's role can be held on single services or on an environment ("every service in Production") besides, or
  instead of, **All services** (R53). On **People & access**, a person's **Access** section lists their roles and adds
  or removes them (a fresh confirmation code; audited); **Explain** shows what they add up to; a service's page has an
  **Access** tab. A person may have **No role on all services**; with no role at all they see "You do not have access
  to anything yet".
- Such a person sees, counts, exports and acts on only their services' servers, Key Vaults, certificates, signing
  requests, SSH keys, ACME certificates, scan scopes and findings, jobs, deployments and incidents; the dashboard counts
  them only. Anything of another service answers as if it did not exist; a certificate or key of another service on one
  of their servers shows the places on their servers and "and N more outside your services". Creating in, deploying to,
  moving between and trusting services need the role on every service involved. People, settings, the license, single
  sign-on and directories, backups, the audit log and discovery scopes stay with roles on all services.
- API: `GET/POST /api/v1/role-bindings`, `DELETE /api/v1/role-bindings/{id}`, `GET /api/v1/users/{id}/access`
  (permission `access.manage`: an Administrator with all services and a fresh code, never a token); `access` in
  `GET /api/v1/auth/session`; `allowed_actions` on rows, `hidden_count` on detail lists, `{"outside": true}` for a
  service outside the caller's; codes `ALC-SVC-0005`, `ALC-SVC-0006`, `ALC-SVC-0012`, `ALC-ACC-0001`, `ALC-ACC-0005`,
  `ALC-USR-0004`.

**Changed**
- A user's `role` may be `null` (no role on all services). Every audit entry about a resource names its service
  (`details.service_id`); an export by a person with roles on some services records them (`details.reach`).
- Nothing changes for an installation without role bindings: everybody keeps their role on all services.
- Migration `00028`: the administrator the setup wizard created always keeps a role on all services; role bindings are
  indexed by service and environment. Rulings: `docs/superpowers/rulings/scoped-access.md` ("Phase 2").

## Unreleased — What should be there, what was deployed, what is there today

**Added**
- For every certificate file that follows a certificate (an issued certificate or a Key Vault certificate), Alice
  keeps four facts apart, each with its own time: the certificate it should have, what Alice last deployed, what the
  file held at the last scan that read it, and what the website served at the last check (from Alice or from the
  server itself, with the R51 trust). Its state comes from them: **In sync**, **Changed outside Alice**, **Waiting for
  deployment**, **Not reachable**, **Not checked recently** (R52). The issued certificate's page and the server's page
  show them per place, with a summary ("Live and verified on 17 of 20 places; 2 not reachable; 1 serves another
  certificate (it ends in 18 h)").
- Alice checks those places about every 6 hours (`drift.schedule` and `drift.observe`, read-only: a certificate-only
  scan and the deployment's own check of the website).
- Per place, what Alice does when it changes outside Alice: **Report only**, **Prepare a repair** (**Repair** deploys
  the right certificate again with one click) or **Repair automatically** (`drift.repair`, continuity work: a
  deployment through the engine, with every guard; an administrator's choice with a fresh code). Automatic repair stops
  after 3 repairs within 24 hours that came back ("another tool keeps changing this file") or failed. E-mails, once
  each: changed outside Alice, repair ready, put back, stopped (TR/EN).
- API: `observation` on every certificate location and ACME binding; `PUT /api/v1/locations/{id}/drift-mode`, `POST
  /api/v1/locations/{id}/actions/repair`; codes `ALC-DEP-0027` to `ALC-DEP-0030`.

**Changed**
- An ACME binding is **Up to date** (`current`) only while no check newer than the deployment disagrees; a past
  successful deployment alone no longer counts. New state `drifted` (**Changed outside Alice**).
- Places connected before this version keep **Report only**: nothing is repaired until you choose. A place connected
  later repairs automatically by default when automatic deployment is on for it.
- Migration `00027` (`certificate_locations.file_observed_at`, `location_observations`, the deployment trigger
  `drift_repair`, three alert kinds). Rulings: `docs/superpowers/rulings/certificate-drift.md`.

## Unreleased — Services, environments and trusts (scoped access, phase 1)

**Added**
- **Services**: a service groups servers, Key Vaults, certificates, signing requests, ACME certificates, SSH keys and
  scan scopes (for example "Payments (production)"), with an optional **environment** (production, staging, test and
  development come with Alice; Settings → Environments). Every existing resource is in the protected **Default**
  service, and nothing changes for anybody until a second service exists (R49). Administrators create, rename and
  delete services (only an empty one, `ALC-SVC-0003`; never the Default service, `ALC-SVC-0004`), move resources to a
  service (**Move here**, with a preview of what stops) and decide which service accepts the certificates and keys of
  which (**Trusts**); each is a step-up action, never an API token, and works in lock. Lists show each row's service
  and filter by service and environment.
- API: `/api/v1/services` (with `/policy`, `/policy/versions` and `/actions/assign?dry_run=true`),
  `/api/v1/environments`, `/api/v1/service-trusts`; permissions `services.manage`, `services.assign`, `services.trust`;
  optional `service_id` on the create bodies of servers, Key Vaults, uploads, signing requests, generated SSH keys,
  ACME certificates and scan scopes (absent: the Default service); `service` on those rows; list filters `service_id`
  and `environment_id`; `x-scope` on every operation and a Scope column in `docs/authz-matrix.md`. Codes `ALC-SVC-0001`
  to `0004`, `0007`, `0016` to `0018`. Migration `00026` (its Down refuses while a second service exists).

**Security**
- A certificate's private key or an SSH key of one service goes to a server or into a Key Vault of another service only
  when that service trusts the first one (SEC-029): deployments, new Key Vault and ACME connections, Key Vault imports
  and SSH key deploys are refused otherwise (`ALC-SVC-0007`), the deployment engine and the import and key jobs check
  again right before they send, and the automatic deployments of ACME certificates and Key Vault connections leave such
  a website alone (marked **Not accepted by its service**, one e-mail: `acme.auto_deploy_untrusted`,
  `kv.auto_deploy_untrusted`). Rulings: `docs/superpowers/rulings/scoped-access.md`.

## Unreleased — Deployment verification proves trust

**Security**
- After a deployment Alice no longer trusts only "the same certificate with the same number of certificates": it
  verifies the chain each website sends with `crypto/x509` against a trusted root for the name it checked, at the time
  of the check (R51). The roots are the system roots, the CA bundle of the ACME authority that issued the certificate,
  and a root uploaded with the chain. When Alice can verify the chain it deploys against them, a website that sends a
  chain that does not verify (another CA's intermediate, a missing or expired intermediate, the wrong order, an unknown
  root) fails the deployment with `ALC-DEP-0026` (`deployment.verify_untrusted`, parameter `trust_error`), and the
  previous certificate is put back (with the R48 guard). Otherwise, and for a name the certificate does not cover, the
  deployment succeeds with a visible warning.
- `alice-helper` 1.10.0 (protocol 11) reports the chain a website presents in the check from the server itself. An
  older helper keeps working; its checks show the chain as not checked. The sudoers lines are unchanged.

**Changed**
- Every deployment shows its evidence: **Installed**, **Served** or **Trusted**, the chain's trust with the exact
  fault and port, and whether a failed check was the network, the certificate or the chain (API `verification`
  {`level`, `trust`, `failure`}; the verify step's params `trust`, `trust_error`). Level 4, a check of the service
  itself, is reserved.
- One check of a website that times out is measured again instead of being taken as an answer.
- Migration `00025` (`deployments.trust_status`, `trust_error`, `trust_port`, `trust_store`, `trust_enforced`).
  Rulings: `docs/superpowers/rulings/deployment-trust-verification.md`.

## Unreleased — Renewal information (ARI) completed

**Added**
- When the certificate authority publishes renewal information (ARI, RFC 9773), Alice renews at a time it chooses at
  random inside the suggested window (never later than **Renew how many days before it expires** allows), so that
  certificates do not all reach the authority at once. The time is chosen once and kept, also across restarts, until
  the authority moves its window; a window in the past renews at once. Without renewal information nothing changes.
  The certificate page shows the time ("a time Alice chose in the window the authority suggests", TR/EN). API:
  `renew_at` and `renew_at_source` on an ACME certificate. Migration `00024`.
- A renewal names the certificate it replaces (ARI's `replaces`) when the authority offers renewal information and
  the certificate was ordered with the same account, so Let's Encrypt can treat it as a renewal. If the authority says
  another order already replaces it, Alice finishes its own interrupted earlier order when it can, or orders once more
  without naming it; new code `ALC-ACM-0041` (`acme.already_replaced`) when even that fails. API: `replaces` and
  `replaces_outcome` on an order. Rulings: `docs/superpowers/rulings/acme-ari.md` (R50).

**Changed**
- A suggested window is no longer used only by its start: a window that begins before the time Alice would renew by
  itself now gives a random time between its start and the earlier of its end and that time (before this change,
  every such certificate renewed at the window's start).

## Unreleased — No rollback puts a revoked or compromised certificate back

**Security**
- A failed deployment is never undone by putting back a certificate that was revoked or whose key is compromised
  (R48). Alice records which certificate the replaced file held, reads the revocation and compromise marks again right
  before every undo (also when the certificate was marked compromised while the deployment ran), and restores nothing
  when they forbid it: the deployment ends rollback failed with `ALC-DEP-0025` (`deployment.rollback_forbidden`), its
  own e-mail, and on a key compromise incident the place fails with that reason. The website may stay broken until a
  valid certificate is deployed: security first, by design.
- `alice-helper` 1.9.0 (protocol 10) checks the backup it would restore itself, on every restore path (its own undo
  after a failed `nginx -t` or reload, an interrupted change, `nginx-restore`), against the list of compromised keys
  and revoked certificates Alice sends; it records `restore_forbidden` and restores nothing. The sudoers lines are
  unchanged. A replacement during an incident, or any deployment over a revoked or compromised certificate, is refused
  on an older helper before anything is sent (`ALC-SSH-0014`, `ssh.helper_outdated_rollback_guard`).

**Changed**
- An incident place whose server cannot be reached after the replacement was sent shows **Not confirmed: server not
  reached** and is never counted as replaced; the API's incident locations carry `outcome_uncertain`.
- Deployments: phase `restore_forbidden`; the `deployment.started` audit row says whether a rollback could put the
  previous certificate back (`rollback`: allowed, forbidden, unknown). Migration `00023`. Rulings:
  `docs/superpowers/rulings/certificate-revocation.md` ("Rollback guard").

## Unreleased — Never retry before the certificate authority said we may

**Fixed**
- When a certificate authority limited the requests and asked Alice to wait longer than a day (`Retry-After`, for
  example 48 hours), Alice ordered again after 24 hours. The authority's wait is now kept apart from Alice's own
  backoff and honoured in full, up to 7 days (a longer answer counts as 7 days, so a faulty authority cannot stop
  renewal for longer). No order of the certificate starts before that time: not by the renewal planner, not with
  **Order now**, **Get certificate now** or **Test run** (`ALC-ACM-0005` with `Retry-After`, the authority is not
  contacted), and **Check again and resume** switches renewal on again without ordering. The renewal information's
  (ARI) `Retry-After` is honoured up to 7 days too. Migration `00022`.

**Added**
- The certificate page says "The certificate authority asked Alice to wait until …" and keeps **Order now** and
  **Test run** unavailable meanwhile. When the wait leaves little time before the certificate ends, the notice is red
  and the alert recipients get "The certificate authority asked Alice to wait before renewing the certificate for …"
  at once (TR/EN), once per wait. API fields `ca_not_before` and `ca_wait_critical`; `next_attempt_at` is the later of
  Alice's own backoff and the authority's wait. Rulings: `docs/superpowers/rulings/acme-ca-retry-after.md` (R47).

## Unreleased — Certificate revocation and key compromise incidents

**Added**
- **Revoke** on an issued certificate (ACME): Alice asks the certificate authority to revoke the current certificate or
  an earlier one (RFC 8555 §7.6, signed with the account), with an RFC 5280 reason. Administrator with a fresh code; it
  cannot be undone. The revocation (time, reason, who) is kept on the certificate and shown in the inventory and the
  orders; a revoked certificate is never deployed again, and a revoked current certificate is renewed at once while
  automatic renewal is on. API: `POST /api/v1/acme/certificates/{id}/revoke`; codes `ALC-ACM-0037` to `ALC-ACM-0040`,
  `ALC-CRT-0018`.
- **Where it is used** on every certificate: the server files, Key Vault versions and network endpoints that hold the
  certificate or another certificate made with the same private key. API: `GET /api/v1/certificate-impact/{id}`.
- **Key compromised…**: a key compromise incident marks every certificate with the key compromised (never deployed
  again, `ALC-CRT-0019`), replaces the certificate on every server file through the deployment engine (a new order with
  a new key for an issued certificate, a replacement you choose for other sources), and revokes an issued certificate
  with the reason key compromise once the replacements are verified (or at once, when you choose so). The incident page
  shows each place, the revocation, and **Retry**, **Revoke now regardless**, **Choose the replacement** and **Close
  the incident**. New permission `certificates.incident` (Administrator with step-up), periodic task
  `incident.advance`, routes under `/api/v1/incidents`, codes `ALC-INC-0001` to `ALC-INC-0013`.
- **What Alice can do with it**: every certificate shows what Alice can do with it by its source (find, obtain, renew,
  deploy, verify, revoke, recover), and says when only the issuing authority can revoke it. API: `capabilities` on each
  certificate and `GET /api/v1/certificates/capabilities`.
- The fake certificate authority (`alice-fakeacme`) implements revocation (`alreadyRevoked`, `unauthorized`,
  `badRevocationReason`) and reports the status of a certificate (`GET /certificate?serial=` on its control port).

**Changed**
- Network discovery stores the public key hash of the certificates it finds (filled as scans see them again).
- Migration `00021`. Rulings: `docs/superpowers/rulings/certificate-revocation.md`.

## Unreleased — ACME renewal recovers after an outage

**Changed**
- A failed ACME renewal is now classified as a temporary outage (the certificate authority, its DNS lookups or the
  DNS hook unreachable or timing out, a rate limit, a server error) or a cause that needs a person (a setting, the
  account, a refused name, a wrong answer to the check). Only **5 failures that need a person** stop automatic
  renewal; outages never do while the certificate is valid, and Alice keeps trying by itself (at most a day apart,
  12/6/2 hours in the last 7/3/1 days), still honouring the authority's Retry-After. Once a certificate has expired, 5
  failures of any kind stop it. A certificate stopped while its last problem was an outage (also one stopped before
  this version) is retried by itself until it expires. Migration `00020`.
- **Renew now** on an issued certificate is now **Check again and resume**: it switches automatic renewal on again,
  clears the failures and orders the certificate at once (Administrator with a fresh code, as before; also offered
  while renewal is failing). API: `POST /api/v1/acme/certificates/{id}/rearm` starts the order and may answer 409
  `ALC-ACM-0023`/`ALC-ACM-0024`.
- The "renewal failed" and "automatic renewal stopped" e-mails explain the two kinds of failure.

**Added**
- While renewal fails or is stopped, the alert recipients are reminded 14, 7, 3 and 1 days before the certificate
  ends (three e-mails by the kind of the last problem, TR/EN), once per threshold.
- The certificate page shows **Kind of the last problem** and **Last e-mail about it** (how the newest renewal e-mail
  was delivered). API fields `last_failure_class`, `permanent_failures`, `recovering` and, on the single certificate,
  `last_notice`. Rulings: `docs/superpowers/rulings/acme-renewal-recovery.md`.

## Unreleased — Directory sign-in: switch-off and unlock

**Changed**
- Switching a directory off (**Allow sign-in with this directory** off) now signs out every user of that directory at
  once: all their sessions end and all their API tokens are revoked in the same change, audited as
  `user.sessions_ended` (reason `provider_disabled`, by the Administrator) and `token.revoked`; the
  `ldap.directory_changed` entry carries `signed_out_count`. A sign-in whose password the directory accepted just before
  the switch is refused (`ALC-LDAP-0002`). The directory form says so before it is saved. Before, open sessions lasted
  until the next confirmation or until they expired.

**Added**
- Audit entry `auth.ldap.lockout` when three failed directory passwords lock a sign-in name or a directory account
  (`scope`, `minutes`; the person and the sign-in name only when the directory found the entry).
- **People & access** shows **Directory sign-in locked** with the time it ends, and **Manage → Unlock directory
  sign-in** ends it (Administrator with a fresh verification; audited `user.directory_unlocked`). API:
  `POST /api/v1/users/{id}/actions/unlock-directory-sign-in` (`users.manage`) and the optional field
  `directory_sign_in_locked_until` of a user in `/api/v1/users` answers. New error code `ALC-LDAP-0009` (the user does
  not sign in through a directory). The 3-failure, 45-minute rule is unchanged. Rulings:
  `docs/superpowers/rulings/ldap-disable-and-unlock.md`.

## Unreleased — HAProxy (discovery only)

**Added**
- Server type **HAProxy server** (target type `haproxy`): Alice reads a HAProxy server's TLS `bind` lines (the
  frontends and `listen` sections), their certificate files and certificates, and its SSH keys. HAProxy servers are
  discovery only: Alice never deploys to them, never changes a HAProxy file and never reloads HAProxy. Their deploy
  controls are shown disabled with the note "Not available for HAProxy servers yet".
- A **Frontend** column on a HAProxy server's page in place of the website column: each row shows "Frontend: name"
  and, for a `crt-list` line, its server names (SNI filters).
- `alice-helper` 1.8.0 (protocol 9) with the read-only subcommand `haproxy-dump` and the sudoers profile `haproxy`
  (**Server type** **HAProxy server** under **Prepare a server for Alice**). It runs `/usr/sbin/haproxy -v`, reads
  `haproxy.cfg`, runs `haproxy -c -f /etc/haproxy/haproxy.cfg` unless `haproxy.cfg` can be changed by a user other
  than root, reads its `crt-list` files and `crt` folder listings through the root-controlled walk, describes
  certificate files and only `stat`s key files ([docs/haproxy-host-preparation.md](docs/haproxy-host-preparation.md)).
- HAProxy places are shown `conditional`, never guessed, when a `crt-list` line's options name `crt`, `key`, `ocsp`,
  `issuer` or `sctl` (HAProxy 3.0 and later) or hold a quote, backslash or `$`, and when a certificate lies past the
  1000 files the helper opens to find keys. A link in a `crt` folder that leads below a folder not controlled by root
  is listed with the problem `not_root_controlled` instead of being left out (at most 4096 links per discovery,
  `too_complex` past that), and a `crt` folder that is not root-controlled reads `not_root_controlled` instead of
  `not_regular`.
- Warnings `config_dir_not_read` (frontends in `/etc/haproxy/conf.d`, which Alice does not read) and
  `config_file_not_read` (a certificate list or folder could not be read where it is named only in a part Alice cannot
  evaluate).
- Unsupported reason `unknown_keyword`: the `bind` carries an option Alice does not know (usually a newer HAProxy's),
  so its arguments cannot be read.
- `SECURITY-REPORT.md` KI-41 (HAProxy discovery items); Phase C rulings in
  `docs/superpowers/rulings/haproxy-provider.md`.

**Changed (API)**
- `type` of a target, the target list filter, the provider kind and `WebServerFacts.software` accept `haproxy`.
- The server blocks of a certificate location (`servers[]`) have an optional field `section`: the `frontend` or
  `listen` name for HAProxy, absent for Nginx and Apache.
- Error codes `ALC-HAP-0001` (HAProxy not found), `ALC-HAP-0002` (configuration has a problem), `ALC-HAP-0003`
  (server not prepared for HAProxy) and `ALC-HAP-0004` (helper too old for HAProxy)
  ([docs/troubleshooting.md](docs/troubleshooting.md)).
- Migration `00018` adds the type `haproxy`. Its Down refuses while HAProxy servers exist (deleted ones included);
  restore a backup taken before `00018` instead.

**Security**
- The helper runs `nginx`, `apache2ctl` (with `/etc/apache2/envvars` and `apache2`), `httpd` and `haproxy` as root only
  when the program and every directory above it belong to root and cannot be written by group or others (and are not
  on a pseudo or FUSE file system). Otherwise nothing runs and the configuration is reported as untrusted
  (`not_root_controlled`, naming the file). This closes the carry of Apache Ruling 7; `systemctl` is not covered
  (`SECURITY-REPORT.md` KI-40).

**Helper**
- `alice-helper` 1.8.0, protocol 9. New: `haproxy-dump`, and the program pre-check above for the Nginx and Apache
  commands. Nothing else changed for Linux, Nginx and Apache servers: their subcommands, answers and sudoers files are
  the same, and they keep working with `alice-helper` 1.6.x and 1.7.x.

**Upgrade notes**
- Reinstall the helper (1.8.0) on servers that will be HAProxy servers, with the commands of **Server type**
  **HAProxy server**; Nginx, Apache and Linux servers keep working with 1.6.x and 1.7.x, but get the program pre-check
  only with 1.8.0. A HAProxy server with an older helper shows `web_server_helper_too_old` and `ALC-HAP-0004` until
  its helper is updated. Migration `00018` runs at the first start of the new release.
- Owner steps before release: run the root-only helper suite
  (`sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/...`), reinstall helper 1.8.0 on the target servers,
  and review a real customer HAProxy configuration (see the rulings file).

## Unreleased — Apache httpd (discovery only)

**Added**
- Server type **Apache server** (target type `apache`): Alice reads an Apache server's websites, their certificate
  files and certificates, and its SSH keys. Apache servers are discovery only: Alice never deploys to them, never
  changes an Apache file and never reloads Apache. Their deploy controls are shown disabled with the note "Not
  available for Apache servers yet", which keyboard users now reach too (the control stays in the tab order with
  `aria-disabled` and the note as its description). The page texts say that Alice only reads these files.
- A certificate's **Deploy** dialog lists the websites on Apache servers disabled, with the note "Not available for
  Apache servers yet", instead of offering them as choices the server then refused; a certificate used only on Apache
  servers has no **Deploy** button.
- `alice-helper` 1.7.0 (protocol 8) with the read-only subcommand `apache-dump` and the sudoers profile `apache`
  (**Server type** **Apache server** under **Prepare a server for Alice**). It runs `/usr/sbin/apache2ctl` (Debian,
  Ubuntu) or `/usr/sbin/httpd` (Red Hat family) with `-V` and `-D DUMP_INCLUDES|DUMP_MODULES|DUMP_RUN_CFG -t`, reads
  the included configuration files through the root-controlled walk, describes certificate files and only `stat`s
  key files ([docs/apache-host-preparation.md](docs/apache-host-preparation.md)).
- Error codes `ALC-APC-0001` (Apache not found), `ALC-APC-0002` (configuration has a problem), `ALC-APC-0003` (server
  not prepared for Apache) and `ALC-APC-0004` (helper too old for Apache)
  ([docs/troubleshooting.md](docs/troubleshooting.md)).
- Warning `web_server_helper_too_old`: a web server whose helper is older than its software needs still passes
  **Test connection** and still has its SSH keys read; its websites are not read until the helper is updated.
- Unsupported reason `conditional`: a certificate or key set inside `<If>` or another condition Alice cannot
  evaluate, or a website whose `ServerName` or `ServerAlias` is set inside one.
- `SECURITY-REPORT.md` KI-40 (Apache discovery items); Phase B rulings in
  `docs/superpowers/rulings/apache-provider.md`.

**Changed (API)**
- `type` of a target, the target list filter, the provider kind and `WebServerFacts.software` accept `apache`.
- A certificate location (`GET /certificates/{id}`, `GET /targets/{id}/certificate-locations`, `PATCH /locations/{id}`) has two
  new fields: `target_type` (the server's software) and `deployable` (whether that software deploys certificates;
  `false` for Apache).
- At startup Alice rewrites each server's `capabilities` from its provider, so capabilities added by a release reach
  existing servers without a data migration; when anything changed it records one audit entry
  `target.capabilities_synced` (actor `startup`, the number of servers in `targets`).
- The warning `config_file_writable` names the software ("A configuration file used by Apache can be changed by
  users other than root: …").
- Migration `00017` adds the type `apache` and lets the application role update `targets.capabilities`. Its Down
  refuses while Apache servers exist (deleted ones included); restore a backup taken before `00017` instead.

**Helper**
- `alice-helper` 1.7.0, protocol 8. New: `apache-dump` and the "software not installed" code
  `SOFTWARE_NOT_FOUND`. Nothing changed for Linux and Nginx servers: their subcommands, answers and sudoers files are
  the same, and they keep working with `alice-helper` 1.6.x.

**Upgrade notes**
- Reinstall the helper (1.7.0) on servers that will be Apache servers, with the commands of **Server type**
  **Apache server**; Nginx and Linux servers keep working with 1.6.x. An Apache server with an older helper shows
  `web_server_helper_too_old` and `ALC-APC-0004` until its helper is updated.
- Owner steps before release: the root-only helper suite and a review of a real customer Apache configuration (see
  the rulings file).

## Unreleased — Prod-readiness fixes

**Fixes**
- `alice-helper` 1.6.1 (protocol 7 unchanged): a certificate file whose first certificate cannot be read is
  reported as `leaf_unreadable` instead of Alice taking the intermediate after it as the website's certificate
  (REM-4). Reinstall the helper on Nginx servers ("Updating the helper").
- Alice lists a website whose certificate file reports `leaf_unreadable` as **Not supported** with that reason and
  drops the certificate an older helper had linked to it, so a wrong expiry date no longer stays on screen (REM-4).
- Sign-in: when a 15-minute block has ended, the next wrong password starts a new count instead of a new block, so the
  right password is accepted at once and guessing is capped at 10 attempts per 15 minutes (AUTH-1; spec SEC-020).
- Recovery passphrase: the meter, on the server and in the browser, no longer counts repeated words, repeated
  patterns, runs of 3 or more identical characters or runs such as `abcdef` and `123456` toward the length; a
  passphrase with fewer than 16 characters left after that is rated fair and refused (CRY-1). The hint and
  `ALC-SET-0010` say so.
- Nginx discovery: one `nginx-dump` answer may list at most 20,000 server-block entries (one block under one
  certificate location) and 100,000 server names; the rest is left out and the location says the list was cut (`list_truncated`), so a
  hostile dump can no longer exhaust Alice's memory (REM-1).
- SSH key inventory: a key's comment is stored up to 1 KiB and its options text up to 4 KiB, then cut with `…`; the
  `authorized_keys` file itself is never rewritten from the shortened text, and a rotation skips a place whose options
  were cut (`options_truncated`) instead of failing during the run (REM-2).

**Added**
- Two settings in `/opt/alice/.env`, written by the installer and kept by the update: `ALICE_TRUSTED_PROXIES` (the
  reverse proxies whose `X-Forwarded-For` Alice believes; empty by default) and `ALICE_MIGRATE_TIMEOUT` (the time
  limit of a database update, `30m` by default, from `1m` to `24h`; it was a fixed 2 minutes). The update checks the
  format and range of both before it changes anything (Alice applies the final check when it starts) and, like Docker
  Compose, uses the last line of a key written twice (OPS-6, OPS-4).

**Changed (API)**
- A target's web-server facts move from `facts.nginx` to `facts.web_server`, which gains `software`; the warning codes
  `nginx_not_found`, `nginx_profile_missing` and `nginx_config_invalid` become `web_server_not_found`,
  `web_server_profile_missing` and `web_server_config_invalid`; the OpenAPI schema `NginxFacts` becomes
  `WebServerFacts`.
- New capability `http01_challenge`: only a server that has it may be the ACME HTTP-01 server.
- Migration `00016` rewrites the stored facts, warnings, Nginx capabilities and `certificate_locations.kind`
  (`nginx_file` becomes `server_file`). The helper is unchanged (protocol 7, 1.6.1).

**Release and process**
- Migrations `00001` to `00015` are frozen by SHA-256 (`migrations/frozen_test.go`); a schema change is a new
  migration (OPS-5).
- `make release` refuses a working tree with uncommitted changes; `RELEASE_ALLOW_DIRTY=1` is for
  `make release-test` only (OPS-3).
- ZAP rule 10062 ("PII Disclosure") is ignored on the audit log's hash fields by a policy line in `.zap/rules.tsv`
  that expires on 2027-04-01 (a false positive on hex digits; OPS-2).
- Dependabot ignores PostgreSQL major versions: a major needs a planned data-directory upgrade (OPS-7).
- CI: coverage runs in its own job with a 75-minute limit, so lint, tests and build finish inside the `go` job's 30
  minutes (OPS-1).
- `SECURITY-REPORT.md` gains KI-36 to KI-39 (ACME, network discovery, directory sign-in, prod-readiness items
  accepted or deferred) and the review's local gate results; the release checklist gains owner rows 1.41 to 1.43 for
  ACME, discovery and a real Active Directory, and its duplicate row 1.31 is renumbered; spec SEC-043 no longer lists
  the unused audit HMAC label; rulings in `docs/superpowers/rulings/prod-readiness-2026-10-16.md` (OPS-8).

**Upgrade notes**
- After updating from a version that does not know `ALICE_TRUSTED_PROXIES` and `ALICE_MIGRATE_TIMEOUT`, check
  `/opt/alice/.env`: the installed version's update script rewrites the file and drops keys it does not know on that
  one update. Add the keys again if you had set them ([docs/upgrade.md](docs/upgrade.md)).
- Reinstall `alice-helper` 1.6.1 on Nginx servers; with an older helper an unreadable first certificate still shows
  the intermediate as the website's certificate.

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
