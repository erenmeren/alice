# Windows servers and IIS as a deployment target: design

Status: W0 spike done (§14.1); **W1 built (R60)** (§16); **W2 built (R61)** (§17); **W3 built (R62)** (§18); **W4 built (R63)** (§19); W5-W7 design only. Date: 2026-10-21. Written against `main` at `72fa1f9a` (migrations up to `00029`,
decisions up to R56; R57 and R58 are taken by parallel work). Decision number: **R59+ when implemented** (recorded in
`alice-v1/00-decisions.md` by the phase that builds it, not before). Migration and error-code numbers: the next free
ones at merge time. Roadmap and shared groundwork: [2026-10-21-deployment-targets-roadmap.md](2026-10-21-deployment-targets-roadmap.md).

Like [the scoped access design](2026-10-21-scoped-rbac-and-service-ownership-design.md), the implementation proceeds
on the recommended defaults of §15 while the questions stay open, once the owner approves the defaults in advance.

## 1. Purpose and agreed understanding

Customers run a large share of their TLS endpoints on Windows Server: IIS websites, and services that take their
certificate from the Windows certificate store (Remote Desktop, the WinRM HTTPS listener, SQL Server, AD FS, Exchange).
Today Alice deploys only to Nginx over SSH (`internal/providers/nginx`, `alice-helper` protocol 11), discovers Apache and
HAProxy, and reads and writes Azure Key Vault. A Windows server is invisible to Alice unless network discovery happens
to probe it.

This design adds a **Windows server** target whose first consumer is **IIS**. It keeps every guarantee the Nginx path
has: a compare-and-swap against what discovery saw, a journal on the server that survives Alice or the server dying at
any point, a fence for a send that may arrive late (AUD-05), a rollback that never puts a revoked or compromised
certificate back (R48, checked on the server too), verification levels with trust (R51), and drift observation (R52).

| Decision | Choice |
|---|---|
| Transport | **OpenSSH Server for Windows** with Alice's existing platform SSH key and host key pinning; WinRM is a later, optional transport for the same helper (§4). |
| What runs on the server | **`alice-helper.exe`**, a Go program built from this repository (no PowerShell at run time), reached only through an sshd `ForceCommand`: the equivalent of the Linux helper behind sudoers. |
| Where the certificate goes | Imported into `LocalMachine\My` (or `LocalMachine\WebHosting` when the binding already uses it), private key non-exportable, intermediates into `LocalMachine\CA`. |
| What changes for IIS | The **http.sys SSL binding** (`ipport`, `hostnameport`), updated in one call that keeps every other setting; `applicationHost.config` is never written. |
| Rollback | Re-point the binding to the previous certificate, which stays in the store until a cleanup removes it. |
| Location | One http.sys SSL binding (kind `win_sslbinding`); the IIS sites and bindings that use it are its servers, as Nginx server blocks share a file pair. |
| Versions | Windows Server 2019, 2022 and 2025 (Desktop Experience and Server Core), IIS 10. |
| Licensing | A Windows server is one target, like a Linux server. |

## 2. Goals and non-goals

Goals:

- G1. Add a Windows server with the platform SSH key, pin its host key, check the helper, and see its facts (OS build,
  IIS version, elevation, stores).
- G2. Discover every http.sys SSL binding, the certificate each one serves (from the store, with its chain and key
  facts), and the IIS sites and bindings that use it; non-IIS consumers of http.sys are listed but not deployable.
- G3. Deploy a certificate to an IIS binding, manually and through ACME and Key Vault bindings (automatic deployment),
  with the same outcome model as Nginx (`DeployOutcome`, journal phases, fence, recovery).
- G4. Verify with Alice's own TLS probe and, when Alice cannot reach the binding, the helper's probe on the server;
  report R51 levels.
- G5. Roll back to the previous certificate under the R48 guard, checked by Alice and again by the helper.
- G6. Observe drift (R52): a binding re-pointed in IIS Manager, a certificate deleted from the store.
- G7. Remove certificates Alice imported once nothing uses them and no rollback can need them.
- G8. Test everything on Linux CI with an emulated Windows host, and the helper itself on real Windows runners.

Non-goals (some get later phases, §13):

- Windows clients (Windows 10/11), Windows Server 2016 and older, Nano Server.
- A permanent agent or a Windows service of Alice's on the server.
- PowerShell scripts at run time, PowerShell remoting, JEA endpoints (in v1).
- Writing `applicationHost.config`, creating sites or bindings, changing SSL flags, protocols or cipher settings.
- SSH key inventory and rotation on Windows (`administrators_authorized_keys`); Windows targets are certificate targets.
- ACME HTTP-01 on IIS (DNS-01 and Key Vault sources work, as for any location).
- Exchange, AD FS, SQL Server, SSTP and other store consumers (listed by discovery only; RDP is a later phase).
- TPM-backed keys (Microsoft Platform Crypto Provider) and smart-card or HSM key storage providers.
- Active Directory Certificate Services enrolment or autoenrolment.

## 3. Vocabulary

| Term | Meaning |
|---|---|
| http.sys SSL binding | An entry of the HTTP Server API's SSL configuration (`netsh http show sslcert`): `ipport` (IP:port, `0.0.0.0:443` for every address), `hostnameport` (SNI name:port) or `ccs` (port, Centralized Certificate Store). It names the certificate by SHA-1 hash and store name, and an application id. |
| IIS binding | A `<binding>` of a site in `applicationHost.config` (`https`, `ip:port:host`, `sslFlags`). IIS asks http.sys to serve it; the certificate lives only in the http.sys entry. |
| Location | One http.sys SSL binding Alice can deploy to (kind `win_sslbinding`). Its servers are the IIS bindings that use it. |
| Store | A certificate store of the local machine: `My` (Personal), `WebHosting`, `CA` (intermediates), `Root`. |
| Helper | `alice-helper.exe` (`C:\Program Files\Alice\alice-helper.exe`), protocol `winproto` (§7). |
| Alice-imported | A certificate the helper imported and recorded in its own inventory (`C:\ProgramData\Alice\helper\imports.json`) and marked with a friendly name `Alice <first SAN> <notAfter> <op8>`. Only these are ever deleted. |

## 4. Transport choice

### 4.1 Options

| Criterion | WinRM over HTTPS (5986) | OpenSSH Server + helper (22) | An Alice agent (Windows service) |
|---|---|---|---|
| Present on the server | WinRM service on by default since 2012; an HTTPS listener needs a certificate and setup. | Optional feature since 2019 (`Add-WindowsCapability`); installed but stopped on 2025. | A new install and its updates. |
| Authentication without a stored password | Certificate mapping (local accounts only; the account's password is typed once on the server for the mapping); Kerberos needs a domain account's password or keytab and the KDC and DNS reachable from Alice's container; NTLM and Basic need a password. | Alice's platform SSH key, the same in a domain and a workgroup; no password anywhere. | Enrolment token, then a client certificate. |
| Server identity | The listener's certificate, usually self-signed: Alice would need TLS pinning (new) or the customer's CA; Kerberos gives mutual authentication in a domain. | SSH host key pinning, built and reviewed (`providers.HostKeyStore`, the confirm flow, `host_key_changed`). | The agent's certificate. |
| Limiting what Alice can run | WinRS gives a full shell of the account. Only JEA limits it, and JEA needs the PowerShell Remoting Protocol (PSRP), which no maintained Go library implements. | `ForceCommand` to the helper: the account can only run helper subcommands with validated arguments, as sudoers + helper on Linux (SEC-063). | The agent decides. |
| Secrets in Windows logs | Commands are PowerShell or cmd text; PowerShell script block logging (event 4104) and transcription can record what was sent. | Key material travels on the helper's standard input, never on a command line, never through PowerShell. | Agent protocol. |
| Code Alice reuses | None: WS-Management SOAP, message encryption, NTLM or Kerberos (new dependencies such as `masterzen/winrm`, `gokrb5`), envelope size limits for the key upload. | The SSH pool, dial budgets, host keys, `StepLogger`, the helper journal semantics, the fence, the rollback guard, the emulator infrastructure. | Little; plus an inbound port on Alice, enrolment, update channel. |
| Customer familiarity | High (Ansible, SCCM). | Lower; one setup script enables it. | Agents are often refused in regulated networks. |
| Firewall | 5986 from Alice. | 22 from Alice. | Outbound from every server to Alice. |

Amended by R71 (Phase W7 built, §22): the WinRM column is built as an alternative transport with a username and
password over NTLMv2 inside TLS, not certificate mapping (deferred with Kerberos and CredSSP). Its server identity is
the listener's SPKI pinned with the shared TLS pinning and an Administrator's confirmation; the code is an in-house
WinRS subset over `net/http` with `go-ntlmssp` (already in the module graph), not `masterzen/winrm` or `gokrb5`; no
PowerShell is sent, so script block logging sees nothing; and the account is still not limited to the helper (no PSRP
or JEA).

### 4.2 Recommendation

**OpenSSH Server with a forced command to `alice-helper.exe`** (Q1). Reasons, in order: it is the only option where
Alice can run nothing but its own validated subcommands without building PSRP; it needs no password in Alice or on the
server; it reuses the reviewed SSH identity model; key material never passes through PowerShell or a command line.
The cost is customer acceptance of sshd on Windows; the setup script (§6.1) makes that one step, and Windows Server 2025
already ships the binaries.

WinRM is the alternative for a customer that refuses sshd (Phase W7, built, R71, §22): the helper and its protocol do
not change (helper `1.2.0`); the transport is WinRS over HTTPS (TLS 1.2 or later, port 5986), authenticated with the
target's username and a password an Administrator sets in Alice (NTLMv2 only; R71 amends the earlier "certificate
authentication", which is deferred with Kerberos and CredSSP, because every competitor signs in to IIS servers over
WinRM with a stored administrator password); WinRS starts the helper through `cmd.exe` even when asked not to (F25), and
`cmd.exe` parses only the constant `"C:\Program Files\Alice\alice-helper.exe" ssh` while the subcommand travels in
`SSH_ORIGINAL_COMMAND`, which it never parses; the listener's certificate is pinned by SPKI (the shared TLS pinning of the
roadmap's groundwork); Basic, unencrypted HTTP and port 5985 are refused by construction. **The account is not limited
to the helper under WinRM:** whoever holds its username and password has a full administrator shell on the server, and
the password also signs in to the server's other network services; only PSRP with a JEA endpoint could limit it, which
W7 does not build. The owner accepted this residual as competitor parity (WN-26), and the UI and the guides say it
where the transport is chosen. OpenSSH stays the recommended transport and the default.

No agent (non-goal): a permanent service with its own update channel is a larger attack surface than one validated
binary invoked per call.

### 4.3 Account and privileges

The helper needs administrative rights (machine store, http.sys configuration). Two setups, both supported, chosen by
the customer in the setup guide:

- **Workgroup or default**: a local account `alice` in `Administrators`, created by the setup script with a random
  32-character password that is never printed (password sign-in is also refused by sshd for this account), and the user
  rights "Deny log on locally" and "Deny log on through Remote Desktop Services".
- **Domain with a hardened baseline** (where "Deny access to this computer from the network" includes *Local account
  and member of Administrators group*, S-1-5-114, which may block a local administrator's network logon): a dedicated
  domain account that a GPO adds to the local `Administrators` of the managed servers, with the same deny rights.

Either way the key line goes into `C:\ProgramData\ssh\administrators_authorized_keys` (the file Windows OpenSSH reads
for administrators) with `restrict` and the forced command
`command="\"C:\Program Files\Alice\alice-helper.exe\" ssh"` (amended by the W1 final review: sshd reads that file for
every member of Administrators, so only the key line's own `command=` confines the key to the helper on every
administrator account; the `Match User` block is a second layer), and `sshd_config` gets:

```
Match User alice
    ForceCommand "C:\Program Files\Alice\alice-helper.exe" ssh
    AuthenticationMethods publickey
    PermitTTY no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
```

`alice-helper.exe ssh` reads `SSH_ORIGINAL_COMMAND`, splits it into a subcommand and arguments with the protocol's own
validators (no shell, no `cmd.exe` parsing), refuses anything else (`UNKNOWN_SUBCOMMAND`), and checks that its token is
elevated (`NOT_ELEVATED` otherwise; UAC remote restrictions on local accounts are the usual cause, §11).

W0 (§14.1) on 2022 and 2025: a key logon of a local `Administrators` member through this block gets a full token
(elevated, elevation type *default*, high integrity, Administrators enabled) with `LocalAccountTokenFilterPolicy`
absent, so the policy is not needed for sshd; the block, the quoted `ForceCommand` path with spaces and the `restrict`
key option are accepted by sshd 8.1p1 and 9.5p2; password sign-in is refused. The token carries NETWORK (S-1-5-2) and
*Local account and member of Administrators group* (S-1-5-114), which is why the hardened-baseline deny right blocks
the local account and the domain-account setup exists (not testable on a runner).

## 5. Data model

All changes ride on the shared groundwork of the roadmap (location kinds with a locator, TLS pinning, backup models).
Windows-specific:

- `targets.type`: new value `windows` (provider kind `windows`). IIS is a fact of the server (`WebServerFacts` with
  `server: iis`, version, sites count), as Nginx is for a `nginx` target; later consumers (RDP) are more facts and
  location kinds of the same target.
- Credential: none new. The target uses the platform SSH key (`credentials.purpose = 'platform_ssh'`), its
  `os_user` (`alice` or `DOMAIN\alice-svc`) and port in `targets.config`.
- Host keys: `host_keys` unchanged (an SSH host key).
- `certificate_locations.kind`: new value `win_sslbinding`. Locator (`certificate_locations.locator`, groundwork):

  ```json
  {"type": "hostnameport", "host": "www.example.com", "port": 443, "app_id": "{4dc3e181-e14b-4a21-b022-59fc669b0914}"}
  {"type": "ipport", "ip": "0.0.0.0", "port": 443, "app_id": "{4dc3e181-e14b-4a21-b022-59fc669b0914}"}
  ```

  `cert_path` holds the canonical text `http.sys/hostnameport/www.example.com:443` (unique per target, shown in the UI);
  `key_path` is empty; `cert_file_sha256` holds the SHA-256 of the DER of the certificate the binding names (the
  compare-and-swap token); `servers` holds the IIS sites and bindings (`CertServer.Names` = host headers,
  `Section` = site name, `Listens` = `ip:port`); the key facts (provider, exportable, store, usable by SYSTEM) go into
  the location's `details` (groundwork) instead of the Unix `key_mode`, `key_owner` and `key_group`, which stay empty.
- `deployments.rollback_info` (`BackupRef`): `{"operation_id", "store": "My", "previous_sha1": "...",
  "previous_sha256": "..."}`; the previous certificate stays in the store, so no key leaves the server.
- No table for imports: the helper's inventory on the server is the source of truth for what may be deleted (§6.8);
  Alice shows it from the dump.

New location problems (`CertProblem*`): `cert_missing` (the binding names a hash not in the store), `key_missing`,
`key_inaccessible` (the store has the certificate but http.sys cannot use its key). New unsupported reasons
(`Unsupported*`): `win_foreign_app` (an http.sys binding of another application: WinRM, AD FS, SSTP...; named for the
application ids W0 observed, §14 F8, the raw id otherwise), `win_ccs` (a
`ccs` binding, until Phase W5), `win_store_unsupported` (a store other than `My` and `WebHosting`), `win_ctl` (a binding
with a certificate trust list or client certificate mapping Alice does not model; deployable, warned).

## 6. Flows

### 6.1 Adding a server

1. The Administrator picks **Windows server** and gets the setup snippet (`SetupGuide.SetupSnippets`, profile
   `windows`): a PowerShell script to run once as an administrator. It installs OpenSSH Server if missing (from the
   Windows capability, or an MSI the customer downloads in an air-gapped network), sets sshd to start automatically,
   creates the account (or takes the domain account's name), writes `administrators_authorized_keys` with the platform
   key and fixes its ACL (Administrators and SYSTEM only, as sshd requires), adds the `Match` block, installs
   `alice-helper.exe` after checking its SHA-256 against the value embedded in the script (Q2), creates
   `C:\ProgramData\Alice\helper` with an ACL of SYSTEM and Administrators only, adds a firewall rule for port 22 from
   Alice's address only, and registers the event source `Alice Helper`. The script is shown for review, never pushed.
2. Alice tests the connection: first contact shows the host key for confirmation (the existing flow); `version` answers
   the helper version and `winproto`; `win-facts` answers the OS build, IIS presence and version, elevation, the stores
   and the OpenSSH version.
3. Discovery runs (`iis-dump`), and the server counts toward the license from creation, as every target.

### 6.2 Discovery (`iis-dump`, read-only)

The helper reads, in this order, with a budget (the Linux `HelperBudget` rule):

1. Every http.sys SSL binding (`HttpQueryServiceConfiguration` for `HttpServiceConfigSslCertInfo`,
   `HttpServiceConfigSslSniCertInfo`, `HttpServiceConfigSslCcsCertInfo`): type, address or name, port, hash, store,
   application id and the flags Alice must preserve. Shapes seen in W0 (§14.1): an `ipport` address may be IPv6
   (`[::]:443`, SSTP); a NULL store name means `MY`, and the name's case varies (`MY` from netsh-style writers, `My`
   from IIS Manager), so stores compare case-insensitively; a `ccs` record carries an application id and flags but no
   hash and a NULL store; a host can hold 100+ records of other applications (the IIS Express range
   `0.0.0.0:44300-44399` on the GitHub images), which the budget and `WarnListTruncated` must absorb.
2. For each hash, the certificate from the named store: DER, the chain Windows builds for it in the machine context
   (`CertGetCertificateChain`, excluding the root), the private key's presence, provider, exportability, and whether the
   SYSTEM account can open it.
3. IIS sites and bindings through `%windir%\system32\inetsrv\appcmd.exe list site /config /xml` (so shared
   configuration and location paths are resolved by IIS itself, not by Alice's parser), parsed with `encoding/xml` into
   site name, id, state, `https` bindings and `sslFlags`.
4. Facts that warn: IIS shared configuration enabled, the `IIS-AutoCertRebind` scheduled task enabled (AD CS renewal
   can re-point bindings: another writer), Centralized Certificate Store enabled and its path, the count of expired
   certificates in `My` and `WebHosting`, the helper's import inventory.

The answer is bounded like `nginx-dump` (entries, certificates, total size); a cut list carries
`WarnListTruncated`. Each http.sys binding becomes a `CertLocation`; IIS bindings that match no http.sys entry (a site
whose certificate was removed) are reported with `cert_missing`.

### 6.3 Deployment (`iis-deploy`)

Alice's side is the existing engine (`internal/jobs/deployjobs`): pre-check, start record, send, outcome, verify,
rollback, recovery. The provider builds the input on standard input (JSON, `winproto.DeployInput`): operation id,
locator, expected current DER SHA-256, certificate chain PEM, private key PEM, target store, the R48 forbidden lists,
and nothing else. The helper:

1. Validates every field; takes the helper lock (one change at a time per server); refuses when not elevated.
2. Refuses an operation id it already knows (`OPERATION_EXISTS`) or has fenced (`FENCED`).
3. Reads the binding; refuses with `HASH_MISMATCH` (exit 3, nothing changed) when its certificate's DER SHA-256 is not
   the expected one, and answers `unchanged` when it already names the new certificate.
4. Journal `prepared` (`C:\ProgramData\Alice\helper\journal\<op>.json`, written to a temporary file, flushed, then
   `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`): the binding's full previous settings, the
   previous hash and store, the new hash, the forbidden lists.
5. Step `import_chain`: adds each intermediate to `LocalMachine\CA` when absent (never replaces one), recorded.
6. Step `import_certificate`: builds a PKCS #12 in memory with a random one-time password and imports it with
   `PFXImportCertStore` (`CRYPT_MACHINE_KEYSET`, CNG "Microsoft Software Key Storage Provider", **not exportable**),
   then adds the certificate to the target store. When the same certificate is already in the store (imported by
   someone else), it is used as is and recorded as *not* Alice-imported. The in-memory PFX and password are zeroed.
   W0 measured the flags `CRYPT_MACHINE_KEYSET | PKCS12_ALWAYS_CNG_KSP` (without `CRYPT_EXPORTABLE`, never
   `PKCS12_NO_PERSIST_KEY`, which leaves no persisted key for http.sys), and that a standard-library PFX (one data
   ContentInfo, a PBES2/AES-256-CBC `pkcs8ShroudedKeyBag` and a certBag sharing a localKeyId, HMAC-SHA256 MAC) imports
   on both images, so no PKCS #12 module is needed; an equivalent route without a PFX, `NCryptImportKey` of the PKCS #8
   blob as a named machine key with export policy 0 plus `CERT_KEY_PROV_INFO_PROP_ID` on the stored certificate, also
   works (`tools/winspike` on the `windows-w0-spike` branch is the reference for both).
7. Journal `writing`. Step `bind`: `HttpUpdateServiceConfiguration` with the entry read in step 3, only the hash and
   store changed: one call, no moment without a certificate, every other setting (client certificate negotiation,
   revocation checks, TLS 1.3 and legacy TLS flags, CTL) preserved. The call **replaces** the whole record (W0: an
   update carrying only key, hash and application id reset the store, check mode, revocation values and flags of an
   `ipport` record, and was refused with `ERROR_INVALID_PARAMETER` for a `hostnameport` one), so the helper always
   sends the full record it read. http.sys refuses a hash whose certificate has no usable private key in the store
   (`ERROR_NO_SUCH_LOGON_SESSION`, 1312, record unchanged) and an absent record (`ERROR_FILE_NOT_FOUND`, mapped to
   `BINDING_NOT_FOUND`). When step 5 added an intermediate, the bind is written even if the binding already names the
   new certificate (an update with the same hash), because schannel serves the chain it built when the record was last
   written (§6.4).
8. Reads the entry back; a mismatch restores the previous entry itself (with the guard, §6.5) and answers
   `rolled_back` with failed step `bind`.
9. Journal `committed`; an Application event (id 1001, no key material: operation, binding, old and new SHA-256).

The engine then verifies (§6.4). A failed verification makes the provider call `iis-restore` (§6.5) exactly as the
Nginx provider calls `nginx-restore`.

### 6.4 Verification

Endpoints per location: `hostnameport` → the target's address at the port with SNI = the name; `ipport` with
`0.0.0.0` → the target's address with SNI from the IIS host headers or the certificate (the existing `SNIFor` rule);
a specific IP → that IP when Alice can reach it (the existing `probeFromAlice` rule), otherwise the helper's own
`tls-probe` from the server (same answer shape as protocol 11, chain included). The Administrator's per-location
settings (port, SNI, skip, and the groundwork's probe address) apply unchanged.

Every probe uses a fresh TLS session (no session ticket): http.sys serves the new certificate to new handshakes at once,
so polling is not needed; a short retry (the existing attempts) covers the first handshake after the change.

Chain length: Windows builds the served chain itself (schannel sends what `CertGetCertificateChain` finds), which can
differ from what Alice deployed (a cross-signed intermediate already in the store). The provider therefore compares
the served chain length with the chain the helper reported for the new certificate after the import (step 6), not
with Alice's chain; when the two differ, the deployment carries the warning `win.chain_differs` (params: deployed and
built lengths) and the R51 trust check decides as usual.

W0 (§14.1) showed schannel sends the leaf and the intermediates it finds in `CA`, never the root, also when the root
is in no store of the server; and that it caches that chain per binding: an intermediate added to or removed from
`CA` after the record was written changes nothing served until the record is written again (an update with the same
hash is enough). Hence the import-before-bind order of §6.3 and the same-hash write when only intermediates changed;
the helper builds the chain it reports after its imports, which is the chain the next write makes schannel serve.

### 6.5 Rollback and recovery

- **Restore** (`iis-restore <op>`, the forbidden lists on standard input): only when the journal is `committed` or
  `writing` and the binding still names the new certificate (otherwise `SUPERSEDED` or `file_changed`, nothing done);
  the previous certificate must still be in its store (`BACKUP_MISSING` otherwise); the helper checks its leaf SHA-256
  and SPKI SHA-256 against the lists (R48: `restore_forbidden`, nothing restored); then one
  `HttpUpdateServiceConfiguration` back to the previous entry, read back, journal `restored`.
- **Status** (`iis-status <op>`) and **fence** (`iis-fence <op>`) have the Linux semantics: a fence on an unknown
  operation writes a `fenced` journal, and a late `iis-deploy` with that id is refused.
- **Guard required** (R48 `Required`): the helper checks the guard itself, so incident replacements are allowed on
  every supported helper; `GuardsRollback` answers true from `winproto` 1.
- A reboot in the middle: the http.sys configuration is persistent (registry) and the journal is on disk; the next
  `iis-status` reports the phase, and the engine's existing recovery table decides.

### 6.6 Drift (R52)

`drift.observe` works unchanged through `Reconcile` and `VerifyDeployment`: the dump's hash for the binding is the
"file" fact (`file_observed_at`), the probe is the "website" fact. Windows-specific causes are reported with their own
codes in the notice: re-pointed binding (another hash), certificate removed from the store (`cert_missing`), key no
longer usable (`key_inaccessible`), and the `IIS-AutoCertRebind` warning on the server. Repair is a deployment with
trigger `drift_repair`, guarded as every deployment.

### 6.7 Old certificate cleanup

A periodic job `windows.cleanup` (ClassChange, daily, per Windows target; switch per target, on by default) asks
`iis-cleanup --plan` for candidates and sends `iis-cleanup --apply` with the ids Alice accepts. A certificate is removed
only when every rule holds:

1. Alice-imported (in the helper's inventory and with Alice's friendly name);
2. no http.sys binding of any application names it, and neither the RDP listener's hash nor a WinRM listener's
   thumbprint (`win-facts` reads both);
3. no journal of an operation that is not final references it, and Alice says no deployment that may still roll back to
   it exists (the engine's view: the newest final deployment of each location keeps its previous certificate for
   7 days, Q6);
4. it was replaced at least 7 days ago, or it is expired, or (incident) it is the replaced certificate of a closed
   key-compromise incident place (removed at once after the replacement verified, Q7).

The private key is deleted with the certificate (`CertDeleteCertificateFromStore` plus the CNG key). Intermediates are
never deleted. Expired certificates Alice did not import are only counted (`win.expired_in_store`).

## 7. The helper (`cmd/alice-winhelper`, installed as `alice-helper.exe`)

- Go, `GOOS=windows`, amd64 and arm64, `CGO_ENABLED=0`, calls through `golang.org/x/sys/windows` (crypt32, ncrypt) and a
  small hand-written binding of `httpapi.dll` (`HttpInitialize`, `HttpQueryServiceConfiguration`,
  `HttpUpdateServiceConfiguration`, `HttpSetServiceConfiguration`, `HttpTerminate`). No PowerShell, no .NET.
- Protocol package `internal/providers/windows/winproto` (standard library only, imported by the helper and by Alice):
  subcommands, exit codes (the Linux ones: 0, 2, 3, 4), error codes (the Linux names where they mean the same:
  `INVALID_ARGUMENT`, `HASH_MISMATCH`, `FENCED`, `SUPERSEDED`, `OUTCOME_UNKNOWN`; new: `NOT_ELEVATED`, `IIS_NOT_FOUND`,
  `BINDING_NOT_FOUND`, `BACKUP_MISSING`, `STORE_ERROR`), journal phases equal to `providers.Phase*` (a test compares
  them), and the TLS probe answer shared with `helperproto` (moved to a common package if import rules require).
  Protocol starts at 1 and evolves on its own; `MinProtocol` rules as on Linux.
- Subcommands of protocol 1: `version`, `win-facts`, `iis-dump`, `iis-deploy`, `iis-restore`, `iis-status`, `iis-fence`,
  `iis-cleanup`, `tls-probe`.
- Code shared with the Linux helper, where it is platform-neutral: the rollback guard check (leaf and SPKI hashes), the
  journal's state machine, input validation, the probe. Platform code lives behind build tags; the Linux helper is not
  changed by this design.
- Release: built reproducibly with the other artifacts, listed in `SHA256SUMS` (signed with the release key, §17.5 of
  `04-security.md`); the setup script embeds the SHA-256 of the helper it installs. Authenticode signing: Q2.

## 8. Provider (`internal/providers/windows`)

- Kind `windows`, capabilities: `test_connection`, `discover_certificates`, `deploy_certificate`, `verify_deployment`.
- `Open` reuses `linuxssh`'s dial (host key pinning, budgets) but **one fresh SSH connection per helper call**, never a
  pooled connection with several sessions: on Windows OpenSSH (8.1p1 on 2022, 9.5p2 on 2025, W0 §14.1) every session
  after the first on a connection receives the *first* session's `SSH_ORIGINAL_COMMAND` (standard input stays per
  session), so a second command on a reused connection would run the first one again. The emulator models this and a
  provider test asserts one connection per call. The command line sent is the bare subcommand and its arguments (no
  `sudo`), which the forced command receives as `SSH_ORIGINAL_COMMAND`, byte for byte on a fresh connection.
- **The transport seam (W7, R71).** Every helper call goes through one function, `session.run`: `sshRun` (the fresh SSH
  connection above) or, under `transport: winrm`, `winrmRun`. `winrmRun` holds a slot of the shared pool, reads the
  target's WinRM password for the one call, opens one TLS connection to the pinned listener and one WinRS shell, and
  runs the constant command `"C:\Program Files\Alice\alice-helper.exe" ssh` with the subcommand line in the shell's
  environment variable `SSH_ORIGINAL_COMMAND`, so the helper takes its forced-command path byte for byte (WinRS starts
  it through `cmd.exe`, which parses only that constant line, holding no `%` and none of `&<>|^()`, and never the
  environment variable, F25). The connection is authenticated once, on Create
  (NTLM is connection-bound; the sign-in may need a second connection, F24), and closed when the call ends. Standard
  input goes only in Send. Everything after `run` (decoding, the write gate, the journal, the fence, the rollback guard,
  every outcome rule) is one code path for both transports; a write is a refusal only when nothing reached the helper
  (`winrs.ErrNotSent`).
- `ConfigSchema`: `address`, `port` (22; 5986 under WinRM), `os_user`, `transport` (`ssh` or `winrm`, fixed at
  creation), `discovery_interval`. `CredentialSchema`: the platform key; a WinRM target also has its WinRM password.
- `SetupGuide`: profile `windows`, the PowerShell snippet of §6.1, `HelperInfo` = path and `winproto.Protocol`.
- Every outcome rule of `providers` (`CheckDeployReturn`, `CheckRollbackReturn`, `DeploymentState.Validate`) applies; the
  conformance suite (`providertest`) runs against the emulator (§12).

## 9. Security analysis

| Threat | Mitigation |
|---|---|
| **Alice compromised runs arbitrary code on Windows servers** | Forced command: only helper subcommands with validated arguments; no shell, no forwarding, no TTY. The residual (an attacker with Alice deploys any certificate to any binding, or removes Alice-imported certificates) equals Nginx's. |
| **Password theft** | No password exists in Alice; the local account's password is random and never shown; sshd refuses password sign-in for it. |
| **Man in the middle on first contact** | SSH host key confirmation by an Administrator (existing flow); a changed key blocks the target (`host_key_changed`). The setup script prints the host key fingerprint so the Administrator can compare. |
| **Private key exposure on the server** | The key travels in the SSH channel on standard input, is imported non-exportable into the machine CNG store (ACL SYSTEM and Administrators), and never touches disk as a file or PFX; the in-memory PFX password is random and zeroed. |
| **Key material in Windows logs** | No PowerShell, no command-line secrets (process creation auditing, event 4688, sees only the subcommand); the helper's events carry hashes only. |
| **Helper binary replaced on the server** | Same as Linux: an administrator of the server can replace it; the directory ACL limits it to Administrators. The setup script checks the hash at install; Authenticode (Q2) helps WDAC customers. |
| **Rollback reinstalling a compromised certificate** | Alice checks the R48 guard before sending; the helper checks it again on every restore path (step 8 of §6.3, `iis-restore`). |
| **Deleting a certificate someone else uses** | Only Alice-imported certificates, only when no http.sys binding of any application, no RDP or WinRM listener and no live journal references them; intermediates never. |
| **UAC remote restrictions silently filtering the token** | The helper checks elevation and refuses (`NOT_ELEVATED`), never half-works. |
| **Elevation of the `alice` account** | Interactive and RDP logon denied; sshd allows public key only; `administrators_authorized_keys` ACL fixed by the script. |
| **Lateral movement from a Windows server to Alice** | Alice dials out; nothing on the server can call Alice. |
| **Shared IIS configuration across a farm** | Alice never writes `applicationHost.config`; each server's http.sys binding is its own location. |
| **WinRM (W7, R71): the account is not limited to the helper** (WN-26) | Under WinRM, whoever holds the account's username and password, or controls Alice, has a full administrator shell on the server, and the password signs in to its other network services. Alice's client sends only the helper's request set; the password is sealed per target, decrypted per call, never readable and set only with a step-up; the account is per server; the firewall rule opens 5986 to Alice only; WinRM is opt-in per target and the UI and guides say it. Residual High, accepted by the owner as competitor parity. |
| **WinRM: a man in the middle, an NTLM relay, a downgrade** (WN-27) | The listener's SPKI is pinned with an Administrator's confirmation and checked before any HTTP byte, so NTLM messages reach only the pinned listener; NTLMv2 only; Basic never sent, HTTP and 5985 never used, no redirect or proxy. No channel binding is sent, so `CbtHardeningLevel` Strict refuses Alice and the server's relay protection stays at Relaxed. |
| **WinRM: secrets in Windows logs** (WN-28) | No PowerShell runs; WinRS starts the helper through `cmd.exe` with the constant line, so process creation auditing (4688) records `cmd.exe /C "C:\Program Files\Alice\alice-helper.exe" ssh` and the helper's own line, never the subcommand (in the environment) or key material (in Send, over TLS); NTLMv2 sends a proof, never the password; 4624 and 4625 name the account only. |
| **WinRM: password theft from Alice or offline cracking** (WN-29) | Sealed under the master key, one row per server, audited on every set; a captured exchange is inside TLS to a pinned listener; at least 12 characters; the UI and the guide ask for a different password per server. |
| **WinRM: server-side setup weakens the host** (WN-30) | `LocalAccountTokenFilterPolicy` set to 1 only for a local account found at 0 or absent (both runner images ship 1), printed by the script; the account keeps its local and Remote Desktop deny rights; the script never weakens Basic, `AllowUnencrypted` or 5985. |

## 10. Verification levels (R51)

| Level | When |
|---|---|
| 0 none | The deployment failed or was rolled back. |
| 1 installed | The binding names the new certificate (read back by the helper) and verification is skipped for the location. |
| 2 served | Every endpoint (Alice's probe or the helper's) serves the new leaf with the chain length Windows built. |
| 3 trusted | And every served chain verifies against the trust store for the endpoint's name (`providers.CheckServedChain`). |
| 4 healthy | Reserved, as everywhere. |

## 11. Failure modes

| Failure | Outcome |
|---|---|
| sshd unreachable, timeout, host key changed | As Linux: `ssh.*` codes, target status; a deploy send that may have arrived is uncertain and recovered through `iis-status` and the fence. |
| Helper missing or too old | `windows.helper_missing`, `windows.helper_outdated`: nothing sent. |
| Token not elevated (UAC remote restrictions on a local account) | `windows.not_elevated` with the fix (the domain-account setup, or `LocalAccountTokenFilterPolicy` as a documented last resort). W0 never saw it: sshd key logons of a local administrator were elevated on 2022 and 2025 without the policy. |
| IIS not installed | Facts say so; locations of other applications still listed; nothing deployable. |
| Binding changed since discovery | `HASH_MISMATCH`: no change, the engine's precondition failure (`deployment.precondition`), a new discovery is queued. |
| Binding removed since discovery | `BINDING_NOT_FOUND`: no change. |
| Import fails (store, key provider, policy) | `STORE_ERROR` before the bind: nothing changed for the website; anything imported is recorded and cleaned later. |
| Bind call fails or reads back wrong | The helper restores the previous entry (guarded) and answers `rolled_back`. |
| Alice killed at any point | Journal plus fence plus the engine's recovery (the F-66 table run against the emulator). |
| Server reboots during a deployment | The journal phase decides at the next status; http.sys settings are persistent. |
| Verification fails (wrong leaf, network, trust) | `iis-restore` under the guard; the R51 rules decide warning or failure. |
| Schannel serves another chain than deployed | Warning `win.chain_differs`, trust decides. |
| The key is unusable by http.sys | Handshake fails: verification fails with `network` kind on every endpoint; rollback. The dump flags `key_inaccessible` beforehand when it can. |
| Antivirus or EDR blocks the helper | `STORE_ERROR` or process failure; uncertain outcomes recovered; documented exclusion for the helper path. |
| AD CS autoenrolment re-points the binding later | Drift (`drifted`), with the `IIS-AutoCertRebind` warning naming the likely cause. |
| Journal directory full or unwritable | Refused before any change (`JOURNAL_FAILED`), as on Linux. |

## 12. Test strategy

1. **Unit tests** (Linux CI): `winproto` validators and shapes; the provider's command building, outcome mapping and
   verification judgement against canned answers; the cleanup rules as a table.
2. **Emulated Windows host** (`internal/providers/windows/wintest`, Linux CI, the pattern of `linuxsshtest`): an
   in-process SSH server that answers the `winproto` subcommands from a modelled host — machine stores (certificates,
   keys, exportable flag, friendly names), the http.sys binding table, IIS sites and bindings, the helper's journal and
   import inventory — computed by ports of the helper's own decision code (shared, platform-neutral packages), and a real
   TLS listener per binding serving the bound certificate with SNI routing, so Alice's real probe and trust check run.
   Faults: bind fails, read-back differs, not elevated, hash mismatch, kill at every journal point, chain built
   differently, key inaccessible (handshake failure), slow first handshake.
3. **Engine and jobs integration** (Linux, Postgres): the Nginx world of `internal/jobs/deployjobs` gains a Windows
   server on the emulator: manual, ACME and Key Vault deployments, the crash table (F-66), the rollback guard rows,
   drift observe and repair, cleanup.
4. **Real Windows, helper level** (GitHub `windows-2022` and `windows-2025` runners, nightly and on changes under the
   Windows paths): install IIS (`Install-WindowsFeature Web-Server`), create sites with SNI and IP bindings, run
   `go test ./cmd/alice-winhelper/... ./internal/providers/windows/...` natively (real stores, real http.sys, real
   schannel), and the **fidelity test**: the same scenario list run against the emulator and against the real helper,
   answers compared field by field (like `emulator_fidelity_test.go`). W0 facts for these jobs: `actions/setup-go`
   with `go-version-file: go.mod` works on both images and `go test` runs natively against the real stores and
   http.sys; a full checkout fails on Windows because `internal/api/nul.go` is a reserved device name (rename it before
   W4, or keep `core.protectNTFS false` with a sparse checkout as the spike does); the images already have part of
   `Web-Server`, a WinRM HTTPS listener on 5986 and 100 IIS Express records, so tests use their own ports and never
   assume an empty table; Defender real-time protection is off on the images, so antivirus interference is untested.
5. **Real Windows, provider level** (same runners): install OpenSSH Server (the capability: 25-33 s on 2022, already
   installed on 2025; the pinned fallback is
   `https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64-v10.0.0.0.msi`,
   SHA-256 `ddec9c53864280759cf9f74791cefd387100e3946aa849a1c138a4ed1b96b7d9`, checked in W0 against a download and
   GitHub's release digest but never installed on a runner, since the capability worked), run the setup script, and run the provider's tests (tag
   `windows_integration`) dialing `localhost`: providers have no database, so no Postgres is needed on Windows.
6. **Manual matrix before release** (owner, §15): Windows Server 2019 (no GitHub image any more), a domain-joined
   server with the security baseline, Server Core.
7. **e2e** (Linux stack): an emulated Windows host container (`test/images/fakewindows`, wrapping `wintest`) so the
   browser suite adds, discovers, deploys and rolls back on a Windows server.

## 13. Phases

Each phase is its own branch, fully green (`make ci`, e2e), fast-forward merged before the next, behind no flag (a
phase is inert until an Administrator adds a Windows server). Sizes as in the scoped access design.

### Phase W0 — Spike on real Windows (size S, ~3 tasks, no merge of product code)

Confirm the facts of §14 on Windows Server 2022 and 2025 runners with a throwaway program; write the results into this
document. Acceptance: every row of §14 marked confirmed or changed, with the design amended where a fact differs.

### Phase W1 — Target, connection and discovery (size L, ~9 tasks)

Groundwork items it needs (roadmap); `targets.type` `windows`; `winproto` 1 with `version`, `win-facts`, `iis-dump`,
`tls-probe`; the helper's read half; the provider's `Open`, `TestConnection`, `Discover`; setup snippet; emulator read
half; UI: add a Windows server, setup script, facts, locations with IIS sites, problems and unsupported reasons (TR/EN).

Acceptance:
- A Windows server is added, its host key confirmed, its facts shown; a helper that is missing, old or not elevated is
  named precisely.
- Discovery lists every http.sys binding; IIS bindings are their servers; foreign applications and CCS bindings are
  unsupported with their reason; truncation warns.
- The certificate of each binding is linked to inventory by fingerprint (network discovery and inventory show it
  managed).
- Real-runner helper tests and the fidelity test pass for the read subcommands.

### Phase W2 — Deployment, verification, rollback (size XL, ~12 tasks; built, R61, §17)

`iis-deploy`, `iis-restore`, `iis-status`, `iis-fence`; import and bind; the journal; the guard on the server; the
provider's `DeployCertificate`, `RollbackDeployment`, `DeploymentStatus`, `FenceDeployment`, `VerifyDeployment`;
locations bindable to ACME and Key Vault certificates; `win.chain_differs`; error codes; UI deployment pages unchanged
apart from the Windows step names (`import_chain`, `import_certificate`, `bind`).

Acceptance:
- Manual deploy to an SNI and an IP binding: committed, level 3 with a public-CA chain, level 2 with a private CA
  without root, level 1 with skip.
- A hash mismatch changes nothing; an unchanged certificate answers unchanged.
- A failed verification rolls back to the previous certificate; a forbidden backup restores nothing and ends
  `rollback_failed` with `deployment.rollback_forbidden` (the helper's own refusal tested on a real runner too).
- The crash table passes on the emulator; the fidelity test passes for every write subcommand on real Windows.
- ACME and Key Vault automatic deployment reach a Windows location; the scoped-access trust check applies.

### Phase W3 — Drift and cleanup (size M, ~5 tasks; built, R62, §18)

R52 observation for Windows locations; the Windows causes in notices; `iis-cleanup` and `windows.cleanup`; the incident
cleanup rule.

Acceptance:
- A binding re-pointed outside Alice is `drifted`; `auto` repairs it; flapping backs off.
- Cleanup removes only Alice-imported, unreferenced, aged certificates; a certificate bound by a foreign application,
  RDP, WinRM or a live journal is kept (table test on the emulator, one real-runner case).

### Phase W4 — Real-Windows CI job and release (size M, ~4 tasks; built, R63, §19)

Nightly and path-filtered workflow jobs on `windows-2022` and `windows-2025`; the helper in release artifacts and
`SHA256SUMS`; documentation (`docs/admin-guide.md` "Windows servers", operator guide, security overview,
`SECURITY-REPORT.md` delta, `06-quality.md` test IDs `WIN-01..` and `test/matrix/traceability.json`).

Acceptance: the jobs are required for changes under the Windows paths; `make matrix-check` passes; the owner's manual
matrix (§12 item 6) is listed as an owner step.

### Phase W5 — Centralized Certificate Store (size M, ~5 tasks; built, R68, §20)

A CCS location belongs to the Windows server that hosts the CCS folder (a `windows` target, location kind
`win_ccs_file`, the PFX named `<host>.pfx` or `_.<domain>.pfx`), written with the CCS PFX password (an Alice location
secret entered by an Administrator), atomically (temporary file, `ReplaceFile` with a backup file kept for rollback).
The IIS servers' `ccs` bindings are linked to it for verification. No double hop: the helper writes a local path only.

### Phase W6 — Remote Desktop certificate (size M, ~4 tasks; built, R69, §21)

Location kind `win_rdp` (the RDP-Tcp listener): import as in §6.3, grant read on the key to `NETWORK SERVICE`, set the
listener's hash (the `SSLCertificateSHA1Hash` value, Q8), verify by a TLS handshake on 3389 after the RDP security layer
negotiation (new probe mode). Key ACLs are the new risk and get their own review.

### Phase W7 — WinRM transport (size L; only if customers refuse SSH; built, R71, §22)

§4.2: the same helper over WinRS with listener SPKI pinning; authentication amended by R71 to the target's username and
a password over NTLMv2 (certificate mapping deferred).

### Phase W8 (R72) — Windows debt and small features (size M; §23)

The W7 minors and R70's open code items; Alice's address in the setup dialogs, one live Windows server per host
(`ALC-WIN-0029`, migration `00039`), removing a WinRM or CCS password. The helper stays `1.2.0`.

### Interactions with other work

- Scoped access (R49, R53-R56): a Windows server belongs to a service like any target; cross-service deployment needs
  the trust; the service policy applies to what is deployed, unchanged.
- License (R9, R44): discovery ClassReadOnly, deployment and cleanup ClassChange, automatic deployment and drift repair
  ClassContinuity, as for Nginx.
- Revocation and incidents (R46, R48): Windows locations are incident places; the guard is checked twice (§6.5).
- Network discovery: an endpoint whose certificate a Windows location holds shows as managed.

## 14. Facts to confirm in Phase W0

Images measured in W0 (§14.1): `windows-2022` = Windows Server 2022 Datacenter 10.0.20348.5622 (21H2), `windows-2025`
= Windows Server 2025 Datacenter 10.0.26100.33438 (24H2), both Desktop Experience. Same results on both unless stated.

| # | Fact the design relies on | If it is wrong | Result (W0, 2026-10-22) |
|---|---|---|---|
| F1 | IIS keeps an HTTPS binding's certificate only in the http.sys SSL configuration; changing it there is what IIS Manager does, and IIS picks it up without a restart or `applicationHost.config` change. | Write the binding through `appcmd` as well; re-review. | **Confirmed** (2022, 2025). Site `spike` with `https *:8443:` and `*:8444:sni.spike.test` (`sslFlags=1`) made by appcmd; cert A bound, then the `ipport` and `hostnameport` records re-pointed to B with one update each: the next fresh handshake served B (HTTP 200), still B after `iisreset /restart`; `applicationHost.config` SHA-256 identical before and after every step and holding no `certificateHash`. Bindings added the IIS Manager way (`Microsoft.Web.Administration` `Bindings.Add(info, hash, "My"[, Sni])`) wrote only `protocol`/`bindingInformation`/`sslFlags` to the file and the hash to http.sys; that API reads the hash back from http.sys (it showed B after the re-point). |
| F2 | `HttpUpdateServiceConfiguration` updates an `ipport` and a `hostnameport` entry in one call on 2019, 2022, 2025. | Delete and set in two calls inside the journal (a short window without a certificate, recorded as a known risk). | **Confirmed on 2022 and 2025, with a precision; 2019 not measured.** Exported on both images; one call per record changed only the hash, and the read-back kept store, app id, `DefaultCertCheckMode` 1, freshness 600, URL timeout 7000 and `DefaultFlags` 0x42 (`NEGOTIATE_CLIENT_CERT`, `DISABLE_TLS13`). 40 flips A↔B under 4 handshake loops: 0 failed handshakes of 1,471-1,804 with the update, 2,410-3,000 failed of 3,627-4,452 with delete+set. Precision (amended §6.3 step 7): the call replaces the whole record. CTL fields not exercised (a set naming a CTL that does not exist is refused with 1312). Microsoft documents the call from Windows 10 1703 and lists no server minimum; 2019 (build 17763) needs the owner's manual check (`winspike osinfo` prints the export). |
| F3 | A key-based OpenSSH logon of an administrator account gets an elevated token (domain account; local account without UAC filtering). | Recommend the domain account only; document `LocalAccountTokenFilterPolicy`. | **Confirmed for a local account; domain account not testable on a runner.** Local `alicespike` in Administrators, key in `administrators_authorized_keys` (ACL SYSTEM and Administrators only, `restrict`), the §4.3 `Match` block: elevated, type default, S-1-16-12288, Administrators enabled (not deny-only), `LocalMachine\My` opens for write, a real http.sys set and delete succeed, with `LocalAccountTokenFilterPolicy` absent and with 1 (the images ship it as 1; W0 deleted it for the first case). `SSH_ORIGINAL_COMMAND` arrives byte for byte (`iis-deploy "a b" -- --x`, single quotes, `x & whoami \| more %USERNAME%`, not interpreted) **on a fresh connection only**: later sessions on the same connection get the first session's command (changed §8). |
| F4 | `PFXImportCertStore` with `CRYPT_MACHINE_KEYSET` and the CNG provider gives a non-exportable key http.sys can use without extra ACLs. | Set the key's ACL explicitly (SYSTEM read). | **Confirmed** (2022, 2025). With `CRYPT_MACHINE_KEYSET \| PKCS12_ALWAYS_CNG_KSP` (also with `CRYPT_MACHINE_KEYSET` alone or `PKCS12_PREFER_CNG_KSP`) for a PowerShell-exported PFX, a standard-library Go PFX (PBES2 shrouded or plain keyBag) and RSA 2048 and ECDSA P-256, and with `NCryptImportKey` PKCS #8: provider Microsoft Software Key Storage Provider, machine key, export policy 0, `NCryptExportKey` refused (0x80090029), key DACL `O:BAD:P(A;OICI;0xd01f01ff;;;SY)(A;OICI;0xd01f01ff;;;BA)`; http.sys served every one at the first handshake with no ACL change. Deleting the key (`NCryptDeleteKey`) and the certificate leaves the key unopenable (0x80090016). |
| F5 | Schannel sends the chain Windows builds from `CA` and does not send the root. | Adjust the chain-length rule of §6.4. | **Confirmed, with a precision** (2022, 2025). Root in `Root`, intermediate in `CA`: served leaf + intermediate (2), `CertGetCertificateChain` 3 elements; root in no store: still leaf + intermediate; intermediate absent: leaf only. Precision (amended §6.3 step 7, §6.4): schannel keeps the chain of the last write of the record; adding or removing the intermediate changed the served chain only after the record was written again (a same-hash update sufficed). |
| F6 | `appcmd list site /config /xml` resolves shared configuration and is available on Server Core. | Read `applicationHost.config` with redirection handled by the helper. | **Confirmed on Desktop Experience; Server Core not testable on a hosted runner.** Exit 0 in ~0.04 s, `<appcmd><SITE SITE.NAME SITE.ID bindings state><site><bindings><binding protocol bindingInformation sslFlags/>` parsed with `encoding/xml`; unknown site: exit 1 and an empty `<appcmd>`. With `redirection.config` pointed at a local copy, appcmd listed the copy's sites (not a site added only to the local file) and wrote a new site to the copy only. `appcmd.exe` is present with `Web-Server` and no `Web-Mgmt-*` feature installed (the images ship part of `Web-Server` already). |
| F7 | OpenSSH Server installs on the GitHub Windows images in reasonable time. | Pinned Win32-OpenSSH MSI. | **Confirmed.** 2022: capability `NotPresent`, `Add-WindowsCapability` 25.5-32.5 s, no restart, sshd `OpenSSH_8.1p1 for Windows`. 2025: already `Installed` (1.2 s check), `OpenSSH_9.5p2 for Windows`. MSI fallback pinned in §12 item 5, not needed. |
| F8 | The application ids of WinRM, AD FS and SSTP bindings, for the `win_foreign_app` names. | Show the raw id. | **WinRM and SSTP measured, AD FS raw id.** WinRM HTTPS listener (present on both images, its `CertificateThumbprint` equal to the record's hash): `0.0.0.0:5986`, `{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}`, NULL store. SSTP (`RemoteAccess` + `Install-RemoteAccess -VpnType Vpn`, 2025 build 26100 in 206 s; on 2022 the same steps left no SSTP record, and a first 2025 attempt asked for a restart): `0.0.0.0:443` and `[::]:443`, `{ba195980-cd49-458b-9e23-c84ee0adcd75}`, store `MY`. Also seen: IIS Express `{214124cd-d05b-4309-9af9-9caa44b2b74a}` (100 records). AD FS cannot be installed on a runner and no Microsoft page fetched in W0 states its id: unknown, the raw id is shown. |
| F9 (W2) | `HttpQueryServiceConfiguration` of the Ex records returns each extended parameter (HTTP/2 window and limits, performance, TLS restrictions, error headers, session ticket keys), a type not set is reported as such, and an update of the base record leaves them as they were. | Rewrite each extended parameter after the base update and self-restore when the read-back still differs. | **Confirmed on 2022 and 2025, with precisions** (W2 runs 39855366097, 39857454542; §14.1). A base update kept every extended parameter on ipport and hostnameport records; the helper's `exRepair` strategy (read back, rewrite only what changed) wrote none. A type not set is `ERROR_NOT_FOUND` (1168); both report types 0-4 set (defaults when nobody set them); type 5 is 1168 on 2022 and "not supported" on 2025, type 6 1168 on 2022 and undecodable on 2025; type 2 is an aggregate with absolute pointers whose reported size on a hostnameport record includes the SNI host's padding. |
| F10 (W2) | `PFXImportCertStore` of the standard-library PFX into a memory store, then `CertAddCertificateContextToStore(CERT_STORE_ADD_NEW)` into `LocalMachine\My`, keeps the key link so http.sys binds it without 1312. | Import straight into the target store, or the `NCryptImportKey` route of `tools/winspike`. | **Confirmed on 2022 and 2025** (W2 runs 39855366097, 39857454542). With `CRYPT_MACHINE_KEYSET \| PKCS12_ALWAYS_CNG_KSP`: Microsoft Software Key Storage Provider, not exportable (`NCryptExportKey` 0x80090029), bound without 1312; no fallback needed. |
| F11 (W3) | `CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)` then `NCryptDeleteKey` removes the key file of an imported certificate, and `CertDeleteCertificateFromStore` of a duplicated context then removes the certificate; neither touches another certificate's key. | Delete the key through the `CERT_KEY_PROV_INFO_PROP_ID` container name with `NCryptOpenKey(MS_KEY_STORAGE_PROVIDER, NCRYPT_MACHINE_KEY_FLAG)`. | **Confirmed on 2022 and 2025** (W3 run 39912110730). With `ONLY_NCRYPT \| SILENT`: exactly one machine key file removed and none created, `NCryptOpenKey` of the container then 0x80090016, the certificate gone from `My`; the other certificates kept their keys and the binding kept serving. No fallback needed. |
| F12 (W3) | The RDP listener's certificate is `RDP-Tcp` value `SSLCertificateSHA1Hash` (absent when RDP uses its self-signed certificate) and each WinRM HTTPS listener's is `WSMAN\Listener\*+HTTPS` value `certThumbprint`, equal to the hash of the http.sys record `0.0.0.0:5986`. | Read the WinRM thumbprint only from its http.sys record; RDP stays the registry value. | **Confirmed on 2022 and 2025** (W3 run 39912110730). The WinRM value equals the `0.0.0.0:5986` hash and the helper's readings equal PowerShell's; `SSLCertificateSHA1Hash` is absent on both images (RDP uses its self-signed certificate), so a set RDP value is proven by unit tests and the emulator only. No fallback needed. W6 (R69): the set value measured on both images (F20). |
| F13 (W4) | `alice-helper.exe` built on the Windows runner (`go build` with the flags of `make winhelper`, the Go of `go.mod`) is byte-identical to the one `make winhelper` builds on `ubuntu-latest`, for amd64 and arm64, so the bytes the runners build (and the setup script test installs) are the bytes the release (built on Linux) ships. | The comparison warns with both hashes instead of failing; an owner item, and the release engineer compares the CI stage's helper hashes with the local build. | **Confirmed on 2022 and 2025** (W4 run 39956839820, again in run 39958574455). amd64 `fd09f74e720dcb1958898091fd7f02a08c2d89232b5ea3e15fd56515dc2d8e5b`, arm64 `dba2d5b3962324d94c621e34f480cf5c7086701693751693145fd48688491b38` on Linux, windows-2022 and windows-2025 (and a local `make winhelper` with go1.27.3); the legs fail on a difference, no fallback needed. |
| F14 (W4) | GitHub reports a job skipped by its `if:` as `skipped` to a dependent job with `if: always()`, so `windows-required` runs and passes on a run whose `changes` answers `false`; its check name is exactly `windows-required`. | `helper` and `linux-build` always run and exit early with success when `changes` answers `false`; the gate decision changes accordingly. | **Run path confirmed** (W4 run 39956839820: `windows-required` ran with `if: always()` after green legs and reported under exactly `windows-required`). **Skipped path pending**: on the W4 branch every push diffs against the W2 `main`, so `changes` always answered `true`; the first push without a Windows change after `main` carries W4 must show the legs skipped and `windows-required` successful (coordinator step, `docs/dev/windows-ci.md`). |
| F15 (W5) | `ReplaceFileW(file, tmp, backup, REPLACEFILE_WRITE_THROUGH)` on a CCS file keeps its ACL, leaves the old bytes in the backup, and IIS serves the new certificate at the next fresh handshake without a restart; a `*.tmp` or `*.bak` file is never served; whether an appcmd binding with `sslFlags=3` creates the http.sys `ccs:<port>` record. | (a) A same-record update of the `ccs:<port>` records after the replace; (b) otherwise `CCSPickupWait` = the measured maximum + 50 % and the verification retries that long. | **Route (a), confirmed on 2022 and 2025** (W5 runs 1-5, https://github.com/erenmeren/alice/actions/runs/40479436831 .. https://github.com/erenmeren/alice/actions/runs/40494994143). A plain `ReplaceFileW` was not picked up within 2 minutes (run 1) nor 10 s (runs 2-5); the replace followed by a same-record update of the `ccs` record was served after 8-12 ms. ACL kept; the backup holds the replaced bytes; `.bak` and `.tmp` never served. appcmd's `sslFlags=3` binding created no `ccs` record (the fixture adds it with netsh). The helper refreshes every `ccs` record after every replace and restore; `CCSPickupWait` stays 0. The refresh's no-op proof (base and extended parameters of every `ccs` record equal before and after) runs from run 6 (https://github.com/erenmeren/alice/actions/runs/40499784360). |
| F16 (W5) | IIS opens a PFX `BuildPFX` wrote (PBES2/AES-256-CBC key, plain certBag, HMAC-SHA256 MAC) with its private-key password; a file under another password is not served; `PFXImportCertStore(PKCS12_NO_PERSIST_KEY)` reads a PFX without leaving a key file; a wrong password gives 86. | Write through `PFXExportCertStoreEx`; delete a leftover key file. | **Confirmed on 2022 and 2025** (runs 2 and 4, https://github.com/erenmeren/alice/actions/runs/40484509608, https://github.com/erenmeren/alice/actions/runs/40491733346). The `BuildPFX` file is served; a file under another password is not (HttpEvent 15301/15302 only); `NO_PERSIST_KEY` leaves no key file (properties 5 and 79 set); another password and a corrupt file both give 86 (`ccs_password_mismatch`, Windows cannot tell them apart); a certificates-only PFX is `key_missing`. No fallback needed. |
| F17 (W5) | IIS's lookup for SNI host `h` is `h.pfx`, then `_.<parent>.pfx` (one label), without case; an explicit `hostnameport` record wins over the CCS binding on the same port. | Change Ruling 6's linking to the measured order; `win.ccs_shadows` if CCS wins. | **Amended on 2022 and 2025** (runs 3-5, final https://github.com/erenmeren/alice/actions/runs/40494994143). The exact file wins; a wildcard `_.<suffix>.pfx` serves a name any number of labels below it (`a.b.x` through `_.x.pfx`), never its own parent; names compared without case; `ReplaceFileW` leaves the replacement's spelling; `hostnameport` wins, so no `win.ccs_shadows`. Product fact: a file for a host IIS has not served before was not served within 40 s even at `PollingInterval` 10 (default 300 s); files present before IIS's first lookup are served. The order between two wildcards (nearest first) is not measured. |
| F18 (W5) | The chain served for a CCS file: the PFX's intermediates, or what schannel finds in `LocalMachine\CA`? | `ccs-deploy` keeps `import_chain` and writes the intermediates into the PFX either way; only the chain comparison follows. | **The PFX's intermediates, on 2022 and 2025** (runs 4 and 5). A file with the intermediate sends it; an intermediate only in `CA` is sent only after a refresh or for a file first served after the import. The chain is compared with the deployed chain and `win.chain_differs` is never reported for a CCS file. |
| F19 (W6) | On windows-2022 and windows-2025 the test can turn RDP on with `fDenyTSConnections` 0 without a reboot or a service restart, and the listener answers on `127.0.0.1:<PortNumber>`; the self-signed leaf served while `SSLCertificateSHA1Hash` is absent is the single certificate of `LocalMachine\Remote Desktop`. | The real tests cover the registry, the grant and the store half only (probe half an owner item); or the absent value's token becomes the leaf of the helper's own `tls-probe --rdp`. | **Confirmed on 2022 and 2025** (W6 runs 1-3, https://github.com/erenmeren/alice/actions/runs/40644188468 .. https://github.com/erenmeren/alice/actions/runs/40648774432). Both images ship RDP on: `fDenyTSConnections` 0, TermService running (start Manual, account NetworkService), port 3389, `SecurityLayer` 2, `UserAuthentication` 1, the value absent, the policy key holding only `KeepAliveEnable`/`KeepAliveInterval`, firewall on with the Remote Desktop rules enabled. `fDenyTSConnections` 1 stops the listener within 3-255 ms and 0 brings it back within 255 ms, no restart. `Remote Desktop` holds one certificate, and it is the one served while the value is absent. No fallback needed. |
| F20 (W6) | A raw registry write of `SSLCertificateSHA1Hash` naming a certificate in `LocalMachine\My` is served at the next fresh handshake without a restart; deleting the value serves the self-signed certificate again. | (a) A delay below 10 s: `RDPPickupWait` = the maximum + 50 %; (b) not served within 120 s: the WMI `Win32_TSGeneralSetting` route (one task more). | **Route (a), on 2022 and 2025** (runs 1-3). Served after 6-17 ms, the delete after 7-14 ms; the served chain equals `built_chain_length` (2); `Win32_TSGeneralSetting` reports the named hash (type 3) and the self-signed one (type 1); a certificate only in `Remote Desktop` is not served when named (the import stays in `My`). `RDPPickupWait` stays 0 (17 ms + 50 % changes no attempt). Precision: a same-value rewrite does not rebuild the served chain (an added intermediate still unsent after 20 s); deleting then setting the value does within 9-11 ms, with about 10 ms of the self-signed certificate between, so `set_listener` deletes and sets a value the listener already holds (Ruling 14 amended). |
| F21 (W6) | With F4's DACL the RDP handshake fails; after one ACE `(A;;GR;;;NS)` through `NCryptSetProperty(NCRYPT_SECURITY_DESCR_PROPERTY)` it succeeds; removing it gives F4's SDDL back byte for byte; the key stays not exportable. | The measured mask is used; if no grant is needed, the coordinator decides whether `grant_key_read` stays. | **Confirmed on 2022 and 2025, with the stored mask** (runs 1-2, https://github.com/erenmeren/alice/actions/runs/40644188468, https://github.com/erenmeren/alice/actions/runs/40646627907). With F4's DACL TermService resets the connection (Schannel 36870, 0x8009030D, `svchost[TermService]`); after the grant the certificate is served within 10-12 ms without a rewrite. `GENERIC_READ` is enough, but the Microsoft Software KSP stores it as `0x80120089` (`GENERIC_READ` plus `FILE_GENERIC_READ`), normalises a written `0x1` to `0x80000001` and, in run 1, merged a new NETWORK SERVICE allow ACE into an existing one; the helper therefore writes `0x80120089`, reads the DACL back and fails a merged grant. The revoke gives F4's DACL back byte for byte; a NETWORK SERVICE deny ACE, another trustee's allow ACE and a NETWORK SERVICE `DELETE` allow ACE survive grant and revoke. Not exportable (0x80090029). |
| F22 (W6) | The X.224 Connection Request `03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00` is answered by a 19-byte Connection Confirm with `RDP_NEG_RSP` and `selectedProtocol` 1 or 2, and a TLS ClientHello then completes; `SecurityLayer` 0 answers `RDP_NEG_FAILURE` or 0. | `helperproto.RDPNegotiate` follows the measured bytes. | **Confirmed on 2022 and 2025** (runs 1-3). `03 00 00 13 0e d0 00 00 12 34 00 02 <flags> 08 00 02 00 00 00`, flags `0x1f`, `0x2f` or `0x0f` (by image and NLA), `selectedProtocol` 2 (HYBRID) with NLA on and off; TLS completes. `RDPNegotiate` accepts every measured answer unchanged. `SecurityLayer` 0 not measured (the tests never write it); the emulator covers `RDP_NEG_FAILURE`. |
| F23 (W6) | With NLA required the TLS handshake completes before CredSSP, so the leaf is read without credentials, and a disconnect right after it leaves no failed-logon event (4625) and no lockout. | The guides name the 4625 per attempt; or an NLA listener is verified by read-back only. | **Confirmed on 2022 and 2025** (runs 1-3). With `UserAuthentication` 1 the handshake completes before CredSSP; ten probes leave no Security 4625 or 4740 event, with the Logon subcategory auditing Success and Failure on both images. No fallback needed. |
| F24 (W7) | A local account in `Administrators` authenticates with NTLMv2 to the image's `0.0.0.0:5986` listener through `winrs.Client`; `version` answers and the token is elevated with `LocalAccountTokenFilterPolicy` as shipped; the forms `alice`, `HOST\alice` and `.\alice` sign in; the first request costs 3 round trips and later ones 1 on the same connection. | (a) The script sets the policy for a local account; (b) Alice sends `HOST\` forms without the domain; (c) every request does the exchange; (d) `maxDialsPerCall` = 2. | **Confirmed on 2022 and 2025, with (d)** (W7 runs 2, 3 and 6, https://github.com/erenmeren/alice/actions/runs/41182325826 .. https://github.com/erenmeren/alice/actions/runs/41187834322). Create takes 3 requests (anonymous 401 offering `Negotiate` and `Basic realm="WSMAN"`, type 1, type 3), later requests 1 each without credentials; Windows closes the connection after the anonymous 401, so a call takes 2 dials and the second is allowed only during the sign-in. Elevated with the policy at 1 as both images ship it; with the policy at 0 a local administrator's sign-in is refused (run 7), so (a) applies and the script sets a 0 to 1 for a local account; all three forms sign in. |
| F25 (W7) | A shell created with `SSH_ORIGINAL_COMMAND` and the Command `"C:\Program Files\Alice\alice-helper.exe"` `ssh` with `WINRS_SKIP_CMD_SHELL` TRUE runs the helper's forced entry, without `cmd.exe`; 4688 records only the constant line. | Helper 1.3.0 with a `winrs` entry. | **The forced entry works; WinRS inserts `cmd.exe`** (runs 5 and 6). The helper answers `version` from the environment, but its parent is `cmd.exe /C "<program>" ssh` despite the option, and the child's line is the unquoted path; `cmd.exe` parses only the constant line, the subcommand stays in the environment. The helper stays 1.2.0 (the fallback would not remove `cmd.exe`; accepted by the coordinator, 2026-10-31). The quotes travel raw in `rsp:Command`: the escaped `&#34;` reached `cmd.exe` as `&` (run 5). `WINRS_SKIP_CMD_SHELL` with `MustComply="true"` is refused with fault 2150858809 (run 7), so `cmd.exe` cannot be avoided. |
| F26 (W7) | 256 KiB of stdin in Sends of 96 KiB with `End` on the last arrive byte for byte; `MaxEnvelopeSizekb` is 500. | Chunk size = the measured limit minus 25 %. | **Confirmed** (run 6). 1 B, 96 KiB, 96 KiB + 1 and 256 KiB hash equal; `MaxEnvelopeSizekb` 500; a Send of about 615 KB is answered HTTP 413 (no WS-Man fault). |
| F27 (W7) | One shell per call costs under 3 s at p50; an undeleted shell is reaped after its idle time. | Re-check the budgets; set `winrs.ShellIdleTimeout` to the measured minimum. | **Cost confirmed; reaping not measured** (runs 4 and 6). 20 calls: p50 49-67 ms, maximum 54-114 ms; `MaxShellsPerUser` 2147483647. Shells cannot be enumerated as the test account ("A security error occurred"), so the idle clamp and the reaping are not measured: an accepted residual (the clamp unknown; Alice always sends Delete). |
| F28 (W7) | The image's 5986 identity survives a WinRM restart; a listener renewed with a new key fails Alice's handshake before any HTTP request; the same key and an expired certificate are accepted. | The guide says the identity changes on restart; the script makes its own certificate. | **Confirmed** (runs 2, 3 and 6). Unchanged after `Restart-Service WinRM`; a new key is refused at the handshake (no 4624 or 4625, no WinRM Operational event); the same key and an expired certificate with the pinned key work. |
| F29 (W7) | The helper's exits arrive as Receive's `ExitCode`; a missing program is a WS-Man fault 2 at Command. | The emulator and the fault mapping follow the measured codes. | **Exits confirmed; a missing program is `cmd.exe`'s exit 1** (runs 6 and 7, https://github.com/erenmeren/alice/actions/runs/41189449678; accepted by the coordinator). Exits 0, 2, 3 and 4 pass through; a helper killed at `deploy.prepared` exits 137; no fault at Command for a missing program: exit 1, no stdout, and cmd.exe's "is not recognized as an internal or external command" on stderr, mapped to `windows.helper_missing`. |
| F30 (W7) | What the listener offers; a Basic-only offer gets no credentials; a wrong password fails after at most 3 requests; `LmCompatibilityLevel` 5 works; `CbtHardeningLevel` Strict refuses. | A bug in the wrapping; the host guide names the setting. | **Confirmed** (runs 2-4). The image offers `Negotiate` and `Basic realm="WSMAN"`, has a 5985 HTTP listener, Basic and Kerberos on, `CbtHardeningLevel` Relaxed, `AllowUnencrypted` false, `LmCompatibilityLevel` absent; (a), (b) and (c) as expected; Strict refuses. WinRM reads Negotiate from `WSMAN\Service` value `auth_negotiate`. |
| F31 (W7) | The deny rights of §4.3 and `PasswordNeverExpires` do not block the network logon (4624 type 3, NTLM, `NTLM V2`); a changed password refuses the old one; S-1-5-114 in the network deny right refuses a local account; an account out of Administrators is refused. | The script leaves out a blocking right; a fault code maps to `winrm_auth_refused`. | **Confirmed** (runs 3 and 6). 4624 type 3, NTLM, `NTLM V2`, elevated; a wrong password is 4625 (`0xc000006d`); the old password is refused after a change; S-1-5-114 refuses; out of Administrators is a 401. |
| F32 (W7) | The setup script's printed SPKI fingerprint equals `providers.TLSIdentity` of the certificate Alice's client sees, for RSA and ECDSA listeners. | The script prints the SHA-1 thumbprint as well. | **Confirmed** (runs 4 and 6) for the image's RSA listener on 5986 and an ECDSA P-256 listener on 45521; the script prints the thumbprint too. |

### 14.1 Spike results

- Branch `windows-w0-spike` (never merged), program `tools/winspike` (one JSON object per subcommand), workflow
  `.github/workflows/windows-spike.yml`; final spike code commit `beafd039`.
- Runs: <https://github.com/erenmeren/alice/actions/runs/39742287996> and
  <https://github.com/erenmeren/alice/actions/runs/39742418887> (checkout failed on `internal/api/nul.go`),
  <https://github.com/erenmeren/alice/actions/runs/39742512340> (first full run),
  <https://github.com/erenmeren/alice/actions/runs/39743969721> (final run; every result above holds in both full runs
  unless the row names one). 4 of the 15 budgeted runs.
- Timings (2022 / 2025): `Install-WindowsFeature Web-Server` 37.7-44.7 s / 129.8-132.7 s; OpenSSH 28.0-36.9 s / 1.2-1.4 s
  (already installed); spike build 15.9-18.2 s cold, 1.3-1.4 s with the setup-go cache; whole job 4m58s-5m21s /
  8m06s-9m39s, of which the time-boxed SSTP attempt 85-106 s / 115-217 s.
- Amended in this document: §4.3 (token facts), §5 (`win_foreign_app` names), §6.2 step 1 (record shapes), §6.3
  step 6 (import flags, PFX writer and PKCS #8 route) and step 7 (whole-record replace, errors, same-hash write), §6.4
  (served chain and schannel's chain cache), §8 (one connection per helper call), §11 (not elevated), §12 items 4
  and 5 (runner facts, MSI pin).
- Not decided on a runner, by nature: a domain account (F3), Server Core (F6), Windows Server 2019 (F2), AD FS (F8),
  antivirus interference (Defender real-time protection is off on the images). They stay in the owner's manual matrix
  (§12 item 6).
- For W1-W4: the httpapi layouts are in `tools/winspike/httpapi.go` (amd64 sizes: `SSL_PARAM` 80, `SSL_SET` 88,
  `SSL_SNI_SET` 216, `SSL_CCS_SET` 208, `SSL_QUERY` 24, `SSL_SNI_QUERY` 152, `SSL_CCS_QUERY` 144; `HttpInitialize`
  with version 2.0 and `HTTP_INITIALIZE_CONFIG`; the result is the ULONG return value, not `GetLastError`).
  `x/sys/windows.CryptAcquireCertificatePrivateKey` declares the 4-byte BOOL out-parameter as `*bool`: bind it with a
  `*uint32`. `netsh http show sslcert` and the API enumeration agreed record for record (108 records).
- W2 (R61) measured F9 and F10 on branch `windows-w2` with the real helper's own tests (`cmd/alice-winhelper`,
  `.github/workflows/windows.yml`; 6 of the 20 budgeted runs, listed in the rulings file "W2 (R61)"):
  - **F9 confirmed on windows-2022 and windows-2025** (runs <https://github.com/erenmeren/alice/actions/runs/39855366097>
    and <https://github.com/erenmeren/alice/actions/runs/39857454542>): `HttpUpdateServiceConfiguration` of an ipport
    or hostnameport base record keeps every extended parameter the record holds; the helper's `exRepair` strategy
    (base update, read the Ex parameters back, rewrite only what changed) made no Ex write on either image. Both
    images report types 0-4 as set (with their defaults when nobody set them); they differ only beyond them: type 5
    is `ERROR_NOT_FOUND` (1168) on 2022 and "not supported" on 2025, type 6 is 1168 on 2022 and undecodable on 2025,
    types 7-9 are 1168 on both (the helper reads 0-5). Type 2 (performance) is an aggregate
    of six entries with absolute pointers; on a hostnameport record its reported size includes the SNI host's
    padding, so the helper takes its extent from the entries. An Ex type the helper cannot decode is left out and
    never written. A deployment and its restore keep client-certificate negotiation, the revocation values, the TLS
    flags and a set HTTP/2 window (`TestFidelityDeployKeepsEverySetting`; the fidelity tests passed in runs 4-6).
  - **F10 confirmed on both images** (the same runs): `PFXImportCertStore(CRYPT_MACHINE_KEYSET |
    PKCS12_ALWAYS_CNG_KSP)` of the standard-library PFX into a memory store, then `CERT_STORE_ADD_NEW` into
    `LocalMachine\My`, keeps the key link: software KSP, not exportable (`NCryptExportKey` 0x80090029), bound without
    1312.
  - F5 again, between the import and the write: an intermediate the helper imported is not served until the record is
    written (a deployment killed at `deploy.writing` still serves the leaf alone); only a write changes the served
    chain. Hence the binding record keeps the chain of Alice's last committed bind, and `unchanged` needs it (§17).
- W3 (R62) measured F11 and F12 on branch `windows-w3` with the real helper's own tests
  (`TestRealCleanupRemovesKeyAndCertificate`, `TestRealProtectedThumbprints`, `TestFidelityCleanup`; run
  <https://github.com/erenmeren/alice/actions/runs/39912110730>, green on windows-2022 and windows-2025): both
  confirmed, neither fallback route needed (the rulings file "W3 (R62)" lists the runs).

- W4 (R63) measured F13 and F14 on branch `windows-w4` (run <https://github.com/erenmeren/alice/actions/runs/39956839820>,
  green on windows-2022 and windows-2025): F13 confirmed, F14's run path confirmed and its skipped path left to the
  first non-Windows push after `main` carries W4 (the rulings file "W4 (R63)" lists the runs).

## 15. Open questions for the owner (the implementation proceeds on the default)

| # | Question | Recommended default |
|---|---|---|
| Q1 | Transport: OpenSSH with a forced command, WinRM HTTPS, or an agent? | **OpenSSH + forced command to `alice-helper.exe`** (§4.2). WinRM only as a later alternative if customers refuse sshd; no agent. |
| Q2 | Sign `alice-helper.exe` with Authenticode (a code-signing certificate on a hardware token, a yearly cost)? | **Before the first customer that runs WDAC or AppLocker; until then** the release-key-signed `SHA256SUMS` and the hash check in the setup script. Recommended before general availability. |
| Q3 | Windows Server 2016? | **No** (extended support ends 2027-01-12; no built-in OpenSSH). Revisit only for a paying customer. |
| Q4 | A separate helper binary for Windows or one multi-platform `alice-helper`? | **Separate** (`cmd/alice-winhelper`, own protocol `winproto`), sharing platform-neutral packages; the Linux helper's protocol and release are untouched. |
| Q5 | One location per http.sys binding, or one per certificate across the bindings that use it? | **Per http.sys binding** (the unit that changes atomically, like a file pair); the UI groups locations of one server that show the same certificate. |
| Q6 | How long does the previous certificate stay in the store? | **7 days after the replacing deployment is final**, and never while a rollback can need it. |
| Q7 | After a key-compromise replacement, remove the compromised certificate from the store at once? | **Yes when Alice imported it** (after the replacement verified); otherwise a notice to the owners that it is still in the store. |
| Q8 | RDP and other store consumers: when? | **After W4, on demand**, RDP first (W6). Exchange, AD FS, SQL Server stay discovery-only. |
| Q9 | Store for new imports when the binding's store is not `WebHosting`? | **The binding's current store** (`My` by default); never move a binding between stores. |
| Q10 | Does the Windows Application event log get an event per change? | **Yes** (hashes and binding names only), so the customer's SIEM sees Alice's changes from the server's side. |
| Q11 | Licensing: does a Windows server count as one target whatever it hosts (IIS, later RDP)? | **Yes, one target**, like a Linux server with Nginx. |

## 16. Phase W1 as built (2026-10-22, R60)

Built on branch `windows-w1` (plan `docs/superpowers/plans/2026-10-22-windows-w1-target-connection-discovery.md`,
17 tasks); decision R60, rulings in [windows-iis.md](../rulings/windows-iis.md), host preparation
`docs/windows-host-preparation.md`, test IDs `WIN-01`..`WIN-14` (`alice-v1/06-quality.md` §24.7). No migration.

| Item | As built | Differs from this design |
|---|---|---|
| Target | Type `windows`, provider `windows`, capabilities `test_connection`, `discover_certificates`; config `host`, `port`, `username` (local or `DOMAIN\name`, stored as typed) | Not §8's `address`/`os_user` (ruling 1); no SSH key inventory (`IsServer` false; `IsSSHTarget`, `HasCertificateLocations` new) |
| Transport | Windows OpenSSH, `Match User` block (account in lower case) with `ForceCommand ... ssh`, `restrict` key line; bare validated tokens through `linuxssh.ForcedCommand`; one fresh connection per helper call | As §4.3 and §8 (W0-amended) |
| Protocol | `winproto` 1: `version`, `win-facts`, `iis-dump`, `tls-probe`; helper `0.1.0`; W2 adds its subcommands to protocol 1 | `HttpUpdate/SetServiceConfiguration` bindings wait for W2 |
| Helper | `cmd/alice-winhelper` (amd64, arm64, no cgo): httpapi.dll (non-Ex queries), crypt32/ncrypt (chain cache only, key facts from the CNG key's DACL), token elevation, appcmd with an allow-listed environment; decisions shared with the emulator in `winhelper` | Ex records' TLS extended parameters not read (W2 must); `key_usable_by_system` counts SYSTEM's groups (owner to confirm) |
| Elevation | `iis-dump` refuses `NOT_ELEVATED`; `version`, `win-facts`, `tls-probe` run without; the connection test fails with `windows.not_elevated` | None |
| Discovery | One `win_sslbinding` location per http.sys entry (and per IIS https binding without one, `cert_missing`); locator and canonical text of §5; IIS sites as servers; bounds and `list_truncated` / `locations_dropped` | `win_ctl` is a location warning, not an unsupported reason (it is "deployable, warned"); `file_problem` set for problems |
| Setup | PowerShell script (profile `windows`) with the embedded helper checksums (`make winhelper`), ADSI account creation, minimal INF for the deny rights, ACLs without recursion, firewall from `from=` | The helper directory grants the account read and execute (so a filtered token is named `not_elevated`, owner to confirm) |
| Errors | `ALC-WIN-0001` `helper_missing`, `ALC-WIN-0002` `helper_outdated`, `ALC-WIN-0003` `not_elevated` | None |
| UI | Add a Windows server, setup script, Windows and IIS facts, bindings with "IIS site", deploy disabled; EN and TR | The grouping of bindings per certificate (Q5) waits for W2 |
| Tests | Emulator `wintest` (with Windows OpenSSH's first-command behaviour), real-Windows workflow `windows.yml` on windows-2022 and windows-2025 (fidelity test of the read subcommands, setup script smoke test; ports 45300-45399), e2e fake `cmd/alice-fakewindows` | `internal/api/nul.go` renamed (reserved name on Windows) instead of the spike's sparse checkout |

## 17. Phase W2 as built (2026-10-23, R61)

Built on branch `windows-w2` (plan `docs/superpowers/plans/2026-10-22-windows-w2-deployment-verification-rollback.md`,
16 tasks); decision R61, rulings in [windows-iis.md](../rulings/windows-iis.md) "W2 (R61)", test IDs
`WIN-15`..`WIN-28` (`alice-v1/06-quality.md` §24.7), STRIDE `WN-10`..`WN-13`. No migration.

| Item | As built | Differs from this design |
|---|---|---|
| Protocol | `winproto` 1 gains `iis-deploy`, `iis-restore`, `iis-status`, `iis-fence` (`--op <uuid>` only; input as JSON on standard input, 256 KiB and 32 KiB); helper `0.2.0`; Alice refuses a helper below `WriteMinVersion` `0.2.0` before sending | `iis-cleanup` stays W3; the target store is not sent: the helper uses the binding's own (Q9) |
| Transaction | Platform-neutral in `winhelper` behind `WriteHost`, run by the real helper and the emulator: helper lock (20 s), journal phases as on Linux, binding records naming the latest operation and the chain of Alice's last committed bind, fences, a write gate (`IO_ERROR` before the first durable write, `OUTCOME_UNKNOWN` after it, no answer on a kill) | A known operation id is `OPERATION_EXISTS` even when prepared (recovery fences it); `unchanged` also needs the recorded chain to equal the deployment's (W0 F5) |
| Import | Standard-library PFX of the leaf and key (password 32 printable characters, 192 bits), `PFXImportCertStore(CRYPT_MACHINE_KEYSET\|PKCS12_ALWAYS_CNG_KSP)` into a memory store, then `CERT_STORE_ADD_NEW` into the binding's store; intermediates into `CA` first; friendly name `Alice <name> <notAfter> <op8>`; `imports.json` | F10 confirmed: no `NCryptImportKey` route; the "target store" input of §6.3 is not sent |
| Bind | One `HttpUpdateServiceConfiguration` with the record as read, hash and store changed; base and Ex read back; Ex rewritten only when changed (`exRepair`); a read-back mismatch → self-restore under the guard; http.sys's 1312 → nothing written, `restored` with `failed_step bind`, `key_unusable` | F9 confirmed: no Ex write needed on 2022 and 2025; the dump reads no Ex parameters (only the deploy and restore paths do); an undecodable Ex type is left out and never written |
| Restore and recovery | `iis-restore` checks the R48 guard on every path (the self-restore too), `restore_forbidden` monotonic per operation; `BACKUP_MISSING` refused before any write; `iis-status`, `iis-fence` as on Linux; events 1001 and 1002 | §6.5's `SUPERSEDED`/`file_changed` as built: a record already naming the previous certificate is `restored` without a write |
| Provider | Capabilities `deploy_certificate`, `verify_deployment` added; `DeployCertificate`, `RollbackDeployment`, `DeploymentStatus`, `FenceDeployment`, `VerifyDeployment`, one fresh connection per helper call; `RollbackTraits{BackupOnTarget, SelfRestores}`, guard satisfied on every 0.2.0 helper; Windows reasons for every helper code | `RollbackRequest.Backup` (the start record's backup) names the previous certificate, not the location's details |
| Verification | `internal/providers/tlsverify` shared with Nginx (unchanged behaviour); endpoints from the locator, the IIS host headers for SNI, the helper's `tls-probe` for a specific IP Alice cannot reach; fresh handshakes; `chain_differs`, `deployed_chain`, `built_chain` on the verify step | `win.chain_differs` rides on the verify step's params (no warnings column) |
| Inventory and engine | `win_sslbinding` locations deployable (manual, ACME, Key Vault; R49 trust unchanged); rollback info `store`, `previous_sha1`, `previous_sha256`; the token after a deployment is the leaf's DER SHA-256 and the thumbprint the deployed leaf's (or none); a cut scan relabels nothing; `deployjobs` unchanged | Three bugs found by the end-to-end tests fixed (a stored locator's port as `json.Number`; the token's form; the location's thumbprint after a deployment, which the next rollback info names) |
| Errors | `ALC-WIN-0004`..`ALC-WIN-0012` (`binding_changed`, `binding_not_found`, `busy`, `io_error`, `store_error`, `key_unusable`, `backup_missing`, `location_unsupported`, `helper_refused`) | `OUTCOME_UNKNOWN` and `OPERATION_EXISTS` are uncertain, not refusals |
| UI | Bindings grouped by the certificate they serve ("No certificate" last), the deploy dialog's grouped picker with "Select all bindings of this certificate", the steps import chain, import certificate, bind, verify, the previous certificate (`store \ sha1`), the chain note; Windows wording for every deployment reason, notice and e-mail; EN and TR | Notices and e-mails got Windows texts in W2 rather than later |
| Tests | Emulator write half (whole-record replace, schannel's chain cache, kill at every journal point, reboot), engine tests on the emulator (manual, ACME, Key Vault, levels, guard rows, kill matrix), real-Windows fidelity of every write subcommand on windows-2022 and windows-2025 (7 of 20 runs, the last two green; ports 45330-45389, a clean runner checked last), e2e deploy and rollback in EN and TR (`web/e2e/windows.spec.ts`, `ctl stale-tls-on`); local `make ci` green, e2e 158 passed, 4 skipped | The real kill is in process (an `alicetest` build hook) |

## 18. Phase W3 as built (2026-10-23, R62)

Built on branch `windows-w3` (plan `docs/superpowers/plans/2026-10-23-windows-w3-drift-and-cleanup.md`, 13 tasks);
decision R62, rulings in [windows-iis.md](../rulings/windows-iis.md) "W3 (R62)", test IDs `WIN-29`..`WIN-38`
(`alice-v1/06-quality.md` §24.7), STRIDE `WN-14`..`WN-17` and WN-12 amended. One migration, `00032` (the switch's
column).

| Item | As built | Differs from this design |
|---|---|---|
| Protocol | `winproto` 1 gains `iis-cleanup --plan \| --apply` (JSON on standard input, at most 64 KiB; no operation id); helper `0.3.0`; Alice refuses a helper below `CleanupMinVersion` `0.3.0` before sending (`windows.helper_outdated`), a W2 helper still deploys; the dump carries `alice_imported` | No journal or fence for cleanup: `--apply` judges every rule again under the helper lock, so a repeated or late apply is harmless; the listeners are read by the cleanup itself, not by `win-facts` (§6.7 rule 2) |
| Cleanup rules | Two judges that must both agree. The helper: rule 1 (`imports.json`, or a 0.3.0 journal whose "existed" record is false, plus Alice's friendly name ending in that operation and the same DER SHA-256), rule 2 (any http.sys record of any application, the RDP `SSLCertificateSHA1Hash`, every WinRM `certThumbprint`; unreadable: refuse), rule 3's live journals (an unreadable one keeps everything), rule 4 by its own clock (`unbound_since`, 7 days, or expired). Alice: rollback window 7 days after a finished deployment naming it (Q6), no unfinished deployment, no location holding it, the switch on. Q7: a compromised certificate is removed at once after its incident place settles | Rule 4's "replaced at least 7 days ago" is "found unused by daily plans for 7 days" (a binding re-pointed outside Alice leaves no trace in Alice); an import that met an existing copy is never Alice's (`ImportPFX` reports "existed"); a journal-only certificate is adopted into `imports.json` |
| Removal | The CNG key (F11), then the certificate, then the `chain` of every binding record naming it, then its inventory entry, then event 1003 (`removed store ... sha1 ... sha256 ... reason ...`); the next plan heals an interrupted removal; intermediates never removed | Key first, so a kill leaves a keyless certificate the next run removes, never an orphan key; a copy in another store naming the same key container loses its key when unbound (owner item) |
| Bounds | 256 candidates per plan (`truncated`), 256 items per apply, `MaxForbidden` watched certificates; journals and fence tombstones pruned by every plan (7 days for final ones, 30 for `restore_failed` or undecodable, at most 1000; never `writing`, `restoring` or a journal a binding record needs); the W2 write gate (`OUTCOME_UNKNOWN` after the first durable write) | Tombstones were unbounded in W2; an unreadable binding record stops pruning with `binding_record_unreadable` |
| Job | `windows.cleanup` (ClassChange, one attempt, no `job.dead` e-mail) per Windows server, queued by `windows.cleanup_schedule` (hourly; status ok, the capability, no cleanup in 24 hours) and by every final incident place; the switch is the column `targets.certificate_cleanup` (default on, `PATCH /targets/{id}`); each removal audited `windows.certificate_removed` | §6.7's "switch per target" is a column of its own (migration `00032`), not a `targets.config` key: the application may not update the config, which holds the connection |
| Drift | Windows locations in `drift.schedule`, `drift.observe`, `drift.repair` unchanged; one scan rule (a bound binding newly broken gets `changed_outside_at`); cause derived (`binding_repointed`, `cert_removed`, `key_unusable`) with the AutoCertRebind hint; an unrepairable cause is never repaired (`ALC-WIN-0013`) | §6.6's "key no longer usable (`key_inaccessible`)" covers every key problem (`key_unusable`); a removed certificate or broken key is reported, never repaired into a failure loop |
| Notices | Seven Windows drift e-mails and the AutoCertRebind sentence; the lost-connection text for an interrupted Windows deployment; `windows.compromised_in_store` once per incident and certificate, when no place of the incident on the server is still open | The Q7 notice is deduped through the outbox, not a new alert kind |
| Provider | Capability `cleanup_certificates`; `providers.CertificateCleaner` (`PlanCleanup`, `ApplyCleanup`) on one fresh connection per call, strict answer validation; `windows.cleanup_outcome_unknown` (`ALC-WIN-0014`) | The cleanup's value constants live in `providers` (inventory may not import the Windows packages) |
| API and UI | `location_kind` on deployments, `drift_cause` and `autocertrebind` on observations, `repair_available` false for an unrepairable cause, `certificate_cleanup` on a capable server; Windows wording for a binding's observation and cause, no Repair button when it cannot be repaired, the "Imported by Alice" badge, the switch on the server's page; EN and TR | No cleanup history page (the job history and audit log hold it); the web recognises a Windows deployment by `location_kind` |
| Tests | Helper rules and kills (`winhelper`), the emulator's cleanup half (`wintest`), the provider, inventory, `winjobs`, engine tests on the emulator (drift observed, repaired, flapping, a removed certificate never repaired, cleanup after a renewal, the kept rows, the incident rule), real-Windows `TestRealCleanupRemovesKeyAndCertificate`, `TestRealProtectedThumbprints`, `TestFidelityCleanup` (F11, F12; ports 45390-45398); the e2e Windows journey asserts the badge, the switch and `location_kind` | No e2e drift or cleanup journey (the 7-day age cannot pass in a browser run); the age on a runner uses an `alicetest`-only clock offset that never ships |

## 19. Phase W4 as built (2026-10-23, R63)

Built on branch `windows-w4` (plan `docs/superpowers/plans/2026-10-23-windows-w4-ci-and-release.md`, 7 tasks);
decision R63, rulings in [windows-iis.md](../rulings/windows-iis.md) "W4 (R63)", test IDs `WIN-39`..`WIN-45`
(`alice-v1/06-quality.md` §24.7), STRIDE `WN-18` and WN-6 amended. No migration, no new error code.

| Item | As built | Differs from this design |
|---|---|---|
| CI check | `.github/workflows/windows.yml` runs on every branch push (no tags) and pull request; its job `windows-required` (`if: always()`, needs `changes`, `linux-build`, `helper`) is the one required check: success only when `changes` succeeded and either `windows=false` with every leg skipped or `windows=true` with every leg succeeded (`deploy/dev/windows-ci.sh gate`); the legs `helper (windows-2022)` and `helper (windows-2025)` run every `TestReal*` and `TestFidelity*` by name, a skipped one fails | One gate job instead of path-filtered required jobs (a workflow skipped by trigger `paths:` leaves a required check pending); the matrix legs are not themselves required (their names change when an image is retired) |
| Change detection | The ubuntu job `changes` diffs (`git diff --no-renames --name-only -z`) against a pull request's base, for a push to another branch the merge base with the default branch, for a push to the default branch its `before`; `.github/windows-paths.txt` (`dir/**`, `dir/*`, exact paths) matched by `windows-ci.sh changed`; an unknown base or a failed diff runs the legs; archtest keeps the list complete (every package the Windows tests build, the fixed entries, no stale entry) | §13's "path-filtered jobs" is a tested script instead of trigger filters or a third-party filter action; a branch push measures the whole branch, not the push (amended during W4: a superseded push must not leave a Windows change untested); a default-branch push is never cancelled or displaced: it has a concurrency group of its own per commit (`main-<sha>`; final review I-1: GitHub cancels a pending run when a newer one queues in its group, whatever `cancel-in-progress` says); no `merge_group` trigger |
| Nightly | Cron `41 2 * * *` in `windows.yml`, the default branch, both legs, never cancelled by a push; a failure reaches people through GitHub's workflow e-mail | Not in `nightly.yml`: one workflow keeps one check name and one job definition; no Alice-side alert; GitHub pauses the schedule after 60 days without repository activity |
| Release package | `helper/` carries `alice-winhelper-windows-amd64.exe`, `alice-winhelper-windows-arm64.exe` and `alice-winhelper.sha256` next to the Linux files, all in the signed `SHA256SUMS`; `make release` builds them; the stage refuses a missing or mismatching helper and names `make winhelper`; `install.sh` copies `helper/` as a whole | No separate download of the helper outside the package; the administrator copies the file as `alice-helper.exe` |
| Release workflow | `release.yml` calls `windows.yml` with `all: true`; `stage` needs `[gates, zap-full, fuzz, windows]`; the concurrency group's literal `windows-` prefix keeps the call out of `release.yml`'s own group; a tag push never starts `windows.yml` directly | No Windows gate in `make release-gates` (it runs on one Linux machine); release-checklist row 1.46 records the run |
| Helper version | `winproto.Version` `1.0.0`, protocol 1; `WriteMinVersion` 0.2.0, `CleanupMinVersion` 0.3.0 unchanged; the setup script's messages name the package's `helper\` folder | §7's release line as designed: 1.0.0 adds no subcommand, so no server must be updated at once |
| Reproducibility | `linux-build` runs `make winhelper` and passes both SHA-256 values; each Windows leg builds with the same environment and fails on a byte difference (F13 confirmed); `TestRealSetupScript` installs those bytes and calls the helper over SSH, the other real tests and the fidelity tests run the same source built by the test (in-process, `buildHelper`, `-tags alicetest`); `TestWindowsHelperBuildFlagsAgree` keeps the `Makefile`, `deploy/dev/reproducible-check.sh`, `deploy/Dockerfile` and the workflow on one flag set | The Dockerfile's build is checked too (the image embeds those checksums); ARM64 is built and byte-compared but never run on real Windows (no hosted Windows Server ARM64 runner) |
| Documents | Admin guide (the package as the source, versions, what real Windows covers), operator guide (`make winhelper`, `helper/`, updates), host guide (step 1 from the package, the corrected cleanup sentence, "Code signing"), security overview (Windows servers, port 22, the helper in `SHA256SUMS`, KI-42), `SECURITY-REPORT.md` (scope, §3, KI-42, §8, §9), release checklist rows 1.46-1.48, 5.9 and section 8, `docs/dev/windows-ci.md`; the ACME bindings panel speaks of a Windows binding (`location_kind` on the ACME binding) | No Authenticode (§15 Q2): the gap is written in the host guide, the security overview, KI-42 and WN-18 |
| Owner steps | The ruleset that requires `windows-required` (`docs/dev/windows-ci.md`, row 1.47); the manual matrix of release-checklist section 8 (2019, Server Core, a domain baseline, Defender on with a cleanup run, an RDP listener with its own certificate, the helper from the signed package, AD FS and ARM64 when available; row 1.48, `WIN-45`); F14's skipped path after `main` is pushed | §13's acceptance "the jobs are required" depends on the owner's repository setting: the executor writes the steps and never changes settings |

## 20. Phase W5 as built (2026-10-27, R68)

Built on branch `windows-w5` (plan `docs/superpowers/plans/2026-10-27-windows-w5-ccs.md`, 10 tasks); decision R68,
rulings in [windows-iis.md](../rulings/windows-iis.md) "W5 (R68)", test IDs `WIN-46`..`WIN-55`
(`alice-v1/06-quality.md` §24.7), STRIDE `WN-19`..`WN-22`, error codes `ALC-WIN-0015`..`ALC-WIN-0020`. One migration,
`00036`. Facts F15-F18 (§14) measured on windows-2022 and windows-2025.

| Item | As built | Differs from this design |
|---|---|---|
| Location | Kind `win_ccs_file`, one per PFX file of a local CCS folder, discovered automatically; locator `{"type":"ccs_file","path","host"}`, `cert_path` `<folder>\<host>.pfx`; token the leaf's DER SHA-256; an IIS CCS binding without a file is `cert_missing`; the http.sys `ccs:<port>` record stays an unsupported `win_sslbinding` (`win_ccs`) | No Administrator "create location" flow and no file creation: Alice replaces existing files only |
| Links | The IIS `https` bindings with the CCS flag whose host IIS serves from the file: the exact file, else the nearest `_.<suffix>.pfx` at any depth, never the parent (F17); an unlinked file is deployable (`win_ccs_unlinked`) and checked by read-back only | §13's "`_.<domain>.pfx`" serves any depth below the domain, as measured, not one label |
| Password | One per Windows server (IIS has one for the store), `PUT /targets/{id}/ccs-password` by an Administrator with step-up, sealed `credentials` row (purpose `win_ccs`), never deleted (a set or a removal ends the live row, R72), 12-128 printable ASCII without spaces; to the helper only on standard input | §13's "an Alice location secret" is narrowed to one secret per server; no delete in W5 |
| Protocol | Helper `1.1.0`, protocol 1, `CCSMinVersion` 1.1.0: `ccs-dump` (elevated, no lock, at most 500 files of 256 KiB) and `ccs-deploy --op`; restore, status and fence reuse the `iis-*` subcommands on a journal of `kind` `ccs_file`; a 1.0.0 helper is never sent a CCS subcommand | No `ccs-restore` or `ccs-status` |
| Write | Registry read by the helper (disabled, unsupported, changed folder), the file read (missing, password mismatch, another leaf, unchanged), journal, `import_chain`, `write_file` (`BuildPFX` with intermediates, `.alice-<op>.tmp`, `ReplaceFileW` with `<file>.alice-<last 8 hex>.bak`), the refresh of every http.sys `ccs` record (F15 route (a)), read-back, event 1004 | The refresh step is new (IIS does not pick up a replaced file by itself); it touches every `ccs` record of the server with its own values (proven no-op on the runners) and a failure is reported as `ccs_refresh_failed`, never a rollback trigger |
| Verification and rollback | One endpoint per linked binding by host header; the served chain compared with the deployed one (F18: IIS sends the PFX's intermediates); a failed verification moves the backup back (`MoveFileEx`), refreshes and reads back; a third party's file is never overwritten (`SUPERSEDED`, `file_changed`); `BACKUP_MISSING` fails closed | `win.chain_differs` is never reported for a CCS file; inventory accepts a skipped verification for a `win_ccs_file` location whose stored servers are empty |
| Backups and cleanup | `iis-cleanup --plan` prunes a CCS journal's `.tmp` and `.bak` with it after 7 days, and those of the latest operation of a file (whose journal stays) after 7 days too; a backup is removed only with the previous file's bytes; W3's certificate cleanup ignores the CCS folder | §6.7's "a journal a binding record needs is never pruned" keeps the journal but not its backup (amended Ruling 16, WN-22): a backup lives at most 7 days |
| Drift, notices, interactions | The generic drift rule and `drift_repair`; the `rollback_failed`, `outcome_unknown` and `restored_unverified` e-mails have CCS texts (the file, its backup, IIS Manager); scoped access, licence, incidents, canary and network discovery as for any location | — |
| UI | The **CCS password** panel on the server's page, the CCS files under **Websites on this server** with their IIS sites, the warnings, the steps **Import the chain**, **Write the file**, **Verify**, the deploy dialog's CCS summary; EN and TR; e2e `web/e2e/windows-ccs.spec.ts` against `cmd/alice-fakewindows` (demo CCS at `C:\CCS`, `ctl ccs-password`) | — |
| Tests | Helper rules, kills and pruning (`winhelper`), the emulator's CCS half (`wintest`), the provider, inventory, the API, engine tests on the emulator, real-Windows `TestRealCCS*`, `TestFidelityCCS` and `TestRealRunnerIsClean` (ports 45480-45499, one shared CCS folder per test binary torn down by `TestRealCCSSharedFolderRemoved`) | The real tests share one folder and one site made before any CCS handshake and set `PollingInterval` to 10 s (F17's first-serve delay), restored at teardown |
| Limits | No farm layout (a share of another server), no file creation, no removal of the password, no store whose password is outside the rule; a new host's first file may not be served by IIS for minutes | — |

## 21. Phase W6 as built (2026-10-28, R69)

Built on branch `windows-w6` (plan `docs/superpowers/plans/2026-10-28-windows-w6-rdp.md`, 8 tasks); decision R69,
rulings in [windows-iis.md](../rulings/windows-iis.md) "W6 (R69)", test IDs `WIN-56`..`WIN-64`
(`alice-v1/06-quality.md` §24.7), STRIDE `WN-23`..`WN-25`, error codes `ALC-WIN-0021`..`ALC-WIN-0023`. One migration,
`00037`. Facts F19-F23 (§14) measured on windows-2022 and windows-2025 (runs 1-3).

| Item | As built | Differs from this design |
|---|---|---|
| Location | Kind `win_rdp`, one per server: the `RDP-Tcp` listener; locator `{"type":"rdp","listener":"RDP-Tcp"}`, `cert_path` `rdp/RDP-Tcp`, `servers` `[]`; details `port` (refreshed by every scan), `store`, `cert_sha1`, `self_signed`, `enabled`, `security_layer`, `nla`, `cert_template`, read as Windows applies them (the policy key first); token the leaf's DER SHA-256; an absent value is deployable with the single certificate of `Remote Desktop` as its token (F19) | RDP off (`win_rdp_disabled`), `SecurityLayer` 0 (`win_rdp_no_tls`) and no single self-signed certificate (`win_rdp_cert_unknown`) are unsupported; RDP autoenrolment is a warning (`win_rdp_autoenroll`); other listeners and RDS roles are not managed |
| Protocol | Helper `1.2.0`, protocol 1, `RDPMinVersion` 1.2.0: `rdp-dump` (elevated, no lock, no input), `rdp-deploy --op` (`RDPDeployInput`, no locator, no store) and `tls-probe ... --rdp`; restore, status and fence reuse the `iis-*` subcommands on a journal of `kind` `rdp_listener`; a helper below 1.2.0 is never sent an RDP command (`win_rdp_helper_outdated`) | No `rdp-restore` or `rdp-status` |
| Write | Journal, `import_chain`, `import_certificate` (always `My`), `grant_key_read` (one ACE for S-1-5-20, flags 0, mask `0x80120089` as the KSP stores `GENERIC_READ`, F21; `key_read_had` journalled with phase `writing` before the grant; the DACL read back, a merged grant fails), `set_listener` (the value set and read back), event 1005 | The grant mask is the stored form, not `GR`; a value the listener already holds is deleted and set again, because a same-value write does not rebuild the served chain (F20; about 10 ms of the self-signed certificate) |
| Verification | One endpoint, the listener's port at `127.0.0.1`, SNI by the trust rule; `helperproto.RDPNegotiate` (X.224 with `PROTOCOL_SSL \| PROTOCOL_HYBRID`), then the TLS handshake, never CredSSP (F22, F23: no 4625); Alice's `TLSProber{RDP: true}`, or the helper's `tls-probe --rdp` when Alice cannot reach the port; the chain compared with the helper's built chain; `RDPPickupWait` 0 (F20: at most 17 ms) | — |
| Rollback | `iis-restore` under the R48 guard: the previous value set back, or deleted after a first deployment (the self-signed certificate served again); the listener must still name the operation's certificate (`SUPERSEDED`, `file_changed`); the revoke removes only the grant's own ACE (non-inherited, allow, S-1-5-20, flags 0, the exact mask) and a key still readable afterwards is reported (`rdp_key_acl_left`); a failed grant ends `rolled_back` (`windows.rdp_key_acl_failed`) with the listener untouched | The revoke is narrower than "every non-inherited NETWORK SERVICE ACE" (Ruling 10 amended); not revoked by a later deployment that replaces the certificate |
| Drift, cleanup, notices, interactions | The generic drift rule and `drift_repair` (a re-pointed or deleted value is `binding_repointed`; a missing certificate or broken key is reported, never repaired); W3's cleanup keeps what the listener names and removes the key (with its ACE) of a certificate Alice imported; the `rollback_failed`, `outcome_unknown` and `restored_unverified` e-mails have RDP texts (the listener, the previous certificate, `Win32_TSGeneralSetting`, the console or SSH as the way in), the others the RDP note; scoped access, licence, incidents and canary as for any location | Network discovery does not see the listener (it does not speak the RDP negotiation) |
| UI | The row **Remote Desktop (RDP-Tcp)** under **Websites on this server** (port, NLA, **Self-signed by Windows**, reasons, warning), the steps **Import the chain**, **Import the certificate**, **Allow NETWORK SERVICE to read the key**, **Point the listener to the certificate**, **Verify** and the `rdp_key_acl_left` note, the deploy dialog's RDP summary; EN and TR; e2e `web/e2e/windows-rdp.spec.ts` against `cmd/alice-fakewindows` (the demo host's listener on 3389) | — |
| Tests | Helper rules, kills and the rebuild (`winhelper`), the emulator's listener with the negotiation and the NETWORK SERVICE key flag (`wintest`), the provider, inventory, engine tests on the emulator, real-Windows `TestRealRDP*`, `TestFidelityRDP` and `TestRealRunnerIsClean` (the value, RDP, NLA and TermService as found; ports 45500-45519) | The runner's RDP was already on, so the fixture's TermService start path was never needed |
| Limits | Only `RDP-Tcp`; no Remote Desktop setting is changed; a third party's certificate keeps its NETWORK SERVICE ACE; `SecurityLayer` 0 and Windows Server 2019 not measured on a runner | — |

## 22. Phase W7 as built (2026-10-31, R71)

Built on branch `windows-w7` (plan `docs/superpowers/plans/2026-10-28-windows-w7-winrm.md`, Task 0 and 10 tasks);
decision R71, rulings in [windows-iis.md](../rulings/windows-iis.md) "W7 (R71)", test IDs `WIN-68`..`WIN-75`
(`alice-v1/06-quality.md` §24.7), STRIDE `WN-26`..`WN-30`, error codes `ALC-WIN-0024`..`ALC-WIN-0028`. One migration,
`00038`. Facts F24-F32 (§14) measured on windows-2022 and windows-2025 (10 runner runs, the budget).

| Item | As built | Differs from this design |
|---|---|---|
| Transport | `transport: winrm` in `targets.config` (an SSH server's config stays W6's byte for byte), fixed when the target is created (a patch to the other transport is `ALC-WIN-0027`); WinRS over HTTPS on 5986 (TLS 1.2 or later), the listener's certificate pinned by SPKI with the shared TLS pinning (the host-key confirm and re-pin flow); port 5985, Basic and `AllowUnencrypted` refused by construction, before any dial | Authentication is the target's username and a password over NTLMv2 (R71, competitor parity), not client-certificate mapping |
| Client | The in-house WS-Man/WinRS subset `internal/providers/windows/winrs` with `github.com/Azure/go-ntlmssp` (v0.1.1, now a direct module) for NTLMSSP only; the credentials go on the Create request alone and the Basic header never leaves the process; at most 2 dials per call, the second only during the sign-in (Windows closes the connection after the anonymous 401, F24 (d)); a transport failure during the sign-in is `ErrUnreachable`, never a refused password; `MaxSendChunk` 96 KiB, `MaxResponseHeaderBytes` 64 KiB, `OperationTimeout` min(20 s, the call's budget); Signal and Delete on the one connection with 5 s each | The second dial during the sign-in (the plan allowed one) |
| Protocol | Helper `1.2.0` unchanged, protocol 1, no `WinRMMinVersion`: WinRS starts `cmd.exe /C "C:\Program Files\Alice\alice-helper.exe" ssh` and the subcommand travels in `SSH_ORIGINAL_COMMAND`, which `cmd.exe` never parses; `winrs.Client.Run` refuses any argument but `ssh`, any variable but `SSH_ORIGINAL_COMMAND` and a program with a `cmd.exe` metacharacter | F25: WinRS inserts `cmd.exe` even when asked not to (`WINRS_SKIP_CMD_SHELL` ignored; `MustComply` faults 2150858809); the helper 1.3.0 fallback was not taken because it would not remove `cmd.exe` |
| Credential | A sealed per-target password whose rows are never deleted (a set or a removal ends the live row, R72) (purpose `win_winrm`, kind `winrm_password`), set with `PUT /api/v1/targets/{id}/winrm-password` under step-up, 12 to 128 printable ASCII characters without spaces (`ALC-WIN-0028`), never readable, audited as `target_winrm_password_set`; one implementation with the CCS password; in the provider it is released by a `defer` before the slot, so it is zeroed on every path | `targets.credential_id` still names the platform key, unused (Ruling 5) |
| Errors | `windows.winrm_auth_refused` (`ALC-WIN-0024`: a 401 or fault 2147942405 at Create sends nothing; after Create a write is uncertain), `winrm_password_missing` (`ALC-WIN-0025`, before any dial), `winrm_fault` with `wsman_code` (`ALC-WIN-0026`), `transport_immutable` (`ALC-WIN-0027`), `winrm_password_invalid` (`ALC-WIN-0028`); a missing helper is `cmd.exe`'s exit 1 with no stdout, mapped as `helper_missing`; a killed helper exits 137; `title_winrm` variants of the SSH unreachable, timeout, output-too-large and protocol-error reasons, chosen by the param `transport` | F29: a missing program is an exit code, not a WS-Man fault |
| Setup script | `GET /api/v1/targets/{id}/winrm-setup?from=`: the account and a password prompt (typed on the server and in Alice, never generated or printed), the helper install shared with the SSH script, an HTTPS listener on 5986 when there is none, the firewall rule `Alice-WinRM-In` from `$AliceAddress` (Any with a printed warning when `from` is absent), every HTTPS listener's SPKI fingerprint printed; Negotiate read from the registry before any change (off stops the script); `LocalAccountTokenFilterPolicy` 0 or absent becomes 1 for a local account; Negotiate, Basic, `CbtHardeningLevel`, `AllowUnencrypted` and the 5985 listener are never changed; a domain account is never added to Administrators | The web passes no `from` yet (owner item) |
| UI | The transport choice with the WN-26 caution, the WinRM port 5986, the username rule (`alice`, `.\alice`, `SERVER\alice`, `DOMAIN\alice`; a UPN refused), the script dialog then the password panel with step-up and the connection test, the TLS identity confirm, the target page's transport fact; English and Turkish | — |
| Tests | `winrs` unit tests (never Basic, sign-in on Create only, the dial rule, bounds, faults, the shell always deleted), the emulator's WinRM HTTPS listener with NTLMv2 verification and WinRS shells (`wintest`, `alice-fakewindows ctl winrm-account`), provider, inventory, API, notify and deployment-job tests on the emulator, real-Windows `TestRealWinRM*` and `TestFidelityWinRM` on both images (each test as its own account `alice-w7-<n>`, everything restored), e2e `windows-winrm.spec.ts` in EN and TR; `WIN-68`..`WIN-75` | — |
| Security | WN-26 High accepted by the owner (the account is not limited to the helper; competitor parity), WN-27..WN-30 (WN-28: `cmd.exe /C` runs the `AutoRun` values and the Create body goes up to 3 times to the pinned listener; WN-29: lockout and the Go-string residual; WN-30 Med, since F24 (a) applies); the transport review (Ruling 26) and the independent final review at `3b5da306`: 0 critical, 2 important, 10 minor, each fixed or declined with its reason | — |
| Limits | A domain account by syntax and the emulator only; a domain account, Server Core and Windows Server 2019 over WinRM, and `.\alice` on a domain-joined server, are manual-matrix items; no PSRP or JEA, Kerberos, CredSSP, certificate mapping or channel binding (`CbtHardeningLevel` Strict refuses); no password rotation or removal by Alice, no transport change, a second target for one host on the other transport is not refused; the shell `IdleTimeOut` reaping is not measured (Alice always deletes its shell) | — |

## 23. Phase W8 as built

To be filled when phase W8 is accepted (plan `docs/superpowers/plans/2026-10-31-windows-w8-debt.md`, Task 6; decision
R72, rulings in [windows-iis.md](../rulings/windows-iis.md) "W8 (R72)", test IDs `WIN-76`..`WIN-78`).
