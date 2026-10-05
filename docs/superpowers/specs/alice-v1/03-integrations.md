## 11. Azure Key Vault Integration

### 11.1 Scope

Azure Key Vault (KV) is a target of type `azure_key_vault`. One vault = one managed target for licensing. Vaults are added one at a time by URL (`https://<name>.vault.azure.net`). Azure public cloud only.

| Object | Alice reads | Alice writes | Notes |
|---|---|---|---|
| Certificates | list, versions, expiry (`notAfter`), `notBefore`, thumbprint, subject/SANs, issuer, policy (key type/size, exportable, lifetime actions, issuer type), enabled flag | import of an uploaded cert (new version) | Alice never creates, renews or deletes KV certificates. KV renews them itself (self-signed, DigiCert, GlobalSign integrated CAs). |
| Keys | inventory: name, type (RSA/EC), size/curve, expiry, enabled, created/updated | nothing | Alerts on expiry only. No key rotation in v1. Key material is never requested. |
| Secrets | metadata only: name, expiry, enabled, content type, `managed` flag | nothing | Contents are never read, with one exception: the secret that backs a certificate (see 11.4), and only when a deploy is required. |

Not supported in v1: Managed HSM, KV key rotation, App Gateway / Front Door / App Service binding, Azure Government and China clouds, subscription-wide vault discovery, Event Grid (needs inbound internet).

### 11.2 Go SDK packages

All packages are from the official Azure SDK for Go (modules, pinned in `go.mod`, reviewed on each release with `govulncheck`):

| Purpose | Import path |
|---|---|
| Credentials | `github.com/Azure/azure-sdk-for-go/sdk/azidentity` |
| Certificates | `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates` |
| Keys (metadata) | `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys` |
| Secrets (metadata + cert-backing secret) | `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets` |
| Error type | `github.com/Azure/azure-sdk-for-go/sdk/azcore` (`azcore.ResponseError`) |

Implementation rules:
- The `azurekv` provider wraps the three clients behind a small internal interface (`kvAPI`) so the default test suite can use an in-memory fake (decisions: mocked Key Vault by default, optional real Azure suite).
- One `azcertificates.Client` / `azkeys.Client` / `azsecrets.Client` per vault, created lazily and cached per target.
- Only the `Client.NewList...Pager` APIs are used for listing (pagination handled by the pager, max page size 25 requested for metadata calls).
- All calls carry a 30 s context timeout; the Azure SDK default retry policy stays enabled (3 retries, exponential) and Alice adds its own backoff on top for 429 (11.5).
- HTTP proxy: the SDK honours `HTTPS_PROXY`; the Alice container passes it through if the admin sets it in `settings` (needed by many regulated networks).

### 11.3 Authentication options

Configured per vault in the credential store (encrypted, never returned by API). `azidentity` credential types used:

| Option | azidentity type | When to use | Stored in Alice |
|---|---|---|---|
| Service Principal + certificate (recommended) | `ClientCertificateCredential` | Default recommendation; no shared secret, revocable, 1-2 year cert | tenant ID, client ID, PEM/PFX private key + cert (encrypted) |
| Service Principal + client secret | `ClientSecretCredential` | Quick start | tenant ID, client ID, secret (encrypted); UI shows the secret expiry date entered by admin and alerts 30 days before |
| Managed Identity | `ManagedIdentityCredential` (system- or user-assigned via client ID) | Alice runs on an Azure VM | nothing secret; optional client ID |

`DefaultAzureCredential` is NOT used (it probes environment variables and CLI logins, which is unpredictable and can silently use another identity). The identity Alice uses is always the explicitly configured one, and its object ID is shown in the UI ("Alice signs in to Azure as ...").

"Test connection" performs, in order: token acquisition for scope `https://vault.azure.net/.default` -> list certificates (page 1) -> list keys (page 1) -> list secrets (page 1) -> if any binding to Nginx exists, read policy of one bound certificate, and (only when the admin ticks "also test deployment access") `GetSecret` on a bound certificate name without storing or logging the value. The result is a checklist showing which capability level is granted (Monitor / Deploy / Import), derived from which calls returned 403.

### 11.4 Least-privilege permissions

Vaults should use the **Azure RBAC** permission model (default for new vaults). Scope: the vault, or, tighter, an individual certificate/secret for deploy roles (`.../vaults/<v>/secrets/<name>`).

| Alice capability | Role assigned to Alice's identity | What it allows Alice to do |
|---|---|---|
| Monitor only (inventory, expiry alerts, version detection) | `Key Vault Reader` | Reads metadata of vault objects. Cannot read secret values or key material. (verify: whether `Key Vault Reader` alone is sufficient for the data-plane `list` calls of certificates/keys/secrets on RBAC vaults. This is confirmed by the real-Azure test suite in Phase 5; until then the documentation states the role as expected but unconfirmed.) |
| + Deploy to Nginx (read certificate private key) | `Key Vault Secrets User` (in addition) | `GetSecret` on the certificate-backing secret, which contains the PFX/PEM including private key. Can also read every other secret in scope, so the docs recommend scoping the assignment to the individual certificate-backing secrets. `Key Vault Certificate User` is not narrower (it also includes `secrets/getSecret`), so `Key Vault Secrets User` is the role used. |
| + Upload / import certificates | `Key Vault Certificates Officer` (in addition) | `ImportCertificate`, and any other certificate operation (Alice only ever calls import). |

The UI shows this table on the "Add Azure Key Vault" page with copy-paste `az role assignment create` commands. Alice never needs `Key Vault Administrator`, `Contributor`, or any management-plane (ARM) permission, because vaults are added by URL, not discovered.

Legacy **access policy** model (also supported; Alice detects it from HTTP 403 with `ForbiddenByPolicy` vs `ForbiddenByRbac` error codes):

| Capability | Certificate permissions | Secret permissions | Key permissions |
|---|---|---|---|
| Monitor | `List`, `Get` | `List` | `List` |
| + Deploy | (same) | + `Get` | (same) |
| + Import | + `Import` | (same) | (same) |

Note: `Get` on certificates returns the public part only; the private key is exposed only through the secret with the same name, hence secret `Get` for deploy.

### 11.5 How a certificate's private key is retrieved

1. Alice calls `azcertificates.GetCertificatePolicy(name)`. If `Policy.KeyProperties.Exportable == false`, the certificate is marked `exportable=false` in inventory and **cannot be deployed to Nginx**. The UI disables "Deploy" and any binding attempt fails with the message (EN): "This certificate's private key is marked non-exportable in Azure Key Vault, so Alice cannot copy it to a server. Create a new version of the certificate with 'Exportable private key' turned on, or upload a different certificate." Alice never tries the secret endpoint in that case. Changing this needs a new KV certificate policy (Azure does not allow changing exportability of existing key material).
2. If exportable: `azsecrets.GetSecret(name, version)` with the certificate name and the specific version id (never "latest", so that the cert and key are guaranteed to be from the same version).
3. Content-type handling, from `SecretProperties.ContentType` (which is the certificate policy's `SecretProperties.ContentType`):
   - `application/x-pkcs12` (default in KV): value is base64 of a PFX with an empty password. Alice decodes it with `software.sslmate.com/src/go-pkcs12` (pinned in `go.mod`; also used for PFX upload and for building the PFX in 11.8) into private key + leaf + chain.
   - `application/x-pem-file`: value is PEM text with `PRIVATE KEY` (PKCS#8) and `CERTIFICATE` blocks; Alice splits by block type.
4. Alice normalises to two PEM outputs: `fullchain.pem` (leaf first, then intermediates in path order, root omitted unless the KV bundle explicitly included it and the admin enabled "include root") and `privkey.pem` (PKCS#8, unencrypted, will be written 0600).
5. Sanity checks before anything is sent to a server: the private key matches the leaf public key; `notAfter` in the future; leaf thumbprint equals the version's `x509Thumbprint`; chain builds to a root within the bundle or is flagged "chain incomplete" (warning, not blocking).
6. The private key exists only in memory for the duration of the job (zeroed after use where the Go runtime allows), is never written to the DB in clear, never logged, and is not persisted in Alice's secret store unless the admin uses "keep a copy" (default off; KV stays the source of truth).

### 11.6 Change detection (polling)

Default interval 15 minutes per vault (setting `azurekv.poll_interval`, min 5 min, max 24 h), with 0-60 s random jitter per vault. One poll job per vault, run through the jobs queue (`FOR UPDATE SKIP LOCKED`), max 1 poll running per vault.

Algorithm per poll:
1. `ListCertificateProperties` (paged). For each certificate, the returned `Properties` include the current version id (last segment of `ID`), `Updated`, `Created`, `Expires`, `NotBefore`, `Enabled`, `X509Thumbprint`.
2. Compare against the stored `certificates` row (columns: `kv_current_version`, `kv_updated_at`, `thumbprint`). The change key is the tuple (current version id, X.509 thumbprint); ETag is not used. `Updated` is used only as a cheap pre-filter and for display, never as the only trigger (clock skew in Azure metadata).
3. New version detected when the current version id differs. Then: fetch policy + full properties, write a `certificate_versions` record, audit event `kv.cert.new_version`, and decide:
   - Bindings exist with `auto_deploy = true` and the certificate is exportable and enabled -> enqueue one deploy job per bound Nginx host (section 12.7).
   - Bindings with `auto_deploy = false` -> notification "New version available, deploy manually".
4. Keys and secrets metadata lists are refreshed every 4th poll (about hourly) - they only feed inventory and expiry alerts.
5. Objects that disappear from the list are marked `missing` (not deleted), soft-deleted KV items (`ListDeletedCertificateProperties` not used in v1) simply show as missing.
6. A version that is disabled, or whose `Expires` is earlier than the currently deployed one, is not deployed automatically; an alert explains why. A version that is not yet valid (`notBefore` in the future) is not deployed until `notBefore` has passed, and the alert says so. `notBefore` is compared with the Alice server clock for this purpose only; it is never used in license or clock-tamper math (a hostile value must not be able to influence licensing).
7. First poll after adding a vault imports the inventory only; it never auto-deploys existing versions (no surprise deployments). Auto-deploy triggers only for versions that appear after the binding was created and enabled.

Throttling: Key Vault returns HTTP 429 with `Retry-After`. Alice honours `Retry-After` when present, otherwise uses exponential backoff 5 s, 10 s, 20 s, 40 s, up to 5 min with full jitter, max 6 attempts per call. If the poll still fails, the vault status becomes `degraded` and the next poll is delayed (interval x 2, cap 1 h); the next success resets it. Alice keeps a per-vault token bucket (default 5 requests/s, well below the documented limits) and fetches details only for certificates whose version changed, so large vaults (thousands of objects) cost pages, not per-object calls. Vaults do not share a bucket.

Polling stops in license lock; expiry alert emails for KV certificates continue using the last known data, and the email states "license expired; data may be outdated". After a valid license is uploaded, recurring read-only jobs (polling, discovery, expiry checks) resume automatically; pending external-change jobs (auto-deploys that were held) are not started until an Admin confirms them.

### 11.7 KV to Nginx binding model

A **binding** connects one KV certificate name to a list of Nginx certificate locations.

```
binding
  id
  kv_target_id            (azure_key_vault target)
  kv_cert_name
  auto_deploy             bool, default false, per binding
  include_root            bool, default false
  locations[]             -> certificate_locations rows: (nginx_target_id, server_name, cert_path, key_path)
  last_deployed_version, last_result, created_by, created_at
```

Rules:
- A location belongs to at most one binding. A binding may contain locations from many hosts and many server blocks.
- Only locations discovered by the Nginx provider (section 12.4) can be bound; unsupported (variable paths) locations cannot.
- A location can hold ECDSA and RSA certificates side by side (12.4.5); each of the two is bound to its own KV certificate.
- Key type of the KV version must equal the key type of the location being replaced. Mismatch (RSA version into an ECDSA slot) is refused with a clear message.
- Binding creation requires Operator or Admin role and that the vault capability level is at least "Deploy". Toggling `auto_deploy` is an Admin action and is audited.
- Deleting a binding never touches servers. Deleting a vault target requires removing bindings first (or confirming their removal).
- Deploy jobs from one KV version are independent per host: failure on one host does not stop or roll back others. The binding shows per-location status (`deployed <version>`, `pending`, `failed: reason`).
- Manual "Deploy now" is available for any version of the bound certificate, including older versions (rollback by redeploying).
- In license lock, user-initiated external changes (deploy, import) are refused with `license.locked`; creating a binding (a database-only change) and viewing remain possible, but nothing is deployed.

### 11.8 Import of uploaded certificates

Uploads (PFX with password or PEM cert+key+chain) or certificates from an in-platform CSR (signed cert supplied by the admin) can be pushed into a vault:
1. Validate cert/key match, expiry, chain; reject if the key is encrypted with an unknown password.
2. The private key is protected (Alice store) -> repackaged as PFX (empty password) or PEM in memory -> `azcertificates.ImportCertificate(name, ImportCertificateParameters{Base64EncodedCertificate, Password, CertificatePolicy})`.
3. Policy on import: `exportable=true` (required to deploy later), key type/size taken from the uploaded key, secret content type `application/x-pkcs12`, no lifetime actions (imported certs cannot auto-renew in KV; UI says so).
4. If the name already exists, import creates a **new version** (this is a KV feature). The UI warns "This will add a new version to existing certificate <name>", requires confirmation, and then normal detection may trigger bound auto-deploys.
5. Requires `Key Vault Certificates Officer` (or `Import` in access policy). Missing role -> 403 -> mapped message below. Refused with `license.locked` in license lock.

### 11.9 Error cases (plain language)

| Situation | Detected by | Message shown to the user | Action |
|---|---|---|---|
| Wrong tenant/client/secret | `azidentity` auth error (`AADSTS7000215`, `AADSTS700016`) | "Alice could not sign in to Azure with these details. Check the tenant ID, application ID and secret." | vault status `auth_failed`, retry every poll, alert admins after 3 failures |
| Client secret / certificate expired | `AADSTS7000222` | "The secret used by Alice to sign in to Azure has expired. Create a new one in Azure and update it here." | alert |
| Missing permission (403) | `azcore.ResponseError.StatusCode == 403`, error code `Forbidden` / `ForbiddenByRbac` / `ForbiddenByPolicy` | "Alice is signed in but is not allowed to <read secrets/import certificates> in this vault. Ask your Azure admin to assign the role <role name>." | the capability is shown as missing; monitoring continues with what is allowed |
| Vault firewall blocks Alice | 403 `ForbiddenByFirewall`; or network timeout | "The vault's firewall does not allow connections from this Alice server (IP a.b.c.d). Add the address to the vault's allowed networks or use a private endpoint." | alert |
| Vault not found / DNS failure | 404 `VaultNotFound` / DNS error | "The vault address cannot be found. Check the name and network access (private endpoints need internal DNS)." | |
| Throttled | 429 | "Azure is asking Alice to slow down. Alice will retry automatically." | backoff (11.6), status `degraded` only after retries exhausted |
| Non-exportable key | policy check | text in 11.5 | deploy disabled |
| Secret cannot be decoded | PFX/PEM parse error | "The certificate data from Azure could not be read. Nothing was changed on your servers." | deploy job fails before any SSH |
| Certificate disabled / expired version | properties check | "This version is disabled (or expired) in Key Vault, so it was not deployed." | |
| Soft-deleted / purged object | 404 `CertificateNotFound` | "This certificate no longer exists in the vault." | binding marked broken |
| Clock skew | `AADSTS700024`-style / token not yet valid | "The clock on the Alice server appears to be wrong, so Azure rejected the sign-in." | |

Every message above carries a user-visible error code in the format `ALC-<AREA>-<NNNN>` (areas for this section: `AKV`, `NGX`, `SSH`; numbers are assigned in the central error catalog and documented in `troubleshooting.md`). Raw Azure errors (with correlation `x-ms-request-id`) are stored in the job log after redaction (no tokens, no secret values) and shown under "Technical details".

### 11.10 Explicit v1 limits

- Only vaults added manually; no subscription scanning; no Managed HSM; public cloud only.
- Only certificates are written (import); no key/secret writes; no key rotation; no secret content reads except the cert-backing secret.
- Polling only; worst-case detection delay = poll interval + jitter.
- Certificate deployment only to Nginx locations discovered by Alice; no App Gateway, Front Door, App Service, VMs via Azure APIs.
- Exportable certificates only. KV certificates with `contentType` other than PFX/PEM are unsupported.
- KV certificate chains are deployed as delivered by KV; Alice does not fetch missing intermediates from the Internet (air-gapped friendly), it only warns.
- Soft-delete/purge-protection events are not tracked.

---

## 12. Nginx over SSH Integration

### 12.1 Supported systems

| OS | Versions | Nginx package | Service manager |
|---|---|---|---|
| Ubuntu | 20.04+ | distro or nginx.org packages | systemd |
| Debian | 11+ | distro or nginx.org | systemd |
| RHEL / Rocky / AlmaLinux | 8+ | distro AppStream or nginx.org | systemd |

Requirements: OpenSSH server, `sudo`, `nginx` in `/usr/sbin/nginx` (path stored per target from `command -v nginx` at setup), `openssl` (for optional local TLS probe), systemd unit `nginx.service`. Not supported: containerised nginx, ingress-nginx, Nginx Plus API, OpenResty custom prefixes (unless standard paths), TLS inside `stream {}` blocks (discovery shows a warning), Windows.

### 12.2 Service account and helper setup

Alice never has a root login. The admin runs once per target a setup script generated by Alice (downloadable from the "Add target" wizard, shown as a copy-paste block):

```sh
# run as root on the target
curl -o /usr/local/libexec/alice-helper  https://<alice-host>/api/v1/setup/alice-helper   # or scp from the bundle
install -o root -g root -m 0755 alice-helper /usr/local/libexec/alice-helper
useradd --system --create-home --home-dir /var/lib/alice-svc --shell /bin/bash alice-svc
install -d -m 0700 -o alice-svc -g alice-svc /var/lib/alice-svc/.ssh
echo '<Alice public key>' > /var/lib/alice-svc/.ssh/authorized_keys   # with options below
chown alice-svc: /var/lib/alice-svc/.ssh/authorized_keys; chmod 600 /var/lib/alice-svc/.ssh/authorized_keys
install -m 0440 -o root -g root alice-sudoers /etc/sudoers.d/alice   # validated with: visudo -cf
install -d -m 0700 -o root -g root /var/lib/alice-helper/backups
```

(Phase 3, R37: Alice serves no helper binary over HTTP; the script installs the `alice-helper` copied next to it from `make helper` or the release bundle after checking its SHA-256 checksum, and also runs `usermod -p '*' alice-svc` so servers with `UsePAM no` accept the key. The home and `.ssh` of `alice-svc` belong to root (0755) and `authorized_keys` is written as root:root 0644 through `mktemp` and `mv`, with the options `no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc`; `from=` is offered through the API only; the UI shows no helper checksum, the script checks it.)

The authorized_keys line for Alice's key can carry `from="<alice-ip>",no-agent-forwarding,no-X11-forwarding,no-port-forwarding` (the wizard offers the `from=` option, off by default because of NAT/HA). No `command=` restriction (Alice needs SFTP-less exec channels only; it uses exec, never a shell).

The helper is shipped inside the Alice release (`alice-helper`, a small static Go binary built from the same repository, ~1 MB, `GOOS=linux`, amd64 and arm64, checksum shown in the UI) and is **root-owned** on the target. It is installed and updated only by the admin running the setup snippet; Alice cannot update it (no write permission, no sudo for it). On every connect Alice runs `alice-helper version` (unprivileged, allowed) and shows "helper outdated" when the protocol version differs; operations requiring a newer protocol are refused, older-compatible ones still work.

The setup snippet has two sudoers profiles: `nginx` (all subcommands) and `linux` (SSH-key subcommands only, section 13). The `linux` profile is used for generic Linux targets, the `nginx` profile for Nginx targets (which also support SSH-key management).

### 12.3 sudoers and helper interface

`/etc/sudoers.d/alice` (profile `nginx` shown in full; profile `linux` contains only `ALICE_COMMON`, i.e. it omits `ALICE_NGINX_ONLY` and the certificate-file subcommands of `ALICE_PATH_ARGS`):

```
# Managed by Alice. Do not edit. Validate with: visudo -cf /etc/sudoers.d/alice
Defaults:alice-svc !requiretty
Defaults:alice-svc !lecture
Defaults:alice-svc env_reset
Defaults:alice-svc secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults:alice-svc log_output

Cmnd_Alias ALICE_COMMON = \
    /usr/local/libexec/alice-helper sshd-dump, \
    /usr/local/libexec/alice-helper hostkeys, \
    /usr/local/libexec/alice-helper cleanup *, \
    /usr/local/libexec/alice-helper authkeys-list *, \
    /usr/local/libexec/alice-helper authkeys-read *, \
    /usr/local/libexec/alice-helper authkeys-write *

Cmnd_Alias ALICE_NGINX_ONLY = \
    /usr/local/libexec/alice-helper nginx-dump, \
    /usr/local/libexec/alice-helper nginx-test, \
    /usr/local/libexec/alice-helper nginx-reload, \
    /usr/local/libexec/alice-helper stat *, \
    /usr/local/libexec/alice-helper read-cert *, \
    /usr/local/libexec/alice-helper install-cert *, \
    /usr/local/libexec/alice-helper backup *, \
    /usr/local/libexec/alice-helper restore *

alice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_NGINX_ONLY
```

(Phase 3, R37 item 3: the built `ALICE_COMMON` lines are `sshd-dump`, `hostkeys`, `cleanup --op *`, `authkeys-list` (no `*`: sudo needs at least one argument to match a trailing `*`), `authkeys-read /*` and `authkeys-write /* --expect-sha256 * --content-sha256 * --op *`; the `ALICE_NGINX_ONLY` lines are narrowed in Phase 4. `version` prints the protocol 3 of Phase 3; `hostkeys` computes fingerprints in Go, without `ssh-keygen`.)

(Phase 4, R38 items 1–5: helper protocol 4 (1.3.0) replaces `nginx-reload`, `stat`, `read-cert`, `install-cert`, `backup` and `restore` with `nginx-dump` and `nginx-test` (no arguments; `nginx-dump` returns a parsed summary, stat data and parsed `CERTIFICATE` blocks only, after comparing every section of `nginx -T` with the real file), `nginx-deploy --op <id> --cert <path> --key <path> --expect-cert-sha256 <hex> --content-sha256 <hex>` (one journaled root-side transaction, stdin JSON), `nginx-restore --op <id>`, `nginx-status --op <id>`, and the unprivileged `tls-probe`. The built `ALICE_NGINX_ONLY` lines are `nginx-dump`, `nginx-test`, `nginx-deploy --op ????????-????-????-????-???????????? --cert /* --key /* --expect-cert-sha256 <64 ?> --content-sha256 <64 ?>`, `nginx-restore --op <36 ?>` and `nginx-status --op <36 ?>`; `tls-probe` has no line. The "allowed roots" of rule 3 are not used: the helper writes only the two existing files of a supported pair of its own authenticated `nginx -T`, reached through root-owned directories and links that are not group or other writable, with one link and a certificate or key extension (`.cert` added); a pair touched by a configuration file that a non-root user can write is unsupported (`config_file_writable`). Owner and group are kept, the key becomes 0600 unless it was 0640, `restorecon` is not run, and `/usr/sbin/nginx` and `/usr/bin/systemctl` are fixed paths.)

The `*` wildcard in sudoers matches any characters including spaces, so **sudoers is only a coarse gate; the helper is the enforcement point** and treats all arguments as hostile. No `NOEXEC`-breaking commands (no shell, `tee`, `cp`, `systemctl` directly) are ever in sudoers. The helper calls `nginx`, `systemctl`, `restorecon` by absolute path with `exec.Command` (no shell), a clean environment, and umask 077.

Helper protocol: every subcommand exits 0 on success; on failure, exit code 2 = validation refused, 3 = precondition (hash mismatch, missing file), 4 = command failed, and prints one JSON line on stdout `{"ok":false,"code":"PATH_NOT_ALLOWED","message":"..."}`. Alice maps each helper code to a user-facing `ALC-<AREA>-<NNNN>` error code and message; helper codes are internal. Successful output is JSON (except stream payloads). Every call is logged to syslog `authpriv` with the calling user, subcommand and normalised path (never contents) for local audit, plus Alice's own audit log.

| Subcommand | Arguments / stdin | Behaviour |
|---|---|---|
| `version` | none (not sudo) | prints `{"helper":"1.0.0","protocol":1}` |
| `nginx-dump` | - | runs `nginx -T` (stdout+stderr captured, max 20 MB), returns text; also returns `nginx -V` prefix/conf-path/version as JSON header |
| `nginx-test` | - | runs `nginx -t`; returns exit code and output |
| `nginx-reload` | - | `nginx -t` first (refuses if fails), then `systemctl reload nginx`, then `systemctl is-active nginx`; returns status |
| `stat <path>` | path | exists, type, size, mode, owner, group, mtime, SELinux context; no content |
| `read-cert <path>` | path | validates path (below), reads file, outputs **only** blocks of type `CERTIFICATE` (never `PRIVATE KEY` or others); fails if file is not PEM cert or > 256 KB |
| `install-cert <dest> --kind cert\|key --op <opid>` | stdin = PEM (max 256 KB) | validate dest; parse stdin as PEM of the right kind; stage to `<dir>/.alice-<op>-<rand>` created with O_EXCL and mode 0600 in the same directory; copy owner/mode/SELinux context from existing `dest` when it exists, else defaults: cert 0644 root:root, key 0600 root:root; fsync file; rename over dest; fsync directory; `restorecon -F dest` if SELinux enforcing/permissive and `restorecon` present |
| `backup <path> --op <opid>` | path | copies file content + metadata JSON (mode/owner/context/sha256) into `/var/lib/alice-helper/backups/<opid>/<n>.bak` (root:root 0600, dir 0700); returns sha256 |
| `restore <path> --op <opid>` | path | restores from that backup: same atomic rename procedure, original mode/owner/context; refuses if backup missing or its sha256 mismatches its metadata |
| `cleanup --op <opid>` | - | removes backup directory of that op; helper also auto-deletes backup dirs older than 30 days on any call |
| `sshd-dump` | - | `sshd -T` (section 13) |
| `hostkeys` | - | lists `HostKey` files from `sshd -T` and prints fingerprints via `ssh-keygen -lf` on the `.pub` files |
| `authkeys-*` | see section 13 | |

Path validation (used by every path-taking certificate subcommand):
1. Path must be absolute, <= 4096 bytes, contain no NUL/newline/control characters, no `..` component, no glob characters. It is cleaned (`filepath.Clean`).
2. The **parent directory** must exist; it and the file (if present) are resolved with `filepath.EvalSymlinks`. All checks apply to the *resolved* path, so a symlink pointing outside is refused. Writing through a symlink at the final component is allowed only when the resolved target passes the checks (Let's Encrypt style `live/` links); the rename is done onto the resolved target, not the link.
3. Resolved path must be inside one of the allowed roots: `/etc/ssl`, `/etc/nginx`, `/etc/pki` **or** be exactly a path currently referenced by `ssl_certificate` / `ssl_certificate_key` in `nginx -T` output (the helper runs and parses `nginx -T` itself; the caller's claims are not trusted).
4. Never allowed, even inside roots: anything under `/etc/ssl/private` other than for kind `key` writes/backups that are referenced by nginx; `/etc/shadow`-like names are irrelevant because of the root list, but additionally the file name must end with `.pem`, `.crt`, `.cer`, `.key`, `.chained`, `.fullchain` or be referenced by nginx; directories, devices, FIFOs, and files with hard-link count > 1 are refused for writes.
5. `read-cert` and `stat` never return private key content. `install-cert --kind key` accepts a key only via stdin; `backup` of a key file stays inside the root-only backup directory and is never sent back to Alice (restore is done by the helper from its own copy).
6. `--op` must match `^[a-f0-9-]{36}$` (UUID) to prevent path tricks in the backup dir.

### 12.4 Discovery algorithm

Triggered when the target is added, on demand, and on a schedule (default daily; disabled in license lock).

1. SSH connect (host key checked against pinned key; mismatch -> block, alert). Run `alice-helper version`; check OS via `cat /etc/os-release`; check nginx presence via `nginx-dump`.
2. `nginx-dump` returns `nginx -T`. Parse:
   - Tokenizer handles comments (`#`), single/double quoted strings, escaped characters, `;`, `{`, `}`.
   - Lines `# configuration file <path>:` in the `-T` output mark file origins (kept for display: "defined in /etc/nginx/conf.d/site.conf"). `include` directives are already expanded by `nginx -T`, so globbing is not implemented by Alice.
   - Build a tree: `main > http > server > location` (and `stream > server`, recorded as `unsupported: stream`).
   - Effective SSL directives for each `server` = directives in the server, falling back to values inherited from `http` when the server has none (`inherited=true` is shown in UI).
3. For each `server` with at least one `ssl_certificate`:
   - `server_name` list (first name is primary; `_` and empty become "(default server)"; regex names starting `~` are shown but not used for SNI probing).
   - `listen` entries: `[addr]:port`, `[::]:port`, `unix:` (ignored), flags `ssl`, `default_server`, `http2`. SSL ports = entries with `ssl` flag, or all entries if legacy `ssl on;` is set. Default when no listen: 80 (no SSL), so the server is skipped unless ssl is enabled explicitly.
   - Pairs each `ssl_certificate` with the `ssl_certificate_key` of the same index (nginx allows several of each, in order).
4. **Unsupported constructs** (recorded as location with `supported=false`, reason, and a warning in UI; they count as zero targets - only hosts count for license; not deployable):
   - Path contains a variable (`$ssl_server_name`, `$host`, `map`-derived): "Certificate path uses a variable, so Alice cannot know which file is used." (the raw directive text is shown).
   - `data:` values, `engine:` keys, `ssl_certificate_key` missing.
   - `ssl_password_file` present (key encrypted): unsupported in v1.
   - Relative path: resolved against the nginx prefix from `nginx -V` (`--prefix`), and then validated normally; if resolution fails -> unsupported.
   - Stream-block TLS.
   - Path outside the allowed roots and not referenced by nginx: not possible (referenced by nginx by definition); it is allowed because it is in `nginx -T`. Deployment to it is allowed, but the UI displays "custom location" so that operators notice.
5. For each supported certificate path: `stat` then `read-cert` (public certificate only). Parse with `crypto/x509`: subject, SANs, issuer, serial, `notBefore/notAfter`, key algorithm (RSA size / ECDSA curve), SHA-256 fingerprint, chain length in the file. **Key files are never read**; only `stat` on the key path (existence, mode, owner) is performed.
6. Deduplicate: identical (path) referenced by multiple servers becomes one `certificates` row with several `certificate_locations` (server_name + port), because one file deploys to all.
7. **ECDSA+RSA dual certs**: when a server has two `ssl_certificate` directives, Alice creates two locations distinguished by `key_type` (`rsa`/`ecdsa`). Deploys, bindings and verification are per key type.
8. Result diff against DB: new/changed/removed locations are audited; removed = marked `missing` (not deleted). A changed fingerprint that Alice did not deploy is shown as "changed outside Alice".
9. Sanity warnings: certificate expired, SAN mismatch with `server_name`, key file mode more permissive than 0640, key path not found, `nginx -t` failing at discovery time ("nginx configuration is currently invalid; deploying is disabled until fixed").

### 12.5 Concurrency

- One active operation per target: a `target_locks` row (advisory lock via `pg_advisory_lock(hash(target_id))` plus a `jobs.target_id` uniqueness for running operations of type `discovery|deploy|keyop|rotation_step`). A second job for the same target waits in the queue (not failed); UI shows "Waiting for another operation on this server".
- Different targets run in parallel; global SSH concurrency cap default 10 (setting `ssh.max_parallel`), so that a KV renewal bound to 200 hosts does not open 200 connections at once. Deploys for one binding are staggered (default 5 hosts at once) and, optionally, "stop the wave after N failures" (default 3) - remaining hosts are set to `skipped` and an alert is sent.
- Locks carry a lease (job heartbeat every 15 s; stale after 3 missed heartbeats). A crashed Alice process recovers jobs on start (12.6, "crash recovery").

### 12.6 Deploy state machine

Input: certificate version material (from KV or an uploaded/CSR-generated certificate), a location (or list of locations sharing the same file pair), `op_id` (UUID). States are persisted in `deployments.state` after each step (idempotent steps; each step's result and timing in `deployment_steps`).

```
QUEUED
  -> LOCKED            acquire target lock (12.5)
  -> PRECHECK
  -> BACKUP
  -> WRITE_KEY
  -> WRITE_CERT
  -> CONFIG_TEST
  -> RELOAD
  -> VERIFY
  -> CLEANUP
  -> SUCCEEDED
any failure after BACKUP starts -> ROLLBACK -> (ROLLED_BACK | ROLLBACK_FAILED)
failure before BACKUP -> FAILED (nothing changed)
```

Steps:

1. **PRECHECK**: connect; host key matches; helper protocol OK; re-run a fast discovery (`nginx-dump`) and confirm that the location's `ssl_certificate` / `ssl_certificate_key` paths are unchanged (if the config changed, abort "The nginx configuration changed since Alice last looked; run discovery again"); `nginx-test` must pass **before** touching anything (otherwise abort: "nginx already has a configuration error; Alice will not make it worse"); `stat` files: destination directory writable by root (always true via helper) and free disk space (> 10 MB, via `stat` in `nginx-dump`'s header `df` info); the new material is validated (key matches leaf, not expired, key type matches slot, warn on SAN mismatch); record fingerprint of the certificate currently served (TLS probe, for later comparison) and file sha256 of existing files.
2. **BACKUP**: `backup <cert path>`, `backup <key path>` under `op_id` (helper-side, root-only). Sha256 recorded. If a path does not exist yet (new location), rollback will delete instead of restore (`rollback_mode = remove` recorded, executed through `restore` with "absent" marker).
3. **WRITE_KEY**: `install-cert <key path> --kind key` (stdin). The key is written first and the certificate immediately after (ms apart); a mismatched pair would break a spontaneous nginx restart in either order, so the ordering only makes the failure case deterministic, and rollback restores both files.
4. **WRITE_CERT**: `install-cert <cert path> --kind cert` with the fullchain PEM.
5. **CONFIG_TEST**: `nginx-test` (`nginx -t`). Failure -> ROLLBACK.
6. **RELOAD**: `nginx-reload` (`nginx -t` again + `systemctl reload nginx` + `is-active`). Failure -> ROLLBACK. A reload never restarts nginx; existing connections are not dropped.
7. **VERIFY** (12.8). Failure -> ROLLBACK.
8. **CLEANUP**: `cleanup --op` (backup files are kept for 7 days by default, not deleted immediately, so an operator can restore later: setting `nginx.backup_retention_days`, default 7; the helper's own 30-day sweep is the hard cap). State -> SUCCEEDED, `certificates.deployed_version` updated, audit event, notification (optional).

**ROLLBACK**: `restore` key, `restore` cert (each in reverse order of writes, only for those already written), `nginx-test`, `nginx-reload`, verification that the **old** fingerprint is served again. Results: `ROLLED_BACK` (server is as before; job marked failed with the reason and "Your server was restored to its previous certificate") or `ROLLBACK_FAILED` (critical alert to admins: "Automatic restore failed. Files are in /var/lib/alice-helper/backups/<op>. Manual action needed"). If the SSH connection drops mid-deploy, Alice retries up to 5 times over 2 minutes to reconnect and finish the rollback. If the whole Alice process dies, on start any deployment in state between BACKUP and VERIFY is resumed at ROLLBACK (crash recovery), unless it had already reached VERIFY success (then it completes).

License lock: an in-flight deploy always completes or rolls back safely; no new scheduled/auto deploys start, and user-initiated deploys are refused with `license.locked`. Deploys held during lock are not started after renewal until an Admin confirms them.

(Phase 4, R38 items 7, 8, 13–15, 23–27: steps 2–6 and ROLLBACK run inside the helper as one `nginx-deploy` call with a journal in `/var/lib/alice-helper/backups/<deployment id>`; Alice sees the steps when the call returns. States are `queued`, `precheck`, `deploying`, `recovering`, `done`; statuses `pending`, `running`, `succeeded`, `unchanged`, `failed`, `rolled_back`, `rollback_failed`, `needs_attention`. Only a well-formed helper refusal means "nothing changed"; every other failure after the send is uncertain and goes to recovery (`certificate.deploy_recover`, ClassAlways), which reads the journal with `nginx-status` and verifies, finishes or rolls back; a journal reading `none` or `prepared` with no helper running means "nothing was written" only after `nginx-fence` (protocol 5) answered `fenced`, so a helper that starts late can never commit that operation, and only within 24 hours of the start record: later, the helper may have swept a journal of a change it made, and the deployment ends `rollback_failed` with `deployment.outcome_unknown`; the "5 reconnect attempts over 2 minutes" are replaced by a recovery 30 s later and then every 15 minutes, `needs_attention` after four attempts and `rollback_failed` with "outcome could not be confirmed" after 96. Only the latest operation of a pair can be restored (`SUPERSEDED`). A new location is never created, so rollback is always a restore. Step 8: Alice does not call `cleanup`; the helper's sweep removes an operation's backups 7 days after a `committed`, `unchanged`, `restored`, `prepared` or `fenced` journal (by the server's clock); 30 days after a `restore_failed` journal that `nginx-restore` can no longer act on, an unreadable journal, or a directory without a journal; never while the journal says `writing` or `restoring`, or `restore_failed` with the pair still restorable, unless a later operation superseded it (then after 30 days). There is no retry or rollback action on a deployment: deploy again, or deploy the earlier certificate.)

### 12.7 Auto-deploy trigger

The KV poller (11.6) enqueues `deploy` jobs with `trigger=kv_auto`, `binding_id`, `kv_version`. The job re-checks at start that the version is still current, the binding still has `auto_deploy = true`, and that license state is not LOCK (during GRACE everything works). Deployment windows (optional setting, default off): "only deploy between HH:MM and HH:MM"; outside the window jobs wait.

### 12.8 Post-deploy TLS verification

For each location bound to the deployed files, for each SSL `listen` entry of the server:
1. Choose SNI name: first non-wildcard, non-regex `server_name`; for wildcard `*.example.com` use `alice-check.example.com`; for default/`_` servers use the first SAN of the new certificate.
2. Connect address: the target's address (host/IP stored in the target) on the port from `listen` (`443` default for `listen 443 ssl`; e.g. `8443`). If `listen` has an address (not wildcard), that address is used when reachable, otherwise the target address.
3. Go `tls.Dial` with `ServerName = SNI`, `InsecureSkipVerify = true` (identity verification of the chain is **not** the purpose; Alice compares the served leaf) and then compares the **SHA-256 fingerprint** of the peer leaf to the expected new certificate. Up to 5 attempts, 2 s apart (reload is graceful; old workers may answer for a moment).
4. Dual certs: probe twice. RSA: restrict `CipherSuites` to `TLS_ECDHE_RSA_*`, `MaxVersion = TLS12`; ECDSA: `TLS_ECDHE_ECDSA_*` (TLS 1.2) or by offering only ECDSA signature schemes for TLS 1.3 (`tls.Config` `SupportedCurves` plus no RSA `signature_algorithms` is not possible in stdlib, so TLS 1.2 is used for the discriminating probe). Expected fingerprint per key type.
5. Also checks: chain includes intermediates as expected (number of certificates sent), `notAfter` matches.
6. If Alice cannot reach the port from its network (firewall), verification falls back to a local probe executed over the SSH session as the unprivileged service user: `openssl s_client -connect 127.0.0.1:<port> -servername <SNI> </dev/null` and `openssl x509 -noout -fingerprint -sha256`; this is recorded as `verified_locally`. If neither works the deploy is **rolled back** (unverifiable = unsafe) unless the admin ticked "Skip TLS verification for this location" (audited, Admin only).
7. Verification success requires all SSL listens of the server to present the new fingerprint (listens of other servers on the same port are handled by their own locations).

(Phase 4, R38 items 6 and 33: the local probe is the helper's own `tls-probe` (Go, without sudo, no `openssl`). Alice probes a listen itself only when it is on any address or on the address Alice connects to; a listen on another address, a loopback address or a host name (probed at 127.0.0.1) is checked by `tls-probe` alone. At most 10 endpoints, 5 attempts 2 s apart; a typed RSA or ECDSA probe is a second attempt when the served leaf differs. Item 5: the number of certificates served is compared (`deployment.verify_chain`); `notAfter` is not compared separately. Before any change a pre-check probes the certificate the website is known to serve and refuses with nothing changed when it cannot be confirmed; "Skip TLS verification" is the location setting `skip_verify` (Administrator, audited `location.updated`).)

### 12.9 Failure and edge cases

| Case | Behaviour |
|---|---|
| SSH unreachable / auth failed | Job `failed` before changes; target status `unreachable`; retry policy for auto jobs: 3 attempts, 5/15/60 min |
| Host key changed | All operations on that target blocked; critical alert; admin must review and re-confirm |
| `nginx -t` fails before start | Abort, no changes |
| sudo prompts for a password / not permitted | Message: "The Alice account on this server is not allowed to run the helper. Re-run the setup script." |
| Helper missing / wrong version | Same message with detail |
| Certificate file is a symlink (e.g. Let's Encrypt `live/`) | Written through to the resolved target; UI warns that another tool (certbot) may overwrite it |
| Two servers share one file pair | One deploy, verification for all sharing servers |
| Dest directory on read-only FS | helper error 4 -> FAILED before change (stage write fails) |
| Reload succeeds but wrong cert served (e.g. another server block matched) | Verification fails -> rollback |
| Nginx master process stopped | `nginx-test` passes, `is-active` fails -> rollback attempts, alert |
| Disk full during stage | staging file removed; no rename happened |
| Bound KV version rolled back in Azure | Alice deploys the version that is "current" at poll time |
| Same cert already deployed (fingerprint equal) | Job ends `SUCCEEDED (no change)`, no reload |
| Config changes between discovery and deploy | PRECHECK aborts |
| Clock difference | Not used in deploy; verification is fingerprint-based |

Explicit v1 limits: Alice never edits nginx configuration; it does not create new `ssl_certificate` directives; it does not manage `dhparam`, OCSP stapling files, or session ticket keys; no multi-host atomic rollout; no canary logic beyond the stop-after-N-failures rule.

---

## 13. Linux SSH Key Management

### 13.1 Scope and access

A `linux` target (and every `nginx` target) can be scanned for SSH authorized keys. Alice connects as `alice-svc` and uses the helper subcommands via sudo (12.3) because authorized_keys of other users are only readable/writable by root or the owner. The helper-based design keeps the sudoers minimal.

Helper subcommands used (profile `linux`):

| Subcommand | Behaviour |
|---|---|
| `sshd-dump` | runs `sshd -T -C user=<u>,host=<h>,addr=<a>` variants (see 13.2) and returns text |
| `authkeys-list [--user U]` | enumerates users from `getent passwd` with valid home dir and login shell (skips `nologin`, `false`, system UIDs < 1000 except root), returns for each the candidate authorized_keys paths after expanding `%h`, `%u`, `%U` tokens from `AuthorizedKeysFile`; reports file existence, size, sha256, mtime, mode, owner |
| `authkeys-read <path>` | validates path (13.3); outputs the file text |
| `authkeys-write <path> --expect-sha256 <H> --content-sha256 <C> --op <opid>` | stdin = new full file content; if sha256(stdin) != C, refuse (code 3, `CONTENT_MISMATCH`: the content arrived incomplete, Phase 3 protocol 3); if current sha256 != H, refuse (code 3, someone changed the file); backup; atomic replace preserving mode/owner/SELinux; returns new sha256 |
| `hostkeys` | fingerprints of host keys (as 12.3) |

### 13.2 sshd_config reading

`sshd-dump` runs `sshd -T` (needs root to read all host key paths), effective values are parsed for:
- `authorizedkeysfile` (default `.ssh/authorized_keys .ssh/authorized_keys2`; tokens `%h %u %U %%`), relative paths are relative to the user's home.
- `authorizedkeyscommand` and `authorizedkeyscommanduser`: if set to anything other than `none`, then keys may come from an external source; host status is **"keys managed elsewhere"**: Alice still lists file keys, but add/remove/rotate is disabled for this host with the message "This server gets its SSH keys from a program (AuthorizedKeysCommand), so Alice will not change keys here." (decision: warn/skip).
- `pubkeyauthentication` (if `no`: warn "public key login is disabled"), `permitrootlogin`, `passwordauthentication`, `allowusers`, `allowgroups`, `denyusers`, `denygroups`, `authorizedprincipalsfile`/`trustedusercakeys` (certificate-based auth: info banner "SSH certificates are in use; Alice manages plain keys only"), `strictmodes`, `hostkey` list and `hostkeyalgorithms`, `port`, `match` blocks: `sshd -T` prints the global values only, so per-user overrides are obtained with `sshd -T -C user=<u>,host=localhost,addr=127.0.0.1` for each scanned user (batched, max 200 users, then only users with keys found).
- `Include` files are honoured natively by `sshd -T`. If `sshd -T` fails, Alice falls back to the default AuthorizedKeysFile and shows a warning "Could not read SSH server settings; only default key files were checked."

### 13.3 authorized_keys discovery and parsing

1. For each candidate path (from `authkeys-list`; roots: `/root`, `/home/*`, homes from passwd, plus custom paths from `AuthorizedKeysFile`): `authkeys-read`.
2. Path validation in the helper for `authkeys-*`: the path must equal one of the candidate paths computed by the helper itself from passwd + sshd config (not a caller-supplied arbitrary path); must be a regular file (or a not-yet-existing file in an existing `.ssh` directory) owned by that user or root; resolved symlinks may not leave the user's home (or the configured directory); the `.ssh` directory and home may not be group/world writable (mirrors sshd StrictModes; otherwise Alice warns "sshd itself would ignore this file").
3. Parsing (each non-empty non-comment line):
   - Format: `[options] keytype base64 [comment]`. The parser uses `golang.org/x/crypto/ssh.ParseAuthorizedKey`, which handles quoted option values and returns the option list; the raw line is kept verbatim for byte-exact rewriting.
   - Options captured: `from=`, `command=`, `environment=`, `no-*`, `restrict`, `cert-authority`, `principals=`, `expiry-time=`, `permitopen=`, `permitlisten=`, `tunnel=`.
   - Key info: type, size (RSA) or curve, SHA-256 fingerprint (`SHA256:...`), comment (free text, often `user@host`), whether it is `sk-` (FIDO) type, weak flag (RSA < 2048, DSA), `cert-authority` lines flagged and never managed.
   - Unparseable lines are preserved and shown as "unreadable line n"; they are never removed or altered.
4. Each key becomes/updates an `ssh_key_locations` row: (server, OS user, file path, line number, fingerprint, options JSON, first seen, last seen). Keys with the same fingerprint on several hosts map to one `ssh_keys` row. `managed=true` only if the fingerprint matches a key generated/imported by Alice.
5. Dangerous findings are flagged: keys without `from=` for root, `command=` present (shown, stays untouched), duplicate keys, keys older than policy (unknown age: not shown), weak keys, orphan files for deleted users.
6. Discovery runs on target add, on demand, and daily by default; disabled in license lock.

Host key inventory: from `hostkeys` (fingerprints of `/etc/ssh/ssh_host_*_key.pub`), stored per target with type and first/last seen. Alice compares them against the pinned host key of the SSH connection: a difference blocks operations (section decisions); the inventory is informational for other host keys (e.g. RSA key exists, ECDSA missing) and flags DSA/1024-bit RSA host keys.

### 13.4 Add / remove key algorithm

Common procedure (`keyop` job, locked per target as 12.5; in license lock, user-initiated add/remove is refused with `license.locked`):
1. PRECHECK: connection ok; helper version ok; host status not "keys managed elsewhere"; user exists and its authorized_keys path chosen (default first entry of `AuthorizedKeysFile` that expands to inside home; the user can choose if several).
2. READ: `authkeys-read` returns content C0; compute `H0 = sha256(C0)`.
3. Transform in memory:
   - **Add**: if the fingerprint already exists in the file: no change ("already present"). Else append (ensuring the file ends with a newline first) the line `[options ]<type> <base64> <comment>`; options from the request (`from=`, `restrict`, `command=`); comment default `alice:<key-name>:<yyyy-mm-dd>` (newlines and control characters in comments rejected).
   - **Remove**: remove only lines whose parsed key fingerprint equals the target fingerprint (and, when several identical lines exist, all of them); unparseable and comment lines are never touched.
   - **Protection**: refuse if the removed fingerprint equals Alice's own connection key **for the `alice-svc` account** (checked by fingerprint, not by comment), returning "Alice needs this key to connect to this server and will not remove it." The check also refuses when the key is Alice's own key in *any* file, and refuses to remove the last remaining key of the account Alice is currently authenticating as. Removal is also refused if it would leave the target user with zero keys and the user is root (warning with explicit admin confirmation only).
4. WRITE: `authkeys-write <path> --expect-sha256 H0 --content-sha256 H1 --op <id>` with the new content (H1 = its SHA-256; the helper writes nothing when stdin does not hash to H1). Helper: re-read and compare hash under an `flock` on the file's directory lock file (`.alice.lock` not created; uses `flock(2)` on the open file descriptor); backup of the previous content to `/var/lib/alice-helper/backups/<op>/`; write temp file `<dir>/.authorized_keys.alice-<rand>` (O_EXCL, mode 0600 initially), `fchown` to the original owner/group, `fchmod` to the original mode (default 0600 if new), copy SELinux label (`restorecon -F` if available, otherwise copy `security.selinux` xattr from the original), fsync, rename, fsync directory. New file creation (user had none): create `.ssh` (0700, user-owned) if missing.
5. VERIFY: `authkeys-read` again and compare sha256 with the expected new content. Then, where possible, **test login** (below). Failure -> restore from backup via `restore` semantic (`authkeys-write --expect-sha256 <new>` of old content), verify again.
6. Update DB (`ssh_key_locations`), audit, notify (optional).

(Phase 3, R37 item 22: the write lock is a root-private file `/var/lib/alice-helper/locks/<dev>-<ino>.lock`, not `flock` on the key directory; a new file in a root-owned key directory is created root:root 0644; a failed VERIFY is not restored automatically but stops the job for a person with the backup named, until Phase 4 adds the restore primitive.)

Optimistic concurrency: if `authkeys-write` returns hash mismatch (someone edited the file meanwhile), Alice re-reads and retries the transformation up to 3 times, then fails with "The file changed while Alice was working. Please try again."

Test login (only for **Add**): Alice opens a new SSH connection to `host:port` as the target OS user with the *new private key* (when Alice holds it, i.e. platform-generated keys), executing `true`, with `IdentitiesOnly`-equivalent behaviour (only that key offered), verifying host key against pin, timeout 10 s. Not possible when: Alice does not have the private key (imported public key only), the account has no shell (`nologin`, `command=` forces a different command, then only authentication success counts and exit status is ignored), `AllowUsers` / `from=` excludes Alice's IP, or the port is blocked. In these cases the key op result is `applied, not verified` (shown with a yellow icon) and rotation logic refuses to proceed to old-key removal without admin confirmation (13.6). Removal is verified by a login attempt with the removed key expected to fail, when Alice holds that key (informational, not blocking).

### 13.5 Where private keys live and how consumers retrieve them

- Keys generated by Alice (Ed25519 default; RSA 3072/4096 and ECDSA P-256 selectable) have their private key stored in the Alice encrypted store (`secrets` module: per-key random DEK, AES-256-GCM, DEK wrapped by master key). The public key and fingerprint are in `ssh_keys`. Private keys are never on the target servers, never in logs or API list/detail responses.
- Optional passphrase for the downloaded key: the admin may choose a passphrase at download time; Alice encrypts the OpenSSH private key (bcrypt-KDF format) on the fly. The stored version stays under the master-key envelope.
- Retrieval by consumers (people or CI): **only** through the explicit "Download private key" action of an Admin: mandatory free-text reason, MFA re-prompt (step-up), audit event with reason; file returned once over HTTPS with `Cache-Control: no-store`. There is no API-token retrieval in v1 (an API token cannot satisfy the MFA re-prompt). After a rotation the notification e-mail lists the key name and states that a new private key is available to be downloaded by an Admin and that the old key remains valid until the overlap ends, which gives consumers time to fetch the new key.
- Keys discovered on servers (not generated by Alice) are inventory only: Alice has no private key; they can be removed from servers by Operators/Admins but not rotated.
- Alice's own connection key (generated at install) is stored the same way, excluded from download and rotation in v1 (a UI note explains; replacing it is a manual documented procedure).

### 13.6 Rotation state machine

Scope: only platform-managed keys (Alice holds the private key), with an enabled rotation policy (disabled by default, Admin only). Policy fields: schedule (interval in days or cron-like weekday/time), `overlap_days` (default 7), `notify_before_hours` (default 24), key type/size for the new key, locations (all current locations of the key or a subset), `require_verification` (default true), `remove_old` (default true).

```
SCHEDULED
  -> PREVIEWED       dry-run computed and stored; notification sent to admins (recipients in settings)
  -> GENERATING      after notify_before_hours (skipped if admin clicks "Run now")
  -> ADDING          new key added to each location (13.4), per-location state
  -> VERIFYING       test login per location with the new key
  -> OVERLAP         both keys valid; timer overlap_days
  -> REMOVING        pre-check that the new key still works everywhere; remove old key per location
  -> COMPLETED
failures: ADDING_FAILED | VERIFY_FAILED | REMOVE_PARTIAL -> ROLLED_BACK_NEW | NEEDS_ATTENTION
```

Details:
1. **Dry-run preview** (always before each run, and available on demand): lists hosts, users, files, the exact lines to be added/removed (public parts only), hosts that will be skipped and why (`AuthorizedKeysCommand`, unreachable, "keys managed elsewhere", host key changed), and the planned dates. The scheduled run starts only after the preview notification was sent.
2. **GENERATING**: new key pair generated, stored encrypted as a new `ssh_keys` row linked to the old (`rotated_from`), comment `alice:<name>:<date>`; options (`from=`, etc.) copied from the old lines per location.
3. **ADDING**: performed with 13.4 for each location, in parallel across hosts within the concurrency caps. If any location fails to add: the run stops adding; already-added new keys are removed again (`ROLLED_BACK_NEW`); old key untouched; alert. Result `NEEDS_ATTENTION` if the rollback also fails on some host (listing where the new key remains, which is harmless since it is unused but must be cleaned).
4. **VERIFYING**: test login with the new key for each location. Locations that cannot be verified technically (13.4) are `unverifiable`; if `require_verification` and any location failed verification -> `VERIFY_FAILED`: new key removed everywhere (rollback), old key stays, alert. If some are only `unverifiable`, the rotation pauses in `VERIFYING` awaiting an Admin decision ("Confirm the new key works on these hosts"), up to 14 days, then it is rolled back automatically. Old keys are **never** removed by an incomplete rotation.
5. **OVERLAP**: `overlap_until = verified_at + overlap_days`. The old key remains in authorized_keys. The admin can shorten ("Finish now") or extend. Notification at start with instructions to download the new key (13.5) and at 1 day before end.
6. **REMOVING**: before any removal, re-check that the new key is still present and works for each location (fresh test login). Per location: remove old key. Locations where the new key check fails keep the old key and the rotation ends `NEEDS_ATTENTION` (never a partial state without an alert). Successful locations: old `ssh_key_locations` marked `removed`; the old key record goes to `retired` (private key retained encrypted for 30 days for emergencies, then destroyed on schedule; configurable: keep/destroy). Then `COMPLETED`, new key is now the managed key.
7. **Idempotency and crash recovery**: each transition and each per-location result is persisted in `rotations` / `rotation_steps` (with the backup op ids); after an Alice restart the job resumes at the last persisted state; add/remove steps are idempotent by fingerprint.
8. **Never remove the old key** when: the run is not `VERIFIED`, when license is in LOCK, when host key changed, or when the removed fingerprint is Alice's own key.
9. **License lock**: scheduled rotations stop being created; a rotation in `ADDING`/`VERIFYING` finishes its current in-flight host operation and then pauses (`PAUSED_LICENSE`) with the old key untouched (the new key is not removed either, since the old-key guarantee is the priority). A rotation in `OVERLAP` keeps waiting; when the overlap ends during lock, it stays in `OVERLAP` (state shown as "waiting for license"), and no removal occurs. When a valid license is uploaded, recurring read-only jobs resume automatically but the pending REMOVING step does not start on its own: it needs Admin confirmation, then re-verifies the new key on every location and sends a fresh dry-run notice first; the overlap effectively extends. Timers do not fire during lock.
10. Rotation policies are per key; a rotation is one `rotations` record with steps; audit events for every state change.

(Phase 6, R41: as built, the states are the run statuses `dry_run_notified`, `adding_new`, `verifying_new`, `overlap`, `removing_old`, `completed`, `rolling_back`, `aborted`, `needs_attention`, `cancelled` with `paused_license` as a flag, and per-place states in `rotation_locations`; the policy has no schedule other than `interval_days`, no `require_verification`, no `remove_old` and no subset of places; a scheduled run starts only after its preview email was delivered by the planned start; places Alice cannot test are kept or the run is stopped, never "confirmed"; files holding several places of the key are skipped; the test login is an authentication only; in a lock a started run pauses at the first sweep, its overlap timer stops and resumes after **Continue** with the remaining time, and only **Stop and undo** is possible; migration `00010` enforces the state machine and the old-key rule of item 8 in the database. R41 items 9–33 and 34–66 give each rule.)

### 13.7 Explicit v1 limits

- Plain public keys in `authorized_keys` only; no OpenSSH certificates, principals, `AuthorizedKeysCommand`, LDAP-sourced keys, or `authorized_keys` in non-standard home mounts that the helper cannot resolve.
- Rotation only for platform-generated keys; imported/discovered keys are inventory or manual add/remove.
- No password changes, no user creation/deletion, no sudoers management on hosts.
- No agent on hosts; scanning is pull-based over SSH.
- Test login is best-effort; unverifiable locations require an admin decision.
- No API-token download of private keys.
- No Windows or macOS targets.
