# Troubleshooting

Every error returned by the Alice API carries a stable code in the form `ALC-<AREA>-<NNNN>`. Quote the code and the `request_id` when asking for help.

## Cannot sign in

- **"Incorrect username or password." although the password is right.** After 5 wrong attempts Alice makes the
  account wait a few seconds; after 10 it blocks the account for 15 minutes. Wait 15 minutes and try again: when a
  block ends the count starts again, so the right password is accepted at once and someone who keeps guessing gets at
  most 10 attempts per 15 minutes. An administrator can see `auth.lockout`
  in the audit log, and **Set a new password** on **People & access** lifts the block at once. If you are the only
  administrator, the server operator runs `alice admin unlock <username>` ([operator-guide.md](operator-guide.md));
  `alice admin reset-mfa` does not end a block.
- **Lost the phone with the authenticator app.** Choose **Use a recovery code** on the sign-in page. Without
  recovery codes, ask an administrator to reset your MFA (**People & access**). If you are the only administrator, the
  server operator runs `alice admin reset-mfa <username>` ([operator-guide.md](operator-guide.md)).
- **"Your session ended. Please sign in again."** Sessions end after 30 minutes without activity and always after
  12 hours. Pages that refresh themselves do not count as activity; clicking, typing, scrolling with the wheel or
  touching the page does (see [admin-guide.md](admin-guide.md#staying-signed-in)). Sign in again.
- **Alice does not start on a new installation: "no installation in the database and the time record file cannot be
  read".** The state volume (`/opt/alice/state`) or its `hwm.dat` cannot be read by user 10001, so Alice cannot tell
  whether an installation existed before; it creates nothing. Fix the volume's owner and permissions and start again.
- **Alice does not start on a new installation: "sync keys directory <directory>: …" or "sync parent of keys
  directory <directory>: …".** The file system refused to make the new master key's directory entry durable
  (`fsync` on the keys directory, or on its parent when Alice had just created the keys directory). Alice keeps the
  key file. After the first message the next start tries the sync of the keys directory again; after the second it
  does not repeat the parent's sync (run `sync` on the host once). On a file system that never allows a directory
  sync, put the keys volume on an ordinary local file system (ext4, XFS).
- **The setup wizard says the setup code is wrong or the session expired.** Create a new code with
  `alice setup-token --reset` (development: `make setup-token`). After five wrong codes the wizard waits
  15 minutes (`ALC-SET-0002`). Once an administrator exists the wizard no longer accepts codes: sign in instead.
- **Alice does not start: "the master key file is missing" / "does not match this database".** See
  [operator-guide.md](operator-guide.md#master-key).
- **Alice does not start: "the database server … rejected the user name or password".** The database password in
  the configuration is wrong, or (development) a Phase 0 database volume lacks the new `alice_app` role: run
  `make reset`.

## Servers and SSH keys

- **"Connecting to the server…" ends with "Cannot be reached".** Check the address and port, that the server's SSH
  service runs, and that a firewall lets the Alice server through (`ALC-SSH-0001`, `ALC-SSH-0003`). Then choose
  **Test connection** on the server's page. Alice also tests a server that cannot be reached once per discovery
  interval on its own and scans it as soon as the test succeeds; becoming unreachable and a failed scheduled re-test
  send no email of their own (the server is shown on **Servers** and in the audit log), but a scan or a **Test
  connection** you started that fails on its last attempt sends the usual email about a stopped task. A new server whose fingerprint
  is not confirmed yet is not tested on its own.
- **"Sign-in refused" (`ALC-SSH-0002`).** The server does not accept Alice's key for the user you entered. Run the
  setup commands again (they put the key in `/var/lib/alice-svc/.ssh/authorized_keys`), check that the user
  name is `alice-svc`, then choose **Test connection**. Alice does not try a server with a refused key again on its
  own, so the server never locks the account because of Alice.
- **"The Alice account on this server is not allowed to run the helper" (`ALC-SSH-0004`) or "The alice-helper on
  this server is outdated" (`ALC-SSH-0005`).** Copy the `alice-helper` file of this Alice version next to the
  commands from **Servers → Prepare a server for Alice** and run them again as root; they install the helper and the
  sudoers file. Next time, update the helpers before Alice: a new helper works with the previous Alice.
- **The setup commands stop with "./alice-helper is not the alice-helper of this Alice version".** The file's
  checksum differs from the one built into Alice. Copy `alice-helper-linux-amd64` (x86_64) or
  `alice-helper-linux-arm64` (aarch64) built by `make helper` from the same Alice version, renamed to
  `alice-helper`.
- **Server identity changed (`ALC-TGT-0004`).** See [nginx-host-preparation.md](nginx-host-preparation.md#when-the-server-is-rebuilt).
  Never accept a new fingerprint you have not compared on the server itself. If the server shows its previous
  fingerprint again, choose **Review the new fingerprint** and **The server still shows the previous fingerprint**.
- **A key of a deleted account is still listed as found.** Alice marks the keys of a deleted account **No longer
  found** only when the server's account list is complete (no warning about accounts Alice did not list, no
  directory-service or systemd accounts, not more accounts than Alice lists), and keeps the keys of an account that
  got a `nologin` shell or lost its home as last seen; see
  [operator-guide.md](operator-guide.md#keys-of-accounts-alice-no-longer-lists).
- **"Alice did not list the SSH keys of the account with user ID N".** The account's name, its user or group ID, or
  its home directory in `/etc/passwd` is outside what Alice supports (the warning says which). Run
  `getent passwd N` on the server to find the account; rename it, write its user and group ID as plain numbers below
  4294967295 (without `+` or `-`), or give it a plain absolute home directory, then choose **Scan for SSH keys**. Until then the server's account list is incomplete.
- **"The file /etc/passwd on this server contains a NUL byte".** Remove the NUL byte (as root, for example with
  `vipw`); Alice reads each line only up to it, as the system does.
- **"Accounts from a directory service (for example LDAP or SSSD), from systemd user records or from a source Alice
  cannot check are not listed."** The `passwd:` line of `/etc/nsswitch.conf` names a source other than `files`,
  `systemd` or `mymachines`; or the server has systemd user records or systemd-homed accounts; or
  `/etc/nsswitch.conf` is missing, larger than 64 KiB, or not a plain file of root's that only root can change. The
  warning stays as long as that is so.
- **"This server gets its SSH keys from a program" (`ALC-SSH-0008`).** The server uses `AuthorizedKeysCommand`;
  Alice lists keys but does not change them there.
- **A key removal says "The file changed while Alice was working" (`ALC-SSH-0007`).** Someone or something edited
  the file at the same moment; Alice changed nothing. Try again.
- **A key removal says "Alice could not read the SSH server settings" (`ALC-KEY-0004`).** Run `sshd -T` as root on
  the server, fix what it reports, choose **Scan for SSH keys**, then try again.
- **"Alice needs this key to connect to this server and will not remove it." (`ALC-KEY-0001`).** This is Alice's
  own key; it is protected on purpose.

## SSH key rotation

- **Deploy offers no file, or a deploy is refused with `ALC-KEY-0014`.** Alice offers only files it knows the account it
  connects with does not read. Choose **Scan for SSH keys** on the server's page (on an Nginx server, **Discover**), then open the deploy dialog again.
- **A scheduled rotation was cancelled with `ALC-ROT-0017`.** A scheduled run starts only after its preview email was
  delivered to an administrator before the planned start. Check the email settings; **Run now** does not wait for an email.
- **Every server refuses deploys after the upgrade, and every place is skipped with `connection_files_unknown`.** Servers
  last scanned before this version have no list of the key files of the account Alice connects with. Choose **Scan for
  SSH keys** on each server's page (on an Nginx server, **Discover**), or wait for its next scan: Alice scans each
  connected server once per discovery interval (one day unless it was changed).
- **A rotation stays paused (`ALC-ROT-0011`).** Nothing is added or removed while the license does not allow changes; the
  overlap's time stops. After a renewal, Alice emails the administrators within about a minute; then choose **Continue** on
  the rotation's page (until then Continue answers `ALC-ROT-0021`). **Stop and undo** works while paused, also in lock: it
  removes the new key where Alice added it.
- **The old key is still on some servers after a finished rotation.** A rotation never removes the old key where the new key
  was not checked just before the removal. The run's page shows these places; the "kept" count says how many there are.
- **A rotation "Needs attention".** Either the old key could not be removed on some servers (`ALC-ROT-0009`: both keys
  work there), or undoing the rotation could not remove the new key everywhere (`ALC-ROT-0008`). The run's page and the
  email name the servers. Alice does not touch those places again for this run; fix the cause, scan the servers, and remove
  the key you no longer want on its page once the other key works. After `ALC-ROT-0009` the policy still belongs to the old
  key: create a policy for the new key if it should be rotated too.
- **A scheduled rotation never starts and nothing is emailed.** If the key has more places than one run can hold
  (`ALC-ROT-0019`), the scheduled planning fails at every check and only Alice's log says so. **Run now** answers with
  the code; split the key's places among several keys.
- **A deploy says the key was added but not tested.** Alice could not prove a login: the line has `from=` and may exclude
  Alice's address, the server let Alice in without asking for the key, or Alice could not connect for the test. The line
  stays; check the login yourself.
- **Why a place is skipped in a preview.** Each skipped place names its reason:
  - **The server was removed from Alice** (`target_deleted`). Nothing: the server is no longer managed by Alice.
  - **The server's fingerprint is not confirmed yet** (`host_key_unconfirmed`). Confirm the server's fingerprint on its page.
  - **The server's identity changed** (`host_key_changed`). Review the new fingerprint on the server's page (`ALC-TGT-0004`).
  - **Alice cannot connect to the server right now** (`target_not_connected`). Fix the connection, choose **Test connection**, then preview again.
  - **The server gets this user's keys from a program** (`keys_managed_elsewhere`). Change the key in the program that serves the keys (`AuthorizedKeysCommand`).
  - **Alice could not read the SSH server settings** (`sshd_unreadable`). Run `sshd -T` as root, fix what it reports, then scan the server again (`ALC-KEY-0004`).
  - **This is the account Alice connects with** (`connection_account`). Nothing: the setup commands own that account's key file.
  - **The key was no longer found here** (`missing`). Scan the server again; Alice rotates only keys it found.
  - **This line is a certificate authority** (`cert_authority`). Replace a `cert-authority` line by hand; Alice only lists such lines.
  - **Several users of this server read this file, so Alice does not change the key in it** (`shared_file_skipped`). Give each user a key file of their own (`AuthorizedKeysFile` with `%h` or `%u`), scan again, then preview again.
  - **The SSH server does not accept keys** (`pubkey_disabled`). Nothing, unless the server should accept keys (`PubkeyAuthentication`).
  - **root may sign in here only with a fixed command, and this line has none** (`root_forced_commands_only`). Add the forced `command=` to the line, or change `PermitRootLogin`, then scan again.
  - **The key is listed more than once in this file** (`duplicate_lines`). Remove the extra lines of the key from the file by hand (the SSH server uses the first), then scan again.
  - **Alice does not know all key files of the account it connects with on this server; scan the server again** (`connection_files_unknown`). Choose **Scan for SSH keys** on the server's page (on an Nginx server, **Discover**), then preview again (`ALC-KEY-0014`).
  - **This place belongs to the account Alice connects with or to one of its files; Alice never changes those** (`connection_account_file`). Nothing: the setup commands own those files (`ALC-KEY-0017`).
  - **Alice could not read this line's options exactly** (`options_unreadable`). Check the line's options on the server (they are not valid UTF-8), fix them, then scan again.
  - **This line's options are longer than Alice stores, so Alice cannot copy them to the new key** (`options_truncated`). The line's option list is longer than 4 KiB (4095 bytes). Shorten it on the server (for example move long `environment=` values into the forced command's own configuration), scan again, then preview again; or rotate the key at that place by hand.

## Certificates

- **An upload is refused.** The message says why and nothing is stored; the codes are listed below
  (`ALC-CRT-0001`…`ALC-CRT-0015`). Common cases: the key belongs to another certificate (`ALC-CRT-0002`; use the key
  created with this certificate), the key has a password (`ALC-CRT-0004`; remove it with
  `openssl pkey -in protected.key -out plain.key`, or upload a PFX file with its password), the certificate has
  expired (`ALC-CRT-0003`), or a weak key or SHA-1 signature (`ALC-CRT-0006`).
- **"Alice already has this certificate with its key" (`ALC-CRT-0008`) right after an upload that seemed to fail.**
  The first upload reached Alice but its answer was lost. The certificate is in the list; deploy it from there.
- **"Alice is busy reading other PFX files" (`ALC-CRT-0015`).** Alice reads at most two PFX files at a time. Wait a
  moment and upload again. If it keeps happening, someone may be uploading PFX files that take very long to open;
  check the audit log for `certificate.upload_rejected` and `certificate.uploaded`, and restart Alice if needed.
- **"The chain is incomplete" after an upload.** Add the intermediate certificates your certificate authority sent
  (in any order) and upload again, or let an administrator deploy it with a confirmation
  ([admin-guide.md](admin-guide.md#incomplete-chains)).
- **The certificate list says "Not in Alice" in the Private key column.** Alice found this certificate on a server and
  never reads private keys from servers. Upload the certificate with its key to deploy it elsewhere.
- **A signing request's certificate is refused (`ALC-CRT-0013`).** It was not issued for this request's key: paste the
  certificate your certificate authority returned for exactly this request.

## Deployments

- **"Deploying is unavailable for now." on a server's websites.** The reason is shown under it: the server is not
  connected (see its status), the Nginx permissions are not installed (`ALC-NGX-0004`: run the setup commands with
  **Server type** **Nginx server** again), Nginx was not found (`ALC-NGX-0001`), Nginx's configuration has an error
  (`ALC-NGX-0002`: run `nginx -t` on the server), or the last scan failed. Fix it, then choose **Discover**.
- **A website is "Not supported".** The row says why. The cases and what to change are in
  [nginx-host-preparation.md](nginx-host-preparation.md#configurations-alice-cannot-manage). After a change on the
  server, choose **Discover**.
- **"Alice cannot trust Nginx's output for this configuration" or "Alice cannot read this configuration safely".**
  Alice refuses the whole server and names the reason and, where it can, the file with the problem. Usual causes: a
  configuration file or folder that users other than root can change (`chmod go-w` on it, owner root), an `include`
  written with `..` (write the path without `..`), a configuration file name with a space, or a comment in a real
  configuration file that starts with `# configuration file`. Then choose **Discover**.
- **"A configuration file of this website can be changed by users other than root."** The website is not supported
  until the file and its folders belong to root and are not writable by group or others. This is on purpose: whoever
  can edit that file could otherwise make Alice write a key to a file of their choosing.
- **The check before the deployment fails with "Alice could not reach the website on port N" (`ALC-DEP-0005`).**
  Nothing was changed. Check that the website answers on that port from the Alice server or, failing that, on the
  server itself (`curl -kv https://127.0.0.1:<port>/`). If the website's `listen` names a host name (for example
  `listen www.example.com:443 ssl;`) that resolves to an address other than 127.0.0.1, Alice cannot check it from
  either side, although the message suggests a firewall: change the `listen` to an IP address or to `listen 443 ssl;`,
  or ask an administrator to turn off the check for that website (**Verification settings**, not recommended).
- **The check before the deployment fails with "Alice could not confirm which certificate the website serves"
  (`ALC-DEP-0004`).** Nothing was changed. The website served a certificate Alice did not expect: a load balancer or
  proxy in front of it (an administrator can set the port and name to check in **Verification settings**), the
  certificate changed since the last scan (choose **Discover**), or another `server` block listens on the server's
  own address and port and answers for this name (Nginx prefers a `listen` with an explicit address; give both blocks
  the same kind of `listen`).
- **"The website serves the expected certificate with a different chain (port N)." (`ALC-DEP-0012`).** The number of certificates
  the website sends differs from the uploaded chain. Check that the website's `ssl_certificate` file is the one Alice
  replaced and that no proxy changes the chain.
- **A deployment shows "Confirming the outcome" or "Needs attention".** Alice did not get a clear answer from the
  server and is finding out how the change ended (see
  [operator-guide.md](operator-guide.md#interrupted-deployments)). The server is usually unreachable: check its
  status and its network. The deployment then shows `ALC-DEP-0010` while the latest recovery attempt shows the
  connection error (`ALC-SSH-0001` or `ALC-SSH-0003`); the same lost connection can appear under either code.
  Nothing needs to be done once the server is back.
- **A deployment ended "Outcome not confirmed".** Alice cannot vouch for what the website serves now. Check it:
  `openssl s_client -connect <server>:443 -servername <website> </dev/null | openssl x509 -noout -fingerprint -sha256`
  shows the served certificate's fingerprint; compare it with **Previous certificate** and **New certificate** on the
  deployment's page. On the server, compare the files with the backup in
  `/var/lib/alice-helper/backups/<deployment ID>` (`sha256sum`), restore by hand if needed
  ([nginx-host-preparation.md](nginx-host-preparation.md#restoring-a-previous-certificate-by-hand)), run `nginx -t` and
  `systemctl reload nginx`, then choose **Discover**. The error code tells which case it is (`ALC-DEP-0008`, `0014`,
  `0017`, `0018`, `0019`, `0020`).

  Do **not** restore the backup after `ALC-DEP-0014` (a later deployment replaced the files: restoring would put
  back a key that the later deployment replaced) or after `ALC-DEP-0020` (another program, for example certbot,
  changed the certificate or key file while Alice was deploying or putting the previous files back: Alice put back
  at most the files it had written itself and left the other program's file, so restoring would overwrite that
  file). After `ALC-DEP-0020` the certificate and key on the server may not belong together: run `nginx -t` on the
  server at once; if it fails, let the other program write a matching pair again (for certbot, renew the
  certificate) or deploy the intended certificate from Alice. In both cases find out which certificate is meant to
  be there and deploy it, or leave the files to the other program. Restore by hand only when the files on the server
  still hold what this deployment wrote (`sha256sum` of the certificate file equals `new_cert_sha256` in the
  folder's `journal.json`) and the website is broken.
- **"The previous files are back, but the website was not confirmed." (`ALC-DEP-0019`) although the website looks right.** This
  happens when another `server` block answers on the server's own address and port: Alice's check reaches that
  block instead. Check the website in a browser and see the previous point.
- **"Alice is still finishing an earlier deployment on this server" (`ALC-DEP-0002`).** Wait until that deployment
  shows a result in **Deployments**; at most about a day when the server stays unreachable.
- **"The certificate file changed since Alice last looked" (`ALC-NGX-0006`).** Another tool (for example certbot)
  replaced the file. Decide which tool manages this website; choose **Discover** before deploying again.
- **"The server does not have enough free disk space." (`ALC-NGX-0005`).** The server needs room for the new files, their backups and 10 MiB
  more. The same answer comes when the helper already keeps 1000 deployment backups: old ones are removed
  automatically after 7 days.
- **"Another certificate change is running on this server" (`ALC-NGX-0008`).** The helper changes one website at a
  time on a server. Wait a minute and try again.
- **"The certificate file contains a block that is not a certificate. Alice ignored it."** A certificate file holds a
  block that Alice cannot read as a certificate. The note does not name the file: check the files of the server's
  websites with `openssl crl2pkcs7 -nocrl -certfile <file> | openssl pkcs7 -print_certs -noout`. If it was the first
  block of a file, that website is **Not supported** with "The first certificate in the file cannot be read, so Alice
  does not know which certificate this website serves." (`leaf_unreadable`): replace the certificate (for example one
  with a negative serial number, which Nginx loads but Alice cannot read) and choose **Discover**. A server whose
  `alice-helper` is older than 1.6.1 instead shows the next certificate of that file, usually the intermediate.
- **"These websites may be out of date".** The last scan could not read the websites (the reason is shown); the list
  is the one Alice read at the time shown. Fix the reason and choose **Discover**.
- **A website shows "The certificate changed outside Alice."** Its file holds a certificate Alice did not deploy (for
  example renewed by certbot, or restored by hand). Expected after a manual change; otherwise find out which program
  changed it.
- **A website's warning says Alice could not order the certificates of its file** (warning code `chain_unresolved`).
  The certificate file holds many certificates with the same name that could each have issued the others; Alice
  stops after 100 signature checks per file, keeps only the website's own certificate and counts its chain as
  incomplete. The website still works as before. Put only the certificate and its real chain in the file (for
  example certbot's `fullchain.pem`) and choose **Discover**.
- **The website list or the certificate files are incomplete on a very large server** ("This server has more
  websites than Alice lists", "This server uses more certificate files than Alice lists", or `ALC-SSH-0009`). Alice
  reads at most 1000 certificate files and 16 MiB of website summary per server; such servers are not fully managed
  in this release.

## Key Vault

How to give Alice access to a vault (identity, roles, network) is in [azure-setup.md](azure-setup.md); using a vault
in Alice is in [operator-guide.md](operator-guide.md#key-vaults).

- **A vault shows "Partly working", "Credentials refused" or "Cannot reach Azure".** Open the vault and read the
  **Access check**: each row says what Alice may do and, for a missing permission, which Azure role to give
  (`ALC-AKV-0003`). Alice checks a vault every 15 minutes by default (**Check now** runs one at once); a vault that
  fails is checked less often, at most once an hour.
- **A website did not get the renewed certificate.** Open the vault certificate: **Connected websites** shows each
  website's state, and **Automatic deployment** must be on. A version that appeared while the license was not available is held for
  an administrator (`ALC-AKV-0022`); a version that is disabled, expired, not yet valid or older than the website's
  certificate is skipped and Alice emails once. After three failed deployments of one version Alice stops that
  version's wave and emails once (`Stopped after 3 failures`).
- **An import says "Not confirmed yet".** Alice sent the certificate and did not get the vault's answer. It never
  sends it again by itself: the next check settles it as **Imported** when it sees the certificate, and after
  24 to 72 hours as outcome unknown (`ALC-AKV-0026`).
- **A vault certificate suddenly shows "Monitor only".** A deployment read its secret and found no private key in
  it, so Alice treats the key as not exportable (`ALC-AKV-0016`, then `ALC-AKV-0013`). Turn **Exportable private
  key** on in the certificate's policy in Key Vault and create a new version; a later check that finds the key
  exportable again also removes the mark.
- **Deploy now asks to confirm the chain of a version that is not held.** A read of that version's secret found its
  certificate chain incomplete. Alice remembers this for the version, also after an administrator released it, so
  every manual deployment of it needs an administrator to confirm the chain (`ALC-CRT-0011`); automatic deployment
  never deploys it. Add the intermediate certificates to the certificate in Key Vault (a new version) to avoid
  this.

## Issued certificates (ACME)

Setting up certificate authorities, accounts and DNS hooks is in
[admin-guide.md](admin-guide.md#certificate-authorities-acme); using **Issued certificates** is in
[operator-guide.md](operator-guide.md#issued-certificates-acme). The `ALC-ACM-…` codes are explained one by one
below.

- **Start with a Test run.** It shows whether the authority can verify every name without issuing anything. Use
  **Let's Encrypt (staging, for tests)** while you try a new setup: the public service's request limits are low and
  failed checks count against them (`ALC-ACM-0005`).
- **"The certificate authority could not be reached" or "The authority's connection is not trusted".** Alice needs
  a direct HTTPS route to the authority: proxy settings are ignored, and link-local or metadata addresses are never
  contacted (`ALC-ACM-0001`). A company CA needs its root certificate in the authority's settings (`ALC-ACM-0013`).
- **The DNS proof fails.** Check the hook's own log first: Alice sends `present` and `cleanup` with the bearer
  secret and an `X-Alice-Signature` header (the contract is under **How does the hook work?**). A wrong secret or a
  hook that answers with anything but 200 or 204 is `ALC-ACM-0008`; a record the authority cannot see yet is
  `ALC-ACM-0006` (raise **Wait after adding the record**, or let the hook answer `{"ready":false}` until the record is
  visible). A wildcard and its base name need two TXT values at the same name.
- **The web proof fails.** The name must point to the chosen Nginx server, port 80 must be open to the authority and
  to Alice, and the server needs the `location ^~ /.well-known/acme-challenge/` block and the root-owned directory of
  [nginx-host-preparation.md](nginx-host-preparation.md) ("Publishing HTTP-01 challenges"). A redirect to HTTPS in
  front of the block makes the proof fail (`ALC-ACM-0007`). An older helper gives `ALC-SSH-0013`.
- **"This name is not allowed" (`ALC-ACM-0015`).** Every name must end in a domain ending allowed for the authority,
  and for the DNS proof also for the hook. An empty list allows nothing.
- **A certificate is "Renewal stopped".** Five renewals in a row failed. Fix the cause shown under **Last problem**,
  then **Order now**, or an administrator chooses **Renew now** to switch automatic renewal on again.
- **A website did not get the renewed certificate.** Both the certificate's **Automatic deployment of new
  certificates** and the website's own switch must be on (the panel says "Will deploy automatically to N of M
  websites"). A certificate with an incomplete chain, or one that arrived before the license allowed changes again,
  is held for an administrator. After three failed deployments automatic deployment of that certificate stops; the
  website shows **Needs attention** from about a minute after the failure. Use **Deploy now** after fixing the cause.
- **After Deploy now the website still says "Waiting for deployment".** The page does not refresh the websites by
  itself: reload it, or follow the deployment on **Deployments**.
- **A restored installation does not renew.** A restore switches automatic renewal off on every certificate from a
  certificate authority; switch it on again on each certificate's page.

## Alerts, e-mail and single sign-on

- **No e-mails arrive.** Open **Settings → Email** and choose **Send test e-mail** (it uses the saved settings). Its
  answer names the cause: no mail settings (`ALC-NTF-0002`), server not reachable (`ALC-NTF-0003`), encryption
  (`ALC-NTF-0004`), certificate not trusted (`ALC-NTF-0005`: compare the fingerprint, then **Trust this
  certificate**, or enter your certificate authority), user name or password (`ALC-NTF-0006`), sender or recipient
  refused (`ALC-NTF-0007`), an address Alice does not connect to (`ALC-NTF-0009`). If the test works, check
  **Settings → Recipients** (with **Send alerts to every administrator with an e-mail address** on, an administrator
  without an e-mail address on **People & access** gets nothing; Alice's log then says `alerts.no_recipients` after an expiry
  check) and **Settings → Alerts**. The banner **E-mails could not be sent** shows the last error code of the
  scheduled e-mails (`smtp.connect`, `smtp.tls`, `smtp.untrusted`, `smtp.auth`, `smtp.rejected`,
  `smtp.address_refused`). A server whose certificate was renewed needs **Trust this certificate** again. E-mails
  queued while the mail server was down are retried for 24 hours and then given up (`notify.gave_up` in the log).
- **A certificate expires and no e-mail came.** Only certificates in use on a server are e-mailed: an uploaded
  certificate on no server, or one whose places all disappeared, is listed but not e-mailed. Each threshold is sent
  once per expiry date; after a downtime only the most urgent reached threshold is sent; changing the thresholds
  never resends. In one check at most 20 e-mails per kind are sent; the rest are in one "More expiry notices"
  e-mail. Look for **Expiry notice recorded** (`alert.sent`) in the audit log.
- **`ALICE_SMTP_*` changes have no effect.** Since Phase 7 the mail settings live in **Settings → Email**; the
  variables were imported once and are now ignored (Alice logs a warning at every start). See
  [operator-guide.md](operator-guide.md#email).
- **SSO sign-in refused.** The sign-in page shows the reason, and the audit log has one **Single sign-on refused**
  entry (`auth.oidc.denied`; for a return that names no sign-in Alice started, at most one a minute per address) whose
  `reason` names it: `no_access` (no group of the person is mapped, `ALC-SSO-0006`),
  `groups_overage` (Entra ID sent no groups, `ALC-SSO-0007`), `email_in_use` (a local account has the e-mail,
  `ALC-SSO-0008`), `idp_unreachable` (`ALC-SSO-0009`), `login_invalid` (the token failed a check: signature, issuer,
  audience, times, nonce, or a groups claim that is not a list of names, `ALC-SSO-0010`), `login_expired` (started more than 10 minutes ago, in another browser, or
  used twice, `ALC-SSO-0011`), `user_disabled` (`ALC-SSO-0012`), `provider_disabled` (`ALC-SSO-0013`),
  `stepup_other_user` (`ALC-SSO-0014`), `idp_error` (the provider answered with an error, often a redirect address
  that is not registered, `ALC-SSO-0015`). Check the group values against what the provider sends (Entra ID: object
  IDs; Keycloak with full paths: `/group`), that the redirect address shown in Alice is registered exactly, and that
  **Settings → General** holds Alice's address (`ALC-SSO-0004`). The local administrator can always sign in with
  password and authenticator code.
- **"Alice could not read the identity provider's settings" (`ALC-SSO-0001`).** The `cause` says why: `connect`,
  `tls` (enter the provider's certificate authority), `status`, `document`, `issuer_mismatch` (the issuer address must
  be exactly the one in the provider's discovery document, including a trailing `/v2.0` or `/adfs`), `not_https`
  (also for an endpoint whose address carries a query) or `jwks`.
- **Active Directory: "Your account has no access to Alice" (`ALC-SSO-0006`, reason `no_access`) for everyone.**
  The ID token carries no groups, or other values than the mappings. Alice reads only the claim named in **Groups
  claim**, only from the ID token. A missing claim counts as "no groups". Decode one ID token and check:
  - No group claim at all: AD FS has no rule that sends groups into the ID token; Keycloak has no **Group
    Membership** mapper, or **Add to ID token** is off; Entra ID has no groups claim in **Token configuration**.
  - A different claim name: AD FS often uses `group`, not `groups`. Enter the name from the token as **Groups claim**.
  - Different values: upper and lower case count. `CORP\alice-operators` (AD FS, Token-Groups qualified by domain
    name), `alice-operators` (unqualified names, or Keycloak with **Full group path** off), `/alice-operators`
    (Keycloak with full path on), `S-1-5-21-…` (Token-Groups as SIDs) and an object ID (Entra ID) are all different
    values. Map exactly what the token carries. See [admin-guide.md](admin-guide.md#active-directory).
- **Active Directory: only people in nested groups are refused (`no_access`).** Keycloak's **Group Membership**
  mapper sends only direct groups: a member of a group nested in the mapped group does not carry the mapped group.
  Put the people directly into the mapped group, map the nested group too, or use the AD-only strategy described in
  [admin-guide.md](admin-guide.md#active-directory-through-keycloak). AD FS Token-Groups and Entra ID include nested
  groups (not run by the author).
- **Entra ID: "Your identity provider did not send your groups" (`ALC-SSO-0007`, reason `groups_overage`).** The
  person is in more than 200 groups, so Entra ID left the groups out. Choose **Groups assigned to the application**
  (see [admin-guide.md](admin-guide.md#microsoft-entra-id)).
- **"The sign-in answer of the identity provider was not accepted" (`ALC-SSO-0010`) for every confirmation of an
  AD FS user.** Alice needs `auth_time` in the ID token, at most 5 minutes old. Check that the AD FS ID token
  carries it and that the clocks of Alice and AD FS agree within 60 seconds.
- **An SSO user name looks odd** (`corpada`, `idem`, `sso-…`). Alice keeps only `a`–`z`, `0`–`9`, `.`, `_`, `-` and `@`
  from `preferred_username`, `upn` or e-mail; a backslash and non-ASCII letters are dropped. The user name is only a
  label; the display name keeps every character. Send a `preferred_username` or `upn` in ASCII if you need readable
  names.
- **A person disabled in AD can still work in Alice.** An open session keeps working until it ends (at most 30
  minutes idle, 12 hours in all), and a session the person still has at the identity provider may sign them in
  again silently. Choose **Disable** on **People &
  access** to stop it at once. With Keycloak in front of AD, also set the LDAP **Cache policy** to `NO_CACHE` or a
  short lifespan, so that group removals reach the next token.
- **An SSO user still has access after leaving a group.** The role is read again at every single sign-on and
  confirmation; an open session keeps working until it ends (at most 12 hours). Choose **Disable** on **People & access** to
  stop it at once.
- **"Confirm at your identity provider" right after a single sign-on.** Alice opens the 5-minute confirmation window
  at a single sign-on only when the provider authenticated the person within the last 5 minutes (`auth_time`); a
  silent sign-in at the provider, or one without `auth_time`, asks for the confirmation at the first protected
  action.
- **Saving the mail settings or a provider says the password or client secret is required.** A new mail server or
  port, or a new issuer address, needs the secret again: Alice never sends a stored secret to a new destination.
- **"Too many requests" when starting a single sign-on.** Starting one counts against the sign-in limit of 10 a minute
  per address; many people behind one address share it. Wait a minute.
- **An export failed.** `ALC-RPT-0001` (more than 50,000 rows: narrow the filter), `ALC-RPT-0004` (your previous
  export still runs), `ALC-SYS-0005` (more than 10 exports a minute).

The audit actions of these features: `settings.smtp_changed`, `settings.smtp_imported`, `settings.smtp_removed`,
`settings.smtp_tested`, `settings.smtp_trusted`, `settings.smtp_untrusted`, `settings.recipients_changed`,
`settings.thresholds_changed`, `settings.general_changed`, `alert.sent`, `alert.summarized`, `inventory.exported`,
`sso.provider_created`, `sso.provider_changed`, `sso.provider_refreshed`, `sso.provider_deleted`,
`sso.mapping_created`, `sso.mapping_deleted`, `sso.mapping.denied`, `sso.admin_role_allowed`,
`sso.admin_role_disallowed`, `auth.oidc.denied`, `user.provisioned`, `user.role_synced`, `user.demoted`,
`user.sessions_ended`; single sign-ons and confirmations are `auth.login` and `auth.stepup` with `method` `oidc`.

## Directory sign-in (LDAP and Active Directory)

**Directory sign-in refused.** The person sees one of two texts: "The user name or password is wrong, or you have no
access." (`ALC-LDAP-0001`) or "The directory cannot be used for sign-in right now." (`ALC-LDAP-0002`), or "Too many
requests" (see the lockout below). The page never says more, on purpose. Work through it as an Administrator:

1. **Read the audit entry.** **Audit trail**, action `auth.ldap.denied` (**Directory sign-in refused**): the `reason`
   says why; the sign-in name is there only when the directory found the entry. `bad_credentials` (unknown name, wrong
   or empty password; also a person disabled, locked or with an expired password in AD, which AD answers as a wrong
   password), `ambiguous_user` (the user filter found several entries), `no_access` (no group mapped), `email_in_use`
   (a local account has the e-mail), `user_disabled` (disabled in Alice), `locked` (blocked in Alice after wrong
   authenticator codes: `alice admin unlock <username>` or wait 15 minutes), `login_invalid` (a name Alice cannot send,
   for example with a control character), `identity_invalid` (a value of the entry cannot be stored, for example its
   sign-in name), `directory_unreachable`, `directory_misconfigured`, `provider_disabled` (sign-in through the
   directory is off). "AD answers as a wrong password" is from AD's documentation, not run by the author.
2. **Run Test connection** on **Settings → Directories**. Its message names the step:
   - `connect`: no address could be connected. Check the address and port (636 by default), DNS, and the firewall
     between the Alice server and the directory: TCP 636 must be open outbound from the Alice host (and its Docker
     network). An address that resolves to a link-local or cloud metadata address is refused by Alice on purpose.
   - `timeout`: an address or a request took too long (10 seconds to connect, 15 per request). A firewall that drops
     packets instead of refusing them looks like this.
   - `tls`: the certificate was not trusted. Paste the authority that issued the directory's certificate (root and
     intermediate, PEM) into **Certificate authority (optional, PEM)**, and check that the host name in the address
     is in the certificate (an address by IP needs the IP in the certificate). Check the clocks: a certificate that is
     not yet valid or expired for Alice's server clock is refused (keep Alice and the domain controllers on NTP). Plain
     `ldap://` or StartTLS on port 389 does not work: Alice talks only `ldaps://`.
   - `service_bind`: the directory refused the service account. Check the **Service account DN** (the full DN, not a
     user name) and enter its password again (it may have expired or been changed in the directory).
   - `user_search`: the **User base DN** does not exist or the service account may not read it.
   - `response_size`, `size_limit`: the directory sent more than Alice accepts (8 MiB per connection, 5,000 values
     of one attribute, 1,000 groups for one person). Narrow the base DNs or the filters.
3. **Run Test sign-in** with the person's name and password. It shows the reason and the step, or the groups found
   and the role:
   - `not_found` (`bad_credentials`): the user filter matches nothing. Check the filter (for example AD's
     `(&(objectClass=user)(sAMAccountName={login}))`, OpenLDAP's `(&(objectClass=inetOrgPerson)(uid={login}))`), the
     user base DN (people in another OU are not found) and that the person types the name the filter expects
     (`sAMAccountName` is `ada`, not `CORP\ada` or `ada@corp.example.com`).
   - `ambiguous_user`: two or more entries match (for example the same `uid` in two OUs). Make the filter or the base
     DN narrower; Alice never picks one.
   - `unique_id`: the entry has no single value of the **Unique ID attribute** (`objectGUID` in AD, `entryUUID` in
     OpenLDAP). Check the spelling, and that the service account may read it.
   - **No group was found**: the group filter matches nothing. Check the **Group base DN**, that the groups use the
     attribute of the filter (`member` holding DNs for `(member={dn})`; `memberUid` holding names for
     `(memberUid={login})`), and that the service account may read the groups.
   - **Nested groups are missing**: `(member={dn})` finds direct memberships only. In AD use the template
     `(member:1.2.840.113556.1.4.1941:={dn})` (the Active Directory preset); other directories have no such rule, so
     put the people directly into the mapped group or map the nested group too.
   - **Groups are listed but the role is "None"**: a mapping must equal the value exactly, upper and lower case
     included. Copy the value from the **Groups found** list (with an empty **Group name attribute** the value is the
     group's full DN).
4. **Too many requests** (HTTP 429, `ALC-SYS-0005`) for one name: three failed attempts for that name at that
   directory within 30 minutes lock it in Alice for 45 minutes, also for the right password and from every address.
   Wait (the answer says how long). An Administrator cannot end it; a restart of Alice clears it. If it happens again,
   check the audit log for `auth.ldap.denied` entries of that name: someone may be guessing. The general limit of 10
   sign-in attempts a minute per address also answers "Too many requests"; wait a minute.
5. **Everyone gets "The directory cannot be used"** although Test connection works: check whether **Allow sign-in with
   this directory** is on, whether the service account's password changed (Alice's log has a warning at most every 10
   minutes per directory), and whether a person is in more than 1,000 groups.

Other directory problems:

- **Confirm it's you always fails for directory users** although sign-in works. Alice confirms with the sign-in name
  the directory holds in the **Sign-in name attribute**; a user filter on another attribute (for example `mail`) does
  not find that name. Make the user filter use the sign-in name attribute. A confirmation that found another entry
  for the stored name (the name was given to someone else) is refused as `stepup_other_user`.
- **"Set up your authenticator first" (`ALC-LDAP-0007`) at Confirm it's you.** The person has no authenticator yet
  (for example after **Reset two-factor sign-in**); they sign out and in again to set it up.
- **A person removed from the group can still work.** The role is read again at every sign-in and confirmation; an
  open session keeps working until then (at most 30 minutes idle, 12 hours in all). Choose **Disable** on **People &
  access** to stop it at once.
- **Saving says the service account password is required.** A new address, service account DN, unique ID attribute
  or certificate authority needs the password again: Alice never sends a stored password to a new destination.
- **"This directory has users" (`ALC-LDAP-0003`).** Once people have signed in, the unique ID attribute cannot change
  and the directory cannot be deleted: switch it off, or add a new directory for another unique ID attribute. The
  addresses can still change (removing or reordering needs nothing; adding one needs the service account password).
- **A user name looks odd** (`cagla-2`, `ldap-…`). Letters are transliterated by a table, other characters dropped,
  taken names get `-2`; the user name is only a label (see [admin-guide.md](admin-guide.md#user-names)).

The audit actions of directory sign-in: `ldap.directory_created`, `ldap.directory_changed`, `ldap.directory_deleted`,
`ldap.directory_tested`, `ldap.signin_tested`, `ldap.mapping_created`, `ldap.mapping_deleted`, `ldap.mapping.denied`,
`auth.ldap.denied`, `user.provisioned`, `user.role_synced`, `user.sessions_ended`; directory sign-ins without MFA and
confirmations are `auth.login` and `auth.stepup` with `method` `ldap` (with MFA, the sign-in is `auth.login` with
`method` `totp`).

## License messages

- **"The server clock changed unexpectedly …"** The server's clock is behind the latest time Alice has seen. Alice
  keeps using the later time (and keeps counting while the clock is behind), so nothing is extended or locked
  because of it. Correct the server time (NTP). The warning is recorded in the audit log once a day
  (`clock.rollback_detected`).
- **"The server clock jumped forward by N days"** Alice keeps the previous time for 24 hours. If the new time is
  wrong, correct it (the warning then ends); otherwise wait, or ask the vendor for a correction license, which
  accepts the new time at once.
- **"License data was changed outside Alice"** A stored license file no longer matches its signature (the database
  was edited or damaged). Alice ignores it. Upload the license file from the vendor again.
- **Everyone sees "The evaluation period has ended" or "License expired"** An administrator uploads a license on
  the **License** page; everything works again at once.
- **"The evaluation period has ended" right after a database change, and the Audit log lists "Installation record
  changed outside Alice" (`license.installation_tampered`).** The Installation ID or the evaluation start in the
  database no longer matches its protection (problem `seal_mismatch`), its protection was removed (`seal_missing`),
  or the record was deleted while something else still shows that Alice ran before (`installation_missing`; the
  entry's `evidence` names what: a time record in the database or on the state volume, a damaged time record, the
  completed setup, earlier audit entries, or users, credentials or servers in the database). Alice does not trust a
  changed record and ignores every license until the original record is restored, for example from a backup (restore
  the whole database, not single tables). If the original record cannot be restored, the database owner removes the
  record (`DELETE FROM license`); at the next start Alice creates a new Installation ID whose evaluation has already
  ended: send it to your vendor for a license. The same happens when a new installation starts on a new database
  next to the state volume of an earlier one.
- **Everyone sees "Alice could not check its license since …".** See `ALC-LIC-0009` below.
- **Alice logs "this build has no build time".** The image was built without `ALICE_BUILD_TIME` (for example with a
  plain `docker compose build`). Rebuild with `make up`; see `docs/dev/getting-started.md`.
- **Every upload says "This license was issued with a key this version of Alice does not know."** If this happens
  with every file from your vendor, the build has no vendor key (`alice license keys` says so): install the
  vendor's release build.
- **No warning emails arrive.** See "No e-mails arrive" under
  [Alerts, e-mail and single sign-on](#alerts-e-mail-and-single-sign-on).
- **Alice logs "this build embeds no license verification key".** A development or pre-release build: only the
  evaluation works. See `alice license keys`.

## ALC-SYS-0001: Not found

**Meaning.** The requested API path does not exist (HTTP 404).

**Likely cause.** A typo in the URL, an outdated client calling a removed endpoint, or a wrong HTTP method on an API route.

**What to do.** Check the path against the API documentation and make sure the client matches the server version (`GET /api/v1/version`).

## ALC-SYS-0002: Alice is temporarily unavailable

**Meaning.** A dependency is not ready, so Alice cannot serve the request (HTTP 503, retryable). `/healthz` returns this code.

**Likely cause.** The database is unreachable (for example still starting after a host reboot) or its migrations have not been applied yet.

**What to do.** Wait a minute and retry. If it persists, check that the database container is running and healthy, then read the Alice logs (`docker compose logs alice`) for the `database_unreachable` or `migrations_pending` reason.

## ALC-SYS-0003: Unexpected error

**Meaning.** Alice hit an unexpected internal problem while handling the request (HTTP 500).

**Likely cause.** A bug or an unforeseen condition. Details are deliberately not shown in the response.

**What to do.** Retry once. If it repeats, look up the `request_id` from the response in the Alice logs and report it together with the steps that led to the error.

## ALC-SYS-0004: Request could not be read

**Meaning.** The request body is not valid JSON, contains fields the endpoint does not accept, or has data after the JSON value (HTTP 400). The same answer refuses text Alice cannot store: a query parameter (name or value) holding a NUL character or bytes that are not valid UTF-8, a query that does not parse (a bad percent escape such as `%zz`, or `;` between parameters), or a JSON body whose text holds the escape `\u0000`. Then `details` names the parameter (or `query` when the name itself is the problem) or `body`, with the code `validation.pattern`; the value is never repeated. Such a sign-in is not an attempt and is not audited; such a license upload is audited as `license.upload.invalid` (problem `not_json`, as the license module records such a file).

**Likely cause.** An outdated browser tab after an upgrade, an API client sending extra or misspelled fields, or a client that sends binary data as text.

**What to do.** Reload the page. API users: compare the request with the schemas in `api/openapi.yaml`; unknown fields are always rejected. Send binary content (a PFX file) base64-encoded in its documented field, and query values percent-encoded as UTF-8.

## ALC-SYS-0005: Too many requests

**Meaning.** A rate limit was reached (HTTP 429, retryable). The `Retry-After` header says how many seconds to wait.

**Likely cause.** More than 300 requests per minute for one session or token, more than 60 per minute from one address without signing in, more than 60 calls of `/healthz` on the public port per minute from one address, more than 60 per minute from one address with a session cookie or API token Alice does not accept (sessions and tokens Alice accepted in the last 30 minutes are exempt), more than 10 sign-in attempts or 5 verification codes per minute from one address.

**What to do.** Wait for the time in `Retry-After`. If many people share one address through a proxy, ask the administrator to set `ALICE_TRUSTED_PROXIES=<proxy address or CIDR, comma-separated>` in `/opt/alice/.env` and run `cd /opt/alice && sudo docker compose up -d alice`, so Alice sees real client addresses (an update keeps the value); when Docker forwards the port through a proxy process (rootless Docker), all clients also share one address (see [operator-guide.md](operator-guide.md#health-endpoints-and-request-limits)). After Alice restarts, people behind an address that sends many bad credentials may have to sign in again.

## ALC-SYS-0006: Some fields need attention

**Meaning.** One or more fields failed validation (HTTP 422). `details` lists each field with a `validation.*` code.

**Likely cause.** A required field is empty, a value is too long, or a value does not have the expected format (for example a username with spaces).

**What to do.** Correct the fields named in `details` and send the request again.

## ALC-SYS-0007: Request too large

**Meaning.** The request body is larger than 1 MiB (HTTP 413).

**Likely cause.** A very large paste or file was sent to an endpoint that accepts small JSON documents.

**What to do.** Send less data. Certificate and license uploads (later versions) have their own, larger limit.

## ALC-AUTH-0001: Session ended

**Meaning.** The request has no valid session or API token (HTTP 401).

**Likely cause.** The user signed out, was idle for 30 minutes (pages that refresh themselves do not count as activity), reached the 12-hour session limit, was disabled, or an administrator ended their sessions (**Sign out everywhere** or **Set a new password**); or an API token expired or was revoked, also by **Set a new password**, **Sign out everywhere** or **Disable** for its owner.

**What to do.** Sign in again. API users: create a new token. A browser that keeps sending a cookie Alice refused
is told to delete it.

## ALC-AUTH-0002: Permission denied

**Meaning.** The signed-in user or token is not allowed to perform this action (HTTP 403). The attempt is recorded in the audit log as `authz.denied`; repeats of the same refusal by the same person within 10 minutes are counted in one later entry (`suppressed_count`) instead of one entry each.

**Likely cause.** The user's role (Administrator, Operator, Auditor) does not include the action, or an API token is used for an action that needs a browser session.

**What to do.** Ask an administrator for the right role. See `docs/authz-matrix.md` for who may do what.

## ALC-AUTH-0003: Confirmation required

**Meaning.** A sensitive action needs a fresh verification code (HTTP 403). The confirmation lasts 5 minutes.

**Likely cause.** More than 5 minutes passed since the last sign-in or confirmation, and the action changes users, tokens, recovery codes or backup settings.

**What to do.** Enter the 6-digit code from the authenticator app when Alice asks (`POST /api/v1/auth/stepup`), then repeat the action.

## ALC-AUTH-0004: Request blocked (CSRF)

**Meaning.** A state-changing request did not carry the page's security token, or came from another site (HTTP 403).

**Likely cause.** An old browser tab, a browser extension changing requests, or a malicious page trying to act on the user's behalf.

**What to do.** Reload the page. API clients should use an API token (`Authorization: Bearer alice_...`), which needs no CSRF token.

## ALC-AUTH-0005: Incorrect username or password

**Meaning.** Sign-in failed (HTTP 401). The message is the same whether the user exists, the password is wrong, or the account is temporarily blocked, so attackers learn nothing.

**Likely cause.** A typo, a wrong password, a disabled account, or too many failed attempts: after 5 failures Alice waits 1, 2, 4, ... seconds between attempts, after 10 it blocks the account for 15 minutes. When a block ends, the count starts again: the next wrong attempt is the first of a new series, so the limit is 10 attempts per 15 minutes and the right password is accepted as soon as the block has ended.

**What to do.** Wait 15 minutes and try again carefully. An administrator can reset the password in Users. Failed attempts are listed in the audit log (`auth.login`, `auth.lockout`).

## ALC-AUTH-0006: Wrong verification code

**Meaning.** The 6-digit code or the recovery code was not accepted (HTTP 401).

**Likely cause.** A typo, a code that was already used (each code works once), or a phone or server clock that is more than 30 seconds off.

**What to do.** Wait for the next code and try again, or use a recovery code. Check that the server and phone clocks are correct (NTP).

## ALC-AUTH-0007: Authenticator already set up

**Meaning.** The account already has an authenticator app enrolled (HTTP 409).

**Likely cause.** The enrollment page was opened twice.

**What to do.** Enter a code from the app. If the device is lost, an administrator can reset it (**People & access**, **Manage**, **Reset two-factor sign-in**), or the host administrator can run `alice admin reset-mfa <username>`.

## ALC-AUTH-0008: Password too short

**Meaning.** The new password has fewer than 12 characters (HTTP 422, `params.min`).

**Likely cause.** A short password was chosen.

**What to do.** Use at least 12 characters; a short sentence works well.

## ALC-AUTH-0009: Password too long

**Meaning.** The new password has more than 128 characters (HTTP 422, `params.max`).

**Likely cause.** A very long value was pasted.

**What to do.** Use at most 128 characters.

## ALC-AUTH-0010: Password too common

**Meaning.** The password is on Alice's built-in list of 100,000 commonly used passwords (HTTP 422). The check is offline.

**Likely cause.** A well-known password such as `qwerty123456` was chosen.

**What to do.** Choose a different password that is not used anywhere else.

## ALC-AUTH-0011: Current password incorrect

**Meaning.** When changing a password, the current password did not match (HTTP 422).

**Likely cause.** A typo in the current password field.

**What to do.** Enter the current password again. If it is forgotten, ask an administrator to reset it.

## ALC-AUTH-0012: Account busy, try again

**Meaning.** Alice could not check the password or verification code in time because another check for the same account was still running (HTTP 503, retryable, `Retry-After: 1`). Nothing was verified and the attempt was not counted as a failure.

**Likely cause.** Many sign-in or verification attempts for one account at the same moment, for example a script retrying in parallel or someone guessing the password while the owner signs in.

**What to do.** Wait a second and try again. If it happens often, look in the audit log for many `auth.login` failures on that account and find where they come from.

## ALC-USR-0001: Username already in use

**Meaning.** Another user already has this username (HTTP 409). Usernames ignore case, so `Admin` and `admin` are the same.

**Likely cause.** The person already has an account, or the name is taken.

**What to do.** Choose a different username, or edit the existing user.

## ALC-USR-0002: Last administrator

**Meaning.** The change would leave no enabled local administrator (HTTP 409). Alice always keeps one as a break-glass account.

**Likely cause.** Disabling or demoting the only remaining administrator, including yourself.

**What to do.** Give the Administrator role to another person first, then repeat the change.

## ALC-USR-0003: This change is not possible for a single sign-on or directory user

**Meaning.** A role change, a password change or reset, an authenticator reset or a new API token was refused for a user who signs in through an identity provider, or a role change, a password change or reset, a new API token or a confirmation with the authenticator code alone was refused for a user who signs in through a directory (LDAP or Active Directory). (HTTP 409, reason `user.sso_user`.)

**Likely cause.** The role of a single sign-on or directory user comes from their groups. They have no Alice password and cannot create API tokens, and they confirm it's them at their identity provider or with their directory password.

**What to do.** Change the user's groups at the identity provider or in the directory; disable the user here if they must stop at once.

## ALC-TOK-0001: Token access not allowed

**Meaning.** The requested token access exceeds what the owner's role allows (HTTP 422).

**Likely cause.** An Auditor asked for a token with "operate" access.

**What to do.** Create a read-only token.

## ALC-AUD-0001: Audit log check or export already running

**Meaning.** Alice is already checking or exporting the audit log. (HTTP 503, reason `audit.busy`, retryable;
the answer carries `Retry-After`.)

**Likely cause.** Alice reads the whole audit log for one check (**Verify**) or export at a time, and someone
else's check or export was still running. A large log can take minutes to read; an export may take up to
10 minutes. Nothing was checked or exported; the refusal is recorded in the audit log (the action with the
result `denied` and the reason `busy`, once per person every 10 minutes), so an administrator can see who keeps
asking. The limit is per Alice process; the daily check and `alice audit verify` on the server do not wait for it.

**What to do.** Wait until the other check or export has finished, then try again.

## ALC-AUD-0002: Alice does not send audit entries to this address

**Meaning.** The audit forwarding settings or the test message name a syslog receiver whose address Alice never connects to: a link-local address (the cloud metadata address 169.254.169.254 among them), a multicast, unspecified or reserved address, given directly or as a name that resolves to one. Nothing was saved or sent. (HTTP 422, reason `audit.forwarding_address_refused`.)

**Likely cause.** A typo in the host, or a name that resolves to `169.254.169.254` or `0.0.0.0` in this network.

**What to do.** Enter the address of your syslog server or SIEM on your network under **Settings → Audit forwarding**, then save or choose **Send test message** again.

## ALC-AUD-0003: Alice could not reach the syslog receiver

**Meaning.** The test message, or the background forwarding (every 15 seconds), found no connection to the syslog receiver. Audit entries are never lost locally: they stay in Alice's audit log, the backlog on **Settings → Audit forwarding** grows, and forwarding continues from the same entry once the receiver answers. (HTTP 502, reason `audit.forwarding_unreachable`; retryable.)

**Likely cause.** The host name or port is wrong, the receiver is down, the transport does not match the receiver (TLS, TCP or UDP), or a firewall blocks the connection.

**What to do.** Check the host, port and transport, then choose **Send test message** again. While the receiver stays unreachable, the tab shows the last error and when it happened.

## ALC-AUD-0004: Alice does not trust the syslog receiver's certificate

**Meaning.** The TLS connection to the syslog receiver was refused because its certificate did not verify against the system's certificate authorities plus the CA entered in the settings, or it names another host. Nothing was sent. (HTTP 502, reason `audit.forwarding_untrusted`.)

**Likely cause.** The receiver uses a certificate from an internal certificate authority that was not entered, the host field does not match a name in the certificate, or the certificate has expired.

**What to do.** Paste the certificate authority (PEM) that issued the receiver's certificate into the CA field, make the host match the certificate, then choose **Send test message** again.

## ALC-SET-0001: Wrong setup code

**Meaning.** The one-time setup code entered in the setup wizard is not correct (HTTP 401).

**Likely cause.** A typo, or the code was replaced by running `setup-token --reset` again.

**What to do.** Type the code exactly as printed (dashes and case do not matter). To get a new code, run `alice setup-token --reset` on the server (in development: `make setup-token`).

## ALC-SET-0002: Setup temporarily blocked

**Meaning.** Five wrong setup codes were entered from this address; setup is blocked for 15 minutes from it (HTTP 429, `Retry-After`).

**Likely cause.** Repeated typos, or someone guessing the code.

**What to do.** Wait 15 minutes. If you did not make these attempts, check who can reach the server.

## ALC-SET-0003: Setup session ended

**Meaning.** The wizard session is missing or expired (HTTP 401).

**Likely cause.** The wizard was idle for 60 minutes, cookies were cleared, or setup was completed in another browser.

**What to do.** Enter the setup code again. If an administrator already exists, sign in instead.

## ALC-SET-0004: Administrator details missing

**Meaning.** The verification-code step of the wizard was sent before the administrator form (HTTP 409).

**Likely cause.** The page was reloaded between the two steps after the wizard session was renewed.

**What to do.** Reload the page and enter the setup code again; the wizard then asks for the administrator
details once more. (The wizard has no "Back" button yet.)

## ALC-SET-0005: Recovery passphrase too short

**Meaning.** The recovery passphrase has fewer than 16 characters (HTTP 422, `params.min`).

**Likely cause.** A short passphrase was chosen.

**What to do.** Choose at least 16 characters, for example several unrelated words.

## ALC-SET-0006: Passphrases do not match

**Meaning.** The passphrase and its repetition differ (HTTP 422).

**Likely cause.** A typo in one of the two fields.

**What to do.** Type the same passphrase in both fields.

## ALC-SET-0007: Recovery passphrase already set

**Meaning.** A recovery passphrase was already chosen for this installation (HTTP 409).

**Likely cause.** The step was submitted twice.

**What to do.** Continue with the next step. The passphrase cannot be changed in this version.

## ALC-SET-0008: Setup not finished

**Meaning.** Setup cannot be completed yet (HTTP 409).

**Likely cause.** The recovery passphrase has not been chosen.

**What to do.** Choose the recovery passphrase in the wizard, then finish setup.

## ALC-SET-0009: License step not done

**Meaning.** Setup cannot be finished because the license step is open (HTTP 409).

**Likely cause.** Neither a license file was uploaded nor **Start 30-day evaluation** was chosen.

**What to do.** On the wizard's license step, upload the license file from your vendor or start the evaluation, then
choose **Go to the dashboard**. The evaluation has been running since Alice was first started either way.

## ALC-SET-0010: The recovery passphrase is too easy to guess

**Meaning.** The recovery passphrase is long enough but rated **fair**: Alice accepts only a passphrase the strength meter rates good or strong, judged on the text the backup key is derived from. Nothing was stored. (HTTP 422, reason `setup.passphrase_too_weak`.)

**Likely cause.** The passphrase is one word repeated, uses only one kind of character, or follows a pattern (for example `aaaaaaaaaaaaaaaa` or `1234567890123456`).

**What to do.** Use several unrelated words, or mix letters, digits and symbols without repeating the same characters or words, until the meter shows good or strong. Repeated characters, repeated words and runs such as `abcdef` or `123456` count almost nothing. Write the passphrase down and keep it away from the server: every backup needs it, and it cannot be changed in this version.

## ALC-LIC-0001: Not available while the license is expired

**Meaning.** The action changes a managed server, key or certificate, and the license or the 30-day evaluation has
ended (HTTP 403). Alice is in lock mode: automatic tasks are paused and such changes are refused. Signing in,
uploading a license, backups, the audit log, exports and user administration keep working. Nothing was changed.

**Likely cause.** The license expired more than 7 days ago (168 hours), or the evaluation ended. Between its hourly
checks Alice also counts the time itself: when the lock time is reached before the next check, changes are refused
at once and a check starts; queued work is only held for an administrator after that check confirmed the lock (if
the check finds a renewal, everything continues by itself).

**What to do.** Ask your vendor for a renewed license (send the Installation ID shown on the **License** page) and
upload it there. Everything works again immediately; work that was paused waits for an administrator's confirmation.

## ALC-LIC-0002: Not a valid license file

**Meaning.** The uploaded file is not a license Alice can accept (HTTP 422): it is not a license file, it is
damaged, or a value in it was changed after the vendor signed it. Nothing was changed; the installed license stays.

**Likely cause.** The file was opened and saved by an editor that changed it, only part of it was copied, or the
wrong attachment was chosen.

**What to do.** Save the attachment from the vendor's email again, without opening it, and upload that file.

## ALC-LIC-0003: License for another installation

**Meaning.** The license names a different Installation ID (HTTP 422). The message shows the last six characters of
both IDs.

**Likely cause.** The license was made for another Alice server, or the ID was mistyped when it was requested.

**What to do.** Copy the Installation ID from the **License** page, send it to your vendor and upload the new file.
Restoring a backup keeps the Installation ID, so a license keeps working after moving to new hardware.

## ALC-LIC-0004: Unknown signing key

**Meaning.** The license was signed with a key this Alice version does not contain (HTTP 422).

**Likely cause.** The license is for a newer Alice release, or it was not issued by your vendor. A development build
without the vendor's key refuses every license.

**What to do.** Contact your vendor's support, quoting the request ID.

## ALC-LIC-0005: Signing key no longer trusted

**Meaning.** The license was signed with a vendor key that this Alice version marks as revoked (HTTP 422).

**Likely cause.** The vendor replaced its signing key.

**What to do.** Ask your vendor for a new license file; it is free of charge.

## ALC-LIC-0006: Newer license format

**Meaning.** The license uses a newer file format than this Alice version reads (HTTP 422). The current license
stays in use.

**Likely cause.** The vendor issued the license for a newer Alice release.

**What to do.** Update Alice (see `docs/upgrade.md` when available), then upload the file again.

## ALC-LIC-0007: A newer license is already installed

**Meaning.** The file is older than the license in use and does not last longer (HTTP 409). Nothing was changed.

**Likely cause.** An old license file was uploaded by mistake.

**What to do.** Nothing, if the current license is right. If your vendor sent the older file on purpose, ask them
for a correction license (it names the license it replaces and is always accepted).

## ALC-LIC-0008: License target limit reached

**Meaning.** Adding a target would exceed the number of targets the license allows (HTTP 409, `params.used`,
`params.max`). Existing targets keep working; nothing is locked.

**Likely cause.** All licensed targets are in use, or a renewal lowered the limit below the targets in use.

**What to do.** Remove a target that is no longer needed, or ask your vendor to increase the license.

## ALC-LIC-0009: The license could not be checked

**Meaning.** Alice checks its license at start, after every upload and every hour, in every Alice process; a failed
check is tried again after 1, 2, 4 and 8 minutes, then every 10 minutes. No check has succeeded for more than 3 hours since the process started (time while the host was suspended counts; after a long suspend the first check runs at once) (`license.unverified`, HTTP 503, retryable), so the action was refused. Nothing was changed. Every action that works on a managed server is refused
meanwhile: changes to servers, keys and certificates, and also **Test connection**, **Scan for SSH keys** and
**Discover**; the daily scans are not started. Everyone sees a red banner with the time of the last successful
check. Reading everything, signing in, uploading a license, the audit log and its export, user and API token
administration, **Discard** of a waiting job, and the recovery and rollback of deployments keep working. Queued jobs
are not cancelled and need no confirmation: they wait and start by themselves after the next successful check if
the license is still valid.

**Likely cause.** The database was unreachable or overloaded for hours, or another database session keeps the
`license` row locked (a check waits at most 30 seconds for it and gives up after 2 minutes). Alice logs "the
license could not be checked for more than 3h0m0s" once, and "scheduled task failed" with `job_type=license.evaluate`
for each failed check.

**What to do.** Check that the database is reachable and healthy. As the database owner, look for a session that
holds the license row: `SELECT pid, state, xact_start, query FROM pg_stat_activity WHERE pid = ANY
(pg_blocking_pids(<pid of a waiting Alice session>))`, or list long transactions with `SELECT pid, usename,
xact_start, query FROM pg_stat_activity WHERE xact_start < now() - interval '5 minutes'`; end such a session with
`SELECT pg_terminate_backend(<pid>)`. If the license is still valid, changes resume after the next successful check,
which is retried at least every 10 minutes (or restart Alice to check at once). If the license itself has expired, the answer
then becomes ALC-LIC-0001.

## ALC-SYS-0008: Changed while you were editing

**Meaning.** The item was changed by someone else after you opened it (HTTP 412). Your change was not saved.

**Likely cause.** Two people edited the same server at the same time, or the page was open for a long time.

**What to do.** Reload the page, check the current values and make your change again.

## ALC-SYS-0009: This request method is not accepted here

**Meaning.** The API address exists but does not accept this request method, or a HEAD request to an export (`/api/v1/certificates/export`, `/api/v1/ssh-keys/export`, `/api/v1/audit/export`) was refused before anything ran; no audit row was written. The `Allow` header of the answer lists the methods the address accepts (not for the exports' HEAD). (HTTP 405, reason `system.method_not_allowed`.)

**Likely cause.** A script uses the wrong method for the address (for example DELETE where the API documents POST …/actions/…). An export is downloaded with GET only; a HEAD request would run the whole export and record it without sending the file.

**What to do.** Use a method from the `Allow` header and the API reference (`docs/api.md`). Download an export with GET, for example with the Export button.

## ALC-TGT-0001: Server already exists

**Meaning.** Another server already has this name, or the same address and SSH port (HTTP 409). Names are compared
without regard to upper and lower case.

**Likely cause.** The server was added before, perhaps under another name.

**What to do.** Choose another name, or open the existing server on the **Servers** page.

## ALC-TGT-0002: Fingerprint not confirmed yet

**Meaning.** Alice does nothing on a server until an administrator confirms its SSH host-key fingerprint (HTTP 409).

**Likely cause.** The server was just added and nobody has clicked **Yes, this is my server** yet.

**What to do.** Open the server, run the shown `ssh-keygen -lf …` command on the server, compare the fingerprints and
confirm.

## ALC-TGT-0003: Not the fingerprint the server presented

**Meaning.** The fingerprint you confirmed is not the one the server presented (HTTP 409). Nothing was pinned.

**Likely cause.** The page was open while the server presented another key, or the fingerprint was edited.

**What to do.** Reload the page and compare again. If the server keeps presenting different keys, stop and ask your
security team: something may be intercepting the connection.

## ALC-TGT-0004: Server identity changed

**Meaning.** The server presented another host key than the confirmed one. Alice stopped every operation on it
(HTTP 409) and emailed the administrators.

**Likely cause.** The server was reinstalled or its SSH host keys were regenerated, or someone is impersonating it.

**What to do.** Ask your security team to confirm the change on the server itself. Then an administrator opens the
server, chooses **Review the new fingerprint**, gives a reason and chooses **Accept new fingerprint** (the previous
fingerprint stays in the history) or, when the previous fingerprint is still the right one, **The server still shows
the previous fingerprint** (Alice tests the connection again and blocks the server again if it presents another
key). Alice asks for an authenticator code if the last one is more than five minutes old.

## ALC-TGT-0005: Fingerprint cannot be accepted now

**Meaning.** The confirmation does not fit the server's state (HTTP 409): a first fingerprint can be confirmed only
while the server waits for it, a new one only after the identity changed.

**Likely cause.** Another administrator already confirmed it, or the page is outdated.

**What to do.** Reload the server's page.

## ALC-TGT-0006: Server disabled

**Meaning.** The server is disabled, so Alice runs no task on it (shown on the task, HTTP 409 when returned directly).

**Likely cause.** The server was disabled while the task waited in the queue.

**What to do.** Open the server to see why it is disabled, then click **Test connection**.

## ALC-SSH-0001: Server cannot be reached

**Meaning.** Alice could not open an SSH connection (HTTP 502 when returned directly; usually shown on the server and its
tasks).

**Likely cause.** The server is off, the address or port is wrong, or a firewall blocks the Alice host. A connection
that is closed or reset while Alice signs in also counts as unreachable (it is retried), not as a refused sign-in;
only the server's explicit refusal of every sign-in method (or "too many authentication failures") is
`ALC-SSH-0002`.

**What to do.** Check the server and the network path to its SSH port, then click **Test connection**.

## ALC-SSH-0002: Server refused Alice's key

**Meaning.** The server rejected the sign-in of the `alice-svc` account with Alice's key. The server is marked "Sign-in
refused" and administrators get an email. Alice never tries a refused key again on its own (no scheduled scan or
test), so the server never locks the account because of Alice; only **Test connection** tries again.

**Likely cause.** The preparation commands were not run, the key line was removed from
`/var/lib/alice-svc/.ssh/authorized_keys`, or the account is locked.

**What to do.** Run the preparation commands from the **Servers** page again as root on the server, then test the
connection.

## ALC-SSH-0003: Server answered too slowly

**Meaning.** A connection or a command took longer than its time limit (10 s to connect, 30–60 s per command).

**Likely cause.** A very slow network or an overloaded server.

**What to do.** Try again later; check the server's load.

## ALC-SSH-0004: Helper not allowed or not installed

**Meaning.** `sudo -n /usr/local/libexec/alice-helper …` failed on the server.

**Likely cause.** `alice-helper` is missing, or `/etc/sudoers.d/alice` is missing or was changed.

**What to do.** Copy `alice-helper` from the Alice bundle to the server and run the preparation commands again as root.

## ALC-SSH-0005: Helper outdated

**Meaning.** The helper on the server speaks an older protocol than this Alice version needs (this release needs
protocol 6, `alice-helper` 1.5.0; `params.required_protocol` is `6`). Alice does nothing on that server: no scan, no
key removal, no deployment, and a deployment that is being finished there waits.

**Likely cause.** Alice was updated but the helper on the server was not.

**What to do.** Copy the helper from the current Alice bundle and run the preparation commands again, then choose
**Test connection**. The new helper also works with the previous Alice release, so update the helpers first next
time ([nginx-host-preparation.md](nginx-host-preparation.md#updating-the-helper)).

## ALC-SSH-0006: Helper refused the request

**Meaning.** The helper checked the request and refused it (`params.helper_code` names the rule, for example
`PATH_NOT_ALLOWED`).

**Likely cause.** A key file is outside the places the helper may read or change (for example a symbolic link that
leaves the user's home), or the file is not a regular file.

`CONTENT_MISMATCH` means the new file content reached the server incomplete (the connection dropped while Alice
sent it); the helper wrote nothing. `HOME_NOT_WRITABLE` means the user has no `.ssh` directory yet and may not create
one in their home directory (for example a home owned by root); the helper wrote nothing. `params.reason`
`too_many_users` means the server has more accounts than the helper lists (200) and the requested user is not among
them, so Alice cannot check that a new key file belongs to that user.

**What to do.** Scan the server again. If the refusal stays, check the named file on the server; contact support with
the request ID if needed. After `CONTENT_MISMATCH`, check the network path to the server and run the action again.

## ALC-SSH-0007: File changed during the operation

**Meaning.** The `authorized_keys` file changed between Alice's read and write, three times in a row (HTTP 409). Alice
wrote nothing.

**Likely cause.** Another tool or person edited the file at the same time.

**What to do.** Try again.

## ALC-SSH-0008: Keys managed elsewhere

**Meaning.** The server's SSH daemon uses `AuthorizedKeysCommand`, so Alice lists the file keys but does not change keys
there (HTTP 409).

**Likely cause.** Keys come from a directory service or another program.

**What to do.** Manage those keys in the system that provides them.

## ALC-SSH-0009: Answer too large

**Meaning.** The server sent more than Alice accepts (8 MiB per command, 1 MiB per key file).

**Likely cause.** An unusually large key file, SSH configuration or Nginx configuration (`nginx -T`).

**What to do.** Inspect the server's `authorized_keys` files, `sshd -T` output and `nginx -T` output.

## ALC-SSH-0010: Unexpected answer from the server

**Meaning.** The helper's answer could not be read.

**Likely cause.** The file at `/usr/local/libexec/alice-helper` is not Alice's helper, or it is damaged.

**What to do.** Install the helper again from the Alice bundle and compare its checksum with `alice-helper.sha256`.

## ALC-SSH-0011: This build cannot show the setup commands

**Meaning.** Alice cannot show **Prepare a server for Alice** (`GET /api/v1/ssh-keys/platform-key`, HTTP 500). Its
setup commands check `alice-helper` against the checksums built into Alice before they install it as root, and this
build has none. Alice also logs "this build has no alice-helper checksums" at every start.

**Likely cause.** Alice was built by hand with `go build` and a version number, not with `make build` or the image
build, which embed the checksums. (A development build, version `dev`, shows the commands with a warning that they
cannot check the helper.)

**What to do.** Install an official Alice release, or rebuild with `make build` or the image build. Servers that are
already prepared keep working.

## ALC-SSH-0012: Alice does not connect to this server's address

**Meaning.** When Alice connected, the server's name resolved to an address Alice never connects to, so Alice opened
no connection (nothing was sent). These are the addresses that are refused when a server is added by address: link-local
addresses, including the cloud metadata address `169.254.169.254` and its IPv6 forms, multicast addresses, unspecified
addresses (`0.0.0.0`, `::`, which reach services of Alice's own host), `0.0.0.0/8`, `240.0.0.0/4` (with
`255.255.255.255`), and the IPv6 forms that never name a server (IPv4-compatible `::a.b.c.d`, IPv4-translated
`::ffff:0:a.b.c.d`, Teredo `2001::/32`). Loopback and private addresses are allowed. Alice checks every address the
name resolves to, at every connection (SSH and its own TLS check of a website), on the address it actually connects
to; a refused address is never connected, another address of the same name may be. The reason is also shown when the
name has a refused address and its other addresses failed to connect (one address down, one refused): the refused
record is what needs fixing. The server's status becomes **Cannot be reached** with this reason (a server still waiting
for its fingerprint confirmation keeps that status); the job is not retried, and the next scheduled test or a **Test
connection** tries again. When only Alice's own TLS check of a website is refused, the check on the server decides and
Alice logs a warning with this reason.

**Likely cause.** The server's DNS record changed (by mistake, or a wildcard DNS name such as `*.nip.io` that encodes an
address), or someone is trying to make Alice reach a service of its own host or the cloud metadata service through a
name that resolves differently over time (DNS rebinding).

**What to do.** Check the server's DNS record (`dig +short <name>` from Alice's host). Fix the record, then choose
**Test connection**. A server's address cannot be changed in Alice: if the name itself is wrong, remove the server and
add it again with its real address or a name that resolves to it. If you did not change the record, treat it as a
possible attack on Alice's network position.

## ALC-SSH-0013: Reinstall the helper on this server to use this proof method

**Meaning.** Alice was asked to prove a name with the HTTP-01 method on this server, but the server cannot write the
challenge file yet: its `alice-helper` is older than protocol 7 (`alice-helper` 1.6.0; `params.helper_protocol` and
`params.required_protocol`), or its sudoers file does not have the two `acme-challenge` lines yet (sudo refused the
command although the helper is new enough). Alice wrote nothing on the server. Everything else (scans, key changes,
deployments) keeps working there: protocol 6 is still enough for those.

**Likely cause.** Alice was updated but the server's helper and sudoers file were not, or the server was prepared with
the **Linux server** type (the HTTP-01 lines are in the **Nginx server** profile only).

**What to do.** Copy `alice-helper` from the current Alice bundle and run the preparation commands of the **Nginx server**
type again (they install the helper and the sudoers file together), then choose **Test connection**. Or use the DNS
proof method for this certificate. See
[nginx-host-preparation.md](nginx-host-preparation.md#publishing-http-01-challenges-optional).

## ALC-KEY-0001: Alice's own key is protected

**Meaning.** Alice refuses to remove its own connection key (HTTP 409), in any file and whatever its comment says, and
refuses a rotation policy or a rotation of it. A refused removal or rotation policy is recorded in the audit log.

**Likely cause.** The key that Alice uses to sign in was chosen for removal, or for a rotation policy.

**What to do.** Keep the key; Alice never rotates it. To stop managing a server, remove the server from Alice instead.

## ALC-KEY-0002: Last key of root

**Meaning.** Removing this key would leave the root account (or another account with user ID 0) without any key
(HTTP 409).

**Likely cause.** The key is the only line in the `authorized_keys` file of `root` or of another account with user
ID 0 (for example `toor`).

**What to do.** Add another key for root first, or let an administrator confirm the removal on purpose.

## ALC-KEY-0003: Key cannot be changed in this file

**Meaning.** Alice cannot remove (or add) this key in this file (HTTP 409 when returned directly; on a task,
`params.reason` names the cause: `cert_authority` or `file_too_large`).

**Likely cause.** The key location no longer exists or was already removed, the line is a `cert-authority` line that
Alice only lists, or the `authorized_keys` file is larger than 1 MiB.

**What to do.** Click **Scan for SSH keys** on the server and try again; check the size of the file on the server.

## ALC-KEY-0004: SSH server settings could not be read

**Meaning.** The last scan could not read the SSH server's effective settings (`sshd -T`) for the server or for the
key's user, so Alice refuses to change keys there (HTTP 409). The refusal is recorded in the audit log.

**Likely cause.** `sshd -T` fails on the server, for example because of a broken `sshd_config` or a `Match` block it
cannot evaluate for that user.

**What to do.** Run `sshd -T` as root on the server and fix the reported problem, scan the server again, then retry.

## ALC-KEY-0005: Change could not be verified

**Meaning.** Alice wrote the `authorized_keys` file but reading it back did not show the expected result. The task
stops for a person ("needs attention"); Alice did not record the key as removed. The task's result names the backup of
the previous file.

**Likely cause.** Another program changed the file right after Alice's write, or the file system did not keep the write.

**What to do.** Compare the file on the server with the backup named on the task, restore it if needed, then scan the
server again.

## ALC-KEY-0006: Alice holds no private key for this key

**Meaning.** A deploy, a private key download or a rotation policy was refused for a key whose private key Alice does not hold, or a deploy or a private key download for Alice's own connection key (a rotation policy for it is refused with `ALC-KEY-0001`). A refused download or policy is recorded in the audit log, and so is a refused deploy of Alice's own key; a refused deploy of a key found on a server is not. (HTTP 409, reason `sshkey.not_managed`.)

**Likely cause.** Only keys generated in Alice can be deployed, downloaded or rotated. Keys found on servers and Alice's own connection key are only listed.

**What to do.** Generate a new key in Alice and use that one instead.

## ALC-KEY-0007: This key was replaced by a rotation and is no longer used

**Meaning.** A deploy or a new rotation policy was refused for a key that a finished rotation retired. (HTTP 409, reason `sshkey.retired`.)

**Likely cause.** A finished rotation retired it. Alice keeps its private key for 30 days for emergencies, then destroys it.

**What to do.** Use the newer key that replaced it. The finished rotation of this key names it. An administrator can still download the retired key's private key until it is destroyed.

## ALC-KEY-0008: The private key of this key was destroyed

**Meaning.** The private key of this key no longer exists in Alice, so it cannot be downloaded or deployed. A refused download is recorded in the audit log. (HTTP 410, reason `sshkey.private_key_destroyed`.)

**Likely cause.** Alice destroys the private key of a retired key 30 days after it was retired. A key found in use on a server again after its private key was destroyed stays retired; the audit log records it once as "Destroyed key found on a server again" (`sshkey.live_after_destruction`).

**What to do.** Use the newer key. Backups made before the destruction still contain it in encrypted form.

## ALC-KEY-0009: Alice does not change the keys of the account it connects with

**Meaning.** A deploy was refused because it would change the key file of the account Alice signs in with. The refusal is recorded in the audit log. (HTTP 409, reason `sshkey.connection_account`.)

**Likely cause.** The chosen user is the account Alice signs in with, or the chosen file is one of that account's key files. The setup commands own that account's key file and write it again whenever they run.

**What to do.** Choose another user or another file on the server.

## ALC-KEY-0010: The server did not accept a login with the new key

**Meaning.** After adding a key, Alice tried to sign in with it as that user and the server refused. It shows on a deploy task and on a place of a rotation ("New key did not work"). (HTTP 502, reason `sshkey.login_failed`.)

**Likely cause.** The key is in the file, but the SSH server refused it: the account may be locked, the server may read another file for this user, or a setting such as AllowUsers leaves the account out.

**What to do.** Check the account and the SSH server settings for this user, then try again. Alice removes the key it added again; the page shows whether that worked. A rotation with such a place is undone; the old key is not touched.

## ALC-KEY-0011: Alice is busy generating other keys

**Meaning.** Generating a key was refused because two keys are being generated already. Nothing was created. The answer carries `Retry-After`. (HTTP 503, reason `sshkey.generate_busy`.)

**Likely cause.** Generating an RSA key takes a few seconds, so Alice generates at most two keys at a time.

**What to do.** Try again in a moment.

## ALC-KEY-0012: Alice could not remove the key again after a failed check

**Meaning.** A deploy added the key, the login with it failed, and removing it again failed too. The key line is still in the file. (HTTP 502, reason `sshkey.add_undo_failed`.)

**Likely cause.** Alice added the key, the check after it failed, and removing the key failed as well (for example, the server could not be reached).

**What to do.** When the server can be reached, choose **Scan for SSH keys** on the server's page (on an Nginx server, **Discover**; Alice also queues a scan by itself, at the latest about two hours after the task ended), then remove the key from this server on the key's page.

## ALC-KEY-0013: This file is not one of the user's key files

**Meaning.** A deploy named a file that is not one of the files the SSH server reads for that user, as the last scan found them. (HTTP 409, reason `sshkey.not_a_key_file`.)

**Likely cause.** Alice adds keys only to the files the SSH server reads for that user, as the last scan found them.

**What to do.** Scan the server again, then choose one of the files offered.

## ALC-KEY-0014: Alice does not know all key files of the account it connects with on this server

**Meaning.** A deploy was refused because Alice cannot rule out that the chosen file is one the account it connects with reads. The deploy dialog offers no file on such a server. The refusal is recorded in the audit log. (HTTP 409, reason `sshkey.connection_files_unknown`.)

**Likely cause.** The last scan did not list every key file the SSH server reads for the account Alice signs in with, so Alice cannot rule out that the chosen file is one of them. Servers last scanned by an earlier version of Alice have no such list. After upgrading to the version with SSH key rotation, every server refuses deploys until it is scanned again. A server with more than 200 accounts, or whose account that Alice connects with is not in `/etc/passwd`, keeps refusing, because Alice cannot list that account's files completely there.

**What to do.** Scan the server again, then try again. Choose **Scan for SSH keys** on the server's page (on an Nginx server, **Discover**); the deploy dialog offers the files once the scan has listed them.

## ALC-KEY-0015: Alice's clock is behind a time it already recorded

**Meaning.** A private key download was refused because the clock of Alice's host is earlier than the time Alice recorded for the last download of this key. No file was handed out, nothing was counted and no audit row was written. The answer is retryable and carries `Retry-After`. (HTTP 503, reason `sshkey.clock_behind`.)

**Likely cause.** The clock of the computer that runs Alice was set back after the last download of this private key. Alice handed out nothing and recorded nothing.

**What to do.** Check the time of the computer that runs Alice (NTP), then try again in a moment.

## ALC-KEY-0016: Alice does not know yet whether the key was added

**Meaning.** A deploy task sent the key to the server but got no answer. While the request may still arrive (the helper's time limit plus 30 seconds after the last send), the task waits, then starts over. When the login with the key then does not succeed and Alice cannot prove that it wrote the line (it was not shown absent by a complete listing before the first send), the task stops for a person: Alice never removes a line it is not sure it added, and it queues a scan of the server about an hour later. (HTTP 502, reason `sshkey.add_uncertain`.)

**Likely cause.** The server did not answer Alice's request to add the key, and the key is not in the file yet. The request may still arrive at the server.

**What to do.** If the task is still waiting, nothing: it tries again by itself. If it stopped, check the user's key file on the server after the scan: remove the line on the key's page if you do not want it, or deploy again. If this repeats, check the connection to the server.

## ALC-KEY-0017: This place belongs to the account Alice connects with

**Meaning.** A place of a rotation was skipped, or its change refused when Alice was about to send it, because it is the account Alice signs in with or one of that account's key files. (HTTP 409, reason `sshkey.connection_account_file`.)

**Likely cause.** The user is the account Alice signs in with, or the file is one of that account's key files. Alice never changes those: the setup commands own them.

**What to do.** Nothing to do here. Use another user or another file for this key.

## ALC-KEY-0018: This key is the new key of a rotation that has not finished

**Meaning.** A deploy was refused because the key is the new key of a rotation that has not finished; this is checked when the deploy is asked for and again when its task runs. (HTTP 409, reason `sshkey.in_rotation`.)

**Likely cause.** A running rotation adds this key to its servers itself. If the rotation is stopped or undone, Alice removes the key again wherever it was added, so a key deployed by hand now could disappear with it.

**What to do.** Wait until the rotation has finished, or stop it on its page, then deploy the key.

## ALC-NTF-0001: Alice could not queue the email about the license renewal

**Meaning.** A paused rotation shows this as its notice error (`notice_error` of the run) next to ALC-ROT-0021: the email that tells the administrators about the license renewal could not be queued, so Continue is still refused. (HTTP 503, reason `notify.queue_failed`; retryable.)

**Likely cause.** Writing the email to Alice's outbox failed. A paused rotation continues only after that email is queued, and Alice tries again at every background check.

**What to do.** Check Alice's logs and its database, then choose Continue again once the email is queued.

## ALC-NTF-0002: Mail settings are missing

**Meaning.** A test e-mail, removing the mail settings or trusting a certificate was refused because Alice has no mail server configured. (HTTP 409, reason `notify.smtp_not_configured`.)

**Likely cause.** Alice has no mail server to send through. Without one, the e-mails of the expiry alerts, the lockout and the license are recorded as skipped and never sent.

**What to do.** Enter the mail server in Settings, then try again.

## ALC-NTF-0003: Alice could not reach the mail server

**Meaning.** A test e-mail could not be sent because Alice found no connection to the mail server; scheduled e-mails fail with the label `smtp.connect` and are retried for 24 hours. (HTTP 502, reason `notify.smtp_connect`; retryable.)

**Likely cause.** The server name or port may be wrong, the server may be down, or a firewall blocks the connection.

**What to do.** Check the server name and port, then send a test e-mail again.

## ALC-NTF-0004: The encrypted connection to the mail server failed

**Meaning.** Alice connected to the mail server but could not set up encryption with it; nothing was sent (label `smtp.tls`). A certificate that is not trusted is ALC-NTF-0005 instead. (HTTP 502, reason `notify.smtp_tls`.)

**Likely cause.** The server does not offer the selected encryption (STARTTLS or TLS), or the handshake failed.

**What to do.** Choose the encryption the server offers (port 587 usually uses STARTTLS, port 465 TLS), then try again.

## ALC-NTF-0005: Alice does not trust the mail server's certificate

**Meaning.** The test e-mail stopped before anything was sent because the server's certificate did not verify (label `smtp.untrusted`). The answer carries the certificate's SHA-256 fingerprint, subject and expiry (params `fingerprint`, `subject`, `not_after`) and nothing else the server sent; Alice remembers that certificate for one hour so that it can be trusted. (HTTP 502, reason `notify.smtp_untrusted`.)

**Likely cause.** The certificate is not signed by a trusted authority, does not match the server name, or has expired. Its fingerprint is shown below.

**What to do.** Check with your mail administrator that the fingerprint is the server's, then choose Trust this certificate, or add your organisation's certificate authority. Trusting pins exactly this certificate: when the server gets a new one, send a test e-mail and trust the new one.

## ALC-NTF-0006: The mail server rejected the user name or password

**Meaning.** The mail server refused Alice's sign-in (label `smtp.auth`); nothing was sent. (HTTP 502, reason `notify.smtp_auth`.)

**Likely cause.** The sign-in data in the mail settings are wrong or the account is locked at the mail server.

**What to do.** Enter the correct user name and password, then send a test e-mail again. A user name always needs a password: saving one without a stored or new password is refused with a field error on `password`.

## ALC-NTF-0007: The mail server refused the message

**Meaning.** The mail server accepted the connection and the sign-in but refused the sender or the recipient (label `smtp.rejected`). (HTTP 502, reason `notify.smtp_rejected`.)

**Likely cause.** The sender or recipient address is not accepted by the server.

**What to do.** Check the sender address and the recipient, then try again.

## ALC-NTF-0008: Alice did not see this certificate recently

**Meaning.** Trust this certificate was refused: no failed test e-mail to the configured server and port showed a certificate with this fingerprint in the last hour. (HTTP 409, reason `notify.certificate_not_seen`.)

**Likely cause.** Only a certificate that a test e-mail found in the last hour can be trusted. Changing the server name or port, or trusting the certificate once already, also ends that hour.

**What to do.** Send a test e-mail again, then trust the certificate it shows.

## ALC-NTF-0009: Alice does not connect to this mail server address

**Meaning.** The mail server's name resolved to an address Alice never connects to (label `smtp.address_refused`); nothing was sent. (HTTP 409, reason `notify.smtp_address_refused`.)

**Likely cause.** The server name points to a link-local or cloud metadata address, which Alice never contacts.

**What to do.** Use the mail server's normal address.

## ALC-RPT-0001: The export is too large

**Meaning.** A CSV export was refused because its filter matches more than 50,000 rows (param `max`). Nothing was written and nothing was recorded in the audit log. (HTTP 409, reason `export.too_large`.)

**Likely cause.** An export holds at most 50,000 rows, and this filter matches more. Alice counts the rows before it writes the file; when rows are added between that count and the end of the file, the file stops at 50,000 rows without an error, so an export of a list that grows right then can hold fewer rows than the list shows at the end.

**What to do.** Narrow the filter, for example by server or expiry, then export again.

## ALC-RPT-0002: You have reached the limit of saved views

**Meaning.** Saving a view was refused: you already keep 50 saved views (param `max`), on both list pages together. (HTTP 409, reason `views.limit_reached`.)

**Likely cause.** A person can keep at most 50 saved views.

**What to do.** Delete a view you no longer need, then save again.

## ALC-RPT-0003: A saved view with this name already exists

**Meaning.** Saving a view was refused because one of your views on the same page has this name (upper and lower case count as the same). (HTTP 409, reason `views.name_taken`.)

**Likely cause.** Each of your views on a page needs its own name.

**What to do.** Choose another name.

## ALC-RPT-0004: Another export of yours is still running

**Meaning.** A CSV export was refused because the same person (or the same API token's owner) has an export running; nothing was written or recorded. (HTTP 409, reason `export.busy`; retryable, with Retry-After.)

**Likely cause.** Each person can run one export at a time, and your previous export has not finished yet.

**What to do.** Wait until the previous download has finished, then export again.

## ALC-SSO-0001: Alice could not read the identity provider's settings

**Meaning.** Adding, changing or re-reading an identity provider failed because Alice could not read its discovery document or key list (param `cause`: connect, tls, status, document, issuer_mismatch, not_https or jwks); nothing was saved. (HTTP 502, reason `sso.discovery_failed`; retryable.)

**Likely cause.** Its discovery document or key list could not be fetched or is not valid (reason: the `cause` label).

**What to do.** Check the issuer address and, for a private certificate authority, its certificate, then try again.

## ALC-SSO-0002: A group cannot be mapped to Administrator

**Meaning.** A group mapping to Administrator was refused and recorded in the audit log. (HTTP 409, reason `sso.admin_mapping_disabled`.)

**Likely cause.** SSO users may be Admin is switched off, so single sign-on and directory users can be at most Operators. The switch covers the group mappings of identity providers and of directories.

**What to do.** Switch on SSO users may be Admin first, or map the group to another role.

## ALC-SSO-0003: SSO users may be Admin cannot be switched off yet

**Meaning.** Switching off "SSO users may be Admin" was refused. (HTTP 409, reason `sso.admin_mappings_exist`.)

**Likely cause.** Some groups of an identity provider or a directory are still mapped to Administrator.

**What to do.** Remove those mappings, then switch the setting off.

## ALC-SSO-0004: Alice's address is not set

**Meaning.** A single sign-on could not start because Alice's own address (Settings, General) is empty. (HTTP 409, reason `sso.public_url_missing`.)

**Likely cause.** The identity provider sends users back to Alice's address, and Alice does not know it yet.

**What to do.** Enter Alice's address under Settings, General, then try again.

## ALC-SSO-0005: This identity provider still has users

**Meaning.** Deleting an identity provider was refused. (HTTP 409, reason `sso.provider_in_use`.)

**Likely cause.** People have signed in through it, so it cannot be deleted.

**What to do.** Switch the provider off instead, or remove its users first.

## ALC-SSO-0006: Your account has no access to Alice, contact your administrator

**Meaning.** A single sign-on was refused: no group of the person has a role in Alice. The sign-in page shows this (`sso_error=sso.no_access`); the person's sessions and API tokens end. (HTTP 403, reason `sso.no_access`.)

**Likely cause.** You signed in at your identity provider, but none of your groups is given a role in Alice.

**What to do.** Ask your administrator to add your group to Alice's group mappings.

## ALC-SSO-0007: Your identity provider did not send your groups

**Meaning.** A single sign-on was refused because the identity provider left out the groups (Microsoft Entra ID sends at most 200). Alice does not ask Microsoft Graph for them. (HTTP 403, reason `sso.groups_overage`.)

**Likely cause.** You are a member of more groups than it puts into a sign-in, so it left them all out.

**What to do.** Ask your administrator to send only the groups assigned to Alice's application (Microsoft Entra ID: "Groups assigned to the application").

## ALC-SSO-0008: Single sign-on was refused for this e-mail address

**Meaning.** A single sign-on was refused because a local account has the same e-mail address. (HTTP 403, reason `sso.email_in_use`.)

**Likely cause.** A local Alice account already uses this e-mail address, and Alice never joins a single sign-on identity to a local account.

**What to do.** Ask your administrator to change or remove the local account's e-mail address, then sign in again.

## ALC-SSO-0009: Alice could not reach the identity provider

**Meaning.** A single sign-on failed because Alice could not reach the identity provider to finish it (token or key list). (HTTP 502, reason `sso.idp_unreachable`; retryable.)

**Likely cause.** The identity provider is down or the network path to it is blocked.

**What to do.** Try again later. Administrators can still sign in with their local account and authenticator code.

## ALC-SSO-0010: The sign-in answer of the identity provider was not accepted

**Meaning.** A single sign-on was refused because the identity provider's answer did not pass Alice's checks (signature, issuer, audience, times, nonce). (HTTP 401, reason `sso.login_invalid`.)

**Likely cause.** Alice could not confirm that the answer really came from your identity provider for this sign-in.

**What to do.** Sign in again. If this keeps happening, ask your administrator to check the single sign-on settings.

## ALC-SSO-0011: This sign-in has expired

**Meaning.** A single sign-on was refused because its state was missing, used, older than 10 minutes or started in another browser. (HTTP 401, reason `sso.login_expired`.)

**Likely cause.** A sign-in must be finished within 10 minutes and in the same browser, and each one can be used only once.

**What to do.** Start the sign-in again.

## ALC-SSO-0012: Your Alice account is disabled

**Meaning.** A single sign-on was refused because the Alice account is disabled. (HTTP 403, reason `sso.user_disabled`.)

**Likely cause.** An administrator disabled your account.

**What to do.** Contact your administrator.

## ALC-SSO-0013: This sign-in option is switched off

**Meaning.** A single sign-on was refused because the identity provider is switched off in Alice. (HTTP 403, reason `sso.provider_disabled`.)

**Likely cause.** An administrator switched off this identity provider in Alice.

**What to do.** Use another sign-in option or contact your administrator.

## ALC-SSO-0014: The confirmation was made with another account

**Meaning.** A confirmation (step-up) at the identity provider was refused because another person answered it. (HTTP 403, reason `sso.stepup_other_user`.)

**Likely cause.** You confirmed at the identity provider as a different person than the one signed in to Alice.

**What to do.** Confirm again with your own account.

## ALC-SSO-0015: The identity provider ended the sign-in

**Meaning.** The identity provider sent the browser back with an error instead of a sign-in. (HTTP 401, reason `sso.idp_error`.)

**Likely cause.** It answered with an error, for example because the sign-in was cancelled or Alice's address is not registered there.

**What to do.** Try again. If this keeps happening, ask your administrator to check that Alice's address is registered at the identity provider.

## ALC-SSO-0016: Your account does not use single sign-on

**Meaning.** A confirmation at an identity provider was asked for a local account. (HTTP 409, reason `sso.not_sso_user`.)

**Likely cause.** Only single sign-on users confirm at the identity provider.

**What to do.** Confirm with your authenticator code instead.

## ALC-LDAP-0001: The user name or password is wrong, or you have no access

**Meaning.** A sign-in through a directory (LDAP or Active Directory) was refused. Every refusal that could tell something about a person gets this one answer: an unknown user name, a wrong password, no group mapped to a role, a user disabled or locked in Alice, an e-mail address that belongs to a local account, a name that matches several entries or that cannot be sent to a directory. The answer always takes at least 1.5 seconds. (HTTP 401, reason `ldap.signin_refused`.)

**Likely cause.** The user name or password is wrong, or none of the person's groups is given a role in Alice. The audit log records the reason of each refusal as `auth.ldap.denied`; the sign-in name is recorded only when the directory found the entry.

**What to do.** Check the user name and password and try again. Administrators: find the `auth.ldap.denied` row of the attempt (its `reason` says why) and run **Test sign-in** on the directory to see the groups the directory returns.

## ALC-LDAP-0002: The directory cannot be used for sign-in right now

**Meaning.** A directory sign-in or confirmation could not be checked, because the directory could not be reached, its settings do not work (certificate, service account, base DN, filter, attribute) or sign-in through it is switched off. (HTTP 503, reason `ldap.directory_unavailable`.)

**Likely cause.** The directory server is down or the network path to port 636 is blocked, the service account's password changed, or an Administrator switched the directory off.

**What to do.** Try again later or choose another sign-in option. Administrators can still sign in with their local account and authenticator code; run **Test connection** on the directory to see where it stops.

## ALC-LDAP-0003: This directory has users

**Meaning.** Deleting a directory, or changing its unique ID attribute, was refused. Addresses can be changed at any time (adding one needs the service account password again). (HTTP 409, reason `ldap.directory_in_use`.)

**Likely cause.** People have signed in through this directory. Their accounts are tied to it and to the unique ID attribute.

**What to do.** Switch sign-in through the directory off instead.

## ALC-LDAP-0004: The connection test failed

**Meaning.** Test connection could not bind as the service account or search the user base DN. The answer names the reason and the step where it stopped, never the server's own text. (HTTP 422, reason `ldap.connection_test_failed`.)

**Likely cause.** A wrong address or port, a certificate the authority field does not trust (`tls`), a wrong service account DN or password (`service_bind`), a user base DN that does not exist (`user_search`), or a firewall (`connect`, `timeout`).

**What to do.** Check the addresses, the certificate authority, the service account and the user base DN, then test again.

## ALC-LDAP-0005: No more directories can be added

**Meaning.** Adding a directory was refused. (HTTP 409, reason `ldap.too_many_directories`.)

**Likely cause.** Alice works with at most 3 directories.

**What to do.** Delete a directory you no longer use, or change an existing one.

## ALC-LDAP-0006: The sign-in test failed

**Meaning.** Test sign-in was refused by the directory. Nobody was signed in and nothing was stored; the answer names the reason and the step where it stopped. (HTTP 422, reason `ldap.signin_test_failed`.)

**Likely cause.** A wrong user name or password (`bad_credentials`), a user filter that finds nobody (`not_found`) or several entries (`ambiguous_user`), or an entry without the unique ID attribute (`unique_id`).

**What to do.** Check the user name and password, the user filter and the sign-in name attribute, then test again.

## ALC-LDAP-0007: Set up your authenticator first

**Meaning.** A directory user's confirmation ("Confirm it's you") was refused after the directory accepted the password: no authenticator code could be checked. Nothing was counted as a failed attempt. (HTTP 409, reason `ldap.enrolment_required`.)

**Likely cause.** The directory asks for an authenticator code, and the user has none yet (for example after an Administrator reset it).

**What to do.** Sign out and sign in again: Alice then sets up the authenticator.

## ALC-LDAP-0008: Your account does not sign in through a directory

**Meaning.** A confirmation with a directory password was asked for an account that does not sign in through a directory. (HTTP 409, reason `ldap.not_directory_user`.)

**Likely cause.** Only directory users confirm with their directory password.

**What to do.** Confirm with your authenticator code instead.

## ALC-ROT-0001: This key already has a rotation policy

**Meaning.** Creating a rotation policy was refused because the key has one already. (HTTP 409, reason `rotation.policy_exists`.)

**Likely cause.** Each key has at most one rotation policy.

**What to do.** Change the existing policy on the key's page.

## ALC-ROT-0002: A rotation of this key is already running

**Meaning.** Run now, deleting a policy or creating a policy was refused because a rotation of the key is running. (HTTP 409, reason `rotation.in_progress`.)

**Likely cause.** Only one rotation runs for a key at a time. A policy with a running rotation cannot be deleted, and the new key of a running rotation cannot get a policy of its own.

**What to do.** Wait for the rotation to finish, or stop it on its page.

## ALC-ROT-0003: The servers or keys changed since the preview

**Meaning.** Run now was refused, or a planned run was cancelled, because the plan built now differs from the plan that was previewed. Nothing was changed on any server. (HTTP 409, reason `rotation.plan_changed`.)

**Likely cause.** A rotation runs only exactly as it was previewed, and something changed since then. Nothing was changed on any server. Typical changes: a server became unreachable or was scanned again, a key line was added or removed by hand, the policy's new key type changed.

**What to do.** Open the preview again, check it, and start the rotation from there. A scheduled run is previewed again with a new email.

## ALC-ROT-0004: No server can take part in this rotation

**Meaning.** Run now was refused because no place of the key can change. A scheduled run is not created either: the administrators get one email naming the skipped servers and reasons, and the policy moves on to its next interval. (HTTP 409, reason `rotation.nothing_to_rotate`.)

**Likely cause.** Every place where the key is used is skipped. The preview shows the reason for each.

**What to do.** Fix the reasons shown in the preview, scan the servers again, then try again.

## ALC-ROT-0005: This rotation is not waiting for that action

**Meaning.** A decision on a run (Continue, Finish now, Keep the old key, Stop and undo) was refused because the run is not in a state that takes it. Keep the old key is refused as a whole when one of the places named is not one Alice could not test, or when no place where the new key works would remain. (HTTP 409, reason `rotation.not_waiting`.)

**Likely cause.** The rotation has moved on, or the action does not apply in its current state.

**What to do.** Reload the page to see the current state.

## ALC-ROT-0006: Alice could not add the new key on a server, so it undid the rotation

**Meaning.** The result of a rotation that was undone because the new key could not be added on a server (also shown on that place). (HTTP 502, reason `rotation.add_failed`.)

**Likely cause.** A server refused the change or could not be reached. The old key was not touched anywhere.

**What to do.** See the failed server on the rotation's page, fix the problem, then start the rotation again.

## ALC-ROT-0007: The new key did not work on a server, so Alice undid the rotation

**Meaning.** The result of a rotation that was undone because a login with the new key failed on a server. (HTTP 502, reason `rotation.verify_failed`.)

**Likely cause.** Alice could not sign in with the new key there. The old key was not touched anywhere.

**What to do.** See the server on the rotation's page, check its SSH settings for that user, then start the rotation again.

## ALC-ROT-0008: Alice could not remove the new key from every server

**Meaning.** The result of a rotation that needs attention because undoing it did not remove the new key everywhere. (HTTP 502, reason `rotation.undo_failed`.)

**Likely cause.** Undoing the rotation failed on the servers listed on its page: they could not be reached, Alice could not read the key file completely (`ALC-ROT-0025`), or the old key was already gone there and Alice kept the new key so that the account keeps a working key (`ALC-ROT-0018`). The old key was not touched.

**What to do.** When those servers can be reached, remove the new key from them on the new key's page, once another key works for those accounts.

## ALC-ROT-0009: The old key was kept on some servers

**Meaning.** The result of a rotation that needs attention because the old key could not be removed on some servers after Alice tried several times. (HTTP 502, reason `rotation.remove_incomplete`.)

**Likely cause.** Before removing the old key, Alice checks the new key again. On the servers listed, that check or the removal failed, so the old key stays there.

**What to do.** Check those servers, then remove the old key from them on the old key's page. Both keys stay valid on those servers until a person removes one.

## ALC-ROT-0010: No decision was made within 14 days, so Alice undid the rotation

**Meaning.** The result of a rotation that was undone because no administrator decided about the places Alice could not test within 14 days (the time the rotation was paused for the license does not count). (HTTP 409, reason `rotation.decision_timeout`.)

**Likely cause.** Alice could not test the new key in some places and waited 14 days for an administrator.

**What to do.** Start the rotation again and decide about the places Alice cannot test.

## ALC-ROT-0011: The rotation is paused because the license has expired or could not be checked

**Meaning.** A rotation is paused because the license does not allow changes; the paused rotation is shown with this reason. (HTTP 409, reason `rotation.paused_license`.)

**Likely cause.** While the license does not allow changes, Alice adds no new key and removes no old key for this rotation, and the old key stays in place.

**What to do.** Upload a valid license, or wait until Alice can check it again, then choose Continue on the rotation's page. After the renewal Alice emails the administrators before anything continues; every removal is preceded by a fresh login with the new key.

## ALC-ROT-0012: The planned rotation was cancelled because the license did not allow changes when it was due

**Meaning.** The result of a planned run that was cancelled before it started because the license did not allow changes. (HTTP 409, reason `rotation.cancelled_license`.)

**Likely cause.** Alice starts no rotation while the license is expired or cannot be checked.

**What to do.** After a renewal, Alice plans the next run of a policy that is on with a new preview and email.

## ALC-ROT-0013: An administrator stopped the rotation

**Meaning.** The result of a rotation an administrator stopped with Stop and undo (or of a planned run stopped before it started). (HTTP 409, reason `rotation.stopped`.)

**Likely cause.** Alice removes the new key again where it had added it; the old key is not touched. The rotation's page shows where this is done.

**What to do.** Start the rotation again when you are ready.

## ALC-ROT-0014: The planned run was cancelled because the policy was switched off, changed or deleted

**Meaning.** The result of a planned run that was cancelled because its policy was switched off, changed or deleted before it started. (HTTP 409, reason `rotation.policy_off`.)

**Likely cause.** A policy that is off starts no run. Changing the interval, the overlap, the notice time or the new key type of a policy that is on switches it off.

**What to do.** Switch the policy on again to plan the next run.

## ALC-ROT-0015: The new key no longer worked when Alice checked it again, so the old key stays

**Meaning.** The error of a place where the login with the new key failed in the check just before the old key would have been removed. The old key stays there. (HTTP 502, reason `rotation.new_key_failed`.)

**Likely cause.** Just before removing the old key, Alice could not sign in with the new key on this server.

**What to do.** Check the new key on this server, then remove the old key on the old key's page when the new key works.

## ALC-ROT-0016: Alice gave up on this server after several attempts

**Meaning.** The error of a place where Alice gave up after five attempts of the same step. (HTTP 502, reason `rotation.retries_exhausted`.)

**Likely cause.** The work on this server was interrupted again and again (for example, by restarts).

**What to do.** Check the server and Alice's logs, then start the rotation again.

## ALC-ROT-0017: The planned rotation was cancelled because its notice email was not delivered in time

**Meaning.** The result of a scheduled run that was cancelled at its planned start because no preview email had been delivered to an administrator by then. Run now does not wait for an email. (HTTP 409, reason `rotation.notice_undelivered`.)

**Likely cause.** A scheduled rotation starts only after its preview email was delivered to at least one administrator before the planned start. Email is not set up, no administrator has an email address, or the mail server did not accept the message in time.

**What to do.** Check the email settings and the administrators' email addresses. The policy plans its next run one interval later; to rotate now, open the preview and choose Run now.

## ALC-ROT-0018: Alice kept the new key here because the old key is gone

**Meaning.** The error of a place where Alice did not remove the new key while undoing a rotation, because the old key was no longer in the file. The rotation needs attention. (HTTP 409, reason `rotation.old_key_gone`.)

**Likely cause.** While undoing the rotation, Alice found that the old key is no longer in this file, for example because someone removed it after switching to the new key. Removing the new key too could leave the account without a working key.

**What to do.** Find out who uses this account. Remove the new key on the new key's page only after another key works for it.

## ALC-ROT-0019: This rotation has too many places for one run

**Meaning.** Run now or a planned run was refused because the plan is too large for one run. (HTTP 409, reason `rotation.plan_too_large`.)

**Likely cause.** A run holds at most 10 000 places, and its stored plan must fit in 2 MiB. Nothing was created or changed.

**What to do.** Use separate keys for groups of servers and give each key its own policy.

## ALC-ROT-0020: Alice could not start the rotation, so it cancelled the run

**Meaning.** The result of a run that Run now created and could not start; Alice cancelled it in the same step. (HTTP 409, reason `rotation.start_failed`.)

**Likely cause.** Run now created the run, but starting it failed, for example because Alice was busy generating other keys. Nothing was changed on any server.

**What to do.** Choose Run now again in a moment.

## ALC-ROT-0021: Alice is still preparing the email about the license renewal

**Meaning.** Continue was refused because the email that tells the administrators about the license renewal has not been queued yet. The answer is retryable and carries `Retry-After`. (HTTP 409, reason `rotation.notice_pending`.)

**Likely cause.** After a renewal, Alice emails the administrators before a paused rotation may continue. The next background check queues that email, within about a minute. Nothing was changed.

**What to do.** Continue becomes available once the email about the renewal has been queued, usually within a minute.

## ALC-ROT-0022: A server's answer arrived after Alice had given up on it

**Meaning.** The reason of the email "Late answer in the SSH key rotation" and of the step **A late answer arrived after Alice had given up** on a place of a rotation: a server's definite answer to a removal (of the old key, or of the new key while undoing) arrived after Alice had stopped working on that place. The run's result does not change, the email is sent once per place, and Alice queues a scan of the server. (HTTP 409, reason `rotation.late_result`.)

**Likely cause.** Alice had stopped waiting for this place after several attempts. Its answer came later, so the rotation's record and the key file on the server may differ there.

**What to do.** Open the rotation's page and check the key file on this server, then scan the server again so that Alice lists its keys as they are.

## ALC-ROT-0023: Alice stopped working on this place because the database refused its records

**Meaning.** The error of a place where Alice stopped because the database refused to record its next step. The place ends failed; the rotation needs attention or is undone. (HTTP 409, reason `rotation.guard_refused`.)

**Likely cause.** The database's safety checks refused to record a step of this place, for example because the old key's place became Alice's own connection key after the removal was sent. Alice did nothing more there.

**What to do.** Check this place on the rotation's page and the server's keys, then report it together with Alice's logs.

## ALC-ROT-0024: This place was skipped when Alice was about to change it

**Meaning.** The error of a place that was cancelled, or whose add failed, when Alice was about to change it: the plan's skip reasons were checked again then. The place's skip reason names the cause. (HTTP 409, reason `rotation.skipped_at_send`.)

**Likely cause.** When Alice was about to send the change, the server's last scan showed a reason the plan skips; the place's skip reason names it. Alice sent nothing more there; if the new key had already been sent, undoing the rotation removes it again.

**What to do.** Fix the skip reason shown on the rotation's page, scan the server again, then start the rotation again.

## ALC-ROT-0025: Alice could not read this account's key file completely

**Meaning.** The error of a place that ended because Alice could not read that account's key file completely on its last attempts, so it could not tell whether a key is there. (HTTP 409, reason `rotation.listing_incomplete`.)

**Likely cause.** The file could not be read in full on every attempt (for example it is a symbolic link or not a regular file, it cannot be read, it is too large, or it holds a line Alice does not understand), so Alice could not prove whether a key is in it and stopped working on this place.

**What to do.** Make the file a readable regular file on the server, scan the server again, then start a new rotation.

## ALC-JOB-0001: Task is not waiting

**Meaning.** Only tasks paused by an expired license ("Waiting for an administrator") can be run, and only those and
tasks that have not started yet can be discarded (HTTP 409).

**Likely cause.** The task already ran or was discarded by someone else.

**What to do.** Reload the page.

## ALC-JOB-0002: Task interrupted

**Meaning.** A task's lease ran out because Alice stopped while running it; Alice queued it again (shown on the task).

**Likely cause.** A restart, an update or a lost database connection.

**What to do.** Nothing; if it happens often, find out why Alice restarts.

## ALC-JOB-0003: Task changed outside Alice

**Meaning.** A stored task failed its integrity check (HMAC), so Alice did not run it and recorded `job.tampered`.

**Likely cause.** Someone wrote to the `jobs` table directly.

**What to do.** Review database access; start the work again from its page.

## ALC-JOB-0004: Unknown task type

**Meaning.** A stored task has a type this Alice version does not know; it was not run.

**Likely cause.** Two Alice versions use the same database.

**What to do.** Run only one Alice version per database.

## ALC-JOB-0005: Same task already queued with other options

**Meaning.** A task of this kind is already queued for the same item with different options, so the new request was not
queued (HTTP 409).

**Likely cause.** Two people asked for the same work at almost the same time, for example removing the same key with
and without the confirmation for root's last key.

**What to do.** Wait until the queued task has finished, then try again.

## ALC-NGX-0001: Nginx not found

**Meaning.** Nginx was not found on this server. (HTTP 502, reason `nginx.not_found`.)

**Likely cause.** Alice looked for `/usr/sbin/nginx`, where the standard packages install it.

**What to do.** Install Nginx from your distribution or nginx.org, or add this server as a Linux server.

## ALC-NGX-0002: Nginx configuration has a problem

**Meaning.** Nginx's configuration has a problem, so Alice will not deploy to this server until it is fixed. (HTTP 409, reason `nginx.config_invalid`.)

**Likely cause.** Nginx's configuration has an error, or it uses files or settings Alice cannot safely read. Nothing was changed.

**What to do.** Run `nginx -t` on the server and fix any error. If it passes, check the file named on the server's page, then choose Discover again.

## ALC-NGX-0003: Nginx configuration changed

**Meaning.** The Nginx configuration changed since Alice last looked. (HTTP 409, reason `nginx.config_changed`.)

**Likely cause.** This website no longer uses the certificate and key files Alice found. Nothing was changed.

**What to do.** Choose Discover on the server's page, then deploy again.

## ALC-NGX-0004: Server not prepared for Nginx

**Meaning.** This server is not prepared for Nginx work. (HTTP 502, reason `nginx.profile_missing`.)

**Likely cause.** The Alice account may run `alice-helper` for SSH keys only (Linux profile), not for certificates.

**What to do.** On the Servers page choose Server type Nginx server, copy the commands and run them on the server again.

When the Nginx lines disappear from `/etc/sudoers.d/alice` after the last scan, a deployment cannot tell sudo's refusal
from a change that started (sudo may already have read the new key): it is not ended as this failure but goes to
**Confirming the outcome**, whose checks fail with this code until the commands are run again (after about a day it
ends **Outcome not confirmed**, `ALC-DEP-0018`). After any change to the sudoers file, choose **Test connection** and
**Discover** on the server's page before deploying.

## ALC-NGX-0005: Not enough free disk space

**Meaning.** The server does not have enough free disk space. (HTTP 502, reason `nginx.no_space`.)

**Likely cause.** Alice needs room for the new files and a backup of the old ones. Nothing was changed.

**What to do.** Free some space on the server, then deploy again.

## ALC-NGX-0006: Certificate file changed

**Meaning.** The certificate file changed since Alice last looked. (HTTP 409, reason `nginx.file_changed`.)

**Likely cause.** Someone or another tool replaced the file after the last discovery. Nothing was changed.

**What to do.** Choose Discover on the server's page, check the website, then deploy again.

## ALC-NGX-0007: Certificates cannot be changed here

**Meaning.** Alice cannot change certificates at this place. (HTTP 409, reason `nginx.location_unsupported`.)

**Likely cause.** The website's certificate setup is one Alice does not support, its files no longer meet Alice's safety rules (for example a folder that users other than root can change), or the website no longer uses this file. Nothing was changed.

**What to do.** Choose Discover on the server's page to see the reason next to the website, and change the setup on the server if you want Alice to manage it.

## ALC-NGX-0008: Another certificate change is running

**Meaning.** Another certificate change is running on this server. (HTTP 409, reason `nginx.busy`.)

**Likely cause.** `alice-helper` changes one website at a time on a server.

**What to do.** Wait a minute and try again.

## ALC-NGX-0009: Server could not complete the file work

**Meaning.** The server could not complete the file work. Nothing was changed. (HTTP 502, reason `nginx.io_error`.)

**Likely cause.** `alice-helper` reported an input or output error before it replaced any file, for example a folder it cannot write, a read-only file system, or Nginx stopping while it was checked.

**What to do.** Check the server's disks and certificate folders, then deploy again.

## ALC-NGX-0010: Nginx not running

**Meaning.** Nginx is not running on the server. Nothing was changed. (HTTP 502, reason `nginx.not_running`.)

**Likely cause.** `alice-helper` checks before it changes any file that `/usr/bin/systemctl` exists and that `systemctl is-active nginx` succeeds; otherwise a reload could not apply the new certificate. Nginx was stopped or failed, or the server does not use systemd.

**What to do.** Run `systemctl status nginx` on the server, start Nginx (`systemctl start nginx`), then deploy again.
A server that runs Nginx under another systemd unit name, or without systemd, cannot be deployed to (a known
limitation).

## ALC-APC-0001: Apache not found

**Meaning.** Apache was not found on this server. (HTTP 502, reason `apache.not_found`.)

**Likely cause.** Alice looked for `/usr/sbin/apache2ctl` (Debian, Ubuntu) and `/usr/sbin/httpd` (Red Hat family), where the standard packages install Apache.

**What to do.** Install Apache from your distribution or add this server as a Linux server. [apache-host-preparation.md](apache-host-preparation.md) lists what Alice expects.

## ALC-APC-0002: Apache configuration has a problem

**Meaning.** Apache's configuration has a problem, so Alice cannot read this server's certificates until it is fixed. (HTTP 409, reason `apache.config_invalid`.)

**Likely cause.** Apache's configuration has an error, or it uses files or settings Alice cannot safely read. Nothing was changed.

**What to do.** Run `apache2ctl -t` (Debian, Ubuntu) or `httpd -t` (Red Hat family) on the server and fix any error. If it passes, check the file named on the server's page and [apache-host-preparation.md](apache-host-preparation.md), then choose Discover again.

## ALC-APC-0003: Server not prepared for Apache

**Meaning.** This server is not prepared for Apache work. (HTTP 502, reason `apache.profile_missing`.)

**Likely cause.** The Alice account may run `alice-helper` for SSH keys only (Linux profile), not for Apache.

**What to do.** On the Servers page choose Server type Apache server, copy the commands and run them on the server again. [apache-host-preparation.md](apache-host-preparation.md) describes the preparation.

## ALC-APC-0004: alice-helper too old for Apache

**Meaning.** The `alice-helper` on this server is too old to read Apache. (HTTP 502, reason `apache.helper_too_old`.)

**Likely cause.** Reading Apache needs `alice-helper` 1.7.0 or newer, and the one installed on the server is older.

**What to do.** The Apache profile needs `alice-helper` 1.7.0 or newer. On the Servers page choose Server type Apache server, copy the commands and run them on the server again to install it. [apache-host-preparation.md](apache-host-preparation.md) describes the steps.

## ALC-CRT-0001: Not a readable certificate

**Meaning.** This is not a certificate Alice can read. (HTTP 422, reason `certificate.invalid`.)

**Likely cause.** Alice expects PEM text with `BEGIN CERTIFICATE` blocks, or a PFX file. During a deployment, the stored certificate could not be sent to the server in that form.

**What to do.** When uploading, check that you chose the certificate file, not a request or another file. After a deployment, look at the deployment's steps: if the certificate file itself is at fault, upload a corrected certificate and deploy that one. If it happens again, report the request ID.

## ALC-CRT-0002: Certificate and key do not match

**Meaning.** The certificate does not match its private key. (HTTP 422, reason `certificate.key_mismatch`.)

**Likely cause.** When uploading: the private key belongs to another certificate. During a deployment: after the new files were written, `nginx -t` reported that a certificate and its key file on the server do not belong together.

**What to do.** When uploading, use the key that was created together with this certificate. After a deployment, check which certificate and key files the websites on this server use; the deployment's status shows whether the previous files are back.

## ALC-CRT-0003: Certificate expired

**Meaning.** This certificate has already expired. (HTTP 422, reason `certificate.expired`.)

**Likely cause.** Its validity period has ended, so browsers would refuse it.

**What to do.** Get a renewed certificate from your certificate authority and upload that one.

## ALC-CRT-0004: Private key protected with a password

**Meaning.** The private key is protected with a password. (HTTP 422, reason `certificate.key_encrypted`.)

**Likely cause.** Alice cannot store a key it cannot read.

**What to do.** Remove the password from the key, or upload a PFX file and enter its password.

## ALC-CRT-0005: Wrong PFX password

**Meaning.** The PFX password is wrong or the file is damaged. (HTTP 422, reason `certificate.pfx_password`.)

**Likely cause.** Alice could not open the PFX file with this password.

**What to do.** Check the password, or export the PFX file again.

## ALC-CRT-0006: Weak key or signature

**Meaning.** This certificate or one in its chain uses a weak key or signature. (HTTP 422, reason `certificate.weak`.)

**Likely cause.** RSA keys shorter than 2048 bits and MD5 or SHA-1 signatures are no longer safe.

**What to do.** Ask your certificate authority for a certificate with a stronger key and a SHA-256 signature.

## ALC-CRT-0007: Key type not supported

**Meaning.** Alice supports RSA and ECDSA certificates only. (HTTP 422, reason `certificate.unsupported_key`.)

**Likely cause.** This certificate uses another key type (for example Ed25519), another curve, or an RSA key larger than 16384 bits.

**What to do.** Use a certificate with an RSA key of 2048 to 16384 bits, or an ECDSA P-256 or P-384 key.

## ALC-CRT-0008: Certificate already stored

**Meaning.** Alice already has this certificate with its key. (HTTP 409, reason `certificate.duplicate`.)

**Likely cause.** This certificate and its key are already stored, from an earlier upload or a signing request.
One upload of a stored certificate is accepted: when the chain Alice holds is incomplete and the upload brings the
certificate with its complete chain (and its key), Alice completes the stored chain instead (answer "chain
completed", audit `certificate.chain_completed`). A certificate from a signing request cannot be uploaded (its key
never leaves Alice), so its chain cannot be completed this way.

**What to do.** Open the certificate in the list and deploy it from there.

## ALC-CRT-0009: Private key not held

**Meaning.** Alice does not have the private key of this certificate. (HTTP 409, reason `certificate.no_private_key`.)

**Likely cause.** Alice found this certificate on a server, and private keys are never read from servers.

**What to do.** Upload the certificate together with its key, then deploy it.

## ALC-CRT-0010: Key type does not fit this place

**Meaning.** This certificate's key type does not fit this place. (HTTP 409, reason `certificate.key_type_mismatch`.)

**Likely cause.** Key type the website uses here: `<expected>`. Key type of this certificate: `<actual>`.

**What to do.** Choose a certificate with the same key type, or the website's other certificate place.

## ALC-CRT-0011: Incomplete chain needs an administrator

**Meaning.** An administrator must confirm the incomplete chain of this certificate. (HTTP 409, reason `certificate.chain_unconfirmed`.)

**Likely cause.** The certificate chain does not reach a trusted root, so some browsers may not trust it.

**What to do.** Ask an administrator to deploy it and confirm the chain. For a Key Vault version, Alice knows the chain is incomplete after it read the version once; from then on **Deploy now** asks for the confirmation, also after the version was released (releasing does not confirm the chain).

## ALC-CRT-0012: Signing request no longer open

**Meaning.** This signing request is no longer open. (HTTP 409, reason `csr.not_pending`.)

**Likely cause.** It was completed or cancelled.

**What to do.** Create a new signing request if you need one.

## ALC-CRT-0013: Certificate not issued for this request

**Meaning.** This certificate was not issued for this signing request. (HTTP 422, reason `csr.certificate_mismatch`.)

**Likely cause.** Its public key is not the one Alice created for the request.

**What to do.** Paste the certificate your certificate authority returned for this request.

## ALC-CRT-0014: Certificate not valid yet

**Meaning.** This certificate is not valid yet. (HTTP 409, reason `certificate.not_yet_valid`.)

**Likely cause.** Its validity period has not started, so browsers would refuse it.

**What to do.** Deploy it once its validity period has started, or check the clock of the Alice host.

## ALC-CRT-0015: Busy reading other PFX files

**Meaning.** Alice is busy reading other PFX files. (HTTP 503, reason `certificate.pfx_busy`.)

**Likely cause.** Alice reads at most two PFX files at a time, and that limit was reached: an upload, or a Key Vault deployment reading a PFX secret at its step "Read the certificate from Key Vault" (that step tries again before it fails). Nothing was stored or sent to a server.

**What to do.** Wait a moment and try again: upload the file again, or deploy the vault certificate again.

## ALC-CRT-0016: Busy creating other signing requests

**Meaning.** Alice is busy creating other signing requests. (HTTP 503, reason `csr.busy`.)

**Likely cause.** Alice creates the keys of at most two signing requests at a time (an RSA 4096 key takes about a second of one processor core), and that limit was reached. Nothing was stored.

**What to do.** Wait a moment and create the signing request again.

## ALC-CRT-0017: Too many open signing requests

**Meaning.** There are too many open signing requests. (HTTP 409, reason `csr.too_many_pending`.)

**Likely cause.** Alice keeps at most 1000 open signing requests for the whole installation, all users together (each holds a private key that waits for its certificate), and that limit was reached. Nothing was created.

**What to do.** Complete or cancel the signing requests you no longer need (under **Open signing requests** on the Certificates page), then create this one again.

## ALC-DEP-0001: Deployment already in progress

**Meaning.** Another deployment to this website is in progress. (HTTP 409, reason `deployment.in_progress`.)

**Likely cause.** Alice runs one deployment per certificate file at a time.

**What to do.** Wait until it finishes; its progress is in the deployment history.

## ALC-DEP-0002: Earlier deployment still being finished

**Meaning.** Alice is still finishing an earlier deployment on this server. (HTTP 409, reason `deployment.recovery_pending`.)

**Likely cause.** An earlier deployment on this server did not end normally, and Alice must first find out how it ended and finish it. The server's helper gives the same answer when an earlier change of the same files that Alice is still finishing blocks them.

**What to do.** Wait until that deployment shows its result in the deployment history, then deploy again. (When the blocking change is one Alice no longer follows, the deployment ends with `ALC-DEP-0023` or `ALC-DEP-0024` instead.)

## ALC-DEP-0003: Website still serves the previous certificate

**Meaning.** The website still serves the previous certificate. (HTTP 502, reason `deployment.verify_failed`.)

**Likely cause.** After the change the website kept serving the previous certificate, for example because the website's configuration sends this name to another website, or Nginx was not reloaded. The deployment's status shows whether the previous files are back.

**What to do.** Check which part of the Nginx configuration answers for this website's name, then deploy again.

## ALC-DEP-0004: Served certificate could not be confirmed

**Meaning.** Alice could not confirm which certificate the website serves. (HTTP 502, reason `deployment.verify_other`.)

**Likely cause.** The website served a certificate that is neither the previous nor the new one (for example from a load balancer in front of it), or Alice has not read the website's current certificate yet. The deployment's status shows whether anything was changed.

**What to do.** Choose Discover on the server's page. If the website is behind another server, an administrator can set the port and name to check in its verification settings.

## ALC-DEP-0005: Website could not be reached for the check

**Meaning.** Alice could not reach the website on port `<port>`. (HTTP 502, reason `deployment.verify_unreachable`.)

**Likely cause.** Neither Alice nor the server itself could connect to the website, or the website has no HTTPS address Alice can check. The certificate it serves could not be checked. The deployment's status shows whether anything was changed.

**What to do.** Allow Alice to reach this port, or ask an administrator to change the website's verification settings.

When the website's `listen` names a host name that resolves to an address other than 127.0.0.1, no firewall change
helps: Alice cannot check such a website. Change the `listen` to an IP address or to a plain port, or turn the check
off in its verification settings (see [Deployments](#deployments)).

## ALC-DEP-0006: Nginx did not reload

**Meaning.** Nginx did not reload. (HTTP 502, reason `deployment.reload_failed`.)

**Likely cause.** `systemctl reload nginx` failed after the new files were written. The deployment's status shows whether the previous files are back.

**What to do.** Run `systemctl status nginx` on the server to see why, then deploy again.

## ALC-DEP-0007: Nginx rejected the new files

**Meaning.** Nginx rejected the new files. (HTTP 502, reason `deployment.config_test_failed`.)

**Likely cause.** `nginx -t` failed after the new certificate and key were written. The deployment's status shows whether the previous files are back.

**What to do.** Check the certificate file format and the chain, then deploy again.

## ALC-DEP-0008: Previous certificate not confirmed back

**Meaning.** Alice could not confirm that the previous certificate is back. Manual action is needed. (HTTP 502, reason `deployment.rollback_failed`.)

**Likely cause.** The deployment failed, and putting the previous certificate and key back did not finish or could not be confirmed. A backup of the previous files is on the server in `/var/lib/alice-helper/backups`, in the folder named with this deployment's ID.

A deployment may show `ALC-DEP-0019` (the files are back but the website was not confirmed) or `ALC-DEP-0020` (another program changed the files) instead; a task (job) record always shows this code.

**What to do.** Check the website now. Compare the files with the backup on the server, then run `nginx -t` and `systemctl reload nginx`.

## ALC-DEP-0009: Files restored but Nginx did not reload

**Meaning.** Files are back in place but Nginx did not reload. (HTTP 502, reason `deployment.rollback_reload_failed`.)

**Likely cause.** Alice restored the previous certificate and key, but `systemctl reload nginx` failed afterwards.

**What to do.** Run `systemctl status nginx` on the server, fix the cause, then reload Nginx.

## ALC-DEP-0010: Deployment did not finish normally

**Meaning.** The deployment did not finish normally. (HTTP 502, reason `deployment.interrupted`.)

**Likely cause.** While the deployment ran, the connection to the server was lost, Alice restarted, or the server could not finish writing the files. The deployment's status shows which certificate the server has; if Alice does not know yet, it keeps checking.

**What to do.** Check the deployment history. Once it shows a result, deploy again if needed.

## ALC-DEP-0011: Server not ready for a deployment

**Meaning.** Alice cannot deploy to this server now. (HTTP 409, reason `deployment.target_not_ready`.)

**Likely cause.** The server is not connected: its host key fingerprint is not confirmed or has changed, Alice cannot sign in, or the server is disabled.

**What to do.** Open the server's page, solve the problem shown there, then deploy again.

## ALC-DEP-0012: Website serves a different chain

**Meaning.** The website serves the expected certificate with a different chain (port `<port>`). (HTTP 502, reason `deployment.verify_chain`.)

**Likely cause.** The number of certificates the website sends differs from the chain Alice expected, for example because another file or a proxy adds or drops intermediate certificates. The deployment's status shows whether anything was changed.

**What to do.** Check which certificate files this website's configuration uses, then deploy again.

## ALC-DEP-0013: Nothing to restore

**Meaning.** There was nothing to restore. (HTTP 502, reason `deployment.nothing_to_restore`.)

**Likely cause.** `alice-helper` found that this deployment had not changed any file, so there was nothing to put back.

**What to do.** Check the deployment's result in the deployment history, then deploy again if needed.

## ALC-DEP-0014: A later change replaced the files

**Meaning.** A later change replaced the files, so Alice did not restore them. (HTTP 502, reason `deployment.superseded`.)

**Likely cause.** While Alice was finishing this deployment, a later operation on the server replaced the certificate files. Alice cannot tell what they hold now.

**What to do.** Check which certificate the website serves now, then choose Discover on the server's page.

## ALC-DEP-0015: Server has no record of the deployment

**Meaning.** The server has no record of this deployment. (HTTP 502, reason `deployment.unknown_operation`.)

**Likely cause.** `alice-helper` has no record of this deployment, for example because it never received it or because it removed the record after 7 days or more.

**What to do.** Check which certificate the website serves now, then choose Discover on the server's page.

## ALC-DEP-0016: Server deleted during the deployment

**Meaning.** The server was deleted before the deployment finished. (HTTP 409, reason `deployment.target_deleted`.)

**Likely cause.** The server was removed from Alice while this deployment was waiting or running. If a change had already reached the server, Alice cannot check it any more.

**What to do.** If the server still exists, check its website and the certificate files on it.

## ALC-DEP-0017: Alice stopped trying to finish the deployment

**Meaning.** Alice stopped trying to finish this deployment. Manual action is needed. (HTTP 502, reason `deployment.recovery_exhausted`.)

**Likely cause.** For about a day Alice could not find out how the deployment ended, usually because it could not reach the server. If the change reached the server, a backup of the previous files is there in `/var/lib/alice-helper/backups`, in the folder named with this deployment's ID.

**What to do.** Check the website and the server's connection now, then choose Discover on the server's page.

## ALC-DEP-0018: Outcome of the deployment unknown

**Meaning.** Alice cannot tell how this deployment ended. Manual action is needed. (HTTP 502, reason `deployment.outcome_unknown`.)

**Likely cause.** Alice no longer has the records it needs to check or undo this deployment. If the change reached the server, a backup of the previous files is there in `/var/lib/alice-helper/backups`, in the folder named with this deployment's ID.

**What to do.** Check the website now, then choose Discover on the server's page.

## ALC-DEP-0019: Files restored but the website was not confirmed

**Meaning.** The previous files are back, but the website was not confirmed. (HTTP 502, reason `deployment.restored_unverified`.)

**Likely cause.** Alice put the previous certificate and key back, but then could not confirm that the website serves the previous certificate again.

**What to do.** Check the website now. If it is wrong, run `nginx -t` and `systemctl reload nginx` on the server.

## ALC-DEP-0020: Files changed by another program during the deployment

**Meaning.** Another program changed the certificate files during the deployment. Manual action is needed. (HTTP 502, reason `deployment.rollback_file_changed`.)

**Likely cause.** While Alice was deploying or putting the previous files back, another program changed the certificate or key file. Alice never overwrites that program's file: it put back at most the files it had written itself, so the certificate and key on the server may not belong together now. A backup of the previous files is on the server in `/var/lib/alice-helper/backups`, in the folder named with this deployment's ID.

**What to do.** Run `nginx -t` on the server now: if it fails, the certificate and key do not belong together. Find out which program changed the files (for example certbot), put a matching pair back from that program or from the backup, check the website, then choose Discover on the server's page. Do not restore the backup over the other program's file without checking which certificate is meant to be there (see the deployment points above).

## ALC-DEP-0021: Files must be read again first

**Meaning.** Alice must read this website's files again before deploying. (HTTP 409, reason `deployment.rescan_needed`.)

**Likely cause.** Alice does not know the current content of the certificate file, which it needs to make sure nobody changed the file in the meantime.

**What to do.** Choose Discover on the server's page, then deploy again.

## ALC-DEP-0022: Deployment cancelled by an administrator

**Meaning.** An administrator cancelled this deployment before anything was sent to the server. (HTTP 409, reason `deployment.cancelled`.)

**Likely cause.** An administrator chose **Discard** for the deployment's waiting job (for example a job held while the license was expired), so Alice sent nothing to the server. The website keeps its previous certificate, and no failure email is sent.

**What to do.** Deploy the certificate again if it is still needed.

## ALC-DEP-0023: An unfinished change of the files on the server stops new changes

**Meaning.** An unfinished change of these certificate files on the server stops new changes. The server refused the deployment because an earlier change of the same certificate and key files did not finish there; this deployment's certificate was not written. (HTTP 409, reason `deployment.server_operation_pending`; the parameter `operation_id` names the unfinished change.)

**Likely cause.** An earlier change was interrupted on the server (for example the helper was killed between writing the key and the certificate) and Alice no longer follows it, and `alice-helper` refuses new changes of those files until that change is undone. Alice undoes such a change by itself, once, only when it does not know the change at all (the server was deleted and added again, or Alice's database was restored from a backup) or knows it as a deployment of this same website whose outcome was not confirmed; it then deploys again. This message means one of:

- Alice does not undo that change because it knows it otherwise: from another website, or as a change that ended normally.
- Alice tried and the undo did not finish (the step **recover_pending** in the deployment's history shows it failed). It may have put back one of the two files.
- The change's record on the server cannot be read (see below).

**Where to find the operation id.** Open the deployment in **Deployments**: the error's details show `operation_id`, and so does the step **recover_pending** if Alice tried the undo. It is a deployment ID; if Alice still has a deployment with that ID, the history shows it.

**What to do.** On the server, as root:

1. Run `/usr/local/libexec/alice-helper nginx-restore --op <operation_id>` and read its answer. A `restored` phase means the files from before that change are back.
2. Run `nginx -t` and, if it passes, `systemctl reload nginx`.
3. In Alice choose **Discover** on the server's page, then deploy again.

If `nginx-restore` answers `IO_ERROR`, the change's record (`/var/lib/alice-helper/backups/<operation_id>/journal.json`) usually cannot be read, typically one written by an older helper for a file name the helper no longer accepts. The helper keeps such a record, and keeps refusing changes of those files, for 30 days; `cleanup --op` refuses to remove it. `IO_ERROR` is also the helper's answer to a disk or permission problem, so first check that `journal.json` exists in that folder and is either not valid JSON or names a file the helper refuses; if the file reads normally, look for a full disk or changed permissions under `/var/lib/alice-helper` instead and do not continue with the steps below. To unblock the files before the 30 days pass, by hand:

1. **Warning: this folder holds the previous private key.** Copy the whole folder somewhere only root can read first, for example `cp -a /var/lib/alice-helper/backups/<operation_id> /root/alice-backup-<operation_id>`.
2. Find the certificate and key files of the website (from the Nginx configuration, or `cat journal.json` if it can still be read as text). Check that they belong together: `openssl x509 -in <certificate file> -noout -pubkey` and `openssl pkey -in <key file> -pubout` must print the same key. If they do not, put back both previous files from `cert.bak` and `key.bak` in that folder with the owner, group and mode the current files have (`install -o … -g … -m … key.bak <key file>`, the key first; see [nginx-host-preparation.md](nginx-host-preparation.md#restoring-a-previous-certificate-by-hand)), and check again.
3. Run `nginx -t` and `systemctl reload nginx`.
4. Remove the change's folder: `rm -r /var/lib/alice-helper/backups/<operation_id>`. Only this removal unblocks the files (the helper then no longer finds an unfinished change for them). Do not remove any other folder.
5. In Alice choose **Discover**, then deploy again.

## ALC-DEP-0024: Alice undid an unfinished earlier change; the certificate was not deployed

**Meaning.** An earlier change of the same certificate and key files on the server did not finish, and Alice no longer followed it. Alice put back the files that change had replaced, so the website now serves the certificate from before that change; the certificate of this deployment was not written. (HTTP 409, reason `deployment.pending_change_restored`, status rolled back; the parameter `operation_id` names the earlier change, and the deployment's history shows the step `recover_pending`.)

**Likely cause.** The earlier change was interrupted on the server (for example the helper was killed after replacing the files), and Alice had stopped following it: its outcome was recorded as unknown, the server was deleted and added again, or Alice's database was restored. The new deployment found the files blocked, restored them, and then could not write its own certificate, typically because the files no longer held what Alice had last read (it had read the earlier change's files).

**What to do.** Choose **Discover** on the server's page so that Alice reads the files again, then deploy the certificate again.

## ALC-AKV-0001: Azure sign-in refused

**Meaning.** Azure refused Alice's sign-in with the details of this vault (the parameter `aadsts` carries Entra's AADSTS number when Azure sent one). (HTTP 502, reason `azure.auth_failed`.)

**Likely cause.** A wrong tenant ID, application ID, secret or certificate; a secret that was deleted and re-created; an application that belongs to another directory (reason `tenant_mismatch`); a certificate that is not registered with the application. `AADSTS7000215` is a wrong secret, `AADSTS700016` an unknown application, `AADSTS90002` an unknown tenant, `AADSTS700027` a certificate Azure does not know.

**What to do.** Open the vault in Alice and choose **Replace credentials**. Copy the directory (tenant) ID and the application (client) ID from the application's overview page in Azure. For a secret, copy its **value** (not its ID) right after creating it; for a certificate, upload the certificate that is registered under the application's **Certificates & secrets**. After three failed sign-ins in a row Alice emails the administrators once.

## ALC-AKV-0002: Azure sign-in secret expired

**Meaning.** The client secret or certificate Alice signs in with has expired (`AADSTS7000222`). (HTTP 502, reason `azure.credentials_expired`.)

**Likely cause.** Azure secrets and certificates have an end date. The vault page shows the secret's end date as it was typed when the vault was added (Alice cannot read it from Azure), or the sign-in certificate's expiry date, and warns from 30 days before.

**What to do.** Create a new secret or certificate for the application in Azure, then choose **Replace credentials** on the vault's page in Alice. Websites keep serving their current certificates in the meantime; only new versions are not noticed.

## ALC-AKV-0003: Missing permission in the vault

**Meaning.** Alice is signed in to Azure, but the vault refuses what Alice tried. The parameter `role` names the Azure role that would allow it and `model` says whether the vault uses Azure roles (`rbac`) or access policies (`access_policy`). (HTTP 502, reason `azure.forbidden`.)

**Likely cause.** Alice's identity lacks a role on this vault. The vault page's **Access check** shows which row is not allowed. Alice needs `Key Vault Reader` to list and monitor certificates, keys and secrets; `Key Vault Secrets User` to read a certificate's private key when it deploys to a website (F-41: before anything is sent to a server); `Key Vault Certificates Officer` to import a certificate into the vault.

**What to do.** Ask your Azure administrator to assign the role named in the message to Alice's identity on this vault (the vault's page shows the object ID Alice signs in as). The vault's page lists the commands under **Roles Alice needs**, with the client ID and the vault's name filled in, for example `az role assignment create --role "Key Vault Secrets User" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)/secrets/<certificate-name>"`; all of them, and the access-policy commands for a vault that does not use Azure roles, are in [azure-setup.md](azure-setup.md#2-roles). Role assignments can take a few minutes to apply; then choose **Check again** under **Access check** on the vault's page. Alice cannot confirm that `Key Vault Reader` alone is enough on every vault: it is expected to be, and the access check tells.

## ALC-AKV-0004: Vault firewall blocks Alice

**Meaning.** The vault's own firewall refused the connection from this Alice server (the parameter `client_address` names the address the vault saw, when Azure told). (HTTP 502, reason `azure.firewall`.)

**Likely cause.** The vault allows only selected networks, and the address of this Alice server is not among them.

**What to do.** Add the address to the vault's **Networking** allow list in Azure, or reach the vault through a private endpoint (the vault's name must then resolve to the endpoint's address on this Alice server; see [azure-setup.md](azure-setup.md#3-network)). When a check of the vault was refused, the vault's page shows the address under **Alice's address as the vault saw it**. Then choose **Check now**. (The form of Azure's firewall answer is not yet confirmed on a real vault; if Azure answers differently, a firewall refusal may read as a missing permission, `ALC-AKV-0003`, with no address.)

## ALC-AKV-0005: Vault not found

**Meaning.** The vault's address could not be found. (HTTP 502, reason `azure.vault_not_found`.)

**Likely cause.** A misspelled name, a vault that was deleted (or is soft-deleted and purged), or a private endpoint whose name does not resolve on the Alice server.

**What to do.** Check the name against the vault's overview page in Azure (it must end in `.vault.azure.net`). With a private endpoint, make sure the Alice server's DNS resolves the vault's name to the endpoint.

## ALC-AKV-0006: Cannot reach Azure

**Meaning.** Alice could not connect to Azure or to the vault. Nothing was changed. (Retryable.) (HTTP 502, reason `azure.unreachable`.)

**Likely cause.** A network problem between this Alice server and `login.microsoftonline.com` or the vault (port 443), a DNS failure, or an Azure outage.

**What to do.** Check that the Alice server reaches both hosts on port 443 and that DNS works. Alice tries again at the vault's next check; the vault shows **Cannot reach Azure** until then.

## ALC-AKV-0007: Azure asked Alice to slow down

**Meaning.** Azure asked Alice to slow down (HTTP 429). Alice waits as Azure says and tries again. (Retryable.) (HTTP 503, reason `azure.throttled`.)

**Likely cause.** Many requests to the same vault or tenant in a short time, possibly from other programs.

**What to do.** Nothing, unless this continues for an hour: then reduce other programs' use of the vault, or raise the vault's check interval.

## ALC-AKV-0008: Unexpected answer from Azure

**Meaning.** Azure answered in a way Alice does not understand. Nothing was changed. (Retryable.) (HTTP 502, reason `azure.unexpected_response`.)

**Likely cause.** A temporary Azure fault (a 5xx answer, a cut-off body), a proxy that changes answers, or a change in Azure that Alice does not know yet.

**What to do.** Wait for the next check. If this continues, quote the request ID shown with the message (and the Azure request ID in the parameter `azure_request_id`, when present) to your administrator.

## ALC-AKV-0009: Server clock rejected by Azure

**Meaning.** Azure rejected the sign-in because the clock of the Alice server is too far from the true time (`AADSTS700024`). (HTTP 502, reason `azure.clock_skew`.)

**Likely cause.** The Alice server's time is wrong, for example a virtual machine that was suspended.

**What to do.** Correct the time of the Alice server (run an NTP client), then choose **Check now**.

## ALC-AKV-0010: Managed identity not available

**Meaning.** Alice could not get a managed identity from the machine it runs on. (HTTP 502, reason `azure.managed_identity_unavailable`.)

**Likely cause.** Managed identity works only on an Azure virtual machine that has a managed identity assigned; Alice reads it from the machine's own metadata address (169.254.169.254) and nowhere else. App Service, Azure Arc and other hosts that offer an identity through another endpoint are not supported.

**What to do.** Assign a system-assigned or user-assigned managed identity to the machine in Azure (for a user-assigned one, enter its application ID in Alice), give it the vault roles, or replace the credentials with a certificate or a client secret.

## ALC-AKV-0011: Azure address not allowed

**Meaning.** Alice refused to connect to an address that is not Azure's, or its own environment holds a setting that is not allowed. (HTTP 502, reason `azure.address_not_allowed`.)

**Likely cause.** Alice connects only to `login.microsoftonline.com` and to the vault's own address (for a managed identity also to the machine's metadata address), and follows no redirect or link to another host. When one of these names resolves to a link-local or metadata address (such as 169.254.169.254), or to a multicast, unspecified or reserved address, Alice refuses to connect; private addresses (a private endpoint) are allowed. This message also appears when `AZURE_REGIONAL_AUTHORITY_NAME`, `MSAL_FORCE_REGION` or `AZURE_SDK_GO_LOGGING` is set in Alice's environment: Alice refuses to sign in to Azure then. The region variables (`AZURE_REGIONAL_AUTHORITY_NAME`, `MSAL_FORCE_REGION`) send the sign-in to another host; `AZURE_SDK_GO_LOGGING` makes the Azure library print Azure's answers to the log, which Alice never allows.

**What to do.** Check what the vault's name and `login.microsoftonline.com` resolve to on the Alice server (a private endpoint's address is allowed). Ask whoever runs Alice to remove the three variables above from Alice's environment (compose file, service unit or orchestrator) and restart Alice: the check is made when Alice starts a session, so a running Alice keeps failing until it is restarted with the variables gone.

## ALC-AKV-0012: Azure's certificate is not trusted

**Meaning.** The certificate Azure presented is not trusted by this Alice server. (HTTP 502, reason `azure.tls_untrusted`.)

**Likely cause.** A proxy or firewall that inspects TLS and replaces Azure's certificate, a missing CA bundle in the container, or a wrong clock on the Alice server. Alice trusts the certificate authorities of its container's operating system; this version has no setting to add a company root for Azure.

**What to do.** Let Alice reach Azure directly, or exempt `login.microsoftonline.com` and the vault's name from inspection. Check the server's time.

## ALC-AKV-0013: Private key not exportable

**Meaning.** The vault certificate's private key is marked non-exportable, so Alice cannot read it from the vault and cannot copy it to a server. A connection to websites, automatic deployment and **Deploy now** are refused for it. (HTTP 422, reason `kv.not_exportable`.)

**Likely cause.** The certificate's policy in Key Vault has **Exportable private key** turned off (or the key is in a managed HSM), or a read of its secret came back without a key (Alice then marks it itself; a later check that finds the key exportable clears the mark).

**What to do.** Create a new version with an exportable key (change the policy, then renew), or use a different certificate. A monitor-only certificate still shows its versions and expiry.

## ALC-AKV-0014: Version disabled in Key Vault

**Meaning.** The version is disabled in Key Vault, so Alice did not deploy it. (HTTP 409, reason `kv.version_disabled`.)

**Likely cause.** Someone disabled the version in Key Vault. (An expired version is refused with `ALC-CRT-0003` instead.)

**What to do.** Enable the version in Key Vault and choose **Check now**, or deploy another version.

## ALC-AKV-0015: Certificate no longer in the vault

**Meaning.** The certificate no longer exists in the vault (or the vault's list no longer shows it). (HTTP 409, reason `kv.certificate_not_found`.)

**Likely cause.** It was deleted (or soft-deleted) in Key Vault.

**What to do.** Restore (recover) it in Key Vault and choose **Check now**, or remove its connection to websites. Websites keep their current certificate.

## ALC-AKV-0016: Certificate data could not be read

**Meaning.** The certificate data Alice read from the vault could not be used. Nothing was changed on any server. (HTTP 502, reason `kv.secret_unreadable`.)

**Likely cause.** The vault returned a certificate without a private key, a content type that is neither PFX nor PEM, an empty or too large value, or a key that does not fit its certificate.

**What to do.** Check the certificate's content type and policy in Key Vault (PFX or PEM, exportable key), create a new version if needed, and deploy again. When the secret had no private key, the key is not exportable: Alice marks the certificate **Monitor only** when it recognises a value without a key (the form Azure sends is not yet confirmed on a real vault), and the next request answers ALC-AKV-0013 until Alice sees an exportable key again (a new version, or the certificate's policy on a later check). If the certificate is not marked **Monitor only**, check the content type and whether the key is exportable.

## ALC-AKV-0017: Vault data does not match the version

**Meaning.** What the vault returned is not the version Alice recorded (another leaf certificate, thumbprint or key type). Nothing was changed on any server. (HTTP 502, reason `kv.secret_mismatch`.)

**Likely cause.** The certificate was renewed or replaced between Alice's last check and the deployment, or the vault serves different data for the version.

**What to do.** Choose **Check now** on the vault's page and deploy the new current version.

## ALC-AKV-0018: Website already connected

**Meaning.** The website (certificate location) is already connected to another vault certificate, or follows a certificate from a certificate authority (ACME). The parameter `location_id` names it. Nothing was connected. (HTTP 409, reason `kv.location_bound`.)

**Likely cause.** A website follows at most one certificate, from a vault or from a certificate authority.

**What to do.** Disconnect the website from its other certificate first, or leave it out of this selection.

## ALC-AKV-0019: Certificate already connected

**Meaning.** The vault certificate already has connected websites. (HTTP 409, reason `kv.binding_exists`.)

**Likely cause.** A certificate has one connection with a set of websites.

**What to do.** Change the websites of the existing connection (**Connected websites**) instead of creating another.

## ALC-AKV-0020: Vault still has connected websites

**Meaning.** The vault still has certificates with connected websites, so it was not removed. (HTTP 409, reason `kv.vault_has_bindings`.)

**Likely cause.** Removing the vault would stop the automatic updates of those websites.

**What to do.** Disconnect the websites first, or remove the vault together with its connections (an administrator with a fresh verification code can choose that). Nothing changes on the websites or in Azure.

## ALC-AKV-0021: Version cannot be deployed

**Meaning.** Alice cannot deploy this version: it has not read the version's details yet, or it belongs to another certificate than the connection's. (HTTP 409, reason `kv.version_not_deployable`.)

**Likely cause.** A brand-new version that the next check has not described yet, a version that was never the certificate's current version while Alice watched the vault (Alice reads the details of current versions only), or a request for a version of another certificate.

**What to do.** Choose **Check now** on the vault's page, wait for it to finish, and try again. An older version Alice never saw as current cannot be deployed: make it current in Key Vault (a new version with the same content, or an import).

## ALC-AKV-0022: An administrator must deploy this version

**Meaning.** The version is held: the license was not available at some point since the version appeared, or its certificate chain is incomplete. Only an administrator may deploy or release a held version. (HTTP 403, reason `kv.held_needs_admin`.)

**Likely cause.** Alice never deploys by itself a version that appeared while the license was locked (or that Azure created, or Alice detected, before the license came back), and an incomplete chain needs a person's confirmation.

**What to do.** Ask an administrator to open the certificate and choose **Deploy now** (with a fresh verification code), or to release the version.

## ALC-AKV-0023: Name already used in the vault

**Meaning.** The vault already has a certificate with this name (the parameter `certificate_name`). Alice imports into an existing name only after an explicit confirmation, because it adds a new version and can replace the certificate's settings, including its own renewal in Key Vault. Nothing was sent. (HTTP 409, reason `kv.import_confirm_needed`.)

**Likely cause.** A certificate of that name is in the vault's inventory.

**What to do.** Confirm that a new version may be added (an administrator), or choose another name.

## ALC-AKV-0024: Import already running

**Meaning.** An import under this name into this vault is queued, running or not confirmed yet. (Retryable.) (HTTP 409, reason `kv.import_in_progress`.)

**Likely cause.** A previous request for the same name has not finished; an import whose answer was lost stays open until a check sees it, or for 24 to 72 hours (see `ALC-AKV-0026`). A waiting import task held for the license also keeps the name until an administrator runs or discards it.

**What to do.** Wait until it has finished (the import history on the certificate's page in **Certificates** shows its state), then try again.

## ALC-AKV-0025: Key Vault refused the import

**Meaning.** The vault refused the import with a well-formed refusal (the parameter `azure_code` carries Azure's error code when it matches a strict shape). Nothing was created. (HTTP 502, reason `kv.import_rejected`.)

**Likely cause.** The certificate's key or policy is not accepted, the vault's policy forbids the import, or the vault is not in a state to accept it.

**What to do.** Check the certificate (valid, with its private key, RSA or ECDSA) and the vault's policies; quote the request ID and the Azure code to your Azure administrator.

## ALC-AKV-0026: Import outcome unknown

**Meaning.** Alice sent the import but never learned whether the vault accepted it, and no later check of the vault showed the certificate: Alice ends it so at the first check with a complete certificate list 24 hours after the send, and 72 hours after the send in any case; removing the vault ends it at once. Alice never sends it again by itself. (HTTP 502, reason `kv.import_outcome_unknown`.)

**Likely cause.** The connection broke after the request reached Azure, or Azure did not answer; or the vault was removed from Alice meanwhile.

**What to do.** Open the vault in Azure and look for the certificate by its name and thumbprint. If it is there, nothing more is needed; if not, import it again.

## ALC-AKV-0027: Sign-in certificate not usable

**Meaning.** The certificate Alice would sign in with has no usable key. (HTTP 422, reason `kv.client_certificate_invalid`.)

**Likely cause.** Azure application certificates for Alice must be RSA keys of 2048 bits or more, and the file must contain the private key (PEM or PFX).

**What to do.** Create a certificate with an RSA key of at least 2048 bits, register its public part with the application in Azure, and give Alice the certificate and its key.

## ALC-AKV-0028: Vault already added

**Meaning.** Alice already has a vault with this address, or a vault or a server with this name. (HTTP 409, reason `kv.vault_duplicate`.)

**Likely cause.** Names are unique across servers and vaults, and a vault address can be added only once.

**What to do.** Choose another name, or open the vault or server that already has it.

## ALC-AKV-0029: A certificate with this name exists in the vault

**Meaning.** When Alice sent the import, the vault already had a certificate with this name that Alice did not know about yet. Nothing was imported. (HTTP 409, reason `kv.import_name_exists`.)

**Likely cause.** The certificate appeared in the vault after Alice's last check.

**What to do.** Choose **Check now**, then import again and confirm that a new version may be added, or choose another name.

## ALC-AKV-0030: Certificate cannot be imported

**Meaning.** Alice could not prepare the import: the name, the key or the file is outside what Key Vault accepts, or the certificate changed in Alice after the import was requested. Nothing was sent. (HTTP 422, reason `kv.import_invalid`.)

**Likely cause.** A name with characters other than letters, digits and hyphens (1 to 127), a key that is not RSA or ECDSA, a file that cannot be read, or a certificate that was replaced in Alice between the request and the send.

**What to do.** Use a valid name and a certificate with an RSA or ECDSA private key, then try again.

## ALC-AKV-0031: Website is no longer connected

**Meaning.** The website was disconnected from the vault certificate before the deployment started, so nothing was read from the vault and nothing was sent. (HTTP 409, reason `kv.binding_gone`.)

**Likely cause.** Someone removed the connection or released the website after the deployment was queued.

**What to do.** Connect the website again if it should follow the certificate.

## ALC-AKV-0032: Automatic deployment was switched off

**Meaning.** An automatic deployment did not run because automatic deployment of the connection was switched off after it was queued. Nothing was sent. (HTTP 409, reason `kv.auto_deploy_off`.)

**Likely cause.** An administrator switched **Automatic deployment** off (this stays possible while the license is expired).

**What to do.** Deploy this version by hand with **Deploy now**. Switching automatic deployment on again applies only to versions Alice finds afterwards.

## ALC-AKV-0033: Vault is disabled or removed

**Meaning.** The vault is disabled or was removed from Alice, so its certificate cannot be read. (HTTP 409, reason `kv.vault_unavailable`.)

**Likely cause.** The vault was disabled or deleted while a deployment was waiting.

**What to do.** Check the vault's status on the **Key Vaults** page, or add it again.

## ALC-AKV-0034: Version is held

**Meaning.** The version is held, so the deployment did not start. Nothing was sent. (HTTP 409, reason `kv.version_held`.)

**Likely cause.** A version that appeared while the license was not available, or with an incomplete chain, is held until an administrator releases it.

**What to do.** An administrator can open the certificate and deploy or release the version.

## ALC-AKV-0035: Version is not held

**Meaning.** The version is not held, so there is nothing to release. (HTTP 409, reason `kv.version_not_held`.)

**Likely cause.** It was released already (possibly by someone else a moment ago), or it was never held.

**What to do.** Reload the certificate's page.

## ALC-AKV-0036: A newer version replaced this one

**Meaning.** An automatic deployment did not run because the version it was queued for is no longer the certificate's current version. Nothing was read from the vault and nothing was sent. (HTTP 409, reason `kv.version_superseded`.)

**Likely cause.** The vault renewed the certificate again after the deployment was queued.

**What to do.** Nothing, when automatic deployment is on: Alice deploys the newer version. Otherwise open the certificate and choose **Deploy now** for the version you want.

## ALC-AKV-0037: Automatic deployment of this version was stopped

**Meaning.** Three deployments of this version failed in this connection, so Alice stopped deploying it automatically; an automatic deployment that was still queued for it sent nothing. (HTTP 409, reason `kv.wave_stopped`.)

**Likely cause.** The same problem made each attempt fail (a website's Nginx configuration, a missing role on the vault, a server that cannot be reached).

**What to do.** Fix the cause shown on the failed deployments, then choose **Deploy now** for the version. A newer version starts a new automatic wave by itself.

## ALC-AKV-0038: Vault was removed before the import was sent

**Meaning.** The vault was removed from Alice while the import was waiting, so nothing was sent to Azure. (HTTP 409, reason `kv.import_vault_deleted`.)

**Likely cause.** An administrator removed the vault between the request and the moment the task would have sent it.

**What to do.** Add the vault again if the certificate should still go into it, then import again.

## ALC-AKV-0039: Import cancelled before it was sent

**Meaning.** The task that would have sent the import ended before it sent anything to Azure (it was cancelled, failed or is gone), so nothing was created in the vault. (HTTP 409, reason `kv.import_cancelled`.)

**Likely cause.** An administrator discarded the waiting task, it failed before the send, or Alice was restored from a backup that no longer held it.

**What to do.** Import the certificate again. A new request is safe: nothing reached the vault.

## ALC-AKV-0040: The person who requested the import is no longer an administrator

**Meaning.** The import was requested by an administrator who, when the task ran, no longer was one (their role changed or their account was disabled), so Alice sent nothing. Importing moves a private key out of Alice and is allowed to administrators only. (HTTP 403, reason `kv.import_admin_required`; the import's record stores it as `auth.forbidden`.)

**Likely cause.** The requester's role was changed or the account was disabled between the request and the moment the task ran.

**What to do.** An administrator can request the import again.

## ALC-AKV-0041: Alice cannot read this vault's stored credentials

**Meaning.** The sign-in credentials Alice stored for the vault (a client secret or a sign-in certificate's private key, sealed with Alice's master key) cannot be decrypted, so Alice did not sign in to Azure: nothing was read from the vault and nothing was changed on any server. A deployment of a certificate from this vault ends failed with this code at its step "Read the certificate from Key Vault". (HTTP 409, reason `kv.credential_unreadable`; not retried, because retrying cannot help.)

**Likely cause.** Alice runs with another master key than the one the credentials were sealed with (the key file was replaced, or the database was restored next to another key), or the stored row was damaged.

**What to do.** On the vault's page choose **Replace credentials** and enter the vault's sign-in details again (Alice seals them with the current key), then deploy again. If many vaults or servers show this, check first that Alice runs with the right master key file. Only a deployment names this cause: **Check now**, the access check and an import of this vault show `ALC-SYS-0003` in the same situation.

## ALC-BAK-0001: Another backup is being made

**Meaning.** **Back up now** was refused because another backup is being written: one started by the daily schedule, by another administrator or on the server with `alicectl backup`. Alice makes one backup at a time. (HTTP 409, reason `backup.running`; retryable.)

**Likely cause.** The daily backup runs (by default at 02:30 in Alice's time zone), or someone else started a backup moments earlier. A large installation can take several minutes.

**What to do.** Wait a few minutes until the other backup is listed on **Settings → Backups**, then try again if you still need a new one.

## ALC-BAK-0002: Backups are not set up yet

**Meaning.** No backup can be made because Alice has no backup key: the recovery passphrase was never set, or this installation's backup key predates the current backup format. Scheduled backups wait for it too and record the failure. (HTTP 409, reason `backup.not_configured`.)

**Likely cause.** The setup wizard's recovery passphrase step was not completed. A development installation set up before Phase 8 has an old backup key and makes no backups until it is set up again on a fresh database.

**What to do.** Finish the setup wizard's recovery passphrase step; backups start after it. The Backups tab says **Backups start after the recovery passphrase is set.** until then.

## ALC-BAK-0003: This backup was not found

**Meaning.** The backup named in the download request is not in the backups directory, or the name is not one Alice gives or accepts for a backup file. Nothing outside the backups directory is ever opened. (HTTP 404, reason `backup.not_found`.)

**Likely cause.** The file was removed by the retention rule (Alice keeps the newest automatic backups, 14 by default) or by hand on the server after the list was loaded.

**What to do.** Reload **Settings → Backups** and download a file that is listed. Backups you want to keep longer must be copied off the server.

## ALC-BAK-0004: The backup could not be written

**Meaning.** Alice could not write the backup file: the free space check failed before the file was opened, or writing, syncing or renaming the file failed. Alice removed the incomplete file and recorded the failure; a failed daily backup e-mails the administrators. (HTTP 500, reason `backup.write_failed`; retryable.)

**Likely cause.** The disk of the backups directory is nearly full (Alice needs twice the size of the newest backup plus 1 GiB free), the directory is not writable by Alice, or the disk reported an error.

**What to do.** Free disk space in the backups directory (**Settings → Backups** shows the free space): copy older manual and pre-update backups to another machine and delete them on the server, then back up again. If it keeps failing with enough space, send Alice's log to support.

## ALC-TLS-0001: The private key does not belong to the certificate

**Meaning.** The uploaded HTTPS certificate was refused because none of the uploaded certificates was issued for the uploaded private key. The certificate in use did not change. (HTTP 422, reason `tls.key_mismatch`.)

**Likely cause.** The key of another certificate (an older one, or one of another server) was selected, or only the chain was uploaded.

**What to do.** Upload the certificate together with the private key it was issued for (both PEM), or a PFX file that contains both.

## ALC-TLS-0002: The certificate is not valid now

**Meaning.** The uploaded HTTPS certificate was refused because it is not valid now: its validity has not started, has ended, or ends within one day. The certificate in use did not change. (HTTP 422, reason `tls.not_valid_now`.)

**Likely cause.** An expired certificate was uploaded, a new certificate's start date is still ahead, or the server's clock is wrong.

**What to do.** Upload a certificate that is valid now and for more than one day. If the dates look right, check the server's date and time.

## ALC-TLS-0003: The certificate's key is not accepted

**Meaning.** The uploaded HTTPS certificate was refused because of its key type or size. Alice accepts RSA keys of 2,048 bits or more and ECDSA keys on the P-256 or P-384 curve. The certificate in use did not change. (HTTP 422, reason `tls.weak_key`.)

**Likely cause.** An RSA key of 1,024 bits, an Ed25519 key, or an ECDSA key on another curve.

**What to do.** Ask your certificate authority for a certificate with an accepted key, then upload it.

## ALC-TLS-0004: The PFX password is wrong

**Meaning.** The uploaded PFX file could not be opened with the password that came with it. The certificate in use did not change. (HTTP 422, reason `tls.pfx_password`.)

**Likely cause.** A typo in the password, or the password of another export.

**What to do.** Enter the password the PFX file was exported with, then upload it again.

## ALC-TLS-0005: The certificate file could not be read

**Meaning.** The upload is neither PEM text with the certificate and exactly one unencrypted private key nor a PFX file, or a part of it is larger than 1 MiB. The upload is never quoted in the answer or the log. The certificate in use did not change. (HTTP 422, reason `tls.unreadable`.)

**Likely cause.** An encrypted private key, a signing request instead of a certificate, two private keys, text after the PEM blocks, or a file of another format.

**What to do.** Upload the certificate and its unencrypted private key as PEM, or a PFX file with its password. To decrypt a key: `openssl pkey -in key.pem -out key-plain.pem`.

## ALC-ACM-0001: The certificate authority could not be reached

**Meaning.** Alice could not open a connection to the certificate authority, or the connection broke before the answer arrived. The order was not started. (HTTP 502, reason `acme.provider_unreachable`; retryable.)

**Likely cause.** The network path is blocked or down, the address is wrong, or the authority is under maintenance.

**What to do.** Check the provider's address in Settings and that this server may reach it, then order again later.

## ALC-ACM-0002: The address is not a certificate authority

**Meaning.** The provider's directory answered with something that is not a valid ACME directory (missing or unusable entries). Nothing was changed. (HTTP 502, reason `acme.directory_invalid`.)

**Likely cause.** The directory address points to a web page, a different service or a different API version.

**What to do.** Open the provider in Settings, correct the directory address and save it again.

## ALC-ACM-0003: The terms of service have not been accepted

**Meaning.** The authority requires its terms of service to be accepted and the registration did not confirm them. No account was created. (HTTP 422, reason `acme.terms_not_accepted`.)

**Likely cause.** The terms box was not ticked, or the authority published new terms.

**What to do.** Register the account again and accept the terms shown on the screen.

## ALC-ACM-0004: The authority rejected the account

**Meaning.** The authority refused to create or use the account (HTTP error from its account endpoint). The key and key identifier are never shown. (HTTP 422, reason `acme.account_rejected`.)

**Likely cause.** The external account binding key identifier or key is wrong, expired or was already used, or the contact e-mail is refused.

**What to do.** Get a fresh key identifier and key from the authority, enter them again and register the account.

## ALC-ACM-0005: The authority is limiting requests

**Meaning.** The authority answered that a request limit was reached (too many orders, failed validations or certificates for the same names). Nothing was issued. (HTTP 503, reason `acme.ca_rate_limited`; retryable.)

**Likely cause.** Too many tests or orders in a short time, or the same names were issued often.

**What to do.** Wait until the limit passes, and use the authority's staging service for tests.

## ALC-ACM-0006: The DNS proof failed

**Meaning.** The authority checked the DNS challenge record and did not find the value it expects, or it found no record at all. Nothing was issued. (HTTP 422, reason `acme.validation_failed_dns`.)

**Likely cause.** The hook wrote the record to a different zone, the change was not yet published when the authority checked, or a wildcard or CNAME points elsewhere.

**What to do.** Check the hook's own log, the zone and the record, allow the DNS change to spread (a longer **Wait after adding the record**, or a hook that answers `{"ready":false}` until the record is visible), then use **Test run** and order again.

## ALC-ACM-0007: The web proof failed

**Meaning.** The authority requested the HTTP-01 proof file and did not get the expected content. Nothing was issued. (HTTP 422, reason `acme.validation_failed_http`.)

**Likely cause.** The name points to another server, port 80 is blocked, or a redirect or web server rule hides the proof file.

**What to do.** Check the name's address and the firewall for port 80, then order again.

## ALC-ACM-0008: The DNS hook refused the request

**Meaning.** The hook answered with an error status, did not answer, or its answer could not be verified. The record was not added, or was not removed. (HTTP 502, reason `acme.hook_refused`.)

**Likely cause.** The hook's secret is wrong or was changed, the hook is down, or it does not manage this zone.

**What to do.** Correct the hook's address or secret, check that it serves the zone of the name, then order again.

## ALC-ACM-0009: The authority will not issue for this name

**Meaning.** The authority answered that a name in the order is not allowed (rejectedIdentifier or a policy refusal). Nothing was issued. (HTTP 422, reason `acme.identifier_refused`.)

**Likely cause.** Public authorities do not issue for internal names, or the name or domain is blocked by the authority.

**What to do.** Use names the authority supports, or use an authority that issues for internal names.

## ALC-ACM-0010: The certificate was not issued in time

**Meaning.** The order stayed pending or processing until the wait ended. Alice stopped waiting; a later attempt starts a new order. (HTTP 504, reason `acme.not_issued_in_time`; retryable.)

**Likely cause.** The authority is slow or overloaded, or validation is still being processed.

**What to do.** Wait a while and order again.

## ALC-ACM-0011: The key type is not allowed

**Meaning.** The authority refused the certificate request because of its key (type or size). Nothing was issued. (HTTP 422, reason `acme.key_policy_not_allowed`.)

**Likely cause.** The authority accepts only some key types or sizes.

**What to do.** Change the certificate's key type, or ask the authority which types it accepts.

## ALC-ACM-0012: The authority is still in use

**Meaning.** The certificate authority still has an account (active, or a key change not settled), or at least one ACME certificate refers to it. The provider was not changed. (HTTP 409, reason `acme.provider_in_use`.)

**Likely cause.** Certificates were created for this provider and still exist, or its account was not deactivated.

**What to do.** Delete those certificates (or move them to another authority) and deactivate the account, then remove the provider.

## ALC-ACM-0013: The authority's connection is not trusted

**Meaning.** The authority's TLS certificate is not signed by a root Alice trusts (the system roots and the provider's own bundle). No request was sent. (HTTP 502, reason `acme.tls_trust_failed`.)

**Likely cause.** A private authority's root certificate is missing from the provider's bundle, or the connection is intercepted.

**What to do.** Paste the authority's root certificate (PEM) in the provider settings, or contact whoever runs the authority.

## ALC-ACM-0014: The authority cannot change the account key

**Meaning.** The authority's directory has no key-change entry, so the account key cannot be rolled over. (HTTP 422, reason `acme.rollover_unsupported`.)

**Likely cause.** Not every authority implements account key rollover.

**What to do.** Register a new account instead, or ask the authority.

## ALC-ACM-0015: This name is not allowed

**Meaning.** A name does not end with any allowed domain suffix of the provider or of the hook (an empty list allows nothing). No order was made. (HTTP 422, reason `acme.name_not_allowed`.)

**Likely cause.** The allowed names list is empty or does not contain the domain.

**What to do.** Ask an Administrator to add the domain ending (for example .corp.example.com) to the provider and the hook.

## ALC-ACM-0016: An order is already running

**Meaning.** An order of this certificate is queued or running. The request was not queued again. An account key change (**Rotate account key**) answers this too while an order of any certificate of the authority runs: the order signs with the key the change would replace. Nothing was changed. (HTTP 409, reason `acme.order_running`; retryable.)

**Likely cause.** The order or the test button was used twice, or the scheduler already started a renewal.

**What to do.** Wait for the running order to finish, then check the certificate.

## ALC-ACM-0017: This proof method cannot be used here

**Meaning.** The web proof (HTTP-01) cannot be used for these names or this server. Nothing was changed. (HTTP 422, reason `acme.challenge_unavailable`.)

**Likely cause.** A wildcard name (only the DNS proof can prove it), a server that is not an Nginx server in Alice or was removed, or a challenge the helper cannot publish. A server whose helper is too old answers `ALC-SSH-0013` instead.

**What to do.** Use the DNS proof, or choose an Nginx server that answers for the names on port 80.

## ALC-ACM-0018: The key type cannot be changed

**Meaning.** The certificate has an issued version bound to locations, and the requested key type differs from the bound one. (HTTP 409, reason `acme.key_type_locked`.)

**Likely cause.** A key type edit was made on a certificate that is already in use on servers.

**What to do.** Create a second certificate with the new key type and bind it in place of this one.

## ALC-ACM-0019: The DNS hook is still in use

**Meaning.** At least one ACME certificate publishes its DNS-01 proof through the hook. The hook was not changed. (HTTP 409, reason `acme.hook_in_use`.)

**Likely cause.** Certificates were created with this hook and still exist.

**What to do.** Delete those certificates or switch them to another hook, then delete the hook.

## ALC-ACM-0020: This name is already used

**Meaning.** Another live certificate authority (or another DNS hook) has this name; names are compared without regard to letter case. Nothing was saved. (HTTP 409, reason `acme.name_taken`.)

**Likely cause.** The name was used before, or two Administrators added the same authority at once.

**What to do.** Choose another name, or edit the existing entry.

## ALC-ACM-0021: This authority already has an account

**Meaning.** The provider already has an active account (Alice keeps one per provider). No account was registered. If two registrations raced, the account the losing one created at the authority is deactivated again. (HTTP 409, reason `acme.account_exists`.)

**Likely cause.** The account was registered before, or twice at the same time.

**What to do.** Use the existing account, or deactivate it and register again.

## ALC-ACM-0022: Changing the address needs your confirmation

**Meaning.** The request changes the directory URL of a provider that has an active account, without the confirmation. Nothing was changed. (It is also returned when the address changed while an account was being registered.) (HTTP 409, reason `acme.directory_change_unconfirmed`.)

**Likely cause.** A new directory URL usually is another authority, where the account does not exist.

**What to do.** Confirm the change (the account is then retired and a new one must be registered), or keep the old address.

## ALC-ACM-0023: The account cannot do this now

**Meaning.** The account is retired, deactivated, a pending key or belongs to a deleted provider, so the rollover, deactivation or recovery does not apply. Nothing was changed. (HTTP 409, reason `acme.account_state`.)

**Likely cause.** The page showed an older state, or another Administrator changed the account.

**What to do.** Reload the page and act on the provider's current active account.

## ALC-ACM-0024: The account key change is not finished

**Meaning.** Another account operation of this provider (registration, key change, check or deactivation, in any Alice process) is running, or an account key rollover was sent to the authority but its answer was lost. The new key is kept as pending until it is settled. Registration, a second rollover, deactivation and a directory change wait for it. (HTTP 409, reason `acme.rollover_pending`; retryable.)

**Likely cause.** A double click or a retry while the first request still runs, or a network failure or timeout during the key change.

**What to do.** Try again in a moment. If a key change is waiting, run the key change check (recover) a few minutes later: Alice asks the authority which key it knows and settles the account.

## ALC-ACM-0025: A stored secret cannot be read

**Meaning.** An ACME account key, an external account binding key or a DNS hook secret cannot be decrypted with the current master key. Nothing was sent. (HTTP 409, reason `acme.secret_unreadable`.)

**Likely cause.** The database was restored with another master key, or the row was damaged.

**What to do.** Restore the matching master key; otherwise enter the binding or hook secret again, or register a new account.

## ALC-ACM-0026: The interrupted certificate request was abandoned

**Meaning.** A certificate request (an ACME order) was interrupted and could not be finished afterwards: the certificate authority had not issued the certificate yet. Nothing was stored and the prepared private key was deleted. This is the order's result, not an answer to a request. (HTTP 409, reason `acme.order_abandoned`; retryable.)

**Likely cause.** Alice was stopped or restarted, or lost its job, while the order ran.

**What to do.** Request the certificate again. Proof records (DNS records, token files) that were still published are removed automatically by the cleanup job.

## ALC-ACM-0027: This certificate has not been issued yet

**Meaning.** The ACME certificate has no issued certificate yet, so a website cannot be connected to it and nothing can be deployed. Nothing was changed. (HTTP 409, reason `acme.not_issued`.)

**Likely cause.** The first order of the certificate has not finished or did not succeed.

**What to do.** Get the certificate first (**Get certificate now** on its page under **Issued certificates**), then connect the websites or deploy it.

## ALC-ACM-0028: This website already follows another certificate

**Meaning.** A website (a certificate file on a managed Nginx server) follows only one certificate: this one is already connected to another certificate from a certificate authority, or to a certificate in a Key Vault. Nothing was changed. (HTTP 409, reason `acme.location_bound`.)

**Likely cause.** The website was connected earlier, possibly by another person.

**What to do.** Disconnect the website from the other certificate first, or choose another website.

## ALC-ACM-0029: This website is not connected to this certificate

**Meaning.** Deploy now of a certificate from a certificate authority puts it only on the websites connected to it, and the request named a website that is not. Nothing was deployed. (HTTP 422, reason `acme.location_not_bound`.)

**Likely cause.** The website was disconnected after the page was loaded, or it was never connected.

**What to do.** Connect the website to the certificate first, or leave it out of the selection.

## ALC-ACM-0030: The website no longer follows this certificate

**Meaning.** An automatic deployment of a certificate from a certificate authority was waiting to run, but the website was disconnected from the certificate (or the certificate was removed, or the website now follows another certificate). Nothing was sent to the server. This is a deployment's result, not an answer to a request. (HTTP 409, reason `acme.binding_gone`.)

**Likely cause.** The binding was removed or the ACME certificate deleted while the deployment waited (for example during a long licence lock).

**What to do.** Nothing to do if this was intended. Otherwise connect the website to the certificate again and choose Deploy now.

## ALC-ACM-0031: Automatic deployment was switched off

**Meaning.** An automatic deployment of a certificate from a certificate authority was waiting to run, but automatic deployment was switched off for the certificate or for this website. Nothing was sent to the server. This is a deployment's result, not an answer to a request. (HTTP 409, reason `acme.auto_deploy_off`.)

**Likely cause.** An administrator switched automatic deployment off while the deployment waited.

**What to do.** Nothing to do if this was intended. To put the certificate on the website now, choose Deploy now.

## ALC-ACM-0032: A newer certificate replaced this one

**Meaning.** An automatic deployment was waiting to run, but the certificate authority has issued a newer certificate for these names since. Nothing was sent to the server; Alice deploys the newer certificate instead. This is a deployment's result, not an answer to a request. (HTTP 409, reason `acme.certificate_superseded`.)

**Likely cause.** A renewal finished while the earlier certificate's deployment waited.

**What to do.** Nothing to do: the newer certificate is deployed automatically.

## ALC-ACM-0033: Automatic deployment of this certificate stopped

**Meaning.** Three deployments of this certificate failed, so Alice stopped deploying it automatically. A deployment that was still waiting sent nothing to the server. This is a deployment's result, not an answer to a request. (HTTP 409, reason `acme.deploy_stopped`.)

**Likely cause.** The certificate failed to deploy three times; the remaining queued deployment was not run.

**What to do.** Look at the failed deployments, remove the cause, then choose Deploy now.

## ALC-ACM-0034: This certificate is waiting for an administrator

**Meaning.** Alice holds this certificate for an administrator before it is deployed automatically (it arrived before the license allowed changes again, or Alice cannot confirm the certificates that vouch for it). A deployment that was waiting sent nothing to the server. This is a deployment's result, not an answer to a request. (HTTP 409, reason `acme.deploy_held`.)

**Likely cause.** The certificate was held for an administrator after the deployment was queued.

**What to do.** An administrator checks the certificate, then chooses Deploy now or releases it for automatic deployment.

## ALC-ACM-0035: No website is connected to this certificate yet

**Meaning.** Deploy now of a certificate from a certificate authority, with no website chosen, puts it on every website connected to it, and none is connected. Nothing was deployed. (HTTP 409, reason `acme.no_bindings`.)

**Likely cause.** The certificate was issued but no website was connected to it yet, or the last connection was removed.

**What to do.** Connect at least one website to the certificate, then choose Deploy now again.

## ALC-ACM-0036: Choose the websites to deploy to

**Meaning.** Deploy now of a certificate from a certificate authority, with no website chosen, would deploy to every website connected to it, and it is connected to more websites than one deployment request can take (at most 20). Nothing was deployed. (HTTP 422, reason `acme.too_many_bindings`.)

**Likely cause.** The certificate is connected to many websites.

**What to do.** Select the websites to deploy to, at most 20 at a time, and choose Deploy now again.

## ALC-DSC-0001: This scope is too large to scan

**Meaning.** A scan scope (the list of addresses, ports and server names Alice looks at during network discovery) covers more than one scan may. Nothing was saved. (HTTP 422, reason `discovery.scope_too_large`.)

**Likely cause.** A wide network range, such as a /16, or many ports or server names. A scope covers at most 4,096 addresses (a /20), one scan at most 20,000 combinations of address, port and server name, and an IPv6 range at most a /120.

**What to do.** Split the network into several smaller scopes, or list fewer ports or server names, then save again.

## ALC-DSC-0002: This address may not be scanned

**Meaning.** An entry of the scope points at an address Alice refuses to scan. Nothing was saved. (HTTP 422, reason `discovery.entry_not_allowed`.)

**Likely cause.** The address is outside the **Allowed scan networks** an Administrator set in the discovery settings (an empty list allows nothing), or it is one Alice never scans: its own addresses, the database server, loopback, link-local and cloud metadata addresses, or a range in the exclusions. A host name that leads to such an address is refused in the same way.

**What to do.** Remove the entry. If the network should be scanned, ask an Administrator to add it to the Allowed scan networks, then save the scope again.

## ALC-DSC-0003: An entry of this scope is not valid

**Meaning.** Alice could not read an entry of the scope. Nothing was saved. (HTTP 422, reason `discovery.entry_invalid`.)

**Likely cause.** A typing mistake: an entry must be an IP address (`10.0.0.5`), a network range (`10.0.0.0/24`) or a host name (`www.example.com`). Ports must be numbers between 1 and 65535, and server names must be plain host names without spaces.

**What to do.** Correct the entry the form marks and save again.

## ALC-DSC-0004: A scan of this scope is already running

**Meaning.** A scan was started for a scope that is already being scanned, so no second scan was started. (HTTP 409, reason `discovery.scan_running`; retryable.)

**Likely cause.** Someone else started the scan a moment earlier, or the scope's schedule started it.

**What to do.** Follow the running scan on the **Scans** tab of Network discovery. Start a new scan after it has finished.

## ALC-DSC-0005: The scan was cancelled

**Meaning.** The scan ended before it had looked at every address. The results found until then are kept. (HTTP 409, reason `discovery.scan_cancelled`.)

**Likely cause.** An Operator or Administrator cancelled the scan, or Alice stopped it because the license is locked.

**What to do.** Start the scan again when you need it. If the license is locked, resolve that first (see License messages).

## ALC-DSC-0006: The scan took too long and was stopped

**Meaning.** The scan reached its time limit of 60 minutes and was stopped. The results found until then are kept. (HTTP 504, reason `discovery.scan_timed_out`.)

**Likely cause.** The scope is large and its rate is low (at the default 20 connections per second a full /20 on one port takes about 3.4 minutes; many ports or server names multiply that), or many addresses do not answer and each one waits for its timeout.

**What to do.** Make the scope smaller, or have an Administrator raise its connections per second (at most 100), then scan again.

## ALC-DSC-0007: Too many scans are running

**Meaning.** At most two scans run at the same time, and two already run, so this one was not started. (HTTP 409, reason `discovery.too_many_scans`; retryable.)

**Likely cause.** Other scopes are being scanned at the moment, by a person or by their schedules.

**What to do.** Wait until one of the running scans has finished (the **Scans** tab shows them), then start this one again.

## ALC-DSC-0008: This scan scope was not found

**Meaning.** The scan scope named in the request does not exist. (HTTP 404, reason `discovery.scope_not_found`.)

**Likely cause.** The scope was deleted, possibly by another Administrator while the page was open.

**What to do.** Reload the list of scopes and choose one that is listed.

## ALC-DSC-0009: The schedule of this scope is not valid

**Meaning.** The automatic schedule of the scope cannot be used. Nothing was saved. (HTTP 422, reason `discovery.schedule_invalid`.)

**Likely cause.** The interval is outside 1 to 168 hours (one week), a time window has only a start or only an end, the start and the end are the same time, or the time zone is not one Alice knows.

**What to do.** Correct the schedule and save again. Leave the window empty to allow scans at any time of day.

## ALC-DSC-0010: A host name in this scope could not be found

**Meaning.** Alice looked up a host name of the scope and got no address back. Nothing was saved. (HTTP 422, reason `discovery.name_unresolved`.)

**Likely cause.** A typing mistake in the name, or the server Alice runs on uses a name server that does not know internal names. For safety, Alice does not show what a name resolves to.

**What to do.** Check the spelling of the host name and that the server Alice runs on can look it up, then save again. You can also enter the IP address instead.

## ALC-DSC-0011: A scan scope with this name already exists

**Meaning.** Every scan scope needs its own name, and another scope already uses this one. Nothing was saved. (HTTP 409, reason `discovery.name_taken`.)

**Likely cause.** The name is in use; names are compared without regard to upper and lower case.

**What to do.** Choose a different name and save again.

## ALC-DSC-0012: The scan was interrupted

**Meaning.** The scan stopped before it finished. The results found until then are kept. (HTTP 409, reason `discovery.scan_interrupted`.)

**Likely cause.** Alice restarted while the scan ran, or this installation was restored from a backup that was made during a scan. A restored copy never continues the original's scans.

**What to do.** Start the scan again.

## ALC-DSC-0013: This scan scope is switched off

**Meaning.** A scan of a scope that is switched off was asked for and not started. (HTTP 409, reason `discovery.scope_disabled`.)

**Likely cause.** The scope was switched off, by an Administrator or by a restore from a backup (a restored copy switches off the scopes that have a schedule). A scope that is switched off is scanned neither by its schedule nor by hand.

**What to do.** Switch the scope on in its settings on the Scopes tab, then start the scan again.

## Install and start problems

The installer (`install.sh`) lists every failed check before it stops, and changes nothing until all checks pass.
Each line, and what to do ([install-guide.md](install-guide.md) has the preparation steps):

| `[FAIL]` line | What to do |
|---|---|
| `This installer must be run with administrator rights. Run it again as: sudo ./install.sh` | Run it with `sudo` (not `sudo -E`). |
| `Alice needs a 64-bit Intel/AMD Linux server. This machine is <arch>.` | Use an x86_64 server. |
| `Docker is not installed or not running. Install Docker Engine 24 or newer (see docs/install-guide.md), then run this installer again.` | Install Docker from Docker's repository and start it: `sudo systemctl enable --now docker`. |
| `Your Docker is too old (found <version>). Alice needs version 24 or newer.` | Install Docker Engine 24 or newer from Docker's repository. |
| `The Docker compose plugin is missing. Install docker-compose-plugin (see docs/install-guide.md), then run this installer again.` | Install the `docker-compose-plugin` package. |
| `The Docker socket /var/run/docker.sock can be used by every user on this server. Restrict it to the docker group (chmod 660), then run this installer again.` | `sudo chmod 660 /var/run/docker.sock`, and find what widened it (a drop-in of the `docker.socket` unit, a script). |
| `OpenSSL 3 is needed to check the package signature. Install the openssl package, then run this installer again.` | Install the `openssl` package (version 3 on Ubuntu 22.04, Debian 12 and Rocky 9). |
| `Not enough free disk space in <directory>: <n> GB free, 20 GB needed.` | Free space, or install on a larger partition with `--dir`. |
| `This server has <n> GB of memory. Alice needs at least 4 GB.` | Give the server at least 4 GB (from 3 GB it is a warning only). |
| `This server has <n> CPU. Alice needs at least 2.` | Give the server at least 2 CPUs. |
| `Another program is already using port <port> (<program>, pid <pid>). Stop it or run the installer with --port 8443.` | Stop the other program, or use another port with `--port`. |
| `The package signature is not valid. Do not install this package; download it again and check it with your vendor.` | Do not use the package. Download it again and check it as in the install guide, section 3. |
| `The installation package is damaged or incomplete. Download it again and compare the checksum.` | A file is missing, changed, or not listed (a link, an extra file). Download the package again and check it. |
| `The package could not be copied next to <dir> for checking. Check the free disk space, then run this installer again.` | The installer copies the package beside the installation directory first; free disk space there. |
| `The server clock looks wrong (it says <year>). Fix the date/time first; licenses depend on it.` | Set the date and time and turn on NTP (`sudo timedatectl set-ntp true`). |
| `Alice is already installed in <dir>. To upgrade use ./alice-update.sh.` | Update instead ([upgrade.md](upgrade.md)). To start over on a server with no data you need, see "A failed first installation" below. |
| `Docker already has containers of the project alice. Choose another --project, or update the installation that uses it with its own alice-update.sh.` | Another Alice installation runs on this server. Update that one. |
| `The containers of the project alice could not be listed. Check that Docker is running, then run this installer again.` | Start Docker, then run the installer again. |
| `The installation directory <dir> has a parent that other users can change (<path>). Choose another --dir.` | Every parent of the installation directory must belong to root and must not be writable by group or others (exit code 2). Choose another `--dir`, or fix the parent's owner and mode. |
| `<path> is a symbolic link. Remove it, then run this installer again.` | A directory the installer creates exists as a link. Remove the link. |

**The fingerprint question.** After the package checks the installer prints
`Package signed by release key <key id> (SHA-256 fingerprint <64 hex>). Compare this fingerprint with the one your vendor published.`
and asks `Does this fingerprint match the one your vendor published? Type yes to continue: `. Anything but `yes`
prints `Nothing was changed.` (exit code 1). If the fingerprint differs from the one your vendor published, do not
install the package: it was not signed by your vendor's release key. With `--non-interactive`, a different
`--fingerprint` stops with `The package fingerprint does not match --fingerprint. Nothing was changed.`, and a
missing or malformed one is an option error (exit code 2).

**`[WARN] This package is signed with a TEST key. Never install it for production.`** The package was built for the
vendor's tests and is signed with a test key. Stop (Ctrl-C at the fingerprint question) and ask your vendor for the
release package. The same warning appears in `alice-update.sh`.

**`[WARN] Test override ALICE_PROC_DIR is set; results of this check are not real.`** (or `ALICE_DOCKER_SOCK`): a
variable meant for the vendor's tests is set in your shell. Unset it and run the installer again.

**`[WARN] Alice could not confirm that the clock is synchronised. …`** Turn on NTP. **`[WARN] The time zone of this
server could not be read; Alice uses UTC.`** The daily backup then runs at 02:30 UTC until an administrator changes the
time zone on **Settings → Backups**.

**`Alice did not start. Send <dir>/install.log to support.`** The database or Alice did not become healthy within 3
minutes. The installer printed the last 30 log lines of each container above that line, and they are in
`install.log`. Look for the first error there and in `cd /opt/alice && sudo docker compose logs alice`. Send
`install.log` and a support bundle to support.

**A failed first installation.** The installer does not undo its work when a step after the checks fails (for example
`Alice did not start`, or `The installation package is damaged or incomplete.` right after the images were loaded,
which means the loaded image IDs differ from the package's `RELEASE`). A second run then says
`Alice is already installed in <dir>.` On a **new** installation, where nothing needs to be kept, remove it and
start again:

```
sudo /opt/alice/install.sh --uninstall --purge --confirm DELETE
```

This deletes `/opt/alice` with everything in it; never run it on an installation with data.

If the installer stopped while it was still writing its files (a full disk, for example), before `VERSION` was
written, nothing of it was started: a second run completes the files, saying
`[WARN] An earlier installation in <dir> stopped before its files were complete; this one completes it.`, and
`--uninstall` says `The installation in <dir> stopped before it was complete; nothing of it runs. …`
(`--uninstall --purge` deletes it).

Whether the image IDs
stay the same after `docker load` on a fresh Docker engine (Docker's newer containerd image store among them) is an
owner check of this release that has not been run yet; if the image check fails on a package you verified, send
`install.log` and `sudo docker version` to support.

**`Alice is running, but the setup code could not be read. Run: sudo <dir>/alicectl setup-token --reset`** Alice was
installed and runs; only the code could not be shown. Run the printed command.

**`Unexpected error (line <n>). Nothing was changed.`** or **`… Alice was not installed completely. Send <dir>/install.log to support.`**
An unexpected command failure. The first form changed nothing: run the installer again after checking its output. The
second form: send `install.log` to support, then see "A failed first installation".

**Rocky 9 with SELinux enforcing.** This combination has not been verified yet (an owner step of this release). If
the containers report "permission denied" on their mounted directories, send `install.log` and the output of
`sudo ausearch -m avc -ts recent` to support.

**Alice does not start after a change: `database schema is at version <n> but this Alice needs <m>: run the migrate service first (docker compose run --rm migrate)`.**
The database is older than the Alice image, for example after `.env` was edited by hand. Run the update script
instead of changing image tags by hand ([upgrade.md](upgrade.md)); to bring the schema up to the installed image:
`cd /opt/alice && sudo docker compose run --rm migrate`, then `sudo docker compose up -d alice`.

## Backup failed

A failed daily backup e-mails the administrators ("Alice could not make its daily backup", with an error code), shows
**The last backup failed. Alice e-mailed the administrators.** on **Settings → Backups** and on the Overview (tab **Assurance**), and is
recorded in the audit log as **Backup failed** with the same code. **Back up now** shows the `ALC-BAK-…` code of the
section above. Alice tries the daily backup again after 5 minutes, then after 10, 20 and 40 minutes, then every hour;
a `not_configured` failure is recorded once and the backup is made at the first check (every 5 minutes) after the key
works again. To back up at once after fixing the cause, choose **Back up now**. The error codes:

| Code | Meaning | What to do |
|---|---|---|
| `disk_full` | Less free space in the backups directory than twice the newest backup plus 1 GiB; Alice did not start the backup (`ALC-BAK-0004`). | Copy manual, pre-restore and pre-update backups off the server and delete them there; check the free space line on **Settings → Backups**. |
| `not_configured` | No usable backup key: the recovery passphrase was never set, or the installation's backup key predates the current backup format (a development installation set up before backups existed) (`ALC-BAK-0002`). | Finish the setup wizard's passphrase step. An installation with an old-format key makes no backups until it is set up again on a fresh database. |
| `io` | Writing, syncing or renaming the file failed, or a file to back up could not be read. | Check the disk and the owner of `/opt/alice/backups` (user 10001) and `/opt/alice/keys`; look at `sudo docker compose logs alice`. |
| `database` | The database could not be read for the backup. | Check `sudo /opt/alice/alicectl selfcheck`; look at the logs of both containers. |
| `file_too_large` | One of the key or state files is larger than 1 MiB, which no file Alice writes is. | Check `/opt/alice/keys` and `/opt/alice/state` for files changed by hand. |

After 48 hours without a successful backup, every administrator sees **No successful backup for 48 hours** and gets
"Alice has had no successful backup for 48 hours". The alarm ends with the next successful backup: fix the cause,
then choose **Back up now**.

`alicectl backup` on the server answers `Backups start after the recovery passphrase is set. Finish the setup wizard first.`
for `not_configured` and `Another backup is running. Try again when it has finished.` while another backup runs.

## Restore refused

`alicectl restore` checks everything before it changes anything. Unless the message says otherwise, nothing was
changed and Alice runs as before (the restore starts it again in every case and runs `selfcheck`).

| Message | Meaning and what to do |
|---|---|
| `The backup file must be in <dir>/backups. Copy it there first.` | Copy the file (with its `.sha256` file) into `/opt/alice/backups` ([backup-restore.md](backup-restore.md#restore-on-a-new-server), step 3). A link that leads out of that directory is refused too. |
| `There is no backup file at that path.` | Check the file name. |
| `This is not an Alice backup.` | The file is empty, a text file or not a backup. Copy the right file. |
| `This backup was created by a newer Alice version (<v>). Install Alice <v> or newer, then restore.` | Update Alice first ([upgrade.md](upgrade.md)), or restore on a new server with that version. Without a version in the message, the file's format is newer than this Alice: install the newest version. |
| `The passphrase is wrong or the file is damaged. Nothing was changed.` | Type the passphrase again (case matters). If it is right, the file was changed or cut: take another copy, for example from the off-host storage, and check it with `alicectl backup verify FILE --deep`. |
| `A passphrase is needed. Run this command in a terminal, or pass --passphrase-file to alicectl.` | Run it in a terminal, or give `--passphrase-file` with a file only root can read. |
| `Without a terminal, pass --confirm RESTORE to confirm the restore.` | In a script, add `--confirm RESTORE`. |
| `Restore cancelled. Nothing was changed.` | You did not type `RESTORE` exactly. |
| `The backup could not be verified (<reason>). Nothing was changed.` | The loaded data did not pass a check (row counts, the master key check, the installation record). The file is not usable; use another backup and send the reason to support. |
| `The audit log in this backup is damaged at entry <n>. Nothing was changed. To restore it anyway, run the command again with --accept-broken-audit-log (the damage stays visible in Alice).` | The backup's own audit chain is broken. Prefer another backup. If you need this one, add `--accept-broken-audit-log`; the restore's `system.restored` entry records that the restored log was not intact. |
| `This installation has data but no recovery passphrase, so no safety backup can be made first. Nothing was changed. To restore anyway, run the command again with --no-safety-backup (the current data is then replaced without a copy).` | The current data cannot be saved first. Add `--no-safety-backup` only if you do not need the current data. |
| `Not enough free disk space for a restore: <n> GB free, <m> GB needed.` | A restore needs twice the current database plus 1 GiB free beside the database. Free space on the partition of `/opt/alice/data`. |
| `The restore failed: <reason>` | For example the safety backup of the current data could not be written (free space in the backups directory). Fix the reason and run it again. |
| `Alice is still connected to the database. Stop it first.` | Another process used the database for 150 seconds after Alice was stopped. Check `cd /opt/alice && sudo docker compose ps` for a container you started by hand, stop it, and run the restore again. |
| `Another restore is running. Wait for it to finish.` / `Another update or restore of Alice is running in <dir>. Wait until it has finished, then run this again.` | One restore or update at a time. |
| `An interrupted restore left an unverified copy of the database (<database>_restore) and no live database. …` | See [operator-guide.md](operator-guide.md#an-interrupted-restore). |
| `ALICE_KEYS_DIR and ALICE_STATE_DIR must be two different directories. Nothing was changed.` | Only after the compose file was changed by hand: restore the package's compose file. |
| `Alice could not be started again. Run: cd <dir> && sudo docker compose logs alice` | The restore ended but Alice did not become healthy. Read the logs and send a support bundle. |

`alicectl backup verify` without `--deep` can also say
`The checksum file <file>.sha256 is missing, so the file can only be checked with the passphrase (--deep).`: copy the
`.sha256` file too, or use `--deep`.

## Update rolled back

**`The update to <new> failed and Alice was returned to <installed>. Your data is unchanged as of <backup time>. Details: <log>. Please send this file to support.`**

The new version did not pass its start or its database update. The update script stopped it, put back the previous
configuration from `/opt/alice/rollback/<installed>/`, restored the database from the backup it made before the
update, and started the installed version, which passed `selfcheck`. Alice runs as before the update. Nothing done
during the update is lost: Alice was stopped for the whole update. Send the update log
(`/opt/alice/update-<time>.log`) to support and wait for their answer before trying again. The pre-update backup stays
in `/opt/alice/backups`.

**`The update to <new> failed and Alice could not be returned to <installed> automatically. Your backup is <file>. Restore it by hand: cd <dir> && sudo ./alicectl restore <file>   (details: <log>)`** (exit code 3)

Run the printed restore command (it asks for the passphrase and `RESTORE`): it restores the installed version's data
from the pre-update backup, starts Alice and runs `selfcheck`. Send the update log to support in any case. The script
kept its work directory `/opt/alice/.update-<time>/` for support; remove it once the case is closed.

**`Alice <new> is running, but the update could not install all its files. Details: <log>. Please send this file to support.`**
(exit code 3) The new version runs and passed `selfcheck`, but a script, the release keys, the documentation or the
version files could not be replaced. Send the update log to support before the next update.

## Update stopped before any change

**`The update was stopped before any change; Alice is running version <installed> again.`** (exit code 1)

The update failed after Alice was stopped but before anything of the installation changed: the backup, its check
with the passphrase, the rollback copy or the loading of the new images failed. The installed version runs again.
The update log names the step, for example:

- `[FAIL] The pre-update backup failed.`: see [Backup failed](#backup-failed), for example the free disk space.
- `[FAIL] The pre-update backup could not be opened with this passphrase.`: the passphrase was mistyped (or the file
  was damaged). Run the update again and type the passphrase carefully.
- `[FAIL] The installation package is damaged or incomplete. …` while loading the images: download the package
  again.

Other messages before any change (wrong version, missing signature, disk space, an unhealthy installation) stop the
update before Alice is stopped; they are listed in [upgrade.md](upgrade.md#when-the-update-fails).

**`Alice could not be started again. Details: <log>. Please send this file to support.`** (exit code 3) The update
stopped before any change, but the installed version did not start again. Run
`cd /opt/alice && sudo docker compose up -d` and `sudo /opt/alice/alicectl selfcheck`, read
`sudo docker compose logs alice`, and send the update log to support.

## How to create a support bundle

Support asks for a support bundle when a problem is not clear from the error code. On the server:

```
sudo /opt/alice/alicectl support-bundle
```

Expected: `Support bundle written: /opt/alice/support-bundle-<time>.tar.gz` (mode 0600). `--out FILE` writes it
elsewhere; an existing file is never overwritten (`The file <out> already exists.`).

The bundle holds: Alice's own report (`bundle.json`: versions, the configuration without passwords, the `selfcheck`
results, the database schema version and row counts per table, the license state and days left, job counts,
the last successful backup and whether backups fail, whether audit forwarding is on and its backlog), the last 2,000
log lines of Alice and of the database, the container list, `docker version`, `df -h`, and `.env` without any line
whose name contains `PASSWORD`, `SECRET` or `KEY`.

It never holds a password, a private key, a token, the master key, the recovery passphrase, the Installation ID,
the customer's name or database content. The logs can name your servers (in messages about connections); look
through the bundle before you send it (`tar -tzvf`, then `tar -xzf` into an empty directory). Send it to support by the
channel your support contract names, together with the error code and the `request_id` if you have one.
