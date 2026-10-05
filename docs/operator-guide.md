# Operator Guide

This guide is for the person who runs the Alice server. Commands run inside the `alice` container. On a
development machine use the `make` targets; on a server use
`sudo docker compose exec alice /usr/local/bin/alice <command>` in the Alice directory.

## Commands

| Command | What it does |
|---|---|
| `alice setup-token --reset` | Prints a new one-time setup code to the terminal (never to a file). Any earlier code stops working. Works only while no administrator exists. Development: `make setup-token`. |
| `alice audit verify` | Verifies the audit hash chain. Exit code 0 and "The audit log is intact: … head hash …" when the chain is complete; exit code 1 and "Audit log integrity problem at entry N" otherwise. The check is itself recorded in the audit log (actor `cli`). |
| `alice admin reset-mfa <username>` | Removes the person's authenticator and recovery codes and ends their sessions; they enrol again at the next sign-in. Use it when the only administrator lost both phone and recovery codes. Recorded in the audit log as done by `cli`. It does not end a sign-in block. |
| `alice admin unlock <username>` | Ends the person's sign-in delay or 15-minute block and sets their failed sign-in count back to zero; nothing else changes. Use it when the only administrator is blocked after too many wrong attempts. Recorded in the audit log as `user.unlocked`, done by `cli`. Development: `make unlock ACCOUNT=<username>`. |
| `alice license status` | Prints the Installation ID, the license state (`evaluation`, `evaluation_expired`, `active`, `grace`, `locked`) and the license in force or the end of the evaluation, and warns when the server clock is behind. Changes nothing. |
| `alice license keys` | Lists the vendor license keys built into this binary with their status and SHA-256 fingerprints; compare them with the fingerprint your vendor publishes. A build without the vendor key says so and accepts no license (evaluation only). |
| `alice migrate` | Applies database migrations and exits. `alice serve` also applies them at startup. |
| `make helper` (development checkout) | Builds the static `alice-helper` for Linux amd64 and arm64 into `bin/` with `bin/alice-helper.sha256`. See [nginx-host-preparation.md](nginx-host-preparation.md). |

`alice audit verify` does not need the master key, so it works even when Alice refuses to start because of a
key problem.

## Database roles

Alice uses two PostgreSQL roles:

- The **owner** role (`ALICE_MIGRATE_DATABASE_URL`) creates and changes tables at startup.
- The **application** role `alice_app` (`ALICE_DATABASE_URL`) serves requests and runs the commands above. It can
  only add and read audit log entries, never change or delete them. A database trigger blocks changes even for
  the owner.

If `ALICE_MIGRATE_DATABASE_URL` is empty, Alice uses the application URL for both and logs a warning, because the
audit log is then protected by the triggers only.

In this release the owner role of the Docker Compose stack is the PostgreSQL superuser `alice`, and its URL is in
the `alice` container's environment. A superuser can switch the triggers off, so anyone who takes over the
`alice` container could rewrite the audit log. A dedicated non-superuser owner and a separate one-shot migration
container arrive with the installer packaging.

## Master key

Alice encrypts secrets (for example authenticator secrets) with a 256-bit master key in `master.key` inside the
keys directory (`/opt/alice/keys`). On the very first start Alice creates it (mode 0400). Afterwards:

- If the file is missing, Alice refuses to start ("the master key file is missing but this database already holds
  encrypted data"). Restore the file from your backup; Alice never creates a new key over existing data.
- If the file is different from the one the database was created with, Alice refuses to start ("the master key
  does not match this database").
- If the file permissions are wider than 0400, the file belongs to another user, or it is a symbolic link, Alice
  refuses to start and prints the command that fixes it (for example `chmod 0400 master.key`).

When Alice creates the file, or finds one an installer put there before the database knows it, it makes the file's
directory entry durable (`fsync` of the keys directory, and of its parent when it created the directory) before the
database starts to depend on the key. If that fails, Alice refuses to start and keeps the file; the next start tries
again. A file system that does not allow `fsync` on a directory therefore cannot hold the keys directory: Alice
never gets past its first start there. Use an ordinary local file system (ext4, XFS) for the keys volume.

The server disk must use full-disk encryption: anyone who can read both the database and this file can decrypt the
secrets. The `alice` container has core dumps disabled so a crash never writes key material to disk.

## Alice's SSH key

On its first start after the Phase 3 update Alice creates its own Ed25519 SSH key (comment `alice-platform`) and
records `platform_key.created` in the audit log. The private key is stored only encrypted with the master key,
inside the database (table `credentials`, row with `purpose = 'platform_ssh'`); there is no key file. Backups of the
database therefore contain it, protected like every other secret. The public key and its fingerprint are shown on
**Servers** and in the setup wizard.

Alice protects this key on every server: it refuses to remove any key whose fingerprint is that of a stored
platform key, in any file, and a database trigger refuses to delete or un-mark the inventory entry of Alice's own
key. The application role cannot change or delete rows of `credentials`.

Replacing the key needs your vendor in this release: there is no command and no page for it. Contact the vendor
before you change anything. The new public key must be on every server before Alice switches to it, and Alice never
removes its own key (old or new) from a server, so the old line is removed by hand afterwards. During such a change
do not run the server preparation commands again: they replace `/var/lib/alice-svc/.ssh/authorized_keys` with a
single line holding the key Alice uses at that moment, which removes the other key. Connections Alice opened with
the old key may stay in use for up to 60 seconds after the switch.

## The `alice-svc` account on each server

Whoever can run commands as `alice-svc` on a server (Alice itself, or anyone who holds its key or the master key
and the database) is effectively root there: the helper writes the `authorized_keys` file of any listed account,
`root` included, and on an Nginx server it replaces the certificate and key of any website Nginx serves. Treat
Alice's key and `alice-svc` accordingly.

The sudoers file sets `Defaults:alice-svc log_output`, so sudo keeps an I/O log of every helper call, including
every answer the helper prints (lists of key files, the content of the `authorized_keys` files Alice read, and on
Nginx servers the website summary with the public certificates). These are not secrets: private keys travel only
on the helper's input, which sudo does not log. The logs grow with every scan: rotating or removing them (by
default below `/var/log/sudo-io`) is the server administrator's job.

## Keys of accounts Alice no longer lists

The helper scans only some accounts of a server (see "What Alice reads and changes" in
[nginx-host-preparation.md](nginx-host-preparation.md#what-alice-reads-and-changes)), but it reports every account
in `/etc/passwd`: by name when the name follows the rule below, otherwise by user ID only. Lines the system itself
does not read as accounts (fewer than four fields, a user or group ID that is not a number, `+`/`-` lines, comments)
are skipped, as glibc skips them. When an account is deleted and that list is complete, Alice marks its keys **No
longer found**. The list is not complete (the server's page shows a warning for each reason) when:

- an entry of `/etc/passwd` cannot be listed: a name longer than 32 characters, with characters other than letters,
  digits, `_`, `.` and `-` (and one final `$`), starting with `.` or `-`, or made only of digits; a user or group ID
  written with a sign (`+1000`, `-1`) or of 4294967295 or more; or, for an account Alice would scan, a home directory that is not a plain absolute
  path (for example one with `..`). The warning names the user ID: `getent passwd <user ID>` on the server shows the
  account. Rename the account or fix its line, then scan again;
- `/etc/passwd` contains a NUL byte;
- accounts may come from somewhere else than `/etc/passwd`: a directory service (LDAP, SSSD, winbind, NIS and any
  other source in the `passwd:` line of `/etc/nsswitch.conf`), systemd user records or systemd-homed accounts
  (files in `/etc/userdb`, `/run/userdb`, `/run/host/userdb`, `/usr/local/lib/userdb`, `/usr/lib/userdb` or
  `/var/lib/systemd/home`), or a `/etc/nsswitch.conf` that is missing or that the helper cannot read safely (not a
  plain file of root's that only root can change, or larger than 64 KiB);
- the server has more accounts than Alice lists (more than 200 accounts to scan, or more than 5000 names), or the
  helper's answer had to be cut.

Several of these never go away by themselves (for example an account whose name has a space, or a server that uses
LDAP or systemd-homed): on such a server the keys of a deleted account stay as they were last seen. An account that
still exists but gets a shell such as `/usr/sbin/nologin` or loses its home directory is not scanned any more either.
In these cases **Remove key** fails because the helper refuses a file of an account it does not scan
(`ALC-SSH-0006`).

Accounts with a user ID from 1 to 999 (other than `alice-svc`), `nobody`, accounts whose shell ends in `/nologin` or
`/false` and accounts without an existing home directory are never inventoried and not reported, even where the SSH
server could accept a key for them (for example through an `AuthorizedKeysFile` outside the home). Keys a server
offers only through `AuthorizedKeysCommand` are not inventoried either (Alice lists the keys it finds in files and
changes nothing on such a server). The helper reads
`/etc/passwd` the way glibc does; servers with another C library (for example Alpine's musl) are not supported.

To spot it: on the key's page (**SSH keys**, then the key), **Where this key is used** shows a **Last seen** time that
stays behind the server's latest scan. To handle it, check the account on the server (`getent passwd <user>`):

- The account was deleted (on a server whose account list is incomplete): its keys no longer let anyone sign in as
  that user. If its home directory is still on the server, delete the old `authorized_keys` file there.
- The account still exists with a `nologin` or `false` shell, or without its home directory: the SSH server may still
  accept its keys (for example for port forwarding). Remove the key lines from the file on the server yourself, or
  give the account a login shell and its home again, choose **Scan for SSH keys**, and remove the key in Alice.

In both cases the entry stays in Alice as last seen; this is a known limitation of this release.

## Certificates

**Certificates** lists every TLS certificate Alice knows, once per certificate: the ones it found on Nginx servers
and the ones you added. Filter by **Search** (name, domain name or fingerprint), **Server**, **Source** (**Found on
servers**, **Uploaded**, **From a signing request**) and **Expiry**. The **Private key** column says **In Alice** when
Alice holds the key (only then can it deploy the certificate) and **Not in Alice** otherwise: Alice never reads a
private key from a server. Open a certificate to see its details, whether its chain is complete, **Where this
certificate is used** and its deployments. Administrators and operators add and deploy certificates; auditors only
read.

### Uploading a certificate

Choose **Upload certificate**, then the **File format**:

- **PEM text**: paste the certificate with its chain into **Certificate and chain (PEM)** and the private key into
  **Private key (PEM)**. The order of the chain does not matter; Windows line endings are fine. The key may be
  PKCS #1, PKCS #8 or an EC key, but not protected with a password.
- **PFX file**: choose the `.pfx` or `.p12` file and enter its **PFX password** (it may be empty).

**Name (optional)** is a label for the list. Choose **Upload**. Alice checks everything before it stores anything:
the key must belong to one of the certificates (that one becomes the website certificate, the others its chain),
the certificate must not have expired, keys must be RSA of 2048 to 16384 bits or ECDSA P-256 or P-384, and no
certificate in the chain may be signed with MD5 or SHA-1 (a root certificate in the chain, one that names itself as its issuer, is exempt: its own
signature is not checked by browsers). Each field is limited to 256 KiB. The private key is stored
encrypted and is never shown again. A refused upload says why ([troubleshooting.md](troubleshooting.md), codes
`ALC-CRT-…`) and stores nothing; every attempt is in the audit log.

Alice may store the certificate with a warning:

- "The chain is incomplete": the chain does not lead to a root that Alice's system trusts or that came with the
  upload. Some browsers may refuse it; only an administrator can deploy it, with a confirmation.
- "A certificate in the chain has expired": replace the chain when you can.
- "This certificate is not valid yet": it cannot be deployed before its start date.

Uploading a certificate Alice already holds with its key is refused ("Alice already has this certificate with its
key"); open it from the list instead. One exception: when the chain Alice holds is incomplete, upload the same
certificate again with its complete chain (and its key) to complete it; Alice keeps the key it has, takes the
**Name** you enter (an empty one keeps the stored name) and records `certificate.chain_completed`. This works only
for certificates you uploaded: the key of a certificate from a signing request never leaves Alice, so it cannot be
uploaded again. Paste the full chain when you add a signed certificate; if a signed certificate was added with an
incomplete chain, only an administrator can deploy it (with the confirmation) and its chain cannot be completed
later. If your browser lost the answer to an upload, check the list before you try again.

The chain Alice deploys with a key you gave it is the chain you gave with that key. When you upload the key of a
certificate Alice first found on a server (or a signing request is completed with a certificate already found on a
server), the certificate takes the chain of your upload, whatever the server's file held, and from then on it is
listed as **Uploaded** (or **From a signing request**); later scans never change that chain. For a certificate found
only on servers, Alice keeps the certificate the server serves and the certificates that lead from it to its root,
in order, never the other certificates of the file.

### Signing requests

When you want Alice to create the private key, choose **Create signing request**, enter the **Main domain name** (at
most 64 characters), **Other domain names (one per line)** and the **Key type** (**ECDSA P-256 (recommended)**, **RSA
3072** or **RSA 4096**), and choose **Create request**. Copy the request (**Copy request** or **Download request**)
and send it to your certificate authority. The private key never leaves Alice.

When the certificate arrives, open **Open signing requests**, choose **Add signed certificate** in the request's row,
paste the certificate with its chain (never a private key: Alice refuses a key pasted here) and choose **Add
certificate**. Alice accepts only a certificate for the request's key; if its domain names differ from the request (certificate authorities sometimes change them), Alice
adds it with a warning, so check that it is the certificate you ordered. **Cancel request** ends a request you no
longer need. Alice keeps at most 1000 open requests for the whole installation, all users together
(`ALC-CRT-0017`); a cancelled request's key stays sealed in the database (it is never deleted). Alice creates at most
two keys at a time
(`ALC-CRT-0016`: wait a moment and try again). A request's key belongs only to the certificate that completes it: a
certificate re-issued later for the same key cannot be added, so create a new request for it.

### Websites on an Nginx server

On an Nginx server's page, **Websites on this server** lists each certificate file that Nginx uses: the website
(server name; **(default server)** for `_`), the port, the file, the certificate in it, its expiry and a state:
**Ready**, **Not supported** (with the reason), **No longer found** or **Deployment in progress**. **Discover** reads
the server again (SSH keys and websites). Alice also does this on its own once per discovery interval. When the last
scan could not read the websites (Nginx missing, its configuration has an error, or the Nginx permissions are not
installed), the page says so and that the list may be out of date. Why a website can be **Not supported** is
explained in [nginx-host-preparation.md](nginx-host-preparation.md#configurations-alice-cannot-manage).

A website shows **The certificate changed outside Alice.** when its file holds a certificate that Alice did not
deploy (for example renewed by certbot or by hand). That is not an error: it tells you that something else manages
this file.

Warnings next to a website say what Alice noticed in its files, for example that the certificate has expired, that
it does not cover the website's names, that the key file is readable by others, or (warning code
`chain_unresolved`) that Alice could not order the other certificates of the file within its limit of 100
signature checks: it then keeps only the website's certificate and counts its chain as incomplete (see
[troubleshooting.md](troubleshooting.md)).

### Deploying a certificate

Two ways lead to the same dialog, **Deploy a certificate**:

- On the server's page choose **Deploy certificate** in a website's row, then choose the certificate. Alice offers
  only certificates it holds the key of and whose key type (RSA or ECDSA) fits that place.
- On a certificate's page choose **Deploy** and tick the websites (only websites that already use this
  certificate are offered, at most 20 at once). To put a renewed certificate on a website that uses another one,
  start from the server's page.

Choose **Deploy**. A request for several websites is all or nothing: if one website cannot take the certificate,
nothing is queued and the message names that website. Each website then gets its own deployment, which runs in the
background; the dialog follows them and you can close it at any time.

What happens, step by step (the names are those of the deployment's **Steps**):

| Step | What it means |
|---|---|
| **Check the current certificate** | Alice connects to the website and checks that it serves the certificate Alice last saw there. If Alice cannot reach it or sees another certificate, it stops here and changes nothing. |
| **Backup** | The helper copies the current certificate and key file on the server. |
| **Write the private key**, **Write the certificate** | The helper replaces the two files (each atomically). |
| **Check** | `nginx -t` with the new files. |
| **Reload** | `systemctl reload nginx` (never a restart; open connections are kept) and a check that Nginx is still running. |
| **Verify** | Alice checks that the website now serves the new certificate with the expected chain, on every HTTPS port of the website, from its own network or, when it cannot reach the website, from the server itself. |
| **Restore**, **Check again**, **Reload again**, **Verify the previous certificate** | Only when something failed: the previous files are put back, Nginx is checked and reloaded, and Alice checks that the previous certificate is served again. |

The steps from **Backup** to **Reload** (and the restore after a failure) run inside one helper call on the server,
which finishes even when the connection drops.

### Results and what to do

| Status | Meaning | What to do |
|---|---|---|
| **Succeeded** | The new certificate is live and verified ("Checked from Alice" or "Checked from the server itself"; **Skipped** when an administrator turned the check off for that website). | Nothing. |
| **No change needed** | The website already had this certificate; nothing was written. | Nothing. |
| **Failed, nothing changed** | Alice stopped before writing (for example the website could not be checked, the file changed since the last scan, the configuration has an error). | Read the error, fix the cause, deploy again. |
| **Failed, restored** | The files were written but a check failed, and the previous certificate and key are back (Alice reloaded Nginx and, when it could reach the website, checked it). | Read the error (for example `ALC-DEP-0003`), fix the cause, deploy again. |
| **Outcome not confirmed** | Manual action is needed: the previous files could not be put back, are back but could not be confirmed, another program changed them, or Alice gave up confirming the outcome. | Check the website now; see the error code in [troubleshooting.md](troubleshooting.md) and the backup on the server. |
| **Needs attention** | Alice is still trying to find out how the deployment ended (see below). | Check the server's connection. |

Administrators with an email address get an email for every deployment that failed or needs manual action, and one
when a deployment needs attention. A successful deployment sends no email. Every deployment is in the audit log.

### Deployment history

**Deployment history** lists every deployment, newest first, with the server, certificate file, certificate and
result. **Open** shows the deployment: **Status** and **State**, who requested it, **Previous certificate** and **New
certificate** (fingerprints), **Verification**, the **Steps** with their results, the error with what to do, and
**Backup on the server** (`/var/lib/alice-helper/backups/<deployment ID>`). A certificate's page lists its own
deployments. There is no button to repeat or undo a deployment: deploy again, or deploy the earlier certificate
(Alice needs its key). Undoing by hand from the backup is described in
[nginx-host-preparation.md](nginx-host-preparation.md#restoring-a-previous-certificate-by-hand).

### Interrupted deployments

When Alice does not get a clear answer from the server (the connection dropped, the helper was killed, Alice
restarted), it never sends the deployment again. The deployment's state becomes **Confirming the outcome**: about 30
seconds later Alice asks the helper how the change ended (the helper finishes its work on the server on its own) and
then either confirms the new certificate (after verifying it), or puts the previous files back. When the helper has
no record of the deployment at all (for example the connection dropped before the command reached it), Alice first
tells the helper to refuse that deployment for good (`nginx-fence`), so it can never be applied later, and only then
ends it **Failed**: nothing was written. While the server
cannot be reached Alice tries again every 15 minutes; after four failed attempts the status becomes **Needs
attention** and the administrators get one email. After about a day (96 attempts) Alice stops trying: the deployment
ends **Outcome not confirmed** (`ALC-DEP-0017`) with an email, and the website can be deployed to again. Check the
website and the files on the server yourself then.

If Alice itself was stopped for more than a day while a deployment was being sent, the helper may meanwhile have
removed the deployment's journal (it keeps it 7 days after a success). Alice then cannot learn what happened: the
deployment ends **Outcome not confirmed** (`ALC-DEP-0018`) with an email. Choose **Discover** and check which
certificate the website serves; deploy again if needed. Before it records that, Alice also tries to fence the
deployment on the server (when the server answers), so that it can never be applied later.

An unfinished change can also be one Alice no longer follows: its outcome was recorded as not confirmed, or the
server was removed and added again, or Alice's database was restored from a backup. The helper then refuses every
new change of those files and names the unfinished change (its operation ID). A new deployment of that website
handles it like this:

- When Alice does not know that change at all, or knows it only as a deployment of this same website whose outcome
  was not confirmed, it undoes it once, as a step of the new deployment (the deployment history shows a step for
  restoring the unfinished earlier change, with its operation ID, followed by the restore's own steps), and sends
  the new certificate again. If the new certificate is then written, the deployment ends as usual.
- If the files were put back but the new certificate could not be written, the deployment ends **Failed, restored**
  with `ALC-DEP-0024` and an email: the website now serves the certificate from before the unfinished change
  (possibly an older one). Choose **Discover** and deploy again.
- If Alice does not undo the change (it knows it from another website or as a change that ended normally) or the
  undo did not finish, the deployment ends **Failed** with `ALC-DEP-0023`; the steps to take on the server are in
  [troubleshooting.md](troubleshooting.md).

While a deployment on a server is being finished, new deployments to that server are refused (`ALC-DEP-0002`; the
helper also refuses a new change of the same files while the earlier one is unfinished); scans and SSH key work go
on. Finishing a deployment also runs when the license has expired. A deployment that was
waiting to start when the license locked is held as "On hold for the license" until an administrator runs or
discards it after the next license is installed. A discarded deployment ends **cancelled** (`ALC-DEP-0022`): nothing
was sent, the website keeps its certificate, and no failure email is sent.

## Key Vaults

**Key Vaults** lists the Azure Key Vaults Alice watches, with their address, status, sign-in method and last
successful check. How an Azure administrator gives Alice access (identity, roles, network) and how a vault is added
is in [azure-setup.md](azure-setup.md). Adding a vault, replacing its credentials, switching automatic deployment on
or off, releasing a held version and importing a certificate are for administrators with a fresh authenticator
code, never for API tokens. Connecting websites, **Deploy now** of a version that is not held, **Check now** and the
access check are for administrators and operators. Everyone can read. Each vault counts as one target of the
license.

### Status of a vault

| Status | Meaning |
|---|---|
| **Connected** | The last check signed in and read the certificate list. |
| **Partly working** (or **No permission to read certificates**) | Alice reaches the vault only in part: a role is missing, the vault firewall refuses Alice, or Azure asked Alice to slow down in three checks in a row. The page shows the reason; with a firewall refusal also **Alice's address as the vault saw it**. |
| **Credentials refused** (or **Credentials expired**) | Azure refused the sign-in. Choose **Replace credentials**. Alice keeps checking, at most once an hour, and emails the administrators once, at the third failed sign-in in a row. |
| **Cannot reach Azure** | No connection to Azure or the vault (network, DNS, an unknown vault, an untrusted certificate). Alice tries again at the next check. |

Alice checks each vault every 15 minutes by default (**Check every (minutes)** on the vault's page, 5 to 1440,
administrators). A check that fails makes the next one wait longer (twice, then four times the interval, at most an
hour or the interval if that is longer). **Check now** queues a check at once; at most two vault checks run at the
same time for the whole installation. **Access check** (**Check again**) signs in and reads the first page of each
list; with **Also test deployment access** it also reads one exportable certificate's secret once, discards it and
records the read in the audit log. Import access is never tested in advance.

### What Alice shows of a vault

- **Certificates**: name, current version, expiry and state: **Monitor only** (the private key cannot be exported,
  so Alice can never deploy it), **New version found**, **Held**, **Connected websites**, **Disabled in Key
  Vault**, **Details not read yet**, and **Removed from Key Vault** for a certificate that is no longer listed (it
  stays in the list; recovering it in Azure brings it back at the next check). **New version found** is a hint the
  browser computes: the current version was created in Azure after Alice first saw the certificate, within the last
  seven days.
- **Keys**: type, size or curve, expiry, whether enabled, and whether the key belongs to a certificate (**Managed**).
- **Secrets**: content type, expiry, enabled and managed. Alice never reads or shows a secret's value.

A certificate's page shows its policy (whether the key is exportable, issuer, whether Key Vault renews it), every
version Alice has seen, newest first (thumbprint, validity, enabled, when Alice found it, held), and **Connected
websites**. Alice reads the details of a certificate's current version only; an older version that was never
current while Alice watched is listed without details and cannot be deployed. A check reads at most 5000
certificates, 5000 keys and 10,000 secrets, and the details of 100 changed certificates (the rest at the next
check); a larger vault is shown incomplete.

When a deployment reads a certificate's secret and finds no private key in it, Alice marks the certificate
**Monitor only** and the deployment fails with `ALC-AKV-0016`; later requests are refused with `ALC-AKV-0013`. A
later check that finds the key exportable again (usually a new version with **Exportable private key** on) removes
the mark.

### Connecting websites

On a certificate's page choose **Connect websites** and tick the Nginx websites that should use it (only websites
whose key type matches are offered; 1 to 200). A certificate has one connection, and a website follows at most one
vault certificate. Alice refuses a connection for a certificate whose key is not exportable, whose current version
it has not read yet, or that is disabled or removed. Connecting changes nothing on the websites; it does not check
that Alice may read the private key (**Check deploy access** on the connection reads the certificate's secret once
to check it).

**Remove website** takes one website out of the connection; **Delete connection** releases all of them. Neither
changes anything on the servers; deployments to a released website that are still waiting stop, and one that is
already running finishes. Adding websites to a connection that deploys automatically needs an administrator.

### Automatic deployment

**Automatic deployment** starts off for every connection. When an administrator switches it on, Alice deploys new
versions by itself under these rules:

- Only the certificate's **current** (newest) version, and only one that Alice found after automatic deployment was
  switched on and that Azure created after that moment (when Azure gives a creation time). A version that misses this rule is never deployed by
  itself; Alice emails once ("… is not deployed automatically").
- Never a version that is held, disabled, expired, not yet valid, with a key that cannot be exported, or that ends
  earlier than the certificate the website already serves (Alice emails once for each such version), and never a
  version whose certificate chain is incomplete (it is held, see below).
- At most **five** unfinished automatic deployments per connection at a time; nothing for a website while another
  deployment of it is unfinished or when it already serves the version.
- After a failed deployment, the next attempt for that website comes **one hour** later at the earliest.
- After **three** failed deployments of the version, Alice stops its automatic deployment for the connection
  ("Stopped after 3 failures") and emails once. Fix the cause, then use **Deploy now**. A newer version starts a new
  round by itself.

Alice plans once a minute, so a new version found by a check is deployed about a minute later. Automatic
deployments are ordinary deployments (see [Deploying a certificate](#deploying-a-certificate)) with one more first
step, **Read the certificate from Key Vault**: Alice reads the secret of that exact version (never "the latest")
and checks it before anything is sent to the server. A failure in that step changes nothing on the server (for
example `ALC-AKV-0003` when Alice lacks **Key Vault Secrets User**). **Deployment history** shows such deployments
as "From Key Vault: <vault>". Switching automatic deployment off takes effect at once: queued automatic deployments
of the connection do not start (`ALC-AKV-0032`).

With automatic deployment off, a connected certificate's new version is only announced by email ("A new version of
… was found").

### Deploy now

**Deploy now** (on the connection, or in a version's row) deploys one version Alice has read, chosen in the dialog,
to some or all of the connection's websites, also an older version. All websites or none are queued, as for any
deployment. An operator cannot deploy a held version or a version whose chain Alice knows is incomplete; the version's
row and the dialog say so.

### Incomplete chains

Alice learns a version's chain only when it reads its secret. A version whose chain is incomplete is never deployed
automatically: the automatic attempt fails with nothing changed and the version is held ("Held because its
certificate chain is incomplete."). From the first read that finds the chain incomplete, every **Deploy now** of
that version, held or not, asks an administrator to tick the chain confirmation (`ALC-CRT-0011` otherwise); releasing
the version does not confirm the chain. The very first manual deployment of a version that was never read is
accepted and then fails at **Read the certificate from Key Vault** if the chain turns out incomplete. Prefer
adding the intermediate certificates to the certificate in Key Vault.

### Held versions after a lock

A version that appears while the license is locked, or around the moment a lock ends, is **Held** with the text
"This version is waiting for an administrator: …"; when websites are connected to the certificate, the
administrators get one email. Alice never deploys a held
version by itself, and a check never releases it. An administrator can:

- **Deploy now** (with a fresh code): deploys it to the websites chosen; the version stays held.
- **Release** (with a fresh code): lifts the hold. The dialog says what follows: for a version held for the
  license that is the current version of a connection with automatic deployment on, Alice may deploy it by itself,
  usually within a minute; for other versions held for the license nothing is deployed and you use **Deploy now**. Releasing a version held for its chain asks for the chain confirmation,
  but automatic deployment still never deploys an incomplete chain: the next automatic attempt (an hour later at the
  earliest) holds it again, and **Deploy now** asks for the confirmation again.

While the license is locked Alice does not check vaults, **Check now**, **Add Key Vault**, connecting websites,
**Deploy now** and imports are refused, and automatic deployment plans nothing. Switching automatic deployment off
and deleting a connection stay possible.

### Importing a certificate into a vault

On a certificate's page in **Certificates** (a certificate whose key is in Alice), an administrator can choose
**Import into Key Vault**, pick the vault and the certificate's name in the vault (letters, digits and hyphens, up to
127). The private key leaves Alice and is stored in the vault; the vault needs **Key Vault Certificates Officer**
(see [azure-setup.md](azure-setup.md#2-roles)). An imported certificate does not renew itself in Key Vault.

If the vault already has a certificate of that name, Alice asks you to confirm that a new version is added: that
version replaces the certificate's settings in the vault (the vault may stop renewing it), and when websites are
connected to it, automatic deployment may deploy the imported version.

The import runs in the background and is sent once. Its state is in **Imports into Key Vault** on the certificate's
page: **Waiting to start**, **Running**, **Imported** (with the version in the vault), **Failed** (with the reason;
when nothing reached the vault you can try again), **Not confirmed yet** or **Outcome unknown**. **Not confirmed
yet** means Alice sent the certificate but did not get the vault's answer: Alice never sends it again by itself, the
next checks of the vault settle it as **Imported** when they see the certificate, and it ends **Outcome unknown**
after 24 to 72 hours (`ALC-AKV-0026`). Do not import it again while it is shown; look for the certificate in the
vault instead. Only one import per vault and name runs at a time (`ALC-AKV-0024`).

### Removing a vault

**Remove Key Vault** (administrators) makes Alice forget the vault and what it knows of its certificates, keys and
secrets, frees its license slot and changes nothing in Azure. A vault with connected websites is refused
(`ALC-AKV-0020`) unless the administrator chooses **Remove the connections and the vault** (with a fresh code); the
websites keep the certificate they serve. Imports of the vault that are still open end at once.

## Master-key rotation and the installation record

Master-key rotation (§7.2 of the design, `alice keys rotate-master`) is not available yet. When it is added it must,
in the same procedure, re-seal the installation record (`license.installation_seal`, HMAC under the HKDF label
`alice/installation/v1`) and re-write both copies of the license time record (`settings.time.hwm` and
`<ALICE_STATE_DIR>/hwm.dat`, labels `alice/hwm/v1` and `alice/hwm-enc/v1`) with the new key; otherwise the next
start reports the installation as tampered and the evaluation as ended. It must also re-encrypt the platform SSH key
and re-compute the job payload MACs (label `alice/job/v1`). Do not replace `master.key` by hand.

## Background jobs

Work on servers runs in a job queue stored in PostgreSQL: connection tests, scans, key removals, certificate
deployments and the finishing of interrupted deployments. A running job
holds a 45-second lease that it renews every 15 seconds. If Alice stops or crashes, a job whose lease has run out is
put back in the queue (audited as `job.recovered`) when it has attempts left, and is otherwise stopped
(`job.dead`). Two jobs for the same server never run at the same time. Failed attempts are retried after 30
seconds, doubling up to 30 minutes (connection tests are not retried; scans get 5 attempts, other jobs 3). A failed
sign-in is not retried: the server is marked "Sign-in refused" until someone tests it again. A deployment job that
runs again after a crash never deploys again once it may have reached the server: it finishes the deployment as
described in "Interrupted deployments". A job that finishes an interrupted deployment runs once; the next one is
queued 15 minutes later by a check that runs every minute, and it never sends the stopped-task email (the
deployment's own email tells the administrators).

Scheduled work per server: every minute Alice looks for servers that are due. A **Connected** server is scanned
once per discovery interval (default one day, at least one hour). Alice starts at most one scheduled job per server
per interval, whatever its outcome: a scheduled scan that fails (for example because the helper is outdated, or the
license lock cancelled it) is tried again only after a full interval. A server that **Cannot be reached** gets a
connection test at its discovery interval instead; when it succeeds, the server is **Connected** again and Alice
scans it at once. A scheduled test that fails ends as failed, without a dead-job email; the server keeps its status
and the next interval tests it again. A server becoming unreachable sends no email of its own (the audit log records
one `target.status_changed` entry per change of status), and a failed scheduled re-test sends none either. A scan,
or a connection test a person started, that fails on its last attempt still ends as a stopped job and sends the
usual `job.dead` email. A server left at **Checking…** after its fingerprint was confirmed (because
Alice restarted, or the license lock cancelled the test) is tested the same way, at once the first time. Any
successful scan or key removal also returns a server that could not be
reached to **Connected** (audited as `target.status_changed` with the reason `discovery_ok` or `removal_ok`). A
server marked **Sign-in refused** or **Server identity changed**, one waiting for its fingerprint confirmation and a
disabled one are never tried automatically: a person must act first.

If Alice cannot renew a running job's lease (for example because the database cannot be reached) and the lease
would run out before the next renewal, Alice stops the job's work and hands the job back to the queue; with the
defaults this happens about 30 seconds after the last renewal. When a server is removed while a job runs on it, a
key removal that already changed the server is still recorded in the audit log; a removal whose retry finds the
server removed is recorded as `sshkey.remove_failed` (reason `system.not_found`) and stops for a person, because the
earlier attempt may have changed the server; and a connection test ends as failed (`ALC-SYS-0001`) without a retry
or an email.

At most 10 SSH connections are in use at once (2 per server); an idle connection is kept for up to 60 seconds and
reused, except by **Test connection**, which always opens a new connection. Each step has its own time limit: 10 seconds to connect, 15 seconds for the SSH handshake, 30 seconds per
command (60 seconds for reading the SSH settings, for listing, reading and changing key files and for reading the
Nginx configuration; 240 seconds for a certificate deployment or restore; the helper on the server normally stops
after 50 seconds, before Alice gives up, and a certificate deployment that already replaced a file always finishes;
a change that timed out is still treated as an uncertain outcome). Every job payload carries an HMAC; a job
changed in the database is never run (`job.tampered`).

Each time Alice connects to a server (SSH, and its own check of a website's certificate), it checks the address the
server's name resolves to at that moment, and never connects to a link-local address (such as the cloud metadata
address `169.254.169.254`), a multicast, unspecified or reserved address, or an IPv6 form that only carries such an
IPv4 address (`ALC-SSH-0012`). Loopback and private addresses are allowed: a server name that later resolves to
`127.0.0.1` makes Alice open an SSH connection (or a TLS check) to its own host; only administrators can add servers.
Already open connections are not affected by a DNS change.

While the license is locked, nothing new can be requested on servers (`ALC-LIC-0001`), scheduled scans are not
queued, queued tests and scans are cancelled (each recorded as `job.cancelled_license`), and queued key removals and
deployments are held as "Waiting for an administrator" on **Servers** until an administrator runs or discards them
after the next license is installed. A deployment that already reached a server is still finished or undone in
lock.

Alice also stops changes when it cannot check its license. Each Alice process checks the license at start, every
hour and after an upload; a failed check is tried again after 1, 2, 4 and 8 minutes, then every 10 minutes. When no
check has succeeded for 3 hours (counted in the time the process was running, so a suspended host does not count),
everyone sees "Alice could not check its license since …" and every request that works on a server is refused with
`ALC-LIC-0009`: not only changes (adding, changing or removing a server, confirming a fingerprint, **Remove key**,
certificate uploads, signing requests, deployments, verification settings, **Run now** of a waiting job) but also
**Test connection**, **Scan for SSH keys** and **Discover**. Queued jobs of these kinds are neither cancelled nor
held: they stay queued and start by themselves after the next successful check; the daily scans are not started
meanwhile. What keeps running: reading everything in the web UI and the API, signing in, user and token
administration, license upload, the audit log (check, export, the daily check), **Discard** of a waiting job,
emails, clean-up, and the finishing or undoing of a deployment that already reached a server. Between checks Alice
also counts the time itself: when the license reaches its lock time before the next check, the same requests are
refused at once (`ALC-LIC-0001`), queued jobs wait the same way, and a check starts immediately; queued jobs are held
for an administrator (or cancelled) only after that check confirmed the lock. A database outage that ends within
about 2 hours 48 minutes of the last successful check never stops changes. Every wait for the license row is limited
to 30 seconds: if another database session keeps that row locked, a check fails (and is retried), and Alice does not
start at all (it exits after 30 seconds). See `ALC-LIC-0009` in [troubleshooting.md](troubleshooting.md).

If two Alice processes run against the same database (for example during an update), only one of them schedules
periodic work (a PostgreSQL advisory lock), except the license check, which runs in every process; both may run
queued jobs, and each job still runs exactly once. A license uploaded in one process reaches the other one at its
next check (within an hour, or at once when that process refuses a change); until then the other process may refuse
or pause changes, never allow them past a lock. On
shutdown Alice stops taking new jobs and gives running jobs up to 60 seconds to finish (the Compose file allows 90
seconds before it kills the container). A job that the shutdown cuts off counts the attempt like a crash does; if it
was the last attempt, the job is stopped and recorded as `job.dead` with `shutdown=true`, but no email is sent,
because the stop was planned. A job stopped after a crash or a killed process is announced by email as usual.

Periodic work: license evaluation (hourly in every process, retried within minutes when it fails), email sending
(every minute), audit chain verification (checked every
hour, run once a day, recorded as `audit.verified` by `scheduler`), clean-up (hourly: expired sessions and setup
sessions, finished jobs older than 90 days), scheduling of the daily server scans (every minute) and the check for
interrupted deployments (every minute), and for Key Vaults the queueing of due vault checks with the clean-up of
imports whose task ended (`kv.schedule`, every minute) and the planning of automatic deployments (`kv.auto_deploy`,
every minute). A vault check (`kv.poll`) runs once, without a retry and without a dead-job email (its failure is
shown on the vault, and the next check follows the vault's interval); an access check (`kv.test_connection`) runs
once; an import (`kv.import`) gets up to 3 attempts and is retried only before it was sent, and when another path
ended its import (the vault was removed) the job ends failed with the import's code, without an email. Administrators
with an email address get an email when a job stops after its last attempt, when a job was changed in the
database, and when the daily audit check finds a problem.

## Checking an audit export outside Alice

The JSON export (`GET /api/v1/audit/export?format=json`, or **Export JSON** on the **Audit log** page) holds a
`verification` object (the result Alice computed, with `head_seq` and `head_hash`) and all `entries` in order.
Entries appended while the export was being written are not covered by `verification`. The response header
`X-Alice-Audit-Intact` carries the same result. An export may take up to 10 minutes to write; for a log too large
for that the download fails (it is aborted, never ended as if complete): use `alice audit verify` on the server in
that case. Alice runs one check (**Verify**) or export at a time; another one started meanwhile is refused with
`ALC-AUD-0001` (try again later). The daily check and `alice audit verify` are not counted in that limit.

The CSV export starts (after the UTF-8 byte order mark) with one comment line that carries the same result,
followed by the header row on line 2:

```
# alice audit export: intact=true checked=1234 head_seq=1234 head_hash=9f86d0…
```

On a broken chain the line ends with ` first_bad_seq=<n> problem=<hash_mismatch|sequence_gap|tail_truncated>`.
CSV (RFC 4180) has no comments: tell your reader to skip lines starting with `#` (Go `csv.Reader.Comment = '#'`,
pandas `comment="#"`), or skip the first line; a spreadsheet shows it as one cell in the first row.

Repeated refusals are recorded once per 10 minutes: when the same person is refused the same permission
(`authz.denied`, also with the reason `not_owner` for another user's token list) or the same change by the
license (`request.denied_license`) for the same reason on the same API route again within 10 minutes of the
recorded refusal, no new entry is written. A person's sessions count as one; all API tokens of one person count
as one more (each recorded entry names its token in `token_id`). A refused **Verify** or export because another
one was running (`ALC-AUD-0001`) is recorded the same way, as `audit.verified` or `audit.exported` with the
result `denied` and the reason `busy`. When those 10 minutes end (or Alice stops, or the next refusal after them
arrives), one more entry of the same action records how many were left out: `suppressed_count`, `window_start`
and `window_end` in its details, and what the left-out refusals varied in: `distinct_ip_count` with up to three
addresses in `ip_samples`, `distinct_object_count` (for example how many user IDs were asked for) and
`distinct_token_count` (a count above 64 is written as `64+`). That entry has no address, request ID or
object ID: it stands for many requests. Counts not yet written when the Alice process dies are lost, and each
Alice process counts its own refusals.

To recompute the chain yourself, for each entry in `seq` order:

1. Build the JSON object with exactly these keys in this order: `seq`, `at`, `actor_type`, `actor_id`,
   `actor_name`, `ip`, `action`, `object_type`, `object_id`, `result`, `details`, `request_id`. Write `null`
   `actor_id` and `ip` as `""`, write `at` in UTC with exactly six fractional digits
   (`2026-09-30T08:15:02.120000Z`), sort the `details` keys, use no spaces, and escape `<`, `>`, `&`, U+2028 and U+2029
   as `\u003c`, `\u003e`, `\u0026`, `\u2028` and `\u2029` (Go `encoding/json` rules); other non-ASCII characters stay
   as UTF-8.
2. `hash = SHA-256(previous hash || that JSON)`, where the previous hash of the first entry is 32 zero bytes.
3. Compare with the entry's `hash` (hex).

The CSV export is meant for spreadsheets: cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return
get a leading apostrophe, so use the JSON export for this check.

## State volume

Alice keeps its license time record (the latest time it has seen, encrypted and protected with a MAC derived from
the master key) in `ALICE_STATE_DIR` (default `/opt/alice/state`, the `alice-state` volume, owned by user 10001)
in addition to the database. Back it up with the other volumes, and restore the database as a whole: a database
restored without its `license` table (or only some tables) counts as a removed installation record and ends the
evaluation. On a new, empty database Alice refuses to start when the file exists but cannot be read (for example
because the volume's permissions are wrong): it creates nothing and says "make the state directory readable by
Alice and start again". A new installation must also start with an empty state volume: a time record left by an
earlier installation counts as an earlier installation, and the new one starts with an
ended evaluation (ask the vendor for a license for the new Installation ID). If the file is lost or damaged, Alice uses the copy
in the database and records "time record damaged" (`clock.hwm_damaged`) in the audit log; if both are lost on an
existing installation, Alice starts from the later of the system clock and the release's build time and records
"time reference reset" (`clock.time_reference_reset`). Neither ever extends a license.

## Email

In this release email is configured with environment variables in `deploy/.env`; a Settings page follows in a later
release. Alice sends license warnings to every enabled administrator with an email address, in their language.

| Variable | Meaning |
|---|---|
| `ALICE_SMTP_HOST` | Mail server. Empty = no email: warnings are then shown only as banners, and each email is recorded as skipped. |
| `ALICE_SMTP_PORT` | Default 587 with `starttls`, 465 with `tls` |
| `ALICE_SMTP_FROM` | Sender, for example `Alice <alice@example.com>`; required when `ALICE_SMTP_HOST` is set |
| `ALICE_SMTP_USERNAME` | Optional user name; needs `ALICE_SMTP_PASSWORD_FILE` (both or neither) |
| `ALICE_SMTP_PASSWORD_FILE` | Path, inside the container, of a file holding the password (never the password itself) |
| `ALICE_SMTP_TLS` | `starttls` (default) or `tls`. Alice never sends email unencrypted, needs TLS 1.2 or newer and checks the server certificate. |
| `ALICE_SMTP_CA_FILE` | Path, inside the container, of a PEM file with a private certificate authority, if the mail server's certificate comes from one |

The password and CA files must be mounted into the container. Add a `docker-compose.override.yml` next to
`docker-compose.yml`:

    services:
      alice:
        volumes:
          - ./secrets/smtp_password:/run/secrets/smtp_password:ro
          - ./secrets/smtp_ca.pem:/run/secrets/smtp_ca.pem:ro

and set `ALICE_SMTP_PASSWORD_FILE=/run/secrets/smtp_password` (and `ALICE_SMTP_CA_FILE=/run/secrets/smtp_ca.pem`)
in `deploy/.env`. `make up` (and `make down`, `make reset`, `make logs` and the other targets of that stack) adds
the override file when it exists, and `docker compose` run by hand in `deploy/` reads it by itself; keep the file
and `deploy/secrets/` out of git (both are ignored). The e2e stack (`make e2e-up`) never reads it.
`ALICE_TRUSTED_PROXIES` and `ALICE_LOG_LEVEL` set in `deploy/.env` reach Alice the same way as the email
settings (see `docs/dev/getting-started.md`, Configuration).
Alice refuses to start with a clear message when the settings are inconsistent or a file cannot
be read; the recovery commands (`alice admin …`, `alice audit verify`) do not read the email settings and keep
working. A failed send is retried for about 2 hours (10 attempts, 30 seconds doubling up to 30 minutes); every
failed attempt is logged with a reason code (never the password), and the email is then marked `failed`.

## Health endpoints and request limits

Alice serves `/livez` (the process is up) and `/healthz` (the database is reachable and migrations are
current) on two listeners:

- The **internal health listener** (`ALICE_HEALTH_ADDR`, default `127.0.0.1:8081`, inside the container) has no
  request limit. The container healthcheck (`alice healthcheck`) and orchestrators use it.
- The **public HTTPS listener** serves both too. There `/healthz` asks the database, so it answers at most 60
  requests a minute per client address and then `ALC-SYS-0005` (429 with `Retry-After`). This limit is counted
  on its own: probes never make sign-in from the same address wait. Point external monitoring at it no more
  than once a second, or use `/livez`, which is not limited.

Requests that carry a session cookie, a setup cookie or an API token that Alice does not know (wrong, expired,
revoked) are limited to 60 a minute per client address (an IPv6 client counts by its /64), counted before the
database is asked; after that such requests get `ALC-SYS-0005` without a lookup. People whose session or token this
Alice process accepted (or issued) in the last 30 minutes (the session idle timeout) are not affected, nor are
requests without any credential (the sign-in page and sign-in itself have their own limits). When Alice refuses a
session cookie it tells the browser to delete it, so a stale cookie stops counting (a cookie replaced a moment ago,
when someone confirmed their identity or changed their password, is left alone).

Alice tells clients apart by address. When many clients reach Alice from one address, they share these limits: while
one of them sends many bad credentials, the others wait (`ALC-SYS-0005`, `Retry-After`) if Alice has not accepted
their own session or token in the last 30 minutes, for example a nightly script's API token, and after Alice
restarts everyone from that address waits until they sign in again. This happens:

- behind a reverse proxy: set `ALICE_TRUSTED_PROXIES` in `deploy/.env` to the proxy's address or network (comma-
  separated); Alice then takes the client address from the proxy's `X-Forwarded-For` header. Without it everyone
  has the proxy's address. List only your proxies, never a client network: Alice believes the `X-Forwarded-For`
  header of every address in these ranges, so a client inside them can claim any address. It could then escape the
  per-address limits (sign-in attempts, bad credentials, `/healthz`) and write a false address into the audit log;
- when the published port is forwarded by a proxy process instead of the kernel (rootless Docker's default port
  forwarding, or Docker's userland proxy, which handles connections from the Docker host itself): Alice then sees
  one internal address for those clients. Check the **IP address** column of a few audit entries: if different
  people show the same address, this is the case;
- behind NAT, where many people share one public address.

## Development stack reset

`make reset` **deletes the development database, keys and state volumes** (everything: users, audit log, license
files, Installation ID, master key, time record) and starts a fresh installation with a new Installation ID and a
new 30-day evaluation. Use it after pulling a phase that needs a fresh database (for example Phase 1 onto a Phase 0
stack: the `alice_app` role is created only on a fresh database). A license issued for the old Installation ID does
not work on the new one.

`make e2e-up` starts the **test build** as a separate compose project, `alice-e2e`, with its own database and volumes
on its own port (`ALICE_E2E_PORT`, default 9443); every Playwright run empties all its tables (`POST /test/reset`).
It never touches the `make up` stack. Never run the test build on a server.
