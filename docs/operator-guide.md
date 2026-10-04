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
[nginx-host-preparation.md](nginx-host-preparation.md#what-alice-reads-and-changes)), but it reports the name of
every account in `/etc/passwd`. When an account is deleted and that list is complete, Alice marks its keys **No
longer found**. The list is not complete when the server also has accounts in a directory service (LDAP, SSSD) or
more accounts than Alice lists (the server's page shows a warning in both cases); then the keys of a deleted account
stay as they were last seen. An account that still exists but gets a shell such as `/usr/sbin/nologin` or loses its
home directory is not scanned any more either. In these cases **Remove key** fails because the helper refuses a file
of an account it does not scan (`ALC-SSH-0006`).

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
certificate again with its complete chain (and its key) to complete it; Alice keeps the key it has and records
`certificate.chain_completed`. If your browser lost the answer to an upload, check the list before you try again.

A chain read from a server never replaces the chain of a certificate you uploaded or whose key Alice holds: what
Alice deploys is what you gave it. For a certificate found only on servers, Alice keeps the certificate the server
serves and the certificates that lead from it to its root, in order, never the other certificates of the file.

### Signing requests

When you want Alice to create the private key, choose **Create signing request**, enter the **Main domain name** (at
most 64 characters), **Other domain names (one per line)** and the **Key type** (**ECDSA P-256 (recommended)**, **RSA
3072** or **RSA 4096**), and choose **Create request**. Copy the request (**Copy request** or **Download request**)
and send it to your certificate authority. The private key never leaves Alice.

When the certificate arrives, open **Open signing requests**, choose **Add signed certificate** in the request's row,
paste the certificate with its chain (never a private key: Alice refuses a key pasted here) and choose **Add
certificate**. Alice accepts only a certificate for the request's key; if its domain names differ from the request (certificate authorities sometimes change them), Alice
adds it with a warning, so check that it is the certificate you ordered. **Cancel request** ends a request you no
longer need. Alice keeps at most 1000 open requests (`ALC-CRT-0017`) and creates at most two keys at a time
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
then either confirms the new certificate (after verifying it), or puts the previous files back. While the server
cannot be reached Alice tries again every 15 minutes; after four failed attempts the status becomes **Needs
attention** and the administrators get one email. After about a day (96 attempts) Alice stops trying: the deployment
ends **Outcome not confirmed** (`ALC-DEP-0017`) with an email, and the website can be deployed to again. Check the
website and the files on the server yourself then.

If Alice itself was stopped for more than a day while a deployment was being sent, the helper may meanwhile have
removed the deployment's journal (it keeps it 7 days after a success). Alice then cannot learn what happened: the
deployment ends **Outcome not confirmed** (`ALC-DEP-0018`) with an email. Choose **Discover** and check which
certificate the website serves; deploy again if needed.

While a deployment on a server is being finished, new deployments to that server are refused (`ALC-DEP-0002`); scans
and SSH key work go on. Finishing a deployment also runs when the license has expired. A deployment that was
waiting to start when the license locked is held as "On hold for the license" until an administrator runs or
discards it after the next license is installed. A discarded deployment ends **cancelled** (`ALC-DEP-0022`): nothing
was sent, the website keeps its certificate, and no failure email is sent.

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

While the license is locked, nothing new can be requested on servers (`ALC-LIC-0001`), scheduled scans are not
queued, queued tests and scans are cancelled (each recorded as `job.cancelled_license`), and queued key removals and
deployments are held as "Waiting for an administrator" on **Servers** until an administrator runs or discards them
after the next license is installed. A deployment that already reached a server is still finished or undone in
lock.

If two Alice processes run against the same database (for example during an update), only one of them schedules
periodic work (a PostgreSQL advisory lock); both may run queued jobs, and each job still runs exactly once. On
shutdown Alice stops taking new jobs and gives running jobs up to 60 seconds to finish (the Compose file allows 90
seconds before it kills the container). A job that the shutdown cuts off counts the attempt like a crash does; if it
was the last attempt, the job is stopped and recorded as `job.dead` with `shutdown=true`, but no email is sent,
because the stop was planned. A job stopped after a crash or a killed process is announced by email as usual.

Periodic work: license evaluation (hourly), email sending (every minute), audit chain verification (checked every
hour, run once a day, recorded as `audit.verified` by `scheduler`), clean-up (hourly: expired sessions and setup
sessions, finished jobs older than 90 days), scheduling of the daily server scans (every minute) and the check for
interrupted deployments (every minute). Administrators
with an email address get an email when a job stops after its last attempt, when a job was changed in the
database, and when the daily audit check finds a problem.

## Checking an audit export outside Alice

The JSON export (`GET /api/v1/audit/export?format=json`, or **Export JSON** on the **Audit log** page) holds a
`verification` object (the result Alice computed, with `head_seq` and `head_hash`) and all `entries` in order.
Entries appended while the export was being written are not covered by `verification`. The response header
`X-Alice-Audit-Intact` carries the same result. Very large logs may not finish within the server's 60-second
response limit; use `alice audit verify` on the server in that case.

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
in addition to the database. Back it up with the other volumes. If the file is lost or damaged, Alice uses the copy
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
in `deploy/.env`. Alice refuses to start with a clear message when the settings are inconsistent or a file cannot
be read; the recovery commands (`alice admin …`, `alice audit verify`) do not read the email settings and keep
working. A failed send is retried for about 2 hours (10 attempts, 30 seconds doubling up to 30 minutes); every
failed attempt is logged with a reason code (never the password), and the email is then marked `failed`.

## Development stack reset

`make reset` **deletes the development database, keys and state volumes** (everything: users, audit log, license
files, Installation ID, master key, time record) and starts a fresh installation with a new Installation ID and a
new 30-day evaluation. Use it after pulling a phase that needs a fresh database (for example Phase 1 onto a Phase 0
stack: the `alice_app` role is created only on a fresh database). A license issued for the old Installation ID does
not work on the new one.

`make e2e-up` starts the **test build** as a separate compose project, `alice-e2e`, with its own database and volumes
on its own port (`ALICE_E2E_PORT`, default 9443); every Playwright run empties all its tables (`POST /test/reset`).
It never touches the `make up` stack. Never run the test build on a server.
