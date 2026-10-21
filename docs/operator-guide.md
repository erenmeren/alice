# Operator Guide

This guide is for the person who runs the Alice server: system operators and on-call staff. Installing is in
[install-guide.md](install-guide.md), updating in [upgrade.md](upgrade.md), backups and restores in
[backup-restore.md](backup-restore.md).

On a server installed from the release package, run the maintenance commands with `alicectl`, as root:
`sudo /opt/alice/alicectl <command>` ([alicectl reference](#alicectl-reference)). The few commands `alicectl` does not
wrap run inside the `alice` container: `sudo docker compose exec alice /usr/local/bin/alice <command>` in
`/opt/alice` (a root shell: the directory is readable by root only). On a development machine use the `make`
targets.

## Commands

| Command | What it does |
|---|---|
| `alice setup-token --reset` | Prints a new one-time setup code to the terminal (never to a file). Any earlier code stops working. Works only while no administrator exists. Development: `make setup-token`. |
| `alice audit verify` | Verifies the audit hash chain. Exit code 0 and "The audit log is intact: … head hash …" when the chain is complete; exit code 1 and "Audit log integrity problem at entry N" otherwise. The check is itself recorded in the audit log (actor `cli`). |
| `alice admin reset-mfa <username>` | Removes the person's authenticator and recovery codes and ends their sessions; they enrol again at the next sign-in. Use it when the only administrator lost both phone and recovery codes. Recorded in the audit log as done by `cli`. It does not end a sign-in block. |
| `alice admin unlock <username>` | Ends the person's sign-in delay or 15-minute block and sets their failed sign-in count back to zero; nothing else changes. Use it when the only administrator is blocked after too many wrong attempts. Recorded in the audit log as `user.unlocked`, done by `cli`. Development: `make unlock ACCOUNT=<username>`. |
| `alice license status` | Prints the Installation ID, the license state (`evaluation`, `evaluation_expired`, `active`, `grace`, `locked`) and the license in force or the end of the evaluation, and warns when the server clock is behind. Changes nothing. |
| `alice license keys` | Lists the vendor license keys built into this binary with their status and SHA-256 fingerprints; compare them with the fingerprint your vendor publishes. A build without the vendor key says so and accepts no license (evaluation only). |
| `alice migrate` | Applies database migrations and exits. The whole run must finish within `ALICE_MIGRATE_TIMEOUT` (default 30m). `alice serve` also applies them at startup. |
| `make helper` (development checkout) | Builds the static `alice-helper` for Linux amd64 and arm64 into `bin/` with `bin/alice-helper.sha256`. See [nginx-host-preparation.md](nginx-host-preparation.md). |

`alice audit verify` does not need the master key, so it works even when Alice refuses to start because of a
key problem.

## Production layout

`install.sh` creates this layout (`--dir` changes `/opt/alice`; everything else is relative to it):

```
/opt/alice/                          0750 root          installation directory
  VERSION, RELEASE                   0644 root          the installed version and its release data
  docker-compose.yml, .env           0644 / 0640 root   the production compose file; project name, images, port,
                                                        address, host names, time zone (no secret)
  install.sh, alice-update.sh, alicectl   0755 root     the scripts of the installed version
  lib/                               0755 root          script library, database role script
  release-keys/rk-*.pem              0644 root          release public keys trusted for updates
  helper/                            0755 root          alice-helper for the managed servers, with checksums
  docs/, licenses/, sbom/, CHANGELOG.md                 copies from the package
  secrets/                           0700 root          db_postgres_password, db_owner_password, db_app_password
  keys/                              0700 user 10001    master.key (0400), tls.crt (0644), tls.key (0400)
  state/                             0700 user 10001    hwm.dat (license time record)
  backups/                           0700 user 10001    *.alicebak and *.alicebak.sha256 (0600)
  data/postgres/                     0700 user 70       the database files
  rollback/<version>/                0700 root          configuration of the version before the last update
  install.log, update-<time>.log, support-bundle-<time>.tar.gz   0600 root
```

The containers run as user 10001 (Alice) and 70 (PostgreSQL), so the files in `keys/`, `state/`, `backups/` and
`data/` belong to those users. Do not change files there by hand; the scripts do not either.

The database passwords are 32 random bytes each, used only by the containers as Docker secrets. Nobody needs to know
them, and no command prints them.

## alicectl reference

`alicectl` is the operator's tool. Run it as root: `sudo /opt/alice/alicectl <command>`. While Alice runs, it runs
the command inside the Alice container; when Alice is stopped, in a one-time maintenance container. Exit codes: `0`
success, `1` failure, `2` a wrong command, option or file. Nothing `alicectl` prints is written to a log file.

A backup `FILE` must be in `/opt/alice/backups` (a link out of it is refused):
`The backup file must be in /opt/alice/backups. Copy it there first.` A passphrase is asked on the terminal
(`Recovery passphrase: `, nothing is shown while you type), or read from the first line of `--passphrase-file FILE`,
a file that only root can read (mode 600; a file others can read is refused).

| Command | What it does | Output |
|---|---|---|
| `alicectl backup` | Makes a manual backup now. No passphrase needed. | `Backup written: /opt/alice/backups/alice-backup-7F3K92QD-20261011T091500Z-manual.alicebak (12.3 MiB)` |
| `alicectl backup --out /opt/alice/backups/<name>.alicebak` | The same, under a name of your choice (it must end in `.alicebak` and not start with a dot; the path is the one inside the container, `/opt/alice/backups`, whatever `--dir` you installed to). | as above |
| `alicectl backup --reason TEXT` | Stores a reason in the backup's manifest. | as above |
| `alicectl backup list` | Lists the backups, newest first. | `NAME  KIND  SIZE  CREATED (UTC)  ALICE  CHECK`, then one row per file; CHECK is `ok`, `missing checksum`, `checksum mismatch`, `unreadable header` or `unreadable (<reason>)`. |
| `alicectl backup verify FILE` | Checks header, size and checksum file, without the passphrase. | `The backup file looks complete (header, size and checksum are correct).` |
| `alicectl backup verify FILE --deep` | Decrypts the whole file with the passphrase. Changes nothing. | `The backup opens with this passphrase and is complete: Backup from 2026-10-10 02:30 UTC, Alice 1.0.0, host alice01, installation ALICE-….` |
| `alicectl restore FILE` | Replaces all data with the backup ([backup-restore.md](backup-restore.md#restore-on-the-same-server)). Options `--passphrase-file FILE`, `--confirm RESTORE`, `--db-only`, `--accept-broken-audit-log`, `--no-safety-backup`. | `Restore finished. Everyone must sign in again. Users and API tokens are as they were when the backup was made; review them.` |
| `alicectl selfcheck` | Checks the running installation (below). Changes nothing. | Seven `[ OK ]` or `[FAIL]` lines; exit code 0 only when all are OK. |
| `alicectl audit verify` | Verifies the audit log chain (recorded in the audit log, actor `cli`). | `The audit log is intact: 1234 entries checked, head entry 1234, head hash 9f86d0….` or `Audit log integrity problem at entry <n> (<problem>). <m> entries checked.` (exit code 1) |
| `alicectl setup-token --reset` | Prints a new one-time setup code to the terminal only. Works only while no administrator exists. | `One-time setup code: <code>`; once an administrator exists: `An administrator already exists, so a setup code is no longer needed. Sign in instead.` |
| `alicectl support-bundle` | Writes a support bundle ([troubleshooting.md](troubleshooting.md#how-to-create-a-support-bundle)). `--out FILE` chooses the file; an existing file is never overwritten. | `Support bundle written: /opt/alice/support-bundle-<time>.tar.gz` |
| `alicectl help` | Lists the commands. | |

The failure messages of `backup verify` and `restore` are in [troubleshooting.md](troubleshooting.md#restore-refused).

**`alicectl selfcheck`** prints, for a healthy installation:

```
[ OK ] Database reachable
[ OK ] Database schema is current (version <n>)
[ OK ] Master key opens the stored key check
[ OK ] Audit log intact (<n> entries, head <first 16 hex characters of the head hash>)
[ OK ] License readable (<state>)
[ OK ] HTTPS listener answers with the installed certificate
[ OK ] Background jobs running (last heartbeat <hh:mm> UTC)
```

A failed check prints `[FAIL] <check>: <reason>`. The last check waits up to 90 seconds for a heartbeat of the
background jobs right after a start or a restore, so `selfcheck` can take that long. The update and the restore run
`selfcheck` themselves; run it after a reboot or any change on the server.

## Backups and restores on the server

The full guide is [backup-restore.md](backup-restore.md). In short, for the operator:

- Alice backs up every day by itself (02:30 in the server's time zone by default) into `/opt/alice/backups`. Copy the
  files to another machine every night ([backup-restore.md](backup-restore.md#copy-backups-off-the-server)).
- **Once a month, run `sudo /opt/alice/alicectl backup verify <newest file> --deep`** with the passphrase. Only the
  deep check proves that the backups open with the passphrase you hold.
- **Restore on the same server:** `sudo /opt/alice/alicectl restore /opt/alice/backups/<file>`. Alice opens the whole
  file while it keeps running, asks you to type `RESTORE`, then stops, saves the current data as a `pre-restore`
  backup, restores, starts again and runs `selfcheck` (also when the restore was refused).
- **Restore on a new server:** the recovery passphrase is all a new server needs besides the backup file. Install
  with `sudo ./install.sh --restore-mode` from the package (same or newer version), copy the file into
  `/opt/alice/backups`, and run `alicectl restore` ([backup-restore.md](backup-restore.md#restore-on-a-new-server)).
- **After a restore, review users and API tokens.** They are as they were when the backup was made: a person
  disabled or a token revoked since then is back. Everyone must sign in again.
- **After a restore, review the held tasks.** Work of the backup's queue that changes servers or Key Vaults does not
  start by itself: it waits under **Servers → Waiting for an administrator** (`system.restored` records the number as
  `held_jobs`).
- **After a restore with audit forwarding on**, expect the syslog server to receive rows again: from where the
  backup's forwarding stood, first identical copies of entries it already has (up to the backup's newest entry), then
  `system.restored` and the entries after it under sequence numbers it already holds with other content. That is a
  visible fork of the chain, expected after a restore; keep both branches.

### An interrupted restore

A restore loads the backup into a separate database (`alice_restore`) and switches to it in one step only after every
check passed. If the server loses power or the restore process is killed before that step, the current data stays
in use and the next restore cleans up.

One case needs a hand: on a **new** server, where no current database exists yet, a restore interrupted before the
switch leaves the unverified copy, and the next restore stops with
`An interrupted restore left an unverified copy of the database (<database>_restore) and no live database. Nothing was changed. Drop that copy by hand (see the operator guide), then run the restore again.`
Drop it, then run the restore again:

```
cd /opt/alice && sudo docker compose exec -T postgres psql -U postgres -d postgres -c 'DROP DATABASE alice_restore'
```

After a successful switch, the replaced database is kept as `alice_previous_<time>` until the restore has put the
restored key files in place, then dropped. If the server stops in between, Alice finishes the key files at its next
start, and the old copy stays until the next restore drops it. To see whether one is left, and how much space it
uses:

```
cd /opt/alice && sudo docker compose exec -T postgres psql -U postgres -d postgres -c '\l+'
```

If the restore switched databases but could not put the key files in place (`The restore failed: … the previous
database is kept as alice_kept_<time> …`), the replaced database is kept as `alice_kept_<time>`. No later restore
drops it: it is the way back while you find out what happened. Restore again (with `--no-safety-backup` if the
restore says the current data cannot be saved first), and drop the kept copy by hand once it is no longer needed:

```
cd /opt/alice && sudo docker compose exec -T postgres psql -U postgres -d postgres -c 'DROP DATABASE alice_kept_<time>'
```

## Updates

The full guide is [upgrade.md](upgrade.md): `cd /opt/alice && sudo ./alice-update.sh <package>` (from a root shell),
with the recovery passphrase at hand. The update stops Alice **before** it makes its backup, so the outage starts
with the backup and lasts a few minutes; announce it. A failed update returns to the installed version by itself.

## Logs

| What | Where |
|---|---|
| Alice's log (JSON lines, no secrets) | `cd /opt/alice && sudo docker compose logs alice` (add `--since 1h` or `-f`) |
| The database's log | `cd /opt/alice && sudo docker compose logs postgres` |
| The installation | `/opt/alice/install.log` |
| Each update | `/opt/alice/update-<time>.log` |

Docker keeps each container's log in files of 20 MB, at most 5 per container; older lines are dropped. Ship the logs
to your log system with Docker's means if you need them longer. The audit log is not a log file: it is in the
database ([admin-guide.md](admin-guide.md#audit-trail)) and can be forwarded ([admin-guide.md](admin-guide.md#audit-forwarding)).

## Health and monitoring

Alice answers `/livez` (the process is up) and `/healthz` (the database is reachable and current) on its HTTPS port
([Health endpoints and request limits](#health-endpoints-and-request-limits)). Docker checks the container's health
itself (`docker compose ps` shows `healthy`).

Alert on:

- **`alicectl selfcheck` failing.** Run it from cron, for example every 15 minutes, and alert on a non-zero exit code:

  ```
  */15 * * * * root /opt/alice/alicectl selfcheck >/dev/null 2>&1 || logger -t alice-selfcheck "Alice selfcheck failed"
  ```

- **`/healthz` not answering 200** from your monitoring system (at most once a second, or `/livez`).
- **The backup alarm.** No successful backup for 48 hours: the red banner for administrators, the e-mails "Alice could
  not make its daily backup" and "Alice has had no successful backup for 48 hours", **Recovery readiness**
  on the Overview's **Assurance** tab. Also alert when your off-host copy job finds no new file for a day.
- **The forwarding backlog.** **Entries waiting to be sent** on **Settings → Audit forwarding** (also `forwarding` →
  `backlog` in the support bundle's `bundle.json`) should stay near zero; a backlog that keeps growing means the
  syslog server gets nothing. At the syslog server, alert on gaps in `seq`.
- **The Overview's conditions.** **Needs attention** (a server's identity changed, a refused sign-in on a server,
  failed deployments, a broken audit chain, failing e-mail delivery), the license banners, and the e-mail about a
  failed daily audit check.
- **Disk space** of the partition holding `/opt/alice` (below).
- **The HTTPS certificate's end date**, when you uploaded your own: Alice does not renew it.

## Disk space

The partition of `/opt/alice` holds the database, the backups and the logs. Alice refuses work rather than fill it:

| When | Needs free | Refusal |
|---|---|---|
| Installation | 20 GB | `Not enough free disk space in <dir>: <n> GB free, 20 GB needed.` |
| Every backup | twice the newest backup + 1 GiB, in `backups/` | the backup fails with `disk_full` (`ALC-BAK-0004`), e-mail to the administrators |
| A restore | twice the current database + 1 GiB, beside the database | `Not enough free disk space for a restore: <n> GB free, <m> GB needed.` |
| An update | twice the database + 5 GB | `Not enough free disk space in <dir>: <n> GB free, <m> GB needed for the update.` |

Check with `df -h /opt/alice` and `sudo du -sh /opt/alice/backups /opt/alice/data`. To make room, copy manual,
pre-restore and pre-update backups to another machine and delete them on the server (Alice deletes only daily
backups by itself), remove old `update-*.log` and `support-bundle-*` files, and remove the images of old versions
that `docker image ls` lists and no container uses.

## Replacing the HTTPS certificate and changing mail settings

Both are done by an administrator in the web interface, without a restart:

- **Settings → HTTPS certificate** → **Upload certificate** ([admin-guide.md](admin-guide.md#https-certificate)). The
  new certificate is used at once. If the server's name changes, also update `ALICE_TLS_HOSTS` in `/opt/alice/.env`
  (it names the temporary certificate and the `name_mismatch` check) and restart Alice with
  `cd /opt/alice && sudo docker compose up -d alice`.
- **Settings → Email** ([admin-guide.md](admin-guide.md#mail-server)); then **Send test e-mail**.

## Reboot

Docker starts at boot (`systemctl enable docker`), and the database and Alice restart by themselves
(`restart: unless-stopped`), unless someone stopped them with `docker compose stop`: start them again with
`cd /opt/alice && sudo docker compose up -d`. After a reboot:

- running jobs whose lease ran out are queued again ([Background jobs](#background-jobs));
- a daily backup missed while the server was off runs at once;
- a restore interrupted after its switch is finished at Alice's start;
- run `sudo /opt/alice/alicectl selfcheck`.

## User off-boarding

When someone leaves:

1. **Disable** the person on **People & access** (administrators). Their sessions end at once and their API tokens stop working.
   For a single sign-on user, also remove them at the identity provider (Alice's role mapping follows the groups).
2. Revoke their API tokens: administrators list them with `GET /api/v1/tokens?user_id=<id>` and revoke each with
   `DELETE /api/v1/tokens/<token id>` ([admin-guide.md](admin-guide.md#api-tokens)).
3. If they knew the recovery passphrase: it cannot be changed in this version, so tighten access to the backup copies
   (below).
4. If they had root on the Alice server, they could read the master key: treat the server's secrets as exposed and
   follow your incident process.

After a restore of an older backup, check again: disabled people and revoked tokens come back with it.

A person who held roles on single services (role bindings, R53) keeps them while disabled; remove them on the person's
**Access** section (or `DELETE /api/v1/role-bindings/<id>`, listed by `GET /api/v1/role-bindings?user_id=<id>`) when the
account is to be used again by someone else. A removed binding takes effect at the person's next request.

A single sign-on or directory user whose only access is a group's role on a service (R54) loses it at their next sign-in
after leaving the group; **Disable** stops them at once. A pipeline's automation account is disabled the same way on
**People & access**, **Automation accounts**: its tokens are revoked for good.

A person who leaves stops receiving a service's e-mails as its owner (R56) as soon as they are disabled; an owner
group's member at their next sign-in after leaving the group. Remove them from the service's **Owners** (its
**Overview**, **Edit owners**) when someone else takes over: a disabled owner receives nothing, so the service's
e-mails would otherwise reach only its other owners and the administrators.

## Moving to a new server

1. Make a manual backup on the old server (`sudo /opt/alice/alicectl backup`) and copy it with its `.sha256` file to
   the new server.
2. Stop Alice on the old server (`sudo /opt/alice/install.sh --uninstall`; data and backups stay there).
3. Restore on the new server ([backup-restore.md](backup-restore.md#restore-on-a-new-server)): the Installation ID and
   the license come with the backup ([licensing.md](licensing.md#moving-to-new-hardware)).
4. Point the DNS name to the new server; upload a certificate if the name changed.
5. Never start the old server's Alice again: two copies of one installation would both rotate keys and deploy
   certificates.

## What cannot be changed in this version

- **The recovery passphrase.** It is fixed when the administrator sets it in the setup wizard. An exposed passphrase
  together with a copy of a backup file opens that backup, and every older file stays readable with it for ever:
  keep the copies of the backups as protected as the passphrase.
- **The master key.** There is no command to replace it ([Master-key rotation and the installation
  record](#master-key-rotation-and-the-installation-record)). Never replace `master.key` by hand.

## Database roles

Alice uses two PostgreSQL roles:

- The **owner** role (`ALICE_MIGRATE_DATABASE_URL`) creates and changes tables at startup.
- The **application** role `alice_app` (`ALICE_DATABASE_URL`) serves requests and runs the commands above. It can
  only add and read audit log entries, never change or delete them. A database trigger blocks changes even for
  the owner.

If `ALICE_MIGRATE_DATABASE_URL` is empty, Alice uses the application URL for both and logs a warning, because the
audit log is then protected by the triggers only.

On a server installed from the release package, the owner role is `alice_owner`, which is not a superuser, and the
running Alice container does not have its password: only the one-time `migrate` container (run by the installer and
the update) and the maintenance container of `alicectl` get it. The schema is changed before Alice starts
(`ALICE_MIGRATE=external`); an Alice whose database schema is older than its own refuses to start with
`database schema is at version <n> but this Alice needs <m>: run the migrate service first (docker compose run --rm migrate)`.
The PostgreSQL superuser exists only inside the database container.

The development stack (`make up`) still uses the PostgreSQL superuser `alice` as the owner role, with its URL in the
`alice` container's environment. A superuser can switch the triggers off, so there anyone who takes over the `alice`
container could rewrite the audit log. See [Development stack and production](#development-stack-and-production).

## Master key

Alice encrypts secrets (for example authenticator secrets) with a 256-bit master key in `master.key` inside the
keys directory (`/opt/alice/keys`). On the very first start Alice creates it (mode 0400). Afterwards:

- If the file is missing, Alice refuses to start ("the master key file is missing but this database already holds
  encrypted data"). Restore the installation from a backup ([backup-restore.md](backup-restore.md)): every backup
  carries the master key. Alice never creates a new key over existing data.
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
the old key may stay in use for up to 60 seconds after the switch. Key rotation (see
[SSH keys and rotation](#ssh-keys-and-rotation)) never touches this key: Alice refuses it as a policy's key, as a
rotation's old or new key, in a deploy and in a download, and the database refuses it too.

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
servers**, **Uploaded**, **From a signing request**, **Issued by ACME**) and **Expiry**. **Issued by ACME** are the
certificates Alice got from a certificate authority (see [Issued certificates (ACME)](#issued-certificates-acme)). The **Private key** column says **In Alice** when
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

An **Apache server** (discovery only) shows the same list, read through `apache-dump`
([apache-host-preparation.md](apache-host-preparation.md)): its websites, their certificate files, certificates,
expiry, states and warnings, and its certificates appear under **Certificates**. Alice never changes anything on it:
the **Deploy certificate** and **Verification settings** controls in its rows are disabled, and the note "Not
available for Apache servers yet" is shown when you point at them or reach them with the keyboard (Tab). The texts
of the page say that Alice reads these files and never changes them. Why an Apache website can be **Not supported**
is explained in [apache-host-preparation.md](apache-host-preparation.md#configurations-alice-cannot-read). Renew
the certificates of an Apache server with your own tools; Alice shows the new certificate after the next
**Discover**.

A **HAProxy server** (discovery only) shows the same list, read through `haproxy-dump`
([haproxy-host-preparation.md](haproxy-host-preparation.md)), with a **Frontend** column in place of the website
column: each row is one TLS `bind` of a `frontend` or `listen` section, or, for a `crt-list` file, one line of it. The
row shows the frontend's name ("Frontend: name"), the addresses and ports of the `bind`, the server names (SNI
filters) of that certificate-list line (none for a plain `crt`), the certificate file, its expiry,
states and warnings. Its certificates appear under **Certificates**. Alice never changes anything on it: the
**Deploy certificate** and **Verification settings** controls are disabled with the note "Not available for HAProxy
servers yet". Why a HAProxy place can be **Not supported**, and what Alice does not read (for example
`/etc/haproxy/conf.d`, which the page warns about), is explained in
[haproxy-host-preparation.md](haproxy-host-preparation.md#configurations-alice-cannot-read). Renew the certificates
of a HAProxy server with your own tools; Alice shows the new certificate after the next **Discover**.

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

The alert recipients (**Settings → Recipients**, by default every administrator with an email address) get an email
for every deployment that failed or needs manual action, and one when a deployment needs attention. A successful deployment sends no email. Every deployment is in the audit log.

### Deployments

**Deployments** (it was called **Deployment history** before) lists every deployment, newest first: the certificate,
the server with the certificate file, who triggered it (a person, or **Alice (automatic)**), the result and when it
was requested. A deployment that succeeded without being verified keeps **Succeeded** in a warning color with
"Verification: Skipped" or "Verification: Not done" under it. **Show more** loads older deployments; the page shows
how many are listed ("N shown") and never a total or a count per result. The arrow at the end of a row (**Open
deployment**) opens the deployment: **Status** and **State** at the top, then the outcome (after a failure, the error
with what to do), the **Deployment sequence** (each step with its own result; a step that did not run is never shown
as done), **Operation details** (certificate, server, source, certificate and key file, when it was requested, by
whom, started and finished, and **Verification**), **Evidence** (the new certificate's fingerprint, the served
certificate's when the verification reported it, the **Previous certificate** and the **Backup on the server**,
`/var/lib/alice-helper/backups/<deployment ID>`) and, when Alice has them, **Technical details** (the failed step,
its cause and the helper's error). A certificate's page lists its own deployments. There is no
button to repeat or undo a deployment: deploy again, or deploy the earlier certificate (Alice needs its key). Undoing
by hand from the backup is described in
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
example `ALC-AKV-0003` when Alice lacks **Key Vault Secrets User**). **Deployments** shows such deployments
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

## Issued certificates (ACME)

**Issued certificates** lists the certificates Alice gets from a certificate authority (for example Let's Encrypt or
your company's own CA) and renews by itself. An administrator first adds the authority, registers an account with it
and sets up how names are proved (a DNS hook, or the web proof on an Nginx server); that setup is in
[admin-guide.md](admin-guide.md#certificate-authorities-acme). Everyone can read these pages. Administrators and
operators run tests, order and deploy; only administrators choose which certificates Alice gets, delete them and
switch automatic renewal and automatic deployment on. Each certificate Alice receives is also listed under
**Certificates** as **Issued by ACME**, with its private key in Alice.

The list shows each certificate's names, authority, **Status**, proof method, expiry, **Next renewal** and whether it
renews and deploys automatically. Filter by **Status** and **Certificate authority**.

| Status | Meaning |
|---|---|
| **Not issued yet** | Saved, but no certificate was received yet. Nothing happens until someone chooses **Get certificate now**. |
| **Being issued** | An order is running. |
| **Active** | Alice holds a current certificate and renews it as planned. |
| **Renewal failing** | The last renewal attempts failed; Alice tries again by itself with growing waits. The page says when. |
| **Renewal stopped** | Five renewals in a row failed and Alice stopped trying by itself. See [Renewal](#renewal). |

### Get a certificate

**Get a certificate** (administrators) opens five steps; **Back** keeps every answer:

1. **Authority**: only authorities with a registered account and allowed names can be chosen; the others say why.
   Each shows the domain endings it may issue for.
2. **Names**: up to 100 names, each with at least two parts (`www.example.com`). A wildcard is only allowed as the whole
   first part (`*.example.com`). No IP addresses. Alice warns at once about a name outside the allowed endings.
3. **Proof method**: **DNS proof (DNS record)**, with the DNS provider or hook to use; or **Web proof (file on the web server)**, with
   the Nginx server that answers for the names on port 80 (not for wildcard names). **Prepare the server once**
   shows the three Nginx lines the server's administrator adds.
4. **Websites and options**: **Key type** (ECDSA P-256 is recommended; ECDSA P-384, RSA 2048, 3072 or 4096),
   **Renew how many days before it expires** (1 to 60, default 30), **Renew automatically** (on by default) and
   **Deploy new certificates automatically**. Websites are connected later, on the certificate's page, once the first
   certificate is issued.
5. **Review**, then **Save certificate** (with a fresh code). Saving orders nothing.

Then choose **Run a test first** (recommended), **Get certificate now**, or **Open the certificate**.

### Test run

**Test run** (administrators and operators) checks that the authority can verify every name, without getting a
certificate: Alice publishes the proofs (the DNS record or the file), the authority checks them, and Alice removes
them again. No key is made, nothing is issued or installed, and a failed Test run does not count as a failed
renewal. The result appears at the top of the page ("Test run succeeded: the authority verified every name" or "Test
run failed" with the reason). A Test run does contact the authority, and failed checks count against the authority's
request limits: test with **Let's Encrypt (staging, for tests)** first when you try out a new setup.

### Get certificate now and Order now

**Get certificate now** (before the first certificate) and **Order now** (afterwards) ask the authority for a new
certificate at once (administrators and operators, also with a **Read and operate** API token). While Alice talks to
the authority the page says so and updates by itself every few seconds; Alice waits at most about ten minutes for
the authority (`ALC-ACM-0010` after that). Only one order of a certificate runs at a time (`ALC-ACM-0016`). The new certificate
becomes the **Current certificate** (fingerprint, issuer, validity, whether its chain is complete, **Open in the
certificate list**). It is put on websites only by automatic deployment (both switches on, see
[Websites](#websites-of-an-issued-certificate)) or by **Deploy now**.

**Orders** lists the last orders, newest first: when, **Certificate** or **Test run**, the result, the problem in
plain words, and **Started by** (**By a person** or **Automatic renewal**). A problem shows its title, "What to do"
and its code; every code is explained in [troubleshooting.md](troubleshooting.md).

### Renewal

The **Renewal** panel shows when Alice renews the certificate (**Renews**), whether **Automatic renewal** is on (only
an administrator changes it), **Failed attempts in a row**, **Last attempt**, **Next attempt**, the **Window suggested
by the authority** when the authority publishes one, and the **Last problem**. Alice renews by itself when the time
left falls below the chosen number of days, or below a third of the certificate's lifetime if that is shorter, or
earlier when the authority suggests it. **Next renewal** in the list is calculated from the same rule in your browser
and can differ from Alice's own plan by a few minutes.

After a failed renewal Alice tries again after 1, 2, 4, 8 and 16 hours, then once a day, or later when the
authority asks for a longer wait ("Renewal is failing … Alice tries again at <time>"). The authority's wait is
honoured in full, up to 7 days: the page then says "The certificate authority asked Alice to wait until <time>", and
**Order now** and **Test run** stay unavailable until that time (ordering sooner only makes the wait longer). **Kind of the last problem**
says whether it was a temporary outage (Alice keeps trying by itself, more often as the certificate nears its end,
until it is renewed) or a cause that needs a person. The alert recipients get an e-mail at the third failure in a
row, and reminders 14, 7, 3 and 1 days before the certificate ends while renewal fails. After the fifth failure that
needs a person, the status is **Renewal stopped** and they get another e-mail; the current certificate keeps working
until it expires. Fix the cause shown under **Last problem**, then:

- an operator uses **Test run** to check, and **Order now** to renew at once: a successful order ends the stop;
- an administrator can also choose **Check again and resume** (with a fresh code), which switches automatic renewal
  on again, clears the failures and orders the certificate at once.

### Websites of an issued certificate

**Websites using this certificate** lists the websites (a certificate file on a managed Nginx server) that follow
this certificate, with the server, the file, what the website serves now and its state:

| State | Meaning |
|---|---|
| **Up to date** | The website got the current certificate and no newer check disagrees. |
| **Waiting for deployment** | The website does not serve the current certificate yet: nothing was deployed yet, a deployment is waiting or running, or automatic deployment is off for it. |
| **Needs attention** | The last automatic deployment of the current certificate to this website failed. The row shows the problem and since when. The website kept its previous certificate (a failed deployment is undone). |
| **Changed outside Alice** | The website had the current certificate, and a newer check found another one on it or in its file (R52). |

**Observed today** shows, for each website, what it should have, what Alice last deployed, what the file held at the
last scan that read it and what the website served at the last check (each with its time, and whether the website
was checked from Alice or from the server itself). Alice checks each website about every 6 hours. **Changes outside
Alice** is the choice of what Alice does when a website changes outside Alice: **Report only**, **Prepare a repair**
(then **Repair** deploys the right certificate again with one click, as **Deploy now** would) or **Repair
automatically** (an administrator's choice, with a fresh code); after 3 repairs within 24 hours that came back, Alice
stops repairing the website by itself because another tool keeps changing it, and says so in the row. See
[admin-guide.md](admin-guide.md#drift-what-should-be-there-and-what-is-there). The server's page shows the same for its
certificate files.

**Needs attention** appears at the next run of the automatic deployment planner, about a minute after the
deployment failed, not at the moment it fails. **Deployments** has the details of each deployment at once.

- **Add websites** (administrators and operators, after the first certificate is issued) lists the Nginx websites
  whose key type fits the certificate. A website follows only one certificate: one already connected to another
  certificate from an authority or to a Key Vault certificate is refused (`ALC-ACM-0028`). Websites are connected one
  after another; if one is refused, the dialog says how many were connected and that the rest were not tried.
  Connecting changes nothing on the server.
- **Deploy now** (administrators and operators) puts the current certificate on the websites you tick, at most 20 at
  a time, each as its own deployment (see [Deploying a certificate](#deploying-a-certificate) and
  [Results and what to do](#results-and-what-to-do)). Follow it on **Deployments** with **Open this deployment**.
  **This page does not refresh the websites' states by itself after Deploy now**: reload it to see **Up to date**.
  A certificate whose chain is incomplete is deployed only by an administrator who confirms the chain.
- **Remove** takes a website out: Alice no longer deploys this certificate to it, and the website keeps the
  certificate it serves. It works also while the license is locked.
- Before you change one of these websites' certificate by hand, remove the website here, or switch off its automatic
  deployment and choose **Report only**; otherwise Alice may put this certificate back at the next renewal or, with
  automatic repair, at the next check.

**Automatic deployment** needs two switches: **Automatic deployment of new certificates** for the certificate, and
the switch of each website. The panel says "Will deploy automatically to N of M websites" and warns when only one
kind of switch is on. Only an administrator, with a fresh code, can switch them on (Alice asks for a confirmation
first); an operator can switch a website's automatic deployment off. After each renewal Alice deploys the new
certificate to those websites within about a minute, at most 5 at a time, waits an hour before trying a failed
website again, and stops after three failed deployments ("Automatic deployment stopped": fix the cause, then **Deploy
now**). Two holds wait for a person: **Automatic deployment is waiting for an administrator** (the certificate
arrived before the license allowed changes again: an administrator chooses **Release**, or anyone uses **Deploy
now**) and **Automatic deployment is holding this certificate** (its chain is incomplete: an administrator uses
**Deploy now** and confirms the chain).

### Deleting an issued certificate

**Delete** (administrators, with a fresh code) stops renewing the certificate and forgets which websites follow it.
The websites keep the certificate they serve, and the certificates already issued stay under **Certificates**. It is
refused while an order runs (`ALC-ACM-0016`) and works while the license is locked. The web interface changes only
the switches of a saved certificate; to change its names, authority, proof method or key type, an administrator
saves a new certificate (or uses `PATCH /api/v1/acme/certificates/{id}`). The key type cannot change while websites
are connected (`ALC-ACM-0018`).

### Revoked and compromised certificates

An issued certificate that an administrator revoked shows **Revoked** in its orders and on the certificate's page,
with the time and the reason; one whose private key was marked compromised shows **Key compromised**. Neither is
deployed again: **Deploy now** and automatic deployment refuse it (`ALC-CRT-0018`, `ALC-CRT-0019`), and a deployment
that was waiting for it ends without sending anything. While automatic renewal is on, Alice orders a new certificate
at once. Revoking and key compromise incidents are administrators' work
([admin-guide.md](admin-guide.md#key-compromise-replace-a-certificate-everywhere)); everyone can read **Where it is
used** and the incident pages.

### While the license is locked

The page says "The license does not allow changes now": **Test run**, ordering, **Deploy now**, adding websites and
switching automatic deployment (on or off) are refused (`ALC-LIC-0001`) and nothing is renewed or deployed
automatically. **Remove** of a website and **Delete** of a certificate still work.

## Network discovery

**Network discovery** finds the certificates that servers on your network present, also the ones Alice does not
manage. Everyone can read it (auditors read only); administrators and operators start and cancel scans; only
administrators define what may be scanned (the **Scopes**, the **Allowed scan networks**, the exclusions and the
retention). That setup, the limits and what Alice never scans are in
[admin-guide.md](admin-guide.md#network-discovery). A scan opens a TLS connection to each address and port of a
scope, reads the certificate the server presents and closes the connection. It sends nothing else and changes
nothing on the scanned servers. **Nothing is scanned until an administrator adds a scope.**

### Starting and following a scan

On **Scopes**, choose **Scan now** on a scope, or **Start a scan** on **Scans** to pick one. A scope that cannot be
scanned now says why next to the button: switched off, already being scanned (`ALC-DSC-0004`), two scans already
running (`ALC-DSC-0007`), no allowed scan networks set, or the license does not allow it. Scopes with a schedule are
also scanned by themselves. **Scans** lists the newest scans first, with **Answered**, **not answering** and the total
of places tried, the start, the end and the duration; the list updates by itself while a scan on the first page
runs. **Cancel scan** stops a running scan (administrators and operators, also while the license is locked); the
places already tried keep their results. A scan ends **Finished**, **Cancelled**, **Took too long** (60 minutes;
`ALC-DSC-0006`) or **Failed** (for example when Alice restarted during it; `ALC-DSC-0012`). Open scans started from
outside the page (an API call) show up after you reload the page.

An **Answered** place completed a TLS handshake; **not answering** places refused the connection, did not answer in
time, closed it during the handshake, or **did not complete a TLS handshake** (a plain-text service, a TLS alert, no
common protocol version or cipher suite). The last group is deliberately one state: Alice does not say "plain text",
because it cannot tell.

### Reading the results

The **Results** tab shows the certificates still found (**Still found**; **Include no longer found** adds the rest),
one row per certificate with the number of places it was found on. Filter by status, expiry, who signed it, scope,
or search a name. A row opens a side panel with the places (address, port, the server name asked for, the last
problem in words, TLS version and cipher, first and last found, earlier certificates there, and the server in Alice
if one has that address or host name).

- **Unmanaged**: Alice has no record of this exact certificate. This includes a certificate on a proxy or a load
  balancer in front of servers Alice manages, unless Alice stores that same certificate.
- **Managed**: Alice has it, and it is in use on a server it manages. **Known**: Alice has it in its inventory but not
  on any server it manages now.
- **Self-signed** and the expiry badge say what the certificate is, not whether to trust it: Alice checks nothing
  about the chain or the name. Discovery has no **Wrong name?** warning.

The count in **Found on the network, not managed (n)** on **Certificates** (shown only when a scope exists) and the
Overview line count the unmanaged certificates a place still presents, so they can be lower than the **Unmanaged**
list when **Include no longer found** is on.

**Add as server** (administrators) opens the Add server dialog with the place's address filled in. A new server
counts toward the license, which Alice checks when you add it; the SSH port stays 22. When the certificate then
appears in the inventory, the next scan shows it as **Managed**.

**Export** saves the filtered list as a CSV file. Discovery never changes the number of servers the license
counts.

### Before you scan

Scans can trip intrusion detection and rate-based alarms: a /20 is thousands of TLS connections from the Alice
server in minutes. Tell the people who run those systems first, and start with a small scope. A scan of a few
addresses finishes in seconds; at the default 20 connections a second, 5,000 places take about 4 minutes.

## SSH keys and rotation

Alice can generate SSH keys, put a key into a user's key file on a managed server (**Deploy**), hand the private key to
an administrator, and replace a key everywhere it is used (**rotation**). Only keys Alice generated can be deployed,
downloaded or rotated; keys Alice found on servers are listed and can be removed (see
[admin-guide.md](admin-guide.md#ssh-keys)). Alice's own connection key is never deployed, downloaded or rotated (see
[Alice's SSH key](#alices-ssh-key)). Who may do what, what Alice stores and the background tasks are in
[admin-guide.md](admin-guide.md#generated-keys-and-rotation). The decisions behind this chapter are R41 in the design
record.

### Generating a key

Open **SSH keys** and choose **Generate key**. Give it a **Name** you recognise (1 to 100 characters, for example the
team or system that uses it) and a **Key type**: **Ed25519 (recommended)**, **RSA 3072**, **RSA 4096** or **ECDSA
P-256**. Administrators and operators can generate keys. Alice keeps the private key only encrypted with its master
key and never shows it; the key appears in the list as **Generated by Alice** at once, before it is used anywhere.
Alice generates at most two keys at a time ("Alice is busy generating other keys", `ALC-KEY-0011`: try again in a
moment). Nothing can be generated while the license does not allow changes.

### Deploying a key

On the key's page choose **Deploy to a server**, then the **Server**, the **User on the server** and the **File**.
Optionally enter **Allowed source addresses** (up to 16 IP addresses or networks, written as `from="…"`) and tick
**Allow sign-in only (no forwarding)**, which adds OpenSSH's `restrict` option: no port, agent or X11 forwarding, no
terminal for the session and no `~/.ssh/rc`. Alice writes no other option. The line ends with the comment
`alice:<name>:<date>`.

Alice adds the line in the background, then proves it: it opens a new SSH connection to the server as that user,
offering only the new key and requiring the server fingerprint you confirmed. Nothing is run on the server; only the
sign-in is tested. The result:

| Result | What happened |
|---|---|
| "Alice added the key and verified a login with it." | Done. |
| "Alice added the key but could not test a login with it." | The line stays. Alice could not prove a login: the line has allowed source addresses that may exclude Alice, the server let Alice in without asking for the key, or Alice could not connect for the test. Check the login yourself. |
| "The key was already on the server." | Alice changed nothing. It never removes a line that was there before it started. Alice scans the server so that its list shows the line. |
| "The server did not accept the key, so Alice removed it again." | The sign-in with the new key was refused (`ALC-KEY-0010`); Alice removed only the line it had added. Check the account and the SSH settings for that user. |
| "Alice could not add the key." | The server refused the change or could not be reached; nothing was changed. |
| "The key did not work and Alice could not remove it again." | The line is still in the file (`ALC-KEY-0012`). Remove it on the key's page when the server can be reached. |

If the server's answer to the addition was lost, Alice waits until the request can no longer arrive (about 80
seconds) and then looks at the file again. It never removes a line it cannot prove it wrote; when it cannot decide,
the task stops for a person (`ALC-KEY-0016`) and Alice scans the server about an hour later.

**Files Alice will not touch, and why:**

- The account Alice connects with (`alice-svc`) and every key file that account reads: the setup commands own them
  and write them again whenever they run (`ALC-KEY-0009`). Alice checks this by file, not only by user, so a file that
  several accounts share with `alice-svc` is refused too.
- Any file on a server where the last scan did not list the key files of `alice-svc` completely: Alice cannot rule out
  that the file is one of them, so the dialog offers no file and a deploy is refused (`ALC-KEY-0014`). **After the
  upgrade to this version every server is in this state until it has been scanned again.** A server with more than
  200 accounts, or one whose `alice-svc` is not in `/etc/passwd`, stays in it.
- Files the SSH server does not read for that user as the last scan found them (`ALC-KEY-0013`). A user or an
  `AuthorizedKeysFile` setting added after the last scan needs a scan first.
- Servers that get their keys from a program (`AuthorizedKeysCommand`), servers whose SSH settings the last scan could
  not read, disabled servers, servers whose identity changed and servers whose fingerprint is not confirmed.
- A retired key, a key whose private key was destroyed, a key found on a server, and the new key of a rotation that
  has not finished (`ALC-KEY-0018`: if that rotation were undone, the line would disappear with it).

**Scan the server again** means: open the server's page and choose **Scan for SSH keys** (on an Nginx server,
**Discover**), wait until it has finished, then open the dialog again. Alice also scans every connected server on its
own once per discovery interval (one day unless it was changed).

A deploy is a background task of the server (up to three attempts). While the license does not allow changes it is
held under **Waiting for an administrator** on **Servers** (see [Background jobs](#background-jobs)).

### Downloading a private key

On the key's page an administrator chooses **Download private key**. Alice asks for a **Reason** (10 to 500
characters; do not paste secrets there) and, before the file is sent, a fresh code from the authenticator app. Tick
**Protect the file with a passphrase (recommended)** and enter a passphrase of at least 12 characters (at most 1024
bytes): Alice encrypts the file with it (OpenSSH format, `aes256-ctr` with bcrypt) and does not keep it; without it the
file cannot be opened. Without a passphrase the file is not encrypted.

The file is an OpenSSH private key named `alice-<name>-<8 hex characters>.key`; use it with `ssh -i <file>`, or
convert it with `ssh-keygen -p -m PKCS8 -f <file>` for a tool that reads only PKCS #8. Alice records the download in
the audit log (with your reason and whether the file is protected) and counts it ("Downloaded N times") before the
first byte of the file is sent; if that record cannot be written, no file is sent. Keep the file safe and delete it
when it is no longer needed.

Rules: administrators only, in a signed-in browser (never with an API token); at most 5 downloads per minute per
person; possible while the license does not allow changes; possible for a retired key until its private key is
destroyed. Alice's own key and keys found on servers cannot be downloaded (`ALC-KEY-0006`), nor a key whose private
key was destroyed (`ALC-KEY-0008`). A download is refused while the computer's clock is behind the time of this key's
last download (`ALC-KEY-0015`).

### Rotation policies

A rotation replaces a generated key: on every server and user where Alice found it, Alice adds a new key next to the
old one, checks that the new key works, keeps both for an overlap, checks the new key again and only then removes the
old key. On a generated key's page, under **Automatic rotation**, an administrator chooses **Create rotation
policy**:

| Field | Meaning |
|---|---|
| **Name** | 1 to 100 characters. |
| **Rotate every (days)** | 1 to 3650. The first run is due this many days after the policy is switched on, the next one this many days after each run started. |
| **Keep the old key for (days)** | The overlap, 0 to 90 (default 7). Both keys work during this time, so that people and systems can switch to the new key. |
| **Notify before each run (hours)** | 1 to 168 (default 24): how long before a scheduled run Alice emails its preview. |
| **New key type** | **Same as now** (default) or another type. |

A key has at most one policy. A new policy is **Off**: Alice plans no run until an administrator switches **Rotate
automatically** on, which asks for an authenticator code. Changing the interval, the overlap, the notice time or the
new key type of a policy that is on switches it off and cancels a planned run that has not started; switch it on
again afterwards. Renaming leaves it on. **Delete policy** leaves the key as it is and cancels a planned run that has
not started; it is refused while a run has started. A rotation always covers every place of the key (there are no
partial policies) and there are no weekday or time-of-day schedules.

**Key rotations** (under **Operations** in the navigation, for every role; also reached from **SSH keys** through the
**Rotation policies** tab) shows the rotations that are running, each with its progress (**Generate new key**,
**Deploy & verify**, **Overlap period**, **Retire old key**) and **Inspect run and locations**, and every policy with
its interval, overlap, next run and last result. The page only reads: policies are created, changed and run on the
key's own page, and the decisions of a run are on the run's page.

### Previews and notices

**Preview next run** shows exactly what a run would do now: for each place (server, user, file) the line to add and
the line removed after the overlap, the places Alice cannot test a login in, and the places it skips with the reason
(the reasons are listed in [troubleshooting.md](troubleshooting.md#ssh-key-rotation)). A preview changes nothing and
is also emailed to the administrators, at most once per key in 10 minutes (the dialog says whether it was emailed).

For a scheduled run, Alice plans the run when the notice time before it is reached, and emails its preview to every
administrator. **A scheduled run starts only when that email was delivered to at least one administrator before the
planned start** (accepted by the mail server). Otherwise it is cancelled at the planned start ("its notice email was
not delivered in time", `ALC-ROT-0017`) and the next interval's run is planned as usual: without working email
delivery no scheduled rotation ever runs (see [Email](#email)); **Run now** still works. At the planned start Alice
plans again; if anything changed (a server became unreachable or was scanned again, a key line was added or removed by
hand, the policy changed), the run is cancelled (`ALC-ROT-0003`) and a new preview is emailed. If no place can change,
no run is created: the administrators get one email naming the skipped servers, and the policy moves on to its next
interval.

### Run now

**Run now** opens the preview; check it and choose **Run now**, then **Start rotation** (with an authenticator code).
Alice starts exactly the plan you saw: if it changed meanwhile, nothing starts and the dialog shows the new preview to
check. **Run now** also starts a planned run early (the run still shows "Scheduled run"); it does not wait for the
preview email. It is refused while another run of the key has started (`ALC-ROT-0002`) and while the license does not
allow changes.

### The run page

Each run has a page (**Key rotation**; open it from the key's page with **Open the current run**). It shows the old and
the new key, the state, the places with their state, counts and the recorded steps. A run goes through these states:

1. **Planned**: previewed and waiting for its start.
2. **Adding the new key**: in each place Alice adds the new key next to the old one (with the same options as the old
   line) and signs in with it at once. If the new key cannot be added anywhere, or a sign-in with it is refused, Alice
   undoes the whole run (**Undoing**, then **Undone**): it removes the new key wherever it added it. The old key is
   never touched by an undo.
3. **Waiting for a decision**: Alice could not test the new key in some places (allowed source addresses that may
   exclude Alice, a server that lets Alice in without asking for a key, root on a server that does not allow root to
   sign in). The administrators get an email; the decision is due within 14 days, otherwise Alice undoes the run.
4. **Both keys valid**: the overlap. The administrators get an email with its end; with an overlap of more than two
   days, another one day before the end. Use this time to switch people and systems to the new key (an administrator
   downloads its private key on the new key's page).
5. **Removing the old key**: in each place Alice signs in with the new key again (at most 15 minutes before the
   removal) and removes the old key only where that worked.
6. **Completed**, with an email; "completed" with a count of places where the old key stays when some were kept or
   skipped. The policy now belongs to the new key, and the old key is retired once nothing uses it.

The decisions, offered only when they apply and only to administrators:

- **Continue**: after a license pause (see below). Alice goes on where it stopped and tests the new key again before
  it removes any old key. Needs an authenticator code.
- **Finish now**: ends the overlap now and emails the administrators the new removal time. Each removal still needs a
  fresh sign-in with the new key. Needs an authenticator code.
- **Keep the old key on these servers**: for places Alice could not test. Tick the places where the old key stays;
  Alice never removes it there, nor from other places in the same file. At least one place where the new key works
  must remain (otherwise only **Stop and undo** is possible). When no untested place is left, the overlap begins.
  Needs an authenticator code.
- **Stop and undo**: possible until the removal of the old key begins. Alice removes the new key where it added it;
  the old key stays. It needs no authenticator code and also works while the license does not allow changes; an
  administrator's API token with operate access may use it too.

A place shows one of: **Waiting**, **Skipped**, **Not started** (never sent, or refused when Alice was about to send
it), **Adding**, **Added**, **Could not add**, **New key works**, **Cannot be tested**, **New key did not work**,
**Old key kept**, **Removing the old key**, **Old key removed**, **Old key not removed**, **Removing the new key**,
**New key removed**, **New key could not be removed**.

### What a license pause does

While the license does not allow changes (expired, or not checked for 3 hours), no rotation is planned and a planned
run that has not started is cancelled (`ALC-ROT-0012`); after the renewal the policy previews a new run with a new
email. A started run is paused at the next background check (within a minute): Alice adds no new key, removes no old
key and sends nothing to the run's servers, and the overlap's time and the 14-day decision time stop. Two things
still reach servers: an addition or removal that was already being sent when the lock began finishes, and the
removal of the new key after **Stop and undo** (or after a failed sign-in). The administrators get one email when the
run pauses.

After the renewal Alice emails the administrators within about a minute; then an administrator chooses **Continue**
(before that email is queued Continue answers "Alice is still preparing the email about the license renewal",
`ALC-ROT-0021`). A paused overlap resumes with the time that was left, and every removal is preceded by a fresh
sign-in with the new key. While paused, **Stop and undo** is the only other decision.

### Kept and skipped places

The old key stays in place, and the run's count "Places where the old key stays" includes the place, when it is:

- **Skipped**: the preview's reasons (for example the server cannot be reached, a file several users of the server
  share, the account Alice connects with, a key listed twice in the file). Nothing is sent there.
- **Not started**: the reason was found when Alice was about to send the change.
- **Old key kept**: an administrator chose **Keep the old key on these servers**, or another place of the run in the
  same file was not verified (Alice never changes a file in part).
- **Old key not removed**: the fresh sign-in or the removal failed five times.

Before you remove the old key from such a place yourself, make sure the new key works there: in skipped and not
started places Alice never added the new key. A finished run with kept places sends its own email.

### When a run needs attention

**Needs attention** means Alice stopped and will not change these places again for this run:

- **The old key was kept on some servers** (`ALC-ROT-0009`): the sign-in with the new key or the removal failed there.
  Both keys work on those servers. Check them, then remove the old key there on the old key's page once the new key
  works. The policy stays with the old key (it moves to the new key only after a completed run): create a policy for
  the new key if it should be rotated too.
- **Alice could not remove the new key from every server** (`ALC-ROT-0008`): while undoing, a server could not be
  reached, its key file could not be read completely (`ALC-ROT-0025`), or the old key was already gone there and Alice
  kept the new key so that the account keeps a working key (`ALC-ROT-0018`). The old key was not touched. When another
  key works for those accounts, remove the new key there on the new key's page.

The email and the run's page name the servers. If a server's answer arrives after Alice gave up on a place, Alice
records it, scans the server and sends one more email ("Late answer in the SSH key rotation").

### Retired keys

After a completed run the old key becomes **Retired** once no place uses it any more (a key kept on some servers stays
active until it is removed there). Alice keeps a retired key's private key for 30 days, during which an administrator
can still download it, then destroys it (**Private key destroyed**); a retired key cannot be deployed. A retired key
found on a server again before that (for example a server restored from a backup) becomes active again; one found after
its private key was destroyed stays retired, and the audit log records it once ("Destroyed key found on a server
again"). Database backups taken before the destruction still contain the encrypted private key.

## Master-key rotation and the installation record

Master-key rotation (§7.2 of the design) is not available yet; there is no command for it. When it is added it must,
in the same procedure, re-seal the installation record (`license.installation_seal`, HMAC under the HKDF label
`alice/installation/v1`) and re-write both copies of the license time record (`settings.time.hwm` and
`<ALICE_STATE_DIR>/hwm.dat`, labels `alice/hwm/v1` and `alice/hwm-enc/v1`) with the new key; otherwise the next
start reports the installation as tampered and the evaluation as ended. It must also re-encrypt the platform SSH key
and re-compute the job payload MACs (label `alice/job/v1`). Do not replace `master.key` by hand.

The private keys of generated SSH keys (`managed_private_keys`) must be re-wrapped by the same procedure, and so must
the secrets of the settings in `setting_secrets` (the SMTP password `notify.smtp.password` and each identity
provider's client secret `sso.provider.<id>.client_secret`, AAD `setting_secrets/<key>/ciphertext`): a key left
sealed with the old master key makes e-mail (`smtp.*` failures) or that provider's sign-ins fail until an
administrator enters the secret again. The database
accepts a re-wrap only as a change of the wrapped data key and the key version together, and only to a higher key
version; nothing else of a stored private key can change, and a destroyed one stays destroyed. A re-wrap therefore
cannot be rolled back in place: going back to the previous master key means restoring the database backup taken
before the rotation together with the `master.key` it belongs to (a private key destroyed after that backup comes
back with it).

## Background jobs

Work on servers runs in a job queue stored in PostgreSQL: connection tests, scans, key removals, certificate
deployments and the finishing of interrupted deployments, SSH key deploys (`sshkey.add`) and the work of a key
rotation on one place (`rotation.location`). A running job
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
reached to **Connected** (audited as `target.status_changed` with the reason `discovery_ok`, `removal_ok` or
`key_added`, the last when a deploy or a rotation recorded a key it added). A
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
queued, queued tests and scans are cancelled (each recorded as `job.cancelled_license`), and queued key removals, key
deploys and deployments are held as "Waiting for an administrator" on **Servers** until an administrator runs or discards them
after the next license is installed. A deployment that already reached a server is still finished or undone in
lock. Key rotations pause instead (see [What a license pause does](#what-a-license-pause-does)).

Alice also stops changes when it cannot check its license. Each Alice process checks the license at start, every
hour and after an upload; a failed check is tried again after 1, 2, 4 and 8 minutes, then every 10 minutes. When no
check has succeeded for 3 hours (counted in the time since the process started, including time the host or virtual
machine was suspended),
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
(`notify.send`, every minute; retries for 24 hours, see [Email](#email)), the expiry check (`alerts.scan`, every 15
minutes, also in lock: it records and queues the expiry e-mails of certificates in use, Key Vault certificates, keys
and client secrets; at most 20 e-mails per kind and check plus one summary; one check at a time across processes,
through a database lock, so a second one is skipped and logs `alerts.scan_skipped`; when notices were recorded but
nobody would get them it logs `alerts.no_recipients`), audit chain verification (checked every
hour, run once a day, recorded as `audit.verified` by `scheduler`; its result and the verified head hash are on the
**Overview**, tab **Assurance**), clean-up (hourly: expired sessions and setup
sessions, single sign-on states older than 10 minutes, finished jobs older than 90 days), scheduling of the daily server scans (every minute) and the check for
interrupted deployments (every minute), and for Key Vaults the queueing of due vault checks with the clean-up of
imports whose task ended (`kv.schedule`, every minute) and the planning of automatic deployments (`kv.auto_deploy`,
every minute), and for SSH keys the planning of scheduled rotations (`rotation.plan`, every minute; not while the
license does not allow changes), the rotation sweep (`rotation.sweep`, every minute, also in lock: it advances every
run, pauses runs in lock, sends the renewal email and queues the work of each place again, at most five times per
place and step) and the hourly `sshkey.destroy_retired` (destroys the private keys of keys retired 30 days ago, at most
500 per run, after the retention of **Settings → General**, 30 days by default; retires old keys nothing uses any more, and records the outcome of key deploys whose task ended without
one, queueing a scan of their server; not in lock). A key deploy gets up to 3 attempts; a rotation's place job is
queued again by the sweep and never sends the dead-job email (the rotation's own emails report its failures). A vault check (`kv.poll`) runs once, without a retry and without a dead-job email (its failure is
shown on the vault, and the next check follows the vault's interval); an access check (`kv.test_connection`) runs
once; an import (`kv.import`) gets up to 3 attempts and is retried only before it was sent, and when another path
ended its import (the vault was removed) the job ends failed with the import's code, without an email. For
certificates from certificate authorities: the renewal planner (`acme.schedule`, every minute; not while the license
does not allow changes), the automatic deployment planner (`acme.auto_deploy`, every minute; not in lock either) and
the sweep (`acme.sweep`, every minute, also in lock: outside lock it finishes an order that a restart interrupted
after the authority issued the certificate, ends one it cannot finish after 5 minutes without its task (`ALC-ACM-0026`), and
queues the removal of proof records left behind). An order (`acme.issue`) runs once: its retries are the renewal
planner's, never the queue's. The removal of proof records (`acme.cleanup`, also in lock) gets up to 5 attempts and
no dead-job email; the sweep queues it again every hour for seven days. The network discovery jobs: a scan (`netdisco.scan`, one per scope and at most two at once; it
runs once, with no retry, and stops as cancelled while the license is locked), the schedule check
(`netdisco.schedule`, every minute, on the leader; not while the license does not allow changes) and the cleanup
(`netdisco.retention`, every hour, also in lock; it touches only discovery data). A scan whose job died is ended as
**Failed** (`ALC-DSC-0012`) by the next schedule check or cleanup; after a lost lease the old run may keep connecting for up to
45 seconds, so three scans can briefly run. The alert recipients get the usual dead-job e-mail when a scan job dies;
there is no other scan-failure e-mail. The alert
recipients get an email when a job stops after its last attempt, when a job was changed in the
database, and when the daily audit check finds a problem.

## Checking an audit export outside Alice

The JSON export (`GET /api/v1/audit/export?format=json`, or **Export JSON** on the **Audit trail** page) holds a
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

The CSV export is meant for spreadsheets: cells that start with `=`, `+`, `-`, `@`, a tab, a carriage return or a
line feed get a leading apostrophe, so use the JSON export for this check.

## State volume

Alice keeps its license time record (the latest time it has seen, encrypted and protected with a MAC derived from
the master key) in `ALICE_STATE_DIR` (default `/opt/alice/state`, the `alice-state` volume, owned by user 10001)
in addition to the database. Every backup includes it, and `alicectl restore` restores it together with the whole
database ([backup-restore.md](backup-restore.md)): a database put back by other means without its `license` table
(or only some tables) counts as a removed installation record and ends the evaluation. On a new, empty database Alice refuses to start when the file exists but cannot be read (for example
because the volume's permissions are wrong): it creates nothing and says "make the state directory readable by
Alice and start again". A new installation must also start with an empty state volume: a time record left by an
earlier installation counts as an earlier installation, and the new one starts with an
ended evaluation (ask the vendor for a license for the new Installation ID). If the file is lost or damaged, Alice uses the copy
in the database and records "time record damaged" (`clock.hwm_damaged`) in the audit log; if both are lost on an
existing installation, Alice starts from the later of the system clock and the release's build time and records
"time reference reset" (`clock.time_reference_reset`). Neither ever extends a license.

## Email

Since Phase 7 the mail server is set up by an administrator in the web UI, **Settings → Email** (with a test e-mail
and **Trust this certificate**), and who gets the e-mails in **Settings → Recipients**; see
[admin-guide.md](admin-guide.md#mail-server). The settings are stored in the database; the password only as an
envelope encrypted with the master key (table `setting_secrets`), never in a file, a log line or an API answer.

**Upgrading from the `ALICE_SMTP_*` variables.** At the first start of this version, when no mail settings exist in
the database yet, Alice imports `ALICE_SMTP_HOST`, `ALICE_SMTP_PORT`, `ALICE_SMTP_FROM`, `ALICE_SMTP_USERNAME`,
`ALICE_SMTP_TLS`, the password from `ALICE_SMTP_PASSWORD_FILE` and the certificate authority from
`ALICE_SMTP_CA_FILE` **once** (audit entry **Mail settings imported from the environment**, actor `startup`). The rules
of the import:

- `ALICE_SMTP_USERNAME` without a readable password (no `ALICE_SMTP_PASSWORD_FILE`, or an empty file): nothing is
  imported and the log says "ALICE_SMTP_USERNAME is set without a password file; the SMTP settings were not imported".
  Enter the settings in the web UI instead.
- Values Alice cannot accept, or a password or CA file that cannot be read: Alice does not start and says why; fix or
  remove the variables.
- After the import, and whenever mail settings exist (also after an administrator removed them with
  `DELETE /api/v1/settings/smtp`), the variables are **ignored** and every start logs the warning "ALICE_SMTP_* is set
  but the mail settings in Settings are used; remove the variables". Remove them from `deploy/.env`, delete the
  password file from `deploy/secrets/` and the mounts from `docker-compose.override.yml`: changing them has no effect
  any more.

Alice never sends e-mail unencrypted (`starttls` or `tls`, TLS 1.2 or newer) and checks the server's certificate
against the system's authorities, the optional certificate authority of the settings, or the certificate an
administrator pinned. The mail server is reached through the same address rule as SSH (link-local and metadata
addresses refused, `ALC-NTF-0009`).

**Delivery.** E-mails are queued in the database (`notifications_outbox`) and sent every minute, one per recipient
(task `notify.send`). A failed send is retried after 30 seconds, doubling up to one hour, for 24 hours after it was
queued; then it is marked `failed` and Alice logs an error with `event=notify.gave_up`. Every failed attempt is logged
with a reason code (`smtp.connect`, `smtp.tls`, `smtp.untrusted`, `smtp.auth`, `smtp.rejected`,
`smtp.address_refused`), never the password or the server's text. After three failed attempts in a row administrators
see **E-mails could not be sent**; `GET /api/v1/notifications/status` (administrators and their API tokens) gives the
counts and the last error code. Without mail settings every e-mail is marked `skipped_no_smtp` and never sent later.

**Scheduled SSH key rotations need working email delivery.** A scheduled rotation starts only after its preview email
was accepted by the mail server for at least one recipient before the planned start; without mail settings, or while
the mail server refuses Alice, every scheduled run is cancelled (`ALC-ROT-0017`). **Run now** does not need email.
See [Previews and notices](#previews-and-notices). The failing banner and the test e-mail make a broken setup visible
before a rotation is due.

`ALICE_TRUSTED_PROXIES` and `ALICE_LOG_LEVEL` are still read from `deploy/.env` (see `docs/dev/getting-started.md`,
Configuration).

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

- behind a reverse proxy: set `ALICE_TRUSTED_PROXIES=<proxy address or CIDR, comma-separated>` in
  `/opt/alice/.env`, then run `cd /opt/alice && sudo docker compose up -d alice`. Alice then takes the client
  address from the proxy's `X-Forwarded-For` header. An update keeps the value, with one exception: the update
  script of the installed version rewrites `.env`, so an installed version that does not know the key (a release
  before this setting) drops it on that one update. Check `/opt/alice/.env` after the update and add the key again
  if needed. Without this setting everyone has the proxy's address. List only your proxies, never a client network: Alice believes the `X-Forwarded-For`
  header of every address in these ranges, so a client inside them can claim any address. It could then escape the
  per-address limits (sign-in attempts, bad credentials, `/healthz`) and write a false address into the audit log;
- when the published port is forwarded by a proxy process instead of the kernel (rootless Docker's default port
  forwarding, or Docker's userland proxy, which handles connections from the Docker host itself): Alice then sees
  one internal address for those clients. Check the **IP address** column of a few audit entries: if different
  people show the same address, this is the case;
- behind NAT, where many people share one public address.

## Development stack and production

| | Development stack | Production (release package) |
|---|---|---|
| Compose file | `deploy/docker-compose.yml` in the source, started with `make up` | `/opt/alice/docker-compose.yml` from the package, started by `install.sh` |
| Images | built from the source (`alice:dev`) | loaded from the signed package, never pulled (`pull_policy: never`) |
| Database owner role | the superuser `alice` | `alice_owner` (not a superuser); `alice_app` for the running Alice |
| Schema changes | at Alice's start | before Alice starts, in the one-time `migrate` container |
| Data | Docker volumes `alice_*` | directories under `/opt/alice` |
| Commands | `make setup-token`, `make unlock`, … | `sudo /opt/alice/alicectl …` |
| Backups, update | not set up for daily use | daily backups, `alice-update.sh` |

Never run the development or the test stack on a production server.

## Development stack reset

`make reset` **deletes the development database, keys and state volumes** (everything: users, audit log, license
files, Installation ID, master key, time record) and starts a fresh installation with a new Installation ID and a
new 30-day evaluation. Use it after pulling a phase that needs a fresh database (for example Phase 1 onto a Phase 0
stack: the `alice_app` role is created only on a fresh database). A license issued for the old Installation ID does
not work on the new one.

`make e2e-up` starts the **test build** as a separate compose project, `alice-e2e`, with its own database and volumes
on its own port (`ALICE_E2E_PORT`, default 9443); every Playwright run empties all its tables (`POST /test/reset`).
It never touches the `make up` stack. Never run the test build on a server.

The e2e stack also runs two test-only fakes, never part of a release and hardened like the other e2e containers
(`make e2e-hardening-check`): `fakesmtp` (a mail server with STARTTLS and a self-signed certificate generated at
start, a MailHog-compatible message API, and switches to go down or refuse an address; on the internal network only)
and `fakeidp` (an OpenID Connect identity provider with discovery, keys, sign-in and token endpoints and a switch for
the next person who signs in; published on `127.0.0.1:9444` only, reached by Playwright's browser as
`https://idp.alice-e2e.test:9444` through Chromium's host-resolver rule). Both are driven with `ctl` commands inside
their containers, for example `docker compose -p alice-e2e exec fakesmtp /alice-fakesmtp ctl messages` or
`… exec fakeidp /alice-fakeidp ctl next-user --sub S --groups alice-operators`; Phase 7's journeys
(`web/e2e/phase7.spec.ts`) use them. The e2e build never runs the expiry check on its own: tests run it with
`POST /test/scheduler/run`, and `POST /test/seed/dashboard` loads the dashboard's data set. The fake identity
provider signs with the real time, so a test that moves Alice's clock by more than about a minute must do its single
sign-on steps first.

`make perf` runs two performance tests (tags `integration perf`, in `internal/api`; one command, about 40 seconds): R32
(`TestR32DashboardAndListBudgets`): a test database with 5,000 certificates on 500 servers, 500 deployments and 5,000
audit entries, then 10 warm-up and 100 measured requests per page through the whole HTTP stack, against the budgets of
500 ms (dashboard) and 300 ms (lists) at the 95th percentile; and `TestPerfNetdiscoScan`: network discovery with
5,000 places, 5,000 certificates and 1,000 shared intermediates written through the scanner's own storage path, 500
servers and 5,000 inventory certificates for the managed, known and unmanaged links, then the same kind of requests
against the discovery pages (lists and details 300 ms, the Overview metric 500 ms), the CSV export of 5,000 rows (3 s)
and of 50,000 synthetic rows (30 s), the time to store a scan's results plus the connection time at the default rate
(under 5 minutes in all), and a flat heap over a second round. It also checks that the place list uses the
`discovery_targets_host` index. The numbers are in
[docs/security/reviews/network-discovery.md](security/reviews/network-discovery.md). Both need Docker
(testcontainers) and nothing else using it; never run them while Playwright runs.

### The discovery fleet in tests

The e2e stack also runs `fakefleet` (`cmd/alice-fakefleet`, `internal/testutil/fakefleet`; test-only and never in a
release): about twenty TLS servers on `10.89.0.10` of the internal `fleet` network (`10.89.0.0/24`; Alice is
`10.89.0.2`), each kind on its own port (the valid one on 443), also reachable as `<kind>.fleet.alice-e2e.test`:
valid, expired, not yet valid, self-signed, certificates in the wrong order or without the intermediate, one that
depends on the name asked for, TLS 1.0, 1.2 and 1.3 only, an RSA-key-exchange-only server, a SHA-1 signed leaf, a
slow-loris, a giant and a huge chain, a reset, a plain-text server, 256 names on one address and a malformed
certificate. Its certificates are made when it starts. The journeys (`web/e2e/phase11.spec.ts`) first set the
**Allowed scan networks** to `10.89.0.0/24` through the API, because loopback and everything the scan policy refuses by
itself are never scannable, and read what the fleet saw with `docker compose -p alice-e2e exec fakefleet
/alice-fakefleet ctl log --settle` (which addresses were dialed and whether an application byte came after a
handshake). The Go integration tests start the same fleet in-process on a private interface address of the machine
(`ALICE_REQUIRE_FLEET=1` in `make test-integration` and `make coverage` makes the test fail instead of skip when the
machine has none). The fleet is built with `docker build --network host` like the other test images; if
`make e2e-up` fails at the fleet image on your machine, build `alice-e2e-fakefleet` that way and bring the stack up
again.

### Migration 00014 was edited in place

Migration `00014` (the network discovery tables) was edited while the feature was being built: its check on
`alerts.kind` gained `discovered_certificate_expiry`. **A development database that is already at version 14 does not
get the change.** Migrate it down to version 13 and up again (the migrations are goose files: `goose down`, then `goose up`) or run `make reset` to start over, or
discovery alerts fail with a constraint error. Databases of released installations are not affected: the migration
was not part of a release before.

From the commit that added `migrations/frozen_test.go` on, migrations `00001` to `00015` are frozen by a checksum test; every later change to the schema is a new numbered migration.
