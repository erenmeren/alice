# Backup and Restore

This guide is for operators, IT managers and auditors who need evidence of business continuity. It explains what
Alice backs up, how to keep copies away from the server, and how to restore on the same or on a new server.

Commands run on the Alice server as root, in the installation directory `/opt/alice` (see
[operator-guide.md](operator-guide.md#alicectl-reference) for every `alicectl` command and its output).

## What a backup holds

One backup is one encrypted file. It holds everything needed to bring the installation back:

| Part | What it is |
|---|---|
| The database | Every table: users with their (encrypted) authenticator secrets, API tokens, servers, certificates and their (encrypted) private keys, SSH keys, Key Vaults and their (encrypted) credentials, rotations, jobs, settings, the license and the installation record with its Installation ID, and the whole audit log. Alice's own SSH key is in the database too (encrypted). |
| `keys/master.key` | The master key that opens every encrypted value in the database. |
| `keys/tls.crt`, `keys/tls.key` | The HTTPS certificate and its private key. |
| `state/hwm.dat` | The license time record. |

Not in a backup: the database passwords in `/opt/alice/secrets/` (a new server makes its own), `.env` and the
compose file (the installer writes them), the container logs, and the other backup files.

The database is read in one consistent snapshot while Alice keeps running. Nothing of the backup is ever written to
disk unencrypted.

**How it is encrypted.** The file is encrypted (AES-256-GCM in chunks of 64 KiB, each chunk authenticated) with a
key that only the installation's **backup key pair** can derive. The private half of that pair is stored only
inside the file, sealed with the **recovery passphrase** (Argon2id, 64 MiB of memory, 3 passes). Making a backup
therefore needs no passphrase; opening one needs the passphrase and nothing else, also on a new server. Every file
is also bound to the installation that made it (a second, installation-only key): a file that someone assembled
from the public parts of another backup does not open with your passphrase. That protection holds only against people
who do not know the passphrase: anyone who knows the recovery passphrase and has one of your backup files can build a
file that opens with it, and a restore of that file installs whatever they put in it. Keep the passphrase as secret as
the master key, and restore only backups you made and kept write-protected off the host. See
[security-overview.md](security-overview.md#encryption) for the details.

**File names.** `alice-backup-<first 8 characters of the Installation ID>-<UTC time>-<kind>.alicebak`, for example
`alice-backup-7F3K92QD-20261010T023000Z-auto.alicebak`, with a checksum file `<name>.sha256` beside it. Both are in
`/opt/alice/backups/` (mode 0600). The kinds:

| Kind | Shown as | Made by | Deleted automatically |
|---|---|---|---|
| `auto` | Daily | the daily schedule | yes, beyond the number to keep |
| `manual` | Manual | **Back up now** or `alicectl backup` | never |
| `pre-restore` | Before a restore | a restore, of the data it replaces | never |
| `pre-upgrade-<version>` | Before the update to … | the update, before it changes anything | never |

## Schedule and retention

Alice makes a backup every day at 02:30 in the time zone of the server at installation (UTC if it could not be
read). An administrator changes the time, the time zone and **Automatic backups to keep** (7 to 60, default 14) on
**Settings → Backups** ([admin-guide.md](admin-guide.md#backups)). Daily backups cannot be switched off. If the
server was off at the scheduled time, Alice makes the missed backup as soon as it runs again.

When there is not enough free disk space in the backups directory (twice the size of the newest backup plus 1 GiB),
Alice does not start the backup at all. A failed daily backup e-mails the administrators ("Alice could not make its
daily backup", with the error code, for example `disk_full`). After 48 hours without a successful backup,
administrators see the red banner **No successful backup for 48 hours** on every page and get the e-mail "Alice has
had no successful backup for 48 hours". The **Overview** (tab **Assurance**, **Recovery readiness**) shows the age of the last successful
backup to administrators and auditors.

Backups start only once the recovery passphrase is set in the setup wizard. Until then **Settings → Backups** says
**Backups start after the recovery passphrase is set.**

## The recovery passphrase

The administrator chooses it in the setup wizard ([first-run.md](first-run.md)). Rules:

- At least 16 characters, and the strength meter must say **Good** or **Strong**: a passphrase rated **Fair** is
  refused (`ALC-SET-0010`).
- Alice normalises the passphrase to Unicode NFKC before it uses it: the same text typed as one composed character
  or as a letter plus a combining mark (for example `ş`), or with full-width letters, opens the same backups. Upper
  and lower case still differ.
- The server never stores the passphrase, and no file on it can replace it.
- **It cannot be changed in this version**, and neither can the master key.

**If the passphrase is lost**, nobody (including the vendor) can open any backup of this installation. Alice itself
keeps working, but its backups are useless for a restore. Keep the passphrase written down in two safe places, away
from the server and away from the backup copies.

**If the passphrase is exposed**, anyone who has it and a copy of a backup file can open that backup, and every
older file stays readable with it for ever. Because the passphrase cannot be changed in this version, protect every
backup copy with access control of its own (who can read the backup share, the bucket, the tapes).

## Copy backups off the server

The backups directory is on the same disk as Alice. It does not protect against the loss of the disk or the server.
The files are encrypted, so they can be copied to any storage. Follow the **3-2-1 rule**: 3 copies, on 2 kinds of
storage, 1 of them off-site; and keep the recovery passphrase in a different place from the backups.

Copy the `.alicebak` files together with their `.sha256` files, and never overwrite a copy that already exists.
Every recipe below copies only those regular files (no links). Run them as root on the Alice server.

**rsync over SSH** to a backup host (a nightly cron job, `/etc/cron.d/alice-backup-copy`):

```
30 4 * * * root rsync -rt --no-links --ignore-existing --include='*.alicebak' --include='*.alicebak.sha256' --exclude='*' /opt/alice/backups/ backup@store.example.com:/srv/alice-backups/
```

**scp** of one file by hand:

```
sudo scp /opt/alice/backups/alice-backup-7F3K92QD-20261010T023000Z-auto.alicebak /opt/alice/backups/alice-backup-7F3K92QD-20261010T023000Z-auto.alicebak.sha256 backup@store.example.com:/srv/alice-backups/
```

**A Windows (SMB) share**, mounted with a credentials file that only root can read:

```
sudo mount -t cifs //fileserver/alice-backups /mnt/alice-backups -o credentials=/root/.smb-alice,uid=0,gid=0,file_mode=0600,dir_mode=0700
sudo rsync -rt --no-links --ignore-existing --include='*.alicebak' --include='*.alicebak.sha256' --exclude='*' /opt/alice/backups/ /mnt/alice-backups/
```

**S3 or another object store**, with the command-line tool of your choice, for example the AWS CLI or rclone:

```
sudo aws s3 sync /opt/alice/backups/ s3://example-alice-backups/ --exclude '*' --include '*.alicebak' --include '*.alicebak.sha256'
sudo rclone copy --ignore-existing --include '*.alicebak*' /opt/alice/backups/ store:alice-backups
```

Give the target an object-lock or versioning rule if it has one, so a copy cannot be deleted from the Alice server.
Without a script, an administrator can also download a file with **Download** on **Settings → Backups** (recorded
in the audit log).

Each quarter, also copy a backup to offline media.

## Check a backup

```
sudo /opt/alice/alicectl backup verify /opt/alice/backups/<file>
```

The quick check reads the header, the size and the checksum file, without the passphrase:
`The backup file looks complete (header, size and checksum are correct).`

```
sudo /opt/alice/alicectl backup verify /opt/alice/backups/<file> --deep
```

The deep check asks for the passphrase and decrypts the whole file:
`The backup opens with this passphrase and is complete: Backup from 2026-10-10 02:30 UTC, Alice 1.0.0, host alice01, installation ALICE-7F3K-92QD-….`
It changes nothing. **Once a month, run the deep check on the newest backup.** It proves that the backups really
open with the passphrase you hold, which the quick check and the daily schedule cannot prove.

A file must be in `/opt/alice/backups` to be checked; copy it there first.

## Restore on the same server

A restore replaces **all** current data with the backup. Use it after a mistake you cannot undo in Alice, or after
data damage.

1. Put the backup file into `/opt/alice/backups` if it is not there (see step 3 of the next section).
2. Run:

   ```
   sudo /opt/alice/alicectl restore /opt/alice/backups/<file>
   ```

3. Type the recovery passphrase at `Recovery passphrase: `. Alice opens the whole file first, while it keeps
   running. A wrong passphrase or a damaged file stops here (`The passphrase is wrong or the file is damaged. Nothing was changed.`).
4. Alice shows what the backup holds and asks:

   ```
   The backup opens with this passphrase and is complete: Backup from 2026-10-10 02:30 UTC, Alice 1.0.0, host alice01, installation ALICE-7F3K-92QD-….
   Type RESTORE to replace all current data:
   ```

   Type `RESTORE`. Anything else prints `Restore cancelled. Nothing was changed.`
5. Alice stops, and the restore runs. It loads the backup into a separate database, checks the row counts, the
   audit log chain, the master key and the installation record, saves the current data as a `pre-restore` backup,
   and only then switches to the restored data in one step. Then Alice starts again and runs its self-check.

   Expected, at the end:

   ```
   The replaced data was saved first as alice-backup-7F3K92QD-20261011T091500Z-pre-restore.alicebak.
   Restore finished. Everyone must sign in again. Users and API tokens are as they were when the backup was made; review them.
   ```

   followed by the seven `[ OK ]` lines of `alicectl selfcheck`.

Alice is started again whatever the outcome; if a check refuses the restore, the current data stays in use and
nothing was changed. The refusals and what to do are in
[troubleshooting.md](troubleshooting.md#restore-refused).

**After a restore:**

- Everyone signs in again.
- Users and API tokens are as they were when the backup was made: a person or token removed since then exists again.
  Review **People & access** and the API tokens, and disable or revoke what should not be there.
- The task queue is the backup's too. Tasks that change servers or Key Vaults (certificate deployments, Key Vault
  deployments, key removals, SSH key rotation steps) that were waiting or running when the backup was made do **not**
  start by themselves: running them against servers whose state has moved on since the backup could, for example,
  deploy a certificate version that was replaced later. They are held, the restore prints
  `Warning: <n> tasks of the backup that change servers or Key Vaults (queued or running when it was made) are held: review them under Waiting for an administrator on Servers, then run or discard each.`,
  and `system.restored` records the number (`held_jobs`). Open **Servers → Waiting for an administrator** and choose
  **Run now** or **Discard** for each ([admin-guide.md](admin-guide.md#servers)). Tasks that only read (scans,
  checks) and Alice's own maintenance run as usual, and work that falls due after the restore (renewals, rotation
  steps) starts as usual: check the rotations and deployments that were in progress.
- If audit forwarding is on, the syslog server receives entries again from where the backup's forwarding stood:
  first identical copies of entries it already has (up to the backup's newest entry), then `system.restored` and the
  entries after it under sequence numbers it already holds with other content. From there the two chains differ.
  This fork is expected and visible; keep both branches.

**Options** (all optional):

| Option | When to use it |
|---|---|
| `--passphrase-file FILE` | The passphrase from the first line of a file only root can read (mode 600), instead of the terminal. |
| `--confirm RESTORE` | Confirms without the question; needed when there is no terminal. |
| `--accept-broken-audit-log` | The backup's audit log chain is damaged and you still want this backup. The damage stays visible in Alice. |
| `--no-safety-backup` | The current installation has data but no recovery passphrase, so Alice cannot save it first. The current data is then replaced without a copy. |
| `--db-only` | Restores the database only and keeps the current key and state files. The update's automatic return uses it; the backup must have been made with the current master key. |

A backup made by a newer Alice version cannot be restored: install that version or a newer one first. A backup of
an older version is brought up to date during the restore.

A restore needs free disk space next to the database: twice the size of the current database plus 1 GiB.

## Restore on a new server

Use this after the loss of the server, or to move Alice to new hardware. The recovery passphrase and the backup file
are all you need: no key or file of the old server.

1. Prepare the new server as in [install-guide.md](install-guide.md) (sections 1 to 3), with the package of the same
   Alice version as the backup or a newer one.
2. Install in restore mode, with the name people will use:

   ```
   sudo /root/alice-1.0.0/alice/install.sh --restore-mode --hostname alice.example.com
   ```

   This runs the preflight, the package and fingerprint checks, creates the directories, loads the images and starts
   only the database. It makes no master key. Expected, at the end:
   `Alice is ready for a restore. Copy the backup file into /opt/alice/backups, then run: sudo /opt/alice/alicectl restore /opt/alice/backups/<file>`
3. Copy the backup file and its `.sha256` file into the backups directory, owned by Alice's container user:

   ```
   sudo install -o 10001 -g 10001 -m 0600 alice-backup-7F3K92QD-20261010T023000Z-auto.alicebak alice-backup-7F3K92QD-20261010T023000Z-auto.alicebak.sha256 /opt/alice/backups/
   ```

4. Restore it, with the passphrase and `RESTORE` as in the previous section:

   ```
   sudo /opt/alice/alicectl restore /opt/alice/backups/alice-backup-7F3K92QD-20261010T023000Z-auto.alicebak
   ```

   There is no data on the new server, so no `pre-restore` backup is made. After a successful restore Alice starts
   and runs its self-check.
5. Sign in with the existing accounts. The setup wizard does not appear: the restored installation is set up.
6. Point the DNS name (or the address) to the new server. The backup's HTTPS certificate is in use again; if the name
   changed, upload a certificate for the new name on **Settings → HTTPS certificate**. A backup without a certificate
   gets a new temporary one.
7. Check: **License** shows the same Installation ID and the license is valid; **Test connection** works on the
   servers (Alice's SSH key came back with the database, so the servers still trust it).
8. **Shut the old server down for good.** Two copies of one installation must never both run: both would rotate keys
   and deploy certificates.
9. Choose **Back up now** on **Settings → Backups**, and point the off-host copy job at the new server.

If the restore is interrupted (power loss, a killed process) before it switched to the restored data, the next
`alicectl restore` on the new server may stop with
`An interrupted restore left an unverified copy of the database (<database>_restore) and no live database. …`.
Drop that copy by hand ([operator-guide.md](operator-guide.md#an-interrupted-restore)), then run the restore
again.

## Disaster-recovery drill

Practise the restore every 6 months; many regulators ask for evidence of it.

1. Take the newest **off-host** copy of a backup.
2. On a spare virtual machine that cannot reach your production servers (so the copy cannot change anything), follow
   steps 1 to 5 of [Restore on a new server](#restore-on-a-new-server).
3. Check:
   - sign-in works with password and authenticator code;
   - the number of servers, certificates and SSH keys equals the production numbers noted when the backup was made;
   - `sudo /opt/alice/alicectl audit verify` prints `The audit log is intact: …`;
   - `sudo /opt/alice/alicectl selfcheck` prints seven `[ OK ]` lines (this also proves the master key opens the
     stored secrets).
4. Record the drill in the log below: the time from start to a working sign-in (RTO, recovery time) and the age of
   the backup (RPO, recovery point).
5. Destroy the spare virtual machine.

With the default schedule, the recovery point is at most 24 hours old (make a manual backup before risky changes).
The design target for the recovery time is 30 minutes on a prepared server; your drills show what your
installation achieves. No drill result is recorded for this release yet.

**Drill log**

| Date | Performed by | Backup file | Backup age at start (RPO) | Start time | Sign-in works at | Duration (RTO) | Counts match | `audit verify` intact | `selfcheck` all OK | Problems found | Signed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | | |
