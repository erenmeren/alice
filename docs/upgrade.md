# Upgrade Guide

This guide is for the operator who updates Alice to a new release. The update script makes a backup first, and
returns to the installed version by itself when the new one does not start.

## Before you update

- [ ] Check the oldest version the release updates from: `MIN_UPGRADE_FROM` in the package's `RELEASE` file
      (`grep MIN_UPGRADE_FROM alice/RELEASE` in the extracted package; empty means any older version). The update
      script refuses an older installation and names the version to install first.
- [ ] Read the release notes (`CHANGELOG.md` in the package) for anything to do before or after.
- [ ] There is a recent good backup, and a copy of it off the server
      ([backup-restore.md](backup-restore.md#copy-backups-off-the-server)). The update makes its own backup too.
- [ ] You have the recovery passphrase at hand. The update cannot run without it: it opens its own backup with it
      before it changes anything, and needs it to return to the installed version.
- [ ] Choose a quiet period. Alice is unavailable for a few minutes: it stops before the backup and starts again
      after the database update. Running jobs get up to 60 seconds to finish.
- [ ] Announce the outage to the people who use Alice. Alice shows no "update in progress" message of its own.
- [ ] Check the package as in [install-guide.md](install-guide.md#3-check-the-package-before-you-extract-it): the
      vendor's signature of the `.sha256` file and the checksum.

The update script checks the free disk space itself, twice: before it copies the package (three times the
package's size plus 1 GB in the installation directory, for the copy and its unpacking) and after (twice the size
of the database plus 5 GB). It checks the health of the running installation (`alicectl selfcheck`) too, and stops
before changing anything when one of them is not right.

## Run the update

Copy the package file and its two companions (`.sha256` and `.sha256.sig`) to the server, into the same directory,
for example `/root`. Then run the update script of the **installed** version, from the installation directory:

```
cd /opt/alice && sudo ./alice-update.sh /root/alice-1.0.1.tar.gz
```

The installation directory can be read by root only: open a root shell first (`sudo -i`), or run
`sudo /opt/alice/alice-update.sh /root/alice-1.0.1.tar.gz`, which does the same (the script always works on the
installation it belongs to). The script also accepts an extracted package instead of the tarball: the directory
you extracted it into as in [install-guide.md](install-guide.md#4-extract-and-install) (`/root/alice-1.0.1`), or the
`alice` directory inside it (`/root/alice-1.0.1/alice`). Check the tarball as in the install guide before you extract
it: an extracted package has no `.sha256` file, so only the signature over the files inside it is checked.

Type the recovery passphrase at `Recovery passphrase (needed for the automatic backup): `.

Expected, at the end: `Alice is now version 1.0.1.` and exit code 0.

For an unattended update, give the passphrase in a file that only root can read (mode 600, the passphrase on the
first line):

```
cd /opt/alice && sudo ./alice-update.sh /root/alice-1.0.1.tar.gz --non-interactive --passphrase-file /root/alice-passphrase
```

A passphrase file that group or others can read is refused (exit code 2). Delete the file after the update.

## What the update does

1. **Checks, with nothing changed yet.** Root, Docker, the installation, room for the package. The package is copied
   into a directory only root can read (`/opt/alice/.update-<time>/`) and only that copy is used: the signature of
   the `.sha256` file is checked with the release keys **of the installed version** (never with keys that come with
   the new package), then the package's checksum, then the signature and checksums of every file inside it. The new
   version must be newer than the installed one, and the installed one must be at least the package's minimum
   version (`MIN_UPGRADE_FROM`). The script prints the SHA-256 fingerprint of the installed release key that signed
   the package (`Update package signed by release key <id> (SHA-256 fingerprint <hex>). …`) and of each release key
   the package brings (`The package brings release key <id> (SHA-256 fingerprint <hex>).`): after the update only
   those are trusted. Compare them with the fingerprints your vendor published. Then `alicectl selfcheck` must
   pass, and there must be enough free disk for the update.
2. **Passphrase.** Read from the terminal or `--passphrase-file`, kept in memory for this run only.
3. **Stop.** Alice stops; leftover database sessions are ended.
4. **Backup.** A backup of the stopped installation, named `…-pre-upgrade-<installed version>.alicebak`, which is
   then opened completely with the passphrase. A wrong passphrase stops the update here.
5. **Rollback copy.** The compose file, `.env`, `RELEASE`, `VERSION`, the scripts and the release keys are copied to
   `/opt/alice/rollback/<installed version>/`.
6. **Images.** The new images are loaded and their IDs compared with the package's `RELEASE` file.
7. **Database.** The new compose file and `.env` are installed (your port, address, host names and time zone are
   kept), then the database is updated.
8. **Start.** The new version starts and must pass `alicectl selfcheck`.
9. **Finish.** The new scripts, release keys, documentation and version files are installed.

The pre-upgrade backup is never deleted automatically.

## When the update fails

The script decides by how far it got:

- **A failure in steps 3 to 6** (before anything of the installation changed): the installed version starts again.

  ```
  The update was stopped before any change; Alice is running version 1.0.0 again.
  ```

  Exit code 1. Fix the cause in the update log and try again.

- **A failure in steps 7 or 8** (the database may have been changed): the script stops the new version, puts back
  the compose file, `.env`, `RELEASE` and `VERSION` from the rollback copy, and restores the database from the
  pre-upgrade backup with the installed version (`alicectl restore … --db-only`). Then the installed version starts
  and runs its self-check.

  ```
  The update to 1.0.1 failed and Alice was returned to 1.0.0. Your data is unchanged as of 2026-10-11 09:15:02 UTC. Details: /opt/alice/update-20261011T091500Z.log. Please send this file to support.
  ```

  Exit code 1. Changes people made during the update window do not exist: the update stopped Alice first.

- **When even that fails**, the script prints what to do by hand and the backup to use, and exits with code 3:

  ```
  The update to 1.0.1 failed and Alice could not be returned to 1.0.0 automatically. Your backup is /opt/alice/backups/<file>. Restore it by hand: cd /opt/alice && sudo ./alicectl restore /opt/alice/backups/<file>   (details: /opt/alice/update-<time>.log)
  ```

  Run the printed command and send the log to support. After an exit code 3 the script leaves its work directory
  `/opt/alice/.update-<time>/` for support; remove it when the case is closed.

  If the installed version itself does not start again after a failure in steps 3 to 6, the script prints
  `Alice could not be started again. Details: <log>. Please send this file to support.` (also exit code 3).

Messages that stop the update before any change:

| Message | Meaning |
|---|---|
| `This installation is already at version <v>.` | The package is the installed version. |
| `Going back to an older version is only possible by restoring a backup.` | The package is older than the installed version (see [Going back to an earlier version](#going-back-to-an-earlier-version)). |
| `Alice <installed> cannot be updated directly to <new>. Install <min> first.` | Update to the named version first, then to the new one. |
| `The update package signature is not valid. Do not install this package; download it again and check it with your vendor.` | The `.sha256` file is not signed by a release key the installation trusts, the checksum differs, or a companion file is missing. |
| `The installation package is damaged or incomplete. Download it again and compare the checksum.` | A file inside the package does not match its signed checksum. |
| `Not enough free disk space in <dir> to unpack the update package: <n> GB free, <m> GB needed.` | Checked before the package is copied. Free disk space, or copy older backups off the server and delete them. |
| `Not enough free disk space in <dir>: <n> GB free, <m> GB needed for the update.` | Free disk space, or copy older backups off the server and delete them. |
| `Alice is not healthy now (selfcheck failed). Fix it before updating; see <dir>/update-<ts>.log.` | Run `sudo /opt/alice/alicectl selfcheck`, fix what it reports, then update. |
| `Another update or restore of Alice is running in <dir>. Wait until it has finished, then run this again.` | One update or restore runs at a time. |
| `[WARN] This package is signed with a TEST key. Never install it for production.` | A warning only: the package was built for the vendor's tests. Stop the update with Ctrl-C and ask your vendor for the release package. |

See also [troubleshooting.md](troubleshooting.md#update-rolled-back).

## The update log

Every line the script prints is also written to `/opt/alice/update-<yyyymmddThhmmssZ>.log` (mode 0600, root only),
with the output of the steps it runs. The passphrase is never in it. Read it with:

```
sudo ls -t /opt/alice/update-*.log
sudo less /opt/alice/update-20261011T091500Z.log
```

Exit codes: `0` updated; `1` not updated (nothing changed, or returned to the installed version); `2` a wrong option
or passphrase file; `3` the update failed and the automatic return failed too.

## Supported update paths

Each release names the oldest version it updates from (`MIN_UPGRADE_FROM` in its `RELEASE` file, and in the release
notes). An older installation is refused with the version to install first. Release candidates (`1.0.0-rc.1`) count
as older than their release (`1.0.0`).

## Going back to an earlier version

The update script never installs an older version. To go back after a successful update, restore the pre-upgrade
backup into a new installation of the earlier version:

1. Copy the pre-upgrade backup (`…-pre-upgrade-<earlier version>.alicebak`) and its `.sha256` file away from the
   installation directory, for example to `/root`.
2. Stop the current installation: `sudo /opt/alice/install.sh --uninstall`, then move its directory aside
   (`sudo mv /opt/alice /opt/alice-replaced`).
3. Restore the backup with the package of the earlier version, as in
   [Restore on a new server](backup-restore.md#restore-on-a-new-server) (steps 2 to 7).

Everything that happened after the backup is lost. This procedure has not been exercised by a test yet; run it on a
test server first.
