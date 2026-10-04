# Licensing

Alice is licensed per installation for a number of **managed targets** (Nginx servers, Linux hosts and Azure Key
Vaults). Certificates and SSH keys are not counted. Licenses usually run for a year and are renewed by uploading a
new file; no internet connection is needed.

## Your Installation ID

Every installation has an ID such as `ALICE-7F3K-9Q2M-XD41-B8TC`. It is created the first time Alice starts and is
kept by backups and restores, so a license keeps working after moving to new hardware. Find it on the **License**
page (administrators and auditors) or with `alice license status` on the server. The last character is a check
character: your vendor's tool detects a mistyped ID.

## The 30-day evaluation

A new installation runs as an evaluation for 30 days from the moment Alice was first started, with up to 5
targets. The setup wizard asks you to upload a license or to **Start 30-day evaluation (up to 5 targets)**;
choosing the evaluation starts nothing new, because the 30 days are already running. Everyone sees a blue banner
with the days left; administrators are warned 7, 3 and 1 days before the end (the banner turns yellow, then
orange, and an email is sent). When the evaluation ends, Alice goes straight to lock mode (below), without a grace
period. Nothing is deleted.

## Activating or renewing a license

1. Copy the Installation ID on the **License** page (**Copy**) and email it to your vendor with the number of
   targets you need.
   Expected: the vendor replies with a file such as `alice-license-yourcompany-20261001.alicelic`.
2. On **License**, under **Upload a license**, choose the file and **Check the file**. Alice may ask for a new
   6-digit code first.
   Expected: **Confirm the license** shows "Licensed to …. Up to … managed targets. Valid from … to …".
3. Choose **Install license**.
   Expected: "License activated. All features are available again." The page shows "Valid until <date>, N targets".

The license takes effect at once, without a restart. If a renewal starts on a later date, the current license stays
in use until then ("A new license (…) starts on …"). A renewal for fewer targets than you use is accepted: existing
targets keep working and only adding targets is blocked until you are within the limit. A license that has already
expired is installed too; its own dates decide whether Alice is in the grace period or locked.

If the upload is refused, the message says why (see [troubleshooting.md](troubleshooting.md), codes
`ALC-LIC-0002` to `ALC-LIC-0007`): a damaged or edited file, a license for another installation, a key this build
does not trust, a file that needs a newer Alice, or an older file than the one installed. A refused upload changes
nothing and is recorded in the audit log.

## What you see before and after the end date

| When | Who sees what | What works |
|---|---|---|
| 60, 30, 14, 7 and 1 days before the end | Administrators: yellow banner (orange at 7 and 1 days) and an email each time | Everything |
| From the end date, for 7 days (168 hours) | Everyone: red banner with the day of the grace period; administrators get a daily email | Everything |
| After the grace period (lock mode) | Everyone: red banner "License expired. Automatic tasks are paused. …" | See below |
| After uploading a renewal | "License activated. All features are available again." | Everything, at once |

Each warning email is sent once per license, also when Alice was stopped across several warning dates (only the
current one is sent). Emails need the SMTP settings (see [operator-guide.md](operator-guide.md#email)); without
them the banners still appear.

## Lock mode

In lock mode Alice makes no changes to your servers and stops automatic work that would change them. Your data is
kept and no certificate is revoked. These keep working: signing in, viewing everything, uploading a license,
backups, the audit log and its export, inventory export, user administration, API tokens and settings. Actions that
would change a server are refused with `ALC-LIC-0001` ("Not available while the license is expired."). Uploading a
renewal ends lock mode at once.

In lock mode adding or removing servers, confirming fingerprints, **Test connection**, **Scan for SSH keys**,
**Discover**, key removals, certificate uploads, signing requests, deployments and verification settings are
refused, and the daily scans are not started. Key removals and deployments that were already waiting in the queue
are paused; after the renewal they appear under **Waiting for an administrator** on **Servers**, and an
administrator chooses **Run now** or **Discard** for each (nothing starts on its own; a discarded deployment ends
cancelled, `ALC-DEP-0022`, without a failure email). A deployment that had already
reached a server when the lock began is still finished or undone, so no server is left half-changed. Certificate
expiry alerts by email with a note that the license expired arrive with the release that adds alerts.

## Clock changes

Alice remembers the latest time it has seen, in the database and in a protected file on the `alice-state` volume.

- **The server clock is set back** (by hand, or by restoring a virtual machine snapshot): Alice keeps counting from
  the later time, so a license never gets longer, and time keeps moving while the clock is behind. Administrators
  see "The server clock changed unexpectedly (…)" once the difference is more than about an hour; the audit log
  records it once a day. Nothing is locked because of it.
- **The clock jumps more than two days ahead** while Alice runs: administrators are warned (banner and email), and
  Alice keeps using the previous time for 24 hours before the new time can start the grace period or the lock.
  This gives you time to correct the clock or to ask the vendor for a correction license. Uploading a correction
  license accepts the new time at once.
- A jump that happens while Alice is stopped is counted like normal downtime: it can only make the license end
  sooner, never later. If that happens by mistake, ask the vendor for a correction license.

Keep the server time synchronised (NTP). A server clock set back by more than about 30 seconds also makes sign-in
codes from phone authenticators fail: the phone follows the real time, the server does not, so the codes are
refused **until the server clock is corrected** (it does not catch up by itself). Correct the clock first; if the
only administrator still cannot sign in, the server operator runs `alice admin reset-mfa <username>`.

## Frequently asked questions

- **We restored a backup onto a new server. Do we need a new license?** No. The Installation ID, the evaluation
  start and the license are restored with the database.
- **We copied the whole installation to a test server.** The copy has the same Installation ID; your license terms
  decide whether that is allowed.
- **Which build accepts our license?** Every release from your vendor. `alice license keys` shows the vendor key
  fingerprints the build trusts; compare them with the fingerprint in the vendor's email.
- **Can someone restart the evaluation by editing or deleting the installation record in the database?** No. The
  Installation ID and the evaluation start are protected with a key derived from the master key. A changed record
  is ignored: Alice treats the evaluation as ended (lock mode) until the original record is restored, and the audit
  log lists "Installation record changed outside Alice". A deleted record gets a new Installation ID whose
  evaluation has already ended, so a license for the new ID is needed.
- **Can someone edit the license file to get more targets?** No. The file is signed; any change makes it "not a
  valid Alice license". An edited file already stored in the database is ignored, and administrators see "License
  data was changed outside Alice …".
