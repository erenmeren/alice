# Licensing: vendor guide (not shipped to customers)

This guide is for the Alice vendor, the person who signs licenses and releases. It covers `licensectl`, the signing
key, the issuance ledger, correction licenses, key rotation and the separate release key (spec §16.7, §17.5,
§19.2, SEC-107, R8, R36). Customers never see this guide
and never get `licensectl`. `licensectl` never uses the network.

## Rules that never change

- The production license signing key is created and used **only on an offline machine** (a freshly installed
  laptop without network, or a live USB system). It is never on a computer connected to the internet, in CI, in
  cloud storage, in e-mail, in a password manager that syncs, or in this repository.
- No script, test, assistant or CI job ever creates, stores or prints the production key or its passphrase. The
  repository's tests use throw-away keys in temporary directories, and the test key is trusted only by the e2e
  build.
- Only the **public** key goes into Alice builds, through `internal/license/keys/production.json`.
- Until that file lists a key, release builds accept **no** license (every upload is refused as an unknown key;
  the evaluation still works) and `make release-keycheck` fails.
- **Every license format keeps the envelope.** A future format may add payload fields, but every format must keep
  the outer object `{format, key_id, payload, signature}` with exactly these key names, an integer outer `format`
  equal to `payload.format`, and the Ed25519 signature over `"ALICE-LICENSE-v1\n"` followed by the RFC 8785
  canonical bytes of the whole payload object (every member, numbers that are IEEE doubles, nesting at most 16).
  The file as a whole also stays within what every build checks before it looks at the format: at most 64 KiB
  (65,536 bytes), valid UTF-8 (a leading byte order mark is ignored), exactly one JSON object with no key repeated
  in any object at any level, and nesting at most 16.
  Then a customer on an older Alice who uploads a newer license is told to update Alice (`ALC-LIC-0006`); a format
  that breaks any of this is reported to them as "not a valid license" (`ALC-LIC-0002`). An older build reports a
  newer format only after the signature verified, so an unsigned or edited file is always "not valid".
  `licensectl verify` on such a file prints `SIGNATURE OK, NEWER FORMAT (…)` and exits 1.

## Build licensectl

On a trusted build machine: `make licensectl` (or `go build -trimpath -o bin/licensectl ./cmd/licensectl`) gives
`bin/licensectl`. Copy the binary to the offline machine with a clean USB stick. `licensectl` runs on Linux and
macOS (the ledger lock uses `flock`); Windows is not supported. `licensectl help` lists the commands.

## 1. Create the signing key (once per key, offline)

1. Choose a passphrase of **at least 6 random Diceware words**, for example with physical dice and the English
   Diceware list. `licensectl` refuses fewer than 6 words or fewer than 24 characters. Use only lower-case ASCII
   letters and spaces: the passphrase is used byte for byte, so an accented letter typed on another keyboard or
   operating system can produce different bytes and the key would not open. Write the passphrase on paper.
2. Run:

       bin/licensectl keygen --out /media/offline/alice-vendor --key-id vk-2026-01

   and type the passphrase twice (it is not shown and never printed).
   Expected: `Private key (encrypted): …/alice-license-private.pem`, `Public key: …/alice-license-public.pem`,
   `Key ID: vk-2026-01` and `Fingerprint: SHA256:…`. Write the fingerprint on the paper too.

   The private key file is encrypted with Argon2id (256 MiB, 4 passes) and AES-256-GCM and written with mode 0600.
   `keygen` never overwrites an existing key. Key IDs have the form `vk-YYYY-NN`; IDs starting with `vk-test-` are
   reserved for test keys and are refused in a production key set.

### Backups (R8)

3. Copy the whole `alice-vendor` directory (private key, public key, and later the ledger) to **two
   hardware-encrypted USB drives**.
4. Print the private key file `alice-license-private.pem` (it is encrypted) on paper as the third copy.
5. Store USB drive 1 in the fireproof safe on your premises; USB drive 2 and the printout in a bank safe deposit
   box or with a notary; the passphrase paper **separately** from both drives. When a second trusted person
   exists, give them a sealed copy of the passphrase.
6. Check that each drive's copy opens: run `licensectl issue --key <copy> …` up to the summary and answer `no`
   (nothing is signed and no license file or ledger row is written; the only file that may appear is an empty
   lock file `issued.csv.lock` next to the copy, which is harmless and can stay).

If the key is lost, no new licenses can be issued that shipped builds accept. If it leaks, anyone can forge
licenses: follow "Key compromise" below at once.

## 2. Put the public key into Alice builds (once per key)

1. On the offline machine:

       bin/licensectl keyset --pub /media/offline/alice-vendor/alice-license-public.pem

   Expected: a JSON block `{"keys": [{"key_id": "vk-2026-01", "public_key": "…", "status": "active"}]}` and
   `Fingerprint: SHA256:…`, the same fingerprint as on your paper.
2. Carry only that output (the public key; it is not secret) to your development machine and write it into
   `internal/license/keys/production.json`, replacing `{"keys": []}`. Commit it yourself, for example
   `git commit -m "chore(license): embed vendor license key vk-2026-01"`.
3. Run `make release-keycheck`.
   Expected: `ok  alice/internal/license`. It fails while the file lists no key, and it refuses a test key such as
   `vk-test-01`. The release pipeline runs it.
4. After building a release image, run `alice license keys` in it and compare the fingerprint with your paper.
   Publish the fingerprint on your website and in license emails (R20), so customers can compare it too.

## 3. Issue a license

Checklist: confirm the paid order; check the Installation ID the customer sent; issue; verify; record the ledger
head; send.

1. Mount USB drive 1 on the offline machine.
2. Run:

       bin/licensectl issue --key /media/offline/alice-vendor/alice-license-private.pem \
           --installation ALICE-7F3K-9Q2M-XD41-B8TC --customer "Example Bank A.S." --targets 100 \
           --out alice-license-examplebank-20261001.alicelic

   Options: `--from 2026-10-01` (first valid day; default today; at most one day in the past except for a
   correction; for an early renewal use the old expiry date), `--months 12` (1 to 60), `--features a,b` (unused in
   v1), `--license-id` (default `LIC-<year>-<6 digits>`), `--ledger` (default `issued.csv` next to the key).
3. Type the passphrase, read the summary, type `yes`.
   Expected: `Written: …`, `SHA-256: …`, `Ledger: …/issued.csv`, `Ledger rows: N` and `Chain head: …`.
4. **Write the ledger rows and the chain head in the paper log** kept with the key (see "The ledger").
5. `bin/licensectl verify --pub /media/offline/alice-vendor/alice-license-public.pem alice-license-examplebank-20261001.alicelic`
   Expected: `OK`.
6. Copy the license file to a clean USB stick and email it to the customer together with the key fingerprint.

`licensectl` refuses before anything is signed: a mistyped Installation ID (it ends with a check character, so a
wrong or swapped character is detected; lower case, spaces, `O` for `0` and `I`/`L` for `1` are corrected), an
existing `--out` file, a private key file that others can read or write (run `chmod 600` on it), and a ledger that
does not verify. Customer names and other text are normalized to Unicode NFC before signing.
`licensectl inspect FILE` shows what a license file says without checking its signature; text that could control
the terminal is shown quoted.

## 4. Correction licenses (R7)

Use `--replaces <license ID>` when a customer's clock jumped, the customer name was wrong, or targets were added
mid-term. A correction may start earlier than one day ago (its issue date is then set to its start date), Alice
accepts it even though it is older than the installed license, and uploading it ends a held clock jump at once.

- The replaced license must be in **this key's ledger** and belong to the **same installation**.
- A correction that ends **earlier** than the license it replaces is refused unless you add `--shorten`. Use it
  only when the customer agreed to a shorter term: Alice uses the correction in place of the replaced license.
- Replacing licenses in a cycle is refused, and a license ID is never issued twice.

## 5. The ledger

`issued.csv` next to the key records every license: ID, customer, installation, dates, targets, replaced license
and the SHA-256 of the file. Every row is chained to the previous one (SHA-256) and signed with the license key, so
an edited, removed or reordered row is detected:

    bin/licensectl ledger-verify --pub /media/offline/alice-vendor/alice-license-public.pem

Expected: `Ledger OK: N licenses` and `Chain head: …`. A missing ledger file is an error, never an empty ledger.

- **The chain cannot detect rows cut from the end, or an older copy of the ledger put back**: both still verify.
  That is why you write the row count and the chain head down after every issue. Before the next issue, run
  `ledger-verify` and compare both values with the last line of the paper log. If they differ, stop and find out
  why before signing anything.
- Two `licensectl issue` runs on the same machine take turns: a lock file `issued.csv.lock` sits next to the
  ledger, and the checks are repeated under the lock just before the row is written. Do not run `ledger-verify`
  while an `issue` is in progress (it reads without the lock and can report a half-written row).
- Copy the ledger to both USB drives after every issue, and compare the two copies during the yearly recovery
  test.

## 6. Yearly recovery test

Once a year, on a clean offline machine: copy the key from USB drive 2, open it with the passphrase from the paper,
issue a test license for a test installation with `--customer "Recovery test"` and a separate `--ledger` file,
and check it with `licensectl verify`. Compare the ledgers on both drives (`ledger-verify` on each: the same row
count and chain head as the paper log). Record the date in the paper log.

## 7. Key rotation

1. Create the next key (`vk-YYYY-NN`) ahead of time in its own directory, as in step 1, with its own backups.
2. Add it to `production.json` (both keys `"active"`) at least one release before you sign with it, so customers
   who update late already trust it.
3. Every key has **its own ledger** (`issued.csv` next to that key). A correction can only replace a license from
   the same key's ledger: to replace a license signed with an older key, issue a normal license with the new key
   (not `--replaces`).
4. Remove an old key, or mark it `"revoked"` with a `"revoked_from"` cutoff (the first issue date no longer
   trusted), only after every license signed with it has expired or been reissued. A cutoff is only for retiring
   a key that was **not** compromised.

`licensectl keyset` prints one key. To trust several, merge the `"keys"` entries of each output into the one
`"keys"` list of `production.json` by hand (one entry per key ID, never two with the same ID), then run
`make release-keycheck` and `alice license keys` in the built image and compare every fingerprint with your paper.
For example, after a rotation that retires `vk-2026-01` for licenses issued from 2028 on (the public keys are
shortened here):

```json
{
  "keys": [
    {"key_id": "vk-2026-01", "public_key": "q1Xr…=", "status": "revoked", "revoked_from": "2028-01-01T00:00:00Z"},
    {"key_id": "vk-2027-01", "public_key": "Z8bT…=", "status": "active"}
  ]
}
```

After a compromise (step 8) the leaked key's entry has **no** `revoked_from`:
`{"key_id": "vk-2026-01", "public_key": "q1Xr…=", "status": "revoked"}`. An `"active"` key may not have
`revoked_from`; Alice refuses to start with such a key set, so `make release-keycheck` fails first.

## 8. Key compromise

If the private key **or** its passphrase may have leaked:

1. Create a new key offline with the next key ID, as in step 1.
2. Ship an emergency release whose `production.json` adds the new key and marks the leaked key
   `"status": "revoked"` **with no `revoked_from` cutoff**. `issued_at` is chosen by whoever signs, so an attacker
   holding the key can backdate a forged license to before any cutoff; only a revocation without a cutoff rejects
   every license signed with that key (a test proves this).
3. Reissue every customer's active license with the new key, free of charge, and make sure every customer **has
   the new file before, or together with, the release** that revokes the old key. As soon as a customer runs that
   release, every stored license signed with the leaked key stops counting: with no other license, Alice is in
   "evaluation ended" (lock mode, usually at once, because the 30-day evaluation ran out long ago), the License page
   lists the old file as **Damaged**, and only uploading the new file ends the lock. Uploading an old file again
   shows "This license was signed with a key that is no longer trusted."
4. Notify customers (spec §17.4) and start a new ledger and paper log for the new key.

## 9. Release key

Releases are signed with a **release key**, a second Ed25519 key that is never the license key (spec §16.7,
SEC-107). Compromise of one must not compromise the other, so the two are separate keys with separate
passphrases, separate backups and separate directories. Every rule of this guide's first section applies to the
release key too: it is created and used only on the offline machine, and no script, test, assistant or CI job ever
creates, stores or prints it.

The key file says what it signs: a release key file has the block type `ALICE RELEASE SIGNING KEY` and the header
`Alice-Key-Purpose: release`, both bound into its encryption. `licensectl issue` refuses a release key, and the
release commands refuse a license key ("this key is for another purpose").

### Generation (once per key, offline)

1. Choose a **new** Diceware passphrase of at least 6 words, as in step 1 (never the license key's passphrase), and
   write it on its own paper.
2. Run, in a directory of its own (never the license key directory, which `licensectl` refuses, and never
   `deploy/release/keys` of a repository):

       bin/licensectl release-keygen --out /media/offline/alice-release --key-id rk-2026-01

   Expected: `Private release key (encrypted): …/rk-2026-01.key`, `Public release key: …/rk-2026-01.pem`,
   `Key ID: rk-2026-01` and `Fingerprint (SHA-256): <64 hex>`. Write the fingerprint on the paper. Release key IDs
   have the form `rk-YYYY-NN`; `rk-test-NN` belongs to the throw-away keys of test packages and is refused.
3. Back the directory up exactly like the license key (two hardware-encrypted USB drives, a printout of
   `rk-2026-01.key`, the passphrase paper stored separately).
4. On the build machine, copy **only** `rk-2026-01.pem` into `deploy/release/keys/` and commit it. Then
   `make release-keycheck` checks that the release keys are production keys and that none of them is a license key
   in `internal/license/keys/production.json` (it fails until both keys are committed).
5. Publish the fingerprint on a vendor channel customers can compare against (your website and the order
   confirmation). `install.sh` prints it and asks the customer to compare (R43 row 43); the install guide checks the
   outer signature with the published key first.

### Signing ceremony (every release)

1. On the release build machine, from the signed tag: run every release gate of the release checklist (their
   results are recorded in `bin/release-gates.log`, which becomes `RELEASE-CHECKLIST-SIGNED.txt` in the package;
   the log names the commit the gates ran on, and `make release` refuses a log of another commit), then
   `make release VERSION=x.y.z`. Only a stage built this way is signed; a stage built by CI is only compared with it (`make reproducible-check`
   compares the binaries) and is never signed (S-26).
2. Copy `bin/release/alice-x.y.z/alice/SHA256SUMS` to the offline machine on a clean USB stick and run:

       bin/licensectl release-sign --key /media/offline/alice-release/rk-2026-01.key SHA256SUMS

   It asks for the passphrase once, prints the SHA-256 of each file it signs, and writes `SHA256SUMS.sig` (a raw
   64-byte Ed25519 signature). Compare the printed SHA-256 with `sha256sum SHA256SUMS` on the build machine.
3. Copy `SHA256SUMS.sig` back into `bin/release/alice-x.y.z/alice/`, run `make release-pack VERSION=x.y.z`, and sign
   the outer checksum the same way:

       bin/licensectl release-sign --key /media/offline/alice-release/rk-2026-01.key alice-x.y.z.tar.gz.sha256

4. Check both signatures before publishing, with `licensectl release-verify --pub rk-2026-01.pem FILE FILE.sig`
   and with the command the customer's installer uses:

       openssl pkeyutl -verify -pubin -inkey rk-2026-01.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig

`release-sign` signs checksum files only (at most 1 MiB) and never overwrites a `.sig`.

Test packages (`make release-test VERSION=x.y.z-rc.N`, the release harness) are signed with a key that
`tools/releasesign` generates at test time in `bin/release-test-key/` (`rk-test-01`, not encrypted). Such a package
says `TEST_SIGNED=1` in `RELEASE`, the installer warns that it must never be installed for production, and a
version without `-rc.N` is refused. The broken-update package for the owner's VM test is built with
`make release-broken VERSION=x.y.z-rc.N BROKEN=fail SIGN=offline` (for example `1.0.1-rc.1` to test the update
from `1.0.0`) and signed in this ceremony like a release. Its version is never a customer version: the script
refuses a version without `-rc.N` and a version whose package already exists in `bin/release/`. Keep it on the test
VM only and never publish it.

### Rotation

1. Create the next key (`rk-YYYY-NN`) ahead of time, as above, with its own backups.
2. Commit its `.pem` beside the current one in `deploy/release/keys/` at least one release before you sign with it.
   An installation trusts a new release key only when it arrives in a package signed by a key it already trusts,
   and an update **replaces** the installed `release-keys/` with the package's set (R43 row 21).
3. Sign with the new key from the next release on; remove the old `.pem` from `deploy/release/keys/` one release
   later. Installations that skip that release still update, because the release in between trusted both keys.

If the release key or its passphrase may have leaked: create a new key, publish its fingerprint, remove the leaked
key from `deploy/release/keys/` in the next release, and tell customers (spec §17.4) to check the fingerprint the
installer prints against the newly published one. Packages signed with the leaked key after the leak cannot be told
apart from genuine ones by signature alone, so customers verify downloads against the new fingerprint only.
