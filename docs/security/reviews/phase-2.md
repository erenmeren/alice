# Security Review — Phase 2 (Licensing and licensectl)

Scope (spec §17.2, Phase 2): signature verification, canonicalization, HWM MAC, fake-clock tests, lock behavior
safety. Exit criteria: tamper, forgery and downgrade tests pass; no data loss on lock; no High finding open.

The decisions behind this phase are R36 and its addendum in `docs/superpowers/specs/alice-v1/00-decisions.md`.

## Evidence

All commands run from the repository root; integration tests (`-tags integration`) need Docker.

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | License format, canonical JSON, strict parser, key set, forgery and revocation incl. a backdated license under a compromised key (L-40..L-47) | `go test ./internal/license/... -count=1` | ok |
| 2 | Test key trusted only by the test build; release binary refuses test-signed files, links no test signer, issuer or `x/term`, and is not marked | `go test -tags testlicense ./internal/license/... -count=1` and `go test ./cmd/alice -run 'TestReleaseBinary\|TestReleaseBuild' -count=1` | ok |
| 3 | Fuzzing the parser (§25.6) | `make fuzz-license` | no crasher |
| 4 | State machine L-01..L-33, L-48, L-70..L-78, order-independent license selection | `go test ./internal/license -run 'Evaluation\|Threshold\|Grace\|Renewal\|Pending\|Target\|Correction\|Boundaries\|Monotonicity\|N[123]' -count=1` | ok |
| 5 | Clock guard and HWM (L-50..L-63) | `go test ./internal/license -run 'Guard\|HWM' -count=1` and `go test -tags integration ./internal/license -run 'Rollback\|Restarts\|ForwardJump\|Correction\|StartChooses\|StartPrefers\|StartWith\|StartFalls' -count=1` | ok |
| 6 | Uploads, concurrency, tamper, notices exactly once (L-11..L-18, L-49, L-74) | `go test -tags integration ./internal/license/... -count=1` | ok |
| 7 | Fault injection: a failed evaluation, upload or start writes and publishes nothing | `go test -tags integration ./internal/license -run 'Faults\|Rejection\|BeforeStart\|BrokenTransaction' -count=1` | ok |
| 8 | Lock gate: route classes, guard, scheduler (X-01, L-26, L-27, L-29, L-30, L-80..L-88 stubs) | `go test ./internal/api ./internal/jobs -run 'License\|Lock\|JobType\|Scheduler\|Task\|Running\|InFlight\|Due\|Target' -count=1` | ok |
| 9 | L-79 static check (every target insert calls the license check) | `go test ./internal/archtest ./internal/jobs -count=1` | ok |
| 10 | License tables append-only for the app; grants | `go test -tags integration ./migrations -count=1` | ok |
| 11 | Secret-leak suite incl. HWM sub-keys and SMTP password; GET routes never write | `go test -tags integration ./internal/api -run 'TestSecretsNeverLeak\|TestA06' -count=1` and `go test -tags integration ./cmd/alice -count=1` | ok |
| 12 | SMTP: TLS required, untrusted certificate refused, no AUTH before TLS, header injection | `go test ./internal/notify -count=1` | ok |
| 13 | licensectl on Linux and macOS (key file, ledger lock, typo detection, terminal-safe inspect) | CI job `licensectl` | green on both |
| 14 | Coverage floors (R36 item 15) | `make coverage` | every package `ok` |
| 15 | E2E EN/TR incl. axe at 375/640/1280/1920 px | `make e2e-up && make e2e` | all passed |
| 16 | Release key gate | `make release-keycheck` | fails until the vendor key is committed (expected), then ok |

## Crypto design review checklist

- [ ] Signed bytes = `"ALICE-LICENSE-v1\n"` ‖ RFC 8785 payload; parse strictly (64 KiB, UTF-8, one object, no
      duplicate or case-variant keys, no unknown fields, integers and RFC 3339 UTC whole-second times),
      re-canonicalize, verify before any semantic use; `format` inside and outside the payload; an explicit empty
      or null `replaces` is refused.
- [ ] Ed25519 via the standard library; key selection by `key_id`; a malformed public key is an unknown key, never
      a panic; revoked keys with an optional `revoked_from` cutoff, and no cutoff after a compromise.
- [ ] Release builds embed only `keys/production.json` (which may not contain `vk-test-*`); the test key only under
      `testlicense`, derived from a fixed public label in test-only code.
- [ ] HWM record AES-256-GCM (`alice/hwm-enc/v1`) + HMAC-SHA256 (`alice/hwm/v1`) over `"v1"‖hwm‖seq`; invalid =
      missing (audited); trailing bytes refused; the file is read only if it is a regular file, at most 4 KiB.
- [ ] Trusted time never decreases across restarts; rollback clamp with time advancing by uptime; forward-jump
      hold 48 h / 24 h (R26), measured from the later of the last wall time and the HWM.
- [ ] Vendor key file: Argon2id m=256 MiB t=4 p=4 (bounded when read), AES-256-GCM, headers bound as AAD, seed and
      key zeroed after use, file mode checked.
- [ ] Ledger rows chained with SHA-256 and signed with Ed25519 under `"ALICE-LEDGER-v1\n"`; exclusive lock; head
      (rows, chain) printed for the paper log.
- [ ] SMTP: STARTTLS or implicit TLS required, TLS 1.2+, verified certificate, AUTH only after TLS; the password is
      read from a file and never logged.

## Findings

| ID | Severity | Description | Decision |
|---|---|---|---|
| P2-01 | Medium | Someone with the master key and write access to the database and the state volume can rewrite the HWM and roll time back (spec §16.6). Restoring both the database and the state volume to an older valid pair (a VM snapshot plus a database restore) does the same without the key. | Accepted (§16.6, "larger valid wins"); root on the host already defeats the license by patching the binary. |
| P2-02 | Low | A forward clock jump that happens while Alice is stopped is not detected (downtime and a jump look the same), and the first observation after a start never detects a jump: a start with a far-future clock goes straight to the phase of that time. | Accepted: a forward jump can only shorten a license; a correction license (which also ends a held jump) covers it. |
| P2-03 | Low | The SMTP password is read from a file on the host (`ALICE_SMTP_PASSWORD_FILE`). | Accepted for Phase 2; Phase 7 stores it envelope-encrypted in `setting_secrets`. |
| P2-04 | Low | Removing the last rows of the vendor ledger, or putting an older copy back, is not detectable from the ledger alone. | Accepted: `licensectl` prints the row count and chain head after every issue for the vendor's paper log; both USB copies are compared during the yearly recovery test. |
| P2-05 | Low | A server clock set back more than about 30 s rejects the codes of phone authenticators (which follow the real time) until the server clock is corrected; it does not catch up by itself. Phase 1 replay protection also refuses codes for steps before the last used one. | Accepted; documented in `docs/licensing.md`; correct the clock (NTP); `alice admin reset-mfa` recovers the only administrator. |
| P2-06 | Low | The periodic scheduler has no cross-process lock (§8.3); two processes during an update both evaluate. | Accepted: evaluations serialize on the license row and notices are unique per license. Phase 3's queue adds the advisory lock. |
| P2-07 | Low | `replaces` is honored for any license ID, even one never uploaded, both for the "older license" rule and for accepting a held clock jump; an expired correction still supersedes its target and an A↔B replace cycle supersedes both. | Accepted: only the vendor can sign such a file and license time only moves forward; `licensectl` refuses shortening corrections without `--shorten`, cycles and corrections across installations or keys. |
| P2-08 | Info | Until the owner commits the production key, release builds accept no license. | Intended (R36); `make release-keycheck` blocks a release. |
| P2-09 | Info | `licensectl` is Unix-only (`flock`), opens the lock file without `O_NOFOLLOW`, and `ledger-verify` reads without the lock (it can report a half-written row during a concurrent `issue`). | Accepted: the vendor machine is a single-user offline Linux or macOS system; the vendor guide says not to verify during an issue. |
| P2-10 | Medium | Final review B1: the installation row (ID and timestamp) was not authenticated, so editing it restarted the evaluation or bound a license issued for another installation, and deleting it created a fresh evaluation. | Fixed: the row is sealed (HMAC under `alice/installation/v1`); a mismatch, a removed seal or a removed row with a valid time record or completed setup is audited (`license.installation_tampered`) and evaluated as an ended evaluation; `alice_app` can no longer update the ID or the timestamp. Remaining accepted bypasses (R36 addendum j): whoever holds the master key can compute a valid seal; a patched binary skips every check; a database emptied of every trace (installation row, both time record copies, setup completion) is indistinguishable from a new one; and the owner role can clear the seal of an installation that was never sealed by the one-time upgrade step, which then seals the edited row once (audited as `license.installation_sealed`). Superseded by the audit remediation (R39 item 6, `audit-remediation.md`): there is no upgrade seal any more, a missing seal is always tampering, and the seal column is read-only for `alice_app`. |

No High finding is open.

## Known limitations

- **No infrastructure yet.** Nothing changes managed servers, so no Phase 2 route is refused in lock: the lock gate
  is proven with a synthetic route, the route-table rules and stub jobs. The first real `ClassChange` routes and
  jobs arrive in Phase 3 (targets), together with the `403 license.locked` response in `api/openapi.yaml` and a
  user-visible "Not available while the license is expired." Owner step 4's "try to add something" becomes
  possible then. L-04 and L-70..L-79 run against the stub target counter (`license.NoTargets`) until Phase 3.
- **Deferred matrix cases (R36 addendum e).** L-81 (durable queue, Phases 3/4), L-82 (deploy job, Phase 4),
  L-83..L-86 and L-88 (rotation runner, Phase 6), L-87 (Key Vault poll and deploy, Phases 5/4) and the real-job
  parts of L-29 (Phase 3+); their gate parts pass as stub-job tests (`internal/jobs/stubjobs_test.go`). R29's
  "paused external-change jobs wait for an administrator's confirmation" needs the queue.
- **Certificate evidence (Phase 4).** The `notBefore` warning of R28/L-53/L-56/L-57 needs discovered certificates;
  the license module has no `notBefore` input by construction (R28).
- **Alerts (Phase 7) and backup (Phase 8).** L-28 (expiry emails with the "license expired" note) arrives with
  alerts; L-06 and L-44 (restore keeps the Installation ID, the installation timestamp and the license) are
  exercised with backup/restore. Email configuration moves from `ALICE_SMTP_*` to Settings → Email in Phase 7.
- **Banner coverage.** The `tampered`, `over_limit` and `limit_reached` banners cannot be reached in the Phase 2
  e2e build (no targets, no way to edit a stored file), so they have unit tests but no axe or overflow check yet.
- **Evaluation details.** If the evaluation that follows a committed upload fails, the snapshot (and the gate)
  stay at the pre-upload state until the next successful hourly evaluation; the upload is still reported as
  accepted. A clock jump first seen during shutdown is not audited (consistent with the first-observation rule).
  After a downgrade to a build that cannot read a newer stored file, that file is reported as `license.tampered`
  (no longer true since the audit remediation, R39 item 6: such a file is not tampering).
  A fresh database next to a leftover damaged `hwm.dat` is not audited (no longer true since R39 item 6: a
  damaged copy is evidence of an earlier installation, and an unreadable file stops the first start). Validation runs before the installation
  binding, so a foreign file with impossible dates is reported as invalid rather than as foreign.
- **Clock.** P2-02 and P2-05 above.
- **Installation record.** P2-10's remaining bypasses. An installation whose record was changed outside Alice stays
  in "evaluation ended" until the original record is restored (for example from a backup); a removed record gets a
  new Installation ID whose evaluation has already ended, so the customer needs a license for the new ID. The License
  page shows the phase but no dedicated banner for this; the audit log names it.
- **Deferred small items.** `licensectl keygen --split` (Shamir, §16.7, only with a second trusted person); the
  "Download request file" button (§19.1); a native-speaker tone review of the Turkish texts; Windows vendor
  machines. The Phase 1 findings still open (P1-01..P1-10) stay as recorded in `docs/security/reviews/phase-1.md`.

## Owner verification

Spec §26.4 "Owner verifies". Steps 1–3 need **your offline production signing key**, which only you create and
hold (`docs/vendor/licensing-vendor.md`); no build agent ever does them. Steps 4–5 use the **test build** and need
no key. Run everything on your development machine, never on a server with real data.

> **Warning.** `make reset` (step 1) **deletes the development database, keys and license time record** —
> every user, audit entry, license file and the Installation ID — and starts a fresh installation. The test
> build of steps 4–5 (`make e2e-up`) uses the same development database, and `make e2e` empties all its tables.
> Do these steps only on a development stack whose data you do not need.

If `deploy/.env` sets `ALICE_PORT` to something other than 443, write `localhost:<port>` instead of `localhost`
everywhere below, including the `Origin` header.

### Steps that need the production key (1–3)

1. **Create the key and build it into Alice.** On the offline vendor computer follow "1. Create the signing key"
   and "2. Put the public key into Alice builds" in `docs/vendor/licensing-vendor.md` (key, two USB drives, paper
   copy, commit `internal/license/keys/production.json`, `make release-keycheck` says `ok`). Then, on the
   development machine:

   ```bash
   make reset          # DELETES the development data (see the warning above), starts a fresh release-mode stack
   make setup-token    # prints the one-time setup code
   ```

   Open `https://localhost`, follow `docs/first-run.md` and finish the wizard with
   **Start 30-day evaluation (up to 5 targets)**. Then run:

   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec -T alice /usr/local/bin/alice license keys
   ```

   Expected: one line `vk-… active SHA256:…` whose fingerprint equals the one on your paper, and no "test build"
   warning.
2. **Issue and install a real license.** Open **License** and choose **Copy** next to the Installation ID. On the
   offline vendor computer:

   ```bash
   bin/licensectl issue --key /media/offline/alice-vendor/alice-license-private.pem \
       --installation <the Installation ID> --customer "Test Company" --targets 10 --out test.alicelic
   ```

   Type the passphrase and `yes`, and write the ledger rows and chain head in your paper log. Carry `test.alicelic`
   to the development machine. In Alice open **License**, **Upload a license**, choose the file,
   **Check the file**, then **Install license**.
   Expected: "License activated. All features are available again." and "Valid until <date one year ahead>,
   10 targets"; the blue evaluation banner is gone.
3. **An edited file is refused.** Open `test.alicelic` in a text editor, change any number (for example
   `"max_targets": 10` to `"max_targets": 11`), save it as `edited.alicelic` and upload it.
   Expected: "This file is not a valid Alice license." and the page still shows "Valid until <date>, 10 targets".
   **Audit log** lists "License upload refused: signature does not match" (`license.upload.invalid_signature`).

### Steps with the test build (4–5)

The test build lets you move Alice's clock. Your phone's authenticator follows the real time, so after moving the
clock sign-in codes come from this command instead (it computes the code for Alice's clock):

```bash
python3 -c 'import base64,datetime,hashlib,hmac,json,re,ssl,struct,sys,urllib.request
n=json.load(urllib.request.urlopen("https://localhost/test/clock",context=ssl._create_unverified_context()))["now"]
t=int(datetime.datetime.fromisoformat(re.sub(r"\.\d+","",n).replace("Z","+00:00")).timestamp())//30
h=hmac.new(base64.b32decode(sys.argv[1].replace(" ","").upper()),struct.pack(">Q",t),hashlib.sha1).digest();o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' <YOUR KEY>
```

`<YOUR KEY>` is the authenticator key of the administrator you create in step 4's wizard (the reset at the start
of step 4 removes every earlier administrator, so an older key no longer works). Capture it on the wizard's
**Set up your authenticator app** screen: below the QR code, under "Cannot scan the code? Type this key into the
app instead:", Alice shows the key as one line of capital letters and digits. Write it down (or copy it into a
text file on your development machine) before you continue, and also add it to your phone's authenticator as usual.
A code works once: wait 30 seconds before the next sign-in at the same clock time.

4. **Warnings, grace, lock and renewal.** Start the test build and **reset it first. The reset erases everything
   steps 1–3 created** (the administrator, the real license, the audit log and the Installation ID), because the
   test build uses the same development database; finish steps 1–3 and write their results down before this.

   ```bash
   make e2e-up         # the test build, on the development database (see the warning above)
   curl -sk -X POST -H 'Origin: https://localhost' https://localhost/test/reset   # empties every table: a fresh installation
   make setup-token
   ```

   Instead of the `curl` line you can run `make reset && make e2e-up` (it also deletes the key and state volumes).
   Open `https://localhost` and finish the wizard with **an email address for the administrator** and
   **Start 30-day evaluation (up to 5 targets)**. On the authenticator screen write down the key as described
   above. Create a test license that ends in 61 days and save it as a file:

   ```bash
   curl -sk -X POST -H 'Origin: https://localhost' https://localhost/test/license -d '{"valid_days":61}' \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["license"])' > test61.alicelic
   ```

   Upload `test61.alicelic` on **License** (**Check the file**, **Install license**).
   Expected: "Valid until <date>, 10 targets" and no banner.

   Now move the clock with the command below, using the number of seconds from the table, one row at a time. After
   each move, reload the page and sign in again (password, then the code from the python command). Check the
   banner and open `https://localhost/test/mail` to see the newest email (its subject names the warning).

   ```bash
   curl -sk -X POST -H 'Origin: https://localhost' https://localhost/test/clock -d '{"advance_seconds":<SECONDS>}'
   ```

   | Move by `<SECONDS>` | Days left afterwards | Expected banner (administrator) | New email |
   |---|---|---|---|
   | `90000` (25 hours) | 60 | Yellow: "Your license expires in 60 days (…)" | Yes, the 60-day warning |
   | `2592000` (30 days) | 30 | Yellow, 30 days | Yes |
   | `1382400` (16 days) | 14 | Yellow, 14 days | Yes |
   | `604800` (7 days) | 7 | Orange, 7 days | Yes |
   | `518400` (6 days) | 1 | Orange, 1 day | Yes |
   | `86400` (1 day) | grace day 1 | Red: "Your license expired on … Grace day 1 of 7." | Yes, the grace email |
   | `86400` (1 day) | grace day 2 | Red, grace day 2; everything still works (**Users**, **Audit log**, **License**) | Yes, one per day |
   | `518400` (6 days) | after 168 hours | Red: "License expired. Automatic tasks are paused. …" | Yes, the lock email |

   Reloading or signing in again at the same clock time never sends a second email for the same warning. Trying
   to add a server that would be refused in lock mode becomes possible with targets in Phase 3.

   Finally create and upload a renewal for the new clock time:

   ```bash
   curl -sk -X POST -H 'Origin: https://localhost' https://localhost/test/license -d '{"valid_days":365}' \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["license"])' > renewal.alicelic
   ```

   Expected after **Install license**: "License activated. All features are available again." and the red banner
   is gone at once.
5. **A clock set back does not extend the license.** Still signed in, note the date on **License**
   ("Valid until <date>"), then move the clock five days back and reload the page (do not sign out: with the test
   clock set back, sign-in codes are refused until it passes the last code used; on a real server phone codes are
   refused until the clock is corrected, see P2-05):

   ```bash
   curl -sk -X POST -H 'Origin: https://localhost' https://localhost/test/clock -d '{"advance_seconds":-432000}'
   ```

   Expected: the orange banner "The server clock changed unexpectedly (it says …, but Alice last saw …)" and the
   "Valid until <date>" is the same date as before (not five days later). **Audit log** lists
   "Server clock set back" (`clock.rollback_detected`) once.

When you are done, run `make down`. The next `make up` builds the release image again; its data is what the test
left behind, so run `make reset` (which deletes it) before using the stack for anything else.

Results (filled in by the owner):

| Step | Result |
|---|---|
| Date / commit | |
| 1 | |
| 2 | |
| 3 | |
| 4 | |
| 5 | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
