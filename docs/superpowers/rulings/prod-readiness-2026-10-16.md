# Prod-readiness fixes — rulings

Decisions taken while closing the prod-readiness review of 2026-10-16 on branch `prod-readiness-fixes` (review
`docs/security/reviews/prod-readiness-review-2026-10-16.md`, reviewed commit a86def1a; plan
`docs/superpowers/plans/2026-10-16-prod-readiness-fixes.md`). Each entry: item — decision — why — cost if wrong.
Accepted and deferred items are also KI-39 (and KI-38 for AUTH-2) of `SECURITY-REPORT.md`.

## Fixed, with the reading the fix took

- AUTH-1 (= A-1, a wrong password every 15 minutes kept an account blocked for ever) — a failure recorded after a
  15-minute block has ended starts a new count at 1, in the same `UPDATE` that counts it, so it is atomic under the
  row lock; the right password is accepted as soon as the block has ended; the counter is not decayed by time
  otherwise. SEC-020 now names the end of a block as a reset beside a completed sign-in and a successful step-up
  (`internal/auth:TestAFailureAfterTheBlockEndedStartsANewCount`) — why: the block is meant as a ceiling of 10
  evaluated guesses per 15 minutes, not a permanent state an anonymous caller can hold; a sliding window would add a
  column and a migration for no stronger bound — cost if wrong: someone who knows a user name can still keep that
  account blocked by sending 10 wrong passwords every 15 minutes (KI-26), and each block still mails the
  Administrators.
- CRY-1 (= C-2, `aaaaaaaaaaaaaaaaaaaa` rated strong) — the meter, on the server (`internal/setup/strength.go`) and in
  the browser (`web/src/pages/setup/strength.ts`), driven by one vector file (`internal/setup/testdata/strength.json`,
  `TestPassphraseStrengthVectors`), first collapses a repeated word cycle, then a repeated rune period, then every run
  of 3 or more identical runes to one, then every run of 3 or more runes stepping +1 or -1 to its first two; the rune
  count left is the effective length. Below 16 effective is Fair (refused); otherwise the old score applies to the
  effective length, with distinct words instead of all words. No zxcvbn dictionary — why: the review's examples
  (repeats, sequences, one word repeated) are what people actually type for a forced 16 characters; a dictionary
  model would add a large dependency to both sides and drift between Go and TypeScript — cost if wrong: a
  passphrase built from common words or keyboard walks (`qwertyuiop…`) can still rate good; it protects every backup
  and `master.key` inside it, so the guides keep telling people to use several unrelated words.
- REM-1 (= RA-01, a 16 MiB `nginx-dump` grew to about 7 GiB of server copies) — a budget for the whole dump:
  `maxMembershipsPerDump = 20000` (one server block listed under one certificate location) and
  `maxNamesPerDump = 100000` server names; a server block that does not fit is left out and the location says the
  list was cut (`list_truncated`), as the per-location bound already did
  (`internal/providers/nginx:TestConvertBoundsMembershipsAcrossTheDump`, `TestConvertKeepsARealisticLargeConfiguration`)
  — why: the per-file and per-location bounds multiply; a dump-wide count is the one bound that does not, and 20,000
  memberships is far above a realistic configuration (the second test keeps one whole) — cost if wrong: a very large Nginx
  estate shows some websites as "list cut" and their servers are missing from the location's list until the
  configuration is split.
- REM-2 (= RA-03, unbounded key comments and options in the inventory) — the inventory keeps at most 1024 bytes of a
  key's comment and 4095 bytes of its options text, cut on a rune boundary, followed by `…` (so a stored value is at
  most the cap plus the 3-byte ellipsis); the raw line used to rewrite `authorized_keys` and the parsed options stay
  complete (`internal/providers/linuxssh:TestKeyCommentAndOptionsAreCapped`) — why: the inventory is for people to
  read; the file itself must never be rewritten from a shortened copy — cost if wrong: two keys whose comments differ
  only after 1 KiB look alike in the list (their fingerprints still differ). Whole-branch review fix: a rotation
  builds the new key's line from the stored options text, so a cut list (ending in `…`, which no valid option list
  does) made the place fail during the run (`internal.unexpected`); the options cap was raised from 1 KiB to 4 KiB (4095 bytes, so a cut value of 4095 characters plus `…` fits
  `rotation_locations.options`, `CHECK (char_length(options) <= 4096)`, which a run inserts for every place, skipped
  ones included; F1 re-review: an 8 KiB cap made that insert fail and the whole run with it,
  `internal/sshkeys:TestRunStartsWithACutOptionsLocationSkipped`) and the planner skips such a place in the preview and at send time (`options_truncated`,
  `internal/sshkeys/plan:TestCutOptionsAreSkippedBeforeTheLineIsBuilt`) — cost: a key whose option list is longer
  than 4 KiB is not rotated at that place until the list is shortened.
- REM-2, second half (inventory rows of keys that vanished from a server are never pruned) — by design, not changed:
  a row keeps `missing_since` and `removed_by_alice_at`, the history of where a key was and when it went, which a
  rotation or a revocation is checked against. The caps (1 KiB comment, 4 KiB options) bound each row — cost if wrong: the table grows by the
  number of distinct keys ever seen per account, not by the number of scans.
- REM-4 (= RA-02, an unreadable first certificate made the intermediate look like the website's certificate and
  silenced its expiry alarm) — `alice-helper` 1.6.1 reports such a file as `leaf_unreadable` (protocol 7
  unchanged); Alice lists the location as not supported with that reason and drops the certificate link stored for
  it, as for `not_a_certificate` (`internal/inventory:TestPrepareLocation`,
  `TestReconcileMissingChangedOutsideAndInvalidConfiguration`) — why: a link written by an older helper points at the
  intermediate; keeping it would keep the wrong expiry date on screen; no link is better than a wrong one — cost if
  wrong: until the file is fixed, that website has no certificate in Alice and no expiry e-mail; the location's
  problem is shown instead. A server with a helper older than 1.6.1 still shows the intermediate (the guides say to
  reinstall the helper). Follow-up for 1.0.x (whole-branch review): `certBlocks` in `cmd/alice-helper/nginx.go`
  matches only `-----BEGIN CERTIFICATE-----`, so a leaf labelled `TRUSTED CERTIFICATE` or `X509 CERTIFICATE`
  (OpenSSL's `PEM_read_bio_X509_AUX` reads both, so Nginx serves it) followed by a normal intermediate still hands
  the intermediate to Alice as the leaf, with no warning; KI-39 tells customers to use the `CERTIFICATE` label.
- OPS-6 (`ALICE_TRUSTED_PROXIES` could not be set by a customer) and OPS-4 (the migration limit was a fixed 2
  minutes) — both are keys of `/opt/alice/.env` (`ALICE_MIGRATE_TIMEOUT` default `30m`, from `1m` to `24h`),
  written by the installer, carried over by the update, and checked for format and range in the update's preflight
  before anything changes (the binary applies the final check at start). Whole-branch review fix: the preflight's
  character-class checks accepted values the binary refuses (`25h`, `999.1.1.1`, `10.0.0.1/33`); it now parses the
  duration (60 s to 24 h) and each proxy entry (IPv4 with `/0`-`/32`, IPv6 with `/0`-`/128`); and `.env` is read
  like Docker Compose reads it, the last line of a key winning, so a proxy list appended after the installer's empty
  `ALICE_TRUSTED_PROXIES=` is kept (`deploy/release:TestUpdateKeepsTheLastLineOfAKeyWrittenTwice`). First-update caveat, accepted: the update script that runs is the installed version's, which rewrites
  `.env` from the keys it knows, so an installed version from before this change drops both keys on that one update
  (and its database update uses the default limit). `docs/upgrade.md` and `docs/operator-guide.md` say to check
  `.env` after that update — why: an old script cannot be changed after it shipped; no customer has a release
  before 1.0.0, so the case is a development installation — cost if wrong: a proxy setting silently lost for one
  update puts everyone behind the proxy in one rate-limit bucket until it is set again.
- OPS-5 (= RA-04, migrations edited in place) — migrations `00001` to `00015` are frozen by SHA-256
  (`migrations:TestReleasedMigrationsAreFrozen`); a change to the schema is a new numbered migration — why: an
  installed database never runs an edited file again, so an edit makes a fresh install differ from an upgraded one
  without any error — cost if wrong: a defect found in one of the 15 files must be fixed forward by a new migration,
  never by an edit; changing the test's checksum is a deliberate act a review must question.
- OPS-3 (= DO-01, `make release` built from the working tree) — `release-preflight` refuses uncommitted changes to
  tracked files; `RELEASE_ALLOW_DIRTY=1` skips the check and exists only for `make release-test` — why: the signed
  package must be the release commit that the gates ran on; untracked files are not checked (`git status
  --untracked-files=no`), so build outputs and local notes do not block a release — cost if wrong: an untracked file
  that the image build reads (`COPY . .`) still reaches the package; the release checklist builds the stage from a
  checkout of the signed tag, which has none.

## Process changes

- OPS-1 (CI never green: the 20-minute `go` job was cancelled inside `make coverage`) — coverage runs in its own
  `coverage` job with a 75-minute limit; the `go` job keeps lint, tests, govulncheck, build and the symbol check at 30
  minutes — why: the slow step is the integration coverage run; splitting it lets the other gates report even when it
  is slow — cost if wrong: a remote run has not been recorded since the change; if the coverage job still exceeds 75
  minutes, coverage floors are again unproven in CI (release checklist row 1.1 needs a green run).
- OPS-2 (ZAP 10062 "PII Disclosure" failed the nightly baseline) — ignored by a policy line in `.zap/rules.tsv` with
  its reason and the expiry 2027-04-01 (within the file's 180-day rule): the rule matched Luhn-valid digit runs
  inside the 64-hex `hash` and `prev_hash` fields of `GET /api/v1/audit` (nightly of 2026-10-15); the audit log
  carries no card or personal numbers — why: a false positive of a pattern rule on hex; ignoring only this rule ID
  keeps every other High alert failing — cost if wrong: a real personal number in another answer would not fail the
  baseline until the line expires; at expiry the line is re-triaged, not renewed by default.
- OPS-7 (Dependabot proposed PostgreSQL 16 to 18) — Dependabot ignores PostgreSQL majors in its `docker` and
  `docker-compose` entries for `/deploy` (`.github/dependabot.yml`); the open pull request #5 is closed by the owner, not merged; a major is a planned release with its own
  data-directory migration — why: `alice-update.sh` has no `pg_upgrade` step, so every customer update would fail and
  roll back — cost if wrong: PostgreSQL 16 reaches end of life in November 2028; the major upgrade must be planned
  before then, and minor updates still arrive.

## Accepted (documented, no code change)

- A-2 (TOTP enrolment needs only the password) — accepted: the pending session the password opens is single-use,
  and the first verified code closes it and completes the sign-in — why: at enrolment the password is the only
  credential the account has; asking for anything else would need an out-of-band channel v1 does not have — cost if
  wrong: someone who learns a user's password while that user has no authenticator (a new account, or after an MFA
  reset) can enrol their own; hand initial passwords over privately and watch the audit log for sign-ins you do not
  expect.
- Z-03 (operate API tokens need no step-up) — accepted: a token cannot answer a step-up, and every high-impact action
  refuses tokens outright instead (the "API token" column of `docs/authz-matrix.md`, pinned by
  `internal/api:TestAuthzMatrix`); the operate scope covers only routine operations an Operator may automate — why:
  a step-up for a token would be the token again — cost if wrong: a leaked operate token can run every operate
  action (deploys, scans, tests) until it is revoked or expires (at most 365 days); tokens are listed, audited and
  revocable.
- N-02 (no TLS between Alice and PostgreSQL) — accepted for v1: the database runs on the same host on Docker's
  internal `backend` network with no published port, every TCP rule is SCRAM, and the application role holds no owner
  credential — why: the traffic never leaves the host; TLS would add a certificate to issue, rotate and back up for
  no attacker that does not already have the host (KI-01, KI-10) — cost if wrong: someone able to sniff the Docker
  bridge on the host reads queries; that person is root or in the `docker` group, which is root-equivalent (KI-17).
- CORE-1 and CORE-3 (job leases follow the application's wall clock; database sessions have no statement, lock or
  idle-in-transaction timeout) — accepted for v1 as low risk, not absent: one `alice` process per installation is the
  supported deployment (the production compose runs one) and high availability and several processes are out of
  scope for v1, so there is no second process competing for leases, and only Alice's own sessions and the host
  operator hold locks in its database. With one process, a clock jump of more than a lease can still run one
  target's job twice, and a stuck lock still makes the workers that need it wait without limit — cost if wrong:
  those two effects on a host whose clock is stepped (customers keep it on NTP, KI-39, KI-07) or whose database
  hangs a lock (a restart of Alice releases only the locks its own sessions hold; a lock held by another session,
  such as an operator's `psql` or a backup tool, must be ended in PostgreSQL; a restart does nothing for the
  clock-jump double run); both become likely with a second process, so both must be fixed before any
  multi-process or HA support.
- CRY-3 (= C-1, SEC-043 claimed an audit HMAC key) — the spec text is corrected, not the code: the audit chain is an
  unkeyed SHA-256 chain in v1 (KI-05); `alice/audit-hmac/v1` and `secrets.LabelAuditHMAC` are reserved for v2 and
  unused — cost if wrong: none; the label stays reserved so a keyed chain later cannot collide with another sub-key.

## Deferred

- AUTH-2 (anyone who knows a directory sign-in name can lock it in Alice for 45 minutes, again and again) — deferred
  to the owner's directory-lockout decision, with the other open directory decisions (an Administrator unlock
  action, ending sessions when a directory is switched off, the default group names). Nothing changed in this
  branch; KI-38 states the trade-off — why: the review's alternatives (a lock per name and source prefix, an
  exemption for a browser that signed in before) each weaken the protection of the directory account against
  guessing through Alice, which is why the lock exists; that is a product decision, not a fix — cost if wrong: until
  the decision, an unauthenticated attacker can keep chosen directory users, Administrators included, out of Alice;
  a local Administrator and a restart remain the way back in.
- AUTH-5 (no `If-Match` on `PATCH /api/v1/users/{id}`) and VC-1 to VC-4 (vendor console) — carried to 1.0.x (KI-39):
  AUTH-5 needs a version column and a web change; the vendor console never ships to customers.
