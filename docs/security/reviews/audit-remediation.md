# Security Review — Audit remediation (independent audit of 2026-10-04)

Scope: the 25 findings (AUD-01 to AUD-25) of the independent audit of 2026-10-04
(`docs/security/reviews/independent-audit-2026-10-04.md`, kept as written and not part of the repository's history,
with its proof-of-concept notes next to it). Seven of them were already closed in the Phase 4 fix wave; this
remediation (branch `audit-remediation`, from `master` at `57b11fb`) fixes or records the others. Exit criterion: no
finding of the audit open without a fix, an owner action or a recorded decision; no new High finding.

The decisions behind this remediation are R39 in `docs/superpowers/specs/alice-v1/00-decisions.md`; R39 item numbers
are given in brackets below. Every fix was implemented by one agent and reviewed by another, with fix rounds until the
reviewer approved; the defects those reviews found are listed under "Defects found during the remediation".

## Finding map

Severity is the audit's (AUD-01 to AUD-10 Medium, AUD-11 to AUD-25 Low). Commits are those whose message names the
finding (`git log --grep 'AUD-NN' master..HEAD`), plus the Phase 4 commits for the findings closed there.

| AUD | Severity | Outcome | Commits | Tests that pin it | Decision or reason |
|---|---|---|---|---|---|
| AUD-01 idle timeout defeated by polling | Medium | Fixed here | 580b7dc, 7b94d31, 61d092b, 9e76d52 | `TestBackgroundPollsDoNotExtendTheIdleTimeout`, `TestActivitySlidesAndPollsDoNotTouchTheSession`, `TestRecordActivityNeverRevivesOrOutlivesASession` (auth, integration); `TestOnlyActivitySlidesTheSession`, `TestRefusedRequestsAndActivity`, `TestRecordActivityFailureIsUnavailable`; `TestA02BackgroundPollsDoNotKeepASessionAlive`, `TestA02ActivityAmongPollsSlides`, `TestA02OnlyAcceptedRequestsSlide`, `TestA02MarkerOnAnEndedSessionAndTokens` (api, integration); Vitest `activity`, `client`, `LicenseBanners`, `SessionActivity`, `polling`; Playwright `phase1.spec.ts` "a tab left open is signed out 30 minutes after the last input although it keeps polling (AUD-01)" and "a person who keeps reading stays signed in until the 12-hour limit (AUD-01)" (EN, TR) | [1] |
| AUD-02 license gate trusts a stale evaluation | Medium | Fixed here | a6d56de, ae993e8, d64f402, 00a3d36, eacabae, 6f40137 | `TestGateLocksAtLocksAtWhileTheRowIsHeld`, `TestGateFailsClosedWhenEvaluationsStop`, `TestForeignLeaderLockDoesNotStopEvaluation`, `TestGateIgnoresTheWallClockBetweenEvaluations`, `TestStartGivesUpWhenTheRowIsHeld`, `TestLockDueIsNotAConfirmedLock`, `TestLockDueInAnotherProcessHoldsNothing`, `TestFailedEvaluationsAreRetriedWithinMinutes`, `TestRetriesNeverLeaveThreeHoursWithoutASuccess`, `TestTwoEvaluatorsRecordEachTransitionOnce`, `TestAProcessWithoutTheHoldLeavesTheStateToTheHolder`, `TestShutdownGivesUpBehindARunningEvaluation` (license); `TestUnverifiedPausesQueuedWorkWithoutHoldingIt`, `TestUnverifiedAfterTheClaimQueuesTheJobAgain`, `TestRecoveryRunsWhileTheLicenseIsUnverified` (jobs); `TestDiscardWorksInEveryLicenseState` (api); Vitest `LicenseBanners` | [2] |
| AUD-03 accounts outside the old name rule skipped silently | Medium | Fixed here | ac71c89, f2b86dd, 78dc937, e200376, b14cd4b, 5857518, 514e6e6, d0af08d, e4df392, c49d1ad, 6f40137 | `TestAccountsOutsideTheOldGrammarAreListed`, `TestUnlistedAccountsAreReportedNeverSilent`, `TestPasswdNULBytesAreReadAsGlibcReadsThem`, `TestOddIDsAreReported`, `TestNISCompatLinesAreNoAccounts`, `TestDirectoryUsersAreAnySourceButFiles`, `TestUserdbRecordsMakeTheListIncomplete`, `TestSymlinkedNSSwitchIsFollowedOrRefused`, `TestUnreadableNSSwitchIsNotLocal`, `TestPasswdLineSpellings` (helper); `TestDiscoverReportsUnlistedAccounts`, `TestLastKeyOfAnyUID0AccountNeedsConfirmationInAFreshSession`, `TestEmulatorFidelityAuthKeysList`, `TestEmulatorFidelityAuthKeysListTruncated` (linuxssh); `TestRealOpenSSH` (real matrix, Ubuntu 22.04, Debian 12, Rocky 9: dotted, capitalised and `$` names, a trailing-slash home, two unlisted entries, and a complete list with `John`, `john` and a shared uid) | [3] |
| AUD-04 discovery data unbounded; RSA size | Medium | Fixed in Phase 4 | d375100, 73e71c8, 1191814 (P4-45, P4-26) | as recorded in `phase-4.md` | — |
| AUD-05 late-starting helper applies a "nothing written" deployment | Medium | Fixed in Phase 4 | 83522dd, 59601fe, d44d50f, e0cd19e (P4-38, P4-49) | as recorded in `phase-4.md` | — |
| AUD-06 refusal rows grow the log; scans reread everything | Medium | Fixed here (verification stays a full recomputation) | 3d919fd, f7a09b2, 1f8ce8f, a3f9d8d, ab72da0, 6a95367 | `TestDenialCoalescer`, `TestDenialCoalescerIsBoundedAndNeverDropsARow`, `TestGuardCoalescesRepeatedRefusals`, `TestTokensOfOneOwnerShareAWindow`, `TestForeignTokenListsAreCoalesced`, `TestChainScansRunOneAtATime`, `TestStopScansEndsARunningScan`, `TestStopScansAbortsAStartedExport`, `TestDistinctSetIsBounded`, `TestChainScanRoutesMatchTheRouteTable` (api); `TestRepeatedDenialsAreCoalesced`, `TestForeignTokenListEnumerationIsCoalesced` (api, integration); `TestShutdownStopsScansThenDrainsThenFlushes` (cmd/alice); Vitest `AuditPage` | [4], [7] |
| AUD-07 e2e stack published on every interface | Medium | Fixed in Phase 4 | 5d187b1 | `TestE2ETargetIsTestOnlyAndUnpublished`; `check-hardening.sh` "alice (e2e) publishes only on 127.0.0.1" | — |
| AUD-08 CI never runs on the branches used; no remote | Medium | Fixed here (the trigger); the remote, the first run and branch protection are owner-pending | b5cf2a4 | actionlint (0 findings, recorded by the implementer) | [9] |
| AUD-09 build inputs pinned by mutable tags | Medium | Fixed here | 0071dca, 4da6947, a3ab994 | `TestRepositoryIsPinned` and the form tables of `tools/pincheck` (`TestDockerRunImageOperand`, `TestWorkflowContainersServicesAndRunSteps`, `TestDockerPullAndDockerfileCase`, …) | [9] |
| AUD-10 dropped handshake classified as an authentication failure | Medium | Fixed in Phase 4 | 4abe22d, 02fbc36, 79d0382 (P4-44, P4-50) | as recorded in `phase-4.md` | — |
| AUD-11 parallel sign-in timing reveals existing names | Low | Fixed here (small residual) | 7f1774c | `TestParallelSignInsForOneNameQueueAlikeWhetherOrNotItExists`, `TestBlockedPasswordChangeChecksUnderTheAccountLock` (auth, integration) | [12] |
| AUD-12 reset and sign-out-everywhere keep API tokens | Low | Fixed here | 3e9ce6f, 4a02ac1, 5cae1a6, b28f373, 6f40137, b6e8226 | `TestAdminPasswordResetRevokesTheUsersAPITokens`, `TestSignOutEverywhereRevokesTheUsersAPITokens`, `TestOwnPasswordChangeKeepsAPITokens`, `TestATokenReadBeforeTheRevocationCommitsIsRefusedAfterIt`, `TestNoLastingCredentialFromASessionBeingRevoked`, `TestDisablingRevokesTokensForGood` (auth, integration); `TestAdminIncidentActionsRevokeAPITokens` (api, integration); Vitest `UsersPage`; Playwright `phase1.spec.ts` "dialogs, …" | [5] |
| AUD-13 NUL or invalid UTF-8 reaches PostgreSQL (500) | Low | Fixed here | e8576a1, 15b76d7, b09b9d2, 11dbe1d | `TestEveryRouteRefusesUnstorableQueryText`, `TestEveryRouteWithABodyRefusesNULText`, `TestOnlyTheDecodeHelpersReadRequests`, `TestChunkedBodyOverTheCapIsTooLargeEvenWithNUL`, `TestLicenseUploadWithNULTextIsAudited`, `TestWriteJSONNeverTruncatesAnAnswer`, `FuzzNULEscape` (api); `TestUnstorableTextIsRefusedAtTheEdge`, `TestUploadRefusesCertificatesOutsideYears1To9999` (api, integration); `TestCursorTimeRange`, `TestCertificateCursorAtTheEndsOfItsRange`, `TestDiscoveryRefusesCertificatesOutsideYears1To9999` (inventory); `internal/certs/validity_test.go`; `internal/providers/nginx/chainrange_test.go` | [10] |
| AUD-14 signing-request key generation unbounded | Low | Fixed in Phase 4 | 715c908, 8a163c9 (P4-27) | as recorded in `phase-4.md` | — |
| AUD-15 refusals lost when the client leaves | Low | Fixed here | 3d919fd, 1f8ce8f, 6a95367 | `TestRefusalIsAuditedAfterTheClientLeft`, `TestFailedRefusalAuditStillRefusesAndRetries` (api); `TestDenialIsRecordedWhenTheClientDisconnects` (api, integration); `TestTokenObjectLevelAccess` (auth, the cancelled-context case) | [4] |
| AUD-16 rate limit after the credential lookup; `/healthz` unlimited | Low | Fixed here | 7dc8b6c, b68dc10, 9e76d52 | `TestValidSessionsNeverMeetTheFailedCredentialBucket`, `TestConcurrentGarbageCannotOverrunTheBucket`, `TestFailedLookupsKeepTheirToken`, `TestGarbageSessionNextToValidSetupCookieIsBounded`, `TestRotatedAwayCookieIsNotDeleted`, `TestRecentlyValidatedForTheSessionIdleTimeout`, `TestHealthzHasItsOwnBucket`, `TestHealthzLimitedOnlyOnThePublicListener` (api); `TestFailedCredentialLimitWithRealSessions` (api, integration); Vitest `client`, `retry`, `App` | [11] |
| AUD-17 a scan rewrites an uploaded chain; incomplete chain not completable | Low | Fixed in Phase 4 | 92c5e10, 1191814, 2854564, a6a5ee7 (P4-25, P4-46) | as recorded in `phase-4.md` | — |
| AUD-18 evaluation restartable with the owner role | Low | Fixed here | dcce48f, 765b90d | `TestEvaluationRestartAttempts`, `TestRemovedSealIsTamperingOnEveryInstallation`, `TestRemovedInstallationIsNotAFreshEvaluation`, `TestUnreadableStateDirectoryStopsTheFirstStart`, `TestUnreadableStateDirectoryWithAnInstallation`, `TestAppRoleCannotRewriteTheInstallation` (license, integration); `TestMigration00007SealIsReadOnly` (migrations) | [6] |
| AUD-19 newer format with new fields reported as invalid | Low | Fixed here | 9c80313 | `TestNewerFormatWithNewFieldsAsksForAnUpdate`, `TestNewerFormatFromARevokedKey`, `TestCanonicalJSONIsRFC8785`, `TestStoredNewerFormatIsNotTampering`, `FuzzParseLicense` (license); `TestNewerFormatLicenseAnswers` (api); `TestNewerFormatIsReportedOnlyWhenSigned` (licensectl) | [14] |
| AUD-20 master key file's directory not synced | Low | Fixed here | 29b8aeb, a40966c, d2bb792 | `TestCreateKeyFileSyncsItsDirectory`, `TestCreateKeyFileFailsWhenTheDirectorySyncFails`, `TestCreateKeyFileLoserFailsWhenTheDirectorySyncFails`, `TestCreateKeyFileFailsWhenTheParentSyncFails`, `TestSyncDirectory`; `TestAdoptedKeyFileIsRecordedOnlyAfterItsDirectorySync` (integration) | [13] |
| AUD-21 a setup-code reset does not stop a running administrator creation | Low | Fixed here | 8ae95db, 8fad0d1 | `TestResetDuringAdminCreationWins`, `TestResetWaitingBehindAdminCreationFindsTheAdministrator`, `TestSessionOpenedWithTheOldCodeDoesNotSurviveAConcurrentReset`, `TestStartSessionBlockedBehindAResetRereadsTheNewCode`, `TestWrongCodeTakesNoRowLock`, `TestConcurrentResetAndCreateHaveExactlyOneOutcome` (setup, integration) | [13] |
| AUD-22 every read and write rescans all accounts | Low | Fixed here for discovery (key reads and writes still scan) | ac71c89, f2b86dd, 78dc937, e200376, b14cd4b, 5857518, 514e6e6 | `TestRealOpenSSH` (sudo's I/O log: one more `authkeys-list` and no `authkeys-read` during a discovery); the inline-content tests of the helper and of `protocol6_test.go`; `TestEmulatorTruncatesLikeTheHelper` | [3] |
| AUD-23 release image never inspected; gates missing | Low | Fixed here: `make image-check`, build-tag checks in `release-symcheck` and `internal/archtest`, `npm ci --ignore-scripts`, `go mod verify`, Dependabot, Vitest thresholds, Go coverage floors; `osv-scanner` deferred to Phase 8 | b3bc908, 8b22874, efe74eb, 517b4cd, 41ce75e, 7727fd2 | `make image-check` (26 checks), `TestImageCheckComparesHelperChecksumsOnlyWithTheSameGo`, `TestTestOnlyFilesRequireTheirTag`, `TestReleaseBinariesLinkNoTestPackages` and the other `internal/archtest/buildtags_test.go` rules, `make release-symcheck`, `make web-coverage`, `make coverage` | [9] |
| AUD-24 Compose override ignored; two variables not passed | Low | Fixed here | efe9e7e | `TestComposePassesConfigurationAndUsesTheOverride`, `TestComposePassesEveryConfigurationVariable` | [9] |
| AUD-25 (a) names bypass the address rule | Low | Fixed here (loopback still allowed: residual) | 88622c7, 7cf6218, 683bc85 | `TestAllowedEveryAddressForm`, `TestControl`, `TestDialContextChecksTheResolvedAddress`, `TestDialContextReportsARefusalAmongFailures` (netaddr); `TestDialRefusesAResolvedLinkLocalAddress`, `TestDialRefusesANameThatNowResolvesToARefusedAddress`, `TestProbeChangedRefusesANameThatMoved`, `TestPoolRedialRefusesANameThatMoved` (linuxssh); `TestTLSProberRefusesAnAddressAliceNeverConnectsTo`, `TestVerifyFallsBackToTheServerProbeWhenAlicesProbeIsRefused` (nginx); `TestStatusForAddressNotAllowed`; `TestRemoveKeyRecordsARefusedAddressOnTheTarget` | [8] |
| AUD-25 (b) lockout scope written too narrowly | Low | Recorded, not fixed | — | — | [15]: separating the counters needs a schema change and the SEC-020 semantics of R35's addendum; lockout alerting arrives in Phase 7 |
| AUD-25 (c) CSV export lacks the verification status | Low | Fixed here | f7a09b2 | `TestExportCSV`, `TestExportCSVFirstLineOfABrokenChain` (api) | [7] |
| AUD-25 (d) web robustness | Low | Fixed here | b28f373, 6f40137, eacabae, 9e76d52, b6e8226, ab72da0 | Vitest `RouteErrorPage`, `i18n`, `start`, `TargetsPage` (held jobs), `StepUpProvider`, `AuditPage`, `labels`, `client`, `retry`, `polling`; Playwright `phase1.spec.ts` "new screens have no serious accessibility violations" (audit details at phone width) | [16] |

## Evidence

All commands run from the repository root; `-tags integration`, `make coverage` and `make test-ssh` need Docker
(testcontainers). "Recorded" means the result is taken from the run an implementer or reviewer recorded while the
fix was built (the commit is named), not from a run made for this review.

| # | Check | Command | Expected | Result for this review |
|---|---|---|---|---|
| 1 | Helper as a normal user | `go test ./cmd/alice-helper -count=1` | ok | recorded after c49d1ad; also part of `go test ./...` below: ok |
| 2 | Helper as root (the root-only tests) | `CGO_ENABLED=0 go test -c -o /tmp/alice-helper.test ./cmd/alice-helper && docker run --rm --network none -v /tmp/alice-helper.test:/alice-helper.test:ro debian:12 /alice-helper.test -test.count=1` | PASS | recorded after c49d1ad: PASS |
| 3 | Real OpenSSH and Nginx matrix on Ubuntu 22.04, Debian 12, Rocky 9 | `make test-ssh` | both suites PASS | recorded: PASS after b14cd4b (twice), d0af08d (twice), e4df392 and c49d1ad; not run for this review |
| 4 | Emulator fidelity | `go test ./cmd/alice-helper -run Fidelity -count=1` | ok | recorded after c49d1ad (as uid 1001 and as root): ok |
| 5 | Integration suites of the changed modules | `go test -race -tags integration ./internal/auth/... ./internal/license/... ./internal/api/... ./internal/setup/...` | ok | run for this review as part of row 13 (all four ok) |
| 6 | Pin check | `go test ./tools/pincheck` and `go run ./tools/pincheck` | ok, no finding | run for this review: ok, no finding |
| 7 | Release build without test code | `make release-symcheck` | ok | recorded after b3bc908: ok; also run by `make ci` |
| 8 | Release image | `make image-check` | every check ok | recorded after efe9e7e: 26 `ok`, `image-check: ok (alice:ci)`; negative control on `alice:e2e`: 7 failures; run by `make ci` |
| 9 | Secrets in the history | `make secrets-scan` | no leaks | recorded after 517b4cd: 513 commits, no leaks found; run by `make ci` |
| 10 | Go and npm vulnerabilities, module integrity | `make vuln` | `all modules verified`, no vulnerability | recorded after 8b22874: ok; run by `make ci` |
| 11 | Unit tests | `go test ./... -count=1` | ok | run for this review (see the task report): ok |
| 12 | Lint, translations, authorization matrix, web | `make lint`, `make i18n-check`, `make authz-doc` (no diff), `make web-lint web-test` | ok | run for this review (see the task report) |
| 13 | Coverage floors (also runs rows 5 and the integration suites of every package under `-race`) | `make coverage` | every package ok | run for this review: the first run failed on a timing assertion of a Phase 4 test (`TestDumpWarningsAreBounded`: 1.096 s against its 1 s bound under `-race` and load) and showed `internal/secrets` at 81.5 % below its floor of 82; tests for the new AUD-20 branches were added (d2bb792), the two packages were measured again (secrets 83.0 %, nginx 98.2 %, the flaky test passing) and every floor is met (`covercheck` exit 0); floors below |
| 14 | E2E EN/TR incl. the AUD-01 journeys and axe, on the compose project `alice-e2e` | `make e2e-up && make e2e-hardening-check && make e2e`, then `make e2e-down` | all passed | recorded after b6e8226: 62 passed, 0 retried, 0 failed; after ab72da0: `phase1.spec.ts` 18 passed; run by `make ci` |
| 15 | The whole pipeline | `make ci` | every stage passes | run by the controller after this review was written; result recorded in the remediation's rulings |

Coverage (row 13, measured for this review; floors are the measured values rounded down, never lowered): new floors
`cmd/alice` 90 (90.5 %), `internal/setup` 82 (82.8 %), `internal/platform/tlscert` 73 (73.6 %),
`internal/platform/netaddr` 97 (97.8 %), `internal/platform/validate` 100 (100 %); raised `cmd/alice-helper` 90
(90.1 %), `internal/api` 93 (93.7 %), `internal/auth/ratelimit` 96 (96.5 %), `internal/certs` 97 (97.9 %),
`internal/jobs/deployjobs` 99 (99.1 %), `internal/providers` 100, `internal/providers/linuxssh` 92 (92.8 %),
`internal/secrets` 83 (83.0 %). Vitest thresholds stay at 93/90/93/95 (statements, branches, functions, lines;
measured 94.46/91.48/94.21/96 after ab72da0).

## Defects found during the remediation

Found by the reviewers (and two by implementers) while the fixes were built; each was fixed before the task was
accepted, unless the last column says otherwise.

| ID | Severity | Description | Closed by |
|---|---|---|---|
| R-D01 | Critical (in the fix) | A NUL byte in `/etc/passwd` made the helper and glibc read different lines; with the first-entry rule an account could be hidden while the list said complete (verified against real glibc). | 5857518: lines are cut at the NUL as glibc does, `accounts_nul_byte` makes the list incomplete |
| R-D02 | Important | The last-root-key guard did not see uid-0 accounts other than `root` in a fresh session (it depended on a listing in the same session). | 514e6e6: `authkeys-read` answers the uid; the guard decides from the read |
| R-D03 | Important | Directory accounts were detected only for `ldap` and `sss`; then systemd userdb and homed records, a symbolic-linked (authselect) `nsswitch.conf`, an unreadable or oversized one, the spellings `passwd sss` and `passwd : sss`, CR/VT/FF as blanks and a missing file were each read as local. | 5857518, e4df392, c49d1ad |
| R-D04 | Minor | Odd uid/gid spellings, NIS `+`/`-` lines and the cause of a truncation were not reported; a six-field passwd line (sshd accepts it) and a later duplicate name were mishandled by the helper before protocol 6. | f2b86dd, 5857518, 514e6e6 |
| R-D05 | Important | A lock the gate only estimated from its own clock was treated as confirmed: the runner held or cancelled queued work although a renewal could already be in force (a pending license, or an upload in another process). | ae993e8: `ErrLockDue`, pause and kick |
| R-D06 | Important | The 3-hour window had no margin over hourly ticks, and a failing hourly tick replaced the pending retry (backoff cap = interval): a 62-minute outage still left a 3-hour gap (verified by probe). | ae993e8, d64f402: retries 1, 2, 4, 8, then every 10 minutes, never postponed |
| R-D07 | Minor | Discarding a job was refused while the license was unverified or locked; `Shutdown` could wait without bound behind an evaluation; two processes could flip the stored state hourly during a clock-jump hold; inventory's denial rows said `locked` for unverified. | ae993e8, d64f402 |
| R-D08 | Important | An unreadable state file on a brand-new installation counted as evidence of removal, so the first start sealed an ended evaluation (regression of the AUD-18 fix). | 765b90d: the start fails and creates nothing |
| R-D09 | Minor | The application role could still update the seal column. | 765b90d: migration 00007 |
| R-D10 | Important | `GET /api/v1/tokens?user_id=<any id>` wrote an uncoalesced `not_owner` row per request on the request context (any signed-in user). | 1f8ce8f: refused in the API through the coalescer |
| R-D11 | Important | Token subjects were per token and tokens are unlimited, so the per-person bound did not hold. | 1f8ce8f: one subject for all of a person's tokens |
| R-D12 | Important | A 10-minute export used up the shutdown budget, so the denial flush wrote nothing; the summary writer was not joined before the flush. | a3f9d8d: `StopScans` before the drain, writer joined |
| R-D13 | Minor | Coalesced windows lost the attacker's addresses; the failure log lacked actor and route; busy refusals were not audited; the distinct-value sets allowed about 120 MB in the worst case. | 1f8ce8f, a3f9d8d, 6a95367 (64 per set) |
| R-D14 | Important | The failed-credential token was refunded on a backend error including `context.Canceled`, so aborting requests bought unbounded lookups (verified by probe). | b68dc10: errors keep the token |
| R-D15 | Important | Stale-cookie clearing deleted the new cookie when a request with the old cookie lost the race against step-up, MFA verification or a password change. | b68dc10: the rotated-away set (60 s); 9e76d52: the web ignores a refusal of a replaced session |
| R-D16 | Minor | A garbage session cookie next to a valid setup cookie skipped the bucket; `/healthz` shared the anonymous bucket; the recently-valid lifetime (5 minutes) was shorter than the idle timeout. | b68dc10 |
| R-D17 | Important | The inventory cursor bounds did not cover the UTC readings of offset GeneralizedTimes, so a certificate's own next-page cursor was refused. | 15b76d7 |
| R-D18 | Important | A certificate with NotAfter in year 10000 UTC (which a managed server can plant) could not be JSON-encoded: the list and detail answers were cut off after the 200 (found by the implementer). | b09b9d2: refused at ingestion; `writeJSON` encodes before the status |
| R-D19 | Important | An out-of-range chain certificate in a discovered file hid the valid leaf. | 11dbe1d: dropped like an unparsable block |
| R-D20 | Minor | A chunked oversized body with a NUL answered 400 instead of 413; malformed query pairs were dropped silently; an encode failure logged nothing; `api/openapi.yaml` stopped parsing for one commit. | 15b76d7, b09b9d2, 11dbe1d |
| R-D21 | Important | A token created (or recovery codes regenerated) while the revocation transaction was open survived the revocation. | 5cae1a6: session re-check under the user's row lock |
| R-D22 | Minor | Disabling a user wrote no per-token rows, and two count keys differed. | 5cae1a6: one form, `revoked_tokens_count` |
| R-D23 | Important | A setup session opened with the old code could survive a concurrent reset (found by the implementer); wrong codes then took a row lock; a failed directory sync deleted the key file. | 8ae95db, 8fad0d1, a40966c |
| R-D24 | Minor | The address rule missed IPv4-compatible, IPv4-translated and Teredo forms and 0.0.0.0/8 and 240.0.0.0/4; a refused TLS probe was invisible. | 7cf6218 |
| R-D25 | Minor | `pincheck` could be evaded by a continued line, a trailing comment, `alice:` elsewhere on the line, and workflow containers, services and `run:` steps; it ignored `docker pull` and lower-case Dockerfile names. | 4da6947, a3ab994 |
| R-D26 | Minor | `image-check` failed (instead of skipping) when the host's Go differed from the image's. | 41ce75e |
| R-D27 | Minor | A pending activity mark was lost when the tab was hidden; StrictMode and GET-only polling were not pinned. | 9e76d52 |
| R-D28 | Info | Process: two commits carried another agent's uncommitted hunks through the shared index (7dc8b6c took a troubleshooting text of AUD-13; 7cf6218 took OpenAPI text of AUD-12, taken out again by 683bc85 and committed by 4a02ac1). Nothing was lost; history was not rewritten. | — |
| R-D29 | Low (text) | The catalogue's action for `ALC-SSH-0012` (`locales/common`, shown in the UI) says "edit the server and enter its real address", but a server's address cannot be changed in Alice (`PATCH /targets/{id}` takes only the name and the discovery interval). `docs/troubleshooting.md` says the right thing (remove the server and add it again). | fixed: the locale text (EN and TR) now says to remove the server and add it again with its real address |

## Findings of the remediation

New or remaining risks the remediation accepts; each is also under "Known limitations".

| ID | Severity | Description | Decision |
|---|---|---|---|
| R-1 | Low | The activity marker is asserted by the client: whoever holds a session cookie can keep that session alive, and input through the browser's own pipeline (automation, remote desktop) counts. | Accepted [1]: the idle timeout protects an unattended screen, not against its own client |
| R-2 | Low | Counts of coalesced refusals live in memory per process: they are lost when the process dies, and N processes write up to N times the rows. | Accepted [4] |
| R-3 | Info | A strict CSV reader sees one extra one-cell row (the verification line). | Accepted [7] |
| R-4 | Low | The failed-credential bucket is shared by every client behind one address (NAT, a proxy without `ALICE_TRUSTED_PROXIES`, Docker's userland or rootless port forwarding): while one floods, others whose credential this process has not validated for 30 minutes wait, also nightly API tokens and, after a restart, everyone. | Accepted [11]; documented with `ALICE_TRUSTED_PROXIES` |
| R-5 | Low | The testcontainers Ryuk image and Playwright's browser download are not pinned; the npm lockfile is not scanned for secrets. | Accepted [9]; the lockfile scan needs a decision |
| R-6 | Low | A server name an Administrator added that later resolves to 127.0.0.1 is still connected to (SSH banner and key exchange, or a TLS ClientHello, to Alice's own host). | Accepted [8]: loopback allowed in v1 (R37 item 24) |
| R-7 | Low | The license gate's 3-hour bound counts awake time; a stalled monotonic clock, or a frozen clock with the process killed before each hourly evaluation, keeps changes possible (root on the host). | Accepted [2]: within Phase 2's P2-01 and "downtime not counted" |
| R-8 | Low | The holder of `master.key` and the database can carry a seal over from a scratch database, or remove every trace of the installation (eight places) and start a fresh evaluation. | Accepted [6]: P2-10, P2-01 |
| R-9 | Info | A small sign-in timing difference remains between existing and unknown names (one or two `UPDATE`s, legacy hashes, the row-lock wait). | Accepted [12] |

No High finding is open.

## Known limitations

- **Accounts not inventoried.** Accounts with uid 1–999 (other than `alice-svc`), `nobody`, a `nologin`/`false`
  shell or a home that does not exist are neither scanned nor reported, even where sshd could accept a key for them
  (for example through an absolute `AuthorizedKeysFile`) [3].
- **Permanently incomplete account lists.** A name longer than 32 bytes, non-ASCII, all digits or with other
  characters, an odd uid/gid spelling, a home with `..` or other characters, a NUL in `/etc/passwd`, a non-local
  passwd source (LDAP, SSSD, winbind, NIS, …), systemd userdb or homed records, or a missing or unsafe
  `nsswitch.conf` keep the server's list incomplete until fixed on the server; keys of deleted accounts are then
  not marked missing there. Debian's `useradd` creates all-digit names [3].
- **Custom userdb sockets.** A userdb service socket below `/run/systemd/userdb` (other than the stock ones) is not
  checked; the helper models only the drop-in directories.
- **glibc only.** The helper reads `/etc/passwd` like glibc's files module; musl distributions are not supported.
- **Key changes still scan every account.** `authkeys-read` and `authkeys-write` keep the full scan (needed for the
  first-account owner rule): a key change is two scans; only discovery is one [3].
- **Every managed server needs `alice-helper` 1.5.0** before this Alice works on it; an Alice updated first shows
  `ALC-SSH-0005` everywhere and deployments in recovery wait.
- **A person reading one page for 30 minutes without input is signed out** [1]; a non-GET request the web sends
  automatically would slide the session (none exists; only review guards it); watching a deployment for 30 minutes
  is covered by unit tests and reasoning, not by an e2e journey.
- **License gate, multi-process.** A process that started after a forward clock jump does not adopt the other
  process's stored hold; if every holder is gone for good and that process is never restarted, it writes no state,
  history, audit rows or emails while its own gate stays strict (abandoned foreign hold). The first evaluation after
  a start trusts the wall clock under the high-water mark (one early lock email possible). The time record is
  last-writer-wins across processes. A process lags an upload made in another process until its next hourly or
  kicked evaluation [2].
- **License gate, other.** With an unhealthy database the banner can show the grace period while the API refuses
  with `ALC-LIC-0001` (lock due) for up to 3 hours; after 3 hours the API says `ALC-LIC-0009` even for a license that
  really is locked; the bound is awake time (a suspended host does not count) [2].
- **An outage longer than about 2 h 48 min** pauses changes until the first successful evaluation after it [2].
- **The edge refusal of a license upload** writes the audit row but no license history row [10].
- **Refusal rows.** Inventory's own denial rows (`target.add.denied_license`, `deployment.denied`,
  `sshkey.remove.denied`) and auth's revoke `not_owner` are not coalesced (one row per refusal, bounded by the
  session rate limit); the scheduled daily check and `alice audit verify` are outside the one-scan slot; one reader
  can keep the slot busy (export slot fairness); verification time keeps growing with the log [4], [7].
- **What a browser shows for a busy (503) export download** was not observed (no way to make the server busy in the
  e2e stack).
- **Web states tested with Vitest only:** the route error page, the `unverified` banner, the locale fallback, the
  hidden-tab activity mark, the replaced-session rule and the busy export; axe ran on the audit details but not on
  the error page or the banner [16].
- **Shared addresses** (R-4): nightly tokens wait during a neighbour's flood; after a restart the recently-valid set
  is empty.
- **Address rule:** loopback allowed (R-6); an idle pooled connection opened before a DNS change keeps working [8].
- **Master key directory.** A failed sync of the parent of a freshly created keys directory is not retried by later
  starts; a file system that refuses `fsync` on a directory cannot hold the keys volume (the first start fails) [13].
- **Installation record.** A development database never started since before the seal reads as tampered (`make
  reset`); an honest re-install over an old state volume, or a restore of only some tables without the `license`
  row, starts with an ended evaluation (R-8 for what remains) [6].
- **Lockout scope** (AUD-25 (b)): the per-account count also blocks step-up and password changes, and
  `alice admin unlock` is undone by the attacker's next attempts [15].
- **Exotic certificates:** certificates dated outside years 1 to 9999 cannot be managed [10].
- **Supply chain:** Ryuk and the browser download unpinned; the npm lockfile not secret-scanned (gitleaks' default
  allowlist and trivy skip it; the options are a full rule copy or a lockfile shape test); `osv-scanner` deferred to
  Phase 8; `pincheck` checks only the forms it knows (an image only in a variable other than the two tool variables is
  reported, never passed; commands that pull without a `docker://` reference, such as a remote `docker buildx build`
  context, are not seen); the `# syntax=` digest was not exercised by a BuildKit build here; Dependabot's reading of
  `test/images/sshd/*.Dockerfile` is unverified [9].
- **CI has never run on GitHub:** the workflow (including `ssh-matrix` and the macOS `licensectl` job) has no remote
  run yet; actionlint ran locally only.
- **`make image-check` needs the host's Go equal to the image's** for the two helper-checksum checks (otherwise they
  are skipped with a message).
- **A flaky timing assertion:** `TestDumpWarningsAreBounded` (Phase 4, `internal/providers/nginx`) asserts under 1 s
  for 100,000 warnings and failed once under `-race` and machine load (1.096 s) during this review.
- The Phase 1–4 findings and limitations still open stay as recorded in their review notes, except what this
  remediation changed: the upgrade seal of Phase 2 (P2-10's last bypass) is gone, a leftover damaged `hwm.dat` is now
  evidence, and a stored newer-format license is no longer tampering (`phase-2.md` carries notes).

## Owner-pending

- **AUD-08:** create a remote, push `master` and the branches, watch the first run of `.github/workflows/ci.yml`
  (including `ssh-matrix` and the macOS `licensectl` job, which have never run; re-run actionlint there), turn
  Dependabot on and set branch protection with the CI jobs as required checks.
- **Production license key:** `internal/license/keys/production.json` is empty; `make release-keycheck` fails by
  design (R36).
- **Owner walkthroughs** of Phases 1–4 (their result tables are empty), the Turkish tone review of the new texts,
  and the crypto sign-off.
- **A full `make ci` on a clean, idle machine**, including `image-check` and `image-scan` (the audit saw 54/56
  Playwright passes under load and no image scan).
- **Real-systemd Nginx job:** Phase 8 (R38 item 16; spec §26.6 carries the pointer).
- **Decisions to take:** the npm lockfile secret scan (R-5); whether loopback targets should be refusable (R-6); the
  `ALC-SSH-0012` locale action text (R-D29).

| Item | Result | Date and person |
|---|---|---|
| Remote, first CI run, Dependabot, branch protection | | |
| Production license key | | |
| Owner walkthroughs of Phases 1–4 | | |
| Turkish tone review | | |
| Crypto sign-off | | |
| Full `make ci` on a clean machine | | |

## Owner verification

You need a development stack (`make up`), signed in as an administrator, a test server prepared as in
`docs/nginx-host-preparation.md` with the `alice-helper` 1.5.0 of this checkout (`make helper`), and a second person's
account with an API token.

1. **Idle timeout.** Open **Servers** and leave the tab alone (no click, key, wheel or touch) for 31 minutes.
   Expected: the sign-in page with "Your session ended. Please sign in again."; scrolling once a minute keeps you
   signed in.
2. **Accounts.** On the test server, as root: `useradd -m -s /bin/bash john.doe`, add a key to
   `/home/john.doe/.ssh/authorized_keys`, and add a line `bad,name:x:1600:1600::/home/bad:/bin/bash` to
   `/etc/passwd`. Choose **Scan for SSH keys**.
   Expected: the key of `john.doe` is listed; the server shows "Alice did not list the SSH keys of the account with
   user ID 1600: …". Remove the line again and scan: the warning is gone.
3. **Old helper.** On a second server keep an older helper. Expected: "The alice-helper on this server is
   outdated." until you run the new setup commands with 1.5.0.
4. **API tokens.** As administrator choose **Sign out everywhere** for the second person. Expected: the dialog says
   their API tokens stop working; a request with their token answers 401; the audit log shows "API token revoked"
   with the reason.
5. **Audit log.** As an auditor, call a refused operation (for example `POST /api/v1/targets`) 20 times with an
   API token, wait 11 minutes, open **Audit log**. Expected: one refusal entry and one entry "… more like …" with the
   count; **Export CSV** opens with the line `# alice audit export: intact=true …`.

| Step | Result (pass, or what differed) | Date and tester |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
