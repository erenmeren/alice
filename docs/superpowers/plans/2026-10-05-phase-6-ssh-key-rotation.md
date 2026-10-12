# Phase 6: SSH Key Lifecycle and Rotation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An Administrator or Operator generates an SSH key in Alice (Ed25519 by default; RSA 3072/4096 or ECDSA P-256 selectable), whose private key Alice stores only sealed under the master key, and deploys its public key to a user on a managed server; Alice adds the line, then proves the key works by signing in to the server as that user with the new key (only that key offered, the pinned host key required) and reports "verified", "added but not testable", or undoes its own addition when the server refuses the key. An Administrator downloads a private key only with a fresh authenticator code and a written reason, the download is recorded in the audit log before the file is sent, and the file can be protected with a passphrase. An Administrator creates a rotation policy for a key Alice generated (Off by default: every N days, keep the old key for an overlap of 7 days by default), previews exactly which lines will change on which servers (and the preview is emailed), and the rotation runner — per server, through the existing job queue — adds a new key next to the old one, verifies a login with it, keeps both through the overlap, signs in with the new key again and only then removes the old key. Every failure at every step leaves the old key in place; a rotation interrupted by a crash resumes from its last recorded step; Alice's own connection key and keys Alice did not generate are never touched; in license lock nothing new starts, an overlap that ends waits for the license and an Administrator, and nothing is removed.

**Architecture:** Two pure packages carry the logic that must be exactly right: `internal/sshkeys/keymat` (key generation, PKCS #8 sealing input, the OpenSSH private-key file with an optional bcrypt passphrase, `authorized_keys` lines and comments, the test-login signer) and `internal/sshkeys/plan` (the rotation planner: which locations change, which are skipped and why, which can be verified, the plan digest, and every timer). A new module `internal/sshkeys` owns generated keys, their private keys (`managed_private_keys`, owner `ssh_key`), deploy requests, the audited download, rotation policies, rotation runs and their per-location state (`rotations`, `rotation_locations`, `rotation_steps`), and the rotation controller `Advance` — a database-only state machine called by the sweep, by every per-location job when it ends and by the Administrator's actions. Remote work happens only in queue jobs of `internal/jobs/sshkeyjobs`: `sshkey.add` (a manual deploy) and `rotation.location` (add + verify, re-verify + remove, or undo, for one location; bound to its server, so the queue's per-server lock serialises it with discovery and removals). The provider framework gains one read-only capability, `VerifyKeyLogin` (a fresh SSH connection as the OS user with only the new key; nothing is executed), and the discovery result gains each user's candidate key files. Nothing changes in `alice-helper`: adds and removals use the protocol 6 `authkeys-*` subcommands as they are, and the undo of an addition is the removal of the new key by its fingerprint (unique to the run). Migration `00010` adds the tables, the Ed25519 private-key form, download counters and destruction, and database checks that refuse removing an old key without a recorded verification. The API adds generate, deploy, download, key files, policy and run routes; the SPA adds the generate and deploy dialogs, the download dialog and the rotation section and run page. The e2e build gets one test-only endpoint that sets a policy's overlap in minutes, so Playwright can watch a one-minute overlap.

**Tech Stack:** Go 1.27.1; no new Go module (`golang.org/x/crypto` v0.57.0 already provides `ssh.MarshalPrivateKey`, `ssh.MarshalPrivateKeyWithPassphrase`, `ssh.NewSignerFromKey`, `ssh.FingerprintSHA256`); pgx v5, goose v3, testify, testcontainers-go v0.44; React 18 + TypeScript 6 + Vite 8, Mantine 8, React Router 7, TanStack Query 5, i18next, Vitest 5 + Testing Library + msw 2, Playwright 1.63 + axe-core. No new web dependency.

**Spec:** `docs/superpowers/specs/alice-v1/` — `00-decisions.md` ("SSH key lifecycle", "Linux SSH keys", "Secrets protection", Security, R9, R18, R23, R24, R29, R33, R36 item 6, R37 (all of it: the platform key, helper protocol, job queue, removal rules), R38 items 8–9 and 20–22, R39 (all of it), R40 rows 11 and 29), `01-product.md` S6, S7, S8 AC3, S9 AC1, §3.1 (SSH keys row), `02-architecture.md` §5.3–§5.4 (modules and import rules), §6.1–§6.6 (provider interface, the connector refuses its own key), §7.2 (`managed_private_keys`), §7.3 (`ssh_keys`, `ssh_key_locations`, `rotation_policies`), §7.4 (`rotations`, `rotation_steps`), §8 (job types `sshkey.*`, `rotation.*`, retries, concurrency, lock gating §8.6, in-flight work §8.7, crash recovery §8.8), §9 (conventions, step-up, errors, endpoint groups `ssh-keys` and `rotation`), `03-integrations.md` §13 (all of it), `04-security.md` A2, J-2, J-4, SEC-009, SEC-022, SEC-040..SEC-047, SEC-050..SEC-052, SEC-062, SEC-070, SEC-081, §15.4 (role table), §17.2 (Phase 6 gate), `05-operations.md` §19.3 (lock and recovery rows), §21 (admin guide contents), `06-quality.md` §22.4, §23.8 (L-83..L-88), §24.2 (F-36..F-39), §24.4 (F-67), §25.1, §25.2 (S-01..S-05, S-09, S-11), §25.4 (A-09, A-12), §26.1, §26.8. `00-decisions.md` wins on conflict; this plan proposes **R41** (written in Task 19) for the conflicts listed under "Spec conflicts resolved by this plan". Carry sources: `docs/superpowers/rulings/phase-{1,2,3,4,5}.md` and `audit-remediation.md` ("Parked / carried …" and "Carried to later phases"), `docs/security/reviews/phase-{3,4,5}.md` and `audit-remediation.md` ("Known limitations"). Format and style reference: `docs/superpowers/plans/2026-10-05-phase-5-azure-key-vault.md`; helper-adjacent planning: `2026-10-01-phase-3-ssh-targets.md`, `2026-10-03-phase-4-nginx-certificates.md`.

**Plan verification:** written against branch `phase-6` at `39838e7` (= `master`: Phases 0–5 and the audit remediation merged). Every existing path, symbol, route, Make target and command a task uses was checked with `grep`/`sed` in that tree, among them: `providers.{Session,UnsupportedSession,CredentialSource,Env,TargetRef,AuthKeyChange,AuthKeyResult,DiscoveryResult,DiscoveredSSHKey,SSHDSummary,Warning,StepLogger,StepStatus,Error,NewError,ErrUnsupported,Capability,CapAuthorizedKeys,knownCapabilities,NewCapabilitySet}`, `providertest.{sessionOps,CheckSession}`, `fake.{Config,Provider,session,Call}` (no `UnsupportedSession` embedding), `linuxssh.{Provider,Options,New,session (fields conn, cfg, caps, version, release),Pool (field dialer),Dialer.Dial,Config,ServiceUser,precheck,begin,addOnce,writeAndVerify,refusedRequest,step}` (Dial maps a refused key to `ssh.auth_failed` with param `reason` `key_rejected`, and a server that let the client in without its key, or offered no public-key method, to `ssh.auth_failed` with `reason` `publickey_not_offered`), `linuxsshtest.{Server (checkKey, Authorize, AcceptNoAuth, DisablePublicKeyAuth),Emulator (SetFile, File, AddUser, BeforeWrite, FailWrite, Handler)}`, `helperproto.{Protocol (6),Version ("1.5.0"),ValidAccount,ValidPath,AuthKeysListResponse}`, `secrets.{Plaintext,NewPlaintext,Keyring.Seal,Keyring.Open,Location,Envelope}`, `certs.KeyInfo`, `inventory.{Service,Config,Actor,Target (Username, Status, KeysManagedElsewhere, Facts),Facts,KeyLocation,SSHKey,getTarget,checkClaim,Claim,WithClaim,ClaimFrom,ErrClaimLost,protectedFingerprints,ProtectedFingerprints,loadPlatformKey,PlatformKey,MarkKeyRemoved,RequestKeyRemoval,managedElsewhereFor,sshdUnreadFor,validateReason (10–500 runes, no PEM, no control/format/bidi),keyLocation,storeKey,loadKey,upsertLocation,clean,JobRequest,Enqueuer,Notifier,LicenseGate,detachedTimeout,Err*,Status*}`, `jobs.{Register,Type,Types,Job,HandlerFunc,StepRecorder,Retry,Fail,Attention,FromProvider,MaxAttemptsFor,AlertsWhenExhausted,Task,Scheduler,NewScheduler,RunNow,Runner.Handle,Runner.Handles,Runner.RunOnce,Runner.Recover,Runner.Reap,Kind*,Status*}`, `targetjobs.handlers.{open,recordFailure,close,removeKey,reasonOf}`, `deployjobs` test harness (`killer`, `newKiller`, `killer.at`, `env.drain`, `env.restart`), `audit.{Event,Actor,SystemActor,Success,Failure,Denied,Log.Append,sensitiveSegments,checkDetails}`, `license.{Class,ClassAlways,ClassReadOnly,ClassChange,ErrLocked,Service.Allow}`, `rbac.{Permission,Policy,policies,InventoryOperate,Admin,Operator,Auditor,ScopeOperate,ScopeRead,Decide}`, `auth.{Principal (UserID, SessionHash),StepUpWindow}`, `api.{route,limitClass,limitMFA,server.apiRoutes,sshKeyRoutes,allowRate,ErrorCode,errors.go codes ALC-KEY-0001..0005 and ALC-AKV-0001..0041,secretText,unescapeJSONString,onSecretBytes,decodeExact,pathUUID,etag,ifMatch,actor,writeJSON,fail}`, `api/openapi.yaml` (`removeKeyLocation`, `Accepted`, `Error`), `notify.AdminNotifier`, `migrations/00005` (ssh tables, `ssh_key_locations_protect_alice_key`), `00006` (`managed_private_keys` and its default-named constraints `managed_private_keys_owner_type_check`, `managed_private_keys_algorithm_check`, `managed_private_keys_check`), `cmd/alice/{wiring.go:periodicTypes,checkWiring,services.go:buildScheduler,buildRunner,testapi_e2e.go:resetSQL,testHandler,sweepEvery,kvScheduleEvery}`, `test/images/e2e-target/Dockerfile` (user `deploy`, uid 1001, bash), the web `SSHKeysPage`, `SSHKeyDetailPage`, `RemoveKeyDialog`, `StepUpProvider` (`useStepUp().run`), `api/client.ts` (`apiFetch`, `isApiError`), `components/ImportHistory.tsx`, `components/AddKeyVaultDialog.tsx`, the e2e helpers (`targetExec`, `drainJobs`, `runScheduled`, `advanceClock`, `freshCode`, `apiAs`, `expectAccessible`, `expectWide`, `COPY`), and the Make targets `test`, `test-integration`, `test-ssh`, `lint`, `vuln`, `build`, `release-symcheck`, `image-check`, `e2e-up`, `e2e`, `e2e-down`, `authz-doc`, `i18n-check`, `web-test`, `web-coverage`, `coverage`, `fuzz-ssh`, `secrets-scan`, `fs-scan`, `ci`. Nothing in this plan has been compiled: before Task 1 the controller runs the pre-flight scan earlier phases used (apply each task's code in a scratch worktree and compile it); every task's red/green steps are the real check. Where a sketch says "as `<name>` does", the implementer reads the code named before writing.

## Global Constraints

- Go module path is `alice`; toolchain `go 1.27.1`. Every shell step assumes `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"` and the repository root as working directory.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `tr.json` files.
- **Commits:** Conventional Commits, made with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "<message>" -m "Co-Authored-By: <the model that wrote the commit> <noreply@anthropic.com>" -- <paths>` (`-m` before `--`: after it, `-m` is read as a path). Several agents share one working tree and one git index: stage new files with `git add -- <paths>` and commit **only** your paths; never `git add -A`, `git add .`, `git commit -a`, a bare `git commit`, `git stash`, `git reset` of paths you did not write, or `git rm --cached -r`. Never squash, rebase or amend: `.gitleaksignore` is pinned to commit hashes, so the branch merges into `master` fast-forward only.
- **Never read, edit, move, add or commit** `docs/security/reviews/independent-audit-2026-10-04.md`, `docs/security/reviews/independent-audit-2026-10-04-poc/` or `.claude/`.
- **Docker safety:** the owner's live compose project `alice` (image `alice:dev`, volumes `alice_*`) and the owner's other local containers are never touched: no `make up`, `make down`, `make reset`, `make logs`, `make setup-token`, `make unlock`, `make hardening-check`, no `docker compose` without `-p alice-e2e`, no `docker system/volume/image prune`, no `docker rm`/`stop` of a container you did not create. Allowed: testcontainers (integration tests), `docker run --rm` throwaway containers, `docker create`/`docker cp`/`docker rm` of a container created from `alice:ci` in the same step, and the e2e project `alice-e2e` (`make e2e-up`, `make e2e`, `make e2e-down`, port `127.0.0.1:9443`; compose builds its Alice image as `alice:e2e` with the tags `e2e testlicense`, while `alice:ci` is the release image `make image` builds). **Never run Docker test containers (integration tests, `make coverage`, `make test-ssh`) while Playwright runs**: Chromium aborts requests whenever a host network interface changes. Tasks marked "Docker alone" run with no other agent using Docker. The final `make ci` runs with no other Docker user at all. Every step that runs Docker says so.
- **Build machine networking:** containers on Docker's default bridge cannot reach the LAN DNS on this machine. An image build that needs the network is primed with `docker build --network host` (same Dockerfile, same tag); trivy runs as `make ci TRIVY_IMAGE="--network host <the pinned trivy image from the Makefile>"`.
- **Helper rule (R21, R37, R38):** this plan changes **no** `alice-helper` code and no helper protocol: `helperproto.Protocol` stays `6`, `Version` stays `1.5.0`, `bin/alice-helper.sha256` does not change. Should an implementer find a helper change unavoidable, they stop and report: a helper change needs the root-only suites (`sudo -E go test ./cmd/alice-helper/...` as in the Phase 4 plan), `make test-ssh`, new checksums, a protocol and version bump with Alice refusing older helpers (`ssh.helper_outdated`), and a plan amendment. Build inputs are pinned by version or `sha256` digest; `go run ./tools/pincheck` refuses unpinned ones; this plan adds no build input.
- **Secrets in the repository and in artefacts:** no private key, passphrase or token is committed or written to a test artefact. SSH keys in tests are generated at run time (`keymat.Generate`, `ed25519.GenerateKey`); strings that look like PEM private-key markers are built at run time (`"-----BEGIN " + "OPENSSH PRIVATE KEY-----"`), as Phases 3–5 did. Playwright tests that download a private key run with `trace: 'off'` and `video: 'off'` and delete the downloaded file in a `finally` block. If `make secrets-scan` still flags a file, add the finding to `.gitleaksignore` with the new commit hash in the same task.
- **Secret rule (security-critical, SEC-040..SEC-047, SEC-050..SEC-052, S-01..S-05, S-11):** a generated private key exists in clear only (a) inside `keymat.Generate` until it is sealed, (b) inside a test-login signer for one SSH handshake, (c) inside the download handler while the response is built; each holder is a `secrets.Plaintext` or a byte slice its owner zeroes on every path. It is stored only as an envelope in `managed_private_keys` (AAD `managed_private_keys/<id>/ciphertext`, the Phase 4 form, PKCS #8 DER for every key type). It never appears in a log (any level), an API answer other than the download, an error, an audit row, a job payload or result, a rotation row, a step's params, an email, a trace or a test artefact. A download passphrase is a `secretText` the handler zeroes. Go strings, `big.Int` limbs and `pem.EncodeToMemory`'s growth copies cannot be cleared (known limitation P4-04, extended).
- **Old-key rule (security-critical, §13.6 item 8, AC4, J-4, the §26.8 property):** Alice removes an old key from a file only when (1) the rotation reached `removing_old` with `removal_allowed`, (2) every location of the old key in that file belongs to the rotation and was verified, (3) a login with the new key as that location's user succeeded no more than 15 minutes before the removal is sent (`rotation_locations.reverified_at`), (4) the license gate allows changes and the rotation is not paused, and (5) the fingerprint is not Alice's own key. Each condition is enforced in the store (`BeginRemove`), and (1), (3) and (5) again in the database. The undo of a rotation removes only the **new** key (its fingerprint was generated by that run). No code path removes an old key for any other reason.
- No SQL string building (SEC-060). SQL time comes from the injected clock as a bind parameter. `alice_app` gets explicit grants for every new table and column; the grant guard (`migrations/roles_integration_test.go`) lists every non-default and column-level grant.
- Code blocks are gofmt-clean except for column alignment of consecutive one-line declarations and struct fields: run `gofmt -w` (or `make lint`) on every changed Go file before committing.
- Tests: Go stdlib `testing` plus testify `require`/`assert` only; small hand fakes, no mock frameworks. Integration tests carry `//go:build integration`, call `pgtest.Main` from `TestMain` and get a fresh database per test from `pgtest.New(t)` (pools `Owner` and `App`; the application always uses `App`). A red step in a brand-new package may fail with "no non-test Go files"; that is the expected failure.
- Build tags: `integration`, `e2e`, `testlicense`, `releasecheck`, `azure`. Release images are built with no tag; the e2e image with `e2e testlicense`.
- Lint is golangci-lint v2 (`make lint`): gosec, errorlint, forbidigo, bodyclose, misspell, noctx, gofmt, goimports (`local-prefixes: alice`). Forbidden: `fmt.Print*`, `strings.ToUpper`/`ToLower`/`Title` (use ASCII folding), `time.Now` outside `internal/platform/clock` and tests (use the injected clock), `ssh.InsecureIgnoreHostKey`, `InsecureSkipVerify` (except `helperproto.ProbeTLSConfig`). No `//nolint` without a reason.
- **Module import rules** (`internal/archtest`): Task 1 adds the rule `"alice/internal/sshkeys/...": {platform, "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/rbac/...", "alice/internal/providers", "alice/internal/inventory/..."}` and the deny entry `"alice/internal/sshkeys/keymat": {"alice/internal/platform/db/..."}` and `"alice/internal/sshkeys/plan": {"alice/internal/platform/db/..."}` (pure packages); adds `"alice/internal/sshkeys/..."` to the allowed lists of `alice/internal/jobs/...` and `alice/internal/api/...`. `sshkeys` never imports `jobs`, `notify` or `api`; `keymat` imports only the standard library, `golang.org/x/crypto/ssh`, `alice/internal/secrets` and `alice/internal/platform/...`; `plan` only the standard library, `github.com/google/uuid`, `keymat` and `alice/internal/platform/...` (exact rule keys for the two, which win over the module's subtree rule). `TestAllowed` gets the new positive and negative cases in Task 1 (before any `sshkeys` package exists, so `TestImportRules` never sees a package without a rule).
- API JSON conventions from Phase 1 (snake_case, UTC RFC 3339, error body `code`, `reason`, `message_key`, `message`, `request_id`, `retryable`, `params`, `details`; lists `{items, next_cursor}`); every new code `ALC-<AREA>-<NNNN>` has `errors.<reason>.title|cause|action` in `locales/common/{en,tr}.json`, a section in `docs/troubleshooting.md` and an entry wherever its neighbours are listed (enforced by `internal/api/errors_test.go` and `errors_catalogue_test.go`). Every new route is in the route table with a permission and (for non-GET methods) a license class, in `api/openapi.yaml` with the same `x-permission`, in `docs/authz-matrix.md` (`make authz-doc`) and in the authz tests. Long operations answer `202` with job ids. A `PATCH`/`DELETE` of a policy needs a strong `If-Match` (`etag`/`ifMatch` of `targets_handlers.go`).
- Audit detail keys pass the denylist of `internal/audit/audit.go` (`key`, `private`, `passphrase`, `secret`, `token`, … segments are refused unless the key ends in `id`, `prefix` or `count`): this plan uses `ssh_key_id`, `old_ssh_key_id`, `new_ssh_key_id`, `fingerprint`, `old_fingerprint`, `new_fingerprint`, `algorithm`, `bits`, `label`, `target_id`, `os_user`, `file_path`, `job_id`, `policy_id`, `rotation_id`, `location_id`, `plan_digest`, `change_count`, `skip_count`, `location_count`, `download_count`, `protected`, `reason`, `from`, `to`, `trigger`, `verified`, `emailed`, `planned_for`; never `key_*`, `private_*` or `passphrase*`.
- i18n: every user-visible string is a key in English and Turkish (`make i18n-check`); placeholders `{{name}}` without spaces; no sentence assembly; no suffix attached to a placeholder (rephrase as "Label: {{value}}"); formal-polite Turkish ("siz"); plural forms `_one`/`_other`. Terminology (fixed for EN and TR, used by every task): **SSH key** / "SSH anahtarı", **Generate key** / "Anahtar oluştur", **Generated by Alice** / "Alice tarafından oluşturuldu", **Deploy** / "Dağıt", **private key** / "özel anahtar", **Download private key** / "Özel anahtarı indir", **passphrase** / "parola", **reason** / "gerekçe", **rotation** / "yenileme", **rotation policy** / "yenileme kuralı", **overlap** / "geçiş süresi", **Preview next run** / "Sonraki çalıştırmayı önizle", **Run now** / "Şimdi çalıştır", **Continue** / "Devam et", **Finish now** / "Şimdi bitir", **Stop and undo** / "Durdur ve geri al", **verified** / "doğrulandı". Fingerprints, public keys, paths, user names and `authorized_keys` lines are rendered with `<Code>`/monospace, never translated or case-transformed, always as text (A-11). The "UI copy" tables of the contract are exact and are what the Vitest and Playwright tests match.
- Accessibility: new screens and dialogs have no serious or critical axe violation at 640, 1280 and 1920 px (`expectAccessible`) and at 375 px for the key page and the rotation page (tables scroll inside their own named group, as Phase 5's), in English and Turkish, keyboard usable, no horizontal page scroll.
- Frontend: no `dangerouslySetInnerHTML`, no `toUpperCase`/`toLowerCase`; a downloaded private key is a `Blob` that is handed to one temporary object URL, revoked on the next task, and never kept in React state, a query cache, `localStorage` or a log.
- **Coverage floors in `coverage-floors.json` are never lowered.** New packages get floors in Task 19: `internal/sshkeys/plan` 100 (pure), `internal/sshkeys/keymat` (pure, but with standard-library failure branches no input reaches), `internal/sshkeys` and `internal/jobs/sshkeyjobs` at their measured values rounded down. Thin floors: `internal/inventory` (89.1 measured, floor 89), `internal/certs` (98.1, floor 98; this plan does not touch `certs`), `internal/jobs` (89.2, floor 89): every line a task adds there carries its tests. `internal/providers` stays at 100, `internal/rbac` at 98, `internal/api` at 94, `internal/providers/linuxssh` at 92, `cmd/alice` at 90.
- **Parallel work:** at most three agents at once, grouped by package ownership so that two agents never edit one package (or one locale file) at the same time; the schedule is in "Task index". The locale files `locales/common/{en,tr}.json` belong to Task 13 (errors, emails), `web/src/locales/{en,tr}.json` to Tasks 16–17 in sequence; a task that needs a key in a file it does not own lists it in its report and the owner adds it.

## Review Focus

1. **The old key under every failure** — a server that refuses the add, drops the connection after the write was sent, refuses the new key's login, accepts a login without asking for any key (`none` method), has `PermitRootLogin no` for a root location, shares one absolute `AuthorizedKeysFile` among several users of whom one is skipped, loses its network between verification and removal (owner step 6), whose new key line is deleted by someone during the overlap, whose host key changes mid-rotation, or is deleted from Alice mid-rotation; Alice killed at every recorded point; the license locking at every point. Expected: the old key stays in every file whose every location was not freshly verified with the new key; a refused or unprovable login is never "verified"; a shared file loses the old key only when all its users verified; the run ends `aborted` (new key removed where this run added it) or `needs_attention` (with the servers named), never a silent partial state. Tests: Task 4 (`TestVerifyKeyLoginOutcomes`, `TestVerifyKeyLoginWithoutKeyIsUnprovable`), Task 2 (`TestSharedFileSkippedTogether`, `TestRootLoginDisabledIsNotVerifiable`), Task 11 (`TestNewKeyDeletedDuringOverlapKeepsOld`, `TestHostKeyChangeMidRotationRemovesNothing`, `TestTargetDeletedMidRotation`, `TestOwnerStep6NetworkLoss`), Task 12 (`TestOldKeyRemainsUnderAnyInjectedFailure`, `TestF67KillBetweenAddAndVerify`, `TestKillAtEveryRecordedPoint`).
2. **Private keys that must never leak** — the generated key, a key with a passphrase, a reason that contains a PEM block, a failed download (destroyed key, wrong role, no step-up, an API token), a panic during encoding, the Playwright download. Expected: the private key appears only in the one download response, after its audit row committed; nowhere in DEBUG logs, other responses, job payloads and results, audit details, rotation rows and steps, emails or test artefacts; a reason with `-----BEGIN` is refused; the database holds only AES-GCM envelopes; a destroyed key holds no ciphertext. Tests: Task 1 (`TestMaterialNeverPrints`, `TestOpenSSHZeroesItsCopies`), Task 7 (`TestDownloadAuditsBeforeTheFile`, `TestStoredKeyIsAnEnvelope`, `TestDestroyRetiredKeys`), Task 14 (`TestS09PrivateKeyDownload`, `TestSecretLeakSuiteWithGeneratedKeys`).
3. **License lock at every rotation state** — lock entering at the moment a preview is due, during an add, during a verification that fails, in the overlap, when the overlap ends, during removal; renewal after 20 days; an unverified license (no evaluation for 3 hours). Expected: L-83..L-88 exactly; no remote command is started by a scheduled task in lock (the fake server's command log is empty); after renewal nothing changes servers until an Administrator chooses **Continue**, which records a fresh notice, and every removal is preceded by a fresh login. Tests: Task 12 (`TestL83..TestL88`), Task 14 (`TestRotationInLockRunsNoCommand`).
4. **Dry-run equals the run** — servers that change state between the preview and the start (a server becomes unreachable, a location is found missing, a key line is added by hand, the policy's new key type changes), two Administrators pressing **Run now** with two different previews, a scheduled run whose preview was sent while the plan later changed. Expected: a run starts only with the plan whose digest was previewed; a manual start with an outdated digest answers 409 `ALC-ROT-0003` and changes nothing; a scheduled start that finds a different plan is cancelled and previewed again with a new notice. Tests: Task 2 (`TestDigestIgnoresOrderAndDisplayFields`, `TestDigestChangesWithEveryDecision`), Task 8 (`TestRunNowNeedsThePreviewedDigest`), Task 9 (`TestScheduledStartReplansAndRenotifies`), Task 14 (`TestDryRunEqualsActualPlan`).
5. **Who may do what** — Operator and Auditor sessions, `read` and `operate` API tokens of an Administrator and of an Operator, an Administrator without a fresh step-up, against every policy and run route, the download, generation and deploy; Alice's own key offered to a policy, a deploy, a download and a rotation (by its row, by fingerprint under another comment). Expected: the matrix of the contract; F-36 refusals are 409 `ALC-KEY-0001` (removal, rotation) or `ALC-KEY-0006` (download, deploy, policy of a key Alice does not hold), audited `*.denied`, with no remote command. Tests: Task 13 (`TestRotationRoutesAuthz`, `TestDownloadNeedsSessionAdminStepUp`), Task 14 (`TestF36OwnKeyNeverRotatedOrDownloaded`).

---
## Spec conflicts resolved by this plan (proposed R41, written in Task 19)

Each row: the conflict, the decision, why, and the cost if the decision is wrong. Task 19 writes them, corrected to the built code, as **R41** in `00-decisions.md`.

| # | Conflict | Decision | Why | Cost if wrong |
|---|---|---|---|---|
| 1 | §5.4 lists modules; `ssh_keys` belongs to `inventory` (§7.3); generation, policies and rotations have no module | New module `internal/sshkeys` (with pure subpackages `keymat` and `plan`) owns generated keys, their private keys, deploy requests, the download, policies, rotations and the controller; `inventory` keeps discovery, reconciliation and removal and exports the few transactional reads and writes `sshkeys` needs (Task 6) | `inventory` is 33,000 lines with a thin floor (89.1 vs 89); the rotation logic needs its own tests, floor and owner | Two modules write `ssh_keys`/`ssh_key_locations`; every such write goes through an exported inventory function or a column only `sshkeys` uses (`private_key_id`, `rotated_from`, `retired_at`) |
| 2 | §7.2 `managed_private_keys` (owner `certificate`, `csr`) vs R11 "managed_private_keys … generated SSH keys"; R37 keeps the platform key in `credentials` | Generated SSH keys are rows of `managed_private_keys` with owner `ssh_key`, payload PKCS #8 DER for every type (Ed25519 included: algorithm `ed25519`, bits 256), AAD as Phase 4; the platform key stays in `credentials` | One sealed-key table and one unseal function; PKCS #8 is what `x509.MarshalPKCS8PrivateKey` writes for all three types | none known |
| 3 | §26.8 "Ed25519 default, RSA 3072/4096, ECDSA" vs §13.5 "ECDSA P-256" | Types `ed25519` (default), `rsa-3072`, `rsa-4096`, `ecdsa-p256`; no P-384 | §13.5 is specific; SEC-046 | A customer wanting P-384 SSH keys cannot generate them |
| 4 | SEC-045 "optional passphrase-protected PKCS#8 export" vs §13.5 "OpenSSH private key (bcrypt-KDF format)" | The download is an OpenSSH private-key file (`-----BEGIN OPENSSH PRIVATE KEY-----`), unencrypted or, with a passphrase of 12–1024 bytes, `aes256-ctr` with bcrypt-pbkdf (x/crypto `MarshalPrivateKeyWithPassphrase`); no PKCS #8 export | §13.5 is the SSH-specific rule; every OpenSSH client reads the format; Go has no PKCS #8 encryption | A tool that reads only PKCS #8 needs `ssh-keygen -p -m PKCS8` |
| 5 | §9.6 lists `/{id}/private-key/download` (a GET); S-09; GET routes never mutate (A-06) | `POST /api/v1/ssh-keys/{id}/actions/download-private-key` with `reason` and optional `passphrase` in the body; permission `sshkeys.download` (Administrator, browser session, step-up; no API token: R23, A-09); 5 per minute per user (SEC-022); license class `always` (it changes nothing outside Alice); the audit row and the counter commit before the first byte of the file | The request carries a reason and a secret, and it counts; a lock must not hold the customer's own access keys hostage | A download during a lock is possible (audited) |
| 6 | §9.6 `/certificates/{id}/private-key/download`; Phase 4's review says "no download (Phase 6)" | **Re-deferred** (see Carries): Phase 6 builds the SSH key download only | §26.8 scopes Phase 6 to SSH keys; a TLS key download needs its own format decision (PKCS #8 encryption) | A TLS key Alice holds still cannot be taken out |
| 7 | §15.4 role table has no row for generating an SSH key | Generating a key needs `inventory.operate` (Administrator, Operator, `operate` tokens), license class `change` | S7 gives Operators key additions; only the download is Administrator-only | An Operator can create keys whose private half only Administrators can download (intended) |
| 8 | §13.4 "Add" takes any key line with options `from=`, `restrict`, `command=` | Deploy accepts only keys Alice generated (`sshkey.not_managed` otherwise) with options `from="<list>"` (IPv4/IPv6 addresses and CIDR prefixes, at most 16) and `restrict`; `command=` is not offered; comment `alice:<label-slug>:<yyyy-mm-dd>`; never into the connection account's files (`sshkey.connection_account`) | Alice can verify only keys whose private half it holds; the setup script owns `alice-svc`'s file and rewrites it (R37 item 2); `command=` quoting is a footgun | Distributing an outside public key needs another tool |
| 9 | §13.4 "Test login … executing `true`" | The test login is an SSH authentication only (a fresh connection, the pinned host key required, only the new key offered, 10 s budget), no channel is opened and nothing runs. Outcomes: `accepted`; `refused` (the server answered that no method is left); `unprovable` (the server let Alice in without asking for the key, or offers no public-key method). A refused login on a line with `from=` is `unverifiable`; a root location on a server with `PermitRootLogin no` is planned `unverifiable` without a try; a test login never changes the target's status | Authentication is what proves the key; running a command as an arbitrary user adds surface (`~/.ssh/rc`, PAM sessions); a `none`-accepting server would otherwise "verify" anything | A key that authenticates but whose forced command breaks the consumer still counts as working (as spec §13.4 itself says for `command=`) |
| 10 | §13.4 step 5 "Failure -> restore from backup … `authkeys-write --expect-sha256 <new>` of old content" | An addition whose login is refused is undone by removing the new key by its fingerprint (`RemoveAuthorizedKey`, CAS as usual); file contents are never kept between steps | The new key's fingerprint is unique to the request (it was not in the file when it was read, or Alice would not have written); a removal by fingerprint keeps every other byte | none known |
| 11 | §13.6 policy fields `require_verification` (default true) and `remove_old` (default true); §13.6 item 4 "Confirm the new key works on these hosts" | Neither field is offered: verification is always required and the old key is always removed after the overlap where it may be. For `unverifiable` locations an Administrator may only **Keep the old key there** (both keys stay at those locations) or **Stop and undo**; there is no "confirm it works" | The old-key rule: a person's belief is not a verified login | A server Alice cannot test keeps both keys after every rotation |
| 12 | §13.6 schedule "interval in days or cron-like weekday/time"; §7.3 `schedule_cron` | `interval_days` (1–3650); the first run is due `interval_days` after the policy is switched on, the next one `interval_days` after a run's start; **Run now** at any time | Owner step 3 ("every 90 days"); cron syntax is a translation and validation burden | No "first Sunday 02:00" schedules |
| 13 | §13.6 "locations (all current locations of the key or a subset)" | All locations of the key; skipped ones are listed with their reason | Simplest correct reading; a subset would leave the old key in use where the policy did not reach | No partial rotations |
| 14 | §7.3 `overlap_days int`; §26.8 "a 1-minute overlap in the e2e build" | Stored as `overlap_minutes` (0–129600); the API takes and shows `overlap_days` (0–90, default 7) and also returns `overlap_minutes`; only the e2e build's `POST /test/rotation/overlap` sets minutes directly | The release API stays in days; the e2e build can show a real one-minute overlap without a demo-clock jump of a week | none known |
| 15 | §13.6 "notification sent to admins (recipients in settings)"; "the scheduled run starts only after the preview notification was sent" | Recipients are all Administrators (`NotifyAdmins`) until Settings (Phase 7); "sent" means the notice was queued in `notifications_outbox` by the committed transaction that created the run (`rotations.notified_at`); delivery is the outbox's (retries, F-60) | No recipient setting exists; Alice cannot make SMTP succeed | An SMTP outage delays the email, not the run |
| 16 | Owner step 4 "Click Preview next run … and sends you an email"; §13.6 "available on demand" | An on-demand preview also emails the Administrators, at most once per policy per 10 minutes (`rotation_policies.preview_mailed_at`); the answer says whether it emailed | Owner step 4; a bound against an email storm | A second preview within 10 minutes is not emailed |
| 17 | "Dry-run equals actual plan" (§26.8) has no mechanism | Every plan has a SHA-256 digest over its decisions (the plan package); a scheduled run re-plans at its start and is cancelled (`rotation.plan_changed`) and previewed again with a fresh notice when the digest differs; **Run now** must carry the digest of the preview the Administrator saw (409 `ALC-ROT-0003` otherwise) | The previewed plan is the only one that can run | A busy fleet can cancel scheduled runs repeatedly (each with an email) |
| 18 | §8.2 job `rotation.advance` (one job per rotation) | The controller `sshkeys.Advance` runs in-process (sweep, end of each location job, actions); remote work is one queue job `rotation.location` per location and phase, bound to its server | The queue's per-server lock (§8.5) then serialises rotation work with discovery and removals; servers run in parallel within the worker caps (§13.6 item 3) | One more job type; a rotation of 200 locations queues 200 jobs |
| 19 | §13.6 ADDING (all) then VERIFYING (all); L-85 "verification step also runs (it is part of the in-flight operation)" | Per location: add, then verify at once, in one job; the rotation status is `adding_new` until every location is done | L-85; a failure stops the run before more servers are touched | none known |
| 20 | §8.6 "Gated: … `rotation.*`" | `rotation.plan` is read-only (no tick in lock: L-88); `rotation.sweep` and `rotation.location` are `always`, and every forward change inside them asks the gate (`Allow(ClassChange)`) at a safe boundary: before an add is sent, before a removal is sent, before the overlap ends; an in-flight add and its verification finish, and an undo always runs (L-85, L-86, as `certificate.deploy_recover`); `sshkey.add` is `change`; `sshkey.destroy_retired` is read-only (no deletion in lock) | The queue's own lock handling would block the undo and the finish of in-flight work | A bug in a handler's gate check is not caught by the queue (each boundary has its own lock test) |
| 21 | §13.6 item 9 `PAUSED_LICENSE` state; L-83 "flagged `paused_license`"; R24; R29 | `paused_license` is a flag beside the status; a run not yet started when its start falls into lock is **cancelled** (`rotation.cancelled_license`) and the policy previews a new run after the renewal; a started run is paused, and only an Administrator's **Continue** (step-up) clears the flag — it queues a fresh notice (`rotation.preview_after_license`) in the same transaction; every removal then needs its own fresh login | L-83..L-88; a stale preview must not start weeks later | A renewal after a long lock restarts the schedule with a new notice period |
| 22 | §7.4 statuses vs §13.6 state names | Statuses `dry_run_notified`, `adding_new`, `verifying_new` (only while waiting for an Administrator's decision on unverifiable locations), `overlap`, `removing_old`, `completed`, `rolling_back`, `aborted`, `needs_attention`, `cancelled`; `planned` is not used (a run is created already notified); per-location states in `rotation_locations` | One name per state, the spec's where they exist | — |
| 23 | §13.6 item 6 "old key record goes to `retired` (private key retained … 30 days, then destroyed; configurable)" | The old key is retired only when none of its locations is live (not removed, not missing) — keys kept on skipped or undecided servers stay active; its private key is destroyed 30 days after retirement by `sshkey.destroy_retired` (hourly, not in lock), which sets the envelope columns to NULL once (trigger); the 30 days are a constant until Settings (Phase 7); a retired key can still be downloaded until destroyed | Retiring a key that still opens servers would hide it; "no data deletion in lock" | Database backups taken before the destruction still hold the sealed key (documented) |
| 24 | Permissions: §15.4 "Rotation policies (create/enable): Admin"; SEC-009 step-up for "rotation policy enabling"; §25.1 | `rotation.manage` (Administrator; `operate` tokens): create, edit, delete, switch off, preview, stop and undo; `rotation.operate` (Administrator, browser session, step-up): switch on, **Run now**, **Continue**, **Finish now**, **Keep the old key there**; reads are `read` | Starting changes on servers is the sensitive part; automation may still prepare and stop policies | — |
| 25 | §9.6 rotation actions `approve|abort|dry-run` | `…/runs/{id}/actions/continue` (R29 confirmation), `/finish-now`, `/keep-old`, `/abort`; the dry run is `…/policies/{id}/actions/preview` | Names that say what happens | — |
| 26 | §13.6 item 4 "up to 14 days, then rolled back automatically"; "timers do not fire during lock" | Kept: the decision deadline is 14 days after the run started waiting; an expired deadline in lock waits for the license | spec | — |
| 27 | §13.6 item 6 "re-check that the new key … works for each location (fresh test login)" has no freshness bound | The re-check must be at most 15 minutes before the removal is sent (CHECK on `rotation_locations`) | A re-check from yesterday proves nothing about today | none known |
| 28 | §13.4 step 1 "the user can choose if several" files; no source for the choice | Discovery stores each user's candidate key files (`facts.key_files`, at most 200 users × 8 files, from the helper's `authkeys-list`); the deploy dialog offers them; the server re-checks at the write (R37 item 22) | A GET must not open SSH sessions | A user created after the last scan needs a scan first |
| 29 | §13.6 item 2 copies options per location; §13.3 shared absolute `AuthorizedKeysFile` paths | A file holding the old key for several users is changed only as a whole: if any of its locations is skipped, all are skipped (`shared_file_skipped`), and the old key is removed from it only when all of its locations verified | Removing a shared line for one verified user removes it for every user of the file | A shared file with one unreachable condition is not rotated |
| 30 | Error areas | New area `ALC-ROT-0001..0016`; `ALC-KEY-0006..0013` | §9.3 | — |
| 31 | §13.6 "Admin can shorten (Finish now) or extend" | **Finish now** sets the overlap end to now (removal still needs every fresh login); extending is editing the policy's overlap before the run starts — a running overlap is not extended | The extension of a running overlap has no safety value the policy edit lacks | An overlap cannot be lengthened mid-run (stop and undo instead) |
| 32 | §8.5 per-target SSH cap 2 | The test login dials outside the connection pool (its own short-lived connection, closed at once) | It must authenticate as another user with another key | One extra connection per test login |
| 33 | `05-operations.md` §19.3 "rotation removals … wait for Admin confirmation" via the held-jobs panel (R29, L-81) | Rotation confirmations happen on the rotation page (**Continue**); `sshkey.add` jobs held in lock use the existing held-jobs panel (L-81) | A rotation's continuation needs its own preview and fresh notice | Two places to confirm work after a renewal |

## Carries and deferred items

| # | Carry | Decision | Where |
|---|---|---|---|
| 1 | L-83, L-84, L-85, L-86, L-88 (rotation runner; R37 item 18, Phase 5 carry 4) | **Included** with the real runner and the real scheduler; `internal/jobs/stubjobs_test.go`'s `testRotation` stub stays for the generic gate tests and gains a pointer to the real tests | Task 12 |
| 2 | L-29 real-job parts for rotation and deploy (no remote command in lock) | **Included**: in lock every new route that changes servers answers 403 `license.locked`, the scheduled tasks start no remote command (the emulator's command log stays empty), nothing is deleted | Task 14 |
| 3 | L-81 for `sshkey.add` (queued before the lock, held, confirmed after renewal) | **Included** | Task 12 |
| 4 | Helper: adding and removing a key scan all accounts more than once (audit remediation, Phase 4) | **Re-deferred to Phase 8**: performance only (a rotation of one location costs about four helper scans); a fix changes the helper and its protocol, which this phase avoids; the 60 s command budget holds at the 200-account bound | — |
| 5 | Helper: an unreadable journal blocks its pair for 30 days; the dropped-certificate warning without the file; a TLS block without `ssl` listen; host-name listens (Phase 4) | **Re-deferred** (Nginx helper; no helper change in Phase 6) | — |
| 6 | Phase 5 parked: the import history drops a vault's rows silently when a read fails (`web/src/components/ImportHistory.tsx`) | **Included**: an error line per vault whose read failed, with a retry | Task 17 |
| 7 | Phase 5 parked: one more query per certificate in each poll, under the vault lock (`internal/inventory/kv_store.go`) | **Re-deferred to Phase 7**: performance only, needs a measurement on a large vault; Phase 6 does not touch Key Vault code and `inventory` has a thin floor | — |
| 8 | Phase 5 parked: the OpenAPI sentence on the 412 of `PATCH /bindings/{id}` (a missing `If-Match` is answered first) | **Included** (one sentence) | Task 13 |
| 9 | Phase 5 parked: the add-vault dialog shows only the roles text when a role is missing and a check failed as well | **Included**: both texts are shown | Task 17 |
| 10 | Phase 3/4: an `authorized_keys` change whose read-back differs still stops for a person (`ALC-KEY-0005`, no automatic restore) | **Partly included**: deploys and rotations undo their own additions by fingerprint; the manual removal path stays as it is (re-deferred: Alice keeps no file contents between steps, and restoring a removed line needs them) | Tasks 10, 11 |
| 11 | Certificate private-key download (§9.6; Phase 4 review "no download (Phase 6)") | **Re-deferred to Phase 7** (row 6) | — |
| 12 | Inventory's own refusal rows are not coalesced | **Re-deferred**; the new `sshkey.deploy.denied`, `sshkey.private_key_download.denied` and `rotation.policy.denied` rows follow the same uncoalesced pattern (bounded by the session rate limit) | — |
| 13 | `facts.nginx.scanned_at`; recovery codes lost when the completing answer is lost; a certificate re-issued for a completed signing request's key; e2e hooks for the route error page, `unverified` banner and locale fallback; the Phase 5 Key Vault limitations (`kv.credential_unreadable` on other paths, the disabled-vault wording, a held import blocking its name, the limiter counting attempts, a failing detail read discarding the listing) | **Re-deferred** (unrelated to SSH keys) | — |
| 14 | Lockfile secret scanning, `osv-scanner`, real-systemd job, nightly pipeline, mutation testing | **Re-deferred to Phase 8** | — |
| 15 | Owner items: a git remote and the first workflow run, the production license key, the walkthroughs of Phases 1–5 and the remediation, the real-Azure suite, the Turkish tone review, the crypto sign-off, a clean-machine `make ci` | Owner only; Phase 6 adds its own walkthrough table (§26.8 owner steps 1–6) | Task 19 |

## Spec coverage map (§26.8)

| §26.8 item | Task(s) | Test(s) |
|---|---|---|
| SSH key generation (Ed25519 default, RSA 3072/4096, ECDSA) | 1, 7, 13, 16 | `TestGenerateEveryType`, `TestGenerateStoresAnEnvelope`, `GenerateKeyDialog.test.tsx` |
| Private key storage | 1, 5, 7 | `TestStoredKeyIsAnEnvelope`, `TestManagedPrivateKeyGuard`, `TestDestroyRetiredKeys` |
| Audited download flow (S-09) | 1, 7, 13, 14, 16 | `TestS09PrivateKeyDownload`, `TestDownloadAuditsBeforeTheFile`, `DownloadKeyDialog.test.tsx`, e2e download |
| Deploy public key | 3, 4, 6, 7, 10, 16 | `TestDeployVerifiesLogin`, `TestDeployRefusedLoginIsUndone`, e2e deploy |
| Remove key | (Phase 3) + 11 | rotation removals; Phase 3 removal tests unchanged |
| Rotation policies (Admin only, Off by default, overlap 7 days, platform-managed keys only) | 5, 8, 13, 17 | `TestPolicyDefaults`, `TestPolicyOnlyForGeneratedKeys`, `TestRotationRoutesAuthz` |
| Dry-run preview and notification before each run | 2, 8, 13, 17 | `TestPreviewEmailsAdmins`, `TestScheduledRunNotifiesBeforeStart`, `TestDryRunEqualsActualPlan` |
| Rotation runner (add, verify, overlap, remove) with recorded steps and rollback info | 8, 9, 11 | `TestRotationHappyPath`, `TestStepsRecorded` |
| Pause on lock | 9, 11, 12 | L-83..L-88 |
| Never remove the old key after an incomplete rotation | 5, 9, 11, 12 | `TestOldKeyRemainsUnderAnyInjectedFailure` |
| F-36..F-39 for rotation | 11, 12, 14 | `TestF36OwnKeyNeverRotatedOrDownloaded`, `TestF37RotationIntoFileWithoutNewline`, `TestF38RotationFileChangedBetweenReadAndWrite`, `TestF39SlowHostDuringRotation` |
| F-67 | 12 | `TestF67KillBetweenAddAndVerify` |
| L-83..L-88 with the real runner | 12 | `TestL83OverlapLockRemovesNothing`, `TestL84RenewalAfterTwentyDays`, `TestL85AddInFlightAtLock`, `TestL86VerifyFailsDuringLock`, `TestL88LockAtPreviewTime`; L-87 is a Key Vault case closed in Phase 5 (`TestL87PollInFlightAtLock`, `internal/jobs/kvjobs`), unchanged and re-run by Task 19's `make coverage` |
| Planner unit tests (only managed keys, never Alice's key, overlap boundaries with the fake clock, dry-run equals actual plan) | 2 | `TestOnlyManagedKeys`, `TestNeverAlicesOwnKey`, `TestOverlapBoundaries`, `TestPlanIsDeterministic` |
| Property test: any injected failure at any step keeps the old key | 12 | `TestOldKeyRemainsUnderAnyInjectedFailure` |
| S-09 | 14 | `TestS09PrivateKeyDownload` |
| Authz matrix for policy endpoints (Admin only) | 13 | `TestAuthzMatrix` (generated), `TestRotationRoutesAuthz` |
| E2E: generate, deploy, verify login, manual rotation with a 1-minute overlap, old key removed only after the overlap, EN and TR | 15, 18 | `web/e2e/phase6.spec.ts` |
| Owner verification steps 1–6 | 19 | walkthrough table in `docs/security/reviews/phase-6.md` (empty, owner's) |
| Exit: property under fault injection; pause and resume with license; no High finding | 12, 19 | security review |

---

## File Structure

```
internal/sshkeys/keymat/                   keymat.go (types, Generate), openssh.go (download file), line.go (comment, from=,
                                           authorized line), signer.go (test-login signer); tests, FuzzAuthorizedLine (Task 1)
internal/sshkeys/plan/                     plan.go (Input, Plan, Action, Build), digest.go, times.go; tests (Task 2)
internal/providers/                        types.go (KeyLoginRequest/Result, UserKeyFiles, AuthKeyResult.LineNo,
                                           DiscoveryResult.KeyFiles), provider.go (Session.VerifyKeyLogin), capability.go
                                           (CapKeyLogin), unsupported.go; fake (KeyWorld, faults); providertest (Task 3)
internal/providers/linuxssh/               keylogin.go (VerifyKeyLogin), keyops.go (LineNo), discover.go (KeyFiles),
                                           provider.go (session fields), linuxsshtest/server.go (per-user login check),
                                           linuxsshtest/emulator.go (AcceptsLogin) (Task 4)
migrations/00010_ssh_key_rotation.sql      managed_private_keys, ssh_keys, rotation_policies, rotations,
                                           rotation_locations, rotation_steps, triggers, grants (Task 5)
internal/inventory/                        keychange.go (KeyChangeRefusal, TargetTx, CheckClaimTx, KeyLocationsTx,
                                           ProtectedFingerprintsTx, RecordKeyAddedTx, ValidateReason), sshkeys.go
                                           (facts.key_files), types.go, removal.go (uses KeyChangeRefusal) (Task 6)
internal/archtest/arch_test.go             sshkeys rules (Task 1)
internal/sshkeys/                          service.go, errors.go, types.go, keys.go (generate, managed key reads),
                                           deploy.go, download.go, destroy.go, signer.go (Task 7); policies.go, preview.go,
                                           schedule.go, notify.go (Task 8); rotations.go, controller.go, store.go,
                                           sweep.go, decisions.go (Task 9)
internal/jobs/types.go                     sshkey.add, rotation.location, rotation.plan, rotation.sweep,
                                           sshkey.destroy_retired (Task 10)
internal/jobs/sshkeyjobs/                  sshkeyjobs.go (Register, Deps, open), deploy.go (Task 10); location.go (Task 11);
                                           property, crash and lock tests (Task 12)
internal/rbac/rbac.go                      sshkeys.download, rotation.manage, rotation.operate (Task 13)
internal/api/                              sshkeys_handlers.go, rotation_handlers.go, rotation_dto.go, errors.go,
                                           guard.go (limitDownload), server.go (Task 13); integration suites (Task 14)
api/openapi.yaml, docs/authz-matrix.md     new operations; the bindings 412 sentence (Task 13)
locales/common/{en,tr}.json                error texts and email templates (Task 13)
cmd/alice/                                 services.go, wiring.go, testapi_e2e.go, testapi_release.go, tests (Task 15)
test/images/e2e-target/Dockerfile          `usermod -p '*' deploy` (Task 15)
web/src/                                   api/sshkeys.ts, components/GenerateKeyDialog, DeployKeyDialog, DownloadKeyDialog,
                                           pages/SSHKeyDetailPage, SSHKeysPage (Task 16); api/rotation.ts,
                                           components/RotationPolicyPanel, RotationPolicyDialog, RotationPreviewDialog,
                                           pages/RotationRunPage, router, audit labels, ImportHistory, AddKeyVaultDialog
                                           (Task 17)
web/e2e/phase6.spec.ts                     EN/TR journeys (Task 18)
docs/                                      admin-guide.md, operator-guide.md, troubleshooting.md, security/reviews/phase-6.md,
                                           superpowers/rulings/phase-6.md, specs R41 and pointers, CHANGELOG, floors (Task 19)
```

Task order is bottom-up: pure packages (1–2), provider (3–4), schema (5), inventory (6), the `sshkeys` module (7–9), jobs (10–12), HTTP (13–14), wiring (15), web (16–17), end-to-end (18), documentation and verification (19). Each task leaves the repository green (`make lint`, `make test`, the integration packages it touches, `make web-test` and `make i18n-check` where it touches the web).

### Task index

1. `internal/sshkeys/keymat`: key generation, the OpenSSH download file, `authorized_keys` lines and comments, the test-login signer; `FuzzAuthorizedLine`
2. `internal/sshkeys/plan`: the rotation planner, skip and verification rules, the digest, timers
3. Provider framework: `VerifyKeyLogin`, `CapKeyLogin`, candidate key files, the added line's number; the fake's `KeyWorld` with fault injection; conformance
4. `linuxssh`: `VerifyKeyLogin` over a fresh connection, key files in discovery, `LineNo`; the test server's per-user logins; real OpenSSH case
5. Migration `00010_ssh_key_rotation.sql`
6. Inventory: key-change readiness, transactional reads, recording an added key, `facts.key_files`, `ValidateReason`
7. `internal/sshkeys` part 1: the module, generation, managed-key reads, deploy requests and their bookkeeping, the signer source, the download, destruction of retired keys
8. `internal/sshkeys` part 2: policies, previews and their emails, scheduled planning, **Run now**
9. `internal/sshkeys` part 3: rotation store, the controller `Advance`, the sweep, decisions (continue, finish now, keep old, stop and undo), rotation emails
10. Jobs: the five job types, `sshkeyjobs.Register`, the `sshkey.add` handler
11. Jobs: the `rotation.location` handler (add + verify, re-verify + remove, undo)
12. Jobs: property test under fault injection, F-67 and kills at every point, L-81 and L-83..L-88, F-36..F-39 at rotation level
13. API: permissions, routes, DTOs, the download handler and its limiter, error codes and texts, emails' texts, OpenAPI, authz matrix
14. API integration: journeys over the emulator, S-09, the secret-leak suite with generated keys, dry run equals run, lock (L-29), F-36
15. Wiring and the e2e build: services, runner, scheduler, periodic types, `POST /test/rotation/overlap`, reset, e2e target account
16. Web part 1: API layer, **Generate key**, **Deploy**, **Download private key**, the key pages
17. Web part 2: rotation policy panel and dialogs, preview, the rotation run page, audit labels; Phase 5 web carries
18. End-to-end: Phase 6 journeys in EN and TR, accessibility
19. Coverage floors, documentation, R41, security review, rulings, CHANGELOG, `make ci`

**Schedule (at most three agents; package ownership):**

| Wave | Agent A | Agent B | Agent C | Docker |
|---|---|---|---|---|
| 1 | Task 1 → Task 2 (`archtest`, `sshkeys/keymat`, `sshkeys/plan`) | Task 3 → Task 4 (`providers`, `providers/fake`, `providertest`, `linuxssh`, `nginx`) | Task 5 (`migrations`), then Task 6 (`inventory`) once Task 3 is committed (it needs `DiscoveryResult.KeyFiles`) | B (Task 4's real OpenSSH case) and C use testcontainers; allowed together |
| 2 | Task 7 → Task 8 → Task 9 (`sshkeys`; Task 7 starts when Tasks 1, 2 and 6 are committed) | Task 13 (`rbac`, `api`, `api/openapi.yaml`, `docs/authz-matrix.md`, `docs/troubleshooting.md`, `locales/common`, `internal/notify/render_test.go`); it compiles against C7, so it starts once Task 8 is committed and finishes after Task 9 | Task 16 (`web/src`; msw against the DTOs of C13) | testcontainers only |
| 3 | Task 10 → Task 11 → Task 12 (`jobs`, `jobs/sshkeyjobs`) | Task 14 (`internal/api` tests; after Tasks 11 and 13) | Task 17 (`web/src`, after Task 16) | testcontainers only |
| 4 | Task 15 (`cmd/alice`, `test/images/e2e-target`) | — | — | an image build only |
| 5 | Task 18 (`web/e2e`) | — | — | **Docker alone** (Playwright; no testcontainers anywhere) |
| 6 | Task 19 (docs, floors, `make coverage`, `make ci`) | — | — | **Docker alone** (no other Docker user at all) |

Recommended execution: subagent-driven, one reviewer per task, an additional security reviewer on Tasks 1, 4, 5, 7, 9, 11, 12 and 14. Tasks 1–2, 3–4, 7–9 and 10–12 each keep one implementer.

---
## Cross-task contract

Every task's **Interfaces** block repeats the parts of this contract it consumes or produces. When a task and this section disagree, this section wins and the task is a plan defect to fix at execution time (record it in the task's report).

### C1. Names

| Kind | Name | Value / meaning |
|---|---|---|
| Package | `alice/internal/sshkeys/keymat` | pure key material (Task 1) |
| Package | `alice/internal/sshkeys/plan` | pure rotation planner (Task 2) |
| Package | `alice/internal/sshkeys` | the module (Tasks 7–9) |
| Package | `alice/internal/jobs/sshkeyjobs` | job handlers (Tasks 10–12) |
| Queue job | `sshkey.add` (`sshkeys.JobDeploy`) | class `change`, 3 attempts, target-bound; payload `ssh_key_id`, `os_user`, `file_path`, `options`; dedupe `sshkey.add:<ssh_key_id>:<target_id>:<sha256(os_user+"\n"+file_path) first 16 hex>` |
| Queue job | `rotation.location` (`sshkeys.JobRotationLocation`) | class `always`, 3 attempts, no `job.dead` email (`AlertsWhenExhausted` false), target-bound; payload `rotation_id`, `location_id`, `phase` (`add` \| `remove` \| `undo`); dedupe `rotation.location:<location_id>:<phase>` |
| Periodic task | `rotation.plan` | class `read_only`, every minute (e2e: never); `sshkeys.Service.PlanDue` |
| Periodic task | `rotation.sweep` | class `always`, every minute (e2e: never); `sshkeys.Service.Sweep` |
| Periodic task | `sshkey.destroy_retired` | class `read_only`, every hour (e2e: never); `sshkeys.Service.DestroyRetiredKeys` |
| Permission | `sshkeys.download` | Administrator, browser session, step-up; no API token |
| Permission | `rotation.manage` | Administrator; `operate` API tokens allowed |
| Permission | `rotation.operate` | Administrator, browser session, step-up; no API token |
| Permission (existing) | `inventory.operate` | generate, deploy |
| Rate limit | `limitDownload` | 5 per minute per user (`"u:" + Principal.UserID`), besides the general limit |
| Constant | `sshkeys.RetiredKeyRetention` | `30 * 24 * time.Hour` |
| Constant | `sshkeys.DecisionWindow` | `14 * 24 * time.Hour` |
| Constant | `sshkeys.ReverifyFreshness` | `15 * time.Minute` (also the database CHECK) |
| Constant | `sshkeys.PreviewMailEvery` | `10 * time.Minute` |
| Constant | `sshkeys.MaxLocationJobs` | `5` jobs per location and phase before the location is failed with `rotation.retries_exhausted` |
| Constant | `linuxssh.KeyLoginBudget` | `10 * time.Second` (one test login, dial to authentication) |
| Constant | `sshkeys.MaxGenerations` | `2` keys generated at once in the process (`sshkey.generate_busy` beyond) |

### C2. Database (migration `00010_ssh_key_rotation.sql`, Task 5)

```sql
-- +goose Up
-- Phase 6: SSH keys generated by Alice and their private keys, rotation policies and rotation runs
-- (spec §7.2-§7.4, §13.4-§13.6; R41). Same conventions as 00006 and 00008: closed lists for values
-- Alice owns, format checks for names, no clock defaults.

-- Generated SSH keys keep their private key here (owner ssh_key, PKCS #8 DER for every type; R41 row 2).
-- Ed25519 is new. download_count and last_downloaded_at belong to the audited download. A retired key's
-- private key is destroyed 30 days after its retirement (R41 row 23): its envelope columns become NULL
-- once, with destroyed_at; nothing else may ever change an envelope (managed_private_keys_guard).
ALTER TABLE managed_private_keys DROP CONSTRAINT managed_private_keys_owner_type_check;
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_owner_type_check
    CHECK (owner_type IN ('certificate', 'csr', 'ssh_key'));
ALTER TABLE managed_private_keys DROP CONSTRAINT managed_private_keys_algorithm_check;
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_algorithm_check
    CHECK (algorithm IN ('rsa', 'ecdsa', 'ed25519'));
ALTER TABLE managed_private_keys DROP CONSTRAINT managed_private_keys_check;
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_bits_check CHECK ((algorithm = 'rsa' AND bits >= 2048)
    OR (algorithm = 'ecdsa' AND bits IN (256, 384)) OR (algorithm = 'ed25519' AND bits = 256));
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_ssh_types CHECK (owner_type <> 'ssh_key'
    OR (algorithm = 'ed25519') OR (algorithm = 'rsa' AND bits IN (3072, 4096)) OR (algorithm = 'ecdsa' AND bits = 256));
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_ed25519_is_ssh CHECK (algorithm <> 'ed25519' OR owner_type = 'ssh_key');
ALTER TABLE managed_private_keys ADD COLUMN download_count integer NOT NULL DEFAULT 0 CHECK (download_count >= 0);
ALTER TABLE managed_private_keys ADD COLUMN last_downloaded_at timestamptz;
ALTER TABLE managed_private_keys ADD COLUMN destroyed_at timestamptz;
ALTER TABLE managed_private_keys ALTER COLUMN ciphertext DROP NOT NULL, ALTER COLUMN nonce DROP NOT NULL,
    ALTER COLUMN wrapped_dek DROP NOT NULL, ALTER COLUMN key_version DROP NOT NULL;
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_destroyed CHECK (
    (destroyed_at IS NULL AND ciphertext IS NOT NULL AND nonce IS NOT NULL AND wrapped_dek IS NOT NULL AND key_version IS NOT NULL)
    OR (destroyed_at IS NOT NULL AND owner_type = 'ssh_key' AND ciphertext IS NULL AND nonce IS NULL AND wrapped_dek IS NULL
        AND key_version IS NULL));

-- +goose StatementBegin
CREATE FUNCTION managed_private_keys_guard() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.destroyed_at IS NOT NULL THEN
        RAISE EXCEPTION 'a destroyed private key cannot change' USING ERRCODE = 'Z1009';
    END IF;
    IF NEW.id <> OLD.id OR NEW.owner_type <> OLD.owner_type OR NEW.algorithm <> OLD.algorithm OR NEW.bits <> OLD.bits
            OR NEW.public_key_sha256 <> OLD.public_key_sha256 OR NEW.created_at <> OLD.created_at
            OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
        RAISE EXCEPTION 'a private key''s identity cannot change' USING ERRCODE = 'Z1009';
    END IF;
    IF NEW.destroyed_at IS NOT NULL THEN
        -- Destruction: the envelope goes (the CHECK requires NULLs), the counters stay.
        IF NEW.download_count <> OLD.download_count OR NEW.last_downloaded_at IS DISTINCT FROM OLD.last_downloaded_at THEN
            RAISE EXCEPTION 'a destruction changes nothing but the envelope' USING ERRCODE = 'Z1009';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.ciphertext IS DISTINCT FROM OLD.ciphertext OR NEW.nonce IS DISTINCT FROM OLD.nonce
            OR NEW.wrapped_dek IS DISTINCT FROM OLD.wrapped_dek OR NEW.key_version IS DISTINCT FROM OLD.key_version THEN
        RAISE EXCEPTION 'a private key''s envelope cannot be replaced' USING ERRCODE = 'Z1009';
    END IF;
    IF NEW.download_count < OLD.download_count OR NEW.download_count > OLD.download_count + 1 THEN
        RAISE EXCEPTION 'a download counts one' USING ERRCODE = 'Z1009';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER managed_private_keys_guard BEFORE UPDATE ON managed_private_keys
    FOR EACH ROW EXECUTE FUNCTION managed_private_keys_guard();

-- A generated key (managed) has exactly one private key and is never the platform key (R41 rows 1-2).
-- rotated_from links a rotation's new key to the key it replaces; retired_at is set when no location
-- of a rotated key is live any more (R41 row 23).
ALTER TABLE ssh_keys ADD COLUMN private_key_id uuid UNIQUE REFERENCES managed_private_keys (id);
ALTER TABLE ssh_keys ADD COLUMN key_comment text NOT NULL DEFAULT '' CHECK (key_comment ~ '^[!-~]{0,100}$');
ALTER TABLE ssh_keys ADD COLUMN rotated_from uuid REFERENCES ssh_keys (id);
ALTER TABLE ssh_keys ADD COLUMN created_by uuid REFERENCES users (id);
ALTER TABLE ssh_keys ADD CONSTRAINT ssh_keys_managed_has_private_key CHECK (managed = (private_key_id IS NOT NULL));
ALTER TABLE ssh_keys ADD CONSTRAINT ssh_keys_managed_is_not_platform CHECK (NOT (managed AND is_platform_key));
ALTER TABLE ssh_keys ADD CONSTRAINT ssh_keys_label_length CHECK (char_length(label) <= 100);
CREATE INDEX ssh_keys_rotated_from ON ssh_keys (rotated_from) WHERE rotated_from IS NOT NULL;

-- One policy per live key (§13.6 item 10). It follows the key: a completed rotation moves ssh_key_id
-- to the new key. enabled implies a next run (R41 row 12). preview_mailed_at bounds on-demand preview
-- emails (row 16).
CREATE TABLE rotation_policies (
    id                  uuid PRIMARY KEY,
    ssh_key_id          uuid NOT NULL REFERENCES ssh_keys (id),
    name                text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    enabled             boolean NOT NULL DEFAULT false,
    interval_days       integer NOT NULL CHECK (interval_days BETWEEN 1 AND 3650),
    overlap_minutes     integer NOT NULL DEFAULT 10080 CHECK (overlap_minutes BETWEEN 0 AND 129600),
    notify_before_hours integer NOT NULL DEFAULT 24 CHECK (notify_before_hours BETWEEN 1 AND 168),
    new_key_type        text NOT NULL DEFAULT 'same' CHECK (new_key_type IN ('same', 'ed25519', 'rsa-3072', 'rsa-4096', 'ecdsa-p256')),
    next_run_at         timestamptz,
    preview_mailed_at   timestamptz,
    version             integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by          uuid REFERENCES users (id),
    created_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL,
    deleted_at          timestamptz,
    CHECK (deleted_at IS NOT NULL OR enabled = (next_run_at IS NOT NULL))
);
CREATE UNIQUE INDEX rotation_policies_one_per_key ON rotation_policies (ssh_key_id) WHERE deleted_at IS NULL;
CREATE INDEX rotation_policies_due ON rotation_policies (next_run_at) WHERE enabled AND deleted_at IS NULL;

-- A policy's key is a key Alice generated, not retired, and never Alice's own key (F-36, SEC-081): the
-- service refuses first; this holds even if it had a bug. Same search_path discipline as 00005.
-- +goose StatementBegin
CREATE FUNCTION rotation_policies_check_key() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    platform_fp text;
BEGIN
    IF NEW.deleted_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    SELECT public_info->>'fingerprint' INTO platform_fp FROM public.credentials WHERE purpose = 'platform_ssh';
    IF NOT EXISTS (SELECT 1 FROM public.ssh_keys k WHERE k.id = NEW.ssh_key_id AND k.managed AND NOT k.is_platform_key
                   AND k.retired_at IS NULL AND k.fingerprint_sha256 IS DISTINCT FROM platform_fp) THEN
        RAISE EXCEPTION 'a rotation policy needs a live key Alice generated, never Alice''s own key' USING ERRCODE = 'Z1010';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER rotation_policies_key_check BEFORE INSERT OR UPDATE OF ssh_key_id, deleted_at ON rotation_policies
    FOR EACH ROW EXECUTE FUNCTION rotation_policies_check_key();

-- One rotation run (§7.4; R41 rows 17-22). plan is the public preview (no secret: lines carry public keys
-- and options only); plan_digest is what a start must match. paused_license is the lock flag (L-83..L-86);
-- removal_allowed is set only on entering removing_old, which needs verified_at (old-key rule).
CREATE TABLE rotations (
    id                   uuid PRIMARY KEY,
    policy_id            uuid NOT NULL REFERENCES rotation_policies (id),
    old_ssh_key_id       uuid NOT NULL REFERENCES ssh_keys (id),
    new_ssh_key_id       uuid REFERENCES ssh_keys (id),
    trigger              text NOT NULL CHECK (trigger IN ('scheduled', 'manual')),
    status               text NOT NULL CHECK (status IN ('dry_run_notified', 'adding_new', 'verifying_new', 'overlap',
                             'removing_old', 'completed', 'rolling_back', 'aborted', 'needs_attention', 'cancelled')),
    paused_license       boolean NOT NULL DEFAULT false,
    paused_at            timestamptz,
    awaiting_decision    boolean NOT NULL DEFAULT false,
    decision_due_at      timestamptz,
    plan                 jsonb NOT NULL CHECK (jsonb_typeof(plan) = 'object' AND octet_length(plan::text) <= 2097152),
    plan_digest          text NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    new_key_type         text NOT NULL CHECK (new_key_type IN ('ed25519', 'rsa-3072', 'rsa-4096', 'ecdsa-p256')),
    overlap_minutes      integer NOT NULL CHECK (overlap_minutes BETWEEN 0 AND 129600),
    planned_for          timestamptz NOT NULL,
    notified_at          timestamptz NOT NULL,
    started_at           timestamptz,
    verified_at          timestamptz,
    overlap_until        timestamptz,
    reminder_sent_at     timestamptz,
    removal_allowed      boolean NOT NULL DEFAULT false,
    continued_by         uuid REFERENCES users (id),
    continued_at         timestamptz,
    renotified_at        timestamptz,
    finished_at          timestamptz,
    result_code          text NOT NULL DEFAULT '' CHECK (result_code = '' OR result_code ~ '^[a-z][a-z0-9_]{0,40}\.[a-z][a-z0-9_]{0,60}$'),
    created_by           uuid REFERENCES users (id),
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    version              integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CHECK (status <> 'removing_old' OR removal_allowed),
    CHECK (NOT removal_allowed OR (verified_at IS NOT NULL AND new_ssh_key_id IS NOT NULL)),
    CHECK (new_ssh_key_id IS DISTINCT FROM old_ssh_key_id),
    CHECK (status IN ('dry_run_notified', 'cancelled') OR new_ssh_key_id IS NOT NULL),
    CHECK (paused_license = (paused_at IS NOT NULL)),
    CHECK (awaiting_decision = (decision_due_at IS NOT NULL)),
    CHECK ((status IN ('completed', 'aborted', 'needs_attention', 'cancelled')) = (finished_at IS NOT NULL))
);
CREATE UNIQUE INDEX rotations_one_live_per_key ON rotations (old_ssh_key_id)
    WHERE status NOT IN ('completed', 'aborted', 'needs_attention', 'cancelled');
CREATE UNIQUE INDEX rotations_one_live_per_policy ON rotations (policy_id)
    WHERE status NOT IN ('completed', 'aborted', 'needs_attention', 'cancelled');
CREATE INDEX rotations_live ON rotations (status) WHERE status NOT IN ('completed', 'aborted', 'needs_attention', 'cancelled');

-- One location of the old key in a run (§13.6 items 3-6; R41 rows 19, 27, 29). The CHECKs carry the
-- old-key rule: nothing is "removing" or "removed" without a verified and freshly re-verified new key,
-- and the re-verification is at most 15 minutes before the removal was sent.
CREATE TABLE rotation_locations (
    id                uuid PRIMARY KEY,
    rotation_id       uuid NOT NULL REFERENCES rotations (id),
    n                 integer NOT NULL CHECK (n BETWEEN 1 AND 10000),
    old_location_id   uuid NOT NULL REFERENCES ssh_key_locations (id),
    target_id         uuid NOT NULL REFERENCES targets (id),
    os_user           text NOT NULL CHECK (char_length(os_user) BETWEEN 1 AND 64),
    file_path         text NOT NULL CHECK (char_length(file_path) BETWEEN 1 AND 4096),
    options           text NOT NULL DEFAULT '' CHECK (char_length(options) <= 4096),
    verify_note       text NOT NULL DEFAULT '' CHECK (verify_note IN ('', 'root_login_disabled', 'from_option', 'login_without_key')),
    state             text NOT NULL CHECK (state IN ('planned', 'skipped', 'cancelled', 'adding', 'added', 'add_failed', 'verified',
                          'unverifiable', 'verify_failed', 'kept_old', 'removing', 'removed', 'remove_failed', 'undoing', 'undone',
                          'undo_failed')),
    skip_reason       text NOT NULL DEFAULT '' CHECK (skip_reason = '' OR skip_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    error_code        text NOT NULL DEFAULT '' CHECK (error_code = '' OR error_code ~ '^[a-z][a-z0-9_]{0,40}\.[a-z][a-z0-9_]{0,60}$'),
    add_op_id         uuid,
    add_sent_at       timestamptz,
    added_line_no     integer CHECK (added_line_no IS NULL OR added_line_no >= 1),
    new_location_id   uuid REFERENCES ssh_key_locations (id),
    verified_at       timestamptz,
    reverified_at     timestamptz,                 -- the latest fresh login before a removal
    remove_op_id      uuid,
    remove_verified_at timestamptz,                -- the fresh login the latest removal send relied on
    remove_sent_at    timestamptz,
    removed_at        timestamptz,
    undo_op_id        uuid,
    undo_sent_at      timestamptz,
    backup            text NOT NULL DEFAULT '' CHECK (char_length(backup) <= 200),
    job_count         integer NOT NULL DEFAULT 0 CHECK (job_count BETWEEN 0 AND 1000),
    updated_at        timestamptz NOT NULL,
    UNIQUE (rotation_id, n),
    UNIQUE (rotation_id, old_location_id),
    CHECK (state <> 'skipped' OR skip_reason <> ''),
    CHECK (state NOT IN ('removing', 'removed') OR (verified_at IS NOT NULL AND remove_verified_at IS NOT NULL
                                                    AND remove_sent_at IS NOT NULL AND remove_op_id IS NOT NULL)),
    CHECK (remove_sent_at IS NULL OR (remove_verified_at IS NOT NULL AND remove_verified_at <= remove_sent_at
                                      AND remove_verified_at >= remove_sent_at - interval '15 minutes')),
    CHECK (remove_verified_at IS NULL OR verified_at IS NOT NULL),
    CHECK (removed_at IS NULL OR state = 'removed'),
    CHECK (state NOT IN ('undoing', 'undone', 'undo_failed') OR add_sent_at IS NOT NULL),
    CHECK (verified_at IS NULL OR add_sent_at IS NOT NULL)
);
CREATE INDEX rotation_locations_target ON rotation_locations (target_id);

-- A location may become "removing" only while its run is removing_old (and so removal_allowed), and
-- never for the platform key's fingerprint. Rows of a finished run do not change.
-- +goose StatementBegin
CREATE FUNCTION rotation_locations_guard() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    run_status text;
    allowed boolean;
    platform_fp text;
    old_fp text;
BEGIN
    SELECT r.status, r.removal_allowed, k.fingerprint_sha256 INTO run_status, allowed, old_fp
      FROM public.rotations r JOIN public.ssh_keys k ON k.id = r.old_ssh_key_id WHERE r.id = NEW.rotation_id;
    IF TG_OP = 'UPDATE' AND run_status IN ('completed', 'aborted', 'needs_attention', 'cancelled') THEN
        RAISE EXCEPTION 'a finished rotation''s locations cannot change' USING ERRCODE = 'Z1011';
    END IF;
    IF NEW.state = 'removing' AND (TG_OP = 'INSERT' OR OLD.state <> 'removing') THEN
        SELECT public_info->>'fingerprint' INTO platform_fp FROM public.credentials WHERE purpose = 'platform_ssh';
        IF run_status <> 'removing_old' OR NOT allowed OR old_fp = platform_fp THEN
            RAISE EXCEPTION 'the old key may be removed only while its rotation is removing it' USING ERRCODE = 'Z1011';
        END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER rotation_locations_guard BEFORE INSERT OR UPDATE ON rotation_locations
    FOR EACH ROW EXECUTE FUNCTION rotation_locations_guard();

-- The recorded steps of a run (§7.4 rotation_steps, §26.8 "recorded steps"), append-only.
CREATE TABLE rotation_steps (
    id          uuid PRIMARY KEY,
    rotation_id uuid NOT NULL REFERENCES rotations (id),
    n           integer NOT NULL CHECK (n >= 1),
    location_id uuid REFERENCES rotation_locations (id),
    name        text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{0,63}$'),
    status      text NOT NULL CHECK (status IN ('started', 'ok', 'failed', 'skipped')),
    at          timestamptz NOT NULL,
    params      jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 4096),
    UNIQUE (rotation_id, n)
);

GRANT UPDATE (download_count, last_downloaded_at, destroyed_at, ciphertext, nonce, wrapped_dek, key_version)
    ON managed_private_keys TO alice_app;
GRANT UPDATE (retired_at) ON ssh_keys TO alice_app;
GRANT SELECT, INSERT ON rotation_policies, rotations, rotation_locations, rotation_steps TO alice_app;
GRANT UPDATE (ssh_key_id, name, enabled, interval_days, overlap_minutes, notify_before_hours, new_key_type, next_run_at,
    preview_mailed_at, version, updated_at, deleted_at) ON rotation_policies TO alice_app;
GRANT UPDATE (new_ssh_key_id, status, paused_license, paused_at, awaiting_decision, decision_due_at, started_at, verified_at,
    overlap_until, reminder_sent_at, removal_allowed, continued_by, continued_at, renotified_at, finished_at, result_code,
    updated_at, version) ON rotations TO alice_app;
GRANT UPDATE (state, skip_reason, error_code, add_op_id, add_sent_at, added_line_no, new_location_id, verified_at,
    reverified_at, remove_op_id, remove_verified_at, remove_sent_at, removed_at, undo_op_id, undo_sent_at, backup, job_count,
    updated_at, verify_note) ON rotation_locations TO alice_app;

-- +goose Down
-- Needs a database without Phase 6 data (no ssh_key or ed25519 rows, no destroyed keys).
REVOKE UPDATE (retired_at) ON ssh_keys FROM alice_app;
REVOKE UPDATE (download_count, last_downloaded_at, destroyed_at, ciphertext, nonce, wrapped_dek, key_version)
    ON managed_private_keys FROM alice_app;
DROP TABLE rotation_steps;
DROP TRIGGER rotation_locations_guard ON rotation_locations;
DROP FUNCTION rotation_locations_guard();
DROP TABLE rotation_locations;
DROP TABLE rotations;
DROP TRIGGER rotation_policies_key_check ON rotation_policies;
DROP FUNCTION rotation_policies_check_key();
DROP TABLE rotation_policies;
DROP INDEX ssh_keys_rotated_from;
ALTER TABLE ssh_keys DROP CONSTRAINT ssh_keys_label_length, DROP CONSTRAINT ssh_keys_managed_is_not_platform,
    DROP CONSTRAINT ssh_keys_managed_has_private_key;
ALTER TABLE ssh_keys DROP COLUMN created_by, DROP COLUMN rotated_from, DROP COLUMN key_comment, DROP COLUMN private_key_id;
DROP TRIGGER managed_private_keys_guard ON managed_private_keys;
DROP FUNCTION managed_private_keys_guard();
ALTER TABLE managed_private_keys DROP CONSTRAINT managed_private_keys_destroyed;
ALTER TABLE managed_private_keys ALTER COLUMN ciphertext SET NOT NULL, ALTER COLUMN nonce SET NOT NULL,
    ALTER COLUMN wrapped_dek SET NOT NULL, ALTER COLUMN key_version SET NOT NULL;
ALTER TABLE managed_private_keys DROP COLUMN destroyed_at, DROP COLUMN last_downloaded_at, DROP COLUMN download_count;
ALTER TABLE managed_private_keys DROP CONSTRAINT managed_private_keys_ed25519_is_ssh, DROP CONSTRAINT managed_private_keys_ssh_types,
    DROP CONSTRAINT managed_private_keys_bits_check;
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_check
    CHECK ((algorithm = 'rsa' AND bits >= 2048) OR (algorithm = 'ecdsa' AND bits IN (256, 384)));
ALTER TABLE managed_private_keys DROP CONSTRAINT managed_private_keys_algorithm_check;
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_algorithm_check CHECK (algorithm IN ('rsa', 'ecdsa'));
ALTER TABLE managed_private_keys DROP CONSTRAINT managed_private_keys_owner_type_check;
ALTER TABLE managed_private_keys ADD CONSTRAINT managed_private_keys_owner_type_check CHECK (owner_type IN ('certificate', 'csr'));
```

Notes binding every task that writes these tables: the application role has no `UPDATE` on `ssh_keys.managed`, `private_key_id`, `rotated_from` or `is_platform_key` for generated keys beyond the Phase 3 grant (`is_platform_key`, `weak`), so a generated key's identity never changes; `rotations.plan`, `plan_digest`, `new_key_type`, `overlap_minutes`, `planned_for` and `notified_at` are fixed at insert (no grant): a re-plan is a new run.

### C3. `keymat` (Task 1)

```go
package keymat

type KeyType string

const (
	Ed25519   KeyType = "ed25519"
	RSA3072   KeyType = "rsa-3072"
	RSA4096   KeyType = "rsa-4096"
	ECDSAP256 KeyType = "ecdsa-p256"
)

func KeyTypes() []KeyType                       // the four, in this order (the UI's order; Ed25519 first and default)
func (t KeyType) Valid() bool
func TypeOf(algorithm string, bits int) KeyType // ("ed25519",256)→Ed25519, ("rsa",3072|4096), ("ecdsa",256); anything else → Ed25519

// Material is a freshly generated key. PKCS8 is the only clear private part; the caller zeroes it.
type Material struct {
	PKCS8           secrets.Plaintext
	PublicKey       string // authorized_keys form without comment: "ssh-ed25519 AAAA…"
	Fingerprint     string // ssh.FingerprintSHA256
	Algorithm       string // "ed25519" | "rsa" | "ecdsa" (managed_private_keys.algorithm)
	Bits            int    // 256, 3072, 4096, 256
	PublicKeySHA256 string // hex SHA-256 of the PKIX SubjectPublicKeyInfo DER (managed_private_keys.public_key_sha256)
}

func (Material) String() string; GoString; Format; MarshalJSON; LogValue // all print the fingerprint only

func Generate(rnd io.Reader, t KeyType) (Material, error)          // ErrKeyType for an invalid type
func PublicOf(pkcs8 secrets.Plaintext) (publicKey, fingerprint string, err error)
func OpenSSHFile(pkcs8 secrets.Plaintext, comment string, passphrase []byte) (secrets.Plaintext, error)
func Signer(pkcs8 secrets.Plaintext) (ssh.Signer, func(), error)   // release zeroes what it decoded
func Comment(label string, day time.Time) string                   // "alice:<slug>:<yyyy-mm-dd>"
func FromOption(list string) (string, error)                       // `from="a,b"` or ErrFromOption
func Line(options, publicKey, comment string) (string, error)      // ErrLine on any invalid part
func HasFromOption(options string) bool

const (
	MinPassphrase = 12
	MaxPassphrase = 1024
	MaxFromEntries = 16
)

var (
	ErrKeyType    = errors.New("keymat: unknown key type")
	ErrPassphrase = errors.New("keymat: the passphrase must be 12 to 1024 bytes")
	ErrFromOption = errors.New("keymat: from= must list IP addresses or networks")
	ErrLine       = errors.New("keymat: the authorized_keys line is not valid")
	ErrKeyData    = errors.New("keymat: the stored private key cannot be read")
)
```

### C4. `plan` (Task 2)

```go
package plan

// Key is the key a rotation replaces, as the planner needs it.
type Key struct {
	ID          uuid.UUID
	Fingerprint string
	PublicKey   string // "type base64"
	Label       string
	Managed     bool
	IsPlatform  bool
	Retired     bool
	KeyType     string // keymat type of the key itself ("ed25519", …)
}

// Target is the part of a server's state that decides skips.
type Target struct {
	ID                    uuid.UUID
	Name                  string
	Deleted               bool
	Status                string // inventory.Status*: "ok", "unreachable", "checking", "auth_failed", "pending_host_key", "host_key_changed", "disabled"
	ConnectionUser        string // inventory.Target.Username
	KeysManagedElsewhere  bool
	ManagedElsewhereUsers []string
	SSHDRead              bool
	SSHDUnreadUsers       []string
	PermitRootLogin       string // "yes", "no", "prohibit-password", "without-password", "forced-commands-only", "" (unknown)
	PubkeyAuthentication  string // "yes", "no", ""
	UID0Users             []string
}

// Location is one live or missing place of the key (inventory.KeyLocation).
type Location struct {
	ID                   uuid.UUID
	TargetID             uuid.UUID
	OSUser, FilePath     string
	Options, Comment     string
	Flags                []string
	Missing              bool
	IsAliceConnectionKey bool
}

type Input struct {
	Key            Key
	Locations      []Location
	Targets        map[uuid.UUID]Target
	Protected      []string // inventory.ProtectedFingerprints
	NewKeyType     string   // policy value: "same" or a keymat type
	OverlapMinutes int
	NewComment     string // keymat.Comment(label, planned day): display only, not in the digest
}

type Action struct {
	N            int
	LocationID   uuid.UUID
	TargetID     uuid.UUID
	TargetName   string
	OSUser       string
	FilePath     string
	Options      string
	Skip         string // "" = this location changes; otherwise a Skip* value
	Verify       bool   // a test login will be tried
	VerifyNote   string // "", "root_login_disabled", "from_option"
	RemoveLine   string // the old line (public): "[options ]<old public key> <old comment>"
	AddLine      string // the new line (public) with the new key shown as "<new-key-type> (new key)"
}

type Plan struct {
	KeyID       uuid.UUID
	Fingerprint string
	NewKeyType  string // resolved: never "same"
	Overlap     int    // minutes
	Actions     []Action
	Changes     int
	Skips       int
}

const (
	SkipTargetDeleted       = "target_deleted"
	SkipHostKeyUnconfirmed  = "host_key_unconfirmed"
	SkipHostKeyChanged      = "host_key_changed"
	SkipTargetNotConnected  = "target_not_connected" // unreachable, checking, auth_failed, disabled
	SkipKeysManagedElsewhere = "keys_managed_elsewhere"
	SkipSSHDUnreadable      = "sshd_unreadable"
	SkipConnectionAccount   = "connection_account"
	SkipMissing             = "missing"
	SkipCertAuthority       = "cert_authority"
	SkipSharedFile          = "shared_file_skipped"
	SkipPubkeyDisabled      = "pubkey_disabled"
)

var (
	ErrNotManaged       = errors.New("plan: the key was not generated by Alice")
	ErrOwnKey           = errors.New("plan: the key is Alice's own key")
	ErrRetired          = errors.New("plan: the key is retired")
	ErrNothingToRotate  = errors.New("plan: no location can change")
)

func Build(in Input) (Plan, error)
func (p Plan) Digest() string // 64 hex

// Timers (all UTC; boundaries are inclusive at the due instant).
func FirstRun(enabledAt time.Time, intervalDays int) time.Time
func NextRun(startedAt time.Time, intervalDays int) time.Time
func NoticeDue(nextRun time.Time, notifyBeforeHours int) time.Time
func PlannedFor(now, nextRun time.Time, notifyBeforeHours int) time.Time // max(nextRun, now + notify)
func OverlapUntil(verifiedAt time.Time, overlapMinutes int) time.Time
func Due(now, at time.Time) bool // !now.Before(at)
func ReminderDue(overlapUntil time.Time, overlapMinutes int) (time.Time, bool) // overlapUntil-24h when the overlap is longer than 48 h
func DecisionDue(waitingSince time.Time) time.Time // + 14 days
func Fresh(now, reverifiedAt time.Time) bool // reverifiedAt within 15 minutes before now (and not after now)
```

### C5. Provider framework additions (Tasks 3–4)

```go
// capability.go
CapKeyLogin Capability = "key_login" // VerifyKeyLogin; added to knownCapabilities; linuxssh and nginx advertise it

// types.go
type KeyLoginOutcome string

const (
	KeyLoginAccepted   KeyLoginOutcome = "accepted"   // the server authenticated Alice with exactly this key
	KeyLoginRefused    KeyLoginOutcome = "refused"    // the server answered that no authentication method is left
	KeyLoginUnprovable KeyLoginOutcome = "unprovable" // let in without the key, or no public-key method offered
)

// KeyLoginRequest asks for one test login (spec §13.4): a fresh connection to the target as OSUser,
// offering only Key, the target's pinned host key required; nothing is executed.
type KeyLoginRequest struct {
	OSUser string
	Key    CredentialSource
}

type KeyLoginResult struct{ Outcome KeyLoginOutcome }

// UserKeyFiles lists one account's candidate authorized_keys files as the helper resolved them
// (sshd's AuthorizedKeysFile order). At most 8 files per user, 200 users per result.
type UserKeyFiles struct {
	OSUser string   `json:"os_user"`
	Files  []string `json:"files"`
}

// DiscoveryResult gains:
KeyFiles []UserKeyFiles // the SSH half only; nil when SSH keys were not read

// AuthKeyResult gains:
LineNo int // AddAuthorizedKey: 1-based line number of the key's line in the new (or unchanged) file; 0 otherwise

// provider.go, Session gains:
// VerifyKeyLogin (CapKeyLogin) tries one login (KeyLoginRequest). A refused or unprovable login is an
// outcome with a nil error; a connection that fails (unreachable, timeout, host key changed or
// unconfirmed, address refused) is an error. It never changes any target state itself.
VerifyKeyLogin(ctx context.Context, req KeyLoginRequest) (KeyLoginResult, error)
```

`UnsupportedSession.VerifyKeyLogin` returns `ErrUnsupported`. The conformance op is `{"VerifyKeyLogin", CapKeyLogin, func(ctx, s) { return s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{}) }}`: an empty request is refused with a `*providers.Error` (`ssh.helper_refused`, param `field` `os_user`) before anything is sent.

The fake (`internal/providers/fake`) gains `Config.KeyLogin func(req providers.KeyLoginRequest) (providers.KeyLoginResult, error)` and `Config.Keys *KeyWorld`:

```go
// KeyWorld models authorized_keys files of several targets for rotation tests (safe for concurrent use).
type KeyWorld struct{ /* mu; files map[fileRef][]string; log []Event; fault func(FaultPoint) Fault; calls int */ }

func NewKeyWorld() *KeyWorld
func (w *KeyWorld) Put(target uuid.UUID, osUser, file string, lines ...string)  // a file's lines, verbatim
func (w *KeyWorld) Lines(target uuid.UUID, file string) []string                 // one file per (target, path), shared by its users
func (w *KeyWorld) Has(target uuid.UUID, file, fingerprint string) bool          // any line of that key in the file
func (w *KeyWorld) Events() []Event                                              // every call, in order
func (w *KeyWorld) SetFault(f func(FaultPoint) Fault)

type FaultPoint struct {
	N           int    // 1-based index over every Add, Remove and VerifyKeyLogin call of the world
	Method      string // "AddAuthorizedKey" | "RemoveAuthorizedKey" | "VerifyKeyLogin"
	Target      uuid.UUID
	OSUser      string
	FilePath    string
	Fingerprint string // remove: the key removed; add and login: the key added or offered
}

type Fault int

const (
	FaultNone        Fault = iota
	FaultRefuse            // add/remove: helper refusal before any change (ssh.helper_refused, definite); login: KeyLoginRefused
	FaultUnreachable       // nothing happens; ssh.unreachable (retryable, nothing sent)
	FaultAfterWrite        // add/remove: the change happens, then ssh.timeout (outcome uncertain); login: ssh.timeout
	FaultFileChanged       // add/remove: ssh.file_changed after 3 attempts (definite, nothing written)
	FaultUnprovable        // login only: KeyLoginUnprovable
	FaultHang              // block until ctx ends, then the change does NOT happen and ctx.Err is returned wrapped in ssh.timeout
)

type Event struct {
	FaultPoint
	Fault   Fault
	Changed bool
	Outcome providers.KeyLoginOutcome // logins
}
```

With `Keys` set, the fake's `ListAuthorizedKeys`, `AddAuthorizedKey`, `RemoveAuthorizedKey` and `VerifyKeyLogin` act on the world: add appends `req.Line` unless a line of its fingerprint is present (`LineNo` = the line's index + 1), remove deletes every line of `req.Fingerprint` and refuses `req.ProtectedFingerprints` with `sshkey.own_key_protected` (as linuxssh), login is accepted when any file of that target holds a line of the offered key for `req.OSUser` (the signer's fingerprint, read through `req.Key.SSHSigner` and released at once).

### C6. Inventory exports (Task 6)

```go
// keychange.go
// KeyChangeRefusal is the readiness rule every key change shares (RequestKeyRemoval, deploys, rotations):
// nil, or ErrNotFound (deleted), ErrHostKeyUnconfirmed (pending_host_key), ErrHostKeyChanged,
// ErrTargetDisabled (disabled), ErrKeysManagedElsewhere (server-wide or for osUser), ErrSSHDUnreadable
// (server-wide or for osUser). An unreachable, checking or auth_failed server is not refused here.
func KeyChangeRefusal(t Target, osUser string) error

func (s *Service) TargetTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (Target, error) // getTarget; ErrNotFound when deleted
func CheckClaimTx(ctx context.Context, tx pgx.Tx) error                                              // checkClaim
func ProtectedFingerprintsTx(ctx context.Context, tx pgx.Tx) ([]string, error)                       // protectedFingerprints
// KeyLocationsTx returns every location of the key that was not removed by Alice (missing ones
// included, Missing set), ordered by target id, file path, OS user; with lock, FOR UPDATE OF l.
func (s *Service) KeyLocationsTx(ctx context.Context, tx pgx.Tx, keyID uuid.UUID, lock bool) ([]KeyLocation, error)

// KeyAdded records a key line Alice added (a deploy or a rotation).
type KeyAdded struct {
	SSHKeyID, TargetID uuid.UUID
	OSUser, FilePath   string
	Options, Comment   string
	LineNo             int
	Actor              audit.Actor // its RequestID is the job id
	Verified           bool
}

// RecordKeyAddedTx upserts the location (as Reconcile's upsertLocation: missing_since and
// removed_by_alice_at cleared), records the connection (markConnected, reason "key_added") and appends
// audit sshkey.added. Refuses a protected fingerprint (ErrOwnKeyProtected).
func (s *Service) RecordKeyAddedTx(ctx context.Context, tx pgx.Tx, in KeyAdded) (uuid.UUID, error)

func ValidateReason(reason string) validate.Errors // the existing validateReason, exported

// types.go: Facts gains
KeyFiles []providers.UserKeyFiles `json:"key_files,omitempty"`
```

`MarkKeyRemoved` (existing) records a rotation's removal of an old location; its audit row (`sshkey.removed`) keeps its form.

### C7. `sshkeys` service (Tasks 7–9)

```go
package sshkeys

const (
	JobDeploy           = "sshkey.add"
	JobRotationLocation = "rotation.location"
	TaskPlan            = "rotation.plan"
	TaskSweep           = "rotation.sweep"
	TaskDestroyRetired  = "sshkey.destroy_retired"
)

type LicenseGate interface{ Allow(c license.Class) error }
type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}

// Inventory is the part of *inventory.Service this module uses.
type Inventory interface {
	TargetTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (inventory.Target, error)
	KeyLocationsTx(ctx context.Context, tx pgx.Tx, keyID uuid.UUID, lock bool) ([]inventory.KeyLocation, error)
	RecordKeyAddedTx(ctx context.Context, tx pgx.Tx, in inventory.KeyAdded) (uuid.UUID, error)
	MarkKeyRemoved(ctx context.Context, locationID uuid.UUID, actor audit.Actor, res providers.AuthKeyResult) error
	KeyLocation(ctx context.Context, id uuid.UUID) (inventory.KeyLocation, error)
}

type Config struct {
	Pool      *pgxpool.Pool
	Keyring   *secrets.Keyring
	Audit     *audit.Log
	Clock     clock.Clock
	License   LicenseGate
	Inventory Inventory
	Jobs      inventory.Enqueuer
	Notifier  Notifier // nil = no emails (tests only)
	Log       *slog.Logger
	Rand      io.Reader // Ed25519 seeds; nil = crypto/rand
}

func New(c Config) *Service

// ---- Task 7: keys, deploy, download, destruction ----
type GenerateInput struct {
	Label   string // 1-100 runes, validName rules (no control, format or bidi characters)
	KeyType string // keymat type; "" = ed25519
}

type ManagedKey struct {
	ID, PrivateKeyID         uuid.UUID
	Fingerprint, PublicKey   string
	KeyType                  string // keymat type
	Bits                     int
	Label, Comment           string
	CreatedBy                uuid.UUID
	CreatedAt                time.Time
	RetiredAt, DestroyedAt   *time.Time
	RotatedFrom              *uuid.UUID
	DownloadCount            int
	LastDownloadedAt         *time.Time
	PolicyID                 *uuid.UUID
	OpenRotationID           *uuid.UUID
}

func (s *Service) Generate(ctx context.Context, a inventory.Actor, in GenerateInput) (ManagedKey, error)
func (s *Service) ManagedKey(ctx context.Context, id uuid.UUID) (ManagedKey, error) // ErrNotManaged for a key Alice did not generate; ErrNotFound

type DeployInput struct {
	KeyID, TargetID  uuid.UUID
	OSUser, FilePath string
	From             string // "" or a comma list for keymat.FromOption
	Restrict         bool
}

func (s *Service) RequestDeploy(ctx context.Context, a inventory.Actor, in DeployInput) (uuid.UUID, error) // job id

// DeployJob is a validated sshkey.add payload, read again from the database when the job runs.
type DeployJob struct {
	KeyID, TargetID   uuid.UUID
	Fingerprint       string
	OSUser, FilePath  string
	Options, Comment  string
	Line              string
	Protected         []string // ProtectedFingerprints at the time the job runs
}

type DeployOutcome struct {
	Result   string // DeployVerified | DeployUnverified | DeployAlreadyPresent | DeployUndone | DeployFailed | DeployUndoFailed
	Reason   string // closed reason for the last three
	LineNo   int
	Backup   string
	Note     string // verify note for DeployUnverified: "from_option", "login_without_key", "root_login_disabled"
}

const (
	DeployVerified       = "verified"
	DeployUnverified     = "unverified"
	DeployAlreadyPresent = "already_present"
	DeployUndone         = "undone"
	DeployFailed         = "failed"
	DeployUndoFailed     = "undo_failed"
)

func (s *Service) DeployJob(ctx context.Context, jobID, targetID uuid.UUID, payload map[string]string) (DeployJob, error)
func (s *Service) FinishDeploy(ctx context.Context, actor audit.Actor, d DeployJob, out DeployOutcome) error
func (s *Service) KeySigner(keyID uuid.UUID) providers.CredentialSource // unseals per SSHSigner call; release zeroes
func (s *Service) ProtectedFingerprints(ctx context.Context) ([]string, error)

type DownloadInput struct {
	KeyID      uuid.UUID
	Reason     string
	Passphrase []byte // nil = unencrypted; the caller zeroes it
}

type Download struct {
	FileName string            // "alice-<slug>-<first 8 of fingerprint hash>.key", [a-z0-9.-] only
	Body     secrets.Plaintext // the OpenSSH file; the caller zeroes it after writing
}

func (s *Service) DownloadPrivateKey(ctx context.Context, a inventory.Actor, in DownloadInput) (Download, error)
func (s *Service) DestroyRetiredKeys(ctx context.Context) (int, error)

// ---- Task 8: policies, previews, planning, Run now ----
type PolicyInput struct {
	SSHKeyID          uuid.UUID
	Name              string
	IntervalDays      int    // 1..3650
	OverlapDays       int    // 0..90 → overlap_minutes = days * 1440
	NotifyBeforeHours int    // 1..168, 0 = 24
	NewKeyType        string // "same" (default) or a keymat type
}

type PolicyPatch struct { // nil = unchanged
	Name              *string
	IntervalDays      *int
	OverlapDays       *int
	NotifyBeforeHours *int
	NewKeyType        *string
}

type Policy struct {
	ID, SSHKeyID       uuid.UUID
	Name               string
	Enabled            bool
	IntervalDays       int
	OverlapMinutes     int
	NotifyBeforeHours  int
	NewKeyType         string
	NextRunAt          *time.Time
	OpenRotationID     *uuid.UUID
	Version            int
	CreatedAt, UpdatedAt time.Time
}

func (s *Service) CreatePolicy(ctx context.Context, a inventory.Actor, in PolicyInput) (Policy, error)
func (s *Service) UpdatePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, p PolicyPatch) (Policy, error)
func (s *Service) SetPolicyEnabled(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, enabled bool) (Policy, error)
func (s *Service) DeletePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int) error
func (s *Service) Policy(ctx context.Context, id uuid.UUID) (Policy, error)
func (s *Service) Policies(ctx context.Context) ([]Policy, error) // live ones, by name

type Preview struct {
	PolicyID   uuid.UUID
	Plan       plan.Plan
	Digest     string
	PlannedFor time.Time
	Emailed    bool
}

func (s *Service) Preview(ctx context.Context, a inventory.Actor, policyID uuid.UUID) (Preview, error)
func (s *Service) RunNow(ctx context.Context, a inventory.Actor, policyID uuid.UUID, digest string) (Rotation, error)
func (s *Service) PlanDue(ctx context.Context) (int, error) // rotation.plan

// ---- Task 9: runs, controller, sweep, decisions, runner-facing store ----
type Rotation struct {
	ID, PolicyID, OldKeyID uuid.UUID
	NewKeyID               *uuid.UUID
	OldFingerprint         string
	NewFingerprint         string
	Trigger, Status        string
	PausedLicense          bool
	AwaitingDecision       bool
	DecisionDueAt          *time.Time
	Plan                   plan.Plan
	Digest                 string
	NewKeyType             string
	OverlapMinutes         int
	PlannedFor, NotifiedAt time.Time
	StartedAt, VerifiedAt, OverlapUntil, FinishedAt *time.Time
	ResultCode             string
	Locations              []RotationLocation
	Steps                  []Step
	Version                int
}

type RotationLocation struct {
	ID, OldLocationID, TargetID uuid.UUID
	N                           int
	TargetName, OSUser, FilePath, Options string
	State, SkipReason, VerifyNote, ErrorCode, Backup string
	AddSentAt, VerifiedAt, ReverifiedAt, RemoveSentAt, RemovedAt *time.Time
	NewLocationID               *uuid.UUID
	AddOpID, RemoveOpID, UndoOpID uuid.UUID // uuid.Nil until the step began; a resumed job re-sends with the same id
}

type Step struct {
	N          int
	LocationID *uuid.UUID
	Name       string
	Status     string
	At         time.Time
	Params     map[string]string
}

type RotationFilter struct {
	PolicyID, KeyID uuid.UUID // uuid.Nil = any
	Cursor          string
	Limit           int // 1..200, default 50
}

func (s *Service) Rotation(ctx context.Context, id uuid.UUID) (Rotation, error)
func (s *Service) Rotations(ctx context.Context, f RotationFilter) ([]Rotation, string, error) // without Steps

// Decisions (each takes the run's version from If-Match-free action bodies: none; they act on the current state).
func (s *Service) Continue(ctx context.Context, a inventory.Actor, id uuid.UUID) error
func (s *Service) FinishNow(ctx context.Context, a inventory.Actor, id uuid.UUID) error
func (s *Service) KeepOld(ctx context.Context, a inventory.Actor, id uuid.UUID, locationIDs []uuid.UUID) error
func (s *Service) Abort(ctx context.Context, a inventory.Actor, id uuid.UUID) error

// Controller and sweep.
func (s *Service) Advance(ctx context.Context, id uuid.UUID) error
func (s *Service) Sweep(ctx context.Context) (SweepSummary, error)

type SweepSummary struct{ Advanced, Paused, Requeued, Failed int }

// Runner-facing store (Task 11 is the only caller). Every write is fenced to the job's claim
// (inventory.CheckClaimTx) and is a compare-and-set on the location's state.
type LocationWork struct {
	Rotation   Rotation          // without Steps
	Location   RotationLocation
	OldKeyID   uuid.UUID
	NewKeyID   uuid.UUID
	OldFingerprint, NewFingerprint string
	NewLine    string // the exact line to add: options, new public key, new comment
	Protected  []string
}

func (s *Service) LocationWork(ctx context.Context, locationID uuid.UUID) (LocationWork, error)
func (s *Service) BeginAdd(ctx context.Context, locationID uuid.UUID) (op uuid.UUID, err error)          // planned → adding
func (s *Service) FinishAdd(ctx context.Context, locationID uuid.UUID, r AddRecord) error                // adding → added | add_failed
func (s *Service) RecordVerify(ctx context.Context, locationID uuid.UUID, r VerifyRecord) error          // added|adding → verified | unverifiable | verify_failed
func (s *Service) RecordReverify(ctx context.Context, locationID uuid.UUID, r VerifyRecord) error        // verified|removing: reverified_at, or remove_failed (new_key_failed)
func (s *Service) BeginRemove(ctx context.Context, locationID uuid.UUID) (op uuid.UUID, err error)       // verified → removing
func (s *Service) FinishRemove(ctx context.Context, actor audit.Actor, locationID uuid.UUID, r RemoveRecord) error // removing → removed | remove_failed
func (s *Service) BeginUndo(ctx context.Context, locationID uuid.UUID) (op uuid.UUID, err error)         // any added-ish → undoing
func (s *Service) FinishUndo(ctx context.Context, actor audit.Actor, locationID uuid.UUID, r UndoRecord) error // undoing → undone | undo_failed
func (s *Service) Step(ctx context.Context, rotationID uuid.UUID, locationID *uuid.UUID, name string, status providers.StepStatus, params map[string]string) error

type AddRecord struct {
	Definite bool   // true: the add answered (added or refused); false: the outcome is uncertain (stays adding)
	Added    bool   // the line is in the file (changed or already present)
	LineNo   int
	Reason   string // when !Added and Definite
	Backup   string
	Actor    audit.Actor
}

type VerifyRecord struct {
	Outcome providers.KeyLoginOutcome // "" when Err is set
	Reason  string                    // closed reason of a connection failure
}

type RemoveRecord struct {
	Definite bool
	Removed  int
	Reason   string
	Backup   string
	Res      providers.AuthKeyResult
}

type UndoRecord struct {
	Definite bool
	Reason   string
	Res      providers.AuthKeyResult
}

// Errors of the store that the runner treats as "stop here, the controller decides" (no remote call is made):
var (
	ErrNotYourTurn = errors.New("sshkeys: the location is not in the state this step needs")
	ErrPaused      = errors.New("sshkeys: the rotation is paused or the license refuses changes")
)

func Templates() []string // every email template of this module (render tests)
```

Errors (`errors.go`), each mapped by the API (C11):

```go
var (
	ErrNotFound          = inventory.ErrNotFound
	ErrNotManaged        = errors.New("sshkeys: Alice holds no private key for this key")
	ErrRetired           = errors.New("sshkeys: the key is retired")
	ErrDestroyed         = errors.New("sshkeys: the private key was destroyed")
	ErrConnectionAccount = errors.New("sshkeys: Alice does not change its connection account's keys")
	ErrNotAKeyFile       = errors.New("sshkeys: the file is not one of the user's key files")
	ErrGenerateBusy      = errors.New("sshkeys: too many keys are being generated")
	ErrPolicyExists      = errors.New("sshkeys: the key already has a rotation policy")
	ErrRotationInProgress = errors.New("sshkeys: a rotation of this key is running")
	ErrPlanChanged       = errors.New("sshkeys: the plan changed since the preview")
	ErrNothingToRotate   = errors.New("sshkeys: no location can change")
	ErrNotWaiting        = errors.New("sshkeys: the rotation is not waiting for this action")
	ErrVersionMismatch   = inventory.ErrVersionMismatch
	ErrOwnKeyProtected   = inventory.ErrOwnKeyProtected
)
```

### C8. Rotation state machine (Tasks 9 and 11)

Run statuses (`rotations.status`) and who moves them; `G` = `license.Allow(ClassChange) == nil`; `P` = `paused_license`.

| From | Event (who) | To | Conditions and effects |
|---|---|---|---|
| (new) | `PlanDue` (task) or `RunNow` (Admin) | `dry_run_notified` | plan built and its digest stored; locations inserted (`planned` or `skipped`); notice `rotation.preview` queued; audit `rotation.created`; refused with `ErrNothingToRotate` when no action changes |
| `dry_run_notified` | `Advance`, `¬G` | `cancelled` | result `rotation.cancelled_license`; audit; email none (L-88: the policy previews again after the renewal) |
| `dry_run_notified` | `Advance`, `G`, `now ≥ planned_for`, re-plan digest differs | `cancelled` | result `rotation.plan_changed`; `PlanDue` previews again at its next tick |
| `dry_run_notified` | `Advance`, `G`, `now ≥ planned_for`, digest equal | `adding_new` | new key generated (`keymat.Generate`, slot) and stored (`ssh_keys` managed, `rotated_from` = old, label = old label, comment `keymat.Comment(label, start day)`); `started_at`; enabled policy: `next_run_at = plan.NextRun(started_at, interval)`; audit `rotation.status_changed`; `rotation.location` jobs (phase `add`) queued for every `planned` location |
| `dry_run_notified` | `SetPolicyEnabled(false)`, `DeletePolicy` | `cancelled` | result `rotation.policy_off` |
| `dry_run_notified` | `Abort` | `cancelled` | result `rotation.stopped` |
| `adding_new` | `Advance`, any location `add_failed` or `verify_failed` | `rolling_back` | result `rotation.add_failed` or `rotation.verify_failed` (the first failure's); `planned` locations → `cancelled`; `undo` jobs for every location with `add_sent_at` |
| `adding_new` | `Advance`, `¬G` and a `planned` location exists | (same) + `P` | pause (L-85): audit `rotation.paused`, email `rotation.paused_license` once |
| `adding_new` | `Advance`, all non-skipped locations `verified`/`unverifiable` | `overlap` or `verifying_new` | no `unverifiable`: `verified_at = now`, `overlap_until = now + overlap`, email `rotation.overlap_started`; with `unverifiable`: `awaiting_decision`, `decision_due_at = now + 14 d`, email `rotation.decision_needed` |
| `verifying_new` | `KeepOld` (Admin) on every `unverifiable` location | `overlap` | those locations and every other location of the run in the same `(target, file)` become `kept_old`; at least one `verified` must remain (else `ErrNotWaiting`, nothing changed); as above |
| `verifying_new` | `Advance`, `G`, `now ≥ decision_due_at` | `rolling_back` | result `rotation.decision_timeout` |
| `overlap` | `Advance`, `now ≥ reminder` (overlap > 48 h) | (same) | email `rotation.overlap_ending` once (`reminder_sent_at`) |
| `overlap` | `Advance` or `FinishNow`, `now ≥ overlap_until`, `¬P`, `¬G` | (same) + `P` | L-83: nothing removed; pause email |
| `overlap` | `Advance`, `now ≥ overlap_until`, `¬P`, `G` | `removing_old` | `removal_allowed = true`; `remove` jobs for every `verified` location |
| `overlap`, `adding_new`, `verifying_new` | `Abort` (Admin) | `rolling_back` | result `rotation.stopped` |
| any started, `P` | `Continue` (Admin, `G`) | (same), `¬P` | `continued_by/at`, `renotified_at`, email `rotation.preview_after_license` in the same transaction (L-84); then `Advance` |
| `removing_old` | `Advance`, `¬G` with a `verified` location left | (same) + `P` | in-flight removals finish; no new one |
| `removing_old` | `Advance`, every `verified` location ended | `completed` or `needs_attention` | all `removed` (or `kept_old`/`skipped` elsewhere): `completed`, policy moves to the new key, old key retired when it has no live location (`sshkey.retired`), email `rotation.completed`; any `remove_failed`: `needs_attention`, result `rotation.remove_incomplete`, email `rotation.needs_attention` |
| `rolling_back` | `Advance`, every undo ended | `aborted` or `needs_attention` | all `undone` (or never added): `aborted` (keeps the earlier result), email `rotation.aborted`; any `undo_failed`: `needs_attention`, result `rotation.undo_failed` |

Location states (`rotation_locations.state`):

| From | Step (who) | To | Rule |
|---|---|---|---|
| `planned` | `BeginAdd` (job) | `adding` | run `adding_new`, `¬P`, `G`, the target passes `KeyChangeRefusal`; sets `add_op_id` (new UUIDv7), `add_sent_at = now` **before** the add is sent; else `ErrPaused` (gate, pause) or `ErrNotYourTurn` |
| `adding` | `FinishAdd{Definite, Added}` | `added` | records `added_line_no`, `backup`, the new location (`RecordKeyAddedTx`, `Verified=false`) |
| `adding` | `FinishAdd{Definite, ¬Added}` | `add_failed` | `error_code` = reason (nothing written) |
| `adding` | `FinishAdd{¬Definite}` | `adding` | uncertain: the job goes on to verify, which resolves it |
| `adding`/`added` | `RecordVerify{accepted}` | `verified` | `verified_at = now` |
| `adding`/`added` | `RecordVerify{unprovable}` or `{refused}` with `from=` | `unverifiable` | `verify_note` `login_without_key` or `from_option`; a note the plan already set (`root_login_disabled`, `from_option`) is kept |
| `added` | `RecordVerify{refused}` without `from=`, or a connection failure | `verify_failed` | `error_code` `sshkey.login_failed` or the connection reason |
| `adding` | `RecordVerify{refused}` (uncertain add) | `adding` once, then `verify_failed` | the job re-sends the add once (idempotent) when `G`; otherwise `verify_failed` |
| `planned` (planned `Verify=false`) | after `added` | `unverifiable` | `verify_note` `root_login_disabled`, no login tried |
| `planned` | run stops | `cancelled` | never touched |
| `verified` | `RecordReverify{accepted}` | `verified` | `reverified_at = now` |
| `verified` | `RecordReverify{refused/unprovable/err}` | `remove_failed` | `error_code` `rotation.new_key_failed`; the old key stays |
| `verified` | `BeginRemove` (job) | `removing` | run `removing_old`, `¬P`, `G`, `plan.Fresh(now, reverified_at)`, every location of the run in the same `(target, file)` is `verified` or `removing`/`removed`, the old key's fingerprint is not protected; sets `remove_op_id` (new UUIDv7), `remove_verified_at = reverified_at`, `remove_sent_at = now` **before** the removal is sent; database CHECK and trigger again |
| `removing` | `FinishRemove{Definite}` | `removed` or `remove_failed` | `removed_at`; `MarkKeyRemoved(old_location_id)` when the provider removed lines |
| `removing` | `FinishRemove{¬Definite}` | `removing` | resumed by a later job: `RecordReverify` (fresh login), then `BeginRemove` again (it accepts `removing`, sets a new `remove_verified_at`/`remove_sent_at`, keeps `remove_op_id`), then the removal is re-sent (idempotent by fingerprint); a refused re-verify ends `remove_failed` (`rotation.new_key_failed`) |
| `adding`/`added`/`verified`/`unverifiable`/`verify_failed`/`add_failed` (with `add_sent_at`)/`kept_old` (only on Abort before overlap end) | `BeginUndo` | `undoing` | always allowed (L-86), never for the old key: the undo removes the **new** fingerprint |
| `undoing` | `FinishUndo` | `undone` or `undo_failed` | — |

Ordering rule for every transaction that ends a run: location rows change first (`planned` → `cancelled`, …), the run's status last (the location trigger refuses changes to a finished run's rows). Every status change appends one audit row `rotation.status_changed` (`rotation_id`, `from`, `to`, `reason`) and one step (`name` = the new status, `status` `ok`); every location change appends `rotation.location_changed` (`rotation_id`, `location_id`, `target_id`, `os_user`, `file_path`, `from`, `to`, `reason`) and a step.

A location job that finds a state not listed for its phase records nothing and ends successfully (`ErrNotYourTurn`); the sweep re-queues a job (dedupe) for every location in `adding`, `added`, `removing`, `undoing`, and for `planned` (run `adding_new`, `¬P`), `verified` (run `removing_old`, `¬P`) and undo-pending locations (run `rolling_back`) without a live job, at most `MaxLocationJobs` times per location and phase, after which the location ends `add_failed`, `remove_failed` or `undo_failed` with `rotation.retries_exhausted`.

### C9. Job handlers (Tasks 10–11)

```go
package sshkeyjobs

// Keys is the part of *sshkeys.Service the handlers use.
type Keys interface {
	DeployJob(ctx context.Context, jobID, targetID uuid.UUID, payload map[string]string) (sshkeys.DeployJob, error)
	FinishDeploy(ctx context.Context, actor audit.Actor, d sshkeys.DeployJob, out sshkeys.DeployOutcome) error
	KeySigner(keyID uuid.UUID) providers.CredentialSource
	ProtectedFingerprints(ctx context.Context) ([]string, error)
	LocationWork(ctx context.Context, locationID uuid.UUID) (sshkeys.LocationWork, error)
	BeginAdd(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error)
	FinishAdd(ctx context.Context, locationID uuid.UUID, r sshkeys.AddRecord) error
	RecordVerify(ctx context.Context, locationID uuid.UUID, r sshkeys.VerifyRecord) error
	RecordReverify(ctx context.Context, locationID uuid.UUID, r sshkeys.VerifyRecord) error
	BeginRemove(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error)
	FinishRemove(ctx context.Context, actor audit.Actor, locationID uuid.UUID, r sshkeys.RemoveRecord) error
	BeginUndo(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error)
	FinishUndo(ctx context.Context, actor audit.Actor, locationID uuid.UUID, r sshkeys.UndoRecord) error
	Step(ctx context.Context, rotationID uuid.UUID, locationID *uuid.UUID, name string, status providers.StepStatus, params map[string]string) error
	Advance(ctx context.Context, rotationID uuid.UUID) error
}

// Targets is the part of *inventory.Service the handlers use to open sessions (as targetjobs).
type Targets interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
	RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error
}

type Deps struct {
	Keys     Keys
	Targets  Targets
	Registry *providers.Registry
	Clock    clock.Clock
	Log      *slog.Logger
}

func Register(r *jobs.Runner, d Deps) // panics on a missing dependency; handles jobs.SSHKeyAdd and jobs.RotationLocation
```

`sshkey.add` decision table (one job = one location; `wrote` = the provider reported the write step `started`, as `targetjobs.writeTracker`):

| Provider answer | Login | Outcome | Job |
|---|---|---|---|
| add refused before writing (`writeRefused`, `!wrote`) | — | `failed`, reason = provider code | `jobs.Fail(reason)` (or `Retry` for `ssh.unreachable`/`ssh.timeout` before the write) |
| `Changed=false` (already present) | accepted | `already_present` | success |
| `Changed=false` | refused/unprovable | `already_present` with note | success (Alice did not add it, so never removes it) |
| `Changed=true`, `Verified` read-back | accepted | `verified` | success |
| `Changed=true` | unprovable, or refused with `from=` | `unverified` (note) | success |
| `Changed=true` | refused without `from=` | remove the new fingerprint: removed → `undone`, reason `sshkey.login_failed`; removal failed → `undo_failed`, reason `sshkey.add_undo_failed` | `jobs.Fail("sshkey.login_failed")` / `jobs.Attention("sshkey.add_undo_failed")` |
| write sent, outcome uncertain (`wrote`, error) | accepted | `verified` (the line is there) | success |
| write sent, outcome uncertain | refused/unprovable or connection error | remove the new fingerprint as above | as above |
| `Changed=true`, read-back differs (`!Verified`) | any | remove the new fingerprint as above, reason `sshkey.verify_failed` | `jobs.Attention("sshkey.verify_failed")` when the undo failed, else `jobs.Fail` |

A connection failure of the platform-key session (`ssh.unreachable`, `ssh.auth_failed`, `target.host_key_changed`, …) is recorded on the target (`RecordConnectionFailure`) as `targetjobs` does; a test-login failure never is.

`rotation.location` (phase from the payload; every remote call is preceded by the store call that records it):

- `add`: `LocationWork`; state `planned` → `BeginAdd` (stop on `ErrPaused`/`ErrNotYourTurn`) → open the session → `AddAuthorizedKey{OperationID: op, Line: NewLine, OSUser, FilePath, ProtectedFingerprints}` → `FinishAdd` → (state `adding` or `added`) `VerifyKeyLogin{OSUser, KeySigner(NewKeyID)}` unless the plan said `Verify=false` → `RecordVerify` → `Advance`. An uncertain add whose login is refused is re-sent once when the gate allows (`AddAuthorizedKey` is idempotent by fingerprint), then verified again; otherwise `RecordVerify` records `verify_failed`.
- `remove`: state `verified` or `removing` → `VerifyKeyLogin` with the new key → `RecordReverify` (a failed login ends the location `remove_failed`, `rotation.new_key_failed`) → `BeginRemove` → `RemoveAuthorizedKey{OperationID: op, Fingerprint: OldFingerprint, ProtectedFingerprints, AllowLastRootKey: false}` → `FinishRemove` → `Advance`.
- `undo`: state with `add_sent_at` → `BeginUndo` → `RemoveAuthorizedKey{Fingerprint: NewFingerprint, AllowLastRootKey: false}` → `FinishUndo` → `Advance`. An undo never asks the gate.
- Opening a session fails before anything was sent: phase `add` → `FinishAdd{Definite, Added: false, Reason}`; phase `remove` → `FinishRemove{Definite, Removed: 0, Reason}` (`remove_failed`, old key kept); phase `undo` → `FinishUndo{Definite: true, Reason}` (`undo_failed`).
- The handler returns `nil` after recording an outcome; it returns `jobs.Retry("internal.unexpected", …)` only when a store write fails before any remote call of this run, so the queue's attempts never repeat a remote change blindly.

### C10. Emails (Tasks 8–9; texts in `locales/common/{en,tr}.json` under `email.rotation.*`, Task 13)

All go to every Administrator (`NotifyAdmins`). Parameters are strings; times are formatted `2006-01-02 15:04 UTC`. `code` is the ALC code of the run's result.

| Template | Params | EN subject | EN body | TR subject | TR body |
|---|---|---|---|---|---|
| `rotation.preview` | `key_label`, `fingerprint`, `planned_for`, `change_count`, `skip_count` | `Planned SSH key rotation: {{key_label}}` | `Alice will rotate the SSH key {{key_label}} ({{fingerprint}}) at {{planned_for}}.\n\nIt will add a new key next to the old one, check that the new key works, keep both keys for the overlap, then remove the old key. Nothing is removed where the new key did not work.\n\nPlaces that will change: {{change_count}}. Places that will be skipped: {{skip_count}}.\n\nOpen the key's page in Alice to see the exact servers, users and files. To stop this run, switch the policy off before it starts.` | `Planlanan SSH anahtarı yenilemesi: {{key_label}}` | `Alice, {{key_label}} ({{fingerprint}}) SSH anahtarını şu zamanda yenileyecek: {{planned_for}}.\n\nEski anahtarın yanına yeni bir anahtar ekleyecek, yeni anahtarın çalıştığını denetleyecek, geçiş süresince iki anahtarı da tutacak ve ardından eski anahtarı kaldıracak. Yeni anahtarın çalışmadığı yerlerde hiçbir şey kaldırılmaz.\n\nDeğişecek yer sayısı: {{change_count}}. Atlanacak yer sayısı: {{skip_count}}.\n\nSunucuları, kullanıcıları ve dosyaları tam olarak görmek için Alice'te anahtarın sayfasını açın. Bu çalıştırmayı durdurmak için başlamadan önce kuralı kapatın.` |
| `rotation.preview_after_license` | `key_label`, `fingerprint`, `change_count` | `SSH key rotation continues after the license renewal: {{key_label}}` | `An administrator chose to continue the rotation of the SSH key {{key_label}} ({{fingerprint}}), which was paused while the license was expired.\n\nBefore Alice removes the old key anywhere, it signs in with the new key again on that server. Where this fails, the old key stays.\n\nPlaces that will change: {{change_count}}. Open the rotation's page in Alice to see them.` | `SSH anahtarı yenilemesi lisans yenilemesinden sonra sürüyor: {{key_label}}` | `Bir yönetici, lisansın süresi dolduğu için duraklatılan {{key_label}} ({{fingerprint}}) SSH anahtarı yenilemesini sürdürmeyi seçti.\n\nAlice eski anahtarı bir yerden kaldırmadan önce o sunucuda yeni anahtarla yeniden oturum açar. Bu başarısız olursa eski anahtar yerinde kalır.\n\nDeğişecek yer sayısı: {{change_count}}. Bu yerleri görmek için Alice'te yenilemenin sayfasını açın.` |
| `rotation.overlap_started` | `key_label`, `new_fingerprint`, `overlap_until` | `New SSH key ready: {{key_label}}` | `The new key for {{key_label}} works on every server where Alice could check it (new fingerprint: {{new_fingerprint}}). The old and the new key are both valid until {{overlap_until}}. Then Alice removes the old key, after checking the new key once more.\n\nIf people or systems use this key outside Alice, an administrator can download the new private key now from the new key's page in Alice.` | `Yeni SSH anahtarı hazır: {{key_label}}` | `{{key_label}} için yeni anahtar, Alice'in denetleyebildiği her sunucuda çalışıyor (yeni parmak izi: {{new_fingerprint}}). Eski ve yeni anahtar şu zamana kadar geçerli: {{overlap_until}}. Ardından Alice, yeni anahtarı bir kez daha denetledikten sonra eski anahtarı kaldırır.\n\nBu anahtarı Alice dışında kullanan kişiler ya da sistemler varsa, bir yönetici yeni özel anahtarı şimdi Alice'te yeni anahtarın sayfasından indirebilir.` |
| `rotation.overlap_ending` | `key_label`, `overlap_until` | `The old SSH key will be removed soon: {{key_label}}` | `At {{overlap_until}} Alice removes the old key {{key_label}} from the servers, after checking the new key once more. If something still uses the old key, an administrator should download the new private key now.` | `Eski SSH anahtarı yakında kaldırılacak: {{key_label}}` | `Alice, {{overlap_until}} zamanında yeni anahtarı bir kez daha denetledikten sonra {{key_label}} eski anahtarını sunuculardan kaldıracak. Eski anahtarı hâlâ kullanan bir şey varsa, bir yönetici yeni özel anahtarı şimdi indirmelidir.` |
| `rotation.completed` | `key_label`, `new_fingerprint` | `SSH key rotation finished: {{key_label}}` | `Alice removed the old key {{key_label}} from every server where the new key works. The new key (fingerprint {{new_fingerprint}}) is now the key the policy rotates. Alice keeps the old private key, encrypted, for 30 days after the old key is no longer used anywhere, then destroys it.` | `SSH anahtarı yenilemesi tamamlandı: {{key_label}}` | `Alice, {{key_label}} eski anahtarını yeni anahtarın çalıştığı her sunucudan kaldırdı. Yeni anahtar (parmak izi {{new_fingerprint}}) artık kuralın yenilediği anahtardır. Alice eski özel anahtarı, eski anahtar hiçbir yerde kullanılmadığı andan sonra 30 gün şifreli olarak saklar ve ardından yok eder.` |
| `rotation.aborted` | `key_label`, `code` | `SSH key rotation undone: {{key_label}}` | `The rotation of {{key_label}} did not finish, so Alice removed the new key again where it had added it. The old key was not touched anywhere and keeps working.\n\nCode: {{code}}. The troubleshooting guide explains it, and the rotation's page in Alice shows each server's state.` | `SSH anahtarı yenilemesi geri alındı: {{key_label}}` | `{{key_label}} yenilemesi tamamlanmadı; bu nedenle Alice eklediği yerlerden yeni anahtarı yeniden kaldırdı. Eski anahtara hiçbir yerde dokunulmadı ve çalışmaya devam ediyor.\n\nKod: {{code}}. Sorun giderme kılavuzu bu kodu açıklar; Alice'te yenilemenin sayfası her sunucunun durumunu gösterir.` |
| `rotation.needs_attention` | `key_label`, `code` | `SSH key rotation needs attention: {{key_label}}` | `The rotation of {{key_label}} stopped with a problem a person must look at. Alice removed the old key only where the new key had just worked.\n\nCode: {{code}}. Open the rotation's page in Alice to see each server's state.` | `SSH anahtarı yenilemesi ilgi bekliyor: {{key_label}}` | `{{key_label}} yenilemesi, bir kişinin bakması gereken bir sorunla durdu. Alice eski anahtarı yalnızca yeni anahtarın az önce çalıştığı yerlerden kaldırdı.\n\nKod: {{code}}. Her sunucunun durumunu görmek için Alice'te yenilemenin sayfasını açın.` |
| `rotation.paused_license` | `key_label` | `SSH key rotation paused: {{key_label}}` | `The license has expired, so Alice paused the rotation of {{key_label}}. The old key stays in place and nothing is removed.\n\nAfter a valid license is uploaded, an administrator must choose Continue on the rotation's page.` | `SSH anahtarı yenilemesi duraklatıldı: {{key_label}}` | `Lisansın süresi dolduğu için Alice {{key_label}} yenilemesini duraklattı. Eski anahtar yerinde kalır ve hiçbir şey kaldırılmaz.\n\nGeçerli bir lisans yüklendikten sonra bir yöneticinin yenilemenin sayfasında Devam et'i seçmesi gerekir.` |
| `rotation.decision_needed` | `key_label`, `count`, `decision_due` | `SSH key rotation waits for a decision: {{key_label}}` | `Alice added the new key for {{key_label}} but could not test a login with it in some places (count: {{count}}). On the rotation's page, decide whether to keep the old key there or to stop and undo the rotation. Without a decision Alice undoes the rotation at {{decision_due}}.` | `SSH anahtarı yenilemesi bir karar bekliyor: {{key_label}}` | `Alice {{key_label}} için yeni anahtarı ekledi ancak bazı yerlerde anahtarla oturum açmayı deneyemedi (sayı: {{count}}). Yenilemenin sayfasında, eski anahtarın oralarda kalmasına mı yoksa yenilemenin durdurulup geri alınmasına mı karar verin. Karar verilmezse Alice yenilemeyi şu zamanda geri alır: {{decision_due}}.` |

### C11. Error catalogue (Task 13; `internal/api/errors.go`, `locales/common/{en,tr}.json` `errors.<reason>`, `docs/troubleshooting.md`)

| Code | Reason | HTTP | Retryable |
|---|---|---|---|
| `ALC-KEY-0006` | `sshkey.not_managed` | 409 | no |
| `ALC-KEY-0007` | `sshkey.retired` | 409 | no |
| `ALC-KEY-0008` | `sshkey.private_key_destroyed` | 410 | no |
| `ALC-KEY-0009` | `sshkey.connection_account` | 409 | no |
| `ALC-KEY-0010` | `sshkey.login_failed` | 502 | no |
| `ALC-KEY-0011` | `sshkey.generate_busy` | 503 | yes |
| `ALC-KEY-0012` | `sshkey.add_undo_failed` | 502 | no |
| `ALC-KEY-0013` | `sshkey.not_a_key_file` | 409 | no |
| `ALC-ROT-0001` | `rotation.policy_exists` | 409 | no |
| `ALC-ROT-0002` | `rotation.in_progress` | 409 | no |
| `ALC-ROT-0003` | `rotation.plan_changed` | 409 | no |
| `ALC-ROT-0004` | `rotation.nothing_to_rotate` | 409 | no |
| `ALC-ROT-0005` | `rotation.not_waiting` | 409 | no |
| `ALC-ROT-0006` | `rotation.add_failed` | 502 | no |
| `ALC-ROT-0007` | `rotation.verify_failed` | 502 | no |
| `ALC-ROT-0008` | `rotation.undo_failed` | 502 | no |
| `ALC-ROT-0009` | `rotation.remove_incomplete` | 502 | no |
| `ALC-ROT-0010` | `rotation.decision_timeout` | 409 | no |
| `ALC-ROT-0011` | `rotation.paused_license` | 409 | no |
| `ALC-ROT-0012` | `rotation.cancelled_license` | 409 | no |
| `ALC-ROT-0013` | `rotation.stopped` | 409 | no |
| `ALC-ROT-0014` | `rotation.policy_off` | 409 | no |
| `ALC-ROT-0015` | `rotation.new_key_failed` | 502 | no |
| `ALC-ROT-0016` | `rotation.retries_exhausted` | 502 | no |

Texts (title / cause / action):

| Reason | EN | TR |
|---|---|---|
| `sshkey.not_managed` | Alice holds no private key for this key. / Only keys generated in Alice can be deployed, downloaded or rotated. Keys found on servers and Alice's own connection key are only listed. / Generate a new key in Alice and use that one instead. | Alice bu anahtarın özel anahtarını tutmuyor. / Yalnızca Alice'te oluşturulan anahtarlar dağıtılabilir, indirilebilir ya da yenilenebilir. Sunucularda bulunan anahtarlar ve Alice'in kendi bağlantı anahtarı yalnızca listelenir. / Alice'te yeni bir anahtar oluşturup onun yerine onu kullanın. |
| `sshkey.retired` | This key was replaced by a rotation and is no longer used. / A finished rotation retired it. Alice keeps its private key for 30 days for emergencies, then destroys it. / Use the newer key shown on this page. | Bu anahtar bir yenilemeyle değiştirildi ve artık kullanılmıyor. / Tamamlanan bir yenileme onu kullanımdan kaldırdı. Alice özel anahtarını acil durumlar için 30 gün saklar, sonra yok eder. / Bu sayfada gösterilen yeni anahtarı kullanın. |
| `sshkey.private_key_destroyed` | The private key of this key was destroyed. / Alice destroys the private key of a retired key 30 days after it was retired. / Use the newer key. Backups made before the destruction still contain it in encrypted form. | Bu anahtarın özel anahtarı yok edildi. / Alice, kullanımdan kaldırılan bir anahtarın özel anahtarını kaldırıldıktan 30 gün sonra yok eder. / Yeni anahtarı kullanın. Yok etmeden önce alınan yedeklerde şifreli olarak hâlâ bulunur. |
| `sshkey.connection_account` | Alice does not change the keys of the account it connects with. / The setup script owns that account's key file and rewrites it whenever it runs. / Choose another user on the server. | Alice bağlandığı hesabın anahtarlarını değiştirmez. / Bu hesabın anahtar dosyası kurulum betiğine aittir ve betik her çalıştığında yeniden yazılır. / Sunucuda başka bir kullanıcı seçin. |
| `sshkey.login_failed` | The server did not accept a login with the new key. / The key is in the file, but the SSH server refused it: the account may be locked, the server may read another file for this user, or a setting such as AllowUsers leaves the account out. / Check the account and the SSH server settings for this user, then try again. Alice removed the key it had added. | Sunucu yeni anahtarla oturum açılmasını kabul etmedi. / Anahtar dosyada, ancak SSH sunucusu onu reddetti: hesap kilitli olabilir, sunucu bu kullanıcı için başka bir dosya okuyor olabilir ya da AllowUsers gibi bir ayar hesabı dışarıda bırakıyor olabilir. / Bu kullanıcının hesabını ve SSH sunucu ayarlarını denetleyip yeniden deneyin. Alice eklediği anahtarı kaldırdı. |
| `sshkey.generate_busy` | Alice is busy generating other keys. / Generating an RSA key takes a few seconds, so Alice generates at most two keys at a time. / Try again in a moment. | Alice şu anda başka anahtarlar oluşturuyor. / Bir RSA anahtarı oluşturmak birkaç saniye sürer; bu nedenle Alice aynı anda en çok iki anahtar oluşturur. / Birazdan yeniden deneyin. |
| `sshkey.add_undo_failed` | Alice could not remove the key again after a failed check. / Alice added the key, the check after it failed, and removing the key failed as well (for example, the server could not be reached). / When the server can be reached, remove the key from this server on the key's page. | Başarısız bir denetimden sonra Alice anahtarı yeniden kaldıramadı. / Alice anahtarı ekledi, ardından yapılan denetim başarısız oldu ve anahtarı kaldırma da başarısız oldu (örneğin sunucuya ulaşılamadı). / Sunucuya ulaşılabildiğinde anahtarı, anahtarın sayfasından bu sunucudan kaldırın. |
| `sshkey.not_a_key_file` | This file is not one of the user's key files. / Alice adds keys only to the files the SSH server reads for that user, as the last scan found them. / Scan the server again, then choose one of the files offered. | Bu dosya kullanıcının anahtar dosyalarından biri değil. / Alice anahtarları yalnızca SSH sunucusunun o kullanıcı için okuduğu dosyalara, son taramada bulunduğu biçimiyle ekler. / Sunucuyu yeniden tarayıp sunulan dosyalardan birini seçin. |
| `rotation.policy_exists` | This key already has a rotation policy. / Each key has at most one rotation policy. / Change the existing policy on the key's page. | Bu anahtarın zaten bir yenileme kuralı var. / Her anahtarın en çok bir yenileme kuralı olabilir. / Anahtarın sayfasında mevcut kuralı değiştirin. |
| `rotation.in_progress` | A rotation of this key is already running. / Only one rotation runs for a key at a time, and a policy with a running rotation cannot be deleted. / Wait for the rotation to finish, or stop it on its page. | Bu anahtarın bir yenilemesi zaten çalışıyor. / Bir anahtar için aynı anda yalnızca bir yenileme çalışır ve yenilemesi süren bir kural silinemez. / Yenilemenin bitmesini bekleyin ya da sayfasında durdurun. |
| `rotation.plan_changed` | The servers or keys changed since the preview. / A rotation runs only exactly as it was previewed, and something changed since then. / Open the preview again, check it, and start the rotation from there. | Önizlemeden bu yana sunucular ya da anahtarlar değişti. / Bir yenileme yalnızca önizlendiği gibi çalışır ve o zamandan bu yana bir şey değişti. / Önizlemeyi yeniden açıp denetleyin ve yenilemeyi oradan başlatın. |
| `rotation.nothing_to_rotate` | No server can take part in this rotation. / Every place where the key is used is skipped. The preview shows the reason for each. / Fix the reasons shown in the preview, scan the servers again, then try again. | Bu yenilemeye hiçbir sunucu katılamıyor. / Anahtarın kullanıldığı her yer atlanıyor. Önizleme her birinin nedenini gösterir. / Önizlemede gösterilen nedenleri giderin, sunucuları yeniden tarayın ve yeniden deneyin. |
| `rotation.not_waiting` | This rotation is not waiting for that action. / The rotation has moved on, or the action does not apply in its current state. / Reload the page to see the current state. | Bu yenileme bu işlemi beklemiyor. / Yenileme ilerledi ya da işlem şu anki durumunda geçerli değil. / Şu anki durumu görmek için sayfayı yeniden yükleyin. |
| `rotation.add_failed` | Alice could not add the new key on a server, so it undid the rotation. / A server refused the change or could not be reached. The old key was not touched anywhere. / See the failed server on the rotation's page, fix the problem, then start the rotation again. | Alice yeni anahtarı bir sunucuya ekleyemedi; bu nedenle yenilemeyi geri aldı. / Bir sunucu değişikliği reddetti ya da sunucuya ulaşılamadı. Eski anahtara hiçbir yerde dokunulmadı. / Başarısız sunucuyu yenilemenin sayfasında görün, sorunu giderin ve yenilemeyi yeniden başlatın. |
| `rotation.verify_failed` | The new key did not work on a server, so Alice undid the rotation. / Alice could not sign in with the new key there. The old key was not touched anywhere. / See the server on the rotation's page, check its SSH settings for that user, then start the rotation again. | Yeni anahtar bir sunucuda çalışmadı; bu nedenle Alice yenilemeyi geri aldı. / Alice orada yeni anahtarla oturum açamadı. Eski anahtara hiçbir yerde dokunulmadı. / Sunucuyu yenilemenin sayfasında görün, o kullanıcı için SSH ayarlarını denetleyin ve yenilemeyi yeniden başlatın. |
| `rotation.undo_failed` | Alice could not remove the new key from every server. / Undoing the rotation failed on the servers listed on its page (for example, they could not be reached). The old key was not touched; the unused new key does no harm but should be removed. / When those servers can be reached, remove the new key from them on the new key's page. | Alice yeni anahtarı her sunucudan kaldıramadı. / Yenilemeyi geri alma, sayfasında listelenen sunucularda başarısız oldu (örneğin onlara ulaşılamadı). Eski anahtara dokunulmadı; kullanılmayan yeni anahtar zarar vermez ancak kaldırılmalıdır. / Bu sunuculara ulaşılabildiğinde yeni anahtarı yeni anahtarın sayfasından kaldırın. |
| `rotation.remove_incomplete` | The old key was kept on some servers. / Before removing the old key, Alice checks the new key again. On the servers listed, that check or the removal failed, so the old key stays there. / Check those servers, then remove the old key from them on the old key's page. | Eski anahtar bazı sunucularda tutuldu. / Alice eski anahtarı kaldırmadan önce yeni anahtarı yeniden denetler. Listelenen sunucularda bu denetim ya da kaldırma başarısız oldu; bu nedenle eski anahtar orada kalır. / Bu sunucuları denetleyin, ardından eski anahtarı eski anahtarın sayfasından bu sunuculardan kaldırın. |
| `rotation.decision_timeout` | No decision was made within 14 days, so Alice undid the rotation. / Alice could not test the new key in some places and waited 14 days for an administrator. / Start the rotation again and decide about the places Alice cannot test. | 14 gün içinde karar verilmedi; bu nedenle Alice yenilemeyi geri aldı. / Alice yeni anahtarı bazı yerlerde deneyemedi ve 14 gün boyunca bir yöneticiyi bekledi. / Yenilemeyi yeniden başlatın ve Alice'in deneyemediği yerler için karar verin. |
| `rotation.paused_license` | The rotation is paused because the license has expired. / While the license is expired Alice starts no change on servers, and the old key stays in place. / Upload a valid license, then choose Continue on the rotation's page. | Lisansın süresi dolduğu için yenileme duraklatıldı. / Lisansın süresi dolmuşken Alice sunucularda hiçbir değişiklik başlatmaz ve eski anahtar yerinde kalır. / Geçerli bir lisans yükleyin, ardından yenilemenin sayfasında Devam et'i seçin. |
| `rotation.cancelled_license` | The planned rotation was cancelled because the license expired before it started. / Alice starts no rotation while the license is expired. / After a renewal, Alice plans the next run with a new preview and email. | Planlanan yenileme, başlamadan önce lisansın süresi dolduğu için iptal edildi. / Lisansın süresi dolmuşken Alice hiçbir yenilemeyi başlatmaz. / Lisans yenilendikten sonra Alice sonraki çalıştırmayı yeni bir önizleme ve e-postayla planlar. |
| `rotation.stopped` | An administrator stopped the rotation. / Alice removed the new key again where it had added it; the old key was not touched. / Start the rotation again when you are ready. | Bir yönetici yenilemeyi durdurdu. / Alice yeni anahtarı eklediği yerlerden yeniden kaldırdı; eski anahtara dokunulmadı. / Hazır olduğunuzda yenilemeyi yeniden başlatın. |
| `rotation.policy_off` | The planned run was cancelled because the policy was switched off. / A policy that is off starts no run. / Switch the policy on again to plan the next run. | Kural kapatıldığı için planlanan çalıştırma iptal edildi. / Kapalı bir kural hiçbir çalıştırma başlatmaz. / Sonraki çalıştırmayı planlamak için kuralı yeniden açın. |
| `rotation.new_key_failed` | The new key no longer worked when Alice checked it again, so the old key stays. / Just before removing the old key, Alice could not sign in with the new key on this server. / Check the new key on this server, then remove the old key on the old key's page when the new key works. | Alice yeniden denetlediğinde yeni anahtar artık çalışmıyordu; bu nedenle eski anahtar yerinde kalıyor. / Alice, eski anahtarı kaldırmadan hemen önce bu sunucuda yeni anahtarla oturum açamadı. / Bu sunucuda yeni anahtarı denetleyin ve yeni anahtar çalıştığında eski anahtarı eski anahtarın sayfasından kaldırın. |
| `rotation.retries_exhausted` | Alice gave up on this server after several attempts. / The work on this server was interrupted again and again (for example, by restarts). / Check the server and Alice's logs, then start the rotation again. | Alice birkaç denemeden sonra bu sunucuda vazgeçti. / Bu sunucudaki iş tekrar tekrar kesildi (örneğin yeniden başlatmalar nedeniyle). / Sunucuyu ve Alice'in günlüklerini denetleyip yenilemeyi yeniden başlatın. |

### C12. Audit actions (written by Tasks 6–9; labels in `web/src/locales/{en,tr}.json` `audit.actions.*`, Task 17)

| Action | Details | EN label | TR label |
|---|---|---|---|
| `sshkey.generated` | `ssh_key_id`, `fingerprint`, `algorithm`, `bits`, `label` | SSH key generated | SSH anahtarı oluşturuldu |
| `sshkey.deploy_requested` | `ssh_key_id`, `fingerprint`, `target_id`, `os_user`, `file_path`, `job_id` | SSH key deployment requested | SSH anahtarı dağıtımı istendi |
| `sshkey.deploy.denied` | `reason`, `ssh_key_id`, `target_id`, `os_user` | SSH key deployment refused | SSH anahtarı dağıtımı reddedildi |
| `sshkey.added` | `ssh_key_id`, `fingerprint`, `target_id`, `os_user`, `file_path`, `job_id`, `verified` | SSH key added | SSH anahtarı eklendi |
| `sshkey.add_failed` | `ssh_key_id`, `target_id`, `os_user`, `file_path`, `job_id`, `reason` | SSH key addition failed | SSH anahtarı eklenemedi |
| `sshkey.private_key_downloaded` | `ssh_key_id`, `fingerprint`, `reason`, `protected`, `download_count` | Private key downloaded | Özel anahtar indirildi |
| `sshkey.private_key_download.denied` | `ssh_key_id`, `reason` | Private key download refused | Özel anahtar indirme reddedildi |
| `sshkey.retired` | `ssh_key_id`, `fingerprint`, `rotation_id` | SSH key retired | SSH anahtarı kullanımdan kaldırıldı |
| `sshkey.private_key_destroyed` | `ssh_key_id`, `fingerprint` | Private key destroyed | Özel anahtar yok edildi |
| `rotation.policy_created` | `policy_id`, `ssh_key_id`, `interval_days`*, `overlap_minutes`*, `notify_before_hours`*, `new_type`* | Rotation policy created | Yenileme kuralı oluşturuldu |
| `rotation.policy_updated` | `policy_id`, the changed fields (`name`, `interval_days`, `overlap_minutes`, `notify_before_hours`, `new_type`) | Rotation policy changed | Yenileme kuralı değiştirildi |
| `rotation.policy_enabled` / `rotation.policy_disabled` | `policy_id`, `next_run_at` | Rotation policy switched on / off | Yenileme kuralı açıldı / kapatıldı |
| `rotation.policy_deleted` | `policy_id` | Rotation policy deleted | Yenileme kuralı silindi |
| `rotation.policy.denied` | `reason` (`own_key`, `not_managed`, `retired`), `ssh_key_id` | Rotation policy refused | Yenileme kuralı reddedildi |
| `rotation.previewed` | `policy_id`, `plan_digest`, `change_count`, `skip_count`, `emailed` | Rotation previewed | Yenileme önizlendi |
| `rotation.created` | `rotation_id`, `policy_id`, `trigger`, `plan_digest`, `planned_for` | Rotation planned | Yenileme planlandı |
| `rotation.status_changed` | `rotation_id`, `from`, `to`, `reason` | Rotation state changed | Yenileme durumu değişti |
| `rotation.location_changed` | `rotation_id`, `location_id`, `target_id`, `os_user`, `file_path`, `from`, `to`, `reason` | Rotation step on a server | Bir sunucuda yenileme adımı |
| `rotation.paused` | `rotation_id`, `reason` | Rotation paused | Yenileme duraklatıldı |
| `rotation.continued` | `rotation_id` | Rotation continued | Yenileme sürdürüldü |
| `rotation.finish_requested` | `rotation_id` | Rotation overlap ended early | Yenilemenin geçiş süresi erken bitirildi |
| `rotation.old_kept` | `rotation_id`, `location_count` | Old key kept on some servers | Eski anahtar bazı sunucularda tutuldu |
| `rotation.stop_requested` | `rotation_id` | Rotation stopped | Yenileme durduruldu |

(* `interval_days`, `overlap_minutes`, `notify_before_hours` and `new_type` pass the denylist: no sensitive segment.)

### C13. API (Task 13)

| Method and path | Permission | License class | Limit | Body / query | Answer |
|---|---|---|---|---|---|
| `POST /api/v1/ssh-keys/generate` | `inventory.operate` | change | default | `{"label": string, "key_type": "ed25519"\|"rsa-3072"\|"rsa-4096"\|"ecdsa-p256"}` (exact keys) | 201 `SSHKey` |
| `GET /api/v1/ssh-keys/{id}` (existing) | `read` | — | — | — | `SSHKey` gains `managed_key` |
| `GET /api/v1/ssh-keys` (existing) | `read` | — | — | unchanged | items already carry `managed`; generated keys without any location are listed too (Task 6) |
| `POST /api/v1/ssh-keys/{id}/actions/deploy` | `inventory.operate` | change | default | `{"target_id", "os_user", "file_path", "from": string (optional), "restrict": bool (optional)}` | 202 `Accepted` |
| `POST /api/v1/ssh-keys/{id}/actions/download-private-key` | `sshkeys.download` | always | `limitDownload` | `{"reason": string, "passphrase": string (optional)}` | 200 `application/octet-stream`, `Content-Disposition: attachment; filename="<Download.FileName>"`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`; the body is the file |
| `GET /api/v1/targets/{id}/key-files` | `read` | — | — | — | `{"items": [{"os_user", "files": [string], "default_file": string}], "scanned_at": time\|null}` from `facts.key_files` (the connection account is left out) |
| `GET /api/v1/rotation/policies` | `read` | — | — | — | `{"items": [Policy]}` |
| `POST /api/v1/rotation/policies` | `rotation.manage` | change | default | `{"ssh_key_id", "name", "interval_days", "overlap_days" (optional, 7), "notify_before_hours" (optional, 24), "new_key_type" (optional, "same")}` | 201 `Policy`, `ETag` |
| `GET /api/v1/rotation/policies/{id}` | `read` | — | — | — | `Policy`, `ETag` |
| `PATCH /api/v1/rotation/policies/{id}` | `rotation.manage` | change | default | any of `name`, `interval_days`, `overlap_days`, `notify_before_hours`, `new_key_type`; `If-Match` | `Policy`, `ETag` |
| `DELETE /api/v1/rotation/policies/{id}` | `rotation.manage` | change | default | `If-Match` | 204 |
| `POST /api/v1/rotation/policies/{id}/actions/enable` | `rotation.operate` | change | default | `If-Match` | `Policy` |
| `POST /api/v1/rotation/policies/{id}/actions/disable` | `rotation.manage` | change | default | `If-Match` | `Policy` |
| `POST /api/v1/rotation/policies/{id}/actions/preview` | `rotation.manage` | change | default | — | `Preview` |
| `POST /api/v1/rotation/policies/{id}/actions/run` | `rotation.operate` | change | default | `{"plan_digest": "<64 hex>"}` | 202 `{"rotation_id", "status_url": "/api/v1/rotation/runs/<id>"}` |
| `GET /api/v1/rotation/runs` | `read` | — | — | `?policy_id`, `?ssh_key_id`, `?cursor`, `?limit` | `{"items": [Rotation without steps], "next_cursor"}` |
| `GET /api/v1/rotation/runs/{id}` | `read` | — | — | — | `Rotation` |
| `POST /api/v1/rotation/runs/{id}/actions/continue` | `rotation.operate` | change | default | — | 204 |
| `POST /api/v1/rotation/runs/{id}/actions/finish-now` | `rotation.operate` | change | default | — | 204 |
| `POST /api/v1/rotation/runs/{id}/actions/keep-old` | `rotation.operate` | change | default | `{"location_ids": [uuid] (1..10000)}` | 204 |
| `POST /api/v1/rotation/runs/{id}/actions/abort` | `rotation.manage` | change | default | — | 204 |

DTOs (JSON, snake_case):

- `SSHKey` (existing `sshKeyDTO`) gains `managed: bool` and `managed_key: null | {"label", "comment", "key_type", "created_by", "created_at", "retired_at", "destroyed_at", "rotated_from", "download_count", "last_downloaded_at", "policy_id", "open_rotation_id"}`. Never a private key field (S-08).
- `Policy`: `{"id", "ssh_key_id", "name", "enabled", "interval_days", "overlap_days" (minutes / 1440, rounded down), "overlap_minutes", "notify_before_hours", "new_key_type", "next_run_at", "open_rotation_id", "version", "created_at", "updated_at"}`.
- `Preview`: `{"policy_id", "plan_digest", "planned_for", "new_key_type", "overlap_minutes", "change_count", "skip_count", "emailed", "actions": [{"n", "location_id", "target_id", "target_name", "os_user", "file_path", "options", "skip_reason" ("" when it changes), "verify" (bool), "verify_note", "remove_line", "add_line"}]}`.
- `Rotation`: `{"id", "policy_id", "old_ssh_key_id", "new_ssh_key_id", "old_fingerprint", "new_fingerprint", "trigger", "status", "paused_license", "awaiting_decision", "decision_due_at", "planned_for", "notified_at", "started_at", "verified_at", "overlap_until", "finished_at", "result_code" (an ALC code or ""), "plan_digest", "new_key_type", "overlap_minutes", "actions_allowed": ["continue"|"finish_now"|"keep_old"|"abort"], "locations": [{"id", "n", "target_id", "target_name", "os_user", "file_path", "options", "state", "skip_reason", "verify_note", "error_code" (ALC code or ""), "backup", "verified_at", "reverified_at", "removed_at"}], "steps": [{"n", "location_id", "name", "status", "at", "params"}]}`. `actions_allowed` is computed by `sshkeys.AllowedActions(r Rotation, gateOK bool) []string` (Task 9) — the UI shows only those buttons.
- `GET /api/v1/jobs` items of `sshkey.add` jobs carry `ssh_key_id` (from the payload) and their `result` (`{"result": "verified"|…, "note"}`); `rotation.location` jobs carry `rotation_id`.

Validation (422 with field details; `validate.*` codes): `label` 1–100 runes without control/format/bidi characters; `key_type` one of four; `os_user` `helperproto.ValidAccount`; `file_path` `helperproto.ValidPath`; `from` `keymat.FromOption`; `reason` `inventory.ValidateReason`; `passphrase` 12–1024 bytes (`validate.TooShort`/`TooLong` with `min`/`max`); `name` 1–100 runes; `interval_days` 1–3650; `overlap_days` 0–90; `notify_before_hours` 1–168; `new_key_type` `same` or one of four; `plan_digest` `^[0-9a-f]{64}$`; `location_ids` UUIDs, 1–10000, no repeats.

### C14. UI copy (Tasks 16–17; `web/src/locales/{en,tr}.json`)

| Key | EN | TR |
|---|---|---|
| `sshKeys.generate` | Generate key | Anahtar oluştur |
| `sshKeys.generateTitle` | Generate an SSH key | SSH anahtarı oluştur |
| `sshKeys.label` | Name | Ad |
| `sshKeys.labelHelp` | A name you recognise, for example the team or system that uses the key. | Anahtarı tanımanızı sağlayacak bir ad; örneğin anahtarı kullanan ekip ya da sistem. |
| `sshKeys.keyTypeLabel` | Key type | Anahtar türü |
| `sshKeys.types.ed25519` | Ed25519 (recommended) | Ed25519 (önerilir) |
| `sshKeys.types.rsa-3072` | RSA 3072 | RSA 3072 |
| `sshKeys.types.rsa-4096` | RSA 4096 | RSA 4096 |
| `sshKeys.types.ecdsa-p256` | ECDSA P-256 | ECDSA P-256 |
| `sshKeys.generateSubmit` | Generate | Oluştur |
| `sshKeys.generated` | Key generated. Alice keeps its private key encrypted. | Anahtar oluşturuldu. Alice özel anahtarı şifreli olarak saklar. |
| `sshKeys.managedBadge` | Generated by Alice | Alice tarafından oluşturuldu |
| `sshKeys.retiredBadge` | Retired | Kullanımdan kaldırıldı |
| `sshKeys.destroyedBadge` | Private key destroyed | Özel anahtar yok edildi |
| `sshKeys.rotatedFrom` | Replaces an earlier key | Önceki bir anahtarın yerini alır |
| `sshKeys.deploy` | Deploy to a server | Sunucuya dağıt |
| `sshKeys.deployTitle` | Deploy this key | Bu anahtarı dağıt |
| `sshKeys.deployServer` | Server | Sunucu |
| `sshKeys.deployUser` | User on the server | Sunucudaki kullanıcı |
| `sshKeys.deployFile` | File | Dosya |
| `sshKeys.deployNoFiles` | Alice has not found this user's key files yet. Scan the server, then try again. | Alice bu kullanıcının anahtar dosyalarını henüz bulmadı. Sunucuyu tarayıp yeniden deneyin. |
| `sshKeys.deployFrom` | Allowed source addresses (optional) | İzin verilen kaynak adresler (isteğe bağlı) |
| `sshKeys.deployFromHelp` | Comma-separated IP addresses or networks, for example 10.0.0.0/8. Leave empty to allow any address. | Virgülle ayrılmış IP adresleri ya da ağlar; örneğin 10.0.0.0/8. Her adrese izin vermek için boş bırakın. |
| `sshKeys.deployRestrict` | Allow sign-in only (no forwarding) | Yalnızca oturum açmaya izin ver (yönlendirme yok) |
| `sshKeys.deploySubmit` | Deploy | Dağıt |
| `sshKeys.deployQueued` | Alice is adding the key and will test a login with it. | Alice anahtarı ekliyor ve anahtarla oturum açmayı deneyecek. |
| `sshKeys.deployResult.verified` | Alice added the key and verified a login with it. | Alice anahtarı ekledi ve anahtarla oturum açılabildiğini doğruladı. |
| `sshKeys.deployResult.unverified` | Alice added the key but could not test a login with it. | Alice anahtarı ekledi ancak anahtarla oturum açmayı deneyemedi. |
| `sshKeys.deployResult.already_present` | The key was already on the server. | Anahtar sunucuda zaten vardı. |
| `sshKeys.deployResult.undone` | The server did not accept the key, so Alice removed it again. | Sunucu anahtarı kabul etmedi; bu nedenle Alice onu yeniden kaldırdı. |
| `sshKeys.deployResult.failed` | Alice could not add the key. | Alice anahtarı ekleyemedi. |
| `sshKeys.deployResult.undo_failed` | The key did not work and Alice could not remove it again. | Anahtar çalışmadı ve Alice onu yeniden kaldıramadı. |
| `sshKeys.download` | Download private key | Özel anahtarı indir |
| `sshKeys.downloadTitle` | Download the private key | Özel anahtarı indir |
| `sshKeys.downloadWarning` | Anyone with this file can sign in wherever this key is allowed. The download is recorded in the audit log with your reason. | Bu dosyaya sahip olan herkes bu anahtarın izinli olduğu her yerde oturum açabilir. İndirme, gerekçenizle birlikte denetim kaydına yazılır. |
| `sshKeys.downloadReason` | Reason | Gerekçe |
| `sshKeys.downloadReasonHelp` | At least 10 characters. Do not paste secrets here. | En az 10 karakter. Buraya gizli bilgi yapıştırmayın. |
| `sshKeys.downloadProtect` | Protect the file with a passphrase (recommended) | Dosyayı bir parolayla koruyun (önerilir) |
| `sshKeys.downloadPassphrase` | Passphrase | Parola |
| `sshKeys.downloadPassphraseRepeat` | Repeat the passphrase | Parolayı tekrarlayın |
| `sshKeys.downloadPassphraseHelp` | At least 12 characters. Alice does not keep it; without it the file cannot be opened. | En az 12 karakter. Alice bu parolayı saklamaz; parola olmadan dosya açılamaz. |
| `sshKeys.downloadMismatch` | The passphrases do not match. | Parolalar eşleşmiyor. |
| `sshKeys.downloadSubmit` | Download | İndir |
| `sshKeys.downloadDone` | The file was downloaded. Keep it safe and delete it when it is no longer needed. | Dosya indirildi. Güvenli bir yerde saklayın ve artık gerekmediğinde silin. |
| `sshKeys.downloadCount_one` | Downloaded {{count}} time | {{count}} kez indirildi |
| `sshKeys.downloadCount_other` | Downloaded {{count}} times | {{count}} kez indirildi |
| `sshKeys.noDownloadPlatform` | This is Alice's own connection key. It cannot be downloaded. | Bu, Alice'in kendi bağlantı anahtarıdır. İndirilemez. |
| `rotation.title` | Automatic rotation | Otomatik yenileme |
| `rotation.none` | No rotation policy. Alice changes this key only when you ask. | Yenileme kuralı yok. Alice bu anahtarı yalnızca siz istediğinizde değiştirir. |
| `rotation.create` | Create rotation policy | Yenileme kuralı oluştur |
| `rotation.name` | Name | Ad |
| `rotation.intervalDays` | Rotate every (days) | Yenileme aralığı (gün) |
| `rotation.overlapDays` | Keep the old key for (days) | Eski anahtarı tutma süresi (gün) |
| `rotation.overlapHelp` | Both keys work during this time, so people and systems can switch to the new key. | Bu süre boyunca iki anahtar da çalışır; böylece kişiler ve sistemler yeni anahtara geçebilir. |
| `rotation.notifyHours` | Notify before each run (hours) | Her çalıştırmadan önce bildirim (saat) |
| `rotation.newKeyType` | New key type | Yeni anahtar türü |
| `rotation.sameType` | Same as now | Şimdikiyle aynı |
| `rotation.save` | Save | Kaydet |
| `rotation.on` | On | Açık |
| `rotation.off` | Off | Kapalı |
| `rotation.switch` | Rotate automatically | Otomatik yenile |
| `rotation.offHelp` | The policy is off. Alice plans no run until you switch it on. | Kural kapalı. Siz açana kadar Alice hiçbir çalıştırma planlamaz. |
| `rotation.nextRun` | Next run: {{date}} | Sonraki çalıştırma: {{date}} |
| `rotation.every_one` | Every {{count}} day | Her {{count}} günde bir |
| `rotation.every_other` | Every {{count}} days | Her {{count}} günde bir |
| `rotation.overlap` | Overlap: {{duration}} | Geçiş süresi: {{duration}} |
| `rotation.duration.days_one` | {{count}} day | {{count}} gün |
| `rotation.duration.days_other` | {{count}} days | {{count}} gün |
| `rotation.duration.minutes_one` | {{count}} minute | {{count}} dakika |
| `rotation.duration.minutes_other` | {{count}} minutes | {{count}} dakika |
| `rotation.preview` | Preview next run | Sonraki çalıştırmayı önizle |
| `rotation.runNow` | Run now | Şimdi çalıştır |
| `rotation.edit` | Edit | Düzenle |
| `rotation.delete` | Delete policy | Kuralı sil |
| `rotation.deleteConfirm` | Delete this rotation policy? The key stays as it is. | Bu yenileme kuralını silmek istiyor musunuz? Anahtar olduğu gibi kalır. |
| `rotation.previewTitle` | Preview of the next run | Sonraki çalıştırmanın önizlemesi |
| `rotation.previewIntro` | Alice will add a new key next to the old one in these places, check that it works, keep both keys for the overlap, then remove the old key. | Alice bu yerlerde eski anahtarın yanına yeni bir anahtar ekleyecek, çalıştığını denetleyecek, geçiş süresince iki anahtarı da tutacak ve ardından eski anahtarı kaldıracak. |
| `rotation.previewEmailed` | This preview was sent to the administrators by email. | Bu önizleme yöneticilere e-postayla gönderildi. |
| `rotation.previewNotEmailed` | This preview was already emailed in the last 10 minutes. | Bu önizleme son 10 dakika içinde zaten e-postayla gönderildi. |
| `rotation.col.server` | Server | Sunucu |
| `rotation.col.user` | User | Kullanıcı |
| `rotation.col.file` | File | Dosya |
| `rotation.col.change` | Change | Değişiklik |
| `rotation.col.state` | State | Durum |
| `rotation.willChange` | Will change | Değişecek |
| `rotation.skipped` | Skipped | Atlanacak |
| `rotation.adds` | Adds | Ekler |
| `rotation.removesAfter` | Removes after the overlap | Geçiş süresinden sonra kaldırır |
| `rotation.noLoginTest` | Alice cannot test a login here | Alice burada oturum açmayı deneyemez |
| `rotation.changes` | Places that will change: {{count}} | Değişecek yer sayısı: {{count}} |
| `rotation.skips` | Places that will be skipped: {{count}} | Atlanacak yer sayısı: {{count}} |
| `rotation.runConfirmTitle` | Start this rotation now? | Bu yenilemeyi şimdi başlatmak istiyor musunuz? |
| `rotation.runConfirm` | Start rotation | Yenilemeyi başlat |
| `rotation.runStarted` | The rotation started. | Yenileme başladı. |
| `rotation.runTitle` | Key rotation | Anahtar yenileme |
| `rotation.oldKey` | Old key | Eski anahtar |
| `rotation.newKey` | New key | Yeni anahtar |
| `rotation.overlapUntil` | Both keys work until {{date}} | İki anahtar da şu zamana kadar çalışır: {{date}} |
| `rotation.decisionDue` | Decide before {{date}}, or Alice undoes the rotation. | {{date}} zamanından önce karar verin; aksi hâlde Alice yenilemeyi geri alır. |
| `rotation.pausedBanner` | Paused: the license expired. Nothing is removed. After a renewal, choose Continue. | Duraklatıldı: lisansın süresi doldu. Hiçbir şey kaldırılmaz. Lisans yenilendikten sonra Devam et'i seçin. |
| `rotation.continue` | Continue | Devam et |
| `rotation.finishNow` | Finish now | Şimdi bitir |
| `rotation.finishNowHelp` | Alice checks the new key once more on each server, then removes the old key. | Alice her sunucuda yeni anahtarı bir kez daha denetler, ardından eski anahtarı kaldırır. |
| `rotation.keepOld` | Keep the old key on these servers | Bu sunucularda eski anahtarı tut |
| `rotation.abort` | Stop and undo | Durdur ve geri al |
| `rotation.abortConfirm` | Stop the rotation and remove the new key where Alice added it? The old key stays. | Yenileme durdurulsun ve Alice'in eklediği yerlerden yeni anahtar kaldırılsın mı? Eski anahtar yerinde kalır. |
| `rotation.steps` | Steps | Adımlar |
| `rotation.history` | Earlier runs | Önceki çalıştırmalar |
| `rotation.status.dry_run_notified` | Planned | Planlandı |
| `rotation.status.adding_new` | Adding the new key | Yeni anahtar ekleniyor |
| `rotation.status.verifying_new` | Waiting for a decision | Karar bekleniyor |
| `rotation.status.overlap` | Both keys valid | İki anahtar da geçerli |
| `rotation.status.removing_old` | Removing the old key | Eski anahtar kaldırılıyor |
| `rotation.status.completed` | Completed | Tamamlandı |
| `rotation.status.rolling_back` | Undoing | Geri alınıyor |
| `rotation.status.aborted` | Undone | Geri alındı |
| `rotation.status.needs_attention` | Needs attention | İlgi bekliyor |
| `rotation.status.cancelled` | Cancelled | İptal edildi |
| `rotation.loc.planned` | Waiting | Bekliyor |
| `rotation.loc.skipped` | Skipped | Atlandı |
| `rotation.loc.cancelled` | Not started | Başlatılmadı |
| `rotation.loc.adding` | Adding | Ekleniyor |
| `rotation.loc.added` | Added | Eklendi |
| `rotation.loc.add_failed` | Could not add | Eklenemedi |
| `rotation.loc.verified` | New key works | Yeni anahtar çalışıyor |
| `rotation.loc.unverifiable` | Cannot be tested | Denenemiyor |
| `rotation.loc.verify_failed` | New key did not work | Yeni anahtar çalışmadı |
| `rotation.loc.kept_old` | Old key kept | Eski anahtar tutuldu |
| `rotation.loc.removing` | Removing the old key | Eski anahtar kaldırılıyor |
| `rotation.loc.removed` | Old key removed | Eski anahtar kaldırıldı |
| `rotation.loc.remove_failed` | Old key kept (check failed) | Eski anahtar tutuldu (denetim başarısız) |
| `rotation.loc.undoing` | Removing the new key | Yeni anahtar kaldırılıyor |
| `rotation.loc.undone` | New key removed | Yeni anahtar kaldırıldı |
| `rotation.loc.undo_failed` | New key could not be removed | Yeni anahtar kaldırılamadı |
| `rotation.skip.target_deleted` | The server was removed from Alice. | Sunucu Alice'ten kaldırıldı. |
| `rotation.skip.host_key_unconfirmed` | The server's fingerprint is not confirmed yet. | Sunucunun parmak izi henüz onaylanmadı. |
| `rotation.skip.host_key_changed` | The server's identity changed. | Sunucunun kimliği değişti. |
| `rotation.skip.target_not_connected` | Alice cannot connect to the server right now. | Alice şu anda sunucuya bağlanamıyor. |
| `rotation.skip.keys_managed_elsewhere` | The server gets this user's keys from a program. | Sunucu bu kullanıcının anahtarlarını bir programdan alıyor. |
| `rotation.skip.sshd_unreadable` | Alice could not read the SSH server settings. | Alice SSH sunucu ayarlarını okuyamadı. |
| `rotation.skip.connection_account` | This is the account Alice connects with. | Bu, Alice'in bağlandığı hesaptır. |
| `rotation.skip.missing` | The key was no longer found here. | Anahtar artık burada bulunamadı. |
| `rotation.skip.cert_authority` | This line is a certificate authority. | Bu satır bir sertifika yetkilisi. |
| `rotation.skip.shared_file_skipped` | Another user of the same file is skipped. | Aynı dosyayı kullanan başka bir kullanıcı atlanıyor. |
| `rotation.skip.pubkey_disabled` | The SSH server does not accept keys. | SSH sunucusu anahtar kabul etmiyor. |
| `rotation.note.root_login_disabled` | root may not sign in over SSH here | Burada root SSH ile oturum açamaz |
| `rotation.note.from_option` | The key is limited to certain addresses | Anahtar belirli adreslerle sınırlı |
| `rotation.note.login_without_key` | The server let Alice in without the key | Sunucu Alice'i anahtar olmadan içeri aldı |

---

### Task 1: `internal/sshkeys/keymat`: key generation, the OpenSSH download file, `authorized_keys` lines and comments, the test-login signer; `FuzzAuthorizedLine`

**Files:**
- Create: `internal/sshkeys/keymat/keymat.go`, `internal/sshkeys/keymat/openssh.go`, `internal/sshkeys/keymat/line.go`, `internal/sshkeys/keymat/signer.go`
- Create: `internal/sshkeys/keymat/keymat_test.go`, `internal/sshkeys/keymat/line_test.go`, `internal/sshkeys/keymat/fuzz_test.go`
- Modify: `Makefile` (target `fuzz-ssh`: one more line)
- Modify: `internal/archtest/arch_test.go` (the `sshkeys` rules of Global Constraints and their `TestAllowed` cases, for the whole module: the later tasks' packages are covered from the start)

**Interfaces:**
- Consumes: `secrets.Plaintext`, `secrets.NewPlaintext` (`internal/secrets/plaintext.go`); `golang.org/x/crypto/ssh` v0.57.0.
- Produces: C3 exactly (`KeyType`, the four constants, `KeyTypes`, `Valid`, `TypeOf`, `Material`, `Generate`, `PublicOf`, `OpenSSHFile`, `Signer`, `Comment`, `FromOption`, `Line`, `HasFromOption`, `MinPassphrase`, `MaxPassphrase`, `MaxFromEntries`, the five errors).

- [ ] **Step 1: Write the failing tests**

`internal/sshkeys/keymat/keymat_test.go`:

```go
package keymat

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/secrets"
)

func TestGenerateEveryType(t *testing.T) {
	cases := []struct {
		t         KeyType
		algorithm string
		bits      int
		sshType   string
	}{
		{Ed25519, "ed25519", 256, "ssh-ed25519"},
		{RSA3072, "rsa", 3072, "ssh-rsa"},
		{RSA4096, "rsa", 4096, "ssh-rsa"},
		{ECDSAP256, "ecdsa", 256, "ecdsa-sha2-nistp256"},
	}
	for _, c := range cases {
		t.Run(string(c.t), func(t *testing.T) {
			m, err := Generate(rand.Reader, c.t)
			require.NoError(t, err)
			defer m.PKCS8.Zero()
			assert.Equal(t, c.algorithm, m.Algorithm)
			assert.Equal(t, c.bits, m.Bits)
			assert.True(t, strings.HasPrefix(m.PublicKey, c.sshType+" "), m.PublicKey)
			assert.Regexp(t, `^SHA256:[A-Za-z0-9+/]{43}$`, m.Fingerprint)
			assert.Regexp(t, `^[0-9a-f]{64}$`, m.PublicKeySHA256)
			pub, fp, err := PublicOf(m.PKCS8)
			require.NoError(t, err)
			assert.Equal(t, m.PublicKey, pub)
			assert.Equal(t, m.Fingerprint, fp)
			assert.Equal(t, c.t, TypeOf(m.Algorithm, m.Bits))
		})
	}
}

func TestGenerateRefusesUnknownTypeAndShortRandomness(t *testing.T) {
	_, err := Generate(rand.Reader, KeyType("dsa"))
	assert.ErrorIs(t, err, ErrKeyType)
	_, err = Generate(bytes.NewReader(make([]byte, 5)), Ed25519)
	assert.Error(t, err)
	assert.Equal(t, []KeyType{Ed25519, RSA3072, RSA4096, ECDSAP256}, KeyTypes())
	assert.False(t, KeyType("").Valid())
	assert.Equal(t, Ed25519, TypeOf("rsa", 2048), "an unknown size falls back to the default type")
}

func TestEd25519IsDeterministicFromTheReader(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	a, err := Generate(bytes.NewReader(seed), Ed25519)
	require.NoError(t, err)
	b, err := Generate(bytes.NewReader(seed), Ed25519)
	require.NoError(t, err)
	assert.Equal(t, a.Fingerprint, b.Fingerprint)
}

// Review Focus 2: a Material never prints its private key, whatever renders it.
func TestMaterialNeverPrints(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	der := append([]byte(nil), m.PKCS8.Bytes()...)
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("m", "material", m)
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	for _, out := range []string{fmt.Sprint(m), fmt.Sprintf("%+v %#v %s %q %x", m, m, m, m, m), string(raw), logs.String()} {
		assert.Contains(t, out, m.Fingerprint)
		assert.NotContains(t, out, string(der))
		assert.NotContains(t, out, fmt.Sprintf("%x", der[len(der)-16:]))
	}
}

func TestOpenSSHFileRoundTrip(t *testing.T) {
	for _, kt := range KeyTypes() {
		t.Run(string(kt), func(t *testing.T) {
			m, err := Generate(rand.Reader, kt)
			require.NoError(t, err)
			defer m.PKCS8.Zero()
			plain, err := OpenSSHFile(m.PKCS8, "alice:web:2026-10-05", nil)
			require.NoError(t, err)
			defer plain.Zero()
			assert.True(t, bytes.HasPrefix(plain.Bytes(), []byte("-----BEGIN "+"OPENSSH PRIVATE KEY-----\n")))
			k, err := ssh.ParseRawPrivateKey(plain.Bytes())
			require.NoError(t, err)
			s, err := ssh.NewSignerFromKey(k)
			require.NoError(t, err)
			assert.Equal(t, m.Fingerprint, ssh.FingerprintSHA256(s.PublicKey()))

			pass := []byte("correct horse battery")
			locked, err := OpenSSHFile(m.PKCS8, "alice:web:2026-10-05", pass)
			require.NoError(t, err)
			defer locked.Zero()
			_, err = ssh.ParseRawPrivateKey(locked.Bytes())
			var missing *ssh.PassphraseMissingError
			assert.ErrorAs(t, err, &missing)
			_, err = ssh.ParseRawPrivateKeyWithPassphrase(locked.Bytes(), []byte("wrong passphrase!"))
			assert.Error(t, err)
			k2, err := ssh.ParseRawPrivateKeyWithPassphrase(locked.Bytes(), pass)
			require.NoError(t, err)
			s2, err := ssh.NewSignerFromKey(k2)
			require.NoError(t, err)
			assert.Equal(t, m.Fingerprint, ssh.FingerprintSHA256(s2.PublicKey()))
		})
	}
}

func TestOpenSSHFileRefusals(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	_, err = OpenSSHFile(m.PKCS8, "c", []byte("short"))
	assert.ErrorIs(t, err, ErrPassphrase)
	_, err = OpenSSHFile(m.PKCS8, "c", bytes.Repeat([]byte("x"), MaxPassphrase+1))
	assert.ErrorIs(t, err, ErrPassphrase)
	_, err = OpenSSHFile(m.PKCS8, "two words", nil)
	assert.ErrorIs(t, err, ErrLine)
	_, err = OpenSSHFile(secrets.NewPlaintext([]byte("not a key")), "c", nil)
	assert.ErrorIs(t, err, ErrKeyData)
	_, _, err = PublicOf(secrets.NewPlaintext([]byte{0x30, 0x00}))
	assert.ErrorIs(t, err, ErrKeyData)
}

// S-11: the PEM block's DER, which OpenSSHFile owns, is cleared before it returns.
func TestOpenSSHZeroesItsCopies(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	var seen []byte
	onBlock = func(b []byte) { seen = b }
	defer func() { onBlock = nil }()
	out, err := OpenSSHFile(m.PKCS8, "c", []byte("a long enough passphrase"))
	require.NoError(t, err)
	out.Zero()
	require.NotEmpty(t, seen)
	assert.Equal(t, make([]byte, len(seen)), seen, "the block's bytes were cleared")
	assert.Equal(t, make([]byte, len(out.Bytes())), out.Bytes())
}

func TestSignerSignsAndReleases(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	s, release, err := Signer(m.PKCS8)
	require.NoError(t, err)
	assert.Equal(t, m.Fingerprint, ssh.FingerprintSHA256(s.PublicKey()))
	sig, err := s.Sign(rand.Reader, []byte("data"))
	require.NoError(t, err)
	require.NoError(t, s.PublicKey().Verify([]byte("data"), sig))
	release()
	_, _, err = Signer(secrets.NewPlaintext([]byte("x")))
	assert.ErrorIs(t, err, ErrKeyData)
}
```

`internal/sshkeys/keymat/line_test.go`:

```go
package keymat

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestComment(t *testing.T) {
	day := time.Date(2026, 10, 5, 23, 59, 0, 0, time.FixedZone("x", 3*3600))
	cases := map[string]string{
		"CI deploy key":                    "alice:ci-deploy-key:2026-10-05",
		"İstanbul yedek":                   "alice:stanbul-yedek:2026-10-05",
		"  --  ":                           "alice:key:2026-10-05",
		"web.prod_01":                      "alice:web.prod_01:2026-10-05",
		strings.Repeat("a", 80):            "alice:" + strings.Repeat("a", 40) + ":2026-10-05",
		"a‮b":                         "alice:a-b:2026-10-05",
	}
	for label, want := range cases {
		got := Comment(label, day)
		assert.Equal(t, want, got, label)
		assert.Regexp(t, `^[!-~]{1,100}$`, got)
	}
}

func TestFromOption(t *testing.T) {
	got, err := FromOption(" 10.0.0.0/8, 192.0.2.7,2001:db8::/32 ")
	require.NoError(t, err)
	assert.Equal(t, `from="10.0.0.0/8,192.0.2.7,2001:db8::/32"`, got)
	for _, bad := range []string{"", " ", "10.0.0.1/8", "host.example", "10.0.0.0/8,", `1.2.3.4"`, "fe80::1%eth0",
		strings.Repeat("10.0.0.1,", MaxFromEntries) + "10.0.0.1", "*"} {
		_, err := FromOption(bad)
		assert.ErrorIs(t, err, ErrFromOption, bad)
	}
}

func TestLine(t *testing.T) {
	m, err := Generate(rand.Reader, Ed25519)
	require.NoError(t, err)
	defer m.PKCS8.Zero()
	line, err := Line(`from="10.0.0.0/8",restrict`, m.PublicKey, "alice:web:2026-10-05")
	require.NoError(t, err)
	assert.Equal(t, `from="10.0.0.0/8",restrict `+m.PublicKey+" alice:web:2026-10-05", line)
	pk, comment, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, m.Fingerprint, ssh.FingerprintSHA256(pk))
	assert.Equal(t, "alice:web:2026-10-05", comment)
	assert.Equal(t, []string{`from="10.0.0.0/8"`, "restrict"}, opts)

	plain, err := Line("", m.PublicKey, "c")
	require.NoError(t, err)
	assert.Equal(t, m.PublicKey+" c", plain)

	for name, args := range map[string][3]string{
		"cert-authority":     {"cert-authority", m.PublicKey, "c"},
		"Cert-Authority":     {`Cert-Authority`, m.PublicKey, "c"},
		"newline in options": {"restrict\nssh-ed25519 AAAA", m.PublicKey, "c"},
		"space in comment":   {"", m.PublicKey, "two words"},
		"empty comment":      {"", m.PublicKey, ""},
		"bad key":            {"", "ssh-ed25519 AAAA", "c"},
		"two keys":           {"", m.PublicKey + " c\n" + m.PublicKey, "c"},
		"NUL":                {"", m.PublicKey, "c\x00"},
	} {
		_, err := Line(args[0], args[1], args[2])
		assert.ErrorIs(t, err, ErrLine, name)
	}
}

func TestHasFromOption(t *testing.T) {
	assert.True(t, HasFromOption(`from="10.0.0.0/8"`))
	assert.True(t, HasFromOption(`restrict,FROM="1.2.3.4"`))
	assert.False(t, HasFromOption(`command="echo from=x",restrict`))
	assert.False(t, HasFromOption(""))
	assert.False(t, HasFromOption(`environment="A=from=1"`))
}
```

`internal/sshkeys/keymat/fuzz_test.go`:

```go
package keymat

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// FuzzAuthorizedLine (spec §25.6, with FuzzParseAuthorizedKeys): Line never panics, and a line it
// accepts is exactly one plain key line with the requested comment, no line break and no
// certificate authority.
func FuzzAuthorizedLine(f *testing.F) {
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	f.Add("", pub, "c")
	f.Add(`from="10.0.0.0/8",restrict`, pub, "alice:web:2026-10-05")
	f.Add("cert-authority", pub, "c")
	f.Add(`command="a\"b"`, pub, "c")
	f.Fuzz(func(t *testing.T, options, publicKey, comment string) {
		line, err := Line(options, publicKey, comment)
		if err != nil {
			return
		}
		if strings.ContainsAny(line, "\r\n\x00") {
			t.Fatalf("line break in %q", line)
		}
		_, got, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(rest) != 0 || got != comment {
			t.Fatalf("accepted line does not parse back: %q", line)
		}
		for _, o := range opts {
			if strings.EqualFold(o, "cert-authority") {
				t.Fatalf("certificate authority accepted: %q", line)
			}
		}
	})
}
```

(The constant above is a public key — a random 32-byte value in the Ed25519 public-key encoding — and is not secret.)

`internal/archtest/arch_test.go` `TestAllowed` cases (append to the table):

```go
		{"alice/internal/sshkeys", "alice/internal/inventory", true},
		{"alice/internal/sshkeys", "alice/internal/jobs", false},
		{"alice/internal/sshkeys", "alice/internal/notify", false},
		{"alice/internal/sshkeys", "alice/internal/api", false},
		{"alice/internal/sshkeys/plan", "alice/internal/sshkeys/keymat", true},
		{"alice/internal/sshkeys/keymat", "alice/internal/platform/db", false},
		{"alice/internal/sshkeys/plan", "alice/internal/platform/db", false},
		{"alice/internal/jobs/sshkeyjobs", "alice/internal/sshkeys", true},
		{"alice/internal/api", "alice/internal/sshkeys", true},
		{"alice/internal/inventory", "alice/internal/sshkeys", false},
```

(Use the table's existing field order; if `TestAllowed` is written differently, add the same ten pairs in its form.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/sshkeys/keymat/`
Expected: FAIL — `no non-test Go files` / undefined: `Generate`, `KeyType`, …

- [ ] **Step 3: Write the implementation**

`internal/sshkeys/keymat/keymat.go`:

```go
// Package keymat holds the SSH key material Alice generates (spec §13.5, SEC-046): key generation,
// the OpenSSH private-key file of the audited download, authorized_keys lines and comments, and the
// signer of a test login. Nothing here logs, and no value of this package prints a private key.
package keymat

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"golang.org/x/crypto/ssh"

	"alice/internal/secrets"
)

// KeyType is a key Alice can generate.
type KeyType string

// Key types (spec §13.5; R41 row 3). Ed25519 is the default.
const (
	Ed25519   KeyType = "ed25519"
	RSA3072   KeyType = "rsa-3072"
	RSA4096   KeyType = "rsa-4096"
	ECDSAP256 KeyType = "ecdsa-p256"
)

// Passphrase and from= bounds of the download and the deploy options.
const (
	MinPassphrase  = 12
	MaxPassphrase  = 1024
	MaxFromEntries = 16
)

// Errors carry no input.
var (
	ErrKeyType    = errors.New("keymat: unknown key type")
	ErrPassphrase = errors.New("keymat: the passphrase must be 12 to 1024 bytes")
	ErrFromOption = errors.New("keymat: from= must list IP addresses or networks")
	ErrLine       = errors.New("keymat: the authorized_keys line is not valid")
	ErrKeyData    = errors.New("keymat: the stored private key cannot be read")
)

// KeyTypes lists the generatable types in the order the UI offers them.
func KeyTypes() []KeyType { return []KeyType{Ed25519, RSA3072, RSA4096, ECDSAP256} }

// Valid reports whether t is one of KeyTypes.
func (t KeyType) Valid() bool {
	switch t {
	case Ed25519, RSA3072, RSA4096, ECDSAP256:
		return true
	}
	return false
}

// TypeOf maps a stored algorithm and size back to its type; anything else is Ed25519 (the default
// a rotation then uses).
func TypeOf(algorithm string, bits int) KeyType {
	switch {
	case algorithm == "rsa" && bits == 3072:
		return RSA3072
	case algorithm == "rsa" && bits == 4096:
		return RSA4096
	case algorithm == "ecdsa" && bits == 256:
		return ECDSAP256
	default:
		return Ed25519
	}
}

// Material is a freshly generated key. PKCS8 is the only clear private part; the caller zeroes it.
type Material struct {
	PKCS8           secrets.Plaintext
	PublicKey       string
	Fingerprint     string
	Algorithm       string
	Bits            int
	PublicKeySHA256 string
}

func (m Material) String() string                { return "keymat.Material{" + m.Fingerprint + "}" }
func (m Material) GoString() string              { return m.String() }
func (m Material) Format(f fmt.State, _ rune)    { _, _ = io.WriteString(f, m.String()) }
func (m Material) MarshalJSON() ([]byte, error)  { return json.Marshal(m.String()) }
func (m Material) LogValue() slog.Value          { return slog.StringValue(m.String()) }

// Generate creates a key of type t. An Ed25519 seed is read from rnd (crypto/rand when nil), so a
// test can fix it; RSA and ECDSA keys come from the standard library with rnd.
func Generate(rnd io.Reader, t KeyType) (Material, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	var priv crypto.Signer
	switch t {
	case Ed25519:
		seed := make([]byte, ed25519.SeedSize)
		defer clear(seed)
		if _, err := io.ReadFull(rnd, seed); err != nil {
			return Material{}, fmt.Errorf("keymat: read randomness: %w", err)
		}
		k := ed25519.NewKeyFromSeed(seed)
		defer clear(k)
		priv = k
	case RSA3072, RSA4096:
		bits := 3072
		if t == RSA4096 {
			bits = 4096
		}
		k, err := rsa.GenerateKey(rnd, bits)
		if err != nil {
			return Material{}, fmt.Errorf("keymat: generate an RSA key: %w", err)
		}
		priv = k
	case ECDSAP256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rnd)
		if err != nil {
			return Material{}, fmt.Errorf("keymat: generate an ECDSA key: %w", err)
		}
		priv = k
	default:
		return Material{}, ErrKeyType
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Material{}, ErrKeyData
	}
	m, err := publicParts(priv)
	if err != nil {
		clear(der)
		return Material{}, err
	}
	m.PKCS8 = secrets.NewPlaintext(der)
	return m, nil
}

// PublicOf returns the authorized_keys public key and fingerprint of a stored key.
func PublicOf(pkcs8 secrets.Plaintext) (publicKey, fingerprint string, err error) {
	priv, err := parse(pkcs8)
	if err != nil {
		return "", "", err
	}
	defer wipe(priv)
	m, err := publicParts(priv)
	if err != nil {
		return "", "", err
	}
	return m.PublicKey, m.Fingerprint, nil
}

func publicParts(priv crypto.Signer) (Material, error) {
	pub := priv.Public()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return Material{}, ErrKeyData
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Material{}, ErrKeyData
	}
	sum := sha256.Sum256(spki)
	m := Material{PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
		Fingerprint: ssh.FingerprintSHA256(sshPub), PublicKeySHA256: hex.EncodeToString(sum[:])}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		m.Algorithm, m.Bits = "ed25519", 256
	case *rsa.PublicKey:
		m.Algorithm, m.Bits = "rsa", k.N.BitLen()
	case *ecdsa.PublicKey:
		m.Algorithm, m.Bits = "ecdsa", k.Curve.Params().BitSize
	default:
		return Material{}, ErrKeyData
	}
	return m, nil
}

// parse reads a stored PKCS #8 key of one of the three algorithms.
func parse(pkcs8 secrets.Plaintext) (crypto.Signer, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8.Bytes())
	if err != nil {
		return nil, ErrKeyData
	}
	switch s := k.(type) {
	case ed25519.PrivateKey:
		return s, nil
	case *rsa.PrivateKey:
		return s, nil
	case *ecdsa.PrivateKey:
		return s, nil
	}
	return nil, ErrKeyData
}

// wipe clears what can be cleared of a parsed key: an Ed25519 key's bytes. The limbs of RSA and
// ECDSA keys (big.Int) cannot be (known limitation P4-04).
func wipe(k crypto.Signer) {
	if e, ok := k.(ed25519.PrivateKey); ok {
		clear(e)
	}
}
```

`internal/sshkeys/keymat/openssh.go`:

```go
package keymat

import (
	"encoding/pem"

	"golang.org/x/crypto/ssh"

	"alice/internal/secrets"
)

// onBlock sees the PEM block's DER before it is cleared (tests only; nil in production).
var onBlock func([]byte)

// OpenSSHFile returns the OpenSSH private-key file of a stored key (spec §13.5; R41 row 4):
// unencrypted with a nil passphrase, otherwise aes256-ctr with bcrypt-pbkdf. The caller zeroes the
// result; the DER of the PEM block is cleared here. pem.EncodeToMemory's growth copies cannot be.
func OpenSSHFile(pkcs8 secrets.Plaintext, comment string, passphrase []byte) (secrets.Plaintext, error) {
	if passphrase != nil && (len(passphrase) < MinPassphrase || len(passphrase) > MaxPassphrase) {
		return secrets.Plaintext{}, ErrPassphrase
	}
	if !validComment(comment) {
		return secrets.Plaintext{}, ErrLine
	}
	priv, err := parse(pkcs8)
	if err != nil {
		return secrets.Plaintext{}, err
	}
	defer wipe(priv)
	var block *pem.Block
	if passphrase == nil {
		block, err = ssh.MarshalPrivateKey(priv, comment)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, comment, passphrase)
	}
	if err != nil {
		return secrets.Plaintext{}, ErrKeyData
	}
	out := pem.EncodeToMemory(block)
	if onBlock != nil {
		onBlock(block.Bytes)
	}
	clear(block.Bytes)
	return secrets.NewPlaintext(out), nil
}
```

`internal/sshkeys/keymat/line.go`:

```go
package keymat

import (
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxSlug = 40

// Comment is the comment of a line Alice adds (spec §13.4): "alice:<slug>:<yyyy-mm-dd>", the slug
// made of the label's ASCII letters (lower case), digits, '.' and '_', other runs folded to one '-'.
func Comment(label string, day time.Time) string {
	var b strings.Builder
	dash := false
	for _, r := range label {
		if b.Len() >= maxSlug {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_':
			b.WriteRune(r)
			dash = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "key"
	}
	return "alice:" + slug + ":" + day.UTC().Format("2006-01-02")
}

// validComment: 1-100 printable ASCII characters without a space (ssh_keys.key_comment).
func validComment(c string) bool {
	if c == "" || len(c) > 100 {
		return false
	}
	for i := 0; i < len(c); i++ {
		if c[i] < '!' || c[i] > '~' {
			return false
		}
	}
	return true
}

// FromOption validates a comma-separated list of IP addresses and networks (host bits zero, no
// zone, at most MaxFromEntries) and returns the option text `from="…"` in canonical form.
func FromOption(list string) (string, error) {
	parts := strings.Split(list, ",")
	if strings.TrimSpace(list) == "" || len(parts) > MaxFromEntries {
		return "", ErrFromOption
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if pfx, err := netip.ParsePrefix(p); err == nil && pfx == pfx.Masked() && pfx.Addr().Zone() == "" {
			out = append(out, pfx.String())
			continue
		}
		if a, err := netip.ParseAddr(p); err == nil && a.Zone() == "" {
			out = append(out, a.String())
			continue
		}
		return "", ErrFromOption
	}
	return `from="` + strings.Join(out, ",") + `"`, nil
}

// Line builds "[options ]<type> <base64> <comment>" and refuses anything that is not exactly one
// plain key line: a line break or NUL anywhere, a key that does not parse, a comment that is not
// validComment, options ssh.ParseAuthorizedKey does not accept, or a certificate authority.
func Line(options, publicKey, comment string) (string, error) {
	if strings.ContainsAny(options+publicKey+comment, "\r\n\x00") || !validComment(comment) {
		return "", ErrLine
	}
	pk, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil || len(rest) != 0 {
		return "", ErrLine
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + comment
	if options != "" {
		line = options + " " + line
	}
	got, gotComment, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(rest) != 0 || gotComment != comment || ssh.FingerprintSHA256(got) != ssh.FingerprintSHA256(pk) {
		return "", ErrLine
	}
	for _, o := range opts {
		if strings.EqualFold(o, "cert-authority") {
			return "", ErrLine
		}
	}
	return line, nil
}

// HasFromOption reports whether an option list (as stored for a location) holds from=.
func HasFromOption(options string) bool {
	for _, o := range splitOptions(options) {
		if len(o) >= 5 && strings.EqualFold(o[:5], "from=") {
			return true
		}
	}
	return false
}

// splitOptions splits an option list on commas outside double quotes (a backslash escapes the
// next character inside quotes, as sshd reads it).
func splitOptions(s string) []string {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if quoted {
				i++
			}
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}
```

`internal/sshkeys/keymat/signer.go`:

```go
package keymat

import (
	"golang.org/x/crypto/ssh"

	"alice/internal/secrets"
)

// Signer returns an SSH signer for one test login. release clears what can be cleared of the parsed
// key; the signer must not be used after it.
func Signer(pkcs8 secrets.Plaintext) (ssh.Signer, func(), error) {
	priv, err := parse(pkcs8)
	if err != nil {
		return nil, nil, err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		wipe(priv)
		return nil, nil, ErrKeyData
	}
	return s, func() { wipe(priv) }, nil
}
```

Archtest: add to `rules`

```go
	"alice/internal/sshkeys/...": {platform, "alice/internal/secrets/...", "alice/internal/audit/...", "alice/internal/license/...",
		"alice/internal/rbac/...", "alice/internal/providers", "alice/internal/inventory/..."},
```

to `denied` `"alice/internal/sshkeys/keymat": {"alice/internal/platform/db/..."}` and `"alice/internal/sshkeys/plan": {"alice/internal/platform/db/..."}` with exact rule keys `"alice/internal/sshkeys/keymat": {platform, "alice/internal/secrets/..."}` and `"alice/internal/sshkeys/plan": {platform, "alice/internal/sshkeys/keymat"}` (exact keys win over the subtree), and `"alice/internal/sshkeys/..."` to the lists of `alice/internal/jobs/...` and `alice/internal/api/...`.

`Makefile`, target `fuzz-ssh`, add after the `FuzzParseSSHDConfig` line:

```make
	go test -count=1 -run '^$$' -fuzz FuzzAuthorizedLine -fuzztime 60s ./internal/sshkeys/keymat/
```

- [ ] **Step 4: Run the tests to verify they pass, with full coverage**

Run: `go test -count=1 -coverprofile=/tmp/keymat.out ./internal/sshkeys/keymat/ && go tool cover -func=/tmp/keymat.out`
Expected: `ok  alice/internal/sshkeys/keymat`; every function at 100 % except the branches that handle a failure of a standard-library call no input can provoke (`rsa.GenerateKey`, `ecdsa.GenerateKey`, `x509.MarshalPKCS8PrivateKey` and `x509.MarshalPKIXPublicKey` of a key the package itself created, `ssh.NewSignerFromKey` of a parsed key, and `publicParts`' type switch default); total at least 95 %. (Do not reach the type-switch default with a DSA test double: DSA is grep-forbidden by SEC-047.) Task 19 sets the floor at the measured value rounded down (C1 and Global Constraints: `keymat` is not held to 100).

Run: `go test -count=1 -run '^$' -fuzz FuzzAuthorizedLine -fuzztime 30s ./internal/sshkeys/keymat/`
Expected: `PASS` (no crasher).

Run: `go test -count=1 ./internal/archtest/ && make lint`
Expected: `ok`; no finding.

- [ ] **Step 5: Commit**

```bash
git add -- internal/sshkeys/keymat
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(sshkeys): key material — generation, OpenSSH download file, authorized_keys lines, test-login signer" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/sshkeys/keymat Makefile internal/archtest/arch_test.go
```

(The `Co-Authored-By` line always names the model that wrote the commit.)

---

### Task 2: `internal/sshkeys/plan`: the rotation planner, skip and verification rules, the digest, timers

**Files:**
- Create: `internal/sshkeys/plan/plan.go`, `internal/sshkeys/plan/digest.go`, `internal/sshkeys/plan/times.go`
- Create: `internal/sshkeys/plan/plan_test.go`, `internal/sshkeys/plan/times_test.go`

**Interfaces:**
- Consumes: `keymat.HasFromOption` (Task 1); `providers.FlagCertAuthority` only in a test (the plan package keeps the literal `"cert_authority"`).
- Produces: C4 exactly.

- [ ] **Step 1: Write the failing tests**

`internal/sshkeys/plan/plan_test.go`:

```go
package plan

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers"
)

var (
	t1    = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	t2    = uuid.MustParse("00000000-0000-7000-8000-000000000002")
	keyID = uuid.MustParse("00000000-0000-7000-8000-0000000000aa")
)

func okTarget(id uuid.UUID, name string) Target {
	return Target{ID: id, Name: name, Status: "ok", ConnectionUser: "alice-svc", SSHDRead: true, PermitRootLogin: "prohibit-password",
		PubkeyAuthentication: "yes"}
}

func loc(target uuid.UUID, user, file, options string) Location {
	return Location{ID: uuid.Must(uuid.NewV7()), TargetID: target, OSUser: user, FilePath: file, Options: options, Comment: "old"}
}

func input(locs ...Location) Input {
	return Input{
		Key: Key{ID: keyID, Fingerprint: "SHA256:" + "A0aB1bC2cD3dE4eF5fG6gH7hI8iJ9jK0kL1lM2mN3nO", PublicKey: "ssh-ed25519 AAAA",
			Label: "ci", Managed: true, KeyType: "ed25519"},
		Locations:      locs,
		Targets:        map[uuid.UUID]Target{t1: okTarget(t1, "web-01"), t2: okTarget(t2, "db-01")},
		Protected:      []string{"SHA256:platformplatformplatformplatformplatformpla"},
		NewKeyType:     "same",
		OverlapMinutes: 7 * 1440,
		NewComment:     "alice:ci:2026-10-05",
	}
}

func TestFlagNameMatchesProviders(t *testing.T) {
	assert.Equal(t, providers.FlagCertAuthority, flagCertAuthority)
}

func TestOnlyManagedKeys(t *testing.T) {
	in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
	in.Key.Managed = false
	_, err := Build(in)
	assert.ErrorIs(t, err, ErrNotManaged)
	in.Key.Managed, in.Key.Retired = true, true
	_, err = Build(in)
	assert.ErrorIs(t, err, ErrRetired)
}

// F-36, SEC-081: Alice's own key is refused by its flag, by fingerprint (any comment or options) and
// when any of its locations is Alice's connection key.
func TestNeverAlicesOwnKey(t *testing.T) {
	in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
	in.Key.IsPlatform = true
	_, err := Build(in)
	assert.ErrorIs(t, err, ErrOwnKey)

	in = input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
	in.Protected = append(in.Protected, in.Key.Fingerprint)
	_, err = Build(in)
	assert.ErrorIs(t, err, ErrOwnKey)

	l := loc(t1, "alice-svc", "/home/alice-svc/.ssh/authorized_keys", "")
	l.IsAliceConnectionKey = true
	_, err = Build(input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", ""), l))
	assert.ErrorIs(t, err, ErrOwnKey)
}

func TestSkipReasons(t *testing.T) {
	cases := []struct {
		name   string
		target func(*Target)
		loc    func(*Location)
		want   string
	}{
		{"deleted", func(t *Target) { t.Deleted = true }, nil, SkipTargetDeleted},
		{"pending", func(t *Target) { t.Status = "pending_host_key" }, nil, SkipHostKeyUnconfirmed},
		{"changed", func(t *Target) { t.Status = "host_key_changed" }, nil, SkipHostKeyChanged},
		{"unreachable", func(t *Target) { t.Status = "unreachable" }, nil, SkipTargetNotConnected},
		{"auth failed", func(t *Target) { t.Status = "auth_failed" }, nil, SkipTargetNotConnected},
		{"missing", nil, func(l *Location) { l.Missing = true }, SkipMissing},
		{"cert authority", nil, func(l *Location) { l.Flags = []string{"cert_authority"} }, SkipCertAuthority},
		{"connection account", nil, func(l *Location) { l.OSUser = "alice-svc" }, SkipConnectionAccount},
		{"keys elsewhere", func(t *Target) { t.KeysManagedElsewhere = true }, nil, SkipKeysManagedElsewhere},
		{"keys elsewhere for user", func(t *Target) { t.ManagedElsewhereUsers = []string{"deploy"} }, nil, SkipKeysManagedElsewhere},
		{"sshd unread", func(t *Target) { t.SSHDRead = false }, nil, SkipSSHDUnreadable},
		{"sshd unread for user", func(t *Target) { t.SSHDUnreadUsers = []string{"deploy"} }, nil, SkipSSHDUnreadable},
		{"pubkey off", func(t *Target) { t.PubkeyAuthentication = "no" }, nil, SkipPubkeyDisabled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			other := loc(t2, "deploy", "/home/deploy/.ssh/authorized_keys", "")
			l := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
			if c.loc != nil {
				c.loc(&l)
			}
			in := input(l, other)
			if c.target != nil {
				tg := in.Targets[t1]
				c.target(&tg)
				in.Targets[t1] = tg
			}
			p, err := Build(in)
			require.NoError(t, err)
			i := slices.IndexFunc(p.Actions, func(a Action) bool { return a.LocationID == l.ID })
			assert.Equal(t, c.want, p.Actions[i].Skip)
			assert.False(t, p.Actions[i].Verify)
			assert.Equal(t, 1, p.Changes)
			assert.Equal(t, 1, p.Skips)
		})
	}
	// A location whose target is not in the map at all is a deleted target.
	in := input(loc(uuid.Must(uuid.NewV7()), "deploy", "/x", ""), loc(t2, "deploy", "/y", ""))
	p, err := Build(in)
	require.NoError(t, err)
	assert.Equal(t, SkipTargetDeleted, p.Actions[slices.IndexFunc(p.Actions, func(a Action) bool { return a.TargetID != t2 })].Skip)
}

func TestNothingToRotateStillReturnsThePlan(t *testing.T) {
	l := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	l.Missing = true
	p, err := Build(input(l))
	assert.ErrorIs(t, err, ErrNothingToRotate)
	assert.Equal(t, 1, p.Skips)
	assert.Equal(t, SkipMissing, p.Actions[0].Skip)
}

// Review Focus 1, R41 row 29: one shared file, one skipped user: the whole file is skipped.
func TestSharedFileSkippedTogether(t *testing.T) {
	a := loc(t1, "deploy", "/etc/ssh/keys/shared", "")
	b := loc(t1, "backup", "/etc/ssh/keys/shared", "")
	c := loc(t1, "app", "/home/app/.ssh/authorized_keys", "")
	in := input(a, b, c)
	tg := in.Targets[t1]
	tg.SSHDUnreadUsers = []string{"backup"}
	in.Targets[t1] = tg
	p, err := Build(in)
	require.NoError(t, err)
	byLoc := map[uuid.UUID]Action{}
	for _, x := range p.Actions {
		byLoc[x.LocationID] = x
	}
	assert.Equal(t, SkipSharedFile, byLoc[a.ID].Skip)
	assert.Equal(t, SkipSSHDUnreadable, byLoc[b.ID].Skip)
	assert.Equal(t, "", byLoc[c.ID].Skip)
}

func TestRootLoginDisabledIsNotVerifiable(t *testing.T) {
	r := loc(t1, "root", "/root/.ssh/authorized_keys", "")
	z := loc(t1, "toor", "/root/.ssh/authorized_keys2", "")
	d := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", `from="10.0.0.0/8"`)
	in := input(r, z, d)
	tg := in.Targets[t1]
	tg.PermitRootLogin = "no"
	tg.UID0Users = []string{"root", "toor"}
	in.Targets[t1] = tg
	p, err := Build(in)
	require.NoError(t, err)
	for _, a := range p.Actions {
		switch a.OSUser {
		case "root", "toor":
			assert.False(t, a.Verify)
			assert.Equal(t, "root_login_disabled", a.VerifyNote)
		case "deploy":
			assert.True(t, a.Verify)
			assert.Equal(t, "from_option", a.VerifyNote)
		}
	}
}

func TestLinesAndNewType(t *testing.T) {
	in := input(loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "restrict"))
	in.NewKeyType = "rsa-4096"
	p, err := Build(in)
	require.NoError(t, err)
	assert.Equal(t, "rsa-4096", p.NewKeyType)
	assert.Equal(t, "restrict ssh-ed25519 AAAA old", p.Actions[0].RemoveLine)
	assert.Equal(t, "restrict rsa-4096 (new key) alice:ci:2026-10-05", p.Actions[0].AddLine)
	in.NewKeyType = "same"
	p, err = Build(in)
	require.NoError(t, err)
	assert.Equal(t, "ed25519", p.NewKeyType)
	in.NewKeyType = ""
	p, err = Build(in)
	require.NoError(t, err)
	assert.Equal(t, "ed25519", p.NewKeyType)
}

// Dry run equals the actual plan: the same state in any order gives the same plan and digest.
func TestPlanIsDeterministic(t *testing.T) {
	a := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	b := loc(t2, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	c := loc(t1, "app", "/home/app/.ssh/authorized_keys", "restrict")
	p1, err := Build(input(a, b, c))
	require.NoError(t, err)
	p2, err := Build(input(c, a, b))
	require.NoError(t, err)
	assert.Equal(t, p1.Actions, p2.Actions)
	assert.Equal(t, p1.Digest(), p2.Digest())
	for i, x := range p1.Actions {
		assert.Equal(t, i+1, x.N)
	}
}

func TestDigestIgnoresOrderAndDisplayFields(t *testing.T) {
	a := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	in := input(a)
	p1, err := Build(in)
	require.NoError(t, err)
	in.Targets[t1] = func() Target { x := in.Targets[t1]; x.Name = "renamed"; return x }()
	in.NewComment = "alice:ci:2027-01-01"
	l := in.Locations[0]
	l.Comment = "a different old comment"
	in.Locations[0] = l
	p2, err := Build(in)
	require.NoError(t, err)
	assert.Equal(t, p1.Digest(), p2.Digest())
	assert.Regexp(t, `^[0-9a-f]{64}$`, p1.Digest())
}

func TestDigestChangesWithEveryDecision(t *testing.T) {
	fixed := loc(t1, "deploy", "/home/deploy/.ssh/authorized_keys", "")
	base := func() Input { return input(fixed) }
	ref, err := Build(base())
	require.NoError(t, err)
	changes := map[string]func(*Input){
		"overlap":      func(in *Input) { in.OverlapMinutes = 1 },
		"new key type": func(in *Input) { in.NewKeyType = "rsa-3072" },
		"options":      func(in *Input) { in.Locations[0].Options = "restrict" },
		"user":         func(in *Input) { in.Locations[0].OSUser = "app" },
		"file":         func(in *Input) { in.Locations[0].FilePath = "/home/deploy/.ssh/authorized_keys2" },
		"skip":         func(in *Input) { x := in.Targets[t1]; x.Status = "unreachable"; in.Targets[t1] = x },
		"verify note":  func(in *Input) { in.Locations[0].Options = `from="10.0.0.0/8"` },
		"another location": func(in *Input) {
			in.Locations = append(in.Locations, loc(t2, "deploy", "/home/deploy/.ssh/authorized_keys", ""))
		},
	}
	again, err := Build(base())
	require.NoError(t, err)
	assert.Equal(t, ref.Digest(), again.Digest(), "the same state gives the same digest")
	for name, change := range changes {
		in := base()
		change(&in)
		p, _ := Build(in) // "skip" leaves nothing to rotate: the plan is still returned
		assert.NotEqual(t, ref.Digest(), p.Digest(), name)
	}
}
```

`input` builds a fresh `Targets` map and copies the location values on every call, so a change in one case never leaks into the next.

`internal/sshkeys/plan/times_test.go`:

```go
package plan

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// §26.8 "overlap boundaries with the fake clock": a timer is due at its instant, not a nanosecond before.
func TestOverlapBoundaries(t *testing.T) {
	c := clock.NewFake(t0)
	until := OverlapUntil(c.Now(), 7*1440)
	assert.Equal(t, t0.Add(7*24*time.Hour), until)
	c.Advance(7*24*time.Hour - time.Nanosecond)
	assert.False(t, Due(c.Now(), until))
	c.Advance(time.Nanosecond)
	assert.True(t, Due(c.Now(), until))
	c.Advance(time.Hour)
	assert.True(t, Due(c.Now(), until))
	assert.Equal(t, t0, OverlapUntil(t0, 0), "an overlap of 0 ends at the verification")
	assert.Equal(t, t0.Add(time.Minute), OverlapUntil(t0, 1))
}

func TestScheduleTimes(t *testing.T) {
	assert.Equal(t, t0.Add(90*24*time.Hour), FirstRun(t0, 90))
	assert.Equal(t, t0.Add(24*time.Hour), NextRun(t0, 1))
	next := t0.Add(48 * time.Hour)
	assert.Equal(t, next.Add(-24*time.Hour), NoticeDue(next, 24))
	assert.Equal(t, next, PlannedFor(t0, next, 24), "enough notice: the scheduled time")
	assert.Equal(t, t0.Add(30*time.Hour), PlannedFor(t0.Add(6*time.Hour), t0.Add(10*time.Hour), 24), "late: now + notice")
	assert.Equal(t, t0.Add(14*24*time.Hour), DecisionDue(t0))
}

func TestReminder(t *testing.T) {
	at, ok := ReminderDue(t0, 3*1440)
	assert.True(t, ok)
	assert.Equal(t, t0.Add(-24*time.Hour), at)
	_, ok = ReminderDue(t0, 48*60)
	assert.False(t, ok, "an overlap of 48 hours or less gets no reminder")
}

func TestFresh(t *testing.T) {
	assert.True(t, Fresh(t0, t0))
	assert.True(t, Fresh(t0, t0.Add(-15*time.Minute)))
	assert.False(t, Fresh(t0, t0.Add(-15*time.Minute-time.Nanosecond)))
	assert.False(t, Fresh(t0, t0.Add(time.Second)), "a verification in the future is not fresh")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/sshkeys/plan/`
Expected: FAIL — `no non-test Go files`.

- [ ] **Step 3: Write the implementation**

`internal/sshkeys/plan/plan.go`:

```go
// Package plan is the rotation planner (spec §13.6 items 1-2; R41 rows 13, 17, 29): from a key, its
// locations and their servers it decides, purely, which locations change, which are skipped and
// why, where a test login is possible, and the lines involved (public parts only). The same function
// serves the on-demand preview, the scheduled preview and the start of a run, so a dry run and the
// run it announces are the same plan (Digest).
package plan

import (
	"bytes"
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	"alice/internal/sshkeys/keymat"
)

// flagCertAuthority is providers.FlagCertAuthority (the planner does not import providers).
const flagCertAuthority = "cert_authority"

// Skip reasons (closed list; web locale rotation.skip.<reason>).
const (
	SkipTargetDeleted        = "target_deleted"
	SkipHostKeyUnconfirmed   = "host_key_unconfirmed"
	SkipHostKeyChanged       = "host_key_changed"
	SkipTargetNotConnected   = "target_not_connected"
	SkipKeysManagedElsewhere = "keys_managed_elsewhere"
	SkipSSHDUnreadable       = "sshd_unreadable"
	SkipConnectionAccount    = "connection_account"
	SkipMissing              = "missing"
	SkipCertAuthority        = "cert_authority"
	SkipSharedFile           = "shared_file_skipped"
	SkipPubkeyDisabled       = "pubkey_disabled"
)

// Verify notes.
const (
	NoteRootLoginDisabled = "root_login_disabled"
	NoteFromOption        = "from_option"
)

var (
	ErrNotManaged      = errors.New("plan: the key was not generated by Alice")
	ErrOwnKey          = errors.New("plan: the key is Alice's own key")
	ErrRetired         = errors.New("plan: the key is retired")
	ErrNothingToRotate = errors.New("plan: no location can change")
)

// (Key, Target, Location, Input, Action, Plan: exactly as in the contract, C4.)

// Build plans a rotation. It refuses a key Alice did not generate, Alice's own key (by flag, by
// fingerprint, or by a location marked as Alice's connection key) and a retired key. Actions are
// ordered by target, file and user, numbered from 1. A plan with no changing action is returned with
// ErrNothingToRotate, so a preview can still show why.
func Build(in Input) (Plan, error) {
	switch {
	case in.Key.IsPlatform || slices.Contains(in.Protected, in.Key.Fingerprint):
		return Plan{}, ErrOwnKey
	case slices.ContainsFunc(in.Locations, func(l Location) bool { return l.IsAliceConnectionKey }):
		return Plan{}, ErrOwnKey
	case !in.Key.Managed:
		return Plan{}, ErrNotManaged
	case in.Key.Retired:
		return Plan{}, ErrRetired
	}
	newType := in.NewKeyType
	if newType == "" || newType == "same" {
		newType = in.Key.KeyType
	}
	locs := slices.Clone(in.Locations)
	slices.SortFunc(locs, func(a, b Location) int {
		return cmp.Or(bytes.Compare(a.TargetID[:], b.TargetID[:]), strings.Compare(a.FilePath, b.FilePath),
			strings.Compare(a.OSUser, b.OSUser), bytes.Compare(a.ID[:], b.ID[:]))
	})
	p := Plan{KeyID: in.Key.ID, Fingerprint: in.Key.Fingerprint, NewKeyType: newType, Overlap: in.OverlapMinutes,
		Actions: make([]Action, 0, len(locs))}
	type fileRef struct {
		target uuid.UUID
		path   string
	}
	skippedFile := map[fileRef]bool{}
	for i, l := range locs {
		t, known := in.Targets[l.TargetID]
		a := Action{N: i + 1, LocationID: l.ID, TargetID: l.TargetID, TargetName: t.Name, OSUser: l.OSUser, FilePath: l.FilePath,
			Options: l.Options, RemoveLine: joinLine(l.Options, in.Key.PublicKey, l.Comment),
			AddLine: joinLine(l.Options, newType+" (new key)", in.NewComment)}
		a.Skip = skipReason(t, known, l)
		if a.Skip != "" {
			skippedFile[fileRef{l.TargetID, l.FilePath}] = true
		}
		p.Actions = append(p.Actions, a)
	}
	for i := range p.Actions {
		a := &p.Actions[i]
		if a.Skip == "" && skippedFile[fileRef{a.TargetID, a.FilePath}] {
			a.Skip = SkipSharedFile
		}
		if a.Skip == "" {
			a.Verify, a.VerifyNote = verifyRule(in.Targets[a.TargetID], a.OSUser, a.Options)
			p.Changes++
		} else {
			p.Skips++
		}
	}
	if p.Changes == 0 {
		return p, ErrNothingToRotate
	}
	return p, nil
}

func skipReason(t Target, known bool, l Location) string {
	switch {
	case !known || t.Deleted:
		return SkipTargetDeleted
	case t.Status == "pending_host_key":
		return SkipHostKeyUnconfirmed
	case t.Status == "host_key_changed":
		return SkipHostKeyChanged
	case t.Status != "ok":
		return SkipTargetNotConnected
	case l.Missing:
		return SkipMissing
	case slices.Contains(l.Flags, flagCertAuthority):
		return SkipCertAuthority
	case l.OSUser == t.ConnectionUser:
		return SkipConnectionAccount
	case t.KeysManagedElsewhere || slices.Contains(t.ManagedElsewhereUsers, l.OSUser):
		return SkipKeysManagedElsewhere
	case !t.SSHDRead || slices.Contains(t.SSHDUnreadUsers, l.OSUser):
		return SkipSSHDUnreadable
	case t.PubkeyAuthentication == "no":
		return SkipPubkeyDisabled
	}
	return ""
}

// verifyRule: a superuser location on a server with PermitRootLogin no cannot be tested (R41 row 9);
// a from= option may exclude Alice's address, so a refused login there is unverifiable, not failed.
func verifyRule(t Target, user, options string) (bool, string) {
	if (user == "root" || slices.Contains(t.UID0Users, user)) && t.PermitRootLogin == "no" {
		return false, NoteRootLoginDisabled
	}
	if keymat.HasFromOption(options) {
		return true, NoteFromOption
	}
	return true, ""
}

func joinLine(options, key, comment string) string {
	parts := make([]string, 0, 3)
	for _, p := range []string{options, key, comment} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " ")
}
```

`internal/sshkeys/plan/digest.go`:

```go
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
)

type digestAction struct {
	Location uuid.UUID `json:"l"`
	Target   uuid.UUID `json:"t"`
	User     string    `json:"u"`
	File     string    `json:"f"`
	Options  string    `json:"o"`
	Skip     string    `json:"s"`
	Verify   bool      `json:"v"`
	Note     string    `json:"n"`
}

// Digest is the SHA-256 of the plan's decisions: the key, the new key type, the overlap and every
// action's location, server, user, file, options, skip and verification rule, in the plan's order.
// Display text (server names, comments, the lines) is not part of it.
func (p Plan) Digest() string {
	d := struct {
		Key        uuid.UUID      `json:"k"`
		FP         string         `json:"fp"`
		NewKeyType string         `json:"nt"`
		Overlap    int            `json:"o"`
		Actions    []digestAction `json:"a"`
	}{Key: p.KeyID, FP: p.Fingerprint, NewKeyType: p.NewKeyType, Overlap: p.Overlap, Actions: make([]digestAction, 0, len(p.Actions))}
	for _, a := range p.Actions {
		d.Actions = append(d.Actions, digestAction{a.LocationID, a.TargetID, a.OSUser, a.FilePath, a.Options, a.Skip, a.Verify, a.VerifyNote})
	}
	raw, _ := json.Marshal(d) // cannot fail: fixed struct of strings, bools, ints and UUIDs
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
```

`internal/sshkeys/plan/times.go`:

```go
package plan

import "time"

const (
	day            = 24 * time.Hour
	decisionWindow = 14 * day
	freshness      = 15 * time.Minute
)

// FirstRun is when a policy switched on at enabledAt first runs (R41 row 12).
func FirstRun(enabledAt time.Time, intervalDays int) time.Time {
	return enabledAt.UTC().Add(time.Duration(intervalDays) * day)
}

// NextRun is the run after one that started at startedAt.
func NextRun(startedAt time.Time, intervalDays int) time.Time {
	return startedAt.UTC().Add(time.Duration(intervalDays) * day)
}

// NoticeDue is when the preview of a run due at nextRun is sent.
func NoticeDue(nextRun time.Time, notifyBeforeHours int) time.Time {
	return nextRun.UTC().Add(-time.Duration(notifyBeforeHours) * time.Hour)
}

// PlannedFor is the start of a run previewed now: never earlier than the full notice period.
func PlannedFor(now, nextRun time.Time, notifyBeforeHours int) time.Time {
	earliest := now.UTC().Add(time.Duration(notifyBeforeHours) * time.Hour)
	if nextRun.Before(earliest) {
		return earliest
	}
	return nextRun.UTC()
}

// OverlapUntil is the end of the overlap of a run verified at verifiedAt.
func OverlapUntil(verifiedAt time.Time, overlapMinutes int) time.Time {
	return verifiedAt.UTC().Add(time.Duration(overlapMinutes) * time.Minute)
}

// Due reports whether a timer at "at" has fired at now (inclusive).
func Due(now, at time.Time) bool { return !now.Before(at) }

// ReminderDue is the "one day before the end" reminder of an overlap longer than 48 hours.
func ReminderDue(overlapUntil time.Time, overlapMinutes int) (time.Time, bool) {
	if overlapMinutes <= 48*60 {
		return time.Time{}, false
	}
	return overlapUntil.UTC().Add(-day), true
}

// DecisionDue is the end of the window for an Administrator's decision on unverifiable locations.
func DecisionDue(waitingSince time.Time) time.Time { return waitingSince.UTC().Add(decisionWindow) }

// Fresh reports whether a re-verification at reverifiedAt may justify a removal sent at now.
func Fresh(now, reverifiedAt time.Time) bool {
	return !reverifiedAt.After(now) && now.Sub(reverifiedAt) <= freshness
}
```

- [ ] **Step 4: Run the tests to verify they pass, with full coverage**

Run: `go test -count=1 -coverprofile=/tmp/plan.out ./internal/sshkeys/plan/ && go tool cover -func=/tmp/plan.out | tail -1`
Expected: `ok` and `total: (statements) 100.0%`.

Run: `make lint`
Expected: no finding.

- [ ] **Step 5: Commit**

```bash
git add -- internal/sshkeys/plan
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(sshkeys): rotation planner — skips, verification rules, shared files, digest, timers" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/sshkeys/plan
```

---

### Task 3: Provider framework: `VerifyKeyLogin`, `CapKeyLogin`, candidate key files, the added line's number; the fake's `KeyWorld` with fault injection; conformance

**Files:**
- Modify: `internal/providers/types.go` (KeyLogin types, `UserKeyFiles`, `DiscoveryResult.KeyFiles`, `AuthKeyResult.LineNo`)
- Modify: `internal/providers/provider.go` (`Session.VerifyKeyLogin` with its doc comment from C5)
- Modify: `internal/providers/capability.go` (`CapKeyLogin`, `knownCapabilities`)
- Modify: `internal/providers/unsupported.go` (`VerifyKeyLogin` → `ErrUnsupported`)
- Modify: `internal/providers/providertest/providertest.go` (one `sessionOps` entry)
- Create: `internal/providers/fake/keyworld.go`; Modify: `internal/providers/fake/fake.go` (`Config.KeyLogin`, `Config.Keys`, `session.VerifyKeyLogin`, world-backed list/add/remove, `Call.Login`)
- Test: `internal/providers/providers_test.go`, `internal/providers/fake/keyworld_test.go`

**Interfaces:**
- Consumes: existing `providers` types (C5 lists the additions).
- Produces: C5 exactly; `fake.KeyWorld`, `fake.NewKeyWorld`, `fake.FaultPoint`, `fake.Fault*`, `fake.Event`, `Config.Keys`, `Config.KeyLogin`. Every other `Session` implementation in the tree gets the method in this task or the next: `linuxssh.session` (Task 4; it embeds `UnsupportedSession`, so it compiles here and answers `ErrUnsupported` until Task 4), `nginx.session` (embeds `providers.Session`), `azurekv` (embeds `UnsupportedSession`), `fake.session` (this task).

- [ ] **Step 1: Write the failing tests**

Append to `internal/providers/providers_test.go`:

```go
func TestKeyLoginIsAKnownCapabilityAndUnsupportedByDefault(t *testing.T) {
	assert.True(t, providers.NewCapabilitySet(providers.CapKeyLogin).Has(providers.CapKeyLogin))
	_, err := providers.UnsupportedSession{}.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	for _, o := range []providers.KeyLoginOutcome{providers.KeyLoginAccepted, providers.KeyLoginRefused, providers.KeyLoginUnprovable} {
		assert.NotEmpty(t, string(o))
	}
}
```

(`providers_test.go` already checks that every capability constant is in `knownCapabilities`; the new constant is covered by that table once it is added there.)

`internal/providers/fake/keyworld_test.go`:

```go
package fake

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
)

type keySource struct{ s ssh.Signer }

func (k keySource) SSHSigner(context.Context) (ssh.Signer, func(), error) { return k.s, func() {}, nil }

func newKey(t *testing.T) (line, fp string, src providers.CredentialSource) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " c", ssh.FingerprintSHA256(s.PublicKey()), keySource{s}
}

func worldSession(t *testing.T, w *KeyWorld, target uuid.UUID) providers.Session {
	t.Helper()
	p := New(providers.KindLinuxSSH, providers.CapTestConnection, providers.CapAuthorizedKeys, providers.CapKeyLogin)
	p.Configure(func(c *Config) { c.Keys = w; c.SkipHostKeyCheck = true })
	s, err := p.Open(context.Background(), providers.TargetRef{ID: target, Kind: providers.KindLinuxSSH}, nil, providers.Env{})
	require.NoError(t, err)
	return s
}

func TestKeyWorldAddLoginRemove(t *testing.T) {
	ctx := context.Background()
	w := NewKeyWorld()
	target := uuid.New()
	oldLine, oldFP, oldKey := newKey(t)
	newLine, newFP, newKey := newKey(t)
	w.Put(target, "deploy", "/home/deploy/.ssh/authorized_keys", "# comment", oldLine)
	s := worldSession(t, w, target)

	r, err := s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: oldKey})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginAccepted, r.Outcome)
	r, err = s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: newKey})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginRefused, r.Outcome)

	res, err := s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Line: newLine}, nil)
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.Equal(t, 3, res.LineNo)
	res, err = s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Line: newLine}, nil)
	require.NoError(t, err)
	assert.False(t, res.Changed, "adding a present key changes nothing")
	assert.Equal(t, 3, res.LineNo)
	r, err = s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: newKey})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginAccepted, r.Outcome)

	_, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Fingerprint: oldFP, ProtectedFingerprints: []string{oldFP}}, nil)
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "sshkey.own_key_protected", pe.Code)

	res, err = s.RemoveAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Fingerprint: oldFP}, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, res.Removed)
	assert.Equal(t, []string{"# comment", newLine}, w.Lines(target, "/home/deploy/.ssh/authorized_keys"))
	assert.False(t, w.Has(target, "/home/deploy/.ssh/authorized_keys", oldFP))
	assert.True(t, w.Has(target, "/home/deploy/.ssh/authorized_keys", newFP))
	// three logins, two adds, one removal; the refused protected removal never reached the world
	assert.Len(t, w.Events(), 6)
}

func TestKeyWorldSharedFileServesEveryUser(t *testing.T) {
	ctx := context.Background()
	w := NewKeyWorld()
	target := uuid.New()
	line, _, key := newKey(t)
	w.Put(target, "deploy", "/etc/ssh/keys/shared", line)
	w.Put(target, "backup", "/etc/ssh/keys/shared", line)
	s := worldSession(t, w, target)
	for _, u := range []string{"deploy", "backup"} {
		r, err := s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: u, Key: key})
		require.NoError(t, err)
		assert.Equal(t, providers.KeyLoginAccepted, r.Outcome, u)
	}
	assert.Equal(t, []string{line}, w.Lines(target, "/etc/ssh/keys/shared"), "one file, not one per user")
}

func TestKeyWorldFaults(t *testing.T) {
	ctx := context.Background()
	target := uuid.New()
	file := "/home/deploy/.ssh/authorized_keys"
	add := func(s providers.Session, line string) (providers.AuthKeyResult, error, []string) {
		var steps []string
		res, err := s.AddAuthorizedKey(ctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy", FilePath: file, Line: line},
			stepFunc(func(name string, st providers.StepStatus) { steps = append(steps, name+":"+string(st)) }))
		return res, err, steps
	}
	cases := []struct {
		fault       Fault
		code        string
		changed     bool
		writeStart  bool
	}{
		{FaultRefuse, "ssh.helper_refused", false, false},
		{FaultUnreachable, "ssh.unreachable", false, false},
		{FaultAfterWrite, "ssh.timeout", true, true},
		{FaultFileChanged, "ssh.file_changed", false, true},
	}
	for _, c := range cases {
		w := NewKeyWorld()
		w.Put(target, "deploy", file)
		w.SetFault(func(p FaultPoint) Fault {
			if p.Method == "AddAuthorizedKey" {
				return c.fault
			}
			return FaultNone
		})
		line, fp, _ := newKey(t)
		res, err, steps := add(worldSession(t, w, target), line)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, c.code, pe.Code)
		assert.Equal(t, c.changed, w.Has(target, file, fp))
		assert.Equal(t, c.changed, res.Changed)
		assert.Equal(t, c.writeStart, slicesContains(steps, "write:started"))
	}

	w := NewKeyWorld()
	w.Put(target, "deploy", file)
	w.SetFault(func(p FaultPoint) Fault { return FaultHang })
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	line, fp, _ := newKey(t)
	_, err := worldSession(t, w, target).AddAuthorizedKey(cctx, providers.AuthKeyChange{OperationID: uuid.New(), OSUser: "deploy",
		FilePath: file, Line: line}, nil)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, w.Has(target, file, fp))

	w = NewKeyWorld()
	line, _, key := newKey(t)
	w.Put(target, "deploy", file, line)
	for fault, want := range map[Fault]providers.KeyLoginOutcome{FaultRefuse: providers.KeyLoginRefused, FaultUnprovable: providers.KeyLoginUnprovable} {
		w.SetFault(func(FaultPoint) Fault { return fault })
		r, err := worldSession(t, w, target).VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: key})
		require.NoError(t, err)
		assert.Equal(t, want, r.Outcome)
	}
	w.SetFault(func(FaultPoint) Fault { return FaultUnreachable })
	_, err = worldSession(t, w, target).VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: key})
	assert.Error(t, err)
	n := 0
	for _, e := range w.Events() {
		assert.Equal(t, n+1, e.N)
		n = e.N
	}
}

type stepFunc func(name string, st providers.StepStatus)

func (f stepFunc) Step(name string, st providers.StepStatus, _ map[string]string) { f(name, st) }

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestScriptedKeyLoginWithoutWorld(t *testing.T) {
	p := New(providers.KindLinuxSSH, providers.CapKeyLogin)
	p.Configure(func(c *Config) {
		c.SkipHostKeyCheck = true
		c.KeyLogin = func(providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
			return providers.KeyLoginResult{Outcome: providers.KeyLoginUnprovable}, nil
		}
	})
	s, err := p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	r, err := s.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy"})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginUnprovable, r.Outcome)
	assert.Equal(t, 1, p.Count("VerifyKeyLogin"))

	q := New(providers.KindLinuxSSH) // no CapKeyLogin
	q.Configure(func(c *Config) { c.SkipHostKeyCheck = true })
	s2, err := q.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	_, err = s2.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
}
```

Also extend the fake's own conformance test (the existing `fake` test that runs `providertest.CheckSession`): give it `CapKeyLogin` and a `KeyLogin` func that refuses an empty request with `providers.NewError("ssh.helper_refused", false, nil, map[string]string{"field": "os_user"})`, as every provider must.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/providers/ ./internal/providers/fake/`
Expected: FAIL — undefined: `providers.CapKeyLogin`, `KeyLoginRequest`, `NewKeyWorld`, …

- [ ] **Step 3: Write the implementation**

`internal/providers/types.go` and `capability.go`, `provider.go`, `unsupported.go`: add exactly the declarations of C5 (`CapKeyLogin` in `knownCapabilities`; `UnsupportedSession.VerifyKeyLogin` returns `KeyLoginResult{}, ErrUnsupported`).

`internal/providers/providertest/providertest.go`, in `sessionOps` after `RemoveAuthorizedKey`:

```go
	// An empty request names no user: a provider refuses it before anything is sent (and, with a
	// cancelled context, with an error wrapping context.Canceled).
	{"VerifyKeyLogin", providers.CapKeyLogin, func(ctx context.Context, s providers.Session) (any, error) {
		return s.VerifyKeyLogin(ctx, providers.KeyLoginRequest{})
	}},
```

`internal/providers/fake/keyworld.go`:

```go
package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
)

// KeyWorld models authorized_keys files of several targets (C5). A file is identified by its target
// and path; Put also records which users read it, so a shared file serves all of them (spec §13.3).
type KeyWorld struct {
	mu     sync.Mutex
	files  map[worldFile][]string
	users  map[worldUser][]string // (target, user) -> file paths the user's logins read
	events []Event
	fault  func(FaultPoint) Fault
	n      int
}

type worldFile struct {
	target uuid.UUID
	path   string
}

type worldUser struct {
	target uuid.UUID
	user   string
}

// FaultPoint, Fault, the Fault constants and Event: exactly as in C5.

// NewKeyWorld returns an empty world without faults.
func NewKeyWorld() *KeyWorld {
	return &KeyWorld{files: map[worldFile][]string{}, users: map[worldUser][]string{}}
}

// Put sets a file's lines (verbatim) and records that osUser reads it.
func (w *KeyWorld) Put(target uuid.UUID, osUser, file string, lines ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.files[worldFile{target, file}] = slices.Clone(lines)
	u := worldUser{target, osUser}
	if !slices.Contains(w.users[u], file) {
		w.users[u] = append(w.users[u], file)
	}
}

// Lines returns a copy of a file's lines (nil when the file does not exist).
func (w *KeyWorld) Lines(target uuid.UUID, file string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.files[worldFile{target, file}])
}

// Has reports whether any line of the file holds the key with this fingerprint.
func (w *KeyWorld) Has(target uuid.UUID, file, fingerprint string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return indexOf(w.files[worldFile{target, file}], fingerprint) >= 0
}

// Events returns every call, in order.
func (w *KeyWorld) Events() []Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.events)
}

// SetFault installs the fault decision (nil: none).
func (w *KeyWorld) SetFault(f func(FaultPoint) Fault) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fault = f
}

func lineFingerprint(line string) string {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pk)
}

func indexOf(lines []string, fp string) int {
	return slices.IndexFunc(lines, func(l string) bool { return fp != "" && lineFingerprint(l) == fp })
}

func digest(lines []string) string {
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// begin numbers the call and asks the fault decision, under the lock.
func (w *KeyWorld) begin(p FaultPoint) (FaultPoint, Fault) {
	w.n++
	p.N = w.n
	f := FaultNone
	if w.fault != nil {
		f = w.fault(p)
	}
	return p, f
}

func (w *KeyWorld) record(p FaultPoint, f Fault, changed bool, o providers.KeyLoginOutcome) {
	w.events = append(w.events, Event{FaultPoint: p, Fault: f, Changed: changed, Outcome: o})
}

func step(log providers.StepLogger, name string, st providers.StepStatus) {
	if log != nil {
		log.Step(name, st, nil)
	}
}

// hang blocks until ctx ends (FaultHang), then answers as a timed-out call that changed nothing.
func hang(ctx context.Context) error {
	<-ctx.Done()
	return providers.NewError("ssh.timeout", true, ctx.Err(), nil)
}

func (w *KeyWorld) add(ctx context.Context, target uuid.UUID, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	fp := lineFingerprint(req.Line)
	w.mu.Lock()
	p, f := w.begin(FaultPoint{Method: "AddAuthorizedKey", Target: target, OSUser: req.OSUser, FilePath: req.FilePath, Fingerprint: fp})
	if f == FaultHang {
		w.record(p, f, false, "")
		w.mu.Unlock()
		return providers.AuthKeyResult{}, hang(ctx)
	}
	defer w.mu.Unlock()
	file := worldFile{target, req.FilePath}
	old := w.files[file]
	step(log, "precheck", providers.StepOK)
	switch f {
	case FaultRefuse:
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.helper_refused", false, nil, map[string]string{"helper_code": "INVALID_ARGUMENT"})
	case FaultUnreachable:
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
	case FaultFileChanged:
		step(log, "write", providers.StepStarted)
		step(log, "write", providers.StepFailed)
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.file_changed", true, nil, map[string]string{"attempts": "3"})
	}
	if i := indexOf(old, fp); i >= 0 {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{OldSHA256: digest(old), NewSHA256: digest(old), LineNo: i + 1}, nil
	}
	step(log, "write", providers.StepStarted)
	next := append(slices.Clone(old), req.Line)
	w.files[file] = next
	u := worldUser{target, req.OSUser}
	if !slices.Contains(w.users[u], req.FilePath) {
		w.users[u] = append(w.users[u], req.FilePath)
	}
	res := providers.AuthKeyResult{Changed: true, OldSHA256: digest(old), NewSHA256: digest(next), LineNo: len(next), Verified: true,
		Backup: "/var/lib/alice-helper/backups/" + req.OperationID.String()}
	w.record(p, f, true, "")
	if f == FaultAfterWrite {
		return res, providers.NewError("ssh.timeout", true, nil, nil)
	}
	step(log, "write", providers.StepOK)
	return res, nil
}

func (w *KeyWorld) remove(ctx context.Context, target uuid.UUID, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	if slices.Contains(req.ProtectedFingerprints, req.Fingerprint) {
		return providers.AuthKeyResult{}, providers.NewError("sshkey.own_key_protected", false, nil,
			map[string]string{"reason": "protected_fingerprint"})
	}
	w.mu.Lock()
	p, f := w.begin(FaultPoint{Method: "RemoveAuthorizedKey", Target: target, OSUser: req.OSUser, FilePath: req.FilePath, Fingerprint: req.Fingerprint})
	if f == FaultHang {
		w.record(p, f, false, "")
		w.mu.Unlock()
		return providers.AuthKeyResult{}, hang(ctx)
	}
	defer w.mu.Unlock()
	file := worldFile{target, req.FilePath}
	old := w.files[file]
	step(log, "precheck", providers.StepOK)
	switch f {
	case FaultRefuse:
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.helper_refused", false, nil, map[string]string{"helper_code": "INVALID_ARGUMENT"})
	case FaultUnreachable:
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
	case FaultFileChanged:
		step(log, "write", providers.StepStarted)
		step(log, "write", providers.StepFailed)
		w.record(p, f, false, "")
		return providers.AuthKeyResult{}, providers.NewError("ssh.file_changed", true, nil, map[string]string{"attempts": "3"})
	}
	next := slices.DeleteFunc(slices.Clone(old), func(l string) bool { return lineFingerprint(l) == req.Fingerprint })
	removed := len(old) - len(next)
	if removed == 0 {
		w.record(p, f, false, "")
		return providers.AuthKeyResult{OldSHA256: digest(old), NewSHA256: digest(old)}, nil
	}
	step(log, "write", providers.StepStarted)
	w.files[file] = next
	res := providers.AuthKeyResult{Changed: true, Removed: removed, OldSHA256: digest(old), NewSHA256: digest(next), Verified: true,
		Backup: "/var/lib/alice-helper/backups/" + req.OperationID.String()}
	w.record(p, f, true, "")
	if f == FaultAfterWrite {
		return res, providers.NewError("ssh.timeout", true, nil, nil)
	}
	step(log, "write", providers.StepOK)
	return res, nil
}

func (w *KeyWorld) login(ctx context.Context, target uuid.UUID, req providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
	if req.OSUser == "" || req.Key == nil {
		return providers.KeyLoginResult{}, providers.NewError("ssh.helper_refused", false, nil, map[string]string{"field": "os_user"})
	}
	s, release, err := req.Key.SSHSigner(ctx)
	if err != nil {
		return providers.KeyLoginResult{}, providers.NewError("internal.unexpected", false, err, nil)
	}
	fp := ssh.FingerprintSHA256(s.PublicKey())
	release()
	w.mu.Lock()
	p, f := w.begin(FaultPoint{Method: "VerifyKeyLogin", Target: target, OSUser: req.OSUser, Fingerprint: fp})
	if f == FaultHang {
		w.record(p, f, false, "")
		w.mu.Unlock()
		return providers.KeyLoginResult{}, hang(ctx)
	}
	defer w.mu.Unlock()
	switch f {
	case FaultRefuse:
		w.record(p, f, false, providers.KeyLoginRefused)
		return providers.KeyLoginResult{Outcome: providers.KeyLoginRefused}, nil
	case FaultUnprovable:
		w.record(p, f, false, providers.KeyLoginUnprovable)
		return providers.KeyLoginResult{Outcome: providers.KeyLoginUnprovable}, nil
	case FaultUnreachable:
		w.record(p, f, false, "")
		return providers.KeyLoginResult{}, providers.NewError("ssh.unreachable", true, nil, nil)
	case FaultAfterWrite:
		w.record(p, f, false, "")
		return providers.KeyLoginResult{}, providers.NewError("ssh.timeout", true, nil, nil)
	}
	out := providers.KeyLoginRefused
	for _, file := range w.users[worldUser{target, req.OSUser}] {
		if indexOf(w.files[worldFile{target, file}], fp) >= 0 {
			out = providers.KeyLoginAccepted
			break
		}
	}
	w.record(p, f, false, out)
	return providers.KeyLoginResult{Outcome: out}, nil
}
```

`internal/providers/fake/fake.go`: add to `Config`

```go
	// KeyLogin decides VerifyKeyLogin when Keys is nil; nil = accepted.
	KeyLogin func(req providers.KeyLoginRequest) (providers.KeyLoginResult, error)
	// Keys, when set, makes ListAuthorizedKeys, AddAuthorizedKey, RemoveAuthorizedKey and VerifyKeyLogin act on
	// the modelled files (AddResult, RemoveResult and their errors are then ignored).
	Keys *KeyWorld
```

(`Config.clone` copies both pointers as they are: the world is shared on purpose.) `Call` gains `Login providers.KeyLoginRequest` with `Key` set to nil when recorded (the fake keeps no signer). The session methods:

```go
func (s *session) AddAuthorizedKey(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	cfg := s.p.record(Call{Method: "AddAuthorizedKey", Target: s.target, Change: req})
	if !s.p.caps.Has(providers.CapAuthorizedKeys) {
		return providers.AuthKeyResult{}, providers.ErrUnsupported
	}
	if cfg.Keys != nil {
		return cfg.Keys.add(ctx, s.target, req, log)
	}
	return cfg.AddResult, cfg.AddErr
}

func (s *session) RemoveAuthorizedKey(ctx context.Context, req providers.AuthKeyChange, log providers.StepLogger) (providers.AuthKeyResult, error) {
	cfg := s.p.record(Call{Method: "RemoveAuthorizedKey", Target: s.target, Change: req})
	if !s.p.caps.Has(providers.CapAuthorizedKeys) {
		return providers.AuthKeyResult{}, providers.ErrUnsupported
	}
	if cfg.Keys != nil {
		return cfg.Keys.remove(ctx, s.target, req, log)
	}
	return cfg.RemoveResult, cfg.RemoveErr
}

func (s *session) VerifyKeyLogin(ctx context.Context, req providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
	kept := req
	kept.Key = nil
	cfg := s.p.record(Call{Method: "VerifyKeyLogin", Target: s.target, Login: kept})
	if !s.p.caps.Has(providers.CapKeyLogin) {
		return providers.KeyLoginResult{}, providers.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return providers.KeyLoginResult{}, providers.NewError("ssh.timeout", true, err, nil)
	}
	if cfg.Keys != nil {
		return cfg.Keys.login(ctx, s.target, req)
	}
	if cfg.KeyLogin != nil {
		return cfg.KeyLogin(req)
	}
	return providers.KeyLoginResult{Outcome: providers.KeyLoginAccepted}, nil
}
```

`ListAuthorizedKeys` with `Keys` set lists the target's files' parseable lines as `DiscoveredSSHKey` (one per (user, file, line)), so an inventory reconciliation in the job tests sees what the world holds.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race ./internal/providers/... && go vet ./... && go vet -tags integration ./...`
Expected: `ok` for every package; `go vet` clean (every `Session` implementation compiles: `linuxssh` and `azurekv` through `UnsupportedSession`, `nginx` through its embedded session).

Run: `go test -count=1 -coverprofile=/tmp/prov.out ./internal/providers/ && go tool cover -func=/tmp/prov.out | tail -1`
Expected: `total: (statements) 100.0%` (floor 100).

- [ ] **Step 5: Commit**

```bash
git add -- internal/providers/fake/keyworld.go internal/providers/fake/keyworld_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(providers): VerifyKeyLogin capability, candidate key files, added line number; fake key world with faults" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/providers
```

---

### Task 4: `linuxssh`: `VerifyKeyLogin` over a fresh connection, key files in discovery, `LineNo`; the test server's per-user logins; real OpenSSH case

**Files:**
- Create: `internal/providers/linuxssh/keylogin.go`, `internal/providers/linuxssh/keylogin_test.go`
- Modify: `internal/providers/linuxssh/provider.go` (session fields `target`, `dialer`; `CapKeyLogin` in `New`), `internal/providers/linuxssh/keyops.go` (`LineNo` on add), `internal/providers/linuxssh/discover.go` (`KeyFiles`)
- Modify: `internal/providers/linuxssh/linuxsshtest/server.go` (`SetLoginCheck`), `internal/providers/linuxssh/linuxsshtest/emulator.go` (`AcceptsLogin`)
- Modify: `internal/providers/nginx/provider.go` (`CapKeyLogin` in the capability set; the embedded session implements it)
- Test: `internal/providers/linuxssh/keyops_test.go` (LineNo), `internal/providers/linuxssh/provider_test.go` (KeyFiles), `internal/providers/linuxssh/containers_integration_test.go` (real OpenSSH)

**Interfaces:**
- Consumes: C5 (Task 3); `Dialer.Dial(ctx, target, Config, CredentialSource)` (maps a refused key to `ssh.auth_failed` with `reason` `key_rejected`, and an authentication without the offered key, or no public-key method, to `ssh.auth_failed` with `reason` `publickey_not_offered`).
- Produces: `linuxssh.KeyLoginBudget = 10 * time.Second`; `(*session).VerifyKeyLogin`; `linuxsshtest.Server.SetLoginCheck(func(user string, key ssh.PublicKey) bool)`; `linuxsshtest.Emulator.AcceptsLogin(user string, key ssh.PublicKey) bool`; `DiscoveryResult.KeyFiles` filled from `authkeys-list` (users in the helper's order, files in sshd's order, at most 200 users and 8 files each; the connection account included — inventory leaves it out of the deploy list).

- [ ] **Step 1: Write the failing tests**

`internal/providers/linuxssh/keylogin_test.go` (uses the package's existing test environment `newProvEnv`/`provEnv` of `helpers_test.go`: an emulator behind a `linuxsshtest.Server`, a pinned host key and the platform key authorized — read it before writing):

```go
package linuxssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/providers"
)

type signerSource struct {
	s        ssh.Signer
	released *bool
}

func (k signerSource) SSHSigner(context.Context) (ssh.Signer, func(), error) {
	return k.s, func() {
		if k.released != nil {
			*k.released = true
		}
	}, nil
}

func newUserKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " alice:test:2026-10-05"
}

// Review Focus 1: accepted only when the server took exactly this key for this user.
func TestVerifyKeyLoginOutcomes(t *testing.T) {
	e := newProvEnv(t)
	s, line := newUserKey(t)
	other, _ := newUserKey(t)
	e.emu.AddUser("deploy", 1001, "/home/deploy")
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(line+"\n"))
	e.srv.SetLoginCheck(e.emu.AcceptsLogin)
	sess := e.open(t)
	defer sess.Close()

	released := false
	r, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, &released}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginAccepted, r.Outcome)
	assert.True(t, released, "the key is released after the handshake")

	r, err = sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{other, nil}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginRefused, r.Outcome)

	r, err = sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "nobody", Key: signerSource{s, nil}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginRefused, r.Outcome, "the key is not the user's")

	for _, cmd := range e.srv.Commands() {
		assert.NotContains(t, cmd, "deploy", "a test login runs nothing")
	}
}

// Review Focus 1: a server that lets anyone in without a key proves nothing.
func TestVerifyKeyLoginWithoutKeyIsUnprovable(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	e.srv.AcceptNoAuth()
	r, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginUnprovable, r.Outcome)
}

func TestVerifyKeyLoginNoPublicKeyMethodIsUnprovable(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	e.srv.DisablePublicKeyAuth()
	r, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	require.NoError(t, err)
	assert.Equal(t, providers.KeyLoginUnprovable, r.Outcome)
}

func TestVerifyKeyLoginRefusesBadRequestsAndHonoursContext(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	for _, req := range []providers.KeyLoginRequest{{}, {OSUser: "deploy"}, {OSUser: "bad user", Key: signerSource{s, nil}}} {
		_, err := sess.VerifyKeyLogin(context.Background(), req)
		var pe *providers.Error
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, "ssh.helper_refused", pe.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sess.VerifyKeyLogin(ctx, providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	assert.ErrorIs(t, err, context.Canceled)
	require.NoError(t, sess.Close())
	_, err = sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	assert.Error(t, err, "a closed session refuses")
}

// A host key change seen by the test login is an error, never an outcome.
func TestVerifyKeyLoginHostKeyChanged(t *testing.T) {
	e := newProvEnv(t)
	s, _ := newUserKey(t)
	sess := e.open(t)
	defer sess.Close()
	e.srv.SetHostKey(newTestHostKey(t)) // another key than the pinned one
	_, err := sess.VerifyKeyLogin(context.Background(), providers.KeyLoginRequest{OSUser: "deploy", Key: signerSource{s, nil}})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "target.host_key_changed", pe.Code)
}

func TestKeyLoginBudget(t *testing.T) { assert.Equal(t, 10*time.Second, KeyLoginBudget) }
```

(`newTestHostKey` is `linuxsshtest.NewHostKey`; `e.open` is the existing helper that opens a session through the provider; when the helper names differ, use the existing ones — the assertions stay.)

In `keyops_test.go` add to the existing add tests: `assert.Equal(t, 3, res.LineNo)` after adding to a two-line file, `assert.Equal(t, 2, res.LineNo)` when the key is already on line 2 (`Changed == false`), and a case for the F-37 file without a trailing newline (`LineNo` counts the line the key now starts). In `provider_test.go` add `TestDiscoverReportsKeyFiles`: an emulator with users `root` and `deploy`, sshd `AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2`; `res.KeyFiles` equals `[{root [/root/.ssh/authorized_keys /root/.ssh/authorized_keys2]} {deploy [/home/deploy/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys2]}]` in the helper's order, and with 9 candidate files only the first 8 are kept.

In `containers_integration_test.go` (the real OpenSSH matrix of Phase 3, `-tags integration`, testcontainers) add to the per-image subtest, after the F-38 case: generate an Ed25519 key, `AddAuthorizedKey` it for the fixture user with a key file, `VerifyKeyLogin` → `accepted`; a second, never-added key → `refused`; `RemoveAuthorizedKey` the first → `VerifyKeyLogin` → `refused`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/providers/linuxssh/`
Expected: FAIL — `sess.VerifyKeyLogin` answers `ErrUnsupported`; `e.srv.SetLoginCheck` undefined; `res.LineNo` is 0.

- [ ] **Step 3: Write the implementation**

`internal/providers/linuxssh/keylogin.go`:

```go
package linuxssh

import (
	"context"
	"errors"
	"time"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// KeyLoginBudget bounds one test login, dial to authentication (spec §13.4: 10 s).
const KeyLoginBudget = 10 * time.Second

// VerifyKeyLogin is the test login of spec §13.4 (R41 row 9): a fresh connection outside the pool,
// the target's pinned host key required, authenticating as OSUser with only req.Key. No channel is
// opened and nothing runs. The connection is closed at once. It records nothing about the target:
// a refused or unprovable login is an outcome; a connection failure is the dial's error (a changed
// host key is still observed by the store, as for every dial).
func (s *session) VerifyKeyLogin(ctx context.Context, req providers.KeyLoginRequest) (providers.KeyLoginResult, error) {
	if err := s.begin(ctx); err != nil {
		return providers.KeyLoginResult{}, err
	}
	if req.Key == nil || !helperproto.ValidAccount(req.OSUser) {
		return providers.KeyLoginResult{}, refusedRequest("os_user")
	}
	ctx, cancel := context.WithTimeout(ctx, KeyLoginBudget)
	defer cancel()
	cfg := s.cfg
	cfg.Username = req.OSUser
	conn, err := s.dialer.Dial(ctx, s.target, cfg, req.Key)
	if err == nil {
		_ = conn.Close()
		return providers.KeyLoginResult{Outcome: providers.KeyLoginAccepted}, nil
	}
	var pe *providers.Error
	if errors.As(err, &pe) && pe.Code == "ssh.auth_failed" {
		if pe.Params["reason"] == "publickey_not_offered" {
			return providers.KeyLoginResult{Outcome: providers.KeyLoginUnprovable}, nil
		}
		return providers.KeyLoginResult{Outcome: providers.KeyLoginRefused}, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return providers.KeyLoginResult{}, providers.NewError("ssh.timeout", true, ctxErr, nil)
	}
	return providers.KeyLoginResult{}, err
}
```

`Conn.Close` is the existing close of a dialed connection (if the type's close method has another name, use it). `provider.go`: the session struct gains `target uuid.UUID` and `dialer *Dialer`; `Open` sets them from `t.ID` and `p.pool.dialer`; `New` adds `providers.CapKeyLogin` to the capability set. `nginx/provider.go` adds `providers.CapKeyLogin` to its capability set (its session embeds the linuxssh one).

`keyops.go`, in `addOnce`: when the key is present (`!added`), return `LineNo` = the 1-based index of the first key line whose fingerprint matches in `ak.Lines` (line numbers as `ParseAuthorizedKeys` counts them, the same the inventory stores); after a write, `LineNo` = the key's line in `next` (the last line). Add a helper `lineOf(ak AuthorizedKeys, fp string) int` beside `RemoveFingerprint` in `authkeys.go`, with its own unit test.

`discover.go`: after the account list is read, fill `res.KeyFiles` from `list.Users` (`UserFiles.User` and `Files[].Path`), skipping users with `SSHDUnreadable` (their files may be wrong) — at most 200 users and 8 files per user (constants `maxKeyFileUsers = 200`, `maxKeyFilesPerUser = 8`).

`linuxsshtest/server.go`:

```go
// SetLoginCheck makes the server also accept a public key that check accepts for the user (the
// connection user's single authorized key of Authorize keeps working as before).
func (s *Server) SetLoginCheck(check func(user string, key ssh.PublicKey) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loginCheck = check
}
```

and `checkKey(meta ssh.ConnMetadata, key ssh.PublicKey)` accepts when `authorized` matches (as before) **or** `loginCheck != nil && loginCheck(meta.User(), key)`; the check runs outside `s.mu` (copy the function under the lock first) because the emulator takes its own lock.

`linuxsshtest/emulator.go`:

```go
// AcceptsLogin reports whether one of user's candidate files (as authkeys-list resolves them) holds
// key, as sshd would decide for a plain key line.
func (e *Emulator) AcceptsLogin(user string, key ssh.PublicKey) bool
```

implemented with the emulator's own scan (`scanLocked` and the file map; parse each line with `ssh.ParseAuthorizedKey`, compare `key.Marshal()`; a `cert-authority` line never matches).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race ./internal/providers/linuxssh/... ./internal/providers/nginx/...`
Expected: `ok` for every package.

Run (testcontainers; another agent may use testcontainers at the same time, Playwright must not be running): `go test -count=1 -tags integration -run 'TestContainers|TestRealOpenSSH' ./internal/providers/linuxssh/`
Expected: `ok` (the per-image subtests include the test-login case).

Run: `go test -count=1 -coverprofile=/tmp/lssh.out ./internal/providers/linuxssh/ && go tool cover -func=/tmp/lssh.out | tail -1`
Expected: total ≥ 92.0 % (floor 92).

Run: `git diff --stat -- cmd/alice-helper internal/providers/linuxssh/helperproto bin/alice-helper.sha256`
Expected: no output (no helper change).

- [ ] **Step 5: Commit**

```bash
git add -- internal/providers/linuxssh/keylogin.go internal/providers/linuxssh/keylogin_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(linuxssh): test login with a key as the OS user, candidate key files in discovery, added line number" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/providers/linuxssh internal/providers/nginx/provider.go
```

---

### Task 5: Migration `00010_ssh_key_rotation.sql`

**Files:**
- Create: `migrations/00010_ssh_key_rotation.sql` (C2, verbatim)
- Create: `migrations/rotation_integration_test.go`
- Modify: `migrations/roles_integration_test.go` (`explicitGrants`, `explicitColumnGrants`)
- Modify: `cmd/alice/testapi_e2e.go` is **not** touched here (Task 15 extends `resetSQL`)

**Interfaces:**
- Consumes: migrations `00005`, `00006`, `00008`.
- Produces: the schema of C2: tables `rotation_policies`, `rotations`, `rotation_locations`, `rotation_steps`; columns `managed_private_keys.{download_count, last_downloaded_at, destroyed_at}`, `ssh_keys.{private_key_id, key_comment, rotated_from, created_by}`; triggers `managed_private_keys_guard` (`Z1009`), `rotation_policies_key_check` (`Z1010`), `rotation_locations_guard` (`Z1011`).

- [ ] **Step 1: Write the failing test**

`migrations/rotation_integration_test.go` (`//go:build integration`; package `migrations_test` as its neighbours; `pgtest.New(t)`; seed rows with the owner pool and act with the application pool, as `keyvault_integration_test.go` does):

```go
//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errorsAs(err, &pg) {
		return pg.Code
	}
	return ""
}

// seedSSHKey inserts a generated key (managed, with its private key row) and returns the key id and
// the private key id.
func seedSSHKey(t *testing.T, db *pgtest.DB, fp string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	pk, key := uuid.New(), uuid.New()
	_, err := db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'ed25519', 256, repeat('a', 64), '\x01', repeat('\x00', 12)::bytea, '\x02', 1, $2)`,
		pk, now)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, bits, public_key, managed, private_key_id, first_seen_at,
    created_at) VALUES ($1, $2, 'ssh-ed25519', 256, 'ssh-ed25519 AAAA', true, $3, $4, $4)`, key, fp, pk, now)
	require.NoError(t, err)
	return key, pk
}

func TestManagedPrivateKeyGuard(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	_, pk := seedSSHKey(t, db, "SHA256:"+repeat43("A"))

	_, err := db.App.Exec(ctx, "UPDATE managed_private_keys SET download_count = download_count + 1, last_downloaded_at = $2 WHERE id = $1", pk, now)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET download_count = download_count + 2 WHERE id = $1", pk)
	assert.Equal(t, "Z1009", sqlState(err), "a download counts one")
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET download_count = 0 WHERE id = $1", pk)
	assert.Equal(t, "Z1009", sqlState(err))
	_, err = db.App.Exec(ctx, `UPDATE managed_private_keys SET ciphertext = '\x09' WHERE id = $1`, pk)
	assert.Equal(t, "Z1009", sqlState(err), "an envelope cannot be replaced")
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET ciphertext = NULL WHERE id = $1", pk)
	assert.Error(t, err, "half a destruction is refused (CHECK)")
	_, err = db.App.Exec(ctx, `UPDATE managed_private_keys SET destroyed_at = $2, ciphertext = NULL, nonce = NULL, wrapped_dek = NULL,
    key_version = NULL WHERE id = $1`, pk, now)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE managed_private_keys SET last_downloaded_at = $2 WHERE id = $1", pk, now)
	assert.Equal(t, "Z1009", sqlState(err), "a destroyed key never changes")
	_, err = db.App.Exec(ctx, "DELETE FROM managed_private_keys WHERE id = $1", pk)
	assert.Error(t, err, "no DELETE grant")

	// A certificate key cannot be destroyed, and Ed25519 is only for SSH keys.
	_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'certificate', 'ed25519', 256, repeat('b', 64), '\x01', repeat('\x00', 12)::bytea, '\x02', 1, $2)`,
		uuid.New(), now)
	assert.Error(t, err)
	_, err = db.App.Exec(ctx, `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) VALUES ($1, 'ssh_key', 'rsa', 2048, repeat('b', 64), '\x01', repeat('\x00', 12)::bytea, '\x02', 1, $2)`,
		uuid.New(), now)
	assert.Error(t, err, "RSA SSH keys are 3072 or 4096 bits")
}

func TestSSHKeyManagedConstraints(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	_, err := db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, managed, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', true, $3, $3)`, uuid.New(), "SHA256:"+repeat43("B"), now)
	assert.Error(t, err, "a managed key needs its private key")
	key, _ := seedSSHKey(t, db, "SHA256:"+repeat43("C"))
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET is_platform_key = true WHERE id = $1", key)
	assert.Error(t, err, "a generated key is never the platform key")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET managed = false WHERE id = $1", key)
	assert.Error(t, err, "no grant on managed")
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", key, now)
	require.NoError(t, err)
}

func TestRotationPolicyKeyCheck(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	insert := func(key uuid.UUID) error {
		_, err := db.App.Exec(ctx, `INSERT INTO rotation_policies (id, ssh_key_id, name, interval_days, created_at, updated_at)
VALUES ($1, $2, 'p', 90, $3, $3)`, uuid.New(), key, now)
		return err
	}
	key, _ := seedSSHKey(t, db, "SHA256:"+repeat43("D"))
	require.NoError(t, insert(key))
	var overlap, notify int
	var enabled bool
	require.NoError(t, db.App.QueryRow(ctx, "SELECT overlap_minutes, notify_before_hours, enabled FROM rotation_policies WHERE ssh_key_id = $1",
		key).Scan(&overlap, &notify, &enabled))
	assert.Equal(t, 10080, overlap, "7 days by default")
	assert.Equal(t, 24, notify)
	assert.False(t, enabled, "off by default")
	assert.Error(t, insert(key), "one live policy per key")

	discovered := uuid.New()
	_, err := db.App.Exec(ctx, `INSERT INTO ssh_keys (id, fingerprint_sha256, key_type, public_key, first_seen_at, created_at)
VALUES ($1, $2, 'ssh-ed25519', 'k', $3, $3)`, discovered, "SHA256:"+repeat43("E"), now)
	require.NoError(t, err)
	assert.Equal(t, "Z1010", sqlState(insert(discovered)), "only keys Alice generated")

	platform := "SHA256:" + repeat43("F")
	_, err = db.Owner.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', jsonb_build_object('fingerprint', $2::text), '\x01', repeat('\x00', 12)::bytea, '\x02', 1, $3)`,
		uuid.New(), platform, now)
	require.NoError(t, err)
	own, _ := seedSSHKey(t, db, platform) // impossible through the service; the trigger holds anyway
	assert.Equal(t, "Z1010", sqlState(insert(own)), "never Alice's own key (F-36)")

	retired, _ := seedSSHKey(t, db, "SHA256:"+repeat43("G"))
	_, err = db.App.Exec(ctx, "UPDATE ssh_keys SET retired_at = $2 WHERE id = $1", retired, now)
	require.NoError(t, err)
	assert.Equal(t, "Z1010", sqlState(insert(retired)))

	_, err = db.App.Exec(ctx, "UPDATE rotation_policies SET enabled = true WHERE ssh_key_id = $1", key)
	assert.Error(t, err, "enabled needs a next run")
}

// The old-key rule in the schema (C2): removing needs removal_allowed and a fresh verification.
func TestRotationRemovalGuards(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	rot, loc := seedRotation(t, db) // a run in adding_new with one location in state verified (helper below)

	_, err := db.App.Exec(ctx, "UPDATE rotations SET status = 'removing_old' WHERE id = $1", rot)
	assert.Error(t, err, "removing_old needs removal_allowed")
	_, err = db.App.Exec(ctx, "UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $3 WHERE id = $1",
		loc, uuid.New(), now)
	assert.Equal(t, "Z1011", sqlState(err), "the run is not removing")

	_, err = db.App.Exec(ctx, "UPDATE rotations SET status = 'removing_old', removal_allowed = true, verified_at = $2 WHERE id = $1", rot, now)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $4
WHERE id = $1`, loc, uuid.New(), now, now.Add(16*time.Minute))
	assert.Error(t, err, "a verification older than 15 minutes is not fresh")
	_, err = db.App.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = $3, remove_sent_at = $4
WHERE id = $1`, loc, uuid.New(), now, now.Add(14*time.Minute))
	require.NoError(t, err)

	_, err = db.App.Exec(ctx, "UPDATE rotations SET status = 'completed', finished_at = $2 WHERE id = $1", rot, now)
	require.NoError(t, err)
	_, err = db.App.Exec(ctx, "UPDATE rotation_locations SET backup = 'x' WHERE id = $1", loc)
	assert.Equal(t, "Z1011", sqlState(err), "a finished run's rows are frozen")
}
```

Helpers in the same file: `repeat43(s string) string` (43 characters for a fingerprint), `errorsAs` (= `errors.As`), and `seedRotation(t, db) (rotationID, locationID uuid.UUID)` which seeds a target (as `inventory_integration_test.go` seeds one), a generated old key and a generated new key (`seedSSHKey`), an `ssh_key_locations` row of the old key, a policy, a `rotations` row (`status 'adding_new'`, `plan '{}'`, `plan_digest repeat('0', 64)`, `new_key_type 'ed25519'`, `overlap_minutes 1`, `planned_for`, `notified_at`, `started_at`, `new_ssh_key_id`, `created_at`, `updated_at` = `now`) and a `rotation_locations` row in state `verified` with `add_sent_at` and `verified_at` = `now`. Also add `TestRotationPlatformFingerprintNeverRemoving`: with a `platform_ssh` credential whose fingerprint equals the old key's, moving the location to `removing` raises `Z1011` even with the run in `removing_old`.

`migrations/roles_integration_test.go`: add every new table to `explicitGrants` (`SELECT, INSERT` for the four tables) and every new column grant of C2 to `explicitColumnGrants`, so the grant guard passes and keeps guarding.

- [ ] **Step 2: Run the test to verify it fails**

Run (testcontainers): `go test -count=1 -tags integration -run 'TestManagedPrivateKeyGuard|TestSSHKeyManagedConstraints|TestRotation' ./migrations/`
Expected: FAIL — `relation "rotation_policies" does not exist`, column `download_count` does not exist.

- [ ] **Step 3: Write the migration**

Create `migrations/00010_ssh_key_rotation.sql` with exactly the SQL of C2.

- [ ] **Step 4: Run the tests to verify they pass**

Run (testcontainers): `go test -count=1 -tags integration ./migrations/`
Expected: `ok  alice/migrations` (including the existing up/down round trip `down_integration_test.go` and the grant guard).

- [ ] **Step 5: Commit**

```bash
git add -- migrations/00010_ssh_key_rotation.sql migrations/rotation_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(db): SSH key rotation schema — generated keys, download counter, destruction, policies, runs, old-key guards" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- migrations
```

---

### Task 6: Inventory: key-change readiness, transactional reads, recording an added key, `facts.key_files`, `ValidateReason`

**Files:**
- Create: `internal/inventory/keychange.go`, `internal/inventory/keychange_integration_test.go`, `internal/inventory/keychange_test.go`
- Modify: `internal/inventory/removal.go` (`RequestKeyRemoval` uses `KeyChangeRefusal`; behaviour unchanged)
- Modify: `internal/inventory/sshkeys.go` (`Reconcile` stores `KeyFiles` with the other SSH facts; `ListSSHKeys` lists generated keys without locations), `internal/inventory/types.go` (`Facts.KeyFiles`)
- Modify: `internal/inventory/hostkeys.go` (`validateReason` becomes `ValidateReason`; callers renamed)

**Interfaces:**
- Consumes: C5 (`DiscoveryResult.KeyFiles`, `providers.UserKeyFiles`); `getTarget`, `checkClaim`, `protectedFingerprints`, `upsertLocation`'s SQL, `markConnected`, `scanLocation`, `locationSelectAny`.
- Produces: C6 exactly.

- [ ] **Step 1: Write the failing tests**

`internal/inventory/keychange_test.go` (pure):

```go
package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/providers"
)

func readyTarget() Target {
	return Target{Status: StatusOK, Username: "alice-svc", Facts: Facts{SSHD: &providers.SSHDSummary{Read: true}}}
}

func TestKeyChangeRefusal(t *testing.T) {
	assert.NoError(t, KeyChangeRefusal(readyTarget(), "deploy"))
	cases := map[string]struct {
		edit func(*Target)
		want error
	}{
		"pending":            {func(t *Target) { t.Status = StatusPendingHostKey }, ErrHostKeyUnconfirmed},
		"changed":            {func(t *Target) { t.Status = StatusHostKeyChanged }, ErrHostKeyChanged},
		"disabled":           {func(t *Target) { t.Status = StatusDisabled }, ErrTargetDisabled},
		"elsewhere":          {func(t *Target) { t.KeysManagedElsewhere = true }, ErrKeysManagedElsewhere},
		"elsewhere for user": {func(t *Target) { t.Facts.Warnings = []providers.Warning{{Code: "keys_managed_elsewhere", Params: map[string]string{"user": "deploy"}}} }, ErrKeysManagedElsewhere},
		"sshd unread":        {func(t *Target) { t.Facts.SSHD = &providers.SSHDSummary{Read: false} }, ErrSSHDUnreadable},
		"no sshd facts":      {func(t *Target) { t.Facts.SSHD = nil }, ErrSSHDUnreadable},
		"sshd unread user":   {func(t *Target) { t.Facts.Warnings = []providers.Warning{{Code: "sshd_unreadable", Params: map[string]string{"user": "deploy"}}} }, ErrSSHDUnreadable},
	}
	for name, c := range cases {
		tg := readyTarget()
		c.edit(&tg)
		assert.ErrorIs(t, KeyChangeRefusal(tg, "deploy"), c.want, name)
	}
	for _, st := range []string{StatusUnreachable, StatusChecking, StatusAuthFailed} {
		tg := readyTarget()
		tg.Status = st
		assert.NoError(t, KeyChangeRefusal(tg, "deploy"), "the job reports a connection problem itself: %s", st)
	}
}

func TestValidateReasonIsExported(t *testing.T) {
	assert.Empty(t, ValidateReason("Rotating the CI key after an audit"))
	assert.NotEmpty(t, ValidateReason("short"))
	assert.NotEmpty(t, ValidateReason("-----BEGIN "+"OPENSSH PRIVATE KEY----- pasted"))
}
```

(If `StatusDisabled`/`ErrTargetDisabled` do not exist under these names in `inventory`, use the existing status constant for `disabled` and add `ErrTargetDisabled = errors.New("inventory: the server is disabled")` in `errors.go`, mapped by the API to the existing `ALC-TGT-0006`.)

`internal/inventory/keychange_integration_test.go` (`//go:build integration`; uses the package's integration harness of `harness_integration_test.go` — a service on a fresh database with a fake provider — read it first):

- `TestKeyLocationsTxListsLiveAndMissing`: a key with three locations (present, missing, removed by Alice) on a target → `KeyLocationsTx` returns the present and the missing one (`MissingSince` set), ordered by target, file, user; with `lock` the rows are locked (a second transaction's `SELECT … FOR UPDATE NOWAIT` on them fails).
- `TestRecordKeyAddedTx`: inserts a location for a generated key (seeded as in Task 5) with `LineNo`, options and comment; audit `sshkey.added` with `ssh_key_id`, `fingerprint`, `target_id`, `os_user`, `file_path`, `job_id`, `verified`; an `unreachable` target becomes `ok` (`markConnected`, reason `key_added`); calling it again for the same place updates `line_no` and clears `missing_since` and `removed_by_alice_at`; a protected fingerprint is refused with `ErrOwnKeyProtected` and nothing is written.
- `TestCheckClaimTxRefusesALostClaim`: with a `Claim` on the context whose job is no longer `running` under that worker, `CheckClaimTx` returns `ErrClaimLost`.
- `TestReconcileStoresKeyFiles`: a discovery result with `KeyFiles` stores them in `facts.key_files`; a certificates-only result (`sshHalfRead` false) keeps the earlier ones.
- `TestRemovalStillRefusesAsBefore`: the existing removal refusals (pending, changed, managed elsewhere, sshd unreadable) still answer the same errors and audit rows through `KeyChangeRefusal` (run the existing removal tests: they are the regression check; add this test only for the disabled case, which is new).
- `TestListSSHKeysShowsGeneratedKeysWithoutLocations`: a generated key (seeded with the owner pool: a `managed_private_keys` row and a managed `ssh_keys` row with `key_comment`) and no location is listed by `ListSSHKeys` with no filter (`LocationCount` 0, `TargetCount` 0, `Missing` false, `Comment` = its `key_comment`), found by `q` on its comment, and **not** listed with a `TargetID`, `OSUser` or `Flag` filter; a discovered key whose every location is missing stays hidden without `IncludeMissing`, as before; `GetSSHKey` of the generated key answers it with an empty `Locations`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/inventory/ -run 'TestKeyChangeRefusal|TestValidateReasonIsExported'`
Expected: FAIL — undefined: `KeyChangeRefusal`, `ValidateReason`.

- [ ] **Step 3: Write the implementation**

`internal/inventory/keychange.go`:

```go
package inventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
)

// KeyChangeRefusal is the readiness rule every authorized_keys change shares (RequestKeyRemoval,
// deploys, rotations; C6). Connection problems (unreachable, checking, auth_failed) are not refused
// here: the job finds them and records them on the target.
func KeyChangeRefusal(t Target, osUser string) error {
	switch {
	case t.Status == StatusPendingHostKey:
		return ErrHostKeyUnconfirmed
	case t.Status == StatusHostKeyChanged:
		return ErrHostKeyChanged
	case t.Status == StatusDisabled:
		return ErrTargetDisabled
	case t.KeysManagedElsewhere || managedElsewhereFor(t.Facts, osUser):
		return ErrKeysManagedElsewhere
	case sshdUnreadFor(t.Facts, osUser):
		return ErrSSHDUnreadable
	}
	return nil
}

// TargetTx reads a live target in tx (FOR UPDATE with lock); ErrNotFound when deleted or unknown.
func (s *Service) TargetTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (Target, error) {
	return getTarget(ctx, tx, id, lock)
}

// CheckClaimTx is ErrClaimLost when the job run on ctx no longer holds its job (no claim: nil).
func CheckClaimTx(ctx context.Context, tx pgx.Tx) error { return checkClaim(ctx, tx) }

// ProtectedFingerprintsTx is ProtectedFingerprints in tx.
func ProtectedFingerprintsTx(ctx context.Context, tx pgx.Tx) ([]string, error) { return protectedFingerprints(ctx, tx) }

// KeyLocationsTx returns the key's locations that Alice did not remove (missing ones included), of
// live targets, ordered by target id, file path and OS user; FOR UPDATE OF l with lock.
func (s *Service) KeyLocationsTx(ctx context.Context, tx pgx.Tx, keyID uuid.UUID, lock bool) ([]KeyLocation, error) {
	q := locationSelect + ` WHERE l.ssh_key_id = $1 AND l.removed_by_alice_at IS NULL ORDER BY l.target_id, l.file_path, l.os_user`
	if lock {
		q += " FOR UPDATE OF l"
	}
	rows, err := tx.Query(ctx, q, keyID)
	if err != nil {
		return nil, fmt.Errorf("inventory: read key locations: %w", err)
	}
	return collectLocations(rows)
}

// KeyAdded records a key line Alice added (C6).
type KeyAdded struct {
	SSHKeyID, TargetID uuid.UUID
	OSUser, FilePath   string
	Options, Comment   string
	LineNo             int
	Actor              audit.Actor
	Verified           bool
}

// RecordKeyAddedTx upserts the location of an added line, records the connection and audits
// sshkey.added. Alice's own key is refused (the database trigger holds too).
func (s *Service) RecordKeyAddedTx(ctx context.Context, tx pgx.Tx, in KeyAdded) (uuid.UUID, error) {
	if err := checkClaim(ctx, tx); err != nil {
		return uuid.Nil, err
	}
	now := s.clock.Now().UTC()
	t, err := getTarget(ctx, tx, in.TargetID, true)
	if err != nil {
		return uuid.Nil, err
	}
	var fp string
	if err := tx.QueryRow(ctx, "SELECT fingerprint_sha256 FROM ssh_keys WHERE id = $1", in.SSHKeyID).Scan(&fp); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, fmt.Errorf("inventory: read the added key: %w", err)
	}
	protected, err := protectedFingerprints(ctx, tx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, p := range protected {
		if p == fp {
			return uuid.Nil, ErrOwnKeyProtected
		}
	}
	lineNo := max(in.LineNo, 1)
	var id uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO ssh_key_locations (id, ssh_key_id, target_id, os_user, file_path, line_no, options, comment, flags,
    first_seen_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}', $9, $9)
ON CONFLICT (ssh_key_id, target_id, os_user, file_path) DO UPDATE SET line_no = EXCLUDED.line_no, options = EXCLUDED.options,
    comment = EXCLUDED.comment, last_seen_at = EXCLUDED.last_seen_at, missing_since = NULL, removed_by_alice_at = NULL
RETURNING id`, uuid.Must(uuid.NewV7()), in.SSHKeyID, in.TargetID, clean(in.OSUser), clean(in.FilePath), lineNo, clean(in.Options),
		clean(in.Comment), now).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("inventory: record the added key: %w", err)
	}
	if err := s.markConnected(ctx, tx, t, now, false, "key_added", nil); err != nil {
		return uuid.Nil, err
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: in.Actor, Action: "sshkey.added", ObjectType: "ssh_key_location",
		ObjectID: id.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": in.SSHKeyID.String(), "fingerprint": fp,
			"target_id": in.TargetID.String(), "os_user": in.OSUser, "file_path": in.FilePath, "job_id": in.Actor.RequestID,
			"verified": strconv.FormatBool(in.Verified)}})
	return id, err
}
```

(`markConnected`'s reason list must accept `key_added` beside `discovery_ok` and `removal_ok`; if the function validates reasons, add it there and to the audit `target.status_changed` reasons in `docs/troubleshooting.md`'s list, which Task 19 updates.)

`removal.go`: in `RequestKeyRemoval`, replace the four status/elsewhere/sshd `case`s with

```go
		if err := KeyChangeRefusal(t, loc.OSUser); err != nil {
			switch {
			case errors.Is(err, ErrKeysManagedElsewhere):
				return &denial{reason: "keys_managed_elsewhere", err: err, loc: loc}
			case errors.Is(err, ErrSSHDUnreadable):
				return &denial{reason: "sshd_unreadable", err: err, loc: loc}
			default:
				return err
			}
		}
```

keeping the earlier `case`s (removed, missing, cert-authority, own key) in front, so the order of checks and every audit row stay as they were.

`types.go`: `Facts` gains `KeyFiles []providers.UserKeyFiles \`json:"key_files,omitempty"\``. `sshkeys.go`, in `Reconcile`'s `sshHalfRead` branch: `f.KeyFiles = slices.Clone(res.KeyFiles)`.

`hostkeys.go`: rename `validateReason` to `ValidateReason` (exported, same body) and its callers.

`sshkeys.go`, `ListSSHKeys`: the query lists generated keys that have no location yet. Replace its `FROM … JOIN` and the aggregates with:

```sql
SELECT k.id, k.fingerprint_sha256, k.key_type, k.bits, k.public_key, k.managed, k.is_platform_key, k.weak, k.first_seen_at,
    count(l.id), count(DISTINCT l.target_id),
    coalesce((array_agg(l.comment ORDER BY l.last_seen_at DESC, l.id DESC) FILTER (WHERE l.id IS NOT NULL))[1], k.key_comment),
    coalesce(bool_and(l.missing_since IS NOT NULL OR l.removed_by_alice_at IS NOT NULL) FILTER (WHERE l.id IS NOT NULL), false)
FROM ssh_keys k
LEFT JOIN (ssh_key_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL) ON l.ssh_key_id = k.id
WHERE (l.id IS NOT NULL OR (k.managed AND $1::uuid IS NULL AND $2::text = '' AND $4::text = ''))
  AND ($1::uuid IS NULL OR l.target_id = $1)
  AND ($2::text = '' OR l.os_user = $2)
  AND ($3::text = ''
       OR translate(k.fingerprint_sha256, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $3 ESCAPE '\'
       OR translate(coalesce(l.comment, k.key_comment), 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $3 ESCAPE '\'
       OR translate(k.key_type, 'ABCDEFGHIJKLMNOPQRSTUVWXYZİı', 'abcdefghijklmnopqrstuvwxyzii') LIKE $3 ESCAPE '\')
  AND ($4::text = '' OR $4 = ANY (l.flags))
  AND ($5::boolean OR l.id IS NULL OR (l.missing_since IS NULL AND l.removed_by_alice_at IS NULL))
  AND ($6::timestamptz IS NULL OR (k.first_seen_at, k.id) > ($6::timestamptz, $7::uuid))
GROUP BY k.id
ORDER BY k.first_seen_at, k.id
LIMIT $8
```

(the parameters are unchanged; `key_comment` exists from migration `00010`, Task 5).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/inventory/ && go test -count=1 -tags integration ./internal/inventory/` (testcontainers)
Expected: `ok` (all existing removal tests unchanged and green).

Run: `go test -count=1 -tags integration -coverprofile=/tmp/inv.out ./internal/inventory/ && go tool cover -func=/tmp/inv.out | tail -1`
Expected: total ≥ 89.1 % (floor 89; this task must not lower the measured value: every new line is covered).

- [ ] **Step 5: Commit**

```bash
git add -- internal/inventory/keychange.go internal/inventory/keychange_test.go internal/inventory/keychange_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(inventory): key-change readiness, transactional key reads, added-key records, candidate key files" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/inventory
```

---

### Task 7: `internal/sshkeys` part 1: the module, generation, managed-key reads, deploy requests and their bookkeeping, the signer source, the download, destruction of retired keys

**Files:**
- Create: `internal/sshkeys/service.go` (Config, Service, New, interfaces of C7), `internal/sshkeys/errors.go`, `internal/sshkeys/types.go` (ManagedKey, DeployInput, DeployJob, DeployOutcome, constants)
- Create: `internal/sshkeys/keys.go` (Generate, ManagedKey, the generation slots), `internal/sshkeys/deploy.go` (RequestDeploy, DeployJob, FinishDeploy), `internal/sshkeys/signer.go` (KeySigner, ProtectedFingerprints), `internal/sshkeys/download.go`, `internal/sshkeys/destroy.go`
- Create: `internal/sshkeys/harness_integration_test.go`, `internal/sshkeys/keys_integration_test.go`, `internal/sshkeys/deploy_integration_test.go`, `internal/sshkeys/download_integration_test.go`

**Interfaces:**
- Consumes: C3 (`keymat`), C6 (inventory exports), `secrets.Keyring.Seal/Open`, AAD `managed_private_keys/<id>/ciphertext` (the form of `inventory.keyLocation`), `audit.Log.Append`, `license.ClassChange`, `inventory.Actor`, `inventory.JobRequest`/`Enqueuer`, `db.InTx` (`internal/platform/db`).
- Produces: C7 "Task 7" part and the errors of C7; job type constant `JobDeploy`; audit actions `sshkey.generated`, `sshkey.deploy_requested`, `sshkey.deploy.denied`, `sshkey.add_failed`, `sshkey.private_key_downloaded`, `sshkey.private_key_download.denied`, `sshkey.private_key_destroyed` (C12).

Rules this task implements (each has a test below):

1. **Generate** — refuses with the gate (`License.Allow(ClassChange)`), validates the label with `validLabel` (1–100 runes; no rune of `unicode.IsControl`, `unicode.Cf` or `unicode.Bidi_Control`, the rune classes `inventory`'s target-name rule refuses; `validate.Required`, `validate.TooLong` or `validate.Pattern` on field `label`) and the key type (`""` → `ed25519`); takes one of `MaxGenerations` slots without waiting (`ErrGenerateBusy` otherwise); generates outside any transaction (`keymat.Generate(s.rand, …)`, `randMu` as inventory does for a non-concurrent reader); then in one transaction inserts `managed_private_keys` (owner `ssh_key`, the sealed PKCS #8, `public_key_sha256`, algorithm, bits, `created_by`) and `ssh_keys` (`managed = true`, `private_key_id`, `fingerprint_sha256`, `key_type` = the SSH type of the public key (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`), `bits`, `public_key`, `label`, `key_comment` = `keymat.Comment(label, now)`, `created_by`, `first_seen_at` = `created_at` = now) and appends `sshkey.generated`. `PKCS8` is zeroed on every path (`defer m.PKCS8.Zero()` right after `Generate`).
2. **ManagedKey** — reads the key with its private-key row (`download_count`, `last_downloaded_at`, `destroyed_at`), its live policy id and its open rotation id (as old key); a key without `private_key_id` is `ErrNotManaged`.
3. **RequestDeploy** — in one transaction: gate; the key (`ErrNotManaged`, `ErrRetired`); the target (`inventory.TargetTx(lock)`, `ErrNotFound`), `inventory.KeyChangeRefusal(t, os_user)`; `os_user == t.Username` → `ErrConnectionAccount`; the file must be one of `t.Facts.KeyFiles` for that user (`ErrNotAKeyFile`); options from `From`/`Restrict` (`keymat.FromOption`, then `restrict`), line = `keymat.Line(options, publicKey, key_comment)`; enqueue `sshkey.add` (C1 payload and dedupe) and append `sshkey.deploy_requested`. Refusals that protect access (`ErrConnectionAccount`, `ErrKeysManagedElsewhere`, `ErrSSHDUnreadable`, `ErrNotManaged` for Alice's own key) are audited `sshkey.deploy.denied` in their own transaction (as `inventory.auditDenial`), with `reason` `connection_account`, `keys_managed_elsewhere`, `sshd_unreadable`, `own_key`.
4. **DeployJob** — re-reads everything from the database when the job runs (never trusts the payload beyond ids and the three strings): the key must still be managed and not retired, the target still pass `KeyChangeRefusal`, the user not the connection account; returns the line rebuilt from the database (`Line` of the stored public key and comment with the payload's options re-validated by `keymat.Line`); `Protected` = `ProtectedFingerprints`.
5. **FinishDeploy** — `verified`, `unverified`, `already_present`: `RecordKeyAddedTx` (Verified = result `verified`); `undone`, `failed`, `undo_failed`: audit `sshkey.add_failed` with the reason; nothing else.
6. **KeySigner(keyID)** — a `providers.CredentialSource` whose `SSHSigner` reads the key's envelope (`destroyed_at IS NULL`, else `ErrDestroyed`), opens it with the keyring (AAD of the private-key row), builds `keymat.Signer`, and returns a release that calls the signer's release and zeroes the opened plaintext. It never logs; its errors carry no key material.
7. **DownloadPrivateKey** — order (S-09): validate (`inventory.ValidateReason`, passphrase length) → read the key and its private-key row (a key with `is_platform_key` or no private key → audit `sshkey.private_key_download.denied` reason `own_key` / `not_managed`, `ErrNotManaged`; destroyed → denied `destroyed`, `ErrDestroyed`) → open the envelope and build the file (`keymat.OpenSSHFile`, comment = `key_comment`) **outside** the transaction → in one transaction: `UPDATE managed_private_keys SET download_count = download_count + 1, last_downloaded_at = now` and append `sshkey.private_key_downloaded` (`ssh_key_id`, `fingerprint`, `reason`, `protected` = passphrase given, `download_count` = the new count) → commit → return. A failed commit zeroes the file and returns the error: no file without its committed audit row. The plaintext PKCS #8 is zeroed before the transaction starts.
8. **DestroyRetiredKeys** — for every SSH private key whose key has `retired_at <= now - RetiredKeyRetention` and `destroyed_at IS NULL`: in one transaction per key, `UPDATE … SET destroyed_at = now, ciphertext = NULL, nonce = NULL, wrapped_dek = NULL, key_version = NULL`, audit `sshkey.private_key_destroyed`; returns the count.

- [ ] **Step 1: Write the failing tests**

`internal/sshkeys/harness_integration_test.go` (`//go:build integration`): `TestMain` with `pgtest.Main`; `newEnv(t)` builds on `pgtest.New(t)`: a keyring (as inventory's harness), `audit.Log`, a fake clock at `2026-10-05T12:00:00Z`, a switchable gate (`lockGate` as `deployjobs` has: `Allow` returns `license.ErrLocked` when locked), an `inventory.Service` with the fake provider registry, a `jobs.Queue` as the `Enqueuer` (its MAC deriver from the keyring), a recording notifier (`NotifyAdmins` appends template and params), and `sshkeys.New`. Helpers: `e.generate(label)` (Generate as the Administrator, `require.NoError`), `e.generateUnlocked(label)` (unlocks the gate, generates, locks again; returns the id), `e.discoveredKey()` (a key reconciled from a fake discovery: no private key), `e.platformKeyRow()` (`inventory.EnsurePlatformKey`, then a discovery that lists the platform key, so its `ssh_keys` row has `is_platform_key`), `e.retire(id)`/`e.retireAt(id, at)` and `e.destroy(id)` (owner-pool updates of `retired_at` and of the private key's envelope), `e.envelope(privateKeyID)` and `e.wrappedDEK(privateKeyID)` (owner-pool reads), `e.job(id)` (`jobs.Queue.Get` plus the payload), `e.setTargetStatus(id, status)`, `e.lastAuditDetail(action, key)`, `e.dumpTable(name)` (every row as `t::text` of `SELECT t::text FROM ` + `pgx.Identifier{name}.Sanitize()` + ` t`, joined, owner pool; the name comes from the test's own list and is quoted, so gosec's SQL rules stay quiet), and `keyBodyLines(pem)`; `e.server(name)` adds a confirmed `ok` target with `facts.key_files` `[{deploy [/home/deploy/.ssh/authorized_keys]}, {root [/root/.ssh/authorized_keys]}, {alice-svc [/home/alice-svc/.ssh/authorized_keys]}]` and SSH facts read; `e.admin`, `e.operator` actors; `e.count(sql, args...)`; `e.audits(action)`.

`internal/sshkeys/keys_integration_test.go`:

```go
//go:build integration

package sshkeys_test

func TestGenerateStoresAnEnvelope(t *testing.T) {
	e := newEnv(t)
	k, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "CI deploy"})
	require.NoError(t, err)
	assert.Equal(t, "ed25519", k.KeyType)
	assert.Equal(t, "alice:ci-deploy:2026-10-05", k.Comment)
	var ct, nonce []byte
	var owner, algorithm string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT ciphertext, nonce, owner_type, algorithm FROM managed_private_keys WHERE id = $1`,
		k.PrivateKeyID).Scan(&ct, &nonce, &owner, &algorithm))
	assert.Equal(t, "ssh_key", owner)
	assert.Equal(t, "ed25519", algorithm)
	assert.NotContains(t, string(ct), "PRIVATE KEY")
	assert.False(t, bytes.HasPrefix(ct, []byte{0x30}), "not DER in clear")
	pt, err := e.keyring.Open(secrets.Location{Table: "managed_private_keys", RowID: k.PrivateKeyID.String(), Column: "ciphertext"},
		e.envelope(k.PrivateKeyID))
	require.NoError(t, err)
	defer pt.Zero()
	pub, fp, err := keymat.PublicOf(pt)
	require.NoError(t, err)
	assert.Equal(t, k.PublicKey, pub)
	assert.Equal(t, k.Fingerprint, fp)
	assert.Equal(t, 1, e.audits("sshkey.generated"))
	// S-04: two keys, two DEKs, two different ciphertexts
	k2, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "CI deploy"})
	require.NoError(t, err)
	assert.NotEqual(t, e.wrappedDEK(k.PrivateKeyID), e.wrappedDEK(k2.PrivateKeyID))
}

func TestGenerateEveryType(t *testing.T) {
	e := newEnv(t)
	for _, kt := range []string{"ed25519", "rsa-3072", "rsa-4096", "ecdsa-p256"} {
		k, err := e.svc.Generate(e.ctx, e.operator, sshkeys.GenerateInput{Label: "k " + kt, KeyType: kt})
		require.NoError(t, err, kt)
		assert.Equal(t, kt, k.KeyType)
	}
	_, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "x", KeyType: "dsa"})
	var verr validate.Errors
	assert.ErrorAs(t, err, &verr)
	_, err = e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "a‮b"})
	assert.ErrorAs(t, err, &verr)
}

func TestGenerateRefusedInLockAndWhenBusy(t *testing.T) {
	e := newEnv(t)
	e.gate.lock()
	_, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "x"})
	assert.ErrorIs(t, err, license.ErrLocked)
	e.gate.unlock()
	release := sshkeys.HoldGenerationSlots(t) // export_test.go: takes every slot until release
	_, err = e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "x"})
	assert.ErrorIs(t, err, sshkeys.ErrGenerateBusy)
	release()
	assert.Zero(t, e.count("SELECT count(*) FROM ssh_keys"))
}

func TestManagedKeyReads(t *testing.T) {
	e := newEnv(t)
	k, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "ci"})
	require.NoError(t, err)
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, k.Fingerprint, got.Fingerprint)
	assert.Zero(t, got.DownloadCount)
	discovered := e.discoveredKey() // a key found on a server: no private key
	_, err = e.svc.ManagedKey(e.ctx, discovered)
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	_, err = e.svc.ManagedKey(e.ctx, uuid.New())
	assert.ErrorIs(t, err, sshkeys.ErrNotFound)
}
```

`internal/sshkeys/deploy_integration_test.go`:

```go
//go:build integration

package sshkeys_test

func TestDeployRequestQueuesTheJob(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	id, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", From: "10.0.0.0/8", Restrict: true})
	require.NoError(t, err)
	j := e.job(id)
	assert.Equal(t, "sshkey.add", j.Type)
	assert.Equal(t, srv, j.TargetID)
	assert.Equal(t, map[string]string{"ssh_key_id": k.ID.String(), "os_user": "deploy",
		"file_path": "/home/deploy/.ssh/authorized_keys", "options": `from="10.0.0.0/8",restrict`}, j.Payload)
	assert.Equal(t, 1, e.audits("sshkey.deploy_requested"))
	again, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", From: "10.0.0.0/8", Restrict: true})
	require.NoError(t, err)
	assert.Equal(t, id, again, "the same deploy while queued is the same job")
}

func TestDeployRequestRefusals(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	cases := []struct {
		name   string
		in     sshkeys.DeployInput
		want   error
		denied string // audited reason, "" = not audited
	}{
		{"connection account", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "alice-svc", FilePath: "/home/alice-svc/.ssh/authorized_keys"},
			sshkeys.ErrConnectionAccount, "connection_account"},
		{"not a key file", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: "/etc/shadow"}, sshkeys.ErrNotAKeyFile, ""},
		{"unknown user", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "nobody", FilePath: "/home/nobody/.ssh/authorized_keys"},
			sshkeys.ErrNotAKeyFile, ""},
		{"discovered key", sshkeys.DeployInput{KeyID: e.discoveredKey(), TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"},
			sshkeys.ErrNotManaged, ""},
		{"platform key", sshkeys.DeployInput{KeyID: e.platformKeyRow(), TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"},
			sshkeys.ErrNotManaged, "own_key"},
		{"bad from", sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys", From: "*"},
			validate.Errors{}, ""},
	}
	for _, c := range cases {
		before := e.audits("sshkey.deploy.denied")
		_, err := e.svc.RequestDeploy(e.ctx, e.operator, c.in)
		if _, isV := c.want.(validate.Errors); isV {
			var verr validate.Errors
			assert.ErrorAs(t, err, &verr, c.name)
		} else {
			assert.ErrorIs(t, err, c.want, c.name)
		}
		if c.denied != "" {
			assert.Equal(t, before+1, e.audits("sshkey.deploy.denied"), c.name)
			assert.Equal(t, c.denied, e.lastAuditDetail("sshkey.deploy.denied", "reason"), c.name)
		}
	}
	e.setTargetStatus(srv, "host_key_changed")
	_, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, inventory.ErrHostKeyChanged)
	e.retire(k.ID)
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: e.server("web-02"), OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, sshkeys.ErrRetired)
	e.gate.lock()
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: e.generateUnlocked("x"), TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.Zero(t, e.count("SELECT count(*) FROM jobs WHERE type = 'sshkey.add'"))
}

func TestDeployJobRereadsTheDatabase(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	id, err := e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys", Restrict: true})
	require.NoError(t, err)
	j := e.job(id)
	d, err := e.svc.DeployJob(e.ctx, id, srv, j.Payload)
	require.NoError(t, err)
	assert.Equal(t, "restrict "+k.PublicKey+" "+k.Comment, d.Line)
	assert.Contains(t, d.Line, k.Comment)
	forged := maps.Clone(j.Payload)
	forged["options"] = "cert-authority"
	_, err = e.svc.DeployJob(e.ctx, id, srv, forged)
	assert.Error(t, err, "options are validated again")
	forged = maps.Clone(j.Payload)
	forged["os_user"] = "alice-svc"
	_, err = e.svc.DeployJob(e.ctx, id, srv, forged)
	assert.ErrorIs(t, err, sshkeys.ErrConnectionAccount)
}

func TestFinishDeployRecordsTheLocation(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	d := sshkeys.DeployJob{KeyID: k.ID, TargetID: srv, Fingerprint: k.Fingerprint, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys",
		Comment: k.Comment}
	actor := audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: uuid.NewString()}
	require.NoError(t, e.svc.FinishDeploy(e.ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployVerified, LineNo: 3}))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND line_no = 3", k.ID))
	assert.Equal(t, "true", e.lastAuditDetail("sshkey.added", "verified"))
	require.NoError(t, e.svc.FinishDeploy(e.ctx, actor, d, sshkeys.DeployOutcome{Result: sshkeys.DeployUndone, Reason: "sshkey.login_failed"}))
	assert.Equal(t, "sshkey.login_failed", e.lastAuditDetail("sshkey.add_failed", "reason"))
}

func TestKeySignerSignsAndZeroes(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	var seen []byte
	sshkeys.OnOpenedKey(t, func(b []byte) { seen = b }) // export_test.go hook, called with the opened plaintext
	s, release, err := e.svc.KeySigner(k.ID).SSHSigner(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, k.Fingerprint, ssh.FingerprintSHA256(s.PublicKey()))
	release()
	assert.Equal(t, make([]byte, len(seen)), seen, "the opened key is zeroed on release")
	e.destroy(k.ID)
	_, _, err = e.svc.KeySigner(k.ID).SSHSigner(e.ctx)
	assert.ErrorIs(t, err, sshkeys.ErrDestroyed)
}
```

`internal/sshkeys/download_integration_test.go`:

```go
//go:build integration

package sshkeys_test

// S-09 at the service: Administrator only is the route's job; here: a reason, the audit row is
// committed before the file is handed out, every download is counted and audited.
func TestDownloadAuditsBeforeTheFile(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "Hand-over to the CI team"})
	require.NoError(t, err)
	defer dl.Body.Zero()
	// The row is visible to another connection: it was committed before the call returned.
	var count int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM audit_log WHERE action = 'sshkey.private_key_downloaded'
  AND details->>'ssh_key_id' = $1 AND details->>'reason' = 'Hand-over to the CI team' AND details->>'download_count' = '1'
  AND details->>'protected' = 'false'`, k.ID.String()).Scan(&count))
	assert.Equal(t, 1, count)
	assert.True(t, bytes.HasPrefix(dl.Body.Bytes(), []byte("-----BEGIN "+"OPENSSH PRIVATE KEY-----")))
	assert.Regexp(t, `^alice-ci-[0-9a-f]{8}\.key$`, dl.FileName)

	dl2, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "Second copy for the backup host",
		Passphrase: []byte("a passphrase of length")})
	require.NoError(t, err)
	defer dl2.Body.Zero()
	_, err = ssh.ParseRawPrivateKeyWithPassphrase(dl2.Body.Bytes(), []byte("a passphrase of length"))
	require.NoError(t, err)
	got, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, got.DownloadCount, "the second download is counted and audited too")
	assert.Equal(t, 2, e.audits("sshkey.private_key_downloaded"))
	assert.Equal(t, "true", e.lastAuditDetail("sshkey.private_key_downloaded", "protected"))
}

func TestDownloadRefusals(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	_, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "short"})
	var verr validate.Errors
	assert.ErrorAs(t, err, &verr)
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "-----BEGIN " + "RSA PRIVATE KEY----- x"})
	assert.ErrorAs(t, err, &verr, "S-05: a reason holding a PEM block is refused")
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "long enough reason", Passphrase: []byte("short")})
	assert.ErrorAs(t, err, &verr)
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: e.platformKeyRow(), Reason: "long enough reason"})
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	assert.Equal(t, "own_key", e.lastAuditDetail("sshkey.private_key_download.denied", "reason"))
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: e.discoveredKey(), Reason: "long enough reason"})
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	e.retire(k.ID)
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "emergency after a rotation"})
	require.NoError(t, err, "a retired key can be downloaded until it is destroyed")
	dl.Body.Zero()
	e.destroy(k.ID)
	_, err = e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "too late for this one"})
	assert.ErrorIs(t, err, sshkeys.ErrDestroyed)
	assert.Equal(t, "destroyed", e.lastAuditDetail("sshkey.private_key_download.denied", "reason"))
}

func TestStoredKeyIsAnEnvelope(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	dl, err := e.svc.DownloadPrivateKey(e.ctx, e.admin, sshkeys.DownloadInput{KeyID: k.ID, Reason: "canary extraction"})
	require.NoError(t, err)
	body := string(dl.Body.Bytes())
	dl.Body.Zero()
	canaries := keyBodyLines(body) // the base64 lines between the PEM markers, each at least 20 characters
	for _, table := range []string{"managed_private_keys", "ssh_keys", "audit_log", "jobs", "notifications_outbox"} {
		dump := e.dumpTable(table) // every column of every row as text (owner pool)
		for _, c := range canaries {
			assert.NotContains(t, dump, c, table)
		}
		assert.NotContains(t, dump, "PRIVATE KEY", table)
	}
}

func TestDestroyRetiredKeys(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	e.retireAt(k.ID, e.clock.Now())
	e.clock.Advance(30*24*time.Hour - time.Second)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "kept for 30 days")
	e.clock.Advance(time.Second)
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM managed_private_keys WHERE destroyed_at IS NOT NULL AND ciphertext IS NULL"))
	assert.Equal(t, 1, e.audits("sshkey.private_key_destroyed"))
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "destroyed once")
}
```

`internal/sshkeys/export_test.go` (package `sshkeys`): `HoldGenerationSlots(t) func()` fills the slot channel and returns the release; `OnOpenedKey(t, fn)` sets the package hook `onOpenedKey` (nil in production) and resets it in `t.Cleanup`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -tags integration ./internal/sshkeys/`
Expected: FAIL — `no non-test Go files`.

- [ ] **Step 3: Write the implementation**

`internal/sshkeys/service.go` — `Config`, `Service`, `New` (C7); `New` fills `Log` (discard), `Rand` (`crypto/rand`, `randSafe`), and allocates `genSlots := make(chan struct{}, MaxGenerations)` as a package variable (`acquireGenSlot` as `inventory.acquireCSRSlot`).

`internal/sshkeys/download.go` — the core of S-09 (the rest of the task's files follow rules 1–6 and 8 above, mirroring `inventory.CreateCSR`, `inventory.storeKey`, `inventory.RequestKeyRemoval` and `inventory.auditDenial`):

```go
package sshkeys

// DownloadPrivateKey hands out a generated key's private key as an OpenSSH file (spec §13.5, S-09,
// SEC-045; R41 rows 4-5). Order: validation, refusals (audited), the file built outside any
// transaction, then the counter and the audit row committed together; only then is the file
// returned. The route enforces Administrator, browser session, step-up and the rate limit.
func (s *Service) DownloadPrivateKey(ctx context.Context, a inventory.Actor, in DownloadInput) (Download, error) {
	errs := inventory.ValidateReason(in.Reason)
	switch {
	case in.Passphrase != nil && len(in.Passphrase) < keymat.MinPassphrase:
		errs.Add("passphrase", validate.TooShort, map[string]string{"min": strconv.Itoa(keymat.MinPassphrase)})
	case len(in.Passphrase) > keymat.MaxPassphrase:
		errs.Add("passphrase", validate.TooLong, map[string]string{"max": strconv.Itoa(keymat.MaxPassphrase)})
	}
	if len(errs) > 0 {
		return Download{}, errs
	}
	row, err := s.keyForDownload(ctx, in.KeyID) // key, private key id, is_platform_key, destroyed_at, label, comment, fingerprint
	if err != nil {
		return Download{}, err
	}
	switch {
	case row.isPlatform:
		s.auditDownloadDenied(ctx, a, in.KeyID, "own_key")
		return Download{}, ErrNotManaged
	case row.privateKeyID == uuid.Nil:
		s.auditDownloadDenied(ctx, a, in.KeyID, "not_managed")
		return Download{}, ErrNotManaged
	case row.destroyed:
		s.auditDownloadDenied(ctx, a, in.KeyID, "destroyed")
		return Download{}, ErrDestroyed
	}
	file, err := s.buildFile(ctx, row, in.Passphrase) // opens the envelope, keymat.OpenSSHFile, zeroes the PKCS #8
	if err != nil {
		return Download{}, err
	}
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `UPDATE managed_private_keys SET download_count = download_count + 1, last_downloaded_at = $2
WHERE id = $1 AND destroyed_at IS NULL RETURNING download_count`, row.privateKeyID, s.clock.Now().UTC()).Scan(&n); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrDestroyed // destroyed between the read and now
			}
			return fmt.Errorf("sshkeys: count the download: %w", err)
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "sshkey.private_key_downloaded", ObjectType: "ssh_key",
			ObjectID: in.KeyID.String(), Result: audit.Success, Details: map[string]string{"ssh_key_id": in.KeyID.String(),
				"fingerprint": row.fingerprint, "reason": in.Reason, "protected": strconv.FormatBool(in.Passphrase != nil),
				"download_count": strconv.Itoa(n)}})
		return err
	})
	if err != nil {
		file.Zero()
		return Download{}, err
	}
	return Download{FileName: fileName(row.label, row.fingerprint), Body: file}, nil
}

// fileName: "alice-<slug>-<first 8 hex of SHA-256(fingerprint)>.key" with the slug of keymat.Comment
// (only [a-z0-9._-]), so the header needs no quoting rules.
func fileName(label, fingerprint string) string {
	slug := strings.TrimSuffix(strings.TrimPrefix(keymat.Comment(label, time.Time{}), "alice:"), ":0001-01-01")
	sum := sha256.Sum256([]byte(fingerprint))
	return "alice-" + slug + "-" + hex.EncodeToString(sum[:4]) + ".key"
}
```

`buildFile` opens the envelope with `s.keyring.Open(keyLocation(row.privateKeyID), env)` (`keyLocation` = `secrets.Location{Table: "managed_private_keys", RowID: id.String(), Column: "ciphertext"}`, the AAD inventory uses), calls `onOpenedKey` when set, defers `pt.Zero()`, and returns `keymat.OpenSSHFile(pt, row.comment, passphrase)`; a decryption failure is `errors.New("sshkeys: the private key cannot be decrypted with this master key")` (no key material). `auditDownloadDenied` appends `sshkey.private_key_download.denied` (`ssh_key_id`, `reason`) in its own detached transaction (`context.WithoutCancel`, 5 s), as `inventory.auditDenial`.

- [ ] **Step 4: Run the tests to verify they pass**

Run (testcontainers): `go test -count=1 -race -tags integration ./internal/sshkeys/ && go test -count=1 ./internal/archtest/`
Expected: `ok` for both.

Run: `make lint`
Expected: no finding.

- [ ] **Step 5: Commit**

```bash
git add -- internal/sshkeys/*.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(sshkeys): generated keys, deploy requests, signer source, audited private key download, destruction of retired keys" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/sshkeys
```

(`git add -- internal/sshkeys/*.go` adds this task's new files only; the subpackages `keymat` and `plan` were committed in Tasks 1–2.)

---

### Task 8: `internal/sshkeys` part 2: policies, previews and their emails, scheduled planning, **Run now**

**Files:**
- Create: `internal/sshkeys/policies.go` (CreatePolicy, UpdatePolicy, SetPolicyEnabled, DeletePolicy, Policy, Policies), `internal/sshkeys/preview.go` (Preview, loadPlanInput, insertRun), `internal/sshkeys/schedule.go` (PlanDue, RunNow), `internal/sshkeys/notify.go` (template constants, `Templates`, the email parameter builders)
- Create: `internal/sshkeys/policies_integration_test.go`, `internal/sshkeys/preview_integration_test.go`

**Interfaces:**
- Consumes: Task 7 (`Service`, errors, `ManagedKey`), C4 (`plan.Build`, `Digest`, timers), C6 (`TargetTx`, `KeyLocationsTx`, `ProtectedFingerprintsTx`), `Notifier`.
- Produces: C7 "Task 8" part; `insertRun(ctx, tx, policy, p plan.Plan, digest, trigger, plannedFor, actor) (uuid.UUID, error)` (package-private, used by Task 9 too); audit actions `rotation.policy_*`, `rotation.policy.denied`, `rotation.previewed`, `rotation.created`; email templates `rotation.preview`.

Rules:

1. **CreatePolicy** — gate; key checks in this order: protected fingerprint or `is_platform_key` → `ErrOwnKeyProtected` with audit `rotation.policy.denied` reason `own_key` (F-36); not managed → `ErrNotManaged` (denied `not_managed`); retired → `ErrRetired` (denied `retired`); an existing live policy → `ErrPolicyExists`; validation (C13 bounds; `overlap_minutes = overlap_days * 1440`; `new_key_type` `same` or a keymat type); insert disabled with `next_run_at` NULL; audit `rotation.policy_created`. A `Z1010` from the trigger (a race with a retirement) maps to `ErrRetired`.
2. **UpdatePolicy** — version check (`ErrVersionMismatch`), only the fields given; `version + 1`, `updated_at`; when `interval_days` changes on an enabled policy without an open run, `next_run_at` is recomputed from `updated_at` (`plan.FirstRun`); audit `rotation.policy_updated` with the changed fields only.
3. **SetPolicyEnabled(true)** — gate; `next_run_at = plan.FirstRun(now, interval_days)`; audit `rotation.policy_enabled`. **(false)** — `next_run_at` NULL; an open run in `dry_run_notified` is cancelled (`rotation.policy_off`, the cancellation of C8); a started run continues; audit `rotation.policy_disabled`.
4. **DeletePolicy** — version check; an open run in `dry_run_notified` is cancelled (`rotation.policy_off`); any other open run → `ErrRotationInProgress`; soft delete (`deleted_at`, `enabled = false`, `next_run_at` NULL); audit.
5. **loadPlanInput(ctx, tx, policy, lock)** — reads the key row (managed, platform flag, retired, public key, label, type from `managed_private_keys.algorithm/bits` via `keymat.TypeOf`), `KeyLocationsTx(tx, key, lock)`, every distinct target with `TargetTx(tx, id, lock)` in ascending id order (a deleted target is left out of the map: the planner skips it), `ProtectedFingerprintsTx`, and maps them to `plan.Input` (Target fields from `inventory.Target`: `Status`, `Username`, `KeysManagedElsewhere`, `ManagedElsewhereUsers` and `SSHDUnreadUsers` from the facts' warnings with param `user`, `SSHDRead` from `Facts.SSHD`, `PermitRootLogin` and `PubkeyAuthentication` from `Facts.SSHD`, `UID0Users`); `NewComment = keymat.Comment(label, plannedFor)`.
6. **Preview** — gate (in lock: `license.ErrLocked`, L-88: no email in lock); `plan.Build`; refusals map: `plan.ErrOwnKey` → `ErrOwnKeyProtected`, `plan.ErrNotManaged` → `ErrNotManaged`, `plan.ErrRetired` → `ErrRetired`; `plan.ErrNothingToRotate` is **not** an error for a preview (it shows the skips); `PlannedFor` = `next_run_at` when enabled, else now; in one transaction: when `preview_mailed_at` is NULL or at least `PreviewMailEvery` old, `NotifyAdmins("rotation.preview", …)` and set `preview_mailed_at`; audit `rotation.previewed` (`emailed`).
7. **insertRun** — inserts the `rotations` row (`status = dry_run_notified`, `plan` = the JSON of `plan.Plan` (public data only), `plan_digest`, `new_key_type`, `overlap_minutes`, `planned_for`, `notified_at = now`), one `rotation_locations` row per action (`planned` or `skipped` with `skip_reason`; `verify_note`; `options`), queues `rotation.preview` (in the same transaction: this is the "notification before each run"), appends `rotation.created` and the first step (`dry_run_notified`).
8. **PlanDue** (task `rotation.plan`) — for every enabled live policy with `now ≥ plan.NoticeDue(next_run_at, notify_before_hours)` and no open run: in one transaction per policy (row lock on the policy), `loadPlanInput(lock)`, `plan.Build`; on `ErrNothingToRotate` nothing is created and the run is skipped until the next tick (logged at info with the policy id, no email storm: at most one `rotation.preview` per run created); on any other planner refusal the policy is switched off (`rotation.policy_disabled` with reason) — it can no longer run; else `insertRun(…, "scheduled", plan.PlannedFor(now, next_run_at, notify_before_hours))`. Returns the number of runs created.
9. **RunNow(policyID, digest)** — gate; the policy's open run: none → build the plan now (`loadPlanInput(lock)`), compare its digest with `digest` (`ErrPlanChanged` when different), `ErrNothingToRotate` refused, `insertRun(…, "manual", now)`, then `Advance` (Task 9) once in the same call so the run starts at once; an open `dry_run_notified` run → its stored digest must equal `digest` and a fresh plan's digest must equal it too (`ErrPlanChanged`), then its `planned_for` becomes now (the trigger becomes `manual`) and `Advance` runs; any other open run → `ErrRotationInProgress`.

- [ ] **Step 1: Write the failing tests**

`internal/sshkeys/policies_integration_test.go`:

```go
//go:build integration

package sshkeys_test

func TestPolicyDefaults(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	p, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "CI key", IntervalDays: 90})
	require.NoError(t, err)
	assert.False(t, p.Enabled, "off by default")
	assert.Equal(t, 7*1440, p.OverlapMinutes, "7 days of overlap by default")
	assert.Equal(t, 24, p.NotifyBeforeHours)
	assert.Equal(t, "same", p.NewKeyType)
	assert.Nil(t, p.NextRunAt)
	assert.Equal(t, 1, p.Version)
	assert.Equal(t, 1, e.audits("rotation.policy_created"))
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "again", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrPolicyExists)
}

func TestPolicyOnlyForGeneratedKeys(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: e.platformKeyRow(), Name: "p", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrOwnKeyProtected, "F-36 for rotation")
	assert.Equal(t, "own_key", e.lastAuditDetail("rotation.policy.denied", "reason"))
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: e.discoveredKey(), Name: "p", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrNotManaged)
	k := e.generate("old")
	e.retire(k.ID)
	_, err = e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90})
	assert.ErrorIs(t, err, sshkeys.ErrRetired)
	assert.Zero(t, e.count("SELECT count(*) FROM rotation_policies"))
}

func TestPolicyValidationAndVersions(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	for _, in := range []sshkeys.PolicyInput{
		{SSHKeyID: k.ID, Name: "", IntervalDays: 90},
		{SSHKeyID: k.ID, Name: "p", IntervalDays: 0},
		{SSHKeyID: k.ID, Name: "p", IntervalDays: 3651},
		{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, OverlapDays: 91},
		{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, NotifyBeforeHours: 169},
		{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, NewKeyType: "dsa"},
	} {
		_, err := e.svc.CreatePolicy(e.ctx, e.admin, in)
		var verr validate.Errors
		assert.ErrorAs(t, err, &verr, "%+v", in)
	}
	p, err := e.svc.CreatePolicy(e.ctx, e.admin, sshkeys.PolicyInput{SSHKeyID: k.ID, Name: "p", IntervalDays: 90, OverlapDays: 0})
	require.NoError(t, err)
	assert.Zero(t, p.OverlapMinutes, "an overlap of 0 is allowed (§7.3 CHECK overlap_days >= 0)")
	name := "renamed"
	p2, err := e.svc.UpdatePolicy(e.ctx, e.admin, p.ID, p.Version, sshkeys.PolicyPatch{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, 2, p2.Version)
	_, err = e.svc.UpdatePolicy(e.ctx, e.admin, p.ID, p.Version, sshkeys.PolicyPatch{Name: &name})
	assert.ErrorIs(t, err, sshkeys.ErrVersionMismatch)
}

func TestEnableSetsTheFirstRunAndDisableCancelsAPreview(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy") // generated and recorded at /home/deploy/.ssh/authorized_keys (RecordKeyAddedTx)
	p := e.policy(k.ID, 90, 7, 24)
	p, err := e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, true)
	require.NoError(t, err)
	assert.Equal(t, e.clock.Now().Add(90*24*time.Hour), *p.NextRunAt)
	e.clock.Advance(89 * 24 * time.Hour) // notice due
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	p = e.reloadPolicy(p.ID)
	_, err = e.svc.SetPolicyEnabled(e.ctx, e.admin, p.ID, p.Version, false)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	assert.Equal(t, "cancelled", r.Status)
	assert.Equal(t, "rotation.policy_off", r.ResultCode)
	assert.Equal(t, 1, e.count("SELECT count(*) FROM rotation_locations WHERE state = 'cancelled'"))
}

func TestDeleteRefusedWhileARunIsStarted(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	r := e.runNow(p) // preview + RunNow: the run starts (adding_new; location jobs queued)
	require.Equal(t, "adding_new", r.Status)
	err := e.svc.DeletePolicy(e.ctx, e.admin, p.ID, e.reloadPolicy(p.ID).Version)
	assert.ErrorIs(t, err, sshkeys.ErrRotationInProgress)
}
```

`internal/sshkeys/preview_integration_test.go`:

```go
//go:build integration

package sshkeys_test

func TestPreviewEmailsAdmins(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.True(t, pv.Emailed)
	assert.Equal(t, 1, pv.Plan.Changes)
	assert.Regexp(t, `^[0-9a-f]{64}$`, pv.Digest)
	m := e.mails("rotation.preview")
	require.Len(t, m, 1)
	assert.Equal(t, "ci", m[0]["key_label"])
	assert.Equal(t, "1", m[0]["change_count"])
	assert.Equal(t, "0", m[0]["skip_count"])
	pv, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.False(t, pv.Emailed, "at most one email per policy per 10 minutes")
	e.clock.Advance(10 * time.Minute)
	pv, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.True(t, pv.Emailed)
	assert.Equal(t, 3, e.audits("rotation.previewed"))
	assert.Zero(t, e.count("SELECT count(*) FROM rotations"), "a preview creates no run")
}

func TestPreviewRefusedInLockSendsNothing(t *testing.T) {
	e := newEnv(t)
	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	e.gate.lock()
	_, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.Empty(t, e.mails("rotation.preview"))
}

func TestPreviewShowsSkipsWhenNothingCanChange(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	e.setTargetStatus(srv, "unreachable")
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	assert.Zero(t, pv.Plan.Changes)
	assert.Equal(t, "target_not_connected", pv.Plan.Actions[0].Skip)
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrNothingToRotate)
}

// §13.6 item 1: the scheduled run is created only together with its notice, and starts only after it.
func TestScheduledRunNotifiesBeforeStart(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24) // next run at +90 d
	e.clock.Advance(89*24*time.Hour - time.Second)
	n, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "the notice is not due yet")
	e.clock.Advance(time.Second)
	n, err = e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	r := e.onlyRun(p.ID)
	assert.Equal(t, "dry_run_notified", r.Status)
	assert.Equal(t, e.clock.Now(), r.NotifiedAt)
	assert.Equal(t, e.clock.Now().Add(24*time.Hour), r.PlannedFor)
	assert.Len(t, e.mails("rotation.preview"), 1, "the notice was queued with the run")
	n, err = e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "one open run per policy")
}

func TestRunNowNeedsThePreviewedDigest(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.policy(k.ID, 90, 7, 24)
	pv, err := e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	e.addLocation(k.ID, e.server("web-02"), "deploy") // the fleet changes after the preview
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrPlanChanged)
	assert.Zero(t, e.count("SELECT count(*) FROM rotations"))
	pv, err = e.svc.Preview(e.ctx, e.admin, p.ID)
	require.NoError(t, err)
	r, err := e.svc.RunNow(e.ctx, e.admin, p.ID, pv.Digest)
	require.NoError(t, err)
	assert.Equal(t, "adding_new", r.Status)
	assert.Equal(t, "manual", r.Trigger)
	assert.Equal(t, pv.Digest, r.Digest)
	assert.Len(t, r.Locations, 2)
	assert.Equal(t, 2, e.count("SELECT count(*) FROM jobs WHERE type = 'rotation.location'"))
}

func TestRunNowStartsAPreviewedScheduledRun(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err := e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	started, err := e.svc.RunNow(e.ctx, e.admin, p.ID, r.Digest)
	require.NoError(t, err)
	assert.Equal(t, r.ID, started.ID, "the previewed run starts, no second run")
	assert.Equal(t, "adding_new", started.Status)
	_, err = e.svc.RunNow(e.ctx, e.admin, p.ID, r.Digest)
	assert.ErrorIs(t, err, sshkeys.ErrRotationInProgress)
}
```

Harness additions (`harness_integration_test.go`): `e.deployed(label, target, user) sshkeys.ManagedKey` (generate, then `RecordKeyAddedTx` for `/home/<user>/.ssh/authorized_keys`, `/root/.ssh/authorized_keys` for root), `e.addLocation(keyID, target, user)`, `e.policy(keyID, interval, overlapDays, notifyHours)`, `e.enabledPolicy(…)`, `e.reloadPolicy(id)`, `e.onlyRun(policyID) sshkeys.Rotation`, `e.runNow(p) sshkeys.Rotation` (Preview then RunNow with its digest), `e.mails(template) []map[string]string` (the recording notifier's calls).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -tags integration -run 'TestPolicy|TestEnable|TestDelete|TestPreview|TestScheduledRun|TestRunNow' ./internal/sshkeys/`
Expected: FAIL — undefined: `CreatePolicy`, `Preview`, `PlanDue`, `RunNow`.

- [ ] **Step 3: Write the implementation**

Implement rules 1–9 above. Two pieces in full:

```go
// preview.go

// toPlanInput maps what inventory knows to the planner's input (rule 5).
func toPlanInput(key keyRow, locs []inventory.KeyLocation, targets map[uuid.UUID]inventory.Target, protected []string,
	pol Policy, plannedFor time.Time) plan.Input {
	in := plan.Input{
		Key: plan.Key{ID: key.id, Fingerprint: key.fingerprint, PublicKey: key.publicKey, Label: key.label, Managed: key.managed,
			IsPlatform: key.isPlatform, Retired: key.retiredAt != nil, KeyType: string(keymat.TypeOf(key.algorithm, key.bits))},
		Targets:        make(map[uuid.UUID]plan.Target, len(targets)),
		Protected:      protected,
		NewKeyType:     pol.NewKeyType,
		OverlapMinutes: pol.OverlapMinutes,
		NewComment:     keymat.Comment(key.label, plannedFor),
	}
	for id, t := range targets {
		pt := plan.Target{ID: id, Name: t.Name, Status: t.Status, ConnectionUser: t.Username, KeysManagedElsewhere: t.KeysManagedElsewhere,
			UID0Users: t.Facts.UID0Users}
		if t.Facts.SSHD != nil {
			pt.SSHDRead = t.Facts.SSHD.Read
			pt.PermitRootLogin = t.Facts.SSHD.PermitRootLogin
			pt.PubkeyAuthentication = t.Facts.SSHD.PubkeyAuthentication
		}
		for _, w := range t.Facts.Warnings {
			switch w.Code {
			case "keys_managed_elsewhere":
				if u := w.Params["user"]; u != "" {
					pt.ManagedElsewhereUsers = append(pt.ManagedElsewhereUsers, u)
				}
			case "sshd_unreadable":
				if u := w.Params["user"]; u != "" {
					pt.SSHDUnreadUsers = append(pt.SSHDUnreadUsers, u)
				} else {
					pt.SSHDRead = false
				}
			}
		}
		in.Targets[id] = pt
	}
	for _, l := range locs {
		in.Locations = append(in.Locations, plan.Location{ID: l.ID, TargetID: l.TargetID, OSUser: l.OSUser, FilePath: l.FilePath,
			Options: l.Options, Comment: l.Comment, Flags: l.Flags, Missing: l.MissingSince != nil,
			IsAliceConnectionKey: l.IsAliceConnectionKey})
	}
	return in
}

// planError maps the planner's refusals to the module's errors.
func planError(err error) error {
	switch {
	case errors.Is(err, plan.ErrOwnKey):
		return ErrOwnKeyProtected
	case errors.Is(err, plan.ErrNotManaged):
		return ErrNotManaged
	case errors.Is(err, plan.ErrRetired):
		return ErrRetired
	case errors.Is(err, plan.ErrNothingToRotate):
		return ErrNothingToRotate
	}
	return err
}
```

(`keyRow` is the package-private read of the key: `id`, `fingerprint`, `publicKey`, `label`, `managed`, `isPlatform`, `retiredAt`, `algorithm`, `bits` from `ssh_keys` joined to `managed_private_keys`, `algorithm`/`bits` defaulting to `ed25519`/256 for a key without a private key — such a key never plans: `Managed` is false.)

Email params (`notify.go`): `previewParams(key keyRow, p plan.Plan, plannedFor time.Time) map[string]string` = `key_label`, `fingerprint`, `planned_for` (`plannedFor.UTC().Format("2006-01-02 15:04 UTC")`), `change_count`, `skip_count`. Template constants (`TemplatePreview = "rotation.preview"`, `TemplatePreviewAfterLicense`, `TemplateOverlapStarted`, `TemplateOverlapEnding`, `TemplateCompleted`, `TemplateAborted`, `TemplateNeedsAttention`, `TemplatePausedLicense`, `TemplateDecisionNeeded`) and `Templates()` returning the nine, in C10's order.

- [ ] **Step 4: Run the tests to verify they pass**

Run (testcontainers): `go test -count=1 -race -tags integration ./internal/sshkeys/`
Expected: `ok`. (`TestDeleteRefusedWhileARunIsStarted` and `TestRunNow*` need `Advance` from Task 9 to start a run: until Task 9 lands, `RunNow` calls a package-private `start` that Task 9 replaces by `Advance`; write `start` here as the `dry_run_notified → adding_new` transition of C8 — key generation, `rotated_from`, comment, `next_run_at`, location jobs — and let Task 9's `Advance` call it, so nothing is written twice.)

- [ ] **Step 5: Commit**

```bash
git add -- internal/sshkeys/policies.go internal/sshkeys/preview.go internal/sshkeys/schedule.go internal/sshkeys/notify.go \
  internal/sshkeys/policies_integration_test.go internal/sshkeys/preview_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(sshkeys): rotation policies, previews and their emails, scheduled planning, Run now with the previewed digest" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/sshkeys
```

---

### Task 9: `internal/sshkeys` part 3: rotation store, the controller `Advance`, the sweep, decisions, rotation emails

**Files:**
- Create: `internal/sshkeys/rotations.go` (Rotation reads, `Rotations`, `AllowedActions`), `internal/sshkeys/controller.go` (`Advance`, `start`, the per-status functions, `finish`), `internal/sshkeys/store.go` (runner-facing store of C7), `internal/sshkeys/sweep.go` (`Sweep`), `internal/sshkeys/decisions.go` (`Continue`, `FinishNow`, `KeepOld`, `Abort`)
- Create: `internal/sshkeys/controller_integration_test.go`, `internal/sshkeys/store_integration_test.go`, `internal/sshkeys/decisions_integration_test.go`

**Interfaces:**
- Consumes: Tasks 7–8; C8 (the state machine — the tables are this task's specification); `inventory.CheckClaimTx`, `RecordKeyAddedTx`, `MarkKeyRemoved`, `KeyLocation`; `keymat.Generate`, `keymat.Line`, `keymat.Comment`; `plan.*` timers.
- Produces: C7 "Task 9" part; audit actions `rotation.status_changed`, `rotation.location_changed`, `rotation.paused`, `rotation.continued`, `rotation.finish_requested`, `rotation.old_kept`, `rotation.stop_requested`, `sshkey.retired`; emails of C10 except `rotation.preview`; `func AllowedActions(r Rotation, gateOK bool) []string`.

Implementation notes binding this task:

- **Locking order** (deadlock-free with inventory): a transaction that touches a run locks the `rotations` row first (`SELECT … FOR UPDATE`), then the `rotation_locations` rows it changes in `n` order; it never locks a target row except through `inventory.RecordKeyAddedTx` (which locks the target, as inventory's own writers do: target before location). `Advance` is serialised per run by the row lock; the sweep and a location job may call it concurrently.
- **Fencing**: every store write and `Advance` call `inventory.CheckClaimTx` first, so a location job that lost its lease writes nothing (as the deployment engine since P4-15).
- **CAS**: every location transition is `UPDATE rotation_locations SET state = $new, … WHERE id = $1 AND state = ANY($allowed)`; zero rows → `ErrNotYourTurn`.
- **Gate**: `G` of C8 is `s.license.Allow(license.ClassChange) == nil`. The store's `BeginAdd` and `BeginRemove` return `ErrPaused` when `¬G` or the run is paused; `BeginUndo` never asks.
- **start** (`dry_run_notified → adding_new`, called by `Advance` and `RunNow`): outside the transaction, `keymat.Generate(s.rand, newKeyType)` in a generation slot (`ErrGenerateBusy` → the run waits for the next sweep, no state change); then one transaction: lock the run, re-check `status = dry_run_notified`, re-plan with `loadPlanInput(lock)`, compare digests (different → cancel `rotation.plan_changed`, zero the key, return), insert the new key (as `Generate` of Task 7: `ssh_keys` managed with `rotated_from` = old, `label` = old label, `key_comment` = `keymat.Comment(label, now)`; `managed_private_keys`), set `new_ssh_key_id`, `started_at`, status `adding_new`; for an enabled policy `next_run_at = plan.NextRun(now, interval_days)`; queue one `rotation.location` job (phase `add`) per `planned` location; audit and step. `NewLine` of each location (computed in `LocationWork`) is `keymat.Line(location.options, newPublicKey, newComment)`.
- **Advance** makes **at most one status transition per call** (the sweep, the next location job or the next action makes the next one), so every intermediate state is observable and tested; it implements the run rows of C8 in one transaction per call, then sends nothing outside it (emails are outbox rows of that transaction). When it ends a run (`completed`): `UPDATE rotation_policies SET ssh_key_id = new WHERE id = policy` (the policy follows the key), and when `inventory.KeyLocationsTx(old)` has no live row (none without `missing_since`), `UPDATE ssh_keys SET retired_at = now` for the old key and audit `sshkey.retired`.
- **Sweep**: for each live run (status not terminal), in `planned_for`/`created_at` order: call `Advance(id)` (errors counted, never stopping the loop); then re-queue (dedupe) location jobs per the last paragraph of C8, incrementing `job_count`; a location at `MaxLocationJobs` without progress is ended with `rotation.retries_exhausted` (state `add_failed` for `planned`/`adding`, `remove_failed` for `verified`/`removing`, `undo_failed` for undo-pending) and `Advance` runs again. Lock handling: when `¬G`, `Advance` pauses or cancels as C8 says; the sweep itself only flags (it never starts remote work: it queues `undo` jobs in `rolling_back` and re-queues in-flight `adding`/`removing` resumptions, which the job handles under the store's rules).
- **Decisions**: `Continue` needs `paused_license` and `G` (`ErrNotWaiting`/`license.ErrLocked`), clears the pause, sets `continued_by/at`, `renotified_at`, queues `rotation.preview_after_license` (L-84) and audits `rotation.continued`, then calls `Advance`; `FinishNow` needs status `overlap` (`ErrNotWaiting`) and `G`, sets `overlap_until = now`, audits `rotation.finish_requested`, then `Advance`; `KeepOld` needs `verifying_new` with `awaiting_decision` and every id an `unverifiable` location of the run; it moves them **and every other location of the run in the same `(target, file)`** (a shared file is kept as a whole, R41 row 29) to `kept_old`, and refuses (`ErrNotWaiting`, nothing changed) when no `verified` location would remain; audits `rotation.old_kept` (`location_count`), then `Advance`; `Abort` needs status `dry_run_notified` (→ `cancelled`, `rotation.stopped`) or `adding_new`/`verifying_new`/`overlap` (→ `rolling_back`, result `rotation.stopped`; `planned` → `cancelled`; undo jobs for every location with `add_sent_at`, `kept_old` included), audits `rotation.stop_requested`; in `removing_old` or later → `ErrNotWaiting`.
- **AllowedActions**: `continue` when paused and `gateOK`; `finish_now` in `overlap`, not paused, `gateOK`; `keep_old` in `verifying_new` with `awaiting_decision` and at least one `verified` location; `abort` in `dry_run_notified`, `adding_new`, `verifying_new`, `overlap` with `gateOK`.

- [ ] **Step 1: Write the failing tests**

`internal/sshkeys/store_integration_test.go` drives the store by hand (no jobs), as the runner will:

```go
//go:build integration

package sshkeys_test

// The whole happy path through the store, by hand: add, verify, overlap, re-verify, remove.
func TestRotationHappyPathThroughTheStore(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	p := e.enabledPolicy(k.ID, 90, 1, 24) // overlap 1 day
	r := e.runNow(p)
	loc := r.Locations[0]
	w, err := e.svc.LocationWork(e.claimed(), loc.ID) // claimed(): a context with the location job's claim
	require.NoError(t, err)
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(w.NewLine))
	require.NoError(t, err)
	assert.Equal(t, w.NewFingerprint, ssh.FingerprintSHA256(pk), "the line carries the new key")
	assert.Equal(t, "alice:ci:2026-10-05", comment)
	op, err := e.svc.BeginAdd(e.claimed(), loc.ID)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, op)
	require.NoError(t, e.svc.FinishAdd(e.claimed(), loc.ID, sshkeys.AddRecord{Definite: true, Added: true, LineNo: 2, Actor: e.jobActor()}))
	require.NoError(t, e.svc.RecordVerify(e.claimed(), loc.ID, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	r = e.run(r.ID)
	assert.Equal(t, "overlap", r.Status)
	assert.Equal(t, e.clock.Now().Add(24*time.Hour), *r.OverlapUntil)
	assert.Len(t, e.mails("rotation.overlap_started"), 1)

	_, err = e.svc.BeginRemove(e.claimed(), loc.ID)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "no removal during the overlap")
	e.clock.Advance(24 * time.Hour)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "removing_old", e.run(r.ID).Status)
	_, err = e.svc.BeginRemove(e.claimed(), loc.ID)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "no removal without a fresh login")
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc.ID, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	rop, err := e.svc.BeginRemove(e.claimed(), loc.ID)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, rop)
	require.NoError(t, e.svc.FinishRemove(e.claimed(), e.jobActor(), loc.ID, sshkeys.RemoveRecord{Definite: true, Removed: 1,
		Res: providers.AuthKeyResult{Changed: true, Removed: 1, Verified: true}}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	r = e.run(r.ID)
	assert.Equal(t, "completed", r.Status)
	assert.Equal(t, *r.NewKeyID, e.reloadPolicy(p.ID).SSHKeyID, "the policy follows the new key")
	old, err := e.svc.ManagedKey(e.ctx, k.ID)
	require.NoError(t, err)
	assert.NotNil(t, old.RetiredAt, "no live location left: retired")
	assert.Len(t, e.mails("rotation.completed"), 1)
	assert.GreaterOrEqual(t, len(r.Steps), 8, "every transition is a recorded step (§26.8)")
}

func TestBeginRemoveRefusals(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r, loc := e.runInRemoving(k) // a run in removing_old, its location verified (helper)
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	e.clock.Advance(15*time.Minute + time.Second)
	_, err := e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, "a re-verification older than 15 minutes is stale")
	require.NoError(t, e.svc.RecordReverify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	e.gate.lock()
	_, err = e.svc.BeginRemove(e.claimed(), loc)
	assert.ErrorIs(t, err, sshkeys.ErrPaused)
	e.gate.unlock()
	_, err = e.svc.BeginRemove(e.lostClaim(), loc)
	assert.ErrorIs(t, err, inventory.ErrClaimLost)
	require.NoError(t, e.svc.Advance(e.ctx, r))
	_, err = e.svc.BeginRemove(e.claimed(), loc)
	require.NoError(t, err)
}

// R41 row 29: a shared file loses the old key only when every one of its locations was verified;
// keeping the old key for one user of a shared file keeps it for the file.
func TestSharedFileRemovedOnlyWhenEveryUserVerified(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployedShared("ci", srv, "/etc/ssh/keys/shared", "deploy", "backup") // one file, two users; backup's line has from=
	e.addLocation(k.ID, srv, "app")                                                // app's own file
	r, locs := e.runToDecisionWith(k, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted,
		"backup": providers.KeyLoginRefused, "app": providers.KeyLoginAccepted}) // refused with from=: unverifiable
	assert.Equal(t, "verifying_new", r.Status)
	require.NoError(t, e.svc.KeepOld(e.ctx, e.admin, r.ID, []uuid.UUID{locs["backup"]}))
	r = e.run(r.ID)
	assert.Equal(t, "overlap", r.Status)
	assert.Equal(t, "kept_old", e.locState(r, "deploy"), "the shared file is kept as a whole")
	assert.Equal(t, "kept_old", e.locState(r, "backup"))
	e.clock.Advance(7 * 24 * time.Hour)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	for _, user := range []string{"deploy", "backup"} {
		_, err := e.svc.BeginRemove(e.claimed(), locs[user])
		assert.ErrorIs(t, err, sshkeys.ErrNotYourTurn, user)
	}
	require.NoError(t, e.svc.RecordReverify(e.claimed(), locs["app"], sshkeys.VerifyRecord{Outcome: providers.KeyLoginAccepted}))
	_, err := e.svc.BeginRemove(e.claimed(), locs["app"])
	require.NoError(t, err)

	// Without another verified location, keeping the shared file's old key leaves nothing to rotate: refused.
	e2 := newEnv(t)
	srv2 := e2.server("web-01")
	k2 := e2.deployedShared("ci", srv2, "/etc/ssh/keys/shared", "deploy", "backup")
	r2, locs2 := e2.runToDecisionWith(k2, map[string]providers.KeyLoginOutcome{"deploy": providers.KeyLoginAccepted,
		"backup": providers.KeyLoginRefused})
	assert.ErrorIs(t, e2.svc.KeepOld(e2.ctx, e2.admin, r2.ID, []uuid.UUID{locs2["backup"]}), sshkeys.ErrNotWaiting)
}

func TestUndoNeverTouchesTheOldKey(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.deployed("ci", srv, "deploy")
	r := e.runNow(e.policy(k.ID, 90, 7, 24))
	loc := r.Locations[0].ID
	_, err := e.svc.BeginAdd(e.claimed(), loc)
	require.NoError(t, err)
	require.NoError(t, e.svc.FinishAdd(e.claimed(), loc, sshkeys.AddRecord{Definite: true, Added: true, LineNo: 2, Actor: e.jobActor()}))
	require.NoError(t, e.svc.RecordVerify(e.claimed(), loc, sshkeys.VerifyRecord{Outcome: providers.KeyLoginRefused}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "rolling_back", e.run(r.ID).Status)
	w, err := e.svc.LocationWork(e.claimed(), loc)
	require.NoError(t, err)
	op, err := e.svc.BeginUndo(e.claimed(), loc)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, op)
	assert.NotEqual(t, w.OldFingerprint, w.NewFingerprint)
	require.NoError(t, e.svc.FinishUndo(e.claimed(), e.jobActor(), loc, sshkeys.UndoRecord{Definite: true,
		Res: providers.AuthKeyResult{Changed: true, Removed: 1}}))
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	r = e.run(r.ID)
	assert.Equal(t, "aborted", r.Status)
	assert.Equal(t, "rotation.verify_failed", r.ResultCode)
	assert.Zero(t, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND removed_by_alice_at IS NOT NULL", k.ID),
		"the old key's location was never marked removed")
	assert.Len(t, e.mails("rotation.aborted"), 1)
}
```

Harness additions: `e.claimed()` (a context carrying an `inventory.Claim` of a running `rotation.location` job the harness inserted and claimed), `e.lostClaim()` (the same job taken back), `e.jobActor()`, `e.run(id)`, `e.locState(r, user)`, `e.deployedShared(label, target, file, users...)` (one file recorded for several users; the second and later users' lines with `from="10.0.0.0/8"`), `e.runToDecisionWith(k, outcomes) (sshkeys.Rotation, map[string]uuid.UUID)` (create a policy with a 7-day overlap, run it, drive every location through `BeginAdd`/`FinishAdd`/`RecordVerify` with the given outcomes, `Advance`; return the run and the location ids by user) and `e.runInRemoving(k) (runID, locationID uuid.UUID)` (the same with one accepted location, then the clock past the overlap and `Advance`: the run is `removing_old`).

`internal/sshkeys/controller_integration_test.go`:

- `TestScheduledStartReplansAndRenotifies`: a scheduled run is previewed; before `planned_for` a second location of the key appears; at `planned_for` `Advance` cancels the run with `rotation.plan_changed`; the next `PlanDue` creates a new run with a new digest and a second `rotation.preview` email; nothing was generated (no new `ssh_keys` row).
- `TestStartIsIdempotentAndBusySafe`: two concurrent `Advance` calls at `planned_for` create exactly one new key and one set of location jobs; with every generation slot held, `Advance` leaves the run in `dry_run_notified` and a later call starts it.
- `TestAdvanceGatesEveryForwardStep` (table: `dry_run_notified` at `planned_for` in lock → `cancelled`/`rotation.cancelled_license`, no email but none sent before; `adding_new` with a `planned` location in lock → paused, `rotation.paused_license` email once, a second `Advance` sends no second email; `overlap` ended in lock → paused, status stays `overlap` (L-83); `removing_old` with a `verified` location left in lock → paused; `rolling_back` in lock → undo jobs still queued).
- `TestDecisionTimeout`: `verifying_new` waiting; at `decision_due_at - 1s` nothing; at `decision_due_at` → `rolling_back`, result `rotation.decision_timeout`; in lock at that time → waits (timers do not fire in lock).
- `TestReminderBeforeOverlapEnd`: overlap 3 days → `rotation.overlap_ending` email at `overlap_until - 24h`, once; overlap 2 days → none.
- `TestCompletedKeepsAnOldKeyThatIsStillUsed`: one location skipped (unreachable) at planning, the other rotated: `completed`, the old key not retired, the policy on the new key.
- `TestStepsRecorded`: every status and location change appends a step and an audit row (`rotation.status_changed`, `rotation.location_changed`) with C12's details.

`internal/sshkeys/decisions_integration_test.go`:

- `TestContinueAfterRenewalRenotifies` (L-84 at the store): a paused run in `overlap` past `overlap_until`; `Continue` in lock → `license.ErrLocked`; after unlock `Continue` → flag cleared, `continued_by`, `renotified_at`, one `rotation.preview_after_license` email, `Advance` moves to `removing_old`; `BeginRemove` still needs a fresh `RecordReverify`.
- `TestFinishNow`: only in `overlap` (else `ErrNotWaiting`); sets `overlap_until = now`; the next `Advance` enters `removing_old`.
- `TestKeepOldNeedsAVerifiedLocation`: all locations unverifiable → `KeepOld` with all of them → `ErrNotWaiting`; with one verified → accepted, the others `kept_old`, status `overlap`.
- `TestAbortStates`: `dry_run_notified` → `cancelled` (`rotation.stopped`); `overlap` → `rolling_back` (undo jobs for every added location, `kept_old` ones included); `removing_old` → `ErrNotWaiting`.
- `TestAllowedActions` (pure table over `sshkeys.AllowedActions`).
- `TestSweepRequeuesAndBoundsRetries`: a location in `adding` without a live job gets a job (dedupe: a second sweep adds none while it is live); after `MaxLocationJobs` re-queues without progress the location ends `add_failed` with `rotation.retries_exhausted` and the run goes `rolling_back`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -tags integration -run 'TestRotationHappyPath|TestBeginRemove|TestShared|TestUndo|TestScheduledStart|TestStart|TestAdvance|TestDecision|TestReminder|TestCompleted|TestSteps|TestContinue|TestFinish|TestKeepOld|TestAbort|TestAllowed|TestSweep' ./internal/sshkeys/`
Expected: FAIL — undefined: `Advance`, `LocationWork`, `BeginAdd`, …

- [ ] **Step 3: Write the implementation**

Implement C7 (Task 9 part) and C8 with the notes above. The removal gate, in full (the one function every removal passes):

```go
// BeginRemove moves a verified location to removing just before its removal is sent (C8). It is the
// only way to obtain the operation id RemoveAuthorizedKey of the old key is called with.
func (s *Service) BeginRemove(ctx context.Context, locationID uuid.UUID) (uuid.UUID, error) {
	now := s.clock.Now().UTC()
	var op uuid.UUID
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := inventory.CheckClaimTx(ctx, tx); err != nil {
			return err
		}
		run, loc, err := lockRunAndLocation(ctx, tx, locationID) // run row FOR UPDATE, then the location FOR UPDATE
		if err != nil {
			return err
		}
		if s.license.Allow(license.ClassChange) != nil || run.pausedLicense {
			return ErrPaused
		}
		switch {
		case run.status != "removing_old" || !run.removalAllowed:
			return ErrNotYourTurn
		case loc.state != "verified" && loc.state != "removing":
			return ErrNotYourTurn
		case loc.reverifiedAt == nil || !plan.Fresh(now, *loc.reverifiedAt):
			return ErrNotYourTurn
		}
		blocked, err := fileHasUnverifiedLocation(ctx, tx, run.id, loc.targetID, loc.filePath) // any location of the run in that
		if err != nil {                                                                      // (target, file) not in verified,
			return err                                                                       // removing or removed
		}
		if blocked {
			return ErrNotYourTurn
		}
		protected, err := inventory.ProtectedFingerprintsTx(ctx, tx)
		if err != nil {
			return err
		}
		if slices.Contains(protected, run.oldFingerprint) {
			return ErrOwnKeyProtected
		}
		op = loc.removeOpID
		if op == uuid.Nil {
			op = uuid.Must(uuid.NewV7())
		}
		tag, err := tx.Exec(ctx, `UPDATE rotation_locations SET state = 'removing', remove_op_id = $2, remove_verified_at = reverified_at,
    remove_sent_at = $3, updated_at = $3 WHERE id = $1 AND state IN ('verified', 'removing')`, locationID, op, now)
		if err != nil {
			return fmt.Errorf("sshkeys: begin the removal: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrNotYourTurn
		}
		return s.locationChanged(ctx, tx, run, loc, "removing", "") // audit rotation.location_changed + step
	})
	return op, err
}
```

The same pattern (claim, lock run then location, rule checks of C8, one CAS update, audit and step) is used by `BeginAdd`, `FinishAdd`, `RecordVerify`, `RecordReverify`, `FinishRemove`, `BeginUndo` and `FinishUndo`. `FinishAdd{Definite, Added}` also calls `inventory.RecordKeyAddedTx` (Verified false) and stores `new_location_id`; `FinishRemove` with `Removed > 0` calls `inventory.MarkKeyRemoved(old_location_id)` after its own commit (the inventory method opens its own transaction; a failure there is logged and retried by the next sweep's reconciliation of `removed` locations whose `ssh_key_locations.removed_by_alice_at` is NULL); `FinishUndo` with `Removed > 0` marks the new location removed the same way.

- [ ] **Step 4: Run the tests to verify they pass**

Run (testcontainers): `go test -count=1 -race -tags integration ./internal/sshkeys/`
Expected: `ok`.

Run: `go test -count=1 -tags integration -coverprofile=/tmp/sk.out ./internal/sshkeys/ && go tool cover -func=/tmp/sk.out | tail -1`
Expected: a total (recorded in the task report; Task 19 sets the floor from the final measurement). Every function of `store.go` and `controller.go` above 90 %.

- [ ] **Step 5: Commit**

```bash
git add -- internal/sshkeys/rotations.go internal/sshkeys/controller.go internal/sshkeys/store.go internal/sshkeys/sweep.go \
  internal/sshkeys/decisions.go internal/sshkeys/controller_integration_test.go internal/sshkeys/store_integration_test.go \
  internal/sshkeys/decisions_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(sshkeys): rotation store, controller, sweep and decisions; the old key leaves only after a fresh login" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/sshkeys
```

---

### Task 10: Jobs: the five job types, `sshkeyjobs.Register`, the `sshkey.add` handler

**Files:**
- Modify: `internal/jobs/types.go` (registrations, `MaxAttemptsFor`, `AlertsWhenExhausted`)
- Modify: `internal/jobs/stubjobs_test.go` (a comment on `testRotation` pointing to the real tests of Task 12)
- Create: `internal/jobs/sshkeyjobs/sshkeyjobs.go` (Keys, Targets, Deps, Register, `open`, `recordFailure`, `close`, `classify`), `internal/jobs/sshkeyjobs/deploy.go` (the `sshkey.add` handler)
- Create: `internal/jobs/sshkeyjobs/harness_integration_test.go`, `internal/jobs/sshkeyjobs/deploy_integration_test.go`, `internal/jobs/sshkeyjobs/sshkeyjobs_test.go`
- Test: `internal/jobs/types_test.go` (or the file holding the registry tests; add there)

**Interfaces:**
- Consumes: C7 (Task 7 part: `DeployJob`, `FinishDeploy`, `KeySigner`, `ProtectedFingerprints`), C9, `targetjobs`' session pattern (`open`, `recordFailure`, `close`, `writeTracker`, `connectionReasons`), `jobs.Fail/Retry/Attention/FromProvider`.
- Produces: `jobs.SSHKeyAdd`, `jobs.RotationLocation`, `jobs.RotationPlan`, `jobs.RotationSweep`, `jobs.SSHKeyDestroyRetired`; `sshkeyjobs.Register`, `Deps`, `Keys`, `Targets`; the `sshkey.add` decision table of C9.

- [ ] **Step 1: Write the failing tests**

In the jobs registry test file:

```go
func TestPhase6JobClasses(t *testing.T) {
	assert.Equal(t, license.ClassChange, jobs.SSHKeyAdd.Class)
	assert.Equal(t, license.ClassAlways, jobs.RotationLocation.Class, "finishing in-flight work and undoing are never blocked (L-85, L-86)")
	assert.Equal(t, license.ClassReadOnly, jobs.RotationPlan.Class, "no preview is sent in lock (L-88)")
	assert.Equal(t, license.ClassAlways, jobs.RotationSweep.Class, "the sweep flags pauses in lock (L-83)")
	assert.Equal(t, license.ClassReadOnly, jobs.SSHKeyDestroyRetired.Class, "no deletion in lock (L-29)")
	assert.Equal(t, 3, jobs.MaxAttemptsFor(jobs.SSHKeyAdd))
	assert.Equal(t, 3, jobs.MaxAttemptsFor(jobs.RotationLocation))
	assert.False(t, jobs.AlertsWhenExhausted(jobs.RotationLocation), "the rotation's own emails carry its failures")
	assert.True(t, jobs.AlertsWhenExhausted(jobs.SSHKeyAdd))
}
```

`internal/jobs/sshkeyjobs/harness_integration_test.go` (`//go:build integration`): `TestMain` with `pgtest.Main`; `newEnv(t)` as the `deployjobs` harness (fake clock, `lockGate`, `license.Service` stand-in through the gate, `inventory.Service` and `sshkeys.Service` on one pool, `jobs.Queue`, a `jobs.Runner` with `sshkeyjobs.Register`, the fake provider `fake.New(providers.KindLinuxSSH, CapTestConnection, CapDiscoverSSHKeys, CapAuthorizedKeys, CapKeyLogin)` with `Config.Keys = e.world` registered for target type `linux`), fields `e.ctx`, `e.keys` (`*sshkeys.Service`), `e.queue`, `e.gate`, `e.world` (`*fake.KeyWorld`), `e.provider` (`*fake.Provider`), `e.operator` and `e.admin` (`inventory.Actor`), `e.adminID` and `e.adminAudit` (for `Queue.Confirm`); helpers `e.server(name)` (a confirmed `ok` target with key-file facts as Task 7's harness, and the platform key's line in its `alice-svc` file in the world), `e.generate(label)`, `e.otherKeyLine(t)` (a fresh unrelated public key line), `e.job(id) jobs.View`, `e.events(method) []fake.Event`, `e.countEvents(method) int`, `e.targetStatus(id) string`, `e.count(sql, args...)`, `e.lastAuditDetail(action, key)`, `e.drain()` (`runner.RunOnce` until none ran, at most 200), `e.restart()` (clock +46 s, `runner.Recover`), `e.audits(action)`, the `killer` of `deployjobs`' harness (copied: `newKiller`, `at`, `firedAt`, `runtime.Goexit` at a point) wrapped around the `Keys` interface (`killKeys` embeds `*sshkeys.Service` and calls `k.at("before:<Method>")` / `k.at("after:<Method>")` around every method), and around the session (`session:after:<Method>` points through a provider wrapper, as `deployjobs.hookProvider`).

`internal/jobs/sshkeyjobs/deploy_integration_test.go`:

```go
//go:build integration

package sshkeyjobs_test

const deployFile = "/home/deploy/.ssh/authorized_keys"

func TestDeployVerifiesLogin(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	e.world.Put(srv, "deploy", deployFile, e.otherKeyLine(t)) // an existing key of someone else
	k := e.generate("ci")
	job, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: deployFile})
	require.NoError(t, err)
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "verified", v.Result["result"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint))
	assert.Len(t, e.world.Lines(srv, deployFile), 2, "the other key is untouched")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM ssh_key_locations WHERE ssh_key_id = $1 AND line_no = 2", k.ID))
	assert.Equal(t, "true", e.lastAuditDetail("sshkey.added", "verified"))
	logins := e.events("VerifyKeyLogin")
	require.Len(t, logins, 1)
	assert.Equal(t, k.Fingerprint, logins[0].Fingerprint, "the login offered the new key only")
}

func TestDeployUnverifiedWithFrom(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse // Alice's address is not in from=
		}
		return fake.FaultNone
	})
	job, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: deployFile,
		From: "10.0.0.0/8"})
	require.NoError(t, err)
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusSucceeded, v.Status)
	assert.Equal(t, "unverified", v.Result["result"])
	assert.Equal(t, "from_option", v.Result["note"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint), "kept: Alice cannot know whether from= excludes her")
}

func TestDeployRefusedLoginIsUndone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	other := e.otherKeyLine(t)
	e.world.Put(srv, "deploy", deployFile, other)
	k := e.generate("ci")
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: deployFile})
	require.NoError(t, err)
	e.drain()
	v := e.job(job)
	assert.Equal(t, jobs.StatusFailed, v.Status)
	assert.Equal(t, "sshkey.login_failed", v.LastErrorCode)
	assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint), "Alice removed the key it had added")
	assert.Equal(t, []string{other}, e.world.Lines(srv, deployFile))
	assert.Equal(t, "sshkey.login_failed", e.lastAuditDetail("sshkey.add_failed", "reason"))
	assert.Equal(t, "ok", e.targetStatus(srv), "a refused test login never marks the server")
}

func TestDeployUncertainWriteResolvedByLogin(t *testing.T) {
	for _, loginWorks := range []bool{true, false} {
		e := newEnv(t)
		srv := e.server("web-01")
		k := e.generate("ci")
		e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
			switch {
			case p.Method == "AddAuthorizedKey":
				return fake.FaultAfterWrite // written, then the connection dropped
			case p.Method == "VerifyKeyLogin" && !loginWorks:
				return fake.FaultRefuse
			}
			return fake.FaultNone
		})
		job, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: deployFile})
		require.NoError(t, err)
		e.drain()
		v := e.job(job)
		if loginWorks {
			assert.Equal(t, "verified", v.Result["result"])
			assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint))
		} else {
			assert.False(t, e.world.Has(srv, deployFile, k.Fingerprint), "the uncertain line is removed by its fingerprint")
		}
		assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"), "an uncertain write is never re-sent blindly by the queue")
	}
}

func TestDeployAlreadyPresentIsNeverUndone(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.world.Put(srv, "deploy", deployFile, k.PublicKey+" "+k.Comment) // already there (added by hand)
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	job, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: deployFile})
	require.NoError(t, err)
	e.drain()
	assert.Equal(t, "already_present", e.job(job).Result["result"])
	assert.True(t, e.world.Has(srv, deployFile, k.Fingerprint), "Alice did not add it, so it never removes it")
	assert.Zero(t, e.countEvents("RemoveAuthorizedKey"))
}

func TestDeployUndoFailedNeedsAttention(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		switch p.Method {
		case "VerifyKeyLogin":
			return fake.FaultRefuse
		case "RemoveAuthorizedKey":
			return fake.FaultUnreachable
		}
		return fake.FaultNone
	})
	job, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: deployFile})
	require.NoError(t, err)
	e.drain()
	v := e.job(job)
	assert.Equal(t, "sshkey.add_undo_failed", v.LastErrorCode)
	assert.Equal(t, "undo_failed", v.Result["result"])
}

// L-81 with the deploy job: queued before the lock, held, confirmed after the renewal.
func TestDeployHeldInLockThenConfirmed(t *testing.T) {
	e := newEnv(t)
	srv := e.server("web-01")
	k := e.generate("ci")
	job, err := e.keys.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: deployFile})
	require.NoError(t, err)
	e.gate.lock()
	e.drain()
	assert.Equal(t, jobs.StatusBlocked, e.job(job).Status)
	assert.Empty(t, e.world.Events(), "no remote command in lock")
	e.gate.unlock()
	e.drain()
	assert.Equal(t, jobs.StatusBlocked, e.job(job).Status, "it does not run on its own after the renewal (R29)")
	require.NoError(t, e.queue.Confirm(e.ctx, e.adminAudit, e.adminID, job))
	e.drain()
	assert.Equal(t, jobs.StatusSucceeded, e.job(job).Status)
}
```

`sshkeyjobs_test.go` (unit): `TestRegisterPanicsWithoutDependencies` (each nil field of `Deps`), `TestClassifyAddFailure` (table over `definiteNoChange(wrote, res, err)`: no write started → definite; write started and `ssh.file_changed` → definite; write started and `ssh.timeout` → uncertain; `res.Changed` → uncertain).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/jobs/ && go test -tags integration ./internal/jobs/sshkeyjobs/`
Expected: FAIL — undefined: `jobs.SSHKeyAdd`; `no non-test Go files` in `sshkeyjobs`.

- [ ] **Step 3: Write the implementation**

`internal/jobs/types.go` (after the Phase 5 block):

```go
// Phase 6 job types (spec §8.2, §8.6, §13.4-§13.6; R41 rows 18-20). Deploying a generated key changes a
// server (refused and held in lock). A rotation's per-location work finishes in-flight operations and
// undoes the run's own additions in every state; its forward steps ask the gate themselves at every
// boundary (internal/jobs/sshkeyjobs, sshkeys.BeginAdd and BeginRemove). Planning previews is read-only
// work (no tick in lock: L-88); the sweep runs in every state to flag pauses (L-83); destroying retired
// private keys is a deletion, so it pauses in lock.
var (
	SSHKeyAdd            = Register(sshkeys.JobDeploy, license.ClassChange)
	RotationLocation     = Register(sshkeys.JobRotationLocation, license.ClassAlways)
	RotationPlan         = Register(sshkeys.TaskPlan, license.ClassReadOnly)
	RotationSweep        = Register(sshkeys.TaskSweep, license.ClassAlways)
	SSHKeyDestroyRetired = Register(sshkeys.TaskDestroyRetired, license.ClassReadOnly)
)
```

`MaxAttemptsFor`: unchanged default (3) covers both queue types. `AlertsWhenExhausted`: `return t.Name != inventory.JobDeployRecover && t.Name != inventory.JobKVPoll && t.Name != sshkeys.JobRotationLocation`.

`internal/jobs/sshkeyjobs/sshkeyjobs.go`: the package comment states the two properties this package enforces (no old-key removal except through `BeginRemove`; an undo removes only the new fingerprint), `Keys`, `Targets`, `Deps` and `Register` of C9; `open(ctx, targetID)` = `targetjobs.handlers.open` with `needConfirmed` true and a pooled connection (copy it; `targetjobs` is not imported); `recordFailure` and `close` likewise; `connectionReasons` copied from `targetjobs`; `definiteNoChange` as in the test.

`internal/jobs/sshkeyjobs/deploy.go`: the handler of C9's `sshkey.add` table, in this order: `DeployJob` (a `sshkeys` refusal → `jobs.Fail(reason)` after `FinishDeploy{failed}`), `open` (connection failure → `recordFailure`, `FinishDeploy{failed}`, `jobs.FromProvider`), `AddAuthorizedKey` with a `writeTracker`, the table's branches, `VerifyKeyLogin{OSUser, KeySigner(KeyID)}` (never `recordFailure` for its errors), the undo (`RemoveAuthorizedKey{Fingerprint: d.Fingerprint, ProtectedFingerprints: d.Protected}`) only when this job's write may have added the line (`res.Changed` or an uncertain write), `FinishDeploy`, and the job result map `{"result": out.Result, "note": out.Note, "line_no": out.LineNo, "ssh_key_id": d.KeyID}` (ids and public facts only).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race ./internal/jobs/... && go test -count=1 -race -tags integration ./internal/jobs/sshkeyjobs/` (testcontainers)
Expected: `ok`.

Run: `go test -count=1 -tags integration -coverprofile=/tmp/jobs.out ./internal/jobs/ && go tool cover -func=/tmp/jobs.out | tail -1`
Expected: total ≥ 89.2 % (floor 89; the registrations and the `AlertsWhenExhausted` branch are covered by `TestPhase6JobClasses`).

- [ ] **Step 5: Commit**

```bash
git add -- internal/jobs/sshkeyjobs
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(jobs): Phase 6 job types and the sshkey.add handler — add, test login, undo of a refused addition" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/jobs/types.go internal/jobs/stubjobs_test.go internal/jobs/sshkeyjobs \
  internal/jobs/types_test.go
```

(Name the registry test file actually edited if it is not `types_test.go`.)

---

### Task 11: Jobs: the `rotation.location` handler (add + verify, re-verify + remove, undo)

**Files:**
- Create: `internal/jobs/sshkeyjobs/location.go`
- Create: `internal/jobs/sshkeyjobs/location_integration_test.go`

**Interfaces:**
- Consumes: C7 runner-facing store (Task 9), C8, C9; Task 10's `open`, `close`, `recordFailure`, `definiteNoChange`, `writeTracker`.
- Produces: the handler of `jobs.RotationLocation` registered by `Register`.

The handler, in full (every remote call follows the store call that records it; every outcome is recorded before `Advance`):

```go
package sshkeyjobs

// location runs one phase of one rotation location (C9). It returns nil after recording an outcome;
// jobs.Retry only when the store failed before any remote call of this run.
func (h *handlers) location(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	locID, err1 := uuid.Parse(j.Payload["location_id"])
	runID, err2 := uuid.Parse(j.Payload["rotation_id"])
	if err := errors.Join(err1, err2); err != nil {
		return nil, jobs.Fail("rotation.not_waiting", nil, err)
	}
	actor := audit.Actor{Type: audit.ActorSystem, Name: "jobs", RequestID: j.ID.String()}
	w, err := h.d.Keys.LocationWork(ctx, locID)
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	if w.Rotation.ID != runID || w.Location.TargetID != j.TargetID {
		return nil, jobs.Fail("rotation.not_waiting", nil, nil) // a payload that names another run or server
	}
	var res map[string]any
	switch j.Payload["phase"] {
	case "add":
		res = h.addPhase(ctx, w, actor, steps)
	case "remove":
		res = h.removePhase(ctx, w, actor, steps)
	case "undo":
		res = h.undoPhase(ctx, w, actor, steps)
	default:
		return nil, jobs.Fail("rotation.not_waiting", nil, nil)
	}
	if err := h.d.Keys.Advance(ctx, runID); err != nil {
		h.d.Log.Warn("rotation could not advance; the sweep retries", "rotation_id", runID, "error_type", fmt.Sprintf("%T", err))
	}
	return res, nil
}

func (h *handlers) addPhase(ctx context.Context, w sshkeys.LocationWork, actor audit.Actor, steps jobs.StepRecorder) map[string]any {
	loc := w.Location
	if loc.State == "planned" {
		if _, err := h.d.Keys.BeginAdd(ctx, loc.ID); err != nil {
			return stopped(err) // ErrPaused or ErrNotYourTurn: nothing was sent; the controller decides
		}
	} else if loc.State != "adding" && loc.State != "added" {
		return map[string]any{"state": loc.State}
	}
	sess, err := h.open(ctx, loc.TargetID)
	if err != nil {
		h.recordFailure(ctx, loc.TargetID, err)
		if loc.State == "planned" { // BeginAdd just ran: nothing was sent
			h.finishAdd(ctx, loc.ID, sshkeys.AddRecord{Definite: true, Reason: reasonOf(err), Actor: actor})
		} else {
			h.recordVerify(ctx, loc.ID, sshkeys.VerifyRecord{Reason: reasonOf(err)}) // in flight and unreachable: failed
		}
		return map[string]any{"reason": reasonOf(err)}
	}
	defer h.close(sess)
	// Only a location this run just began is sent; a resumed "adding" (F-67: killed after the send) is
	// verified first, and verifyAfterAdd re-sends at most once, only when the login is refused.
	if loc.State == "planned" {
		if !h.sendAdd(ctx, sess, w, actor, steps) {
			return map[string]any{"state": "add_failed"}
		}
	}
	return h.verifyAfterAdd(ctx, sess, w, actor, steps)
}
```

(`reasonOf(err) string` here returns only the closed reason: a `*jobs.Failure`'s or `*providers.Error`'s code, else `internal.unexpected`.)

`sendAdd` calls `AddAuthorizedKey{OperationID: <the add op of BeginAdd, read back in LocationWork>, OSUser, FilePath, Line: w.NewLine, ProtectedFingerprints: w.Protected}` with a `writeTracker`; `definiteNoChange` → `FinishAdd{Definite: true, Added: false, Reason}` and returns false; success → `FinishAdd{Definite: true, Added: true, LineNo, Backup}`; uncertain → `FinishAdd{Definite: false}` (the state stays `adding`) and returns true (verification decides). `verifyAfterAdd`: when the plan said `Verify=false` → `RecordVerify{Outcome: KeyLoginUnprovable}` with the planned note; else `VerifyKeyLogin{OSUser, KeySigner(w.NewKeyID)}`; an error → `RecordVerify{Reason}`; `accepted`/`unprovable` → recorded; `refused` while the state is `adding` (uncertain add) → when `BeginAdd`'s gate allows (`sshkeys` exposes it through a second `sendAdd` that calls `AddAuthorizedKey` again with the same op id: the store accepts `FinishAdd` in `adding`), re-send once and verify once more; any other `refused` → `RecordVerify{Outcome: KeyLoginRefused}` (the store turns it into `unverifiable` when the options hold `from=`, else `verify_failed`).

`removePhase`: state `verified` or `removing` (else return the state); open; `VerifyKeyLogin` with the new key → `RecordReverify` (a refusal, an unprovable answer or an error ends the location `remove_failed` with `rotation.new_key_failed` inside the store; the handler returns); `BeginRemove` (stop on `ErrPaused`/`ErrNotYourTurn`/`ErrOwnKeyProtected`); `RemoveAuthorizedKey{OperationID: op, OSUser, FilePath, Fingerprint: w.OldFingerprint, ProtectedFingerprints: w.Protected, AllowLastRootKey: false}` with a `writeTracker`; `FinishRemove{Definite: definiteNoChange(...) || err == nil, Removed: res.Removed, Reason, Backup, Res: res}` — an uncertain removal stays `removing` (the next job re-verifies and re-sends).

`undoPhase`: any state with `add_sent_at` (the store refuses others); `BeginUndo`; open (a failure → `FinishUndo{Definite: true, Reason}`, `undo_failed`); `RemoveAuthorizedKey{OperationID: op, Fingerprint: w.NewFingerprint, ProtectedFingerprints: w.Protected, AllowLastRootKey: false}`; `FinishUndo{Definite: err == nil || definiteNoChange(...), Reason, Res}`; an uncertain undo is `undo_failed` too (it is never retried blindly; the sweep's re-queue bound applies).

`stopped(err)` returns `{"stopped": "paused"}` for `ErrPaused`, `{"stopped": "not_your_turn"}` otherwise.

- [ ] **Step 1: Write the failing tests**

`internal/jobs/sshkeyjobs/location_integration_test.go`:

```go
//go:build integration

package sshkeyjobs_test

// One rotation end to end through the real queue, three locations on two servers.
func TestRotationHappyPath(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy") // RecordKeyAdded + the line in the world
	e.place(k, web, "app")
	e.place(k, db, "deploy")
	p := e.policy(k.ID, 1) // overlap 1 day
	r := e.runNow(p)
	e.drain() // three location jobs: add + verify each
	r = e.run(r.ID)
	require.Equal(t, "overlap", r.Status)
	newFP := r.NewFingerprint
	for _, f := range e.files(k) { // every (target, file) of the old key
		assert.True(t, e.world.Has(f.target, f.path, k.Fingerprint), "the old key stays during the overlap")
		assert.True(t, e.world.Has(f.target, f.path, newFP))
	}
	e.clock.Advance(24*time.Hour - time.Second)
	e.sweep()
	e.drain()
	assert.Equal(t, "overlap", e.run(r.ID).Status, "nothing before the overlap ends")
	e.clock.Advance(time.Second)
	e.sweep()
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "completed", r.Status)
	for _, f := range e.files(k) {
		assert.False(t, e.world.Has(f.target, f.path, k.Fingerprint))
		assert.True(t, e.world.Has(f.target, f.path, newFP))
	}
	e.assertEveryRemovalFollowedAFreshLogin(t, k.Fingerprint, newFP) // invariant I1 of Task 12
	assert.Len(t, e.mails("rotation.completed"), 1)
}

func TestAddRefusedRollsBack(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "AddAuthorizedKey" && p.Target == db {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "aborted", r.Status)
	assert.Equal(t, "rotation.add_failed", r.ResultCode)
	for _, f := range e.files(k) {
		assert.True(t, e.world.Has(f.target, f.path, k.Fingerprint), "old key untouched everywhere")
		assert.False(t, e.world.Has(f.target, f.path, r.NewFingerprint), "new key removed where this run added it")
	}
	assert.Zero(t, e.removalsOf(k.Fingerprint))
}

func TestUnverifiableWaitsForDecision(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.placeWithOptions(k, web, "deploy", `from="10.0.0.0/8"`)
	e.place(k, web, "app")
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" && p.OSUser == "deploy" {
			return fake.FaultRefuse
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 0))
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "verifying_new", r.Status)
	assert.True(t, r.AwaitingDecision)
	assert.Len(t, e.mails("rotation.decision_needed"), 1)
	assert.Zero(t, e.removalsOf(k.Fingerprint), "no removal while a decision is open")
}

func TestReverifyFailureKeepsOld(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	r := e.runNow(e.policy(k.ID, 0))
	e.drain()
	require.Equal(t, "overlap", e.run(r.ID).Status)
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		if p.Method == "VerifyKeyLogin" {
			return fake.FaultRefuse // someone broke the new key during the overlap
		}
		return fake.FaultNone
	})
	e.sweep()
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "needs_attention", r.Status)
	assert.Equal(t, "rotation.remove_incomplete", r.ResultCode)
	assert.True(t, e.world.Has(web, "/home/deploy/.ssh/authorized_keys", k.Fingerprint), "the old key stays")
}

// Owner step 6: the network goes away in the middle of a rotation.
func TestOwnerStep6NetworkLoss(t *testing.T) {
	e := newEnv(t)
	web, db := e.server("web-01"), e.server("db-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	e.place(k, db, "deploy")
	added := 0
	e.world.SetFault(func(p fake.FaultPoint) fake.Fault {
		if p.Target == db && p.Method == "AddAuthorizedKey" {
			added++
			return fake.FaultAfterWrite // the line arrived, then the network went
		}
		if p.Target == db {
			return fake.FaultUnreachable
		}
		return fake.FaultNone
	})
	r := e.runNow(e.policy(k.ID, 7))
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "needs_attention", r.Status)
	assert.Equal(t, "rotation.undo_failed", r.ResultCode, "the new key stays on db-01 until it can be reached")
	assert.True(t, e.world.Has(db, "/home/deploy/.ssh/authorized_keys", k.Fingerprint))
	assert.True(t, e.world.Has(web, "/home/deploy/.ssh/authorized_keys", k.Fingerprint))
	assert.Equal(t, 1, added)
	assert.Len(t, e.mails("rotation.needs_attention"), 1)
}
```

Plus `TestNewKeyDeletedDuringOverlapKeepsOld` (the world deletes the new line during the overlap: the re-verify is refused, the old key stays, `needs_attention`), `TestHostKeyChangeMidRotationRemovesNothing` (the target turns `host_key_changed` during the overlap: the removal's `open` fails, `remove_failed`, old key kept; no `RemoveAuthorizedKey` event), `TestTargetDeletedMidRotation` (the target is deleted during the overlap: its location ends `remove_failed` with `system.not_found`, other servers complete), `TestUndoRemovesOnlyTheNewKey` (the event log of an aborted run holds `RemoveAuthorizedKey` events only for the new fingerprint).

Harness additions: `e.place(k, target, user)`, `e.placeWithOptions`, `e.policy(keyID, overlapDays)`, `e.runNow(p)`, `e.run(id)`, `e.sweep()` (`keys.Sweep`), `e.files(k) []fileRef`, `e.removalsOf(fp) int` (world events of `RemoveAuthorizedKey` with that fingerprint and `Changed`), `e.mails(template)`, `e.assertEveryRemovalFollowedAFreshLogin(t, oldFP, newFP)` (Task 12's invariant I1 as a helper here, so both tasks use one implementation).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -tags integration -run 'TestRotation|TestAddRefused|TestUnverifiable|TestReverify|TestOwnerStep6|TestNewKeyDeleted|TestHostKeyChange|TestTargetDeleted|TestUndoRemoves' ./internal/jobs/sshkeyjobs/`
Expected: FAIL — the `rotation.location` jobs stay queued (`Register` handles only `sshkey.add`).

- [ ] **Step 3: Write the implementation**

`location.go` as above; `Register` adds `r.Handle(jobs.RotationLocation, h.location)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run (testcontainers): `go test -count=1 -race -tags integration ./internal/jobs/sshkeyjobs/`
Expected: `ok`.

- [ ] **Step 5: Commit**

```bash
git add -- internal/jobs/sshkeyjobs/location.go internal/jobs/sshkeyjobs/location_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(jobs): rotation.location — add and verify, re-verify and remove, undo of the run's own additions" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/jobs/sshkeyjobs
```

---

### Task 12: Jobs: property test under fault injection, F-67 and kills at every point, L-81 and L-83..L-88, F-36..F-39 at rotation level

**Files:**
- Create: `internal/jobs/sshkeyjobs/property_integration_test.go`, `internal/jobs/sshkeyjobs/crash_integration_test.go`, `internal/jobs/sshkeyjobs/lock_integration_test.go`, `internal/jobs/sshkeyjobs/failures_integration_test.go`
- Modify: `internal/jobs/stubjobs_test.go` (comment only, if not done in Task 10)

**Interfaces:**
- Consumes: everything of Tasks 9–11; `fake.KeyWorld` faults; the `killer`; `jobs.Scheduler` with `RotationPlan`/`RotationSweep` tasks for L-88.
- Produces: tests only. Any product defect they find is fixed in the package that owns it (`sshkeys` or `sshkeyjobs`) by this task's implementer, with the fix in its own commit.

**The invariants** (helpers in `property_integration_test.go`, used by every test of this task):

- **I1 (old key):** for every world event `RemoveAuthorizedKey` with `Changed` of the old fingerprint in `(target, file)`, and for every user `u` that has a rotation location in that `(target, file)`: an earlier event `VerifyKeyLogin` of `u` on `target` with the new fingerprint and outcome `accepted` exists, and no `AddAuthorizedKey` or `RemoveAuthorizedKey` event of that `(target, file)` lies between that login and the removal.
- **I2 (own key):** no event removes the platform fingerprint (the platform key's line is in every world file of the connection account) or any line whose key is neither the old nor the new key; every file's lines that hold neither key are byte-equal to the start.
- **I3 (undo):** every `RemoveAuthorizedKey` with `Changed` of the new fingerprint happened in a `(target, file)` where an `AddAuthorizedKey` of the new fingerprint happened earlier in the run.
- **I4 (end state):** after the system settles, the run is `completed`, `aborted`, `needs_attention`, `cancelled`, or paused (`paused_license`) in a non-terminal status; for every location of the old key, the old key is in its file unless that location is `removed`; when the run is not `completed`, every location whose old key was removed has I1's verification.
- **I5 (records):** every location's recorded state matches the world: `removed` ⇒ the old key is not in the file; `undone` ⇒ the new key is not in the file; `undo_failed` and `needs_attention` runs name every file that still holds the new key.

**Settling** (`e.settle(t)`): up to 200 rounds of: `drain()`; when the run is paused and the license gate is open, `Continue` as the Administrator; `sweep()`; advance the clock by 1 hour (crossing every overlap and decision deadline of the scenarios within 30 rounds); stop when the run is terminal and no job is queued, or paused with the gate locked.

Harness additions for this task (in `harness_integration_test.go`): `e.setKiller(k *killer)` (installs the killer in the `killKeys` wrapper and the provider wrapper; `nil` removes it), `e.drainDying()` (runs `runner.RunOnce` in a goroutine and returns when it returned or the killer fired, as `deployjobs`' `runDying`), `e.loginsWith(fp) int` (world `VerifyKeyLogin` events offering that key).

- [ ] **Step 1: Write the failing tests**

`internal/jobs/sshkeyjobs/property_integration_test.go`:

```go
//go:build integration

package sshkeyjobs_test

// §26.8 exit criterion: for any failure injected at any step, the old key remains wherever the new
// key was not freshly verified. The scenario is fixed (two servers, three locations, one of them a
// shared file of two users, overlap 1 hour); the fault space is every (call index × fault kind) of
// the fault-free run, plus a license lock and a process kill at every call index.
func TestOldKeyRemainsUnderAnyInjectedFailure(t *testing.T) {
	baseline := runScenario(t, nil, scenarioOpts{})
	require.Equal(t, "completed", baseline.status, "the fault-free run completes")
	calls := baseline.calls // the number of world calls (Add, Remove, VerifyKeyLogin) of the fault-free run
	require.Greater(t, calls, 8)
	kinds := []fake.Fault{fake.FaultRefuse, fake.FaultUnreachable, fake.FaultAfterWrite, fake.FaultFileChanged, fake.FaultUnprovable, fake.FaultHang}
	for n := 1; n <= calls; n++ {
		for _, kind := range kinds {
			t.Run(fmt.Sprintf("call%02d/%v", n, kind), func(t *testing.T) {
				res := runScenario(t, faultAt(n, kind), scenarioOpts{})
				res.assertInvariants(t)
			})
		}
		t.Run(fmt.Sprintf("call%02d/lock", n), func(t *testing.T) {
			res := runScenario(t, nil, scenarioOpts{lockAtCall: n, renewAfter: 20 * 24 * time.Hour})
			res.assertInvariants(t)
		})
		t.Run(fmt.Sprintf("call%02d/kill", n), func(t *testing.T) {
			res := runScenario(t, nil, scenarioOpts{killAtCall: n})
			res.assertInvariants(t)
		})
	}
}

// faultAt injects kind at the n-th world call only (a FaultUnprovable on an add or remove is
// meaningless and is mapped to FaultNone by the world's own switch).
func faultAt(n int, kind fake.Fault) func(fake.FaultPoint) fake.Fault {
	return func(p fake.FaultPoint) fake.Fault {
		if p.N == n {
			return kind
		}
		return fake.FaultNone
	}
}
```

`runScenario(t, fault, opts) scenarioResult` builds a fresh `newEnv(t)` (its own database), places the old key at `web-01:deploy` (own file), `web-01:{deploy2,backup}` (one shared file `/etc/ssh/keys/shared`), `db-01:deploy`, puts the platform key's line in each server's `alice-svc` file in the world, creates a policy (overlap 60 minutes), installs `fault`, runs `RunNow` and `settle`; `opts.lockAtCall` locks the gate from inside the fault hook at that call (the call itself proceeds) and unlocks it after `opts.renewAfter` of clock during settling (then `Continue` is pressed by `settle`); `opts.killAtCall` makes the provider wrapper `runtime.Goexit` the job right after that world call returned, then `e.restart()` once, then settles. `scenarioResult` keeps the world's events, the files at start and end, the run and its locations, and implements `assertInvariants` (I1–I5).

`internal/jobs/sshkeyjobs/crash_integration_test.go`:

```go
//go:build integration

package sshkeyjobs_test

// F-67: Alice is killed between "add new key" and "verify". On restart the runner verifies the new
// key, the old key remains, and the run resumes from the last recorded step; nothing is removed by
// the recovery without a passing verification.
func TestF67KillBetweenAddAndVerify(t *testing.T) {
	e := newEnv(t)
	web := e.server("web-01")
	k := e.generate("ci")
	e.place(k, web, "deploy")
	kill := newKiller("session:after:AddAuthorizedKey")
	e.setKiller(kill)
	r := e.runNow(e.policy(k.ID, 1))
	e.drainDying()
	require.Equal(t, "session:after:AddAuthorizedKey", kill.firedAt())
	loc := e.run(r.ID).Locations[0]
	assert.Equal(t, "adding", loc.State, "the add was recorded as sent, its outcome not yet")
	assert.True(t, e.world.Has(web, "/home/deploy/.ssh/authorized_keys", k.Fingerprint))
	e.setKiller(nil)
	e.restart()
	e.drain()
	r = e.run(r.ID)
	assert.Equal(t, "overlap", r.Status, "the run resumed and verified")
	assert.Equal(t, 1, e.countEvents("AddAuthorizedKey"), "the recovery verified instead of adding again")
	assert.Equal(t, 1, e.loginsWith(r.NewFingerprint))
	assert.True(t, e.world.Has(web, "/home/deploy/.ssh/authorized_keys", k.Fingerprint), "the old key remains")
	assert.Zero(t, e.removalsOf(k.Fingerprint))
	assert.Equal(t, 1, e.audits("job.recovered"))
}

// Every point the engine records or calls: before and after each store method and each provider call.
func TestKillAtEveryRecordedPoint(t *testing.T) {
	points := []string{
		"before:BeginAdd", "after:BeginAdd", "session:after:AddAuthorizedKey", "before:FinishAdd", "after:FinishAdd",
		"session:after:VerifyKeyLogin", "before:RecordVerify", "after:RecordVerify", "before:Advance", "after:Advance",
		"before:RecordReverify", "after:RecordReverify", "before:BeginRemove", "after:BeginRemove",
		"session:after:RemoveAuthorizedKey", "before:FinishRemove", "after:FinishRemove",
		"before:BeginUndo", "after:BeginUndo", "before:FinishUndo", "after:FinishUndo",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			res := runScenario(t, undoNeededFor(point), scenarioOpts{killAt: point})
			res.assertInvariants(t)
		})
	}
}
```

(`undoNeededFor(point)` returns a fault that makes the db-01 login refused for the undo points, so those points are reached; `nil` otherwise.)

`internal/jobs/sshkeyjobs/lock_integration_test.go`:

- `TestL83OverlapLockRemovesNothing`: run in `overlap` with 4 days left; lock; the clock passes the overlap end; sweeps and drains for 5 days of clock: status `overlap`, `paused_license`, no `RemoveAuthorizedKey` event, both keys present, one `rotation.paused_license` email.
- `TestL84RenewalAfterTwentyDays`: from L-83's state, 20 days of lock; unlock (renewal); sweeps and drains: still paused, nothing removed (R29); `Continue` as the Administrator: one `rotation.preview_after_license` email; drain: for every location a `VerifyKeyLogin` with the new key **before** its `RemoveAuthorizedKey`, in the event log (I1), and the run `completed`.
- `TestL85AddInFlightAtLock`: the gate locks inside the first `AddAuthorizedKey` (fault hook): that add completes, its `VerifyKeyLogin` runs, the location is `verified`; no further `AddAuthorizedKey`, no `RemoveAuthorizedKey`; the run `adding_new` with `paused_license`.
- `TestL86VerifyFailsDuringLock`: the gate locks inside the first add; the following login is refused: the run goes `rolling_back` in lock, the undo removes the new key from that file only (the only place this run added it), the old key is untouched everywhere, the run `aborted` with `rotation.verify_failed`, audit `rotation.status_changed` rows.
- `TestL88LockAtPreviewTime`: a real `jobs.Scheduler` with the `rotation.plan` task (and the license gate) at the instant the preview is due, locked at that instant: the tick does not run (`ClassReadOnly`), no `rotations` row, no `rotation.preview` email, nothing else changes (row counts of every Phase 6 table equal); after unlock the next tick previews.
- `TestL81DeployHeldInLock` is Task 10's `TestDeployHeldInLockThenConfirmed` (referenced, not repeated).
- `TestNoRemoteCommandFromScheduledWorkInLock` (L-29 for rotation): lock; run the plan, sweep and destroy tasks through the scheduler for 3 days of clock: the world's event log stays empty, nothing is deleted (`managed_private_keys` envelope count unchanged).

`internal/jobs/sshkeyjobs/failures_integration_test.go`:

- `TestF36OwnKeyNeverRotated`: the platform key's ssh_keys row cannot get a policy (Task 8's refusal), and a forged `rotation.location` job naming a location of the platform key (inserted with a valid MAC through the queue, payload pointing at a `rotation_locations` row seeded by the owner pool with the platform fingerprint as old key) reaches no `RemoveAuthorizedKey` of the platform fingerprint: `BeginRemove` answers `ErrOwnKeyProtected`, the database trigger `Z1011` holds even when the store is bypassed, and the world's own refusal is the third layer.
- `TestF37RotationIntoFileWithoutNewline`: with `newRealEnv(t)` — the same harness with the real `linuxssh` provider over a `linuxsshtest` server and emulator instead of the fake world (built as `targetjobs`' integration harness builds it; one server, `SetLoginCheck(emu.AcceptsLogin)`): the deploy user's file has no trailing newline; the rotation adds the new key on its own line; the earlier lines are byte-equal.
- `TestF38RotationFileChangedBetweenReadAndWrite`: same real-provider setup; `emu.BeforeWrite` changes the file once before Alice's write: the add is retried (CAS) and succeeds; when it changes before every write (3 attempts), the location ends `add_failed` (`ssh.file_changed`) and the run is undone with the old key untouched.
- `TestF39SlowHostDuringRotation`: the world's `FaultHang` on the second location's add with the job context's deadline: the job ends with the location `adding` (uncertain), the session closed (`Close` call recorded), and the sweep's next job verifies it (no blind re-send); the run never removes anything during this.

- [ ] **Step 2: Run the tests to verify they fail (or reveal defects)**

Run (testcontainers): `go test -count=1 -tags integration -run 'TestOldKeyRemains|TestF67|TestKillAtEvery|TestL8|TestNoRemoteCommand|TestF3' ./internal/jobs/sshkeyjobs/`
Expected: the new tests compile and run; any failure is a defect of Tasks 9–11 — fix it in the owning file with a test-first commit, then re-run.

- [ ] **Step 3: Fix what the tests reveal**

No code is planned here beyond the tests: every fix goes into `internal/sshkeys` or `internal/jobs/sshkeyjobs` with a commit message naming the failing subtest (for example `fix(sshkeys): BeginRemove refuses a shared file with an undecided user (TestOldKeyRemains…/call07/FaultRefuse)`).

- [ ] **Step 4: Run the tests to verify they pass**

Run (testcontainers): `go test -count=1 -race -tags integration ./internal/jobs/sshkeyjobs/`
Expected: `ok` (the property test runs roughly 200 scenarios, each on its own database; budget under 5 minutes; if it exceeds 10 minutes, share one database between scenarios by truncating the Phase 6 tables and the job queue between them instead of `pgtest.New`).

Run: `go test -count=1 -tags integration -coverprofile=/tmp/skj.out ./internal/jobs/sshkeyjobs/ && go tool cover -func=/tmp/skj.out | tail -1`
Expected: a total recorded in the report (floor set in Task 19).

- [ ] **Step 5: Commit**

```bash
git add -- internal/jobs/sshkeyjobs/property_integration_test.go internal/jobs/sshkeyjobs/crash_integration_test.go \
  internal/jobs/sshkeyjobs/lock_integration_test.go internal/jobs/sshkeyjobs/failures_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(jobs): old-key property under fault injection, kills at every point (F-67), L-83..L-88, F-36..F-39 for rotation" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/jobs/sshkeyjobs
```

---

### Task 13: API: permissions, routes, DTOs, the download handler and its limiter, error codes and texts, emails' texts, OpenAPI, authz matrix

**Files:**
- Modify: `internal/rbac/rbac.go`, `internal/rbac/rbac_test.go`
- Modify: `internal/api/server.go` (`Deps.SSHKeys`, `SSHKeysService`, `limitDownload`, `s.download` limiter, `apiRoutes` + `rotationRoutes`), `internal/api/guard.go` (`allowRate` case), `internal/api/errors.go` (codes of C11, `errorMap` entries for `sshkeys` and `plan` errors, `codeForReason` of every rotation result reason)
- Modify: `internal/api/sshkeys_handlers.go` (generate, deploy, download, key files; `getSSHKey` adds `managed_key`)
- Create: `internal/api/rotation_handlers.go`, `internal/api/rotation_dto.go`
- Modify: `internal/api/jobs_handlers.go` (`ssh_key_id`, `rotation_id` on job items)
- Modify: `internal/api/fakes_test.go` (a `fakeSSHKeys`), Create: `internal/api/sshkeys_phase6_test.go`, `internal/api/rotation_handlers_test.go`
- Modify: `api/openapi.yaml` (operations and schemas of C13; the sentence on `PATCH /bindings/{id}`'s 412), `docs/authz-matrix.md` (`make authz-doc`)
- Modify: `locales/common/en.json`, `locales/common/tr.json` (errors of C11; `email.rotation.*` of C10), `internal/notify/render_test.go` (renders every `sshkeys.Templates()` in both languages)
- Modify: `docs/troubleshooting.md` (one section per new code, the format of the `ALC-KEY-0005` section; the test `errors_catalogue_test.go` checks them)

**Interfaces:**
- Consumes: C7 (the whole `sshkeys` API), C11, C13, C10; `rbac.Decide`; `secretText`; `inventory.Actor` via `s.actor(r)`; `etag`/`ifMatch`.
- Produces: routes and DTOs of C13; `rbac.SSHKeysDownload`, `rbac.RotationManage`, `rbac.RotationOperate`; error codes; locale texts; OpenAPI.

```go
// internal/api/server.go
// SSHKeysService is *sshkeys.Service.
type SSHKeysService interface {
	Generate(ctx context.Context, a inventory.Actor, in sshkeys.GenerateInput) (sshkeys.ManagedKey, error)
	ManagedKey(ctx context.Context, id uuid.UUID) (sshkeys.ManagedKey, error)
	RequestDeploy(ctx context.Context, a inventory.Actor, in sshkeys.DeployInput) (uuid.UUID, error)
	DownloadPrivateKey(ctx context.Context, a inventory.Actor, in sshkeys.DownloadInput) (sshkeys.Download, error)
	CreatePolicy(ctx context.Context, a inventory.Actor, in sshkeys.PolicyInput) (sshkeys.Policy, error)
	UpdatePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, p sshkeys.PolicyPatch) (sshkeys.Policy, error)
	SetPolicyEnabled(ctx context.Context, a inventory.Actor, id uuid.UUID, version int, enabled bool) (sshkeys.Policy, error)
	DeletePolicy(ctx context.Context, a inventory.Actor, id uuid.UUID, version int) error
	Policy(ctx context.Context, id uuid.UUID) (sshkeys.Policy, error)
	Policies(ctx context.Context) ([]sshkeys.Policy, error)
	Preview(ctx context.Context, a inventory.Actor, id uuid.UUID) (sshkeys.Preview, error)
	RunNow(ctx context.Context, a inventory.Actor, id uuid.UUID, digest string) (sshkeys.Rotation, error)
	Rotation(ctx context.Context, id uuid.UUID) (sshkeys.Rotation, error)
	Rotations(ctx context.Context, f sshkeys.RotationFilter) ([]sshkeys.Rotation, string, error)
	Continue(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	FinishNow(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	KeepOld(ctx context.Context, a inventory.Actor, id uuid.UUID, locations []uuid.UUID) error
	Abort(ctx context.Context, a inventory.Actor, id uuid.UUID) error
}
```

`rbac.go` (Phase 6 block after `CredentialsManage`):

```go
	// Phase 6 (R41 rows 5, 24; §15.4, SEC-009, SEC-045, R23). The private key download: Administrator in a
	// browser session with step-up, never an API token. Rotation policies: Administrators prepare, change,
	// preview and stop them (operate tokens allowed); starting changes on servers — switching a policy on,
	// Run now, Continue after a renewal, Finish now, Keep the old key — needs a step-up session.
	SSHKeysDownload Permission = "sshkeys.download"
	RotationManage  Permission = "rotation.manage"
	RotationOperate Permission = "rotation.operate"
```

and in `policies`: `SSHKeysDownload: {Roles: []Role{Admin}, StepUp: true}`, `RotationManage: {Roles: []Role{Admin}, TokenScope: ScopeOperate}`, `RotationOperate: {Roles: []Role{Admin}, StepUp: true}`.

The download handler (the only route that may answer a private key, S-02):

```go
// downloadPrivateKey answers the OpenSSH file of a generated key (S-09). The service commits the audit
// row and the counter before it returns the file; only then is the first byte written. The body's
// passphrase is a secretText this handler zeroes on every path; the file is zeroed after the write.
func (s *server) downloadPrivateKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	var req struct {
		Reason     string     `json:"reason"`
		Passphrase secretText `json:"passphrase"`
	}
	defer func() { req.Passphrase.zero() }()
	if !s.decodeExact(w, r, &req, maxActionBody, "reason", "passphrase") {
		return
	}
	var pass []byte
	if req.Passphrase != nil {
		pass = req.Passphrase
	}
	dl, err := s.deps.SSHKeys.DownloadPrivateKey(r.Context(), s.actor(r), sshkeys.DownloadInput{KeyID: id, Reason: req.Reason, Passphrase: pass})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer dl.Body.Zero()
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+dl.FileName+`"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(dl.Body.Bytes())))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dl.Body.Bytes()) // a failed write after the audit row is recorded as downloaded (S-09: audit first)
}
```

(A passphrase given as `""` decodes to an empty, non-nil `secretText`: the service refuses it as too short, so an empty field never silently means "unencrypted"; `null` or an absent key means unencrypted.)

`errors.go`: the codes of C11 as `ErrorCode` values beside their areas; `errorMap` maps `sshkeys.ErrNotManaged` → `ALC-KEY-0006`, `ErrRetired` → `0007`, `ErrDestroyed` → `0008`, `ErrConnectionAccount` → `0009`, `ErrGenerateBusy` → `0011`, `ErrNotAKeyFile` → `0013`, `ErrPolicyExists` → `ALC-ROT-0001`, `ErrRotationInProgress` → `0002`, `ErrPlanChanged` → `0003`, `ErrNothingToRotate` → `0004`, `ErrNotWaiting` → `0005`, `ErrVersionMismatch` → the existing 412 code, `ErrOwnKeyProtected` → `ALC-KEY-0001`; `codeForReason` knows every reason of C11 (rotation `result_code`s and location `error_code`s are rendered as their ALC codes in the DTOs). The download route's 409/410/422/403 answers go through the usual error writer (JSON, never a file).

`api/openapi.yaml`: every operation of C13 with its `x-permission`, request schemas (`additionalProperties: false`; `passphrase` with `writeOnly: true`, `minLength: 12`, `maxLength: 1024`; `reason` `minLength: 10`, `maxLength: 500`), responses (the download's `200` with `content: application/octet-stream: schema: {type: string, format: binary}` and the headers), and the schemas `GeneratedKey`, `ManagedKeyInfo`, `KeyFiles`, `RotationPolicy`, `RotationPreview`, `RotationRun`; S-08: no response schema has a property named `private_key`, `passphrase` or `secret` (the download's response is a binary body without properties). On `PATCH /api/v1/bindings/{id}` (Phase 5 carry 8), replace the two sentences that begin "412 ALC-SYS-0008 when the If-Match header is missing" with: "412 ALC-SYS-0008 when the If-Match header is missing (answered first, before the body is read) or names another version than the connection's current one (compared after the request is read (400, 413, 422) and the connection is found (404), and before anything about the change is judged)." — the handler checks `ifMatch(r)` before decoding (`bindings_handlers.go`), which the old sentence contradicted.

- [ ] **Step 1: Write the failing tests**

`internal/rbac/rbac_test.go`:

```go
func TestPhase6Policies(t *testing.T) {
	admin := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin}
	adminUp := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin, StepUp: true}
	op := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Operator, StepUp: true}
	aud := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Auditor, StepUp: true}
	adminTok := rbac.Subject{Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeOperate}
	adminRead := rbac.Subject{Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeRead}
	cases := []struct {
		p    rbac.Permission
		s    rbac.Subject
		want rbac.Decision
	}{
		{rbac.SSHKeysDownload, adminUp, rbac.Allow},
		{rbac.SSHKeysDownload, admin, rbac.DenyStepUp},
		{rbac.SSHKeysDownload, op, rbac.DenyForbidden},
		{rbac.SSHKeysDownload, adminTok, rbac.DenyForbidden}, // R23, A-09: no token retrieves a private key
		{rbac.RotationManage, admin, rbac.Allow},
		{rbac.RotationManage, adminTok, rbac.Allow},
		{rbac.RotationManage, adminRead, rbac.DenyForbidden},
		{rbac.RotationManage, op, rbac.DenyForbidden},
		{rbac.RotationManage, aud, rbac.DenyForbidden},
		{rbac.RotationOperate, adminUp, rbac.Allow},
		{rbac.RotationOperate, admin, rbac.DenyStepUp},
		{rbac.RotationOperate, adminTok, rbac.DenyForbidden},
		{rbac.RotationOperate, op, rbac.DenyForbidden},
		{rbac.InventoryOperate, op, rbac.Allow}, // generate and deploy
		{rbac.InventoryOperate, aud, rbac.DenyForbidden},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, rbac.Decide(c.p, c.s), "%s %+v", c.p, c.s)
	}
}
```

`internal/api/rotation_handlers_test.go` and `sshkeys_phase6_test.go` (unit, with `fakeSSHKeys` recording calls and returning scripted values; the server built as the package's other handler tests build it):

- `TestRotationRoutesAuthz`: for every route of C13 under `/rotation/` and the three key routes, the decision per identity (anonymous 401; Operator 403 and the `*.denied` audit row; Auditor 403; Administrator token `operate` allowed only on `rotation.manage` and `inventory.operate` routes; `read` token only on GETs; Administrator session without step-up 403 `ALC-AUTH-0003` on `rotation.operate` and `sshkeys.download`; with step-up allowed) — and the fake service saw no call for any refused request (no side effect).
- `TestDownloadNeedsSessionAdminStepUp`: the download route answers 403 for an Administrator `operate` token (and the fake saw no call), 403 `ALC-AUTH-0003` without step-up, 200 with step-up; the 200 has `Content-Type: application/octet-stream`, `Cache-Control: no-store`, `Content-Disposition: attachment; filename="alice-ci-…key"`, `X-Content-Type-Options: nosniff`, and the body the fake returned; the sixth download within a minute by the same user answers 429 with `Retry-After`.
- `TestDownloadZeroesThePassphrase`: with `onSecretBytes` capturing the passphrase slice, after the handler returns (success and each failure path: validation, `ErrNotManaged`) the slice is all zero.
- `TestDownloadErrorsAreJSON`: `ErrNotManaged` → 409 `ALC-KEY-0006` JSON; `ErrDestroyed` → 410 `ALC-KEY-0008`; a validation error → 422 with field `reason`; none has `Content-Disposition`.
- `TestGenerateAndDeployHandlers`: body validation (unknown key → 400; `key_type` outside the four → 422), 201 with the `SSHKey` DTO incl. `managed_key`; deploy → 202 with `job_id` and `status_url`; refused in lock (route class `change`) with 403 `ALC-LIC-0001` and no call.
- `TestPolicyHandlers`: create 201 with `ETag: "1"`; `PATCH` without `If-Match` → the existing missing-`If-Match` answer; with a stale `If-Match` → 412; `DELETE` likewise; enable/disable carry `If-Match`.
- `TestPreviewAndRunHandlers`: preview DTO fields of C13; run with a malformed `plan_digest` → 422; `ErrPlanChanged` → 409 `ALC-ROT-0003`; success → 202 with `rotation_id`, `status_url`.
- `TestRunDTOActionsAllowed`: `actions_allowed` follows `sshkeys.AllowedActions` with the gate's answer.
- `TestKeyFilesHandler`: `facts.key_files` rendered with `default_file` = the first file; the connection account left out; `scanned_at` from `last_discovery_at`.
- `TestJobItemsCarrySSHKeyAndRotationIDs`.

`internal/api/errors_test.go` and `errors_catalogue_test.go` already iterate `AllErrorCodes()`: they fail until the texts and troubleshooting sections exist (the expected red).

`internal/notify/render_test.go`: `TestRotationTemplatesRender` renders every `sshkeys.Templates()` in `en` and `tr` with the parameters of C10 and asserts no `{{` remains and the subject has no line break.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/rbac/ ./internal/api/ ./internal/notify/`
Expected: FAIL — undefined `rbac.SSHKeysDownload`; routes 404; missing locale keys and troubleshooting sections.

- [ ] **Step 3: Write the implementation**

Implement the handlers per C13 (each one: `decodeExact` with its key list, validation into `validate.Errors`, the service call, `s.fail` for errors, `writeJSON` with the DTO), the DTO builders in `rotation_dto.go` (times UTC; `result_code` and `error_code` via `codeForReason`; `actions_allowed` from `sshkeys.AllowedActions(r, s.deps.License.Allow(license.ClassChange) == nil)`), the rate limiter (`download: ratelimit.New(5, time.Minute)` built like `mfa`; `allowRate`'s `case limitDownload:` keyed `"u:" + p.UserID.String()`; `server.reset` for tests resets it too), the locale texts (exactly C10 and C11; the TR texts as given), the troubleshooting sections (title = C11 EN title; **Meaning**, **Likely cause**, **What to do** from the EN title/cause/action, expanded to the section style of `ALC-KEY-0005`), OpenAPI, then `make authz-doc`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race ./internal/rbac/ ./internal/api/ ./internal/notify/ && make authz-doc && git diff --exit-code docs/authz-matrix.md || true`
Expected: `ok`; `docs/authz-matrix.md` regenerated with the new routes (commit it).

Run: `make i18n-check && make lint`
Expected: both pass.

- [ ] **Step 5: Commit**

```bash
git add -- internal/api/rotation_handlers.go internal/api/rotation_dto.go internal/api/rotation_handlers_test.go internal/api/sshkeys_phase6_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(api): key generation, deploy, audited private key download, rotation policies and runs; ALC-KEY/ROT codes" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/rbac internal/api internal/notify/render_test.go \
  api/openapi.yaml docs/authz-matrix.md docs/troubleshooting.md locales/common/en.json locales/common/tr.json
```

---

### Task 14: API integration: journeys over the emulator, S-09, the secret-leak suite with generated keys, dry run equals run, lock (L-29), F-36

**Files:**
- Create: `internal/api/sshkeys_integration_test.go`, `internal/api/rotation_integration_test.go`, `internal/api/sshkeys_leak_integration_test.go`
- Modify: the API integration harness (`internal/api/stack_integration_test.go` or the file that builds the full stack for `targets_integration_test.go`): wire `sshkeys.Service`, `sshkeyjobs.Register`, the `linuxsshtest` emulator with `SetLoginCheck(emu.AcceptsLogin)`

**Interfaces:**
- Consumes: the whole stack of Tasks 3–13.
- Produces: tests only (defects found are fixed in the owning package by this task's implementer, each in its own commit).

- [ ] **Step 1: Write the tests**

`internal/api/sshkeys_integration_test.go`:

- `TestOwnerSteps1And2OverTheWire` (§26.8 owner steps 1–2): sign in as the Administrator; add and confirm a server whose emulator has user `deploy`; discovery; `POST /ssh-keys/generate` (`ed25519`); `GET /targets/{id}/key-files` offers `/home/deploy/.ssh/authorized_keys` and not `alice-svc`; `POST /ssh-keys/{id}/actions/deploy`; run the jobs; `GET /jobs/{job}` → `succeeded`, `result.result` = `verified`; the emulator's file holds the new line; `POST …/download-private-key` without step-up → 403 `ALC-AUTH-0003`; after `POST /auth/stepup` → 200 file; `GET /audit` lists `sshkey.private_key_downloaded` with the reason.
- `TestS09PrivateKeyDownload` (S-09 exactly): (a) Operator session with step-up → 403, Auditor → 403, Administrator `operate` token → 403, Administrator session without step-up → 403; each refusal audited (`*.denied` per R39 item 4) and no `sshkey.private_key_downloaded` row; (b) an empty reason → 422; (c) a successful download: the audit row was committed **before** the response was sent — the test's `http.Client` uses a `RoundTripper` whose response body reader, on its first read, queries `audit_log` through the owner pool and records whether the row exists (it must); (d) the response has `Cache-Control: no-store`; (e) a second download is audited too (two rows, `download_count` 1 and 2).
- `TestF36OwnKeyNeverRotatedOrDownloaded` (F-36 over the API): the platform key's `ssh_keys` row (same key under another comment in `deploy`'s file, as Phase 3's F-36 test seeds it): `POST /rotation/policies` → 409 `ALC-KEY-0001`, audit `rotation.policy.denied` reason `own_key`; download → 409 `ALC-KEY-0006`, audit denied `own_key`; deploy → 409 `ALC-KEY-0006`; the emulator's command log has no `authkeys-write`.
- `TestF37DeployIntoFileWithoutNewline`: deploy into a file without a trailing newline: the new key on its own line, the other lines byte-equal.

`internal/api/rotation_integration_test.go`:

- `TestOwnerSteps3To5OverTheWire`: create a policy (`interval_days` 90, `overlap_days` 7) → `enabled: false`; `POST …/preview` → the actions name the server, user and file with `remove_line` and `add_line`; an email row `rotation.preview` in the outbox; `POST …/run` with `plan_digest` → 202; run the jobs; `GET /rotation/runs/{id}` → `overlap`, both keys in the emulator's file; advance the clock 7 days, run the sweep and the jobs → `completed`, the old key gone, the new one present; audit rows `rotation.status_changed` for every transition.
- `TestDryRunEqualsActualPlan`: preview; run with its digest; the run's `locations` equal the preview's `actions` one to one (location id, server, user, file, options, skip reason, verification); then a second key whose preview is taken, a server added to its locations, and a run with the old digest → 409 `ALC-ROT-0003`, no run created.
- `TestRotationInLockRunsNoCommand` (L-29 for rotation): a run in `overlap`; the license locks (test license expired, `Tick`); every Phase 6 route that changes something answers 403 `ALC-LIC-0001` except the download (class `always`, R41 row 5); the scheduler's `rotation.plan`, `rotation.sweep` and `sshkey.destroy_retired` run for 3 days of clock; the emulator's command log gains no command; no row of `ssh_keys`, `managed_private_keys`, `ssh_key_locations` or `rotation_*` is deleted; the run is `paused_license`.
- `TestContinueAfterRenewalOverTheWire` (L-84 over the wire): from the previous state, a renewal (new test license, `Tick`); `actions_allowed` = `["continue"]`; `POST …/continue` without step-up → 403; with step-up → 204; jobs and sweep → `completed`; the outbox has one `rotation.preview_after_license`.

`internal/api/sshkeys_leak_integration_test.go` — `TestSecretLeakSuiteWithGeneratedKeys` (S-01..S-05 with SSH private keys): DEBUG log capture of the whole stack; generate keys of all four types; deploy one (success) and one (refused login → undo); run a rotation to completion and one that aborts; download each key once (the one allowed answer) and keep its base64 body lines as canaries, plus a passphrase canary `CANARY-<random>` used for one download and a reason containing `-----BEGIN ` + `OPENSSH PRIVATE KEY-----` (refused); then assert: no canary and no `PRIVATE KEY` marker in the captured logs (S-01), in any other HTTP response body or header of the run (the response recorder of the harness, S-02), in job payloads, results and `last_error_code`, audit details, `rotation_steps.params`, `rotations.plan`, `notifications_outbox.params` (S-03, S-05), and the raw `managed_private_keys.ciphertext` holds no canary and no PEM marker (S-04); the S-08 OpenAPI check of Phase 1 still passes with the new schemas.

- [ ] **Step 2: Run them**

Run (testcontainers; Playwright not running): `go test -count=1 -tags integration -run 'TestOwnerSteps|TestS09|TestF36Own|TestF37Deploy|TestDryRun|TestRotationInLock|TestContinueAfterRenewal|TestSecretLeakSuiteWithGeneratedKeys' ./internal/api/`
Expected: all pass; a failure is a defect to fix in its owning package (commit the fix separately, then re-run).

- [ ] **Step 3: Run the whole API package**

Run (testcontainers): `go test -count=1 -tags integration ./internal/api/`
Expected: `ok`, coverage of `internal/api` still ≥ 94 % (`go test -tags integration -coverprofile=/tmp/api.out ./internal/api/ && go tool cover -func=/tmp/api.out | tail -1`).

- [ ] **Step 4: Commit**

```bash
git add -- internal/api/sshkeys_integration_test.go internal/api/rotation_integration_test.go internal/api/sshkeys_leak_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(api): SSH key and rotation journeys, S-09, secret-leak suite with generated keys, lock and F-36 over the wire" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/api
```

---

### Task 15: Wiring and the e2e build: services, runner, scheduler, periodic types, `POST /test/rotation/overlap`, reset, e2e target account

**Files:**
- Modify: `cmd/alice/services.go` (`services.sshkeys`, `buildServices`, `buildRunner` → `sshkeyjobs.Register(runner, sshkeyDeps(...))`, `buildScheduler` → the three tasks), `cmd/alice/wiring.go` (`periodicTypes` gains `jobs.RotationPlan`, `jobs.RotationSweep`, `jobs.SSHKeyDestroyRetired`), `cmd/alice/main.go` or wherever `api.Deps` is filled (`SSHKeys`)
- Modify: `cmd/alice/testapi_e2e.go` (`rotationPlanEvery`, `rotationSweepEvery`, `destroyRetiredEvery` = never; `resetSQL` gains `rotation_steps, rotation_locations, rotations, rotation_policies` before `ssh_key_locations`; `POST /test/rotation/overlap`), `cmd/alice/testapi_release.go` (the three intervals: 1 minute, 1 minute, 1 hour)
- Modify: `cmd/alice/wiring_test.go`, `cmd/alice/testapi_e2e_test.go`, `cmd/alice/testapi_release_test.go`
- Modify: `test/images/e2e-target/Dockerfile` (`usermod -p '*' deploy` after `useradd … deploy`)

**Interfaces:**
- Consumes: Tasks 7–13.
- Produces: a wired server; the e2e endpoint `POST /test/rotation/overlap` with body `{"policy_id": "<uuid>", "minutes": <0..129600>}` that sets `rotation_policies.overlap_minutes` (owner pool, no audit: test-only) and answers `{"overlap_minutes": n}`; 404 for an unknown policy, 400 for anything else.

- [ ] **Step 1: Write the failing tests**

`cmd/alice/wiring_test.go`: `TestCheckWiringNamesRotationGaps` — a runner without `sshkeyjobs.Register` and a scheduler without the three tasks: `checkWiring` names `sshkey.add`, `rotation.location`, `rotation.plan`, `rotation.sweep`, `sshkey.destroy_retired`; the real `buildRunner`/`buildScheduler` pass it.
`cmd/alice/testapi_e2e_test.go` (`//go:build e2e`): `TestRotationOverlapEndpoint` (unit with a fake pool seam, as the other `/test` endpoints are tested: body validation, 404, the update), and `TestResetSQLCoversPhase6Tables` (every table of migration `00010` is in `resetSQL`).
`cmd/alice/testapi_release_test.go`: `TestReleaseHasNoRotationTestEndpoint` (the release `testHandler` is nil; `release-symcheck` already refuses `/test/` symbols).

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./cmd/alice/ && go test -tags 'e2e testlicense' ./cmd/alice/`
Expected: FAIL — `checkWiring` reports the unwired types / the endpoint is missing.

- [ ] **Step 3: Write the implementation**

Wire as above (`sshkeys.New(sshkeys.Config{Pool, Keyring, Audit, Clock, License: svc.license, Inventory: svc.inventory, Jobs: svc.queue, Notifier: notify.AdminNotifier{Clock: clk}, Log})`; `sshkeyjobs.Deps{Keys: svc.sshkeys, Targets: svc.inventory, Registry, Clock, Log}`; scheduler tasks `jobs.Task{Type: jobs.RotationPlan, Every: rotationPlanEvery, Run: func(ctx) error { _, err := svc.sshkeys.PlanDue(ctx); return err }}`, likewise `RotationSweep` (`Sweep`) and `SSHKeyDestroyRetired` (`DestroyRetiredKeys`)). The Dockerfile line: in the `RUN set -eu; useradd --uid 1001 …` block, add `usermod -p '*' deploy;` right after `useradd` (the account then is not "locked" for an sshd without PAM, R37 item 2's form; Ubuntu's PAM accepted the key before too).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./cmd/alice/ && go test -count=1 -tags 'e2e testlicense' ./cmd/alice/ && make release-symcheck`
Expected: `ok`, `ok`, release-symcheck passes.

Run (testcontainers): `go test -count=1 -tags integration ./cmd/alice/`
Expected: `ok` (the serve integration tests start a fully wired server).

Run (builds the e2e SSH target image under the tag `deploy/docker-compose.e2e.yml` gives it; Docker, no Playwright running; host networking because of this machine's DNS): `docker build --network host -f test/images/e2e-target/Dockerfile -t alice-e2e-sshtarget . >/dev/null && echo built`
Expected: `built`.

- [ ] **Step 5: Commit**

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(alice): wire SSH key lifecycle and rotation; e2e overlap endpoint and reset; e2e target account usable by key" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- cmd/alice test/images/e2e-target/Dockerfile
```

---

### Task 16: Web part 1: API layer, **Generate key**, **Deploy**, **Download private key**, the key pages

**Files:**
- Modify: `web/src/api/client.ts` (`FetchOptions.responseType`), `web/src/api/client.test.ts`
- Create: `web/src/api/sshkeys.ts` (types and calls), `web/src/api/sshkeys.test.ts`
- Create: `web/src/components/GenerateKeyDialog.tsx`, `DeployKeyDialog.tsx`, `DownloadKeyDialog.tsx`, `saveBlob.ts` and their `*.test.tsx`
- Modify: `web/src/pages/SSHKeysPage.tsx` (button **Generate key**, the **Generated by Alice** badge), `web/src/pages/SSHKeyDetailPage.tsx` (managed-key section: badges, comment, downloads count, **Deploy to a server**, **Download private key**; the platform key note), their tests
- Modify: `web/src/api/queryKeys.ts` (`sshKey(id)`, `keyFiles(targetId)`), `web/src/locales/en.json`, `web/src/locales/tr.json` (the `sshKeys.*` keys of C14)

**Interfaces:**
- Consumes: C13 DTOs and routes; `useStepUp().run` (`StepUpProvider`); `waitForJob` (`api/jobs.ts`); `ErrorAlert`; `AppModal`; `CodeText`.
- Produces (used by Task 17): `api/sshkeys.ts` exports `ManagedKeyInfo`, `SSHKeyDetail` (the existing type extended with `managed_key`), `KeyFiles`, `generateKey(body)`, `deployKey(id, body)`, `downloadPrivateKey(id, body): Promise<Blob>`, `getKeyFiles(targetId)`.

`client.ts`: `FetchOptions` gains `responseType?: 'json' | 'blob'` (default `json`); for `blob` and a successful answer, `apiFetch` returns `(await res.blob()) as T` instead of reading text; error answers are read as text and parsed exactly as now.

```ts
// web/src/api/sshkeys.ts
import { apiFetch } from './client';

export type KeyType = 'ed25519' | 'rsa-3072' | 'rsa-4096' | 'ecdsa-p256';
export const KEY_TYPES: KeyType[] = ['ed25519', 'rsa-3072', 'rsa-4096', 'ecdsa-p256'];

export interface ManagedKeyInfo {
  label: string;
  comment: string;
  key_type: KeyType;
  created_by: string;
  created_at: string;
  retired_at: string | null;
  destroyed_at: string | null;
  rotated_from: string | null;
  download_count: number;
  last_downloaded_at: string | null;
  policy_id: string | null;
  open_rotation_id: string | null;
}

export interface KeyFiles {
  items: { os_user: string; files: string[]; default_file: string }[];
  scanned_at: string | null;
}

export function generateKey(body: { label: string; key_type: KeyType }) {
  return apiFetch<{ id: string; managed_key: ManagedKeyInfo }>('/api/v1/ssh-keys/generate', { method: 'POST', body });
}

export function deployKey(id: string, body: { target_id: string; os_user: string; file_path: string; from?: string; restrict?: boolean }) {
  return apiFetch<{ job_id: string; status_url: string }>(`/api/v1/ssh-keys/${encodeURIComponent(id)}/actions/deploy`, { method: 'POST', body });
}

// downloadPrivateKey returns the OpenSSH file as a Blob. The passphrase travels only in this request body;
// the caller drops its copy as soon as this promise settles.
export function downloadPrivateKey(id: string, body: { reason: string; passphrase?: string }): Promise<Blob> {
  return apiFetch<Blob>(`/api/v1/ssh-keys/${encodeURIComponent(id)}/actions/download-private-key`, {
    method: 'POST',
    body,
    responseType: 'blob',
  });
}

export function getKeyFiles(targetId: string) {
  return apiFetch<KeyFiles>(`/api/v1/targets/${encodeURIComponent(targetId)}/key-files`);
}
```

`saveBlob.ts`:

```ts
// saveBlob hands a Blob to the browser as a download through one temporary object URL, revoked on the next
// task (some browsers read it only after click() returns). Nothing keeps a reference to the Blob.
export function saveBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
```

`DownloadKeyDialog` (props `{ keyId: string; label: string; opened: boolean; onClose: () => void }`): the warning text, **Reason** (required, 10–500, the help), the checkbox **Protect the file with a passphrase (recommended)** checked by default, two password inputs (`autoComplete="new-password"`, `data-1p-ignore`, `data-lpignore="true"`, as the Phase 4 upload form's secret fields) shown while checked, client checks (reason ≥ 10 characters; passphrase ≥ 12 and equal to the repeat: `sshKeys.downloadMismatch`); on submit `useStepUp().run(() => downloadPrivateKey(keyId, { reason, passphrase }))`, then `saveBlob(blob, fileNameFrom(label))` — the file name the server sent is not readable through `apiFetch`, so the client uses `alice-<label slug>.key` (lower-case ASCII letters, digits, `.`, `_`, `-`; the server's name differs only by the fingerprint suffix); on success the form state (reason, both passphrases) is cleared, the dialog shows `sshKeys.downloadDone` and invalidates `sshKey(keyId)` (the count changes); on error `ErrorAlert` and the passphrases are cleared; closing clears everything.

`DeployKeyDialog` (props `{ keyId: string; opened: boolean; onClose: () => void }`): **Server** select from `listAllTargets()` filtered to servers (`type` `linux` or `nginx`, status not `pending_host_key`), **User on the server** from `getKeyFiles(target)` (the connection account is already absent), **File** select (default `default_file`; `sshKeys.deployNoFiles` when the list is empty), **Allowed source addresses (optional)**, **Allow sign-in only (no forwarding)**; submit → `deployKey` → `sshKeys.deployQueued` → `waitForJob(job_id)` → the result text `sshKeys.deployResult.<result>` from the job's `result.result` (or `ErrorAlert` for a failed job, which renders `last_error_code`'s texts).

`GenerateKeyDialog` (props `{ opened: boolean; onClose: () => void; onGenerated: (id: string) => void }`): **Name** with help, **Key type** radio group in `KEY_TYPES` order (Ed25519 preselected), **Generate**; on success `sshKeys.generated` and `onGenerated` (the page navigates to the key).

- [ ] **Step 1: Write the failing tests** (Vitest + Testing Library + msw, as `RemoveKeyDialog.test.tsx` and `UploadCertificateDialog.test.tsx`)

- `client.test.ts`: `responseType: 'blob'` returns a Blob for a 200; an error answer still throws `ApiError` with the parsed body.
- `sshkeys.test.ts`: each function hits its path with its method and body; `downloadPrivateKey` sends `reason` and `passphrase` and resolves a Blob.
- `GenerateKeyDialog.test.tsx`: Ed25519 preselected; the four options in order with the C14 labels; a 422 on `label` shows the field error; success calls `onGenerated` with the id.
- `DeployKeyDialog.test.tsx`: user and file lists from `key-files`; `alice-svc` never offered; an empty list shows `sshKeys.deployNoFiles` and disables **Deploy**; a `from` value is sent as typed; after the job ends `verified` the text `Alice added the key and verified a login with it.` is shown; a failed job with `sshkey.login_failed` shows that error's title.
- `DownloadKeyDialog.test.tsx`: the step-up dialog appears when the server answers `auth.stepup_required` and the download retries after the code; a reason of 9 characters is refused before any request; mismatching passphrases show `sshKeys.downloadMismatch` and send nothing; on success `URL.createObjectURL` is called once with a Blob and `revokeObjectURL` on the next task (fake timers), the reason and passphrase inputs are empty afterwards, and no `localStorage`/`sessionStorage` key was written (spy); the passphrase never appears in `console` output (spy on `console.*`).
- `SSHKeyDetailPage.test.tsx`: a managed key shows **Generated by Alice**, `Downloaded 2 times`, **Deploy to a server** for Operators and Administrators, **Download private key** only for Administrators; a retired key shows **Retired** and no **Deploy**; a destroyed key shows **Private key destroyed** and no download button; the platform key shows `sshKeys.noDownloadPlatform`; an Auditor sees none of the buttons.
- `SSHKeysPage.test.tsx`: **Generate key** for Administrators and Operators only; managed rows carry the badge.
- `screens.i18n.test.tsx`: the new dialogs render in Turkish with no missing key.

- [ ] **Step 2: Run them to verify they fail**

Run: `make web-test`
Expected: FAIL — modules `./api/sshkeys`, `./components/GenerateKeyDialog`, … not found.

- [ ] **Step 3: Write the implementation**

As above, with Mantine components as the neighbouring dialogs use them; the locale keys of C14 (`sshKeys.*`) in both files; fingerprints, public keys, paths and comments in `CodeText`.

- [ ] **Step 4: Run them to verify they pass**

Run: `make web-test && make web-lint && make i18n-check && make web-coverage`
Expected: all pass; `web-coverage` thresholds of `web/vite.config.ts` hold.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/api/sshkeys.ts web/src/api/sshkeys.test.ts web/src/components/GenerateKeyDialog.tsx web/src/components/GenerateKeyDialog.test.tsx \
  web/src/components/DeployKeyDialog.tsx web/src/components/DeployKeyDialog.test.tsx web/src/components/DownloadKeyDialog.tsx \
  web/src/components/DownloadKeyDialog.test.tsx web/src/components/saveBlob.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): generate, deploy and download SSH keys; managed key details" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src
```

---

### Task 17: Web part 2: rotation policy panel and dialogs, preview, the rotation run page, audit labels; Phase 5 web carries

**Files:**
- Create: `web/src/api/rotation.ts` (+ test), `web/src/components/RotationPolicyPanel.tsx`, `RotationPolicyDialog.tsx`, `RotationPreviewDialog.tsx`, `web/src/pages/RotationRunPage.tsx` (+ tests)
- Modify: `web/src/pages/SSHKeyDetailPage.tsx` (the panel, the earlier runs list), `web/src/router.tsx` (`rotation/runs/:id`), `web/src/api/queryKeys.ts`, `web/src/locales/{en,tr}.json` (`rotation.*` of C14, `audit.actions.*` of C12)
- Modify: `web/src/components/ImportHistory.tsx` (+ test): Phase 5 carry 6
- Modify: `web/src/components/AddKeyVaultDialog.tsx` (+ test): Phase 5 carry 9

**Interfaces:**
- Consumes: C13 (`Policy`, `Preview`, `Rotation`), Task 16's API layer and `useStepUp`, `ETag`/`If-Match` handling as `LocationSettingsDialog` does it.
- Produces: the screens owner steps 3–6 use.

Behaviour:

- **RotationPolicyPanel** (on a managed, not retired key's page): no policy → `rotation.none` and **Create rotation policy** (Administrators); a policy → name, `rotation.every_*`, `rotation.overlap` (days, or minutes when `overlap_minutes` is not a multiple of 1440), `rotation.notifyHours`, the switch **Rotate automatically** (On/Off; switching on runs through `useStepUp().run` with the policy's ETag; `rotation.offHelp` while Off), `rotation.nextRun`, buttons **Preview next run**, **Run now**, **Edit**, **Delete policy** (Administrators; Auditors and Operators see the panel read-only), and a link to the open run (`/rotation/runs/:id`).
- **RotationPolicyDialog**: create or edit with the C14 fields; defaults 90 / 7 / 24 / "Same as now"; validation as C13; `If-Match` on edit; a 412 shows the existing "changed since you opened it" text and reloads.
- **RotationPreviewDialog**: calls `POST …/preview` when opened; shows `rotation.previewIntro`, `rotation.changes`, `rotation.skips`, `rotation.previewEmailed` or `rotation.previewNotEmailed`, and a table (scrolls in its own named group) with **Server**, **User**, **File**, **Change** (`rotation.willChange` with the lines `rotation.adds` / `rotation.removesAfter` in `CodeText`, or `rotation.skipped` with `rotation.skip.<reason>`), and the note `rotation.noLoginTest` / `rotation.note.<note>`; **Run now** (Administrators) opens `rotation.runConfirmTitle` and posts `{plan_digest}` of **this** preview through `useStepUp().run`; a 409 `ALC-ROT-0003` shows its error text and re-runs the preview.
- **RotationRunPage**: header with the status label (`rotation.status.*`), old and new fingerprints, `rotation.overlapUntil` in the overlap, `rotation.decisionDue` while waiting, the red `rotation.pausedBanner` when `paused_license`, the result's `ErrorAlert` when `result_code` is set; buttons only from `actions_allowed` (`continue`, `finish_now` with `rotation.finishNowHelp` confirmation, `keep_old` with a checklist of the `unverifiable` locations, `abort` with `rotation.abortConfirm`), `rotation.operate` ones through `useStepUp().run`; the locations table (state labels `rotation.loc.*`, skip reasons, notes, error codes rendered as their titles, the backup path in `CodeText`); the steps list (`rotation.steps`); polls every 3 s while the run is not terminal (with `Retry-After` honoured, as the deploy dialog's bounded loop of P4-21).
- **Audit labels**: every action of C12 in `audit.actions.<action with "." replaced by "_">` in both languages.
- **ImportHistory** (carry 6): when the read of one vault's imports fails, the history shows, in place of that vault's rows, `ErrorAlert` with the error and a **Try again** button that refetches only that vault (`imports.loadFailed` / "The import history of {{vault}} could not be loaded." / "{{vault}} kasasının içe aktarma geçmişi yüklenemedi."); rows of the vaults that loaded stay visible.
- **AddKeyVaultDialog** (carry 9): when the add answers with a missing role **and** the access check failed too, both the role guide and the check's error are shown (the role text first), instead of the role text alone.

- [ ] **Step 1: Write the failing tests**

- `rotation.test.ts`: paths, methods, bodies, `If-Match` headers of every call.
- `RotationPolicyPanel.test.tsx`: Off by default with `rotation.offHelp`; switching on asks for the step-up code (msw answers `auth.stepup_required` first) and sends `If-Match: "1"`; Operator and Auditor see no buttons; overlap rendering `7 days` / `1 minute`.
- `RotationPreviewDialog.test.tsx`: the table of a preview with one change and one skip (`target_not_connected` → "Alice cannot connect to the server right now."); the lines in monospace; `rotation.previewNotEmailed` when `emailed` is false; **Run now** posts the preview's own `plan_digest`; a 409 `ALC-ROT-0003` re-fetches the preview.
- `RotationRunPage.test.tsx`: each status label; buttons exactly per `actions_allowed`; the paused banner; **Keep the old key on these servers** sends the checked location ids; polling stops at a terminal status; the 375 px layout has no horizontal page scroll (the table scrolls in its group).
- `ImportHistory.test.tsx`: one vault's read fails → its error with **Try again**, the other vault's rows still shown; **Try again** refetches only that vault.
- `AddKeyVaultDialog.test.tsx`: a missing role plus a failed check → both texts.
- `labels.test.ts` / `terms.test.ts` (existing locale guards): the new keys pass (EN/TR parity, terminology of Global Constraints).

- [ ] **Step 2: Run them to verify they fail**

Run: `make web-test`
Expected: FAIL — missing modules and texts.

- [ ] **Step 3: Write the implementation** (as above)

- [ ] **Step 4: Run them to verify they pass**

Run: `make web-test && make web-lint && make i18n-check && make web-coverage`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/api/rotation.ts web/src/api/rotation.test.ts web/src/components/RotationPolicyPanel.tsx \
  web/src/components/RotationPolicyPanel.test.tsx web/src/components/RotationPolicyDialog.tsx web/src/components/RotationPolicyDialog.test.tsx \
  web/src/components/RotationPreviewDialog.tsx web/src/components/RotationPreviewDialog.test.tsx web/src/pages/RotationRunPage.tsx \
  web/src/pages/RotationRunPage.test.tsx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): rotation policies, preview, run page; import history and add-vault texts (Phase 5 carries)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src
```

---

### Task 18: End-to-end: Phase 6 journeys in EN and TR, accessibility (**Docker alone**)

**Files:**
- Create: `web/e2e/phase6.spec.ts`
- Modify: `web/e2e/helpers.ts` (`setOverlapMinutes(request, policyId, minutes)` → `POST /test/rotation/overlap`; `COPY` entries of C14 for both languages)

**Interfaces:**
- Consumes: the e2e stack (`make e2e-up`: compose project `alice-e2e`, `127.0.0.1:9443`, image `alice:e2e` built with `e2e testlicense`, the e2e target with user `deploy`), helpers `resetInstall`, `runWizard`, `signIn`, `freshCode`, `targetExec`, `drainJobs`, `runScheduled`, `advanceClock`, `expectAccessible`, `expectWide`, `apiAs`, `uploadLicense`/`POST /test/license`.
- Produces: `phase6.spec.ts`.

Journey per language (`for (const lang of ['en', 'tr'] as const)`, as `phase3.spec.ts`), one `test.describe` with `test.use({ trace: 'off', video: 'off', screenshot: 'off' })` (a private key crosses the browser):

1. `resetInstall`, wizard, test license, add the e2e target and confirm its host key, drain the discovery (as Phase 3's journey).
2. **SSH keys** → **Generate key** → name `ci-deploy` → **Ed25519 (recommended)** preselected → **Generate**; `expectAccessible(page, 'generate-key')` with the dialog open.
3. On the key page: **Deploy to a server** → server, user `deploy`, file `/home/deploy/.ssh/authorized_keys` → **Deploy** → `drainJobs` → the text `Alice added the key and verified a login with it.` (TR text in the TR run); `targetExec(['cat', '/home/deploy/.ssh/authorized_keys'])` contains the key's public key from the page.
4. **Download private key** → step-up code (`freshCode`) → reason `Hand-over for the e2e journey` → passphrase unchecked → **Download**; `page.waitForEvent('download')`; read the file into memory, assert it starts with `-----BEGIN ` + `OPENSSH PRIVATE KEY-----`; prove it is the key's private half without writing it to disk outside the container: `targetExec(['sh', '-c', 'umask 077; f=$(mktemp); cat > "$f"; ssh-keygen -y -f "$f"; rm -f "$f"'], fileText)` prints a line that starts with the public key shown on the page (type and base64; newer OpenSSH appends the comment); `finally`: `await download.delete()` and drop the string. **Audit log** lists **Private key downloaded** with the reason.
5. **Create rotation policy** → `90` / `7` / `24` → **Save** → the panel shows **Off** and `The policy is off. Alice plans no run until you switch it on.`
6. **Preview next run** → the table names the server, `deploy` and the file with **Will change**; `GET /test/mail` has a message whose subject is `Planned SSH key rotation: ci-deploy` (TR subject in the TR run).
7. `setOverlapMinutes(request, policyId, 1)`; **Preview next run** again (the digest changed with the overlap) → **Run now** → step-up → **Start rotation** → `drainJobs` → the run page shows **Both keys valid** and `targetExec(cat …)` holds the old and the new public key.
8. `advanceClock(request, 30)`; `runScheduled(request, 'rotation.sweep')`; `drainJobs` → still **Both keys valid**, the old key still in the file (the overlap is not over).
9. `advanceClock(request, 31)`; `runScheduled(request, 'rotation.sweep')`; `drainJobs`; `runScheduled(request, 'rotation.sweep')` → **Completed**; the file holds the new key and not the old one; the old key's page shows it is no longer the policy's key; the audit log lists **Rotation state changed** rows.
10. Accessibility: `expectAccessible` on the key page, the preview dialog and the run page at 640/1280/1920; `expectWide` at 375 px for the key page and the run page.

A second test per language, `owner step 6 without the network is a Go test`, is not added: the network-loss case is `TestOwnerStep6NetworkLoss` (Task 11); the e2e journey covers the happy path only, as §26.8 lists.

- [ ] **Step 1: Write the spec** (the journey above, with `COPY[lang]` texts from C14 and the email subjects from C10)

- [ ] **Step 2: Build and start the stack, run the spec** (**Docker alone**: no testcontainers, no other agent using Docker)

Run: `make e2e-up`
Expected: the compose project `alice-e2e` is up and healthy (`--wait`), images `alice:e2e`, `alice-e2e-sshtarget`, `alice-e2e-fakeazure`; `curl -sk https://127.0.0.1:9443/livez` → `ok`. If the build fails to download a module or a package (this machine's containers cannot reach the LAN DNS), prime the three images with `docker build --network host` using exactly the `build:` sections of `deploy/docker-compose.e2e.yml` (its context `..`, dockerfile and `args`, tagged with its `image:` name), then run `make e2e-up` again.

Run: `cd web && ALICE_E2E_PROJECT=alice-e2e npx playwright test phase6`
Expected: both language journeys pass.

- [ ] **Step 3: Run the whole suite once**

Run: `make e2e`
Expected: all specs pass (Phases 1–6).

- [ ] **Step 4: Stop the stack**

Run: `make e2e-down`
Expected: the `alice-e2e` project is removed; the owner's `alice` project is untouched (`docker compose -p alice ps` unchanged — read only).

- [ ] **Step 5: Commit**

```bash
git add -- web/e2e/phase6.spec.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(e2e): Phase 6 — generate, deploy with verified login, download, rotation with a one-minute overlap (EN, TR)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/e2e/phase6.spec.ts web/e2e/helpers.ts
```

---

### Task 19: Coverage floors, documentation, R41, security review, rulings, CHANGELOG, `make ci` (**Docker alone**)

**Files:**
- Modify: `coverage-floors.json`
- Modify: `docs/admin-guide.md` (section "SSH keys": generating, deploying, the test login and its three answers, downloading with a reason and passphrase, rotation policies, preview and emails, Run now, overlap, Continue after a renewal, Finish now, keeping the old key, Stop and undo, retired keys and their 30 days), `docs/operator-guide.md` (the scheduled tasks `rotation.plan`, `rotation.sweep`, `sshkey.destroy_retired`; backups keep destroyed keys; Alice's own key still replaced by hand), `docs/troubleshooting.md` (already has the code sections from Task 13; add the audit actions of C12 to its action list and `key_added` to the `target.status_changed` reasons)
- Modify: `CHANGELOG.md` (Phase 6 entry)
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md` (**R41**: one item per row of "Spec conflicts resolved by this plan", corrected to the built code, plus an addendum for decisions made while building), `docs/superpowers/specs/alice-v1/03-integrations.md` (one pointer line after §13.6: "(Phase 6, R41: …)"), `docs/superpowers/specs/alice-v1/06-quality.md` (one pointer after §26.8 naming the tests that cover it)
- Create: `docs/security/reviews/phase-6.md`, `docs/superpowers/rulings/phase-6.md`

**Interfaces:**
- Consumes: everything.
- Produces: the phase close.

- [ ] **Step 1: Coverage floors** (**Docker alone**: `make coverage` starts testcontainers)

Run: `make coverage`
Expected: every existing floor holds (`internal/inventory` ≥ 89, `internal/jobs` ≥ 89, `internal/providers` 100, `internal/rbac` ≥ 98, `internal/api` ≥ 94, `internal/providers/linuxssh` ≥ 92, `cmd/alice` ≥ 90, `internal/certs` ≥ 98 untouched). Then add to `coverage-floors.json`: `"alice/internal/sshkeys/plan": 100`, and `alice/internal/sshkeys/keymat`, `alice/internal/sshkeys`, `alice/internal/jobs/sshkeyjobs` at their measured values rounded down; raise any existing floor whose measured value rose by a whole point. Run `make coverage` again: PASS.

- [ ] **Step 2: Guides, troubleshooting, changelog**

Write the guide sections listed above in the style of the existing ones (plain language, the exact button names of C14). `CHANGELOG.md` gets a "Phase 6 — SSH key lifecycle and rotation" entry: added (generation, deploy with test login, download, policies, preview, runs, emails, codes `ALC-KEY-0006..0013`, `ALC-ROT-0001..0016`, migration `00010`), changed (`facts.key_files`, the key list shows generated keys without locations, the OpenAPI 412 sentence, the import history and add-vault texts), security (the old-key rule, S-09).

- [ ] **Step 3: R41, the two spec pointers, the rulings**

`00-decisions.md`: append **R41** (Phase 6, approved with the Phase 6 plan; corrected to the built code at the end of Phase 6) with items 1–33 = the rows of "Spec conflicts resolved by this plan" as built, and an addendum for the decisions made while building (from the task reports). `docs/superpowers/rulings/phase-6.md`: the controller's rulings during execution (format of `phase-5.md`: before the tasks, per area, final review, process, status at phase close, carried to later phases — the re-deferred carries of this plan's "Carries and deferred items" with their reasons).

- [ ] **Step 4: Security review**

`docs/security/reviews/phase-6.md` in the format of `phase-5.md`: Method; **Evidence** table (rows for `make test`, `make test-integration`, the property test's scenario count, `make test-ssh` (unchanged helper: run to show no regression of the real OpenSSH test-login case), `make e2e`, `make coverage`, `make ci`, `make secrets-scan`, `make vuln`, `make fs-scan`; cells marked `PENDING-FINAL-RUN` until Step 5 fills them); **Threat notes** (private keys at rest and in transit, the download, the test login and a server that lets anyone in, the old-key rule and its three layers, lock behaviour, shared files, platform key); **Review checklist** (§17.2 Phase 6 gate: never remove last access, own-key protection, overlap logic; failure-injection tests; platform key cannot be removed); **Findings** (with severities; no open High); **Known limitations** (at least: Go strings and `big.Int` limbs of RSA/ECDSA keys cannot be cleared (P4-04 extended), backups keep destroyed keys, the download may be used during a lock (by design), the test login proves authentication only, a forced `command=` that breaks a consumer still counts as working, servers Alice cannot test keep both keys, rotation adds about four helper scans per location (carry 4), notification recipients are all Administrators until Phase 7, the 30-day retention is not configurable until Phase 7, no certificate private-key download (carry 11), no cron schedules, no partial-location policies); **Owner verification** — the empty table of §26.8 owner steps 1–6:

| # | Step (§26.8) | Expected | Result | Date | Notes |
|---|---|---|---|---|---|
| 1 | Generate an Ed25519 key, deploy it to a test server and user | Alice reports a verified login with the new key | | | |
| 2 | Download private key | Authenticator code and reason are asked; the Audit log records the download | | | |
| 3 | Create a rotation policy (every 90 days, keep the old key 7 days) | It stays Off until switched on | | | |
| 4 | Preview next run | The exact servers, users and files; an email arrives | | | |
| 5 | Start a rotation manually | Both keys on the server during the overlap; nothing removed before the overlap ends and the new key was checked again | | | |
| 6 | Cut the test server's network in the middle of a rotation | The old key stays; Alice reports the incomplete rotation | | | |

and **Sign-off** (empty).

- [ ] **Step 5: `make ci`** (**Docker alone**, no other Docker user at all; Playwright not running)

Run: `make ci TRIVY_IMAGE="--network host aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"`
Expected: exit code 0 (the image reference is the Makefile's pinned `TRIVY_IMAGE`; if Task work changed the pin, use the new value verbatim). Fill the Evidence cells with the results and the commit hash.

- [ ] **Step 6: Commit**

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs: Phase 6 — guides, troubleshooting, changelog, R41, security review and rulings; coverage floors" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- coverage-floors.json docs/admin-guide.md docs/operator-guide.md \
  docs/troubleshooting.md CHANGELOG.md docs/superpowers/specs/alice-v1/00-decisions.md docs/superpowers/specs/alice-v1/03-integrations.md \
  docs/superpowers/specs/alice-v1/06-quality.md
git add -- docs/security/reviews/phase-6.md docs/superpowers/rulings/phase-6.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs(security): Phase 6 review with the owner verification table; controller rulings" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- docs/security/reviews/phase-6.md docs/superpowers/rulings/phase-6.md
```

---

## Self-review (done while writing this plan)

1. **Spec coverage.** Every §26.8 deliverable and named test maps to a task (table "Spec coverage map"). The spec items with no task are deliberately re-deferred with reasons (certificate private-key download, cron schedules, partial-location policies, the `require_verification`/`remove_old` switches, configurable retention): see "Spec conflicts" rows 6, 11–13, 23 and "Carries".
2. **Placeholders.** None intended: every step names files, code or exact contracts, commands and expected output. Where a step must read existing code first (test harness helper names, the Makefile's e2e invocation), it names the file to read and the behaviour to keep.
3. **Type consistency.** Names used across tasks are defined once in the contract (C1–C14): `sshkeys.{Generate, ManagedKey, RequestDeploy, DeployJob, FinishDeploy, KeySigner, DownloadPrivateKey, DestroyRetiredKeys, CreatePolicy, UpdatePolicy, SetPolicyEnabled, DeletePolicy, Preview, RunNow, PlanDue, Rotation, Rotations, Continue, FinishNow, KeepOld, Abort, Advance, Sweep, LocationWork, BeginAdd, FinishAdd, RecordVerify, RecordReverify, BeginRemove, FinishRemove, BeginUndo, FinishUndo, Step, AllowedActions, Templates}`, `plan.{Build, Digest, Fresh, …}`, `keymat.{Generate, OpenSSHFile, Line, …}`, `providers.{VerifyKeyLogin, KeyLoginRequest, KeyLoginResult, KeyLogin*, CapKeyLogin, UserKeyFiles, AuthKeyResult.LineNo, DiscoveryResult.KeyFiles}`, `inventory.{KeyChangeRefusal, TargetTx, CheckClaimTx, ProtectedFingerprintsTx, KeyLocationsTx, KeyAdded, RecordKeyAddedTx, ValidateReason, Facts.KeyFiles}`, job and task names of C1, permissions of C1, codes of C11.
4. **Review Focus.** The five items each name the task whose tests pin them.


