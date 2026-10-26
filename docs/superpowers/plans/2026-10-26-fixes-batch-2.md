# Fixes Batch 2 (Load- and Time-Sensitive Tests, the Engine's `auto_deploy` Re-Check, the Windows Test Ports Verdict) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the tests that failed under a loaded machine (load average 15-21 during the R65 and R66 gates) robust without weakening what they prove; build the one engine item R66 deferred until R65 merged (the first send re-checks the service policy's `deployment.auto_deploy`); settle the Windows helper's fixed test ports with evidence.

**Architecture:** No new module, no migration, no new error code, no new permission, no helper protocol bump.
- Five test files and one Vitest config change (Tasks 1-5). One test is rewritten deterministically (cloudflare), one is synchronised on the event it asserts (LDAP), two bounds are widened by a factor the house already uses (nginxconf and apacheconf: haproxyconf's coverage factor; Vitest: a longer hang bound), one product defect is fixed (the vendor console rendered dates in the machine's zone while the test, and its own other pages, use UTC). Two are left with reasons (route53, the e2e held-chain journey).
- Task 6 adds one refusal to `inventory.DeploymentMaterial`'s unsent block, next to the trust re-check of R49: an automatic deployment (trigger `acme_renewal` or `kv_renewal`) whose source service's policy now says `auto_deploy: forbidden` ends with the closed reason `service.auto_deploy_forbidden` before any server or vault contact. The engine maps the error through its existing `kvRefusals` table; the planners treat the reason as neutral.
- The Windows helper's fixed ports are http.sys/IIS binding ports, not Go listeners, and lie outside Windows' ephemeral range: the item is closed as not applicable with evidence (Task 7).

**Tech Stack:** Go 1.27.3, pgx/v5, React 18 + Mantine + TanStack Query + i18next, Vitest 5, Playwright.

**Spec:** the open items of these files (the plan argues from them):
- `docs/superpowers/rulings/fixes-2026-10-25.md`: "Found, not fixed" F2 and F3 (the load-sensitive tests), "Deferred" (the scoped-access first-send item).
- `docs/superpowers/rulings/canary-deployment.md`: "Found, not fixed" (fixed test ports), "Gate evidence" (the `route53:TestContextEnds` failure).
- `docs/superpowers/rulings/scoped-access.md`: Phase 5 Ruling 11 and "What remains (Phase 5 as built)"; design `docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md` §7.3 (`deployment.auto_deploy`), §5.6 (c) ("checked again by the deployment engine at the first send"), lines 1116 and 1164 ("Not built: a re-check of `auto_deploy` at the engine's first send").
- R66's model for a robust test: `docs/superpowers/rulings/fixes-2026-10-25.md` Ruling 6 and `docs/superpowers/plans/2026-10-25-fixes-batch-1.md` Task 4.

The format model is `docs/superpowers/plans/2026-10-25-fixes-batch-1.md`.

**Decision:** R67 "Fixes batch 2", appended to `docs/superpowers/specs/alice-v1/00-decisions.md` after the R66 entry (line 166, the last line) in the same style. **Size:** S, 6 tasks plus docs and the final gates. **Migrations:** none.

## Coordinator precisions (at approval, 2026-10-26)

- **C1.** The owner approved this batch on 2026-10-26 ("tek kucuk bach a onay veriyorum") with the scope: the flaky load- and time-sensitive tests, the Windows helper's fixed test ports, and the engine's first-send re-check of `deployment.auto_deploy`. Items outside it are listed under "Found, not fixed" and not fixed.
- **C2.** Task 2 also applies the coverage factor to `internal/providers/apacheconf/parse_test.go:437,479` (the same `raceSlowdown`-only bounds in the sibling parser; a three-line copy of the same helper). Reason: the same defect class in the same test family; fixing it when it flakes would cost a gate rerun. The property proven is unchanged, as for nginxconf.
- **C3.** Item B (the Windows helper's fixed test ports) is closed as not applicable with the evidence in Task 7, docs only. The probe-then-`netsh` approach is rejected: it reopens the race it means to close and dissolves the range proofs.
- **C4.** Ruling 8 (the first-send re-check) proceeds as planned; it amends R55 Ruling 11 and is listed under "Owner to confirm". Ruling 6 (UTC dates on the vendor console) proceeds; "Owner to confirm".
- **C5.** The coordinator runs nothing heavy on `main` while this branch's gates run; the implementer runs the final gate (Task 8) as the only `make ci` on the machine, after `pgrep -af 'playwright|make ci|go test'` answers nothing.

## Global Constraints

- **Branch.** Worktree branch `fixes-2`, cut from `main` at `9be0c32e` (current `origin/main`). The first commit is this plan file, copied unchanged. Take `main` in with `git merge main`, never rebase. Never push `main` and never open a pull request; the coordinator merges and pushes.
- **Commits.**
  - Command: `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R67)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R67)`.
  - Stage new files with `git add -- <path>`. Never use `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (an untracked root binary) or `docs/security/reviews/*`. Never rebase, squash or amend (`.gitleaksignore` pins commit hashes).
- **Parallel branches.** None known to touch these files. Task 6 touches `internal/inventory/deployment_records.go`, `internal/inventory/errors.go`, `internal/inventory/kv_autodeploy_plan.go` and `internal/jobs/deployjobs/kv.go`; R65 is merged, so no conflict is expected. If `git merge main` conflicts in `deployment_records.go`, keep both changes.
- **Migrations.** None. If one ever proves unavoidable, stop and report (the next free number is `00036`).
- **Error codes.** None new. Task 6 reuses `ALC-SVC-0013` (`service.auto_deploy_forbidden`, `internal/api/errors.go:600`) as a deployment's closed reason, as `service.untrusted` (`ALC-SVC-0007`) already is.
- **Test IDs.** `FX-07`..`FX-12` go in a new `docs/superpowers/specs/alice-v1/06-quality.md` §24.11 "Fixes batch 2 (R67)" (§24.9 is headed "(R66)" and §24.10 is R65's; a new section keeps one decision per section). Their rows go in `test/matrix/traceability.json`; `docs/security/traceability.md` is regenerated (Task 7). `tools/matrixcheck/main.go` already accepts the `FX` prefix.
- **Ports.** No fake listener is needed. If one ever is, use `45460`-`45479`.
- **e2e.** No spec changes. The final gate's project is `alice-e2e-fx2` on `ALICE_E2E_PORT=9981`: `make ci E2E_PROJECT=alice-e2e-fx2 ALICE_E2E_PORT=9981`, and `E2E_PROJECT=alice-e2e-fx2 make e2e-down` after a staged run. Docker-based Go runs (testcontainers, `make coverage`, `make test-ssh`) and Playwright never run at the same time, and neither runs while another `make ci` is active. Check with `pgrep -af 'playwright|make ci|go test'` first. Only one `make ci` runs on this machine at a time; the final gate (Task 8) is run by the implementer and no other gate runs then.
- **Per-task gate.** `make lint` and the package's `go test` (or `npm --prefix web run test -- <file>`), never the whole `make ci` until Task 8.
- **Coverage floors** (`coverage-floors.json`): never lower one. No new package.
- **Archtest.** No new import edge: `inventory` already imports `authz`; `deployjobs` reaches the new error through an `inventory` alias, as it does `ErrServiceUntrusted`.
- **Locales.** EN and TR keep identical keys and placeholders (`make i18n-check`). No locale change is planned.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `go test -race -count=1 ./<pkgs>`
  - Integration (Docker; never alongside Playwright): `go test -race -count=1 -tags integration ./<pkgs> -run <name>`
  - Web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - `make lint`, `make test`, `make i18n-check`, `make docs-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`; at the end, `make ci`.

## Review Focus

1. **An automatic deployment queued before the policy forbade automatic deployment is refused at its first send** with `service.auto_deploy_forbidden`, before any server command or vault call, and the planner counts it as no failure. **A person's deployment, Deploy now, a drift repair and a rollout's second wave are not judged** (Deploy now is never held, R55 Ruling 11). Tests: Task 6 `TestACMEQueuedDeploymentIsJudgedAgain` (new row), `TestKVAutoDeployForbiddenWhileQueued` (with its manual control), `TestEveryNeutralReasonCanBeProducedByTheEngine`.
2. **No test proves less than before.** Each of Tasks 1-5 states the property before and after; the reviewer checks the two match.
3. **The vendor console's dates are UTC dates** on every page, as `pages.go:233` and `notifications.go:55` already print them. Test: Task 4 under `TZ=Asia/Tokyo`.

---

### Task 1: The Cloudflare dead-context test is split so no in-flight request can leak into the "nothing sent after Zero" count; the Route 53 deadline test is left (FX-07)

**Finding** (verified at `9be0c32e`):
- `internal/acme/solver/dnsapi/cloudflare/cloudflare_test.go:374-394` `TestDeadContextAndZero` proves three things in one fake: (a) an already-cancelled context is answered `context.Canceled` without a request; (b) a 100 ms deadline during the fake's one-minute delay is answered `context.DeadlineExceeded`; (c) after `Zero()` a call is a permanent `acme.ReasonDNSProviderError` and **no request is sent** (`assert.Len(t, f.Requests(), before)`).
- The fake records a request **before** it applies the delay fault: `internal/testutil/fakecloudflare/api.go:113-119` (`i := s.record(r, op)` then `applyFault`, which waits on the timer or `r.Context().Done()`). The client gives up at 100 ms. Under load, the server goroutine that owns the connection may not have run `record` yet when the client returns; the test then reads `before := len(f.Requests())` (line 387), the starved goroutine records the delayed request, and the final `Len` fails with "nothing is sent after Zero". That is the one race in the test, and it is a scheduler race: it cannot be reproduced on demand.
- `dnsapi.Do` (`internal/acme/solver/dnsapi/client.go:150-171`) returns `ctx.Err()` whenever the client fails with a dead context, and neither provider retries (`grep -n "retry\|Sleep" cloudflare.go route53.go` finds nothing), so (b) is deterministic by construction.
- `internal/acme/solver/dnsapi/route53/route53_test.go:477-485` `TestContextEnds` asserts only (b) with a 5 s delay and a 100 ms deadline. The fake's `withFault` honours the request context (`internal/testutil/fakeroute53/faults.go:83`, `sleepCtx` lines 141-151); `call` (`route53.go:358-382`) passes `Do`'s error through. It failed in the R65 gate (`canary-deployment.md:266`, "passes alone three times in a row") and once in the R66 gate; neither run saved the assertion message. No load-dependent step exists in the code it exercises.

**Property before and after.** Unchanged: (a), (b) and (c) above. After the split, (c) is asserted on a fake that has never received a request, so the count cannot be disturbed by (b)'s delayed request.

**Decision.** Cloudflare: deterministic rewrite (split). Route 53: leave, with reason; the next failure must be captured with `-v` output (see Step 3).

**Files:** `internal/acme/solver/dnsapi/cloudflare/cloudflare_test.go` only.

- [ ] **Step 1: Record the race evidence** (there is no on-demand RED). Run: `go test -race -count=30 -run 'TestDeadContextAndZero$' ./internal/acme/solver/dnsapi/cloudflare/`
  Expected: PASS (unloaded). Record the result in the rulings file with the file:line evidence above.
- [ ] **Step 2: Split the test.**
  - `TestDeadContextAndDeadline`: the current lines 375-385 (fake, provider, solver; the cancelled context → `context.Canceled`; `FailNext(fcf.OpZones, fcf.Fault{Delay: time.Minute})`, the 100 ms deadline → `context.DeadlineExceeded`). Keep the 100 ms deadline: it only needs to be far below the minute.
  - `TestZeroSendsNothing`: a fresh `newFake(t, fcf.Options{Zones: []string{"example.com"}})`, `providerFor`, then `before := len(f.Requests())`, `p.Zero()`, `FindZone(ctx(t), …)` → `acme.ReasonDNSProviderError`, `acme.ClassPermanent`, `assert.Len(t, f.Requests(), before, "nothing is sent after Zero")`.
  - A one-line comment above the second test: why the fake is fresh (R67 Ruling 2).
- [ ] **Step 3: Run.** `go test -race -count=5 ./internal/acme/solver/dnsapi/cloudflare/ ./internal/acme/solver/dnsapi/route53/ && make lint`
  Expected: PASS. Add to the rulings file: `route53:TestContextEnds` is left; if it fails again, the gate runner must re-run `go test -race -count=1 -v -run 'TestContextEnds$' ./internal/acme/solver/dnsapi/route53/` and paste the failing assertion into the rulings before anything else.
- [ ] **Step 4: Commit.** Message: `test(dnsapi): the Cloudflare Zero check runs on a fake that has no request in flight, so a delayed request recorded late under load cannot fail it; route53 TestContextEnds is left with its evidence (FX-07, R67)`.

---

### Task 2: The Nginx and Apache hostile-size bounds take the coverage factor haproxyconf already applies (FX-08)

**Finding.**
- `internal/providers/nginx/nginxconf/nginxconf_test.go:383-408` `TestHostileSizesFinishQuickly` parses 15 hostile inputs and asserts each is refused within `2*time.Second*raceSlowdown` (`raceSlowdown` is 1, or 10 under `-race`: `race_off_test.go`, `race_on_test.go`). It proves the parser's bounds hold (no quadratic or cubic blow-up; the fixed A2-I2 case took 6.7 s unloaded without race).
- Measured at `9be0c32e` without race: the whole test 0.54 s, the slowest subtest 0.16 s (`inherited certificates, own keys`). Under `-race` that is about 1.6 s against a 20 s bound; `make coverage` adds atomic coverage instrumentation, which `internal/providers/haproxyconf/slowdown_test.go` measures as "about five times more" (so about 8 s); a load average of 15-21 on this 4-core machine divides the CPU share by 4-5 again, which passes 20 s. The bound was never meant to include the coverage factor; haproxyconf fixed the same thing with `slowdown()` (`testing.CoverMode() != ""` → `raceSlowdown * 5`). nginxconf and apacheconf still multiply by `raceSlowdown` only.
- `internal/providers/apacheconf/parse_test.go:437,479` carry the same `raceSlowdown`-only bounds (coordinator precision C2).

**Property before and after.** Before: each hostile input is refused within 2 s, times 10 under the race detector. After: the same, times 5 more when the binary is coverage-instrumented. A cubic regression (6.7 s unloaded) would still take 6.7 × 10 × 5 = 335 s under race and coverage, far above the 100 s bound; 67 s under race alone, far above 20 s. The bound still discriminates. The load itself is governed by the "one `make ci` at a time" rule, not by the test.

**Decision.** Wider bound by the house factor (copy haproxyconf's helper) in both parsers.

**Files:**
- Create `internal/providers/nginx/nginxconf/slowdown_test.go` and `internal/providers/apacheconf/slowdown_test.go` (the haproxyconf file verbatim with the package name changed). If apacheconf has no `raceSlowdown` constant pair, copy haproxyconf's `race_off_test.go`/`race_on_test.go` too.
- Modify `internal/providers/nginx/nginxconf/nginxconf_test.go:405`: `2*time.Second*raceSlowdown` → `2*time.Second*slowdown()`.
- Modify `internal/providers/apacheconf/parse_test.go:437,479` the same way (read the lines first; keep each bound's base value).

- [ ] **Step 1: Measure** (the RED of a bound is its margin). Run: `go test -race -covermode=atomic -count=1 -v -run 'TestHostileSizesFinishQuickly' ./internal/providers/nginx/nginxconf/ 2>&1 | grep -E '^\s+--- |^ok'`
  Expected: PASS; record the slowest subtest's time (expected several seconds) in the rulings file. Do the same for the two apacheconf tests.
- [ ] **Step 2: Implement** the changes.
- [ ] **Step 3: Run.** `go test -race -count=1 ./internal/providers/nginx/nginxconf/ ./internal/providers/apacheconf/ && go test -race -covermode=atomic -count=1 ./internal/providers/nginx/nginxconf/ ./internal/providers/apacheconf/ && make lint`
  Expected: PASS in both modes.
- [ ] **Step 4: Commit.** Message: `test(nginxconf,apacheconf): the hostile-size bounds take the coverage factor haproxyconf already applies, so make coverage on a loaded machine does not fail them (FX-08, R67)`.

---

### Task 3: Vitest's hang bound is raised to 60 s (FX-09)

**Finding.**
- `web/vite.config.ts:25` sets `testTimeout: 20_000`, raised from 5 s on 2026-10-16 with the comment that a few page tests take 5-7 s under `make coverage` with 144 files in parallel. `web/src/test/setup.ts` sets `asyncUtilTimeout: 5000`.
- The eight files that timed out at 20 s under load 15-21 (`DeployDialog` 48 tests, `AcmeCertificatePage` 56, `SetupPage` 30, `TargetDetailPage` 55, `TargetsPage` 36, `AcmeSettings` 43, `AddKeyVaultDialog` 17, `SavedViews` 6) use `userEvent` heavily (41-252 interactions per file) and `findBy*`/`waitFor` (25-185 per file). Only `SavedViews.test.tsx:42` runs axe, once, and that single pass is the test's purpose (`aria-required-children`, `color-contrast`); there is no redundant axe work to remove. The slow part is jsdom and Mantine rendering under `vitest run --coverage` with as many workers as cores (4), sharing those cores with the other session's `make ci`.
- A passing test is not slower with a longer bound; only a hang waits longer. `make web-coverage` runs alone inside `make ci`, so the real guard is the one-`make ci` rule; the bound only needs to tolerate the load the rule allows.

**Property before and after.** Unchanged: every test's assertions, `findBy` waits of at most 5 s, and the fact that a hung test fails. After: a hung test fails after 60 s instead of 20 s.

**Decision.** Global raise, with the reason in the comment. No per-file change (eight files is already most of the slow set; a per-file list would rot).

**Files:** `web/vite.config.ts` only.

- [ ] **Step 1: Change** `testTimeout: 20_000` to `testTimeout: 60_000` and extend the comment: the 20 s bound was passed by eight files when another `make ci` loaded the machine to 15-21 (R66 F2/F3, R67); passing tests are not slower, only a hang waits longer; axe runs once per file where it runs at all.
- [ ] **Step 2: Run.** `cd web && npx vitest run src/components/DeployDialog.test.tsx src/pages/AcmeCertificatePage.test.tsx src/pages/SetupPage.test.tsx src/pages/TargetDetailPage.test.tsx src/pages/TargetsPage.test.tsx src/components/acme/AcmeSettings.test.tsx src/components/AddKeyVaultDialog.test.tsx src/components/SavedViews.test.tsx && npx tsc --noEmit && npm run lint`
  Expected: 291 tests pass; record the slowest file's duration.
- [ ] **Step 3: Commit.** Message: `test(web): Vitest's hang bound is 60 s; eight files passed 20 s only under another session's load (FX-09, R67)`.

---

### Task 4: The vendor console prints dates in UTC on every page; the license list test pins it (FX-10)

**Finding** (the real cause, not the filter):
- `internal/vconsole/web/pages_integration_test.go:143-174` seeds `near, mid, far = now+10 d, +50 d, +200 d` with `now := time.Now().UTC()` and asserts the page contains `near.Format("2006-01-02")` (UTC). The `ending=30/90` filter (`internal/vconsole/store/licenses.go:28-41`: `valid_until <= now + days AND valid_until >= now`) is 20-40 days away from every seeded date, so the filter boundary cannot be the cause.
- The templates format without a zone: `internal/vconsole/web/templates/licenses.html:20` (`{{.ValidFrom.Format "2006-01-02"}}`, `{{.ValidUntil.Format "2006-01-02"}}`, `{{.RevokedAt.Format "2006-01-02"}}`), `home.html:44`, `request_emergency.html:12`, `request.html:25` (`"2006-01-02 15:04 MST"`). pgx scans `timestamptz` into `time.Time` in the process's local zone, so these print the **machine's** date. The same package already prints UTC elsewhere: `pages.go:233` (`old.ValidUntil.UTC().Format`), `notifications.go:55`, `emergency.go:37`.
- This machine is `Europe/London` (`readlink /etc/localtime`). British Summer Time (UTC+1) lasted until 2026-10-25 01:00 UTC. At 23:57 UTC the page printed `near` as the next local day; the test expected the UTC day: failure. At 00:05 UTC the local day equals the UTC day: pass. Since 2026-10-25 the machine is on GMT (= UTC) and the flake cannot show again until 2027-03-28, which is why it must be pinned under an explicit `TZ`.

**Property before and after.** Before: the list shows licenses ending within 30/90 days ordered by end date, hides the far one, and prints their end dates. After: the same, and the printed date is the UTC date, whatever the machine's zone.

**Decision.** Product fix (templates) plus a test that controls the zone. The server's injectable clock (`e.clk`, `passkey_integration_test.go:62`) governs the filter, not the rendering, so the clock is not the lever here; the zone is.

**Files:**
- `internal/vconsole/web/templates/licenses.html`, `home.html`, `request_emergency.html`, `request.html`: insert `.UTC` before each `.Format` (`{{.ValidUntil.UTC.Format "2006-01-02"}}`; Go templates chain no-argument methods). `request.html` prints `… UTC` instead of the machine's zone abbreviation.
- `internal/vconsole/web/pages_integration_test.go` `TestLicenseListShowsEndDatesAndExpiryFilter`.

- [ ] **Step 1: Write the failing test.** In the test, after `now := time.Now().UTC()`, seed times at 23:30 UTC on their day so a zone east of UTC moves them to the next date: `late := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 23, 30, 0, 0, time.UTC) }`; `near, mid, far := late(now.Add(10*day)), late(now.Add(50*day)), late(now.Add(200*day))`. Keep every assertion; add `assert.NotContains(t, body, near.AddDate(0, 0, 1).Format("2006-01-02"), "the UTC date, not the machine's")`. Rewrite the comment above the test (R67 Ruling 6).
- [ ] **Step 2: Run to verify it fails.** `TZ=Asia/Tokyo go test -race -count=1 -tags integration -run 'TestLicenseListShowsEndDatesAndExpiryFilter$' ./internal/vconsole/web/`
  Expected: FAIL (the page prints the next day). Then without `TZ`: PASS (the machine is on GMT).
- [ ] **Step 3: Implement** the template changes.
- [ ] **Step 4: Run.** `TZ=Asia/Tokyo go test -race -count=1 -tags integration ./internal/vconsole/web/ && go test -race -count=1 -tags integration ./internal/vconsole/web/ && make lint`
  Expected: PASS under both.
- [ ] **Step 5: Commit.** Message: `fix(vconsole): the console's pages print dates in UTC, as its other pages do; the license list test seeds 23:30 UTC dates and runs under TZ=Asia/Tokyo (FX-10, R67)`.

---

### Task 5: The directory lockout test waits for the three held attempts to reach the directory before counting them (FX-11)

**Finding.**
- `internal/api/ldap_integration_test.go:884-958` `TestDirectoryLockoutReservesParallelAttempts` fires 10 parallel sign-ins while the fake directory holds every answer; it proves at most 3 reach the directory, the other 7 get 429 at once, and every slot is released on every outcome.
- The name slot is reserved before any traffic (`internal/api/ldap_handlers.go:98-99`, `:261`); the fake counts a call when `Authenticate` runs (`ldap_fake_test.go:112-114`), later in the same goroutine. Line 907 asserts `assert.Equal(t, 3, s.dir.calls())` the instant the seventh 429 arrives; under load one of the three reserving goroutines may not have reached `Authenticate` yet, so the count reads 2. That is the only instant-count in the test; every later wait already uses `require.Eventually` or a deadline loop.

**Property before and after.** Unchanged: exactly 3 of 10 parallel attempts reach the directory (never a fourth), 7 are refused with 429 without reaching it, and the slots are released. After: "exactly 3" is asserted once the three have arrived (within 5 s) and again after they answered, which also proves no fourth ever arrived.

**Decision.** Channel/condition synchronisation (`require.Eventually`), no bound change.

**Files:** `internal/api/ldap_integration_test.go` only.

- [ ] **Step 1: Change** line 907 to `require.Eventually(t, func() bool { return s.dir.calls() == 3 }, 5*time.Second, time.Millisecond, "exactly 3 attempts reach the directory")`. After the loop that collects the three 401s (line 921), add `assert.Equal(t, 3, s.dir.calls(), "no later attempt reached the directory")`. Update the comment above the test (R67 Ruling 7).
- [ ] **Step 2: Run.** `go test -race -count=3 -tags integration -run 'TestDirectoryLockout' ./internal/api/ && make lint`
  Expected: PASS.
- [ ] **Step 3: Commit.** Message: `test(api): the parallel lockout test waits for the three reserved attempts to reach the directory before counting them (FX-11, R67)`.

---

### Task 6: The engine's first send re-checks the service policy's `deployment.auto_deploy` for automatic deployments (FX-12)

**Finding** (the item is **not** satisfied by R65's code):
- `inventory.DeploymentMaterial` (`internal/inventory/deployment_records.go:299`) is the engine's first-send read (`internal/jobs/deployjobs/deploy.go:212`, `DeploymentMaterial(ctx, d.ID, true)`) for every deployment kind, Key Vault included. Its unsent block (`if !m.Recorded`, lines 378-388) re-judges revocation and the R49 trust (`checkDeploymentTrust`). The ACME planner's queued deployments are re-judged further down (`acmeDeployPrecheck`, `acme_autodeploy.go:525-557`) and the Key Vault ones in `KVDeployPrecheck` (`kv_material.go:203-260`). None of these reads the policy: `grep -n "LoadPolicy\|AutoDeployForbidden" deployment_records.go kv_material.go acme_autodeploy.go` finds only the planners' marks (`acme_autodeploy.go:278`, `kv_autodeploy.go:298`). `scoped-access.md:387` (Ruling 11) and `:404` say so explicitly.
- Intended behaviour (design §7.3 row `deployment.auto_deploy`; §5.6 "checked again by the deployment engine at the first send"; rulings Phase 5 Ruling 10 "judged on the source's service": the vault's for Key Vault, the ACME certificate's for ACME; Ruling 11 "Deploy now is never held"): an **automatic** deployment queued before the policy forbade automatic deployment must not go; a person's must.
- Rollouts (R65): a person's rollout inserts wave 2 with `Trigger: "manual"` (`internal/inventory/canary_advance.go:683`), so it is never judged. An automatic rollout's wave-1 deployments carry the planner's trigger and are judged at their own first send; wave 2 of an automatic rollout is the planner's next plan, which the policy already holds. A `holding` deployment has been sent (`m.Recorded`), so the block does not run for it; the canary releases or reverts it. The check therefore belongs in the unsent block of `DeploymentMaterial` and nowhere in the canary code.
- Engine mapping: `deployjobs.kvRefusals` (`kv.go:107-139`) turns inventory refusals from `DeploymentMaterial` into closed reasons (`deploy.go:220-223`, `kvRefusal`). `inventory.NeutralDeploymentReasons()` (`kv_autodeploy_plan.go:157-164`) lists the reasons both planners do not count toward their three-failure stop (`acme_autodeploy_plan.go:186,207`, `kv_autodeploy_plan.go:363`); `TestEveryNeutralReasonCanBeProducedByTheEngine` (`kv_test.go:1114`) requires every neutral reason to have a `kvRefusals` row.
- The closed reason `service.auto_deploy_forbidden` is `ALC-SVC-0013` in the catalogue, with EN/TR texts (`locales/common/en.json:98-102`); the deployment's `error` carries it as `service.untrusted` is carried today. `inventory.ReasonAutoDeployForbidden` already exists (`errors.go:97`) as the planners' attention code; `authz.ErrAutoDeployForbidden` exists (`authz/policy.go:131`).

**Files:**
- `internal/inventory/errors.go`: `var ErrAutoDeployForbidden = authz.ErrAutoDeployForbidden` with a doc comment next to `ErrServiceUntrusted` (line 88): the policy of the source's service forbids automatic deployment; an automatic deployment refused for it at its first send ends with `ReasonAutoDeployForbidden`.
- `internal/inventory/deployment_records.go`:
  - in the `!m.Recorded` block, after `checkDeploymentTrust`: `if err := checkAutoDeployPolicy(ctx, s.pool, d); err != nil { return Material{}, err }`;
  - new `func checkAutoDeployPolicy(ctx context.Context, q db.Querier, d Deployment) error` after `checkDeploymentTrust`: returns nil unless `d.Trigger == TriggerACMERenewal || d.Trigger == triggerKVRenewal`; reads the source service in one query: `SELECT coalesce((SELECT v.service_id FROM bindings b JOIN targets v ON v.id = b.kv_target_id WHERE b.id = $2), (SELECT ac.service_id FROM acme_orders o JOIN acme_certificates ac ON ac.id = o.acme_certificate_id WHERE o.certificate_id = $1 ORDER BY o.finished_at DESC NULLS LAST LIMIT 1), (SELECT c.service_id FROM certificates c WHERE c.id = $1))` with `d.CertificateID, d.BindingID` (adapt the column names and the nullable binding id to the real schema; read the tables first); then `p, err := authz.LoadPolicy(ctx, q, source)`; `return p.CheckAutoDeploy()`. Doc comment: design §7.3 at an automatic deployment's first send (R67); judged on the source's service as the planners judge it; a person's deployment, Deploy now, a drift repair and a rollout's second wave are not judged.
- `internal/inventory/kv_autodeploy_plan.go` `NeutralDeploymentReasons`: add `ReasonAutoDeployForbidden` with the comment "A queued automatic deployment whose source's policy forbade automatic deployment before its first send (R67)".
- `internal/jobs/deployjobs/kv.go` `kvRefusals`: `{inventory.ErrAutoDeployForbidden, inventory.ReasonAutoDeployForbidden}` after the `ErrServiceUntrusted` row, with a comment.
- Tests:
  - `internal/jobs/deployjobs/services_integration_test.go`: `func (e *env) setPolicy(service uuid.UUID, doc string)`, the two statements of `internal/inventory/policy_integration_test.go:25-33` (`INSERT INTO service_policies … SELECT id, policy_version + 1, $2::jsonb, now() FROM services WHERE id = $1`; `UPDATE services SET policy_version = policy_version + 1 WHERE id = $1`) on `e.db.Owner`.
  - `internal/jobs/deployjobs/acme_integration_test.go` `TestACMEQueuedDeploymentIsJudgedAgain` (line 400): a row `{"the service's policy forbade automatic deployment", func(w *acmeWorld, _ inventory.ACMECertificate, _, _ uuid.UUID) { w.setPolicy(w.defaultService(), `{"schema":1,"deployment":{"auto_deploy":"forbidden"}}`) }, inventory.ReasonAutoDeployForbidden}`. The table's body already asserts failed status, the reason, neutrality, no server command, no write, the served fingerprint unchanged and no `deployment.started` audit row.
  - `internal/jobs/deployjobs/kv_integration_test.go`: `TestKVAutoDeployForbiddenWhileQueued`, modelled on `TestKVAutoDeploySwitchedOffWhileQueued` (line 304): bind, switch automatic deployment on, `id := w.deploy(b, false)[0]`, set `trigger = 'kv_renewal'` by hand, `w.setPolicy(w.defaultService(), …forbidden…)`, `d := w.settle(id)`; assert `DeployStatusFailed`, `ErrorCode == inventory.ReasonAutoDeployForbidden`, not one vault call, `w.untouched(s, cmds)`. Then the control: with the policy still forbidden, `id2 := w.deploy(b, false)[0]` (trigger `manual`), `w.settle(id2)` is `DeployStatusSucceeded` (Deploy now is never held).
- Docs:
  - `docs/troubleshooting.md` `ALC-SVC-0013` "Meaning": add "An automatic deployment that was already queued when the policy changed ends with this reason before anything is sent (R67); a deployment a person asked for is not affected."
  - `docs/superpowers/rulings/scoped-access.md`: Ruling 11's "(the engine's first send does not read the policy)" gains "(until R67, `docs/superpowers/rulings/fixes-2026-10-26.md`)"; the "What remains (Phase 5 as built)" line 404 gains "Done in R67."
  - `docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md` lines 1116 and 1164: add "(built in R67)" after the first-send clause.

**Interfaces:**
- Produces: `inventory.ErrAutoDeployForbidden`; `DeploymentMaterial(id, true)` on an unsent `acme_renewal`/`kv_renewal` deployment returns it when the source service's policy forbids automatic deployment. Signatures unchanged.

- [ ] **Step 1: Write the failing tests** (the helper, the ACME row, the KV test) and add the reason to `NeutralDeploymentReasons` first.
- [ ] **Step 2: Run to verify they fail.**
  Run: `go test -race -count=1 -run 'TestEveryNeutralReasonCanBeProducedByTheEngine' ./internal/jobs/deployjobs/`
  Expected: FAIL, "the engine can end a deployment with service.auto_deploy_forbidden".
  Run: `go test -race -count=1 -tags integration -run 'TestACMEQueuedDeploymentIsJudgedAgain|TestKVAutoDeployForbiddenWhileQueued' ./internal/jobs/deployjobs/`
  Expected: FAIL: the new ACME row and the KV test see `succeeded` (the deployment went ahead) and a server write.
- [ ] **Step 3: Implement** the error alias, `checkAutoDeployPolicy`, the `kvRefusals` row and the docs.
- [ ] **Step 4: Run.** `go test -race -count=1 ./internal/inventory/ ./internal/jobs/... ./internal/api/ && go test -race -count=1 -tags integration ./internal/jobs/deployjobs/ && go test -race -count=1 -tags integration ./internal/inventory/ -run 'Policy|AutoDeploy|Canary|Rollout' && make lint docs-check`
  Expected: PASS, including `TestEveryInventoryRefusalOfTheVaultStepHasAReason` (the new check is not in `kv_material.go`, so its AST scan is unchanged), the canary suites (wave 2 is `manual`), and `TestDeploymentAcrossServicesNeedsATrust`.
- [ ] **Step 5: Commit.** Message: `feat(inventory): an automatic deployment queued before its service's policy forbade automatic deployment ends with service.auto_deploy_forbidden at its first send, before any server or vault contact; the planners count it as no failure (design §7.3; FX-12, R67)`.

---

### Task 7: Decision R67, test IDs, traceability, the changelog, and the closed items' markers (including the Windows ports verdict)

**Finding, Windows test ports** (item B; verified at `9be0c32e`): `cmd/alice-winhelper/*_windows_test.go` never listen: `grep -n "net.Listen\|Listen(\|httptest" cmd/alice-winhelper/*_windows_test.go` finds nothing. The ports `45301`-`45399` are http.sys SSL records and IIS site bindings written with `netsh`/`appcmd` (`emulator_fidelity_windows_test.go:367-383` `addBinding`, `httpapi_windows_test.go:181-238`), served by IIS, and the ranges are themselves part of what the tests prove: the dump is filtered to the twin's ports (`emulator_fidelity_windows_test.go:45,381`), the W2/W3 fixtures assert theirs (`fidelity_write_windows_test.go:130-131`), and `TestRealRunnerIsClean` (`zz_runner_clean_windows_test.go:34`) proves no record is left in `45330`-`45398`. A system-chosen port would need a probe-then-release (`net.Listen("tcp", ":0")`, close, then `netsh` on that number), which reopens the race it means to close and dissolves the range proofs. Windows' ephemeral range is `49152`-`65535` (`canary-deployment.md` "Found, not fixed" says so), so the mechanism that took `45422` and `45428` on the Linux runner (an outgoing connection) cannot take `45310`-`45399` on the Windows runner. No test relies on the port through a config file or the emulator (`cmd/alice-fakewindows/main_test.go:278`: "tests listen on random ports"). Verdict: not applicable; closed with this evidence (coordinator precision C3). The cross-compile checks below only prove nothing in that package changed.

**Files:**
- `docs/superpowers/specs/alice-v1/00-decisions.md`: an R67 entry after R66 (line 166) in R66's form, naming: the batch's items; no migration, no new error code or permission; the engine's first-send re-check (`service.auto_deploy_forbidden` as a closed reason, automatic triggers only); the robustness changes; the Windows ports verdict; tests `FX-07`..`FX-12` (`06-quality.md` §24.11).
- `docs/superpowers/specs/alice-v1/06-quality.md`: §24 intro line (238) gains "fixes batch 2, R67: FX-07..FX-12, §24.11"; new §24.11 after §24.10 with the table below.
- `test/matrix/traceability.json`: rows `FX-07`..`FX-12` (format as `FX-03`/`FX-05`, lines 2717-2743):
  - FX-07: `internal/acme/solver/dnsapi/cloudflare:TestDeadContextAndDeadline`, `internal/acme/solver/dnsapi/cloudflare:TestZeroSendsNothing`, `internal/acme/solver/dnsapi/route53:TestContextEnds`
  - FX-08: `internal/providers/nginx/nginxconf:TestHostileSizesFinishQuickly` plus the two apacheconf tests changed in Task 2
  - FX-09: `web/src/components/SavedViews.test.tsx:holds only menu items in the open menu`, `web/src/pages/AcmeCertificatePage.test.tsx:deploys now to the chosen websites`
  - FX-10: `internal/vconsole/web:TestLicenseListShowsEndDatesAndExpiryFilter`
  - FX-11: `internal/api:TestDirectoryLockoutReservesParallelAttempts`
  - FX-12: `internal/jobs/deployjobs:TestACMEQueuedDeploymentIsJudgedAgain`, `internal/jobs/deployjobs:TestKVAutoDeployForbiddenWhileQueued`, `internal/jobs/deployjobs:TestEveryNeutralReasonCanBeProducedByTheEngine`
- `docs/security/traceability.md`: regenerated with `go run ./tools/matrixcheck -update`.
- `CHANGELOG.md`: a new top section "Unreleased — Fixes batch 2 (R67)": **Changed**: "An automatic deployment that was still queued when its service's policy forbade automatic deployment now ends with `service.auto_deploy_forbidden` before anything is sent, instead of going ahead; deployments a person asked for are unchanged." **Fixed**: "The vendor console's pages print dates in UTC on every page."
- `docs/superpowers/rulings/canary-deployment.md` "Found, not fixed": the ports entry gains "Closed in R67 as not applicable (`docs/superpowers/rulings/fixes-2026-10-26.md`): the ports are IIS/http.sys bindings, not listeners, and lie outside Windows' ephemeral range."
- `docs/superpowers/rulings/fixes-2026-10-25.md`: F2 and F3 gain "treated in R67 (`fixes-2026-10-26.md`)"; the Deferred first-send item gains "done in R67".

| ID | Case | Expected |
|---|---|---|
| FX-07 | A DNS API call with a dead context, or whose deadline ends during the provider's delay; a call after `Zero` | `context.Canceled` / `context.DeadlineExceeded`; after `Zero` a permanent provider error and no request, on a fake with nothing in flight |
| FX-08 | Hostile Nginx and Apache configurations under the race detector and coverage instrumentation | Each refused within its bound × 10 (race) × 5 (coverage); a cubic regression still fails |
| FX-09 | A Vitest page test on a loaded machine | Passes within 60 s; a hang still fails |
| FX-10 | The vendor console's license pages on a machine in any time zone | End dates printed as UTC dates; the 30/90-day filters and order unchanged |
| FX-11 | Ten parallel directory sign-ins for one name while the directory holds | Exactly 3 reach the directory, 7 are refused with 429 at once; every slot released |
| FX-12 | An automatic (ACME renewal or Key Vault) deployment queued before its service's policy forbade automatic deployment | Ends `service.auto_deploy_forbidden` before any server or vault contact; the planner counts it as no failure; a person's deployment under the same policy goes ahead |

- [ ] **Step 1: Write** the entries.
- [ ] **Step 2: Run.** `go test ./tools/matrixcheck/ && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/... && GOOS=windows go test -tags alicetest -c -o /dev/null ./cmd/alice-winhelper/`
  Expected: PASS; every FX ID maps to existing tests; the Windows package still cross-compiles unchanged (the GitHub `windows.yml` run on the branch is the Windows-side evidence; record its URL in the rulings file).
- [ ] **Step 3: Commit.** Message: `docs: decision R67, test IDs FX-07..FX-12 with their traceability, the Windows test ports closed as not applicable, and the changelog of fixes batch 2 (R67)`.

---

### Task 8: Gates, final review and the rulings file

**Files:**
- Create `docs/superpowers/rulings/fixes-2026-10-26.md` in the form of `fixes-2026-10-25.md` (coordinator rulings at approval, Rulings, Final review fixes, Owner to confirm, Deferred, Found not fixed, Gate evidence), containing the [Rulings](#rulings-each-goes-into-docssuperpowersrulingsfixes-2026-10-26md) below plus execution rulings, each with its reason and cost if wrong; the Task 1-2 measurements; the `windows.yml` run URL.

- [ ] **Step 1: Full gate.** First `pgrep -af 'playwright|make ci|go test'` must answer nothing. Then `make ci E2E_PROJECT=alice-e2e-fx2 ALICE_E2E_PORT=9981`.
  Expected: exit 0. Record the e2e totals, the coverage floors met (quote `internal/inventory`, `internal/jobs`, `internal/api`, `internal/vconsole/web` if floored), and `make matrix-check MATRIXCHECK_FLAGS=-strict` totals.
  If the machine needs it, run in stages as R64 and R65 did: `make lint test coverage perf test-backup-cycle test-ssh build release-symcheck i18n-check web-lint web-coverage vuln secrets-scan fs-scan`, then `E2E_PROJECT=alice-e2e-fx2 ALICE_E2E_PORT=9981 make e2e-up e2e-hardening-check e2e`, `E2E_PROJECT=alice-e2e-fx2 make e2e-down`, then `make image-check image-scan`. A failure caused by another branch or by the machine is recorded with its evidence (`-v` output for any Go test) and rerun, never hidden.
- [ ] **Step 2: Final review.** `superpowers:requesting-code-review` over `main..fixes-2` with a fresh reviewer given the code, not this plan's conclusions. Fix every Critical and Important finding in its own commit (subject ending `(R67)`), re-run the affected tests, list declined Minors with reasons.
- [ ] **Step 3: Write** the rulings file and the markers. Run: `make docs-check`. Expected: PASS.
- [ ] **Step 4: Commit.** Message: `docs(rulings): fixes batch 2 rulings, owner items and gate evidence (R67)`.

---

## Files touched for the merge order

| Task | Files |
|---|---|
| 1 | `internal/acme/solver/dnsapi/cloudflare/cloudflare_test.go` |
| 2 | `internal/providers/nginx/nginxconf/slowdown_test.go` (new), `internal/providers/nginx/nginxconf/nginxconf_test.go`, `internal/providers/apacheconf/slowdown_test.go` (new), `internal/providers/apacheconf/parse_test.go` |
| 3 | `web/vite.config.ts` |
| 4 | `internal/vconsole/web/templates/{licenses,home,request_emergency,request}.html`, `internal/vconsole/web/pages_integration_test.go` |
| 5 | `internal/api/ldap_integration_test.go` |
| 6 | `internal/inventory/{errors,deployment_records,kv_autodeploy_plan}.go`, `internal/jobs/deployjobs/kv.go`, tests `internal/jobs/deployjobs/{services,acme,kv}_integration_test.go`, `docs/troubleshooting.md`, `docs/superpowers/rulings/scoped-access.md`, `docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md` |
| 7 | `docs/superpowers/specs/alice-v1/{00-decisions,06-quality}.md`, `test/matrix/traceability.json`, `docs/security/traceability.md`, `CHANGELOG.md`, `docs/superpowers/rulings/{canary-deployment,fixes-2026-10-25}.md` |
| 8 | `docs/superpowers/rulings/fixes-2026-10-26.md` (new) |

## Rulings (each goes into `docs/superpowers/rulings/fixes-2026-10-26.md`)

1. **One decision, R67, for the batch.** No migration, no new code or permission, no protocol bump. Test IDs `FX-07`..`FX-12` in a new §24.11. Cost if wrong: none functional.
2. **The Cloudflare Zero check runs on a fake that has never received a request.** The fake records a request before applying its delay (`fakecloudflare/api.go:113-119`); the client gives up at 100 ms; a starved server goroutine recorded late and moved the count the test had just read. Cost if wrong: none; the three properties are still asserted.
3. **`route53:TestContextEnds` is left.** The fake honours the request context and `dnsapi.Do` returns `ctx.Err()`; no retry, no load-dependent step. Two failures, no saved message. The next failure is captured with `-v` before anything else. Cost if wrong: one more rerun.
4. **The Nginx and Apache hostile-size bounds take haproxyconf's coverage factor (×5 under `testing.CoverMode()`).** Cost if wrong: a 5× slower parser regression under coverage passes; it still fails under plain `-race` (20 s) and the cubic case fails everywhere.
5. **Vitest's hang bound is 60 s, globally.** Passing tests are not slower; a hang waits longer. Only `SavedViews` runs axe, once, as its purpose. Cost if wrong: a hung web test costs 40 s more per occurrence.
6. **The vendor console prints UTC dates on every page.** pgx returns `timestamptz` in the process's zone; the templates formatted that; the console's other pages already print UTC. The test seeds 23:30 UTC and runs under `TZ=Asia/Tokyo`. Cost if wrong: a reader east of UTC sees the UTC date of an end-of-day expiry. **Owner to confirm.**
7. **The lockout test waits (≤ 5 s) for the three reserved attempts to reach the directory, then asserts exactly 3 twice.** The slot is reserved before traffic (`ldap_handlers.go:261`); the fake counts at `Authenticate`. Cost if wrong: none.
8. **The engine's first send refuses an automatic deployment whose source service's policy forbids automatic deployment**, with `service.auto_deploy_forbidden` (`ALC-SVC-0013`), judged on the source's service as the planners judge it (the vault's, the ACME certificate's), for triggers `acme_renewal` and `kv_renewal` only; a person's deployment, Deploy now, a drift repair and a rollout's wave 2 (`manual`) are never judged; a holding wave-1 deployment is already sent and untouched. The planners count the reason as neutral. This amends R55 Ruling 11 ("Deployments queued before the policy changed are not stopped"). Cost if wrong: an automatic deployment queued seconds before an Administrator forbade automatic deployment now ends instead of going; the planner resumes it when the policy allows. **Owner to confirm.**
9. **The Windows helper's fixed test ports are not changed.** They are IIS/http.sys binding ports outside Windows' ephemeral range, the ranges are part of the cleanup proof, and no listener exists to take `:0`. Cost if wrong: a rare "address in use" on the Windows runner if another process binds `45301`-`45399`.
10. **The e2e held-chain journey is left.** It has no fixed wait: `heldUntilShown` reloads inside `drainUntil`'s 90 s `toPass` (`web/e2e/helpers.ts:901-910`, `phase5.spec.ts:357-361`). Cost if wrong: one Playwright retry.

## Owner to confirm

1. Ruling 8: an automatic deployment already queued when the policy changed now ends with `service.auto_deploy_forbidden`; R55 Ruling 11 said such deployments were not stopped.
2. Ruling 6: the vendor console shows UTC dates (an expiry at 23:30 UTC shows the UTC day everywhere).

## Deferred (recorded in the rulings file)

- `route53:TestContextEnds` (Ruling 3) and the e2e held-chain journey (Ruling 10): left, with the capture rule.
- Everything in R66's "Deferred" list is unchanged except the first-send item, done here.
- The ALC-SVC-0013 catalogue `cause` text ("those switched on before wait until the policy allows it again") stays: it describes the planners' hold, which is still true; the troubleshooting entry gains the queued-deployment sentence.

## Found, not fixed

- **`fakeroute53` counts (`s.count`) after `takeFault`**, like fakecloudflare records before the delay; no route53 test asserts a count after a timed-out request today.
- **Other templates that format pgx times without `.UTC()`** outside `internal/vconsole/web` were not surveyed (the main API serialises times itself).
