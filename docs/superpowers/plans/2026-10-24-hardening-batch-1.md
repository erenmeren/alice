# Hardening Batch 1 (Incident List, Incident E-mails, Revocation Checks, Helper Labels, Two API Fixes) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close six owner-approved items (2026-10-24, "yap 6'yı"):
- D2: an incident list page.
- D3: incident e-mails, sent once each.
- D5: OCSP/CRL checks of certificates Alice did not revoke itself.
- KI-39: the helper's PEM label gap.
- The unreachable `!vaultSide` branches of `bindingChange`.
- The `ErrTargetDisabled` code mismatch.

**Architecture:** Mostly additive, with no new top-level module apart from the revocation checker.
- D2 extends the existing incident list API with a state filter and keyset paging, and adds an `/incidents` page.
- D3 queues e-mails inside the transaction of the incident's state change, so each change sends exactly one. A new `incident_notices` table (migration `00033`) replaces the outbox lookup that let the W3 store notice go out twice.
- D5 adds a pure checker package `internal/revocation`, with its own guarded HTTP fetch, a fake OCSP responder and a fake CRL server. A periodic inventory task `revocation.check` records results in `revocation_checks` (migration `00034`). A revocation the authority signed marks an inventory certificate revoked for good, so nothing deploys it again and an ACME certificate renews at once. It also sends an e-mail.
- KI-39 is a helper fix to 1.11.0 with protocol 11 unchanged. Items 5 and 6 are small API and inventory corrections, each locked by a test.

**Tech Stack:** Go 1.27.3, pgx/v5, goose migrations, `golang.org/x/crypto/ocsp` (already in the module at v0.57.0; first use), `crypto/x509` CRL parsing, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright.

**Spec:** Owner approval of 2026-10-24 for these six items. The items come from:
- `docs/superpowers/rulings/certificate-revocation.md` §"Not done / deferred" D2, D3 and D5, and ruling 16 ("No e-mail is sent for an incident in this version").
- `docs/superpowers/rulings/prod-readiness-2026-10-16.md` REM-4 follow-up, and `SECURITY-REPORT.md` KI-39.
- `docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md` §5.6 (the row "Removing a binding or one of its locations: **either** side's permission"), §7.2 (e-mail recipients) and §5.4 (route scoping).
- The W3 owner items in `docs/superpowers/rulings/windows-iis.md` "Owner items (W3)" (the duplicate store notice).
- The memory note "bindingChange !vaultSide unreachable (widen route or drop), ErrTargetDisabled codeOf mismatch".

The format model is `docs/superpowers/plans/2026-10-23-windows-w4-ci-and-release.md`.

**Decision:** R64 "Hardening batch 1" (R63 is the last entry of `docs/superpowers/specs/alice-v1/00-decisions.md`). **Size:** L, 12 tasks. **Migrations:** `00033_incident_notices.sql`, `00034_revocation_checks.sql`.

## Global Constraints

- **Branch.** Worktree branch `hardening-1`, cut from `main` at `961f3bbb` or later. The first commit is this plan file, copied unchanged. Never switch branches inside a task. Take `main` in with `git merge main`, never rebase. Never push `main`, never open a pull request; the coordinator merges and pushes.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R64)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R64)`.
  - New files: run `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (an untracked binary at the root) or `docs/security/reviews/*`.
  - `.gitleaksignore` is pinned to commit hashes, so never rebase, squash or amend a pushed commit.
- **Migrations.** `migrations/frozen_test.go` pins `00001`-`00017`; never edit any existing migration. The new files are `00033_incident_notices.sql` (Task 6) and `00034_revocation_checks.sql` (Task 8). After them, the next free number is `00035`. Every new relation and column grant goes into `migrations/roles_integration_test.go`'s expected-grant table.
- **Error codes.** New: `ALC-CRT-0020`..`ALC-CRT-0025` (Task 9; the last today is `ALC-CRT-0019`). No new `ALC-INC-*` code (the last stays `ALC-INC-0013`). Each new code gets EN+TR `errors.<reason>.title`/`.text` in `locales/common/{en,tr}.json` and a section in `docs/troubleshooting.md`.
- **Test IDs.** `HB-01`..`HB-17`, in a new `docs/superpowers/specs/alice-v1/06-quality.md` §24.8 "Hardening batch 1 (R64)" with rows in `docs/security/traceability.md` (Task 11).
- **Ports.** The fake revocation servers bind `127.0.0.1:0` behind a dial seam (Task 7). A fixed port, if one is ever needed, is taken from `45400`-`45419`.
- **e2e.** `E2E_PROJECT=alice-e2e-hb1 ALICE_E2E_PORT=9978 make e2e-up e2e; E2E_PROJECT=alice-e2e-hb1 make e2e-down`. One new spec, `web/e2e/hardening1.spec.ts`, in EN and TR. Docker-based Go runs (testcontainers, `make coverage`, `make test-ssh`) and Playwright never run at the same time, and neither runs while another `make ci` on the machine is active.
- **Coverage floors** (`coverage-floors.json`; never lower one). New floor: `"alice/internal/revocation": 95`.
- **Archtest.** New rules (Task 7):
  - `"alice/internal/revocation": {"alice/internal/platform/netaddr", "alice/internal/platform/clock"}`.
  - `"alice/internal/testutil/fakerevocation": {"alice/internal/testutil/pki", "alice/internal/platform/clock"}`.
  - `"alice/internal/revocation"` added to the `alice/internal/inventory/...` list.
  - `TestAllowed` rows for each.
- **Helper.** Any helper change runs `make helper`, the helper's own suites and the emulator fidelity tests. `make test-ssh` runs in Task 12 when the machine is free.
- **Locales.** EN and TR stay identical in keys and placeholders (`make i18n-check`). The web's job-type label guard needs `jobs.types.revocation.check` for the new literal `Register("revocation.check", ...)`.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `go test -race -count=1 ./<pkgs>`
  - Integration: `go test -race -count=1 -tags integration ./<pkgs> -run <name>`. This uses Docker and must never run while Playwright runs.
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make docs-check`, `make authz-doc` (the result is committed); final `make coverage` and `make ci`.
  - web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`

## Review Focus

1. **A revocation check makes Alice send requests to addresses an attacker chose.** A certificate found on a server or by discovery names any OCSP or CRL address it likes: loopback, the cloud metadata address, an internal admin port, a redirect, or a 2 GB body. A reasonable person expects Alice to refuse those addresses and never send a request there. Tests: Task 7 `TestFetchRefusesForbiddenAddresses`, `TestFetchCapsTheAnswer`, `TestFetchNeverFollowsARedirect`.
2. **A responder that is down, slow or answering garbage must never mark a certificate revoked**, and an `unknown` answer must not either. Revocation is final in Alice (Z1022), so a false "revoked" stops every deployment of that certificate for good. Tests: Task 7 `TestCheckOCSPAnswers` (rows `wrong signer`, `garbage`, `unknown`, `stale`) and `TestCheckCRL` (rows `bad signature`, `other issuer`, `stale not listed`); Task 8 `TestRevocationRunNeverMarksOnFailure`.
3. **Incident e-mails go out exactly once per state change, and still go out while the licence is locked.** Two engines advancing the same incident, a rolled-back transaction, a retry that fails again, and outbox pruning must not add or lose a mail. Tests: Task 6 `TestIncidentNeedsAttentionMailedOncePerEntry`, `TestIncidentCompletedMailedOnce`, `TestIncidentMailsInLock`, `TestCompromisedInStoreNoticeOnceUnderRace`, `TestCompromisedInStoreNoticeSurvivesOutboxPruning`.
4. **The incident list shows a scoped person only the incidents of their services, on every page and under every filter.** Tests: Task 4 `TestListIncidentsFiltersAndPagesWithinReach`; Task 5 Vitest `pages through incidents with Load more`.
5. **A website-side person may release their own websites from a Key Vault binding and nothing else.** They may not add a website, and may not release a website of another service they can see. Tests: Task 2 `TestPatchBindingFromTheWebsiteSide`.

---

### Task 1: `ErrTargetDisabled`: incident places get `target.disabled`, locked against the API catalogue (item 6)

**Finding.** Both catalogue entries already agree: `internal/api/errors.go:112` maps `ErrTargetDisabled` to `ALC-TGT-0006` `target.disabled`, and `internal/jobs/sshkeyjobs/deploy.go:332` uses `"target.disabled"`. The mismatch is in the incident engine:
- `internal/inventory/incidents_engine.go` `isRefusal` lists `ErrTargetDisabled` as a refusal that belongs to a location.
- `codeOf` has no case for it and answers `internal.unexpected`.

So an incident place whose server is disabled is stored with `error_code = 'internal.unexpected'` (the page says "unexpected error") instead of `target.disabled`. Nothing ties `codeOf` or `deployRefusals` to the API's reasons, which is how the gap went unseen.

**Files:**
- Modify: `internal/inventory/incidents_engine.go`:
  - add a `case errors.Is(err, ErrTargetDisabled): return "target.disabled"`;
  - export `isRefusal` as `IsIncidentRefusal` and `codeOf` as `IncidentRefusalCode`, updating the callers in the same file.
- Modify: `internal/jobs/sshkeyjobs/deploy.go`: add `func DeployRefusalReasons() map[error]string`, a copy of `deployRefusals` keyed by the sentinel.
- Create: `internal/api/errors_refusal_codes_test.go`.
- Test: `internal/inventory/incidents_more_integration_test.go` (one test).

**Interfaces:**
- Produces:
  - `inventory.IsIncidentRefusal(err error) bool`.
  - `inventory.IncidentRefusalCode(err error) string`.
  - `sshkeyjobs.DeployRefusalReasons() map[error]string`.

- [ ] **Step 1: Write the failing tests.**
  - `internal/api/errors_refusal_codes_test.go`, `TestIncidentRefusalCodesMatchTheCatalogue`. For each of these sentinels: `inventory.ErrNotFound`, `ErrLocationUnsupported`, `ErrNginxConfigInvalid`, `ErrLocationNeedsDiscovery`, `ErrChainUnconfirmed`, `ErrCertificateExpired`, `ErrCertificateNotYetValid`, `ErrNoPrivateKey`, `ErrUnsupportedKey`, `ErrCertificateRevoked`, `ErrCertificateCompromised`, `ErrTargetDisabled`:
    - `require.True(t, inventory.IsIncidentRefusal(err))`;
    - `ec, _, ok := classify(err)`; `require.True(t, ok)`;
    - `assert.Equal(t, ec.Reason, inventory.IncidentRefusalCode(err), name)`.

    Then two more checks:
    - `IncidentRefusalCode(&inventory.KeyTypeMismatchError{...}) == "incident.not_deployable"`, the one documented exception.
    - Every code `IncidentRefusalCode` can return has a code in `AllErrorCodes()` (`codeForReason` is not `ErrUnexpected`).
  - Same file, `TestSSHKeyDeployRefusalsMatchTheCatalogue`: for each `err, reason` of `sshkeyjobs.DeployRefusalReasons()`, `classify(err)` is ok and `ec.Reason == reason`. Exception: `inventory.ErrNotAServer`, whose job reason `system.not_found` equals `ErrNotFound.Reason`; assert that equality explicitly.
  - `internal/inventory/incidents_more_integration_test.go`, `TestIncidentPlaceOnADisabledServerFailsWithTargetDisabled`:
    - start an incident with one pending place;
    - set the server's `disabled_at`;
    - advance;
    - the place is `failed` with `error_code = "target.disabled"`.
- [ ] **Step 2: Run them to verify they fail.**
  Run: `go test ./internal/api/ -run 'RefusalCodes|DeployRefusals'`
  Expected: FAIL. The functions are undefined; once they exist, `ErrTargetDisabled` still gives `internal.unexpected`.
- [ ] **Step 3: Implement** the case and the exports. Add no other behaviour.
- [ ] **Step 4: Run the tests.**
  Run: `go test -race -count=1 ./internal/api/ ./internal/inventory/ ./internal/jobs/sshkeyjobs/ && go test -race -count=1 -tags integration ./internal/inventory/ -run TestIncidentPlaceOnADisabledServer`
  Expected: PASS.
- [ ] **Step 5: Commit.** Message: `fix(inventory): an incident place on a disabled server fails with target.disabled, not internal.unexpected; the engine's and the key deploy job's reasons are locked to the API catalogue (R64)`.

---

### Task 2: `bindingChange`: the website side may release its own websites (item 5)

**Finding.** The PATCH route is `scopeCross` with `by(services.KindKVBinding, "id")`. `checkResource` therefore lets a scoped caller through only when `permReach.Contains(res.Owning)`, and the owning service of a KV binding is the vault's (`internal/authz/services/resolve.go` `KindKVBinding`). A caller with a global grant returns early in `bindingChange` (`reach.All()`). So `vaultSide` is always true there, and both `!vaultSide` branches (refuse an addition; refuse releasing a website the caller has no right on) are unreachable.

The design wants them reachable. §5.6 says "Removing a binding or one of its locations: **either** side's permission: the receiving service can always detach its own server", and the handler's own comment describes the website-side caller. So the route is widened, not the branch dropped (Ruling 9).

**Files:**
- Modify: `internal/api/bindings_handlers.go`:
  - the PATCH route's resolver becomes `&resolver{kind: services.KindKVBinding, param: "id", anyVisible: true}`;
  - the route comment says why (design §5.6 "either side").
- Modify: `internal/api/bindings_targets_cov_test.go` (new test); `docs/authz-matrix.md` (regenerated by `make authz-doc`).

**Interfaces:**
- Consumes: the existing `covBScoped`, `covBResolve` and `covBBinding` helpers.

- [ ] **Step 1: Write the failing test** `TestPatchBindingFromTheWebsiteSide`.
  - Set up a person with `rbac.Operator` on `svcPay` only.
  - `ResolveFn` answers `KindKVBinding` as `Owning: svcDefault` (the vault), `Visible: [svcDefault, svcPay]`.
  - The binding has `locationA`/`locationB` on `targetID` (svcPay) and `covBLocationC` on `covBOtherTarget` (svcDefault).
  - `fakeServices.targetServices` maps `covBOtherTarget` to `svcDefault`, and `Visible` includes svcDefault, so the caller sees website C.
  - Cases:
    - (a) Releasing `locationB`, body `[locationA, covBLocationC]`, is 200, and the inventory receives `[locationA, covBLocationC]`.
    - (b) Adding a new location `locationD` of svcPay is 403 `ALC-AUTH-0002`, and the inventory is not called.
    - (c) Releasing `covBLocationC` (seen, but on svcDefault where the caller holds nothing) is 403, and the inventory is not called.
    - (d) The same person against a binding resolved `Visible: [svcDefault]` only gets 404 (guard), unchanged.
- [ ] **Step 2: Run it to verify it fails.**
  Run: `go test ./internal/api/ -run TestPatchBindingFromTheWebsiteSide`
  Expected: FAIL. Cases (a)-(c) answer 403 from the guard (`scope`), not from `bindingChange`.
- [ ] **Step 3: Implement** the resolver change. Keep `bindingChange` as it is: its branches are now reachable.
- [ ] **Step 4: Run the tests.**
  Run: `go test -race -count=1 ./internal/api/ && make authz-doc && git diff --stat docs/authz-matrix.md`
  Expected: PASS. The matrix shows the PATCH row's scope note. `TestRouteScopes` counts are unchanged (still `scopeCross`). `internal/api:TestScopedIDOR...` (integration) runs in Task 12.
- [ ] **Step 5: Commit.** Message: `fix(api): a person of a website's service may release its own websites from a Key Vault binding (design §5.6 either side); the website-side branches of bindingChange are reachable and tested (R64)`.

---

### Task 3: Helper 1.11.0: a leaf labelled `TRUSTED CERTIFICATE` or `X509 CERTIFICATE` (KI-39)

**What Nginx reads.** OpenSSL's labels for a certificate are `CERTIFICATE`, `X509 CERTIFICATE` (old) and `TRUSTED CERTIFICATE` (a certificate followed by `X509_CERT_AUX` trust settings).
- Nginx, Apache (mod_ssl) and HAProxy read the first certificate of a file with `PEM_read_bio_X509_AUX`, which accepts all three labels.
- They read the chain with `PEM_read_bio_X509`, which accepts the first two and skips other blocks.

The helper reads only `CERTIFICATE`. A labelled leaf is therefore skipped without a warning, and the intermediate reaches Alice as the website's certificate.

The rollback guard's `firstCertificate` (`cmd/alice-helper/rollbackguard.go:79`) has the same gap. A `TRUSTED CERTIFICATE` leaf in a backup makes it compare the intermediate, so a revoked (not compromised) leaf could be restored. This is a defence-in-depth hole of R48 G5, fixed here too.

**Files:**
- Modify: `cmd/alice-helper/nginx.go`:
  - `certBlocks` takes the three labels for the first block and `CERTIFICATE` and `X509 CERTIFICATE` for the rest;
  - the begin and end markers are matched per label;
  - a `TRUSTED CERTIFICATE` body keeps only its first DER element;
  - the doc comment explains each point.
- Modify: `cmd/alice-helper/rollbackguard.go` (`firstCertificate` uses the same leaf rule through a shared `leafDER(p []byte) []byte`).
- Modify: `internal/providers/linuxssh/linuxsshtest/nginx_dump.go` (`certPEMBlocks` mirrors the helper exactly).
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go` (`Version = "1.11.0"`; the protocol comment gains "1.11.0 (R64) reads a leaf labelled TRUSTED CERTIFICATE or X509 CERTIFICATE; protocol unchanged"); `internal/providers/linuxssh/helperproto/helperproto_test.go` (the five `"1.10.0"` assertions).
- Modify docs:
  - `docs/nginx-host-preparation.md`: lines 26, 451, 461 name 1.11.0, plus a paragraph after the 1.6.1 one.
  - `docs/apache-host-preparation.md:74` and `docs/haproxy-host-preparation.md:76`: "this release ships 1.11.0".
  - `docs/troubleshooting.md:284-286`: the `leaf_unreadable` cause adds "or, before 1.11.0, a first certificate labelled TRUSTED CERTIFICATE or X509 CERTIFICATE".
  - `SECURITY-REPORT.md` KI-39 (below).
- Tests: `cmd/alice-helper/nginx_test.go`, `cmd/alice-helper/rollbackguard_test.go`, `cmd/alice-helper/emulator_fidelity_test.go`.

**Interfaces:**
- Produces:
  - `certBlocks(data []byte) (blocks string, dropped, firstDropped bool)` keeps its signature and output shape: blocks re-encoded as `CERTIFICATE`, no new `Problem` value.
  - So `helperproto.Protocol` stays `11` and `MinProtocol` stays `6` (Ruling 8).

- [ ] **Step 1: Write the failing tests.**
  - `nginx_test.go`, `TestCertBlocksReadsTheOpenSSLLeafLabels`, with the leaf and intermediate of `newNginxWorld(t)`:
    - `"X509 CERTIFICATE" leaf + CERTIFICATE intermediate`: `blocks` equals leaf PEM + intermediate PEM, both labelled `CERTIFICATE`, `dropped == false`.
    - `"TRUSTED CERTIFICATE" leaf` (DER of the leaf followed by a minimal `X509_CERT_AUX` `SEQUENCE { SEQUENCE { OID 1.3.6.1.5.5.7.3.1 } }`) + intermediate: `blocks` starts with the leaf's `CERTIFICATE` PEM. The aux bytes appear nowhere in `blocks` (`assert.NotContains` on the base64 of the aux). `dropped == false`.
    - `TRUSTED CERTIFICATE` as the **second** block: dropped (`dropped == true`, `firstDropped == false`), as `PEM_read_bio_X509` skips it.
    - `X509 CERTIFICATE` as the second block: kept.
    - A `TRUSTED CERTIFICATE` first block whose first element is not a certificate, or with nothing after the begin line: `firstDropped == true` (the REM-4 path, `leaf_unreadable`).
    - Mismatched markers (`BEGIN X509 CERTIFICATE` ... `END CERTIFICATE`): treated as unterminated, dropped.
  - Extend `TestCertBlocksNeverReturnAKey` with `"key labelled TRUSTED CERTIFICATE"` and `"key labelled X509 CERTIFICATE"`: `blocks == ""`, dropped.
  - `rollbackguard_test.go`, `TestRollbackGuardReadsATrustedLeaf`: a backup whose certificate file is a `TRUSTED CERTIFICATE` revoked leaf + intermediate, with the leaf's SHA-256 in the forbidden list, is refused (`restore_forbidden`).
  - `emulator_fidelity_test.go`: add the `X509 CERTIFICATE` and `TRUSTED CERTIFICATE` files to the fidelity world of `TestEmulatorFidelityDump`, so the helper and the emulator answer the same.
  - `helperproto_test.go`: `TestHelperVersion111`: `Version == "1.11.0"` and `Protocol == 11`; update the five existing assertions.
- [ ] **Step 2: Run them to verify they fail.**
  Run: `go test ./cmd/alice-helper/ ./internal/providers/linuxssh/... -run 'CertBlocks|RollbackGuardReadsATrusted|EmulatorFidelityDump|HelperVersion'`
  Expected: FAIL.
- [ ] **Step 3: Implement.** Parse the `TRUSTED CERTIFICATE` body with `asn1.Unmarshal(blk.Bytes, &raw)` and keep `raw.FullBytes` only. `x509.ParseCertificate` of that DER must succeed; the remainder is cleared with `clear` and never returned. Clear every refused block's bytes, as today.
- [ ] **Step 4: Run the tests.**
  Run: `go test -race -count=1 -cover ./cmd/alice-helper/ ./internal/providers/linuxssh/... && make helper`
  Expected: PASS. `cmd/alice-helper` stays at or above 90 and `helperproto` at 100.
- [ ] **Step 5: Docs.**
  - The guide's new paragraph: "`alice-helper` 1.11.0 keeps protocol 11 and the same sudoers file. It reads a first certificate labelled `TRUSTED CERTIFICATE` or `X509 CERTIFICATE`, as Nginx does; before, such a file showed its intermediate as the website's certificate. Trust settings after a `TRUSTED CERTIFICATE` are not sent to Alice."
  - `SECURITY-REPORT.md` KI-39: delete the sentence beginning "The helper's leaf check (REM-4) reads only PEM blocks labelled `CERTIFICATE`", the words "and this helper check" in "AUTH-5, VC-1 to VC-4 and this helper check are carried to 1.0.x", and the advice "label every certificate in a file Nginx serves `-----BEGIN CERTIFICATE-----`". Add to the controls column: "`alice-helper` 1.11.0 reads the leaf labels OpenSSL reads (`cmd/alice-helper:TestCertBlocksReadsTheOpenSSLLeafLabels`)."
  - Run `make docs-check`.
- [ ] **Step 6: Commit.** Message: `fix(helper): alice-helper 1.11.0 reads a leaf labelled TRUSTED CERTIFICATE or X509 CERTIFICATE as Nginx does, never the intermediate; the rollback guard reads the same leaf; protocol 11 unchanged (KI-39, R64)`.

---

### Task 4: Incident list API: state filter and keyset paging within the caller's reach (D2, API)

**What exists.** `GET /api/v1/incidents` (`scopeList`, `rbac.Read`, reach applied by `authz.IncidentVisible`) supports `open`, `certificate_id` and `limit`. It is capped at 200, newest first, with no paging and no state filter. The list page needs a state filter and paging; nothing else is missing.

**Files:**
- Modify: `internal/inventory/incidents.go`: `IncidentFilter`, `IncidentCursor`, `IncidentPage`; `ListIncidents` and `ListIncidentsIn` take a filter.
- Modify: `internal/api/incidents_handlers.go` (`listIncidents`, `IncidentService`), `internal/api/incidents_fakes_test.go`, `internal/inventory/db_failure_integration_test.go` (the new call), `api/openapi.yaml` (`/api/v1/incidents`: parameters `state` and `cursor`; `IncidentList` gains `next_cursor: string|null`).
- Tests: `internal/api/incidents_handlers_test.go`, `internal/inventory/incidents_more_integration_test.go`.

**Interfaces:**
- Produces:
  ```go
  type IncidentFilter struct {
      CertificateID *uuid.UUID
      OpenOnly      bool
      State         string          // "" or one of the seven incident states
      Cursor        *IncidentCursor // the last item of the previous page (newest first)
      Limit         int             // 1..MaxIncidentsListed, 0 = 50
  }
  type IncidentCursor struct { CreatedAt time.Time; ID uuid.UUID }
  type IncidentPage struct { Items []Incident; Next *IncidentCursor } // Next nil on the last page
  func (s *Service) ListIncidents(ctx context.Context, f IncidentFilter) (IncidentPage, error)
  func (s *Service) ListIncidentsIn(ctx context.Context, f IncidentFilter, reach authz.Reach) (IncidentPage, error)
  ```
  - The API answer is `{"items": [...], "next_cursor": "<unix ns>.<uuid>" | null}`, using the existing `timeIDCursor`, `parseACMECertCursor` and `cursorParam`.
  - `state` is a closed value. Any other is 422, field `state`, `validate.OneOf`, `values` = the seven states joined by ", ".
  - Order: `created_at DESC, id DESC`. Keyset: `(i.created_at, i.id) < ($c, $id)`. Fetch `limit+1` rows to know whether a next page exists.

- [ ] **Step 1: Write the failing tests.**
  - API (fake): `TestListIncidentsPassesFiltersAndAnswersTheCursor`:
    - `?state=needs_attention&open=true&limit=2&cursor=<valid>` reaches the fake as that filter;
    - a fake page with `Next` gives `next_cursor` equal to `timeIDCursor(...)`;
    - the last page gives `"next_cursor":null`;
    - `?state=broken` is 422 with field `state`;
    - `?cursor=x` is 422 with field `cursor`.
  - Inventory (integration): `TestListIncidentsFiltersAndPagesWithinReach`:
    - five incidents over two services (three in Default, two in Payments), one `needs_attention`, one `closed`;
    - `Limit: 2` over `authz.Everywhere()` gives pages of 2, 2, 1 with no repeat and no gap;
    - `State: needs_attention` gives exactly one item;
    - `OpenOnly` + `State: closed` gives none;
    - `authz.Only(payments)` with `Limit: 1` gives two pages, both Payments incidents, the second with `Next == nil`.
- [ ] **Step 2: Run them to verify they fail.**
  Run: `go test ./internal/api/ -run TestListIncidentsPasses`
  Expected: FAIL (compile).
- [ ] **Step 3: Implement.** Update `api/openapi.yaml` and the web type check `web/src/api/incidents.test.ts` if it compares parameters.
- [ ] **Step 4: Run the tests.**
  Run: `go test -race -count=1 ./internal/api/ ./internal/inventory/ && go test -race -count=1 -tags integration ./internal/inventory/ -run 'ListIncidents|DBFailure'`
  Expected: PASS.
- [ ] **Step 5: Commit.** Message: `feat(api): the incident list filters by state and pages by cursor, within the caller's services (R64)`.

---

### Task 5: The Incidents page and its navigation entry (D2, web)

**Files:**
- Create: `web/src/pages/IncidentsPage.tsx`, `web/src/pages/IncidentsPage.test.tsx`.
- Modify:
  - `web/src/api/incidents.ts`: `listIncidents(q, signal)` takes `{ open?: boolean; certificate_id?: string; state?: IncidentState; cursor?: string | null; limit?: number }` and returns `{ items: Incident[]; next_cursor: string | null }`.
  - `web/src/api/queryKeys.ts`: `incidentListKey` takes `state` too.
  - `web/src/router.tsx` (`{ path: 'incidents', element: <IncidentsPage /> }`).
  - `web/src/layout/AppLayout.tsx` (`NAV_ITEMS`: `{ to: '/incidents', labelKey: 'nav.incidents', perm: 'read', icon: 'ShieldAlert', group: 'operations' }`, after Deployments).
  - `web/src/layout/AppLayout.test.tsx` (every role list gains `'Incidents'` after `'Deployments'`).
  - `web/src/locales/{en,tr}.json`.
  - `web/src/test/screens.ts` and `web/src/test/server.ts` (the MSW handler answers `next_cursor`).
  - `web/src/pages/IncidentPage.tsx`: the back link goes to `/incidents` when the page was opened from the list (`location.state?.from === 'incidents'`), else to the certificate as today.

**Interfaces:**
- Consumes: Task 4's API shape; `INCIDENT_STATES`; the existing `incidents.states.*` and `incidents.revocation.*` labels; `ResourceTable`, `CursorFooter`, `EmptyState`, `PageHeader`, `Panel` from `components/ui`; `formatDateTime`.
- Produces: the page at `/incidents`.
  - Filter: a `SegmentedControl` labelled `incidents.list.filterLabel` with the values `all`, `open`, `needs_attention`, `completed`, `closed`.
  - `open` sends `open=true`; the three states send `state=<state>`; the default is `all`.
  - Columns: certificate (a link to `/incidents/:id` with the certificate name), state, revocation, places (`verified` of the non-skipped total, `incidents.list.places`), started (date and `started_by_name`), finished (date or "—").
  - `useInfiniteQuery` with `CursorFooter` and `incidents.list.loadMore`; `limit: 50`.
- New EN keys (the TR file gets the same keys):

| Key | EN | TR |
|---|---|---|
| `nav.incidents` | Incidents | Olaylar |
| `incidents.list.title` | Key compromise incidents | Anahtar ele geçirme olayları |
| `incidents.list.description` | Every key compromise incident, newest first. | Tüm anahtar ele geçirme olayları, en yenisi önce. |
| `incidents.list.tableLabel` | Incidents | Olaylar |
| `incidents.list.filterLabel` | Show | Göster |
| `incidents.list.filter.all` / `.open` / `.needs_attention` / `.completed` / `.closed` | All / Open / Needs attention / Completed / Closed | Tümü / Açık / İlgi bekliyor / Tamamlandı / Kapatıldı |
| `incidents.list.columns.certificate` / `.state` / `.revocation` / `.places` / `.started` / `.finished` | Certificate / State / Revocation / Places / Started / Finished | Sertifika / Durum / İptal / Yerler / Başladı / Bitti |
| `incidents.list.places` | {{verified}} of {{total}} replaced | {{total}} yerin {{verified}} tanesi değiştirildi |
| `incidents.list.empty` | No incidents. | Olay yok. |
| `incidents.list.emptyFiltered` | No incidents match this filter. | Bu filtreye uyan olay yok. |
| `incidents.list.loadMore` | Show more incidents | Daha fazla olay göster |

The Turkish wording follows `incidents.states.*` (read the current TR values first and reuse their terms; `terms.test.ts` must pass).

- [ ] **Step 1: Write the failing tests** in `IncidentsPage.test.tsx`:
  - `lists incidents newest first with their state and places`: two fixtures; the row texts include `Needs attention` (the existing label) and `1 of 2 replaced`; the link `href` is `/incidents/<id>`.
  - `sends the filter`: choosing **Open** requests `open=true`, choosing **Needs attention** requests `state=needs_attention`; MSW records the query string.
  - `pages through incidents with Load more`: the first answer has `next_cursor: "c1"`, the click requests `cursor=c1`, and the rows append.
  - `shows the empty states`: `No incidents.` when unfiltered, `No incidents match this filter.` with a filter.
  - TR: `renders in Turkish` (heading `Anahtar ele geçirme olayları`).
  - `AppLayout.test.tsx`: the role lists include `Incidents`; `isActive` of `/incidents` is true for `/incidents/abc`.
- [ ] **Step 2: Run them to verify they fail.**
  Run: `cd web && npx vitest run src/pages/IncidentsPage.test.tsx src/layout/AppLayout.test.tsx`
  Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests.**
  Run: `cd web && npx vitest run src/pages src/layout src/api src/locales src/screens.i18n.test.tsx && npx tsc --noEmit && npm run lint && cd .. && make i18n-check`
  Expected: PASS.
- [ ] **Step 5: Commit.** Message: `feat(web): an Incidents page lists every key compromise incident with a state filter and paging, reached from the navigation (D2, R64)`.

---

### Task 6: Incident e-mails, sent once per state change; the store notice deduplicated for good (D3)

**Design.**
- An e-mail is queued inside the transaction that moves the incident:
  - `attention()` and the final branch of `revokeFailed()` (entering `needs_attention`);
  - `complete()` (entering `completed`).
- Each move is a conditional `UPDATE ... WHERE state = $2 AND finished_at IS NULL`. A second engine finds 0 rows and queues nothing, and a rolled-back move takes its mail with it. That makes each mail exactly once per move (Ruling 11).
- The W3 duplicate is fixed separately. `compromisedInStore` looked for an earlier outbox row, so two jobs at the same moment both found none, and outbox pruning made a repeat possible. It now inserts a row into `incident_notices` (primary key `(incident_id, notice)`) with `ON CONFLICT DO NOTHING`, and queues only when the row was inserted (Ruling 12).

**Files:**
- Create: `migrations/00033_incident_notices.sql`, `migrations/incident_notices_integration_test.go`.
- Modify: `internal/inventory/notify.go`:
  - templates `TemplateIncidentNeedsAttention = "incident.needs_attention"`, `TemplateIncidentCompleted = "incident.completed"`, `TemplateIncidentCompletedNotRevocable = "incident.completed_not_revocable"`;
  - `func IncidentTemplates() []string`;
  - `incidentServices`;
  - `notifyIncident`.
- Modify: `internal/inventory/incidents_engine.go` (the three hooks); `internal/inventory/windows_cleanup.go` (`compromisedInStore`).
- Modify: `locales/common/{en,tr}.json` (`email.incident.*`); `migrations/roles_integration_test.go` (`public.incident_notices: {"INSERT", "SELECT"}`).
- Tests: `internal/notify/render_incident_test.go` (new), `internal/inventory/incidents_mail_integration_test.go` (new), `internal/inventory/windows_cleanup_integration_test.go` or the file that holds `TestRecordCleanupAuditsAndNotifiesOnce`.

**Interfaces:**
- Produces:
  - `func (s *Service) notifyIncident(ctx context.Context, tx pgx.Tx, id uuid.UUID, template, attentionCode string) error`:
    - reads in `tx` the certificate name (as `incidentSelect`) and the counts by status;
    - params `certificate_name` (≤200 runes), `incident_id`, `verified`, `failed`, `skipped`, and for needs-attention `error_reason` = the attention code (the Sender renders it as `reason`, the code's plain title);
    - recipients: `incidentServices` = `service_ids` ∪ the certificate's `service_id` through `NotifyServices`, which falls back to the Administrators (RBAC phase 4, design §7.2).
  - `00033`:
    ```sql
    CREATE TABLE incident_notices (
        incident_id uuid NOT NULL REFERENCES certificate_incidents (id),
        notice      text NOT NULL CHECK (notice ~ '^[a-z0-9_.]+:[0-9A-Fa-f]{40}$'),
        created_at  timestamptz NOT NULL,
        PRIMARY KEY (incident_id, notice)
    );
    GRANT SELECT, INSERT ON incident_notices TO alice_app;
    ```
    The Up step also back-fills one row per existing `windows.compromised_in_store` outbox row (`notice = 'windows.compromised_in_store:' || params->>'thumbprint'`, only for incident ids that exist, `ON CONFLICT DO NOTHING`), so an upgrade does not send old notices again. The Down step drops the table.
- EN texts (TR mirrors placeholders):
  - `email.incident.needs_attention.subject` = `Key compromise incident needs attention: {{certificate_name}}`.
    Body: `The key compromise incident of the certificate {{certificate_name}} is waiting for a person. Reason: {{reason}}.\n\nAlice does nothing more on this incident until an administrator acts on its page in Alice (Incidents): Retry, Revoke now regardless, choose the replacement, or Close.\n\nPlaces replaced and checked: {{verified}}. Places that failed: {{failed}}. Places skipped: {{skipped}}.\n\nIncident: {{incident_id}}`
  - `email.incident.completed.subject` = `Key compromise incident completed: {{certificate_name}}`.
    Body: `Alice replaced the certificate {{certificate_name}} at every place it could replace it and checked each one, and the compromised certificate is revoked at its certificate authority (or had nothing left to revoke).\n\nPlaces replaced and checked: {{verified}}. Places skipped: {{skipped}}; the incident's page says why for each one, and those you replace yourself.\n\nIncident: {{incident_id}}`
  - `email.incident.completed_not_revocable.subject` = the same as completed.
    Body: as completed, with the revocation sentence replaced by `Alice cannot revoke this certificate: ask the authority that issued it to revoke it.`

- [ ] **Step 1: Write the failing tests.**
  - `render_incident_test.go`, `TestIncidentTemplatesRenderInBothLanguages`: for each of `inventory.IncidentTemplates()` in `en` and `tr`:
    - no `{{`, no `email.` key in the subject;
    - the subject contains `www.example.test (İzmir)`;
    - the body contains the incident id;
    - the needs-attention body contains the EN title of `errors.incident.deployments_failed` (and the TR title in TR), proving `error_reason` became `reason`.
  - `incidents_mail_integration_test.go`. Setup: the incident harness, an owner on the certificate's service, a recording notifier.
    - `TestIncidentNeedsAttentionMailedOncePerEntry`:
      - a place fails, so the incident needs attention, and one `incident.needs_attention` row is queued per recipient;
      - advancing again adds nothing;
      - Retry, then a new failure, gives a second set;
      - recipients are the owner and the Administrators (policy default).
    - `TestIncidentNeedsAttentionMailedOnRevocationFailure`: a permanent revoke failure (fakeacme `unauthorized`) gives one mail with `error_reason` = `acme.revoke_unauthorized`; transient retries before the fifth attempt send none.
    - `TestIncidentCompletedMailedOnce`: an ACME incident completes with `incident.completed`; an uploaded certificate's incident with a chosen replacement completes with `incident.completed_not_revocable`; closing an incident sends nothing.
    - `TestIncidentMoveRaceMailsOnce`: two goroutines run `AdvanceIncident` on the same incident at the moment it completes; exactly one set of rows.
    - `TestIncidentMailsInLock`: the licence gate refuses `ClassChange` (the harness's locked gate) while a running deployment of the incident fails; the incident needs attention and its mail is queued (Ruling 13).
  - Windows cleanup tests:
    - `TestCompromisedInStoreNoticeOnceUnderRace`: two transactions call `compromisedInStore` for the same incident and thumbprint concurrently; one outbox set, one `incident_notices` row.
    - `TestCompromisedInStoreNoticeSurvivesOutboxPruning`: queue once, `DELETE FROM notifications_outbox` as owner, call again; no new outbox row.
  - `incident_notices_integration_test.go`, `TestMigration00033BackfillsTheStoreNotices`: at `00032`, insert an incident and a `windows.compromised_in_store` outbox row; migrate up; the notice row exists; a second Up is impossible (goose); Down drops the table.
- [ ] **Step 2: Run them to verify they fail.**
  Run: `go test ./internal/notify/ -run TestIncidentTemplates && go test -tags integration ./internal/inventory/ -run 'IncidentNeedsAttention|IncidentCompleted|IncidentMove|IncidentMailsInLock|CompromisedInStoreNotice'`
  Expected: FAIL.
- [ ] **Step 3: Implement.** Add the templates to the render list the notify tests read: `inventory.Templates()` stays as it is, and `IncidentTemplates()` is its own list, as `ACMETemplates()` is.
- [ ] **Step 4: Run the tests.**
  Run: `go test -race -count=1 ./internal/notify/ ./internal/inventory/ && go test -race -count=1 -tags integration ./internal/inventory/ ./internal/notify/ ./migrations/ && make i18n-check`
  Expected: PASS. `internal/notify` stays ≥88 and `internal/inventory` ≥89.
- [ ] **Step 5: Docs.**
  - `docs/admin-guide.md` §incidents: "Alice e-mails the certificate's service recipients when an incident needs attention and when it completes, also while the licence is locked."
  - `docs/superpowers/rulings/certificate-revocation.md` gets no edit; this phase's rulings file records D3 as done.
- [ ] **Step 6: Commit.** Message: `feat(inventory): e-mails when a key compromise incident needs attention and when it completes, once per change and also in lock; the store notice is recorded in incident_notices so it is never sent twice (D3, R64)`.

---

### Task 7: The revocation checker: OCSP, CRL and a guarded fetch, with fake servers (D5, part 1)

**Files:**
- Create: `internal/revocation/revocation.go` (types, `Checker`, `Run`), `internal/revocation/fetch.go` (the guarded client), `internal/revocation/ocsp.go`, `internal/revocation/crl.go`, `internal/revocation/seam_integration.go` (`//go:build integration`: `NewWithDial`), `internal/revocation/revocation_test.go`, `internal/revocation/fetch_test.go`.
- Create: `internal/testutil/fakerevocation/fakerevocation.go`, `internal/testutil/fakerevocation/fakerevocation_test.go`.
- Modify: `internal/testutil/pki/pki.go` (`Opts.OCSPServer []string`, `Opts.CRLDistributionPoints []string`, copied into the leaf template); `internal/archtest/arch_test.go` (rules and `TestAllowed` rows); `coverage-floors.json`.

**Interfaces:**
- Produces:
  ```go
  package revocation

  type Status string
  const (
      StatusGood          Status = "good"
      StatusRevoked       Status = "revoked"
      StatusOnHold        Status = "on_hold"       // certificateHold (6): not final
      StatusUnknown       Status = "unknown"       // the responder does not know the certificate
      StatusUnavailable   Status = "unavailable"   // Code says why; never a finding
      StatusNotCheckable  Status = "not_checkable" // Code: no issuer or no address
      StatusDeferred      Status = "deferred"      // the run's budget for this host is spent; not recorded
  )
  // The closed codes (the API registers each as ALC-CRT-0020..0025, Task 9).
  const (
      CodeUnreachable    = "certificate.revocation_unreachable"
      CodeInvalidAnswer  = "certificate.revocation_invalid_answer"
      CodeAddressRefused = "certificate.revocation_address_refused"
      CodeNoIssuer       = "certificate.revocation_no_issuer"
      CodeNoAddress      = "certificate.revocation_no_address"
      CodeTooLarge       = "certificate.revocation_too_large"
  )
  type Result struct {
      Status    Status
      Method    string    // "ocsp", "crl" or ""
      RevokedAt time.Time // revoked and on_hold
      Reason    string    // RFC 5280 name: unspecified, keyCompromise, cACompromise, affiliationChanged, superseded,
                          // cessationOfOperation, certificateHold, privilegeWithdrawn, aACompromise ("" when good)
      Code      string    // unavailable and not_checkable
  }
  func New(clk clock.Clock) *Checker                     // the guarded production client
  func (c *Checker) NewRun(perHost int) *Run             // one scheduled run: per-host budget and CRL cache
  func (r *Run) Check(ctx context.Context, leaf, issuer *x509.Certificate) Result // issuer nil: not_checkable/no_issuer
  // seam_integration.go (integration build only):
  func NewWithDial(clk clock.Clock, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Checker
  ```
  - The unit tests in the package use the unexported `newChecker(clk, dial)`.

  - `fakerevocation`:
  ```go
  type Fault int
  const (FaultNone Fault = iota; FaultDown /* 500 */; FaultGarbage; FaultWrongSigner; FaultStale; FaultHuge; FaultRedirect; FaultUnknown)
  func New(ca *pki.CA, clk clock.Clock) *Server // POST /ocsp (signed by ca.IntermediateKey), GET /crl (DER CRL signed by it)
  func (s *Server) Revoke(serial *big.Int, reason int, at time.Time)
  func (s *Server) Hold(serial *big.Int, at time.Time)
  func (s *Server) SetFault(path string, f Fault)        // "/ocsp" or "/crl"
  func (s *Server) Requests(path string) int
  func (s *Server) Start(t testing.TB) string            // httptest on 127.0.0.1:0; returns host:port
  ```
- **Check algorithm** (Ruling 16):
  1. `issuer == nil` or `leaf.CheckSignatureFrom(issuer) != nil` gives not_checkable `CodeNoIssuer`.
  2. Take the first `leaf.OCSPServer` URL and the first `leaf.CRLDistributionPoints` URL that pass the URL rule. None at all gives not_checkable `CodeNoAddress`. A URL that fails the rule gives `CodeAddressRefused` if no other is usable.
  3. OCSP:
     - `ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})`;
     - POST with `Content-Type: application/ocsp-request`;
     - `ocsp.ParseResponseForCert(body, leaf, issuer)` (the issuer, or a delegated responder certificate the issuer signed with `id-kp-OCSPSigning`, which the library checks);
     - `ThisUpdate` after `now+5m` or a set `NextUpdate` before `now-5m` gives unavailable `CodeInvalidAnswer`;
     - `Good` gives good, `Revoked` gives revoked (reason by number; 6 gives on_hold; an unknown number gives `unspecified`), `Unknown` gives unknown.
  4. CRL, when OCSP is absent, or answered unavailable or unknown:
     - GET; the body is DER, or one PEM block `X509 CRL`;
     - `x509.ParseRevocationList`, then `CheckSignatureFrom(issuer)`, then `bytes.Equal(crl.RawIssuer, leaf.RawIssuer)`; any failure gives `CodeInvalidAnswer`;
     - the serial listed gives revoked (or on_hold for reason 6) even when the CRL is stale, because revocation is permanent;
     - not listed and `NextUpdate` before `now-5m` gives unavailable `CodeInvalidAnswer`;
     - else good;
     - the CRL is cached per URL for the run (at most 16 CRLs).
  5. When both were tried, the final result is the more definite one: revoked/on_hold beat good, which beats unknown, which beats unavailable.
- **URL and fetch rule** (Ruling 17):
  - scheme `http` or `https`; no user info; a host; port empty, `80` for http or `443` for https;
  - dial through a `net.Dialer` whose `Control` calls `netaddr.Control` and then refuses loopback and unspecified addresses (`CodeAddressRefused`);
  - `Proxy: nil`, no redirect (a 3xx is `CodeUnreachable`), no keep-alive, TLS 1.2+, system roots;
  - 10 s per exchange;
  - answer caps 64 KiB (OCSP) and 10 MiB (CRL), `CodeTooLarge` beyond;
  - `User-Agent: Alice-revocation-check`;
  - a non-200 status is `CodeUnreachable`.
  - Each request counts against its host's per-run budget; a cache hit costs nothing. A spent budget gives deferred.

- [ ] **Step 1: Write the failing tests.**
  - `fetch_test.go`:
    - `TestFetchRefusesForbiddenAddresses`, rows `ftp://`, `http://u:p@h/`, `http://h:8080/`, `https://h:80/`, `http://127.0.0.1/`, `http://[::1]/`, `http://169.254.169.254/`, `http://0.0.0.0/`, `http://localhost/` (resolved through the test resolver to 127.0.0.1). Each gives `CodeAddressRefused`, and the fake's request counter stays 0.
    - `TestFetchCapsTheAnswer` (FaultHuge on both paths gives `CodeTooLarge`).
    - `TestFetchNeverFollowsARedirect` (FaultRedirect gives `CodeUnreachable`, and the redirect target's counter stays 0).
  - `revocation_test.go`: a `pki.NewCA`, and a leaf with `OCSPServer: ["http://ocsp.alice.test/ocsp"]` and `CRLDistributionPoints: ["http://crl.alice.test/crl"]`, all dialled through a seam mapping those host names to the fake's listener.
    - `TestCheckOCSPAnswers`:
      - good → good/ocsp;
      - revoked reason 1 at T → revoked, `keyCompromise`, `RevokedAt == T`;
      - hold → on_hold;
      - unknown → (CRL fallback good) good/crl;
      - wrong signer → OCSP invalid, then CRL decides (good);
      - garbage → CRL decides;
      - stale → CRL decides;
      - OCSP down and CRL down → unavailable `CodeUnreachable`.
    - `TestCheckCRL` (a leaf with a CRL address only):
      - listed → revoked/crl;
      - bad signature → unavailable `CodeInvalidAnswer`;
      - a CRL of another issuer → `CodeInvalidAnswer`;
      - stale and not listed → `CodeInvalidAnswer`;
      - stale and listed → revoked;
      - PEM `X509 CRL` → read.
    - `TestCheckNotCheckable`: no issuer → `CodeNoIssuer`; an issuer that did not sign the leaf → `CodeNoIssuer`; no addresses → `CodeNoAddress`.
    - `TestRunBudgetAndCache`:
      - `NewRun(2)`, five leaves sharing one CRL address: one CRL request, five results;
      - five leaves with OCSP on one host and `perHost` 2: two OCSP requests; the rest fall to CRL, or are deferred when CRL is on the same host and spent.
  - `fakerevocation_test.go`: `TestFakeServesSignedAnswers` (`ocsp.ParseResponseForCert` and `x509.ParseRevocationList` + `CheckSignatureFrom` succeed).
  - `arch_test.go` `TestAllowed` rows:
    - `{"revocation to netaddr allowed", "alice/internal/revocation", "alice/internal/platform/netaddr", true}`;
    - `{"revocation to inventory denied", "alice/internal/revocation", "alice/internal/inventory", false}`;
    - `{"inventory to revocation allowed", "alice/internal/inventory", "alice/internal/revocation", true}`;
    - `{"fakerevocation to revocation denied", "alice/internal/testutil/fakerevocation", "alice/internal/revocation", false}`.
- [ ] **Step 2: Run them to verify they fail.**
  Run: `go test ./internal/revocation/ ./internal/testutil/fakerevocation/ ./internal/archtest/`
  Expected: FAIL (compile).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests.**
  Run: `go test -race -count=1 -cover ./internal/revocation/ ./internal/testutil/... ./internal/archtest/ && go vet -tags integration ./internal/revocation/`
  Expected: PASS, `internal/revocation` ≥95.
- [ ] **Step 5: Commit.** Message: `feat(revocation): an OCSP and CRL checker with a guarded fetch (http/https on 80/443, no loopback or link-local, no proxy, no redirect, capped answers) and fake servers for the tests (D5, R64)`.

---

### Task 8: The scheduled check, its state and what a revocation does (D5, part 2)

**Files:**
- Create: `migrations/00034_revocation_checks.sql`, `migrations/revocation_checks_integration_test.go`.
- Create: `internal/inventory/revocation_checks.go` (selection, run, recording, marking, mail, audit, settings), `internal/inventory/revocation_checks_integration_test.go`.
- Modify:
  - `internal/inventory/service.go` (`Config.Revocation RevocationChecker`; nil means no checks);
  - `internal/inventory/notify.go` (templates and `RevocationTemplates()`);
  - `internal/inventory/certificates.go` (or the file holding `Certificate` and its select): `Certificate.RevokedByAuthority bool` from `revocation_seen <> ''`, and `Certificate.RevocationCheck *RevocationCheck`, read by `GetCertificate`;
  - `internal/jobs/types.go` (`RevocationCheck = Register("revocation.check", license.ClassReadOnly)` with its comment);
  - `cmd/alice/wiring.go` (the type in the periodic list), `cmd/alice/services.go` (the task `Every: revocationCheckEvery` = 15 min; `inventory.Config.Revocation: revocation.New(clk)`; not ticked in the e2e build, like `incident.advance`);
  - `locales/common/{en,tr}.json` (`email.certificate.*`, audit labels if the server renders them), `web/src/locales/{en,tr}.json` (`jobs.types.revocation.check`, `audit.actions.certificate_revoked_by_authority`, `audit.actions.certificate_revocation_on_hold`, `audit.actions.settings_revocation_check_changed`, following the existing audit label key form);
  - `migrations/roles_integration_test.go`.

**Interfaces:**
- Consumes: Task 7's `revocation.Checker`, `Run` and `Result`; Task 6's mail pattern (`servicesOf`).
- Produces:
  ```go
  type RevocationRun interface { Check(ctx context.Context, leaf, issuer *x509.Certificate) revocation.Result }
  type RevocationChecker interface { NewRun(perHost int) RevocationRun } // *revocation.Checker satisfies it via a small adapter
  const JobRevocationCheck = "revocation.check"
  type RevocationRunReport struct{ Checked, Revoked, OnHold, Deferred int }
  func (s *Service) RunRevocationChecks(ctx context.Context) (RevocationRunReport, error)
  type RevocationCheck struct {
      Status, Method, Reason, ErrorCode string
      RevokedAt                         *time.Time
      CheckedAt, NextCheckAt            time.Time
  }
  type RevocationSettings struct{ Enabled bool; Version int } // settings key "revocation.check"; absent = enabled
  func (s *Service) RevocationSettings(ctx context.Context) (RevocationSettings, error)
  func (s *Service) SaveRevocationSettings(ctx context.Context, a audit.Actor, version int, enabled bool) (RevocationSettings, error)
  var ErrRevocationSettingsVersion = errors.New("inventory: the revocation check setting changed since it was read") // in errors.go
  const (
      TemplateCertificateRevokedByAuthority           = "certificate.revoked_by_authority"
      TemplateCertificateRevokedByAuthorityDiscovered = "certificate.revoked_by_authority_discovered"
      TemplateCertificateOnHoldByAuthority            = "certificate.on_hold_by_authority"
  )
  ```
- **`00034`** (Up):
  ```sql
  CREATE TABLE revocation_checks (
      fingerprint_sha256 text PRIMARY KEY CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'),
      status        text NOT NULL CHECK (status IN ('good', 'revoked', 'on_hold', 'unknown', 'unavailable', 'not_checkable')),
      method        text NOT NULL DEFAULT '' CHECK (method IN ('', 'ocsp', 'crl')),
      revoked_at    timestamptz,
      reason        text NOT NULL DEFAULT '' CHECK (reason IN ('', 'unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                        'superseded', 'cessationOfOperation', 'certificateHold', 'privilegeWithdrawn', 'aACompromise')),
      error_code    text NOT NULL DEFAULT '' CHECK (error_code ~ '^[a-z0-9._]{0,100}$'),
      failures      integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
      checked_at    timestamptz NOT NULL,
      next_check_at timestamptz NOT NULL,
      notified_at   timestamptz,
      CHECK ((status IN ('revoked', 'on_hold')) = (revoked_at IS NOT NULL)),
      CHECK ((status IN ('unavailable', 'not_checkable')) = (error_code <> ''))
  );
  CREATE INDEX revocation_checks_due ON revocation_checks (next_check_at);
  GRANT SELECT, INSERT, UPDATE, DELETE ON revocation_checks TO alice_app;
  ```
  - The `certificates.revocation_reason` CHECK is widened to the RFC 5280 final reasons. Add `cACompromise`, `privilegeWithdrawn` and `aACompromise`; leave out `certificateHold` (not final) and `removeFromCRL`. Drop the old column constraint by its catalogue name: read it from `pg_constraint` in the test first; it is expected to be `certificates_revocation_reason_check`.
  - New column `certificates.revocation_seen text NOT NULL DEFAULT '' CHECK (revocation_seen IN ('', 'ocsp', 'crl'))`, plus the table check `revocation_seen = '' OR revoked_at IS NOT NULL`. `GRANT UPDATE (revocation_seen) ON certificates TO alice_app`.
  - `CREATE OR REPLACE FUNCTION certificates_protect_revocation()` also freezes `revocation_seen` once `revoked_at` is set. Re-create the trigger with `revocation_seen` in its `UPDATE OF` list.
  - Upgraded installations keep the check off until an administrator switches it on (Ruling 19): `INSERT INTO settings (key, value, updated_at) SELECT 'revocation.check', '{"enabled": false, "version": 0}', now() WHERE EXISTS (SELECT 1 FROM users) ON CONFLICT (key) DO NOTHING;`
  - Down refuses (`RAISE EXCEPTION`) when a certificate carries a widened reason or a `revocation_seen`. Otherwise it restores the old constraint, function and trigger, drops the column and the table, and deletes the setting.
- **Selection** (one statement, at most `revocationBatch` = 200 rows, ordered by `coalesce(next_check_at, '-infinity')`, then fingerprint). A candidate is unexpired and not self-signed, and has either no check row or a due row whose status is not `revoked`. Sources:
  - (a) Inventory: every `certificates` row with `revoked_at IS NULL`, any source (Ruling 14). The issuer is the first block of `pem_chain` after the leaf that signed it.
  - (b) Network discovery: `discovery_certificates` with `is_leaf`, no `certificates` row with the same fingerprint, and an endpoint presenting it whose `chain_fingerprints[1]` names a stored certificate (the issuer).
- **Run.**
  - Return at once when the setting is off, `Config.Revocation` is nil, or `s.license.Allow(license.ClassReadOnly)` refuses.
  - Use one `checker.NewRun(revocationPerHost = 50)`; stop at the batch or after `revocationRunBudget` = 4 minutes.
  - After the run, delete at most 1000 check rows whose fingerprint is in neither certificate table.
- **Recording per result** (each in its own transaction; `now` from the clock):
  - good: status good, `failures` 0, `error_code` '', next `now+24h`; `notified_at` cleared when it was on_hold.
  - unknown: status unknown, next `now+24h`, no mail (Ruling 18).
  - unavailable: `failures+1`, the code, next `now + min(1h·2^(failures-1), 24h)`. The previous status is not kept and no mark is ever made.
  - not_checkable: the code, next `now+7d`.
  - deferred: no write.
  - on_hold: status on_hold, `revoked_at`, reason `certificateHold`, next `now+6h`; one mail per hold (`notified_at`); audit `certificate.revocation_on_hold`; no mark.
  - revoked, inventory certificate:
    - status revoked, `next_check_at = now`;
    - `UPDATE certificates SET revoked_at = $1, revocation_reason = $2, revocation_seen = $3 WHERE fingerprint_sha256 = $4 AND revoked_at IS NULL` (an unknown or empty reason is stored as `unspecified`);
    - audit `certificate.revoked_by_authority` with details `fingerprint`, `method`, `revoked_at` and `reason` (system actor `revocation`);
    - mail `certificate.revoked_by_authority` once (`notified_at`), to `servicesOf(certificate service ∪ services of servers holding it)`.
  - revoked, discovery certificate: the check row only, plus the mail `certificate.revoked_by_authority_discovered` to the services of the discovery scopes presenting it, falling back to the Administrators; no audit of a certificate row.
- EN texts:
  - `email.certificate.revoked_by_authority.subject` = `Certificate revoked by its authority: {{certificate_name}}`.
    Body: `The certificate authority that issued {{certificate_name}} (SHA-256 {{fingerprint}}) says it was revoked on {{revoked_at}}. Reason given by the authority: {{reason}}. Alice learned this from the authority's {{method}} answer.\n\nBrowsers and other clients refuse a revoked certificate: replace it wherever it is used. Alice no longer deploys it, and an issued certificate (ACME) with automatic renewal on is renewed at once. If the reason is keyCompromise, its private key is no longer secret: start a key compromise incident from the certificate's page.`
  - `..._discovered`: the same facts, plus `Network discovery found it at: {{endpoints}}.` (at most five `address:port` values, then `…`) and no deploy or renewal sentence.
  - `email.certificate.on_hold_by_authority.subject` = `Certificate suspended by its authority: {{certificate_name}}`, with the body naming the date and saying a suspension can be lifted by the authority.
- `{{method}}` is `OCSP` or `CRL`; `{{revoked_at}}` uses `2006-01-02 15:04 UTC`.

- [ ] **Step 1: Write the failing tests** (`revocation_checks_integration_test.go`; the real `revocation.NewWithDial` against `fakerevocation`, with leaves from a `pki.NewCA` carrying the fake's addresses):
  - `TestRevocationRunMarksAnAuthorityRevocation` (HB-15):
    - an uploaded certificate revoked by the fake (reason 1);
    - after one run, `certificates.revoked_at` is set, `revocation_reason = 'keyCompromise'`, `revocation_seen = 'ocsp'`;
    - `RequestDeployment` of it is refused with `ErrCertificateRevoked`;
    - one audit row `certificate.revoked_by_authority`;
    - one outbox set of `certificate.revoked_by_authority`;
    - a second run sends nothing and makes no request for it.
  - `TestRevocationRunRenewsARevokedACMECertificate`: an ACME current certificate revoked by the authority is due at once in the renewal planner's candidates (`renew.Input.Revoked`).
  - `TestRevocationRunNeverMarksOnFailure`: faults Down, Garbage, WrongSigner, Stale-not-listed and Unknown each leave `revoked_at` NULL and the status `unavailable` or `unknown`, with no mail. The failures back off: 1 h, 2 h, 4 h, then capped at 24 h (advance the clock).
  - `TestRevocationRunHoldIsNotFinal`: hold, then one mail and no mark; the fake lifts the hold, then good with `notified_at` cleared; a second hold sends a second mail.
  - `TestRevocationRunChecksDiscoveredLeaves`: a discovery leaf with its issuer in an endpoint chain, revoked, gives the discovered mail to the scope's service and no `certificates` change.
  - `TestRevocationRunBudget`: 300 due certificates on one OCSP host and no CRL; one run checks 50 (`perHost`), the rest stay due; with batch 200, at most 200 are selected.
  - `TestRevocationRunSkipsWhenOffLockedOrUnconfigured` (HB-16): the setting off, the gate refusing `ClassReadOnly`, or `Config.Revocation` nil each make no request (fake counters 0).
  - `TestRevocationSettingsDefaults`: a fresh database reads enabled; save with version 0 gives version 1 and an audit `settings.revocation_check_changed`; a stale version gives the new sentinel `inventory.ErrRevocationSettingsVersion` (Task 9 maps it to `ErrPreconditionFailed`, 412, and adds it to `inventorySentinels` in `internal/api/errors_catalogue_test.go`).
  - `migrations/revocation_checks_integration_test.go`, `TestMigration00034`:
    - a database with a user at `00033` gets the setting `enabled: false`; one without users gets none;
    - the widened reasons are accepted;
    - `revocation_seen` is frozen once revoked (Z1022);
    - Down refuses with a widened reason present and succeeds without one.
- [ ] **Step 2: Run them to verify they fail.**
  Run: `go test -tags integration ./internal/inventory/ ./migrations/ -run 'RevocationRun|RevocationSettings|Migration00034'`
  Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests.**
  Run: `go build ./... && go test -race -count=1 ./internal/inventory/ ./internal/jobs/ ./cmd/alice/ && go test -race -count=1 -tags integration ./internal/inventory/ ./migrations/ && make i18n-check`
  Expected: PASS. `internal/jobs` keeps its type-registry tests green: the class test and the label guard need the web label. `cmd/alice` stays ≥91.
- [ ] **Step 5: Commit.** Message: `feat(inventory): a scheduled OCSP and CRL check of certificates found on servers and by discovery; a revocation the authority signed marks the certificate revoked for good and is e-mailed once; unknown and unreachable answers are recorded, never acted on (D5, R64)`.

---

### Task 9: Revocation checks in the API, the web and the documents (D5, part 3)

**Files:**
- Modify: `internal/api/errors.go`:

| Code | Reason | Status |
|---|---|---|
| `ALC-CRT-0020` | `certificate.revocation_unreachable` | 502 |
| `ALC-CRT-0021` | `certificate.revocation_invalid_answer` | 502 |
| `ALC-CRT-0022` | `certificate.revocation_address_refused` | 422 |
| `ALC-CRT-0023` | `certificate.revocation_no_issuer` | 422 |
| `ALC-CRT-0024` | `certificate.revocation_no_address` | 422 |
| `ALC-CRT-0025` | `certificate.revocation_too_large` | 502 |

  All are stored reasons rendered through `errorRef`; none is answered by a route today. Add them to `AllErrorCodes()`.
  Also map `inventory.ErrRevocationSettingsVersion` to `ErrPreconditionFailed` in `errorMap`.
- Modify: `internal/api/certificates_handlers.go` (the certificate DTO):
  - `revoked_by_authority: bool`;
  - `revocation_check: { status, method, reason, revoked_at, checked_at, next_check_at, error: errorRef|null } | null`.
- Create: `internal/api/revocation_settings_handlers.go`, with routes `GET` and `PUT /api/v1/settings/revocation-checks`:
  - `scopePlatform`, `rbac.SettingsManage`, PUT `lic: license.ClassAlways`;
  - the body `{"enabled": bool}`;
  - `If-Match` and step-up through `settingsChange`, as `putGeneral`;
  - the answer `{"enabled": bool, "version": n}` with `ETag`.
- Modify: `api/openapi.yaml` (the two operations, the DTO fields, the codes); `internal/api/server.go` (the service interface field, satisfied by `*inventory.Service`).
- Modify: `locales/common/{en,tr}.json` (`errors.certificate.revocation_*.title`/`.text`); `docs/troubleshooting.md` (one section per code, quoting the real titles: `TestTroubleshootingQuotesTheRealTitles`).
- Create: `web/src/components/settings/RevocationCheckSettings.tsx` (+ `.test.tsx`), mounted in the General tab of `SettingsPage` under the existing general settings.
- Modify: `web/src/pages/CertificateDetailPage.tsx`:
  - a fact row `certificates.revocationCheck.label` with the status text;
  - when `revoked_by_authority`, the existing revoked notice uses `certificates.revocation.revokedByAuthorityText` instead of `revokedText` (no "revoked by" name).
- Modify: `web/src/api/types.ts`, `web/src/test/fixtures.ts`, `web/src/locales/{en,tr}.json`.
- Modify docs:
  - `docs/admin-guide.md`: a new section "Revocation checks". It covers what is checked, how often, the per-authority limit, the statuses, what a revocation does, the switch and its default (on for a new installation, off after an update until switched on), and the outbound rule (HTTP and HTTPS on ports 80 and 443 to the addresses in the certificates; no proxy).
  - `docs/operator-guide.md`: the update note.
  - `SECURITY-REPORT.md`: a new KI-43 (below) and the scope line.
  - `docs/authz-matrix.md` (`make authz-doc`).
- Tests: `internal/api/revocation_settings_handlers_test.go`, `internal/api/certificates_handlers_test.go`, `internal/api/errors_catalogue_test.go` (a `TestRevocationCheckCodeTable` like `TestPhase5CodeTable`), and the web tests.

**Interfaces:**
- Consumes: Task 8's `RevocationCheck`, `RevocationSettings`, `SaveRevocationSettings` and `Certificate.RevokedByAuthority`.
- New web keys (EN; TR mirrors):

| Key | EN |
|---|---|
| `certificates.revocationCheck.label` | Revocation check |
| `certificates.revocationCheck.status.good` | Not revoked (checked {{date}}, {{method}}) |
| `certificates.revocationCheck.status.revoked` | Revoked by its authority |
| `certificates.revocationCheck.status.on_hold` | Suspended by its authority since {{date}} |
| `certificates.revocationCheck.status.unknown` | The authority does not know this certificate (checked {{date}}) |
| `certificates.revocationCheck.status.unavailable` | Could not check: {{reason}} (next try {{next}}) |
| `certificates.revocationCheck.status.not_checkable` | Cannot be checked: {{reason}} |
| `certificates.revocationCheck.status.none` | Not checked yet |
| `certificates.revocation.revokedByAuthorityText` | The authority that issued this certificate revoked it on {{date}} (reason: {{reason}}). Alice found this in the authority's {{method}} answer and no longer deploys it. |
| `settings.revocationCheck.title` | Revocation checks |
| `settings.revocationCheck.help` | Alice asks the authority that issued each certificate whether it was revoked (OCSP or CRL), about once a day per certificate. Alice connects to the addresses named in the certificates over HTTP and HTTPS, ports 80 and 443. |
| `settings.revocationCheck.enabled` | Check certificates for revocation |

- **KI-43** (`SECURITY-REPORT.md`):
  - Item: "**Revocation checks make outbound requests to addresses named in certificates.** A certificate on a managed server or found by network discovery can name any OCSP or CRL address; Alice fetches it (HTTP or HTTPS, ports 80 and 443) to learn whether the certificate was revoked. Private network addresses are allowed (company authorities), so a request can reach an internal web server on port 80 or 443 with a fixed body; the answer is only parsed as OCSP or CRL and never shown. No proxy support."
  - Severity: Low.
  - Controls: "loopback, link-local, metadata and the other netaddr ranges refused at connect time; no redirect; answers capped (64 KiB, 10 MiB); 10 s per request; at most 50 requests per host per run; the leaf must be signed by the issuer Alice holds (`internal/revocation:TestFetchRefusesForbiddenAddresses`)".
  - Customer advice: "Switch the check off (Settings, General) if outbound HTTP from the Alice host is not wanted; restrict the host's egress to your authorities."

- [ ] **Step 1: Write the failing tests.**
  - `TestRevocationCheckCodeTable`: the six codes, statuses and reasons as in the table; each has EN and TR texts; each reason equals the `revocation.Code*` constant.
  - `TestRevocationSettingsRoutes`: GET answers `{"enabled":true,"version":0}` by default; PUT without `If-Match` is 412 `ErrPreconditionFailed` (what `settingsChange` answers); PUT with a stale version is 412 (`ErrRevocationSettingsVersion`); PUT with `"1"` and `{"enabled":false}` is 200; an Operator gets 403; the route needs a fresh step-up like the other settings.
  - `TestCertificateDTORevocationCheck`: `revoked_by_authority` and `revocation_check` serialize; a nil check gives `null`; the error is an `errorRef` with code `ALC-CRT-0020`.
  - Web:
    - `RevocationCheckSettings.test.tsx`: shows the switch on, saving sends `If-Match` and `{"enabled":false}`.
    - `CertificateDetailPage.test.tsx`: `shows the revocation check` (good, unavailable with its reason title, none) and `says the authority revoked it` (the text contains `Alice found this in the authority's OCSP answer`).
- [ ] **Step 2: Run them to verify they fail.**
  Run: `go test ./internal/api/ -run 'RevocationCheckCode|RevocationSettings|CertificateDTORevocation' && cd web && npx vitest run src/components/settings/RevocationCheckSettings.test.tsx src/pages/CertificateDetailPage.test.tsx`
  Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests.**
  Run: `go test -race -count=1 ./internal/api/ && make i18n-check docs-check authz-doc && cd web && npx vitest run src && npx tsc --noEmit && npm run lint`
  Expected: PASS. `internal/api` stays ≥95.
- [ ] **Step 5: Commit.** Message: `feat(api,web): revocation checks are shown on the certificate page and switched in Settings; ALC-CRT-0020..0025 with their troubleshooting sections; KI-43 (D5, R64)`.

---

### Task 10: e2e journey: the Incidents page in EN and TR (D2)

**Files:**
- Create: `web/e2e/hardening1.spec.ts`.

**Interfaces:**
- Consumes: `helpers.ts` (`test`, `expect`, `translator`, `browserLocale`, `resetInstall`, `runWizard`, `newCert`, `field`, `settle`, `expectAccessible`, `freshCode` if the step-up dialog appears); the certificate upload flow as `phase4.spec.ts` drives it; Task 5's labels.

- [ ] **Step 1: Write the spec.** `for (const lang of ['en', 'tr'] as Lang[])`, describe `Incidents (${lang})`, one test: `start an incident, find it on the Incidents page, filter, open and close it`.
  1. `resetInstall`, then `runWizard`.
  2. Upload `newCert('hb1-incident.example.test')` with its key on **Certificates**.
  3. Open the certificate. Use **Start incident** (`incidents.start.*` labels), confirm the dialog, and answer the step-up with `freshCode` if it is asked. The incident page heading is `incidents.title`.
  4. Use the navigation link `nav.incidents`. The heading is `incidents.list.title`, and one row shows the certificate name and the state label `incidents.states.awaiting_replacement`.
  5. `expectAccessible(page, 'incidents-list')`.
  6. Choose filter `incidents.list.filter.needs_attention`: `incidents.list.emptyFiltered` is shown. Choose `incidents.list.filter.open`: the row is back.
  7. Open the row; the heading is `incidents.title`. **Close** the incident (`incidents.close.*`).
  8. Go back with the back link, which goes to the list (Task 5). Choose `incidents.list.filter.closed`: the row shows `incidents.states.closed`.
  - Every visible text comes from `translator(lang)`. No fixed sleeps (`settle`, `expect.poll`).
- [ ] **Step 2: Run it** (no Docker Go test running):
  Run: `E2E_PROJECT=alice-e2e-hb1 ALICE_E2E_PORT=9978 make e2e-up && cd web && ALICE_E2E_PORT=9978 ALICE_E2E_PROJECT=alice-e2e-hb1 npx playwright test e2e/hardening1.spec.ts --project=chromium; cd .. && E2E_PROJECT=alice-e2e-hb1 make e2e-down`
  Expected: 2 passed (EN, TR).
- [ ] **Step 3: Commit.** Message: `test(e2e): the Incidents page journey in English and Turkish: start, list, filter, open, close (D2, R64)`.

---

### Task 11: Decision R64, test IDs, traceability and the changelog

**Files:**
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md` (an R64 entry after R63, in R63's form). It names:
  - each item and its ruling numbers here;
  - the migrations `00033` and `00034`;
  - the codes `ALC-CRT-0020`..`0025`;
  - helper 1.11.0 with protocol 11;
  - the job `revocation.check` (`ClassReadOnly`);
  - the setting `revocation.check`;
  - the tests `HB-01`..`HB-17`;
  - KI-43.
- Modify: `docs/superpowers/specs/alice-v1/06-quality.md` (§24.8 "Hardening batch 1 (R64)" with the table below; the intro line at §24 lists the range); `docs/security/traceability.md` (one row per ID, naming the tests of each task).
- Modify: `CHANGELOG.md` (a new top section "Unreleased — Hardening batch 1 (R64)" with Added, Changed and Fixed). The update note says: "After an update the revocation check is off; switch it on in Settings, General, once the Alice host may reach your certificate authorities over HTTP and HTTPS. Update the helpers to 1.11.0."

| ID | Case | Expected |
|---|---|---|
| HB-01 | An incident place on a disabled server | The place fails with `target.disabled`; incident and key-deploy reasons equal the API catalogue's |
| HB-02 | A website-side person changes a Key Vault binding | They may release their own websites; adding, or releasing another service's website, is 403 |
| HB-03 | A certificate file whose leaf is labelled `TRUSTED CERTIFICATE` or `X509 CERTIFICATE` | The helper reports the leaf, never the intermediate; trust settings never reach Alice |
| HB-04 | A backup whose revoked leaf is labelled `TRUSTED CERTIFICATE` | The rollback guard refuses the restore |
| HB-05 | Incident list with state, open and paging, scoped | Pages without repeat or gap; only incidents of the caller's services |
| HB-06 | The Incidents page | Rows, filter, Load more and empty states in EN and TR |
| HB-07 | Incidents journey | Start, list, filter, open, close in EN and TR |
| HB-08 | An incident needs attention or completes | One mail per change per recipient, to the service recipients with Administrator fallback; none on close |
| HB-09 | Two cleanup jobs at once; outbox pruned | The store notice is sent once |
| HB-10 | An incident needs attention while the licence is locked | The mail is queued |
| HB-11 | OCSP good, revoked, hold, unknown, wrong signer, garbage, stale | Only a signed, current answer decides; failures fall to CRL or `unavailable` |
| HB-12 | CRL listed, not listed, stale, bad signature, other issuer, PEM | As Ruling 16 |
| HB-13 | OCSP or CRL addresses that are loopback, link-local, metadata, another port, a redirect, too large | Refused before or during the request; nothing is marked |
| HB-14 | 300 due certificates on one host; failures | 50 per host per run, batch 200; backoff 1 h to 24 h |
| HB-15 | The authority revoked an inventory certificate | Marked revoked (final), deployments refused, ACME renewal due, one audit row, one mail |
| HB-16 | The switch | On for a new installation, off after an update; off, locked or unconfigured make no request |
| HB-17 | The certificate page and Settings | The check's status and the switch shown in EN and TR |

- [ ] **Step 1: Write** the entries.
- [ ] **Step 2: Run.**
  Run: `make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check`
  Expected: PASS (every HB ID maps to existing tests).
- [ ] **Step 3: Commit.** Message: `docs: decision R64, test IDs HB-01..HB-17 with their traceability, and the changelog of hardening batch 1 (R64)`.

---

### Task 12: Gates, final review and the rulings file

**Files:**
- Create: `docs/superpowers/rulings/hardening-2026-10-24.md`, containing:
  - the "Rulings" section below, with any execution rulings added, each with its reason and cost if wrong;
  - "Owner to confirm";
  - "Deferred";
  - the gate evidence.
- Modify: `docs/superpowers/rulings/certificate-revocation.md` §"Not done / deferred": D2, D3 and D5 each gain "done in R64 (`docs/superpowers/rulings/hardening-2026-10-24.md`)". D1 and D4 stay open.

- [ ] **Step 1: Run the full gate** on the branch, with no Playwright or other Docker run active:
  Run: `make ci E2E_PROJECT=alice-e2e-hb1 ALICE_E2E_PORT=9978`
  Expected: exit 0. Record in the rulings file:
  - the e2e totals;
  - each coverage floor met, quoting `internal/revocation`, `internal/inventory`, `internal/api`, `internal/notify`, `cmd/alice-helper` and `internal/jobs`;
  - `make test-ssh` green with helper 1.11.0.

  If the machine needs it, run in stages as earlier phases did: `make lint test coverage perf test-backup-cycle test-ssh build release-symcheck i18n-check web-lint web-coverage vuln secrets-scan fs-scan`, then the e2e pair, then `make image-check image-scan`.
- [ ] **Step 2: Final review.** Use `superpowers:requesting-code-review` over `main..hardening-1`. Fix every Critical and Important finding in its own commit (subject ending `(R64)`), and re-run the affected packages' tests. List the declined Minor findings in the rulings file with their reasons.
- [ ] **Step 3: Write the rulings file** and the `certificate-revocation.md` markers.
  Run: `make docs-check`
  Expected: PASS.
- [ ] **Step 4: Commit.** Message: `docs(rulings): hardening batch 1 rulings, owner items and gate evidence (R64)`.

---

## Rulings (each goes into `docs/superpowers/rulings/hardening-2026-10-24.md` for the owner to confirm)

1. **Decision R64: one decision for the six items.**
   - Two migrations (`00033`, `00034`), six codes (`ALC-CRT-0020`..`0025`), test IDs `HB-01`..`HB-17`, KI-43 new and KI-39 amended.
   - Cost if wrong: none functional. A reviewer who wants one decision per item renumbers the entries.

2. **The `ErrTargetDisabled` mismatch is the incident engine's `codeOf`, not the two catalogues** (Task 1).
   - The API and the key deploy job both say `target.disabled`. `codeOf` lacked the case, so a refused incident place stored `internal.unexpected`.
   - The fix adds the case and exports the two functions, so an API test locks both lists to the catalogue: a new sentinel added to `isRefusal` without a code fails `TestIncidentRefusalCodesMatchTheCatalogue`.
   - The one documented exception is the key-type mismatch (`incident.not_deployable`: a stored code carries no params).
   - Cost if wrong: if the memory note meant another mismatch, it is still open. The new tests would have found any reason difference between the job list and the API.

3. **The incident list keeps its route, scope and permission** (`scopeList`, `rbac.Read`, `IncidentVisible`), and only gains `state` and `cursor`.
   - Reading incidents is `read` for every role (certificate-revocation ruling 5). The reach rule already limits rows to the caller's services (R49 Phase 2), and Task 4 pins it under paging.
   - `open` stays for compatibility (the certificate page uses it).
   - Cost if wrong: an Auditor or read token sees incidents of its services, as on the certificate page today. Restricting that is a permission change for the owner.

4. **The list page is a navigation entry under Operations, labelled "Incidents"/"Olaylar", visible with `read`.**
   - It sits beside Deployments: an incident is replacement work in progress. It shows for everyone who can open an incident page.
   - Cost if wrong: a label or position change only.

5. **The incident e-mails are three texts** (`incident.needs_attention`, `incident.completed`, `incident.completed_not_revocable`) **and nothing else.**
   - No mail on start: the starter is an Administrator on the page.
   - No mail on close: a person did it.
   - No mail on `awaiting_replacement`: the starter just chose a non-ACME certificate and the page says a replacement is needed.
   - The attention code is sent as `error_reason`, so the reader sees the code's plain title in their language (as the ACME renewal mails do).
   - Cost if wrong: service owners learn about a new incident only from the first needs-attention or completed mail. Adding a "started" mail is one template.

6. **Recipients are the incident's services, as the RBAC phase 4 rules say.** That is `certificate_incidents.service_ids` (the certificate's service and every service holding an affected place at start) plus the certificate's service, through `NotifyServices`. That gives the Administrators unless every policy leaves them out, the owners and the policies' extra addresses, falling back to the Administrators when nobody is named.
   - Cost if wrong: a service that gained a place after the start gets no mail; the start fixes `service_ids` by design §5.6.

7. **KI-39: accept the OpenSSL labels and re-encode; do not report them as a location problem.**
   - Nginx, Apache and HAProxy serve a `TRUSTED CERTIFICATE` or `X509 CERTIFICATE` leaf (`PEM_read_bio_X509_AUX`), so the website works. Reporting a problem would remove a working website's certificate from Alice and its expiry mails.
   - The trust settings after a `TRUSTED CERTIFICATE` are local OpenSSL trust data that TLS never sends, so dropping them hands Alice exactly what clients see.
   - Mirroring OpenSSL: the chain accepts `CERTIFICATE` and `X509 CERTIFICATE`, and skips a later `TRUSTED CERTIFICATE` (a dropped-block warning, as Nginx skips it).
   - The rollback guard's leaf reader gets the same rule. It took the intermediate for such a leaf and so could restore a revoked one (R48 G5).
   - Cost if wrong: if some server reads the chain differently, the chain Alice shows can differ from the served one. The leaf, the expiry and the guard stay right.

8. **Helper 1.11.0, protocol 11 unchanged.**
   - The answer's shape is the same (blocks labelled `CERTIFICATE`, no new problem value), so an older Alice reads a 1.11.0 helper and Alice reads a 1.10.0 helper.
   - No minimum version is raised. The guides say an older helper still shows the intermediate for such files, and that helpers should be updated first, then Alice.
   - Cost if wrong: if a later change needs the label reported, that needs a protocol bump then.

9. **`bindingChange`: widen the route, keep the branches** (Task 2).
   - Design §5.6 gives either side the right to remove a location ("the receiving service can always detach its own server"). The handler was written for the website side, but the guard's default resolver (`Owning` = the vault's service) never let that caller in.
   - `anyVisible` lets a caller with `certificates.operate` on any service the binding is visible from reach the handler. The handler then refuses additions (403) and the release of websites the caller holds no right on (403), and keeps unseen websites.
   - Adding stays vault-side only. Switching automatic deployment, deploying and deleting the whole binding keep their resolvers.
   - Cost if wrong: a website-side Operator can now release its own servers from a vault binding. That is a safety action the design allows and the ACME binding already allows (`byEither` on its DELETE).

10. **`DELETE /bindings/{id}` stays vault-side.** §5.6 "either side" for removing the whole binding would let one website's service remove a binding that also serves other services' websites. Not done; an owner item.
    - Cost if wrong: a website-side person releases its websites with PATCH instead.

11. **Incident mails are queued in the state change's transaction; no notice table for them.**
    - The conditional `UPDATE ... WHERE state = $2 AND finished_at IS NULL` serializes competing engines: the loser changes 0 rows and queues nothing, and a rollback removes the mail with the change.
    - A retry that fails again is a new entry into `needs_attention` and mails again. That is wanted: it is new news.
    - Cost if wrong: a person who retries in a loop gets one mail per failed retry.

12. **The W3 duplicate store notice is settled with `incident_notices`** (Task 6).
    - The old check read the outbox: two concurrent jobs both found nothing, and the outbox's retention pruning later made a repeat possible.
    - The primary key `(incident_id, notice)` with `ON CONFLICT DO NOTHING` decides once, under concurrency and forever.
    - The upgrade back-fills from the outbox rows still present.
    - Behaviour change: a notice that found no recipient at all (no Administrator with an address) is now recorded and not retried. Before, it was retried by a later job.
    - Cost if wrong: in that rare installation the notice is lost; the incident page still lists the place.

13. **Incident mails go out while the licence is locked** (recommended and adopted).
    - `incident.advance` is `ClassAlways` and already follows running deployments in lock; queuing mail is notification work, which lock never stops (`notify.send` is `ClassAlways`; L-28 sends expiry mails in lock).
    - A key compromise is the case where silence is worst.
    - Cost if wrong: a locked installation still sends incident mails; that is what the expiry mails already do.

14. **D5 checks every unexpired, unrevoked, non-self-signed certificate Alice holds, of any source, plus discovery leaves that have no inventory row.**
    - ACME certificates included: a CA's mass revocation, such as Let's Encrypt's 2020 CAA incident, reaches Alice, and ruling 4 of certificate-revocation renews a revoked current certificate at once.
    - Key Vault and uploaded certificates are included because Alice deploys them.
    - Cost if wrong: more requests than a narrower set; bounded by Ruling 17.

15. **What a revocation does: a finding, not an incident.**
    - A signed revoked answer marks the inventory certificate revoked (final, Z1022), with `revocation_seen` = `ocsp`/`crl`. Marking stops every deployment of it (ALC-CRT-0018) and arms the R48 rollback guard; it is the same mark as an Alice revocation.
    - The mail tells the reader what to do: replace it, or start an incident for `keyCompromise`. Alice never starts an incident by itself: an incident marks every certificate with the key compromised and replaces files on servers, which a revocation for `superseded` or `cessationOfOperation` does not justify. The person decides.
    - `certificateHold` is recorded and mailed but not marked, because the authority can lift it.
    - Cost if wrong: if a responder signs a wrong "revoked", Alice stops deploying a certificate for good. Mitigated by verifying the signature against the issuer Alice holds, and by the certificate being refused by every client anyway.

16. **The check algorithm** (Task 7, "Check algorithm"):
    - OCSP first and CRL as fallback. Only signed, current answers count, and a listed serial in a stale CRL still counts (revocation is permanent).
    - `unknown` is recorded, never acted on.
    - Unreachable and invalid answers are `unavailable` with a closed code and backoff.
    - No nonce: most public responders follow RFC 5019 and ignore one; the freshness window is the replay control.
    - No AIA caIssuers fetch: a certificate without its issuer is `not_checkable` (`no_issuer`).
    - Cost if wrong: certificates whose server sends no intermediate are never checked. Deferred item E2.

17. **Outbound rule** (Task 7):
    - Allowed: http and https on ports 80 and 443 only, through netaddr plus a loopback/unspecified refusal.
    - No proxy, no redirect, a 10 s limit, answers capped at 64 KiB for OCSP and 10 MiB for CRLs.
    - At most 50 requests per responder host per run. Runs every 15 minutes, 200 certificates per run, a 4-minute run budget.
    - A good certificate is checked again after 24 h, an unknown one after 24 h, an on-hold one after 6 h, a not-checkable one after 7 days. Failures back off from 1 h to 24 h.
    - Private addresses are allowed, because company authorities live there.
    - The ACME transport (`internal/acme/transport`) is not reused: it is https-only, and OCSP and CRL are almost always plain http.
    - Cost if wrong: a company authority on another port is refused (`address_refused`; owner item); an installation that needs a proxy cannot check (owner item); 4800 OCSP requests per host per day can be fewer than a very large single-CA estate needs, in which case its certificates are checked less often than daily.

18. **`unknown` is not acted on and sends no mail.** The responder does not know the certificate, which is often a misconfigured responder, not a revocation. The certificate page shows it.
    - Cost if wrong: a certificate a rogue CA "forgot" is not flagged; that is outside what revocation checking can prove.

19. **The switch: on for a new installation, off after an update.**
    - Justification for on: the requests read public data that every TLS client is expected to fetch, they change nothing, and they are bounded. A fresh installation should not miss a revocation for want of a setting nobody knew about.
    - An updated installation gets the setting written `false` by `00034` (when a user exists), because new outbound traffic after an update can trip a customer's egress controls or IDS. The CHANGELOG, the operator guide and Settings say how to switch it on.
    - Cost if wrong: updated installations stay unchecked until someone switches the check on. The owner may prefer on for both.

20. **The check job is `ClassReadOnly`** (paused while the licence is locked), as discovery is: recurring read-only work, R29.
    - The alternative, `ClassAlways` like the expiry scan, was not chosen: this work goes out to third parties, not only to Alice's database.
    - Cost if wrong: during a lock Alice learns of no new revocation. Owner item.

21. **Codes `ALC-CRT-0020`..`0025` continue the certificate family.** They are stored reasons of a check, shown through `errorRef` with troubleshooting sections. None is a route answer today.
    - Cost if wrong: they are renumbered at merge if another branch takes these numbers.

22. **e2e covers D2 only.** D3 and D5 are covered on PostgreSQL with the real checker against the fake servers, and the e2e build never ticks periodic tasks. A Playwright journey for a revocation would need a fake responder in the compose stack.
    - Cost if wrong: the D5 web text is covered by Vitest only. Deferred item E4.

## Owner to confirm

1. Ruling 19: the check **on** for new installations and **off** after an update, or on for both.
2. Ruling 20: `revocation.check` paused in lock (`ClassReadOnly`), or running in every state.
3. Ruling 17: ports 80 and 443 only, no proxy support, private addresses allowed. Does any customer authority need another port or a proxy?
4. Ruling 15: Alice marks a certificate revoked for good on the authority's signed word, and never starts an incident by itself (including for `keyCompromise`).
5. Ruling 5: no "incident started" mail to service owners.
6. Ruling 10: whether the website side may delete a whole Key Vault binding (`DELETE /bindings/{id}`), as §5.6 "either side" could be read.
7. Ruling 12: the store notice is not retried when it had no recipient.
8. Ruling 9: the website side may now release its websites from a Key Vault binding (a widening of what a scoped Operator can do).
9. KI-43 wording and severity (Low).

## Deferred (recorded in the rulings file)

- E1: the discovery page does not show a discovery certificate's revocation status (only the mail does).
- E2: fetching a missing issuer from the AIA caIssuers address.
- E3: OCSP nonce, delta CRLs, partitioned-CRL scope checks (`IssuingDistributionPoint` reasons).
- E4: a revocation e2e journey with a compose fake responder.
- E5: proxy support for outbound checks.
- certificate-revocation D1 (revocation with the certificate's key) and D4 (replacing places of other certificates with the same key) stay open.
