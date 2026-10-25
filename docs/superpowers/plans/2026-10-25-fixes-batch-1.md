# Fixes Batch 1 (Disabled Servers on Every Deploy Path, Discovery Revocation Status, Windows Wording, Test Robustness) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the small, decision-free fixes left open by R60-R64, as the owner asked before leaving ("all remaining small fixes", unattended).

**Architecture:** No new module, no migration, no new error code, no new permission, no helper protocol bump.
- F1 (hardening ruling 23, final review M3, owner item 10) is a single new rule in `checkDeployLocation`: a disabled server is refused with `inventory.ErrTargetDisabled`. Every deploy path uses that check, so every path agrees: manual routes answer `ALC-TGT-0006`, automatic planners skip silently as before, and an incident place fails at once with `target.disabled`.
- E1 (hardening deferred) adds the `revocation_checks` row, read by fingerprint, to the discovered certificate's detail (API and drawer). The certificate page's fact order (a declined R64 minor) is fixed in the same task.
- The ACME bindings panel and the Key Vault texts stop saying "file" or "Nginx" where a Windows binding is shown or deployable.
- One load-sensitive e2e assertion and three release-tooling test minors are made robust, without weakening what they prove.

**Tech Stack:** Go 1.27.3, pgx/v5, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright.

**Spec:** the open items of these files (the plan argues from them):
- `docs/superpowers/rulings/hardening-2026-10-24.md`: ruling 23, "Found, not fixed" F1, "Final review fixes" M3, "Owner to confirm" 10, "Deferred" E1, and the declined Minor findings.
- `docs/superpowers/rulings/windows-iis.md`: W3 "Rulings made during execution" (the ACME bindings panel wording), W4 Task 5, "Deferred to W5+" (minors deferred during W4).
- `docs/superpowers/rulings/certificate-revocation.md`, `scoped-access.md`, `prod-readiness-2026-10-16.md`, `acme-dns-providers.md`, `web-server-standard.md`: evaluated. What they still hold is under [Deferred](#deferred-recorded-in-the-rulings-file), each with its reason.

The format model is `docs/superpowers/plans/2026-10-24-hardening-batch-1.md`.

**Decision:** R66 "Fixes batch 1". R64 is the last entry of `docs/superpowers/specs/alice-v1/00-decisions.md` on `main` at `36a415af`. R65 (canary) is reserved by the parallel branch, so R66 goes after R65 if that branch merged first, otherwise after R64. **Size:** S-M, 6 tasks plus the final gates. **Migrations:** none.

## Global Constraints

- **Branch.** Worktree branch `fixes-1`, cut from `main` at `36a415af` or later. The first commit is this plan file, copied unchanged. Take `main` in with `git merge main`, never rebase. Never push `main` and never open a pull request; the coordinator merges and pushes.
- **Commits.**
  - Command: `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R66)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R66)`.
  - Stage new files with `git add -- <path>`. Never use `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (an untracked root binary) or `docs/security/reviews/*`. Never rebase, squash or amend (`.gitleaksignore` pins commit hashes).
- **Parallel branch (R65 canary).** It changes `internal/inventory/deployment*.go`, `internal/jobs/deployjobs` and `internal/api/deployments*`.
  - Task 1 changes one function in `internal/inventory/deployments.go` (`checkDeployLocation`) plus two doc comments in that file. It changes nothing in `deployjobs` or `internal/api/deployments*`.
  - [Files touched for the merge order](#files-touched-for-the-merge-order) lists every file. If R65 merged first, `git merge main` before Task 1. A conflict in `deployments.go` is resolved by keeping both changes.
  - R65 may also add a test-ID prefix on the same `idRowRe` line of `tools/matrixcheck/main.go` (Task 6) and a §24.x section. Keep both.
- **Migrations.** None. If one ever proves unavoidable, stop and report: the next free number at implementation time is expected to be `00036` (R65 takes `00035`).
- **Error codes.** None new. Task 1 makes `ALC-TGT-0006` (already in `internal/api/errors.go:112`) a deploy-route answer. `ALC-DEP-0031..0035` and `ALC-SVC-0020` are reserved by R65; do not use them.
- **Test IDs.** `FX-01`..`FX-06` go in a new section of `docs/superpowers/specs/alice-v1/06-quality.md`. It is the next free §24.x: `24.9` if R65 has not merged, otherwise the one after R65's. Their rows go in `test/matrix/traceability.json`, and `docs/security/traceability.md` is regenerated (Task 6).
- **Ports.** No fake server is needed. If one ever is, use `45440`-`45459`.
- **e2e.** Only Task 4 changes a spec (`web/e2e/phase4.spec.ts`). Project `alice-e2e-fx1` on `ALICE_E2E_PORT=9980`: `E2E_PROJECT=alice-e2e-fx1 ALICE_E2E_PORT=9980 make e2e-up e2e`, then `E2E_PROJECT=alice-e2e-fx1 make e2e-down`. Docker-based Go runs (testcontainers, `make coverage`, `make test-ssh`) and Playwright never run at the same time, and neither runs while another `make ci` is active. Check with `pgrep -af 'playwright|make ci|go test'` first.
- **Coverage floors** (`coverage-floors.json`): never lower one. No new package, so no new floor.
- **Archtest.** No new import edge. E1 reads `revocation_checks` inside `discoverysvc` with its existing pool, so `discovery` gains no inventory import.
- **Locales.** EN and TR keep identical keys and placeholders (`make i18n-check`).
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `go test -race -count=1 ./<pkgs>`
  - Integration (Docker; never alongside Playwright): `go test -race -count=1 -tags integration ./<pkgs> -run <name>`
  - Web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - `make lint`, `make test`, `make i18n-check`, `make docs-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`; at the end, `make ci`.

## Review Focus

1. **A manual deployment that includes a disabled server's website** must be refused all or nothing. It answers 409 `ALC-TGT-0006` with `params.location_id` naming that website, writes a `deployment.denied` audit row with reason `target_disabled`, and queues nothing for the other websites. This holds on all four manual routes: certificate deploy, Key Vault binding deploy, ACME Deploy now, and drift Repair. Tests: Task 1 `TestRequestDeploymentRefusals` (the new disabled step), `TestRequestKVDeployment` row, `TestCertificateErrorsMapToCodes` row.
2. **The automatic planners must stay silent about a disabled server**: no denial audit, no mail, and the other websites still deploy. Tests: Task 1 `TestACMEAutoDeploySkipsWhatIsNotReady` (the new disabled step); the existing `kv_autodeploy_integration_test.go:420` status table (`disabled: 0`) must stay green unchanged.
3. **An incident whose server is disabled after the start** fails only that place, at once, with `target.disabled`. Places on other servers continue. After the server is enabled again, Retry deploys the place. Test: Task 1 `TestIncidentPlaceOnADisabledServerFailsAtOnce`.
4. **A discovered certificate that was never checked, or whose check failed,** shows "Not checked yet" or the failure's reason, never an empty fact or a crash. The list and the CSV export keep their shape. Tests: Task 2 `TestCertificateInCarriesTheRevocationCheck` (three cases), `TestDiscoveryCertificateDetailRevocationCheck`, Vitest `shows the revocation check of the found certificate`.
5. **An ACME certificate bound to both a Windows binding and a certificate file** shows a column header that fits every row. Test: Task 3 Vitest `names the place column by the kinds it lists`.

---

### Task 1: A disabled server is refused as disabled on every deploy path (F1)

**Finding** (verified at `36a415af`):
- `checkDeployLocation` (`internal/inventory/deployments.go:545`) refuses every status outside `targetReady` (`ok`, `unreachable`, `checking`) as `ErrTargetNotReady`. That includes `disabled`.
- Every deploy path calls it:
  - `RequestDeployment`. This covers the certificate route, ACME Deploy now (`acme_bindings.go:408`), drift Repair through `DeployACMENow`, and the incident engine.
  - `RequestKVDeployment` (`kv_deploy.go:199`). This covers the binding route and drift Repair for Key Vault.
  - The planners: ACME (`acme_autodeploy.go:355`), Key Vault (`kv_autodeploy.go:340,353`) and drift repair (`drift_repair.go:237`).
- So `IncidentRefusalCode`'s `target.disabled` case cannot be reached. The incident engine treats `ErrTargetNotReady` as busy (`incidents_engine.go:428`): 30 runs, then `incident.location_busy`.
- The deploy job already records `target.disabled` at send time (`internal/jobs/deployjobs` tests `deployjobs_test.go:538`, `kv_test.go:909`). Only the request side disagrees.
- `sshkeyjobs.DeployRefusalReasons` already maps `ErrTargetDisabled` to `target.disabled` (SSH key deploys use `KeyChangeRefusal`, which refuses a disabled server already). It needs no change; `TestSSHKeyDeployRefusalsMatchTheCatalogue` keeps locking it.
- `errorMap` already maps `inventory.ErrTargetDisabled` to `ALC-TGT-0006`, and `fail` adds `params.location_id` for a `*LocationRefusalError`. So no API code change is needed.

**Files:**
- Modify `internal/inventory/deployments.go`:
  - `checkDeployLocation`: add a case after `!s.canDeploy(t.Type)` and before the `targetReady` case: `case t.Status == StatusDisabled: return "target_disabled", ErrTargetDisabled`.
  - Doc comments: in the `targetReady` comment, a disabled server is now named as refused by its own rule. In `RequestDeployment`'s refusal list, add `ErrTargetDisabled` before `ErrTargetNotReady`.
- Modify `internal/inventory/incidents_engine.go`: only the `requestIncidentDeployment` doc comment ("a disabled server fails the place at once"). No code change: `ErrTargetDisabled` is not in the busy case and is already an `IsIncidentRefusal`.
- Tests:
  - `internal/inventory/deployments_integration_test.go`
  - `internal/inventory/kv_deploy_integration_test.go`
  - `internal/inventory/acme_autodeploy_integration_test.go`
  - `internal/inventory/incidents_more_integration_test.go`
  - `internal/api/certificates_handlers_test.go`
- Texts:
  - `locales/common/en.json` and `tr.json`, `errors.deployment.target_not_ready.cause`.
  - `docs/troubleshooting.md`, the `ALC-DEP-0011` and `ALC-TGT-0006` sections.
  - `api/openapi.yaml`: the refusal lists of `deployCertificate` (line ~2205) and of the binding and ACME deploy operations (`/api/v1/bindings/{id}/actions/deploy`, `/api/v1/acme/certificates/{id}/deploy`) where they list refusals.

**Interfaces:**
- Produces: `checkDeployLocation` returns `("target_disabled", ErrTargetDisabled)` for `t.Status == StatusDisabled`. Its signature is unchanged.

- [ ] **Step 1: Write the failing tests.**
  - `TestRequestDeploymentRefusals` (deployments_integration_test.go:274), next to the `host_key_changed` step:
    - `f.setTargetStatus(f.target2, inventory.StatusDisabled)`;
    - `err := req(f.admin, f.cert.ID, false, f.loc3onTarget2)`; `assert.ErrorIs(t, err, inventory.ErrTargetDisabled)`; `assert.NotErrorIs(t, err, inventory.ErrTargetNotReady)`;
    - `var lr *inventory.LocationRefusalError`; `require.ErrorAs(t, err, &lr)`; `assert.Equal(t, f.loc3onTarget2, lr.LocationID)`;
    - all or nothing: `req(f.admin, f.cert.ID, false, f.loc5, f.loc3onTarget2)` errors, and the job and deployment counts do not change;
    - `"target_disabled"` joins the `assert.Subset` list of audit reasons;
    - reset with `f.setTargetStatus(f.target2, "ok")`.
  - `kv_deploy_integration_test.go` (near line 184): after the `auth_failed` row, `b.setTargetStatus(b.target1, inventory.StatusDisabled)`; `refused("a disabled server", inventory.ErrTargetDisabled, "target_disabled", b.admin, v1, b.loc1)`; reset to `ok`.
  - `TestACMEAutoDeploySkipsWhatIsNotReady`: before the `auth_failed` step, `w.setTargetStatus(w.target2, inventory.StatusDisabled)`; `assert.Equal(t, 1, w.plan().Created)`; `assert.Equal(t, []uuid.UUID{w.loc1}, locationsOf(w.deps(cur)))`; `assert.Zero(t, w.h.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.denied'"))`. Then go on with the existing steps, cleaning up the deployment created by this step the way the test already does.
  - Rename `TestIncidentPlaceOnADisabledServerWaitsAndFailsBusy` to `TestIncidentPlaceOnADisabledServerFailsAtOnce`. Keep the setup, then:
    - after one `w.advance()`: `assert.Equal(t, "failed:target.disabled", locationStatus(i)[f.loc2])`; `assert.Equal(t, 1, incidentLocation(t, i, f.loc2).Attempts)`; `assert.Equal(t, "deploying", locationStatus(i)[f.loc1])`;
    - drop the `attempts = 29` part;
    - then `f.setTargetStatus(f.target2, inventory.StatusOK)`; let the incident reach `needs_attention` (finish loc1's deployment as the neighbouring tests do); `h.svc.RetryIncident(h.ctx, f.admin, i.ID)`; `w.advance()`;
    - `assert.Equal(t, "deploying", locationStatus(w.incident(i.ID))[f.loc2])`;
    - rewrite the comment above the test (FX-02; R66 ruling 2).
  - `TestCertificateErrorsMapToCodes` table in `certificates_handlers_test.go` (line ~240): add
    - `{inventory.ErrTargetDisabled, "ALC-TGT-0006", 409, nil}`;
    - `{&inventory.LocationRefusalError{LocationID: locationID, Err: inventory.ErrTargetDisabled}, "ALC-TGT-0006", 409, map[string]string{"location_id": locationID.String()}}`.
- [ ] **Step 2: Run them to verify they fail.**
  Run: `go test -race -count=1 -tags integration ./internal/inventory/ -run 'TestRequestDeploymentRefusals|TestKVDeploy|TestACMEAutoDeploySkipsWhatIsNotReady|TestIncidentPlaceOnADisabledServerFailsAtOnce'`
  Expected: FAIL. The error is `ErrTargetNotReady`, and the place is `pending`. The API rows already pass, because they only lock the mapping.
- [ ] **Step 3: Implement** the case and the comments.
  - EN `errors.deployment.target_not_ready.cause`: "The server is not connected: its host key fingerprint is not confirmed or has changed, or Alice cannot sign in."
  - TR: "Sunucu bağlı değil: ana bilgisayar anahtarının parmak izi onaylanmadı veya değişti ya da Alice oturum açamıyor."
  - `docs/troubleshooting.md` `ALC-DEP-0011` "Likely cause": the same EN text. `ALC-TGT-0006` "Likely cause": "The server was disabled before a deployment was requested, or while a task waited in the queue."
  - OpenAPI: add `409 ALC-TGT-0006 (the server is disabled)` before `409 ALC-DEP-0011` in each refusal list that names `ALC-DEP-0011` or the not-ready case.
- [ ] **Step 4: Run.**
  Run: `go test -race -count=1 ./internal/api/ ./internal/inventory/ ./internal/jobs/... && go test -race -count=1 -tags integration ./internal/inventory/ -run 'Deploy|Incident|ACMEAuto|KVAuto|Drift' && go test -race -count=1 -tags integration ./internal/jobs/acmejobs/ ./internal/jobs/kvjobs/`
  Expected: PASS. `TestIncidentRefusalCodesMatchTheCatalogue`, `TestSSHKeyDeployRefusalsMatchTheCatalogue`, `errors_catalogue_test.go:344` (contains "host key fingerprint") and the troubleshooting tests stay green.
- [ ] **Step 5: Commit.** Message: `fix(inventory): a disabled server is refused as disabled on every deploy path (ALC-TGT-0006 on the manual routes, silent skip in the planners), so an incident place there fails at once with target.disabled instead of waiting 30 runs as busy (F1, R66)`.

---

### Task 2: The discovered certificate's revocation check, and the certificate page's fact order (E1)

**Finding.** `revocation_checks` is keyed by fingerprint and covers discovery leaves without an inventory row (R64 ruling 14), but only the inventory certificate detail shows it (`certificateDetailDTO.revocation_check`). The discovery drawer shows nothing. The R64 final review also declined a Minor: the certificate page lists **Revocation check** as its first fact.

**Files:**
- `internal/discovery/link.go`:
  - `type RevocationCheck struct { Status, Method, Reason, ErrorCode string; RevokedAt *time.Time; CheckedAt, NextCheckAt time.Time }`;
  - `CertificateRow` gains `Revocation *RevocationCheck` ("the detail only; nil when never checked").
- `internal/discovery/discoverysvc/read.go`:
  - `CertificateIn` reads the row with an unexported `revocationCheckOf(ctx, q db.Querier, fingerprint string) (*discovery.RevocationCheck, error)` (the same `SELECT` as `inventory.revocationCheckOf`, `pgx.ErrNoRows` → nil, times in UTC) and sets `list[0].Revocation`;
  - `ListCertificates` and the export are unchanged.
- `internal/api/discovery_dto.go`:
  - `type discoveryCertificateDetailDTO struct { discoveryCertificateDTO; RevocationCheck *revocationCheckDTO `json:"revocation_check"` }`;
  - `func discoveryRevocationJSON(rc *discovery.RevocationCheck) *revocationCheckDTO`, which builds the same DTO as `revocationCheckJSON`, with `Error: errorRef(rc.ErrorCode, nil)`.
- `internal/api/discovery_handlers.go`: `getDiscoveredCertificate` writes the detail DTO.
- `api/openapi.yaml` `DiscoveredCertificate`: `revocation_check`, described as "The detail only; null before the first check", referencing `RevocationCheck` with the same nullability as `CertificateDetail` uses.
- Web:
  - Create `web/src/components/revocationCheck.ts`, exporting `revocationCheckText(t: TFunction, i18n: I18n, rc: RevocationCheck | null | undefined): string` and `methodName`. They move out of `CertificateDetailPage.tsx` unchanged (`undefined` is treated as `null`).
  - `web/src/api/discovery.ts`: `DiscoveredCertificate` gains `revocation_check?: RevocationCheck | null`.
  - `web/src/components/discovery/CertificateDrawer.tsx`: a fact labelled `t('certificates.revocationCheck.label')` with value `revocationCheckText(...)`, right after **Expires**.
  - `CertificateDetailPage.tsx`: imports the helper, and the `revocationCheck` fact moves to just after `chain` (before `privateKey`).
- No new locale key: the drawer reuses `certificates.revocationCheck.*` (EN and TR exist).
- Tests:
  - `internal/discovery/discoverysvc/read_integration_test.go` (create it; no test of `CertificateIn` exists in that package yet);
  - `internal/api/discovery_handlers_test.go`;
  - `web/src/components/discovery/ResultsTab.test.tsx` (it opens the drawer);
  - `web/src/pages/CertificateDetailPage.test.tsx`.

**Interfaces:**
- Produces:
  - `discovery.RevocationCheck`;
  - `discovery.CertificateRow.Revocation`;
  - `revocationCheckText` in `web/src/components/revocationCheck.ts`.

- [ ] **Step 1: Write the failing tests.**
  - `TestCertificateInCarriesTheRevocationCheck` (discoverysvc, integration):
    - (a) A leaf without a row: `c.Revocation == nil`.
    - (b) After inserting a `good` row (method `ocsp`): `Status == "good"`, `Method == "ocsp"`, `CheckedAt` in UTC.
    - (c) A `not_checkable` row with `error_code = 'certificate.revocation_untrusted_issuer'`: `ErrorCode` carried.
    - In every case `ListCertificates` rows have `Revocation == nil`.
  - `TestDiscoveryCertificateDetailRevocationCheck` (discovery_handlers_test.go):
    - `CertificateFn` returns `sampleCertRow()` with `Revocation` set to an `unavailable` row with `ErrorCode: "certificate.revocation_unavailable"` (use a code that exists in `AllErrorCodes()`). The detail's `revocation_check.status` is `"unavailable"` and `revocation_check.error.code` is that code's `ALC-CRT-*`.
    - With `Revocation` nil, `d["revocation_check"]` is present and `nil`.
    - The list body's items have no `revocation_check` key.
  - Vitest `shows the revocation check of the found certificate` (ResultsTab.test.tsx): the detail fixture with `revocation_check: { status: 'good', method: 'ocsp', ... }` shows "Not revoked (checked …, OCSP)" in the drawer's facts. With `revocation_check: null`, it shows "Not checked yet". Run in EN and in TR (the TR `status.none` text).
  - CertificateDetailPage.test.tsx: the facts list's labels are in order, and "Revocation check" comes right after the chain fact's label.
- [ ] **Step 2: Run to verify they fail.**
  Run: `go test ./internal/api/ -run DiscoveryCertificateDetailRevocation && cd web && npx vitest run src/components/discovery/ResultsTab.test.tsx src/pages/CertificateDetailPage.test.tsx`
  Expected: FAIL (no field, no fact, wrong order).
- [ ] **Step 3: Implement** as listed.
- [ ] **Step 4: Run.**
  Run: `go test -race -count=1 ./internal/api/ ./internal/discovery/... && go test -race -count=1 -tags integration ./internal/discovery/discoverysvc/ -run CertificateIn && cd web && npx vitest run src/components/discovery src/pages/CertificateDetailPage.test.tsx && npx tsc --noEmit && npm run lint`
  Expected: PASS.
- [ ] **Step 5: Commit.** Message: `feat(discovery): the found certificate's detail shows its last revocation check (API and drawer); the certificate page lists the check after the chain (E1, R66)`.

---

### Task 3: The ACME bindings panel and the Key Vault texts name Windows bindings

**Finding.** W4 Task 5 (WIN-44) added `location_kind` to the ACME binding and passes `windows` to `ObservationFacts` only. Three things are still wrong:
- The panel's column header is always `acme.issued.bindings.columns.file` ("Certificate file"), also over a `win_sslbinding` row.
- The add dialog's help says "Only Nginx websites", but `listDeployableLocations` also lists Windows bindings.
- The Key Vault texts say Nginx only, although Key Vault deploys to Windows bindings (`KVDeployDialog` follows `location_kind`).

Apache and HAProxy stay discovery-only, so they are not named.

**Files:**
- `web/src/components/acme/AcmeBindingsPanel.tsx`: the header picks:
  - `columns.binding` when every row is `win_sslbinding`;
  - `columns.file` when none is;
  - `columns.place` when the rows are mixed.
  
  Any kind other than `win_sslbinding` counts as a file.
- `web/src/locales/en.json` and `tr.json` (exact copy below).
- `docs/azure-setup.md:123`: the role row's label follows `vaults.roles.deploy`.
- Tests: `web/src/pages/AcmeCertificatePage.test.tsx`, `web/src/components/AccessCheckPanel.test.tsx`, `web/src/components/RoleGuide.test.tsx` (they match "Deploy certificates to Nginx").

| Key | EN | TR |
|---|---|---|
| `acme.issued.bindings.columns.binding` (new) | Binding | Bağlama |
| `acme.issued.bindings.columns.place` (new) | Certificate file or binding | Sertifika dosyası veya bağlama |
| `acme.issued.bindings.addHelp` | Choose the websites that should use this certificate. Only websites on Nginx and Windows (IIS) servers whose key type fits are listed. Automatic deployment starts off for each of them. | Bu sertifikayı kullanacak web sitelerini seçin. Yalnızca Nginx ve Windows (IIS) sunucularındaki, anahtar türü uyan web siteleri listelenir. Her biri için otomatik dağıtım kapalı başlar. |
| `vaults.intro` | Alice watches the certificates, keys and secrets of your Azure Key Vaults and can deploy their certificates to your Nginx websites and Windows (IIS) bindings. | Alice, Azure Key Vault kasalarınızdaki sertifikaları, anahtarları ve gizli anahtarları izler; kasadaki sertifikaları Nginx web sitelerinize ve Windows (IIS) bağlamalarınıza dağıtabilir. |
| `vaults.roles.deploy` | Deploy certificates to Nginx and Windows (IIS) | Sertifikaları Nginx'e ve Windows'a (IIS) dağıtma |
| `vaults.page.boundaryText` | Certificates can be monitored and deployed to Nginx and Windows (IIS). Keys are inventory-only; secrets show metadata only. | Sertifikalar izlenebilir ve Nginx’e ve Windows’a (IIS) dağıtılabilir. Anahtarlar yalnızca envanter içindir; gizli verilerin sadece üst bilgileri gösterilir. |

- [ ] **Step 1: Write the failing test.** Vitest `names the place column by the kinds it lists` (AcmeCertificatePage.test.tsx), with three binding lists:
  - two `server_file` rows: the header "Certificate file";
  - two `win_sslbinding` rows: "Binding";
  - one of each: "Certificate file or binding".
  
  A second test: the add dialog's help text contains "Windows (IIS)". Update the two role tests to "Deploy certificates to Nginx and Windows (IIS)".
- [ ] **Step 2: Run to verify it fails.**
  Run: `cd web && npx vitest run src/pages/AcmeCertificatePage.test.tsx`
  Expected: FAIL.
- [ ] **Step 3: Implement** the header rule and the copy. Change `docs/azure-setup.md:123` to `| Deploy certificates to Nginx and Windows (IIS) | …`.
- [ ] **Step 4: Run.**
  Run: `cd web && npx vitest run src/pages/AcmeCertificatePage.test.tsx src/components/AccessCheckPanel.test.tsx src/components/RoleGuide.test.tsx && npx tsc --noEmit && npm run lint && cd .. && make i18n-check docs-check`
  Expected: PASS. Then `grep -rn "Deploy certificates to Nginx\"\|Only Nginx websites" web/e2e web/src` finds no stale literal.
- [ ] **Step 5: Commit.** Message: `fix(web): the ACME bindings panel names a Windows binding as a binding, and the add help and the Key Vault texts name Windows (IIS) where it is deployable (R66)`.

---

### Task 4: The five-website polling journey proves continuous polling without measuring the machine's speed

**Finding.** `web/e2e/phase4.spec.ts` "a deployment to five websites at once is followed without being throttled" asserts at least 60 deployment reads in a minute and at least 10 reads per run. Under load (W2 `make ci`, load average 5.5) it read 22 a minute and failed.

`watchDeployments` sleeps one tick after each round of reads, so slow answers stretch each tick. The lower bound measures the browser's speed, not Alice. The polling rate itself is proved deterministically by Vitest (`web/src/api/deployments.test.ts`, "stays far below…": at least 55 and at most 125 reads a minute with fake timers). The journey's real claims are:
- never more than the budget;
- no 429;
- every run followed all minute.

**Files:** `web/e2e/phase4.spec.ts` only.

- [ ] **Step 1: Change the assertions.**
  - Keep:
    - the "polls for a full minute" wait (≥ 61 s);
    - `most(deploymentReads()) <= 125`;
    - `most(responses) <= 150`;
    - "every run is followed" (`size === SITES.length`);
    - both "no 429" checks.
  - Replace `toBeGreaterThanOrEqual(60)` and the per-id `>= 10` loop with a loop over each run id. For the times of its reads `ts` within `[pollStart(), pollStart() + 61_000]`, sorted:
    - `expect(ts.length, …).toBeGreaterThanOrEqual(3)`;
    - the largest gap among `[pollStart(), ...ts]` neighbours is `toBeLessThanOrEqual(30_000)` (message: `${id}: read at least every 30 s`).
  - Rewrite the comment block to say why (the Vitest budget test pins the rate; R66 ruling 6).
- [ ] **Step 2: Type-check.**
  Run: `cd web && npx tsc --noEmit -p e2e 2>/dev/null || npx tsc --noEmit && npm run lint`
  Expected: PASS.
- [ ] **Step 3: Run the spec** (no Docker Go run active). `E2E_PROJECT=alice-e2e-fx1 ALICE_E2E_PORT=9980 make e2e-up`, then from `web/`: `ALICE_E2E_PORT=9980 ALICE_E2E_PROJECT=alice-e2e-fx1 npx playwright test e2e/phase4.spec.ts -g "five websites" --project=chromium`.
  Expected: 2 passed (EN, TR). Record the annotation's read counts in the commit body. Leave the stack up for Task 7, or `make e2e-down` with the project.
- [ ] **Step 4: Commit.** Message: `test(e2e): the five-website journey proves every run is read at least every 30 s instead of 60 reads a minute, which measured the machine's load (R66)`.

---

### Task 5: Release tooling minors deferred in W4

**Finding** (`windows-iis.md` "Minors deferred during W4"):
- (a) `helperSetEntries` (`tools/releasebuild/main.go:736`) skips malformed lines and accepts extra or duplicate lines in a helper checksum file (final review m-4). The Makefile writes each file with exactly its two binaries (`Makefile:202,208`), so the strict rule matches every file the build makes.
- (b) No `TestStageRefusesAMissingInput` row covers a checksum file that lacks one `.exe` line.
- (c) `refusalNames` is keyed by subtest names.
- (d) `TestReleasedHelperVersion`'s "numeric, not text" case does not discriminate: `1.0.0` against `0.3.0` is also right as text.

**Files:** `tools/releasebuild/main.go`, `tools/releasebuild/main_test.go`, `internal/providers/windows/winproto/winproto_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestStageRefusesAMissingInput` rows, each naming the checksum file and `make winhelper` (or `make helper`):
    - "a Windows checksum file without its arm64 line" (only the amd64 line);
    - "a duplicate line" (the amd64 line twice plus arm64);
    - "an extra line" (a third line for `alice-winhelper-windows-386.exe` with a valid hash);
    - "a malformed line" (`<hash> alice-winhelper-windows-amd64.exe` with one space).
  - Restructure the row table so each row carries its `names []string` beside its setup function, and delete the `refusalNames` map.
  - In `TestReleasedHelperVersion`, add `if !winproto.VersionAtLeast("0.10.0", "0.9.0") { t.Error("0.10.0 must compare above 0.9.0 numerically") }` and the reverse `if winproto.VersionAtLeast("0.9.0", "0.10.0") {…}`.
- [ ] **Step 2: Run to verify.**
  Run: `go test ./tools/releasebuild/ -run TestStageRefusesAMissingInput ./internal/providers/windows/winproto/ -run TestReleasedHelperVersion`
  Expected: the duplicate, extra and malformed rows FAIL. The missing-line row already passes (lock it). The version cases pass, which proves the comparison is numeric; they stay as the discriminating case.
- [ ] **Step 3: Implement.** `helperSetEntries` parses every line of the trimmed file:
  - each line must match `^[0-9a-f]{64}  (\S+)$`;
  - each name must be in `files` and appear once;
  - the count must equal `len(files)`.
  
  Otherwise return `fmt.Errorf("%s must list exactly %s, each once; run make %s", sumsPath, strings.Join(files, ", "), target)`. The hash comparison stays.
- [ ] **Step 4: Run.**
  Run: `go test -race -count=1 ./tools/releasebuild/ ./internal/providers/windows/winproto/`
  Expected: PASS, including `TestStageLayout` and `TestStageListsTheWindowsHelpersInSHA256SUMS`.
- [ ] **Step 5: Commit.** Message: `fix(releasebuild): a helper checksum file must list exactly its binaries, each once and well formed; refusal rows carry their names; the helper version test discriminates numeric from text order (R66)`.

---

### Task 6: Decision R66, test IDs, traceability and the changelog

**Files:**
- `docs/superpowers/specs/alice-v1/00-decisions.md`: an R66 entry in R64's form. It names:
  - the items: F1, E1, the panel and Key Vault wording, the e2e robustness, the release tooling minors;
  - the rulings here;
  - no migration, no new code;
  - `ALC-TGT-0006` now answered by the deploy routes;
  - the tests `FX-01`..`FX-06`.
- `docs/superpowers/specs/alice-v1/06-quality.md`:
  - a new §24.x "Fixes batch 1 (R66)" (plan and rulings paths, the table below);
  - the §24 intro line names the range;
  - the HB-01 row's Expected becomes "The place fails at once with `target.disabled` (R66); the incident engine's and the key deploy job's reasons equal the API catalogue's".
- `tools/matrixcheck/main.go`: `idRowRe` accepts `FX` (`(?:SR|WIN|HB|FX|[LFSRAOX])`). `tools/matrixcheck/main_test.go` gets a case like the HB one (`FX-01` and `FX-06` read, `FXX-01` ignored). The package comment lists the prefix.
- `test/matrix/traceability.json`: FX rows naming each task's tests. HB-01's entry renames `TestIncidentPlaceOnADisabledServerWaitsAndFailsBusy` to `TestIncidentPlaceOnADisabledServerFailsAtOnce`.
- `docs/security/traceability.md`: regenerated with `go run ./tools/matrixcheck -update`.
- `CHANGELOG.md`: a new top section "Unreleased — Fixes batch 1 (R66)", with these entries:
  - **Changed**: "A deployment to a disabled server is refused with `ALC-TGT-0006` (it was `ALC-DEP-0011`); a key compromise incident's place on a disabled server fails at once with that reason instead of after about 15 minutes as busy."
  - **Added**: "The revocation check of a certificate found by network discovery, in its details."
  - **Fixed**: the panel and Key Vault wording; the release package's checksum check.

| ID | Case | Expected |
|---|---|---|
| FX-01 | A deployment requested by a person to a disabled server (certificate, Key Vault binding, ACME Deploy now, drift Repair) | 409 `ALC-TGT-0006` naming the website, audit reason `target_disabled`, nothing queued; the automatic planners skip it silently |
| FX-02 | A key compromise incident's place on a server disabled after the start | Fails at once with `target.disabled`; other places go on; Retry after enabling deploys it |
| FX-03 | The details of a certificate found by network discovery | Its last revocation check (or "Not checked yet") in EN and TR; list and export unchanged |
| FX-04 | An ACME certificate bound to Windows bindings and certificate files | The panel's column fits its rows; the add help and the Key Vault texts name Windows (IIS) |
| FX-05 | The deploy dialog follows five deployments on a loaded machine | Every run read at least every 30 s, at most 125 reads and 150 requests a minute, no 429 |
| FX-06 | A helper checksum file with a missing, duplicate, extra or malformed line | The release stage refuses it, naming the file and the make target |

- [ ] **Step 1: Write** the entries.
- [ ] **Step 2: Run.**
  Run: `go test ./tools/matrixcheck/ && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check`
  Expected: PASS. Every FX ID maps to existing tests: FX-05 maps to `web/e2e/phase4.spec.ts:read at least every 30 s`.
- [ ] **Step 3: Commit.** Message: `docs: decision R66, test IDs FX-01..FX-06 with their traceability, HB-01 updated, and the changelog of fixes batch 1 (R66)`.

---

### Task 7: Gates, final review and the rulings file

**Files:**
- Create `docs/superpowers/rulings/fixes-2026-10-25.md`, containing:
  - the [Rulings](#rulings-each-goes-into-docssuperpowersrulingsfixes-2026-10-25md) below, plus any execution rulings, each with its reason and cost if wrong;
  - "Owner to confirm";
  - "Deferred" (the list below, with reasons);
  - the gate evidence.
- Modify `docs/superpowers/rulings/hardening-2026-10-24.md`, adding markers only (no rewrite):
  - F1, M3 and owner item 10 each gain "fixed in R66 (`docs/superpowers/rulings/fixes-2026-10-25.md`)";
  - E1 gains "done in R66";
  - the declined Minor "Revocation check as first fact" gains "done in R66".

- [ ] **Step 1: Full gate.** First `pgrep -af 'playwright|make ci|go test'` must answer nothing. Then run `make ci E2E_PROJECT=alice-e2e-fx1 ALICE_E2E_PORT=9980`.
  Expected: exit 0. Record:
  - the e2e totals (including `phase4.spec.ts` "five websites", EN and TR, with its annotation);
  - the coverage floors met, quoting `internal/inventory`, `internal/api`, `internal/discovery/discoverysvc` and `tools/releasebuild` if floored;
  - `make matrix-check MATRIXCHECK_FLAGS=-strict` totals.
  
  If the machine needs it, run in stages as R64 did: `make lint test coverage perf test-backup-cycle test-ssh build release-symcheck i18n-check web-lint web-coverage vuln secrets-scan fs-scan`, then `e2e-up e2e-hardening-check e2e`, `e2e-down`, then `make image-check image-scan`. A failure caused by another branch or by the machine is recorded with its evidence and rerun, never hidden.
- [ ] **Step 2: Final review.** Use `superpowers:requesting-code-review` over `main..fixes-1`, with a fresh reviewer given the code, not this plan's conclusions. Fix every Critical and Important finding in its own commit (subject ending `(R66)`), re-run the affected tests, and list declined Minors with reasons.
- [ ] **Step 3: Write** the rulings file and the markers.
  Run: `make docs-check`
  Expected: PASS.
- [ ] **Step 4: Commit.** Message: `docs(rulings): fixes batch 1 rulings, owner items and gate evidence (R66)`.

---

## Files touched for the merge order

| Task | Files |
|---|---|
| 1 | `internal/inventory/deployments.go` (`checkDeployLocation` and two doc comments), `internal/inventory/incidents_engine.go` (one doc comment); tests `internal/inventory/{deployments,kv_deploy,acme_autodeploy,incidents_more}_integration_test.go`, `internal/api/certificates_handlers_test.go`; `locales/common/{en,tr}.json`, `docs/troubleshooting.md`, `api/openapi.yaml` |
| 2 | `internal/discovery/link.go`, `internal/discovery/discoverysvc/read.go`, `read_integration_test.go` (new), `internal/api/discovery_{dto,handlers}.go`, `internal/api/discovery_handlers_test.go`, `api/openapi.yaml`, `web/src/components/revocationCheck.ts` (new), `web/src/api/discovery.ts`, `web/src/components/discovery/CertificateDrawer.tsx`, `web/src/components/discovery/ResultsTab.test.tsx`, `web/src/pages/CertificateDetailPage{,.test}.tsx` |
| 3 | `web/src/components/acme/AcmeBindingsPanel.tsx`, `web/src/locales/{en,tr}.json`, `web/src/pages/AcmeCertificatePage.test.tsx`, `web/src/components/{AccessCheckPanel,RoleGuide}.test.tsx`, `docs/azure-setup.md` |
| 4 | `web/e2e/phase4.spec.ts` |
| 5 | `tools/releasebuild/main{,_test}.go`, `internal/providers/windows/winproto/winproto_test.go` |
| 6 | `docs/superpowers/specs/alice-v1/{00-decisions,06-quality}.md`, `tools/matrixcheck/main{,_test}.go`, `test/matrix/traceability.json`, `docs/security/traceability.md`, `CHANGELOG.md` |
| 7 | `docs/superpowers/rulings/fixes-2026-10-25.md` (new), `docs/superpowers/rulings/hardening-2026-10-24.md` |

None of these is in `internal/jobs/deployjobs` or `internal/api/deployments*`. Likely overlaps with R65:
- `internal/inventory/deployments.go`: different functions, unless R65 edits `checkDeployLocation`.
- `api/openapi.yaml`, `CHANGELOG.md`, `00-decisions.md`, `06-quality.md`, `traceability.*`, `tools/matrixcheck/main.go` (`idRowRe`) and both locale files: textual merges that keep both sides.

Either order works. Merging R65 first makes Task 1's refusal list in OpenAPI and the R66 entry slot in after R65's.

## Rulings (each goes into `docs/superpowers/rulings/fixes-2026-10-25.md`)

1. **One decision, R66, for the batch.** No migration, no new code, no new permission, no protocol bump. Test IDs `FX-01`..`FX-06`.
   - Cost if wrong: none functional.
2. **A disabled server is refused with `ErrTargetDisabled` in `checkDeployLocation`, before the not-ready rule.** This is a behaviour change on the manual routes:
   - a person (or a token) deploying to a disabled server's website gets 409 `ALC-TGT-0006` "This server is disabled…" instead of 409 `ALC-DEP-0011` "Alice cannot deploy to this server now";
   - the audit reason is `target_disabled` instead of `target_not_ready`.
   
   The status code, the `params.location_id` and the all-or-nothing rule are unchanged. It now matches what the deploy job records at send time (`target.disabled`) and what SSH key changes answer (`KeyChangeRefusal`).
   - Cost if wrong: an API client that keyed on `ALC-DEP-0011` for a disabled server sees another 409 code.
3. **The automatic planners are unchanged.** The ACME and Key Vault planners and the drift repair skip any refused website without an audit row; a disabled server is simply one more reason.
   - Cost if wrong: none (behaviour identical).
4. **An incident place on a disabled server fails at once with `target.disabled`** (closes R64 owner item 10 with the coordinator's chosen answer). The 30-run busy wait is for conditions that clear by themselves: a running deployment, recovery, a reconnect. A disabled server needs a person. The place's reason now says so, and Retry requests it again after the server is enabled.
   - Cost if wrong: a server disabled for a short maintenance during an incident fails its place at once, and someone must press Retry instead of the engine waiting about 15 minutes.
5. **`ALC-DEP-0011`'s cause no longer mentions a disabled server; `ALC-TGT-0006`'s troubleshooting cause covers a deployment request.**
   - Cost if wrong: wording only.
6. **The five-website journey asserts every run is read at least every 30 s (≥ 3 reads in the minute), not 60 reads a minute.** The rate is pinned by the deterministic Vitest budget test. The journey keeps the upper bounds, the no-429 checks and the full minute of polling.
   - Cost if wrong: a regression that slows polling to one read per run every 30 s passes the journey, but still fails the Vitest test (≥ 55 a minute).
7. **E1 reads the check inside `discoverysvc`, not through the inventory service.** It is detail only (`revocation_check`, null before the first check). The list and the CSV are unchanged, and the drawer reuses the certificate page's texts. Visibility is the certificate's own, since the check is a property of the certificate, not of an endpoint.
   - Cost if wrong: the list cannot be filtered or sorted by revocation status (a later change).
8. **The ACME panel's column header follows its rows** ("Certificate file", "Binding", or "Certificate file or binding"). The add help and the Key Vault texts name Nginx and Windows (IIS), not Apache or HAProxy, which do not deploy.
   - Cost if wrong: wording only.
9. **A helper checksum file must list exactly its binaries, each once, in `sha256sum` form.** The build writes exactly that.
   - Cost if wrong: a hand-edited checksum file with a comment or an extra line stops `make release` until `make helper` or `make winhelper` rewrites it.

## Owner to confirm

1. Ruling 2: deploying to a disabled server now answers `ALC-TGT-0006` (was `ALC-DEP-0011`). Is any customer script keyed on the old code?
2. Ruling 4 (R64 owner item 10): a disabled server's incident place fails at once, and the person retries after enabling it.

## Deferred (recorded in the rulings file)

Rejected because they are larger than one task, or need an owner decision, a migration, a permission or a protocol bump:
- **AUTH-5** (no `If-Match` on `PATCH /api/v1/users/{id}`): `users` has no `version` column (migrations `00002`), so the existing pattern needs a migration and a web change. Carried to 1.0.x (KI-39) as prod-readiness says.
- **AUTH-2** (directory sign-in lockout): an owner decision, with the other LDAP decisions.
- **VC-1..VC-4**: vendor console, never shipped to customers.
- **certificate-revocation D1** (revocation with the certificate's own key) and **D4** (other certificates with the same key in one incident): features. **RG3** (delete the compromised key's backup at once) needs a helper change. **RG1/RG2/RG4..RG7**: accepted residual risks.
- **Hardening E2..E5** (AIA caIssuers fetch, OCSP nonce and delta or partitioned CRLs, a revocation e2e with a compose responder, proxy support): features. E5 needs an owner decision (R64 owner item 3).
- **Hardening Minor "a byte budget for the CRL cache"**: closed by R64 M2. A CRL over 1 MiB is not cached (`maxCachedCRLBytes`), so the cache is bounded at 16 × 1 MiB.
- **scoped-access "What remains"**:
  - re-check under the row lock (design §5.4) and the rotation background check (§5.7): engine work;
  - `service` on derived rows and their filters, and the service list showing owners: features;
  - the R32 perf suite for role-bound lists: measurement work;
  - the LDAP Test sign-in hint: waits on the LDAP decisions;
  - the ACME dialog's service picker and policy hints: a feature;
  - the engine's first send re-checking `deployment.auto_deploy`: it touches `internal/jobs/deployjobs`, which R65 changes in parallel. Do it after R65 merges.
- **acme-dns-providers "Departures and defaults"**: all owner confirmations; nothing to fix.
- **web-server-standard Phase B items**: verified closed at `36a415af`:
  - `WEB_SERVER_TYPES` lists nginx, apache and haproxy;
  - the 00016 test uses `UpTo(16)`;
  - one `maxChainCerts` definition remains in `internal`;
  - the "must settle" items were settled in Phase B (R59).
- **windows-iis "Deferred to W5+"**:
  - W5-W7 (CCS, RDP, WinRM), the W2 and W3 carried items, and the declined W3 minors: features or accepted debt;
  - the W4 minors not in Task 5: the `_test` suffix strip in `internal/archtest/windowsci_test.go:181` (no real directory is affected), the Dockerfile subtest's exact string, ShellCheck of workflow `run:` scripts (needs a new tool in CI), and the asserted helper version literal in several tests (the next bump touches them).
- **`check-hardening.sh` failing on a non-default e2e port** (W1 owner note): no longer true. The script reads `ALICE_E2E_PORT` from the environment, then `deploy/.env` (`env_value`, since `2b61f02b`), and `make e2e-hardening-check` passed on ports 9975-9978 in the W2, W3, W4 and R64 gates. No change; the rulings file records it as verified stale.
- **The ACME bindings panel for Windows bindings**: the observation half was done in W4 Task 5 (WIN-44); the header and help texts are Task 3 here.
