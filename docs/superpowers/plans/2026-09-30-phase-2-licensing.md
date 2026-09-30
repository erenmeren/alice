# Phase 2: Licensing and `licensectl` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A vendor issues a signed license with `licensectl`, an administrator uploads it in Alice (wizard or License page), and the demo clock shows evaluation → warnings (60/30/14/7/1 days, banner and email) → grace (red banner, everything works) → lock (automatic work paused, infrastructure changes refused) → renewal (everything works again at once), while moving the server clock backwards never extends a license.

**Architecture:** A new `internal/license` module holds the pure parts — the license file format (strict JSON, RFC 8785 canonical payload, Ed25519 with a domain separator, Crockford installation IDs with a check character), the embedded key set (production keys from a committed file; the test key only under the `testlicense` build tag), the instant-based state machine (`Evaluate`) and the clock guard (MAC'd high-water mark in `settings` and in a file on the state volume, rollback clamp, forward-jump hold) — plus `license.Service`, which stores uploaded files verbatim, re-verifies them on every evaluation, records transitions and one-time notices in `license_history`, writes audit rows, and exposes one gate, `Allow(license.Class)`. That gate is the single lock-mode choke point: the API guard calls it for every route whose table entry is `license.ClassChange`, and the new minimal `internal/jobs` scheduler calls it before every periodic task. `internal/notify` gets an outbox, a sender and a minimal STARTTLS SMTP mailer configured from the environment. The vendor side lives in `internal/license/issuer` and `cmd/licensectl` (passphrase-protected Argon2id + AES-256-GCM key file, signed ledger) and is never linked into `alice`. The SPA gains license banners for every screen, a License page with upload preview/confirm, and the wizard license step.

**Tech Stack:** Go 1.27.1 (stdlib `crypto/ed25519`, `crypto/hkdf`, `crypto/hmac`, `net/smtp`, `crypto/tls`, `encoding/pem`), pgx v5, goose v3, golang.org/x/crypto (argon2), golang.org/x/text (NFC), golang.org/x/term (licensectl only), testify, testcontainers-go; React 18 + TypeScript 6 + Vite 8, Mantine 8, React Router 7, TanStack Query 5, i18next, Vitest 5 + Testing Library + msw 2, Playwright 1.63 + axe-core.

**Spec:** `docs/superpowers/specs/2026-09-29-alice-v1-design.md` and `docs/superpowers/specs/alice-v1/` — especially `00-decisions.md` (Licensing, R1, R7, R8, R9, R17, R20, R24–R30, R33, R34, R35), `02-architecture.md` §5.4, §7.6, §8.2, §8.3, §8.6, §8.7, §9.3, §9.6, `04-security.md` §14.4 (License module), SEC-043, SEC-050, §16.1–§16.7, §17.3 item 8, `05-operations.md` §18.5 step 6, §19.1–§19.3, §21 (`docs/licensing.md`), `06-quality.md` §22.4, §22.6 (license fixtures), §22.7 (coverage), §23 (L-01..L-88), §25.6 (`FuzzParseLicense`), §25.8 X-01, §26.1, §26.4. `00-decisions.md` wins on conflict; this plan proposes **R36** (Task 22) for the conflicts listed under "Spec conflicts resolved by this plan". The Phase 1 plan (`docs/superpowers/plans/2026-09-30-phase-1-core.md`), `docs/superpowers/rulings/phase-1.md` and `docs/security/reviews/phase-1.md` are the style and carry references.

**Plan verification:** the tasks were written against the code on branch `phase-2` at `9ceee73`; every "Modify" step quotes the text it replaces. Owner verification (Task 22, Step 9) runs at execution time.

## Global Constraints

- Go module path is `alice`; toolchain `go 1.27.1`. Every shell step assumes `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"` and the repository root as working directory.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `tr.json` files.
- Commits: Conventional Commits, made with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit`, message ending with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Code blocks in this plan are gofmt-clean except for column alignment of consecutive one-line declarations and struct fields: run `gofmt -w` (or `make lint`) on every changed Go file before committing.
- Tests: Go stdlib `testing` plus testify `require`/`assert` only. Integration tests carry `//go:build integration`, call `pgtest.Main` from `TestMain` and get a fresh database per test from `pgtest.New(t)`. A red step in a brand-new package may fail with "no non-test Go files"; that is the expected failure.
- Build tags: `integration` (PostgreSQL tests), `e2e` (test-only `/test/*` endpoints, demo clock), `testlicense` (trusts the test signing key; spec §22.6), `releasecheck` (release gate that the production key set is not empty). Release images are built with no tag. The e2e image is built with `e2e testlicense`.
- **Vendor key rule (security-critical):** no agent, test, script or CI job ever generates, stores, prints or commits the vendor's production Ed25519 private key or its passphrase. The production public key set lives in `internal/license/keys/production.json`, committed by the owner (Task 22 owner steps); until then it is `{"keys": []}` and release builds accept no license at all (fail closed, see R36 item 1). The test signing key is derived from a fixed public label inside test-only code (`internal/license/licensetest`, and the `testlicense`-tagged key file); it is never trusted by a release build, and a test proves it.
- Runtime Go dependencies of `alice` are unchanged (pgx, goose, x/text, google/uuid, x/crypto, pquerna/otp). `cmd/licensectl` (vendor-only, never shipped) adds `golang.org/x/term` for a no-echo passphrase prompt (already in `go.sum` through x/crypto); a test proves `alice` does not link `golang.org/x/term`, `internal/license/issuer` or `internal/license/licensetest`.
- No new web dependencies.
- Lint is golangci-lint v2 (`make lint`): gosec, errorlint, forbidigo, bodyclose, misspell, noctx, gofmt, goimports (`local-prefixes: alice`); build tags `integration` always, plus `e2e,testlicense` for `./cmd/...` and `./internal/license/...`. Forbidden: `fmt.Print*`, `strings.ToUpper`/`ToLower`/`Title`, `time.Now` outside `internal/platform/clock` and tests. No `//nolint` without a reason.
- Module import rules are enforced by `internal/archtest`: `license` imports only `platform`, `secrets`, `audit`; `notify` only `platform`, `i18n`, `secrets`; `jobs` only `platform`, `audit`, `license`, `inventory`, `providers`, `notify`; `setup` gains no new internal import (it uses a one-method interface for the license).
- No SQL string building (SEC-060); `alice_app` gets explicit grants for every new table and the grant guard test lists every non-default grant set.
- No secret value in logs, errors, audit details or responses: the HWM MAC and encryption sub-keys, the master key, SMTP password, vendor key passphrase. License files are not secret (they are shown to administrators), but they are size-limited (64 KiB) and never logged.
- Licensing rules (verbatim from the spec): license timing is instant-based UTC: ACTIVE while `now < valid_until`; GRACE while `valid_until <= now < valid_until + 168h`; LOCK after (R25). Evaluation: 30 days from the installation timestamp, max 5 targets, ends directly in LOCK without grace, warnings 7/3/1 days before (R1, R27). Expiry warnings 60/30/14/7/1 days computed from `valid_until`, banner + email to Admins. Grace: red banner to all users, everything works; Admins get a daily email. Lock: scheduled jobs that change external systems stop; user-initiated external changes are refused with `license.locked`; nothing is deleted; login, license upload, backup/restore, audit and inventory export remain available (R9). Smaller renewal: existing targets keep working, persistent banner, only adding is blocked (R30). Target limit exceeded only blocks adding targets.
- Clock rules: trusted time `T = max(system_time, hwm)`, and while the clock is behind the HWM advances with uptime (R36 item 17); HWM record `{v:1, hwm, seq, mac}` in `settings` (`time.hwm`) and `<ALICE_STATE_DIR>/hwm.dat` (default `/opt/alice/state`); larger valid wins; invalid MAC = missing (audited); both missing = `max(system_time, build_time)` plus audited "time reference reset"; MAC key `HKDF(master, "alice/hwm/v1")`; rollback never extends a license; forward jump suspicious when wall clock advanced > 48 h beyond monotonic uptime since the last tick; then GRACE/LOCK transitions wait for 24 h of uptime (R26); certificate `notBefore` is never used in license math (R28).
- License file (spec §16.2–§16.3): at most 64 KiB; strict JSON (no duplicate keys, no unknown fields); `format` outside and inside the payload; signed bytes `"ALICE-LICENSE-v1\n" || JCS(payload)`; `max_targets` in [1, 100000]; `valid_from <= valid_until`; `issued_at <= valid_from + 24h`; unknown `features` ignored; a newer `format` answers "update Alice".
- API JSON conventions from Phase 1 (snake_case, UTC RFC 3339, error body with `code`, `reason`, `message_key`, `message`, `request_id`, `retryable`, `params`, `details`); every new code `ALC-<AREA>-<NNNN>` has `errors.<reason>.title|cause|action` in `locales/common/{en,tr}.json` and a section in `docs/troubleshooting.md`.
- Every new route is in the route table with a permission and (for non-GET methods) an explicit license class, in `api/openapi.yaml` with the same `x-permission`, in `docs/authz-matrix.md` (`make authz-doc`), and in the authz matrix test.
- i18n: every user-visible string is a key in English and Turkish (`make i18n-check`); placeholders `{{name}}` without spaces; no sentence assembly; plural forms use i18next `_one`/`_other` keys in both languages. The English and Turkish UI copy in Tasks 18–21 is exact.
- Accessibility: new screens and dialogs have no serious or critical axe violation at 640, 1280 and 1920 px in English and Turkish, are keyboard usable, and do not scroll horizontally.
- Frontend: no `dangerouslySetInnerHTML`, no `toUpperCase`/`toLowerCase`.
- Container: unchanged hardening; a new named volume `alice-state` is mounted at `/opt/alice/state` (read-write, owned by 10001).

## Review Focus

1. **The customer sets the server clock back** (or restores a VM snapshot, or restarts Alice several times with a wrong clock). Expected: the license never gets longer; the effective time never decreases across restarts; administrators see "The server clock changed unexpectedly…" at most once a day in the audit log and as a banner; no lock is caused by the rollback itself. Tests in Tasks 6 and 9 (`TestGuardRollback*`, `TestRestartsNeverMoveEffectiveTimeBackwards`).
2. **Two administrators upload at the same moment, or the same file twice, while the hourly evaluation runs.** Expected: uploads are serialized by the license row lock, both files are stored in order, a duplicate is reported as already installed, and the state column, history and audit agree with each other. Test in Task 8 (`TestConcurrentUploadsAreSerialized`).
3. **A license file mangled in transit** — Windows line endings, a UTF-8 byte-order mark, pretty-printed or compacted JSON, a Turkish customer name ("Örnek Bankası A.Ş."). Expected: every such file verifies; any change to a signed value, a duplicate key or an extra field is refused with the same friendly "not a valid Alice license" message. Test in Task 3 (`TestParseAcceptsHarmlessReformatting`) and Task 4 (`TestVerifyRejectsAnyChangeToSignedValues`).
4. **Installation IDs typed by hand** into `licensectl` — lower case, spaces, `O` for `0`, `I`/`L` for `1`, one wrong or two swapped characters. Expected: harmless variations are normalized; a real typo is rejected by the check character before anything is signed. Tests in Task 3 (`TestInstallationIDDetectsTypos`) and Task 17 (`TestIssueRejectsMistypedInstallationID`).
5. **Alice was down across several warning thresholds, or the demo clock jumps months ahead.** Expected: exactly one email for the current threshold (no burst of old ones), the 60-day warning never repeats after a restart, and long fake-clock advances return immediately. Tests in Task 2 (`TestFakeLongAdvanceIsFast`) and Task 9 (`TestCatchUpSendsOnlyTheCurrentThreshold`, `TestNoticesAreSentOncePerThreshold`).

---

## Spec conflicts resolved by this plan (proposed R36, written in Task 22)

| # | Conflict | Resolution |
|---|---|---|
| 1 | §19.2 embeds the public key "with -ldflags or an embedded file"; no rule for builds before the vendor key exists | Committed file `internal/license/keys/production.json` (`go:embed`), reviewable in git. While it is empty, release builds run and accept **no** license (every upload answers `ALC-LIC-0004`, startup logs an error); `make release-keycheck` (`-tags releasecheck`) fails, and the Phase 8 release pipeline runs it. A failing build would break `make up` and CI for development; a fail-closed runtime never trusts a forged or test-signed file and evaluation keeps working |
| 2 | HWM storage: §7.6 columns `time_high_water_*` in `license` vs §16.5 `settings` key `time.hwm` + file | §16.5: `settings.time.hwm` and `<ALICE_STATE_DIR>/hwm.dat` (new volume); the payload is AES-GCM-encrypted with the extra sub-key label `alice/hwm-enc/v1` and MAC'd with `alice/hwm/v1` |
| 3 | History table name `license_history` (§7.6) vs `license_status_history` (§16.3, L-14) | `license_history`, with the extra event `notice` and a `notice` column; one-time notices (warnings, grace days, lock, clock anomalies) are unique per `(license_id, notice)` |
| 4 | Installation ID stored in `settings` (§16.4) vs `license` row (§7.6) | In the `license` singleton row, with `installed_at` |
| 5 | Lock status code: 403 (§9.3, §9.6) vs 402 (L-26, L-71) | `license.locked` = 403 `ALC-LIC-0001`; target limit = 409 `ALC-LIC-0008` (§9.3). 402 is reserved in RFC 9110 |
| 6 | Mutations refused in lock: §9.6 refuses everything outside {auth, license, backup, audit export, inventory export, settings/smtp, tokens} vs R9 (external changes only) | R9 wins: routes are tagged in the route table; infrastructure groups (`/targets`, `/certificates`, `/locations`, `/deployments`, `/ssh-keys`, `/rotation`, `/keyvault`) are `ClassChange` and refused; platform administration (users, tokens, auth, setup, audit, license, settings, backup) stays available so an administrator can still offboard people in lock. Reads are never refused |
| 7 | `max_targets` upper bound 100,000 (§16.3) vs "above 1,000,000" (L-46) | [1, 100000] |
| 8 | Uploading an already expired license: rejected (§19.1 message) vs accepted (L-32) | Accepted and stored; the state is computed from it; the UI says "This license has already expired" |
| 9 | Rollback warning tolerance: 5 minutes (§16.5) vs 1 hour 5 minutes (L-52) | 65 minutes for the warning; license math always clamps to the HWM regardless |
| 10 | `PENDING` (L-48) and `CLOCK_JUMP_SUSPECTED` (L-59) are not values of the §7.6 `state` column | They are flags (`pending`, `clock_jump`) next to the phase, not phases |
| 11 | L-51 names HWM = E+3d "grace day 3", while L-22 defines day n as the n-th 24-hour period (E+3d starts day 4) | L-22's rule; the L-51 test uses E+2d+1h |
| 12 | L-15: Operators get only `expired` from the status endpoint, but §19.3 shows grace/lock/evaluation banners to everyone | `GET /license/status` returns `expired` plus the banners everyone sees; the phase and administrator banners (warnings, clock, target limit) only to Admins (Auditors also get the phase) |
| 13 | §9.6 lists `GET /license/installation-id` | Folded into `GET /license` (Admin, Auditor); the wizard's administrator can read it |
| 14 | §26.4 "warning emails through notify (email sender exists in minimal form)" but SMTP settings arrive with wizard step 5 in Phase 7 | Minimal STARTTLS/TLS SMTP sender configured by `ALICE_SMTP_*` environment variables (password from a file); without them emails are recorded as `skipped_no_smtp` (L-18). Phase 7 moves the configuration to Settings |
| 15 | §22.7 "coverage gates enforced from Phase 2 (95 % for license, secrets, auth, rbac, audit)" while Phase 1 left auth 84 %, secrets 82 %, audit 90 % | Enforced now: `internal/license/...` ≥ 95 %, `rbac` ≥ 95 %; the other packages may not drop below their Phase 1 floor (ratchet); the 95 % target for them moves to Phase 8 |
| 16 | Audit action names | Spec names where given (`license.activated`, `license.renewed`, `license.expired`, `license.locked`, `license.warning.sent`, `license.upload.<reason>`, `clock.rollback_detected`, `clock.forward_jump`); new: `license.evaluation_ended`, `license.state_changed`, `license.tampered`, `clock.hwm_damaged`, `clock.time_reference_reset`, `clock.jump_accepted`, `clock.jump_cleared`, `request.denied_license`, `setup.evaluation_chosen` |
| 17 | §16.5 "T = max(system_time, hwm)" freezes license time for as long as the clock stays behind (a clock set back a year would stop the license for a year) | While the system clock is behind the HWM, the HWM advances with monotonic uptime; only downtime is not counted |

## Carries from Phase 1 and deferred items

| # | Carry | Decision | Where |
|---|---|---|---|
| 1 | `clock.Fake.Advance` fires ticker ticks one at a time under the lock | Included: O(timers + tickers) per move; a ticker delivers its latest due tick | Task 2 |
| 2a | `web/*.tsbuildinfo` not ignored | Included | Task 1 |
| 2b | Hover of the `red.9` confirm buttons is 4.48:1 | Included: hover `#a51d1d` (7.5:1) with a contrast unit test | Task 1 |
| 2c | Grant guard misses column-level grants on listed relations | Included: every privilege is compared at column level too | Task 1 |
| 2d | Mobile navigation stays open after non-link navigation | Included: closes on every location change | Task 1 |
| 2e | Header overflows below 640 px | Included: name hidden below `sm`; e2e check at 375 px | Tasks 1, 21 |
| 2f | `rbac.SetupFinish` unused (P1-11) | Included: removed (no wizard step needs it; the license step uses `settings.manage`) | Task 1 |
| 3 | Wizard "ends after recovery passphrase" (R35) | Included: license step between passphrase and Finish; `setup.completed_at` requires a license choice; evaluation runs from the installation timestamp created at first start | Tasks 8, 13, 20 |
| — | Phase 1 "no scheduled daily audit verification" and `maintenance.cleanup` | **Re-deferred** to Phase 3: the Phase 2 scheduler is periodic in-process only; the durable job queue arrives with targets | — |
| — | Certificate expiry emails "marked license expired" (L-28) | **Re-deferred** to Phase 7 (alerts); `license.Snapshot.Eval.Locked()` is the input | — |
| — | L-04, L-70..L-79 against real targets; L-80..L-88 against real jobs | Stub target counter and stub jobs now (spec §26.4); re-run in Phases 3, 4, 6 | Tasks 8, 11 |
| — | `licensectl keygen --split` (Shamir) | **Re-deferred**: optional in §16.7 "when more than one trusted person exists"; the owner is the only signer today | — |
| — | "Download request file" (§19.1) | **Re-deferred** to Phase 8: the Copy button covers activation; a download needs a new API route | — |

---

## File Structure

```
.gitignore                                    + /web/*.tsbuildinfo (Task 1)
migrations/00003_license.sql                  license, license_files, license_history, notifications_outbox, grants (Task 7)
migrations/roles_integration_test.go          column-level grant check (Task 1); new explicit grant sets (Task 7)
internal/platform/clock/                      efficient Fake.Advance; Monotonic (Real, Fake, Offset); JumpWall (Task 2)
internal/platform/config/                     ALICE_STATE_DIR, ALICE_SMTP_* (Task 15)
internal/secrets/envelope.go                  LabelHWMEnc, Keyring.SealWith/OpenWith (Task 6)
internal/rbac/                                license.read, license.manage; SetupFinish removed (Tasks 1, 12)
internal/license/
  installid.go                                installation ID (Crockford base32 + Luhn mod 32 check) (Task 3)
  jcs.go, file.go, errors.go                  RFC 8785 canonical payload, strict parser, validation, errors (Task 3)
  keys.go, keys_release.go, keys_testlicense.go, keys/production.json
                                              key set, Verify, build-tag key selection (Task 4)
  licensetest/                                test signer (deterministic test key) (Task 4)
  state.go, class.go                          Evaluate (phases, thresholds, grace day, pending, limits), gate classes (Task 5)
  hwm.go, timeguard.go                        HWM codec and stores, clock guard (Task 6)
  service.go, install.go, banners.go, detail.go, tick.go
                                              Service: Start, Install/Preview, Allow, CheckCanAddTarget, Snapshot/Banners,
                                              Detail, Inspect (Task 8); Tick, notices, anomalies, Shutdown (Task 9)
  issuer/                                     vendor key file, signing, signed ledger (Task 17)
internal/notify/                              outbox (AdminNotifier), Sender, SMTPMailer, templates (Task 10)
internal/jobs/                                job types with license classes (X-01), periodic gated scheduler (Task 11)
internal/setup/                               license step: ChooseEvaluation, Status.LicenseChosen (Task 13)
internal/api/                                 route license classes + guard gate (Task 12); license and setup/evaluation
                                              handlers, DTOs, error codes, integration suites (Task 14)
api/openapi.yaml, docs/authz-matrix.md        new operations (Tasks 12, 14)
cmd/alice/                                    wiring, scheduler, shutdown, `alice license keys|status`, release tests (Task 15);
                                              e2e test API /test/clock (negative, wall_only), /test/license, /test/mail (Task 16)
cmd/licensectl/                               keygen, issue, inspect, verify, keyset, ledger-verify (Task 17)
deploy/                                       alice-state volume, e2e tags, Dockerfile state dir (Task 15)
locales/common/{en,tr}.json                   LIC/SET error texts, email templates (Tasks 10, 12, 14)
web/src/                                      theme hover, nav close (Task 1); license API, banners, nav (Task 18); License page and
                                              upload (Task 19); wizard license step (Task 20)
web/e2e/phase2.spec.ts, helpers.ts            EN/TR journeys with the demo clock and axe (Task 21)
tools/covercheck/, coverage-floors.json       coverage gate (Task 22)
docs/                                         licensing.md, vendor/licensing-vendor.md, troubleshooting, admin/operator/first-run
                                              guides, CHANGELOG, security/reviews/phase-2.md, R36 (Task 22)
```

Task order is bottom-up: residuals and clock (1–2), pure license core (3–6), storage (7), service (8–9), notify and jobs (10–11), HTTP (12–14), wiring and test build (15–16), vendor CLI (17), web (18–20), end-to-end (21), docs and verification (22). Each task leaves the repository green.

---
### Task 1: Phase 1 residuals (ignore file, danger hover contrast, column-level grants, navigation, header, `SetupFinish`)

Six small carries from `docs/superpowers/rulings/phase-1.md` ("Residual items parked for Phase 2") and finding
P1-11. Each has its own regression test; they share one reviewer gate because each is a few lines.

**Files:**
- Modify: `.gitignore`
- Modify: `web/src/theme.ts`; Create: `web/src/theme.test.ts`
- Modify: `migrations/roles_integration_test.go` (`TestGrantGuardCatchesUnlistedRelations`, `grantProblems`)
- Modify: `web/src/layout/AppLayout.tsx`; Modify: `web/src/App.test.tsx` (one new test)
- Modify: `internal/rbac/rbac.go`, `internal/rbac/rbac_test.go`, `internal/api/authz_test.go`, `internal/api/guard_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces (`web/src/theme.ts`): `export const DANGER_HOVER = '#a51d1d'`; the theme's `variantColorResolver` returns `hover: DANGER_HOVER` for `{ variant: 'filled', color: 'red.9' }`.
- Produces (`internal/rbac`): the permission `SetupFinish` no longer exists; `rbac.Permissions()` has 10 entries after this task (Task 12 adds two).

- [ ] **Step 1: Ignore TypeScript build info files**

Append to `.gitignore` under `# Web`:

```
/web/*.tsbuildinfo
```

Run: `git check-ignore -v web/tsconfig.tsbuildinfo`
Expected: `.gitignore:…:/web/*.tsbuildinfo	web/tsconfig.tsbuildinfo`

- [ ] **Step 2: Write the failing contrast test**

Create `web/src/theme.test.ts`:

```ts
import { DEFAULT_THEME, mergeMantineTheme } from '@mantine/core';
import { DANGER_HOVER, theme } from './theme';

// WCAG 2.x relative luminance of a #rrggbb color.
function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

describe('theme', () => {
  const full = mergeMantineTheme(DEFAULT_THEME, theme);

  it('keeps white text on the red confirm buttons above 4.5:1, also on hover', () => {
    const colors = full.variantColorResolver({ color: 'red.9', theme: full, variant: 'filled' });
    expect(colors.hover).toBe(DANGER_HOVER);
    expect(contrast('#ffffff', DANGER_HOVER)).toBeGreaterThanOrEqual(4.5);
    expect(contrast('#ffffff', full.colors.red[9])).toBeGreaterThanOrEqual(4.5);
  });

  it('needs the override: Mantine hovers red 9 with the lighter red 8', () => {
    expect(contrast('#ffffff', full.colors.red[8])).toBeLessThan(4.5);
  });

  it('leaves other filled buttons alone', () => {
    const colors = full.variantColorResolver({ color: 'indigo', theme: full, variant: 'filled' });
    expect(colors.hover).not.toBe(DANGER_HOVER);
  });
});
```

Run: `cd web && npx vitest run src/theme.test.ts`
Expected: FAIL — `DANGER_HOVER` is not exported (`undefined`).

- [ ] **Step 3: Darken the hover of the danger buttons**

In `web/src/theme.ts` replace the block from `// Mantine's "light" and "subtle" variants` to the end of `variantColorResolver` with:

```ts
// Mantine hovers a filled button of shade 9 with the lighter shade 8; for red that is #e03131,
// and white text on it is 4.48:1 (below WCAG AA 4.5:1). The danger buttons (color "red.9")
// hover a darker red instead: #a51d1d is 7.5:1.
export const DANGER_HOVER = '#a51d1d';

// Mantine's "light" and "subtle" variants draw shade-6 text on a pale tint of the
// same color (for example green 2.2:1, indigo 3.8:1), below WCAG AA (4.5:1).
// Keep the tint as the color cue and use black text instead.
const variantColorResolver: VariantColorsResolver = (input) => {
  const colors = defaultVariantColorsResolver(input);
  if (input.variant === 'filled' && input.color === 'red.9') {
    return { ...colors, hover: DANGER_HOVER };
  }
  if (input.variant === 'light' || input.variant === 'subtle') {
    return { ...colors, color: 'var(--mantine-color-black)', hoverColor: 'var(--mantine-color-black)' };
  }
  return colors;
};
```

Run: `cd web && npx vitest run src/theme.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 4: Write the failing column-grant tests**

In `migrations/roles_integration_test.go`, in `TestGrantGuardCatchesUnlistedRelations`, add these two statements at the end of the statement list (after `"CREATE TABLE phase_x.hidden (id int)",`):

```go
		// Column-level grants on relations whose table-level grants are correct.
		"GRANT UPDATE (action) ON audit_log TO alice_app",
		"GRANT REFERENCES (key) ON settings TO alice_app",
```

and replace the assertions after `problems := grantProblems(t, d)` with:

```go
	for _, rel := range []string{"public.phase_x_no_grants", "public.phase_x_too_much", "public.phase_x_columns_only",
		"public.phase_x_view", "public.phase_x_seq", "schema phase_x", "phase_x.hidden",
		"public.audit_log", "public.settings"} {
		assert.Contains(t, problems, rel)
	}
	assert.Len(t, problems, 9, "%v", problems)
```

Run: `go test -count=1 -tags integration -run TestGrantGuardCatchesUnlistedRelations ./migrations/`
Expected: FAIL — `public.audit_log` and `public.settings` are missing from the problems (the table-level sets still match).

- [ ] **Step 5: Compare column-level privileges too**

In `grantProblems`, replace the last select column

```sql
       has_any_column_privilege('alice_app', c.oid, 'SELECT, INSERT, UPDATE, REFERENCES')
```

with

```sql
       CASE WHEN c.relkind = 'S' THEN false ELSE
         (has_any_column_privilege('alice_app', c.oid, 'SELECT') AND NOT has_table_privilege('alice_app', c.oid, 'SELECT'))
         OR (has_any_column_privilege('alice_app', c.oid, 'INSERT') AND NOT has_table_privilege('alice_app', c.oid, 'INSERT'))
         OR (has_any_column_privilege('alice_app', c.oid, 'UPDATE') AND NOT has_table_privilege('alice_app', c.oid, 'UPDATE'))
         OR (has_any_column_privilege('alice_app', c.oid, 'REFERENCES') AND NOT has_table_privilege('alice_app', c.oid, 'REFERENCES'))
       END
```

rename the scanned variable `anyColumn` to `columnOnly` (declaration and `rows.Scan`), and replace the final check

```go
		if !slices.Equal(want, privs) || (len(privs) == 0 && anyColumn) {
```

with

```go
		// A column-level privilege without the table-level one is a hidden extra grant
		// (for example UPDATE on one audit_log column), even when the table-level set matches.
		if !slices.Equal(want, privs) || columnOnly {
```

Update the comment above `TestGrantGuardCatchesUnlistedRelations` to end with: `…, opens another schema to alice_app, or adds a column-level grant fails TestAppRoleGrants.`

Run: `go test -count=1 -tags integration ./migrations/`
Expected: PASS (all tests, including `TestAppRoleGrants` on the real migrations).

- [ ] **Step 6: Write the failing navigation test**

In `web/src/App.test.tsx` change the first import line to

```ts
import { act, screen, waitFor, within } from '@testing-library/react';
```

and add after the test `'opens and closes the navigation with the menu button and closes it after navigating'`:

```ts
  it('closes the navigation after any navigation, not only a menu link', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    const { router } = await renderRoute('/');
    await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' });
    await userEvent.click(screen.getByRole('button', { name: 'Open navigation' }));
    expect(screen.getByRole('button', { name: 'Close navigation' })).toHaveAttribute('aria-expanded', 'true');
    await act(() => router.navigate('/account'));
    expect(await screen.findByRole('heading', { name: 'My account' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open navigation' })).toHaveAttribute('aria-expanded', 'false');
  });

  it('hides the user name below the small breakpoint so the header fits phones', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/');
    expect(await screen.findByTestId('current-user')).toHaveClass('mantine-visible-from-sm');
  });
```

Run: `cd web && npx vitest run src/App.test.tsx`
Expected: FAIL — the menu stays open after `router.navigate` (`aria-expanded` is `true`), and `current-user` has no `mantine-visible-from-sm` class.

- [ ] **Step 7: Close the navigation on every location change; hide the name on phones**

In `web/src/layout/AppLayout.tsx`:

1. Add `import { useEffect } from 'react';` as the first import.
2. Replace

```tsx
  const [navOpened, nav] = useDisclosure(false);
  if (!session) return null;
```

with

```tsx
  const [navOpened, nav] = useDisclosure(false);
  const closeNav = nav.close;
  // Every navigation closes the mobile menu, including redirects and buttons that navigate
  // (a menu link also closes it in its onClick, before the new page renders).
  useEffect(() => {
    closeNav();
  }, [location.pathname, closeNav]);
  if (!session) return null;
```

3. Replace `<Text size="sm" data-testid="current-user">` with `<Text size="sm" data-testid="current-user" visibleFrom="sm">` (below 768 px the burger, the language switcher and **Sign out** must fit a 375 px phone; the name is also on **My account**).

Run: `cd web && npx vitest run src/App.test.tsx`
Expected: PASS.

- [ ] **Step 8: Remove the unused permission `setup.finish` (P1-11)**

In `internal/rbac/rbac.go` delete the line `SetupFinish    Permission = "setup.finish"` and the policy line `SetupFinish:    {Roles: []Role{Admin}},`, and change the comment `// Every permission used by the Phase 1 route table.` to `// Every permission used by the route table.`

In `internal/rbac/rbac_test.go` delete the `rbac.SetupFinish: {…},` row (two lines) from `expected`, and in `TestPermissionsAreSortedAndHavePolicies` change `assert.Len(t, ps, 11)` to `assert.Len(t, ps, 10)`.

In `internal/api/authz_test.go` delete the `rbac.SetupFinish:` row of `expectedMatrix`, and in `TestRouteRuleViolationsCatchesWeakPermissions` replace the two `perm: rbac.SetupFinish` entries with `perm: rbac.Session`.

In `internal/api/guard_test.go`, `TestPendingSessionIsNotASignedInUser`, replace `rbac.SetupFinish` with `rbac.UsersRead`.

Run: `go build ./... && go test -count=1 ./internal/rbac/ ./internal/api/`
Expected: PASS.

- [ ] **Step 9: Run the whole fast suite and lint**

Run: `make lint test && cd web && npm run lint && npm test`
Expected: all green.

- [ ] **Step 10: Commit**

```bash
git add .gitignore web/src/theme.ts web/src/theme.test.ts web/src/layout/AppLayout.tsx web/src/App.test.tsx \
  migrations/roles_integration_test.go internal/rbac/rbac.go internal/rbac/rbac_test.go \
  internal/api/authz_test.go internal/api/guard_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix: close Phase 1 residuals (hover contrast, column grants, mobile navigation, setup.finish)

- ignore web/*.tsbuildinfo
- red 9 danger buttons hover #a51d1d (7.5:1) instead of Mantine's red 8 (4.48:1)
- the grant guard compares column-level privileges of listed relations
- the mobile navigation closes on every location change; the user name is
  hidden below 768 px so the header fits phones
- remove the unused permission setup.finish (finding P1-11)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 2: Clock: efficient `Fake.Advance`, monotonic uptime, wall-clock jumps

Carry 1: `Fake.Advance` looped once per ticker tick under the lock, so a one-year advance with a one-second
ticker hung. The license module (spec §22.4, R26) also needs a monotonic uptime source that is independent of the
wall clock, and tests need to move only the wall clock (an administrator setting the system time).

**Files:**
- Modify: `internal/platform/clock/clock.go`
- Modify: `internal/platform/clock/offset.go`
- Test: `internal/platform/clock/clock_test.go`, `internal/platform/clock/offset_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces (`alice/internal/platform/clock`):
  - `type Monotonic interface { Elapsed() time.Duration }` — never decreases, unaffected by wall-clock changes.
  - `func (Real) Elapsed() time.Duration` — monotonic time since the process started.
  - `func (f *Fake) Elapsed() time.Duration` — the sum of all forward `Advance`/`Set` moves.
  - `func (f *Fake) JumpWall(d time.Duration)` — moves `Now` by `d` without changing `Elapsed` and without firing anything; pending timers and tickers keep their remaining durations.
  - `func (o *Offset) Elapsed() time.Duration` — base elapsed (when the base implements `Monotonic`) plus every positive `Advance`.
  - `func (o *Offset) JumpWall(d time.Duration)` — moves `Now` only.
  - `Fake.Advance`/`Set` cost O(timers log timers + tickers) per call; each ticker delivers at most one tick per call, carrying its latest due time.

- [ ] **Step 1: Write the failing tests**

Append to `internal/platform/clock/clock_test.go`:

```go
// Carry from Phase 0/1: a long advance must not loop once per tick (a year of
// one-millisecond ticks is 3e10 iterations).
func TestFakeLongAdvanceIsFast(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	tk := f.NewTicker(time.Millisecond)
	defer tk.Stop()
	timer := f.After(24 * time.Hour)

	done := make(chan struct{})
	go func() {
		f.Advance(365 * 24 * time.Hour)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Advance over a year with a 1 ms ticker did not return within 2 s")
	}
	v, ok := recv(t, tk.C())
	require.True(t, ok)
	assert.True(t, v.Equal(start.Add(365*24*time.Hour)), "the ticker delivers its latest due tick, got %s", v)
	_, ok = recv(t, tk.C())
	assert.False(t, ok, "one tick per move")
	fired, ok := recv(t, timer)
	require.True(t, ok)
	assert.True(t, fired.Equal(start.Add(24*time.Hour)), "a timer fires with its own deadline")

	f.Advance(time.Millisecond)
	v, ok = recv(t, tk.C())
	require.True(t, ok, "the ticker keeps its schedule after a long move")
	assert.True(t, v.Equal(start.Add(365*24*time.Hour+time.Millisecond)))
}

func TestFakeTickerWithOffsetPhaseDeliversLatestDueTick(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	tk := f.NewTicker(time.Hour)
	defer tk.Stop()
	f.Advance(150 * time.Minute) // ticks due at +1h and +2h
	v, ok := recv(t, tk.C())
	require.True(t, ok)
	assert.True(t, v.Equal(start.Add(2*time.Hour)))
	f.Advance(30 * time.Minute) // +3h
	v, ok = recv(t, tk.C())
	require.True(t, ok)
	assert.True(t, v.Equal(start.Add(3*time.Hour)))
}

func TestRealElapsedGrows(t *testing.T) {
	var m clock.Monotonic = clock.Real{}
	a := m.Elapsed()
	time.Sleep(2 * time.Millisecond)
	assert.Greater(t, m.Elapsed(), a)
}

func TestFakeElapsedCountsOnlyForwardMoves(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	var m clock.Monotonic = f
	assert.Zero(t, m.Elapsed())
	f.Advance(time.Hour)
	assert.Equal(t, time.Hour, f.Elapsed())
	f.Set(start) // backwards: the wall clock moves, uptime does not
	assert.Equal(t, time.Hour, f.Elapsed())
	assert.True(t, f.Now().Equal(start))
	f.Set(start.Add(90 * time.Minute))
	assert.Equal(t, 2*time.Hour+30*time.Minute, f.Elapsed())
}

func TestFakeJumpWallMovesOnlyTheWallClock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := clock.NewFake(start)
	timer := f.After(2 * time.Hour)
	tk := f.NewTicker(time.Hour)
	defer tk.Stop()

	f.JumpWall(72 * time.Hour)
	assert.True(t, f.Now().Equal(start.Add(72*time.Hour)))
	assert.Zero(t, f.Elapsed())
	_, ok := recv(t, timer)
	assert.False(t, ok, "a wall-clock jump fires nothing")
	_, ok = recv(t, tk.C())
	assert.False(t, ok)

	f.Advance(time.Hour)
	_, ok = recv(t, tk.C())
	assert.True(t, ok, "the ticker still ticks after its period of uptime")
	_, ok = recv(t, timer)
	assert.False(t, ok)
	f.Advance(time.Hour)
	_, ok = recv(t, timer)
	assert.True(t, ok, "the timer fires after its remaining duration")
	assert.Equal(t, 2*time.Hour, f.Elapsed())

	f.JumpWall(-100 * time.Hour)
	assert.True(t, f.Now().Equal(start.Add(-26*time.Hour)))
	assert.Equal(t, 2*time.Hour, f.Elapsed())
}
```

Append to `internal/platform/clock/offset_test.go`:

```go
func TestOffsetElapsedAddsForwardAdvancesOnly(t *testing.T) {
	start := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	base := clock.NewFake(start)
	o := clock.NewOffset(base)
	var m clock.Monotonic = o

	base.Advance(time.Minute)
	assert.Equal(t, time.Minute, m.Elapsed())
	o.Advance(48 * time.Hour)
	assert.Equal(t, 48*time.Hour+time.Minute, o.Elapsed(), "a demo-clock advance is also uptime (not a clock jump)")
	o.Advance(-5 * time.Hour)
	assert.Equal(t, 48*time.Hour+time.Minute, o.Elapsed(), "moving back never lowers uptime")
	assert.True(t, o.Now().Equal(start.Add(43*time.Hour+time.Minute)))

	o.JumpWall(10 * 24 * time.Hour)
	assert.Equal(t, 48*time.Hour+time.Minute, o.Elapsed(), "a wall-only jump is not uptime")
	assert.True(t, o.Now().Equal(start.Add(10*24*time.Hour+43*time.Hour+time.Minute)))

	o.Reset()
	assert.True(t, o.Now().Equal(start.Add(time.Minute)))
	assert.Equal(t, 48*time.Hour+time.Minute, o.Elapsed(), "Reset keeps uptime monotonic")
}

func TestOffsetOverNonMonotonicBaseCountsAdvancesOnly(t *testing.T) {
	o := clock.NewOffset(plainClock{})
	o.Advance(time.Hour)
	assert.Equal(t, time.Hour, o.Elapsed())
}

// plainClock is a Clock without Elapsed.
type plainClock struct{}

func (plainClock) Now() time.Time                         { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
func (plainClock) After(time.Duration) <-chan time.Time   { return make(chan time.Time) }
func (plainClock) NewTicker(time.Duration) clock.Ticker   { return nil }
```

Run: `go test -count=1 ./internal/platform/clock/`
Expected: FAIL — compile errors `undefined: clock.Monotonic`, `f.Elapsed undefined`, `f.JumpWall undefined`, `o.Elapsed undefined`, `o.JumpWall undefined`.

- [ ] **Step 2: Add `Monotonic` and make `Fake` jump-aware and fast**

In `internal/platform/clock/clock.go`:

1. Add `"sort"` to the imports.
2. After the `Ticker` interface add:

```go
// Monotonic measures elapsed process time ("uptime"). It never decreases and is not
// affected when someone changes the wall clock (spec R26 compares the two).
type Monotonic interface {
	Elapsed() time.Duration
}

// processStart carries Go's monotonic clock reading, so Real.Elapsed ignores wall-clock changes.
var processStart = time.Now()

// Elapsed returns the monotonic time since the process started.
func (Real) Elapsed() time.Duration { return time.Since(processStart) }
```

3. Replace the `Fake` struct and doc comment with:

```go
// Fake is a manually controlled clock for tests. It is safe for concurrent
// use. Set and Advance fire due timers and tickers deterministically; forward
// moves also count as uptime (Elapsed), JumpWall moves only the wall clock.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	elapsed time.Duration
	timers  []*fakeTimer
	tickers []*fakeTicker
}
```

4. After `Advance` add:

```go
// Elapsed returns the fake uptime: the sum of all forward moves made by Set and Advance.
func (f *Fake) Elapsed() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.elapsed
}

// JumpWall moves only the wall clock by d, like an administrator setting the system
// time: Elapsed does not change, nothing fires, and pending timers and tickers keep
// their remaining durations (Go timers use the monotonic clock too).
func (f *Fake) JumpWall(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	for _, tm := range f.timers {
		tm.at = tm.at.Add(d)
	}
	for _, tk := range f.tickers {
		tk.next = tk.next.Add(d)
	}
}
```

5. Replace the whole `moveTo` function with:

```go
// moveTo sets now to target. Moving forward counts as uptime, fires every due
// timer once (in deadline order) and gives every due ticker one tick carrying its
// latest due time: like time.Ticker with a slow receiver, missed ticks are dropped.
// The ticker schedule is advanced arithmetically, so the cost does not depend on
// how many periods the move spans. The caller must hold f.mu.
func (f *Fake) moveTo(target time.Time) {
	if !target.After(f.now) {
		f.now = target
		return
	}
	f.elapsed += target.Sub(f.now)
	sort.SliceStable(f.timers, func(i, j int) bool { return f.timers[i].at.Before(f.timers[j].at) })
	n := len(f.timers)
	remaining := f.timers[:0]
	for _, tm := range f.timers {
		if tm.at.After(target) {
			remaining = append(remaining, tm)
			continue
		}
		tm.ch <- tm.at // buffered (1) and fires once, never blocks
	}
	for i := len(remaining); i < n; i++ {
		f.timers[i] = nil // drop references to fired timers
	}
	f.timers = remaining
	for _, tk := range f.tickers {
		if tk.next.After(target) {
			continue
		}
		last := tk.next.Add(target.Sub(tk.next) / tk.period * tk.period)
		select {
		case tk.ch <- last:
		default: // the receiver has not taken the previous tick yet
		}
		tk.next = last.Add(tk.period)
	}
	f.now = target
}
```

- [ ] **Step 3: Give `Offset` uptime and wall-only jumps**

Replace `internal/platform/clock/offset.go` with:

```go
package clock

import (
	"sync"
	"time"
)

// Offset is a clock shifted by an adjustable offset from a base clock. Only the
// test-only e2e build uses it (POST /test/clock); release builds use Real.
// Timers and tickers are not shifted: they measure durations on the base clock.
//
// A forward Advance models "time passes" (the demo clock), so it also counts as
// uptime in Elapsed. JumpWall models an administrator changing the system clock:
// only Now moves. Elapsed never decreases.
type Offset struct {
	mu   sync.Mutex
	base Clock
	off  time.Duration // added to the base wall time
	up   time.Duration // added to the base uptime
}

// NewOffset returns an Offset with a zero offset.
func NewOffset(base Clock) *Offset { return &Offset{base: base} }

// Now returns the base time plus the offset.
func (o *Offset) Now() time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.base.Now().Add(o.off)
}

// After delegates to the base clock.
func (o *Offset) After(d time.Duration) <-chan time.Time { return o.base.After(d) }

// NewTicker delegates to the base clock.
func (o *Offset) NewTicker(d time.Duration) Ticker { return o.base.NewTicker(d) }

// Elapsed returns the base clock's uptime (zero if it has none) plus every forward Advance.
func (o *Offset) Elapsed() time.Duration {
	o.mu.Lock()
	defer o.mu.Unlock()
	var base time.Duration
	if m, ok := o.base.(Monotonic); ok {
		base = m.Elapsed()
	}
	return base + o.up
}

// Advance moves Now forward by d (backward for negative d). A forward move is also uptime.
func (o *Offset) Advance(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.off += d
	if d > 0 {
		o.up += d
	}
}

// JumpWall moves Now by d without adding uptime (a wall-clock change).
func (o *Offset) JumpWall(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.off += d
}

// Reset sets the wall offset back to zero. Uptime is kept: it never decreases.
func (o *Offset) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.off = 0
}
```

- [ ] **Step 4: Run the clock tests**

Run: `go test -race -count=1 ./internal/platform/clock/`
Expected: PASS, including the unchanged Phase 1 tests (`TestFakeTickerMultipleTicksDropsLikeTimeTicker`, `TestFakeConcurrentUse`).

- [ ] **Step 5: Run everything that uses the fake clock**

Run: `go test -race -count=1 ./... && go test -race -count=1 -tags integration ./internal/auth/... ./internal/api/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/platform/clock/
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(clock): monotonic uptime, wall-clock jumps and O(1) ticker advances

Fake.Advance no longer loops once per tick: timers fire in deadline order and
each ticker delivers its latest due tick, so a year-long demo-clock move
returns at once. Real, Fake and Offset implement Monotonic (uptime) for the
license clock guard; Fake.JumpWall and Offset.JumpWall move only the wall
clock, as an administrator changing the system time would.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 3: License file format — installation IDs, canonical payload, strict parser, validation

The pure, dependency-free core of spec §16.2–§16.4: the installation ID with its check character, the RFC 8785
canonical form of the payload, a strict parser that refuses duplicate keys and unknown fields, and payload
validation. Signature verification and key sets follow in Task 4.

**Files:**
- Create: `internal/license/doc.go`, `internal/license/errors.go`, `internal/license/installid.go`, `internal/license/jcs.go`, `internal/license/file.go`
- Test: `internal/license/installid_test.go`, `internal/license/jcs_test.go`, `internal/license/file_test.go`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces (`alice/internal/license`):
  - Constants: `MaxFileSize = 64 << 10`, `FormatVersion = 1`, `MaxTargetsLimit = 100000`.
  - Errors: `ErrInvalid`, `ErrUnsupportedFormat`, `ErrUnknownKey`, `ErrRevokedKey`, `ErrWrongInstallation`, `ErrOlderThanInstalled`, `ErrLocked`, `ErrTargetLimit`, `ErrUnclassified`, `ErrInvalidInstallationID`; `type InvalidError struct{ Problem string }` (matches `ErrInvalid`; `Problem` is a fixed label such as `"signature"`, `"duplicate_key"`); `type WrongInstallationError struct{ Expected, Got string }` (matches `ErrWrongInstallation`; both hold the last six characters); `type TargetLimitError struct{ Max, Used int }` (matches `ErrTargetLimit`); `func RejectReason(err error) string` (audit label: `invalid_signature`, `invalid`, `unsupported_format`, `unknown_key`, `revoked_key`, `wrong_installation`, `older_than_installed`, `error`); `func IDSuffix(id string) string` (last six characters).
  - `func NewInstallationID() string` → `"ALICE-XXXX-XXXX-XXXX-XXXX"`; `func ParseInstallationID(s string) (string, error)`.
  - `type Payload struct { LicenseID, Customer, InstallationID string; IssuedAt, ValidFrom, ValidUntil time.Time; MaxTargets int; Features []string; Format int; Replaces string }`; `func (p Payload) Validate() error`.
  - `type File struct { Format int; KeyID string; Payload Payload; Signature []byte }`.
  - `func CanonicalPayload(p Payload) []byte`; `func SignedBytes(p Payload) []byte` (= `"ALICE-LICENSE-v1\n"` + canonical payload).
  - `func ParseFile(raw []byte) (File, error)`; `func EncodeFile(f File) ([]byte, error)`; `func Sign(priv ed25519.PrivateKey, keyID string, p Payload) (File, error)`.

- [ ] **Step 1: Write the failing installation ID tests**

Create `internal/license/installid_test.go`:

```go
package license_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// lowerASCII lower-cases ASCII letters (strings.ToLower is banned repo-wide).
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func idBody(id string) string { return strings.ReplaceAll(strings.TrimPrefix(id, "ALICE-"), "-", "") }

func TestNewInstallationIDFormat(t *testing.T) {
	re := regexp.MustCompile(`^ALICE(-[0-9A-HJKMNP-TV-Z]{4}){4}$`)
	seen := map[string]bool{}
	for range 1000 {
		id := license.NewInstallationID()
		require.Regexp(t, re, id)
		got, err := license.ParseInstallationID(id)
		require.NoError(t, err)
		require.Equal(t, id, got)
		require.False(t, seen[id], "IDs are random")
		seen[id] = true
	}
}

func TestParseInstallationIDNormalizesHandTypedInput(t *testing.T) {
	id := license.NewInstallationID()
	body := idBody(id)
	for _, typed := range []string{
		id,
		"  " + id + "\t",
		lowerASCII(id),
		body,
		body[:4] + " " + body[4:8] + " " + body[8:12] + " " + body[12:],
		"alice " + lowerASCII(body),
		strings.NewReplacer("0", "O", "1", "l").Replace(id), // Crockford: O means 0, I and L mean 1
		strings.NewReplacer("1", "I").Replace(id),
	} {
		got, err := license.ParseInstallationID(typed)
		require.NoError(t, err, typed)
		assert.Equal(t, id, got, typed)
	}
}

// Review Focus 4: a real typo is caught by the check character.
func TestInstallationIDDetectsTypos(t *testing.T) {
	for range 20 {
		chars := []byte(idBody(license.NewInstallationID()))
		for i := range chars {
			for j := 0; j < len(crockford); j++ {
				if crockford[j] == chars[i] {
					continue
				}
				typo := append([]byte(nil), chars...)
				typo[i] = crockford[j]
				_, err := license.ParseInstallationID(string(typo))
				require.ErrorIs(t, err, license.ErrInvalidInstallationID, "substitution at %d", i)
			}
		}
		for i := 0; i+1 < len(chars); i++ {
			a, b := chars[i], chars[i+1]
			// "0Z"/"Z0" is the one neighbour swap Luhn mod 32 cannot see.
			if a == b || (a == '0' && b == 'Z') || (a == 'Z' && b == '0') {
				continue
			}
			swapped := append([]byte(nil), chars...)
			swapped[i], swapped[i+1] = b, a
			_, err := license.ParseInstallationID(string(swapped))
			require.ErrorIs(t, err, license.ErrInvalidInstallationID, "transposition at %d", i)
		}
	}
}

func TestParseInstallationIDRejectsMalformedInput(t *testing.T) {
	id := license.NewInstallationID()
	for _, bad := range []string{
		"", "ALICE-", id[:len(id)-1], id + "0", id[:len(id)-1] + "U", "ALİCE-" + idBody(id), strings.Replace(id, "-", "_", 1),
	} {
		_, err := license.ParseInstallationID(bad)
		assert.ErrorIs(t, err, license.ErrInvalidInstallationID, bad)
	}
}
```

Run: `go test -count=1 ./internal/license/`
Expected: FAIL — `no non-test Go files` / `undefined: license.NewInstallationID`.

- [ ] **Step 2: Create the package, errors and installation IDs**

Create `internal/license/doc.go`:

```go
// Package license verifies Alice's signed license files and computes the license
// state (evaluation, active, grace, locked) from a trusted clock (spec §16, §23).
//
// The file format, key set, state machine and clock guard are pure and tested
// without a database. Service (service.go) stores uploaded files verbatim,
// re-verifies them on every evaluation and is the single lock-mode gate (Allow)
// used by the API guard and the job scheduler.
package license
```

Create `internal/license/errors.go`:

```go
package license

import (
	"errors"
	"fmt"
)

// Errors returned by the license module. The API maps each to a stable ALC-LIC code.
var (
	ErrInvalid               = errors.New("license: not a valid license file")
	ErrUnsupportedFormat     = errors.New("license: the file uses a newer format than this version of Alice supports")
	ErrUnknownKey            = errors.New("license: signed by a key this version of Alice does not know")
	ErrRevokedKey            = errors.New("license: signed by a key that is no longer trusted")
	ErrWrongInstallation     = errors.New("license: issued for another installation")
	ErrOlderThanInstalled    = errors.New("license: a newer license is already installed")
	ErrLocked                = errors.New("license: the license has expired; changes are paused")
	ErrTargetLimit           = errors.New("license: the licensed number of targets is reached")
	ErrUnclassified          = errors.New("license: work without a license class")
	ErrInvalidInstallationID = errors.New("license: installation ID is not valid")
)

// InvalidError says why a file is not a valid license. Problem is a fixed label
// for logs and the audit trail; it never contains file content.
type InvalidError struct{ Problem string }

func (e *InvalidError) Error() string { return "license: not a valid license file (" + e.Problem + ")" }

// Is makes every InvalidError match ErrInvalid.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

func invalid(problem string) error { return &InvalidError{Problem: problem} }

// WrongInstallationError is returned for a license made for another installation.
// Expected and Got are the last six characters of the two IDs (L-43).
type WrongInstallationError struct{ Expected, Got string }

func (e *WrongInstallationError) Error() string {
	return fmt.Sprintf("license: issued for installation …%s, this is …%s", e.Got, e.Expected)
}

// Is makes every WrongInstallationError match ErrWrongInstallation.
func (e *WrongInstallationError) Is(target error) bool { return target == ErrWrongInstallation }

// TargetLimitError is returned when adding a target would exceed the license (L-71).
type TargetLimitError struct{ Max, Used int }

func (e *TargetLimitError) Error() string {
	return fmt.Sprintf("license: %d of %d licensed targets are in use", e.Used, e.Max)
}

// Is makes every TargetLimitError match ErrTargetLimit.
func (e *TargetLimitError) Is(target error) bool { return target == ErrTargetLimit }

// IDSuffix returns the last six characters of an installation ID (shown in messages
// so an administrator can compare IDs without reading the whole value aloud).
func IDSuffix(id string) string {
	if len(id) <= 6 {
		return id
	}
	return id[len(id)-6:]
}

// RejectReason is the audit label of a refused upload: the audit action is
// "license.upload." + RejectReason(err) (spec L-40: license.upload.invalid_signature).
func RejectReason(err error) string {
	var inv *InvalidError
	switch {
	case errors.As(err, &inv) && inv.Problem == "signature":
		return "invalid_signature"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrUnsupportedFormat):
		return "unsupported_format"
	case errors.Is(err, ErrUnknownKey):
		return "unknown_key"
	case errors.Is(err, ErrRevokedKey):
		return "revoked_key"
	case errors.Is(err, ErrWrongInstallation):
		return "wrong_installation"
	case errors.Is(err, ErrOlderThanInstalled):
		return "older_than_installed"
	default:
		return "error"
	}
}
```

Create `internal/license/installid.go`:

```go
package license

import (
	"crypto/rand"
	"strings"
)

// crockford is the Crockford base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// installationIDLen is the number of symbols: 15 random ones (75 bits) and one check symbol.
const installationIDLen = 16

// NewInstallationID returns a random installation ID "ALICE-XXXX-XXXX-XXXX-XXXX" (spec §16.4, R7).
// The last symbol is a Luhn mod 32 check character, so a mistyped symbol or two swapped
// neighbours are detected when the customer emails the ID to the vendor.
func NewInstallationID() string {
	var raw [installationIDLen - 1]byte
	rand.Read(raw[:])
	vals := make([]int, 0, installationIDLen)
	for _, b := range raw {
		vals = append(vals, int(b&31)) // 256 is a multiple of 32: uniform
	}
	vals = append(vals, luhnCheck(vals))
	return formatID(vals)
}

// ParseInstallationID accepts an ID the way a person may type it — any case, with or
// without the ALICE prefix, dashes or spaces between groups, O for 0 and I or L for 1
// (Crockford decoding) — and returns the canonical form. It returns
// ErrInvalidInstallationID when the length, a symbol or the check character is wrong.
func ParseInstallationID(s string) (string, error) {
	body := strings.TrimSpace(s)
	if len(body) >= 5 && strings.EqualFold(body[:5], "ALICE") {
		body = body[5:]
	}
	vals := make([]int, 0, installationIDLen)
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == '-' || c == ' ' {
			continue
		}
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		idx := strings.IndexByte(crockford, c)
		if idx < 0 {
			return "", ErrInvalidInstallationID
		}
		vals = append(vals, idx)
	}
	if len(vals) != installationIDLen || !luhnValid(vals) {
		return "", ErrInvalidInstallationID
	}
	return formatID(vals), nil
}

func formatID(vals []int) string {
	var b strings.Builder
	b.WriteString("ALICE")
	for i, v := range vals {
		if i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(crockford[v])
	}
	return b.String()
}

// luhnCheck computes the Luhn mod 32 check value for body (factor 2 on the rightmost symbol).
func luhnCheck(body []int) int {
	factor, sum := 2, 0
	for i := len(body) - 1; i >= 0; i-- {
		addend := factor * body[i]
		sum += addend/32 + addend%32
		factor = 3 - factor
	}
	return (32 - sum%32) % 32
}

// luhnValid checks a sequence that ends with its check value.
func luhnValid(all []int) bool {
	factor, sum := 1, 0
	for i := len(all) - 1; i >= 0; i-- {
		addend := factor * all[i]
		sum += addend/32 + addend%32
		factor = 3 - factor
	}
	return sum%32 == 0
}
```

Run: `go test -count=1 -run InstallationID ./internal/license/`
Expected: PASS (4 tests).

- [ ] **Step 3: Write the failing canonical JSON and file tests**

Create `internal/license/jcs_test.go`:

```go
package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/license"
)

func TestCanonicalPayloadIsRFC8785(t *testing.T) {
	p := license.Payload{
		LicenseID:      "LIC-2026-000123",
		Customer:       "Örnek \"Bankası\" A.Ş. \\ <&> \u0001\t\n",
		InstallationID: "ALICE-7F3K-9Q2M-XD41-B8TC",
		IssuedAt:       time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC),
		ValidFrom:      time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC),
		ValidUntil:     time.Date(2027, 9, 29, 0, 0, 0, 0, time.UTC),
		MaxTargets:     100,
		Format:         1,
	}
	want := `{"customer":"Örnek \"Bankası\" A.Ş. \\ <&> \u0001\t\n","features":[],"format":1,` +
		`"installation_id":"ALICE-7F3K-9Q2M-XD41-B8TC","issued_at":"2026-09-29T09:00:00Z","license_id":"LIC-2026-000123",` +
		`"max_targets":100,"valid_from":"2026-09-29T00:00:00Z","valid_until":"2027-09-29T00:00:00Z"}`
	assert.Equal(t, want, string(license.CanonicalPayload(p)))

	p.Features = []string{"zeta", "alpha"}
	p.Replaces = "LIC-2026-000100"
	p.IssuedAt = time.Date(2026, 9, 29, 12, 0, 0, 0, time.FixedZone("TRT", 3*3600)) // rendered in UTC
	want = `{"customer":"Örnek \"Bankası\" A.Ş. \\ <&> \u0001\t\n","features":["zeta","alpha"],"format":1,` +
		`"installation_id":"ALICE-7F3K-9Q2M-XD41-B8TC","issued_at":"2026-09-29T09:00:00Z","license_id":"LIC-2026-000123",` +
		`"max_targets":100,"replaces":"LIC-2026-000100","valid_from":"2026-09-29T00:00:00Z","valid_until":"2027-09-29T00:00:00Z"}`
	assert.Equal(t, want, string(license.CanonicalPayload(p)))
	assert.Equal(t, "ALICE-LICENSE-v1\n"+want, string(license.SignedBytes(p)))
}
```

Create `internal/license/file_test.go`:

```go
package license_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// fileTestKey is a throw-away key for format tests (the shared test signer is in licensetest).
var fileTestKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

func samplePayload(t *testing.T) license.Payload {
	t.Helper()
	return license.Payload{
		LicenseID:      "LIC-2026-000123",
		Customer:       "Örnek Bankası A.Ş.",
		InstallationID: license.NewInstallationID(),
		IssuedAt:       time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC),
		ValidFrom:      time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC),
		ValidUntil:     time.Date(2027, 9, 29, 0, 0, 0, 0, time.UTC),
		MaxTargets:     10,
		Features:       []string{},
		Format:         1,
	}
}

func encodeSigned(t *testing.T, p license.Payload) []byte {
	t.Helper()
	f, err := license.Sign(fileTestKey, "vk-2026-01", p)
	require.NoError(t, err)
	raw, err := license.EncodeFile(f)
	require.NoError(t, err)
	return raw
}

// replaceOnce replaces the first from with to and fails the test when from is absent.
func replaceOnce(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	require.Contains(t, string(raw), from)
	return []byte(strings.Replace(string(raw), from, to, 1))
}

func requireInvalid(t *testing.T, raw []byte, problem string) {
	t.Helper()
	_, err := license.ParseFile(raw)
	require.ErrorIs(t, err, license.ErrInvalid)
	var inv *license.InvalidError
	require.ErrorAs(t, err, &inv)
	assert.Equal(t, problem, inv.Problem)
}

func TestEncodeParseRoundTrip(t *testing.T) {
	p := samplePayload(t)
	raw := encodeSigned(t, p)
	assert.Contains(t, string(raw), "\n  \"payload\": {", "files are pretty-printed for people")
	assert.Contains(t, string(raw), "Örnek Bankası", "non-ASCII is written as UTF-8")

	f, err := license.ParseFile(raw)
	require.NoError(t, err)
	assert.Equal(t, 1, f.Format)
	assert.Equal(t, "vk-2026-01", f.KeyID)
	assert.Equal(t, p, f.Payload)
	assert.True(t, ed25519.Verify(fileTestKey.Public().(ed25519.PublicKey), license.SignedBytes(f.Payload), f.Signature))
}

// Review Focus 3: what an email client or editor does to a file must not break it.
func TestParseAcceptsHarmlessReformatting(t *testing.T) {
	p := samplePayload(t)
	raw := encodeSigned(t, p)
	var compact bytes.Buffer
	require.NoError(t, json.Compact(&compact, raw))
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &top))
	reordered := `{"signature":` + string(top["signature"]) + `,"payload":` + string(top["payload"]) +
		`,"key_id":` + string(top["key_id"]) + `,"format":1}`

	for name, variant := range map[string][]byte{
		"CRLF":           bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n")),
		"byte-order mark": append([]byte{0xEF, 0xBB, 0xBF}, raw...),
		"compact":        compact.Bytes(),
		"reordered keys": []byte(reordered),
		"extra spaces":   bytes.ReplaceAll(raw, []byte(": "), []byte(" :   ")),
	} {
		f, err := license.ParseFile(variant)
		require.NoError(t, err, name)
		assert.Equal(t, p, f.Payload, name)
		assert.Equal(t, string(license.CanonicalPayload(p)), string(license.CanonicalPayload(f.Payload)), name)
	}
}

func TestParseRejectsMalformedFiles(t *testing.T) {
	raw := encodeSigned(t, samplePayload(t))
	tooLarge := append(bytes.TrimRight(raw, "\n}"), []byte(strings.Repeat(" ", license.MaxFileSize)+"}")...)

	cases := map[string]struct {
		raw     []byte
		problem string
	}{
		"empty":                     {nil, "empty"},
		"over 64 KiB":               {tooLarge, "too_large"},
		"not JSON":                  {[]byte("garbage"), "not_json"},
		"base64 text":               {[]byte("eyJmb3JtYXQiOjF9"), "not_json"},
		"array":                     {[]byte(`[1]`), "not_json"},
		"two documents":             {append(append([]byte(nil), raw...), raw...), "not_json"},
		"truncated":                 {raw[:len(raw)-20], "not_json"},
		"invalid UTF-8":             {replaceOnce(t, raw, "Örnek", "\xffrnek"), "encoding"},
		"extra top-level field":     {replaceOnce(t, raw, `"format": 1,`, `"format": 1, "comment": "x",`), "fields"},
		"extra payload field":       {replaceOnce(t, raw, `"customer":`, `"discount": 1, "customer":`), "fields"},
		"duplicate top-level key":   {replaceOnce(t, raw, `"format": 1,`, `"format": 1, "format": 1,`), "duplicate_key"},
		"duplicate payload key":     {replaceOnce(t, raw, `"max_targets": 10,`, `"max_targets": 10, "max_targets": 1000,`), "duplicate_key"},
		"missing signature":         {replaceOnce(t, raw, `"signature":`, `"signature_old":`), "fields"},
		"null payload":              {[]byte(`{"format":1,"key_id":"vk-2026-01","payload":null,"signature":"AA"}`), "missing_field"},
		"missing payload field":     {replaceOnce(t, raw, `"max_targets": 10,`, ``), "missing_field"},
		"number as string":          {replaceOnce(t, raw, `"max_targets": 10`, `"max_targets": "10"`), "fields"},
		"fractional number":         {replaceOnce(t, raw, `"max_targets": 10`, `"max_targets": 10.5`), "fields"},
		"offset timestamp":          {replaceOnce(t, raw, `"2026-09-29T09:00:00Z"`, `"2026-09-29T09:00:00+00:00"`), "timestamp"},
		"fractional timestamp":      {replaceOnce(t, raw, `"2026-09-29T09:00:00Z"`, `"2026-09-29T09:00:00.000Z"`), "timestamp"},
		"inner format differs":      {replaceOnce(t, raw, `"format": 1,`+"\n    \"installation_id\"", `"format": 2,`+"\n    \"installation_id\""), "format"},
		"outer format zero":         {replaceOnce(t, raw, `"format": 1,`+"\n  \"key_id\"", `"format": 0,`+"\n  \"key_id\""), "format"},
		"bad key id":                {replaceOnce(t, raw, `"vk-2026-01"`, `"../../etc"`), "key_id"},
		"short signature":           {[]byte(strings.Replace(string(raw), `"signature": "`, `"signature": "AAAA`, 1)), "signature_encoding"},
		"deeply nested features":    {replaceOnce(t, raw, `"features": []`, `"features": [[[["x"]]]]`), "too_deep"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { requireInvalid(t, tc.raw, tc.problem) })
	}
}

// L-45: a newer format is not "invalid": the administrator is told to update Alice.
func TestParseReportsNewerFormats(t *testing.T) {
	raw := encodeSigned(t, samplePayload(t))
	newer := replaceOnce(t, raw, `"format": 1,`+"\n  \"key_id\"", `"format": 99,`+"\n  \"key_id\"")
	_, err := license.ParseFile(newer)
	require.ErrorIs(t, err, license.ErrUnsupportedFormat)
	assert.NotErrorIs(t, err, license.ErrInvalid)
}

// L-46, L-47 and the §16.3 step 5 rules.
func TestValidatePayload(t *testing.T) {
	cases := map[string]struct {
		change  func(p *license.Payload)
		problem string // "" = valid
	}{
		"sample":                         {func(*license.Payload) {}, ""},
		"unknown features are accepted":  {func(p *license.Payload) { p.Features = []string{"future-edition", "x.y_z"} }, ""},
		"until before from":              {func(p *license.Payload) { p.ValidUntil = p.ValidFrom.Add(-time.Second) }, "validity"},
		"until equals from":              {func(p *license.Payload) { p.ValidUntil = p.ValidFrom }, ""},
		"zero targets":                   {func(p *license.Payload) { p.MaxTargets = 0 }, "max_targets"},
		"negative targets":               {func(p *license.Payload) { p.MaxTargets = -1 }, "max_targets"},
		"100000 targets":                 {func(p *license.Payload) { p.MaxTargets = 100000 }, ""},
		"100001 targets":                 {func(p *license.Payload) { p.MaxTargets = 100001 }, "max_targets"},
		"above one million targets":      {func(p *license.Payload) { p.MaxTargets = 1_000_001 }, "max_targets"},
		"issued 25 h after valid_from":   {func(p *license.Payload) { p.IssuedAt = p.ValidFrom.Add(25 * time.Hour) }, "issued_at"},
		"issued 24 h after valid_from":   {func(p *license.Payload) { p.IssuedAt = p.ValidFrom.Add(24 * time.Hour) }, ""},
		"issued long before valid_from":  {func(p *license.Payload) { p.IssuedAt = p.ValidFrom.AddDate(-1, 0, 0) }, ""},
		"dates before 2000":              {func(p *license.Payload) { p.ValidFrom = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) }, "dates"},
		"bad installation id":            {func(p *license.Payload) { p.InstallationID = "ALICE-0000-0000-0000-0001" }, "installation_id"},
		"non-canonical installation id":  {func(p *license.Payload) { p.InstallationID = lowerASCII(p.InstallationID) }, "installation_id"},
		"empty customer":                 {func(p *license.Payload) { p.Customer = "" }, "customer"},
		"customer with a newline":        {func(p *license.Payload) { p.Customer = "Bank\nEvil: header" }, "customer"},
		"customer with outer spaces":     {func(p *license.Payload) { p.Customer = " Bank" }, "customer"},
		"customer 200 runes":             {func(p *license.Payload) { p.Customer = strings.Repeat("ş", 200) }, ""},
		"customer 201 runes":             {func(p *license.Payload) { p.Customer = strings.Repeat("ş", 201) }, "customer"},
		"bad license id":                 {func(p *license.Payload) { p.LicenseID = "LIC 1" }, "license_id"},
		"replaces itself":                {func(p *license.Payload) { p.Replaces = p.LicenseID }, "replaces"},
		"bad feature":                    {func(p *license.Payload) { p.Features = []string{"Upper"} }, "features"},
		"33 features":                    {func(p *license.Payload) { p.Features = make([]string, 33) }, "features"},
		"format 2":                       {func(p *license.Payload) { p.Format = 2 }, "format"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := samplePayload(t)
			tc.change(&p)
			err := p.Validate()
			if tc.problem == "" {
				require.NoError(t, err)
				return
			}
			var inv *license.InvalidError
			require.ErrorAs(t, err, &inv)
			assert.Equal(t, tc.problem, inv.Problem)
		})
	}
}

func TestSignRefusesInvalidPayloads(t *testing.T) {
	p := samplePayload(t)
	p.MaxTargets = 0
	_, err := license.Sign(fileTestKey, "vk-2026-01", p)
	require.ErrorIs(t, err, license.ErrInvalid)
	_, err = license.Sign(fileTestKey, "not a key id", samplePayload(t))
	require.ErrorIs(t, err, license.ErrInvalid)
}

func TestRejectReasonAndSuffix(t *testing.T) {
	assert.Equal(t, "invalid_signature", license.RejectReason(&license.InvalidError{Problem: "signature"}))
	assert.Equal(t, "invalid", license.RejectReason(&license.InvalidError{Problem: "fields"}))
	assert.Equal(t, "wrong_installation", license.RejectReason(&license.WrongInstallationError{Expected: "a", Got: "b"}))
	assert.Equal(t, "unsupported_format", license.RejectReason(license.ErrUnsupportedFormat))
	assert.Equal(t, "older_than_installed", license.RejectReason(license.ErrOlderThanInstalled))
	assert.Equal(t, "B8TC00", license.IDSuffix("ALICE-7F3K-9Q2M-XD41-B8TC00"))
	assert.ErrorIs(t, &license.TargetLimitError{Max: 10, Used: 10}, license.ErrTargetLimit)
}
```

Run: `go test -count=1 ./internal/license/`
Expected: FAIL — `undefined: license.Payload`, `license.ParseFile`, `license.CanonicalPayload`, ….

- [ ] **Step 4: Implement RFC 8785 canonicalization**

Create `internal/license/jcs.go`:

```go
package license

import (
	"sort"
	"strconv"
	"time"
	"unicode/utf16"
)

const hexDigits = "0123456789abcdef"

// appendJCSString appends s as an RFC 8785 string: only '"', '\\' and control
// characters are escaped (\b \t \n \f \r, the others as \u00xx in lower case);
// every other character, including non-ASCII, is written as UTF-8.
func appendJCSString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b = append(b, '\\', '"')
		case c == '\\':
			b = append(b, '\\', '\\')
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\t':
			b = append(b, '\\', 't')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// utf16Less orders object keys by UTF-16 code units (RFC 8785 §3.2.3).
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// formatTime renders an instant the only way the format allows: RFC 3339, UTC, "Z", whole seconds.
func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// CanonicalPayload returns the RFC 8785 (JCS) form of p: members sorted by key, no
// whitespace, integers in decimal. "replaces" is present only when set (spec §16.2).
func CanonicalPayload(p Payload) []byte {
	type member struct {
		key   string
		value []byte
	}
	str := func(s string) []byte { return appendJCSString(nil, s) }
	features := []byte{'['}
	for i, f := range p.Features {
		if i > 0 {
			features = append(features, ',')
		}
		features = appendJCSString(features, f)
	}
	features = append(features, ']')

	members := []member{
		{"customer", str(p.Customer)},
		{"features", features},
		{"format", []byte(strconv.Itoa(p.Format))},
		{"installation_id", str(p.InstallationID)},
		{"issued_at", str(formatTime(p.IssuedAt))},
		{"license_id", str(p.LicenseID)},
		{"max_targets", []byte(strconv.Itoa(p.MaxTargets))},
		{"valid_from", str(formatTime(p.ValidFrom))},
		{"valid_until", str(formatTime(p.ValidUntil))},
	}
	if p.Replaces != "" {
		members = append(members, member{"replaces", str(p.Replaces)})
	}
	sort.Slice(members, func(i, j int) bool { return utf16Less(members[i].key, members[j].key) })

	out := []byte{'{'}
	for i, m := range members {
		if i > 0 {
			out = append(out, ',')
		}
		out = appendJCSString(out, m.key)
		out = append(out, ':')
		out = append(out, m.value...)
	}
	return append(out, '}')
}
```

- [ ] **Step 5: Implement the strict parser, validation, signing and encoding**

Create `internal/license/file.go`:

```go
package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits of the file format (spec §16.2, §16.3).
const (
	MaxFileSize     = 64 << 10
	FormatVersion   = 1
	MaxTargetsLimit = 100000

	signingPrefix    = "ALICE-LICENSE-v1\n"
	maxDepth         = 3 // file object > payload object > features array
	maxCustomerRunes = 200
	maxFeatures      = 32
)

var (
	keyIDPattern   = regexp.MustCompile(`^vk-[a-z0-9]{1,8}(-[a-z0-9]{1,8}){0,3}$`)
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	featurePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	earliestDate   = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	byteOrderMark  = []byte{0xEF, 0xBB, 0xBF}
)

// Payload is the signed content of a license file (spec §16.2).
type Payload struct {
	LicenseID      string
	Customer       string
	InstallationID string
	IssuedAt       time.Time
	ValidFrom      time.Time
	ValidUntil     time.Time
	MaxTargets     int
	Features       []string
	Format         int
	Replaces       string // license ID that a correction license supersedes (R7); "" = none
}

// File is a parsed license file. Nothing in it is trusted before Verify.
type File struct {
	Format    int
	KeyID     string
	Payload   Payload
	Signature []byte
}

// SignedBytes are the bytes the vendor signs: a domain separator and the canonical payload.
func SignedBytes(p Payload) []byte {
	return append([]byte(signingPrefix), CanonicalPayload(p)...)
}

// Sign validates p and signs it with priv (used by licensectl and test signers).
func Sign(priv ed25519.PrivateKey, keyID string, p Payload) (File, error) {
	if !keyIDPattern.MatchString(keyID) {
		return File{}, invalid("key_id")
	}
	if err := p.Validate(); err != nil {
		return File{}, err
	}
	return File{Format: p.Format, KeyID: keyID, Payload: p, Signature: ed25519.Sign(priv, SignedBytes(p))}, nil
}

// EncodeFile renders f as the pretty-printed UTF-8 JSON file sent to customers.
func EncodeFile(f File) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(struct {
		Format    int             `json:"format"`
		KeyID     string          `json:"key_id"`
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
	}{f.Format, f.KeyID, CanonicalPayload(f.Payload), base64.RawURLEncoding.EncodeToString(f.Signature)})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type wireFile struct {
	Format    *int64          `json:"format"`
	KeyID     *string         `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature *string         `json:"signature"`
}

type wirePayload struct {
	LicenseID      *string   `json:"license_id"`
	Customer       *string   `json:"customer"`
	InstallationID *string   `json:"installation_id"`
	IssuedAt       *string   `json:"issued_at"`
	ValidFrom      *string   `json:"valid_from"`
	ValidUntil     *string   `json:"valid_until"`
	MaxTargets     *int64    `json:"max_targets"`
	Features       *[]string `json:"features"`
	Format         *int64    `json:"format"`
	Replaces       *string   `json:"replaces"`
}

// ParseFile parses a license file strictly (spec §16.3 step 1): at most 64 KiB, UTF-8
// (a leading byte-order mark is ignored), exactly one JSON object, no duplicate keys,
// no unknown fields, integers as JSON integers, timestamps as RFC 3339 UTC with "Z" and
// whole seconds. A newer outer format returns ErrUnsupportedFormat. The payload is not
// validated here: callers verify the signature first, then call Payload.Validate.
func ParseFile(raw []byte) (File, error) {
	if len(raw) == 0 {
		return File{}, invalid("empty")
	}
	if len(raw) > MaxFileSize {
		return File{}, invalid("too_large")
	}
	raw = bytes.TrimPrefix(raw, byteOrderMark)
	if !utf8.Valid(raw) {
		return File{}, invalid("encoding")
	}
	if err := checkStructure(raw); err != nil {
		return File{}, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return File{}, invalid("not_json")
	}
	var outer int64
	if err := json.Unmarshal(top["format"], &outer); err != nil {
		return File{}, invalid("format")
	}
	if outer > FormatVersion {
		return File{}, ErrUnsupportedFormat
	}
	if outer != FormatVersion {
		return File{}, invalid("format")
	}

	var w wireFile
	if err := strictDecode(raw, &w); err != nil {
		return File{}, invalid("fields")
	}
	if w.Format == nil || w.KeyID == nil || w.Signature == nil {
		return File{}, invalid("fields")
	}
	if !keyIDPattern.MatchString(*w.KeyID) {
		return File{}, invalid("key_id")
	}
	var wp wirePayload
	if len(w.Payload) == 0 {
		return File{}, invalid("missing_field")
	}
	if err := strictDecode(w.Payload, &wp); err != nil {
		return File{}, invalid("fields")
	}
	p, err := wp.payload()
	if err != nil {
		return File{}, err
	}
	if int64(p.Format) != outer {
		return File{}, invalid("format")
	}
	sig, err := base64.RawURLEncoding.DecodeString(*w.Signature)
	if err != nil {
		sig, err = base64.URLEncoding.DecodeString(*w.Signature)
	}
	if err != nil || len(sig) != ed25519.SignatureSize {
		return File{}, invalid("signature_encoding")
	}
	return File{Format: int(outer), KeyID: *w.KeyID, Payload: p, Signature: sig}, nil
}

func (w wirePayload) payload() (Payload, error) {
	if w.LicenseID == nil || w.Customer == nil || w.InstallationID == nil || w.IssuedAt == nil ||
		w.ValidFrom == nil || w.ValidUntil == nil || w.MaxTargets == nil || w.Features == nil || w.Format == nil {
		return Payload{}, invalid("missing_field")
	}
	var times [3]time.Time
	for i, s := range []string{*w.IssuedAt, *w.ValidFrom, *w.ValidUntil} {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil || formatTime(t) != s {
			return Payload{}, invalid("timestamp")
		}
		times[i] = t.UTC()
	}
	if *w.MaxTargets < 0 || *w.MaxTargets > MaxTargetsLimit {
		return Payload{}, invalid("max_targets")
	}
	if *w.Format < 0 || *w.Format > 1000 {
		return Payload{}, invalid("format")
	}
	p := Payload{
		LicenseID:      *w.LicenseID,
		Customer:       *w.Customer,
		InstallationID: *w.InstallationID,
		IssuedAt:       times[0],
		ValidFrom:      times[1],
		ValidUntil:     times[2],
		MaxTargets:     int(*w.MaxTargets),
		Features:       append([]string{}, (*w.Features)...),
		Format:         int(*w.Format),
	}
	if w.Replaces != nil {
		p.Replaces = *w.Replaces
	}
	return p, nil
}

func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// frame is one open JSON object or array during checkStructure.
type frame struct {
	keys    map[string]bool // nil for arrays
	wantKey bool
}

// checkStructure walks the tokens once: exactly one JSON value, nesting at most
// maxDepth, and no object with the same key twice (encoding/json keeps the last one
// silently, which would let a file show one value and sign another).
func checkStructure(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*frame
	values := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return invalid("not_json")
		}
		if n := len(stack); n > 0 && stack[n-1].keys != nil && stack[n-1].wantKey {
			if tok == json.Delim('}') {
				stack = stack[:n-1]
				values = closeValue(stack, values)
				continue
			}
			key, _ := tok.(string)
			if stack[n-1].keys[key] {
				return invalid("duplicate_key")
			}
			stack[n-1].keys[key] = true
			stack[n-1].wantKey = false
			continue
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) == maxDepth {
				return invalid("too_deep")
			}
			f := &frame{}
			if tok == json.Delim('{') {
				f.keys, f.wantKey = map[string]bool{}, true
			}
			stack = append(stack, f)
		case json.Delim(']'):
			stack = stack[:len(stack)-1]
			values = closeValue(stack, values)
		default:
			values = closeValue(stack, values)
		}
	}
	if values != 1 || len(stack) != 0 {
		return invalid("not_json")
	}
	return nil
}

// closeValue records that a complete value ended: inside an object the next token is
// a key; at the top level one more document was read.
func closeValue(stack []*frame, values int) int {
	if n := len(stack); n > 0 {
		if stack[n-1].keys != nil {
			stack[n-1].wantKey = true
		}
		return values
	}
	return values + 1
}

// Validate checks the payload rules of spec §16.3 step 5 plus field syntax. It returns
// an *InvalidError naming the first problem.
func (p Payload) Validate() error {
	switch {
	case p.Format != FormatVersion:
		return invalid("format")
	case !idPattern.MatchString(p.LicenseID):
		return invalid("license_id")
	case p.Replaces != "" && (!idPattern.MatchString(p.Replaces) || p.Replaces == p.LicenseID):
		return invalid("replaces")
	case !validCustomer(p.Customer):
		return invalid("customer")
	case p.MaxTargets < 1 || p.MaxTargets > MaxTargetsLimit:
		return invalid("max_targets")
	case p.IssuedAt.Before(earliestDate) || p.ValidFrom.Before(earliestDate) || p.ValidUntil.Before(earliestDate):
		return invalid("dates")
	case p.ValidUntil.Before(p.ValidFrom):
		return invalid("validity")
	case p.IssuedAt.After(p.ValidFrom.Add(24 * time.Hour)):
		return invalid("issued_at")
	case len(p.Features) > maxFeatures:
		return invalid("features")
	}
	for _, f := range p.Features {
		if !featurePattern.MatchString(f) {
			return invalid("features")
		}
	}
	if id, err := ParseInstallationID(p.InstallationID); err != nil || id != p.InstallationID {
		return invalid("installation_id")
	}
	return nil
}

func validCustomer(s string) bool {
	if s == "" || strings.TrimSpace(s) != s || utf8.RuneCountInString(s) > maxCustomerRunes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
```

- [ ] **Step 6: Run the tests**

Run: `go test -race -count=1 ./internal/license/`
Expected: PASS. If a `TestParseRejectsMalformedFiles` case fails because its anchor text differs (for example the exact indentation in front of `"installation_id"`), print `string(encodeSigned(t, samplePayload(t)))` once and adjust only the anchor in the test, never the expected problem label.

- [ ] **Step 7: Add the archtest rule check and lint**

Run: `go test -count=1 ./internal/archtest/ && golangci-lint run ./internal/license/...`
Expected: PASS and no findings (the `license` rule already exists in `internal/archtest`).

- [ ] **Step 8: Commit**

```bash
git add internal/license/
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(license): license file format, installation IDs and canonical payload

Strict parser for license files (spec §16.2-§16.3): 64 KiB limit, one JSON
object, no duplicate keys or unknown fields, integer and RFC 3339 UTC checks,
newer formats reported separately. The payload is canonicalized with RFC 8785
and signed as \"ALICE-LICENSE-v1\\n\" || JCS(payload). Installation IDs use
Crockford base32 with a Luhn mod 32 check character.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 4: Key set, signature verification, build-tag key selection, test signer, fuzzing

Spec §16.3 steps 2–3, §16.7 (key IDs, active/revoked keys), §22.6 (test key only under `-tags testlicense`),
§25.6 (`FuzzParseLicense`) and the vendor key rule in Global Constraints. Release builds read the production
public keys from `internal/license/keys/production.json`, which stays `{"keys": []}` until the owner commits the
real public key (Task 22 owner steps). A release build therefore accepts no license until then (R36 item 1), and
`make release-keycheck` fails.

**Files:**
- Create: `internal/license/keys.go`, `internal/license/keys_release.go` (`//go:build !testlicense`), `internal/license/keys_testlicense.go` (`//go:build testlicense`), `internal/license/keys/production.json`
- Create: `internal/license/licensetest/licensetest.go`
- Test: `internal/license/keys_test.go`, `internal/license/keys_release_test.go` (`!testlicense`), `internal/license/keys_testlicense_test.go` (`testlicense`), `internal/license/keys_releasecheck_test.go` (`releasecheck`), `internal/license/fuzz_test.go`
- Modify: `Makefile` (`test`, `lint`, new `release-keycheck`, `fuzz-license`)

**Interfaces:**
- Consumes (Task 3): `File`, `Payload`, `ParseFile`, `SignedBytes`, `Sign`, `EncodeFile`, `invalid`, `keyIDPattern`, `ErrUnknownKey`, `ErrRevokedKey`, `ErrInvalid`.
- Produces (`alice/internal/license`):
  - `type KeyStatus string` with `KeyActive = "active"`, `KeyRevoked = "revoked"`.
  - `type PublicKey struct { ID string; Key ed25519.PublicKey; Status KeyStatus; RevokedFrom time.Time }` (for a revoked key, licenses with `issued_at >= RevokedFrom` are refused; zero = all).
  - `type KeySet struct{ … }`; `func NewKeySet(keys ...PublicKey) KeySet`; `func ParseKeySet(data []byte) (KeySet, error)`; `func EncodeKeySet(keys ...PublicKey) ([]byte, error)`; `func (k KeySet) Len() int`; `func (k KeySet) Keys() []PublicKey` (sorted by ID); `func Fingerprint(pub ed25519.PublicKey) string` (`"SHA256:" + hex`).
  - `func Verify(f File, keys KeySet) error` → `nil`, `ErrUnknownKey`, `*InvalidError{Problem: "signature"}`, `ErrRevokedKey`.
  - `func Check(raw []byte, keys KeySet) (File, error)` = ParseFile + Verify + `Payload.Validate` (everything except the installation check).
  - `func EmbeddedKeys() KeySet`; `const TestKeyTrusted bool` (false in release builds, true with `-tags testlicense`).
- Produces (`alice/internal/license/licensetest`): `const KeyID = "vk-test-01"`; `func PrivateKey() ed25519.PrivateKey`; `func PublicKey() ed25519.PublicKey`; `func KeySet() license.KeySet`; `func Payload(installationID string, validFrom, validUntil time.Time, maxTargets int) license.Payload` (license ID `LIC-TEST-000001`, customer `Test Company`, issued at `validFrom`); `func Sign(p license.Payload) []byte`; `func SignWith(priv ed25519.PrivateKey, keyID string, p license.Payload) []byte`.

- [ ] **Step 1: Write the failing verification tests**

Create `internal/license/keys_test.go`:

```go
package license_test

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

var (
	t0        = time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	otherKey  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	testInstallation = license.NewInstallationID()
)

func signedTestFile(t *testing.T) []byte {
	t.Helper()
	return licensetest.Sign(licensetest.Payload(testInstallation, t0, t0.AddDate(1, 0, 0), 10))
}

func TestCheckAcceptsAGenuineFile(t *testing.T) {
	f, err := license.Check(signedTestFile(t), licensetest.KeySet())
	require.NoError(t, err)
	assert.Equal(t, licensetest.KeyID, f.KeyID)
	assert.Equal(t, 10, f.Payload.MaxTargets)
	assert.Equal(t, testInstallation, f.Payload.InstallationID)
}

// L-40, L-41, L-42.
func TestCheckRejectsForgeries(t *testing.T) {
	raw := signedTestFile(t)
	f, err := license.ParseFile(raw)
	require.NoError(t, err)
	sig := strings.SplitN(strings.SplitN(string(raw), `"signature": "`, 2)[1], `"`, 2)[0]
	flipped := []byte(sig)
	if flipped[10] == 'A' {
		flipped[10] = 'B'
	} else {
		flipped[10] = 'A'
	}
	otherSigned := licensetest.SignWith(otherKey, licensetest.KeyID, f.Payload)

	for name, bad := range map[string][]byte{
		"payload byte changed (L-40)": replaceOnce(t, raw, `"max_targets": 10`, `"max_targets": 1000`),
		"customer changed":            replaceOnce(t, raw, `"Test Company"`, `"Test Companx"`),
		"signature byte changed":      replaceOnce(t, raw, sig, string(flipped)),
		"signed by another key (L-42)": otherSigned,
	} {
		_, err := license.Check(bad, licensetest.KeySet())
		var inv *license.InvalidError
		require.ErrorAs(t, err, &inv, name)
		assert.Equal(t, "signature", inv.Problem, name)
		assert.Equal(t, "invalid_signature", license.RejectReason(err), name)
	}

	unknown := licensetest.SignWith(otherKey, "vk-2099-01", f.Payload)
	_, err = license.Check(unknown, licensetest.KeySet())
	assert.ErrorIs(t, err, license.ErrUnknownKey, "a key ID the binary does not embed (§16.3 step 2)")
}

// Review Focus 3: every signed value is covered by the signature.
func TestVerifyRejectsAnyChangeToSignedValues(t *testing.T) {
	f, err := license.ParseFile(signedTestFile(t))
	require.NoError(t, err)
	require.NoError(t, license.Verify(f, licensetest.KeySet()))
	changes := map[string]func(p *license.Payload){
		"license_id":      func(p *license.Payload) { p.LicenseID += "0" },
		"customer":        func(p *license.Payload) { p.Customer += "." },
		"installation_id": func(p *license.Payload) { p.InstallationID = license.NewInstallationID() },
		"issued_at":       func(p *license.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Second) },
		"valid_from":      func(p *license.Payload) { p.ValidFrom = p.ValidFrom.Add(time.Second) },
		"valid_until":     func(p *license.Payload) { p.ValidUntil = p.ValidUntil.Add(time.Second) },
		"max_targets":     func(p *license.Payload) { p.MaxTargets++ },
		"features":        func(p *license.Payload) { p.Features = append(p.Features, "extra") },
		"replaces":        func(p *license.Payload) { p.Replaces = "LIC-OLD" },
	}
	for name, change := range changes {
		g := f
		g.Payload.Features = append([]string(nil), f.Payload.Features...)
		change(&g.Payload)
		err := license.Verify(g, licensetest.KeySet())
		assert.ErrorIs(t, err, license.ErrInvalid, name)
	}
}

func TestRevokedKeys(t *testing.T) {
	raw := signedTestFile(t) // issued_at = t0
	revoked := func(from time.Time) license.KeySet {
		return license.NewKeySet(license.PublicKey{ID: licensetest.KeyID, Key: licensetest.PublicKey(), Status: license.KeyRevoked, RevokedFrom: from})
	}
	_, err := license.Check(raw, revoked(time.Time{}))
	assert.ErrorIs(t, err, license.ErrRevokedKey, "revoked without a cutoff: nothing signed with it is trusted")
	_, err = license.Check(raw, revoked(t0))
	assert.ErrorIs(t, err, license.ErrRevokedKey, "issued at the cutoff")
	_, err = license.Check(raw, revoked(t0.Add(time.Second)))
	assert.NoError(t, err, "issued before the cutoff stays valid (§16.7)")
}

func TestKeySetFileRoundTripAndErrors(t *testing.T) {
	cut := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	raw, err := license.EncodeKeySet(
		license.PublicKey{ID: "vk-2026-01", Key: licensetest.PublicKey(), Status: license.KeyActive},
		license.PublicKey{ID: "vk-2025-01", Key: otherKey.Public().(ed25519.PublicKey), Status: license.KeyRevoked, RevokedFrom: cut},
	)
	require.NoError(t, err)
	ks, err := license.ParseKeySet(raw)
	require.NoError(t, err)
	require.Equal(t, 2, ks.Len())
	keys := ks.Keys()
	assert.Equal(t, "vk-2025-01", keys[0].ID, "sorted by ID")
	assert.Equal(t, license.KeyRevoked, keys[0].Status)
	assert.True(t, keys[0].RevokedFrom.Equal(cut))
	assert.Equal(t, licensetest.PublicKey(), keys[1].Key)
	assert.Regexp(t, `^SHA256:[0-9a-f]{64}$`, license.Fingerprint(keys[1].Key))

	empty, err := license.ParseKeySet([]byte(`{"keys": []}`))
	require.NoError(t, err)
	assert.Zero(t, empty.Len())

	good := `{"key_id":"vk-2026-01","public_key":"` + b64(licensetest.PublicKey()) + `","status":"active"}`
	for name, bad := range map[string]string{
		"not JSON":             `nope`,
		"missing keys":         `{}`,
		"unknown field":        `{"keys":[],"extra":1}`,
		"bad key id":           `{"keys":[{"key_id":"key1","public_key":"` + b64(licensetest.PublicKey()) + `","status":"active"}]}`,
		"short key":            `{"keys":[{"key_id":"vk-2026-01","public_key":"AAAA","status":"active"}]}`,
		"unknown status":       `{"keys":[{"key_id":"vk-2026-01","public_key":"` + b64(licensetest.PublicKey()) + `","status":"retired"}]}`,
		"duplicate id":         `{"keys":[` + good + `,` + good + `]}`,
		"cutoff on active key": `{"keys":[{"key_id":"vk-2026-01","public_key":"` + b64(licensetest.PublicKey()) + `","status":"active","revoked_from":"2027-01-01T00:00:00Z"}]}`,
	} {
		_, err := license.ParseKeySet([]byte(bad))
		assert.Error(t, err, name)
	}
}
```

Add at the end of `internal/license/keys_test.go`:

```go
func b64(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }
```

and add `"encoding/base64"` to its imports.

Create `internal/license/keys_release_test.go`:

```go
//go:build !testlicense

package license_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// Spec §22.6: a release build (no testlicense tag) never trusts the test signing key,
// so a test-signed license is refused by the binaries customers run.
func TestReleaseBuildDoesNotTrustTheTestKey(t *testing.T) {
	assert.False(t, license.TestKeyTrusted)
	ks := license.EmbeddedKeys()
	for _, k := range ks.Keys() {
		assert.NotEqual(t, licensetest.KeyID, k.ID)
		assert.NotEqual(t, licensetest.PublicKey(), k.Key)
	}
	_, err := license.Check(signedTestFile(t), ks)
	require.Error(t, err)
	assert.ErrorIs(t, err, license.ErrUnknownKey)
}
```

Create `internal/license/keys_testlicense_test.go`:

```go
//go:build testlicense

package license_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

// The test build (-tags testlicense) trusts the test key next to the production keys.
func TestTestBuildTrustsTheTestKey(t *testing.T) {
	assert.True(t, license.TestKeyTrusted)
	_, err := license.Check(signedTestFile(t), license.EmbeddedKeys())
	require.NoError(t, err)
}
```

Create `internal/license/keys_releasecheck_test.go`:

```go
//go:build releasecheck

package license_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// Release gate (make release-keycheck, R36 item 1): a customer build must embed at
// least one active vendor key and no test key. It fails until the owner commits the
// production public key to internal/license/keys/production.json.
func TestProductionKeySetIsReadyForRelease(t *testing.T) {
	require.False(t, license.TestKeyTrusted, "build without -tags testlicense")
	ks := license.EmbeddedKeys()
	require.Positive(t, ks.Len(), "internal/license/keys/production.json lists no key; see docs/vendor/licensing-vendor.md")
	active := 0
	for _, k := range ks.Keys() {
		assert.NotEqual(t, licensetest.PublicKey(), k.Key, "the test key must never be a production key")
		if k.Status == license.KeyActive {
			active++
		}
	}
	assert.Positive(t, active, "at least one key must be active")
}
```

Create `internal/license/fuzz_test.go`:

```go
package license_test

import (
	"fmt"
	"testing"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// FuzzParseLicense (spec §25.6): no input panics, and nothing verifies except a
// genuinely signed payload, however the JSON around it is formatted.
func FuzzParseLicense(f *testing.F) {
	keys := licensetest.KeySet()
	installation := license.NewInstallationID()
	signed := map[string]bool{}
	for i, targets := range []int{1, 10, license.MaxTargetsLimit} {
		p := licensetest.Payload(installation, t0, t0.AddDate(1, 0, 0), targets)
		p.LicenseID = fmt.Sprintf("LIC-FUZZ-%d", i)
		signed[string(license.CanonicalPayload(p))] = true
		f.Add(licensetest.Sign(p))
	}
	for _, seed := range []string{`{"format":1}`, `{"format":99,"x":1}`, `[[[[`, "\xef\xbb\xbf{}", `{"a":1,"a":2}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		file, err := license.Check(raw, keys)
		if err != nil {
			return
		}
		if canon := license.CanonicalPayload(file.Payload); !signed[string(canon)] {
			t.Fatalf("an unsigned payload verified: %s", canon)
		}
	})
}
```

Run: `go test -count=1 ./internal/license/...`
Expected: FAIL — `undefined: license.Check`, `license.KeySet`, … and `no required module provides package alice/internal/license/licensetest`.

- [ ] **Step 2: Implement key sets and verification**

Create `internal/license/keys.go`:

```go
package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// KeyStatus says whether licenses signed with a key are trusted (spec §16.7).
type KeyStatus string

// Key statuses. Retired keys are simply not embedded any more.
const (
	KeyActive  KeyStatus = "active"
	KeyRevoked KeyStatus = "revoked"
)

// PublicKey is one vendor license verification key.
type PublicKey struct {
	ID     string
	Key    ed25519.PublicKey
	Status KeyStatus
	// RevokedFrom, for a revoked key, is the first issued_at that is no longer trusted
	// (licenses issued before it stay valid). Zero means nothing signed with it is trusted.
	RevokedFrom time.Time
}

// KeySet is the set of keys a binary trusts, by key ID.
type KeySet struct{ keys map[string]PublicKey }

// NewKeySet builds a key set (a later key with the same ID replaces an earlier one).
func NewKeySet(keys ...PublicKey) KeySet {
	ks := KeySet{keys: make(map[string]PublicKey, len(keys))}
	for _, k := range keys {
		ks.keys[k.ID] = k
	}
	return ks
}

// Len returns the number of keys.
func (k KeySet) Len() int { return len(k.keys) }

// Keys returns the keys sorted by ID.
func (k KeySet) Keys() []PublicKey {
	out := make([]PublicKey, 0, len(k.keys))
	for _, pk := range k.keys {
		out = append(out, pk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Fingerprint identifies a public key for people: "SHA256:" and 64 hex digits. The
// release process compares it with the vendor's recorded fingerprint (spec §19.2).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

type keySetFile struct {
	Keys []keyEntry `json:"keys"`
}

type keyEntry struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"` // standard base64 of the 32-byte Ed25519 key
	Status      string `json:"status"`
	RevokedFrom string `json:"revoked_from,omitempty"`
}

// ParseKeySet reads the embedded key set file {"keys": [...]}.
func ParseKeySet(data []byte) (KeySet, error) {
	var f keySetFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return KeySet{}, fmt.Errorf("license: key set: %w", err)
	}
	if f.Keys == nil {
		return KeySet{}, errors.New("license: key set: the keys list is missing")
	}
	ks := KeySet{keys: make(map[string]PublicKey, len(f.Keys))}
	for _, e := range f.Keys {
		if !keyIDPattern.MatchString(e.KeyID) {
			return KeySet{}, fmt.Errorf("license: key set: key ID %q is not valid", e.KeyID)
		}
		if _, dup := ks.keys[e.KeyID]; dup {
			return KeySet{}, fmt.Errorf("license: key set: key ID %q appears twice", e.KeyID)
		}
		raw, err := base64.StdEncoding.DecodeString(e.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return KeySet{}, fmt.Errorf("license: key set: key %q is not a base64 Ed25519 public key", e.KeyID)
		}
		k := PublicKey{ID: e.KeyID, Key: ed25519.PublicKey(raw), Status: KeyStatus(e.Status)}
		switch k.Status {
		case KeyActive:
			if e.RevokedFrom != "" {
				return KeySet{}, fmt.Errorf("license: key set: active key %q has revoked_from", e.KeyID)
			}
		case KeyRevoked:
			if e.RevokedFrom != "" {
				t, err := time.Parse(time.RFC3339, e.RevokedFrom)
				if err != nil {
					return KeySet{}, fmt.Errorf("license: key set: revoked_from of %q is not RFC 3339", e.KeyID)
				}
				k.RevokedFrom = t.UTC()
			}
		default:
			return KeySet{}, fmt.Errorf("license: key set: key %q has unknown status %q", e.KeyID, e.Status)
		}
		ks.keys[k.ID] = k
	}
	return ks, nil
}

// EncodeKeySet renders keys in the key set file format (used by licensectl keyset).
func EncodeKeySet(keys ...PublicKey) ([]byte, error) {
	f := keySetFile{Keys: []keyEntry{}}
	for _, k := range NewKeySet(keys...).Keys() {
		e := keyEntry{KeyID: k.ID, PublicKey: base64.StdEncoding.EncodeToString(k.Key), Status: string(k.Status)}
		if k.Status == KeyRevoked && !k.RevokedFrom.IsZero() {
			e.RevokedFrom = formatTime(k.RevokedFrom)
		}
		f.Keys = append(f.Keys, e)
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Verify checks the signature of f against keys (spec §16.3 steps 2-3): an unknown key ID
// is ErrUnknownKey, a wrong signature an *InvalidError with Problem "signature", and a
// license from a revoked key (issued at or after its cutoff) ErrRevokedKey.
func Verify(f File, keys KeySet) error {
	pk, ok := keys.keys[f.KeyID]
	if !ok {
		return ErrUnknownKey
	}
	if !ed25519.Verify(pk.Key, SignedBytes(f.Payload), f.Signature) {
		return invalid("signature")
	}
	if pk.Status == KeyRevoked && (pk.RevokedFrom.IsZero() || !f.Payload.IssuedAt.Before(pk.RevokedFrom)) {
		return ErrRevokedKey
	}
	return nil
}

// Check parses raw, verifies its signature and validates the payload: spec §16.3 steps
// 1, 2, 3 and 5. Step 4 (the installation ID) is checked by Service, which knows it.
func Check(raw []byte, keys KeySet) (File, error) {
	f, err := ParseFile(raw)
	if err != nil {
		return File{}, err
	}
	if err := Verify(f, keys); err != nil {
		return File{}, err
	}
	if err := f.Payload.Validate(); err != nil {
		return File{}, err
	}
	return f, nil
}
```

- [ ] **Step 3: Select the embedded keys by build tag**

Create `internal/license/keys/production.json`:

```json
{
  "keys": []
}
```

Create `internal/license/keys_release.go`:

```go
//go:build !testlicense

package license

import _ "embed"

//go:embed keys/production.json
var productionKeySet []byte

// TestKeyTrusted is false in release builds: only the vendor's production keys are trusted.
const TestKeyTrusted = false

// EmbeddedKeys returns the vendor's license verification keys compiled into this binary
// (spec §16.7, §19.2). The owner commits them to keys/production.json; while the file
// lists no key, no license verifies (R36 item 1) and make release-keycheck fails.
func EmbeddedKeys() KeySet {
	ks, err := ParseKeySet(productionKeySet)
	if err != nil {
		panic("license: keys/production.json is not a valid key set: " + err.Error())
	}
	return ks
}
```

Create `internal/license/keys_testlicense.go`:

```go
//go:build testlicense

package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
)

//go:embed keys/production.json
var productionKeySet []byte

// TestKeyTrusted is true only in test builds (-tags testlicense, spec §22.6).
const TestKeyTrusted = true

// The test key is derived from a public label; licensetest holds the same derivation.
// It is not a secret, which is exactly why release builds must never trust it.
const (
	testKeyLabel = "alice test license signing key v1"
	testKeyID    = "vk-test-01"
)

// EmbeddedKeys returns the production keys plus the test key.
func EmbeddedKeys() KeySet {
	ks, err := ParseKeySet(productionKeySet)
	if err != nil {
		panic("license: keys/production.json is not a valid key set: " + err.Error())
	}
	seed := sha256.Sum256([]byte(testKeyLabel))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	ks.keys[testKeyID] = PublicKey{ID: testKeyID, Key: pub, Status: KeyActive}
	return ks
}
```

- [ ] **Step 4: Add the test signer**

Create `internal/license/licensetest/licensetest.go`:

```go
// Package licensetest signs license files with a fixed, publicly derivable test key,
// for tests and the e2e build (spec §22.6). Release code never imports it: a test in
// cmd/alice checks that the alice binary does not link it, and release builds do not
// trust its key.
package licensetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"alice/internal/license"
)

// KeyID is the key ID of the test signing key.
const KeyID = "vk-test-01"

// seedLabel must equal testKeyLabel in internal/license/keys_testlicense.go.
const seedLabel = "alice test license signing key v1"

// PrivateKey returns the test signing key.
func PrivateKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(seedLabel))
	return ed25519.NewKeyFromSeed(seed[:])
}

// PublicKey returns the public half of the test key.
func PublicKey() ed25519.PublicKey { return PrivateKey().Public().(ed25519.PublicKey) }

// KeySet returns a key set that trusts only the test key.
func KeySet() license.KeySet {
	return license.NewKeySet(license.PublicKey{ID: KeyID, Key: PublicKey(), Status: license.KeyActive})
}

// Payload returns a valid payload: license LIC-TEST-000001 for "Test Company", issued at validFrom.
func Payload(installationID string, validFrom, validUntil time.Time, maxTargets int) license.Payload {
	from := validFrom.UTC().Truncate(time.Second)
	return license.Payload{
		LicenseID:      "LIC-TEST-000001",
		Customer:       "Test Company",
		InstallationID: installationID,
		IssuedAt:       from,
		ValidFrom:      from,
		ValidUntil:     validUntil.UTC().Truncate(time.Second),
		MaxTargets:     maxTargets,
		Features:       []string{},
		Format:         license.FormatVersion,
	}
}

// Sign signs p with the test key and returns the file bytes. It panics on an invalid payload.
func Sign(p license.Payload) []byte { return SignWith(PrivateKey(), KeyID, p) }

// SignWith signs p with any key (tests of foreign or unknown keys).
func SignWith(priv ed25519.PrivateKey, keyID string, p license.Payload) []byte {
	f, err := license.Sign(priv, keyID, p)
	if err != nil {
		panic("licensetest: " + err.Error())
	}
	raw, err := license.EncodeFile(f)
	if err != nil {
		panic("licensetest: " + err.Error())
	}
	return raw
}
```

- [ ] **Step 5: Run the tests in all three key modes**

Run:
```bash
go test -race -count=1 ./internal/license/...
go test -race -count=1 -tags testlicense ./internal/license/...
go test -count=1 -run '^$' -fuzz FuzzParseLicense -fuzztime 20s ./internal/license/
go test -count=1 -tags releasecheck -run TestProductionKeySetIsReadyForRelease ./internal/license/
```
Expected: the first three PASS; the last FAILS with "internal/license/keys/production.json lists no key" — that is the intended release gate until the owner commits the production key (R36 item 1).

- [ ] **Step 6: Wire the modes into `make`**

In `Makefile`:

1. In the `test` target, after `go test -race -count=1 ./...` add the line
   `	go test -race -count=1 -tags testlicense ./internal/license/...`
2. In the `lint` target add the line
   `	golangci-lint run --build-tags testlicense ./internal/license/...`
3. Append:

```make
.PHONY: fuzz-license
fuzz-license: ## Fuzz the license parser for 60 s (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseLicense -fuzztime 60s ./internal/license/

.PHONY: release-keycheck
release-keycheck: ## Release gate: fails until the vendor's production license key is committed (R36)
	go test -count=1 -tags releasecheck -run TestProductionKeySetIsReadyForRelease ./internal/license/
```

Run: `make test lint`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/license/ Makefile
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(license): embedded key set, signature verification and test signer

Release builds trust only internal/license/keys/production.json, which stays
empty until the owner commits the vendor's public key; until then no license
verifies and make release-keycheck fails (fail closed). The test signing key
is trusted only with -tags testlicense. Revoked keys honour an optional
issued_at cutoff. FuzzParseLicense proves only signed payloads verify.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 5: License state machine (`Evaluate`) and lock classes

The pure heart of spec §23: given the effective time, the installation timestamp and the verified uploads,
`Evaluate` returns the phase, the effective and pending license, the warning threshold, the grace day and the
target limit. The gate classes used by the API and the scheduler are defined here too.

**Files:**
- Create: `internal/license/class.go`, `internal/license/state.go`
- Test: `internal/license/state_test.go`

**Interfaces:**
- Consumes (Task 3): `Payload`.
- Produces (`alice/internal/license`):
  - `type Class int` with `ClassUnset`, `ClassAlways`, `ClassReadOnly`, `ClassChange`; `func (c Class) Valid() bool`; `func (c Class) String() string` (`"unset"`, `"always"`, `"read_only"`, `"change"`).
  - `type Phase string` with `PhaseEvaluation = "evaluation"`, `PhaseEvaluationExpired = "evaluation_expired"`, `PhaseActive = "active"`, `PhaseGrace = "grace"`, `PhaseLocked = "locked"`.
  - Constants `EvaluationPeriod = 30*24h`, `EvaluationMaxTargets = 5`, `GracePeriod = 168h`; vars `ExpiryWarningDays = []int{60, 30, 14, 7, 1}`, `EvaluationWarningDays = []int{7, 3, 1}`.
  - `type Installed struct { Seq int64; KeyID string; Payload Payload }`.
  - `type Evaluation struct { Phase Phase; Current, Pending *Payload; CurrentSeq, PendingSeq int64; EndsAt, LocksAt time.Time; DaysLeft, Threshold, GraceDay, MaxTargets int }` (`CurrentSeq`/`PendingSeq` are the upload sequence numbers, 0 = none).
  - `func Evaluate(now, installedAt time.Time, installed []Installed) Evaluation`.
  - Methods: `Locked() bool` (locked or evaluation expired), `Expired() bool` (grace, locked, evaluation expired), `Key() string` (`"evaluation"` or the current license ID; the notice de-duplication key), `CanAdd(targets int) bool`, `OverLimit(targets int) bool`.

- [ ] **Step 1: Write the failing state tests**

Create `internal/license/state_test.go`:

```go
package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

const day = 24 * time.Hour

var (
	installedAt = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC) // T0
	expiry      = time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC) // E
)

// lic returns a verified upload valid from E-365d until E (baseline of §23.1: max_targets 10).
func lic(seq int64, id string, from, until time.Time, targets int) license.Installed {
	p := licensetest.Payload(testInstallation, from, until, targets)
	p.LicenseID = id
	return license.Installed{Seq: seq, KeyID: licensetest.KeyID, Payload: p}
}

func baseline() []license.Installed {
	return []license.Installed{lic(1, "LIC-A", expiry.Add(-365*day), expiry, 10)}
}

// §23.2 Evaluation mode.
func TestEvaluationMode(t *testing.T) {
	e := license.Evaluate(installedAt, installedAt, nil) // L-01
	assert.Equal(t, license.PhaseEvaluation, e.Phase)
	assert.Nil(t, e.Current)
	assert.Equal(t, 30, e.DaysLeft)
	assert.Equal(t, 5, e.MaxTargets)
	assert.True(t, e.EndsAt.Equal(installedAt.Add(30*day)))
	assert.True(t, e.LocksAt.Equal(e.EndsAt), "evaluation ends directly in lock (R1)")
	assert.Zero(t, e.Threshold)
	assert.Equal(t, "evaluation", e.Key())
	assert.False(t, e.Locked())
	assert.False(t, e.Expired())

	e = license.Evaluate(installedAt.Add(29*day+23*time.Hour+59*time.Minute), installedAt, nil) // L-02
	assert.Equal(t, license.PhaseEvaluation, e.Phase)
	assert.Equal(t, 1, e.DaysLeft)

	e = license.Evaluate(installedAt.Add(30*day), installedAt, nil) // L-03
	assert.Equal(t, license.PhaseEvaluationExpired, e.Phase)
	assert.True(t, e.Locked(), "evaluation expired behaves as lock")
	assert.True(t, e.Expired())
	assert.Zero(t, e.DaysLeft)
	assert.Zero(t, e.GraceDay, "no grace for the evaluation")
}

// L-07: administrators are warned 7, 3 and 1 days before the evaluation ends.
func TestEvaluationWarnings(t *testing.T) {
	for offset, want := range map[time.Duration]int{
		22*day + 23*time.Hour: 0,
		23 * day:              7,
		26 * day:              7,
		27 * day:              3,
		29 * day:              1,
		30*day - time.Second:  1,
	} {
		assert.Equal(t, want, license.Evaluate(installedAt.Add(offset), installedAt, nil).Threshold, offset.String())
	}
}

// L-05: a license ends the evaluation at once; L-06: the installation timestamp decides.
func TestLicenseEndsEvaluation(t *testing.T) {
	now := installedAt.Add(3 * day)
	e := license.Evaluate(now, installedAt, []license.Installed{lic(1, "LIC-A", now, now.Add(365*day), 10)})
	assert.Equal(t, license.PhaseActive, e.Phase)
	require.NotNil(t, e.Current)
	assert.Equal(t, "LIC-A", e.Key())
	assert.Equal(t, 10, e.MaxTargets)

	restored := license.Evaluate(installedAt.Add(40*day), installedAt, nil) // restore keeps installed_at (L-06)
	assert.Equal(t, license.PhaseEvaluationExpired, restored.Phase)
}

// §23.3 Warning thresholds (L-10, L-11, L-13).
func TestExpiryWarningThresholds(t *testing.T) {
	cases := []struct {
		at        time.Time
		threshold int
		daysLeft  int
	}{
		{expiry.Add(-61*day - 12*time.Hour), 0, 62}, // L-10
		{expiry.Add(-60 * day), 60, 60},             // L-11
		{expiry.Add(-31 * day), 60, 31},             // L-12: still the 60-day banner
		{expiry.Add(-30 * day), 30, 30},             // L-13
		{expiry.Add(-14 * day), 14, 14},
		{expiry.Add(-7 * day), 7, 7},
		{expiry.Add(-1 * day), 1, 1},
		{expiry.Add(-time.Second), 1, 1},
	}
	for _, tc := range cases {
		e := license.Evaluate(tc.at, installedAt, baseline())
		assert.Equal(t, license.PhaseActive, e.Phase, tc.at.String())
		assert.Equal(t, tc.threshold, e.Threshold, tc.at.String())
		assert.Equal(t, tc.daysLeft, e.DaysLeft, tc.at.String())
	}
}

// §23.4 Expiry, grace and lock (L-20..L-24), instant-based (R25).
func TestGraceAndLock(t *testing.T) {
	e := license.Evaluate(expiry, installedAt, baseline()) // L-20
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, 1, e.GraceDay)
	assert.True(t, e.Expired())
	assert.False(t, e.Locked(), "grace: everything works")
	assert.True(t, e.LocksAt.Equal(expiry.Add(168*time.Hour)))

	assert.Equal(t, 1, license.Evaluate(expiry.Add(23*time.Hour+59*time.Minute+59*time.Second), installedAt, baseline()).GraceDay) // L-21
	for n := 1; n <= 7; n++ { // L-22
		e := license.Evaluate(expiry.Add(time.Duration(n-1)*day), installedAt, baseline())
		assert.Equal(t, license.PhaseGrace, e.Phase, n)
		assert.Equal(t, n, e.GraceDay, n)
	}
	e = license.Evaluate(expiry.Add(167*time.Hour+59*time.Minute+59*time.Second), installedAt, baseline()) // L-23
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, 7, e.GraceDay)

	e = license.Evaluate(expiry.Add(168*time.Hour), installedAt, baseline()) // L-24
	assert.Equal(t, license.PhaseLocked, e.Phase)
	assert.True(t, e.Locked())
	assert.Zero(t, e.GraceDay)
}

// L-17, L-30, L-31: a renewal takes effect immediately and restarts the warnings.
func TestRenewal(t *testing.T) {
	renewed := append(baseline(), lic(2, "LIC-B", expiry.Add(-20*day), expiry.Add(345*day), 10))
	e := license.Evaluate(expiry.Add(-14*day), installedAt, renewed)
	assert.Equal(t, "LIC-B", e.Key())
	assert.Zero(t, e.Threshold, "no 14-day warning of the old license (L-17)")

	inGrace := append(baseline(), lic(2, "LIC-B", expiry.Add(3*day), expiry.Add(368*day), 10))
	assert.Equal(t, license.PhaseActive, license.Evaluate(expiry.Add(3*day), installedAt, inGrace).Phase) // L-31
	inLock := append(baseline(), lic(2, "LIC-B", expiry.Add(20*day), expiry.Add(385*day), 10))
	assert.Equal(t, license.PhaseActive, license.Evaluate(expiry.Add(20*day), installedAt, inLock).Phase) // L-30
}

// L-32: an already expired renewal is accepted; its own dates decide.
func TestAlreadyExpiredRenewal(t *testing.T) {
	now := expiry.Add(30 * day) // locked under LIC-A
	recent := append(baseline(), lic(2, "LIC-B", now.Add(-200*day), now.Add(-100*time.Hour), 10))
	e := license.Evaluate(now, installedAt, recent)
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, "LIC-B", e.Key())
	old := append(baseline(), lic(2, "LIC-B", now.Add(-400*day), now.Add(-168*time.Hour), 10))
	assert.Equal(t, license.PhaseLocked, license.Evaluate(now, installedAt, old).Phase)
}

// L-48: a license that starts later is pending; the previous license (or evaluation) continues.
func TestPendingLicense(t *testing.T) {
	now := expiry.Add(-10 * day)
	uploads := append(baseline(), lic(2, "LIC-B", now.Add(2*day), now.Add(367*day), 20))
	e := license.Evaluate(now, installedAt, uploads)
	assert.Equal(t, "LIC-A", e.Key())
	require.NotNil(t, e.Pending)
	assert.Equal(t, "LIC-B", e.Pending.LicenseID)
	assert.Equal(t, int64(2), e.PendingSeq)
	assert.Equal(t, int64(1), e.CurrentSeq)
	assert.Equal(t, 10, e.MaxTargets)

	e = license.Evaluate(now.Add(2*day), installedAt, uploads)
	assert.Equal(t, "LIC-B", e.Key())
	assert.Nil(t, e.Pending)
	assert.Equal(t, 20, e.MaxTargets)

	evalOnly := []license.Installed{lic(1, "LIC-B", installedAt.Add(5*day), installedAt.Add(370*day), 20)}
	e = license.Evaluate(installedAt.Add(time.Hour), installedAt, evalOnly)
	assert.Equal(t, license.PhaseEvaluation, e.Phase)
	require.NotNil(t, e.Pending)
}

// The newest upload that has started wins, even a correction license with earlier dates (L-61).
func TestNewestStartedUploadWins(t *testing.T) {
	correction := lic(2, "LIC-C", expiry.Add(-400*day), expiry.Add(30*day), 10)
	correction.Payload.Replaces = "LIC-A"
	e := license.Evaluate(expiry.Add(5*day), installedAt, append(baseline(), correction))
	assert.Equal(t, license.PhaseActive, e.Phase)
	assert.Equal(t, "LIC-C", e.Key())

	shorter := lic(2, "LIC-D", expiry.Add(-100*day), expiry.Add(-50*day), 10)
	e = license.Evaluate(expiry.Add(-60*day), installedAt, append(baseline(), shorter))
	assert.Equal(t, "LIC-D", e.Key(), "the vendor's latest file is authoritative, also when it is shorter")

	// Upload order, not slice order, decides.
	e = license.Evaluate(expiry.Add(5*day), installedAt, []license.Installed{correction, baseline()[0]})
	assert.Equal(t, "LIC-C", e.Key())
}

// §23.7 target limit (pure part): L-70, L-71, L-73, L-75..L-78, L-04.
func TestTargetLimit(t *testing.T) {
	active := license.Evaluate(expiry.Add(-100*day), installedAt, baseline())
	assert.True(t, active.CanAdd(9))   // L-70
	assert.False(t, active.CanAdd(10)) // L-71
	assert.False(t, active.OverLimit(10))
	assert.True(t, active.OverLimit(12), "L-75: 12 of 10 after a smaller renewal")
	assert.Equal(t, license.PhaseActive, active.Phase, "exceeding the limit never locks")

	eval := license.Evaluate(installedAt, installedAt, nil)
	assert.True(t, eval.CanAdd(4))
	assert.False(t, eval.CanAdd(5), "L-04: the evaluation allows 5 targets")

	small := license.Evaluate(installedAt.Add(time.Hour), installedAt, []license.Installed{lic(1, "LIC-S", installedAt, installedAt.Add(365*day), 3)})
	assert.True(t, small.OverLimit(5), "L-78")

	locked := license.Evaluate(expiry.Add(200*day), installedAt, baseline())
	assert.False(t, locked.CanAdd(0), "nothing is added while locked")
}

func TestClasses(t *testing.T) {
	assert.False(t, license.ClassUnset.Valid())
	for _, c := range []license.Class{license.ClassAlways, license.ClassReadOnly, license.ClassChange} {
		assert.True(t, c.Valid(), c.String())
	}
	assert.False(t, license.Class(9).Valid())
	assert.Equal(t, "read_only", license.ClassReadOnly.String())
}
```

Run: `go test -count=1 ./internal/license/`
Expected: FAIL — `undefined: license.Evaluate`, `license.Installed`, `license.ClassUnset`, ….

- [ ] **Step 2: Implement the classes**

Create `internal/license/class.go`:

```go
package license

// Class says how lock mode treats a piece of work (spec §8.6, R9, R29). Every job type
// and every state-changing API route declares one; the zero value is refused by the
// gate (fail closed) and by tests of the route table and the job registry (X-01).
type Class int

// License classes.
const (
	ClassUnset Class = iota
	// ClassAlways runs in every state: sign-in, license upload, backup, audit, notifications
	// and the license evaluation itself.
	ClassAlways
	// ClassReadOnly is recurring read-only work on managed systems (discovery, Key Vault
	// polling): paused while locked, resumed automatically after a renewal (R29).
	ClassReadOnly
	// ClassChange changes managed systems or the managed inventory (deploy, add or remove a
	// key, import, add a target): refused while locked; after a renewal, work that was
	// paused needs an Admin's confirmation (R29).
	ClassChange
)

// Valid reports whether c is one of the three real classes.
func (c Class) Valid() bool { return c >= ClassAlways && c <= ClassChange }

func (c Class) String() string {
	switch c {
	case ClassAlways:
		return "always"
	case ClassReadOnly:
		return "read_only"
	case ClassChange:
		return "change"
	default:
		return "unset"
	}
}
```

- [ ] **Step 3: Implement `Evaluate`**

Create `internal/license/state.go`:

```go
package license

import (
	"sort"
	"time"
)

// Phase is the license state (spec §7.6, R25, R1).
type Phase string

// Phases. The evaluation has no grace period: it ends directly in PhaseEvaluationExpired,
// which behaves as lock.
const (
	PhaseEvaluation        Phase = "evaluation"
	PhaseEvaluationExpired Phase = "evaluation_expired"
	PhaseActive            Phase = "active"
	PhaseGrace             Phase = "grace"
	PhaseLocked            Phase = "locked"
)

// Rules of spec §16.3 step 6, §19.3, R1, R25, R27.
const (
	EvaluationPeriod     = 30 * 24 * time.Hour
	EvaluationMaxTargets = 5
	GracePeriod          = 168 * time.Hour
	day                  = 24 * time.Hour
)

// Warning thresholds in days before the end, largest first.
var (
	ExpiryWarningDays     = []int{60, 30, 14, 7, 1}
	EvaluationWarningDays = []int{7, 3, 1}
)

// Installed is a stored license file that verified: its upload order and payload.
type Installed struct {
	Seq     int64
	KeyID   string
	Payload Payload
}

// Evaluation is the license state at one instant.
type Evaluation struct {
	Phase      Phase
	Current    *Payload  // the license in force; nil during the evaluation
	Pending    *Payload  // the newest uploaded license whose valid_from is still ahead (L-48)
	CurrentSeq int64     // upload sequence number of Current; 0 = none
	PendingSeq int64     // upload sequence number of Pending; 0 = none
	EndsAt     time.Time // end of the evaluation, or valid_until
	LocksAt    time.Time // start of lock: EndsAt for the evaluation, valid_until + 168 h otherwise
	DaysLeft   int       // whole days until EndsAt, rounded up; 0 once EndsAt is reached
	Threshold  int       // warning threshold reached (60/30/14/7/1, evaluation 7/3/1); 0 = none
	GraceDay   int       // 1..7 during grace: the n-th 24-hour period after valid_until (L-22)
	MaxTargets int       // 5 during the evaluation, otherwise max_targets of Current
}

// Evaluate computes the license state at now (the trusted, effective time) from the
// installation timestamp and the verified uploads. The newest upload whose valid_from
// has started is in force, even when it is shorter or is a correction with earlier dates:
// the vendor's latest file is authoritative. Newer uploads that have not started yet are
// pending; the previous license, or the evaluation, continues meanwhile (L-48).
func Evaluate(now, installedAt time.Time, installed []Installed) Evaluation {
	now = now.UTC()
	sorted := append([]Installed(nil), installed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Seq > sorted[j].Seq })
	var current, pending *Payload
	var currentSeq, pendingSeq int64
	for i := range sorted {
		p := sorted[i].Payload
		if p.ValidFrom.After(now) {
			if pending == nil {
				pending, pendingSeq = &p, sorted[i].Seq
			}
			continue
		}
		current, currentSeq = &p, sorted[i].Seq
		break
	}

	if current == nil {
		end := installedAt.UTC().Add(EvaluationPeriod)
		e := Evaluation{Pending: pending, PendingSeq: pendingSeq, EndsAt: end, LocksAt: end, MaxTargets: EvaluationMaxTargets}
		if now.Before(end) {
			e.Phase = PhaseEvaluation
			e.DaysLeft = daysLeft(end.Sub(now))
			e.Threshold = threshold(end.Sub(now), EvaluationWarningDays)
		} else {
			e.Phase = PhaseEvaluationExpired
		}
		return e
	}

	e := Evaluation{
		Current:    current,
		Pending:    pending,
		CurrentSeq: currentSeq,
		PendingSeq: pendingSeq,
		EndsAt:     current.ValidUntil,
		LocksAt:    current.ValidUntil.Add(GracePeriod),
		MaxTargets: current.MaxTargets,
	}
	switch {
	case now.Before(current.ValidUntil):
		e.Phase = PhaseActive
		e.DaysLeft = daysLeft(current.ValidUntil.Sub(now))
		e.Threshold = threshold(current.ValidUntil.Sub(now), ExpiryWarningDays)
	case now.Before(e.LocksAt):
		e.Phase = PhaseGrace
		e.GraceDay = int(now.Sub(current.ValidUntil)/day) + 1
	default:
		e.Phase = PhaseLocked
	}
	return e
}

// daysLeft rounds a positive duration up to whole days.
func daysLeft(remaining time.Duration) int {
	if remaining <= 0 {
		return 0
	}
	return int((remaining + day - 1) / day)
}

// threshold returns the smallest warning threshold (in days) that remaining has reached.
func threshold(remaining time.Duration, days []int) int {
	t := 0
	for _, d := range days {
		if remaining <= time.Duration(d)*day {
			t = d
		}
	}
	return t
}

// Locked reports lock behaviour: locked, or the evaluation has ended (R1).
func (e Evaluation) Locked() bool { return e.Phase == PhaseLocked || e.Phase == PhaseEvaluationExpired }

// Expired reports whether the license or evaluation has ended (grace included).
func (e Evaluation) Expired() bool { return e.Phase != PhaseEvaluation && e.Phase != PhaseActive }

// Key identifies the license in force for notice de-duplication: "evaluation" or its license ID.
// A renewal therefore restarts the warnings (L-17).
func (e Evaluation) Key() string {
	if e.Current == nil {
		return "evaluation"
	}
	return e.Current.LicenseID
}

// CanAdd reports whether one more target may be added (L-70, L-71; never while locked).
func (e Evaluation) CanAdd(targets int) bool { return !e.Locked() && targets < e.MaxTargets }

// OverLimit reports more targets than licensed, for example after a smaller renewal (R30).
func (e Evaluation) OverLimit(targets int) bool { return targets > e.MaxTargets }
```

- [ ] **Step 4: Run the tests**

Run: `go test -race -count=1 ./internal/license/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/license/class.go internal/license/state.go internal/license/state_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(license): instant-based state machine and lock classes

Evaluate computes evaluation, active, grace (day 1-7) and lock from UTC
instants (R25), the 60/30/14/7/1 and 7/3/1 day thresholds, pending licenses
(L-48) and the target limit (5 in evaluation). The newest started upload is
in force. License classes (always, read-only, change) tag jobs and routes for
the single lock gate.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 6: Clock guard — MAC'd high-water mark, rollback clamp, forward-jump hold

Spec §16.5, R17, R26, R28 and §23.6: the trusted time never goes backwards, a rolled-back clock never extends a
license, and a suspicious forward jump only counts after 24 hours of uptime. The HWM record is encrypted with a
sub-key and MAC'd with `HKDF(master, "alice/hwm/v1")`; it is stored in `settings` and in a file (both stores
are written by `Service` in Tasks 8–9). This task holds the pure guard, the record codec and the two stores.

**Files:**
- Modify: `internal/secrets/envelope.go` (label `LabelHWMEnc`, `SealWith`, `OpenWith`)
- Test: `internal/secrets/subkey_test.go`
- Create: `internal/license/hwm.go`, `internal/license/timeguard.go`
- Test: `internal/license/hwm_test.go`, `internal/license/timeguard_test.go`

**Interfaces:**
- Consumes: `secrets.Keyring` (`Derive`, unexported `seal`/`open`), `settings.Get/Set`, `db.Querier`, `clock.Clock`; Task 5 `Evaluate`.
- Produces (`alice/internal/secrets`): `const LabelHWMEnc = "alice/hwm-enc/v1"`; `func (k *Keyring) SealWith(label string, aad, plaintext []byte) ([]byte, error)` (nonce ‖ ciphertext under `HKDF(master, label)`); `func (k *Keyring) OpenWith(label string, aad, sealed []byte) ([]byte, error)` (`ErrDecrypt` on any mismatch).
- Produces (`alice/internal/license`):
  - `type HWMRecord struct { At time.Time; Seq uint64 }`; `var ErrHWMInvalid`; `type HWMCodec`; `func NewHWMCodec(k *secrets.Keyring) HWMCodec`; `func (c HWMCodec) Encode(r HWMRecord) ([]byte, error)`; `func (c HWMCodec) Decode(raw []byte) (HWMRecord, error)`.
  - `type HWMStore interface { Name() string; Load(ctx context.Context) ([]byte, error); Save(ctx context.Context, record []byte) error }` (`Load` returns `nil, nil` when there is no record); `const HWMSettingKey = "time.hwm"`; `const HWMFileName = "hwm.dat"`; `type SettingsHWMStore struct { Q db.Querier; Clock clock.Clock }`; `type FileHWMStore struct { Path string }`.
  - Constants `RollbackTolerance = 65*time.Minute`, `JumpThreshold = 48*time.Hour`, `JumpSettle = 24*time.Hour`.
  - `type Reading struct { Wall, Trusted, Effective time.Time; Behind bool; Jump *Jump }`; `type Jump struct { Expected, Detected time.Time; By time.Duration }`.
  - `type ClockEvent int` with `EventRollback`, `EventJumpDetected`, `EventJumpAccepted`, `EventJumpCleared`.
  - `type Guard struct{ … }` (not goroutine-safe; `Service` holds a mutex): `SetHWM(r HWMRecord)`, `HWM() HWMRecord`, `NextRecord() HWMRecord` (increments the sequence), `Observe(wall time.Time, uptime time.Duration) (Reading, []ClockEvent)`, `AcceptJump() bool`, `RestoreJump(expected, detected time.Time, uptime time.Duration)`, `PendingJump() (expected, detected time.Time, ok bool)`.

- [ ] **Step 1: Write the failing sub-key tests**

Create `internal/secrets/subkey_test.go`:

```go
package secrets_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
)

func TestSealWithSubkeyRoundTripAndBinding(t *testing.T) {
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	other, err := secrets.NewKeyring(1, bytes.Repeat([]byte{2}, 32))
	require.NoError(t, err)
	aad := []byte("alice/hwm-record/v1")

	sealed, err := k.SealWith(secrets.LabelHWMEnc, aad, []byte("sixteen bytes!!!"))
	require.NoError(t, err)
	again, err := k.SealWith(secrets.LabelHWMEnc, aad, []byte("sixteen bytes!!!"))
	require.NoError(t, err)
	assert.NotEqual(t, sealed, again, "random nonce per seal")

	pt, err := k.OpenWith(secrets.LabelHWMEnc, aad, sealed)
	require.NoError(t, err)
	assert.Equal(t, "sixteen bytes!!!", string(pt))

	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	for name, open := range map[string]func() ([]byte, error){
		"other label":  func() ([]byte, error) { return k.OpenWith(secrets.LabelHWM, aad, sealed) },
		"other aad":    func() ([]byte, error) { return k.OpenWith(secrets.LabelHWMEnc, []byte("x"), sealed) },
		"tampered":     func() ([]byte, error) { return k.OpenWith(secrets.LabelHWMEnc, aad, tampered) },
		"other master": func() ([]byte, error) { return other.OpenWith(secrets.LabelHWMEnc, aad, sealed) },
		"too short":    func() ([]byte, error) { return k.OpenWith(secrets.LabelHWMEnc, aad, sealed[:12]) },
	} {
		_, err := open()
		assert.ErrorIs(t, err, secrets.ErrDecrypt, name)
	}
	assert.NotEqual(t, k.Derive(secrets.LabelHWM), k.Derive(secrets.LabelHWMEnc), "MAC and encryption keys differ")
}
```

Run: `go test -count=1 -run TestSealWithSubkey ./internal/secrets/`
Expected: FAIL — `undefined: secrets.LabelHWMEnc` / `k.SealWith undefined`.

- [ ] **Step 2: Add sub-key encryption to `secrets`**

In `internal/secrets/envelope.go`:

1. In the label `const` block add, after `LabelCSRF`:

```go
	// LabelHWMEnc encrypts the time high-water mark record; its integrity comes from a MAC
	// under LabelHWM (spec §16.5, R36).
	LabelHWMEnc = "alice/hwm-enc/v1"
```

2. After `Derive` add:

```go
// SealWith encrypts plaintext with AES-256-GCM under the sub-key HKDF(master, label) and
// returns nonce || ciphertext. aad binds the value to its purpose.
func (k *Keyring) SealWith(label string, aad, plaintext []byte) ([]byte, error) {
	key := k.Derive(label)
	defer clear(key)
	ct, nonce, err := seal(key, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// OpenWith reverses SealWith. Any mismatch (label, aad, master key, tampering) returns ErrDecrypt.
func (k *Keyring) OpenWith(label string, aad, sealed []byte) ([]byte, error) {
	if len(sealed) <= nonceSize {
		return nil, ErrDecrypt
	}
	key := k.Derive(label)
	defer clear(key)
	pt, err := open(key, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
```

Run: `go test -race -count=1 ./internal/secrets/`
Expected: PASS.

- [ ] **Step 3: Write the failing HWM record and store tests**

Create `internal/license/hwm_test.go`:

```go
package license_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/secrets"
)

func keyring(t *testing.T, b byte) *secrets.Keyring {
	t.Helper()
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{b}, 32))
	require.NoError(t, err)
	return k
}

func TestHWMRecordRoundTrip(t *testing.T) {
	c := license.NewHWMCodec(keyring(t, 1))
	at := time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)
	raw, err := c.Encode(license.HWMRecord{At: at, Seq: 42})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "2026", "the time is not readable in the record")
	got, err := c.Decode(raw)
	require.NoError(t, err)
	assert.True(t, got.At.Equal(at))
	assert.Equal(t, uint64(42), got.Seq)
}

// L-54: a damaged or forged record is treated as missing, never as valid.
func TestHWMRecordRejectsTampering(t *testing.T) {
	c := license.NewHWMCodec(keyring(t, 1))
	raw, err := c.Encode(license.HWMRecord{At: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Seq: 1})
	require.NoError(t, err)
	other, err := c.Encode(license.HWMRecord{At: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Seq: 9})
	require.NoError(t, err)
	var w, o map[string]any
	require.NoError(t, json.Unmarshal(raw, &w))
	require.NoError(t, json.Unmarshal(other, &o))

	flipped := []byte(w["data"].(string))
	flipped[5] ^= 0x01
	swapMAC, err := json.Marshal(map[string]any{"v": 1, "data": w["data"], "mac": o["mac"]})
	require.NoError(t, err)
	flipData, err := json.Marshal(map[string]any{"v": 1, "data": string(flipped), "mac": w["mac"]})
	require.NoError(t, err)
	v2, err := json.Marshal(map[string]any{"v": 2, "data": w["data"], "mac": w["mac"]})
	require.NoError(t, err)

	for name, bad := range map[string][]byte{
		"bit flip in data":   flipData,
		"MAC of other record": swapMAC,
		"unknown version":    v2,
		"garbage":            []byte("not json"),
		"empty object":       []byte("{}"),
		"extra field":        []byte(`{"v":1,"data":"","mac":"","x":1}`),
	} {
		_, err := c.Decode(bad)
		assert.ErrorIs(t, err, license.ErrHWMInvalid, name)
	}
	_, err = license.NewHWMCodec(keyring(t, 2)).Decode(raw)
	assert.ErrorIs(t, err, license.ErrHWMInvalid, "a record from another installation's master key")
}

func TestFileHWMStore(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state")
	s := license.FileHWMStore{Path: filepath.Join(dir, license.HWMFileName)}
	got, err := s.Load(ctx)
	require.NoError(t, err)
	assert.Nil(t, got, "missing file = no record")

	require.NoError(t, s.Save(ctx, []byte(`{"v":1}`)))
	require.NoError(t, s.Save(ctx, []byte(`{"v":1,"n":2}`)))
	got, err = s.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, `{"v":1,"n":2}`, string(got))
	info, err := os.Stat(s.Path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary files are left behind")
	assert.Equal(t, "file", s.Name())
}
```

Run: `go test -count=1 -run 'HWM' ./internal/license/`
Expected: FAIL — `undefined: license.NewHWMCodec`.

- [ ] **Step 4: Implement the record codec and stores**

Create `internal/license/hwm.go`:

```go
package license

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
	"alice/internal/secrets"
)

// HWMRecord is the persisted time high-water mark (spec §16.5).
type HWMRecord struct {
	At  time.Time // whole seconds, UTC
	Seq uint64    // grows with every save, so a replayed older record loses (L-55)
}

// ErrHWMInvalid means a stored record did not decrypt or its MAC did not match. Such a
// record is treated as missing, never as valid, and the finding is audited (L-54).
var ErrHWMInvalid = errors.New("license: the time record is damaged")

// Where the record lives.
const (
	HWMSettingKey = "time.hwm"
	HWMFileName   = "hwm.dat"
	hwmAAD        = "alice/hwm-record/v1"
	maxHWMRecord  = 4096
)

// HWMCodec encrypts and MACs HWM records with keys derived from the master key.
type HWMCodec struct{ keyring *secrets.Keyring }

// NewHWMCodec returns a codec for the installation's master key.
func NewHWMCodec(k *secrets.Keyring) HWMCodec { return HWMCodec{keyring: k} }

// hwmWire is the stored form {v:1, data, mac}: data is AES-GCM(hwm || seq) under
// alice/hwm-enc/v1 (confidentiality is a convenience) and mac is
// HMAC-SHA256(K_hwm, "v1" || hwm || seq) with K_hwm = HKDF(master, "alice/hwm/v1").
type hwmWire struct {
	V    int    `json:"v"`
	Data string `json:"data"`
	MAC  string `json:"mac"`
}

// Encode seals r.
func (c HWMCodec) Encode(r HWMRecord) ([]byte, error) {
	secs := r.At.Unix()
	if secs < 0 {
		return nil, errors.New("license: time record before 1970")
	}
	plain := make([]byte, 16)
	binary.BigEndian.PutUint64(plain, uint64(secs)) //nolint:gosec // G115: secs is checked non-negative above
	binary.BigEndian.PutUint64(plain[8:], r.Seq)
	sealed, err := c.keyring.SealWith(secrets.LabelHWMEnc, []byte(hwmAAD), plain)
	if err != nil {
		return nil, err
	}
	return json.Marshal(hwmWire{
		V:    1,
		Data: base64.StdEncoding.EncodeToString(sealed),
		MAC:  base64.StdEncoding.EncodeToString(c.mac(plain)),
	})
}

// Decode opens a record. Every failure is ErrHWMInvalid.
func (c HWMCodec) Decode(raw []byte) (HWMRecord, error) {
	if len(raw) > maxHWMRecord {
		return HWMRecord{}, ErrHWMInvalid
	}
	var w hwmWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || w.V != 1 {
		return HWMRecord{}, ErrHWMInvalid
	}
	sealed, err1 := base64.StdEncoding.DecodeString(w.Data)
	mac, err2 := base64.StdEncoding.DecodeString(w.MAC)
	if err1 != nil || err2 != nil {
		return HWMRecord{}, ErrHWMInvalid
	}
	plain, err := c.keyring.OpenWith(secrets.LabelHWMEnc, []byte(hwmAAD), sealed)
	if err != nil || len(plain) != 16 || !hmac.Equal(mac, c.mac(plain)) {
		return HWMRecord{}, ErrHWMInvalid
	}
	secs := binary.BigEndian.Uint64(plain[:8])
	if secs > math.MaxInt64 {
		return HWMRecord{}, ErrHWMInvalid
	}
	return HWMRecord{At: time.Unix(int64(secs), 0).UTC(), Seq: binary.BigEndian.Uint64(plain[8:])}, nil //nolint:gosec // G115: bounded above
}

func (c HWMCodec) mac(plain []byte) []byte {
	key := c.keyring.Derive(secrets.LabelHWM)
	defer clear(key)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("v1"))
	m.Write(plain)
	return m.Sum(nil)
}

// HWMStore is one place the record is kept. Load returns nil, nil when there is none.
type HWMStore interface {
	Name() string
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, record []byte) error
}

// SettingsHWMStore keeps the record in settings (key time.hwm).
type SettingsHWMStore struct {
	Q     db.Querier
	Clock clock.Clock
}

// Name implements HWMStore.
func (SettingsHWMStore) Name() string { return "settings" }

// Load implements HWMStore.
func (s SettingsHWMStore) Load(ctx context.Context) ([]byte, error) {
	var raw json.RawMessage
	found, err := settings.Get(ctx, s.Q, HWMSettingKey, &raw)
	if err != nil || !found {
		return nil, err
	}
	return raw, nil
}

// Save implements HWMStore.
func (s SettingsHWMStore) Save(ctx context.Context, record []byte) error {
	return settings.Set(ctx, s.Q, HWMSettingKey, json.RawMessage(record), s.Clock.Now())
}

// FileHWMStore keeps the record in a file on the state volume, written atomically.
type FileHWMStore struct{ Path string }

// Name implements HWMStore.
func (FileHWMStore) Name() string { return "file" }

// Load implements HWMStore.
func (f FileHWMStore) Load(context.Context) ([]byte, error) {
	b, err := os.ReadFile(f.Path) //nolint:gosec // G304: the path comes from ALICE_STATE_DIR, not from a request
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the time record: %w", err)
	}
	return b, nil
}

// Save implements HWMStore: temporary file, fsync, rename, mode 0600.
func (f FileHWMStore) Save(_ context.Context, record []byte) error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".hwm-*.tmp")
	if err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op after a successful rename
	if _, err := tmp.Write(record); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the time record: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the time record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	if err := os.Rename(name, f.Path); err != nil {
		return fmt.Errorf("write the time record: %w", err)
	}
	return nil
}
```

Run: `go test -count=1 -run 'HWM' ./internal/license/`
Expected: PASS.

- [ ] **Step 5: Write the failing guard tests**

Create `internal/license/timeguard_test.go`:

```go
package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

var w0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func guardAt(hwm time.Time) *license.Guard {
	g := &license.Guard{}
	g.SetHWM(license.HWMRecord{At: hwm, Seq: 7})
	return g
}

// L-50: the HWM follows the clock.
func TestGuardFollowsTheClock(t *testing.T) {
	g := guardAt(w0)
	for h := 1; h <= 50; h++ {
		r, events := g.Observe(w0.Add(time.Duration(h)*time.Hour), time.Duration(h)*time.Hour)
		assert.Empty(t, events)
		assert.True(t, r.Effective.Equal(w0.Add(time.Duration(h)*time.Hour)))
	}
	assert.True(t, g.HWM().At.Equal(w0.Add(50*time.Hour)))
	next := g.NextRecord()
	assert.Equal(t, uint64(8), next.Seq)
	assert.Equal(t, uint64(8), g.HWM().Seq)
}

// L-51 (grace day per L-22's rule, R36 item 11), L-52, L-63.
func TestGuardRollback(t *testing.T) {
	hwm := expiry.Add(2*day + time.Hour)
	g := guardAt(hwm)
	r, events := g.Observe(expiry.Add(-10*day), 0)
	assert.Equal(t, []license.ClockEvent{license.EventRollback}, events)
	assert.True(t, r.Behind)
	assert.True(t, r.Effective.Equal(hwm), "a rolled-back clock never extends the license")
	e := license.Evaluate(r.Effective, installedAt, baseline())
	assert.Equal(t, license.PhaseGrace, e.Phase)
	assert.Equal(t, 3, e.GraceDay)

	g = guardAt(w0)
	r, events = g.Observe(w0.Add(-30*time.Minute), 0) // L-52
	assert.Empty(t, events)
	assert.False(t, r.Behind)
	assert.True(t, r.Effective.Equal(w0))

	r, events = g.Observe(w0.Add(-90*time.Second), time.Minute) // L-63
	assert.Empty(t, events)
	assert.False(t, r.Behind)

	_, events = g.Observe(w0.Add(-66*time.Minute), 2*time.Minute)
	assert.Equal(t, []license.ClockEvent{license.EventRollback}, events, "beyond 65 minutes")
}

// Time keeps moving with uptime while the clock is behind: rolling the clock back a year
// must not freeze the license for a year.
func TestGuardAdvancesWithUptimeWhileBehind(t *testing.T) {
	g := guardAt(w0)
	r, _ := g.Observe(w0.Add(-365*day), 0)
	assert.True(t, r.Effective.Equal(w0))
	r, events := g.Observe(w0.Add(-365*day+3*time.Hour), 3*time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventRollback}, events)
	assert.True(t, r.Behind)
	assert.True(t, r.Effective.Equal(w0.Add(3*time.Hour)))
}

// L-58: restarts with a rolled-back clock never move the effective time backwards.
func TestGuardRestartsNeverMoveBackwards(t *testing.T) {
	g := guardAt(w0)
	last := w0
	for i := range 10 {
		r, _ := g.Observe(w0.Add(-time.Duration(i+1)*day), 0)
		assert.False(t, r.Effective.Before(last), "restart %d", i)
		last = r.Effective
		saved := g.NextRecord()
		g = &license.Guard{} // a restart: a new process loads the saved record
		g.SetHWM(saved)
	}
	assert.True(t, g.HWM().At.Equal(w0))
}

// L-59, L-60: a suspicious forward jump is held for 24 h of uptime, then accepted.
func TestGuardForwardJump(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 0)
	r, events := g.Observe(w0.Add(200*day), time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventJumpDetected}, events)
	require.NotNil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(time.Hour)), "license math keeps the extrapolated time")
	assert.True(t, r.Jump.Expected.Equal(w0.Add(time.Hour)))
	assert.Equal(t, 200*day-time.Hour, r.Jump.By)
	assert.True(t, g.HWM().At.Equal(w0.Add(time.Hour)), "the jumped time is not stored as the HWM")

	r, events = g.Observe(w0.Add(200*day+10*time.Hour), 11*time.Hour)
	assert.Empty(t, events)
	require.NotNil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(11*time.Hour)))

	r, events = g.Observe(w0.Add(200*day+24*time.Hour), 25*time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventJumpAccepted}, events)
	assert.Nil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(200*day+24*time.Hour)), "after 24 h of uptime the new time counts (L-60)")
	assert.Equal(t, license.PhaseLocked, license.Evaluate(r.Effective, installedAt, []license.Installed{lic(1, "LIC-A", w0.Add(-300*day), w0.Add(100*day), 10)}).Phase)
}

// L-62: a 36-hour correction is below the 48-hour threshold.
func TestGuardSmallForwardCorrectionIsAccepted(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 0)
	r, events := g.Observe(w0.Add(37*time.Hour), time.Hour)
	assert.Empty(t, events)
	assert.Nil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(37*time.Hour)))
}

func TestGuardJumpClearedWhenTheClockIsFixed(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 0)
	g.Observe(w0.Add(100*day), time.Hour)
	r, events := g.Observe(w0.Add(3*time.Hour), 2*time.Hour) // the administrator set the right time
	assert.Equal(t, []license.ClockEvent{license.EventJumpCleared}, events)
	assert.Nil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(3*time.Hour)))
}

// L-61: a correction license accepts the new time at once.
func TestGuardAcceptJump(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 0)
	g.Observe(w0.Add(100*day), time.Hour)
	_, _, ok := g.PendingJump()
	require.True(t, ok)
	assert.True(t, g.AcceptJump())
	assert.False(t, g.AcceptJump(), "nothing left to accept")
	r, events := g.Observe(w0.Add(100*day+time.Minute), time.Hour+time.Minute)
	assert.Empty(t, events)
	assert.True(t, r.Effective.Equal(w0.Add(100*day+time.Minute)))
	assert.True(t, g.HWM().At.Equal(w0.Add(100*day+time.Minute)), "the HWM stays at the new time")
}

// A pending jump survives a restart: its 24 hours restart from the new process start.
func TestGuardRestoreJump(t *testing.T) {
	g := guardAt(w0.Add(time.Hour))
	g.RestoreJump(w0.Add(time.Hour), w0.Add(100*day), 0)
	r, _ := g.Observe(w0.Add(100*day+time.Hour), time.Hour)
	require.NotNil(t, r.Jump)
	assert.True(t, r.Effective.Equal(w0.Add(2*time.Hour)))
	_, events := g.Observe(w0.Add(101*day+time.Hour), 25*time.Hour)
	assert.Equal(t, []license.ClockEvent{license.EventJumpAccepted}, events)
}

func TestGuardToleratesUptimeGoingBackwards(t *testing.T) {
	g := guardAt(w0)
	g.Observe(w0, 10*time.Hour)
	r, events := g.Observe(w0.Add(time.Hour), time.Hour)
	assert.Empty(t, events)
	assert.True(t, r.Effective.Equal(w0.Add(time.Hour)))
}
```

Run: `go test -count=1 -run Guard ./internal/license/`
Expected: FAIL — `undefined: license.Guard`.

- [ ] **Step 6: Implement the guard**

Create `internal/license/timeguard.go`:

```go
package license

import "time"

// Clock rules (spec §16.5, R26, L-52).
const (
	// RollbackTolerance: a wall clock this far behind the HWM raises the "clock is behind"
	// warning. License math clamps to the HWM regardless (R36 item 9).
	RollbackTolerance = 65 * time.Minute
	// JumpThreshold: the wall clock advanced this much more than uptime since the last
	// observation = a suspicious forward jump.
	JumpThreshold = 48 * time.Hour
	// JumpSettle: uptime after which a held jump is accepted.
	JumpSettle = 24 * time.Hour
)

// ClockEvent is something the guard noticed during an observation.
type ClockEvent int

// Clock events, audited and shown to administrators by Service.
const (
	EventRollback ClockEvent = iota + 1
	EventJumpDetected
	EventJumpAccepted
	EventJumpCleared
)

// Jump describes a forward jump that is being held.
type Jump struct {
	Expected time.Time     // where the clock should be: the time before the jump plus uptime since
	Detected time.Time     // the wall time when the jump was seen
	By       time.Duration // how far the wall clock is ahead of Expected
}

// Reading is the result of one observation.
type Reading struct {
	Wall      time.Time // the system clock
	Trusted   time.Time // never earlier than any time Alice has accepted
	Effective time.Time // the time license states are computed from
	Behind    bool      // the wall clock is more than RollbackTolerance behind the HWM
	Jump      *Jump     // a held forward jump; nil when none
}

type heldJump struct {
	expected   time.Time     // Expected at baseUptime
	baseUptime time.Duration // uptime when the jump was seen (or when the process restarted)
	detected   time.Time
}

// Guard turns wall-clock and uptime observations into the trusted time. It is not safe
// for concurrent use; Service serializes access.
type Guard struct {
	hwm        time.Time
	seq        uint64
	lastWall   time.Time
	lastUptime time.Duration
	observed   bool
	jump       *heldJump
}

// SetHWM loads a persisted record (at start).
func (g *Guard) SetHWM(r HWMRecord) {
	g.hwm, g.seq = r.At.UTC().Truncate(time.Second), r.Seq
}

// HWM returns the current high-water mark and sequence.
func (g *Guard) HWM() HWMRecord { return HWMRecord{At: g.hwm, Seq: g.seq} }

// NextRecord returns the record to persist next; its sequence is one higher.
func (g *Guard) NextRecord() HWMRecord {
	g.seq++
	return g.HWM()
}

// Observe records the wall clock and the uptime and returns the reading.
//
//   - Trusted = max(wall, HWM + uptime since the previous observation): a clock set back
//     never moves time back (L-51, L-58) and does not stop it either.
//   - A wall clock more than 48 h ahead of the uptime elapsed since the previous
//     observation is a suspicious jump (R26): license math uses the time before the jump
//     plus uptime, and the HWM follows that, until 24 h of uptime have passed, the clock
//     is corrected, or AcceptJump is called (a correction license, L-61).
//   - The first observation after a start has nothing to compare with: downtime is not a jump.
func (g *Guard) Observe(wall time.Time, uptime time.Duration) (Reading, []ClockEvent) {
	wall = wall.UTC()
	var events []ClockEvent
	var dUp time.Duration // uptime since the previous observation
	if g.observed {
		dUp = max(uptime-g.lastUptime, 0)
		if g.jump == nil && wall.Sub(g.lastWall)-dUp > JumpThreshold {
			g.jump = &heldJump{expected: later(g.lastWall.Add(dUp), g.hwm), baseUptime: uptime, detected: wall}
			events = append(events, EventJumpDetected)
		}
	}
	g.lastWall, g.lastUptime, g.observed = wall, uptime, true

	r := Reading{Wall: wall}
	if g.jump != nil {
		held := uptime - g.jump.baseUptime
		if held < 0 {
			held = 0
		}
		expected := g.jump.expected.Add(held)
		switch {
		case wall.Sub(expected) <= JumpThreshold:
			g.jump = nil
			events = append(events, EventJumpCleared)
		case held >= JumpSettle:
			g.jump = nil
			events = append(events, EventJumpAccepted)
		default:
			eff := later(expected, g.hwm)
			g.hwm = eff.Truncate(time.Second)
			r.Trusted, r.Effective = eff, eff
			r.Jump = &Jump{Expected: expected, Detected: g.jump.detected, By: wall.Sub(expected)}
			return r, events
		}
	}
	if g.hwm.Sub(wall) > RollbackTolerance {
		r.Behind = true
		events = append(events, EventRollback)
	}
	// While the wall clock is behind, the HWM advances with uptime, so time never stands
	// still for a customer who set the clock back (only downtime is not counted).
	trusted := later(wall, g.hwm.Add(dUp))
	g.hwm = trusted.Truncate(time.Second)
	r.Trusted, r.Effective = trusted, trusted
	return r, events
}

// AcceptJump accepts a held jump at once. It reports whether one was held.
func (g *Guard) AcceptJump() bool {
	held := g.jump != nil
	g.jump = nil
	return held
}

// RestoreJump re-establishes a held jump after a restart. The 24 hours restart from
// uptime, which favours the customer (downtime is not counted).
func (g *Guard) RestoreJump(expected, detected time.Time, uptime time.Duration) {
	g.jump = &heldJump{expected: expected.UTC(), baseUptime: uptime, detected: detected.UTC()}
}

// PendingJump returns the held jump's expected and detected times.
func (g *Guard) PendingJump() (expected, detected time.Time, ok bool) {
	if g.jump == nil {
		return time.Time{}, time.Time{}, false
	}
	return g.jump.expected, g.jump.detected, true
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
```

- [ ] **Step 7: Run the tests**

Run: `go test -race -count=1 ./internal/license/ ./internal/secrets/`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/secrets/envelope.go internal/secrets/subkey_test.go internal/license/hwm.go internal/license/hwm_test.go \
  internal/license/timeguard.go internal/license/timeguard_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(license): clock guard with a MAC'd high-water mark

The trusted time is max(system clock, HWM); a clock set back never extends a
license and warns beyond 65 minutes. A forward jump of more than 48 h beyond
uptime is held (license math keeps the extrapolated time) until 24 h of
uptime pass, the clock is fixed, or a correction license is installed. HWM
records are AES-GCM encrypted (alice/hwm-enc/v1) and HMAC'd (alice/hwm/v1),
for storage in settings and in a file on the state volume.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 7: Migration: license tables, notification outbox, grants

Spec §7.6 (with R36 items 2–4): a singleton `license` row with the installation ID and timestamp, the uploaded
files stored verbatim (append-only for the application), `license_history` with one-time notices, and the
`notifications_outbox` (§7.6, R11). Every table gets explicit `alice_app` grants; the files and the history are
INSERT + SELECT only, like the audit log.

**Files:**
- Create: `migrations/00003_license.sql`
- Modify: `migrations/roles_integration_test.go` (`explicitGrants`, new test)
- Modify: `cmd/alice/testapi_e2e.go` (`resetSQL` lists the new tables)

**Interfaces:**
- Consumes: `users` (Phase 1).
- Produces (tables):
  - `license(id smallint PK = 1, installation_id text, installed_at timestamptz, state text CHECK IN ('evaluation','evaluation_expired','active','grace','locked'), clock_jump jsonb NULL, updated_at timestamptz)` — app: SELECT, INSERT, UPDATE.
  - `license_files(id uuid PK, seq bigint UNIQUE > 0, sha256 bytea UNIQUE, raw_file bytea 1..65536 bytes, uploaded_at timestamptz, uploaded_by uuid NULL → users)` — app: SELECT, INSERT.
  - `license_history(id uuid PK, at timestamptz, event text CHECK IN ('installed','renewed','state_change','clock_anomaly','rejected','notice'), license_id text, from_state text, to_state text, notice text NULL (set exactly for event 'notice'), details jsonb)`; unique `(license_id, notice) WHERE event = 'notice'` — app: SELECT, INSERT.
  - `notifications_outbox(id uuid PK, kind text 'email', to_address, template_key, params jsonb, locale, status CHECK IN ('pending','sent','failed','skipped_no_smtp'), attempts int, next_attempt_at, sent_at NULL, last_error_code text, created_at)` — app: SELECT, INSERT, UPDATE, DELETE.

- [ ] **Step 1: Write the failing grant and constraint tests**

In `migrations/roles_integration_test.go` replace `explicitGrants` with:

```go
var explicitGrants = map[string][]string{
	"public.audit_log":           {"INSERT", "SELECT"},
	"public.master_key_versions": {"INSERT", "SELECT"},
	"public.goose_db_version":    {"SELECT"},
	// License data: uploaded files and their history are append-only for the application,
	// so a compromised application cannot rewrite which licenses were installed (spec §16).
	"public.license":         {"INSERT", "SELECT", "UPDATE"},
	"public.license_files":   {"INSERT", "SELECT"},
	"public.license_history": {"INSERT", "SELECT"},
}
```

and append:

```go
func TestLicenseTablesAreAppendOnlyForTheApp(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	g := grants(t, d)
	assert.Equal(t, []string{"INSERT", "SELECT", "UPDATE"}, g["license"])
	assert.Equal(t, []string{"INSERT", "SELECT"}, g["license_files"])
	assert.Equal(t, []string{"INSERT", "SELECT"}, g["license_history"])
	assert.Equal(t, []string{"DELETE", "INSERT", "SELECT", "UPDATE"}, g["notifications_outbox"])

	_, err := d.App.Exec(ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
		VALUES (1, 'ALICE-TEST', now(), 'evaluation', now())`)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
		VALUES (2, 'ALICE-TWO', now(), 'evaluation', now())`)
	require.Error(t, err, "the license row is a singleton")
	_, err = d.App.Exec(ctx, `INSERT INTO license_files (id, seq, sha256, raw_file, uploaded_at)
		VALUES (gen_random_uuid(), 1, '\x01', '{}', now())`)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `INSERT INTO license_history (id, at, event, notice) VALUES (gen_random_uuid(), now(), 'notice', 'expiry:30')`)
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `INSERT INTO license_history (id, at, event, notice) VALUES (gen_random_uuid(), now(), 'notice', 'expiry:30')`)
	require.Error(t, err, "a notice is recorded once per license")
	_, err = d.App.Exec(ctx, `INSERT INTO license_history (id, at, event, notice) VALUES (gen_random_uuid(), now(), 'state_change', 'x')`)
	require.Error(t, err, "only notices carry a notice key")

	for _, stmt := range []string{
		"UPDATE license_files SET raw_file = '{\"x\":1}'",
		"DELETE FROM license_files",
		"UPDATE license_history SET event = 'renewed'",
		"DELETE FROM license_history",
		"DELETE FROM license",
	} {
		_, err := d.App.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), stmt)
		assert.Equal(t, "42501", pgErr.Code, "%s must be denied by privileges", stmt)
	}
}
```

Run: `go test -count=1 -tags integration ./migrations/`
Expected: FAIL — `relation "license" does not exist`.

- [ ] **Step 2: Write the migration**

Create `migrations/00003_license.sql`:

```sql
-- +goose Up
-- Phase 2: licensing (spec §7.6, §16; R36) and the notification outbox (§7.6, R11).

-- The installation: its ID and timestamp (the 30-day evaluation runs from installed_at and a
-- restore keeps both), the cached license state (recomputed from the files, never trusted over
-- them) and a held forward clock jump that must survive a restart (R26).
CREATE TABLE license (
    id              smallint PRIMARY KEY CHECK (id = 1),
    installation_id text NOT NULL,
    installed_at    timestamptz NOT NULL,
    state           text NOT NULL CHECK (state IN ('evaluation', 'evaluation_expired', 'active', 'grace', 'locked')),
    clock_jump      jsonb,
    updated_at      timestamptz NOT NULL
);

-- Every accepted upload, verbatim. Parsed values are never stored: they are re-verified from
-- raw_file at every evaluation, so editing a row cannot change a license (L-49).
CREATE TABLE license_files (
    id          uuid PRIMARY KEY,
    seq         bigint NOT NULL UNIQUE CHECK (seq > 0),
    sha256      bytea NOT NULL UNIQUE,
    raw_file    bytea NOT NULL CHECK (octet_length(raw_file) BETWEEN 1 AND 65536),
    uploaded_at timestamptz NOT NULL,
    uploaded_by uuid REFERENCES users (id)
);

-- Status history (spec §7.6 "license_history"). A notice (a warning email, a grace day, the
-- lock, a clock anomaly of one day) is recorded once per license: the unique index is what makes
-- warnings exactly-once across restarts and concurrent evaluations (L-14).
CREATE TABLE license_history (
    id         uuid PRIMARY KEY,
    at         timestamptz NOT NULL,
    event      text NOT NULL CHECK (event IN ('installed', 'renewed', 'state_change', 'clock_anomaly', 'rejected', 'notice')),
    license_id text NOT NULL DEFAULT '',
    from_state text NOT NULL DEFAULT '',
    to_state   text NOT NULL DEFAULT '',
    notice     text,
    details    jsonb NOT NULL DEFAULT '{}',
    CONSTRAINT license_history_notice_key CHECK ((event = 'notice') = (notice IS NOT NULL))
);
CREATE UNIQUE INDEX license_history_notice_once ON license_history (license_id, notice) WHERE event = 'notice';
CREATE INDEX license_history_at ON license_history (at DESC, id DESC);

-- Emails waiting to be sent; drained by the notify.send job so mail failures never block work.
CREATE TABLE notifications_outbox (
    id              uuid PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('email')),
    to_address      text NOT NULL,
    template_key    text NOT NULL,
    params          jsonb NOT NULL DEFAULT '{}',
    locale          text NOT NULL,
    status          text NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'skipped_no_smtp')),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    sent_at         timestamptz,
    last_error_code text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL
);
CREATE INDEX notifications_outbox_due ON notifications_outbox (next_attempt_at) WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE ON license TO alice_app;
GRANT SELECT, INSERT ON license_files, license_history TO alice_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON notifications_outbox TO alice_app;

-- +goose Down
DROP TABLE notifications_outbox;
DROP TABLE license_history;
DROP TABLE license_files;
DROP TABLE license;
```

- [ ] **Step 3: Run the migration tests**

Run: `go test -count=1 -tags integration ./migrations/ ./internal/platform/db/`
Expected: PASS (`TestAppRoleGrants` sees the new tables with their listed grant sets; `gen_random_uuid()` is built into PostgreSQL 16).

- [ ] **Step 4: Keep the e2e reset complete**

In `cmd/alice/testapi_e2e.go` replace `resetSQL` with:

```go
const resetSQL = `TRUNCATE users, user_mfa, recovery_codes, sessions, api_tokens, setup_sessions, settings, audit_log,
license, license_files, license_history, notifications_outbox`
```

Run: `go vet -tags e2e ./cmd/alice/`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add migrations/00003_license.sql migrations/roles_integration_test.go cmd/alice/testapi_e2e.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(db): license, license files and history, notification outbox

License files are stored verbatim and are append-only for alice_app, like
the history; a notice is unique per license so warnings are sent exactly
once. The outbox holds emails for the notify.send job.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 8: `license.Service` — installation, upload, gate, target check, snapshot and banners

The stateful part of spec §16.3–§16.5 and §19: the installation row created at first start, the HWM loaded from
both stores (larger valid record wins; damaged or missing records are audited), license upload with preview,
the single lock gate `Allow`, the transactional target check, the in-memory snapshot the API reads, the role-aware
banners of §19.3 and the detail view. `Tick` here only recomputes the state and saves the HWM; Task 9 replaces
`tick.go` with transitions, notices and clock-anomaly handling.

**Files:**
- Create: `internal/license/service.go`, `internal/license/install.go`, `internal/license/detail.go`, `internal/license/banners.go`, `internal/license/tick.go`
- Test: `internal/license/banners_test.go`, `internal/license/service_integration_test.go`
- Create: `internal/archtest/targets_test.go` (L-79 static check)

**Interfaces:**
- Consumes: Tasks 3–7 (`Check`, `Evaluate`, `Guard`, `HWMCodec`, stores, tables); `audit.Log.Append`, `audit.SystemActor`, `audit.Actor`; `db.InTx`, `db.IsUniqueViolation`, `db.Querier`; `clock.Clock`, `clock.Monotonic`; `secrets.Keyring`.
- Produces (`alice/internal/license`):
  - `type Notifier interface { NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error }`
  - `type TargetCounter interface { CountTargets(ctx context.Context, q db.Querier) (int, error) }`; `type NoTargets struct{}` (always 0; Phase 2).
  - `var ErrNoInstallation`.
  - `type Config struct { Pool *pgxpool.Pool; Keyring *secrets.Keyring; Audit *audit.Log; Clock clock.Clock; Uptime clock.Monotonic; Keys KeySet; StateDir string; BuildTime time.Time; Notifier Notifier; Targets TargetCounter; Log *slog.Logger }`
  - `type Snapshot struct { InstallationID string; InstalledAt time.Time; Eval Evaluation; Reading Reading; Tampered bool; Targets int; Ready bool }`; `func (s Snapshot) Banners(admin bool) []Banner`.
  - `type Severity string` (`SeverityInfo`, `SeverityWarning`, `SeverityCaution`, `SeverityDanger` = `"info"`, `"warning"`, `"caution"`, `"danger"`); `type Banner struct { Kind string; Severity Severity; Params map[string]string }`. Kinds: `evaluation`, `evaluation_ended`, `expiry_warning`, `grace`, `locked` (everyone except `expiry_warning`), `tampered`, `clock_behind`, `clock_jump`, `pending`, `over_limit`, `limit_reached` (Admins only).
  - `type UploadResult struct { Payload Payload; KeyID string; Correction, Pending, AlreadyExpired, Duplicate bool; Phase Phase }`.
  - `type FileInfo struct { ID uuid.UUID; Seq int64; UploadedAt time.Time; Status string; KeyID string; Payload *Payload }` (Status `current|pending|superseded|invalid`); `type HistoryEntry struct { At time.Time; Event, LicenseID, FromState, ToState, Notice string; Details map[string]string }`; `type Detail struct { Snapshot Snapshot; Files []FileInfo; History []HistoryEntry }`.
  - `func New(c Config) *Service`; methods: `Start(ctx) error`, `Tick(ctx) error`, `Shutdown(ctx) error`, `Snapshot() Snapshot`, `Allow(c Class) error`, `CheckCanAddTarget(ctx, tx pgx.Tx) error`, `Preview(ctx, raw []byte) (UploadResult, error)`, `Install(ctx, raw []byte, actor audit.Actor, by uuid.UUID) (UploadResult, error)`, `Installed(ctx) (bool, error)`, `Detail(ctx) (Detail, error)`, `Inspect(ctx) (Snapshot, error)`.
  - Audit actions written here: `license.activated`, `license.renewed`, `license.upload.<reason>` (failure), `clock.jump_accepted`, `clock.hwm_damaged`, `clock.time_reference_reset`.

- [ ] **Step 1: Write the failing banner tests**

Create `internal/license/banners_test.go`:

```go
package license_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/license"
)

func snapshotAt(now time.Time, installed []license.Installed) license.Snapshot {
	return license.Snapshot{
		InstallationID: testInstallation,
		InstalledAt:    installedAt,
		Eval:           license.Evaluate(now, installedAt, installed),
		Reading:        license.Reading{Wall: now, Trusted: now, Effective: now},
		Ready:          true,
	}
}

func kinds(bs []license.Banner) []string {
	out := []string{}
	for _, b := range bs {
		out = append(out, b.Kind+"/"+string(b.Severity))
	}
	return out
}

// §19.3: what everyone sees, and L-15: warnings go to Admins only.
func TestBannersForEveryone(t *testing.T) {
	eval := snapshotAt(installedAt, nil)
	assert.Equal(t, []string{"evaluation/info"}, kinds(eval.Banners(false)))
	b := eval.Banners(false)[0]
	assert.Equal(t, map[string]string{"days_left": "30", "max_targets": "5", "ends_at": "2026-10-31T09:00:00Z"}, b.Params)

	evalWarn := snapshotAt(installedAt.Add(27*day), nil)
	assert.Equal(t, []string{"evaluation/info"}, kinds(evalWarn.Banners(false)))
	assert.Equal(t, []string{"evaluation/caution"}, kinds(evalWarn.Banners(true)), "Admins: 3 days left is orange")
	assert.Equal(t, []string{"evaluation/warning"}, kinds(snapshotAt(installedAt.Add(23*day), nil).Banners(true)))

	assert.Equal(t, []string{"evaluation_ended/danger"}, kinds(snapshotAt(installedAt.Add(30*day), nil).Banners(false)))

	warn := snapshotAt(expiry.Add(-7*day), baseline())
	assert.Empty(t, warn.Banners(false), "L-15: no warning for Operators and Auditors")
	assert.Equal(t, []string{"expiry_warning/caution"}, kinds(warn.Banners(true)))
	assert.Equal(t, map[string]string{"days_left": "7", "valid_until": "2027-10-01T00:00:00Z"}, warn.Banners(true)[0].Params)
	assert.Equal(t, []string{"expiry_warning/warning"}, kinds(snapshotAt(expiry.Add(-30*day), baseline()).Banners(true)))
	assert.Empty(t, snapshotAt(expiry.Add(-61*day), baseline()).Banners(true), "L-10: no banner")

	grace := snapshotAt(expiry.Add(2*day+time.Hour), baseline())
	assert.Equal(t, []string{"grace/danger"}, kinds(grace.Banners(false)))
	assert.Equal(t, map[string]string{"valid_until": "2027-10-01T00:00:00Z", "locks_at": "2027-10-08T00:00:00Z", "grace_day": "3"},
		grace.Banners(false)[0].Params)

	assert.Equal(t, []string{"locked/danger"}, kinds(snapshotAt(expiry.Add(200*day), baseline()).Banners(false)))
}

func TestAdminOnlyBanners(t *testing.T) {
	s := snapshotAt(expiry.Add(-100*day), append(baseline(), lic(2, "LIC-B", expiry.Add(-90*day), expiry.Add(275*day), 10)))
	s.Tampered = true
	s.Reading.Behind = true
	s.Reading.Wall = expiry.Add(-120 * day)
	s.Reading.Jump = &license.Jump{By: 200*day + time.Hour}
	s.Targets = 12
	assert.Empty(t, s.Banners(false))
	assert.Equal(t, []string{"tampered/danger", "clock_behind/caution", "clock_jump/caution", "pending/info", "over_limit/warning"},
		kinds(s.Banners(true)))
	byKind := map[string]map[string]string{}
	for _, b := range s.Banners(true) {
		byKind[b.Kind] = b.Params
	}
	assert.Equal(t, "200", byKind["clock_jump"]["jump_days"])
	assert.Equal(t, map[string]string{"used": "12", "max": "10"}, byKind["over_limit"], "R30: persistent, no end date")
	assert.Equal(t, "2027-07-03T00:00:00Z", byKind["pending"]["valid_from"])

	full := snapshotAt(expiry.Add(-100*day), baseline())
	full.Targets = 10
	assert.Equal(t, []string{"limit_reached/info"}, kinds(full.Banners(true)), "§19.3 target limit reached")
}
```

Run: `go test -count=1 -run Banners ./internal/license/`
Expected: FAIL — `undefined: license.Snapshot`.

- [ ] **Step 2: Write the failing service integration tests**

Create `internal/license/service_integration_test.go`:

```go
//go:build integration

package license_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var uploader = audit.Actor{Type: audit.ActorUser, ID: uuid.MustParse("0190f5a0-0000-7000-8000-000000000001"), Name: "admin"}

type recordingNotifier struct {
	mu    sync.Mutex
	sent  []string
	calls []map[string]string
}

func (r *recordingNotifier) NotifyAdmins(_ context.Context, _ pgx.Tx, template string, params map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, template)
	r.calls = append(r.calls, params)
	return nil
}

func (r *recordingNotifier) templates() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sent...)
}

type env struct {
	t         *testing.T
	ctx       context.Context
	db        *pgtest.DB
	clk       *clock.Fake
	keyring   *secrets.Keyring
	stateDir  string
	buildTime time.Time
	notices   *recordingNotifier
	targets   license.TargetCounter
	svc       *license.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t: t, ctx: context.Background(), db: pgtest.New(t), clk: clock.NewFake(installedAt), keyring: keyring(t, 3),
		stateDir: t.TempDir(), notices: &recordingNotifier{}, targets: license.NoTargets{},
	}
	e.restart()
	return e
}

func (e *env) newService() *license.Service {
	return license.New(license.Config{
		Pool: e.db.App, Keyring: e.keyring, Audit: audit.New(e.clk), Clock: e.clk, Uptime: e.clk,
		Keys: licensetest.KeySet(), StateDir: e.stateDir, BuildTime: e.buildTime, Notifier: e.notices,
		Targets: e.targets, Log: slog.New(slog.DiscardHandler),
	})
}

// restart builds a new Service on the same database, state directory and clock (a process restart).
func (e *env) restart() {
	e.t.Helper()
	e.svc = e.newService()
	require.NoError(e.t, e.svc.Start(e.ctx))
}

func (e *env) installation() string { return e.svc.Snapshot().InstallationID }

func (e *env) payload(id string, from, until time.Time, targets int) license.Payload {
	p := licensetest.Payload(e.installation(), from, until, targets)
	p.LicenseID = id
	return p
}

func (e *env) upload(p license.Payload) (license.UploadResult, error) {
	return e.svc.Install(e.ctx, licensetest.Sign(p), uploader, uuid.Nil)
}

func (e *env) countWhere(table, cond string) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()+" WHERE "+cond).Scan(&n))
	return n
}

func (e *env) auditCount(action string) int {
	return e.countWhere("audit_log", "action = '"+action+"'")
}

func (e *env) state() string {
	e.t.Helper()
	var s string
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT state FROM license WHERE id = 1").Scan(&s))
	return s
}

func TestStartCreatesTheInstallationOnce(t *testing.T) {
	e := newEnv(t)
	snap := e.svc.Snapshot()
	require.True(t, snap.Ready)
	id, err := license.ParseInstallationID(snap.InstallationID)
	require.NoError(t, err)
	assert.Equal(t, id, snap.InstallationID)
	assert.True(t, snap.InstalledAt.Equal(installedAt))
	assert.Equal(t, license.PhaseEvaluation, snap.Eval.Phase) // L-01
	assert.Equal(t, 30, snap.Eval.DaysLeft)
	assert.Zero(t, e.countWhere("audit_log", "true"), "first start writes no audit row (the chain starts with setup.admin_created)")

	e.clk.Advance(time.Hour)
	e.restart()
	assert.Equal(t, snap.InstallationID, e.installation(), "the ID is created once")
	assert.True(t, e.svc.Snapshot().InstalledAt.Equal(installedAt))

	var settingRaw []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT value FROM settings WHERE key = 'time.hwm'").Scan(&settingRaw))
	fileRaw, err := os.ReadFile(filepath.Join(e.stateDir, license.HWMFileName))
	require.NoError(t, err)
	codec := license.NewHWMCodec(e.keyring)
	for _, raw := range [][]byte{settingRaw, fileRaw} {
		rec, err := codec.Decode(raw)
		require.NoError(t, err)
		assert.True(t, rec.At.Equal(installedAt.Add(time.Hour)), "the time record is written to both stores")
	}
}

// L-05, L-30: a license takes effect at once; the audit trail says so.
func TestUploadActivatesImmediately(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	res, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	assert.Equal(t, license.PhaseActive, res.Phase)
	assert.False(t, res.Duplicate)
	assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)
	assert.Equal(t, "active", e.state())
	assert.Equal(t, 1, e.auditCount("license.activated"))
	assert.Equal(t, 1, e.countWhere("license_history", "event = 'installed' AND license_id = 'LIC-A' AND from_state = 'evaluation' AND to_state = 'active'"))
	var details map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT details FROM audit_log WHERE action = 'license.activated'").Scan(&details))
	assert.Equal(t, "Test Company", details["customer"])
	assert.Equal(t, "10", details["max_targets"])
	assert.Equal(t, licensetest.KeyID, details["key_id"])

	renamed := e.payload("LIC-B", now, now.AddDate(2, 0, 0), 20)
	renamed.Customer = "Yeni Unvan A.Ş." // L-33: the name is informational; the installation ID binds
	_, err = e.upload(renamed)
	require.NoError(t, err)
	assert.Equal(t, 1, e.auditCount("license.renewed"))
	assert.Equal(t, 20, e.svc.Snapshot().Eval.MaxTargets)
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT details FROM audit_log WHERE action = 'license.renewed'").Scan(&details))
	assert.Equal(t, "Yeni Unvan A.Ş.", details["customer"], "the audit trail shows the name change")
}

// L-40..L-45: rejected uploads are audited and change nothing.
func TestUploadRejections(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	good := licensetest.Sign(e.payload("LIC-B", now, now.AddDate(1, 0, 0), 10))
	other := licensetest.Payload(license.NewInstallationID(), now, now.AddDate(1, 0, 0), 10)

	cases := map[string]struct {
		raw    []byte
		is     error
		action string
	}{
		"edited (L-40)":            {bytes.Replace(good, []byte(`"max_targets": 10`), []byte(`"max_targets": 1000`), 1), license.ErrInvalid, "license.upload.invalid_signature"},
		"garbage (L-41)":           {[]byte("not a license"), license.ErrInvalid, "license.upload.invalid"},
		"unknown key (L-42)":       {licensetest.SignWith(otherKey, "vk-2099-01", e.payload("LIC-C", now, now.AddDate(1, 0, 0), 10)), license.ErrUnknownKey, "license.upload.unknown_key"},
		"other installation (L-43)": {licensetest.Sign(other), license.ErrWrongInstallation, "license.upload.wrong_installation"},
		"newer format (L-45)":      {bytes.Replace(good, []byte("\"format\": 1,\n  \"key_id\""), []byte("\"format\": 99,\n  \"key_id\""), 1), license.ErrUnsupportedFormat, "license.upload.unsupported_format"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.svc.Install(e.ctx, tc.raw, uploader, uuid.Nil)
			require.ErrorIs(t, err, tc.is)
			assert.Equal(t, 1, e.auditCount(tc.action))
			assert.Equal(t, 1, e.countWhere("license_files", "true"), "nothing stored")
			assert.Equal(t, "LIC-A", e.svc.Snapshot().Eval.Key(), "the installed license is untouched")
		})
	}
	_, err = e.svc.Install(e.ctx, licensetest.Sign(other), uploader, uuid.Nil)
	var wi *license.WrongInstallationError
	require.ErrorAs(t, err, &wi)
	assert.Equal(t, license.IDSuffix(e.installation()), wi.Expected)
	assert.Equal(t, license.IDSuffix(other.InstallationID), wi.Got)
	assert.Equal(t, 6, e.countWhere("license_history", "event = 'rejected'"))
}

// §16.3: an older license is refused unless it lasts longer or is a correction (R7).
func TestOlderLicenseIsRefusedUnlessCorrection(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)

	_, err = e.upload(e.payload("LIC-OLD", now.Add(-10*day), now.Add(300*day), 10))
	require.ErrorIs(t, err, license.ErrOlderThanInstalled)
	assert.Equal(t, 1, e.auditCount("license.upload.older_than_installed"))

	_, err = e.upload(e.payload("LIC-LONGER", now.Add(-10*day), now.Add(400*day), 10))
	require.NoError(t, err, "an older issue date with a later valid_until is accepted")

	correction := e.payload("LIC-FIX", now.Add(-20*day), now.Add(100*day), 12)
	correction.Replaces = "LIC-LONGER"
	res, err := e.upload(correction)
	require.NoError(t, err)
	assert.True(t, res.Correction)
	assert.Equal(t, "LIC-FIX", e.svc.Snapshot().Eval.Key())
}

// Uploading the same license again (also reformatted) is reported, not stored twice.
func TestDuplicateUploadIsIdempotent(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	raw := licensetest.Sign(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	_, err := e.svc.Install(e.ctx, raw, uploader, uuid.Nil)
	require.NoError(t, err)
	var compact bytes.Buffer
	require.NoError(t, json.Compact(&compact, raw))
	for _, again := range [][]byte{raw, compact.Bytes()} {
		res, err := e.svc.Install(e.ctx, again, uploader, uuid.Nil)
		require.NoError(t, err)
		assert.True(t, res.Duplicate)
	}
	assert.Equal(t, 1, e.countWhere("license_files", "true"))
	assert.Equal(t, 1, e.auditCount("license.activated"))
}

// L-32 and L-48.
func TestExpiredAndPendingUploads(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	res, err := e.upload(e.payload("LIC-OLD", now.Add(-400*day), now.Add(-3*day), 10))
	require.NoError(t, err)
	assert.True(t, res.AlreadyExpired)
	assert.Equal(t, license.PhaseGrace, res.Phase, "3 days after valid_until")

	res, err = e.upload(e.payload("LIC-NEXT", now.Add(2*day), now.Add(367*day), 20))
	require.NoError(t, err)
	assert.True(t, res.Pending)
	snap := e.svc.Snapshot()
	assert.Equal(t, "LIC-OLD", snap.Eval.Key(), "the previous license continues until the new one starts")
	require.NotNil(t, snap.Eval.Pending)

	d, err := e.svc.Detail(e.ctx)
	require.NoError(t, err)
	require.Len(t, d.Files, 2)
	assert.Equal(t, "pending", d.Files[0].Status)
	assert.Equal(t, "current", d.Files[1].Status)
	require.NotEmpty(t, d.History)
	assert.Equal(t, "renewed", d.History[0].Event)
}

func TestPreviewStoresNothing(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	res, err := e.svc.Preview(e.ctx, licensetest.Sign(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10)))
	require.NoError(t, err)
	assert.Equal(t, "Test Company", res.Payload.Customer)
	assert.Equal(t, license.PhaseActive, res.Phase, "the phase the upload would give")
	assert.Zero(t, e.countWhere("license_files", "true"))
	assert.Zero(t, e.countWhere("audit_log", "true"))
	_, err = e.svc.Preview(e.ctx, []byte("junk"))
	require.ErrorIs(t, err, license.ErrInvalid)
	assert.Zero(t, e.countWhere("audit_log", "true"), "a preview is not an upload")
}

// Review Focus 2: concurrent uploads are serialized by the license row lock.
func TestConcurrentUploadsAreSerialized(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	same := licensetest.Sign(e.payload("LIC-SAME", now, now.AddDate(1, 0, 0), 10))
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.upload(e.payload(fmt.Sprintf("LIC-P-%d", i), now, now.AddDate(1, i, 0), 10))
			errs <- err
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Install(e.ctx, same, uploader, uuid.Nil)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, 9, e.countWhere("license_files", "true"))
	assert.Equal(t, 9, e.countWhere("license_files", "seq BETWEEN 1 AND 9"), "gapless upload order")
	assert.Equal(t, 9, e.countWhere("license_history", "event IN ('installed', 'renewed')"))
	assert.Equal(t, 1, e.auditCount("license.activated"))
	assert.Equal(t, 8, e.auditCount("license.renewed"))
	assert.Equal(t, "active", e.state())
}

// L-49: a stored file edited in the database no longer counts; the previous one (or the
// evaluation) applies and Admins are told.
func TestStoredFileEditedDirectlyIsIgnored(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	_, err = e.upload(e.payload("LIC-B", now, now.AddDate(1, 0, 0), 20))
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE license_files SET raw_file =
		convert_to(replace(convert_from(raw_file, 'UTF8'), '"max_targets": 20', '"max_targets": 2000'), 'UTF8') WHERE seq = 2`)
	require.NoError(t, err)

	e.restart()
	snap := e.svc.Snapshot()
	assert.True(t, snap.Tampered)
	assert.Equal(t, "LIC-A", snap.Eval.Key(), "falls back to the last valid stored license")
	assert.Equal(t, 10, snap.Eval.MaxTargets)
	assert.Contains(t, kinds(snap.Banners(true)), "tampered/danger")
	d, err := e.svc.Detail(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, "invalid", d.Files[0].Status)
	assert.Nil(t, d.Files[0].Payload)

	_, err = e.db.Owner.Exec(e.ctx, `UPDATE license_files SET raw_file = convert_to('{}', 'UTF8') WHERE seq = 1`)
	require.NoError(t, err)
	e.restart()
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase, "no valid file left: the evaluation rules apply")
}

func TestAllowFollowsThePhase(t *testing.T) {
	e := newEnv(t)
	require.NoError(t, e.svc.Allow(license.ClassChange))
	assert.ErrorIs(t, e.svc.Allow(license.ClassUnset), license.ErrUnclassified)

	e.clk.Advance(30 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.Equal(t, license.PhaseEvaluationExpired, e.svc.Snapshot().Eval.Phase)
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)
	assert.ErrorIs(t, e.svc.Allow(license.ClassReadOnly), license.ErrLocked)
	assert.NoError(t, e.svc.Allow(license.ClassAlways), "sign-in, uploads, backups keep working")

	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	assert.NoError(t, e.svc.Allow(license.ClassChange), "a renewal unlocks at once, without a restart")

	notStarted := e.newService()
	assert.ErrorIs(t, notStarted.Allow(license.ClassChange), license.ErrLocked, "fail closed before Start")
}

type tableCounter struct{}

func (tableCounter) CountTargets(ctx context.Context, q db.Querier) (int, error) {
	var n int
	err := q.QueryRow(ctx, "SELECT count(*) FROM test_targets").Scan(&n)
	return n, err
}

// L-04, L-71, L-74: the limit check and the insert happen in one transaction under a lock.
func TestCheckCanAddTargetIsTransactional(t *testing.T) {
	e := newEnv(t)
	for _, stmt := range []string{
		"CREATE TABLE test_targets (id serial PRIMARY KEY)",
		"GRANT SELECT, INSERT ON test_targets TO alice_app",
		"GRANT USAGE ON SEQUENCE test_targets_id_seq TO alice_app",
		"INSERT INTO test_targets (id) SELECT nextval('test_targets_id_seq') FROM generate_series(1, 4)",
	} {
		_, err := e.db.Owner.Exec(e.ctx, stmt)
		require.NoError(t, err, stmt)
	}
	e.targets = tableCounter{}
	e.restart()

	var wg sync.WaitGroup
	results := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error {
				if err := e.svc.CheckCanAddTarget(e.ctx, tx); err != nil {
					return err
				}
				_, err := tx.Exec(e.ctx, "INSERT INTO test_targets DEFAULT VALUES")
				return err
			})
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		if err == nil {
			ok++
			continue
		}
		var tl *license.TargetLimitError
		require.ErrorAs(t, err, &tl)
		assert.Equal(t, license.TargetLimitError{Max: 5, Used: 5}, *tl)
	}
	assert.Equal(t, 1, ok, "exactly one of the concurrent adds wins")
	assert.Equal(t, 5, e.countWhere("test_targets", "true"), "the count never exceeds the limit")

	e.clk.Advance(31 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	err := db.InTx(e.ctx, e.db.App, func(tx pgx.Tx) error { return e.svc.CheckCanAddTarget(e.ctx, tx) })
	assert.ErrorIs(t, err, license.ErrLocked)
}

// L-53, L-54, L-55: which time record wins at start, and what is audited.
func TestStartChoosesTheTimeRecord(t *testing.T) {
	t.Run("a damaged settings record is ignored and audited (L-54)", func(t *testing.T) {
		e := newEnv(t)
		e.clk.Advance(5 * day)
		require.NoError(t, e.svc.Tick(e.ctx))
		_, err := e.db.Owner.Exec(e.ctx, `UPDATE settings SET value = jsonb_set(value, '{mac}', '"AAAA"') WHERE key = 'time.hwm'`)
		require.NoError(t, err)
		e.clk.Set(installedAt) // the clock is also set back
		e.restart()
		assert.Equal(t, 1, e.auditCount("clock.hwm_damaged"))
		assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(5*day)), "the file record still holds")
	})
	t.Run("a replayed older record loses (L-55)", func(t *testing.T) {
		e := newEnv(t)
		old, err := os.ReadFile(filepath.Join(e.stateDir, license.HWMFileName))
		require.NoError(t, err)
		e.clk.Advance(10 * day)
		require.NoError(t, e.svc.Tick(e.ctx))
		require.NoError(t, os.WriteFile(filepath.Join(e.stateDir, license.HWMFileName), old, 0o600))
		e.clk.Set(installedAt)
		e.restart()
		assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(10*day)))
		assert.Zero(t, e.auditCount("clock.hwm_damaged"), "an old record is valid, just older")
	})
	t.Run("both missing: time reference reset, build time is the floor (L-53)", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.db.Owner.Exec(e.ctx, `DELETE FROM settings WHERE key = 'time.hwm'`)
		require.NoError(t, err)
		require.NoError(t, os.Remove(filepath.Join(e.stateDir, license.HWMFileName)))
		e.buildTime = installedAt.Add(3 * day)
		e.restart()
		assert.Equal(t, 1, e.auditCount("clock.time_reference_reset"))
		assert.Equal(t, 1, e.countWhere("license_history", "event = 'clock_anomaly'"))
		assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(installedAt.Add(3*day)), "max(system clock, build time)")
	})
}

func TestInspectChangesNothing(t *testing.T) {
	e := newEnv(t)
	file := filepath.Join(e.stateDir, license.HWMFileName)
	before, err := os.ReadFile(file)
	require.NoError(t, err)
	var settingBefore []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT value FROM settings WHERE key = 'time.hwm'").Scan(&settingBefore))

	e.clk.Advance(40 * day)
	snap, err := e.newService().Inspect(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, license.PhaseEvaluationExpired, snap.Eval.Phase)

	after, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	var settingAfter []byte
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT value FROM settings WHERE key = 'time.hwm'").Scan(&settingAfter))
	assert.JSONEq(t, string(settingBefore), string(settingAfter))

	blank := pgtest.New(t)
	_, err = license.New(license.Config{Pool: blank.App, Keyring: e.keyring, Audit: audit.New(e.clk), Clock: e.clk, Uptime: e.clk,
		Keys: licensetest.KeySet()}).Inspect(e.ctx)
	assert.ErrorIs(t, err, license.ErrNoInstallation)
}

func TestInstalledReportsAnyStoredLicense(t *testing.T) {
	e := newEnv(t)
	ok, err := e.svc.Installed(e.ctx)
	require.NoError(t, err)
	assert.False(t, ok)
	now := e.clk.Now()
	_, err = e.upload(e.payload("LIC-A", now, now.AddDate(1, 0, 0), 10))
	require.NoError(t, err)
	ok, err = e.svc.Installed(e.ctx)
	require.NoError(t, err)
	assert.True(t, ok)
}
```

Run: `go test -count=1 -tags integration ./internal/license/`
Expected: FAIL — `undefined: license.New`, `license.Config`, ….

- [ ] **Step 3: Implement the service core**

Create `internal/license/service.go`:

```go
package license

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/secrets"
)

// Notifier queues an email to every Administrator inside the caller's transaction. It is
// implemented by notify.AdminNotifier (license may not import notify, spec §5.4).
type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}

// TargetCounter counts managed targets. Phase 3 implements it over the targets table.
type TargetCounter interface {
	CountTargets(ctx context.Context, q db.Querier) (int, error)
}

// NoTargets is the Phase 2 counter: there is no targets table yet (spec §26.4 stub).
type NoTargets struct{}

// CountTargets implements TargetCounter.
func (NoTargets) CountTargets(context.Context, db.Querier) (int, error) { return 0, nil }

// ErrNoInstallation means Alice has never started on this database.
var ErrNoInstallation = errors.New("license: Alice has not been started on this database yet")

// targetLimitLock serializes "count targets, then insert one" across transactions (L-74).
const targetLimitLock int64 = 7160927315633811302

var systemActor = audit.SystemActor("license")

// Config holds the service dependencies.
type Config struct {
	Pool      *pgxpool.Pool
	Keyring   *secrets.Keyring
	Audit     *audit.Log
	Clock     clock.Clock
	Uptime    clock.Monotonic
	Keys      KeySet
	StateDir  string    // directory of the HWM file; "" = settings only (tests)
	BuildTime time.Time // the HWM never falls below the build time; zero when unknown
	Notifier  Notifier  // nil = no emails
	Targets   TargetCounter
	Log       *slog.Logger
}

// Snapshot is the license state as of the last evaluation. The API and the gate read it
// without touching the database.
type Snapshot struct {
	InstallationID string
	InstalledAt    time.Time
	Eval           Evaluation
	Reading        Reading
	Tampered       bool // a stored file no longer verifies (L-49)
	Targets        int
	Ready          bool // Start has completed
}

// Service is the license module.
type Service struct {
	pool      *pgxpool.Pool
	keyring   *secrets.Keyring
	audit     *audit.Log
	clock     clock.Clock
	uptime    clock.Monotonic
	keys      KeySet
	buildTime time.Time
	notifier  Notifier
	targets   TargetCounter
	log       *slog.Logger
	codec     HWMCodec
	stores    []HWMStore

	mu    sync.Mutex
	guard Guard
	snap  Snapshot
}

// New builds the service. Call Start before using it.
func New(c Config) *Service {
	s := &Service{
		pool: c.Pool, keyring: c.Keyring, audit: c.Audit, clock: c.Clock, uptime: c.Uptime, keys: c.Keys,
		buildTime: c.BuildTime.UTC(), notifier: c.Notifier, targets: c.Targets, log: c.Log, codec: NewHWMCodec(c.Keyring),
	}
	if s.targets == nil {
		s.targets = NoTargets{}
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.stores = []HWMStore{SettingsHWMStore{Q: c.Pool, Clock: c.Clock}}
	if c.StateDir != "" {
		s.stores = append(s.stores, FileHWMStore{Path: filepath.Join(c.StateDir, HWMFileName)})
	}
	return s
}

// Snapshot returns the state as of the last evaluation.
func (s *Service) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap
}

func (s *Service) setSnapshot(snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap = snap
}

// Allow is the single lock-mode gate (spec §8.6, R9): the API guard calls it for routes of
// ClassChange, the scheduler before every task. It returns ErrLocked while the license or
// the evaluation has ended, ErrUnclassified for work without a class, and fails closed
// before Start has completed.
func (s *Service) Allow(c Class) error {
	if !c.Valid() {
		return ErrUnclassified
	}
	if c == ClassAlways {
		return nil
	}
	snap := s.Snapshot()
	if !snap.Ready || snap.Eval.Locked() {
		return ErrLocked
	}
	return nil
}

// CheckCanAddTarget must be called in the transaction that inserts a target, before the
// insert (spec L-74, L-79): it serializes concurrent adds, counts the targets and refuses
// with ErrLocked or a *TargetLimitError. Exceeding the limit never locks (R30).
func (s *Service) CheckCanAddTarget(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", targetLimitLock); err != nil {
		return fmt.Errorf("lock the target count: %w", err)
	}
	n, err := s.targets.CountTargets(ctx, tx)
	if err != nil {
		return fmt.Errorf("count targets: %w", err)
	}
	snap := s.Snapshot()
	if !snap.Ready || snap.Eval.Locked() {
		return ErrLocked
	}
	if !snap.Eval.CanAdd(n) {
		return &TargetLimitError{Max: snap.Eval.MaxTargets, Used: n}
	}
	return nil
}

// Installed reports whether any license file was ever accepted (the wizard's license step).
func (s *Service) Installed(ctx context.Context) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM license_files)").Scan(&ok); err != nil {
		return false, fmt.Errorf("read license files: %w", err)
	}
	return ok, nil
}

// Start creates the installation on the first start (installation ID and timestamp, spec
// §16.4), loads the time record from both stores, restores a held clock jump, and runs the
// first evaluation. Problems with the time record of an existing installation are audited.
func (s *Service) Start(ctx context.Context) error {
	fresh, err := s.ensureInstallation(ctx)
	if err != nil {
		return err
	}
	best, damaged, err := s.readHWM(ctx)
	if err != nil {
		return err
	}
	row, err := loadInstallation(ctx, s.pool, false)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.guard = Guard{}
	s.guard.SetHWM(s.floor(best))
	if j, ok := decodeJump(row.ClockJump); ok {
		s.guard.RestoreJump(j.Expected, j.Detected, s.uptime.Elapsed())
	}
	s.mu.Unlock()
	if !fresh && (len(damaged) > 0 || best == nil) {
		if err := s.recordTimeRecordProblem(ctx, damaged, best == nil); err != nil {
			return err
		}
	}
	if s.keys.Len() == 0 {
		s.log.Error("this build embeds no license verification key, so no license file can be installed; " +
			"the evaluation still works (see docs/vendor/licensing-vendor.md)")
	}
	return s.Tick(ctx)
}

// Shutdown saves the time record (spec §16.5: also on graceful shutdown).
func (s *Service) Shutdown(ctx context.Context) error { return s.persistHWM(ctx) }

// Inspect computes the current state without writing anything (alice license status).
func (s *Service) Inspect(ctx context.Context) (Snapshot, error) {
	if _, err := loadInstallation(ctx, s.pool, false); err != nil {
		return Snapshot{}, err
	}
	best, _, err := s.readHWM(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	var g Guard
	g.SetHWM(s.floor(best))
	reading, _ := g.Observe(s.clock.Now(), s.uptime.Elapsed())
	c, err := s.compute(ctx, s.pool, reading, false)
	if err != nil {
		return Snapshot{}, err
	}
	return c.snap, nil
}

func (s *Service) ensureInstallation(ctx context.Context) (bool, error) {
	now := later(s.clock.Now().UTC(), s.buildTime).Truncate(time.Microsecond)
	tag, err := s.pool.Exec(ctx, `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
VALUES (1, $1, $2, 'evaluation', $2) ON CONFLICT (id) DO NOTHING`, NewInstallationID(), now)
	if err != nil {
		return false, fmt.Errorf("create the installation: %w", err)
	}
	if tag.RowsAffected() == 1 {
		s.log.Info("new installation created; the 30-day evaluation starts now")
		return true, nil
	}
	return false, nil
}

// readHWM loads and decodes both stores. It returns the best valid record (the larger time,
// then the larger sequence), and the names of stores whose record is damaged or unreadable.
func (s *Service) readHWM(ctx context.Context) (*HWMRecord, []string, error) {
	var best *HWMRecord
	var damaged []string
	for _, st := range s.stores {
		raw, err := st.Load(ctx)
		if err != nil {
			if _, isFile := st.(FileHWMStore); !isFile {
				return nil, nil, err
			}
			s.log.Error("the time record file cannot be read; check the state volume", "error_type", fmt.Sprintf("%T", err))
			damaged = append(damaged, st.Name())
			continue
		}
		if raw == nil {
			continue
		}
		rec, err := s.codec.Decode(raw)
		if err != nil {
			damaged = append(damaged, st.Name())
			continue
		}
		if best == nil || rec.At.After(best.At) || (rec.At.Equal(best.At) && rec.Seq > best.Seq) {
			r := rec
			best = &r
		}
	}
	return best, damaged, nil
}

// floor is the starting HWM: the best record, never below the build time.
func (s *Service) floor(best *HWMRecord) HWMRecord {
	if best == nil {
		return HWMRecord{At: s.buildTime}
	}
	return HWMRecord{At: later(best.At, s.buildTime), Seq: best.Seq}
}

func (s *Service) recordTimeRecordProblem(ctx context.Context, damaged []string, missing bool) error {
	now := s.clock.Now().UTC()
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if len(damaged) > 0 {
			d := map[string]string{"problem": "hwm_damaged", "stores": strings.Join(damaged, ",")}
			if _, err := insertHistory(ctx, tx, now, "clock_anomaly", "", "", "", "", d); err != nil {
				return err
			}
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: "clock.hwm_damaged",
				ObjectType: "license", Result: audit.Failure, Details: d}); err != nil {
				return err
			}
		}
		if missing {
			d := map[string]string{"problem": "time_reference_reset"}
			if _, err := insertHistory(ctx, tx, now, "clock_anomaly", "", "", "", "", d); err != nil {
				return err
			}
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: "clock.time_reference_reset",
				ObjectType: "license", Result: audit.Failure, Details: d}); err != nil {
				return err
			}
		}
		return nil
	})
}

// persistHWM saves the next record to every store. A failing settings store is an error;
// a failing file is logged (the settings copy still protects the license).
func (s *Service) persistHWM(ctx context.Context) error {
	s.mu.Lock()
	rec := s.guard.NextRecord()
	s.mu.Unlock()
	raw, err := s.codec.Encode(rec)
	if err != nil {
		return err
	}
	var firstErr error
	for _, st := range s.stores {
		if err := st.Save(ctx, raw); err != nil {
			if _, isFile := st.(FileHWMStore); isFile {
				s.log.Error("the time record file cannot be written; check the state volume", "error_type", fmt.Sprintf("%T", err))
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("save the time record: %w", err)
			}
		}
	}
	return firstErr
}

// observe advances the guard with the current clock readings.
func (s *Service) observe() (Reading, []ClockEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.guard.Observe(s.clock.Now(), s.uptime.Elapsed())
}

// peek computes a reading without changing the guard.
func (s *Service) peek() Reading {
	s.mu.Lock()
	g := s.guard
	s.mu.Unlock()
	r, _ := g.Observe(s.clock.Now(), s.uptime.Elapsed())
	return r
}

type installationRow struct {
	ID          string
	InstalledAt time.Time
	State       Phase
	ClockJump   []byte
}

func loadInstallation(ctx context.Context, q db.Querier, forUpdate bool) (installationRow, error) {
	sql := "SELECT installation_id, installed_at, state, clock_jump FROM license WHERE id = 1"
	if forUpdate {
		sql += " FOR UPDATE"
	}
	var r installationRow
	var state string
	err := q.QueryRow(ctx, sql).Scan(&r.ID, &r.InstalledAt, &state, &r.ClockJump)
	if errors.Is(err, pgx.ErrNoRows) {
		return installationRow{}, ErrNoInstallation
	}
	if err != nil {
		return installationRow{}, fmt.Errorf("read the installation: %w", err)
	}
	r.State, r.InstalledAt = Phase(state), r.InstalledAt.UTC()
	return r, nil
}

// jumpRecord is the persisted form of a held clock jump (license.clock_jump).
type jumpRecord struct {
	Expected time.Time `json:"expected"`
	Detected time.Time `json:"detected"`
}

func decodeJump(raw []byte) (jumpRecord, bool) {
	var j jumpRecord
	if len(raw) == 0 || json.Unmarshal(raw, &j) != nil || j.Expected.IsZero() {
		return jumpRecord{}, false
	}
	return j, true
}

type storedFile struct {
	ID         uuid.UUID
	Seq        int64
	SHA256     []byte
	Raw        []byte
	UploadedAt time.Time
}

func loadFiles(ctx context.Context, q db.Querier) ([]storedFile, error) {
	rows, err := q.Query(ctx, "SELECT id, seq, sha256, raw_file, uploaded_at FROM license_files ORDER BY seq")
	if err != nil {
		return nil, fmt.Errorf("read license files: %w", err)
	}
	defer rows.Close()
	var out []storedFile
	for rows.Next() {
		var f storedFile
		if err := rows.Scan(&f.ID, &f.Seq, &f.SHA256, &f.Raw, &f.UploadedAt); err != nil {
			return nil, fmt.Errorf("read license files: %w", err)
		}
		f.UploadedAt = f.UploadedAt.UTC()
		out = append(out, f)
	}
	return out, rows.Err()
}

// verifyStored re-verifies a stored file (L-49): signature, payload and installation.
func (s *Service) verifyStored(f storedFile, installationID string) (Installed, error) {
	file, err := Check(f.Raw, s.keys)
	if err != nil {
		return Installed{}, err
	}
	if file.Payload.InstallationID != installationID {
		return Installed{}, &WrongInstallationError{Expected: IDSuffix(installationID), Got: IDSuffix(file.Payload.InstallationID)}
	}
	return Installed{Seq: f.Seq, KeyID: file.KeyID, Payload: file.Payload}, nil
}

// computed is one evaluation with the data it was made from.
type computed struct {
	snap      Snapshot
	row       installationRow
	files     []storedFile
	installed []Installed
}

// compute reads the installation and the files, re-verifies every file and evaluates the
// state at reading.Effective. Files that fail verification are left out; changed content
// (not a key this build no longer trusts) marks the snapshot as tampered.
func (s *Service) compute(ctx context.Context, q db.Querier, reading Reading, forUpdate bool) (computed, error) {
	row, err := loadInstallation(ctx, q, forUpdate)
	if err != nil {
		return computed{}, err
	}
	files, err := loadFiles(ctx, q)
	if err != nil {
		return computed{}, err
	}
	var installed []Installed
	tampered := false
	for _, f := range files {
		in, err := s.verifyStored(f, row.ID)
		if err != nil {
			if errors.Is(err, ErrInvalid) || errors.Is(err, ErrWrongInstallation) {
				tampered = true
			}
			continue
		}
		installed = append(installed, in)
	}
	targets, err := s.targets.CountTargets(ctx, q)
	if err != nil {
		return computed{}, fmt.Errorf("count targets: %w", err)
	}
	return computed{
		snap: Snapshot{
			InstallationID: row.ID,
			InstalledAt:    row.InstalledAt,
			Eval:           Evaluate(reading.Effective, row.InstalledAt, installed),
			Reading:        reading,
			Tampered:       tampered,
			Targets:        targets,
			Ready:          true,
		},
		row: row, files: files, installed: installed,
	}, nil
}

// insertHistory writes one history row. A notice that exists already for the license is
// skipped (unique index); inserted reports whether the row was written.
func insertHistory(ctx context.Context, tx pgx.Tx, at time.Time, event, licenseID, from, to, notice string, details map[string]string) (bool, error) {
	if details == nil {
		details = map[string]string{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return false, err
	}
	var n *string
	if notice != "" {
		n = &notice
	}
	tag, err := tx.Exec(ctx, `INSERT INTO license_history (id, at, event, license_id, from_state, to_state, notice, details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`, uuid.Must(uuid.NewV7()), at, event, licenseID, from, to, n, raw)
	if err != nil {
		return false, fmt.Errorf("write license history: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
```

Create `internal/license/tick.go`:

```go
package license

import "context"

// Tick observes the clock, re-verifies the stored files, recomputes the state and saves the
// time record. It runs at start, hourly (job license.evaluate), after every upload, and after
// the demo clock moves (e2e build).
func (s *Service) Tick(ctx context.Context) error {
	reading, _ := s.observe()
	c, err := s.compute(ctx, s.pool, reading, false)
	if err != nil {
		return err
	}
	s.setSnapshot(c.snap)
	return s.persistHWM(ctx)
}
```

- [ ] **Step 4: Implement upload and preview**

Create `internal/license/install.go`:

```go
package license

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// UploadResult describes an uploaded (or previewed) license.
type UploadResult struct {
	Payload        Payload
	KeyID          string
	Correction     bool  // replaces is set (R7)
	Pending        bool  // valid_from is still ahead (L-48)
	AlreadyExpired bool  // valid_until has passed; stored anyway (L-32, R36 item 8)
	Duplicate      bool  // this license is already installed; nothing changed
	Phase          Phase // the phase after the upload
}

// contentHash identifies a license independent of JSON formatting.
func contentHash(f File) []byte {
	h := sha256.New()
	h.Write(SignedBytes(f.Payload))
	h.Write(f.Signature)
	return h.Sum(nil)
}

// checkUpload runs spec §16.3 steps 1-5 on an upload.
func (s *Service) checkUpload(raw []byte, installationID string) (File, error) {
	if installationID == "" {
		return File{}, ErrNoInstallation
	}
	f, err := Check(raw, s.keys)
	if err != nil {
		return File{}, err
	}
	if f.Payload.InstallationID != installationID {
		return File{}, &WrongInstallationError{Expected: IDSuffix(installationID), Got: IDSuffix(f.Payload.InstallationID)}
	}
	return f, nil
}

// judge applies the replacement rules of §16.3 against the installed files: a duplicate is
// reported, an older license (earlier issued_at, not longer, not a correction) is refused.
func judge(f File, c computed, reading Reading) (UploadResult, error) {
	now := reading.Effective
	res := UploadResult{
		Payload:        f.Payload,
		KeyID:          f.KeyID,
		Correction:     f.Payload.Replaces != "",
		Pending:        f.Payload.ValidFrom.After(now),
		AlreadyExpired: !now.Before(f.Payload.ValidUntil),
		Phase:          c.snap.Eval.Phase,
	}
	hash := contentHash(f)
	for _, sf := range c.files {
		if bytes.Equal(sf.SHA256, hash) {
			res.Duplicate = true
			return res, nil
		}
	}
	if cur := c.snap.Eval.Current; cur != nil && !res.Correction &&
		f.Payload.IssuedAt.Before(cur.IssuedAt) && !f.Payload.ValidUntil.After(cur.ValidUntil) {
		return UploadResult{}, ErrOlderThanInstalled
	}
	next := int64(1)
	if n := len(c.files); n > 0 {
		next = c.files[n-1].Seq + 1
	}
	all := append(append([]Installed(nil), c.installed...), Installed{Seq: next, KeyID: f.KeyID, Payload: f.Payload})
	res.Phase = Evaluate(now, c.row.InstalledAt, all).Phase
	return res, nil
}

// Preview checks an upload exactly like Install and says what it would do, storing nothing.
func (s *Service) Preview(ctx context.Context, raw []byte) (UploadResult, error) {
	f, err := s.checkUpload(raw, s.Snapshot().InstallationID)
	if err != nil {
		return UploadResult{}, err
	}
	reading := s.peek()
	c, err := s.compute(ctx, s.pool, reading, false)
	if err != nil {
		return UploadResult{}, err
	}
	return judge(f, c, reading)
}

// Install stores an uploaded license and puts it into effect at once (spec §16.3 step 7, §19.1).
// Uploads are serialized by the license row lock. A rejected upload is recorded in the history
// and the audit log ("license.upload.<reason>") and leaves the installed license untouched.
// by is the uploading user (uuid.Nil for none).
func (s *Service) Install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (UploadResult, error) {
	res, err := s.install(ctx, raw, actor, by)
	if err != nil {
		if isRejection(err) {
			s.recordRejection(ctx, actor, err)
		}
		return UploadResult{}, err
	}
	if !res.Duplicate {
		if err := s.Tick(ctx); err != nil {
			return res, err
		}
	}
	return res, nil
}

func isRejection(err error) bool {
	for _, e := range []error{ErrInvalid, ErrUnsupportedFormat, ErrUnknownKey, ErrRevokedKey, ErrWrongInstallation, ErrOlderThanInstalled} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func (s *Service) install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (UploadResult, error) {
	f, err := s.checkUpload(raw, s.Snapshot().InstallationID)
	if err != nil {
		return UploadResult{}, err
	}
	s.mu.Lock()
	_, _, jumpHeld := s.guard.PendingJump()
	s.mu.Unlock()
	acceptJump := jumpHeld && f.Payload.Replaces != ""

	var res UploadResult
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		reading := s.peek()
		c, err := s.compute(ctx, tx, reading, true)
		if err != nil {
			return err
		}
		if res, err = judge(f, c, reading); err != nil || res.Duplicate {
			return err
		}
		now := s.clock.Now().UTC()
		seq := int64(1)
		if n := len(c.files); n > 0 {
			seq = c.files[n-1].Seq + 1
		}
		var uploadedBy *uuid.UUID
		if by != uuid.Nil {
			uploadedBy = &by
		}
		if _, err := tx.Exec(ctx, `INSERT INTO license_files (id, seq, sha256, raw_file, uploaded_at, uploaded_by)
VALUES ($1, $2, $3, $4, $5, $6)`, uuid.Must(uuid.NewV7()), seq, contentHash(f), raw, now, uploadedBy); err != nil {
			return fmt.Errorf("store the license file: %w", err)
		}
		from := c.snap.Eval.Phase
		event, action := "renewed", "license.renewed"
		if c.snap.Eval.Current == nil {
			event, action = "installed", "license.activated"
		}
		p := f.Payload
		details := map[string]string{
			"license_id":  p.LicenseID,
			"customer":    p.Customer,
			"valid_from":  formatTime(p.ValidFrom),
			"valid_until": formatTime(p.ValidUntil),
			"max_targets": strconv.Itoa(p.MaxTargets),
			"key_id":      f.KeyID,
			"from_state":  string(from),
			"to_state":    string(res.Phase),
			"pending":     strconv.FormatBool(res.Pending),
			"correction":  strconv.FormatBool(res.Correction),
		}
		if p.Replaces != "" {
			details["replaces"] = p.Replaces
		}
		if len(p.Features) > 0 {
			details["features"] = fmt.Sprint(p.Features) // unknown features are listed, never used (L-47)
		}
		if _, err := insertHistory(ctx, tx, now, event, p.LicenseID, string(from), string(res.Phase), "", details); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE license SET state = $1, updated_at = $2,
clock_jump = CASE WHEN $3 THEN NULL ELSE clock_jump END WHERE id = 1`, string(res.Phase), now, acceptJump); err != nil {
			return fmt.Errorf("update the license state: %w", err)
		}
		if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: action, ObjectType: "license",
			ObjectID: p.LicenseID, Result: audit.Success, Details: details}); err != nil {
			return err
		}
		if acceptJump {
			_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "clock.jump_accepted", ObjectType: "license",
				ObjectID: p.LicenseID, Result: audit.Success, Details: map[string]string{"reason": "correction_license"}})
			return err
		}
		return nil
	})
	if err != nil {
		return UploadResult{}, err
	}
	if acceptJump && !res.Duplicate {
		s.mu.Lock()
		s.guard.AcceptJump() // L-61: the vendor confirmed the new time
		s.mu.Unlock()
	}
	return res, nil
}

// recordRejection writes the history row and the audit entry of a refused upload.
func (s *Service) recordRejection(ctx context.Context, actor audit.Actor, cause error) {
	reason := RejectReason(cause)
	details := map[string]string{"reason": reason}
	var inv *InvalidError
	if errors.As(cause, &inv) {
		details["problem"] = inv.Problem
	}
	var wi *WrongInstallationError
	if errors.As(cause, &wi) {
		details["expected_suffix"], details["got_suffix"] = wi.Expected, wi.Got
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := insertHistory(ctx, tx, s.clock.Now().UTC(), "rejected", "", "", "", "", details); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "license.upload." + reason,
			ObjectType: "license", Result: audit.Failure, Details: details})
		return err
	})
	if err != nil {
		s.log.Error("recording a refused license upload failed", "error_type", fmt.Sprintf("%T", err))
	}
}
```

- [ ] **Step 5: Implement the detail view and banners**

Create `internal/license/detail.go`:

```go
package license

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// FileInfo is one stored upload as the License page lists it.
type FileInfo struct {
	ID         uuid.UUID
	Seq        int64
	UploadedAt time.Time
	Status     string // current | pending | superseded | invalid
	KeyID      string
	Payload    *Payload // nil when the file no longer verifies
}

// HistoryEntry is one license_history row.
type HistoryEntry struct {
	At        time.Time
	Event     string
	LicenseID string
	FromState string
	ToState   string
	Notice    string
	Details   map[string]string
}

// Detail is everything the License page shows.
type Detail struct {
	Snapshot Snapshot
	Files    []FileInfo     // newest first
	History  []HistoryEntry // newest first, at most historyLimit
}

const historyLimit = 100

// Detail reads the stored files and the recent history. It writes nothing.
func (s *Service) Detail(ctx context.Context) (Detail, error) {
	snap := s.Snapshot()
	files, err := loadFiles(ctx, s.pool)
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Snapshot: snap, Files: []FileInfo{}, History: []HistoryEntry{}}
	for i := len(files) - 1; i >= 0; i-- {
		f := files[i]
		info := FileInfo{ID: f.ID, Seq: f.Seq, UploadedAt: f.UploadedAt, Status: "superseded"}
		in, err := s.verifyStored(f, snap.InstallationID)
		switch {
		case err != nil:
			info.Status = "invalid"
		case f.Seq == snap.Eval.CurrentSeq:
			info.Status = "current"
		case f.Seq == snap.Eval.PendingSeq || f.Seq > snap.Eval.CurrentSeq:
			info.Status = "pending"
		}
		if err == nil {
			p := in.Payload
			info.Payload, info.KeyID = &p, in.KeyID
		}
		d.Files = append(d.Files, info)
	}
	rows, err := s.pool.Query(ctx, `SELECT at, event, license_id, from_state, to_state, coalesce(notice, ''), details
FROM license_history ORDER BY at DESC, id DESC LIMIT $1`, historyLimit)
	if err != nil {
		return Detail{}, fmt.Errorf("read license history: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h HistoryEntry
		var raw []byte
		if err := rows.Scan(&h.At, &h.Event, &h.LicenseID, &h.FromState, &h.ToState, &h.Notice, &raw); err != nil {
			return Detail{}, fmt.Errorf("read license history: %w", err)
		}
		h.At = h.At.UTC()
		if err := json.Unmarshal(raw, &h.Details); err != nil {
			return Detail{}, fmt.Errorf("read license history: %w", err)
		}
		d.History = append(d.History, h)
	}
	return d, rows.Err()
}
```

Create `internal/license/banners.go`:

```go
package license

import (
	"strconv"
	"time"
)

// Severity is the color of a banner: info (blue), warning (yellow), caution (orange), danger (red).
type Severity string

// Banner severities.
const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityCaution Severity = "caution"
	SeverityDanger  Severity = "danger"
)

// Banner is one license message for the page header. Kind selects the translated text
// (license.banner.<kind>); Params are its values (RFC 3339 times and decimal numbers).
type Banner struct {
	Kind     string
	Severity Severity
	Params   map[string]string
}

// Banners returns what a viewer sees (spec §19.3). Everyone sees the evaluation, grace, lock
// and evaluation-ended banners; only Administrators see expiry warnings (L-15), clock
// problems, damaged license data, pending licenses and the target limit.
func (s Snapshot) Banners(admin bool) []Banner {
	e := s.Eval
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	itoa := strconv.Itoa
	var out []Banner
	switch e.Phase {
	case PhaseEvaluation:
		sev := SeverityInfo
		if admin && e.Threshold > 0 {
			sev = SeverityWarning
			if e.Threshold <= 3 {
				sev = SeverityCaution
			}
		}
		out = append(out, Banner{Kind: "evaluation", Severity: sev, Params: map[string]string{
			"days_left": itoa(e.DaysLeft), "max_targets": itoa(e.MaxTargets), "ends_at": ts(e.EndsAt)}})
	case PhaseEvaluationExpired:
		out = append(out, Banner{Kind: "evaluation_ended", Severity: SeverityDanger, Params: map[string]string{"ended_at": ts(e.EndsAt)}})
	case PhaseActive:
		if admin && e.Threshold > 0 {
			sev := SeverityWarning
			if e.Threshold <= 7 {
				sev = SeverityCaution // at 7 and 1 days the banner turns orange (§19.3)
			}
			out = append(out, Banner{Kind: "expiry_warning", Severity: sev, Params: map[string]string{
				"days_left": itoa(e.DaysLeft), "valid_until": ts(e.EndsAt)}})
		}
	case PhaseGrace:
		out = append(out, Banner{Kind: "grace", Severity: SeverityDanger, Params: map[string]string{
			"valid_until": ts(e.EndsAt), "locks_at": ts(e.LocksAt), "grace_day": itoa(e.GraceDay)}})
	case PhaseLocked:
		out = append(out, Banner{Kind: "locked", Severity: SeverityDanger, Params: map[string]string{"valid_until": ts(e.EndsAt)}})
	}
	if !admin {
		return out
	}
	if s.Tampered {
		out = append(out, Banner{Kind: "tampered", Severity: SeverityDanger, Params: map[string]string{}})
	}
	if s.Reading.Behind {
		out = append(out, Banner{Kind: "clock_behind", Severity: SeverityCaution, Params: map[string]string{
			"system_time": ts(s.Reading.Wall), "last_seen": ts(s.Reading.Trusted)}})
	}
	if s.Reading.Jump != nil {
		out = append(out, Banner{Kind: "clock_jump", Severity: SeverityCaution, Params: map[string]string{
			"jump_days": itoa(int(s.Reading.Jump.By / day)), "system_time": ts(s.Reading.Wall)}})
	}
	if e.Pending != nil {
		out = append(out, Banner{Kind: "pending", Severity: SeverityInfo, Params: map[string]string{
			"valid_from": ts(e.Pending.ValidFrom), "license_id": e.Pending.LicenseID}})
	}
	switch {
	case e.OverLimit(s.Targets):
		out = append(out, Banner{Kind: "over_limit", Severity: SeverityWarning, Params: map[string]string{
			"used": itoa(s.Targets), "max": itoa(e.MaxTargets)}})
	case !e.Locked() && s.Targets > 0 && s.Targets == e.MaxTargets:
		out = append(out, Banner{Kind: "limit_reached", Severity: SeverityInfo, Params: map[string]string{"max": itoa(e.MaxTargets)}})
	}
	return out
}
```

- [ ] **Step 6: Add the static L-79 check**

Create `internal/archtest/targets_test.go`:

```go
package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var insertIntoTargets = regexp.MustCompile(`(?i)\binsert\s+into\s+targets\b`)

// targetInsertViolations lists the functions of f that insert into the targets table
// without calling CheckCanAddTarget (spec L-79: no code path may bypass the license limit).
func targetInsertViolations(fset *token.FileSet, f *ast.File) []string {
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		inserts, checks := false, false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind == token.STRING && insertIntoTargets.MatchString(x.Value) {
					inserts = true
				}
			case *ast.SelectorExpr:
				if x.Sel.Name == "CheckCanAddTarget" {
					checks = true
				}
			}
			return true
		})
		if inserts && !checks {
			out = append(out, fset.Position(fn.Pos()).String()+" "+fn.Name.Name)
		}
	}
	return out
}

func TestEveryTargetInsertChecksTheLicense(t *testing.T) {
	root := moduleRoot(t)
	scanned := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			scanned++
			for _, v := range targetInsertViolations(fset, f) {
				t.Errorf("%s inserts into targets without license.Service.CheckCanAddTarget (spec L-79)", v)
			}
			return nil
		})
		require.NoError(t, err)
	}
	require.Positive(t, scanned)
}

func TestTargetInsertCheckCatchesAMissingCall(t *testing.T) {
	src := `package x
func bad(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "INSERT INTO targets (id) VALUES ($1)", 1)
	return err
}
func good(ctx context.Context, tx pgx.Tx, l *license.Service) error {
	if err := l.CheckCanAddTarget(ctx, tx); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "insert into targets (id) values ($1)", 1)
	return err
}
func other(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "INSERT INTO target_locks (id) VALUES ($1)", 1)
	return err
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	require.NoError(t, err)
	v := targetInsertViolations(fset, f)
	require.Len(t, v, 1)
	assert.Contains(t, v[0], "bad")
}
```

- [ ] **Step 7: Run the tests**

Run:
```bash
go test -race -count=1 ./internal/license/... ./internal/archtest/
go test -race -count=1 -tags integration ./internal/license/...
```
Expected: PASS.

- [ ] **Step 8: Lint and commit**

Run: `make lint`
Expected: no findings.

```bash
git add internal/license/ internal/archtest/targets_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(license): license service with upload, gate and target check

The installation ID and timestamp are created on the first start; the time
record is loaded from settings and the state file (the larger valid record
wins; damaged or missing records are audited). Uploads are verified,
serialized by the license row lock, stored verbatim and take effect at once;
refused uploads are audited as license.upload.<reason>. Allow is the single
lock gate; CheckCanAddTarget counts and serializes adds in one transaction
(L-74) and a static test requires it before every targets insert (L-79).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 9: `Tick` — transitions, one-time notices, clock anomalies, tamper findings

The hourly evaluation (job `license.evaluate`, spec §8.2) and the effects §23 tests: a phase change is recorded
once (`license.expired` L-20, `license.locked` L-24, `license.evaluation_ended`); each warning threshold, grace
day and the lock produce exactly one Admin email and one `license.warning.sent` audit row, also across restarts
and missed ticks (L-11..L-18); a clock set back is audited once per day (L-51); a forward jump is audited, emailed
and persisted so its hold survives a restart (L-59..L-61); a damaged stored file is audited once (L-49).

**Files:**
- Modify: `internal/license/tick.go` (replace the whole file)
- Test: `internal/license/tick_integration_test.go`
- Modify: `internal/license/service_integration_test.go` (env gains `noMail`)

**Interfaces:**
- Consumes (Task 8): `computed`, `compute`, `insertHistory`, `loadInstallation`, `verifyStored`, `persistHWM`, `observe`, `systemActor`, `Notifier`, `jumpRecord`; Task 6 `ClockEvent`, `Reading`.
- Produces (`alice/internal/license`):
  - Template names `TemplateExpiryWarning = "license.expiry_warning"`, `TemplateEvaluationWarning = "license.evaluation_warning"`, `TemplateEvaluationEnded = "license.evaluation_ended"`, `TemplateGrace = "license.grace"`, `TemplateLocked = "license.locked"`, `TemplateClockJump = "license.clock_jump"`; `func Templates() []string`.
  - Email params (all strings): `installation_id`, `days_left`, `ends_at`, `locks_at` (format `2006-01-02 15:04 UTC`), plus `customer`, `license_id` when a license is in force, `grace_day` in grace, `jump_days`, `system_time` for a clock jump.
  - Notice keys in `license_history.notice`: `expiry:<60|30|14|7|1>`, `evaluation:<7|3|1>`, `evaluation_ended`, `grace:<1..7>`, `locked` (per license key), `clock_behind:<YYYY-MM-DD of the system clock>`, `tampered:<file id>` (license key `""`).
  - Audit actions: `license.expired`, `license.locked`, `license.evaluation_ended`, `license.state_changed`, `license.warning.sent`, `license.tampered`, `clock.rollback_detected`, `clock.forward_jump`, `clock.jump_accepted`, `clock.jump_cleared`.

- [ ] **Step 1: Let the test environment run without a notifier**

In `internal/license/service_integration_test.go` add the field `noMail bool` to `env` (after `notices`), and in `newService` replace `Notifier: e.notices,` with `Notifier: e.notifier(),` and add:

```go
// notifier returns the recording notifier, or none when the test runs without email (L-18).
func (e *env) notifier() license.Notifier {
	if e.noMail {
		return nil
	}
	return e.notices
}

// tickAt moves the fake clock to at (counting the time as uptime) and runs the hourly evaluation.
func (e *env) tickAt(at time.Time) {
	e.t.Helper()
	e.clk.Set(at)
	require.NoError(e.t, e.svc.Tick(e.ctx))
}
```

- [ ] **Step 2: Write the failing tick tests**

Create `internal/license/tick_integration_test.go`:

```go
//go:build integration

package license_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
)

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// L-10..L-13: one email per threshold, none in between, none before 60 days.
func TestNoticesAreSentOncePerThreshold(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)

	e.tickAt(until.Add(-61*day - 12*time.Hour))
	assert.Empty(t, e.notices.templates(), "L-10")
	for _, d := range []int{60, 30, 14, 7, 1} {
		at := until.Add(-time.Duration(d) * day)
		e.tickAt(at)
		for h := 1; h <= 3; h++ {
			e.tickAt(at.Add(time.Duration(h) * time.Hour)) // L-12: hourly ticks send nothing new
		}
	}
	assert.Equal(t, repeat(license.TemplateExpiryWarning, 5), e.notices.templates())
	assert.Equal(t, 5, e.auditCount("license.warning.sent"))
	assert.Equal(t, 5, e.countWhere("license_history", "event = 'notice' AND license_id = 'LIC-A' AND notice LIKE 'expiry:%'"))
	e.notices.mu.Lock()
	params := e.notices.calls[1]
	e.notices.mu.Unlock()
	assert.Equal(t, "30", params["days_left"])
	assert.Equal(t, "Test Company", params["customer"])
	assert.Equal(t, e.installation(), params["installation_id"])
	assert.Equal(t, until.UTC().Format("2006-01-02 15:04 UTC"), params["ends_at"])
}

// Review Focus 5 and L-16: after downtime only the current threshold is sent.
func TestCatchUpSendsOnlyTheCurrentThreshold(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-31 * day))
	e.clk.Set(until.Add(-29 * day)) // Alice was down for two days
	e.restart()
	assert.Equal(t, 2, len(e.notices.templates()))
	assert.Equal(t, 1, e.countWhere("license_history", "notice = 'expiry:60'"))
	assert.Equal(t, 1, e.countWhere("license_history", "notice = 'expiry:30'"))
	assert.Zero(t, e.countWhere("license_history", "notice IN ('expiry:14', 'expiry:7', 'expiry:1')"))

	e.restart() // L-14: a restart repeats nothing
	e.tickAt(until.Add(-29*day + time.Hour))
	assert.Equal(t, 2, len(e.notices.templates()))
}

// L-17, L-31: a renewal restarts the warnings from its own valid_until.
func TestRenewalRestartsWarnings(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-20 * day))
	require.Len(t, e.notices.templates(), 1)
	_, err = e.upload(e.payload("LIC-B", until.Add(-20*day), until.Add(345*day), 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-14 * day))
	assert.Len(t, e.notices.templates(), 1, "no 14-day warning of the replaced license")
	e.tickAt(until.Add(3 * day))
	assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)
}

// L-20..L-24: grace is announced daily, the lock once, each transition audited once.
func TestGraceAndLock(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-1 * day)) // the 1-day warning (the only one: catch-up sends the current threshold)
	e.tickAt(until)
	assert.Equal(t, "grace", e.state())
	for n := 2; n <= 7; n++ {
		e.tickAt(until.Add(time.Duration(n-1) * day))
		e.tickAt(until.Add(time.Duration(n-1)*day + 12*time.Hour))
	}
	require.NoError(t, e.svc.Allow(license.ClassChange), "grace: everything works (L-22)")
	e.tickAt(until.Add(168 * time.Hour))
	assert.Equal(t, "locked", e.state())
	e.restart()
	e.tickAt(until.Add(169 * time.Hour))

	want := append([]string{license.TemplateExpiryWarning}, repeat(license.TemplateGrace, 7)...)
	assert.Equal(t, append(want, license.TemplateLocked), e.notices.templates())
	assert.Equal(t, 1, e.auditCount("license.expired"), "L-20: once")
	assert.Equal(t, 1, e.auditCount("license.locked"), "L-24")
	assert.Equal(t, 2, e.countWhere("license_history", "event = 'state_change'"))
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked)
	assert.NoError(t, e.svc.Allow(license.ClassAlways))
}

// L-07 and L-03: evaluation warnings at 7, 3 and 1 days, then the end (no grace).
func TestEvaluationNotices(t *testing.T) {
	e := newEnv(t)
	for _, d := range []time.Duration{23 * day, 27 * day, 29 * day, 30 * day} {
		e.tickAt(installedAt.Add(d))
	}
	assert.Equal(t, append(repeat(license.TemplateEvaluationWarning, 3), license.TemplateEvaluationEnded), e.notices.templates())
	assert.Equal(t, 1, e.auditCount("license.evaluation_ended"))
	assert.Equal(t, "evaluation_expired", e.state())
	assert.Equal(t, 4, e.countWhere("license_history", "event = 'notice' AND license_id = 'evaluation'"))
}

// L-18: without email the banner and the record still appear; nobody sees an error.
func TestWithoutEmailTheBannerStillShows(t *testing.T) {
	e := newEnv(t)
	e.noMail = true
	e.restart()
	now := e.clk.Now()
	until := now.Add(100 * day)
	_, err := e.upload(e.payload("LIC-A", now, until, 10))
	require.NoError(t, err)
	e.tickAt(until.Add(-30 * day))
	assert.Empty(t, e.notices.templates())
	assert.Equal(t, 1, e.auditCount("license.warning.sent"))
	assert.Contains(t, kinds(e.svc.Snapshot().Banners(true)), "expiry_warning/warning")
}

// Review Focus 1, L-51: a clock set back never extends the license and is audited once a day.
func TestRollbackIsWarnedOncePerDay(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(15*day), 10))
	require.NoError(t, err)
	e.tickAt(now.Add(10 * day))

	e.clk.JumpWall(-20 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	snap := e.svc.Snapshot()
	assert.True(t, snap.Reading.Behind)
	assert.True(t, snap.Reading.Effective.Equal(now.Add(10*day)), "the high-water mark is used")
	assert.Equal(t, 5, snap.Eval.DaysLeft, "not extended")
	assert.Contains(t, kinds(snap.Banners(true)), "clock_behind/caution")
	assert.Equal(t, 1, e.auditCount("clock.rollback_detected"))

	e.clk.Advance(time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.Equal(t, 1, e.auditCount("clock.rollback_detected"), "once per day")
	assert.True(t, e.svc.Snapshot().Reading.Effective.Equal(now.Add(10*day+time.Hour)), "time keeps moving with uptime")
	e.clk.Advance(24 * time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.Equal(t, 2, e.auditCount("clock.rollback_detected"))
}

// Review Focus 1, L-58: restarts with the clock set back never move time backwards.
func TestRestartsNeverMoveEffectiveTimeBackwards(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(10 * day))
	last := e.svc.Snapshot().Reading.Effective
	for i := range 10 {
		e.clk.JumpWall(-24 * time.Hour)
		e.restart()
		eff := e.svc.Snapshot().Reading.Effective
		assert.False(t, eff.Before(last), "restart %d", i)
		last = eff
	}
	assert.False(t, last.Before(installedAt.Add(10*day)))
}

// L-59, L-60: a forward jump warns first, survives a restart, and counts after 24 h of uptime.
func TestForwardJumpIsHeldThenAccepted(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
	require.NoError(t, err)
	e.clk.Advance(time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))

	e.clk.JumpWall(200 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	snap := e.svc.Snapshot()
	require.NotNil(t, snap.Reading.Jump)
	assert.Equal(t, license.PhaseActive, snap.Eval.Phase, "warn first, no immediate lock")
	assert.Contains(t, kinds(snap.Banners(true)), "clock_jump/caution")
	assert.Equal(t, 1, e.auditCount("clock.forward_jump"))
	assert.Contains(t, e.notices.templates(), license.TemplateClockJump)
	assert.Equal(t, 1, e.countWhere("license", "clock_jump IS NOT NULL"))

	e.restart()
	assert.NotNil(t, e.svc.Snapshot().Reading.Jump, "the hold survives a restart")
	assert.Equal(t, license.PhaseActive, e.svc.Snapshot().Eval.Phase)

	e.clk.Advance(24 * time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))
	snap = e.svc.Snapshot()
	assert.Nil(t, snap.Reading.Jump)
	assert.Equal(t, license.PhaseLocked, snap.Eval.Phase, "L-60: the new time is accepted")
	assert.Equal(t, 1, e.auditCount("clock.jump_accepted"))
	assert.Zero(t, e.countWhere("license", "clock_jump IS NOT NULL"))
}

// L-61: a correction license ends the hold at once; the HWM stays at the new time.
func TestCorrectionLicenseAcceptsTheJump(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
	require.NoError(t, err)
	e.clk.Advance(time.Hour)
	require.NoError(t, e.svc.Tick(e.ctx))
	e.clk.JumpWall(200 * day)
	require.NoError(t, e.svc.Tick(e.ctx))
	jumped := e.clk.Now()

	fix := e.payload("LIC-FIX", jumped.Add(-time.Hour), jumped.Add(365*day), 10)
	fix.Replaces = "LIC-A"
	_, err = e.upload(fix)
	require.NoError(t, err)
	snap := e.svc.Snapshot()
	assert.Nil(t, snap.Reading.Jump)
	assert.Equal(t, license.PhaseActive, snap.Eval.Phase)
	assert.Equal(t, "LIC-FIX", snap.Eval.Key())
	assert.Equal(t, 1, e.auditCount("clock.jump_accepted"))
	raw, err := os.ReadFile(filepath.Join(e.stateDir, license.HWMFileName))
	require.NoError(t, err)
	rec, err := license.NewHWMCodec(e.keyring).Decode(raw)
	require.NoError(t, err)
	assert.False(t, rec.At.Before(jumped.Truncate(time.Second)), "no rollback of the HWM")
}

// L-49: a damaged stored file is audited once, however often it is evaluated.
func TestTamperedFileIsAuditedOnce(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(100*day), 10))
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE license_files SET raw_file =
		convert_to(replace(convert_from(raw_file, 'UTF8'), 'Test Company', 'Evil Company'), 'UTF8')`)
	require.NoError(t, err)
	for range 3 {
		e.clk.Advance(time.Hour)
		require.NoError(t, e.svc.Tick(e.ctx))
	}
	assert.Equal(t, 1, e.auditCount("license.tampered"))
	assert.Equal(t, license.PhaseEvaluation, e.svc.Snapshot().Eval.Phase)
	assert.True(t, e.svc.Snapshot().Tampered)
}

func TestShutdownSavesTheTimeRecord(t *testing.T) {
	e := newEnv(t)
	e.clk.Advance(30 * time.Minute)
	require.NoError(t, e.svc.Shutdown(e.ctx))
	raw, err := os.ReadFile(filepath.Join(e.stateDir, license.HWMFileName))
	require.NoError(t, err)
	rec, err := license.NewHWMCodec(e.keyring).Decode(raw)
	require.NoError(t, err)
	assert.True(t, rec.At.Equal(installedAt), "Shutdown stores the HWM as of the last observation")
	assert.Positive(t, rec.Seq)
}
```

Run: `go test -count=1 -tags integration -run 'Notice|CatchUp|Renewal|GraceAndLock|Evaluation|WithoutEmail|Rollback|Restarts|ForwardJump|Correction|Tampered|Shutdown' ./internal/license/`
Expected: FAIL — `undefined: license.TemplateExpiryWarning`, … (and, once compiling, no notices are sent by the Task 8 `Tick`).

- [ ] **Step 3: Replace `tick.go`**

Replace `internal/license/tick.go` with:

```go
package license

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/platform/db"
)

// Email templates sent to Administrators (rendered by notify from email.<template>.* in
// locales/common).
const (
	TemplateExpiryWarning     = "license.expiry_warning"
	TemplateEvaluationWarning = "license.evaluation_warning"
	TemplateEvaluationEnded   = "license.evaluation_ended"
	TemplateGrace             = "license.grace"
	TemplateLocked            = "license.locked"
	TemplateClockJump         = "license.clock_jump"
)

// Templates lists every email template of the license module.
func Templates() []string {
	return []string{TemplateExpiryWarning, TemplateEvaluationWarning, TemplateEvaluationEnded,
		TemplateGrace, TemplateLocked, TemplateClockJump}
}

// mailTime is how times appear in emails: unambiguous and language-neutral.
func mailTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// Tick observes the clock, re-verifies the stored files and recomputes the state. In one
// transaction holding the license row lock it then records a phase change, sends every due
// notice once, records clock events and damaged files. Finally it saves the time record.
// It runs at start, hourly (job license.evaluate), after each upload and after the e2e
// demo clock moves.
func (s *Service) Tick(ctx context.Context) error {
	reading, events := s.observe()
	var snap Snapshot
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		c, err := s.compute(ctx, tx, reading, true)
		if err != nil {
			return err
		}
		snap = c.snap
		now := s.clock.Now().UTC()
		if err := s.recordTransition(ctx, tx, c, now); err != nil {
			return err
		}
		if err := s.sendNotices(ctx, tx, c, now); err != nil {
			return err
		}
		if err := s.recordClockEvents(ctx, tx, c, reading, events, now); err != nil {
			return err
		}
		return s.recordTampered(ctx, tx, c, now)
	})
	if err != nil {
		return err
	}
	s.setSnapshot(snap)
	return s.persistHWM(ctx)
}

// recordTransition stores a phase change once: the cached state column, a history row and
// an audit row (license.expired when grace begins, L-20; license.locked, L-24).
func (s *Service) recordTransition(ctx context.Context, tx pgx.Tx, c computed, now time.Time) error {
	from, to := c.row.State, c.snap.Eval.Phase
	if from == to {
		return nil
	}
	if _, err := tx.Exec(ctx, "UPDATE license SET state = $1, updated_at = $2 WHERE id = 1", string(to), now); err != nil {
		return fmt.Errorf("update the license state: %w", err)
	}
	key := c.snap.Eval.Key()
	details := map[string]string{"from_state": string(from), "to_state": string(to), "license_id": key}
	if _, err := insertHistory(ctx, tx, now, "state_change", key, string(from), string(to), "", details); err != nil {
		return err
	}
	action := "license.state_changed"
	switch to {
	case PhaseGrace:
		action = "license.expired"
	case PhaseLocked:
		action = "license.locked"
	case PhaseEvaluationExpired:
		action = "license.evaluation_ended"
	}
	_, err := s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: action, ObjectType: "license",
		ObjectID: key, Result: audit.Success, Details: details})
	return err
}

type notice struct {
	key      string
	template string
	params   map[string]string
}

// dueNotice returns the notice of the current state, if any. Only the current threshold is
// due, so after downtime no burst of older warnings is sent (L-16).
func dueNotice(snap Snapshot) (notice, bool) {
	e := snap.Eval
	params := map[string]string{
		"installation_id": snap.InstallationID,
		"days_left":       strconv.Itoa(e.DaysLeft),
		"ends_at":         mailTime(e.EndsAt),
		"locks_at":        mailTime(e.LocksAt),
	}
	if e.Current != nil {
		params["customer"], params["license_id"] = e.Current.Customer, e.Current.LicenseID
	}
	switch {
	case e.Phase == PhaseEvaluation && e.Threshold > 0:
		return notice{"evaluation:" + strconv.Itoa(e.Threshold), TemplateEvaluationWarning, params}, true
	case e.Phase == PhaseEvaluationExpired:
		return notice{"evaluation_ended", TemplateEvaluationEnded, params}, true
	case e.Phase == PhaseActive && e.Threshold > 0:
		return notice{"expiry:" + strconv.Itoa(e.Threshold), TemplateExpiryWarning, params}, true
	case e.Phase == PhaseGrace:
		params["grace_day"] = strconv.Itoa(e.GraceDay)
		return notice{"grace:" + strconv.Itoa(e.GraceDay), TemplateGrace, params}, true // a daily email (§19.3)
	case e.Phase == PhaseLocked:
		return notice{"locked", TemplateLocked, params}, true
	}
	return notice{}, false
}

// sendNotices sends the due notice once per license: the unique history index decides, so
// hourly ticks, restarts and two processes never send it twice (L-12, L-14).
func (s *Service) sendNotices(ctx context.Context, tx pgx.Tx, c computed, now time.Time) error {
	n, ok := dueNotice(c.snap)
	if !ok {
		return nil
	}
	key := c.snap.Eval.Key()
	inserted, err := insertHistory(ctx, tx, now, "notice", key, "", "", n.key, map[string]string{"template": n.template})
	if err != nil || !inserted {
		return err
	}
	if s.notifier != nil {
		if err := s.notifier.NotifyAdmins(ctx, tx, n.template, n.params); err != nil {
			return fmt.Errorf("queue license email: %w", err)
		}
	}
	_, err = s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: "license.warning.sent", ObjectType: "license",
		ObjectID: key, Result: audit.Success, Details: map[string]string{"notice": n.key, "template": n.template}})
	return err
}

// recordClockEvents audits what the guard noticed: a clock set back (once per day of the
// system clock, L-51), a forward jump (history, audit, email, persisted hold; L-59), and
// the end of a hold (accepted after 24 h, or the clock was corrected).
func (s *Service) recordClockEvents(ctx context.Context, tx pgx.Tx, c computed, r Reading, events []ClockEvent, now time.Time) error {
	for _, ev := range events {
		switch ev {
		case EventRollback:
			d := map[string]string{"system_time": r.Wall.Format(time.RFC3339), "last_seen": r.Trusted.Format(time.RFC3339)}
			inserted, err := insertHistory(ctx, tx, now, "notice", "", "", "", "clock_behind:"+r.Wall.Format("2006-01-02"), d)
			if err != nil {
				return err
			}
			if inserted {
				if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: "clock.rollback_detected",
					ObjectType: "license", Result: audit.Failure, Details: d}); err != nil {
					return err
				}
			}
		case EventJumpDetected:
			if r.Jump == nil {
				continue
			}
			raw, err := json.Marshal(jumpRecord{Expected: r.Jump.Expected, Detected: r.Jump.Detected})
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "UPDATE license SET clock_jump = $1, updated_at = $2 WHERE id = 1", raw, now); err != nil {
				return fmt.Errorf("store the clock jump: %w", err)
			}
			d := map[string]string{"problem": "forward_jump", "jump_days": strconv.Itoa(int(r.Jump.By / day)),
				"system_time": r.Wall.Format(time.RFC3339)}
			if _, err := insertHistory(ctx, tx, now, "clock_anomaly", "", "", "", "", d); err != nil {
				return err
			}
			if s.notifier != nil {
				params := map[string]string{"installation_id": c.snap.InstallationID, "jump_days": d["jump_days"], "system_time": mailTime(r.Wall)}
				if err := s.notifier.NotifyAdmins(ctx, tx, TemplateClockJump, params); err != nil {
					return fmt.Errorf("queue clock email: %w", err)
				}
			}
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: "clock.forward_jump",
				ObjectType: "license", Result: audit.Failure, Details: d}); err != nil {
				return err
			}
		case EventJumpAccepted, EventJumpCleared:
			problem, action := "jump_accepted", "clock.jump_accepted"
			if ev == EventJumpCleared {
				problem, action = "jump_cleared", "clock.jump_cleared"
			}
			if _, err := tx.Exec(ctx, "UPDATE license SET clock_jump = NULL, updated_at = $1 WHERE id = 1", now); err != nil {
				return fmt.Errorf("clear the clock jump: %w", err)
			}
			d := map[string]string{"problem": problem, "system_time": r.Wall.Format(time.RFC3339)}
			if _, err := insertHistory(ctx, tx, now, "clock_anomaly", "", "", "", "", d); err != nil {
				return err
			}
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: action,
				ObjectType: "license", Result: audit.Success, Details: d}); err != nil {
				return err
			}
		}
	}
	return nil
}

// recordTampered audits each stored file that no longer verifies, once (L-49).
func (s *Service) recordTampered(ctx context.Context, tx pgx.Tx, c computed, now time.Time) error {
	if !c.snap.Tampered {
		return nil
	}
	for _, f := range c.files {
		_, err := s.verifyStored(f, c.row.ID)
		if err == nil || !(errors.Is(err, ErrInvalid) || errors.Is(err, ErrWrongInstallation)) {
			continue
		}
		d := map[string]string{"file_id": f.ID.String(), "seq": strconv.FormatInt(f.Seq, 10), "reason": RejectReason(err)}
		inserted, err := insertHistory(ctx, tx, now, "notice", "", "", "", "tampered:"+f.ID.String(), d)
		if err != nil {
			return err
		}
		if inserted {
			if _, err := s.audit.Append(ctx, tx, audit.Event{Actor: systemActor, Action: "license.tampered",
				ObjectType: "license", ObjectID: f.ID.String(), Result: audit.Failure, Details: d}); err != nil {
				return err
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run all license tests**

Run:
```bash
go test -race -count=1 ./internal/license/...
go test -race -count=1 -tags integration ./internal/license/...
```
Expected: PASS (the Task 8 tests too: uploads now also run the full `Tick`).

- [ ] **Step 5: Lint and commit**

Run: `make lint`
Expected: no findings.

```bash
git add internal/license/tick.go internal/license/tick_integration_test.go internal/license/service_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(license): hourly evaluation with one-time notices and clock anomalies

Tick records each phase change once (license.expired, license.locked,
license.evaluation_ended), sends the current warning, grace-day or lock
notice exactly once per license (unique history row), audits a clock set
back once per day and a forward jump (held, persisted, emailed), and audits
damaged stored files once. Only the current threshold is sent after
downtime.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 10: `notify` — outbox, sender and a minimal STARTTLS SMTP mailer

Spec §26.4 "warning emails through notify (email sender exists in minimal form)", §7.6 `notifications_outbox`,
§8.2 `notify.send`, F-60/F-61/F-63 in their Phase 2 form, and L-18. Emails are queued inside the transaction of
the change that causes them (the license `Tick`) and sent later with retries, so a mail problem never blocks work.
The SMTP connection must be encrypted (STARTTLS or implicit TLS, TLS ≥ 1.2, verified certificate); no plaintext
fallback exists. Configuration comes from the environment in Phase 2 (Task 15, R36 item 14).

**Files:**
- Create: `internal/notify/outbox.go`, `internal/notify/sender.go`, `internal/notify/smtp.go`
- Test: `internal/notify/smtp_test.go`, `internal/notify/render_test.go`, `internal/notify/outbox_integration_test.go`
- Modify: `locales/common/en.json`, `locales/common/tr.json` (new top-level `email` object)

**Interfaces:**
- Consumes: `i18n.Catalog.T`, `clock.Clock`, `db.InTx`, `secrets.Plaintext`; table `notifications_outbox` (Task 7); `users` (Phase 1).
- Produces (`alice/internal/notify`):
  - `type AdminNotifier struct{ Clock clock.Clock }`; `func (a AdminNotifier) NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error` (implements `license.Notifier`).
  - `type Message struct { To, Subject, Body string }`; `type Mailer interface { Send(ctx context.Context, m Message) error }`.
  - `type Sender struct { Pool *pgxpool.Pool; Mailer Mailer; Catalog *i18n.Catalog; Clock clock.Clock; Log *slog.Logger }` (`Mailer == nil` = SMTP not configured); `func (s *Sender) Drain(ctx context.Context) (int, error)`; `func (s *Sender) Render(to, template, locale string, params map[string]string) Message`; `const MaxAttempts = 10`.
  - `type SMTPConfig struct { Host string; Port int; From, Username string; Password secrets.Plaintext; TLSMode string; RootCAs *x509.CertPool }` (`TLSMode` `"starttls"` default or `"tls"`); `func NewSMTPMailer(c SMTPConfig, clk clock.Clock) (*SMTPMailer, error)`; `func (m *SMTPMailer) Send(ctx context.Context, msg Message) error`.
  - Errors `ErrSMTPConnect`, `ErrSMTPTLS`, `ErrSMTPAuth`, `ErrSMTPRejected`; `func ErrorCode(err error) string` → `smtp.connect|smtp.tls|smtp.auth|smtp.rejected|smtp.error` (stored in `last_error_code`; never server text).
- Produces (catalog keys, `locales/common`): `email.footer`, and `email.<template>.subject|body` for every `license.Templates()` entry.

- [ ] **Step 1: Write the failing SMTP tests**

Create `internal/notify/smtp_test.go`:

```go
package notify_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
)

const smtpPassword = "s3cret-smtp-pw"

type fakeMessage struct {
	from, to, data string
	secure, authed bool
}

// fakeSMTP is a minimal SMTP server: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA, QUIT.
type fakeSMTP struct {
	ln         net.Listener
	tlsConfig  *tls.Config
	pool       *x509.CertPool
	noStartTLS bool
	implicit   bool
	rejectRcpt bool

	mu       sync.Mutex
	messages []fakeMessage
	authSeen bool
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func newFakeSMTP(t *testing.T, opts ...func(*fakeSMTP)) *fakeSMTP {
	t.Helper()
	cert, pool := selfSigned(t)
	f := &fakeSMTP{tlsConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, pool: pool}
	for _, o := range opts {
		o(f)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	if f.implicit {
		ln = tls.NewListener(ln, f.tlsConfig)
	}
	f.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.session(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) got() []fakeMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMessage(nil), f.messages...)
}

func (f *fakeSMTP) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	tp := textproto.NewConn(c)
	secure, authed := f.implicit, false
	var from, to string
	_ = tp.PrintfLine("220 fake ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		switch verb := strings.Fields(line + " x")[0]; verb {
		case "EHLO", "HELO":
			_ = tp.PrintfLine("250-fake greets you")
			if !f.noStartTLS && !secure {
				_ = tp.PrintfLine("250-STARTTLS")
			}
			_ = tp.PrintfLine("250 AUTH PLAIN")
		case "STARTTLS":
			_ = tp.PrintfLine("220 go ahead")
			tc := tls.Server(c, f.tlsConfig)
			if tc.Handshake() != nil {
				return
			}
			c, tp, secure = tc, textproto.NewConn(tc), true
		case "AUTH":
			f.mu.Lock()
			f.authSeen = true
			f.mu.Unlock()
			parts := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			fields := strings.Split(string(raw), "\x00")
			if len(fields) == 3 && fields[1] == "alice" && fields[2] == smtpPassword {
				authed = true
				_ = tp.PrintfLine("235 ok")
			} else {
				_ = tp.PrintfLine("535 bad credentials")
			}
		case "MAIL":
			from = line
			_ = tp.PrintfLine("250 ok")
		case "RCPT":
			if f.rejectRcpt {
				_ = tp.PrintfLine("550 no such user")
				continue
			}
			to = line
			_ = tp.PrintfLine("250 ok")
		case "DATA":
			_ = tp.PrintfLine("354 go on")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.messages = append(f.messages, fakeMessage{from: from, to: to, data: string(data), secure: secure, authed: authed})
			f.mu.Unlock()
			_ = tp.PrintfLine("250 queued")
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("250 ok")
		}
	}
}

var mailClock = clock.NewFake(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))

func mailer(t *testing.T, f *fakeSMTP, change func(*notify.SMTPConfig)) *notify.SMTPMailer {
	t.Helper()
	c := notify.SMTPConfig{
		Host: "127.0.0.1", Port: f.port(), From: "Alice <alice@example.com>", Username: "alice",
		Password: secrets.NewPlaintext([]byte(smtpPassword)), RootCAs: f.pool,
	}
	if change != nil {
		change(&c)
	}
	m, err := notify.NewSMTPMailer(c, mailClock)
	require.NoError(t, err)
	return m
}

func send(m *notify.SMTPMailer, msg notify.Message) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return m.Send(ctx, msg)
}

func TestSMTPMailerSendsOverSTARTTLSWithAuth(t *testing.T) {
	f := newFakeSMTP(t)
	err := send(mailer(t, f, nil), notify.Message{To: "ada@example.com", Subject: "Lisans uyarısı", Body: "Merhaba\nİkinci satır"})
	require.NoError(t, err)
	got := f.got()
	require.Len(t, got, 1)
	assert.True(t, got[0].secure, "the message travels only after STARTTLS")
	assert.True(t, got[0].authed)
	assert.Contains(t, got[0].to, "ada@example.com")
	assert.Contains(t, got[0].data, "Subject: =?utf-8?q?Lisans_uyar=C4=B1s=C4=B1?=")
	assert.Contains(t, got[0].data, "Content-Transfer-Encoding: base64")
	// The fake reads DATA with textproto's dot reader, which turns CRLF into LF.
	body := strings.SplitN(got[0].data, "\n\n", 2)[1]
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\n", ""))
	require.NoError(t, err)
	assert.Equal(t, "Merhaba\r\nİkinci satır", string(decoded))
}

func TestSMTPMailerImplicitTLS(t *testing.T) {
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.implicit = true })
	require.NoError(t, send(mailer(t, f, func(c *notify.SMTPConfig) { c.TLSMode = "tls" }), notify.Message{To: "ada@example.com", Subject: "s", Body: "b"}))
	require.Len(t, f.got(), 1)
	assert.True(t, f.got()[0].secure)
}

// No plaintext fallback: without STARTTLS nothing is sent and the password never leaves.
func TestSMTPMailerRequiresTLS(t *testing.T) {
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.noStartTLS = true })
	err := send(mailer(t, f, nil), notify.Message{To: "ada@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPTLS)
	assert.Equal(t, "smtp.tls", notify.ErrorCode(err))
	assert.Empty(t, f.got())
	f.mu.Lock()
	assert.False(t, f.authSeen, "credentials are never sent unencrypted")
	f.mu.Unlock()
}

func TestSMTPMailerRejectsAnUntrustedCertificate(t *testing.T) {
	f := newFakeSMTP(t)
	err := send(mailer(t, f, func(c *notify.SMTPConfig) { c.RootCAs = x509.NewCertPool() }), notify.Message{To: "ada@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPTLS)
	assert.Empty(t, f.got())
}

func TestSMTPMailerFailures(t *testing.T) {
	f := newFakeSMTP(t)
	err := send(mailer(t, f, func(c *notify.SMTPConfig) { c.Password = secrets.NewPlaintext([]byte("wrong-smtp-pw")) }),
		notify.Message{To: "ada@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPAuth)
	assert.NotContains(t, err.Error(), "wrong-smtp-pw")

	r := newFakeSMTP(t, func(f *fakeSMTP) { f.rejectRcpt = true })
	err = send(mailer(t, r, nil), notify.Message{To: "nobody@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPRejected)

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := closed.Addr().(*net.TCPAddr).Port
	require.NoError(t, closed.Close())
	err = send(mailer(t, f, func(c *notify.SMTPConfig) { c.Port = port }), notify.Message{To: "ada@example.com", Subject: "s", Body: "b"})
	require.ErrorIs(t, err, notify.ErrSMTPConnect)
}

// Header injection through a subject is impossible.
func TestSMTPMailerKeepsTheSubjectOnOneLine(t *testing.T) {
	f := newFakeSMTP(t)
	require.NoError(t, send(mailer(t, f, nil), notify.Message{To: "ada@example.com", Subject: "Hi\r\nBcc: evil@example.com", Body: "b"}))
	for _, line := range strings.Split(f.got()[0].data, "\n") {
		assert.False(t, strings.HasPrefix(line, "Bcc:"), line)
	}
}

func TestNewSMTPMailerValidatesItsConfiguration(t *testing.T) {
	good := notify.SMTPConfig{Host: "mail.example.com", Port: 587, From: "alice@example.com"}
	_, err := notify.NewSMTPMailer(good, mailClock)
	require.NoError(t, err)
	for name, change := range map[string]func(*notify.SMTPConfig){
		"no host":     func(c *notify.SMTPConfig) { c.Host = "" },
		"bad host":    func(c *notify.SMTPConfig) { c.Host = "mail example" },
		"port 0":      func(c *notify.SMTPConfig) { c.Port = 0 },
		"port 70000":  func(c *notify.SMTPConfig) { c.Port = 70000 },
		"bad sender":  func(c *notify.SMTPConfig) { c.From = "not an address" },
		"plain mode":  func(c *notify.SMTPConfig) { c.TLSMode = "none" },
	} {
		c := good
		change(&c)
		_, err := notify.NewSMTPMailer(c, mailClock)
		assert.Error(t, err, name)
	}
}
```

Run: `go test -count=1 ./internal/notify/`
Expected: FAIL — `no non-test Go files in …/internal/notify`.

- [ ] **Step 2: Implement the SMTP mailer**

Create `internal/notify/smtp.go`:

```go
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"alice/internal/platform/clock"
	"alice/internal/secrets"
)

// Classified SMTP failures. The server's own text is never kept: it may echo addresses
// or, for some servers, parts of the credentials.
var (
	ErrSMTPConnect  = errors.New("notify: cannot connect to the mail server")
	ErrSMTPTLS      = errors.New("notify: the mail server's encryption failed or is not offered")
	ErrSMTPAuth     = errors.New("notify: the mail server rejected the user name or password")
	ErrSMTPRejected = errors.New("notify: the mail server refused the message")
)

// ErrorCode is the fixed label of a send failure (notifications_outbox.last_error_code).
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrSMTPConnect):
		return "smtp.connect"
	case errors.Is(err, ErrSMTPTLS):
		return "smtp.tls"
	case errors.Is(err, ErrSMTPAuth):
		return "smtp.auth"
	case errors.Is(err, ErrSMTPRejected):
		return "smtp.rejected"
	default:
		return "smtp.error"
	}
}

// SMTPConfig configures the mailer (Phase 2: from ALICE_SMTP_* variables, R36 item 14).
type SMTPConfig struct {
	Host     string
	Port     int
	From     string
	Username string // "" = no authentication
	Password secrets.Plaintext
	TLSMode  string         // "starttls" (default, port 587) or "tls" (implicit TLS, port 465)
	RootCAs  *x509.CertPool // nil = the system's trusted roots
}

// SMTPMailer sends email over an encrypted SMTP connection. There is no plaintext mode.
type SMTPMailer struct {
	cfg   SMTPConfig
	from  *mail.Address
	clock clock.Clock
}

// NewSMTPMailer validates c.
func NewSMTPMailer(c SMTPConfig, clk clock.Clock) (*SMTPMailer, error) {
	if c.Host == "" || strings.ContainsAny(c.Host, " \t\r\n/") {
		return nil, errors.New("notify: the SMTP host is not valid")
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, errors.New("notify: the SMTP port must be between 1 and 65535")
	}
	if c.TLSMode == "" {
		c.TLSMode = "starttls"
	}
	if c.TLSMode != "starttls" && c.TLSMode != "tls" {
		return nil, errors.New(`notify: the SMTP TLS mode must be "starttls" or "tls"`)
	}
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return nil, errors.New("notify: the SMTP sender address is not valid")
	}
	return &SMTPMailer{cfg: c, from: from, clock: clk}, nil
}

// Send delivers one message: TCP, TLS (implicit or STARTTLS, required), optional
// AUTH PLAIN, then MAIL/RCPT/DATA. ctx bounds the whole exchange.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	to, err := mail.ParseAddress(msg.To)
	if err != nil {
		return fmt.Errorf("%w: the recipient address is not valid", ErrSMTPRejected)
	}
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("%w (%s)", ErrSMTPConnect, addr)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsCfg := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: m.cfg.RootCAs}
	if m.cfg.TLSMode == "tls" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return ErrSMTPTLS
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return ErrSMTPConnect
	}
	defer func() { _ = c.Close() }()
	if m.cfg.TLSMode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%w: STARTTLS is not offered", ErrSMTPTLS)
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return ErrSMTPTLS
		}
	}
	if m.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, string(m.cfg.Password.Bytes()), m.cfg.Host)); err != nil {
			return ErrSMTPAuth
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return ErrSMTPRejected
	}
	if err := c.Rcpt(to.Address); err != nil {
		return ErrSMTPRejected
	}
	w, err := c.Data()
	if err != nil {
		return ErrSMTPRejected
	}
	if _, err := w.Write(m.compose(to, msg)); err != nil {
		return ErrSMTPRejected
	}
	if err := w.Close(); err != nil {
		return ErrSMTPRejected
	}
	_ = c.Quit() // the message is accepted; a failing QUIT changes nothing
	return nil
}

// compose builds a plain-text UTF-8 message. The subject is kept on one line and
// Q-encoded; the body is base64 so any language and line length is safe.
func (m *SMTPMailer) compose(to *mail.Address, msg Message) []byte {
	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", m.from.String())
	header("To", to.String())
	header("Subject", mime.QEncoding.Encode("utf-8", oneLine(msg.Subject)))
	header("Date", m.clock.Now().Format(time.RFC1123Z))
	header("Message-ID", "<"+uuid.NewString()+"@alice.invalid>")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=UTF-8")
	header("Content-Transfer-Encoding", "base64")
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(msg.Body, "\n", "\r\n")))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}

// oneLine collapses all whitespace, including CR and LF, to single spaces.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
```

Create `internal/notify/sender.go` (the types the mailer uses; the sender follows in Step 5):

```go
package notify

import "context"

// Message is one email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Mailer delivers a message.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}
```

Run: `go test -race -count=1 ./internal/notify/`
Expected: PASS (7 tests).

- [ ] **Step 3: Add the email texts**

In `locales/common/en.json` add as the last top-level member (after `"validation"`, with a comma after its closing brace):

```json
  "email": {
    "footer": "This message was sent automatically by Alice. Do not reply to it.",
    "license": {
      "expiry_warning": {
        "subject": "Alice license expires on {{ends_at}}",
        "body": "Your Alice license for {{customer}} (license {{license_id}}) expires on {{ends_at}}.\n\nTo renew it, send your Installation ID {{installation_id}} to your vendor, then upload the new license file on the License page in Alice. Until then everything keeps working."
      },
      "evaluation_warning": {
        "subject": "Alice evaluation ends on {{ends_at}}",
        "body": "The 30-day evaluation of Alice ends on {{ends_at}}. After that, Alice pauses automatic tasks and refuses changes to your servers until a license is installed. Your data is kept.\n\nTo buy a license, send your Installation ID {{installation_id}} to your vendor."
      },
      "evaluation_ended": {
        "subject": "Alice evaluation has ended",
        "body": "The evaluation of Alice ended on {{ends_at}}. Automatic tasks are paused and changes to your servers are refused. Your data is safe.\n\nUpload a license on the License page. Your Installation ID is {{installation_id}}."
      },
      "grace": {
        "subject": "Alice license expired: automatic tasks stop on {{locks_at}}",
        "body": "Your Alice license {{license_id}} for {{customer}} expired on {{ends_at}}. Everything still works during the 7-day grace period (grace day {{grace_day}} of 7). On {{locks_at}} Alice pauses automatic tasks.\n\nContact your vendor now and upload the renewed license on the License page. Your Installation ID is {{installation_id}}."
      },
      "locked": {
        "subject": "Alice license expired: automatic tasks are paused",
        "body": "The grace period of your Alice license {{license_id}} ended on {{locks_at}}. Automatic tasks are paused and changes to your servers are refused. Your data is safe, and certificate expiry alerts still arrive by email.\n\nUpload a new license on the License page to continue. Your Installation ID is {{installation_id}}."
      },
      "clock_jump": {
        "subject": "Alice: the server clock jumped forward",
        "body": "The clock of the Alice server jumped forward by {{jump_days}} days (it now shows {{system_time}}). For the next 24 hours Alice keeps using the previous time for license checks.\n\nIf the new time is wrong, correct the server clock. If it is right, nothing needs to be done; you may ask your vendor for a correction license. Your Installation ID is {{installation_id}}."
      }
    }
  }
```

In `locales/common/tr.json` add at the same place:

```json
  "email": {
    "footer": "Bu ileti Alice tarafından otomatik olarak gönderildi. Lütfen yanıtlamayın.",
    "license": {
      "expiry_warning": {
        "subject": "Alice lisansının süresi doluyor: {{ends_at}}",
        "body": "{{customer}} için Alice lisansınızın ({{license_id}}) süresi şu tarihte doluyor: {{ends_at}}.\n\nYenilemek için Kurulum Kimliğinizi ({{installation_id}}) satıcınıza gönderin, ardından yeni lisans dosyasını Alice'teki Lisans sayfasından yükleyin. O zamana kadar her şey çalışmaya devam eder."
      },
      "evaluation_warning": {
        "subject": "Alice deneme süresi bitiyor: {{ends_at}}",
        "body": "Alice'in 30 günlük deneme süresi şu tarihte bitiyor: {{ends_at}}. Bundan sonra bir lisans yüklenene kadar Alice otomatik işleri duraklatır ve sunucularınızdaki değişiklikleri reddeder. Verileriniz korunur.\n\nLisans almak için Kurulum Kimliğinizi ({{installation_id}}) satıcınıza gönderin."
      },
      "evaluation_ended": {
        "subject": "Alice deneme süresi sona erdi",
        "body": "Alice'in deneme süresi şu tarihte sona erdi: {{ends_at}}. Otomatik işler duraklatıldı ve sunucularınızdaki değişiklikler reddediliyor. Verileriniz güvende.\n\nLisans sayfasından bir lisans yükleyin. Kurulum Kimliğiniz: {{installation_id}}."
      },
      "grace": {
        "subject": "Alice lisansının süresi doldu: otomatik işler duracak ({{locks_at}})",
        "body": "{{customer}} için Alice lisansınızın ({{license_id}}) süresi şu tarihte doldu: {{ends_at}}. 7 günlük ek süre boyunca her şey çalışmaya devam eder (ek süre günü: {{grace_day}} / 7). Alice otomatik işleri şu tarihte duraklatacak: {{locks_at}}.\n\nHemen satıcınızla iletişime geçin ve yenilenen lisansı Lisans sayfasından yükleyin. Kurulum Kimliğiniz: {{installation_id}}."
      },
      "locked": {
        "subject": "Alice lisansının süresi doldu: otomatik işler duraklatıldı",
        "body": "Alice lisansınızın ({{license_id}}) ek süresi şu tarihte sona erdi: {{locks_at}}. Otomatik işler duraklatıldı ve sunucularınızdaki değişiklikler reddediliyor. Verileriniz güvende; sertifika süresi uyarıları e-postayla gelmeye devam ediyor.\n\nDevam etmek için Lisans sayfasından yeni bir lisans yükleyin. Kurulum Kimliğiniz: {{installation_id}}."
      },
      "clock_jump": {
        "subject": "Alice: sunucu saati ileri atladı",
        "body": "Alice sunucusunun saati {{jump_days}} gün ileri atladı (şu anda gösterdiği zaman: {{system_time}}). Alice sonraki 24 saat boyunca lisans denetimlerinde önceki zamanı kullanır.\n\nYeni saat yanlışsa sunucu saatini düzeltin. Doğruysa bir şey yapmanız gerekmez; isterseniz satıcınızdan bir düzeltme lisansı isteyin. Kurulum Kimliğiniz: {{installation_id}}."
      }
    }
  }
```

Run: `make i18n-check`
Expected: `OK` (same keys and placeholders in both catalogs).

- [ ] **Step 4: Write the failing render and outbox tests**

Create `internal/notify/render_test.go`:

```go
package notify_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/locales"
)

// Every license template exists in English and Turkish and uses only the params the
// license module sends.
func TestEveryLicenseTemplateRendersInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{
		"installation_id": "ALICE-7F3K-9Q2M-XD41-B8TC", "days_left": "30", "ends_at": "2027-10-01 00:00 UTC",
		"locks_at": "2027-10-08 00:00 UTC", "customer": "Örnek Bankası A.Ş.", "license_id": "LIC-2026-000123",
		"grace_day": "3", "jump_days": "200", "system_time": "2028-04-18 09:00 UTC",
	}
	for _, tpl := range license.Templates() {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			assert.NotContains(t, m.Subject, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Body, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.Contains(t, m.Body, "ALICE-7F3K-9Q2M-XD41-B8TC", "%s %s", tpl, lang)
		}
	}
	tr := s.Render("ada@example.com", license.TemplateLocked, "tr", params)
	assert.Contains(t, tr.Body, "Lütfen yanıtlamayın.", "the footer is in the person's language")
}

func TestRenderKeepsParamsOnOneLine(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	m := (&notify.Sender{Catalog: cat}).Render("ada@example.com", license.TemplateExpiryWarning, "en",
		map[string]string{"ends_at": "tomorrow\r\nBcc: evil@example.com"})
	assert.NotContains(t, m.Subject, "\n")
	assert.NotContains(t, m.Body, "\nBcc:")
}
```

Create `internal/notify/outbox_integration_test.go`:

```go
//go:build integration

package notify_test

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/testutil/pgtest"
	"alice/locales"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

func addUser(t *testing.T, d *pgtest.DB, username, role, email, locale string, disabled bool) {
	t.Helper()
	var disabledAt *time.Time
	if disabled {
		now := time.Now()
		disabledAt = &now
	}
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, email, password_hash, role, locale, disabled_at, created_at, updated_at)
VALUES ($1, $2, $2, $3, '$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$aGFzaA', $4, $5, $6, now(), now())`,
		uuid.Must(uuid.NewV7()), username, email, role, locale, disabledAt)
	require.NoError(t, err)
}

func queue(t *testing.T, d *pgtest.DB, clk clock.Clock, template string) {
	t.Helper()
	require.NoError(t, db.InTx(context.Background(), d.App, func(tx pgx.Tx) error {
		return notify.AdminNotifier{Clock: clk}.NotifyAdmins(context.Background(), tx, template,
			map[string]string{"installation_id": "ALICE-X", "ends_at": "2027-10-01 00:00 UTC"})
	}))
}

func statuses(t *testing.T, d *pgtest.DB) map[string]int {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), "SELECT status, count(*) FROM notifications_outbox GROUP BY status")
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		require.NoError(t, rows.Scan(&s, &n))
		out[s] = n
	}
	return out
}

type fakeMailer struct {
	mu    sync.Mutex
	fail  int // fail this many sends first
	sent  map[string]int
	calls int
}

func (f *fakeMailer) Send(_ context.Context, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail > 0 {
		f.fail--
		return notify.ErrSMTPConnect
	}
	if f.sent == nil {
		f.sent = map[string]int{}
	}
	f.sent[m.To+"|"+m.Subject]++
	return nil
}

func sender(t *testing.T, d *pgtest.DB, clk clock.Clock, m notify.Mailer) *notify.Sender {
	t.Helper()
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	return &notify.Sender{Pool: d.App, Mailer: m, Catalog: cat, Clock: clk, Log: slog.New(slog.DiscardHandler)}
}

var start = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func TestNotifyAdminsQueuesOneEmailPerEnabledAdminWithAnAddress(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "tr", false)
	addUser(t, d, "noemail", "admin", "", "en", false)
	addUser(t, d, "gone", "admin", "gone@example.com", "en", true)
	addUser(t, d, "otto", "operator", "otto@example.com", "en", false)
	queue(t, d, clk, license.TemplateExpiryWarning)

	var to, locale, tpl string
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		"SELECT to_address, locale, template_key FROM notifications_outbox").Scan(&to, &locale, &tpl))
	assert.Equal(t, "ayse@example.com", to)
	assert.Equal(t, "tr", locale)
	assert.Equal(t, license.TemplateExpiryWarning, tpl)
	assert.Equal(t, map[string]int{"pending": 1}, statuses(t, d))

	err := db.InTx(context.Background(), d.App, func(tx pgx.Tx) error {
		return notify.AdminNotifier{Clock: clk}.NotifyAdmins(context.Background(), tx, "Bad Template", nil)
	})
	assert.Error(t, err)
}

// L-18: without SMTP nothing fails; the email is recorded as skipped.
func TestDrainWithoutSMTPSkips(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, d, clk, license.TemplateGrace)
	n, err := sender(t, d, clk, nil).Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, map[string]int{"skipped_no_smtp": 1}, statuses(t, d))
}

// F-60 in its Phase 2 form: retries with backoff, then delivered exactly once.
func TestDrainRetriesWithBackoff(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, d, clk, license.TemplateLocked)
	m := &fakeMailer{fail: 2}
	s := sender(t, d, clk, m)

	_, err := s.Drain(context.Background())
	require.NoError(t, err)
	var attempts int
	var next time.Time
	var code string
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		"SELECT attempts, next_attempt_at, last_error_code FROM notifications_outbox").Scan(&attempts, &next, &code))
	assert.Equal(t, 1, attempts)
	assert.True(t, next.Equal(start.Add(30*time.Second)))
	assert.Equal(t, "smtp.connect", code)

	n, err := s.Drain(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "not due yet")
	clk.Advance(30 * time.Second)
	_, err = s.Drain(context.Background())
	require.NoError(t, err)
	require.NoError(t, d.Owner.QueryRow(context.Background(), "SELECT next_attempt_at FROM notifications_outbox").Scan(&next))
	assert.True(t, next.Equal(start.Add(90*time.Second)), "the second retry waits twice as long")
	clk.Advance(time.Minute)
	_, err = s.Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"sent": 1}, statuses(t, d))
	assert.Len(t, m.sent, 1)
}

func TestDrainGivesUpAfterMaxAttempts(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	addUser(t, d, "ayse", "admin", "ayse@example.com", "en", false)
	queue(t, d, clk, license.TemplateLocked)
	s := sender(t, d, clk, &fakeMailer{fail: 1000})
	for range notify.MaxAttempts {
		_, err := s.Drain(context.Background())
		require.NoError(t, err)
		clk.Advance(time.Hour)
	}
	assert.Equal(t, map[string]int{"failed": 1}, statuses(t, d))
}

// Two drains at once (for example during an update) never send an email twice.
func TestConcurrentDrainsSendEachEmailOnce(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(start)
	for i := range 5 {
		addUser(t, d, "admin"+string(rune('a'+i)), "admin", "admin"+string(rune('a'+i))+"@example.com", "en", false)
	}
	for _, tpl := range license.Templates() {
		queue(t, d, clk, tpl)
	}
	m := &fakeMailer{}
	s := sender(t, d, clk, m)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Drain(context.Background())
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Equal(t, 30, m.calls, "6 templates x 5 admins")
	for k, n := range m.sent {
		assert.Equal(t, 1, n, k)
	}
	assert.Equal(t, map[string]int{"sent": 30}, statuses(t, d))
}
```

Run: `go test -count=1 ./internal/notify/ && go test -count=1 -tags integration ./internal/notify/`
Expected: FAIL — `undefined: notify.Sender`, `notify.AdminNotifier`.

- [ ] **Step 5: Implement the outbox and the sender**

Create `internal/notify/outbox.go`:

```go
// Package notify queues and sends Alice's emails. An email is queued in
// notifications_outbox inside the transaction of the change that causes it and is sent
// later by Sender (job notify.send), so mail trouble never blocks or undoes work
// (spec §7.6, §8.2).
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/clock"
)

var templatePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// AdminNotifier queues emails to Administrators. It implements license.Notifier.
type AdminNotifier struct{ Clock clock.Clock }

// NotifyAdmins queues template for every enabled Administrator with an email address,
// in the person's language, inside tx.
func (a AdminNotifier) NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error {
	if !templatePattern.MatchString(template) {
		return fmt.Errorf("notify: %q is not a template name", template)
	}
	if params == nil {
		params = map[string]string{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT email::text, locale FROM users
WHERE role = 'admin' AND disabled_at IS NULL AND email <> '' ORDER BY username`)
	if err != nil {
		return fmt.Errorf("notify: read administrators: %w", err)
	}
	type recipient struct{ email, locale string }
	var rcpts []recipient
	for rows.Next() {
		var r recipient
		if err := rows.Scan(&r.email, &r.locale); err != nil {
			rows.Close()
			return fmt.Errorf("notify: read administrators: %w", err)
		}
		rcpts = append(rcpts, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("notify: read administrators: %w", err)
	}
	now := a.Clock.Now().UTC()
	for _, r := range rcpts {
		if _, err := tx.Exec(ctx, `INSERT INTO notifications_outbox
(id, kind, to_address, template_key, params, locale, status, attempts, next_attempt_at, created_at)
VALUES ($1, 'email', $2, $3, $4, $5, 'pending', 0, $6, $6)`, uuid.Must(uuid.NewV7()), r.email, template, raw, r.locale, now); err != nil {
			return fmt.Errorf("notify: queue email: %w", err)
		}
	}
	return nil
}
```

Replace `internal/notify/sender.go` with:

```go
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
)

// Message is one email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Mailer delivers a message.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// Retry policy: 30 s, then doubling up to 30 min, at most MaxAttempts sends (about 2.5 hours).
const (
	MaxAttempts = 10
	baseBackoff = 30 * time.Second
	maxBackoff  = 30 * time.Minute
	sendTimeout = 60 * time.Second
)

// Sender drains the outbox.
type Sender struct {
	Pool    *pgxpool.Pool
	Mailer  Mailer // nil = SMTP is not configured: emails are recorded as skipped_no_smtp (L-18)
	Catalog *i18n.Catalog
	Clock   clock.Clock
	Log     *slog.Logger
}

// Drain handles every due email (sent, skipped, retried or given up) and returns how many.
// Rows are claimed with FOR UPDATE SKIP LOCKED, so parallel drains never send twice.
func (s *Sender) Drain(ctx context.Context) (int, error) {
	n := 0
	for {
		handled, err := s.one(ctx)
		if err != nil {
			return n, err
		}
		if !handled {
			return n, nil
		}
		n++
	}
}

func (s *Sender) one(ctx context.Context) (bool, error) {
	handled := false
	err := db.InTx(ctx, s.Pool, func(tx pgx.Tx) error {
		now := s.Clock.Now().UTC()
		var (
			id                 uuid.UUID
			to, tpl, locale    string
			raw                []byte
			attempts           int
		)
		err := tx.QueryRow(ctx, `SELECT id, to_address, template_key, params, locale, attempts FROM notifications_outbox
WHERE status = 'pending' AND next_attempt_at <= $1 ORDER BY next_attempt_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`, now).
			Scan(&id, &to, &tpl, &raw, &locale, &attempts)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("notify: read the outbox: %w", err)
		}
		handled = true
		if s.Mailer == nil {
			_, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'skipped_no_smtp', last_error_code = 'smtp.not_configured'
WHERE id = $1`, id)
			return err
		}
		var params map[string]string
		if err := json.Unmarshal(raw, &params); err != nil {
			_, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'failed', last_error_code = 'template.params' WHERE id = $1`, id)
			return err
		}
		sendCtx, cancel := context.WithTimeout(ctx, sendTimeout)
		sendErr := s.Mailer.Send(sendCtx, s.Render(to, tpl, locale, params))
		cancel()
		attempts++
		if sendErr == nil {
			_, err := tx.Exec(ctx, `UPDATE notifications_outbox SET status = 'sent', sent_at = $2, attempts = $3, last_error_code = ''
WHERE id = $1`, id, now, attempts)
			return err
		}
		code := ErrorCode(sendErr)
		s.log().Warn("email not sent; it will be retried", "outbox_id", id.String(), "attempt", attempts, "reason", code)
		status := "pending"
		if attempts >= MaxAttempts {
			status = "failed"
		}
		_, err = tx.Exec(ctx, `UPDATE notifications_outbox SET status = $2, attempts = $3, next_attempt_at = $4, last_error_code = $5
WHERE id = $1`, id, status, attempts, now.Add(backoff(attempts)), code)
		return err
	})
	return handled, err
}

func (s *Sender) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

func backoff(attempt int) time.Duration {
	d := baseBackoff
	for i := 1; i < attempt && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// Render builds the email for template in locale (falling back to English). Every
// parameter is flattened to one line, so a value can never add a header or a paragraph.
func (s *Sender) Render(to, template, locale string, params map[string]string) Message {
	clean := make(map[string]string, len(params))
	for k, v := range params {
		clean[k] = oneLine(v)
	}
	subject := oneLine(s.Catalog.T(locale, "email."+template+".subject", clean))
	body := strings.TrimSpace(s.Catalog.T(locale, "email."+template+".body", clean)) + "\n\n" + s.Catalog.T(locale, "email.footer", nil)
	return Message{To: to, Subject: subject, Body: body}
}
```

- [ ] **Step 6: Run the tests**

Run:
```bash
go test -race -count=1 ./internal/notify/
go test -race -count=1 -tags integration ./internal/notify/
go test -count=1 ./internal/archtest/
```
Expected: PASS (the archtest confirms `notify` imports only `platform`, `i18n`, `secrets`; its tests may import `license`).

- [ ] **Step 7: Lint and commit**

Run: `make lint i18n-check`
Expected: no findings.

```bash
git add internal/notify/ locales/common/en.json locales/common/tr.json
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(notify): email outbox, sender with retries and a TLS-only SMTP mailer

Emails to Administrators are queued in the caller's transaction and drained
with FOR UPDATE SKIP LOCKED (exactly once), 30 s doubling backoff and at most
10 attempts; without SMTP they are recorded as skipped (L-18). The SMTP
mailer requires STARTTLS or implicit TLS with a verified certificate, never
sends credentials in the clear, and keeps subjects on one line. License
email texts in English and Turkish.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 11: `jobs` — job types with license classes and the gated periodic scheduler

Spec §8.2, §8.3 (scheduler), §8.6 (`license.Gate` before every scheduled run), §8.7 (running work is never
cancelled by the lock), X-01 (every job type declares its license class) and §26.4 "lock-mode enforcement layer
used by the job framework (scheduler gate)". Phase 2 needs two periodic jobs (`license.evaluate` hourly,
`notify.send` every minute). The durable queue of §8.1 arrives with targets in Phase 3 and reuses the same type
registry and gate; L-80..L-88 are checked here with stub jobs (spec §26.4).

**Files:**
- Create: `internal/jobs/types.go`, `internal/jobs/scheduler.go`
- Test: `internal/jobs/scheduler_test.go`

**Interfaces:**
- Consumes: `license.Class`, `license.ErrLocked`, `license.ErrUnclassified` (Task 5); `clock.Clock` (`NewTicker`).
- Produces (`alice/internal/jobs`):
  - `type Type struct { Name string; Class license.Class }`; `func Register(name string, class license.Class) Type` (panics on an invalid class or a duplicate name); `func Types() []Type` (sorted by name); `var LicenseEvaluate = Register("license.evaluate", license.ClassAlways)`; `var NotifySend = Register("notify.send", license.ClassAlways)`.
  - `type Gate interface { Allow(c license.Class) error }` (implemented by `*license.Service`).
  - `type Task struct { Type Type; Every time.Duration; Run func(ctx context.Context) error }`.
  - `func NewScheduler(clk clock.Clock, gate Gate, log *slog.Logger, tasks ...Task) *Scheduler` (panics on an unregistered type, a `ClassChange` type, a non-positive interval, a nil `Run` or a duplicate); `func (s *Scheduler) Run(ctx context.Context)` (blocks until `ctx` ends); `func (s *Scheduler) RunNow(ctx context.Context, name string) error` (runs after the gate, serialized with the loop; returns `license.ErrLocked` when paused).

- [ ] **Step 1: Write the failing tests**

Create `internal/jobs/scheduler_test.go`:

```go
package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/platform/clock"
)

// Stub job types for L-27, L-30 and L-80 until the real jobs exist (spec §26.4).
var (
	testDiscover = Register("test.discover", license.ClassReadOnly)
	testDeploy   = Register("test.deploy", license.ClassChange)
)

type fakeGate struct {
	mu     sync.Mutex
	locked bool
}

func (g *fakeGate) Allow(c license.Class) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case !c.Valid():
		return license.ErrUnclassified
	case c != license.ClassAlways && g.locked:
		return license.ErrLocked
	}
	return nil
}

func (g *fakeGate) set(locked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.locked = locked
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// X-01: a job type without a license class cannot exist.
func TestEveryJobTypeHasALicenseClass(t *testing.T) {
	types := Types()
	require.NotEmpty(t, types)
	names := map[string]license.Class{}
	for _, jt := range types {
		assert.True(t, jt.Class.Valid(), jt.Name)
		names[jt.Name] = jt.Class
	}
	assert.Equal(t, license.ClassAlways, names["license.evaluate"], "the evaluation itself runs in lock (§8.6)")
	assert.Equal(t, license.ClassAlways, names["notify.send"], "expiry emails continue in lock")
	assert.Panics(t, func() { Register("test.unclassified", license.ClassUnset) })
	assert.Panics(t, func() { Register("test.bogus", license.Class(42)) })
	assert.Panics(t, func() { Register("license.evaluate", license.ClassAlways) }, "names are unique")
}

func TestNewSchedulerRefusesBadTasks(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	run := func(context.Context) error { return nil }
	for name, task := range map[string]Task{
		"unregistered":        {Type: Type{Name: "nope", Class: license.ClassAlways}, Every: time.Minute, Run: run},
		"class differs":       {Type: Type{Name: "license.evaluate", Class: license.ClassReadOnly}, Every: time.Minute, Run: run},
		"external change":     {Type: testDeploy, Every: time.Minute, Run: run},
		"no interval":         {Type: LicenseEvaluate, Run: run},
		"no function":         {Type: LicenseEvaluate, Every: time.Minute},
	} {
		assert.Panics(t, func() { NewScheduler(clk, &fakeGate{}, quiet, task) }, name)
	}
	assert.Panics(t, func() {
		NewScheduler(clk, &fakeGate{}, quiet, Task{Type: NotifySend, Every: time.Minute, Run: run}, Task{Type: NotifySend, Every: time.Hour, Run: run})
	}, "duplicate task")
}

// advanceUntil moves the fake clock by every until ran reports a run (the loop goroutine
// may not have created its ticker yet on the first move).
func advanceUntil(t *testing.T, clk *clock.Fake, every time.Duration, ran <-chan struct{}) {
	t.Helper()
	for range 100 {
		clk.Advance(every)
		select {
		case <-ran:
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("the task did not run")
}

func TestTasksRunOnTheirInterval(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	ran := make(chan struct{}, 10)
	s := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: LicenseEvaluate, Every: time.Hour, Run: func(context.Context) error {
		ran <- struct{}{}
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	advanceUntil(t, clk, time.Hour, ran)
	advanceUntil(t, clk, time.Hour, ran)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// L-27, L-30 (stub jobs): read-only recurring work is paused while locked and resumes by
// itself after a renewal; the evaluation and email jobs run in lock.
func TestLockPausesReadOnlyWorkAndRenewalResumesIt(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{locked: true}
	var discovered, evaluated atomic.Int32
	s := NewScheduler(clk, gate, quiet,
		Task{Type: testDiscover, Every: 15 * time.Minute, Run: func(context.Context) error { discovered.Add(1); return nil }},
		Task{Type: LicenseEvaluate, Every: time.Hour, Run: func(context.Context) error { evaluated.Add(1); return nil }},
	)
	ctx := context.Background()
	assert.ErrorIs(t, s.RunNow(ctx, "test.discover"), license.ErrLocked)
	assert.Zero(t, discovered.Load(), "no external call while locked")
	require.NoError(t, s.RunNow(ctx, "license.evaluate"))
	assert.Equal(t, int32(1), evaluated.Load())

	gate.set(false) // a renewal was uploaded
	require.NoError(t, s.RunNow(ctx, "test.discover"))
	assert.Equal(t, int32(1), discovered.Load())
}

// L-80 (stub): lock is checked before a run starts, never in the middle; running work
// completes on its own.
func TestRunningTaskCompletesWhenLockStarts(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	gate := &fakeGate{}
	started, release := make(chan struct{}), make(chan struct{})
	var finished atomic.Bool
	s := NewScheduler(clk, gate, quiet, Task{Type: testDiscover, Every: time.Hour, Run: func(context.Context) error {
		close(started)
		<-release
		finished.Store(true)
		return nil
	}})
	errc := make(chan error, 1)
	go func() { errc <- s.RunNow(context.Background(), "test.discover") }()
	<-started
	gate.set(true)
	close(release)
	require.NoError(t, <-errc)
	assert.True(t, finished.Load())
	assert.ErrorIs(t, s.RunNow(context.Background(), "test.discover"), license.ErrLocked, "the next run is paused")
}

// A task never runs twice at once: a tick that finds it running is skipped.
func TestATaskNeverOverlapsItself(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	var running, maxRunning, runs atomic.Int32
	release := make(chan struct{})
	s := NewScheduler(clk, &fakeGate{}, quiet, Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error {
		n := running.Add(1)
		for {
			m := maxRunning.Load()
			if n <= m || maxRunning.CompareAndSwap(m, n) {
				break
			}
		}
		runs.Add(1)
		<-release
		running.Add(-1)
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	errc := make(chan error, 1)
	go func() { errc <- s.RunNow(ctx, "notify.send") }()
	require.Eventually(t, func() bool { return running.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	for range 20 {
		clk.Advance(time.Minute)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	require.NoError(t, <-errc)
	assert.Equal(t, int32(1), maxRunning.Load())
}

func TestFailuresAndPanicsAreContained(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	boom := errors.New("boom")
	s := NewScheduler(clk, &fakeGate{}, quiet,
		Task{Type: NotifySend, Every: time.Minute, Run: func(context.Context) error { return boom }},
		Task{Type: LicenseEvaluate, Every: time.Hour, Run: func(context.Context) error { panic("bad") }},
	)
	assert.ErrorIs(t, s.RunNow(context.Background(), "notify.send"), boom)
	assert.Error(t, s.RunNow(context.Background(), "license.evaluate"))
	assert.Error(t, s.RunNow(context.Background(), "no.such.task"))
}
```

Run: `go test -count=1 ./internal/jobs/`
Expected: FAIL — `no non-test Go files in …/internal/jobs`.

- [ ] **Step 2: Implement the job types**

Create `internal/jobs/types.go`:

```go
// Package jobs runs Alice's background work. Every job type declares its license class
// (spec §8.6, X-01), and every scheduled run passes the license gate first. Phase 2 has
// the periodic in-process scheduler; the durable PostgreSQL job queue (§8.1) arrives with
// targets in Phase 3 and uses the same registry and gate.
package jobs

import (
	"fmt"
	"sort"
	"sync"

	"alice/internal/license"
)

// Type is a job type and the way lock mode treats it.
type Type struct {
	Name  string
	Class license.Class
}

var (
	registryMu sync.Mutex
	registry   = map[string]Type{}
)

// Register declares a job type. It panics on an invalid license class or a duplicate name,
// so no job type can exist without a class (X-01).
func Register(name string, class license.Class) Type {
	if name == "" || !class.Valid() {
		panic(fmt.Sprintf("jobs: job type %q must declare a license class", name))
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("jobs: job type %q is registered twice", name))
	}
	t := Type{Name: name, Class: class}
	registry[name] = t
	return t
}

// Types returns every registered job type, sorted by name.
func Types() []Type {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Type, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func lookup(name string) (Type, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	t, ok := registry[name]
	return t, ok
}

// Phase 2 job types (spec §8.2). Both run in every license state (§8.6).
var (
	LicenseEvaluate = Register("license.evaluate", license.ClassAlways)
	NotifySend      = Register("notify.send", license.ClassAlways)
)
```

- [ ] **Step 3: Implement the scheduler**

Create `internal/jobs/scheduler.go`:

```go
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"alice/internal/license"
	"alice/internal/platform/clock"
)

// Gate decides whether work of a license class may start now (license.Service.Allow).
type Gate interface {
	Allow(c license.Class) error
}

// Task is periodic work.
type Task struct {
	Type  Type
	Every time.Duration
	Run   func(ctx context.Context) error
}

type task struct {
	Task
	mu sync.Mutex // one run at a time
}

// Scheduler runs periodic tasks in-process. Every run passes the license gate first
// (spec §8.6); a run that has started is never cancelled by the lock (§8.7).
type Scheduler struct {
	clock clock.Clock
	gate  Gate
	log   *slog.Logger
	tasks map[string]*task
	order []*task
}

// NewScheduler validates tasks. External-change work (ClassChange) is refused: after a
// renewal it must wait for an Administrator's confirmation (R29), which only the job queue
// can provide.
func NewScheduler(clk clock.Clock, gate Gate, log *slog.Logger, tasks ...Task) *Scheduler {
	s := &Scheduler{clock: clk, gate: gate, log: log, tasks: map[string]*task{}}
	for _, t := range tasks {
		reg, ok := lookup(t.Type.Name)
		switch {
		case !ok || reg != t.Type:
			panic(fmt.Sprintf("jobs: task %q does not use a registered job type", t.Type.Name))
		case t.Type.Class == license.ClassChange:
			panic(fmt.Sprintf("jobs: %q changes managed systems and cannot be a periodic task", t.Type.Name))
		case t.Every <= 0 || t.Run == nil:
			panic(fmt.Sprintf("jobs: task %q needs an interval and a function", t.Type.Name))
		}
		if _, dup := s.tasks[t.Type.Name]; dup {
			panic(fmt.Sprintf("jobs: task %q is scheduled twice", t.Type.Name))
		}
		tk := &task{Task: t}
		s.tasks[t.Type.Name] = tk
		s.order = append(s.order, tk)
	}
	return s
}

// Run runs every task on its interval until ctx ends. A tick that finds the task still
// running is skipped.
func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, t := range s.order {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.loop(ctx, t)
		}()
	}
	wg.Wait()
}

func (s *Scheduler) loop(ctx context.Context, t *task) {
	ticker := s.clock.NewTicker(t.Every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			if t.mu.TryLock() {
				_ = s.run(ctx, t)
				t.mu.Unlock()
			}
		}
	}
}

// RunNow runs a task at once (waiting while it runs), after the gate. It returns
// license.ErrLocked when the task is paused.
func (s *Scheduler) RunNow(ctx context.Context, name string) error {
	t, ok := s.tasks[name]
	if !ok {
		return fmt.Errorf("jobs: no task %q", name)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return s.run(ctx, t)
}

func (s *Scheduler) run(ctx context.Context, t *task) (err error) {
	if err := s.gate.Allow(t.Type.Class); err != nil {
		if errors.Is(err, license.ErrLocked) {
			s.log.Info("scheduled task paused while the license is expired", "job_type", t.Type.Name)
		} else {
			s.log.Error("scheduled task refused by the license gate", "job_type", t.Type.Name, "error_type", fmt.Sprintf("%T", err))
		}
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			// The panic value is not logged: it may hold data from the task.
			s.log.Error("scheduled task panicked", "job_type", t.Type.Name)
			err = fmt.Errorf("jobs: task %s panicked", t.Type.Name)
		}
	}()
	if err := t.Run(ctx); err != nil {
		s.log.Error("scheduled task failed", "job_type", t.Type.Name, "error_type", fmt.Sprintf("%T", err))
		return err
	}
	return nil
}
```

- [ ] **Step 4: Run the tests**

Run: `go test -race -count=1 ./internal/jobs/ ./internal/archtest/`
Expected: PASS (the `jobs` import rule already allows `license`).

- [ ] **Step 5: Commit**

```bash
git add internal/jobs/
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(jobs): job types with license classes and a gated periodic scheduler

Every job type declares its license class at registration (X-01). The
periodic scheduler asks the license gate before every run: read-only work
pauses while locked and resumes after a renewal, the evaluation and email
jobs always run, a started run always completes (L-80), and external-change
work is refused as a periodic task.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 12: License permissions and the API lock gate

Spec §9.6 (lock mode on the API), R9 (user-initiated external changes refused with `license.locked`), R36 item 6
(platform administration stays available), SEC-016 (every route in the table), §25.1. Every state-changing route
now declares its license class in the route table next to its permission; the guard asks
`license.Service.Allow` for `ClassChange`/`ClassReadOnly` routes after authorization, so this is the second (and
last) call site of the single gate. Phase 2 has no infrastructure routes yet: a synthetic route proves the
behavior, and a rule test forces every future `/targets`, `/certificates`, … mutation to be `ClassChange`.

**Files:**
- Modify: `internal/rbac/rbac.go`, `internal/rbac/rbac_test.go`
- Modify: `internal/api/server.go` (`route.lic`, `Deps.License`, `LicenseService`), `internal/api/guard.go`, `internal/api/errors.go`
- Modify: `internal/api/auth_handlers.go`, `audit_handlers.go`, `setup_handlers.go`, `tokens_handlers.go`, `users_handlers.go` (`lic: license.ClassAlways` on every non-GET route)
- Modify: `internal/api/authz_test.go` (matrix rows, lock rules, doc column), `internal/api/guard_test.go`, `internal/api/fakes_test.go`, `internal/api/server_test.go` (`testDeps`)
- Modify: `internal/api/stack_integration_test.go` (`deps()` passes a license gate)
- Modify: `locales/common/en.json`, `locales/common/tr.json`, `docs/troubleshooting.md`, `docs/authz-matrix.md` (regenerated)

**Interfaces:**
- Consumes: `license.Class`, `license.ClassAlways/ReadOnly/Change`, `license.ErrLocked` (Task 5).
- Produces (`alice/internal/rbac`): `LicenseRead Permission = "license.read"` (Admin, Auditor; API token `read`), `LicenseManage Permission = "license.manage"` (Admin session with step-up; no tokens). `rbac.Permissions()` has 12 entries.
- Produces (`alice/internal/api`): field `lic license.Class` on `route`; `type LicenseService interface { Allow(c license.Class) error }` (extended in Task 14); `Deps.License LicenseService`; `ErrLicenseLocked = ErrorCode{Code: "ALC-LIC-0001", Reason: "license.locked", Status: 403}`; audit action `request.denied_license` (result `denied`, details `method`, `path`, `class`).

- [ ] **Step 1: Write the failing permission tests**

In `internal/rbac/rbac_test.go` add to `expected` (after the `rbac.SettingsManage` row):

```go
	rbac.LicenseRead: {"anon": U, "setup": U, "pending": U, "admin": A, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": A, "auditor+stepup": A, "token-read-admin": A, "token-operate-admin": A, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": A, "token-noscope-admin": F, "session-unknown-role": F},
	rbac.LicenseManage: {"anon": U, "setup": U, "pending": U, "admin": S, "admin+stepup": A, "operator": F, "operator+stepup": F,
		"auditor": F, "auditor+stepup": F, "token-read-admin": F, "token-operate-admin": F, "token-read-operator": F,
		"token-operate-operator": F, "token-read-auditor": F, "token-noscope-admin": F, "session-unknown-role": F},
```

and change `assert.Len(t, ps, 10)` to `assert.Len(t, ps, 12)`.

In `internal/api/authz_test.go` add to `expectedMatrix` (after `rbac.SettingsManage`):

```go
	rbac.LicenseRead:    row(unau, unau, unau, unau, unau, allw, forb, allw, allw, forb, allw, allw, forb, allw),
	rbac.LicenseManage:  row(unau, unau, unau, unau, unau, step, forb, forb, allw, forb, forb, forb, forb, forb),
```

Run: `go test -count=1 ./internal/rbac/ ./internal/api/`
Expected: FAIL — `undefined: rbac.LicenseRead`.

- [ ] **Step 2: Add the permissions**

In `internal/rbac/rbac.go` add to the permission constants (after `SettingsManage`):

```go
	LicenseRead    Permission = "license.read"   // license status and history: Admin and Auditor (R3)
	LicenseManage  Permission = "license.manage" // license upload: Admin with step-up (§25.1)
```

and to `policies`:

```go
	LicenseRead:    {Roles: []Role{Admin, Auditor}, TokenScope: ScopeRead},
	LicenseManage:  {Roles: []Role{Admin}, StepUp: true},
```

Run: `go test -count=1 ./internal/rbac/ ./internal/api/`
Expected: PASS.

- [ ] **Step 3: Write the failing gate tests**

In `internal/api/fakes_test.go` add:

```go
// fakeLicense implements LicenseService. Allow returns err and counts calls.
type fakeLicense struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (f *fakeLicense) Allow(license.Class) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeLicense) set(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeLicense) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}
```

(add `"alice/internal/license"` to its imports). In `internal/api/server_test.go`, `testDeps`, add the field `License: &fakeLicense{},` after `Audit: &fakeAudit{},`.

Append to `internal/api/guard_test.go` (add `"alice/internal/license"` to its imports):

```go
func gatedHandler(d Deps, class license.Class) http.Handler {
	s := newServer(d)
	return s.handler([]route{{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.Session, lic: class,
		handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }}})
}

// R9, §9.6: while locked, infrastructure changes are refused with license.locked, audited,
// and never reach the handler; after a renewal they work at once.
func TestLicenseGateRefusesChangesWhileLocked(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	fa := d.Audit.(*fakeAudit)
	h := gatedHandler(d, license.ClassChange)

	fl.set(license.ErrLocked)
	rec := call(h, http.MethodPost, "/api/v1/targets", "admin", `{}`)
	require.Equal(t, http.StatusForbidden, rec.Code)
	body := decodeErr(t, rec)
	assert.Equal(t, "ALC-LIC-0001", body.Error.Code)
	assert.Equal(t, "license.locked", body.Error.Reason)
	assert.Equal(t, 1, fa.Count("request.denied_license"))

	fl.set(nil)
	assert.Equal(t, http.StatusNoContent, call(h, http.MethodPost, "/api/v1/targets", "admin", `{}`).Code)
}

func TestLicenseGateOrderAndScope(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	fl.set(license.ErrLocked)

	before := fl.count()
	assert.Equal(t, http.StatusUnauthorized, call(gatedHandler(d, license.ClassChange), http.MethodPost, "/api/v1/targets", "", `{}`).Code,
		"authentication and authorization come first")
	assert.Equal(t, before, fl.count(), "the gate is not consulted for a request that is not allowed anyway")

	assert.Equal(t, http.StatusNoContent, call(gatedHandler(d, license.ClassAlways), http.MethodPost, "/api/v1/targets", "admin", `{}`).Code,
		"ClassAlways routes work in lock")
	assert.Equal(t, before, fl.count(), "and do not consult the gate")

	d.License = nil
	assert.Equal(t, http.StatusForbidden, call(gatedHandler(d, license.ClassChange), http.MethodPost, "/api/v1/targets", "admin", `{}`).Code,
		"no license service: fail closed")
}
```

Append to `internal/api/authz_test.go` (add `"alice/internal/license"` to its imports):

```go
// Route groups and how lock mode treats their state-changing operations (R9, R36 item 6).
var (
	lockAvailable = []string{"/api/v1/auth", "/api/v1/setup", "/api/v1/license", "/api/v1/users", "/api/v1/tokens",
		"/api/v1/audit", "/api/v1/backup", "/api/v1/backups", "/api/v1/settings"}
	lockRefused = []string{"/api/v1/targets", "/api/v1/certificates", "/api/v1/locations", "/api/v1/deployments",
		"/api/v1/ssh-keys", "/api/v1/rotation", "/api/v1/keyvault"}
)

func underAny(pattern string, prefixes []string) bool {
	for _, p := range prefixes {
		if under(pattern, p) {
			return true
		}
	}
	return false
}

// lockRuleViolations: reads are never refused in lock; every state-changing route declares
// a license class; infrastructure changes are ClassChange; platform administration is ClassAlways.
func lockRuleViolations(routes []route) []string {
	var out []string
	for _, rt := range routes {
		key := rt.method + " " + rt.pattern
		if safeMethod(rt.method) {
			if rt.lic != license.ClassUnset && rt.lic != license.ClassAlways {
				out = append(out, key+": reads stay available in lock")
			}
			continue
		}
		switch {
		case !rt.lic.Valid():
			out = append(out, key+": declares no license class")
		case underAny(rt.pattern, lockRefused) && rt.lic != license.ClassChange:
			out = append(out, key+": infrastructure changes must be ClassChange")
		case underAny(rt.pattern, lockAvailable) && rt.lic != license.ClassAlways:
			out = append(out, key+": platform administration must stay available (ClassAlways)")
		}
	}
	return out
}

func TestEveryStateChangingRouteDeclaresALicenseClass(t *testing.T) {
	assert.Empty(t, lockRuleViolations(newServer(Deps{}).apiRoutes()))
}

func TestLockRuleViolationsCatchesMistakes(t *testing.T) {
	bad := []route{
		{method: http.MethodPost, pattern: "/api/v1/users", perm: rbac.UsersManage},
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.Read, lic: license.ClassAlways},
		{method: http.MethodDelete, pattern: "/api/v1/ssh-keys/{id}", perm: rbac.Read, lic: license.ClassReadOnly},
		{method: http.MethodPost, pattern: "/api/v1/license", perm: rbac.LicenseManage, lic: license.ClassChange},
		{method: http.MethodGet, pattern: "/api/v1/targets", perm: rbac.Read, lic: license.ClassChange},
	}
	assert.Len(t, lockRuleViolations(bad), len(bad))
	good := []route{
		{method: http.MethodPost, pattern: "/api/v1/targets", perm: rbac.Read, lic: license.ClassChange},
		{method: http.MethodPost, pattern: "/api/v1/users", perm: rbac.UsersManage, lic: license.ClassAlways},
		{method: http.MethodGet, pattern: "/api/v1/targets", perm: rbac.Read},
	}
	assert.Empty(t, lockRuleViolations(good))
}
```

Run: `go test -count=1 ./internal/api/`
Expected: FAIL — `unknown field lic in struct literal of type route`, `undefined: ErrLicenseLocked`.

- [ ] **Step 4: Add the license class to the route table and the gate to the guard**

In `internal/api/server.go`:

1. Add `"alice/internal/license"` to the imports.
2. After the `AuditService` interface add:

```go
// LicenseService is the part of license.Service the HTTP layer uses.
type LicenseService interface {
	// Allow is the single lock-mode gate (spec §8.6, R9).
	Allow(c license.Class) error
}
```

3. In `Deps` add, after `Audit AuditService`:

```go
	License        LicenseService
```

4. In `route` add, after `limit limitClass`:

```go
	// lic is how lock mode treats this operation. Every non-GET route declares it: ClassAlways
	// for platform administration, ClassChange for changes to managed systems or inventory
	// (refused while the license is expired, R9). GET routes leave it unset (reads stay available).
	lic license.Class
```

In `internal/api/guard.go`:

1. Add `"alice/internal/license"` to the imports.
2. Replace

```go
		case rbac.Allow:
			rt.handler(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
```

with

```go
		case rbac.Allow:
			if (rt.lic == license.ClassChange || rt.lic == license.ClassReadOnly) && !s.licenseAllows(rt.lic) {
				s.auditLicenseDenied(r, rt, p)
				s.writeError(w, r, ErrLicenseLocked)
				return
			}
			rt.handler(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
```

3. After `auditDenied` add:

```go
// licenseAllows asks the single lock gate (license.Service.Allow). Without a license
// service the answer is no: a misconfigured server fails closed.
func (s *server) licenseAllows(c license.Class) bool {
	return s.deps.License != nil && s.deps.License.Allow(c) == nil
}

// auditLicenseDenied records a request refused because the license has expired (L-26).
func (s *server) auditLicenseDenied(r *http.Request, rt route, p auth.Principal) {
	if p.Kind != rbac.UserSession && p.Kind != rbac.APIToken {
		return
	}
	ev := audit.Event{
		Actor:  p.Actor(s.meta(r)),
		Action: "request.denied_license",
		Result: audit.Denied,
		Details: map[string]string{"method": rt.method, "path": rt.pattern, "class": rt.lic.String()},
	}
	if err := s.deps.Audit.Write(r.Context(), ev); err != nil {
		s.deps.Log.Error("audit write failed", append([]any{"request_id", RequestID(r.Context()), "action", ev.Action}, errorAttrs(err)...)...)
	}
}
```

In `internal/api/errors.go` add after `ErrSetupIncomplete`:

```go

	ErrLicenseLocked = ErrorCode{Code: "ALC-LIC-0001", Reason: "license.locked", Status: http.StatusForbidden}
```

and append `ErrLicenseLocked,` to the list returned by `AllErrorCodes` (after `ErrSetupIncomplete,`).

- [ ] **Step 5: Declare the class on every existing state-changing route**

Run:

```bash
sed -i -E '/\{method: http\.Method(Post|Put|Patch|Delete),/ s/ handler: / lic: license.ClassAlways, handler: /' \
  internal/api/auth_handlers.go internal/api/audit_handlers.go internal/api/setup_handlers.go \
  internal/api/tokens_handlers.go internal/api/users_handlers.go
grep -c 'lic: license.ClassAlways' internal/api/*_handlers.go
```

Expected counts: `auth_handlers.go:8`, `audit_handlers.go:1`, `setup_handlers.go:6`, `tokens_handlers.go:2`, `users_handlers.go:5`.

Add `"alice/internal/license"` to the `alice/…` import group of each of the five files, then run `gofmt -w internal/api/*.go` (gofmt sorts the import lines and aligns the route literals).

- [ ] **Step 6: Show the lock behavior in the generated matrix**

In `internal/api/authz_test.go`, `authzMatrixDoc`:

1. After the line `b.WriteString("must also allow the route). Step-up: a fresh verification code (5 minutes) is required.\n\n")` add:

```go
	b.WriteString("In lock: whether the operation still works after the license (or the evaluation) has expired;\n")
	b.WriteString("changes to managed systems are refused with ALC-LIC-0001 (spec R9).\n\n")
```

2. Replace the two header lines with:

```go
	b.WriteString("| Method | Path | Permission | Anonymous | Admin | Operator | Auditor | API token | Step-up | In lock |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
```

3. Replace the `fmt.Fprintf(&b, …)` row with:

```go
		inLock := "yes"
		if rt.lic == license.ClassChange || rt.lic == license.ClassReadOnly {
			inLock = "no"
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s |\n",
			rt.method, rt.pattern, rt.perm, anon, role(rbac.Admin), role(rbac.Operator), role(rbac.Auditor), token, yesNo(pol.StepUp), inLock)
```

Run: `make authz-doc && git diff --stat docs/authz-matrix.md`
Expected: every row gains `| yes |`.

- [ ] **Step 7: Add the error text, the troubleshooting entry and the stack gate**

In `locales/common/en.json`, inside `"errors"`, add after the `"setup"` object:

```json
    "license": {
      "locked": {
        "title": "Not available while the license is expired.",
        "cause": "The license (or the evaluation) has ended, so Alice makes no changes to your servers. Your data is safe.",
        "action": "An administrator can upload a renewed license on the License page. Everything works again at once."
      }
    }
```

In `locales/common/tr.json` at the same place:

```json
    "license": {
      "locked": {
        "title": "Lisans süresi dolduğu için bu işlem kullanılamıyor.",
        "cause": "Lisans (veya deneme süresi) sona erdi; bu nedenle Alice sunucularınızda değişiklik yapmıyor. Verileriniz güvende.",
        "action": "Bir yönetici yenilenen lisansı Lisans sayfasından yükleyebilir. Her şey hemen yeniden çalışır."
      }
    }
```

Append to `docs/troubleshooting.md`:

```markdown

## ALC-LIC-0001: Not available while the license is expired

**Meaning.** The action changes a managed server, key or certificate, and the license or the 30-day evaluation has
ended (HTTP 403). Alice is in lock mode: automatic tasks are paused and such changes are refused. Signing in,
uploading a license, backups, the audit log, exports and user administration keep working. Nothing was changed.

**Likely cause.** The license expired more than 7 days ago (168 hours), or the evaluation ended.

**What to do.** Ask your vendor for a renewed license (send the Installation ID shown on the **License** page) and
upload it there. Everything works again immediately; work that was paused waits for an administrator's confirmation.
```

In `internal/api/stack_integration_test.go`, `deps()`, add `License: allowAll{},` after `Audit: s.auditSvc,`, and add at the end of the file:

```go
// allowAll is the license gate of stacks that do not test licensing (replaced in Task 14).
type allowAll struct{}

func (allowAll) Allow(license.Class) error { return nil }
```

(add `"alice/internal/license"` to its imports).

- [ ] **Step 8: Run the suites**

Run:
```bash
go test -race -count=1 ./internal/rbac/ ./internal/api/
go test -count=1 -tags integration ./internal/api/
make i18n-check lint
```
Expected: PASS; `TestEveryErrorCodeIsWellFormedUniqueAndTranslated` and `TestEveryErrorCodeIsDocumentedInTroubleshooting` include ALC-LIC-0001.

- [ ] **Step 9: Commit**

```bash
git add internal/rbac/ internal/api/ locales/common/ docs/troubleshooting.md docs/authz-matrix.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(api): license permissions and the lock gate in the route table

Every state-changing route declares a license class next to its
permission; the guard asks license.Service.Allow for ClassChange routes
after authorization and answers ALC-LIC-0001 (403 license.locked), audited
as request.denied_license. Platform administration stays available in lock
(R9, R36); a rule test makes future infrastructure mutations ClassChange.
New permissions license.read (Admin, Auditor) and license.manage (Admin with
step-up). The authz matrix shows what works in lock.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 13: Setup wizard license step (service and route)

Carry 3 and spec §18.5 step 6: between the recovery passphrase and Finish the administrator either uploads a license
(Task 14's upload endpoint) or starts the 30-day evaluation. Starting the evaluation starts nothing: the evaluation
has run since the installation timestamp created at first start (R27, Task 8); the choice only completes the
wizard step. `POST /setup/complete` now needs both the passphrase and a license choice. Installations that
finished the Phase 1 wizard stay finished.

Between this task and Task 20 the Playwright wizard journey (`make e2e`) cannot finish setup, because the web wizard
gets its license step in Task 20; all Go and Vitest suites stay green (same accepted cost as the Phase 1 ruling
"CI stack job red until then").

**Files:**
- Modify: `internal/setup/setup.go` (Config.License, Status.LicenseChosen, key, error), `internal/setup/passphrase.go` (Complete)
- Create: `internal/setup/license.go` (ChooseEvaluation)
- Modify: `internal/setup/setup_integration_test.go`
- Modify: `internal/api/server.go` (SetupService), `internal/api/setup_handlers.go`, `internal/api/dto.go`, `internal/api/errors.go`, `internal/api/fakes_test.go`, `internal/api/setup_handlers_test.go`, `internal/api/authz_test.go`, `internal/api/stack_integration_test.go`
- Modify: `api/openapi.yaml`, `locales/common/en.json`, `locales/common/tr.json`, `docs/troubleshooting.md`, `docs/authz-matrix.md` (regenerated)

**Interfaces:**
- Consumes: `setup.Service.authorize` (settings.manage), `hasSetting`, `passphraseLock`; `license.Service.Installed` (Task 8) through an interface.
- Produces (`alice/internal/setup`): `type LicenseState interface { Installed(ctx context.Context) (bool, error) }`; `Config.License LicenseState` (nil = no license can be installed; only the evaluation choice completes the step); `Status.LicenseChosen bool`; `var ErrLicenseChoiceMissing`; `func (s *Service) ChooseEvaluation(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error)` (requires the passphrase first: `ErrIncomplete`; idempotent; audit `setup.evaluation_chosen`); setting `setup.license_choice`.
- Produces (`alice/internal/api`): route `POST /api/v1/setup/evaluation` (`settings.manage`, `ClassAlways`) → 200 `SetupStatus`; `SetupStatus` JSON gains `license_chosen`; `ErrSetupLicenseChoiceMissing = ALC-SET-0009` (409 `setup.license_choice_missing`); `SetupService.ChooseEvaluation`.

- [ ] **Step 1: Write the failing setup tests**

In `internal/setup/setup_integration_test.go`:

1. Add after the `env` type:

```go
// stubLicense stands in for license.Service in the wizard tests.
type stubLicense struct{ installed bool }

func (s *stubLicense) Installed(context.Context) (bool, error) { return s.installed, nil }
```

2. Add the field `license *stubLicense` to `env`, and in `newEnv` replace

```go
	s := setup.New(setup.Config{Pool: d.App, Auth: a, Keyring: kr, Audit: log, Clock: clk, Hasher: h, BackupKDF: fastKDF})
	return &env{ctx: context.Background(), clk: clk, db: d, auth: a, setup: s}
```

with

```go
	lic := &stubLicense{}
	s := setup.New(setup.Config{Pool: d.App, Auth: a, Keyring: kr, Audit: log, Clock: clk, Hasher: h, BackupKDF: fastKDF, License: lic})
	return &env{ctx: context.Background(), clk: clk, db: d, auth: a, setup: s, license: lic}
```

3. In `TestRecoveryPassphraseAndCompletion` replace

```go
	st, err := e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.Equal(t, setup.Status{AdminExists: true, RecoveryPassphraseSet: true, Completed: true, DefaultLocale: "tr"}, st)
	_, err = e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err, "completing twice is harmless")
```

with

```go
	_, err = e.setup.Complete(e.ctx, p, ip1)
	require.ErrorIs(t, err, setup.ErrLicenseChoiceMissing, "the license step comes before Finish")
	st, err := e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.True(t, st.LicenseChosen)
	assert.False(t, st.Completed)
	_, err = e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.NoError(t, err, "choosing twice is harmless")

	st, err = e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.Equal(t, setup.Status{AdminExists: true, RecoveryPassphraseSet: true, LicenseChosen: true, Completed: true, DefaultLocale: "tr"}, st)
	_, err = e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err, "completing twice is harmless")
```

and replace the expected audit actions with

```go
	assert.Equal(t, []string{"setup.admin_created", "setup.recovery_passphrase_set", "setup.evaluation_chosen", "setup.completed"}, actions)
```

4. In `TestPassphraseAndCompleteRequireSettingsManage`, inside the loop `for name, p := range map[string]auth.Principal{"operator": operator, "api token": token} {` that calls `Complete`, add before its closing brace:

```go
		_, err = e.setup.ChooseEvaluation(e.ctx, p, ip1)
		assert.ErrorIs(t, err, setup.ErrForbidden, name)
```

and after `assert.ErrorIs(t, err, setup.ErrForbidden)` for the `stale` Complete add:

```go
	_, err = e.setup.ChooseEvaluation(e.ctx, stale, ip1)
	assert.ErrorIs(t, err, setup.ErrForbidden)
	assert.Empty(t, e.settingRaw(t, "setup.license_choice"))
```

5. Append:

```go
// An uploaded license completes the license step without the evaluation choice.
func TestAnInstalledLicenseCompletesTheLicenseStep(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	require.NoError(t, e.setup.SetRecoveryPassphrase(e.ctx, p, ip1, passphrase, passphrase))
	st, err := e.setup.Status(e.ctx)
	require.NoError(t, err)
	assert.False(t, st.LicenseChosen)

	e.license.installed = true
	st, err = e.setup.Status(e.ctx)
	require.NoError(t, err)
	assert.True(t, st.LicenseChosen)
	st, err = e.setup.Complete(e.ctx, p, ip1)
	require.NoError(t, err)
	assert.True(t, st.Completed)
}

func TestEvaluationChoiceNeedsThePassphraseFirst(t *testing.T) {
	e := newEnv(t)
	res, _ := e.createAdmin(t)
	p, err := e.auth.Authenticate(e.ctx, res.Token)
	require.NoError(t, err)
	_, err = e.setup.ChooseEvaluation(e.ctx, p, ip1)
	require.ErrorIs(t, err, setup.ErrIncomplete)
	assert.Empty(t, e.settingRaw(t, "setup.license_choice"))
}
```

Run: `go test -count=1 -tags integration ./internal/setup/`
Expected: FAIL — `unknown field License in struct literal`, `e.setup.ChooseEvaluation undefined`, `setup.ErrLicenseChoiceMissing undefined`.

- [ ] **Step 2: Implement the license step**

In `internal/setup/setup.go`:

1. Add to the error block:

```go
	ErrLicenseChoiceMissing = errors.New("setup: choose a license option first")
```

2. Add to the settings keys:

```go
	keyLicenseChoice = "setup.license_choice"
```

3. After the `Config` type add:

```go
// LicenseState tells the wizard whether a license file was installed (license.Service).
type LicenseState interface {
	Installed(ctx context.Context) (bool, error)
}
```

4. Add `License   LicenseState // nil: no license can be installed; the evaluation choice still completes the step` to `Config`, `license LicenseState` to `Service`, and `license: c.License,` to the literal in `New`.

5. Add `LicenseChosen         bool` to `Status` (after `RecoveryPassphraseSet`), and in `Status()` after the `RecoveryPassphraseSet` lookup add:

```go
	if st.LicenseChosen, err = s.licenseChosen(ctx, s.pool); err != nil {
		return Status{}, err
	}
```

Create `internal/setup/license.go`:

```go
package setup

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// licenseChosen reports whether the license step is done: the evaluation was chosen or a
// license file was installed (spec §18.5 step 6).
func (s *Service) licenseChosen(ctx context.Context, q db.Querier) (bool, error) {
	set, err := hasSetting(ctx, q, keyLicenseChoice)
	if err != nil || set {
		return set, err
	}
	if s.license == nil {
		return false, nil
	}
	return s.license.Installed(ctx)
}

// ChooseEvaluation completes the license step with the 30-day evaluation. Nothing starts
// here: the evaluation runs from the installation timestamp, and a restore does not reset
// it (R27). It needs the recovery passphrase first and is idempotent.
func (s *Service) ChooseEvaluation(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error) {
	if err := s.authorize(p); err != nil {
		return Status{}, err
	}
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", passphraseLock); err != nil {
			return err
		}
		if set, err := hasSetting(ctx, tx, keyBackupKey); err != nil || !set {
			if err == nil {
				err = ErrIncomplete
			}
			return err
		}
		if chosen, err := hasSetting(ctx, tx, keyLicenseChoice); err != nil || chosen {
			return err
		}
		now := s.clock.Now().UTC()
		if err := settings.Set(ctx, tx, keyLicenseChoice, map[string]string{"choice": "evaluation", "at": now.Format(time.RFC3339)}, now); err != nil {
			return err
		}
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: p.Actor(m), Action: "setup.evaluation_chosen", ObjectType: "setting",
			ObjectID: keyLicenseChoice, Result: audit.Success})
		return err
	})
	if err != nil {
		return Status{}, err
	}
	return s.Status(ctx)
}
```

In `internal/setup/passphrase.go`, `Complete`, replace

```go
		if !set {
			return ErrIncomplete
		}
		done, err := hasSetting(ctx, tx, keyCompletedAt)
```

with

```go
		if !set {
			return ErrIncomplete
		}
		chosen, err := s.licenseChosen(ctx, tx)
		if err != nil {
			return err
		}
		if !chosen {
			return ErrLicenseChoiceMissing
		}
		done, err := hasSetting(ctx, tx, keyCompletedAt)
```

and update its doc comment to `// Complete finishes the wizard. It requires the recovery passphrase and a license choice and is idempotent.`

Run: `go test -race -count=1 -tags integration ./internal/setup/`
Expected: PASS.

- [ ] **Step 3: Write the failing API tests**

In `internal/api/fakes_test.go` add the field `ChooseEvaluationFn func(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)` to `fakeSetup` and:

```go
func (f *fakeSetup) ChooseEvaluation(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error) {
	if f.ChooseEvaluationFn != nil {
		return f.ChooseEvaluationFn(ctx, p, m)
	}
	return setup.Status{}, errNotConfigured
}
```

In `internal/api/setup_handlers_test.go`:

1. Replace ``assert.JSONEq(t, `{"admin_exists":true,"recovery_passphrase_set":false,"completed":false,"default_locale":"tr"}`, rec.Body.String())`` with ``assert.JSONEq(t, `{"admin_exists":true,"recovery_passphrase_set":false,"license_chosen":false,"completed":false,"default_locale":"tr"}`, rec.Body.String())``.
2. In `TestSetupComplete` replace `setup.Status{AdminExists: true, RecoveryPassphraseSet: true, Completed: true, DefaultLocale: "en"}` with `setup.Status{AdminExists: true, RecoveryPassphraseSet: true, LicenseChosen: true, Completed: true, DefaultLocale: "en"}` and its JSON with ``{"admin_exists":true,"recovery_passphrase_set":true,"license_chosen":true,"completed":true,"default_locale":"en"}``.
3. Append:

```go
func TestSetupEvaluation(t *testing.T) {
	d := testDeps(t, nil)
	var got auth.Principal
	d.Setup.(*fakeSetup).ChooseEvaluationFn = func(_ context.Context, p auth.Principal, _ auth.Meta) (setup.Status, error) {
		got = p
		return setup.Status{AdminExists: true, RecoveryPassphraseSet: true, LicenseChosen: true, DefaultLocale: "en"}, nil
	}
	rec := call(NewHandler(d), http.MethodPost, "/api/v1/setup/evaluation", "admin-stepup", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"admin_exists":true,"recovery_passphrase_set":true,"license_chosen":true,"completed":false,"default_locale":"en"}`, rec.Body.String())
	assert.Equal(t, "admin", got.Username)

	rec = call(NewHandler(d), http.MethodPost, "/api/v1/setup/evaluation", "admin", "")
	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, "settings.manage needs step-up")

	d.Setup.(*fakeSetup).CompleteFn = func(context.Context, auth.Principal, auth.Meta) (setup.Status, error) {
		return setup.Status{}, setup.ErrLicenseChoiceMissing
	}
	rec = call(NewHandler(d), http.MethodPost, "/api/v1/setup/complete", "admin-stepup", "")
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-SET-0009", decodeErr(t, rec).Error.Code)
}
```

In `internal/api/authz_test.go`, `routeRuleViolations`, change the case `case under(p, "/api/v1/settings"), p == "/api/v1/setup/recovery-passphrase", p == "/api/v1/setup/complete":` to also cover `p == "/api/v1/setup/evaluation"`, and add `"POST /api/v1/setup/evaluation",` to the list in `TestSensitiveRoutesHaveTheirFixedPermissions`.

Run: `go test -count=1 ./internal/api/`
Expected: FAIL — `fakeSetup does not implement SetupService` / 404 for `/api/v1/setup/evaluation`.

- [ ] **Step 4: Add the route, the DTO field and the error code**

In `internal/api/server.go`, `SetupService`, add after `SetRecoveryPassphrase`:

```go
	ChooseEvaluation(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
```

In `internal/api/setup_handlers.go` add to `setupRoutes()` before the `/api/v1/setup/complete` entry:

```go
		{method: http.MethodPost, pattern: "/api/v1/setup/evaluation", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.setupEvaluation},
```

and the handler:

```go
func (s *server) setupEvaluation(w http.ResponseWriter, r *http.Request) {
	st, err := s.deps.Setup.ChooseEvaluation(r.Context(), principalFrom(r.Context()), s.meta(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, setupStatusJSON(st))
}
```

Update the comment above `setupRoutes` to say "…the remaining steps (recovery passphrase, license choice, completion) need the signed-in administrator…".

In `internal/api/dto.go` add `LicenseChosen         bool   `json:"license_chosen"`` to `setupStatusDTO` (after `RecoveryPassphraseSet`) and `LicenseChosen:         st.LicenseChosen,` to `setupStatusJSON`.

In `internal/api/errors.go` add after `ErrSetupIncomplete`:

```go
	ErrSetupLicenseChoiceMissing = ErrorCode{Code: "ALC-SET-0009", Reason: "setup.license_choice_missing", Status: http.StatusConflict}
```

append `ErrSetupLicenseChoiceMissing,` to `AllErrorCodes` (after `ErrSetupIncomplete,`), and add to `errorMap` after the `setup.ErrIncomplete` entry:

```go
	{setup.ErrLicenseChoiceMissing, ErrSetupLicenseChoiceMissing, nil},
```

In `locales/common/en.json`, inside `errors.setup`, add:

```json
      "license_choice_missing": {
        "title": "Setup is not finished yet.",
        "cause": "No license was uploaded and the evaluation was not started.",
        "action": "Upload a license file or choose Start 30-day evaluation, then finish setup."
      }
```

and in `locales/common/tr.json`:

```json
      "license_choice_missing": {
        "title": "Kurulum henüz tamamlanmadı.",
        "cause": "Lisans yüklenmedi ve deneme süresi başlatılmadı.",
        "action": "Bir lisans dosyası yükleyin veya 30 günlük denemeyi başlatın, ardından kurulumu tamamlayın."
      }
```

Append to `docs/troubleshooting.md` after the `ALC-SET-0008` section:

```markdown

## ALC-SET-0009: License step not done

**Meaning.** Setup cannot be finished because the license step is open (HTTP 409).

**Likely cause.** Neither a license file was uploaded nor **Start 30-day evaluation** was chosen.

**What to do.** On the wizard's license step, upload the license file from your vendor or start the evaluation, then
choose **Go to the dashboard**. The evaluation has been running since Alice was first started either way.
```

- [ ] **Step 5: Document the operation**

In `api/openapi.yaml`:

1. Before `  /api/v1/setup/complete:` insert:

```yaml
  /api/v1/setup/evaluation:
    post:
      operationId: chooseEvaluation
      summary: Complete the wizard's license step with the 30-day evaluation (it runs from the installation timestamp)
      x-permission: settings.manage
      responses:
        "200":
          description: Setup status after the choice
          content:
            application/json:
              schema: { $ref: "#/components/schemas/SetupStatus" }
        "409": { $ref: "#/components/responses/Error" }
        default: { $ref: "#/components/responses/Error" }
```

2. Change the `completeSetup` summary to `Finish the wizard (needs the recovery passphrase and a license choice)`.
3. In `SetupStatus` change `required` to `[admin_exists, recovery_passphrase_set, license_chosen, completed, default_locale]` and add the property `license_chosen: { type: boolean, description: A license was uploaded or the evaluation was chosen }` after `recovery_passphrase_set`.

Run: `make authz-doc`

- [ ] **Step 6: Keep the stack wizard complete**

In `internal/api/stack_integration_test.go`, `setupAdmin`, replace

```go
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/complete", nil), http.StatusOK)
```

with

```go
	requireError(t, c.do(http.MethodPost, "/api/v1/setup/complete", nil), http.StatusConflict, "ALC-SET-0009")
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/evaluation", nil), http.StatusOK)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/complete", nil), http.StatusOK)
```

Run:
```bash
go test -race -count=1 ./internal/api/ ./internal/setup/
go test -race -count=1 -tags integration ./internal/api/ ./internal/setup/
make i18n-check lint
```
Expected: PASS (`TestA06GETRoutesNeverChangeState` and the leak suite pass the new step; `TestRouteTableMatchesSpec` sees the new operation).

- [ ] **Step 7: Commit**

```bash
git add internal/setup/ internal/api/ api/openapi.yaml locales/common/ docs/troubleshooting.md docs/authz-matrix.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(setup): license step between recovery passphrase and Finish

POST /api/v1/setup/evaluation (settings.manage) completes the step with the
30-day evaluation, which runs from the installation timestamp (R27); an
uploaded license completes it too. Finishing setup now needs a license
choice (ALC-SET-0009). The web wizard follows in a later task.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 14: License API — status, detail, preview and upload

Spec §9.6 `license` group (R36 items 12–13), §19.1 (preview "Licensed to …, confirm?"), §25.1 (upload needs
step-up), L-15 (Operators see only `expired` and the banners everyone sees), L-25 (in lock: sign-in, upload,
audit, user administration work), S-01..S-04 (the HWM sub-keys never leak). The stack integration harness now runs
the real `license.Service`.

**Files:**
- Create: `internal/api/license_handlers.go`, `internal/api/license_dto.go`
- Modify: `internal/api/server.go` (`LicenseService`, `apiRoutes`), `internal/api/errors.go`
- Test: `internal/api/license_handlers_test.go`, `internal/api/license_integration_test.go`
- Modify: `internal/api/fakes_test.go`, `internal/api/authz_test.go`, `internal/api/stack_integration_test.go`, `internal/api/leak_integration_test.go`
- Modify: `api/openapi.yaml`, `locales/common/en.json`, `locales/common/tr.json`, `docs/troubleshooting.md`, `docs/authz-matrix.md` (regenerated)

**Interfaces:**
- Consumes: `license.Service` methods `Allow`, `Snapshot`, `Detail`, `Preview`, `Install` (Task 8); `Snapshot.Banners`; errors `ErrInvalid`, `ErrUnknownKey`, `ErrRevokedKey`, `ErrUnsupportedFormat`, `ErrOlderThanInstalled`, `ErrLocked`, `ErrNoInstallation`, `*WrongInstallationError`, `*TargetLimitError`; `licensetest` (tests); `notify.AdminNotifier` (stack).
- Produces (`alice/internal/api`):
  - `LicenseService` gains `Snapshot() license.Snapshot`, `Detail(ctx context.Context) (license.Detail, error)`, `Preview(ctx context.Context, raw []byte) (license.UploadResult, error)`, `Install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (license.UploadResult, error)`.
  - Routes: `GET /api/v1/license/status` (`read`), `GET /api/v1/license` (`license.read`), `POST /api/v1/license/preview` and `POST /api/v1/license` (`license.manage`, `ClassAlways`); request body `{"license": "<file text>"}`.
  - JSON: status `{expired, phase?, banners:[{kind, severity, params}]}`; detail `{installation_id, installed_at, phase, effective_time, current, pending, max_targets, targets_used, ends_at, locks_at, days_left, grace_day, tampered, files:[{status, uploaded_at, license}], history:[{at, event, license_id, from_state, to_state, notice}]}`; license `{license_id, customer, issued_at, valid_from, valid_until, max_targets, features, replaces, key_id}`; upload result `{license, pending, already_expired, correction, duplicate, phase}`.
  - Error codes: `ALC-LIC-0002 license.invalid` (422), `ALC-LIC-0003 license.wrong_installation` (422, params `expected`, `got`), `ALC-LIC-0004 license.unknown_key` (422), `ALC-LIC-0005 license.revoked_key` (422), `ALC-LIC-0006 license.unsupported_format` (422), `ALC-LIC-0007 license.older_than_installed` (409), `ALC-LIC-0008 license.target_limit_reached` (409, params `used`, `max`).

- [ ] **Step 1: Extend the fake and write the failing handler tests**

In `internal/api/fakes_test.go` replace the `fakeLicense` type and its `Allow` method (keep `set` and `count`) with:

```go
// fakeLicense implements LicenseService. Allow returns err and counts calls; the other
// methods call their function fields (errNotConfigured when nil).
type fakeLicense struct {
	mu        sync.Mutex
	err       error
	calls     int
	snap      license.Snapshot
	DetailFn  func(ctx context.Context) (license.Detail, error)
	PreviewFn func(ctx context.Context, raw []byte) (license.UploadResult, error)
	InstallFn func(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (license.UploadResult, error)
}

func (f *fakeLicense) Allow(license.Class) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeLicense) Snapshot() license.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snap
}

func (f *fakeLicense) Detail(ctx context.Context) (license.Detail, error) {
	if f.DetailFn != nil {
		return f.DetailFn(ctx)
	}
	return license.Detail{}, errNotConfigured
}

func (f *fakeLicense) Preview(ctx context.Context, raw []byte) (license.UploadResult, error) {
	if f.PreviewFn != nil {
		return f.PreviewFn(ctx, raw)
	}
	return license.UploadResult{}, errNotConfigured
}

func (f *fakeLicense) Install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (license.UploadResult, error) {
	if f.InstallFn != nil {
		return f.InstallFn(ctx, raw, actor, by)
	}
	return license.UploadResult{}, errNotConfigured
}
```

Create `internal/api/license_handlers_test.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/license/licensetest"
)

var licenseEnd = time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)

func licenseSnapshot(at time.Time) license.Snapshot {
	p := licensetest.Payload(license.NewInstallationID(), licenseEnd.AddDate(-1, 0, 0), licenseEnd, 10)
	return license.Snapshot{
		InstallationID: p.InstallationID,
		InstalledAt:    licenseEnd.AddDate(-1, 0, 0),
		Eval:           license.Evaluate(at, licenseEnd.AddDate(-1, 0, 0), []license.Installed{{Seq: 1, KeyID: licensetest.KeyID, Payload: p}}),
		Reading:        license.Reading{Wall: at, Trusted: at, Effective: at},
		Ready:          true,
	}
}

type statusBody struct {
	Expired bool    `json:"expired"`
	Phase   *string `json:"phase"`
	Banners []struct {
		Kind     string            `json:"kind"`
		Severity string            `json:"severity"`
		Params   map[string]string `json:"params"`
	} `json:"banners"`
}

func status(t *testing.T, h http.Handler, id string) statusBody {
	t.Helper()
	rec := call(h, http.MethodGet, "/api/v1/license/status", id, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var b statusBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &b))
	return b
}

// L-15: warnings go to Administrators; Operators learn only whether the license expired.
func TestLicenseStatusDependsOnTheRole(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	fl.snap = licenseSnapshot(licenseEnd.Add(-7 * 24 * time.Hour))
	h := NewHandler(d)

	op := status(t, h, "operator")
	assert.False(t, op.Expired)
	assert.Nil(t, op.Phase)
	assert.Empty(t, op.Banners)

	admin := status(t, h, "admin")
	require.NotNil(t, admin.Phase)
	assert.Equal(t, "active", *admin.Phase)
	require.Len(t, admin.Banners, 1)
	assert.Equal(t, "expiry_warning", admin.Banners[0].Kind)
	assert.Equal(t, "caution", admin.Banners[0].Severity)
	assert.Equal(t, "7", admin.Banners[0].Params["days_left"])

	auditor := status(t, h, "auditor")
	require.NotNil(t, auditor.Phase, "Auditors can read the license status (R3)")
	assert.Empty(t, auditor.Banners)
	assert.Len(t, status(t, h, "alice_read_admin").Banners, 1, "a read token of an administrator")

	fl.snap = licenseSnapshot(licenseEnd.Add(2*24*time.Hour + time.Hour))
	op = status(t, h, "operator")
	assert.True(t, op.Expired)
	require.Len(t, op.Banners, 1, "the grace banner is for everyone (§19.3)")
	assert.Equal(t, "grace", op.Banners[0].Kind)
	assert.Equal(t, "3", op.Banners[0].Params["grace_day"])
}

func TestLicenseDetail(t *testing.T) {
	d := testDeps(t, nil)
	snap := licenseSnapshot(licenseEnd.Add(-100 * 24 * time.Hour))
	d.License.(*fakeLicense).DetailFn = func(context.Context) (license.Detail, error) {
		cur := *snap.Eval.Current
		return license.Detail{
			Snapshot: snap,
			Files:    []license.FileInfo{{Seq: 1, Status: "current", UploadedAt: licenseEnd.AddDate(-1, 0, 0), KeyID: licensetest.KeyID, Payload: &cur}, {Seq: 2, Status: "invalid"}},
			History:  []license.HistoryEntry{{At: licenseEnd.AddDate(-1, 0, 0), Event: "installed", LicenseID: cur.LicenseID, FromState: "evaluation", ToState: "active"}},
		}, nil
	}
	rec := call(NewHandler(d), http.MethodGet, "/api/v1/license", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, snap.InstallationID, body["installation_id"])
	assert.Equal(t, "active", body["phase"])
	assert.Equal(t, float64(10), body["max_targets"])
	assert.Equal(t, float64(100), body["days_left"])
	assert.Equal(t, "Test Company", body["current"].(map[string]any)["customer"])
	files := body["files"].([]any)
	require.Len(t, files, 2)
	assert.Nil(t, files[1].(map[string]any)["license"], "a file that no longer verifies shows no content")
	assert.Nil(t, body["history"].([]any)[0].(map[string]any)["notice"])

	assert.Equal(t, http.StatusForbidden, call(NewHandler(d), http.MethodGet, "/api/v1/license", "operator", "").Code)
}

func TestLicenseUpload(t *testing.T) {
	d := testDeps(t, nil)
	fl := d.License.(*fakeLicense)
	var gotRaw []byte
	var gotActor audit.Actor
	var gotBy uuid.UUID
	result := license.UploadResult{Payload: licensetest.Payload(license.NewInstallationID(), licenseEnd.AddDate(-1, 0, 0), licenseEnd, 10),
		KeyID: licensetest.KeyID, Pending: true, Phase: license.PhaseActive}
	fl.PreviewFn = func(_ context.Context, raw []byte) (license.UploadResult, error) { gotRaw = raw; return result, nil }
	fl.InstallFn = func(_ context.Context, raw []byte, a audit.Actor, by uuid.UUID) (license.UploadResult, error) {
		gotRaw, gotActor, gotBy = raw, a, by
		return result, nil
	}
	h := NewHandler(d)

	rec := call(h, http.MethodPost, "/api/v1/license/preview", "admin-stepup", `{"license":"{\"format\":1}"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `{"format":1}`, string(gotRaw))
	var res map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, true, res["pending"])
	assert.Equal(t, "active", res["phase"])
	assert.Equal(t, "Test Company", res["license"].(map[string]any)["customer"])

	rec = call(h, http.MethodPost, "/api/v1/license", "admin-stepup", `{"license":"x"}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "admin", gotActor.Name)
	assert.Equal(t, adminID, gotBy)

	assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, call(h, http.MethodPost, "/api/v1/license", "admin", `{"license":"x"}`)).Error.Code, "upload needs step-up (§25.1)")
	assert.Equal(t, http.StatusForbidden, call(h, http.MethodPost, "/api/v1/license", "auditor-stepup", `{"license":"x"}`).Code)
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/license", "admin-stepup", `{"license":"x","extra":1}`).Code)
}

func TestLicenseUploadErrors(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
		params map[string]string
	}{
		{&license.InvalidError{Problem: "signature"}, 422, "ALC-LIC-0002", nil},
		{&license.WrongInstallationError{Expected: "B8TC00", Got: "Q2MXD4"}, 422, "ALC-LIC-0003", map[string]string{"expected": "B8TC00", "got": "Q2MXD4"}},
		{license.ErrUnknownKey, 422, "ALC-LIC-0004", nil},
		{license.ErrRevokedKey, 422, "ALC-LIC-0005", nil},
		{license.ErrUnsupportedFormat, 422, "ALC-LIC-0006", nil},
		{license.ErrOlderThanInstalled, 409, "ALC-LIC-0007", nil},
		{&license.TargetLimitError{Max: 10, Used: 10}, 409, "ALC-LIC-0008", map[string]string{"used": "10", "max": "10"}},
		{license.ErrNoInstallation, 503, "ALC-SYS-0002", nil},
	}
	for _, tc := range cases {
		d := testDeps(t, nil)
		d.License.(*fakeLicense).InstallFn = func(context.Context, []byte, audit.Actor, uuid.UUID) (license.UploadResult, error) {
			return license.UploadResult{}, tc.err
		}
		rec := call(NewHandler(d), http.MethodPost, "/api/v1/license", "admin-stepup", `{"license":"x"}`)
		assert.Equal(t, tc.status, rec.Code, tc.code)
		var body struct {
			Error struct {
				Code   string            `json:"code"`
				Params map[string]string `json:"params"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, tc.code, body.Error.Code)
		if tc.params != nil {
			assert.Equal(t, tc.params, body.Error.Params)
		}
	}
}
```

In `internal/api/authz_test.go`, `routeRuleViolations`, add these cases at the top of the `switch` (before the `/api/v1/users` cases):

```go
		case p == "/api/v1/license/status":
			want = rbac.Read
		case under(p, "/api/v1/license") && !safeMethod(rt.method):
			want = rbac.LicenseManage
		case under(p, "/api/v1/license"):
			want = rbac.LicenseRead
```

and add to the list in `TestSensitiveRoutesHaveTheirFixedPermissions`: `"GET /api/v1/license/status", "GET /api/v1/license", "POST /api/v1/license/preview", "POST /api/v1/license",`.

Run: `go test -count=1 ./internal/api/`
Expected: FAIL — `*fakeLicense does not implement LicenseService (missing …)` is fine only after Step 2; now: 404 for `/api/v1/license/status` and missing error codes.

- [ ] **Step 2: Implement the handlers, DTOs and error mapping**

In `internal/api/server.go` replace the `LicenseService` interface with:

```go
// LicenseService is the part of license.Service the HTTP layer uses.
type LicenseService interface {
	// Allow is the single lock-mode gate (spec §8.6, R9).
	Allow(c license.Class) error
	Snapshot() license.Snapshot
	Detail(ctx context.Context) (license.Detail, error)
	Preview(ctx context.Context, raw []byte) (license.UploadResult, error)
	Install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (license.UploadResult, error)
}
```

and in `apiRoutes` add `routes = append(routes, s.licenseRoutes()...)` after the audit routes.

Create `internal/api/license_dto.go`:

```go
package api

import (
	"time"

	"alice/internal/license"
)

type bannerDTO struct {
	Kind     string            `json:"kind"`
	Severity string            `json:"severity"`
	Params   map[string]string `json:"params"`
}

type licenseStatusDTO struct {
	Expired bool        `json:"expired"`
	Phase   *string     `json:"phase,omitempty"` // Administrators and Auditors only (L-15)
	Banners []bannerDTO `json:"banners"`
}

func bannersJSON(bs []license.Banner) []bannerDTO {
	out := make([]bannerDTO, 0, len(bs))
	for _, b := range bs {
		out = append(out, bannerDTO{Kind: b.Kind, Severity: string(b.Severity), Params: b.Params})
	}
	return out
}

type licenseInfoDTO struct {
	LicenseID  string    `json:"license_id"`
	Customer   string    `json:"customer"`
	IssuedAt   time.Time `json:"issued_at"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	MaxTargets int       `json:"max_targets"`
	Features   []string  `json:"features"`
	Replaces   string    `json:"replaces"`
	KeyID      string    `json:"key_id"`
}

func licenseInfoJSON(p *license.Payload, keyID string) *licenseInfoDTO {
	if p == nil {
		return nil
	}
	features := p.Features
	if features == nil {
		features = []string{}
	}
	return &licenseInfoDTO{
		LicenseID: p.LicenseID, Customer: p.Customer, IssuedAt: p.IssuedAt.UTC(), ValidFrom: p.ValidFrom.UTC(),
		ValidUntil: p.ValidUntil.UTC(), MaxTargets: p.MaxTargets, Features: features, Replaces: p.Replaces, KeyID: keyID,
	}
}

type licenseFileDTO struct {
	Status     string          `json:"status"`
	UploadedAt time.Time       `json:"uploaded_at"`
	License    *licenseInfoDTO `json:"license"`
}

type licenseHistoryDTO struct {
	At        time.Time `json:"at"`
	Event     string    `json:"event"`
	LicenseID string    `json:"license_id"`
	FromState string    `json:"from_state"`
	ToState   string    `json:"to_state"`
	Notice    *string   `json:"notice"`
}

type licenseDetailDTO struct {
	InstallationID string              `json:"installation_id"`
	InstalledAt    time.Time           `json:"installed_at"`
	Phase          string              `json:"phase"`
	EffectiveTime  time.Time           `json:"effective_time"`
	Current        *licenseInfoDTO     `json:"current"`
	Pending        *licenseInfoDTO     `json:"pending"`
	MaxTargets     int                 `json:"max_targets"`
	TargetsUsed    int                 `json:"targets_used"`
	EndsAt         time.Time           `json:"ends_at"`
	LocksAt        time.Time           `json:"locks_at"`
	DaysLeft       int                 `json:"days_left"`
	GraceDay       int                 `json:"grace_day"`
	Tampered       bool                `json:"tampered"`
	Files          []licenseFileDTO    `json:"files"`
	History        []licenseHistoryDTO `json:"history"`
}

func licenseDetailJSON(d license.Detail) licenseDetailDTO {
	s := d.Snapshot
	e := s.Eval
	var currentKey, pendingKey string
	for _, f := range d.Files {
		switch {
		case f.Payload != nil && f.Seq == e.CurrentSeq:
			currentKey = f.KeyID
		case f.Payload != nil && f.Seq == e.PendingSeq:
			pendingKey = f.KeyID
		}
	}
	out := licenseDetailDTO{
		InstallationID: s.InstallationID, InstalledAt: s.InstalledAt.UTC(), Phase: string(e.Phase),
		EffectiveTime: s.Reading.Effective.UTC(), Current: licenseInfoJSON(e.Current, currentKey),
		Pending: licenseInfoJSON(e.Pending, pendingKey), MaxTargets: e.MaxTargets, TargetsUsed: s.Targets,
		EndsAt: e.EndsAt.UTC(), LocksAt: e.LocksAt.UTC(), DaysLeft: e.DaysLeft, GraceDay: e.GraceDay, Tampered: s.Tampered,
		Files: make([]licenseFileDTO, 0, len(d.Files)), History: make([]licenseHistoryDTO, 0, len(d.History)),
	}
	for _, f := range d.Files {
		out.Files = append(out.Files, licenseFileDTO{Status: f.Status, UploadedAt: f.UploadedAt.UTC(), License: licenseInfoJSON(f.Payload, f.KeyID)})
	}
	for _, h := range d.History {
		var notice *string
		if h.Notice != "" {
			n := h.Notice
			notice = &n
		}
		out.History = append(out.History, licenseHistoryDTO{At: h.At.UTC(), Event: h.Event, LicenseID: h.LicenseID,
			FromState: h.FromState, ToState: h.ToState, Notice: notice})
	}
	return out
}

type uploadResultDTO struct {
	License        licenseInfoDTO `json:"license"`
	Pending        bool           `json:"pending"`
	AlreadyExpired bool           `json:"already_expired"`
	Correction     bool           `json:"correction"`
	Duplicate      bool           `json:"duplicate"`
	Phase          string         `json:"phase"`
}

func uploadResultJSON(r license.UploadResult) uploadResultDTO {
	return uploadResultDTO{License: *licenseInfoJSON(&r.Payload, r.KeyID), Pending: r.Pending, AlreadyExpired: r.AlreadyExpired,
		Correction: r.Correction, Duplicate: r.Duplicate, Phase: string(r.Phase)}
}
```

Create `internal/api/license_handlers.go`:

```go
package api

import (
	"net/http"

	"alice/internal/license"
	"alice/internal/rbac"
)

// licenseRoutes serve the license status for every signed-in person (banners), the license
// page for Administrators and Auditors, and the upload for Administrators with step-up
// (spec §9.6, §19.1, §25.1). Uploading works in every license state (R9).
func (s *server) licenseRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/license/status", perm: rbac.Read, handler: s.licenseStatus},
		{method: http.MethodGet, pattern: "/api/v1/license", perm: rbac.LicenseRead, handler: s.licenseDetail},
		{method: http.MethodPost, pattern: "/api/v1/license/preview", perm: rbac.LicenseManage, lic: license.ClassAlways, handler: s.licensePreview},
		{method: http.MethodPost, pattern: "/api/v1/license", perm: rbac.LicenseManage, lic: license.ClassAlways, handler: s.licenseInstall},
	}
}

// licenseStatus answers from the in-memory snapshot: it never touches the database.
func (s *server) licenseStatus(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	snap := s.deps.License.Snapshot()
	out := licenseStatusDTO{Expired: snap.Eval.Expired(), Banners: bannersJSON(snap.Banners(p.Role == rbac.Admin))}
	if p.Role == rbac.Admin || p.Role == rbac.Auditor {
		phase := string(snap.Eval.Phase)
		out.Phase = &phase
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) licenseDetail(w http.ResponseWriter, r *http.Request) {
	d, err := s.deps.License.Detail(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, licenseDetailJSON(d))
}

// licenseUpload is the request body: the license file as text (at most 64 KiB, checked
// by the license module; the JSON body itself is capped at 1 MiB).
type licenseUpload struct {
	License string `json:"license"`
}

func (s *server) licensePreview(w http.ResponseWriter, r *http.Request) {
	var req licenseUpload
	if !s.decode(w, r, &req) {
		return
	}
	res, err := s.deps.License.Preview(r.Context(), []byte(req.License))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, uploadResultJSON(res))
}

func (s *server) licenseInstall(w http.ResponseWriter, r *http.Request) {
	var req licenseUpload
	if !s.decode(w, r, &req) {
		return
	}
	p := principalFrom(r.Context())
	res, err := s.deps.License.Install(r.Context(), []byte(req.License), p.Actor(s.meta(r)), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, uploadResultJSON(res))
}
```

In `internal/api/errors.go`:

1. Add `"alice/internal/license"` to the imports.
2. After `ErrLicenseLocked` add:

```go
	ErrLicenseInvalid            = ErrorCode{Code: "ALC-LIC-0002", Reason: "license.invalid", Status: http.StatusUnprocessableEntity}
	ErrLicenseWrongInstallation  = ErrorCode{Code: "ALC-LIC-0003", Reason: "license.wrong_installation", Status: http.StatusUnprocessableEntity}
	ErrLicenseUnknownKey         = ErrorCode{Code: "ALC-LIC-0004", Reason: "license.unknown_key", Status: http.StatusUnprocessableEntity}
	ErrLicenseRevokedKey         = ErrorCode{Code: "ALC-LIC-0005", Reason: "license.revoked_key", Status: http.StatusUnprocessableEntity}
	ErrLicenseUnsupportedFormat  = ErrorCode{Code: "ALC-LIC-0006", Reason: "license.unsupported_format", Status: http.StatusUnprocessableEntity}
	ErrLicenseOlderThanInstalled = ErrorCode{Code: "ALC-LIC-0007", Reason: "license.older_than_installed", Status: http.StatusConflict}
	ErrLicenseTargetLimit        = ErrorCode{Code: "ALC-LIC-0008", Reason: "license.target_limit_reached", Status: http.StatusConflict}
```

3. Append to `AllErrorCodes` after `ErrLicenseLocked,`:

```go
		ErrLicenseInvalid, ErrLicenseWrongInstallation, ErrLicenseUnknownKey, ErrLicenseRevokedKey,
		ErrLicenseUnsupportedFormat, ErrLicenseOlderThanInstalled, ErrLicenseTargetLimit,
```

4. Append to `errorMap`:

```go
	{license.ErrInvalid, ErrLicenseInvalid, nil},
	{license.ErrUnknownKey, ErrLicenseUnknownKey, nil},
	{license.ErrRevokedKey, ErrLicenseRevokedKey, nil},
	{license.ErrUnsupportedFormat, ErrLicenseUnsupportedFormat, nil},
	{license.ErrOlderThanInstalled, ErrLicenseOlderThanInstalled, nil},
	{license.ErrLocked, ErrLicenseLocked, nil},
	{license.ErrNoInstallation, ErrUnavailable, nil},
```

5. In `fail`, before the `for _, m := range errorMap` loop add:

```go
	var wrong *license.WrongInstallationError
	if errors.As(err, &wrong) {
		s.writeErrorWith(w, r, ErrLicenseWrongInstallation, map[string]string{"expected": wrong.Expected, "got": wrong.Got}, nil)
		return
	}
	var limit *license.TargetLimitError
	if errors.As(err, &limit) {
		s.writeErrorWith(w, r, ErrLicenseTargetLimit, map[string]string{"used": strconv.Itoa(limit.Used), "max": strconv.Itoa(limit.Max)}, nil)
		return
	}
```

- [ ] **Step 3: Add the error texts and troubleshooting entries**

In `locales/common/en.json`, inside `errors.license` (after `"locked"`), add:

```json
      "invalid": {
        "title": "This file is not a valid Alice license.",
        "cause": "The file may be damaged or edited, or it is not a license file.",
        "action": "Download the file again from your vendor's email and upload that file."
      },
      "wrong_installation": {
        "title": "This license file was made for a different installation (ending in {{got}}).",
        "cause": "A license works only on the installation whose ID it names. This installation's ID ends in {{expected}}.",
        "action": "Ask your vendor for a license for this installation and send them the Installation ID shown on this page."
      },
      "unknown_key": {
        "title": "This license was issued with a key this version of Alice does not know.",
        "cause": "The license is for a newer version of Alice, or it was not issued by your vendor.",
        "action": "Contact your vendor's support."
      },
      "revoked_key": {
        "title": "This license was signed with a key that is no longer trusted.",
        "cause": "Your vendor replaced its signing key.",
        "action": "Ask your vendor for a new license file; they issue it free of charge."
      },
      "unsupported_format": {
        "title": "This license needs a newer version of Alice.",
        "cause": "The file uses a format this version of Alice cannot read.",
        "action": "Update Alice, then upload the file again. The current license stays in use meanwhile."
      },
      "older_than_installed": {
        "title": "A newer license is already installed.",
        "cause": "This file is older than the license in use and does not last longer.",
        "action": "Uploading this file is not needed. If your vendor sent it as a correction, ask them for a correction license."
      },
      "target_limit_reached": {
        "title": "Your license allows {{max}} targets.",
        "cause": "{{used}} targets are in use, so no more can be added. Existing targets keep working.",
        "action": "Remove a target you no longer need, or ask your vendor to increase your license."
      }
```

In `locales/common/tr.json` at the same place:

```json
      "invalid": {
        "title": "Bu dosya geçerli bir Alice lisansı değil.",
        "cause": "Dosya bozulmuş veya değiştirilmiş olabilir ya da bir lisans dosyası değildir.",
        "action": "Dosyayı satıcınızın e-postasından yeniden indirin ve o dosyayı yükleyin."
      },
      "wrong_installation": {
        "title": "Bu lisans dosyası başka bir kurulum için hazırlanmış (sonu: {{got}}).",
        "cause": "Lisans yalnızca kimliği içinde yazan kurulumda çalışır. Bu kurulumun kimliğinin sonu: {{expected}}.",
        "action": "Satıcınızdan bu kurulum için lisans isteyin ve bu sayfada gösterilen Kurulum Kimliğini gönderin."
      },
      "unknown_key": {
        "title": "Bu lisans, Alice'in bu sürümünün tanımadığı bir anahtarla düzenlenmiş.",
        "cause": "Lisans Alice'in daha yeni bir sürümü için düzenlenmiş veya satıcınız tarafından düzenlenmemiş.",
        "action": "Satıcınızın destek ekibiyle iletişime geçin."
      },
      "revoked_key": {
        "title": "Bu lisans artık güvenilmeyen bir anahtarla imzalanmış.",
        "cause": "Satıcınız imza anahtarını değiştirdi.",
        "action": "Satıcınızdan yeni bir lisans dosyası isteyin; ücretsiz olarak düzenlenir."
      },
      "unsupported_format": {
        "title": "Bu lisans için Alice'in daha yeni bir sürümü gerekiyor.",
        "cause": "Dosya, Alice'in bu sürümünün okuyamadığı bir biçim kullanıyor.",
        "action": "Alice'i güncelleyin, ardından dosyayı yeniden yükleyin. Bu sırada mevcut lisans kullanılmaya devam eder."
      },
      "older_than_installed": {
        "title": "Daha yeni bir lisans zaten yüklü.",
        "cause": "Bu dosya kullanılan lisanstan daha eski ve daha uzun süreli değil.",
        "action": "Bu dosyayı yüklemeniz gerekmiyor. Satıcınız bunu düzeltme olarak gönderdiyse sizden bir düzeltme lisansı isteyin."
      },
      "target_limit_reached": {
        "title": "Lisansınız en fazla {{max}} hedefe izin veriyor.",
        "cause": "Kullanımdaki hedef sayısı {{used}}; bu nedenle yeni hedef eklenemez. Mevcut hedefler çalışmaya devam eder.",
        "action": "Artık gerekmeyen bir hedefi kaldırın veya satıcınızdan lisansınızı artırmasını isteyin."
      }
```

Append to `docs/troubleshooting.md`:

```markdown

## ALC-LIC-0002: Not a valid license file

**Meaning.** The uploaded file is not a license Alice can accept (HTTP 422): it is not a license file, it is
damaged, or a value in it was changed after the vendor signed it. Nothing was changed; the installed license stays.

**Likely cause.** The file was opened and saved by an editor that changed it, only part of it was copied, or the
wrong attachment was chosen.

**What to do.** Save the attachment from the vendor's email again, without opening it, and upload that file.

## ALC-LIC-0003: License for another installation

**Meaning.** The license names a different Installation ID (HTTP 422). The message shows the last six characters of
both IDs.

**Likely cause.** The license was made for another Alice server, or the ID was mistyped when it was requested.

**What to do.** Copy the Installation ID from the **License** page, send it to your vendor and upload the new file.
Restoring a backup keeps the Installation ID, so a license keeps working after moving to new hardware.

## ALC-LIC-0004: Unknown signing key

**Meaning.** The license was signed with a key this Alice version does not contain (HTTP 422).

**Likely cause.** The license is for a newer Alice release, or it was not issued by your vendor. A development build
without the vendor's key refuses every license.

**What to do.** Contact your vendor's support, quoting the request ID.

## ALC-LIC-0005: Signing key no longer trusted

**Meaning.** The license was signed with a vendor key that this Alice version marks as revoked (HTTP 422).

**Likely cause.** The vendor replaced its signing key.

**What to do.** Ask your vendor for a new license file; it is free of charge.

## ALC-LIC-0006: Newer license format

**Meaning.** The license uses a newer file format than this Alice version reads (HTTP 422). The current license
stays in use.

**Likely cause.** The vendor issued the license for a newer Alice release.

**What to do.** Update Alice (see `docs/upgrade.md` when available), then upload the file again.

## ALC-LIC-0007: A newer license is already installed

**Meaning.** The file is older than the license in use and does not last longer (HTTP 409). Nothing was changed.

**Likely cause.** An old license file was uploaded by mistake.

**What to do.** Nothing, if the current license is right. If your vendor sent the older file on purpose, ask them
for a correction license (it names the license it replaces and is always accepted).

## ALC-LIC-0008: License target limit reached

**Meaning.** Adding a target would exceed the number of targets the license allows (HTTP 409, `params.used`,
`params.max`). Existing targets keep working; nothing is locked.

**Likely cause.** All licensed targets are in use, or a renewal lowered the limit below the targets in use.

**What to do.** Remove a target that is no longer needed, or ask your vendor to increase the license.
```

- [ ] **Step 4: Document the operations**

In `api/openapi.yaml`, after the `/api/v1/audit/verify` path block add:

```yaml
  /api/v1/license/status:
    get:
      operationId: getLicenseStatus
      summary: Whether the license has expired, and the license banners the caller sees
      x-permission: read
      responses:
        "200":
          description: License status
          content:
            application/json:
              schema: { $ref: "#/components/schemas/LicenseStatus" }
        default: { $ref: "#/components/responses/Error" }
  /api/v1/license:
    get:
      operationId: getLicense
      summary: Installation ID, license in force, uploaded files and history
      x-permission: license.read
      responses:
        "200":
          description: License details
          content:
            application/json:
              schema: { $ref: "#/components/schemas/LicenseDetail" }
        default: { $ref: "#/components/responses/Error" }
    post:
      operationId: installLicense
      summary: Upload a license file; it takes effect at once
      x-permission: license.manage
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/LicenseUpload" }
      responses:
        "200":
          description: The license was installed (or was already installed)
          content:
            application/json:
              schema: { $ref: "#/components/schemas/LicenseUploadResult" }
        "409": { $ref: "#/components/responses/Error" }
        "422": { $ref: "#/components/responses/Error" }
        default: { $ref: "#/components/responses/Error" }
  /api/v1/license/preview:
    post:
      operationId: previewLicense
      summary: Check a license file and show what uploading it would do, without storing it
      x-permission: license.manage
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/LicenseUpload" }
      responses:
        "200":
          description: The license could be installed
          content:
            application/json:
              schema: { $ref: "#/components/schemas/LicenseUploadResult" }
        "409": { $ref: "#/components/responses/Error" }
        "422": { $ref: "#/components/responses/Error" }
        default: { $ref: "#/components/responses/Error" }
```

and under `components.schemas` (after `SetupStatus`):

```yaml
    LicenseBanner:
      type: object
      required: [kind, severity, params]
      properties:
        kind:
          type: string
          enum: [evaluation, evaluation_ended, expiry_warning, grace, locked, tampered, clock_behind, clock_jump, pending, over_limit, limit_reached]
        severity: { type: string, enum: [info, warning, caution, danger] }
        params: { type: object, additionalProperties: { type: string } }
    LicenseStatus:
      type: object
      required: [expired, banners]
      properties:
        expired: { type: boolean, description: The license or the evaluation has ended (grace or lock) }
        phase:
          type: string
          enum: [evaluation, evaluation_expired, active, grace, locked]
          description: Only for Administrators and Auditors
        banners: { type: array, items: { $ref: "#/components/schemas/LicenseBanner" } }
    LicenseInfo:
      type: object
      required: [license_id, customer, issued_at, valid_from, valid_until, max_targets, features, replaces, key_id]
      properties:
        license_id: { type: string }
        customer: { type: string }
        issued_at: { type: string, format: date-time }
        valid_from: { type: string, format: date-time }
        valid_until: { type: string, format: date-time }
        max_targets: { type: integer, minimum: 1, maximum: 100000 }
        features: { type: array, items: { type: string } }
        replaces: { type: string, description: License ID a correction license replaces; empty otherwise }
        key_id: { type: string }
    LicenseFile:
      type: object
      required: [status, uploaded_at, license]
      properties:
        status: { type: string, enum: [current, pending, superseded, invalid] }
        uploaded_at: { type: string, format: date-time }
        license:
          oneOf:
            - $ref: "#/components/schemas/LicenseInfo"
            - type: "null"
    LicenseHistoryEntry:
      type: object
      required: [at, event, license_id, from_state, to_state, notice]
      properties:
        at: { type: string, format: date-time }
        event: { type: string, enum: [installed, renewed, state_change, clock_anomaly, rejected, notice] }
        license_id: { type: string }
        from_state: { type: string }
        to_state: { type: string }
        notice: { type: [string, "null"] }
    LicenseDetail:
      type: object
      required: [installation_id, installed_at, phase, effective_time, current, pending, max_targets, targets_used,
        ends_at, locks_at, days_left, grace_day, tampered, files, history]
      properties:
        installation_id: { type: string, examples: [ALICE-7F3K-9Q2M-XD41-B8TC] }
        installed_at: { type: string, format: date-time }
        phase: { type: string, enum: [evaluation, evaluation_expired, active, grace, locked] }
        effective_time: { type: string, format: date-time, description: The trusted time license states are computed from }
        current:
          oneOf:
            - $ref: "#/components/schemas/LicenseInfo"
            - type: "null"
        pending:
          oneOf:
            - $ref: "#/components/schemas/LicenseInfo"
            - type: "null"
        max_targets: { type: integer }
        targets_used: { type: integer }
        ends_at: { type: string, format: date-time }
        locks_at: { type: string, format: date-time }
        days_left: { type: integer }
        grace_day: { type: integer }
        tampered: { type: boolean }
        files: { type: array, items: { $ref: "#/components/schemas/LicenseFile" } }
        history: { type: array, items: { $ref: "#/components/schemas/LicenseHistoryEntry" } }
    LicenseUpload:
      type: object
      additionalProperties: false
      required: [license]
      properties:
        license: { type: string, maxLength: 65536, description: The license file content (UTF-8 JSON text) }
    LicenseUploadResult:
      type: object
      required: [license, pending, already_expired, correction, duplicate, phase]
      properties:
        license: { $ref: "#/components/schemas/LicenseInfo" }
        pending: { type: boolean, description: valid_from is still ahead; the previous license continues until then }
        already_expired: { type: boolean }
        correction: { type: boolean }
        duplicate: { type: boolean, description: This license was already installed; nothing changed }
        phase: { type: string, enum: [evaluation, evaluation_expired, active, grace, locked] }
```

Run: `make authz-doc && go test -count=1 ./internal/api/`
Expected: PASS (route table, spec and matrix agree; the unit tests of Step 1 pass).

- [ ] **Step 5: Run the real license service in the stack harness**

In `internal/api/stack_integration_test.go`:

1. Add to the imports `"alice/internal/license"`, `"alice/internal/license/licensetest"`, `"alice/internal/notify"`.
2. Add the fields `license *license.Service` and `stateDir string` to `stack`, and `stateDir: t.TempDir(),` to the literal in `newStack`.
3. In `start()`, after `hasher := …` and before `s.auth = …`, add:

```go
	s.license = license.New(license.Config{
		Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, Uptime: s.clock,
		Keys: licensetest.KeySet(), StateDir: s.stateDir, Notifier: notify.AdminNotifier{Clock: s.clock},
		Log: logging.New(s.logs, slog.LevelDebug),
	})
	require.NoError(t, s.license.Start(ctx))
```

and add `License: s.license,` to the `setup.Config` literal.
4. In `deps()` replace `License: allowAll{},` with `License: s.license,` and delete the `allowAll` type.

Create `internal/api/license_integration_test.go`:

```go
//go:build integration

package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

type paramsBody struct {
	Error struct {
		Params map[string]string `json:"params"`
	} `json:"error"`
}

func (s *stack) signedLicense(id string, from, until time.Time, targets int) string {
	p := licensetest.Payload(s.license.Snapshot().InstallationID, from, until, targets)
	p.LicenseID = id
	return string(licensetest.Sign(p))
}

// §19.1 and §25.1: preview, confirm, roles.
func TestLicenseUploadAcrossRoles(t *testing.T) {
	s, admin, adminAcct := installed(t)
	now := s.clock.Now()
	file := s.signedLicense("LIC-A", now, now.AddDate(1, 0, 0), 10)

	s.clock.Advance(6 * time.Minute) // the step-up window of the wizard has closed
	requireError(t, admin.do(http.MethodPost, "/api/v1/license/preview", map[string]string{"license": file}), http.StatusForbidden, "ALC-AUTH-0003")
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/license/preview", map[string]string{"license": file})
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "Test Company", decodeBody[map[string]any](t, rec)["license"].(map[string]any)["customer"])
	assert.Equal(t, 0, s.count("license_files"), "a preview stores nothing")

	rec = admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": file})
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "active", decodeBody[map[string]any](t, rec)["phase"])
	detail := decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/license", nil))
	assert.Equal(t, "LIC-A", detail["current"].(map[string]any)["license_id"])
	assert.Equal(t, s.license.Snapshot().InstallationID, detail["installation_id"])

	auditor := s.createUser(admin, adminAcct, "audra", "auditor", "auditor-password-2026")
	ac := s.freshClient()
	s.firstSignIn(ac, auditor)
	requireStatus(t, ac.do(http.MethodGet, "/api/v1/license", nil), http.StatusOK)
	requireStatus(t, ac.do(http.MethodPost, "/api/v1/license", map[string]string{"license": file}), http.StatusForbidden)

	operator := s.createUser(admin, adminAcct, "otto", "operator", "operator-password-2026")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)
	requireStatus(t, oc.do(http.MethodGet, "/api/v1/license", nil), http.StatusForbidden)
	st := decodeBody[map[string]any](t, oc.do(http.MethodGet, "/api/v1/license/status", nil))
	assert.Equal(t, false, st["expired"])
	assert.NotContains(t, st, "phase", "L-15")
}

// L-40, L-43: refused uploads change nothing and are audited.
func TestLicenseUploadRefusals(t *testing.T) {
	s, admin, adminAcct := installed(t)
	now := s.clock.Now()
	s.stepUp(admin, adminAcct)
	good := s.signedLicense("LIC-A", now, now.AddDate(1, 0, 0), 10)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": good}), http.StatusOK)

	edited := strings.Replace(s.signedLicense("LIC-B", now, now.AddDate(1, 0, 0), 10), `"max_targets": 10`, `"max_targets": 1000`, 1)
	requireError(t, admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": edited}), http.StatusUnprocessableEntity, "ALC-LIC-0002")
	other := string(licensetest.Sign(licensetest.Payload(license.NewInstallationID(), now, now.AddDate(1, 0, 0), 10)))
	rec := admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": other})
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-LIC-0003")
	body := decodeBody[paramsBody](t, rec)
	assert.Equal(t, license.IDSuffix(s.license.Snapshot().InstallationID), body.Error.Params["expected"])

	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'license.upload.invalid_signature' AND result = 'failure'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'license.upload.wrong_installation'"))
	assert.Equal(t, 1, s.count("license_files"))
	assert.Equal(t, "LIC-A", s.license.Snapshot().Eval.Key())
}

// L-25 (the parts that exist in Phase 2): in lock, sign-in, the license upload, user
// administration and the audit log keep working.
func TestLockKeepsPlatformAdministrationAvailable(t *testing.T) {
	s, admin, adminAcct := installed(t)
	s.clock.Advance(31 * 24 * time.Hour) // the evaluation ends (R1)
	require.NoError(t, s.license.Tick(t.Context()))
	require.True(t, s.license.Snapshot().Eval.Locked())

	s.signIn(admin, adminAcct) // the old session idled out; signing in still works
	st := decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/license/status", nil))
	assert.Equal(t, true, st["expired"])
	assert.Equal(t, "evaluation_expired", st["phase"])

	s.createUser(admin, adminAcct, "nora", "auditor", "auditor-password-2026")
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/audit", nil), http.StatusOK)
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/audit/export?format=json", nil), http.StatusOK)

	now := s.clock.Now()
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/license", map[string]string{"license": s.signedLicense("LIC-A", now, now.AddDate(1, 0, 0), 10)})
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "active", decodeBody[map[string]any](t, rec)["phase"], "the renewal works at once (L-30)")
	assert.Equal(t, false, decodeBody[map[string]any](t, admin.do(http.MethodGet, "/api/v1/license/status", nil))["expired"])
}
```

- [ ] **Step 6: Extend the secret-leak suite**

In `internal/api/leak_integration_test.go`, `TestSecretsNeverLeak`:

1. Add `"alice/internal/license/licensetest"` to the imports.
2. After the line that revokes the token (`requireStatus(t, browser.do(http.MethodDelete, "/api/v1/tokens/"+tokens[0]["id"].(string), nil), http.StatusNoContent)`) add:

```go
	// License endpoints: status, detail, preview, upload and a refused upload.
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/license/status", nil), http.StatusOK)
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/license", nil), http.StatusOK)
	licFile := string(licensetest.Sign(licensetest.Payload(s.license.Snapshot().InstallationID, s.clock.Now(), s.clock.Now().AddDate(1, 0, 0), 10)))
	requireStatus(t, browser.do(http.MethodPost, "/api/v1/license/preview", map[string]string{"license": licFile}), http.StatusOK)
	requireStatus(t, browser.do(http.MethodPost, "/api/v1/license", map[string]string{"license": licFile}), http.StatusOK)
	requireError(t, browser.do(http.MethodPost, "/api/v1/license", map[string]string{"license": junk}), http.StatusUnprocessableEntity, "ALC-LIC-0002")
```

3. Add to `secretsUnderTest` (after the operator TOTP DEK entry):

```go
		{name: "HWM MAC key", forms: binaryForms(s.keyring.Derive(secrets.LabelHWM))},
		{name: "HWM encryption key", forms: binaryForms(s.keyring.Derive(secrets.LabelHWMEnc))},
```

- [ ] **Step 7: Run everything**

Run:
```bash
go test -race -count=1 ./internal/api/
go test -race -count=1 -tags integration ./internal/api/ ./internal/license/ ./internal/setup/
make lint i18n-check
```
Expected: PASS — including `TestA06GETRoutesNeverChangeState` (the two new GET routes change nothing), `TestSecretsNeverLeak`, `TestOpenAPIResponsesExposeNoSecretFields`, `TestEveryErrorCodeIsDocumentedInTroubleshooting`.

- [ ] **Step 8: Commit**

```bash
git add internal/api/ api/openapi.yaml locales/common/ docs/troubleshooting.md docs/authz-matrix.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(api): license status, details, preview and upload

GET /license/status gives everyone the banners they may see (phase for
Admins and Auditors only, L-15); GET /license (Admin, Auditor) shows the
Installation ID, the license in force, uploads and history; preview and
upload need an Admin with step-up and work in every license state. Upload
errors map to ALC-LIC-0002..0008 with EN/TR texts and troubleshooting
entries. The stack harness runs the real license service; the leak suite
covers the HWM sub-keys.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 15: Wiring — license, email and scheduler in `alice serve`; `alice license keys|status`; state volume

Composition root (spec §5.4 `cmd/*`): `serve` builds the license service (production key set, state directory,
build-time floor), starts it before listening, runs the scheduler (`license.evaluate` hourly, `notify.send` every
minute) and saves the time record at shutdown. Configuration gains `ALICE_STATE_DIR` and the Phase 2 SMTP
variables (R36 item 14). Two operator commands help the owner: `alice license keys` (embedded key IDs and
fingerprints, to compare with the vendor's record, §19.2) and `alice license status`. A release-build test proves
test-signed licenses are refused and that no test or vendor code is linked.

**Files:**
- Modify: `internal/platform/config/config.go`, `internal/platform/config/config_test.go`
- Modify: `cmd/alice/services.go`, `cmd/alice/main.go`, `cmd/alice/cli.go`, `cmd/alice/testapi.go`, `cmd/alice/testapi_release.go`, `cmd/alice/testapi_e2e.go`
- Create: `cmd/alice/license_cli.go`, `cmd/alice/license_release_test.go` (`!e2e && !testlicense`)
- Test: `cmd/alice/cli_test.go`, `cmd/alice/cli_integration_test.go`, `cmd/alice/leak_integration_test.go`
- Modify: `deploy/docker-compose.yml`, `deploy/docker-compose.e2e.yml`, `deploy/Dockerfile`, `Makefile`

**Interfaces:**
- Consumes: `license.New/Config/EmbeddedKeys/Fingerprint/TestKeyTrusted/ErrNoInstallation/EvaluationMaxTargets`, `Service.Start/Tick/Shutdown/Inspect` (Tasks 4, 8, 9); `notify.AdminNotifier`, `notify.Sender`, `notify.NewSMTPMailer`, `notify.SMTPConfig` (Task 10); `jobs.NewScheduler`, `jobs.Task`, `jobs.LicenseEvaluate`, `jobs.NotifySend` (Task 11); `setup.Config.License` (Task 13); `api.Deps.License` (Task 12).
- Produces (`alice/internal/platform/config`): `Config.StateDir string` (`ALICE_STATE_DIR`, default `/opt/alice/state`); `Config.SMTP SMTP`; `type SMTP struct { Host string; Port int; From, Username, PasswordFile, TLSMode, CAFile string }` from `ALICE_SMTP_HOST`, `ALICE_SMTP_PORT` (default 587, or 465 with TLS mode `tls`), `ALICE_SMTP_FROM` (required with a host), `ALICE_SMTP_USERNAME`, `ALICE_SMTP_PASSWORD_FILE`, `ALICE_SMTP_TLS` (`starttls` default | `tls`), `ALICE_SMTP_CA_FILE`; `func (s SMTP) Configured() bool`.
- Produces (`cmd/alice`): `type serverClock interface { clock.Clock; clock.Monotonic }`; `func newClock() serverClock`; `func buildServices(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, clk serverClock, log *slog.Logger) (*services, error)` with fields `license *license.Service`, `sender *notify.Sender`; `var testMailer notify.Mailer` (nil in release builds); `testDeps` gains `License *license.Service`, `Scheduler *jobs.Scheduler`, `Sender *notify.Sender`, `StateDir string`; commands `alice license keys`, `alice license status`.

- [ ] **Step 1: Write the failing configuration tests**

Append to `internal/platform/config/config_test.go`:

```go
func TestStateDirAndSMTPDefaults(t *testing.T) {
	c, err := config.Load(env(nil))
	require.NoError(t, err)
	assert.Equal(t, "/opt/alice/state", c.StateDir)
	assert.False(t, c.SMTP.Configured(), "no SMTP host: emails are recorded as skipped")
	assert.Equal(t, 587, c.SMTP.Port)
	assert.Equal(t, "starttls", c.SMTP.TLSMode)
}

func TestSMTPConfiguration(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"ALICE_STATE_DIR":          "/data/state",
		"ALICE_SMTP_HOST":          " mail.example.com ",
		"ALICE_SMTP_FROM":          "Alice <alice@example.com>",
		"ALICE_SMTP_USERNAME":      "alice",
		"ALICE_SMTP_PASSWORD_FILE": "/run/secrets/smtp_password",
		"ALICE_SMTP_TLS":           "tls",
		"ALICE_SMTP_CA_FILE":       "/opt/alice/keys/smtp-ca.pem",
	}))
	require.NoError(t, err)
	assert.Equal(t, "/data/state", c.StateDir)
	assert.True(t, c.SMTP.Configured())
	assert.Equal(t, config.SMTP{Host: "mail.example.com", Port: 465, From: "Alice <alice@example.com>", Username: "alice",
		PasswordFile: "/run/secrets/smtp_password", TLSMode: "tls", CAFile: "/opt/alice/keys/smtp-ca.pem"}, c.SMTP)
	assert.Contains(t, c.String(), "mail.example.com")

	for name, vars := range map[string]map[string]string{
		"port text":     {"ALICE_SMTP_HOST": "m", "ALICE_SMTP_FROM": "a@b.c", "ALICE_SMTP_PORT": "smtp"},
		"port range":    {"ALICE_SMTP_HOST": "m", "ALICE_SMTP_FROM": "a@b.c", "ALICE_SMTP_PORT": "70000"},
		"tls mode":      {"ALICE_SMTP_HOST": "m", "ALICE_SMTP_FROM": "a@b.c", "ALICE_SMTP_TLS": "none"},
		"missing from":  {"ALICE_SMTP_HOST": "m"},
	} {
		_, err := config.Load(env(vars))
		assert.Error(t, err, name)
	}
}
```

Run: `go test -count=1 ./internal/platform/config/`
Expected: FAIL — `c.StateDir undefined`, `config.SMTP undefined`.

- [ ] **Step 2: Implement the configuration**

In `internal/platform/config/config.go`:

1. Add `"strconv"` to the imports.
2. Add to `Config` after `KeysDir`:

```go
	// StateDir holds state that must survive restarts outside the database: the license
	// time record (spec §16.5). It is a separate volume in the container.
	StateDir string
```

and after `TrustedProxies`:

```go
	// SMTP is the Phase 2 email configuration (R36; Settings replaces it in Phase 7).
	SMTP SMTP
```

3. Add after the `Config` type:

```go
// SMTP configures the mail server. The password is read from PasswordFile at startup and
// never held in Config.
type SMTP struct {
	Host         string
	Port         int
	From         string
	Username     string
	PasswordFile string
	TLSMode      string // "starttls" or "tls"
	CAFile       string // PEM file of a private CA; empty = the system roots
}

// Configured reports whether an SMTP server is set.
func (s SMTP) Configured() bool { return s.Host != "" }
```

4. In `Load`, add `StateDir: withDefault(getenv("ALICE_STATE_DIR"), "/opt/alice/state"),` to the literal, and before `return c, nil` add:

```go
	smtpCfg, err := loadSMTP(getenv)
	if err != nil {
		return Config{}, err
	}
	c.SMTP = smtpCfg
```

5. Add:

```go
func loadSMTP(getenv func(string) string) (SMTP, error) {
	s := SMTP{
		Host:         strings.TrimSpace(getenv("ALICE_SMTP_HOST")),
		From:         strings.TrimSpace(getenv("ALICE_SMTP_FROM")),
		Username:     strings.TrimSpace(getenv("ALICE_SMTP_USERNAME")),
		PasswordFile: strings.TrimSpace(getenv("ALICE_SMTP_PASSWORD_FILE")),
		TLSMode:      withDefault(getenv("ALICE_SMTP_TLS"), "starttls"),
		CAFile:       strings.TrimSpace(getenv("ALICE_SMTP_CA_FILE")),
	}
	if s.TLSMode != "starttls" && s.TLSMode != "tls" {
		return SMTP{}, fmt.Errorf(`ALICE_SMTP_TLS must be "starttls" or "tls" (got %q)`, s.TLSMode)
	}
	s.Port = 587
	if s.TLSMode == "tls" {
		s.Port = 465
	}
	if p := strings.TrimSpace(getenv("ALICE_SMTP_PORT")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return SMTP{}, fmt.Errorf("ALICE_SMTP_PORT must be a number from 1 to 65535 (got %q)", p)
		}
		s.Port = n
	}
	if s.Host != "" && s.From == "" {
		return SMTP{}, errors.New("ALICE_SMTP_FROM must be set when ALICE_SMTP_HOST is set")
	}
	return s, nil
}
```

6. In `LogValue` add after `slog.String("keys_dir", c.KeysDir),`:

```go
		slog.String("state_dir", c.StateDir),
		slog.Group("smtp", "host", c.SMTP.Host, "port", c.SMTP.Port, "from", c.SMTP.From, "username", c.SMTP.Username, "tls", c.SMTP.TLSMode),
```

7. Replace `String()` with:

```go
func (c Config) String() string {
	return fmt.Sprintf("Config{DatabaseURL:%s MigrateDatabaseURL:%s ListenAddr:%s HealthAddr:%s KeysDir:%s StateDir:%s LogLevel:%s TLSHosts:%v TrustedProxies:%v SMTP:%s:%d}",
		redactURL(c.DatabaseURL), redactURL(c.MigrateDatabaseURL), c.ListenAddr, c.HealthAddr, c.KeysDir, c.StateDir, c.LogLevel, c.TLSHosts, c.proxies(), c.SMTP.Host, c.SMTP.Port)
}
```

8. In `MarshalJSON` add the fields `StateDir string `json:"state_dir"`` and `SMTPHost string `json:"smtp_host"`` after `KeysDir` and pass `c.StateDir, c.SMTP.Host` in the matching positions.

Run: `go test -race -count=1 ./internal/platform/config/`
Expected: PASS (the password-redaction tests still pass; no secret is in `SMTP`).

- [ ] **Step 3: Write the failing command tests**

Append to `cmd/alice/cli_test.go`:

```go
func TestLicenseKeysCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	require.Equal(t, 0, run([]string{"license", "keys"}, env(nil), &out, &errOut))
	keys := license.EmbeddedKeys()
	if keys.Len() == 0 {
		assert.Contains(t, out.String(), "No license verification key is embedded in this build")
	}
	for _, k := range keys.Keys() {
		assert.Contains(t, out.String(), k.ID)
		assert.Contains(t, out.String(), license.Fingerprint(k.Key))
	}
	assert.Equal(t, 2, run([]string{"license"}, env(nil), &out, &errOut))
	assert.Equal(t, 2, run([]string{"license", "delete"}, env(nil), &out, &errOut))
}
```

(add `"github.com/stretchr/testify/require"` and `"alice/internal/license"` to its imports if missing).

Create `cmd/alice/license_release_test.go`:

```go
//go:build !e2e && !testlicense

package main

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// Spec §22.6 / §26.4: the binary customers run refuses test-signed licenses.
func TestReleaseBinaryRefusesTestSignedLicenses(t *testing.T) {
	assert.False(t, license.TestKeyTrusted)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	raw := licensetest.Sign(licensetest.Payload(license.NewInstallationID(), now, now.AddDate(1, 0, 0), 10))
	_, err := license.Check(raw, license.EmbeddedKeys())
	assert.ErrorIs(t, err, license.ErrUnknownKey)
}

// The release build of alice links no test signer, no vendor signing code, no testify and
// no terminal library (licensectl-only).
func TestReleaseBinaryLinksNoTestOrVendorCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	require.NoError(t, err)
	deps := strings.Fields(string(out))
	require.Contains(t, deps, "alice/internal/license")
	for _, forbidden := range []string{
		"alice/internal/license/licensetest", "alice/internal/license/issuer",
		"github.com/stretchr/testify/assert", "golang.org/x/term",
	} {
		assert.NotContains(t, deps, forbidden)
	}
}
```

In `cmd/alice/cli_integration_test.go`:

1. Change `cliEnv` to also set `"ALICE_STATE_DIR": t.TempDir()`.
2. Append:

```go
func TestLicenseStatusCLI(t *testing.T) {
	d := pgtest.New(t)
	getenv := cliEnv(t, d)
	code, _, errOut := runCLI(t, getenv, "license", "status")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "has not been started on this database yet")

	id := license.NewInstallationID()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO license (id, installation_id, installed_at, state, updated_at)
VALUES (1, $1, now(), 'evaluation', now())`, id)
	require.NoError(t, err)
	code, out, errOut := runCLI(t, getenv, "license", "status")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "Installation ID: "+id)
	assert.Contains(t, out, "State: evaluation")
	assert.Contains(t, out, "at most 5 targets")
	assert.Zero(t, countRows(t, d, "SELECT count(*) FROM settings WHERE key = 'time.hwm'"), "status changes nothing")
}

func countRows(t *testing.T, d *pgtest.DB, sql string) int {
	t.Helper()
	var n int
	require.NoError(t, d.Owner.QueryRow(context.Background(), sql).Scan(&n))
	return n
}
```

(add `"alice/internal/license"` to its imports).

In `cmd/alice/leak_integration_test.go`, `TestServeLogsNoDatabasePassword`, add `"ALICE_STATE_DIR": t.TempDir(),` to the environment map.

Run: `go test -count=1 ./cmd/alice/`
Expected: FAIL — `unknown command "license"`.

- [ ] **Step 4: Wire the services**

Replace `cmd/alice/services.go` with:

```go
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/i18n"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/version"
	"alice/locales"
)

// Argon2id memory is 64 MiB per password hash, so at most two run at once
// (the container memory limit is 512 MiB). Recovery-code hashes use 8 MiB.
const (
	passwordHashConcurrency = 2
	recoveryHashConcurrency = 4
)

// serverClock is the clock of the process: wall time for everything, plus uptime for the
// license clock guard (spec R26).
type serverClock interface {
	clock.Clock
	clock.Monotonic
}

// services are the module services shared by serve and the CLI commands.
type services struct {
	keyring *secrets.Keyring
	audit   *audit.Service
	auth    *auth.Service
	setup   *setup.Service
	license *license.Service
	sender  *notify.Sender
}

// buildServices loads (or, on a brand-new database, creates) the master key and wires the
// services on the application pool. It starts nothing: serve calls license.Start.
func buildServices(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, clk serverClock, log *slog.Logger) (*services, error) {
	keyring, err := secrets.LoadOrCreateMasterKey(ctx, pool, cfg.KeysDir, clk.Now())
	if err != nil {
		return nil, err
	}
	auditLog := audit.New(clk)
	passwords := auth.NewHasher(auth.PasswordParams, passwordHashConcurrency)
	authSvc := auth.NewService(auth.Config{
		Pool:           pool,
		Keyring:        keyring,
		Audit:          auditLog,
		Clock:          clk,
		Hasher:         passwords,
		RecoveryHasher: auth.NewHasher(auth.RecoveryCodeParams, recoveryHashConcurrency),
	})
	lic := license.New(license.Config{
		Pool:      pool,
		Keyring:   keyring,
		Audit:     auditLog,
		Clock:     clk,
		Uptime:    clk,
		Keys:      license.EmbeddedKeys(),
		StateDir:  cfg.StateDir,
		BuildTime: buildTime(),
		Notifier:  notify.AdminNotifier{Clock: clk},
		Log:       log,
	})
	setupSvc := setup.New(setup.Config{
		Pool:      pool,
		Auth:      authSvc,
		Keyring:   keyring,
		Audit:     auditLog,
		Clock:     clk,
		Hasher:    passwords,
		BackupKDF: secrets.BackupKDF,
		License:   lic,
	})
	mailer, err := newMailer(cfg, clk)
	if err != nil {
		return nil, err
	}
	catalog, err := i18n.Load(locales.FS)
	if err != nil {
		return nil, err
	}
	return &services{
		keyring: keyring,
		audit:   audit.NewService(auditLog, pool),
		auth:    authSvc,
		setup:   setupSvc,
		license: lic,
		sender:  &notify.Sender{Pool: pool, Mailer: mailer, Catalog: catalog, Clock: clk, Log: log},
	}, nil
}

// buildTime is the link-time build timestamp; the license time never falls below it (§16.5).
// Development builds have none.
func buildTime() time.Time {
	t, err := time.Parse(time.RFC3339, version.BuildTime)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// newMailer builds the SMTP mailer from ALICE_SMTP_*. Without a host it returns nil and the
// sender records emails as skipped (L-18). The e2e build uses its test mailbox instead.
func newMailer(cfg config.Config, clk clock.Clock) (notify.Mailer, error) {
	if testMailer != nil {
		return testMailer, nil
	}
	if !cfg.SMTP.Configured() {
		return nil, nil
	}
	c := notify.SMTPConfig{Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, From: cfg.SMTP.From, Username: cfg.SMTP.Username, TLSMode: cfg.SMTP.TLSMode}
	if cfg.SMTP.PasswordFile != "" {
		b, err := os.ReadFile(cfg.SMTP.PasswordFile) //nolint:gosec // G304: operator-supplied path from ALICE_SMTP_PASSWORD_FILE
		if err != nil {
			return nil, fmt.Errorf("read ALICE_SMTP_PASSWORD_FILE %s: %w", cfg.SMTP.PasswordFile, errors.Unwrap(err))
		}
		c.Password = secrets.NewPlaintext(bytes.TrimRight(b, "\r\n"))
	}
	if cfg.SMTP.CAFile != "" {
		pem, err := os.ReadFile(cfg.SMTP.CAFile) //nolint:gosec // G304: operator-supplied path from ALICE_SMTP_CA_FILE
		if err != nil {
			return nil, fmt.Errorf("read ALICE_SMTP_CA_FILE %s: %w", cfg.SMTP.CAFile, errors.Unwrap(err))
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ALICE_SMTP_CA_FILE %s holds no PEM certificate", cfg.SMTP.CAFile)
		}
		c.RootCAs = pool
	}
	m, err := notify.NewSMTPMailer(c, clk)
	if err != nil {
		return nil, err
	}
	return m, nil
}
```

In `cmd/alice/testapi_release.go`:

1. Add `"alice/internal/notify"` to the imports.
2. Replace `func newClock() clock.Clock { return clock.Real{} }` with `func newClock() serverClock { return clock.Real{} }`.
3. Add:

```go
// testMailer is nil: release builds send email only through ALICE_SMTP_*.
var testMailer notify.Mailer
```

In `cmd/alice/testapi_e2e.go`: replace `func newClock() clock.Clock { return e2eClock }` with `func newClock() serverClock { return e2eClock }`, add `"alice/internal/notify"` to the imports, and add `var testMailer notify.Mailer // the test mailbox arrives with the e2e test API` (replaced in Task 16).

In `cmd/alice/testapi.go` replace `testDeps` with:

```go
// testDeps is what the e2e-only test endpoints need. Release builds ignore it.
type testDeps struct {
	OwnerURL    string // migration (owner) role: truncating tables needs it; never logged or returned
	Setup       *setup.Service
	License     *license.Service
	Scheduler   *jobs.Scheduler
	Sender      *notify.Sender
	StateDir    string
	Log         *slog.Logger
	ResetLimits func()
}
```

(imports `alice/internal/jobs`, `alice/internal/license`, `alice/internal/notify`).

- [ ] **Step 5: Start the license and the scheduler in `serve`; save the time record at shutdown**

In `cmd/alice/main.go`:

1. Add `"alice/internal/jobs"` to the imports.
2. In `serve`, replace

```go
	clk := newClock()
	svc, err := buildServices(ctx, pool, cfg.KeysDir, clk)
	if err != nil {
		return err
	}
```

with

```go
	clk := newClock()
	svc, err := buildServices(ctx, pool, cfg, clk, log)
	if err != nil {
		return err
	}
	// The installation ID, the time record and the first evaluation exist before any request.
	if err := svc.license.Start(ctx); err != nil {
		return err
	}
	sched := jobs.NewScheduler(clk, svc.license, log,
		jobs.Task{Type: jobs.LicenseEvaluate, Every: time.Hour, Run: svc.license.Tick},
		jobs.Task{Type: jobs.NotifySend, Every: time.Minute, Run: func(ctx context.Context) error {
			_, err := svc.sender.Drain(ctx)
			return err
		}},
	)
	schedCtx, stopSched := context.WithCancel(ctx)
	schedDone := make(chan struct{})
	go func() {
		sched.Run(schedCtx)
		close(schedDone)
	}()
```

3. In the `testDeps` literal add `License: svc.license, Scheduler: sched, Sender: svc.sender, StateDir: cfg.StateDir,`, and in `deps` add `License: svc.license,` after `Audit: svc.audit,`.
4. Replace the shutdown block

```go
	_ = public.Shutdown(shutdownCtx)
	_ = internal.Shutdown(shutdownCtx)
	return runErr
```

with

```go
	_ = public.Shutdown(shutdownCtx)
	_ = internal.Shutdown(shutdownCtx)
	stopSched()
	<-schedDone
	if err := svc.license.Shutdown(shutdownCtx); err != nil {
		log.Error("could not save the license time record at shutdown", "error_type", fmt.Sprintf("%T", err))
	}
	return runErr
```

5. Add to `usage` after the `admin unlock` line:

```
  license status              Show the installation ID and the license state
  license keys                List the license verification keys built into this binary
```

and to the `switch cmd` in `run`:

```go
	case "license":
		return runLicense(args[1:], cfg, stdout, stderr)
```

In `cmd/alice/cli.go`, `withServices`, replace `svc, err := buildServices(ctx, pool, cfg.KeysDir, newClock())` with `svc, err := buildServices(ctx, pool, cfg, newClock(), slog.New(slog.DiscardHandler))` and add `"log/slog"` to its imports.

Create `cmd/alice/license_cli.go`:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"alice/internal/license"
	"alice/internal/platform/config"
)

func runLicense(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "keys" && args[0] != "status") {
		fmt.Fprintln(stderr, "usage: alice license status\n       alice license keys")
		return 2
	}
	if args[0] == "keys" {
		return printLicenseKeys(stdout)
	}
	return withServices(cfg, stderr, func(ctx context.Context, svc *services) int {
		snap, err := svc.license.Inspect(ctx)
		if errors.Is(err, license.ErrNoInstallation) {
			fmt.Fprintln(stderr, "Alice has not been started on this database yet, so there is no installation ID.")
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, "could not read the license state:", err)
			return 1
		}
		fmt.Fprintf(stdout, "Installation ID: %s\n", snap.InstallationID)
		fmt.Fprintf(stdout, "State: %s\n", snap.Eval.Phase)
		if cur := snap.Eval.Current; cur != nil {
			fmt.Fprintf(stdout, "License: %s for %s, up to %d targets, valid until %s\n",
				cur.LicenseID, cur.Customer, cur.MaxTargets, cur.ValidUntil.Format(time.RFC3339))
		} else {
			fmt.Fprintf(stdout, "Evaluation: ends %s (at most %d targets)\n", snap.Eval.EndsAt.Format(time.RFC3339), license.EvaluationMaxTargets)
		}
		if snap.Reading.Behind {
			fmt.Fprintln(stdout, "Warning: the system clock is behind the time Alice last saw; Alice uses the later time.")
		}
		return 0
	})
}

// printLicenseKeys lists the embedded verification keys so the owner can compare each
// fingerprint with the vendor's recorded one (spec §19.2).
func printLicenseKeys(stdout io.Writer) int {
	keys := license.EmbeddedKeys()
	if keys.Len() == 0 {
		fmt.Fprintln(stdout, "No license verification key is embedded in this build: no license file can be installed (evaluation only).")
	}
	for _, k := range keys.Keys() {
		fmt.Fprintf(stdout, "%s  %s  %s\n", k.ID, k.Status, license.Fingerprint(k.Key))
	}
	if license.TestKeyTrusted {
		fmt.Fprintln(stdout, "WARNING: test build: the test signing key is trusted. Never use this build for real data.")
	}
	return 0
}
```

Run:
```bash
go test -race -count=1 ./cmd/alice/ ./internal/platform/config/
go test -race -count=1 -tags e2e ./cmd/alice/
go test -count=1 -tags integration ./cmd/alice/
```
Expected: PASS.

- [ ] **Step 6: Give the container a state volume and build the e2e image with the test key**

In `deploy/docker-compose.yml`, service `alice`:

1. Add to `environment`:

```yaml
      ALICE_STATE_DIR: /opt/alice/state
      # Phase 2 email (R36): set these in deploy/.env to send license warnings. The password is
      # read from a file; mount it with a compose override (see docs/operator-guide.md).
      ALICE_SMTP_HOST: ${ALICE_SMTP_HOST:-}
      ALICE_SMTP_PORT: ${ALICE_SMTP_PORT:-}
      ALICE_SMTP_FROM: ${ALICE_SMTP_FROM:-}
      ALICE_SMTP_USERNAME: ${ALICE_SMTP_USERNAME:-}
      ALICE_SMTP_PASSWORD_FILE: ${ALICE_SMTP_PASSWORD_FILE:-}
      ALICE_SMTP_TLS: ${ALICE_SMTP_TLS:-}
```

2. Add `      - alice-state:/opt/alice/state` under `volumes` (after `alice-keys`), and `  alice-state: {}` to the top-level `volumes`.

In `deploy/Dockerfile` replace

```dockerfile
 && mkdir -p /out/keys && chmod 0700 /out/keys
```

with

```dockerfile
 && mkdir -p /out/keys /out/state && chmod 0700 /out/keys /out/state
```

and after `COPY --from=build --chown=10001:10001 /out/keys /opt/alice/keys` add:

```dockerfile
COPY --from=build --chown=10001:10001 /out/state /opt/alice/state
```

Replace `deploy/docker-compose.e2e.yml` with:

```yaml
# Test-only overlay: builds the e2e variant of alice (build tags "e2e testlicense"), which adds
# the /test/* endpoints used by Playwright (demo clock, reset, setup code, test licenses, test
# mailbox) and trusts the test license signing key. Never use this file for a real installation;
# release images are built without these tags and refuse test-signed licenses.
services:
  alice:
    image: alice:e2e
    build:
      args:
        GO_TAGS: e2e testlicense
```

In `Makefile`, `test` target, replace `go test -race -count=1 -tags e2e ./cmd/alice/` with `go test -race -count=1 -tags "e2e testlicense" ./cmd/alice/`; in `lint`, replace `golangci-lint run --build-tags e2e ./cmd/...` with `golangci-lint run --build-tags e2e,testlicense ./cmd/...`.

Run: `make lint test && make up && make hardening-check && make down`
Expected: all green; the stack starts with the new volume and `docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec -T alice /usr/local/bin/alice license status` prints an installation ID (run it before `make down`).

- [ ] **Step 7: Commit**

```bash
git add internal/platform/config/ cmd/alice/ deploy/ Makefile
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(cmd): run licensing, email and the scheduler in alice serve

serve starts the license service before listening, runs license.evaluate
hourly and notify.send every minute through the gated scheduler, and saves
the time record at shutdown. New configuration: ALICE_STATE_DIR (a separate
volume) and ALICE_SMTP_*. New commands: alice license keys (embedded key
fingerprints) and alice license status. A release-build test proves
test-signed licenses are refused and no test or vendor code is linked; the
e2e image is built with -tags \"e2e testlicense\".

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 16: e2e test API — demo clock both ways, test licenses, test mailbox, full reset

The demo clock of spec §22.4 and §26.4 owner step 4–5 (the "test build", never shipped): Playwright and the owner
move the server date forward (thresholds, grace, lock) and backward (clock warning); a wall-only jump simulates an
administrator changing the system time. After every move the license evaluation and the email sender run at once,
so banners and emails appear without waiting an hour. `/test/license` issues test-signed licenses for the current
installation (only the `testlicense` build trusts them), `/test/mail` shows the emails the e2e build "sent", and
`/test/reset` also clears the license, the time record file and the mailbox.

**Files:**
- Modify: `cmd/alice/testapi_e2e.go` (replace the whole file)
- Test: `cmd/alice/testapi_e2e_test.go`

**Interfaces:**
- Consumes: `testDeps` fields `License`, `Scheduler`, `StateDir`, `Setup`, `OwnerURL`, `ResetLimits` (Task 15); `jobs.LicenseEvaluate`, `jobs.NotifySend`; `licensetest.Payload/Sign`; `license.HWMFileName`; `notify.Message`; `clock.Offset.Advance/JumpWall/Reset`.
- Produces (e2e build only):
  - `POST /test/clock` `{"advance_seconds": n, "wall_only": bool}` — n in ±315360000 (10 years); negative moves back; `wall_only` changes only the wall clock (no uptime: a suspicious jump). Then runs `license.evaluate` and `notify.send`. Answers `{"now": RFC3339Nano}`.
  - `POST /test/license` `{"installation_id"?, "license_id"?, "customer"?, "max_targets"?, "valid_from"? (RFC 3339), "valid_days"? (default 365), "replaces"?}` → `{"license": "<file text>", "license_id": "..."}`; defaults: this installation, 10 targets, from the demo clock's now.
  - `GET /test/mail` → `{"messages": [{"to", "subject", "body"}]}` (oldest first).
  - `POST /test/reset` additionally truncates the license tables (Task 7), deletes `<state>/hwm.dat`, empties the mailbox and starts the license service again (a fresh installation).
  - `var testMailer notify.Mailer = e2eMailbox`.

- [ ] **Step 1: Write the failing tests**

In `cmd/alice/testapi_e2e_test.go`:

1. In `TestE2EClockRejectsMalformedInput` replace the map entry `` `{"advance_seconds":-5}`:        http.StatusUnprocessableEntity,`` with `` `{"advance_seconds":-315360001}`: http.StatusUnprocessableEntity,``.
2. Append (and add `"context"`, `"alice/internal/license"`, `"alice/internal/notify"` to the imports):

```go
func postTest(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

// Owner step 5: the demo clock can move back; a wall-only jump adds no uptime.
func TestE2EClockMovesBackAndJumps(t *testing.T) {
	t.Cleanup(e2eClock.Reset)
	h := testHandler(testDeps{})
	before, up := e2eClock.Now(), e2eClock.Elapsed()

	require.Equal(t, http.StatusOK, postTest(t, h, "/test/clock", `{"advance_seconds":-86400}`).Code)
	assert.Less(t, e2eClock.Now().Sub(before), -23*time.Hour)
	assert.GreaterOrEqual(t, e2eClock.Elapsed(), up, "uptime never decreases")

	up = e2eClock.Elapsed()
	require.Equal(t, http.StatusOK, postTest(t, h, "/test/clock", `{"advance_seconds":864000,"wall_only":true}`).Code)
	assert.Less(t, e2eClock.Elapsed()-up, time.Second, "a wall-only jump is not uptime")

	assert.Equal(t, http.StatusBadRequest, postTest(t, h, "/test/clock", `{"advance_seconds":1,"extra":true}`).Code)
}

// Only the testlicense build trusts what /test/license signs.
func TestE2ETestLicenseIsSignedWithTheTestKey(t *testing.T) {
	h := testHandler(testDeps{})
	id := license.NewInstallationID()
	rec := postTest(t, h, "/test/license", `{"installation_id":"`+id+`","max_targets":7,"valid_days":30,"customer":"Örnek A.Ş."}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		License   string `json:"license"`
		LicenseID string `json:"license_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	f, err := license.Check([]byte(body.License), license.EmbeddedKeys())
	require.NoError(t, err)
	assert.Equal(t, id, f.Payload.InstallationID)
	assert.Equal(t, 7, f.Payload.MaxTargets)
	assert.Equal(t, "Örnek A.Ş.", f.Payload.Customer)
	assert.Equal(t, body.LicenseID, f.Payload.LicenseID)
	assert.Equal(t, 30*24*time.Hour, f.Payload.ValidUntil.Sub(f.Payload.ValidFrom))

	assert.Equal(t, http.StatusConflict, postTest(t, h, "/test/license", `{}`).Code, "no running license service: the installation is unknown")
	assert.Equal(t, http.StatusUnprocessableEntity, postTest(t, h, "/test/license", `{"installation_id":"`+id+`","max_targets":0}`).Code)
}

func TestE2EMailboxListsSentEmail(t *testing.T) {
	t.Cleanup(e2eMailbox.reset)
	require.NoError(t, testMailer.Send(context.Background(), notify.Message{To: "ada@example.com", Subject: "Hi", Body: "Body"}))
	rec := httptest.NewRecorder()
	testHandler(testDeps{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/test/mail", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"messages":[{"to":"ada@example.com","subject":"Hi","body":"Body"}]}`, rec.Body.String())
}
```

Run: `go test -count=1 -tags "e2e testlicense" ./cmd/alice/`
Expected: FAIL — negative advance answers 422, `/test/license` and `/test/mail` answer 404, `e2eMailbox` undefined.

- [ ] **Step 2: Replace the e2e test API**

Replace `cmd/alice/testapi_e2e.go` with:

```go
//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/api"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
)

// versionSuffix marks the e2e build in "alice version" and /api/v1/version.
const versionSuffix = "+e2e"

// maxTestBody is the request body limit of the API (SEC-023), applied to /test too.
const maxTestBody = 1 << 20

// maxClockMove bounds one POST /test/clock step (10 years of 365 days) in either direction.
const maxClockMove = 10 * 365 * 24 * time.Hour

// e2eClock is the server clock in the e2e build; POST /test/clock moves it.
var e2eClock = clock.NewOffset(clock.Real{})

func newClock() serverClock { return e2eClock }

// testMailbox keeps the emails of the e2e build instead of sending them (GET /test/mail).
type testMailbox struct {
	mu   sync.Mutex
	msgs []notify.Message
}

func (b *testMailbox) Send(_ context.Context, m notify.Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.msgs = append(b.msgs, m)
	return nil
}

func (b *testMailbox) all() []notify.Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]notify.Message(nil), b.msgs...)
}

func (b *testMailbox) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.msgs = nil
}

var e2eMailbox = &testMailbox{}

// testMailer makes serve use the mailbox instead of SMTP.
var testMailer notify.Mailer = e2eMailbox

// resetSQL empties every application table. master_key_versions is kept because the master
// key file on the volume stays the same.
const resetSQL = `TRUNCATE users, user_mfa, recovery_codes, sessions, api_tokens, setup_sessions, settings, audit_log,
license, license_files, license_history, notifications_outbox`

// decodeTest reads a JSON body strictly; an empty body is an empty object.
func decodeTest(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTestBody))
	if err != nil {
		writeTestJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be a JSON object with the documented fields"})
		return false
	}
	return true
}

// afterClockChange runs the license evaluation and the email sender at once, so the effects
// of a demo-clock move are visible immediately instead of at the next hourly tick.
func afterClockChange(ctx context.Context, d testDeps) {
	if d.Scheduler == nil {
		return
	}
	for _, task := range []string{jobs.LicenseEvaluate.Name, jobs.NotifySend.Name} {
		if err := d.Scheduler.RunNow(ctx, task); err != nil && !errors.Is(err, license.ErrLocked) {
			d.Log.Error("test clock: task failed", "job_type", task, "error_type", fmt.Sprintf("%T", err))
		}
	}
}

// testHandler serves the test-only endpoints of the e2e build (never shipped).
func testHandler(d testDeps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /test/clock", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, map[string]string{"now": e2eClock.Now().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("POST /test/clock", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AdvanceSeconds float64 `json:"advance_seconds"`
			WallOnly       bool    `json:"wall_only"`
		}
		if !decodeTest(w, r, &body) {
			return
		}
		if body.AdvanceSeconds < -maxClockMove.Seconds() || body.AdvanceSeconds > maxClockMove.Seconds() {
			writeTestJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "advance_seconds must be between -315360000 and 315360000 (10 years)"})
			return
		}
		step := time.Duration(body.AdvanceSeconds * float64(time.Second))
		if body.WallOnly {
			e2eClock.JumpWall(step)
		} else {
			e2eClock.Advance(step)
		}
		afterClockChange(r.Context(), d)
		writeTestJSON(w, http.StatusOK, map[string]string{"now": e2eClock.Now().Format(time.RFC3339Nano)})
	})
	mux.HandleFunc("POST /test/license", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			InstallationID string  `json:"installation_id"`
			LicenseID      string  `json:"license_id"`
			Customer       string  `json:"customer"`
			MaxTargets     int     `json:"max_targets"`
			ValidFrom      string  `json:"valid_from"`
			ValidDays      float64 `json:"valid_days"`
			Replaces       string  `json:"replaces"`
		}
		body.MaxTargets, body.ValidDays = 10, 365
		if !decodeTest(w, r, &body) {
			return
		}
		installation := body.InstallationID
		if installation == "" {
			if d.License == nil {
				writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no installation: give installation_id"})
				return
			}
			installation = d.License.Snapshot().InstallationID
		}
		from := e2eClock.Now().UTC().Truncate(time.Second)
		if body.ValidFrom != "" {
			t, err := time.Parse(time.RFC3339, body.ValidFrom)
			if err != nil {
				writeTestJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "valid_from must be RFC 3339"})
				return
			}
			from = t.UTC()
		}
		p := licensetest.Payload(installation, from, from.Add(time.Duration(body.ValidDays*24*float64(time.Hour))), body.MaxTargets)
		p.LicenseID = "LIC-E2E-" + rand.Text()[:10]
		if body.LicenseID != "" {
			p.LicenseID = body.LicenseID
		}
		if body.Customer != "" {
			p.Customer = body.Customer
		}
		p.Replaces = body.Replaces
		if err := p.Validate(); err != nil {
			writeTestJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]string{"license": string(licensetest.Sign(p)), "license_id": p.LicenseID})
	})
	mux.HandleFunc("GET /test/mail", func(w http.ResponseWriter, _ *http.Request) {
		type message struct {
			To      string `json:"to"`
			Subject string `json:"subject"`
			Body    string `json:"body"`
		}
		out := []message{}
		for _, m := range e2eMailbox.all() {
			out = append(out, message{To: m.To, Subject: m.Subject, Body: m.Body})
		}
		writeTestJSON(w, http.StatusOK, map[string]any{"messages": out})
	})
	mux.HandleFunc("POST /test/reset", func(w http.ResponseWriter, r *http.Request) {
		if err := resetInstall(r.Context(), d.OwnerURL); err != nil {
			d.Log.Error("test reset failed", "error", err.Error())
			writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "reset failed"})
			return
		}
		if d.StateDir != "" {
			if err := os.Remove(filepath.Join(d.StateDir, license.HWMFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				d.Log.Error("test reset: time record not removed", "error", err.Error())
			}
		}
		e2eClock.Reset()
		e2eMailbox.reset()
		d.Setup.ResetLockouts()
		d.ResetLimits()
		if d.License != nil {
			if err := d.License.Start(r.Context()); err != nil {
				d.Log.Error("test reset: license start failed", "error", err.Error())
				writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "reset failed"})
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /test/setup-token", func(w http.ResponseWriter, r *http.Request) {
		code, err := d.Setup.ResetToken(r.Context())
		if err != nil {
			writeTestJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]string{"code": code})
	})
	mux.HandleFunc("/test/", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "unknown test endpoint"})
	})
	// The endpoints change server state, so a cross-site page must not reach them
	// through a visitor's browser: unsafe methods get the API guard's same-origin check.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !api.SameOrigin(r) {
			writeTestJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request refused"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// resetInstall empties every application table as the owner role. The audit
// triggers forbid TRUNCATE, so they are disabled inside the transaction only.
func resetInstall(ctx context.Context, ownerURL string) error {
	pool, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		for _, stmt := range []string{
			`ALTER TABLE audit_log DISABLE TRIGGER USER`,
			resetSQL,
			`ALTER TABLE audit_log ENABLE TRIGGER USER`,
		} {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	})
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 3: Run the tests and lint**

Run:
```bash
go test -race -count=1 -tags "e2e testlicense" ./cmd/alice/
go test -race -count=1 ./cmd/alice/
golangci-lint run --build-tags e2e,testlicense ./cmd/...
```
Expected: PASS and no findings. (`TestE2EClockRejectsMalformedInput`'s "not json" case answers 400 through `decodeTest`; the 1 MiB case 413.)

- [ ] **Step 4: Try it on the e2e stack**

Run:
```bash
make e2e-up
curl -sk -X POST -H 'Origin: https://localhost' https://localhost:${ALICE_PORT:-443}/test/license -d '{}' | head -c 120; echo
curl -sk -X POST -H 'Origin: https://localhost' https://localhost:${ALICE_PORT:-443}/test/clock -d '{"advance_seconds":-7200}'
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml --env-file deploy/.env exec -T alice /usr/local/bin/alice license keys
```
Expected: a JSON object starting with `{"license":"{\n  \"format\": 1,`, a `now` two hours earlier, and `vk-test-01  active  SHA256:…` followed by the test-build warning. (Set `ALICE_PORT` from `deploy/.env` if it is not 443.)

- [ ] **Step 5: Commit**

```bash
git add cmd/alice/testapi_e2e.go cmd/alice/testapi_e2e_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "test(e2e): demo clock both ways, test licenses and a test mailbox

The e2e build's clock moves backward and can jump without uptime; after
every move the license evaluation and the email sender run at once.
/test/license signs licenses with the test key for this installation,
/test/mail lists the emails the build would have sent, and /test/reset
also clears the license tables, the time record file and the mailbox.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 17: `licensectl` — offline key file, issuing, verifying, signed ledger

Spec §19.2 (`keygen`, `issue`, `inspect`, `verify`, correction licenses via `--replaces`, the ledger, typo-proof
installation IDs), §16.7 and R8 (passphrase-protected key, Argon2id + AES-256-GCM, ≥ 6 Diceware words, signed
append-only issuance log), §26.4 ("a license issued by `licensectl` verifies in the server and one signed with
another key does not"; "tested on Linux and macOS"). The vendor side lives in `internal/license/issuer` so tests
and `licensectl` share it; `alice` never links it (Task 15's release test).

Agents and CI only ever create throw-away test keys in temporary directories with weakened KDF parameters. The
production key is created by the owner on an offline machine (Task 22 owner steps).

**Files:**
- Create: `internal/license/issuer/issuer.go`, `internal/license/issuer/ledger.go`
- Test: `internal/license/issuer/issuer_test.go`
- Create: `cmd/licensectl/main.go`, `cmd/licensectl/terminal.go`
- Test: `cmd/licensectl/main_test.go`
- Modify: `go.mod`, `go.sum` (`golang.org/x/term` becomes a direct dependency), `Makefile` (`licensectl` target), `.github/workflows/ci.yml` (Linux + macOS job), `.gitleaks.toml` (test passphrase)

**Interfaces:**
- Consumes: `license.Payload`, `license.Sign`, `license.EncodeFile`, `license.ParseFile`, `license.Check`, `license.ParseInstallationID`, `license.PublicKey`, `license.NewKeySet`, `license.EncodeKeySet`, `license.Fingerprint`, `license.FormatVersion` (Tasks 3–4); `clock.Clock`.
- Produces (`alice/internal/license/issuer`):
  - `type KDFParams struct { MemoryKiB, Time uint32; Threads uint8 }`; `var KeyKDF = KDFParams{MemoryKiB: 256*1024, Time: 4, Threads: 4}`.
  - `const PrivateKeyFile = "alice-license-private.pem"`, `PublicKeyFile = "alice-license-public.pem"`, `LedgerFile = "issued.csv"`.
  - Errors `ErrWeakPassphrase`, `ErrWrongPassphrase`, `ErrKeyExists`, `ErrBadKeyFile`, `ErrBadKeyID`, `ErrLedgerBroken`.
  - `func CheckPassphrase(p []byte) error`; `func GenerateKey(keyID string, passphrase []byte, p KDFParams) (privPEM, pubPEM []byte, err error)`; `func WriteKeyPair(dir, keyID string, passphrase []byte, p KDFParams) (privPath, pubPath string, err error)`; `func OpenKey(pemBytes, passphrase []byte) (*SigningKey, error)`; `func ReadPublicKey(pemBytes []byte) (license.PublicKey, error)`.
  - `type SigningKey` with `KeyID() string`, `Public() ed25519.PublicKey`, `Issue(p license.Payload) ([]byte, error)`, `Zero()`; it renders as `[redacted]` in every format.
  - `type Request struct { Installation, Customer string; Targets int; From string; Months int; Features []string; Replaces, LicenseID string }`; `func BuildPayload(req Request, now time.Time) (license.Payload, error)`.
  - `type LedgerEntry struct { LicenseID, Customer, InstallationID string; IssuedAt, ValidFrom, ValidUntil time.Time; MaxTargets int; Replaces, FileSHA256 string }`; `func AppendLedger(path string, k *SigningKey, e LedgerEntry) error`; `func VerifyLedger(path string, pub ed25519.PublicKey) (int, error)`.
- Produces (`cmd/licensectl`): `func run(args []string, stdin io.Reader, stdout, stderr io.Writer, ask prompter, clk clock.Clock) int`; `type prompter func(prompt string) ([]byte, error)`; commands `keygen`, `issue`, `inspect`, `verify`, `keyset`, `ledger-verify`.

- [ ] **Step 1: Write the failing issuer tests**

Create `internal/license/issuer/issuer_test.go`:

```go
package issuer_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
)

// Throw-away test keys only: weak KDF parameters keep the tests fast.
var fastKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

const testWords = "amber canyon violet orbit lantern quiet"

func TestPassphraseRules(t *testing.T) {
	assert.NoError(t, issuer.CheckPassphrase([]byte(testWords)))
	assert.NoError(t, issuer.CheckPassphrase([]byte("amber-canyon-violet-orbit-lantern-quiet")))
	for _, weak := range []string{"", "short", "one two three four five", "a b c d e f g h", "correcthorsebatterystaple-longpassword"} {
		assert.ErrorIs(t, issuer.CheckPassphrase([]byte(weak)), issuer.ErrWeakPassphrase, weak)
	}
}

func TestKeyFileRoundTripAndProtection(t *testing.T) {
	priv, pub, err := issuer.GenerateKey("vk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	assert.Contains(t, string(priv), "-----BEGIN ALICE LICENSE SIGNING KEY-----")
	assert.Contains(t, string(priv), "Kdf: argon2id")
	assert.Contains(t, string(pub), "-----BEGIN PUBLIC KEY-----")

	k, err := issuer.OpenKey(priv, []byte(testWords))
	require.NoError(t, err)
	assert.Equal(t, "vk-2026-01", k.KeyID())
	pk, err := issuer.ReadPublicKey(pub)
	require.NoError(t, err)
	assert.Equal(t, pk.Key, k.Public())
	assert.Equal(t, "vk-2026-01", pk.ID)

	_, err = issuer.OpenKey(priv, []byte("amber canyon violet orbit lantern loud"))
	assert.ErrorIs(t, err, issuer.ErrWrongPassphrase)
	for name, bad := range map[string]string{
		"other key id": strings.Replace(string(priv), "Key-Id: vk-2026-01", "Key-Id: vk-2026-02", 1),
		"weaker kdf":   strings.Replace(string(priv), "Kdf-Params: m=64,t=1,p=1", "Kdf-Params: m=64,t=1,p=2", 1),
	} {
		_, err := issuer.OpenKey([]byte(bad), []byte(testWords))
		assert.Error(t, err, name)
	}
	_, err = issuer.OpenKey(pub, []byte(testWords))
	assert.ErrorIs(t, err, issuer.ErrBadKeyFile)

	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), fmt.Sprintf("%x", k)} {
		assert.Contains(t, s, "[redacted]")
	}
	_, _, err = issuer.GenerateKey("key1", []byte(testWords), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrBadKeyID)
	_, _, err = issuer.GenerateKey("vk-2026-01", []byte("too weak"), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrWeakPassphrase)
}

func TestWriteKeyPairNeverOverwrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vendor")
	privPath, pubPath, err := issuer.WriteKeyPair(dir, "vk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	info, err := os.Stat(privPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	before, err := os.ReadFile(privPath)
	require.NoError(t, err)
	_, _, err = issuer.WriteKeyPair(dir, "vk-2026-01", []byte(testWords), fastKDF)
	assert.ErrorIs(t, err, issuer.ErrKeyExists)
	after, err := os.ReadFile(privPath)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.FileExists(t, pubPath)
}

var now = time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC)

// mistype swaps the last two characters of an ID, or, when they are equal, replaces the last one.
func mistype(id string) string {
	n := len(id)
	if id[n-1] != id[n-2] {
		return id[:n-2] + id[n-1:] + id[n-2:n-1]
	}
	repl := "0"
	if id[n-1] == '0' {
		repl = "1"
	}
	return id[:n-1] + repl
}

func TestBuildPayload(t *testing.T) {
	id := license.NewInstallationID()
	p, err := issuer.BuildPayload(issuer.Request{Installation: " " + id + " ", Customer: "Örnek Bankası A.Ş.", Targets: 100}, now)
	require.NoError(t, err)
	assert.Equal(t, id, p.InstallationID)
	assert.True(t, p.ValidFrom.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)), "today, 00:00 UTC")
	assert.True(t, p.ValidUntil.Equal(time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)), "12 months")
	assert.True(t, p.IssuedAt.Equal(now.Truncate(time.Second)))
	assert.Regexp(t, `^LIC-2026-\d{6}$`, p.LicenseID)
	assert.Equal(t, []string{}, p.Features)

	nfd := "O\u0308rnek" // "O" followed by a combining diaeresis (NFD)
	p, err = issuer.BuildPayload(issuer.Request{Installation: id, Customer: nfd, Targets: 1, From: "2026-10-15", Months: 3,
		Features: []string{" ha ", ""}, LicenseID: "LIC-X-1"}, now)
	require.NoError(t, err)
	assert.Equal(t, "Örnek", p.Customer, "customer names are NFC-normalized")
	assert.True(t, p.ValidUntil.Equal(time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)))
	assert.Equal(t, []string{"ha"}, p.Features)
	assert.Equal(t, "LIC-X-1", p.LicenseID)

	fix, err := issuer.BuildPayload(issuer.Request{Installation: id, Customer: "C", Targets: 1, From: "2026-09-01", Replaces: "LIC-X-1"}, now)
	require.NoError(t, err, "a correction license may start in the past (R7)")
	assert.True(t, fix.IssuedAt.Equal(fix.ValidFrom), "its issued_at is set to valid_from so §16.3 accepts it")

	for name, req := range map[string]issuer.Request{
		"typo in the ID":     {Installation: mistype(id), Customer: "C", Targets: 1},
		"no customer":        {Installation: id, Targets: 1},
		"zero targets":       {Installation: id, Customer: "C"},
		"backdated renewal":  {Installation: id, Customer: "C", Targets: 1, From: "2026-09-01"},
		"bad date":           {Installation: id, Customer: "C", Targets: 1, From: "01.10.2026"},
		"61 months":          {Installation: id, Customer: "C", Targets: 1, Months: 61},
	} {
		_, err := issuer.BuildPayload(req, now)
		assert.Error(t, err, name)
	}
}

func TestLedgerIsChainedAndSigned(t *testing.T) {
	priv, _, err := issuer.GenerateKey("vk-2026-01", []byte(testWords), fastKDF)
	require.NoError(t, err)
	k, err := issuer.OpenKey(priv, []byte(testWords))
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), issuer.LedgerFile)
	for i := range 3 {
		require.NoError(t, issuer.AppendLedger(path, k, issuer.LedgerEntry{
			LicenseID: fmt.Sprintf("LIC-%d", i), Customer: "Örnek, \"Bank\"", InstallationID: "ALICE-X",
			IssuedAt: now, ValidFrom: now, ValidUntil: now.AddDate(1, 0, 0), MaxTargets: 10, FileSHA256: "ab",
		}))
	}
	n, err := issuer.VerifyLedger(path, k.Public())
	require.NoError(t, err)
	assert.Equal(t, 3, n)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, lines, 4, "header + 3 rows")
	for name, broken := range map[string]string{
		"edited row":  strings.Replace(string(raw), "LIC-1", "LIC-9", 1),
		"removed row": strings.Join([]string{lines[0], lines[1], lines[3]}, "\n") + "\n",
		"reordered":   strings.Join([]string{lines[0], lines[2], lines[1], lines[3]}, "\n") + "\n",
	} {
		require.NoError(t, os.WriteFile(path, []byte(broken), 0o600))
		_, err := issuer.VerifyLedger(path, k.Public())
		assert.ErrorIs(t, err, issuer.ErrLedgerBroken, name)
	}
}
```

Run: `go test -count=1 ./internal/license/issuer/`
Expected: FAIL — `no non-test Go files`.

- [ ] **Step 2: Implement the key file and issuing**

Create `internal/license/issuer/issuer.go`:

```go
// Package issuer is the vendor side of licensing (spec §16.7, §19.2): the passphrase-protected
// signing key file, license issuing and the signed issuance ledger. Only cmd/licensectl and
// tests import it; the alice binary never links it (a test in cmd/alice checks this).
package issuer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"alice/internal/license"
)

// KDFParams are the Argon2id parameters of the key file.
type KDFParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// KeyKDF is used for new key files: stronger than backups, because the key is opened rarely
// and offline (256 MiB, 4 passes).
var KeyKDF = KDFParams{MemoryKiB: 256 * 1024, Time: 4, Threads: 4}

// File names and limits.
const (
	PrivateKeyFile      = "alice-license-private.pem"
	PublicKeyFile       = "alice-license-public.pem"
	LedgerFile          = "issued.csv"
	MinPassphraseWords  = 6
	MinPassphraseLength = 24

	privatePEMType = "ALICE LICENSE SIGNING KEY"
	publicPEMType  = "PUBLIC KEY"
	keyAAD         = "alice/license-signing-key/v1"
	maxKDFMemory   = 4 * 1024 * 1024 // KiB: a hostile key file cannot exhaust memory
)

// Errors.
var (
	ErrWeakPassphrase  = errors.New("issuer: the passphrase needs at least 6 words and 24 characters")
	ErrWrongPassphrase = errors.New("issuer: wrong passphrase, or the key file is damaged")
	ErrKeyExists       = errors.New("issuer: a key file already exists here; keygen never overwrites a key")
	ErrBadKeyFile      = errors.New("issuer: this is not an Alice license signing key file")
	ErrBadKeyID        = errors.New("issuer: the key ID must look like vk-2026-01")
	ErrLedgerBroken    = errors.New("issuer: the ledger was changed")
)

var keyIDPattern = regexp.MustCompile(`^vk-\d{4}-\d{2}$`)

// CheckPassphrase enforces R8/§16.7: at least six words (separated by spaces or dashes) and
// 24 characters, as a Diceware passphrase has.
func CheckPassphrase(p []byte) error {
	words := strings.FieldsFunc(string(p), func(r rune) bool { return unicode.IsSpace(r) || r == '-' })
	if len(words) < MinPassphraseWords || utf8.RuneCount(p) < MinPassphraseLength {
		return ErrWeakPassphrase
	}
	return nil
}

// SigningKey is an opened signing key. It never prints itself.
type SigningKey struct {
	id   string
	priv ed25519.PrivateKey
}

// KeyID returns the key ID (vk-YYYY-NN).
func (k *SigningKey) KeyID() string { return k.id }

// Public returns the public key.
func (k *SigningKey) Public() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }

// Zero overwrites the private key in memory.
func (k *SigningKey) Zero() { clear(k.priv) }

func (k *SigningKey) redacted() string { return "issuer.SigningKey{" + k.id + " [redacted]}" }

// String, GoString, Format and LogValue never reveal the key.
func (k *SigningKey) String() string               { return k.redacted() }
func (k *SigningKey) GoString() string             { return k.redacted() }
func (k *SigningKey) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, k.redacted()) }
func (k *SigningKey) LogValue() slog.Value         { return slog.StringValue(k.redacted()) }

// Issue signs p and returns the license file.
func (k *SigningKey) Issue(p license.Payload) ([]byte, error) {
	f, err := license.Sign(k.priv, k.id, p)
	if err != nil {
		return nil, err
	}
	return license.EncodeFile(f)
}

// GenerateKey creates a key pair: the private key encrypted under Argon2id(passphrase) with
// AES-256-GCM, and the public key as a PKIX PEM. Both carry the key ID.
func GenerateKey(keyID string, passphrase []byte, p KDFParams) (privPEM, pubPEM []byte, err error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, nil, ErrBadKeyID
	}
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	defer clear(priv)
	seed := priv.Seed()
	defer clear(seed)
	salt := make([]byte, 16)
	rand.Read(salt)
	headers := map[string]string{
		"Key-Id":     keyID,
		"Kdf":        "argon2id",
		"Kdf-Params": fmt.Sprintf("m=%d,t=%d,p=%d", p.MemoryKiB, p.Time, p.Threads),
		"Salt":       base64.StdEncoding.EncodeToString(salt),
		"Public-Key": base64.StdEncoding.EncodeToString(pub),
	}
	gcm, err := keyCipher(passphrase, salt, p)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	headers["Nonce"] = base64.StdEncoding.EncodeToString(nonce)
	ct := gcm.Seal(nil, nonce, seed, keyAADFor(headers))
	privPEM = pem.EncodeToMemory(&pem.Block{Type: privatePEMType, Headers: headers, Bytes: ct})
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Headers: map[string]string{"Key-Id": keyID}, Bytes: der})
	return privPEM, pubPEM, nil
}

func keyCipher(passphrase, salt []byte, p KDFParams) (cipher.AEAD, error) {
	kek := argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, 32)
	defer clear(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// keyAADFor binds the ciphertext to its headers: changing the key ID, the KDF parameters, the
// salt or the public key makes the file fail to open.
func keyAADFor(h map[string]string) []byte {
	return []byte(keyAAD + "\n" + h["Key-Id"] + "\n" + h["Kdf-Params"] + "\n" + h["Salt"] + "\n" + h["Public-Key"])
}

// OpenKey decrypts a key file.
func OpenKey(pemBytes, passphrase []byte) (*SigningKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != privatePEMType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrBadKeyFile
	}
	h := block.Headers
	var p KDFParams
	if !keyIDPattern.MatchString(h["Key-Id"]) || h["Kdf"] != "argon2id" {
		return nil, ErrBadKeyFile
	}
	if _, err := fmt.Sscanf(h["Kdf-Params"], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil ||
		p.MemoryKiB == 0 || p.MemoryKiB > maxKDFMemory || p.Time == 0 || p.Time > 64 || p.Threads == 0 {
		return nil, ErrBadKeyFile
	}
	salt, err1 := base64.StdEncoding.DecodeString(h["Salt"])
	nonce, err2 := base64.StdEncoding.DecodeString(h["Nonce"])
	pub, err3 := base64.StdEncoding.DecodeString(h["Public-Key"])
	if err1 != nil || err2 != nil || err3 != nil || len(salt) != 16 || len(pub) != ed25519.PublicKeySize {
		return nil, ErrBadKeyFile
	}
	gcm, err := keyCipher(passphrase, salt, p)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrBadKeyFile
	}
	seed, err := gcm.Open(nil, nonce, block.Bytes, keyAADFor(h))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrBadKeyFile
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		clear(priv)
		return nil, ErrBadKeyFile
	}
	return &SigningKey{id: h["Key-Id"], priv: priv}, nil
}

// ReadPublicKey reads a public key file written by GenerateKey.
func ReadPublicKey(pemBytes []byte) (license.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != publicPEMType || !keyIDPattern.MatchString(block.Headers["Key-Id"]) {
		return license.PublicKey{}, ErrBadKeyFile
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return license.PublicKey{}, ErrBadKeyFile
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return license.PublicKey{}, ErrBadKeyFile
	}
	return license.PublicKey{ID: block.Headers["Key-Id"], Key: pub, Status: license.KeyActive}, nil
}

// WriteKeyPair writes a new key pair into dir (created with mode 0700): the private key with
// mode 0600, the public key with 0644. It never overwrites an existing file.
func WriteKeyPair(dir, keyID string, passphrase []byte, p KDFParams) (privPath, pubPath string, err error) {
	privPath, pubPath = filepath.Join(dir, PrivateKeyFile), filepath.Join(dir, PublicKeyFile)
	for _, path := range []string{privPath, pubPath} {
		if _, err := os.Lstat(path); err == nil {
			return "", "", ErrKeyExists
		}
	}
	privPEM, pubPEM, err := GenerateKey(keyID, passphrase, p)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	if err := WriteNew(privPath, privPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := WriteNew(pubPath, pubPEM, 0o644); err != nil {
		return "", "", err
	}
	return privPath, pubPath, nil
}

// WriteNew creates path with data and mode; it fails with ErrKeyExists if path exists.
func WriteNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G304: vendor CLI path from its own flags
	if errors.Is(err, os.ErrExist) {
		return ErrKeyExists
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Request is what the vendor types into licensectl issue.
type Request struct {
	Installation string   // as typed; the check character is verified
	Customer     string   // NFC-normalized
	Targets      int      // 1..100000
	From         string   // "" = today 00:00 UTC; "2026-10-01" or RFC 3339
	Months       int      // 0 = 12; at most 60
	Features     []string // empty entries are dropped
	Replaces     string   // license ID a correction replaces (R7)
	LicenseID    string   // "" = LIC-<year>-<6 random digits>
}

// BuildPayload turns a request into a valid payload. A license normally starts at most a day
// in the past (§16.3: issued_at <= valid_from + 24h); a correction license (Replaces) may start
// earlier and then carries issued_at = valid_from ("may have an earlier issued_at", R7).
func BuildPayload(req Request, now time.Time) (license.Payload, error) {
	now = now.UTC().Truncate(time.Second)
	id, err := license.ParseInstallationID(req.Installation)
	if err != nil {
		return license.Payload{}, fmt.Errorf("the installation ID %q is not valid; check each character (the last one is a check character): %w", strings.TrimSpace(req.Installation), err)
	}
	from := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if s := strings.TrimSpace(req.From); s != "" {
		if from, err = parseDate(s); err != nil {
			return license.Payload{}, err
		}
	}
	months := req.Months
	if months == 0 {
		months = 12
	}
	if months < 1 || months > 60 {
		return license.Payload{}, errors.New("--months must be between 1 and 60")
	}
	issued := now
	if now.After(from.Add(24 * time.Hour)) {
		if req.Replaces == "" {
			return license.Payload{}, errors.New("--from is more than a day in the past; only a correction license (--replaces) may start earlier")
		}
		issued = from
	}
	licenseID := req.LicenseID
	if licenseID == "" {
		n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
		if err != nil {
			return license.Payload{}, err
		}
		licenseID = fmt.Sprintf("LIC-%d-%06d", now.Year(), n.Int64())
	}
	features := []string{}
	for _, f := range req.Features {
		if f = strings.TrimSpace(f); f != "" {
			features = append(features, f)
		}
	}
	p := license.Payload{
		LicenseID:      licenseID,
		Customer:       norm.NFC.String(strings.TrimSpace(req.Customer)),
		InstallationID: id,
		IssuedAt:       issued,
		ValidFrom:      from,
		ValidUntil:     from.AddDate(0, months, 0),
		MaxTargets:     req.Targets,
		Features:       features,
		Format:         license.FormatVersion,
		Replaces:       strings.TrimSpace(req.Replaces),
	}
	if err := p.Validate(); err != nil {
		return license.Payload{}, fmt.Errorf("the license would not be valid: %w", err)
	}
	return p, nil
}

func parseDate(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Truncate(time.Second), nil
	}
	return time.Time{}, fmt.Errorf("--from %q must be a date like 2026-10-01 or an RFC 3339 time", s)
}
```

Create `internal/license/issuer/ledger.go`:

```go
package issuer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"time"
)

const ledgerPrefix = "ALICE-LEDGER-v1\n"

var ledgerHeader = []string{"license_id", "customer", "installation_id", "issued_at", "valid_from", "valid_until",
	"max_targets", "replaces", "file_sha256", "chain", "signature"}

// LedgerEntry is one issued license (spec §19.2: the vendor's record of who owns what).
type LedgerEntry struct {
	LicenseID      string
	Customer       string
	InstallationID string
	IssuedAt       time.Time
	ValidFrom      time.Time
	ValidUntil     time.Time
	MaxTargets     int
	Replaces       string
	FileSHA256     string
}

func (e LedgerEntry) fields() []string {
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	return []string{e.LicenseID, e.Customer, e.InstallationID, ts(e.IssuedAt), ts(e.ValidFrom), ts(e.ValidUntil),
		strconv.Itoa(e.MaxTargets), e.Replaces, e.FileSHA256}
}

// ledgerChain = SHA-256(previous chain || each field || NUL).
func ledgerChain(prev []byte, fields []string) []byte {
	h := sha256.New()
	h.Write(prev)
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

func readLedger(path string) ([][]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: vendor CLI path from its own flags
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return csv.NewReader(f).ReadAll()
}

// AppendLedger appends e. Every row carries the chain value and an Ed25519 signature of
// "ALICE-LEDGER-v1\n" || chain, so an edited, removed or reordered row is detected (§16.7).
func AppendLedger(path string, k *SigningKey, e LedgerEntry) error {
	rows, err := readLedger(path)
	if err != nil {
		return fmt.Errorf("read the ledger: %w", err)
	}
	prev := make([]byte, sha256.Size)
	if n := len(rows); n > 1 {
		if prev, err = hex.DecodeString(rows[n-1][9]); err != nil {
			return ErrLedgerBroken
		}
	}
	fields := e.fields()
	chain := ledgerChain(prev, fields)
	sig := ed25519.Sign(k.priv, append([]byte(ledgerPrefix), chain...))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // G304: vendor CLI path from its own flags
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if len(rows) == 0 {
		_ = w.Write(ledgerHeader)
	}
	_ = w.Write(append(fields, hex.EncodeToString(chain), base64.StdEncoding.EncodeToString(sig)))
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// VerifyLedger checks every row's chain and signature and returns the number of licenses.
func VerifyLedger(path string, pub ed25519.PublicKey) (int, error) {
	rows, err := readLedger(path)
	if err != nil {
		return 0, fmt.Errorf("read the ledger: %w", err)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if !slices.Equal(rows[0], ledgerHeader) {
		return 0, fmt.Errorf("%w: the header is not the ledger header", ErrLedgerBroken)
	}
	prev := make([]byte, sha256.Size)
	for i, row := range rows[1:] {
		if len(row) != len(ledgerHeader) {
			return 0, fmt.Errorf("%w: row %d has %d columns", ErrLedgerBroken, i+1, len(row))
		}
		chain := ledgerChain(prev, row[:9])
		sig, err := base64.StdEncoding.DecodeString(row[10])
		if err != nil || hex.EncodeToString(chain) != row[9] || !ed25519.Verify(pub, append([]byte(ledgerPrefix), chain...), sig) {
			return 0, fmt.Errorf("%w at row %d (license %s)", ErrLedgerBroken, i+1, row[0])
		}
		prev = chain
	}
	return len(rows) - 1, nil
}
```

Run: `go test -race -count=1 ./internal/license/issuer/`
Expected: PASS.

- [ ] **Step 3: Write the failing CLI tests**

Create `cmd/licensectl/main_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
)

const testWords = "amber canyon violet orbit lantern quiet"

var testClock = clock.NewFake(time.Date(2026, 10, 1, 9, 30, 0, 0, time.UTC))

func TestMain(m *testing.M) {
	issuer.KeyKDF = issuer.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1} // throw-away test keys only
	os.Exit(m.Run())
}

// answers returns the given passphrases in turn; asking for more fails the test.
func answers(t *testing.T, list ...string) prompter {
	return func(string) ([]byte, error) {
		require.NotEmpty(t, list, "licensectl asked for a passphrase it should not need")
		a := list[0]
		list = list[1:]
		return []byte(a), nil
	}
}

func ctl(t *testing.T, stdin string, ask prompter, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut, ask, testClock)
	return code, out.String(), errOut.String()
}

func keygen(t *testing.T, dir string) {
	t.Helper()
	code, out, errOut := ctl(t, "", answers(t, testWords, testWords), "keygen", "--out", dir, "--key-id", "vk-2026-01")
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, out, "Fingerprint: SHA256:")
}

func keysetOf(t *testing.T, dir string) license.KeySet {
	t.Helper()
	code, out, errOut := ctl(t, "", nil, "keyset", "--pub", filepath.Join(dir, issuer.PublicKeyFile))
	require.Equal(t, 0, code, errOut)
	ks, err := license.ParseKeySet([]byte(strings.SplitN(out, "\nFingerprint", 2)[0]))
	require.NoError(t, err)
	return ks
}

func TestKeygen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vendor")
	keygen(t, dir)
	info, err := os.Stat(filepath.Join(dir, issuer.PrivateKeyFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	code, _, errOut := ctl(t, "", answers(t, testWords, testWords), "keygen", "--out", dir, "--key-id", "vk-2026-01")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "never overwrites")

	other := t.TempDir()
	code, _, errOut = ctl(t, "", answers(t, "too short"), "keygen", "--out", other, "--key-id", "vk-2026-01")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "6 words")
	code, _, errOut = ctl(t, "", answers(t, testWords, testWords+" x"), "keygen", "--out", other, "--key-id", "vk-2026-01")
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "differ")
	assert.NoFileExists(t, filepath.Join(other, issuer.PrivateKeyFile))
}

func issueArgs(dir, installation, out string, extra ...string) []string {
	return append([]string{"issue", "--key", filepath.Join(dir, issuer.PrivateKeyFile), "--installation", installation,
		"--customer", "Test Company", "--targets", "10", "--out", out}, extra...)
}

// §26.4: a license issued by licensectl verifies in the server; one signed with another key does not.
func TestIssuedLicenseVerifiesWithItsKeyOnly(t *testing.T) {
	dir := t.TempDir()
	keygen(t, dir)
	id := license.NewInstallationID()
	out := filepath.Join(t.TempDir(), "alice-license-test-20261001.alicelic")
	code, stdout, errOut := ctl(t, "yes\n", answers(t, testWords), issueArgs(dir, id, out)...)
	require.Equal(t, 0, code, errOut)
	assert.Contains(t, stdout, "Customer:      Test Company")
	assert.Contains(t, stdout, `Type "yes" to sign:`)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	f, err := license.Check(raw, keysetOf(t, dir))
	require.NoError(t, err)
	assert.Equal(t, id, f.Payload.InstallationID)
	assert.Equal(t, 10, f.Payload.MaxTargets)
	assert.True(t, f.Payload.ValidUntil.Equal(time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)))

	otherDir := t.TempDir()
	keygen(t, otherDir)
	_, err = license.Check(raw, keysetOf(t, otherDir))
	assert.ErrorIs(t, err, license.ErrInvalid, "same key ID, different key")

	code, stdout, _ = ctl(t, "", nil, "ledger-verify", "--pub", filepath.Join(dir, issuer.PublicKeyFile))
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "Ledger OK: 1 license")
}

// Review Focus 4: a mistyped installation ID is refused before the key is even opened.
func TestIssueRejectsMistypedInstallationID(t *testing.T) {
	dir := t.TempDir()
	keygen(t, dir)
	id := license.NewInstallationID()
	n := len(id)
	typo := id[:n-2] + id[n-1:] + id[n-2:n-1] // swap the last two characters
	if typo == id {
		typo = id[:n-1] + map[bool]string{true: "1", false: "0"}[id[n-1] == '0'] // or mistype the last one
	}
	out := filepath.Join(t.TempDir(), "x.alicelic")
	code, _, errOut := ctl(t, "yes\n", answers(t), issueArgs(dir, typo, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "check each character")
	assert.NoFileExists(t, out)
}

func TestIssueNeedsYesAndTheRightPassphrase(t *testing.T) {
	dir := t.TempDir()
	keygen(t, dir)
	id := license.NewInstallationID()
	out := filepath.Join(t.TempDir(), "x.alicelic")
	code, stdout, _ := ctl(t, "no\n", answers(t, testWords), issueArgs(dir, id, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "Nothing was signed.")
	assert.NoFileExists(t, out)
	assert.NoFileExists(t, filepath.Join(dir, issuer.LedgerFile))

	code, _, errOut := ctl(t, "yes\n", answers(t, "amber canyon violet orbit lantern loud"), issueArgs(dir, id, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "wrong passphrase")

	require.NoError(t, os.WriteFile(out, []byte("x"), 0o600))
	code, _, errOut = ctl(t, "yes\n", answers(t), issueArgs(dir, id, out)...)
	assert.Equal(t, 1, code)
	assert.Contains(t, errOut, "already exists")
}

// §19.2 step 4: a correction license names the license it replaces and may start earlier.
func TestCorrectionLicense(t *testing.T) {
	dir := t.TempDir()
	keygen(t, dir)
	out := filepath.Join(t.TempDir(), "fix.alicelic")
	code, _, errOut := ctl(t, "yes\n", answers(t, testWords),
		issueArgs(dir, license.NewInstallationID(), out, "--replaces", "LIC-2026-000001", "--from", "2026-09-01")...)
	require.Equal(t, 0, code, errOut)
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	f, err := license.Check(raw, keysetOf(t, dir))
	require.NoError(t, err)
	assert.Equal(t, "LIC-2026-000001", f.Payload.Replaces)
}

func TestInspectAndVerify(t *testing.T) {
	dir := t.TempDir()
	keygen(t, dir)
	out := filepath.Join(t.TempDir(), "x.alicelic")
	code, _, errOut := ctl(t, "yes\n", answers(t, testWords), issueArgs(dir, license.NewInstallationID(), out, "--license-id", "LIC-2026-000123")...)
	require.Equal(t, 0, code, errOut)

	code, stdout, _ := ctl(t, "", nil, "inspect", out)
	require.Equal(t, 0, code)
	for _, want := range []string{"license_id:      LIC-2026-000123", "customer:        Test Company", "max_targets:     10", "format:          1"} {
		assert.Contains(t, stdout, want)
	}
	pub := filepath.Join(dir, issuer.PublicKeyFile)
	code, stdout, _ = ctl(t, "", nil, "verify", "--pub", pub, out)
	assert.Equal(t, 0, code)
	assert.Equal(t, "OK\n", stdout)

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	tampered := filepath.Join(t.TempDir(), "t.alicelic")
	require.NoError(t, os.WriteFile(tampered, bytes.Replace(raw, []byte(`"max_targets": 10`), []byte(`"max_targets": 1000`), 1), 0o600))
	code, stdout, _ = ctl(t, "", nil, "verify", "--pub", pub, tampered)
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "SIGNATURE INVALID")
}

func TestUsage(t *testing.T) {
	code, _, errOut := ctl(t, "", nil)
	assert.Equal(t, 2, code)
	assert.Contains(t, errOut, "keygen")
	code, _, _ = ctl(t, "", nil, "frobnicate")
	assert.Equal(t, 2, code)
	code, _, _ = ctl(t, "", nil, "issue", "--key", "k")
	assert.Equal(t, 2, code, "missing required flags")
}
```

Run: `go test -count=1 ./cmd/licensectl/`
Expected: FAIL — `no non-test Go files in …/cmd/licensectl`.

- [ ] **Step 4: Implement `licensectl`**

Run: `go get golang.org/x/term@v0.46.0 && go mod tidy`
Expected: `golang.org/x/term` moves to the direct `require` block of `go.mod`.

Create `cmd/licensectl/terminal.go`:

```go
package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// terminalPassphrase reads a passphrase without echo. licensectl refuses to read a passphrase
// from a pipe or file, so it never ends up in shell history, scripts or logs.
func terminalPassphrase(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // G115: a file descriptor always fits in int
	if !term.IsTerminal(fd) {
		return nil, errors.New("licensectl must be run in a terminal so the passphrase is not echoed")
	}
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return p, err
}
```

Create `cmd/licensectl/main.go`:

```go
// Command licensectl is the vendor's offline license tool (spec §19.2). It never ships to
// customers, never uses the network, and handles the signing key only in memory.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"alice/internal/license"
	"alice/internal/license/issuer"
	"alice/internal/platform/clock"
)

// prompter asks for a passphrase (no echo on a terminal; injected by tests).
type prompter func(prompt string) ([]byte, error)

const usage = `Usage: licensectl <command> [flags]

Commands:
  keygen --out DIR --key-id vk-YYYY-NN
        Create the license signing key pair (once; never overwrites a key).
  issue --key FILE --installation ID --customer NAME --targets N --out FILE
        [--from YYYY-MM-DD] [--months 12] [--features a,b] [--replaces LICENSE-ID]
        [--license-id ID] [--ledger FILE]
        Sign a license. Asks for the key passphrase and for "yes" before signing.
  inspect FILE
        Print what a license file says (the signature is not checked).
  verify --pub FILE LICENSE-FILE
        Check a license file's signature: prints OK or SIGNATURE INVALID.
  keyset --pub FILE
        Print the key set entry for internal/license/keys/production.json and the fingerprint.
  ledger-verify --pub FILE [--ledger FILE]
        Check the issuance ledger (default: issued.csv next to the public key).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, terminalPassphrase, clock.Real{}))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, ask prompter, clk clock.Clock) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout, stderr, ask)
	case "issue":
		return issue(args[1:], stdin, stdout, stderr, ask, clk)
	case "inspect":
		return inspect(args[1:], stdout, stderr)
	case "verify":
		return verify(args[1:], stdout, stderr)
	case "keyset":
		return keyset(args[1:], stdout, stderr)
	case "ledger-verify":
		return ledgerVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func flags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func keygen(args []string, stdout, stderr io.Writer, ask prompter) int {
	fs := flags("keygen", stderr)
	out := fs.String("out", "", "directory for the key files")
	keyID := fs.String("key-id", "", "key ID, for example vk-2026-01")
	if fs.Parse(args) != nil || *out == "" || *keyID == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	pass, err := ask("New key passphrase (at least 6 random words): ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer clear(pass)
	if err := issuer.CheckPassphrase(pass); err != nil {
		fmt.Fprintln(stderr, "The passphrase is too weak: use at least 6 words and 24 characters (Diceware).")
		return 1
	}
	again, err := ask("Repeat the passphrase: ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer clear(again)
	if !bytes.Equal(pass, again) {
		fmt.Fprintln(stderr, "The two passphrases differ. Nothing was written.")
		return 1
	}
	privPath, pubPath, err := issuer.WriteKeyPair(*out, *keyID, pass, issuer.KeyKDF)
	if errors.Is(err, issuer.ErrKeyExists) {
		fmt.Fprintln(stderr, "A key already exists in", *out, "- keygen never overwrites a key.")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "keygen failed:", err)
		return 1
	}
	pubPEM, err := os.ReadFile(pubPath) //nolint:gosec // G304: the file keygen just wrote
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	pub, err := issuer.ReadPublicKey(pubPEM)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Private key (encrypted): %s\nPublic key: %s\nKey ID: %s\nFingerprint: %s\n",
		privPath, pubPath, pub.ID, license.Fingerprint(pub.Key))
	fmt.Fprintln(stdout, "Next: copy the private key file to two encrypted USB drives and make the paper backup "+
		"(docs/vendor/licensing-vendor.md). Only the public key goes into Alice builds (licensectl keyset).")
	return 0
}

func issue(args []string, stdin io.Reader, stdout, stderr io.Writer, ask prompter, clk clock.Clock) int {
	fs := flags("issue", stderr)
	keyPath := fs.String("key", "", "encrypted private key file")
	installation := fs.String("installation", "", "customer's Installation ID")
	customer := fs.String("customer", "", "customer name")
	targets := fs.Int("targets", 0, "number of managed targets")
	from := fs.String("from", "", "first valid day (YYYY-MM-DD); default today")
	months := fs.Int("months", 12, "validity in months")
	features := fs.String("features", "", "comma-separated feature names (unused in v1)")
	replaces := fs.String("replaces", "", "license ID a correction license replaces")
	licenseID := fs.String("license-id", "", "license ID; default LIC-<year>-<6 digits>")
	out := fs.String("out", "", "license file to write")
	ledger := fs.String("ledger", "", "issuance ledger; default issued.csv next to the key")
	if fs.Parse(args) != nil || *keyPath == "" || *installation == "" || *customer == "" || *targets == 0 || *out == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	p, err := issuer.BuildPayload(issuer.Request{
		Installation: *installation, Customer: *customer, Targets: *targets, From: *from, Months: *months,
		Features: strings.Split(*features, ","), Replaces: *replaces, LicenseID: *licenseID,
	}, clk.Now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := os.Lstat(*out); err == nil {
		fmt.Fprintln(stderr, *out, "already exists; choose another --out file.")
		return 1
	}
	keyPEM, err := os.ReadFile(*keyPath) //nolint:gosec // G304: vendor CLI path from its own flags
	if err != nil {
		fmt.Fprintln(stderr, "cannot read the key file:", err)
		return 1
	}
	pass, err := ask("Key passphrase: ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	k, err := issuer.OpenKey(keyPEM, pass)
	clear(pass)
	if err != nil {
		fmt.Fprintln(stderr, "Cannot open the key:", err)
		return 1
	}
	defer k.Zero()

	fmt.Fprintf(stdout, "License ID:    %s\nCustomer:      %s\nInstallation:  %s\nValid from:    %s\nValid until:   %s\n"+
		"Targets:       %d\nFeatures:      %s\nReplaces:      %s\nSigning key:   %s\n",
		p.LicenseID, p.Customer, p.InstallationID, p.ValidFrom.Format(time.RFC3339), p.ValidUntil.Format(time.RFC3339),
		p.MaxTargets, strings.Join(p.Features, ","), p.Replaces, k.KeyID())
	fmt.Fprint(stdout, `Type "yes" to sign: `)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		fmt.Fprintln(stdout, "Nothing was signed.")
		return 1
	}
	raw, err := k.Issue(p)
	if err != nil {
		fmt.Fprintln(stderr, "signing failed:", err)
		return 1
	}
	if err := issuer.WriteNew(*out, raw, 0o644); err != nil {
		fmt.Fprintln(stderr, "cannot write", *out+":", err)
		return 1
	}
	sum := sha256.Sum256(raw)
	ledgerPath := *ledger
	if ledgerPath == "" {
		ledgerPath = filepath.Join(filepath.Dir(*keyPath), issuer.LedgerFile)
	}
	err = issuer.AppendLedger(ledgerPath, k, issuer.LedgerEntry{
		LicenseID: p.LicenseID, Customer: p.Customer, InstallationID: p.InstallationID, IssuedAt: p.IssuedAt,
		ValidFrom: p.ValidFrom, ValidUntil: p.ValidUntil, MaxTargets: p.MaxTargets, Replaces: p.Replaces,
		FileSHA256: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		fmt.Fprintln(stderr, "The license was written, but the ledger could not be updated:", err)
		return 1
	}
	fmt.Fprintf(stdout, "\nWritten: %s\nSHA-256: %s\nLedger:  %s\n", *out, hex.EncodeToString(sum[:]), ledgerPath)
	return 0
}

func inspect(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	f, err := license.ParseFile(raw)
	if err != nil {
		fmt.Fprintln(stderr, "Not a readable license file:", err)
		return 1
	}
	p := f.Payload
	fmt.Fprintf(stdout, "license_id:      %s\ncustomer:        %s\ninstallation_id: %s\nissued_at:       %s\n"+
		"valid_from:      %s\nvalid_until:     %s\nmax_targets:     %d\nfeatures:        %s\nreplaces:        %s\n"+
		"format:          %d\nkey_id:          %s\nsignature:       not checked (use licensectl verify)\n",
		p.LicenseID, p.Customer, p.InstallationID, p.IssuedAt.Format(time.RFC3339), p.ValidFrom.Format(time.RFC3339),
		p.ValidUntil.Format(time.RFC3339), p.MaxTargets, strings.Join(p.Features, ","), p.Replaces, p.Format, f.KeyID)
	return 0
}

func readPublic(path string, stderr io.Writer) (license.PublicKey, bool) {
	pemBytes, err := os.ReadFile(path) //nolint:gosec // G304: vendor CLI path from its own flags
	if err != nil {
		fmt.Fprintln(stderr, err)
		return license.PublicKey{}, false
	}
	pub, err := issuer.ReadPublicKey(pemBytes)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return license.PublicKey{}, false
	}
	return pub, true
}

func verify(args []string, stdout, stderr io.Writer) int {
	fs := flags("verify", stderr)
	pubPath := fs.String("pub", "", "public key file")
	if fs.Parse(args) != nil || *pubPath == "" || fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	pub, ok := readPublic(*pubPath, stderr)
	if !ok {
		return 1
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := license.Check(raw, license.NewKeySet(pub)); err != nil {
		fmt.Fprintf(stdout, "SIGNATURE INVALID (%s)\n", license.RejectReason(err))
		return 1
	}
	fmt.Fprintln(stdout, "OK")
	return 0
}

func keyset(args []string, stdout, stderr io.Writer) int {
	fs := flags("keyset", stderr)
	pubPath := fs.String("pub", "", "public key file")
	if fs.Parse(args) != nil || *pubPath == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	pub, ok := readPublic(*pubPath, stderr)
	if !ok {
		return 1
	}
	out, err := license.EncodeKeySet(pub)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "%sFingerprint: %s\n", out, license.Fingerprint(pub.Key))
	return 0
}

func ledgerVerify(args []string, stdout, stderr io.Writer) int {
	fs := flags("ledger-verify", stderr)
	pubPath := fs.String("pub", "", "public key file")
	ledger := fs.String("ledger", "", "ledger file; default issued.csv next to the public key")
	if fs.Parse(args) != nil || *pubPath == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	pub, ok := readPublic(*pubPath, stderr)
	if !ok {
		return 1
	}
	path := *ledger
	if path == "" {
		path = filepath.Join(filepath.Dir(*pubPath), issuer.LedgerFile)
	}
	n, err := issuer.VerifyLedger(path, pub.Key)
	if err != nil {
		fmt.Fprintln(stdout, "LEDGER BROKEN:", err)
		return 1
	}
	noun := "licenses"
	if n == 1 {
		noun = "license"
	}
	fmt.Fprintf(stdout, "Ledger OK: %d %s\n", n, noun)
	return 0
}
```

Run: `go test -race -count=1 ./cmd/licensectl/ ./internal/license/...`
Expected: PASS.

- [ ] **Step 5: Build target, CI on Linux and macOS, gitleaks allow-list**

Append to `Makefile`:

```make
.PHONY: licensectl
licensectl: ## Build the vendor's offline license tool into bin/ (never shipped to customers)
	CGO_ENABLED=0 go build -trimpath -o bin/licensectl ./cmd/licensectl
```

In `.github/workflows/ci.yml` add a job after `go`:

```yaml
  licensectl:
    # Spec §26.4: licensectl is tested on Linux and macOS (the vendor's machines).
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v7
        with: { go-version-file: go.mod }
      - run: go test -race -count=1 ./cmd/licensectl/... ./internal/license/...
      - run: go build -trimpath -o bin/licensectl ./cmd/licensectl
```

In `.gitleaks.toml` add `'''amber canyon violet orbit lantern'''` to the `regexes` list (the throw-away test passphrase).

Run: `make licensectl lint secrets-scan && ./bin/licensectl help | head -3`
Expected: builds; no findings; `Usage: licensectl <command> [flags]`.

- [ ] **Step 6: Commit**

```bash
git add internal/license/issuer/ cmd/licensectl/ go.mod go.sum Makefile .github/workflows/ci.yml .gitleaks.toml
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(licensectl): offline key file, license issuing, verification and ledger

licensectl keygen writes an Ed25519 key pair; the private key is encrypted
under Argon2id (256 MiB, t=4) and AES-256-GCM with a Diceware passphrase of
at least six words and is never overwritten. issue checks the installation
ID's check character, asks for the passphrase and a typed \"yes\", and appends
a chained, signed row to the issuance ledger. inspect, verify, keyset (the
entry for the embedded key set) and ledger-verify complete the tool. Tested
on Linux and macOS; x/term is used only here.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 18: Web — license API client and the license banners on every screen

Spec §19.3 (what each person sees in each phase, EN/TR), L-15 (Operators and Auditors get no warnings),
§26.1 item 9 (accessible alerts). Every signed-in screen shows the banners from `GET /api/v1/license/status`,
refreshed every minute. Times are shown in the reader's language and time zone.

**Files:**
- Modify: `web/src/api/types.ts`, `web/src/api/endpoints.ts`
- Create: `web/src/components/LicenseBanners.tsx`
- Test: `web/src/components/LicenseBanners.test.tsx`
- Modify: `web/src/layout/AppLayout.tsx`, `web/src/test/server.ts`, `web/src/test/fixtures.ts`
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json`

**Interfaces:**
- Consumes: `GET /api/v1/license/status` (Task 14); `apiFetch`, `useAuth`, `formatDateTime`.
- Produces (`web/src/api/types.ts`): `LicensePhase`, `BannerSeverity`, `LicenseBanner { kind; severity; params }`, `LicenseStatus { expired; phase?; banners }`, `LicenseInfo`, `LicenseFileEntry`, `LicenseHistoryEntry`, `LicenseDetail`, `LicenseUploadResult` (field names exactly as the Task 14 JSON).
- Produces (`web/src/api/endpoints.ts`): `getLicenseStatus()`, `getLicense()`, `previewLicense(license: string)`, `installLicense(license: string)`.
- Produces (`web/src/components/LicenseBanners.tsx`): `export const LICENSE_STATUS_KEY = ['license', 'status'] as const`; `export function bannerValues(b: LicenseBanner, lang: string): Record<string, string | number>`; `export function LicenseBanners()`; each banner is a Mantine `Alert` with `data-testid="license-banner-<kind>"`, color info→blue, warning→yellow, caution→orange, danger→red, `role="alert"` for danger and `role="status"` otherwise, and (Admins only) a link **Open the License page** to `/license`.
- Produces (`web/src/test/fixtures.ts`): `licenseDetailFixture: LicenseDetail`, `statusWith(...banners: LicenseBanner[]): LicenseStatus`.
- Produces (locale keys, web catalog): `license.banner.<kind>` for every kind (`_one`/`_other` for `evaluation`, `expiry_warning`, `clock_jump`), `license.banner.open`.

- [ ] **Step 1: Add the wire types and endpoints**

Append to `web/src/api/types.ts`:

```ts
export type LicensePhase = 'evaluation' | 'evaluation_expired' | 'active' | 'grace' | 'locked';
export type BannerSeverity = 'info' | 'warning' | 'caution' | 'danger';

export interface LicenseBanner {
  kind: string;
  severity: BannerSeverity;
  params: Record<string, string>;
}

export interface LicenseStatus {
  expired: boolean;
  phase?: LicensePhase; // Administrators and Auditors only
  banners: LicenseBanner[];
}

export interface LicenseInfo {
  license_id: string;
  customer: string;
  issued_at: string;
  valid_from: string;
  valid_until: string;
  max_targets: number;
  features: string[];
  replaces: string;
  key_id: string;
}

export interface LicenseFileEntry {
  status: 'current' | 'pending' | 'superseded' | 'invalid';
  uploaded_at: string;
  license: LicenseInfo | null;
}

export interface LicenseHistoryEntry {
  at: string;
  event: 'installed' | 'renewed' | 'state_change' | 'clock_anomaly' | 'rejected' | 'notice';
  license_id: string;
  from_state: string;
  to_state: string;
  notice: string | null;
}

export interface LicenseDetail {
  installation_id: string;
  installed_at: string;
  phase: LicensePhase;
  effective_time: string;
  current: LicenseInfo | null;
  pending: LicenseInfo | null;
  max_targets: number;
  targets_used: number;
  ends_at: string;
  locks_at: string;
  days_left: number;
  grace_day: number;
  tampered: boolean;
  files: LicenseFileEntry[];
  history: LicenseHistoryEntry[];
}

export interface LicenseUploadResult {
  license: LicenseInfo;
  pending: boolean;
  already_expired: boolean;
  correction: boolean;
  duplicate: boolean;
  phase: LicensePhase;
}
```

In `web/src/api/endpoints.ts` add `LicenseDetail`, `LicenseStatus`, `LicenseUploadResult` to the type import list, and append:

```ts
// License
export const getLicenseStatus = () => apiFetch<LicenseStatus>(`${v1}/license/status`);

export const getLicense = () => apiFetch<LicenseDetail>(`${v1}/license`);

export const previewLicense = (license: string) =>
  apiFetch<LicenseUploadResult>(`${v1}/license/preview`, { method: 'POST', body: { license } });

export const installLicense = (license: string) =>
  apiFetch<LicenseUploadResult>(`${v1}/license`, { method: 'POST', body: { license } });
```

- [ ] **Step 2: Test fixtures and the default handler**

Append to `web/src/test/fixtures.ts` (add `LicenseBanner`, `LicenseDetail`, `LicenseStatus` to its type import):

```ts
export const licenseInfoFixture = {
  license_id: 'LIC-2026-000123',
  customer: 'Örnek Bankası A.Ş.',
  issued_at: '2026-10-01T00:00:00Z',
  valid_from: '2026-10-01T00:00:00Z',
  valid_until: '2027-10-01T00:00:00Z',
  max_targets: 10,
  features: [],
  replaces: '',
  key_id: 'vk-2026-01',
};

export const licenseDetailFixture: LicenseDetail = {
  installation_id: 'ALICE-7F3K-9Q2M-XD41-B8TC',
  installed_at: '2026-10-01T08:00:00Z',
  phase: 'active',
  effective_time: '2026-10-02T08:00:00Z',
  current: licenseInfoFixture,
  pending: null,
  max_targets: 10,
  targets_used: 3,
  ends_at: '2027-10-01T00:00:00Z',
  locks_at: '2027-10-08T00:00:00Z',
  days_left: 364,
  grace_day: 0,
  tampered: false,
  files: [{ status: 'current', uploaded_at: '2026-10-01T09:00:00Z', license: licenseInfoFixture }],
  history: [
    { at: '2026-10-01T09:00:00Z', event: 'installed', license_id: 'LIC-2026-000123', from_state: 'evaluation', to_state: 'active', notice: null },
  ],
};

// statusWith builds a license status with the given banners (no banner = nothing to show).
export function statusWith(...banners: LicenseBanner[]): LicenseStatus {
  return { expired: banners.some((b) => ['grace', 'locked', 'evaluation_ended'].includes(b.kind)), banners };
}
```

In `web/src/test/server.ts` add to `handlers` (import `licenseDetailFixture` from `./fixtures`):

```ts
  http.get('/api/v1/license/status', () => HttpResponse.json({ expired: false, banners: [] })),
  http.get('/api/v1/license', () => HttpResponse.json(licenseDetailFixture)),
```

- [ ] **Step 3: Write the failing banner tests**

Create `web/src/components/LicenseBanners.test.tsx`:

```tsx
import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { LicenseBanner } from '../api/types';
import { sessionFor, sessionHandlers, statusWith } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';
import { bannerValues } from './LicenseBanners';

const evaluation: LicenseBanner = {
  kind: 'evaluation',
  severity: 'info',
  params: { days_left: '22', max_targets: '5', ends_at: '2026-10-31T09:00:00Z' },
};
const warning: LicenseBanner = {
  kind: 'expiry_warning',
  severity: 'caution',
  params: { days_left: '1', valid_until: '2027-10-01T00:00:00Z' },
};
const grace: LicenseBanner = {
  kind: 'grace',
  severity: 'danger',
  params: { valid_until: '2027-10-01T00:00:00Z', locks_at: '2027-10-08T00:00:00Z', grace_day: '3' },
};
const locked: LicenseBanner = { kind: 'locked', severity: 'danger', params: { valid_until: '2027-10-01T00:00:00Z' } };

function useStatus(...banners: LicenseBanner[]) {
  server.use(http.get('/api/v1/license/status', () => HttpResponse.json(statusWith(...banners))));
}

describe('license banners', () => {
  it('shows the evaluation banner to everyone, in plain words', async () => {
    server.use(...sessionHandlers(sessionFor('operator')));
    useStatus(evaluation);
    await renderRoute('/');
    const banner = await screen.findByTestId('license-banner-evaluation');
    expect(banner).toHaveTextContent('Evaluation mode: 22 days left, up to 5 targets.');
    expect(banner).toHaveAttribute('role', 'status');
    expect(within(banner).queryByRole('link')).not.toBeInTheDocument();
  });

  it('shows a one-day warning with the singular and a link for administrators', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    useStatus(warning);
    await renderRoute('/');
    const banner = await screen.findByTestId('license-banner-expiry_warning');
    expect(banner).toHaveTextContent('Your license expires in 1 day (');
    expect(within(banner).getByRole('link', { name: 'Open the License page' })).toHaveAttribute('href', '/license');
  });

  it('announces grace and lock as alerts', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')));
    useStatus(grace, locked);
    await renderRoute('/');
    const g = await screen.findByTestId('license-banner-grace');
    expect(g).toHaveAttribute('role', 'alert');
    expect(g).toHaveTextContent('Grace day 3 of 7.');
    expect(screen.getByTestId('license-banner-locked')).toHaveTextContent('Automatic tasks are paused.');
  });

  it('is translated into Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')));
    useStatus(evaluation, grace, locked, warning);
    await renderRoute('/', { languages: ['tr-TR'] });
    expect(await screen.findByTestId('license-banner-evaluation')).toHaveTextContent('Deneme modu: 22 gün kaldı, en fazla 5 hedef.');
    expect(screen.getByTestId('license-banner-grace')).toHaveTextContent('Ek süre günü: 3 / 7.');
    expectNoRawKeys();
  });

  it('shows nothing when there is nothing to say', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/');
    await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' });
    expect(screen.queryByTestId(/license-banner-/)).not.toBeInTheDocument();
  });
});

describe('bannerValues', () => {
  it('formats times for the reader and passes counts for plurals', () => {
    const v = bannerValues(evaluation, 'en');
    expect(v.count).toBe(22);
    expect(v.max_targets).toBe('5');
    expect(v.ends_at).not.toBe('2026-10-31T09:00:00Z');
    expect(String(v.ends_at)).toMatch(/2026/);
    expect(bannerValues({ kind: 'clock_jump', severity: 'caution', params: { jump_days: '200' } }, 'en').count).toBe(200);
  });
});
```

Run: `cd web && npx vitest run src/components/LicenseBanners.test.tsx`
Expected: FAIL — cannot resolve `./LicenseBanners`.

- [ ] **Step 4: Implement the banners**

Create `web/src/components/LicenseBanners.tsx`:

```tsx
import { Alert, Anchor, Stack } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { getLicenseStatus } from '../api/endpoints';
import type { BannerSeverity, LicenseBanner } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { formatDateTime } from '../datetime';

export const LICENSE_STATUS_KEY = ['license', 'status'] as const;

// Colors of spec §19.3: blue information, yellow warning, orange for the last days, red when expired.
const COLORS: Record<BannerSeverity, string> = { info: 'blue', warning: 'yellow', caution: 'orange', danger: 'red' };

// Banner parameters that are instants; they are shown in the reader's language and time zone.
const TIME_PARAMS = new Set(['ends_at', 'ended_at', 'valid_until', 'valid_from', 'locks_at', 'system_time', 'last_seen']);

// bannerValues turns the server's parameters into translation values. days_left and
// jump_days also become "count", so i18next picks the singular or plural sentence.
export function bannerValues(b: LicenseBanner, lang: string): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(b.params)) out[k] = TIME_PARAMS.has(k) ? formatDateTime(v, lang) : v;
  if (b.params.days_left !== undefined) out.count = Number(b.params.days_left);
  if (b.params.jump_days !== undefined) out.count = Number(b.params.jump_days);
  return out;
}

// LicenseBanners shows the license messages of spec §19.3 on every signed-in screen. The
// server decides who sees what (warnings only for Administrators, L-15).
export function LicenseBanners() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const status = useQuery({ queryKey: LICENSE_STATUS_KEY, queryFn: getLicenseStatus, refetchInterval: 60_000, enabled: !!session });
  if (!status.data || status.data.banners.length === 0) return null;
  const admin = session?.user.role === 'admin';
  return (
    <Stack gap="xs" mb="md">
      {status.data.banners.map((b) => (
        <Alert
          key={b.kind}
          color={COLORS[b.severity] ?? 'blue'}
          role={b.severity === 'danger' ? 'alert' : 'status'}
          data-testid={`license-banner-${b.kind}`}
        >
          {t(`license.banner.${b.kind}`, bannerValues(b, i18n.language))}
          {admin && (
            <>
              {' '}
              <Anchor component={Link} to="/license">
                {t('license.banner.open')}
              </Anchor>
            </>
          )}
        </Alert>
      ))}
    </Stack>
  );
}
```

In `web/src/layout/AppLayout.tsx` import `LicenseBanners` from `'../components/LicenseBanners'` and render `<LicenseBanners />` in `AppShell.Main` directly before `<SetupBanner />`.

Add to `web/src/locales/en.json` a top-level `"license"` object (after `"audit"`):

```json
  "license": {
    "banner": {
      "open": "Open the License page",
      "evaluation_one": "Evaluation mode: {{count}} day left, up to {{max_targets}} targets. To continue after that, an administrator adds a license on the License page.",
      "evaluation_other": "Evaluation mode: {{count}} days left, up to {{max_targets}} targets. To continue after that, an administrator adds a license on the License page.",
      "evaluation_ended": "The evaluation period has ended. Alice is now read-only for changes. Administrators can upload a license on the License page.",
      "expiry_warning_one": "Your license expires in {{count}} day ({{valid_until}}). Send your Installation ID to your vendor to renew.",
      "expiry_warning_other": "Your license expires in {{count}} days ({{valid_until}}). Send your Installation ID to your vendor to renew.",
      "grace": "Your license expired on {{valid_until}}. Alice will stop automatic work on {{locks_at}} (168 hours after expiry). Contact your vendor now. Grace day {{grace_day}} of 7.",
      "locked": "License expired. Automatic tasks are paused. Your data is safe and certificate expiry alerts still arrive by email. Administrators: upload a new license on the License page.",
      "tampered": "License data was changed outside Alice, so Alice ignores the changed file. Upload the license file from your vendor again.",
      "clock_behind": "The server clock changed unexpectedly (it says {{system_time}}, but Alice last saw {{last_seen}}). Alice is using the later date for license checks. Please correct the server time or contact your vendor.",
      "clock_jump_one": "The server clock jumped forward by {{count}} day. For 24 hours Alice keeps using the previous time for license checks. Confirm the time is correct, or contact your vendor.",
      "clock_jump_other": "The server clock jumped forward by {{count}} days. For 24 hours Alice keeps using the previous time for license checks. Confirm the time is correct, or contact your vendor.",
      "pending": "A new license ({{license_id}}) starts on {{valid_from}}. The current license stays in use until then.",
      "over_limit": "You use {{used}} of {{max}} licensed targets. You cannot add more until you are within the limit.",
      "limit_reached": "You are using all {{max}} licensed targets. To add more, ask your vendor to increase your license."
    }
  }
```

and to `web/src/locales/tr.json`:

```json
  "license": {
    "banner": {
      "open": "Lisans sayfasını aç",
      "evaluation_one": "Deneme modu: {{count}} gün kaldı, en fazla {{max_targets}} hedef. Sonrasında devam etmek için bir yönetici Lisans sayfasından lisans ekler.",
      "evaluation_other": "Deneme modu: {{count}} gün kaldı, en fazla {{max_targets}} hedef. Sonrasında devam etmek için bir yönetici Lisans sayfasından lisans ekler.",
      "evaluation_ended": "Deneme süresi sona erdi. Alice artık değişikliklere kapalı. Yöneticiler Lisans sayfasından lisans yükleyebilir.",
      "expiry_warning_one": "Lisansınızın süresi {{count}} gün sonra doluyor ({{valid_until}}). Yenilemek için Kurulum Kimliğinizi satıcınıza gönderin.",
      "expiry_warning_other": "Lisansınızın süresi {{count}} gün sonra doluyor ({{valid_until}}). Yenilemek için Kurulum Kimliğinizi satıcınıza gönderin.",
      "grace": "Lisansınızın süresi şu tarihte doldu: {{valid_until}}. Alice otomatik işleri şu tarihte durduracak: {{locks_at}} (süre dolduktan 168 saat sonra). Hemen satıcınızla iletişime geçin. Ek süre günü: {{grace_day}} / 7.",
      "locked": "Lisans süresi doldu. Otomatik işler duraklatıldı. Verileriniz güvende; sertifika süresi uyarıları e-postayla gelmeye devam ediyor. Yöneticiler: Lisans sayfasından yeni bir lisans yükleyin.",
      "tampered": "Lisans verileri Alice dışında değiştirildi; Alice değiştirilen dosyayı yok sayıyor. Satıcınızdan gelen lisans dosyasını yeniden yükleyin.",
      "clock_behind": "Sunucu saati beklenmedik biçimde değişti (şu anda {{system_time}} gösteriyor, ancak Alice en son {{last_seen}} zamanını gördü). Alice lisans denetimlerinde sonraki tarihi kullanıyor. Lütfen sunucu saatini düzeltin veya satıcınızla iletişime geçin.",
      "clock_jump_one": "Sunucu saati {{count}} gün ileri atladı. Alice 24 saat boyunca lisans denetimlerinde önceki zamanı kullanır. Saatin doğru olduğunu doğrulayın veya satıcınızla iletişime geçin.",
      "clock_jump_other": "Sunucu saati {{count}} gün ileri atladı. Alice 24 saat boyunca lisans denetimlerinde önceki zamanı kullanır. Saatin doğru olduğunu doğrulayın veya satıcınızla iletişime geçin.",
      "pending": "Yeni bir lisans ({{license_id}}) şu tarihte başlıyor: {{valid_from}}. O zamana kadar mevcut lisans kullanılır.",
      "over_limit": "Kullanımdaki hedef sayısı {{used}}, lisanslı hedef sayısı {{max}}. Sınırın altına inene kadar yeni hedef eklenemez.",
      "limit_reached": "Lisanslı {{max}} hedefin tamamını kullanıyorsunuz. Daha fazla hedef için satıcınızdan lisansınızı artırmasını isteyin."
    }
  }
```

- [ ] **Step 5: Run the web suites**

Run: `cd web && npm run lint && npm test && cd .. && make i18n-check`
Expected: PASS — the existing App and page tests pass because the default handlers answer `/api/v1/license/status`.

- [ ] **Step 6: Commit**

```bash
git add web/src/
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(web): license banners on every screen

The shell shows the banners of GET /api/v1/license/status (refreshed every
minute) in the §19.3 colors, with singular and plural texts in English and
Turkish, times in the reader's language, alerts for grace and lock, and a
link to the License page for administrators.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 19: Web — License page with preview, confirm and history

Spec §19.1 (Installation ID with Copy; upload; preview "Licensed to …, Up to … targets, Valid from … to …,
Confirm?"; the four failure messages), §19.3 ("Settings → License shows customer name, license ID, target usage
bar, valid until, current phase, and history"), L-32 ("This license has already expired"), §26.4 owner step 2
("Valid until <date>, 10 targets"). Administrators upload (with step-up); Auditors read.

**Files:**
- Create: `web/src/components/LicenseUpload.tsx`, `web/src/pages/LicensePage.tsx`
- Test: `web/src/pages/LicensePage.test.tsx`
- Modify: `web/src/router.tsx`, `web/src/layout/AppLayout.tsx` (nav item), `web/src/App.test.tsx` (nav labels)
- Modify: `web/src/test/screens.ts`, `web/src/locales/en.json`, `web/src/locales/tr.json`, `web/src/locales/.i18n-identical.json`

**Interfaces:**
- Consumes (Task 18): `getLicense`, `previewLicense`, `installLicense`, `LicenseDetail`, `LicenseUploadResult`, `LICENSE_STATUS_KEY`, `licenseDetailFixture`; `useStepUp().run`, `AppModal`, `ErrorAlert`, `RequireRole`, `formatDateTime`.
- Produces: `export function LicenseUpload({ onInstalled }: { onInstalled: (r: LicenseUploadResult) => void })` (file input labelled **License file**, button **Check the file**, dialog **Confirm the license** with **Install license**/**Cancel**; invalidates every `['license', …]` query after an install); `export function LicensePage()`; route `/license` for Admin and Auditor; nav item **License** (`nav.license`) after **Audit log**; `data-testid`s `installation-id`, `license-phase`, `license-summary`, `license-installed`.

- [ ] **Step 1: Write the failing page tests**

Create `web/src/pages/LicensePage.test.tsx`:

```tsx
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { LicenseUploadResult } from '../api/types';
import { errorResponse, licenseDetailFixture, licenseInfoFixture, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const fileText = '{\n  "format": 1,\n  "key_id": "vk-2026-01"\n}\n';
const result: LicenseUploadResult = {
  license: { ...licenseInfoFixture, customer: 'Test Company', max_targets: 25 },
  pending: false,
  already_expired: false,
  correction: false,
  duplicate: false,
  phase: 'active',
};

async function chooseFile() {
  const input = screen.getByLabelText('License file');
  await userEvent.upload(input, new File([fileText], 'alice-license-test.alicelic', { type: 'application/json' }));
  await userEvent.click(screen.getByRole('button', { name: 'Check the file' }));
}

describe('license page', () => {
  it('shows the installation ID, the license in force and the history', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/license');
    expect(await screen.findByRole('heading', { name: 'License', level: 1 })).toBeInTheDocument();
    expect(screen.getByTestId('installation-id')).toHaveTextContent('ALICE-7F3K-9Q2M-XD41-B8TC');
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(screen.getByTestId('license-phase')).toHaveTextContent('Active');
    expect(screen.getByTestId('license-summary')).toHaveTextContent(/^Valid until .*2027.*, 10 targets$/);
    expect(screen.getByText('Licensed to Örnek Bankası A.Ş. (license LIC-2026-000123)')).toBeInTheDocument();
    expect(screen.getByText('3 of 10 targets used')).toBeInTheDocument();
    const history = screen.getByRole('table', { name: 'History' });
    expect(within(history).getByText('License installed')).toBeInTheDocument();
    expect(within(history).getByText('Evaluation → Active')).toBeInTheDocument();
  });

  it('previews and installs a license (§19.1)', async () => {
    const bodies: unknown[] = [];
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/license/preview', async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json(result);
      }),
      http.post('/api/v1/license', async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json(result);
      }),
    );
    await renderRoute('/license');
    await screen.findByTestId('installation-id');
    await chooseFile();
    const dialog = await screen.findByRole('dialog', { name: 'Confirm the license' });
    expect(dialog).toHaveTextContent('Licensed to Test Company. Up to 25 managed targets. Valid from');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Install license' }));
    expect(await screen.findByTestId('license-installed')).toHaveTextContent('License activated. All features are available again.');
    expect(bodies).toEqual([{ license: fileText }, { license: fileText }]);
  });

  it('explains an edited file and a license for another installation', async () => {
    let call = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/license/preview', () => {
        call += 1;
        return call === 1
          ? errorResponse(422, 'ALC-LIC-0002', 'license.invalid')
          : errorResponse(422, 'ALC-LIC-0003', 'license.wrong_installation', { params: { expected: 'D41B8T', got: 'Q2MXD4' } });
      }),
    );
    await renderRoute('/license');
    await screen.findByTestId('installation-id');
    await chooseFile();
    expect(await screen.findByRole('alert')).toHaveTextContent('This file is not a valid Alice license.');
    await userEvent.click(screen.getByRole('button', { name: 'Check the file' }));
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('This license file was made for a different installation (ending in Q2MXD4).'),
    );
    expect(screen.queryByRole('dialog', { name: 'Confirm the license' })).not.toBeInTheDocument();
  });

  it('says so when the installed license has already expired (L-32)', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/license/preview', () => HttpResponse.json({ ...result, already_expired: true, phase: 'grace' })),
      http.post('/api/v1/license', () => HttpResponse.json({ ...result, already_expired: true, phase: 'grace' })),
    );
    await renderRoute('/license');
    await screen.findByTestId('installation-id');
    await chooseFile();
    const dialog = await screen.findByRole('dialog', { name: 'Confirm the license' });
    expect(dialog).toHaveTextContent('This license has already expired.');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Install license' }));
    expect(await screen.findByTestId('license-installed')).toHaveTextContent('This license has already expired.');
  });

  it('asks for a fresh code before uploading', async () => {
    let attempts = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/license/preview', () => {
        attempts += 1;
        return attempts === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(result);
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    await renderRoute('/license');
    await screen.findByTestId('installation-id');
    await chooseFile();
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(within(stepUp).getByLabelText('6-digit code'), '123456');
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByRole('dialog', { name: 'Confirm the license' })).toBeInTheDocument();
  });

  it('is read-only for auditors and hidden from operators', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')));
    await renderRoute('/license');
    await screen.findByTestId('installation-id');
    expect(screen.queryByLabelText('License file')).not.toBeInTheDocument();

    server.use(...sessionHandlers(sessionFor('operator')));
    await renderRoute('/license');
    expect(await screen.findByText('You do not have access to this page.')).toBeInTheDocument();
  });

  it('shows the evaluation and is translated into Turkish', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin', 'tr')),
      http.get('/api/v1/license', () =>
        HttpResponse.json({ ...licenseDetailFixture, phase: 'evaluation', current: null, max_targets: 5, days_left: 30, files: [], history: [] }),
      ),
    );
    await renderRoute('/license', { languages: ['tr-TR'] });
    expect(await screen.findByTestId('license-summary')).toHaveTextContent('Deneme: 30 gün kaldı, en fazla 5 hedef.');
    expect(screen.getByLabelText('Lisans dosyası')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
```

In `web/src/App.test.tsx` change the expected navigation lists: admin `['Home', 'Users', 'Audit log', 'License', 'API tokens', 'My account']`; auditor (Turkish) `['Ana sayfa', 'Denetim kaydı', 'Lisans', 'API anahtarları', 'Hesabım']`; operator unchanged.

Run: `cd web && npx vitest run src/pages/LicensePage.test.tsx src/App.test.tsx`
Expected: FAIL — `/license` renders "Page not found"; the nav lists lack **License**.

- [ ] **Step 2: Implement the upload component**

Create `web/src/components/LicenseUpload.tsx`:

```tsx
import { Alert, Button, Group, Input, Stack, Text } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useId, useState, type ChangeEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { installLicense, previewLicense } from '../api/endpoints';
import type { LicenseUploadResult } from '../api/types';
import { formatDateTime } from '../datetime';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { useStepUp } from './StepUpProvider';

// LicenseUpload reads a license file, lets the server check it (preview) and installs it
// after the administrator confirms what it says (spec §19.1).
export function LicenseUpload({ onInstalled }: { onInstalled: (r: LicenseUploadResult) => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const inputId = useId();
  const [text, setText] = useState<string | null>(null);
  const [preview, setPreview] = useState<LicenseUploadResult | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const fmt = (iso: string) => formatDateTime(iso, i18n.language);

  const choose = async (ev: ChangeEvent<HTMLInputElement>) => {
    setError(null);
    setPreview(null);
    const file = ev.currentTarget.files?.[0];
    setText(file ? await file.text() : null);
  };

  const check = async () => {
    if (text === null) return;
    setBusy(true);
    setError(null);
    try {
      setPreview(await run(() => previewLicense(text)));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (text === null) return;
    setBusy(true);
    setError(null);
    try {
      const res = await run(() => installLicense(text));
      setPreview(null);
      await client.invalidateQueries({ queryKey: ['license'] });
      onInstalled(res);
    } catch (e) {
      setPreview(null);
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const p = preview?.license;
  return (
    <Stack gap="sm">
      <ErrorAlert error={error} />
      <Input.Wrapper id={inputId} label={t('license.upload.label')} description={t('license.upload.help')}>
        <input
          id={inputId}
          type="file"
          accept=".alicelic,.json,application/json"
          aria-describedby={`${inputId}-description`}
          onChange={(e) => void choose(e)}
        />
      </Input.Wrapper>
      <Group>
        <Button onClick={() => void check()} disabled={text === null} loading={busy && preview === null}>
          {t('license.upload.check')}
        </Button>
      </Group>
      <AppModal opened={preview !== null} onClose={() => setPreview(null)} title={t('license.upload.previewTitle')} centered>
        {preview && p && (
          <Stack>
            <Text>
              {t('license.upload.previewSummary', { customer: p.customer, max: p.max_targets, from: fmt(p.valid_from), until: fmt(p.valid_until) })}
            </Text>
            {preview.correction && <Text size="sm">{t('license.upload.correction', { replaces: p.replaces })}</Text>}
            {preview.already_expired && <Alert color="yellow">{t('license.upload.alreadyExpired')}</Alert>}
            {preview.pending && <Alert color="blue">{t('license.upload.pending', { from: fmt(p.valid_from) })}</Alert>}
            {preview.duplicate && <Alert color="blue">{t('license.upload.duplicate')}</Alert>}
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setPreview(null)}>
                {t('license.upload.cancel')}
              </Button>
              {!preview.duplicate && (
                <Button onClick={() => void confirm()} loading={busy}>
                  {t('license.upload.confirm')}
                </Button>
              )}
            </Group>
          </Stack>
        )}
      </AppModal>
    </Stack>
  );
}
```

- [ ] **Step 3: Implement the page, the route and the navigation item**

Create `web/src/pages/LicensePage.tsx`:

```tsx
import { Alert, Button, Code, CopyButton, Group, Paper, Progress, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getLicense } from '../api/endpoints';
import type { LicenseUploadResult } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { ErrorAlert } from '../components/ErrorAlert';
import { LicenseUpload } from '../components/LicenseUpload';
import { formatDateTime } from '../datetime';

// InstallationID shows the ID with a Copy button (spec §19.1 step 1).
export function InstallationID({ id }: { id: string }) {
  const { t } = useTranslation();
  return (
    <Group gap="xs">
      <Code data-testid="installation-id" fz="md">
        {id}
      </Code>
      <CopyButton value={id}>
        {({ copied, copy }) => (
          <Button size="xs" variant="default" onClick={copy}>
            {copied ? t('license.installation.copied') : t('license.installation.copy')}
          </Button>
        )}
      </CopyButton>
    </Group>
  );
}

export function LicensePage() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const detail = useQuery({ queryKey: ['license', 'detail'], queryFn: getLicense });
  const [installed, setInstalled] = useState<LicenseUploadResult | null>(null);
  const fmt = (iso: string) => formatDateTime(iso, i18n.language);
  const phase = (p: string) => (i18n.exists(`license.phase.${p}`) ? t(`license.phase.${p}`) : p);
  const d = detail.data;

  let installedText = '';
  if (installed) {
    installedText = installed.already_expired
      ? t('license.upload.installedExpired')
      : installed.pending
        ? t('license.upload.installedPending', { from: fmt(installed.license.valid_from) })
        : t('license.upload.activated');
  }

  return (
    <Stack gap="lg">
      <Title order={1}>{t('license.title')}</Title>
      {installed && (
        <Alert color={installed.already_expired ? 'yellow' : 'green'} role="status" data-testid="license-installed">
          {installedText}
        </Alert>
      )}
      {detail.isPending && <PageLoader />}
      {detail.isError && <ErrorAlert error={detail.error} />}
      {d && (
        <>
          <Paper withBorder p="md">
            <Stack gap="xs">
              <Title order={2} size="h3">
                {t('license.installation.title')}
              </Title>
              <Text size="sm">{t('license.installation.help')}</Text>
              <InstallationID id={d.installation_id} />
            </Stack>
          </Paper>

          <Paper withBorder p="md">
            <Stack gap="xs">
              <Title order={2} size="h3">
                {t('license.current.title')}
              </Title>
              <Text fw={700} data-testid="license-phase">
                {phase(d.phase)}
              </Text>
              {d.current ? (
                <>
                  <Text data-testid="license-summary">{t('license.current.summary', { date: fmt(d.current.valid_until), count: d.current.max_targets })}</Text>
                  <Text size="sm">{t('license.current.customer', { customer: d.current.customer, id: d.current.license_id })}</Text>
                </>
              ) : (
                <Text data-testid="license-summary">{t('license.current.evaluation', { count: d.days_left, max: d.max_targets })}</Text>
              )}
              <Text size="sm">{t('license.current.usage', { used: d.targets_used, max: d.max_targets })}</Text>
              <Progress
                value={d.max_targets > 0 ? Math.min(100, (d.targets_used * 100) / d.max_targets) : 0}
                aria-label={t('license.current.usageLabel')}
              />
              {d.pending && <Text size="sm">{t('license.current.pending', { id: d.pending.license_id, date: fmt(d.pending.valid_from) })}</Text>}
              {d.tampered && (
                <Alert color="red" role="alert">
                  {t('license.current.tampered')}
                </Alert>
              )}
            </Stack>
          </Paper>

          {session?.user.role === 'admin' && (
            <Paper withBorder p="md">
              <Stack gap="xs">
                <Title order={2} size="h3">
                  {t('license.upload.title')}
                </Title>
                <LicenseUpload onInstalled={setInstalled} />
              </Stack>
            </Paper>
          )}

          {d.files.length > 0 && (
            <Table.ScrollContainer minWidth={560}>
              <Table striped aria-label={t('license.files.title')}>
                <Table.Caption>{t('license.files.title')}</Table.Caption>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('license.files.columns.license')}</Table.Th>
                    <Table.Th>{t('license.files.columns.customer')}</Table.Th>
                    <Table.Th>{t('license.files.columns.validUntil')}</Table.Th>
                    <Table.Th>{t('license.files.columns.status')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {d.files.map((f) => (
                    <Table.Tr key={`${f.uploaded_at}-${f.license?.license_id ?? 'invalid'}`}>
                      <Table.Td>{f.license?.license_id ?? ''}</Table.Td>
                      <Table.Td>{f.license?.customer ?? ''}</Table.Td>
                      <Table.Td>{f.license ? fmt(f.license.valid_until) : ''}</Table.Td>
                      <Table.Td>{t(`license.fileStatus.${f.status}`)}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}

          {d.history.length > 0 && (
            <Table.ScrollContainer minWidth={560}>
              <Table striped aria-label={t('license.history.title')}>
                <Table.Caption>{t('license.history.title')}</Table.Caption>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t('license.history.columns.time')}</Table.Th>
                    <Table.Th>{t('license.history.columns.event')}</Table.Th>
                    <Table.Th>{t('license.history.columns.license')}</Table.Th>
                    <Table.Th>{t('license.history.columns.change')}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {d.history.map((h, i) => (
                    <Table.Tr key={`${h.at}-${i}`}>
                      <Table.Td>{fmt(h.at)}</Table.Td>
                      <Table.Td>{t(`license.event.${h.event}`)}</Table.Td>
                      <Table.Td>{h.license_id}</Table.Td>
                      <Table.Td>{h.from_state && h.to_state ? t('license.change', { from: phase(h.from_state), to: phase(h.to_state) }) : ''}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </>
      )}
    </Stack>
  );
}
```

In `web/src/router.tsx` import `LicensePage` and add after the `audit` route:

```tsx
            {
              path: 'license',
              element: (
                <RequireRole roles={['admin', 'auditor']}>
                  <LicensePage />
                </RequireRole>
              ),
            },
```

In `web/src/layout/AppLayout.tsx` add to `NAV_ITEMS` after the audit entry:

```ts
  { to: '/license', labelKey: 'nav.license', roles: ['admin', 'auditor'] },
```

- [ ] **Step 4: Add the texts**

In `web/src/locales/en.json` add `"license": "License"` to `nav` (after `"audit"`), and inside the top-level `license` object (next to `banner`):

```json
    "title": "License",
    "change": "{{from}} → {{to}}",
    "installation": {
      "title": "Installation ID",
      "help": "Your vendor needs this ID to make a license for this installation. Copy it and email it to your vendor.",
      "copy": "Copy",
      "copied": "Copied"
    },
    "phase": {
      "evaluation": "Evaluation",
      "evaluation_expired": "Evaluation ended",
      "active": "Active",
      "grace": "Expired, grace period",
      "locked": "Expired, locked"
    },
    "current": {
      "title": "Current license",
      "summary_one": "Valid until {{date}}, {{count}} target",
      "summary_other": "Valid until {{date}}, {{count}} targets",
      "customer": "Licensed to {{customer}} (license {{id}})",
      "evaluation_one": "Evaluation: {{count}} day left, up to {{max}} targets.",
      "evaluation_other": "Evaluation: {{count}} days left, up to {{max}} targets.",
      "usage": "{{used}} of {{max}} targets used",
      "usageLabel": "Targets used",
      "pending": "A new license ({{id}}) starts on {{date}}.",
      "tampered": "A stored license file was changed outside Alice and is ignored."
    },
    "upload": {
      "title": "Upload a license",
      "label": "License file",
      "help": "The file from your vendor's email, for example alice-license-yourcompany-20261001.alicelic.",
      "check": "Check the file",
      "previewTitle": "Confirm the license",
      "previewSummary": "Licensed to {{customer}}. Up to {{max}} managed targets. Valid from {{from}} to {{until}}.",
      "alreadyExpired": "This license has already expired. It is installed anyway; its own dates decide whether Alice is in the grace period or locked.",
      "pending": "This license starts on {{from}}. The current license stays in use until then.",
      "correction": "This license corrects license {{replaces}}.",
      "duplicate": "This license is already installed.",
      "confirm": "Install license",
      "cancel": "Cancel",
      "activated": "License activated. All features are available again.",
      "installedExpired": "This license has already expired.",
      "installedPending": "The license is installed and starts on {{from}}."
    },
    "files": {
      "title": "Uploaded licenses",
      "columns": { "license": "License", "customer": "Customer", "validUntil": "Valid until", "status": "Status" }
    },
    "fileStatus": { "current": "In use", "pending": "Starts later", "superseded": "Replaced", "invalid": "Damaged" },
    "history": {
      "title": "History",
      "columns": { "time": "Time", "event": "Event", "license": "License", "change": "Change" }
    },
    "event": {
      "installed": "License installed",
      "renewed": "License renewed",
      "state_change": "State changed",
      "clock_anomaly": "Clock problem",
      "rejected": "Upload refused",
      "notice": "Notice sent"
    }
```

In `web/src/locales/tr.json` add `"license": "Lisans"` to `nav`, and inside `license`:

```json
    "title": "Lisans",
    "change": "{{from}} → {{to}}",
    "installation": {
      "title": "Kurulum Kimliği",
      "help": "Satıcınız bu kurulum için lisans hazırlamak üzere bu kimliğe ihtiyaç duyar. Kimliği kopyalayın ve e-postayla satıcınıza gönderin.",
      "copy": "Kopyala",
      "copied": "Kopyalandı"
    },
    "phase": {
      "evaluation": "Deneme",
      "evaluation_expired": "Deneme sona erdi",
      "active": "Etkin",
      "grace": "Süresi doldu, ek süre",
      "locked": "Süresi doldu, kilitli"
    },
    "current": {
      "title": "Geçerli lisans",
      "summary_one": "Geçerlilik sonu {{date}}, {{count}} hedef",
      "summary_other": "Geçerlilik sonu {{date}}, {{count}} hedef",
      "customer": "Lisans sahibi: {{customer}} (lisans {{id}})",
      "evaluation_one": "Deneme: {{count}} gün kaldı, en fazla {{max}} hedef.",
      "evaluation_other": "Deneme: {{count}} gün kaldı, en fazla {{max}} hedef.",
      "usage": "Kullanımdaki hedef: {{used}} / {{max}}",
      "usageLabel": "Kullanılan hedefler",
      "pending": "Yeni bir lisans ({{id}}) şu tarihte başlıyor: {{date}}.",
      "tampered": "Kayıtlı bir lisans dosyası Alice dışında değiştirildi ve yok sayılıyor."
    },
    "upload": {
      "title": "Lisans yükle",
      "label": "Lisans dosyası",
      "help": "Satıcınızın e-postasındaki dosya, örneğin alice-license-sirketiniz-20261001.alicelic.",
      "check": "Dosyayı denetle",
      "previewTitle": "Lisansı onaylayın",
      "previewSummary": "Lisans sahibi: {{customer}}. En fazla {{max}} yönetilen hedef. Geçerlilik: {{from}} – {{until}}.",
      "alreadyExpired": "Bu lisansın süresi zaten dolmuş. Yine de yüklenir; Alice'in ek sürede mi yoksa kilitli mi olacağına lisansın kendi tarihleri karar verir.",
      "pending": "Bu lisans şu tarihte başlıyor: {{from}}. O zamana kadar mevcut lisans kullanılır.",
      "correction": "Bu lisans, {{replaces}} lisansını düzeltir.",
      "duplicate": "Bu lisans zaten yüklü.",
      "confirm": "Lisansı yükle",
      "cancel": "Vazgeç",
      "activated": "Lisans etkinleştirildi. Tüm özellikler yeniden kullanılabilir.",
      "installedExpired": "Bu lisansın süresi zaten dolmuş.",
      "installedPending": "Lisans yüklendi; şu tarihte başlıyor: {{from}}."
    },
    "files": {
      "title": "Yüklenen lisanslar",
      "columns": { "license": "Lisans", "customer": "Müşteri", "validUntil": "Geçerlilik sonu", "status": "Durum" }
    },
    "fileStatus": { "current": "Kullanımda", "pending": "Daha sonra başlıyor", "superseded": "Yerine yenisi geldi", "invalid": "Bozuk" },
    "history": {
      "title": "Geçmiş",
      "columns": { "time": "Zaman", "event": "Olay", "license": "Lisans", "change": "Değişiklik" }
    },
    "event": {
      "installed": "Lisans yüklendi",
      "renewed": "Lisans yenilendi",
      "state_change": "Durum değişti",
      "clock_anomaly": "Saat sorunu",
      "rejected": "Yükleme reddedildi",
      "notice": "Bildirim gönderildi"
    }
```

`license.change` is the same arrow template in both languages: replace `web/src/locales/.i18n-identical.json` (currently `[]`) with `["license.change"]`.

- [ ] **Step 5: Include the page in the screen sweep**

In `web/src/test/screens.ts` add to `SCREENS` (before the `/missing` entry):

```ts
  { path: '/license', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Upload a license', tr: 'Lisans yükle' } },
  { path: '/license', session: sessionFor('auditor'), status: installedStatus, ready: { en: 'Installation ID', tr: 'Kurulum Kimliği' } },
```

- [ ] **Step 6: Run the web suites**

Run: `cd web && npm run lint && npm test && npm run build && cd .. && make i18n-check`
Expected: PASS (the page tests, the updated navigation tests and the EN/TR screen sweep).

- [ ] **Step 7: Commit**

```bash
git add web/src/
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(web): License page with preview, confirmation and history

Administrators and Auditors see the Installation ID (with Copy), the phase,
\"Valid until <date>, N targets\", target usage, pending licenses, uploaded
files and the history. Administrators upload a file: the server checks it,
a dialog shows who it is for, how many targets and the dates, and the
license is installed after confirmation (with step-up). EN/TR.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 20: Web — wizard license step and the "finish setting up" banner

Spec §18.5 step 6 and carry 3: after the recovery passphrase the wizard shows the Installation ID (with Copy), lets
the administrator upload a license (the same preview/confirm as the License page) or **Start 30-day evaluation
(up to 5 targets)**, then **Alice is ready**. A returning administrator resumes at this step. This task makes the
Playwright wizard journey pass again (it was blocked since Task 13).

**Files:**
- Create: `web/src/pages/setup/LicenseStep.tsx`
- Modify: `web/src/pages/SetupPage.tsx`, `web/src/api/types.ts` (`SetupStatus.license_chosen`), `web/src/api/endpoints.ts` (`chooseEvaluation`), `web/src/layout/AppLayout.tsx` (`SetupBanner`)
- Test: `web/src/pages/SetupPage.test.tsx`, `web/src/App.test.tsx`
- Modify: `web/src/test/fixtures.ts`, `web/src/test/screens.ts`, `web/src/locales/en.json`, `web/src/locales/tr.json`
- Modify: `web/e2e/helpers.ts` (`runWizard`, `COPY`)

**Interfaces:**
- Consumes: `POST /api/v1/setup/evaluation`, `SetupStatus.license_chosen` (Task 13); `LicenseUpload`, `InstallationID` (Task 19); `getLicense` (Task 18).
- Produces: `SetupStatus.license_chosen: boolean`; `chooseEvaluation(): Promise<SetupStatus>`; `WizardStep` gains `'license'`; `startOf` returns `'license'` when the passphrase is set and no license choice exists; `LicenseStep({ onDone, onGone })`; e2e `COPY.<lang>.licenseHeading`, `COPY.<lang>.startEvaluation`; `runWizard(page, request, lang, admin, opts)` gains `opts.license?: 'evaluation' | string` (a license file text to upload) and fills the admin's email when `admin.email` is set.

- [ ] **Step 1: Write the failing wizard tests**

In `web/src/test/fixtures.ts` add `license_chosen: true` to `installedStatus` and `license_chosen: false` to `freshStatus`.

In `web/src/pages/SetupPage.test.tsx`:

1. In `'walks a fresh install from the setup code to the dashboard'`, add to `server.use(…)`:

```ts
      http.post('/api/v1/setup/evaluation', () => {
        csrfSeen.push('evaluation');
        status = { ...status, license_chosen: true };
        return HttpResponse.json(status);
      }),
```

   and replace the block from `expect(await screen.findByRole('heading', { name: 'Alice is ready' })).toBeInTheDocument();` to the end of the test with:

```ts
    expect(await screen.findByRole('heading', { name: 'Add a license' })).toBeInTheDocument();
    expect(screen.getByTestId('installation-id')).toHaveTextContent('ALICE-7F3K-9Q2M-XD41-B8TC');
    await userEvent.click(screen.getByRole('button', { name: 'Start 30-day evaluation (up to 5 targets)' }));

    expect(await screen.findByRole('heading', { name: 'Alice is ready' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Go to the dashboard' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' })).toBeInTheDocument();
    // The setup session CSRF token is used before the admin exists, the admin session token after.
    expect(csrfSeen).toEqual(['setup-csrf', 'csrf-admin', 'evaluation']);
```

2. In `'asks the returning admin to confirm with a code before saving the passphrase'` and `'never keeps the setup code or passphrase in browser storage'`, add `license_chosen: false` to the status literals, and replace the final `findByRole('heading', { name: 'Alice is ready' })` of each with `findByRole('heading', { name: 'Add a license' })`.
3. In `'asks for a code again when finishing needs a fresh step-up'`, add `license_chosen: true` to the status literal.
4. Replace the `startOf` test body with:

```ts
    expect(startOf(null, null)).toBe('code');
    expect(startOf(freshStatus, null)).toBe('code');
    expect(startOf(installedStatus, null)).toBe('login');
    expect(startOf(installedStatus, admin)).toBe('home');
    expect(startOf({ ...installedStatus, completed: false, recovery_passphrase_set: false, license_chosen: false }, admin)).toBe('passphrase');
    expect(startOf({ ...installedStatus, completed: false, license_chosen: false }, admin)).toBe('license');
    expect(startOf({ ...installedStatus, completed: false }, admin)).toBe('done');
    expect(startOf({ ...installedStatus, completed: false }, sessionFor('operator'))).toBe('home');
```

5. Append inside `describe('setup wizard edge cases', …)`:

```ts
  it('uploads a license in the wizard instead of starting the evaluation', async () => {
    let status = { admin_exists: true, recovery_passphrase_set: true, license_chosen: false, completed: false, default_locale: 'en' };
    const upload = {
      license: { ...licenseInfoFixture, customer: 'Test Company' },
      pending: false,
      already_expired: false,
      correction: false,
      duplicate: false,
      phase: 'active',
    };
    server.use(
      http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
      http.get('/api/v1/auth/session', () => HttpResponse.json(sessionFor('admin'))),
      http.post('/api/v1/license/preview', () => HttpResponse.json(upload)),
      http.post('/api/v1/license', () => {
        status = { ...status, license_chosen: true };
        return HttpResponse.json(upload);
      }),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Add a license' });
    await userEvent.upload(screen.getByLabelText('License file'), new File(['{}'], 'l.alicelic', { type: 'application/json' }));
    await userEvent.click(screen.getByRole('button', { name: 'Check the file' }));
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Confirm the license' })).getByRole('button', { name: 'Install license' }));
    expect(await screen.findByRole('heading', { name: 'Alice is ready' })).toBeInTheDocument();
  });

  it('asks for a code before starting the evaluation when the step-up expired', async () => {
    let attempts = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: true, license_chosen: false, completed: false, default_locale: 'en' }),
      http.post('/api/v1/setup/evaluation', () => {
        attempts += 1;
        return attempts === 1
          ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')
          : HttpResponse.json({ ...installedStatus, completed: false });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    await renderRoute('/setup');
    await userEvent.click(await screen.findByRole('button', { name: 'Start 30-day evaluation (up to 5 targets)' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByRole('heading', { name: 'Alice is ready' })).toBeInTheDocument();
    expect(attempts).toBe(2);
  });
```

   and add `within` to the `@testing-library/react` import and `licenseInfoFixture` to the fixtures import.

In `web/src/App.test.tsx` append:

```ts
  it('reminds the admin of the license step', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), {
        admin_exists: true,
        recovery_passphrase_set: true,
        license_chosen: false,
        completed: false,
        default_locale: 'en',
      }),
    );
    await renderRoute('/');
    expect(await screen.findByTestId('setup-banner')).toHaveTextContent('Finish setting up: add a license or start the evaluation.');
  });
```

and add `license_chosen: false` to the two existing status literals of the setup-banner tests.

Run: `cd web && npx vitest run src/pages/SetupPage.test.tsx src/App.test.tsx`
Expected: FAIL — type errors on `license_chosen`, no **Add a license** heading.

- [ ] **Step 2: Implement the step**

In `web/src/api/types.ts` add `license_chosen: boolean;` to `SetupStatus` (after `recovery_passphrase_set`).

In `web/src/api/endpoints.ts` add after `completeSetup`:

```ts
export const chooseEvaluation = () => apiFetch<SetupStatus>(`${v1}/setup/evaluation`, { method: 'POST' });
```

Create `web/src/pages/setup/LicenseStep.tsx`:

```tsx
import { Button, Divider, Stack, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { chooseEvaluation, getLicense } from '../../api/endpoints';
import { useAuth } from '../../auth/AuthProvider';
import { ErrorAlert } from '../../components/ErrorAlert';
import { LicenseUpload } from '../../components/LicenseUpload';
import { useStepUp } from '../../components/StepUpProvider';
import { InstallationID } from '../LicensePage';
import { isGone } from './gone';

// LicenseStep is wizard step 6 (spec §18.5): upload the vendor's license, or start with the
// 30-day evaluation. The evaluation has run since Alice was first started (R27).
export function LicenseStep({ onDone, onGone }: { onDone: () => void; onGone: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const { refreshSetupStatus } = useAuth();
  const detail = useQuery({ queryKey: ['license', 'detail'], queryFn: getLicense });
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const finish = async () => {
    await refreshSetupStatus();
    onDone();
  };

  const evaluate = async () => {
    setBusy(true);
    setError(null);
    try {
      await run(chooseEvaluation); // settings.manage: a fresh code if the step-up expired
      await finish();
    } catch (e) {
      if (isGone(e)) return onGone();
      setError(e);
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Title order={2}>{t('setup.license.title')}</Title>
      <Text>{t('setup.license.help')}</Text>
      <ErrorAlert error={detail.error} />
      {detail.data && <InstallationID id={detail.data.installation_id} />}
      <Title order={3} size="h4">
        {t('setup.license.uploadTitle')}
      </Title>
      <LicenseUpload onInstalled={() => void finish()} />
      <Divider label={t('setup.license.or')} labelPosition="center" />
      <ErrorAlert error={error} />
      <Button variant="default" onClick={() => void evaluate()} loading={busy}>
        {t('setup.license.evaluate')}
      </Button>
      <Text size="sm" c="gray.7">
        {t('setup.license.evaluateHelp')}
      </Text>
    </Stack>
  );
}
```

In `web/src/pages/SetupPage.tsx`:

1. Import `LicenseStep` from `'./setup/LicenseStep'`.
2. Change `WizardStep` to `'code' | 'language' | 'admin' | 'totp' | 'codes' | 'passphrase' | 'license' | 'done'`.
3. Replace `return status.recovery_passphrase_set ? 'done' : 'passphrase';` with:

```ts
  if (!status.recovery_passphrase_set) return 'passphrase';
  return status.license_chosen ? 'done' : 'license';
```

4. Replace `{current === 'passphrase' && <PassphraseStep onDone={() => setStep('done')} onGone={gone} />}` with:

```tsx
        {current === 'passphrase' && <PassphraseStep onDone={() => setStep('license')} onGone={gone} />}
        {current === 'license' && <LicenseStep onDone={() => setStep('done')} onGone={gone} />}
```

In `web/src/layout/AppLayout.tsx`, `SetupBanner`, replace

```tsx
  const text = setupStatus.recovery_passphrase_set ? t('nav.setupBannerFinish') : t('nav.setupBanner');
```

with

```tsx
  const text = !setupStatus.recovery_passphrase_set
    ? t('nav.setupBanner')
    : !setupStatus.license_chosen
      ? t('nav.setupBannerLicense')
      : t('nav.setupBannerFinish');
```

- [ ] **Step 3: Add the texts and the screen**

`web/src/locales/en.json`: add to `nav` `"setupBannerLicense": "Finish setting up: add a license or start the evaluation."`, and to `setup`:

```json
    "license": {
      "title": "Add a license",
      "help": "Send this Installation ID to your vendor to get a license file, then upload it here. You can also start with the 30-day evaluation and add the license later on the License page.",
      "uploadTitle": "Upload the license file",
      "or": "or",
      "evaluate": "Start 30-day evaluation (up to 5 targets)",
      "evaluateHelp": "The evaluation started when Alice was installed. After 30 days, Alice pauses automatic tasks and changes to your servers until a license is uploaded. Your data is kept."
    }
```

`web/src/locales/tr.json`: add to `nav` `"setupBannerLicense": "Kurulumu tamamlayın: bir lisans ekleyin veya denemeyi başlatın."`, and to `setup`:

```json
    "license": {
      "title": "Lisans ekleyin",
      "help": "Lisans dosyası almak için bu Kurulum Kimliğini satıcınıza gönderin, ardından dosyayı buraya yükleyin. İsterseniz 30 günlük denemeyle başlayıp lisansı daha sonra Lisans sayfasından ekleyebilirsiniz.",
      "uploadTitle": "Lisans dosyasını yükleyin",
      "or": "veya",
      "evaluate": "30 günlük denemeyi başlat (en fazla 5 hedef)",
      "evaluateHelp": "Deneme süresi Alice kurulduğunda başladı. 30 gün sonra, bir lisans yüklenene kadar Alice otomatik işleri ve sunucularınızdaki değişiklikleri duraklatır. Verileriniz korunur."
    }
```

In `web/src/test/screens.ts` add after the passphrase screen:

```ts
  {
    path: '/setup',
    session: sessionFor('admin'),
    status: { ...installedStatus, completed: false, license_chosen: false },
    ready: { en: 'Add a license', tr: 'Lisans ekleyin' },
  },
```

and change the passphrase screen's status to `{ ...installedStatus, completed: false, recovery_passphrase_set: false, license_chosen: false }`.

Run: `cd web && npm run lint && npm test && cd .. && make i18n-check`
Expected: PASS.

- [ ] **Step 4: Teach the e2e wizard helper the new step**

In `web/e2e/helpers.ts`:

1. Add to `COPY.en`: `licenseHeading: 'Add a license', startEvaluation: 'Start 30-day evaluation (up to 5 targets)', licenseFile: 'License file', checkFile: 'Check the file', confirmLicense: 'Confirm the license', installLicense: 'Install license',` and to `COPY.tr`: `licenseHeading: 'Lisans ekleyin', startEvaluation: '30 günlük denemeyi başlat (en fazla 5 hedef)', licenseFile: 'Lisans dosyası', checkFile: 'Dosyayı denetle', confirmLicense: 'Lisansı onaylayın', installLicense: 'Lisansı yükle',`.
2. Add an optional `email?: string` to `Account`.
3. Change the signature of `runWizard` to

```ts
export async function runWizard(
  page: Page,
  request: APIRequestContext,
  lang: Lang,
  admin: Account = ADMIN,
  opts: { a11y?: boolean; license?: 'evaluation' | string } = {},
): Promise<{ totpSecret: string; recoveryCodes: string[] }> {
```

4. After `await field(page, c.fullName).fill(admin.fullName);` add `if (admin.email) await field(page, c.email).fill(admin.email);`.
5. Replace

```ts
  await page.getByRole('button', { name: c.savePassphrase }).click();

  await expect(page.getByRole('heading', { name: c.doneHeading })).toBeVisible();
```

with

```ts
  await page.getByRole('button', { name: c.savePassphrase }).click();

  await expect(page.getByRole('heading', { name: c.licenseHeading })).toBeVisible();
  await expect(page.getByTestId('installation-id')).toHaveText(/^ALICE(-[0-9A-Z]{4}){4}$/);
  if (opts.a11y) await expectAccessible(page, 'wizard license');
  if (opts.license && opts.license !== 'evaluation') {
    await uploadLicense(page, c, opts.license);
  } else {
    await page.getByRole('button', { name: c.startEvaluation }).click();
  }

  await expect(page.getByRole('heading', { name: c.doneHeading })).toBeVisible();
```

6. Add after `runWizard`:

```ts
// uploadLicense chooses a license file, checks it and confirms the preview dialog. The caller
// answers a step-up prompt first if one may appear (see confirmWithStepUp in the specs).
export async function uploadLicense(page: Page, c: Copy, fileText: string, a11y = false): Promise<void> {
  await field(page, c.licenseFile).setInputFiles({ name: 'alice-license.alicelic', mimeType: 'application/json', buffer: Buffer.from(fileText) });
  await page.getByRole('button', { name: c.checkFile }).click();
  const dialog = page.getByRole('dialog', { name: c.confirmLicense });
  await expect(dialog).toBeVisible();
  if (a11y) await expectAccessible(page, 'license preview dialog');
  await dialog.getByRole('button', { name: c.installLicense }).click();
  await expect(dialog).toHaveCount(0);
}
```

Run: `cd web && npx tsc --noEmit && npm run lint`
Expected: no errors (the Phase 1 specs call `runWizard` with the old arguments, which stay valid).

Run: `make e2e-up && make e2e`
Expected: the Phase 1 journeys pass again in EN and TR (the wizard now passes the license step with the evaluation).

- [ ] **Step 5: Commit**

```bash
git add web/
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(web): wizard license step

After the recovery passphrase the wizard shows the Installation ID and lets
the administrator upload the vendor's license or start the 30-day evaluation
(which has run since installation); a returning administrator resumes there
and the setup banner says what is left. The e2e wizard helper takes the
evaluation by default or uploads a given license.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 21: Playwright — Phase 2 journeys in English and Turkish

Spec §26.4 E2E list (evaluation banner, upload valid / tampered / wrong installation, banners at each threshold
with the test clock, in EN and TR) plus grace, lock, renewal unlock and the clock-backwards warning, with axe
checks of the new screens and dialogs at 640/1280/1920 px and the 375 px header check (carry 2e). Every journey
runs on the e2e stack (`make e2e-up`, tags `e2e testlicense`).

**Files:**
- Create: `web/e2e/phase2.spec.ts`

**Interfaces:**
- Consumes (Tasks 16, 20): `/test/license`, `/test/mail`, `/test/clock` (negative moves), `/test/reset`; helpers `runWizard(…, { license })`, `uploadLicense`, `signIn`, `freshCode`, `advanceClock`, `serverNow`, `expectAccessible`, `field`, `COPY` (incl. `licenseHeading`, `startEvaluation`, `licenseFile`, `checkFile`, `confirmLicense`, `installLicense`), `ADMIN`.
- Produces: nothing used by later tasks.

- [ ] **Step 1: Write the journeys**

Create `web/e2e/phase2.spec.ts`:

```ts
import type { APIRequestContext, Locator, Page } from '@playwright/test';
import {
  ADMIN,
  COPY,
  advanceClock,
  browserLocale,
  expect,
  expectAccessible,
  field,
  freshCode,
  resetInstall,
  runWizard,
  serverNow,
  signIn,
  test,
  type Account,
  type Copy,
  type Lang,
} from './helpers';

const ADA: Account = { ...ADMIN, email: 'ada@example.com' };
const DAY = 24 * 3600 * 1000;

// Exact UI copy of Tasks 18–20 (and the shared error texts of Task 14).
const L = {
  en: {
    navLicense: 'License',
    evaluation: 'Evaluation mode: 30 days left, up to 5 targets.',
    notValid: 'This file is not a valid Alice license.',
    otherInstallation: /This license file was made for a different installation \(ending in [0-9A-Z]{6}\)\./,
    summary: (n: number) => new RegExp(`^Valid until .+, ${n} targets$`),
    activated: 'License activated. All features are available again.',
    warning: (days: number) => (days === 1 ? 'Your license expires in 1 day (' : `Your license expires in ${days} days (`),
    grace: (day: number) => `Grace day ${day} of 7.`,
    locked: 'License expired. Automatic tasks are paused.',
    clockBehind: 'The server clock changed unexpectedly',
  },
  tr: {
    navLicense: 'Lisans',
    evaluation: 'Deneme modu: 30 gün kaldı, en fazla 5 hedef.',
    notValid: 'Bu dosya geçerli bir Alice lisansı değil.',
    otherInstallation: /Bu lisans dosyası başka bir kurulum için hazırlanmış \(sonu: [0-9A-Z]{6}\)\./,
    summary: (n: number) => new RegExp(`^Geçerlilik sonu .+, ${n} hedef$`),
    activated: 'Lisans etkinleştirildi. Tüm özellikler yeniden kullanılabilir.',
    warning: (days: number) => `Lisansınızın süresi ${days} gün sonra doluyor (`,
    grace: (day: number) => `Ek süre günü: ${day} / 7.`,
    locked: 'Lisans süresi doldu. Otomatik işler duraklatıldı.',
    clockBehind: 'Sunucu saati beklenmedik biçimde değişti',
  },
} as const;

// Subjects of the license emails in both languages (the admin's language decides).
const SUBJECT = {
  warning: /Alice license expires on|Alice lisansının süresi doluyor/,
  grace: /Alice license expired: automatic tasks stop on|Alice lisansının süresi doldu: otomatik işler duracak/,
  locked: /Alice license expired: automatic tasks are paused|Alice lisansının süresi doldu: otomatik işler duraklatıldı/,
};

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// otherInstallationId is a valid installation ID (Luhn mod 32 check character) of no real installation.
function otherInstallationId(): string {
  const vals = Array.from({ length: 15 }, () => Math.floor(Math.random() * 32));
  let factor = 2;
  let sum = 0;
  for (let i = vals.length - 1; i >= 0; i--) {
    const a = factor * vals[i];
    sum += Math.floor(a / 32) + (a % 32);
    factor = 3 - factor;
  }
  vals.push((32 - (sum % 32)) % 32);
  const s = vals.map((v) => CROCKFORD[v]).join('');
  return `ALICE-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}-${s.slice(12)}`;
}

async function testLicense(request: APIRequestContext, body: Record<string, unknown> = {}): Promise<string> {
  const res = await request.post('/test/license', { data: body });
  expect(res.ok(), await res.text()).toBe(true);
  return ((await res.json()) as { license: string }).license;
}

function validUntil(file: string): number {
  return Date.parse((JSON.parse(file) as { payload: { valid_until: string } }).payload.valid_until);
}

async function mails(request: APIRequestContext): Promise<{ to: string; subject: string }[]> {
  const res = await request.get('/test/mail');
  expect(res.ok()).toBe(true);
  return ((await res.json()) as { messages: { to: string; subject: string }[] }).messages;
}

// advanceTo moves the demo clock to an absolute server time (ms since the epoch).
async function advanceTo(request: APIRequestContext, target: number): Promise<void> {
  await advanceClock(request, Math.round((target - (await serverNow(request))) / 1000));
}

// answerStepUp confirms a step-up dialog with a fresh code if the server asks for one before done appears.
async function answerStepUp(page: Page, request: APIRequestContext, c: Copy, secret: string, done: Locator): Promise<void> {
  const stepUp = page.getByRole('dialog', { name: c.stepUpHeading });
  await expect(stepUp.or(done).first()).toBeVisible();
  if (await stepUp.isVisible()) {
    await field(stepUp, c.code).fill(await freshCode(request, secret));
    await stepUp.getByRole('button', { name: c.stepUpConfirm }).click();
  }
  await expect(done).toBeVisible();
}

async function openLicensePage(page: Page, lang: Lang): Promise<void> {
  await page.getByRole('link', { name: L[lang].navLicense, exact: true }).click();
  await expect(page.getByRole('heading', { name: L[lang].navLicense, level: 1 })).toBeVisible();
}

// chooseAndCheck selects a license file on the License page and asks the server to check it.
async function chooseAndCheck(page: Page, c: Copy, fileText: string): Promise<void> {
  await field(page, c.licenseFile).setInputFiles({ name: 'alice-license.alicelic', mimeType: 'application/json', buffer: Buffer.from(fileText) });
  await page.getByRole('button', { name: c.checkFile }).click();
}

// installOnPage uploads a valid license on the License page and confirms it.
async function installOnPage(page: Page, request: APIRequestContext, lang: Lang, secret: string, fileText: string, a11y = false): Promise<void> {
  const c = COPY[lang];
  await chooseAndCheck(page, c, fileText);
  const dialog = page.getByRole('dialog', { name: c.confirmLicense });
  await answerStepUp(page, request, c, secret, dialog);
  if (a11y) await expectAccessible(page, 'license preview dialog');
  await dialog.getByRole('button', { name: c.installLicense }).click();
  await expect(page.getByTestId('license-installed')).toHaveText(L[lang].activated);
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const c = COPY[lang];
  const l = L[lang];

  test.describe(`Phase 2 licensing (${lang})`, () => {
    test.use({ locale: browserLocale(lang) });
    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
    });

    test('wizard license step, evaluation banner and License page', async ({ page, request }) => {
      await runWizard(page, request, lang, ADMIN, { a11y: true });
      await expect(page.getByTestId('license-banner-evaluation')).toContainText(l.evaluation);
      await expectAccessible(page, 'home with the evaluation banner');

      await openLicensePage(page, lang);
      await expect(page.getByTestId('installation-id')).toHaveText(/^ALICE(-[0-9A-Z]{4}){4}$/);
      await expectAccessible(page, 'license page');

      // Carry 2e: the header fits a 375 px phone.
      await page.setViewportSize({ width: 375, height: 800 });
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, 'horizontal overflow at 375 px').toBeLessThanOrEqual(0);
    });

    test('upload a valid, an edited and a foreign license file', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await openLicensePage(page, lang);

      const good = await testLicense(request, { max_targets: 10 });
      const edited = good.replace('"max_targets": 10', '"max_targets": 1000');
      expect(edited).not.toEqual(good);
      await chooseAndCheck(page, c, edited);
      await answerStepUp(page, request, c, totpSecret, page.getByRole('alert').filter({ hasText: l.notValid }));

      await chooseAndCheck(page, c, await testLicense(request, { installation_id: otherInstallationId() }));
      await expect(page.getByRole('alert').filter({ hasText: l.otherInstallation })).toBeVisible();
      await expectAccessible(page, 'license page with an upload error');

      await installOnPage(page, request, lang, totpSecret, good, true);
      await expect(page.getByTestId('license-summary')).toHaveText(l.summary(10));

      // Owner step 3: an edited file is refused and the installed license stays.
      await chooseAndCheck(page, c, edited);
      await expect(page.getByRole('alert').filter({ hasText: l.notValid })).toBeVisible();
      await expect(page.getByTestId('license-summary')).toHaveText(l.summary(10));
    });

    test('warnings at each threshold, grace, lock and renewal (demo clock)', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang, ADA);
      await openLicensePage(page, lang);
      const file = await testLicense(request, { valid_days: 61 });
      const end = validUntil(file);
      await installOnPage(page, request, lang, totpSecret, file);
      expect(await mails(request)).toHaveLength(0);

      let sent = 0;
      for (const days of [60, 30, 14, 7, 1]) {
        await advanceTo(request, end - days * DAY + 3600 * 1000);
        await signIn(page, request, ADA, totpSecret);
        await expect(page.getByTestId('license-banner-expiry_warning')).toContainText(l.warning(days));
        sent += 1;
        const got = await mails(request);
        expect(got, `one email at ${days} days`).toHaveLength(sent);
        expect(got[sent - 1].to).toBe('ada@example.com');
        expect(got[sent - 1].subject).toMatch(SUBJECT.warning);
      }

      await advanceTo(request, end + 3600 * 1000);
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByTestId('license-banner-grace')).toContainText(l.grace(1));
      await expectAccessible(page, 'home in the grace period');
      expect((await mails(request)).at(-1)?.subject).toMatch(SUBJECT.grace);

      await advanceTo(request, end + 169 * 3600 * 1000);
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByTestId('license-banner-locked')).toContainText(l.locked);
      expect((await mails(request)).at(-1)?.subject).toMatch(SUBJECT.locked);
      await expectAccessible(page, 'home in lock');

      // Renewal: everything works again at once (L-30).
      await openLicensePage(page, lang);
      await installOnPage(page, request, lang, totpSecret, await testLicense(request, { valid_days: 365 }));
      await page.goto('/');
      await expect(page.getByTestId(/license-banner-(locked|grace|expiry_warning)/)).toHaveCount(0);
    });

    test('a clock set back warns and does not extend the license', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      await openLicensePage(page, lang);
      await installOnPage(page, request, lang, totpSecret, await testLicense(request, { valid_days: 30 }));

      await advanceClock(request, 10 * 24 * 3600);
      await signIn(page, request, ADMIN, totpSecret);
      await expect(page.getByTestId('license-banner-expiry_warning')).toContainText(l.warning(20));

      // Back by five days: the session stays valid (its idle limit lies in the future), so the page is simply reloaded.
      await advanceClock(request, -5 * 24 * 3600);
      await page.reload();
      await expect(page.getByTestId('license-banner-clock_behind')).toContainText(l.clockBehind);
      await expect(page.getByTestId('license-banner-expiry_warning')).toContainText(l.warning(20));
      await expectAccessible(page, 'home with the clock warning');
    });
  });
}
```

- [ ] **Step 2: Run the journeys**

Run:
```bash
make e2e-up
make e2e
```
Expected: all Phase 0, Phase 1 and Phase 2 specs pass in Chromium (EN and TR), including the axe checks and the CSP guard. If a Phase 2 step fails on timing (the banner query refreshes every minute), the journey navigates or signs in again after every clock move, which refetches immediately; never add fixed sleeps.

- [ ] **Step 3: Commit**

```bash
git add web/e2e/phase2.spec.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "test(e2e): licensing journeys in English and Turkish

Wizard license step and evaluation banner; upload of a valid, an edited and
a foreign license with the preview dialog; warnings and emails at 60, 30,
14, 7 and 1 days, grace, lock and renewal with the demo clock; a clock set
back warns without extending the license. New screens and dialogs are
checked with axe at 640, 1280 and 1920 px; the header fits 375 px.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 22: Coverage gate, documentation, R36, security review and owner verification

Spec §21 (`docs/licensing.md` and the vendor appendix `docs/vendor/licensing-vendor.md`), §26.1 items 6, 7 and 11,
§17.2 (Phase 2 security review note), §22.7 (coverage gates from Phase 2, R36 item 15), R8 (the owner's offline
key procedure). This task writes no production code except the small coverage tool.

**Files:**
- Create: `tools/covercheck/main.go`, `tools/covercheck/main_test.go`, `coverage-floors.json`
- Modify: `Makefile` (`coverage`), `.github/workflows/ci.yml`
- Create: `docs/licensing.md`, `docs/vendor/licensing-vendor.md`, `docs/security/reviews/phase-2.md`
- Modify: `docs/troubleshooting.md`, `docs/admin-guide.md`, `docs/operator-guide.md`, `docs/first-run.md`, `docs/dev/getting-started.md`, `CHANGELOG.md`
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md` (R36), `docs/superpowers/specs/2026-09-29-alice-v1-design.md` (R1–R36 reference), `docs/superpowers/specs/alice-v1/02-architecture.md` §7.6, `docs/superpowers/specs/alice-v1/04-security.md` §16.5, `docs/superpowers/specs/alice-v1/06-quality.md` §23.1

**Interfaces:**
- Consumes: everything above.
- Produces: `go run ./tools/covercheck -profile coverage.out -floors coverage-floors.json` (exit 1 when a package is below its floor); `make coverage`.

- [ ] **Step 1: Write the failing coverage-tool tests**

Create `tools/covercheck/main_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const profile = `mode: atomic
alice/internal/license/file.go:10.2,12.3 3 1
alice/internal/license/file.go:14.2,15.3 1 0
alice/internal/license/state.go:5.1,9.2 4 2
alice/internal/license/state.go:5.1,9.2 4 0
alice/internal/rbac/rbac.go:1.1,2.2 2 0
`

func TestPackageCoverage(t *testing.T) {
	cov, err := packageCoverage(strings.NewReader(profile))
	require.NoError(t, err)
	assert.InDelta(t, 87.5, cov["alice/internal/license"], 0.01, "7 of 8 statements; a repeated block counts once")
	assert.InDelta(t, 0, cov["alice/internal/rbac"], 0.01)
}

func TestRunEnforcesFloors(t *testing.T) {
	dir := t.TempDir()
	prof := filepath.Join(dir, "coverage.out")
	require.NoError(t, os.WriteFile(prof, []byte(profile), 0o600))
	floors := filepath.Join(dir, "floors.json")

	require.NoError(t, os.WriteFile(floors, []byte(`{"alice/internal/license": 85}`), 0o600))
	var out, errOut bytes.Buffer
	assert.Equal(t, 0, run([]string{"-profile", prof, "-floors", floors}, &out, &errOut))
	assert.Contains(t, out.String(), "alice/internal/license")

	require.NoError(t, os.WriteFile(floors, []byte(`{"alice/internal/license": 95, "alice/internal/missing": 10}`), 0o600))
	out.Reset()
	assert.Equal(t, 1, run([]string{"-profile", prof, "-floors", floors}, &out, &errOut))
	assert.Contains(t, out.String(), "BELOW FLOOR")
	assert.Contains(t, errOut.String(), "alice/internal/missing: no coverage data")
}
```

Run: `go test -count=1 ./tools/covercheck/`
Expected: FAIL — `no non-test Go files`.

- [ ] **Step 2: Implement the tool and the floors**

Create `tools/covercheck/main.go`:

```go
// Command covercheck enforces per-package statement coverage floors (spec §22.7, R36).
//
//	go run ./tools/covercheck -profile coverage.out -floors coverage-floors.json
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("covercheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profilePath := fs.String("profile", "coverage.out", "Go cover profile")
	floorsPath := fs.String("floors", "coverage-floors.json", "JSON object: package import path -> minimum percent")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	raw, err := os.ReadFile(*floorsPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	floors := map[string]float64{}
	if err := json.Unmarshal(raw, &floors); err != nil {
		fmt.Fprintln(stderr, "floors:", err)
		return 2
	}
	f, err := os.Open(*profilePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer func() { _ = f.Close() }()
	cov, err := packageCoverage(f)
	if err != nil {
		fmt.Fprintln(stderr, "profile:", err)
		return 2
	}
	pkgs := make([]string, 0, len(floors))
	for p := range floors {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	failed := false
	for _, p := range pkgs {
		got, ok := cov[p]
		if !ok {
			fmt.Fprintf(stderr, "%s: no coverage data\n", p)
			failed = true
			continue
		}
		status := "ok"
		if got < floors[p] {
			status, failed = "BELOW FLOOR", true
		}
		fmt.Fprintf(stdout, "%-40s %6.1f%%  (floor %.0f%%)  %s\n", p, got, floors[p], status)
	}
	if failed {
		return 1
	}
	return 0
}

// packageCoverage returns statement coverage per package from a cover profile. A block that
// appears more than once (merged profiles) counts once, covered if any copy was executed.
func packageCoverage(r io.Reader) (map[string]float64, error) {
	type block struct {
		stmts   int
		covered bool
	}
	blocks := map[string]*block{}
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			if strings.HasPrefix(line, "mode:") {
				continue
			}
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("bad profile line %q", line)
		}
		stmts, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("bad profile line %q", line)
		}
		b, ok := blocks[fields[0]]
		if !ok {
			b = &block{stmts: stmts}
			blocks[fields[0]] = b
		}
		b.covered = b.covered || count > 0
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	total, covered := map[string]int{}, map[string]int{}
	for key, b := range blocks {
		file := key[:strings.LastIndex(key, ":")]
		pkg := path.Dir(file)
		total[pkg] += b.stmts
		if b.covered {
			covered[pkg] += b.stmts
		}
	}
	out := map[string]float64{}
	for p, n := range total {
		if n > 0 {
			out[p] = 100 * float64(covered[p]) / float64(n)
		}
	}
	return out, nil
}
```

Create `coverage-floors.json`:

```json
{
  "alice/internal/license": 95,
  "alice/internal/rbac": 95,
  "alice/internal/auth": 84,
  "alice/internal/auth/ratelimit": 95,
  "alice/internal/audit": 90,
  "alice/internal/secrets": 81,
  "alice/internal/notify": 80,
  "alice/internal/jobs": 80
}
```

Append to `Makefile`:

```make
.PHONY: coverage
coverage: ## Run all Go tests (with integration) under coverage and enforce coverage-floors.json (R36)
	go test -race -count=1 -tags integration -coverprofile=coverage.out ./...
	go run ./tools/covercheck -profile coverage.out -floors coverage-floors.json
```

In `.github/workflows/ci.yml`, job `go`, replace `- run: make test-integration` with `- run: make coverage`.

Run: `go test -count=1 ./tools/covercheck/ && make coverage`
Expected: the tool tests pass; `make coverage` prints one line per package, all `ok`. If `alice/internal/license` is below 95 %, add tests for the uncovered branches (`go tool cover -func=coverage.out | grep internal/license/`) — never lower the floor.

- [ ] **Step 3: Write the customer guide**

Create `docs/licensing.md`:

```markdown
# Licensing

Alice is licensed per installation for a number of **managed targets** (Nginx servers, Linux hosts and Azure Key
Vaults). Certificates and SSH keys are not counted. Licenses run for a year and are renewed by uploading a new
file; no internet connection is needed.

## Your Installation ID

Every installation has an ID such as `ALICE-7F3K-9Q2M-XD41-B8TC`. It is created the first time Alice starts and is
kept by backups and restores, so a license keeps working after moving to new hardware. Find it on the **License**
page (administrators and auditors) or with `alice license status` on the server. The last character is a check
character: your vendor's tool detects a mistyped ID.

## The 30-day evaluation

A new installation runs as an evaluation for 30 days from the moment Alice was first started, with up to 5
targets. The setup wizard asks you to upload a license or to **Start 30-day evaluation**; choosing the evaluation
starts nothing new — the 30 days are already running. Everyone sees a blue banner with the days left;
administrators are warned 7, 3 and 1 days before the end (banner and email). When the evaluation ends, Alice goes
straight to lock mode (below). Nothing is deleted.

## Activating or renewing a license

1. Copy the Installation ID on the **License** page and email it to your vendor with the number of targets you need.
   Expected: the vendor replies with a file such as `alice-license-yourcompany-20261001.alicelic`.
2. On **License**, under **Upload a license**, choose the file and **Check the file**. Alice may ask for a new
   6-digit code first.
   Expected: **Confirm the license** shows "Licensed to …. Up to … managed targets. Valid from … to …".
3. Choose **Install license**.
   Expected: "License activated. All features are available again." The page shows "Valid until <date>, N targets".

The license takes effect at once, without a restart. If a renewal starts on a later date, the current license stays
in use until then. A renewal for fewer targets than you use is accepted: existing targets keep working and only
adding targets is blocked until you are within the limit.

If the upload is refused, the message says why (see [troubleshooting.md](troubleshooting.md), codes
`ALC-LIC-0002` to `ALC-LIC-0007`): a damaged or edited file, a license for another installation, a file that needs a
newer Alice, or an older file than the one installed. A refused upload changes nothing.

## What you see before and after the end date

| When | Who sees what | What works |
|---|---|---|
| 60, 30, 14, 7 and 1 days before the end | Administrators: yellow banner (orange at 7 and 1 days) and an email each time | Everything |
| From the end date, for 7 days (168 hours) | Everyone: red banner with the day of the grace period; administrators get a daily email | Everything |
| After the grace period (lock mode) | Everyone: red banner "License expired. Automatic tasks are paused." | See below |
| After uploading a renewal | Green message "License activated. All features are available again." | Everything, at once |

Emails need the SMTP settings (see [operator-guide.md](operator-guide.md#email)); without them the banners still
appear.

## Lock mode

In lock mode Alice makes no changes to your servers and stops automatic work that would change them. Your data is
kept and no certificate is revoked. These keep working: signing in, uploading a license, backups, the audit log and
its export, user administration, API tokens, and certificate expiry alerts by email (from a later release, with a
note that the license expired). Actions that would change a server are refused with `ALC-LIC-0001`. Work that was
paused needs an administrator's confirmation after the renewal.

## Clock changes

Alice remembers the latest time it has seen, in the database and in a protected file. If the server clock is set
back, Alice keeps counting from the later time — a license never gets longer — and administrators see "The server
clock changed unexpectedly …". If the clock jumps more than two days ahead, administrators are warned and Alice
waits 24 hours before the new time can start the grace period or the lock, so there is time to fix the clock or to
ask the vendor for a correction license. Keep the server time synchronised (NTP).

A clock set back by more than a minute also stops sign-in codes that are older than the last one used from being
accepted until the clock catches up; if the only administrator is affected, the server operator runs
`alice admin reset-mfa`.

## Frequently asked questions

- **We restored a backup onto a new server. Do we need a new license?** No. The Installation ID and the evaluation
  start are restored with the data.
- **We copied the whole installation to a test server.** The copy has the same Installation ID; your license terms
  decide whether that is allowed.
- **Which build accepts our license?** Every release from your vendor. `alice license keys` shows the vendor key
  fingerprints the build trusts.
```

- [ ] **Step 4: Write the vendor appendix with the owner's key procedure (R8)**

Create `docs/vendor/licensing-vendor.md`:

```markdown
# Licensing — vendor appendix (not shipped to customers)

This appendix is for the vendor. It covers `licensectl`, the signing key, the issuance ledger and correction
licenses (spec §16.7, §19.2, R8). `licensectl` never ships to customers and never uses the network.

## Build licensectl

On a trusted build machine: `make licensectl` → `bin/licensectl`. Copy the binary to the offline signing machine
with a clean USB stick. Tested on Linux and macOS.

## One-time: create the signing key (offline)

Do this once, on an air-gapped machine (a freshly installed laptop without network, or a live USB system). Nobody
else — no build server, no assistant, no CI — ever sees the private key or its passphrase.

1. Choose a Diceware passphrase of at least 6 random words (for example with physical dice). Write it on paper.
2. Run `licensectl keygen --out /media/offline/alice-vendor --key-id vk-2026-01`, type the passphrase twice.
   Expected: `Private key (encrypted): …/alice-license-private.pem`, `Public key: …/alice-license-public.pem`,
   `Key ID: vk-2026-01` and `Fingerprint: SHA256:…`. Write the fingerprint on the paper too.
3. Copy the whole `alice-vendor` directory to **two hardware-encrypted USB drives**.
4. Print the private key file (`alice-license-private.pem`, it is encrypted) on paper as the third backup.
5. Store: USB drive 1 in the fireproof safe on your premises; USB drive 2 and the printout in a bank safe deposit box
   or with a notary; the passphrase paper separately from both drives. When a second trusted person exists, give
   them a sealed copy of the passphrase.
6. Never copy the private key to a computer that is online, to cloud storage, e-mail or a password manager that
   syncs.

## One-time: put the public key into Alice builds

1. On the offline machine: `licensectl keyset --pub /media/offline/alice-vendor/alice-license-public.pem`.
   Expected: a JSON block with `"key_id": "vk-2026-01"` and the same fingerprint as in step 2 above.
2. Carry only that output (the public key) to your development machine and write it into
   `internal/license/keys/production.json`, replacing `{"keys": []}`. Commit it yourself (for example
   `git commit -m "chore(license): embed vendor license key vk-2026-01"`).
3. Run `make release-keycheck`. Expected: `ok`. (It fails while the file lists no key; release builds then accept no
   license at all.)
4. After building a release image, run `alice license keys` in it and compare the fingerprint with your paper.
   Publish the fingerprint on your website and in license emails (R20).

## Issuing a license

Checklist: confirm the paid order; check the Installation ID the customer sent; issue; verify; send; keep the ledger.

1. Mount the USB drive on the offline machine.
2. `licensectl issue --key /media/offline/alice-vendor/alice-license-private.pem --installation ALICE-7F3K-9Q2M-XD41-B8TC --customer "Example Bank A.S." --targets 100 --out alice-license-examplebank-20261001.alicelic`
   Options: `--from 2026-10-01` (start date, at most one day in the past; for an early renewal use the old expiry),
   `--months 12`, `--features a,b` (unused in v1), `--license-id` (default `LIC-<year>-<6 digits>`).
3. Type the passphrase; read the summary; type `yes`.
   Expected: `Written: …`, `SHA-256: …` and `Ledger: …/issued.csv`.
4. `licensectl verify --pub …/alice-license-public.pem alice-license-examplebank-20261001.alicelic` → `OK`.
5. Copy the license file to a clean USB stick and email it to the customer together with the key fingerprint.

A mistyped Installation ID is refused before anything is signed ("check each character").

## Correction licenses

Use `--replaces <license ID>` when a customer's clock jumped, the customer name was wrong, or targets were added
mid-term. A correction license may start earlier than the installed one (its issue date is then set to its start
date) and is always accepted by Alice. Uploading it also ends a held clock jump.

## The ledger

`issued.csv` next to the key records every license (ID, customer, installation, dates, targets, file SHA-256). Every
row is chained to the previous one and signed with the license key, so an edited, removed or reordered row is
detected: `licensectl ledger-verify --pub …/alice-license-public.pem`. Keep the ledger on both USB drives.

## Yearly recovery test

Once a year, on a clean offline machine: copy the key from USB drive 2, issue a test license for a test installation
with `--customer "Recovery test"`, and check it with `licensectl verify`. Record the date.

## Key rotation and compromise

- **Rotation:** create `vk-YYYY-NN` for the next key ahead of time, add it to `production.json` at least one release
  before you use it, and remove an old key only after every license signed with it has expired or been reissued.
- **Compromise** (the private key or its passphrase leaked): 1. create a new key offline; 2. ship an emergency release
  that adds the new key and marks the old one `"status": "revoked"` (optionally with `"revoked_from"`, the first
  issue date that is no longer trusted); 3. reissue every active license with the new key, free of charge; 4. notify
  customers (spec §17.4).
```

- [ ] **Step 5: Update the operator, administrator, first-run and developer guides and the changelog**

In `docs/operator-guide.md`, add to the **Commands** table after `alice admin unlock`:

```markdown
| `alice license status` | Prints the Installation ID, the license state (evaluation, active, grace, locked) and the license in force. Changes nothing. |
| `alice license keys` | Lists the vendor license keys built into this binary with their SHA-256 fingerprints; compare them with the fingerprint your vendor publishes. A development build without the vendor key says so and accepts no license. |
```

and append two sections:

```markdown
## State volume

Alice keeps its license time record in `ALICE_STATE_DIR` (default `/opt/alice/state`, the `alice-state` volume) in
addition to the database. Back it up with the other volumes. If it is lost, Alice uses the copy in the database; if
both are lost on an existing installation, Alice starts from the later of the system clock and the release date and
records "time reference reset" in the audit log.

## Email

In this release email is configured with environment variables in `deploy/.env` (a Settings page follows later):

| Variable | Meaning |
|---|---|
| `ALICE_SMTP_HOST` | Mail server; empty = no email (license warnings are then shown only as banners) |
| `ALICE_SMTP_PORT` | Default 587 (STARTTLS) or 465 (`ALICE_SMTP_TLS=tls`) |
| `ALICE_SMTP_FROM` | Sender, for example `Alice <alice@example.com>` |
| `ALICE_SMTP_USERNAME` | Optional user name |
| `ALICE_SMTP_PASSWORD_FILE` | File with the password, mounted into the container (never the password itself) |
| `ALICE_SMTP_TLS` | `starttls` (default) or `tls`; Alice never sends email unencrypted |
| `ALICE_SMTP_CA_FILE` | PEM file of a private certificate authority, if the mail server uses one |

To mount the password file, add a `docker-compose.override.yml` next to `docker-compose.yml`:

    services:
      alice:
        volumes:
          - ./secrets/smtp_password:/run/secrets/smtp_password:ro

and set `ALICE_SMTP_PASSWORD_FILE=/run/secrets/smtp_password`. Warnings go to every enabled administrator with an
email address, in their language. Failed sends are retried for about 2.5 hours (10 attempts).
```

In `docs/admin-guide.md` insert before `## For auditors`:

```markdown
## License

**License** (administrators and auditors) shows the Installation ID with **Copy**, the state (evaluation, active,
expired with grace period, locked), "Valid until <date>, N targets", how many targets are in use, a license that
starts later, the uploaded files and the history. Administrators upload a license under **Upload a license**:
**Check the file**, read the confirmation, **Install license** (a new 6-digit code may be asked first). The full
guide, including what lock mode does, is [licensing.md](licensing.md).

License banners appear at the top of every page: the evaluation and the expired states for everyone; warnings
60/30/14/7/1 days before the end, clock problems, damaged license data and the target limit for administrators only.
```

In `docs/first-run.md`, in **Before you begin** add the item
`- Optional: a license file from your vendor. Without one, start the 30-day evaluation and add the license later.`,
and replace steps 7 and 8 and the paragraph after them with:

```markdown
7. Type the recovery passphrase twice, tick **I stored the passphrase safely** and choose **Save passphrase**.
   If more than five minutes passed since you last typed a code, Alice first asks for a new 6-digit code
   (**Confirm it's you**).
   Expected: **Add a license**, with your Installation ID.
8. Either upload the license file from your vendor (**Check the file**, then **Install license**), or choose
   **Start 30-day evaluation (up to 5 targets)**. The evaluation has been running since Alice was installed.
   Expected: **Alice is ready**.
9. Choose **Go to the dashboard**. Here too, Alice may ask for a new 6-digit code if more than five minutes
   passed.
   Expected: the home page **Welcome, <your name>**, with a blue evaluation banner if you started the evaluation.

If you close the browser after step 6, sign in normally (password, then the code from your app). Alice shows a
red banner **Finish setting up: choose a recovery passphrase.** until you complete step 7,
**Finish setting up: add a license or start the evaluation.** until you complete step 8, and
**Finish setting up: open the setup wizard to confirm the last step.** until you complete step 9. The banner
links back to the wizard.
```

In `docs/dev/getting-started.md`, add to the configuration table after `ALICE_KEYS_DIR`:

```markdown
| `ALICE_STATE_DIR` | `/opt/alice/state` | Directory for the license time record (`hwm.dat`) |
| `ALICE_SMTP_HOST`, `_PORT`, `_FROM`, `_USERNAME`, `_PASSWORD_FILE`, `_TLS`, `_CA_FILE` | empty | Email for license warnings; see `docs/operator-guide.md` |
```

and replace the paragraph under `### The e2e build` with:

```markdown
`make e2e-up` builds the image with the Go build tags `e2e testlicense` (`deploy/docker-compose.e2e.yml`). Only
that build serves `GET/POST /test/clock` (read the clock, move it forward or back by `advance_seconds`, or jump the
wall clock only with `"wall_only": true`; the license evaluation and the email sender run right after every move),
`POST /test/reset` (empty all tables, the license time record and the mailbox), `POST /test/setup-token`,
`POST /test/license` (a license for this installation signed with the test key, which only this build trusts) and
`GET /test/mail` (emails the build would have sent). Release images are built without the tags; unit tests in
`cmd/alice` fail if the release build has a test endpoint, the demo clock, the test key or the test signer. The
e2e build reports its version with a `+e2e` suffix and logs a warning at startup. Never run it for real data.
```

In `CHANGELOG.md` insert above `## Unreleased — Phase 1: Core`:

```markdown
## Unreleased — Phase 2: Licensing

### Added
- Signed annual licenses per installation (Ed25519, RFC 8785 canonical JSON), limited by managed targets; the
  Installation ID (`ALICE-XXXX-XXXX-XXXX-XXXX`, with a check character) is created at first start and kept by
  restores.
- 30-day evaluation (5 targets) from the installation date; the setup wizard's new license step (upload a license or
  start the evaluation).
- **License** page: Installation ID with Copy, state, "Valid until <date>, N targets", target usage, uploaded files,
  history; upload with a server check, a confirmation dialog and step-up.
- License banners on every page (evaluation, warnings 60/30/14/7/1 days, grace, lock, clock problems) and warning
  emails to administrators (SMTP from `ALICE_SMTP_*`).
- Lock mode after the 7-day grace period: automatic work that changes servers pauses; changes to servers are refused
  (`ALC-LIC-0001`); sign-in, license upload, backups, audit, exports and user administration keep working.
- Clock protection: a server clock set back never extends a license; a large forward jump waits 24 hours.
- `licensectl` (vendor only): `keygen`, `issue`, `inspect`, `verify`, `keyset`, `ledger-verify`.
- CLI: `alice license status`, `alice license keys`.

### Changed
- Finishing setup now needs a license choice (`ALC-SET-0009`).
- New volume `alice-state` at `/opt/alice/state`.
- The permission `setup.finish` was removed (unused).

### Known issues
- Until the vendor's public key is built in, release builds accept no license (evaluation only).
- Nothing in this release changes servers yet, so lock mode only shows its banners; the refusal of changes becomes
  visible with targets in the next release.
- Certificate expiry emails with the "license expired" note arrive with alerts in a later release.
- The full list is in `docs/security/reviews/phase-2.md` ("Known limitations").
```

Add to `docs/troubleshooting.md`, after `## Cannot sign in`, a symptom section:

```markdown
## License messages

- **"The server clock changed unexpectedly …"** The server's clock is behind the latest time Alice has seen. Alice
  keeps using the later time, so nothing is extended or locked because of it. Correct the server time (NTP). The
  warning is recorded in the audit log once a day.
- **"The server clock jumped forward by N days"** Alice keeps the previous time for 24 hours. If the new time is
  wrong, correct it; otherwise wait, or ask the vendor for a correction license.
- **"License data was changed outside Alice"** A stored license file no longer matches its signature (the database
  was edited or damaged). Alice ignores it. Upload the license file from the vendor again.
- **Everyone sees "The evaluation period has ended" or "License expired"** Upload a license on the **License** page.
- **No warning emails arrive.** Check `ALICE_SMTP_*` ([operator-guide.md](operator-guide.md#email)) and that the
  administrators have an email address on **Users**.
```

- [ ] **Step 6: Record R36 and align the spec**

Append to `docs/superpowers/specs/alice-v1/00-decisions.md`:

```markdown
- R36 (Phase 2, approved with the Phase 2 plan) Accepted Phase 2 licensing decisions: the vendor's production public keys are embedded from the committed file `internal/license/keys/production.json` (`go:embed`); while it lists no key, release builds accept no license at all and `make release-keycheck` (`-tags releasecheck`, run by the release pipeline) fails, so a customer build can never trust a test or forged key; the test signing key is trusted only with `-tags testlicense` (e2e image) and a test proves release builds refuse test-signed files and link no test signer, no `licensectl` code and no `golang.org/x/term`; the HWM follows §16.5 (settings `time.hwm` + `<ALICE_STATE_DIR>/hwm.dat`, new volume `alice-state`), AES-GCM-encrypted under the extra HKDF label `alice/hwm-enc/v1` and MAC'd under `alice/hwm/v1`, and while the system clock is behind the HWM the HWM advances with uptime so time never stands still; the rollback warning appears beyond 65 minutes (L-52) while license math always uses the HWM; the installation ID and timestamp live in the `license` singleton row; uploaded files are stored verbatim in `license_files` (append-only for the app) and re-verified at every evaluation (parsed values are never stored); history is `license_history` with an extra `notice` event, unique per `(license_id, notice)`, which makes warning, grace-day, lock and clock notices exactly-once; the newest uploaded license whose `valid_from` has started is in force (pending otherwise); `PENDING` and `CLOCK_JUMP_SUSPECTED` are flags, not phases; grace day n is the n-th 24-hour period after `valid_until` (L-22 over L-51's example); `max_targets` is 1..100000; an already expired license is accepted (L-32); `license.locked` is 403 `ALC-LIC-0001` and the target limit 409 `ALC-LIC-0008` (§9.3 over L-26/L-71); lock mode refuses only routes tagged `ClassChange` in the route table (infrastructure groups `/targets`, `/certificates`, `/locations`, `/deployments`, `/ssh-keys`, `/rotation`, `/keyvault`) and never reads, users, tokens, auth, setup, audit, license, settings or backup (R9 over §9.6's list); `GET /license/status` gives Operators only `expired` and the banners everyone sees, the phase to Admins and Auditors, and warnings, clock, damaged-data and target-limit banners to Admins only (L-15); `GET /license/installation-id` is folded into `GET /license`; license upload has a preview endpoint and both need `license.manage` (Admin + step-up); the wizard license step records `setup.license_choice` and `setup.completed_at` needs it (`ALC-SET-0009`); Phase 2 email uses a TLS-only SMTP sender configured by `ALICE_SMTP_*` with the password in a file (Settings in Phase 7), and without SMTP emails are recorded as `skipped_no_smtp`; the in-process periodic scheduler (`license.evaluate` hourly, `notify.send` every minute) runs every task through the license gate and refuses `ClassChange` tasks, the durable queue following in Phase 3; coverage floors are enforced from Phase 2 (`internal/license` and `rbac` ≥ 95 %, other packages at their Phase 1 level; 95 % for auth, secrets, audit moves to Phase 8); `licensectl` keeps the key in a PEM file encrypted with Argon2id (256 MiB, t=4, p=4) and AES-256-GCM, requires ≥ 6 words and 24 characters, never overwrites a key, and keeps a chained, Ed25519-signed CSV ledger; `keygen --split` (Shamir) and the "Download request file" button are deferred; audit action names as listed in the Phase 2 plan.
```

In `docs/superpowers/specs/2026-09-29-alice-v1-design.md` replace `(including coordinator rulings R1–R35)` with `(including coordinator rulings R1–R36)`.

In `docs/superpowers/specs/alice-v1/02-architecture.md` §7.6, append to the **license** paragraph: `(Phase 2, R36: the uploaded files live verbatim in license_files and are re-verified at every evaluation; the time high-water mark is kept in settings and a state file per §16.5, not in license columns; history is license_history with a notice event.)`

In `docs/superpowers/specs/alice-v1/04-security.md` §16.5, append to the **Rollback behavior** bullet: `(R36: the warning appears beyond 65 minutes, L-52; while the clock is behind, the HWM advances with uptime.)`

In `docs/superpowers/specs/alice-v1/06-quality.md` §23.1, append the bullet: `- Phase 2 status codes and names follow R36: license.locked is 403 (ALC-LIC-0001), the target limit 409 (ALC-LIC-0008).`

- [ ] **Step 7: Write the Phase 2 security review note**

Create `docs/security/reviews/phase-2.md`:

```markdown
# Security Review — Phase 2 (Licensing and licensectl)

Scope (spec §17.2, Phase 2): signature verification, canonicalization, HWM MAC, fake-clock tests, lock behavior
safety. Exit criteria: tamper, forgery and downgrade tests pass; no data loss on lock; no High finding open.

## Evidence

All commands run from the repository root; integration tests need Docker.

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | License format, canonical JSON, strict parser, key set, forgery and revocation (L-40..L-47) | `go test ./internal/license/... -count=1` | ok |
| 2 | Test key trusted only by the test build | `go test -tags testlicense ./internal/license/... -count=1` and `go test ./cmd/alice -run TestReleaseBinary -count=1` | ok |
| 3 | Fuzzing the parser (§25.6) | `make fuzz-license` | no crasher |
| 4 | State machine L-01..L-33, L-48, L-70..L-78 | `go test ./internal/license -run 'Evaluation\|Threshold\|Grace\|Renewal\|Pending\|Target' -count=1` | ok |
| 5 | Clock guard and HWM (L-50..L-63) | `go test ./internal/license -run 'Guard\|HWM' -count=1` and `go test -tags integration ./internal/license -run 'Rollback\|Restarts\|ForwardJump\|Correction\|StartChooses' -count=1` | ok |
| 6 | Uploads, concurrency, tamper, notices exactly once (L-11..L-18, L-49, L-74) | `go test -tags integration ./internal/license/... -count=1` | ok |
| 7 | Lock gate: route classes, guard, scheduler (X-01, L-26, L-27, L-30, L-80 stubs) | `go test ./internal/api ./internal/jobs -run 'License\|Lock\|JobType\|Scheduler\|Running' -count=1` | ok |
| 8 | L-79 static check | `go test ./internal/archtest -count=1` | ok |
| 9 | License tables append-only for the app | `go test -tags integration ./migrations -count=1` | ok |
| 10 | Secret-leak suite incl. HWM sub-keys; GET routes never write | `go test -tags integration ./internal/api -run 'TestSecretsNeverLeak\|TestA06' -count=1` | ok |
| 11 | SMTP: TLS required, no plaintext credentials, header injection | `go test ./internal/notify -count=1` | ok |
| 12 | licensectl on Linux and macOS | CI job `licensectl` | green on both |
| 13 | Coverage floors | `make coverage` | all ok |
| 14 | E2E EN/TR incl. axe | `make e2e-up && make e2e` | all passed |
| 15 | Release key gate | `make release-keycheck` | fails until the vendor key is committed (expected), then ok |

## Crypto design review checklist

- [ ] Signed bytes = `"ALICE-LICENSE-v1\n"` ‖ RFC 8785 payload; parse strictly, re-canonicalize, verify before any
      semantic use; duplicate keys and unknown fields refused; `format` inside and outside the payload.
- [ ] Ed25519 via stdlib; key selection by `key_id`; revoked keys with optional `revoked_from` cutoff.
- [ ] Release builds embed only `keys/production.json`; the test key only under `testlicense`.
- [ ] HWM record AES-256-GCM (`alice/hwm-enc/v1`) + HMAC-SHA256 (`alice/hwm/v1`) over `"v1"‖hwm‖seq`; invalid = missing.
- [ ] Trusted time never decreases; rollback clamp; forward-jump hold 48 h / 24 h (R26).
- [ ] Vendor key file: Argon2id m=256 MiB t=4 p=4, AES-256-GCM, headers bound as AAD, seed zeroed after use.
- [ ] Ledger rows chained with SHA-256 and signed with Ed25519 under `"ALICE-LEDGER-v1\n"`.
- [ ] SMTP: STARTTLS or implicit TLS required, TLS 1.2+, verified certificate, AUTH only after TLS.

## Findings

| ID | Severity | Description | Decision |
|---|---|---|---|
| P2-01 | Medium | Someone with the master key and write access to the database and the state volume can rewrite the HWM and roll time back (spec §16.6). | Accepted (§16.6); root on the host already defeats the license by patching the binary. |
| P2-02 | Low | A forward clock jump that happens while Alice is stopped is not detected (downtime and a jump look the same). | Accepted: a forward jump can only shorten a license; the correction license covers it. |
| P2-03 | Low | The SMTP password is read from a file on the host (`ALICE_SMTP_PASSWORD_FILE`). | Accepted for Phase 2; Phase 7 stores it envelope-encrypted in `setting_secrets`. |
| P2-04 | Low | Removing the last rows of the vendor ledger is not detectable from the ledger alone. | Accepted: the ledger is kept on two USB drives; compare copies during the yearly recovery test. |
| P2-05 | Low | A clock set back more than ~30 s makes TOTP codes that are older than the last used step fail until the clock catches up (Phase 1 replay protection uses the wall clock). | Accepted; documented in `docs/licensing.md`; `alice admin reset-mfa` recovers the only administrator. |
| P2-06 | Low | The periodic scheduler has no cross-process lock (§8.3); two processes during an update both evaluate. | Accepted: evaluations serialize on the license row and notices are unique per license. Phase 3's queue adds the advisory lock. |
| P2-07 | Info | Until the owner commits the production key, release builds accept no license. | Intended (R36); `make release-keycheck` blocks a release. |

## Known limitations

- Nothing changes managed servers yet, so the lock gate refuses only a synthetic route in tests; the first real
  `ClassChange` routes and jobs arrive in Phase 3 (targets), and L-04, L-70..L-79 and L-80..L-88 are re-run against
  real targets and jobs in Phases 3, 4 and 6 (spec §26.4).
- Certificate `notBefore` warnings (L-53, L-56, L-57) need discovered certificates (Phase 4); the license module has
  no `notBefore` input by construction (R28).
- L-28 (expiry emails with the "license expired" note) arrives with alerts in Phase 7; L-44 (restore keeps the
  license) is exercised with backup/restore in Phase 8.
- Email configuration is by environment variables; Settings → Email arrives in Phase 7.
- `licensectl keygen --split` (Shamir) and the "Download request file" button are deferred.
- The Turkish texts have not yet been reviewed for tone by a native speaker.

## Owner verification

Spec §26.4 "Owner verifies". Steps 1–3 need the vendor's real key (made once, offline, per
`docs/vendor/licensing-vendor.md`); steps 4–5 use the test build.

1. Follow "One-time: create the signing key" and "put the public key into Alice builds" in
   `docs/vendor/licensing-vendor.md`. Then `make reset` (release-mode stack), finish the wizard with
   **Start 30-day evaluation**, and run `docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec -T alice /usr/local/bin/alice license keys`:
   the fingerprint equals the one on your paper.
2. On the vendor computer: `licensectl issue --key …/alice-license-private.pem --installation <the ID on the License page> --customer "Test Company" --targets 10 --out test.alicelic`.
   In Alice open **License**, **Upload a license**, choose the file, **Check the file**, **Install license**.
   Expected: "Valid until <date>, 10 targets".
3. Open `test.alicelic` in a text editor, change any number, save as `edited.alicelic` and upload it.
   Expected: "This file is not a valid Alice license." and the page still shows "Valid until <date>, 10 targets".
4. Test build: `make e2e-up`, open `https://localhost`, finish the wizard (with an email address for the
   administrator), and install a test license: `curl -sk -X POST -H 'Origin: https://localhost' https://localhost/test/license -d '{"valid_days":61}'`
   gives the file text (save the `license` value to a file and upload it). Move the date with
   `curl -sk -X POST -H 'Origin: https://localhost' https://localhost/test/clock -d '{"advance_seconds":90000}'`
   (about one day; repeat or change the number) and sign in again after each move. Check at 60, 30, 14, 7 and 1
   day(s) before the end: a yellow (then orange) banner, and a new message at `https://localhost/test/mail`. On
   the last day and during the 7 days after: a red banner, and everything works. After 168 hours: the "License
   expired" banner. (Adding something that changes a server arrives with targets in Phase 3.) Upload a new test
   license: "License activated. All features are available again." and the red banner is gone.
5. Still in the test build: `curl … /test/clock -d '{"advance_seconds":-432000}'` (five days back) and reload.
   Expected: "The server clock changed unexpectedly …" and the days left do not grow.

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
```

- [ ] **Step 8: Run the complete pipeline**

Run: `make ci`
Expected: everything green: lint, unit (all tag variants), coverage, build, i18n, web lint/test, vuln, secrets and fs scans, the e2e stack with the hardening check and Playwright EN/TR, image scan. `make release-keycheck` is not part of `make ci` and fails until the owner commits the production key.

- [ ] **Step 9: Owner verification (at execution time)**

The coordinator runs owner steps 4 and 5 of `docs/security/reviews/phase-2.md` on a clean e2e stack and records the
results; steps 1–3 need the owner's offline key and are handed to the owner in the phase summary (as in Phase 1).

- [ ] **Step 10: Commit**

```bash
git add tools/covercheck/ coverage-floors.json Makefile .github/workflows/ci.yml docs/ CHANGELOG.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "docs: licensing guides, vendor key procedure, R36 and the Phase 2 review

Customer guide docs/licensing.md and vendor appendix with the offline key
procedure (two encrypted USB drives and a paper copy, R8); operator,
administrator, first-run and developer guides; troubleshooting for license
messages; changelog; R36 with the spec alignments; the Phase 2 security
review note with owner verification. Coverage floors are enforced by
tools/covercheck (make coverage).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
## Phase 2 Done When

Spec §26.4 plus the global Definition of Done (§26.1):

1. `licensectl keygen/issue/inspect/verify/keyset/ledger-verify` work and are tested on Linux and macOS (CI job
   `licensectl`); a license issued by `licensectl` verifies with the key set built from its public key, and one
   signed with another key does not (Task 17).
2. The license module implements evaluation (30 days, 5 targets, direct lock), active, grace (168 h), lock, pending
   licenses, correction licenses, the target limit check, the MAC'd HWM in settings and the state file, rollback and
   forward-jump handling — L-01..L-63 and L-70..L-78 pass as unit or integration tests; L-79 is a static test;
   L-80..L-88 pass with stub jobs (Tasks 3–9, 11).
3. Warning emails at 60/30/14/7/1 days (7/3/1 in evaluation), a daily grace email and the lock email are sent exactly
   once per license through the outbox, over TLS-only SMTP, or recorded as skipped without SMTP (Tasks 9, 10).
4. The single lock gate `license.Service.Allow` is used by the scheduler before every task and by the API guard for
   every `ClassChange` route; every state-changing route declares its class; login, license upload, audit, exports,
   users and tokens work in lock (Tasks 11, 12, 14).
5. Every new route is in the route table, `api/openapi.yaml`, `docs/authz-matrix.md` (with the new "In lock"
   column) and the authz matrix test; every new error code has EN/TR texts and a troubleshooting entry.
6. `FuzzParseLicense` finds nothing; release builds refuse test-signed licenses and link no test signer or vendor
   code; `make release-keycheck` fails until the vendor's production public key is committed (R36 item 1).
7. The wizard has the license step; the License page and the banners work in EN and TR; Playwright covers the
   evaluation banner, valid/edited/foreign uploads, every threshold, grace, lock, renewal and the clock warning,
   with axe at 640/1280/1920 px (Tasks 18–21).
8. The secret-leak suite covers the HWM sub-keys; `make coverage` enforces the floors; `make ci` is green.
9. `docs/licensing.md`, `docs/vendor/licensing-vendor.md` (with the R8 owner procedure), the guides, CHANGELOG,
   R36 and `docs/security/reviews/phase-2.md` are written; no High finding is open.
10. Owner verification steps 4–5 were run on a clean e2e stack by the coordinator; steps 1–3 are handed to the owner
    with the phase summary.

## Known Limitations (carried to later phases)

- **No infrastructure yet (Phase 3+).** The lock gate is proven with a synthetic route and stub jobs; the first real
  `ClassChange` routes and jobs arrive with targets. L-04 and L-70..L-79 run against the stub target counter
  (`license.NoTargets`) until Phase 3; L-80..L-88 are re-run against real deployments (Phase 4) and rotations
  (Phase 6). Owner step 4's "try to add something" becomes visible in Phase 3.
- **Durable job queue (Phase 3).** The Phase 2 scheduler is in-process and periodic, without the cross-process
  advisory lock of §8.3 (safe because evaluations serialize on the license row and notices are unique). R29's
  "pending external-change jobs wait for Admin confirmation" needs the queue.
- **Certificate evidence (Phase 4).** The `notBefore` warning of R28/L-53/L-56/L-57 needs discovered certificates.
- **Alerts (Phase 7).** Certificate expiry emails "marked license expired" (L-28); SMTP moves from `ALICE_SMTP_*` to
  Settings → Email with the password envelope-encrypted; the lockout email of Phase 1.
- **Backup/restore (Phase 8).** L-06 and L-44 (restore keeps the Installation ID, the installation timestamp and the
  license) are verified with the backup/restore drill.
- **Vendor key.** Release builds accept no license until the owner commits `internal/license/keys/production.json`
  (owner procedure in `docs/vendor/licensing-vendor.md`).
- **Clock.** A forward jump while Alice is stopped is not detected (P2-02); a clock set back makes older TOTP codes
  fail until the clock catches up (P2-05).
- **Deferred small items.** `licensectl keygen --split` (Shamir, §16.7, only with a second trusted person); the
  "Download request file" button (§19.1); a native-speaker tone review of the Turkish texts; the Phase 1 findings
  still open (P1-01..P1-10) stay as recorded in `docs/security/reviews/phase-1.md`.

## Owner verification (mirrors §26.4)

The full, copy-paste version is in `docs/security/reviews/phase-2.md` ("Owner verification"). In short:

1. On the offline vendor computer create the signing key once (`licensectl keygen`), make the two encrypted USB
   copies and the paper copy, and commit the public key (`licensectl keyset`) to
   `internal/license/keys/production.json`; `alice license keys` shows the same fingerprint.
2. `licensectl issue --installation <ID shown in Alice> --customer "Test Company" --targets 10`; upload the file on
   **License** → "Valid until <date>, 10 targets".
3. Edit a number in the file and upload it → "This file is not a valid Alice license."; the earlier license stays.
4. Test build (`make e2e-up`): move the date with `/test/clock` and see the banners and emails at 60/30/14/7/1 days,
   the red grace banner for 7 days with everything working, the lock banner after 168 hours, and the green
   "License activated" after uploading a renewal.
5. Move the date backward: "The server clock changed unexpectedly …" and no extension.
