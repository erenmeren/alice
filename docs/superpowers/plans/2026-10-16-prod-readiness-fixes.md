# Prod-readiness fixes (2026-10-16 review) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the "fix before release" findings of `docs/security/reviews/prod-readiness-review-2026-10-16.md` (§3.1) that need no owner decision: OPS-1, OPS-2 (B-2), OPS-3, OPS-4, OPS-5, OPS-6, OPS-7, OPS-8, AUTH-1, CRY-1, REM-1, REM-2, REM-4, plus the §3.3 documentation corrections.

**Architecture:** Small, independent changes on one branch `prod-readiness-fixes` from `main` (a86def1a). No schema migration. One helper change (REM-4) bumps `alice-helper` to 1.6.1 with protocol 7 unchanged. Every task ends with its own tests green and one commit.

**Tech Stack:** Go 1.27 (testify), React/TypeScript (Vitest), GitHub Actions, bash release scripts with their Go harness (`deploy/release/scripts_test.go`), Markdown docs.

**Spec:** `docs/security/reviews/prod-readiness-review-2026-10-16.md` (findings), with the raw agent notes still at `/tmp/claude-1001/-home-meren-projects-alice-secrets/99cff3f0-d970-4543-a809-cffb3705265f/scratchpad/review/` (may vanish; the review file is authoritative).

## Global Constraints

- Branch `prod-readiness-fixes` from `main`; commit with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only <files> -m ...` (several agents share the index); end every message with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Never stage untracked files you did not create (`Alice-Proje-Dokumani.pdf`, `docs/security/reviews/*audit*`, `*review*` are untracked and stay so).
- Never run Docker-backed tests (`make coverage`, `make test-integration`, `make test-ssh`, testcontainers) while a Playwright run is in progress on this machine, and the other way round.
- `make lint` must stay clean (gosec, pincheck, docs-check, actionlint, ShellCheck, matrix-check -strict). `make i18n-check` must stay clean: every new `en.json` key gets its `tr.json` twin with identical placeholders.
- Documentation is English, in the existing voice (plain sentences, product names bold, codes in backticks). Rulings go in a new `docs/superpowers/rulings/prod-readiness-2026-10-16.md` in the format of `docs/superpowers/rulings/review-fixes.md` (item — decision — why — cost if wrong).
- Owner-only items stay owner-only: B-3 (production keys), B-5 (real environments), AUTH-2 (directory lockout policy, already on the owner's list). Never fake a checklist result.
- Do not close or merge the Dependabot pull requests; only the configuration changes.

## Review Focus

1. AUTH-1: a wrong password that arrives *during* a block must still be refused unevaluated (`locked`) and must not reset the count; only a failure *after* the block ended starts a new count. Test in Task 8.
2. CRY-1: the Go and TypeScript raters must agree rune for rune on every vector, including Turkish letters, emoji and JavaScript white space; a passphrase accepted before (the e2e fixture `kırmızı-kedi-mavi-deniz-2026`, the setup fixture `uzun ve güvenli bir kurtarma parolası`) must still be accepted. Vectors in Task 9.
3. REM-1: a legitimate large configuration (1000 certificate files, each used by 10 server blocks) must stay complete and un-truncated; only the amplified case is cut. Test in Task 10.
4. REM-4: a file whose *second* block is unreadable keeps its leaf and a `certificate_block_dropped` warning (today's behaviour); only an unreadable *first* block becomes `leaf_unreadable`. Test in Task 12.
5. OPS-6: an installation updated from a `.env` without the two new keys must get them (empty / default) and a `.env` that already has them must keep its values across `alice-update.sh`. Tests in Task 4.

---

### Task 1: OPS-1 — CI: coverage in its own job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Split the `go` job.** Keep `go` (timeout 30) with: checkout, setup-go, setup-node, `make tools`, `go mod verify`, `make lint`, `make test`, `make i18n-check`, `govulncheck ./...`, `make web-install`, `make build`, `make release-symcheck`. Add a new job `coverage` (runs-on ubuntu-latest, `timeout-minutes: 75`) with checkout, setup-go, `make tools`, `make coverage`. Keep `stack: needs: [go, web]` (not coverage). Add a comment above `coverage` naming the reason (the 20-minute `go` job was cancelled inside `make coverage` on every remote run; OPS-1).
- [ ] **Step 2: Verify.** Run: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/ci.yml` or `make lint` (which runs actionlint). Expected: no output / lint clean.
- [ ] **Step 3: Commit** `ci: coverage runs in its own 75-minute job so the go job no longer times out (OPS-1)`.

### Task 2: OPS-2 (B-2) — ZAP rule 10062 on the audit log is a hex-hash false positive

**Files:**
- Modify: `.zap/rules.tsv`
- Modify: `SECURITY-REPORT.md` (section 4, the three "ZAP baseline and API scan as …" rows: add "10062 PII Disclosure on `GET /api/v1/audit` ignored by policy: Luhn-valid digit runs inside SHA-256 hex `hash`/`prev_hash` fields; see `.zap/rules.tsv`")

Evidence: nightly run 38698738911, `admin.json` and `auditor.json`, rule 10062 on `GET /api/v1/audit?limit=50`, evidence `5806971502941005` ("Maestro"), a 16-digit run inside a 64-character hex audit hash. The response carries no card numbers; audit details are a denylisted map of short strings.

- [ ] **Step 1: Add the policy line** (tab-separated, expiry at most 180 days ahead: `2027-04-10`):
  `10062	IGNORE	PII Disclosure fires on Luhn-valid digit runs inside the 64-hex audit hash and prev_hash fields of GET /api/v1/audit (nightly 2026-10-15, evidence 5806971502941005); the audit log carries no personal numbers	2027-04-10`
- [ ] **Step 2: Verify the policy parses.** Run: `go run ./tools/zaprules .zap/rules.tsv` (read `tools/zaprules/main.go` for the exact arguments; if it accepts report files, also pass the downloaded reports at `/tmp/claude-1001/-home-meren-projects-alice-secrets/d93c9910-8f19-48ca-a370-406a5f5f3b11/scratchpad/dast/wrk/*.json` and expect the two 10062 alerts to be listed as ignored and the exit code 0).
- [ ] **Step 3: Commit** `security: ZAP 10062 on the audit hashes is a hex false positive; policy line with expiry (OPS-2)`.

### Task 3: OPS-7 — Dependabot never proposes a PostgreSQL major

**Files:**
- Modify: `.github/dependabot.yml` (the `docker-compose` `/deploy` entry and the `docker` `/deploy` entry)
- Modify: `docs/dev/dependency-updates.md` (PostgreSQL paragraph)

- [ ] **Step 1: Add** to both `/deploy` entries:
  ```yaml
      ignore:
        # A PostgreSQL major needs pg_upgrade or dump/restore: alice-update.sh would fail and roll back on every
        # customer (prod-readiness OPS-7). Majors are a planned release with their own migration path.
        - dependency-name: postgres
          update-types: ["version-update:semver-major"]
  ```
- [ ] **Step 2: Document** in `docs/dev/dependency-updates.md`: one paragraph "PostgreSQL majors" saying Dependabot is told to ignore them, why (the data directory format changes; the update script has no `pg_upgrade` step), and that the open PR #5 (16 → 18) must be closed, not merged, by the owner.
- [ ] **Step 3: Verify** the file still parses: `cd web && node -e "const y=require('yaml');y.parse(require('fs').readFileSync('../.github/dependabot.yml','utf8'));console.log('ok')"` (the `yaml` package is in `web/node_modules`; if not, `npx --yes yaml@2 …` or any YAML parser). Then `make lint`.
- [ ] **Step 4: Commit** `build(deps): Dependabot ignores PostgreSQL majors; the update path is a release of its own (OPS-7)`.

### Task 4: OPS-6 and OPS-4 (scripts) — `ALICE_TRUSTED_PROXIES` and `ALICE_MIGRATE_TIMEOUT` in the release `.env`

**Files:**
- Modify: `deploy/release/docker-compose.yml` (the `alice` service environment gains `ALICE_TRUSTED_PROXIES: ${ALICE_TRUSTED_PROXIES:-}`; the `migrate` service gains `ALICE_MIGRATE_TIMEOUT: ${ALICE_MIGRATE_TIMEOUT:-30m}`)
- Modify: `deploy/release/env.template` (append `ALICE_TRUSTED_PROXIES=` and `ALICE_MIGRATE_TIMEOUT=30m`)
- Modify: `deploy/release/lib/alice-lib.sh` (`alice_env_keys` gains both; `alice_write_env` takes two more positional parameters, `$9` proxies and `${10}` migrate timeout, and prints both lines; a missing `${10}` prints `30m`)
- Modify: `deploy/release/install.sh` (passes `""` and `30m`), `deploy/release/alice-update.sh` (reads both with `alice_env_get`; a missing key reads as `""` / `30m`; passes them through)
- Test: `deploy/release/scripts_test.go`
- Modify: `docs/operator-guide.md` ("Health endpoints and request limits": behind a reverse proxy set `ALICE_TRUSTED_PROXIES=<proxy address or CIDR, comma-separated>` in `/opt/alice/.env`, then `cd /opt/alice && sudo docker compose up -d alice`; the update keeps the value), `docs/troubleshooting.md` (`ALC-SYS-0005`: the same sentence replaces the one that names `deploy/.env`), `docs/upgrade.md` ("Before you update": a large database may need `ALICE_MIGRATE_TIMEOUT` above its default of 30 minutes; the value is a Go duration such as `2h`)

**Interfaces:** Task 5 reads `ALICE_MIGRATE_TIMEOUT` in the binary.

- [ ] **Step 1: Write the failing tests** in `scripts_test.go`, next to the existing `.env` assertions (around lines 695–712 and 950–972):
  - `TestInstallWritesTheProxyAndMigrateKeys`: after an install, `.env` contains `ALICE_TRUSTED_PROXIES=\n` and `ALICE_MIGRATE_TIMEOUT=30m\n`.
  - `TestUpdateKeepsTheProxyAndMigrateKeys`: an installation whose `.env` holds `ALICE_TRUSTED_PROXIES=10.0.0.5/32\nALICE_MIGRATE_TIMEOUT=2h\n` keeps both lines after `alice-update.sh`.
  - `TestUpdateAddsTheProxyAndMigrateKeysWhenMissing`: an installation whose `.env` lacks both keys has `ALICE_TRUSTED_PROXIES=\n` and `ALICE_MIGRATE_TIMEOUT=30m\n` after the update.
  Use the existing harness helpers (`shNew`, `e.pkg`, `e.install`, the update helpers used by the tests around line 950).
- [ ] **Step 2: Run** `go test ./deploy/release/ -run 'ProxyAndMigrate' -count=1` → FAIL.
- [ ] **Step 3: Implement** the script and compose changes above.
- [ ] **Step 4: Run** `go test ./deploy/release/ -count=1` (the whole package: compose hardening and layout tests read the compose file) and `make shellcheck` → PASS.
- [ ] **Step 5: Docs** as listed, then `make docs-check` if present in `make lint` (run `make lint`).
- [ ] **Step 6: Commit** `release: ALICE_TRUSTED_PROXIES and ALICE_MIGRATE_TIMEOUT are customer settings of /opt/alice/.env (OPS-6, OPS-4)`.

### Task 5: OPS-4 (binary) — migration time limit from `ALICE_MIGRATE_TIMEOUT`

**Files:**
- Modify: `internal/platform/config/config.go` (new field `MigrateTimeout time.Duration`; parsed from `ALICE_MIGRATE_TIMEOUT` with `time.ParseDuration`; default `30 * time.Minute`; below `1m` or above `24h` or unparsable → error `ALICE_MIGRATE_TIMEOUT must be a duration between 1m and 24h (got %q)`)
- Modify: `cmd/alice/main.go:173-183` (`migrate` uses `cfg.MigrateTimeout` instead of `2*time.Minute`; the `openDB` budget stays `time.Minute`)
- Test: `internal/platform/config/config_test.go`
- Modify: `docs/operator-guide.md` "Commands" row of `alice migrate`: "The whole run must finish within `ALICE_MIGRATE_TIMEOUT` (default 30m)."

- [ ] **Step 1: Failing tests** in `config_test.go` (follow the file's pattern for env-driven tests): default is 30m; `ALICE_MIGRATE_TIMEOUT=2h` gives 2h; `30s`, `25h` and `soon` each return an error containing `ALICE_MIGRATE_TIMEOUT`.
- [ ] **Step 2: Run** `go test ./internal/platform/config/ -run MigrateTimeout -count=1` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/platform/config/ ./cmd/alice/ -count=1` → PASS; `make lint` clean.
- [ ] **Step 5: Commit** `fix(migrate): the migration time limit is ALICE_MIGRATE_TIMEOUT, 30 minutes by default (OPS-4)`.

### Task 6: OPS-3 — `make release` refuses a dirty working tree

**Files:**
- Modify: `Makefile` (`release-preflight`)
- Modify: `docs/release-checklist.md` section 3 (one sentence: the stage is built only from a clean checkout of the release commit; `RELEASE_ALLOW_DIRTY=1` exists for `make release-test` experiments and is never used for a customer package)

- [ ] **Step 1: Add** to `release-preflight`, after the `RELEASE_COMMIT` check:
  `@if [ -z "$(RELEASE_ALLOW_DIRTY)" ] && [ -n "$$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then echo "make release: the working tree has uncommitted changes; the package must be built from the release commit (RELEASE_ALLOW_DIRTY=1 only for make release-test)"; exit 2; fi`
  (`RELEASE_COMMIT ?= $(shell git rev-parse HEAD)` already, Makefile line 476, so only the dirty-tree check is needed).
- [ ] **Step 2: Verify.** With a tracked file modified: `make release-preflight VERSION=9.9.9` → exit 2 with the message. With a clean tree: `make release-preflight VERSION=9.9.9` → exit 0 (the outputs check passes when no `release/alice-9.9.9` exists). Restore the file.
- [ ] **Step 3: Commit** `release: make release refuses uncommitted changes (OPS-3)`.

### Task 7: OPS-5 — released migrations are frozen by checksum

**Files:**
- Create: `migrations/frozen_test.go` (plain `package migrations_test`, no build tag)

- [ ] **Step 1: Write the test** `TestReleasedMigrationsAreFrozen`: a map `frozen = map[string]string{"00001_init.sql": "<sha256 hex>", …, "00015_ldap.sql": "<sha256 hex>"}` (compute each with `sha256sum migrations/*.sql` at implementation time and paste); the test reads `migrations.FS`, asserts every frozen file exists with that hash and fails with the message `migration %s changed: a released migration is never edited; add a new numbered migration (prod-readiness OPS-5, RA-04)`. A `.sql` file not in the map is allowed (new migrations) and listed with `t.Logf`.
- [ ] **Step 2: Run** `go test ./migrations/ -run Frozen -count=1` → PASS (and, by temporarily appending a comment to `00015_ldap.sql`, FAIL with the message; revert).
- [ ] **Step 3: Doc** one sentence in `docs/dev/getting-started.md` next to the migration notes ("The development stack reset"/"Migration 00014 was edited in place" area of `docs/operator-guide.md` if that is where migrations are discussed): from this commit on, `00001`–`00015` are frozen by `migrations/frozen_test.go`; every change is a new migration.
- [ ] **Step 4: Commit** `test(migrations): released migrations 00001-00015 are frozen by checksum (OPS-5)`.

### Task 8: AUTH-1 — a failure after an ended block starts a new count

**Files:**
- Modify: `internal/auth/login.go:142-153` (`recordFailure`)
- Test: `internal/auth/lockout_integration_test.go`
- Modify: `docs/admin-guide.md` "Sign-in protection" (replace "Because the count is still 10 or more when a block ends, one more wrong attempt starts a new 15-minute block." with "When a block ends, the count starts again: the next wrong attempt is the first of a new series, so someone who keeps guessing gets at most 10 attempts per 15 minutes and the right password is accepted as soon as the block has ended." and adjust the second paragraph's "someone who keeps guessing an administrator's password can keep it that way" accordingly), `docs/troubleshooting.md` lines 8–9 and 603 (same change), `docs/superpowers/specs/alice-v1/04-security.md` SEC-020 (append: "A failure recorded after a lockout has ended starts a new consecutive count (prod-readiness AUTH-1): the lockout is a ceiling of 10 evaluated guesses per 15 minutes, not a permanent state."), `docs/security-overview.md` "Authentication and MFA" bullet (same idea in one clause).

**Interfaces:** `recordFailure(ctx, tx, actor, userID, action, reason)` unchanged.

- [ ] **Step 1: Failing test** `TestAFailureAfterTheBlockEndedStartsANewCount` in `lockout_integration_test.go`: bootstrap; `e.setFailures(t, "admin", auth.LockThreshold-1)`; one wrong login → `failedLogins == LockThreshold` and one `auth.lockout`; `e.clk.Advance(auth.LockDuration - time.Second)`; wrong login → reason `locked`, count unchanged; `e.clk.Advance(2 * time.Second)`; wrong login → `ErrInvalidCredentials`, `failedLogins == 1`, no second `auth.lockout`; then the right password → `Login` succeeds (returns the pending MFA step, as the other tests do).
- [ ] **Step 2: Run** `go test -tags integration ./internal/auth/ -run AFailureAfterTheBlockEnded -count=1` → FAIL (count is 11).
- [ ] **Step 3: Implement** in `recordFailure`: replace the UPDATE with
  `UPDATE users SET failed_logins = CASE WHEN locked_until IS NOT NULL AND locked_until <= $2 AND failed_logins >= $3 THEN 1 ELSE failed_logins + 1 END, updated_at = $2 WHERE id = $1 RETURNING failed_logins` with `$3 = LockThreshold`. Update the function comment.
- [ ] **Step 4: Run** `go test -tags integration ./internal/auth/ -count=1` → PASS (the existing `TestParallelWrongPasswordsStopAtTheThreshold` must still pass).
- [ ] **Step 5: Docs and spec** as listed; `make lint` (docs-check).
- [ ] **Step 6: Commit** `fix(auth): a wrong password after a lockout ended starts a new count instead of a new block (AUTH-1)`.

### Task 9: CRY-1 — repeats and sequences no longer count as length

**Files:**
- Modify: `internal/setup/strength.go` (`PassphraseStrength`), `web/src/pages/setup/strength.ts` (`passphraseStrength`), `internal/setup/testdata/strength.json`
- Test: `internal/setup/strength_test.go`, `web/src/pages/setup/strength.test.ts` (both read the vectors)
- Modify: `docs/first-run.md` (step 7 and the checklist bullet), `docs/backup-restore.md` ("The recovery passphrase" rules), `web/src/locales/{en,tr}.json` only if the meter's helper text names the rule (optional; keep copy minimal)

**Rule (identical in both languages, rune by rune; `classes` is computed on the original text exactly as today):**
1. `length` = number of code points (unchanged); below 16 → `tooShort`.
2. `words` = the text split on JavaScript white space, empty pieces dropped (Go: `strings.FieldsFunc(p, jsSpace)`; TS: `p.trim().split(/\s+/)` with `''` filtered out). `distinct` = number of distinct words (exact comparison).
3. Word cycle: find the smallest `p` with `1 ≤ p ≤ len(words)/2`, `len(words) % p == 0` and `words[i] == words[i mod p]` for every `i`; if found, `words = words[:p]`. `core` = the runes of `words` joined by one space (an empty list gives an empty `core`).
4. Rune period: find the smallest `q` with `1 ≤ q ≤ n/2`, `n % q == 0` and `core[i] == core[i mod q]` for every `i` (`n` = rune count); if found, `core = core[:q]`.
5. Collapse runs: a run of **3 or more** identical runes becomes one rune (`aaa` → `a`; a double such as `ss` stays).
6. Collapse sequences: a run of 3 or more runes where every rune is the previous one plus 1, or every rune is the previous one minus 1 (code points: `abc`, `123`, `zyx`), becomes its first 2 runes.
7. `effective` = rune count of the result. If `effective < 16` → `fair`. Else `score = (effective ≥ 20) + (effective ≥ 28) + (classes ≥ 3 || distinct ≥ 4)`; `score ≥ 2` → `strong`, `1` → `good`, `0` → `fair`.

Worked expectations (pin them as vectors): `aaaaaaaaaaaaaaaaaaaa` → fair (run); `Password12345678` → fair (`P`+`assword` keeps 8, `12345678` → `12`: effective 10); `Abcdefgh12345678` → fair (`A`+`bc`+`12` = 5); `1111111111111111111111111111` → fair; `password password password password` → fair (word cycle → `password`, 8); `abcabcabcabcabcabcabc` → fair (period 3 → `abc` → `ab`); `Aa1!Aa1!Aa1!Aa1!` and `Aa1!Aa1!Aa1!Aa1!Aa1!` → fair (period 4); `abcdefghijklmnopqrst` → fair (sequence → 2); `abcdefghijklmnopqrstuvwxyzab` → fair; `ğüşöçıİğüşöçıİğüşöçıİ` → fair (period 7); the 20 emoji → fair; `    a b c d     ` → fair (core `a b c d` = 7); `a\tb\tc\tddddddddddd` and the other white-space vectors whose last word is a run → fair (they still pin the white-space parity); `one two three fo` → good (unchanged: 16, four distinct words); `Şifre Çözme 2026` → good (unchanged); `correct horse battery staple` → strong (effective 28); `Tr0ub4dor&3-Tr0ub4dor` → strong (21, four classes); `kırmızı-kedi-mavi-deniz-2026` → strong; `uzun ve güvenli bir kurtarma parolası` → strong. Also update the inline expectation `abcdefghijklmnopqrst` → `'fair'` in `web/src/pages/setup/strength.test.ts`.

- [ ] **Step 1: Update the vectors** (`strength.json`): change every expectation the rule changes (the worked list above) and add the new vectors from it, each with a note naming the rule that decides it; keep `require.GreaterOrEqual(len, 30)` satisfied and every rating covered.
- [ ] **Step 2: Run** `go test ./internal/setup/ -run Strength -count=1` and `cd web && npx vitest run src/pages/setup/strength.test.ts` → FAIL on the new vectors.
- [ ] **Step 3: Implement** both raters; keep the Go doc comment in sync with the TypeScript one (the comment enumerates the rule).
- [ ] **Step 4: Run** both test commands → PASS; `go test ./internal/setup/ -count=1`; `cd web && npx vitest run src/pages/setup` (the wizard page tests that type a passphrase use the fixtures above and must still pass).
- [ ] **Step 5: Docs:** `first-run.md` step 7 and `backup-restore.md`: add "Repeated characters, repeated words and runs such as `abcdef` or `123456` count almost nothing: `aaaaaaaaaaaaaaaaaaaa` is refused; several unrelated words are the easiest way to a Strong rating."
- [ ] **Step 6: Commit** `fix(setup): the passphrase meter discounts repeats and sequences on both sides (CRY-1)`.

### Task 10: REM-1 (RA-01) — a dump-wide budget for server memberships

**Files:**
- Modify: `internal/providers/nginx/discover.go` (`convert`; new constants `maxMembershipsPerDump = 20000`, `maxNamesPerDump = 100000` next to `maxServersPerLocation`)
- Test: `internal/providers/nginx/discover_test.go` (or the file that tests `convert`; find with `grep -ln "maxServersPerLocation" internal/providers/nginx/*_test.go`)

- [ ] **Step 1: Failing tests:**
  - `TestConvertBoundsMembershipsAcrossTheDump`: a dump with 1000 certificate paths each used by 500 server blocks (built like the PoC `docs/security/reviews/independent-audit-2026-10-04-poc/reaudit-8f15b80/internal_providers_nginx_zz_reaudit_p4certs_amplify_test.go.txt`, scaled so the test runs in well under a second) yields at most 20000 memberships in total across all locations and the warning `WarnListTruncated` once.
  - `TestConvertKeepsARealisticLargeConfiguration`: 1000 certificate paths × 10 server blocks each (10000 memberships, 1 name each) is returned complete with no truncation warning.
- [ ] **Step 2: Run** `go test ./internal/providers/nginx/ -run 'Convert' -count=1` → FAIL.
- [ ] **Step 3: Implement:** in `convert`, keep running totals `memberships` and `names` (names = `len(cs.Names)` per appended membership); when appending a membership would exceed either budget, set `truncated = true` and skip the append (the location still exists with the servers it has). Document both constants with the PoC numbers (16 MiB dump → 500k memberships → ~7 GiB).
- [ ] **Step 4: Run** `go test ./internal/providers/nginx/ -count=1` → PASS. If `internal/inventory` has a test on the truncation warning for locations, run `go test ./internal/inventory/ -run Truncat -count=1`.
- [ ] **Step 5: Commit** `fix(nginx): a dump-wide budget on server memberships and names stops the 16 MiB amplification (REM-1, RA-01)`.

### Task 11: REM-2 (RA-03) — SSH key comment and options text are capped

**Files:**
- Modify: `internal/providers/linuxssh/authkeys.go` (`parseKeyLine`; constants `maxCommentBytes = 1024`, `maxOptionsTextBytes = 1024`)
- Test: `internal/providers/linuxssh/authkeys_test.go`
- Modify: `docs/admin-guide.md` "SSH keys" (after "Key options such as `command=` … are shown exactly as they are in the file": "up to 1 KiB each; longer comments and option lists are cut in the inventory, never in the file")

- [ ] **Step 1: Failing test** `TestKeyCommentAndOptionsAreCapped`: a valid ed25519 line with a 5000-byte comment and a valid line with a 5000-byte `environment="…"` option list (options must stay known; use repeated `environment="K=v…"` values) parse as `LineKey`; `Comment` and `OptionsText` are at most 1024 bytes, cut at a rune boundary, ending in `…`; `Raw` is untouched; `Options` still lists the options (so `flagsFor` keeps working).
- [ ] **Step 2: Run** `go test ./internal/providers/linuxssh/ -run CommentAndOptionsAreCapped -count=1` → FAIL.
- [ ] **Step 3: Implement** a helper `capText(s string, max int) string` in `authkeys.go` used for both fields.
- [ ] **Step 4: Run** `go test ./internal/providers/linuxssh/ -count=1` and `go test -run '^$' -fuzz FuzzParseAuthorizedKeys -fuzztime 20s ./internal/providers/linuxssh/` → PASS.
- [ ] **Step 5: Commit** `fix(linuxssh): key comments and option text are capped at 1 KiB in the inventory (REM-2, RA-03)`.

### Task 12: REM-4 (RA-02) — an unreadable first certificate block is a problem, not a silent leaf swap

**Files:**
- Modify: `cmd/alice-helper/nginx.go` (`certBlocks` returns whether the *first* CERTIFICATE block was dropped: signature `certBlocks(data []byte) (blocks string, dropped, firstDropped bool)`; `describeCert` sets `fi.Problem = helperproto.FileLeafUnreadable` and `fi.PEM = ""` when `firstDropped`)
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go` (`FileLeafUnreadable = "leaf_unreadable"` next to `FileNotACertificate`; `Version = "1.6.1"`; the protocol comment gains one line "1.6.1 (protocol 7 unchanged): nginx-dump reports `leaf_unreadable` for a certificate file whose first block cannot be read")
- Modify: `internal/providers/types.go` (`CertProblemLeafUnreadable = "leaf_unreadable"`), `internal/providers/nginx/discover.go` (`fileProblems` map gains the pair)
- Modify: `web/src/locales/en.json` (line 1721, the `not_a_certificate` reason: "The file does not contain a certificate.") and the same key path in `tr.json`; add `leaf_unreadable` beside it: EN "The first certificate in the file cannot be read, so Alice does not know which certificate this website serves." TR "Dosyadaki ilk sertifika okunamıyor; Alice bu web sitesinin hangi sertifikayı sunduğunu bilmiyor.")
- Test: `cmd/alice-helper/nginx_test.go` (or the file that tests `certBlocks`), `internal/providers/nginx/discover_test.go`
- Modify: `docs/nginx-host-preparation.md` ("Updating the helper": the 1.6.1 paragraph; "Configurations Alice cannot manage": the new reason), `docs/troubleshooting.md` (the certificate-file reasons list, if one exists: `grep -n not_a_certificate docs/troubleshooting.md`), `CHANGELOG.md` (Unreleased: helper 1.6.1)

- [ ] **Step 1: Failing helper test** `TestCertBlocksReportsAnUnreadableFirstBlock`: data = a CERTIFICATE block whose DER does not parse (e.g. the PoC's negative-serial certificate, or simply `[]byte{0x30, 0x03, 0x02, 0x01, 0x01}` PEM-encoded as CERTIFICATE) followed by a valid self-signed certificate: `firstDropped == true`; the reverse order (valid, then unreadable): `dropped == true, firstDropped == false`, blocks hold the valid one. And `TestDescribeCertMarksLeafUnreadable` through the existing `sys` test harness if the file has one: `fi.Problem == "leaf_unreadable"`, `fi.PEM == ""`, and the dump still carries the `certificate_block_dropped` warning.
- [ ] **Step 2: Failing provider test** in `discover_test.go`: a dump file with `Problem: "leaf_unreadable"` yields a location with `Problem == providers.CertProblemLeafUnreadable` and no certificate.
- [ ] **Step 3: Run** `go test ./cmd/alice-helper/ ./internal/providers/nginx/ -run 'LeafUnreadable|UnreadableFirstBlock' -count=1` → FAIL.
- [ ] **Step 4: Implement** all files above; `make i18n-check`.
- [ ] **Step 5: Run** `go test ./cmd/alice-helper/ ./internal/providers/... ./internal/inventory/ -count=1`, `make i18n-check`, `make lint` → PASS. Then the real matrix on one distribution (Docker; not while Playwright runs): `ALICE_SSH_IMAGES=ubuntu22 make test-ssh` → both lines PASSED.
- [ ] **Step 6: Docs and CHANGELOG** as listed.
- [ ] **Step 7: Commit** `fix(helper): nginx-dump reports leaf_unreadable instead of handing Alice the intermediate as the leaf; helper 1.6.1 (REM-4, RA-02)`.

### Task 13: OPS-8 and §3.3 — security report, checklist, spec text, rulings

**Files:**
- Modify: `SECURITY-REPORT.md`: section 2 "Method" review list gains the ACME, network-discovery, LDAP and prod-readiness reviews; section 7 gains `KI-36` (ACME: tested only against a simulated authority; account keys under the master key; revocation at the authority; cross-reference `docs/security/reviews/acme-issuance.md`), `KI-37` (network discovery: scans trust nothing they find, tested only on simulated servers and loopback, can trip IDS; `docs/security/reviews/network-discovery.md` L1–L16), `KI-38` (directory sign-in: password passes through Alice, 45-minute per-name lock anyone can trigger (AUTH-2, owner decision pending), not run against a real AD; `docs/security/reviews/ldap-signin.md`), `KI-39` (prod-readiness review items accepted or deferred: CORE-1/CORE-3 single-process assumption, REM-2 inventory rows never pruned, AUTH-5 no If-Match on users PATCH, VC-1..VC-4 vendor-side); section 4 adds the three ZAP rows' note (Task 2) and a row "prod-readiness review 2026-10-16: local gates (see the review §2)"; `KI-16` text: "Forwarding, SMTP test, server connections and OIDC discovery may target loopback or private addresses" (scope widened per Z-02).
- Modify: `docs/release-checklist.md`: the second `1.31` row becomes `1.32`; new owner rows under "Exit criteria of spec §26.10 not covered above" (or a new subsection "Features after Phase 8"): ACME against the real authority's staging service with a DNS hook and the web proof; network discovery on one real network segment with IDS owners informed; directory sign-in against a real Active Directory or Samba AD (Test connection, Test sign-in, a nested group, a disabled and a locked account); each Class B, Owner, empty result.
- Modify: `docs/superpowers/specs/alice-v1/04-security.md` SEC-043: the label list drops `alice/audit-hmac/v1` from the "used" list and adds "(`alice/audit-hmac/v1` is reserved and unused: the audit chain is unkeyed in v1, KI-05)"; the `LabelAuditHMAC` constant comment in `internal/secrets/envelope.go` says "reserved for v2; unused (KI-05)".
- Create: `docs/superpowers/rulings/prod-readiness-2026-10-16.md` with entries: AUTH-2 (deferred to the owner's directory-lockout decision; why; cost), A-2 (TOTP enrolment on the password alone, accepted: the pending session is single-use and the first verified code closes it), Z-03 (operate tokens need no step-up, accepted: every high-impact action refuses tokens outright, authz matrix), N-02 (no TLS to PostgreSQL on the internal network, accepted: SCRAM, no published port, same host), REM-2 (inventory rows of vanished keys are never pruned, by design), OPS-7, OPS-3, OPS-5 (frozen from 00015), AUTH-1 (new count after a block), CRY-1 (rule), REM-1 (budgets), CORE-1/CORE-3 (single-process assumption documented; HA is out of scope for v1).
- Modify: `CHANGELOG.md` "Unreleased" gains a "Prod-readiness fixes" block listing AUTH-1, CRY-1, REM-1, REM-2, REM-4 (helper 1.6.1), OPS-4/OPS-6 (two new `.env` keys), OPS-5.
- Modify: `docs/security/traceability.md` only if `make lint`'s `matrix-check -strict` asks for it.

- [ ] **Step 1: Write** every change above.
- [ ] **Step 2: Verify** `make lint` (docs-check, matrix-check) → clean; `grep -c "| 1.31 |" docs/release-checklist.md` → 1.
- [ ] **Step 3: Commit** `docs: security report, release checklist, spec SEC-043 and rulings for the prod-readiness review (OPS-8)`.

### Task 14: Whole-branch verification

- [ ] **Step 1:** `make lint && make test && make web-test && make i18n-check && make authz-doc && git diff --exit-code docs/authz-matrix.md` → all clean.
- [ ] **Step 2:** `make coverage` (Docker; ~12 min; floors of `coverage-floors.json` met).
- [ ] **Step 3:** `make e2e-up && make e2e && make e2e-down` (Chromium; ~25 min; no Docker tests meanwhile). Expected: all passed, skips only for the documented opt-ins.
- [ ] **Step 4:** Report the exact outputs; then merge `prod-readiness-fixes` into `main` fast-forward (no squash, no rebase: `.gitleaksignore` pins commit hashes). Do not push.
