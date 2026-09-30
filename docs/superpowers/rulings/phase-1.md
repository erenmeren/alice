# Phase 1 — controller rulings

Decisions taken on the owner's behalf during autonomous execution of docs/superpowers/plans/2026-09-30-phase-1-core.md (owner instruction 2026-09-30: proceed without waiting). Each line: decision — why — cost if wrong.

- Plan's proposed R35 (hand-written queries + hand-maintained OpenAPI; app-assigned gapless audit seq; CSRF derived from session token + session kind; lockout on users table; master key created on first start only with empty DB; `alice setup-token --reset` until install.sh; React Router 7; wizard ends after recovery passphrase; single-scope API tokens; no forced password change at first sign-in) accepted on the owner's behalf — owner said not to wait; planner dry-ran tasks 1-24 green — cost if wrong: owner may ask to revise R35 items in a later phase.
- Planner dry-ran Tasks 1-24 in a clone (lint/unit/integration/web/e2e green); pre-flight scan therefore focuses on spec conflicts + cross-task interfaces and runs concurrently with Task 1 — cost if wrong: late-found conflicts enter the fix loop.
- Task 25 `make reset` may wipe this project's alice_* dev volumes (throwaway dev data) — never other containers/volumes.
- C6/C7 lockout race + password-change failures fixed in Task 10 with per-user FOR UPDATE transaction and parallel tests — spec lockout thresholds are security-critical — cost: none.
- C10 master key loader refuses symlinks/non-regular/foreign-owned files (Task 5) — SEC-042 — cost: none.
- C14 superuser migration URL in app container kept for Phase 1 dev stack, recorded as Medium Known Limitation, fixed in Phase 8 — restructuring compose into one-shot migrations is packaging work — cost if wrong: an RCE in alice yields DB superuser until Phase 8.
- B20/B21 key/DEK canaries + panic-output test (Task 17), core dumps disabled in compose (Task 16) — cost: none.
- A14/B24 audit export made read-only with stronger no-mutation test — spec: GET never mutates — cost: none.
- B22 add R-03/R-10 tests; R-04 statistical timing test deferred — cost if wrong: timing side-channel unmeasured until later.
- B28/D1 axe at 1280+1920 and keyboard-only sign-in in Task 24 — cost: e2e time.
- B30/D7 owner phone walkthrough (Task 25 Step 10) not executed by agents; handed to owner in phase summary — cost: DoD owner step pending owner.
- Cosmetic rows (A31-A34, B2, B8, B9, A11, B13, B29, C13, C17, C19, D2-D13) folded into the owning tasks / R35 addendum / Known Limitations as listed — cost: none.
- Logger key-coverage gap (masterKey/apiKey/dek/credential/recovery_code/setup_code not redacted) elevated from Minor to Important and fixed in Task 2 — Phase 1 introduces exactly these secrets — cost: none.
- Keyring gets full redaction (String/GoString/Format/LogValue/MarshalJSON) + canary test — master key never in logs (SEC-050) — cost: none.
- Keep a denylist but make it case-insensitive segment-based with id/prefix/count exceptions, verified against every Details literal in the plan — a registered allowlist would break later dry-run tasks — cost if wrong: an unanticipated secret-bearing key name could slip into audit details; recorded in R35.
- Append normalises NUL/invalid UTF-8/zoned IPs before hashing — attacker-controlled input must not suppress audit rows — cost: none.
- Service-level credential semaphore acquired before InTx on Login/ChangePassword/StepUp/VerifyMFA(recovery/enroll) incl. unknown-user path + SET LOCAL lock_timeout 5s — bounds pool use regardless of IP count and equalises timing — cost: global credential throughput capped at hasher concurrency (acceptable; Argon2 already capped).
- Disabling a user revokes all their API tokens (spec silent; disable is Phase 1 offboarding) — cost if wrong: admin must mint new tokens after re-enable.
- UpdateUser locks admin set only for role/disabled changes; last_used_at written at most once per minute — cost: none.
- ListTokens keeps hiding revoked tokens (test checks absence + revoked_at in DB) — matches approved lifecycle test — cost: none.
- Service-level SettingsManage guard added to SetRecoveryPassphrase/Complete — set-once passphrase makes a route mistake irreversible — cost: none.
- XFF joins all header lines; auth backend errors -> logged 503 ALC-SYS-0002 retryable, no authz.denied row — spec: client IP must not be spoofable; fail-closed 503 grants nothing — cost: none.
- gitleaks hits are known test fixtures (qwerty123456 breached-password example, RFC 6238 test secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ, example passphrase correct-horse-battery-2026) — allowlist those exact regexes (not paths) in .gitleaks.toml — cost if wrong: a real secret with the same literal value would be missed (negligible).
- Phase 0 smoke e2e failures on /api/v1/version (401) are fixed by Task 19/24 as planned; CI stack job red until then — cost: CI red for a few tasks.
- e2e build logs a startup warning + version suffix +e2e; e2e-tag Go tests run in make test; /test/clock body/range capped — defence-in-depth against deploying the e2e image — cost: none.
- Task 23 implementer dispatched while Task 22 review runs (reviewer is read-only; only one implementer active) — saves wall-clock — cost if wrong: a Task 22 fix round waits for Task 23 to finish.
- Task 25 docs-only fix is re-verified by grep evidence + the final whole-branch review instead of a separate scoped re-review — one-line doc change — cost if wrong: final reviewer catches it.
- Add `alice admin unlock` CLI instead of changing counter semantics — keeps Task 18 pinned behaviour; gives host-root recovery — cost if wrong: attacker can still re-block every 15 min until admin runs unlock.
- Wizard Back/server-side resume (spec §18.5) documented as R35 deviation + Known Limitation for Phase 8 install wizard rather than built now — cost: reload mid-wizard restarts at setup code.
- POST /audit/verify writable by Auditors/read tokens accepted (intended) — documented.

## Residual items parked for Phase 2

- web/*.tsbuildinfo not gitignored; red.9 hover contrast 4.48:1; grant guard misses column-level grants on listed relations; mobile nav doesn't close on non-link navigation; header may overflow <640px
