# LDAP directory switch-off and lockout unlock — rulings

Decisions taken while implementing two owner-accepted changes from an outside review of directory (LDAP and Active
Directory) sign-in (2026-10-20): (1) switching a directory off ends its users' access at once; (2) the directory
sign-in lockout gets an audit entry when it starts and an Administrator unlock. Spec:
`docs/superpowers/specs/2026-10-15-ldap-directory-signin-design.md`. Each entry: decision — why — cost if wrong.

## 1. Switching a directory off

- R1. **What ends.** `ldap.UpdateDirectory`, when `enabled` goes from true to false, calls
  `auth.EndDirectoryAccess` in its own transaction, after the directory's `UPDATE`: every user whose
  `ldap_directory_id` is the directory has every session (full and pending) ended and every API token revoked, the
  same rows `endAccess` writes for a refusal with `provider_disabled` — why: the review asked for "at once"; API tokens
  are a credential issued on the directory's word, as the SSO rule (O-08) already treats them — cost if wrong: a
  directory switched off by mistake signs everyone of it out; they sign in again once it is switched on.
- R2. **Audit.** `token.revoked` per token and one `user.sessions_ended` (reason `provider_disabled`, `ended_count`,
  `revoked_tokens_count`) per user **that had a session or a token to end**; users with nothing to end get no row. The
  actor is the Administrator who switched it off (not the user, as in `RefuseLDAP`), and `ldap.directory_changed`
  carries `signed_out_count` (the number of such users) only on the switch-off — why: a directory can have many users
  who are not signed in; a row per idle user would bury the audit log, and the Administrator is who ended the access —
  cost if wrong: an auditor who wants the full list of the directory's users at that moment reads it from the users
  list, not the log.
- R3. **No race with an in-flight sign-in.** `SignInLDAP` now locks the directory's row `FOR SHARE` (after the "SSO
  users may be Admin" row, before the user's row) and refuses a directory that is off or gone with the new
  `auth.ErrLDAPDirectoryDisabled`, answered like a switched-off directory (`ALC-LDAP-0002`, audit reason
  `provider_disabled`, which `RefuseLDAP` already treats as ending access). The switch-off's `UPDATE` conflicts with
  that lock, so either the sign-in commits first and the switch-off's later statement sees and ends its session, or
  the switch-off commits first and the sign-in is refused. The users are locked in ID order after the directory row,
  the same order the sign-in takes — why: `Verify` checks `enabled` outside any transaction, so without this a password
  accepted a moment before the switch would open a session that outlives it — cost if wrong: none known; the extra
  row lock is shared and held for one short transaction. `StepUpLDAP` and `VerifyMFA` need no change: the sessions
  they continue were ended by the switch-off, and both re-check the session under the user's row lock.
- R4. **Wiring.** `ldap.Config` gains `Auth *auth.Service` (as `oidc.Config` has); switching a directory off without
  it is an error, never a silent skip (`cmd/alice` passes the service; `cmd/alice:TestReleaseMailSettingsHaveNoDialerOverrideOrFallback` asserts
  it).
- R5. **Deleting a directory** needs nothing: a directory with users cannot be deleted (`ALC-LDAP-0003`, the users'
  foreign key), so it has no sessions to end.
- R6. **Not changed:** switching an OIDC identity provider off still ends nothing by itself (outside this change's
  scope; noted as an open item for the owner).

## 2. Lockout audit and Administrator unlock

- R7. **Where the lockout lives.** It stays in memory per process (`ratelimit.BoundedLockout`, two tables: per
  directory and folded sign-in name, and per directory and unique id). It is not moved to the database: the design
  keeps it in memory on purpose (a refusal must cost no database write for unknown names; spec and KI-38), Alice runs
  as one process, and the unlock acts on the process that answers. Documented in the admin guide and the API
  description — cost if wrong: with several processes behind a load balancer an unlock would reach only one of them.
- R8. **Audit when a lock starts.** `Reservation.Fail` already reported whether it locked; `directoryAttempt.settle`
  now collects which keys locked (`name`, `account`) and writes one `auth.ldap.lockout` (result failure) through
  `auth.RecordLDAPLockout` with `directory_id`, `scope` and `minutes` (45). The gate now remembers the unique id of the
  entry the directory found, also when it refuses a locked account, so the row names the person (actor and object, as
  `RefuseLDAP`) when they have an Alice user, and the sign-in name under the rule of `auth.ldap.denied`
  (`deniedLoginName`: only for an entry the directory found). A name nothing matched is never stored — why: same
  privacy rule as refusals; people type passwords into the name field — cost if wrong: a lock of an unknown name is
  a row without a name, which is the point. Sign-in, step-up and Test sign-in all record it (they share the keys); a
  lock caused by an Administrator's Test sign-in names the person tested, with the Administrator's address and request
  ID (the `ldap.signin_tested` rows beside it name the Administrator). A failure to write is logged, not shown (as
  refusals).
- R9. **No e-mail on a directory lock** (the local lockout mails the Administrators) — why: not asked for, and an
  attacker can start such locks for any name at a rate the per-address limit allows; the audit row and the user list
  are enough — cost if wrong: an Administrator learns of a lock from the person or the log, not from mail.
- R10. **Unlock endpoint.** `POST /api/v1/users/{id}/actions/unlock-directory-sign-in`, permission `users.manage`
  (Administrator, browser session with step-up, no API token), license class `ClassAlways` (works in lock, like the
  other user actions), no body, 204. Placed under the user routes, not the directory routes, because it acts on a
  person and the button lives on **People & access** — why: same conventions as revoke-sessions / reset-mfa — cost if
  wrong: none.
- R11. **What the unlock clears.** The account key (directory, unique id) and the name key of the user's stored
  `ldap_login` (the name the directory last returned), both their lock and their failures (`BoundedLockout.Clear`).
  Other spellings and aliases (a UPN beside the `sAMAccountName`) keep their own name keys until they expire — why:
  Alice never stores the names an attacker typed, so it cannot find them; the account key, which every alias shares,
  is cleared, so the person's usual name works at once — cost if wrong: a person who signs in with another alias than
  the one the directory returns waits for that name's lock to end.
- R12. **Order and audit.** `auth.UnlockDirectorySignIn` locks the user's row, refuses a user who is not a directory
  user (`auth.ErrNotDirectoryUser` → new `409 ALC-LDAP-0009`, reason `ldap.user_not_directory`; `ALC-LDAP-0008` is
  worded for the person's own confirmation), asks the HTTP layer which keys are locked (details `name_locked`,
  `account_locked`, plus `directory_id`), and writes `user.directory_unlocked` by the Administrator; the keys are
  cleared only after that transaction commits — why: an unlock is never unaudited — cost if wrong: a lock that ends
  between the peek and the clear is recorded as locked; harmless. The call is idempotent: 204 and a row also when
  nothing was locked (another process may hold the lock).
- R13. **Seeing a lock.** The user list and `GET/PATCH /api/v1/users/{id}` answers carry the optional
  `directory_sign_in_locked_until` (the later end of the two keys) for a locked directory user; it is omitted
  otherwise and never part of `/auth/session` (`adminUserJSON`). `auth.User` carries the user's unique id and stored
  sign-in name for this; they are never sent to clients. The web page shows a warning badge with the end time in the
  Status column, and **Manage** offers **Unlock directory sign-in** only while a lock is shown, behind a confirmation
  that says aliases stay locked.
- R14. **Policy unchanged.** 3 failures within 30 minutes, 45 minutes, both keys, as before.
