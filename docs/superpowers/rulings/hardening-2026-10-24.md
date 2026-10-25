# Hardening batch 1 (R64): rulings, owner items and gate evidence

Plan: `docs/superpowers/plans/2026-10-24-hardening-batch-1.md`. Decision: R64 in
`docs/superpowers/specs/alice-v1/00-decisions.md`. Tests: `HB-01`..`HB-17` (`docs/superpowers/specs/alice-v1/06-quality.md`
§24.8, `docs/security/traceability.md`). Branch `hardening-1`, cut from `main` at `961f3bbb`.

The six items, owner approval 2026-10-24 ("yap 6'yı"):

- D2: the incident list page (Tasks 4, 5, 10).
- D3: incident e-mails, sent once each (Task 6).
- D5: OCSP and CRL checks of certificates Alice did not revoke herself (Tasks 7, 8, 9).
- KI-39: the helper's PEM label gap (Task 3).
- The unreachable website-side branches of `bindingChange` (Task 2).
- The `ErrTargetDisabled` code mismatch (Task 1).

## Coordinator rulings at plan approval (R64)

- **C1.** The guarded fetch of Task 7 dials through netaddr's connect-time check, so a DNS answer that changes between
  a check and the dial cannot bypass it, plus the explicit loopback and unspecified refusal. `netaddr.DialContext`
  replaces the dialer's `Control`, so the loopback refusal could not sit beside it: `netaddr.DialContextExcept` (the
  same guarded dial with `netaddr.Control` and a further refusal, the same `ErrNotAllowed`) was added and the checker
  dials through it (execution Ruling 31). `internal/revocation:TestFetchRefusesForbiddenAddresses` covers 127.0.0.1,
  ::1, 0.0.0.0, ::, 169.254.169.254, fe80::1 (and with a zone), host names that resolve to 127.0.0.1, ::1 and the
  metadata address (through the test resolver, so the refusal happens at connect time), `localhost`, ports 8080, 80
  for https and 443 for http, user info, an empty host and the schemes ftp and ldap, for OCSP and CRL addresses.
- **C2.** Ruling 19 stands: the check is on for a new installation and off after an update. No release exists yet, so
  every customer installation is "new" and the check is effectively on everywhere; the owner may change this.
- **C3.** Migrations `00033` and `00034` are this branch's; the parallel canary phase takes `00035` and later. Error
  codes `ALC-CRT-0020`..`0025` are this branch's.
- **C4.** `make ci` ran only after checking that no other `make ci`, Playwright or testcontainers run was active
  (`pgrep -af 'playwright|make ci|go test'`).
- **C5.** Defects found outside the six items are listed under "Found, not fixed" and were not fixed.

## Rulings

The plan's rulings 1 to 22, as approved:

1. **Decision R64: one decision for the six items.** Two migrations (`00033`, `00034`), six codes
   (`ALC-CRT-0020`..`0025`), test IDs `HB-01`..`HB-17`, KI-43 new and KI-39 amended. Cost if wrong: none functional.
2. **The `ErrTargetDisabled` mismatch is the incident engine's `codeOf`, not the two catalogues.** The case was added and
   the two functions exported (`IsIncidentRefusal`, `IncidentRefusalCode`), so an API test locks both lists to the
   catalogue; the key-type mismatch (`incident.not_deployable`) is the one documented exception. Cost if wrong: if the
   memory note meant another mismatch, it is still open; the new tests would have found any reason difference.
3. **The incident list keeps its route, scope and permission** (`scopeList`, `rbac.Read`, `IncidentVisible`) and only
   gains `state` and `cursor`; `open` stays. Cost if wrong: an Auditor or read token sees the incidents of its services,
   as on the certificate page today.
4. **The list page is a navigation entry under Operations, "Incidents"/"Olaylar", visible with `read`.** Cost if wrong:
   a label or position change.
5. **The incident e-mails are three texts** (`incident.needs_attention`, `incident.completed`,
   `incident.completed_not_revocable`); none on start, close or `awaiting_replacement`; the attention code is sent as
   `error_reason`. Cost if wrong: service owners learn of a new incident only from its first needs-attention or
   completed mail.
6. **Recipients are the incident's services** (`service_ids` plus the certificate's) through `NotifyServices`. Cost if
   wrong: a service that gained a place after the start gets no mail.
7. **KI-39: accept the OpenSSL labels and re-encode; no location problem.** The chain accepts `CERTIFICATE` and
   `X509 CERTIFICATE` and skips a later `TRUSTED CERTIFICATE` (a dropped-block warning); the rollback guard reads the
   same leaf. Cost if wrong: a server that reads the chain differently shows another chain; the leaf, expiry and guard
   stay right.
8. **Helper 1.11.0, protocol 11 unchanged.** Cost if wrong: a later change that needs the label reported needs a
   protocol bump then.
9. **`bindingChange`: widen the route, keep the branches.** The PATCH resolver is `anyVisible`; the handler refuses
   additions and the release of websites the caller holds no right on unless the caller is the vault's side. Cost if
   wrong: a website-side Operator can release its own servers from a vault binding (a safety action §5.6 allows).
10. **`DELETE /bindings/{id}` stays vault-side.** Cost if wrong: a website-side person releases its websites with PATCH.
11. **Incident mails are queued in the state change's transaction.** A retry that fails again mails again. Cost if
    wrong: a person who retries in a loop gets one mail per failed retry.
12. **The W3 duplicate store notice is settled with `incident_notices`.** Behaviour change: a notice that found no
    recipient is recorded and not retried. Cost if wrong: in that rare installation the notice is lost; the incident
    page still lists the place.
13. **Incident mails go out while the licence is locked.** Cost if wrong: a locked installation still sends incident
    mails, as it sends expiry mails.
14. **D5 checks every unexpired, unrevoked, non-self-signed certificate of any source, plus discovery leaves without an
    inventory row.** Cost if wrong: more requests than a narrower set; bounded by Ruling 17.
15. **What a revocation does: a finding, not an incident.** A signed revoked answer marks the certificate revoked for
    good (`revocation_seen` = `ocsp`/`crl`), audited and mailed once; `certificateHold` is recorded and mailed, never
    marked; Alice never starts an incident by herself. Cost if wrong: a responder that signs a wrong "revoked" stops
    Alice deploying a certificate for good (mitigated by the issuer's signature check).
16. **The check algorithm:** OCSP first, CRL as fallback; only signed, current answers count; a listed serial in a stale
    CRL counts; `unknown` is recorded, never acted on; no nonce; no AIA caIssuers fetch. Cost if wrong: certificates
    whose server sends no intermediate are never checked (deferred E2).
17. **Outbound rule:** http and https on 80 and 443, netaddr plus loopback and unspecified, no proxy, no redirect, 10 s,
    64 KiB and 10 MiB caps, 50 requests per host per run, a run every 15 minutes of at most 200 certificates and 4
    minutes; a good certificate again after 24 h, unknown 24 h, on hold 6 h, not checkable 7 days; failures back off 1 h
    to 24 h; private addresses allowed. Cost if wrong: a company authority on another port is refused; an installation
    that needs a proxy cannot check; a very large single-CA estate is checked less often than daily.
18. **`unknown` is not acted on and sends no mail.** Cost if wrong: a certificate a rogue CA "forgot" is not flagged.
19. **The switch: on for a new installation, off after an update** (see C2). Cost if wrong: updated installations stay
    unchecked until someone switches the check on.
20. **The check job is `ClassReadOnly`** (paused in lock). Cost if wrong: during a lock Alice learns of no revocation.
21. **Codes `ALC-CRT-0020`..`0025` continue the certificate family** (stored reasons, shown through `errorRef`). Cost if
    wrong: renumbered at merge if another branch takes these numbers.
22. **e2e covers D2 only.** D3 and D5 are covered on PostgreSQL with the real checker against the fake servers. Cost if
    wrong: the D5 web text is covered by Vitest only (deferred E4).

Rulings made during execution:

23. **A disabled server never reaches the incident engine as `ErrTargetDisabled`** (Task 1). `RequestDeployment` refuses a
    disabled server as `ErrTargetNotReady` (`disabled` is not in `targetReady`, F-31) before any key-change rule, so the
    planned integration test "the place fails with `target.disabled`" cannot pass. The `codeOf` case was kept (locked by
    the API test, and the existing unit test that pinned `internal.unexpected` now pins `target.disabled`), and the
    integration test became `TestIncidentPlaceOnADisabledServerWaitsAndFailsBusy`: the place waits and fails
    `incident.location_busy` after its last attempt, never `internal.unexpected`. Cost if wrong: none for this item; see
    F1.
24. **The website-side test person also reads the vault's service** (Task 2). The visibility of website C comes from the
    read reach, so an Operator on svcPay only does not see it; the person holds Auditor on svcDefault too. Case (d) uses
    the svcPay-only person (with the Auditor grant it would be 403, not 404). `make authz-doc` made no change (the matrix
    shows the scope kind, `cross`, not the resolver). Cost if wrong: none functional.
25. **Six `"1.10.0"` assertions** (the plan said five) were updated in `helperproto_test.go`; the emulator fidelity test
    gained two scenarios (an `X509 CERTIFICATE` leaf; a `TRUSTED CERTIFICATE` leaf and a later one skipped). Cost if
    wrong: none.
26. **Turkish filter label:** `incidents.list.filter.needs_attention` is "İlgi gerekiyor", the term of
    `incidents.states.needs_attention` (the plan's table said "İlgi bekliyor" but also said to reuse the state terms). The
    back link to the list uses `nav.incidents` as its label. The state badge maps moved to `web/src/pages/incidentStates.ts`.
    Cost if wrong: wording only.
27. **A third path completes an incident** (Task 6): a successful revocation of a revoking incident moves it to completed
    directly. It queues `incident.completed` too, only when its conditional move changed the row. Cost if wrong: none.
28. **`revokeFailed` is conditional on the state read** (Task 6), as every other move, so a second engine changes
    nothing and mails nothing. Cost if wrong: an incident whose state changed between read and failure is not moved by
    this run (the next run reads it again).
29. **The revocation-refusal mail test uses the fake CA's "revokeCert off"** (`acme.revoke_unsupported`), the permanent
    refusal the fake offers; the transient case uses three `serverInternal` faults. Cost if wrong: none (the same
    permanent and transient paths).
30. **The `00033` back-fill compares incident ids as text**, so a malformed outbox row cannot fail the migration with a
    cast error. Cost if wrong: none.
31. **`netaddr.DialContextExcept`** (Task 7, C1): see C1. Cost if wrong: one exported helper in the platform package.
32. **An address that fails the URL rule is `not_checkable`/`address_refused`** (static, again after 7 days); a refusal at
    connect time (a DNS answer) is `unavailable`/`address_refused` (backoff); an empty address is no address. Literal IP
    addresses are not pre-checked: they go through the connect-time guard like names. Cost if wrong: a status choice
    only; never a revocation.
33. **The fake gained `FaultOtherIssuer`** (a CRL signed by the issuer's key under another name, to test the issuer-name
    check) and `Release` (to lift a hold). When OCSP gives no answer (unavailable, unknown or deferred) the CRL is read
    and the more definite result wins (revoked or on hold, then good, unknown, deferred, unavailable; a tie keeps
    OCSP's). Cost if wrong: none.
34. **`00034` widens the reason check**, so the `00021` test that asserted `cACompromise` is refused at the latest schema
    now asserts `certificateHold` is refused; the roles guard learns `revocation_seen` below `00034`; the Down raises a
    plain exception. Cost if wrong: none.
35. **The ACME renewal test swaps the ACME version's stored chain** for a leaf the fake authority issued (the fake ACME CA
    names no revocation address); the integration tests evaluate the licence before each run, as `license.evaluate` does
    in production; the templates and the checker adapter live in `revocation_checks.go`; saves of the switch are
    serialized with an advisory lock (the row may be absent). Cost if wrong: none.
36. **Mail cadence of the check:** `unknown` resets the failures; a hold is mailed when the previous status was not a
    hold or was never mailed; good after a hold clears the mark so the next hold is news; a revoked discovered leaf is
    mailed once and never audited. Cost if wrong: mail cadence only.
37. **The switch's API service is its own dependency** (`api.RevocationService`); nil answers 503 after the `If-Match`
    and body checks; an unknown body member is 400 (`decodeExact`). `revoked_by_authority` is in the certificate list and
    detail answers, `revocation_check` in the detail only. The output enum `RevocationReasonOrEmpty` gains
    `cACompromise`, `privilegeWithdrawn` and `aACompromise`, with web labels; the revoke dialog's list is unchanged. The
    error texts use the catalogue's title, cause and action (the plan said title and text). Cost if wrong: none.
38. **The e2e journey uploads its certificate through the API** (as `service-policy.spec.ts` does) and drives the
    incident in the UI; an uploaded certificate without places waits for its replacement. Cost if wrong: none.
39. **`tools/matrixcheck` reads `HB` rows** (it knew only `SR`, `WIN` and one-letter prefixes);
    `docs/security/traceability.md` was regenerated. Cost if wrong: none.
40. **No notifier, no mail, no panic** (final review): the incident and revocation mails returned early when
    `Config.Notifier` is nil, as every other e-mail path of the inventory does
    (`internal/inventory:TestIncidentAndRevocationWorkWithoutANotifier`). Cost if wrong: none.

41. **The 640 px navigation test scrolls the open navigation** (`web/e2e/phase1.spec.ts`). With the Incidents entry the
    Administration group of an Administrator's navigation is below the fold of an 800 px high window, so the test failed
    in the gate (`make ci` run 3, EN and TR). The test now scrolls the link into view in the open navigation before it
    expects it in the viewport, and also checks that a closed navigation stays off screen when scrolled, so it still
    proves that the menu button opens the navigation and that a closed one never covers the page. Cost if wrong: if the
    owner wants every entry visible at 800 px without scrolling, the navigation needs a more compact layout.

42. **A discovered leaf is checked only when someone vouches for its issuer** (coordinator ruling after the
    independent review, I1). A leaf network discovery found is checked only when the chain its endpoint presented
    verifies to the trusted roots (`Config.Roots`: the system pool unless set; `x509.VerifyOptions` with the endpoint's
    chain as intermediates) or the issuer that signed it is an inventory certificate whose source is not `discovered`
    (the held certificate at the head of the chain vouches only when it is that issuer). Otherwise it is
    `not_checkable` with `certificate.revocation_untrusted_issuer` (`ALC-CRT-0026`) and no request is made. At most 20
    e-mails about discovered leaves (revoked or on hold) per run; the rest are recorded with their status, counted in
    `RevocationRunReport.MailsSuppressed` and not mailed; each suppressed e-mail is logged (warning) with the
    certificate's fingerprint. A suppressed revocation e-mail is lost for good, because a revoked row is never checked
    again; a suppressed hold e-mail goes out at a later check while the hold lasts. The name in every revocation e-mail is reduced to printable
    characters (others become "?") besides the 200-rune cap. Cost if wrong: a discovered certificate of a private
    authority Alice does not hold is never checked; a large mass revocation in discovery mails 20 certificates per run.

## Owner to confirm

1. Ruling 19 (and C2): the check **on** for new installations and **off** after an update, or on for both.
2. Ruling 20: `revocation.check` paused in lock (`ClassReadOnly`), or running in every state.
3. Ruling 17: ports 80 and 443 only, no proxy support, private addresses allowed. Does any customer authority need
   another port or a proxy? Sharpened by ruling 42: a certificate found by discovery is checked only when its chain
   reaches a trusted root or its issuer is held in Alice, and at most 20 discovery revocation e-mails go out per run.
4. Ruling 15: Alice marks a certificate revoked for good on the authority's signed word, and never starts an incident by
   herself (including for `keyCompromise`).
5. Ruling 5: no "incident started" mail to service owners.
6. Ruling 10: whether the website side may delete a whole Key Vault binding (`DELETE /bindings/{id}`).
7. Ruling 12: the store notice is not retried when it had no recipient.
8. Ruling 9: the website side may now release its websites from a Key Vault binding (a widening of what a scoped
   Operator can do).
9. KI-43 wording and severity (Low).
10. Ruling 23 and F1: a disabled server's incident place waits and fails "busy"; whether it should fail at once with
    `target.disabled`. Fixed in R66 (`docs/superpowers/rulings/fixes-2026-10-25.md`).
11. Ruling 41: at 640 x 800 px an Administrator's navigation now scrolls to reach its last group.

## Deferred

- E1: the discovery page does not show a discovery certificate's revocation status (only the mail does). Done in R66.
- E2: fetching a missing issuer from the AIA caIssuers address.
- E3: OCSP nonce, delta CRLs, partitioned-CRL scope checks (`IssuingDistributionPoint` reasons).
- E4: a revocation e2e journey with a compose fake responder.
- E5: proxy support for outbound checks.
- certificate-revocation D1 (revocation with the certificate's key) and D4 (replacing places of other certificates with
  the same key) stay open.

## Found, not fixed (C5)

- **F1.** A key compromise incident's place on a disabled server is retried as "busy" for 30 runs (about 15 minutes)
  and then fails `incident.location_busy`, because `RequestDeployment` refuses a disabled server as not ready. The
  page's reason does not say the server is disabled. Fix candidate: refuse a disabled server with `ErrTargetDisabled` in
  `checkDeployLocation` (a change to every deploy path's answer, `ALC-TGT-0006` instead of the not-ready code). Fixed in R66 (`docs/superpowers/rulings/fixes-2026-10-25.md`).
- **F2.** `make test` was not run per task until Task 9 (the plan's per-task gate named it); CI run `40123556039`
  caught two misses (`web/src/App.test.tsx` navigation lists and the e2e `resetSQL` tables), fixed in `e2936fb6`.
  Process note, not a product defect.

## Final review

A self-review of `961f3bbb..hardening-1` against `superpowers:requesting-code-review`'s reviewer checklist (the
coordinator receives a child agent's notification, not this executor, so no separate reviewer ran; the coordinator may
want a fresh review before merging). One finding was fixed:

- Important, fixed: the incident and revocation e-mails dereferenced a nil notifier (`Config.Notifier` nil means "no
  e-mails" everywhere else in the inventory) inside the move's transaction. Ruling 40;
  `internal/inventory:TestIncidentAndRevocationWorkWithoutANotifier` failed with a nil-pointer panic before the fix and
  passes after it (`25d6c9b5`).

Minor findings, declined:

- One run may cache up to 16 CRLs of up to 10 MiB each (the plan's limits); a byte budget for the cache would bound the
  memory of a run more tightly against certificates that name many huge CRLs.
- The certificate page lists **Revocation check** as its first fact; after the chain would read more naturally. Done in
  R66.

## Gate evidence

`make ci E2E_PROJECT=alice-e2e-hb1 ALICE_E2E_PORT=9978`, run on 2026-10-24 after `pgrep -af 'playwright|make ci|go test'`
answered nothing (C4):

- Run 1 (at `376fd543`): `coverage` failed. Integration tests that do not run in `make test` did not know the new
  migrations and the new route: `cmd/alice:TestServeStartsOnAPhase3Database` (expected schema 32),
  `internal/backup/dump:TestDumpLoadRoundTripsEveryTable` (no row in `incident_notices`, `revocation_checks`),
  `internal/backup:TestACMEBackupCycle` (TRUNCATE of `certificate_incidents` refused by the `incident_notices` foreign
  key), `internal/api:TestA06GETRoutesNeverChangeState` (the stack did not wire the revocation switch: 503). Fixed in
  `ca5880e0`; each rerun green.
- Run 2 (at `ca5880e0`): every test passed; `covercheck` failed `alice/internal/jobs/sshkeyjobs` 85.8 % (floor 86 %):
  `DeployRefusalReasons` was tested only from `internal/api`. A test in its own package (`c154dc02`) gives 86.8 %.
- Run 3 (at `c154dc02`): `lint test coverage perf test-backup-cycle test-ssh build release-symcheck i18n-check web-lint
  web-coverage vuln secrets-scan fs-scan` passed; `e2e-up` and `e2e-hardening-check` passed; `e2e` 158 passed,
  4 skipped, 2 failed: `phase1.spec.ts` "at 640 px the navigation opens from the menu button and never covers the page"
  (EN, TR), caused by this branch (Ruling 41). After the fix, on a fresh `e2e-up`: `e2e-hardening-check` passed,
  `phase1.spec.ts` and `hardening1.spec.ts` 20 passed (the 2 failed tests among them), then `make e2e-down`,
  `make image-check image-scan` passed. The full suite therefore stands at 160 passed and 4 skipped on Chromium, with
  `hardening1.spec.ts` 2 passed (EN, TR).
- Coverage floors (run 3, all met, none lowered): `internal/revocation` 97.0 % (new floor 95), `internal/inventory`
  89.0 % (89), `internal/api` 97.1 % (95), `internal/notify` 88.8 % (88), `cmd/alice-helper` 91.5 % (90),
  `internal/jobs` 90.9 % (89), `internal/jobs/sshkeyjobs` 86.8 % (86), `internal/platform/netaddr` 98.7 % (97),
  `internal/providers/linuxssh/helperproto` 100 % (100), `cmd/alice` 91.7 % (91).
- `make test-ssh` (in run 3) passed with helper 1.11.0: `TestRealOpenSSH`, `TestRealNginx`, `TestRealApache`,
  `TestRealHAProxy`.
- `make matrix-check MATRIXCHECK_FLAGS=-strict`: 305 IDs, 295 by tests, 0 pending, 0 gaps.

## Final review fixes (R64)

An independent review of `main..hardening-1` at `5fa9c6d1` found two Critical and two Important defects (verified by the
coordinator) and five Minor ones; all but M3 were fixed on this branch:

- **C1, Critical: a delegated OCSP responder was accepted without id-kp-OCSPSigning or validity.**
  `golang.org/x/crypto/ocsp.ParseResponseForCert` checks only that the issuer signed the responder certificate, so any
  leaf of the CA could sign "revoked, keyCompromise" for every certificate of it, which Alice marks final. Fix
  (`172bd12e`): a responder certificate other than the issuer needs `x509.ExtKeyUsageOCSPSigning` and must be valid now,
  otherwise `certificate.revocation_invalid_answer`. Tests: `internal/revocation:TestCheckOCSPAnswers` rows "a delegated
  responder" (accepted), "a delegated responder without OCSP signing" and "an expired delegated responder" (both
  refused; they failed before the fix), with the fake's `FaultDelegated`, `FaultDelegatedNoEKU` and
  `FaultDelegatedExpired`.
- **C2, Critical: the CRL cache was keyed by address only.** A cache hit skipped the signature and issuer checks, so a
  CRL verified for one issuer (an attacker's) was searched for a leaf of another (the victim's). Fix (`172bd12e`): the
  key is the SHA-256 of the issuer's public key and name plus the address; another issuer's hit is a miss and is fetched
  and verified again. Test: `internal/revocation:TestCRLCacheIsPerIssuer` (failed before the fix).
- **I1, Important: discovered leaves were checked with whatever issuer the endpoint presented.** Anyone running TLS in
  a scanned range could make Alice send OCSP and CRL requests to internal addresses and send unbounded e-mails with a
  name of their choosing. Fix (`86825ad2`, ruling 42): the trust rule, `ALC-CRT-0026` with its EN and TR texts and
  troubleshooting section, the 20-mail cap and printable names. Tests:
  `internal/inventory:TestRevocationRunSkipsDiscoveredLeavesOfUntrustedIssuers`,
  `internal/inventory:TestRevocationRunCapsDiscoveredMails`, `internal/api:TestRevocationCheckCodeTable` (the new row);
  `TestRevocationRunChecksDiscoveredLeaves` now trusts the fake authority's root.
- **I2, Important: two overlapping runs could both send the first mail.** `SELECT ... FOR UPDATE` locks nothing while no
  check row exists. Fix (`86825ad2`): each recording takes `pg_advisory_xact_lock(hashtext('revocation:' ||
  fingerprint))` first. Test: `internal/inventory:TestRevocationRunRecordsOnceUnderConcurrency` (8 concurrent runs, one
  mail; without the lock it queued 8 in each of 3 runs).
- **M1:** reason 8 (removeFromCRL) is no revocation, in a CRL entry or an OCSP answer (`TestCheckOCSPAnswers` row
  "removeFromCRL", `TestCheckCRL` row "listed with removeFromCRL"); a CRL with the delta CRL indicator (2.5.29.27) is
  refused (`TestCheckCRL` row "a delta CRL", fake `FaultDeltaCRL`). `172bd12e`.
- **M2:** a CRL over 1 MiB is read and used but not cached (`internal/revocation:TestLargeCRLsAreNotCached`).
  `172bd12e`.
- **M4:** an OCSP answer without a next update counts for at most 7 days after it was issued
  (`internal/revocation:TestFreshnessAndReasons`). `172bd12e`.
- **M5:** the `incident_notices` key holds the thumbprint in lower case, on insert and in the `00033` back-fill
  (`lower(params->>'thumbprint')`; `00033` is unreleased and only on this branch). Tests:
  `internal/inventory:TestCompromisedInStoreNoticeKeyIsLowerCase`, `migrations:TestMigration00033BackfillsTheStoreNotices`
  (an upper-case copy of the same notice back-fills one row). `1cd900d5`.
- **M3, not fixed (stays F1, owner item 10):** the disabled-server incident place. Fixed in R66 (`docs/superpowers/rulings/fixes-2026-10-25.md`).

Evidence: `make lint` and `make test` pass; the integration suites of `internal/inventory`, `migrations`,
`internal/backup/...` and `cmd/alice` pass; coverage `internal/inventory` 89.0 % (floor 89), `internal/api` 97.1 % (95),
`internal/revocation` 98.0 % (95); no floor lowered.

Re-review of `5fa9c6d1..8c938ce1` confirmed C1, C2, I2, M1, M2, M4 and M5 fixed and found one remaining bypass of I1:

- **I1 bypass, Important: a held certificate that signed nothing vouched for the attacker's issuer.** The candidate
  query marked a discovered leaf "held" when the head of its presented chain was a non-discovery inventory certificate,
  but the issuer used was any chain certificate that signed the leaf; a chain [the organisation's uploaded certificate,
  the attacker's CA] skipped the trust check and Alice fetched from the attacker's addresses. Fix: the held certificate
  vouches only when its SHA-256 equals the issuer `revocationPair` picked; otherwise the root verification decides and,
  failing it, `certificate.revocation_untrusted_issuer`. Test: `internal/inventory:TestRevocationRunHeldIssuerMustSignTheLeaf`
  (failed before the fix with the leaf marked revoked; passes with no request to the fake).
- **Minor:** a suppressed discovery e-mail is logged with its fingerprint (ruling 42; asserted in
  `TestRevocationRunCapsDiscoveredMails`), and `TestCRLCacheIsPerIssuer` lists the victim's serial before the first fetch,
  so it shows the false revocation the old cache allowed.
