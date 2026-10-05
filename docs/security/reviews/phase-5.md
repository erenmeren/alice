# Security Review — Phase 5 (Azure Key Vault)

Scope (spec §17.2, Phase 5; §26.7): outbound requests to Azure and SSRF (A-14), sign-in credentials and tokens,
vault secrets in deployments, automatic deployment decisions, imports, and the fidelity of the fake Azure service.
Exit criterion of §26.7: renewal to deployment works end to end on the fake "and, if credentials are provided, on
real Azure"; every Key Vault failure mode is handled without a crash loop; nothing in logs or responses contains
vault secrets.

**No Azure subscription was available to anyone who built or reviewed this phase.** Everything below is proven
against the in-repository fake (`internal/testutil/fakekv`, `cmd/alice-fakeazure`), against the real Azure SDK
clients talking to that fake, or by reading documentation and SDK code. Nothing in this document is a statement
about real Azure. The section "Not verified against Azure" lists every behaviour the product depends on that only
a real vault can confirm.

The decisions behind this phase are R40 in `docs/superpowers/specs/alice-v1/00-decisions.md`; R40 item numbers are
given in brackets below. The controller's rulings, with how to reverse each, are in
`docs/superpowers/rulings/phase-5.md`.

## Method

The phase was built in 24 tasks. Each task (or group of tasks sharing a package) was reviewed by another agent
that did not write it; the reviews of the outbound guard and the provider (Tasks 6 to 8), of the deployment engine
(Task 16), of the planner and imports (Tasks 13 and 14) and of the API (Task 17) were run as security reviews.
Reviewers did not only read: they ran probes against the code (hostile answers, cancelled contexts, races, role
and step-up matrices, canary sweeps over logs, API answers and every table) and mutated the code to see whether a
test turned red. Every finding went back to the implementer as a fix round and was reviewed again, until approved;
small follow-ups after an approval were checked by the controller reading the diff and running the package's
tests. Two exceptions are recorded in the rulings document: Task 18 (test-only) got no separate re-review, and
several fix rounds have mutation evidence instead of a red run seen before the change.

After the tasks, a final fix wave made six product changes found late (an unreadable vault credential, a secret
without a key, a vault's last-error params, job IDs, the limiter and a backward clock, the zeroing-observer rule) and
was reviewed; the Playwright task (Task 23) was reviewed and fixed. A final whole-branch review then read the branch
in three areas (provider, identity and fakes; inventory, jobs, API and migrations; web, locales, e2e and these
documents), beside a scoped re-review of the last fix rounds. Their findings went to one final fix round.

A pre-flight scan compiled the plan's code for Tasks 1 to 8 in a scratch worktree before Task 1 and read the rest
against the code: 41 defects of the plan and 15 design findings (S1 to S15), ruled on before the first task.

## Evidence

All commands run from the repository root; `-tags integration` needs Docker (testcontainers). The column "Recorded
before the final run" holds the latest results recorded by the agents who built and fixed the phase, taken from their
reports (the final fix round's runs at c3f2b4e where it ran the check, otherwise as marked), not runs made for this
review, which was written without Docker. The column "Final run" holds the results of the final `make ci` (which runs
`make coverage`) at the commit each cell names.

| # | Check | Command | Expected | Recorded before the final run | Final run |
|---|---|---|---|---|---|
| 1 | Vault address, ID, name, version and thumbprint grammars; fuzz of the address parser | `go test ./internal/platform/azureid -count=1` | ok | ok, coverage 100.00 % (floor 100) | ok, coverage 100.0 % (`make ci` at 3499e68, 2026-10-05) |
| 2 | Guarded transports, sign-in wrapper, error mapping (no Azure text in any rendering), retry and budgets, the per-vault limiter (also with a clock that steps backwards), listing bounds and cycles, managed identity only to the metadata address, refused environment variables, SDK surface rules, import outcomes, secret read | `go test -race -count=3 ./internal/providers/azurekv/` | ok | ok, coverage 98.49 % (floor 98) | ok, coverage 98.5 % (floor 98) (`make ci` at 3499e68, 2026-10-05) |
| 3 | Provider contract: import result rules, conformance of every session implementation, the scripted provider fake | `go test ./internal/providers/... -count=1` | ok | ok, `internal/providers` 100 % (floor 100) | ok, `internal/providers` 100.0 % (`make ci` at 3499e68, 2026-10-05) |
| 4 | Key Vault secret decoding (also a PFX with certificates and no key, in the Java trust-store and the openssl/.NET shapes, and one whose key sits in a nested bag), sign-in certificates, PFX export, buffers cleared; fuzz | `go test ./internal/certs -count=1`, `make fuzz-certs` | ok, no crasher | ok, coverage 98.13 % (floor 98); `FuzzParseKVSecret` 30 s, no crash (Tasks 1–3) | ok, coverage 98.1 % (floor 98); `make fuzz-certs` is not part of `make ci` and was not run in the final run (`make ci` at 3499e68, 2026-10-05) |
| 5 | The fake Azure service against the reference shapes and the real SDK clients (three sign-in methods, paging, import, challenge verification left on) | `go test -race -count=8 ./internal/testutil/fakekv` | ok | ok (`make test`) | ok (`make ci` at 3499e68, 2026-10-05: `make test` and `make coverage`) |
| 6 | Migrations `00008` and `00009`: grants listed exactly, triggers `Z1005`–`Z1008`, no column that can hold a secret, names under a Turkish collation, down refusal, `chain_incomplete` up, down and up again | `go test -tags integration ./migrations -count=1` | ok | ok (integration, final fix round) | ok (`make ci` at 3499e68, 2026-10-05: `make coverage`) |
| 7 | Inventory: vaults and sealed credentials, polling and failure transitions, hold rules, connections, planner, imports, pre-check and material step, the not-exportable mark and its clearing, `chain_incomplete`, zeroing, leak dumps | `go test -tags integration -count=1 -cover ./internal/inventory/...` | ok | ok, coverage 89.12 % (floor 89) | ok, coverage 89.1 % (floor 89) (`make ci` at 3499e68, 2026-10-05) |
| 8 | Jobs: access check, poll, import, periodic tasks, poll cap in the claim, deadlines, L-87 (`TestL87PollInFlightAtLock`), `deployment_id` and `import_id` on job items; the vault step of the deployment engine (also an unreadable sealed credential), L-80 to L-82 with a vault deployment (`TestL80L82WithAKeyVaultDeployment`, `TestL81KVDeploymentHeldThenConfirmed`) | `go test -tags integration -count=1 -cover ./internal/jobs/...` | ok | ok: `kvjobs` 100.00 % (floor 100), `deployjobs` 99.30 % (floor 99), `jobs` 89.21 % (floor 89) | ok, `internal/jobs` 89.2 % (floor 89), `kvjobs` 100.0 %, `deployjobs` 99.3 % (`make ci` at 3499e68, 2026-10-05) |
| 9 | API over the wire with the real provider and the fake service: journeys, F-40 to F-52, A-14, S-01 to S-05 with Azure canaries, license lock, held versions, imports sent once, clock skew, `ALC-AKV-0041`, a secret without a key, a vault's `last_error` params | `go test -tags integration -count=1 -cover ./internal/api/...` | ok | ok, coverage 94.96 % (floor 94) | ok, coverage 95.0 % (floor 94) (`make ci` at 3499e68, 2026-10-05) |
| 10 | Authorization matrix incl. `credentials.manage` and the conditional rules; error catalogue `ALC-AKV-0001`..`0041` with EN and TR texts that render with partial params, and a troubleshooting section for each | `go test ./internal/api ./internal/rbac -count=1` and `make authz-doc && git diff --exit-code docs/authz-matrix.md` | ok, no diff | ok (`make test`); the authz matrix had no diff at 6e26e42 | ok (`make ci` at 3499e68, 2026-10-05: `make test`; `make authz-doc` is not part of `make ci` and was not re-run) |
| 11 | Release binary holds no e2e trust path, no fake and no dial seam; the fake's image reuses the pinned base images; only test files set the request-secret zeroing observer | `make release-symcheck`, `make image-check`, `go test ./internal/archtest/... ./cmd/...` | ok | ok at 6e26e42 (Task 19 and the fix wave); not re-run by the final fix round | ok: `release-symcheck: ok`, `image-check: ok (alice:ci)`, archtest and `cmd` tests ok (`make ci` at 3499e68, 2026-10-05) |
| 12 | Web: Vitest; Playwright journeys EN/TR with axe on the e2e stack with the `fakeazure` service | `make web-coverage`; `make e2e-up && make e2e-hardening-check && make e2e`, then `make e2e-down` | all passed | Vitest: 68 files, 903 tests. Playwright: Phase 5 spec 22 passed (11 journeys in EN and TR); full run 84 passed, 0 failed, 0 retried (26.2 min) | Vitest: 68 files, 903 tests passed. Playwright: 84 passed in 20.0 min, hardening check ok (`make ci` at 3499e68, 2026-10-05) |
| 13 | The setup guide quotes the role guide's `az` commands exactly | `go test ./internal/api -run TestAzureSetupGuideQuotesTheRoleGuideCommands -count=1` | ok | ok at b7ec401 (shown red with one changed character first) and in `make test` of the final fix round | ok (`make ci` at 3499e68, 2026-10-05: `make test`) |
| 14 | Coverage floors: every package at or above its floor; floors of `coverage-floors.json` at c3f2b4e, among them the new `internal/platform/azureid` 100, `internal/providers/azurekv` 98 and `internal/jobs/kvjobs` 100, and the raised `internal/api` 94, `internal/certs` 98, `internal/inventory` 89 | `make coverage` | ok | `make coverage` rc 0 (second run of the final fix round, after f5ef240); floors set from it in c3f2b4e | ok, every package at or above its floor (`make ci` at 3499e68, 2026-10-05) |
| 15 | The whole gate: lint, test, coverage, test-ssh, build, release-symcheck, i18n-check, web-lint, web-coverage, vuln, secrets-scan, fs-scan, the e2e stack with hardening and Playwright, image-check, image-scan | `make ci` | ok | not run as a whole; the final fix round ran lint (0 issues), `make test`, `make coverage`, Vitest, i18n-check and the full e2e run separately | ok (exit code 0) at 3499e68, 2026-10-05, third attempt. Attempt 1 at 10481c6 failed in `web-coverage`: a Phase 4 test (`RouteErrorPage.test.tsx`) asserted the focus before the effect that moves it had run; fixed in 3499e68. Attempt 2 failed in `fs-scan`: on this machine containers cannot reach the LAN DNS, so trivy could not download its database. Attempt 3 ran `make ci TRIVY_IMAGE="--network host <the pinned image>"`, so the two trivy steps used host networking; nothing else differed. trivy: 0 HIGH/CRITICAL in the image; gitleaks: no leaks; govulncheck: no vulnerabilities |
| 16 | The optional real-Azure suite | `make test-azure` | — | **never run** (no subscription) | **never run** (no subscription) |

Mutation evidence of the final review of the provider area (a scratch copy outside the repository, at 6e26e42): of
44 mutants of the provider and certificate code, 32 turned a named test red; 5 were reported red without a named
failing test, most likely by the 90-second test timeout (a hang; not confirmed per mutant): the limiter's backward
step, the `Retry-After` bound, the body cap, the SDK's retries switched back on and the limiter's wait removed; 6
did not compile after the mutation and are inconclusive, not evidence (the scope pin, the `completeRefusal` code
check, the secret's ID and version match, the secret read's total budget, the `errNoBody` branch, the challenge
authority prefix; and on the certificate side `ExportPFX`'s key match makes 7); 1 survived (clearing the decoded
bytes of a refused second private-key block in a PEM secret, not pinned by a test).

Coverage floors at phase close (c3f2b4e): new floors `internal/platform/azureid` 100, `internal/providers/azurekv` 98
and `internal/jobs/kvjobs` 100; raised `internal/api` 94, `internal/certs` 98 and `internal/inventory` 89. The final fix
round's own full `make coverage` (rc 0, after f5ef240) measured `internal/inventory` 89.12, `internal/certs` 98.13 and
`internal/jobs` 89.21: about 0.1 to 0.2 points above their floors, so any change there needs its tests.

## Threat notes

### Outbound requests and SSRF (A-14, SEC-065)

A vault address is accepted only in the grammar of `azureid.ParseVault` [5], so the host is always
`<name>.vault.azure.net`. Every request of a session goes through one of two guarded transports [8]: the identity
transport reaches only `login.microsoftonline.com:443` (and, for a managed identity, `169.254.169.254:80` through
a dialer that accepts exactly that address [4]); the vault transport reaches only that vault's host on port 443.
Redirects are never followed; a `nextLink` or a challenge naming another host is refused before anything is sent;
listings are bounded in pages, link length and repeats; bodies and headers are capped. Every connection is checked
at connect time by `netaddr.DialContext`. The proxy variables of the environment are ignored [7].

Why two transports: with the pinned SDK versions a `nextLink` that names another host is requested and the SDK
sends its bearer token there (seen in `sdk_test.go` of the fake). Only Alice's transport stops it.

Two paths leave through code Alice does not own and are closed by refusal [37]: with a region variable MSAL asks
the instance metadata service through `http.DefaultTransport`; with `AZURE_SDK_GO_LOGGING` the SDK prints Azure's
error bodies. The provider's tests install a failing `http.DefaultTransport` for the whole package, so any request
outside the guard fails the test binary.

### Credentials and tokens

Client secrets and service-principal private keys are sealed in `credentials` as envelopes [9] and never returned
by the API. Request bodies that carry them are zeroed on every path (pinned by an observer that is nil in
production), and the web forms wipe them when the request body is built. A session's SDK credential is built per
job and dropped with the session [33]. Access tokens live inside the SDK; Alice decodes one only to read `oid` and
`tid`, which are stored only if they are GUIDs [6]. Of an Azure or Entra error only a request ID and a code of a
strict shape leave the provider [26].

### Vault secrets in deployments

A deployment reads the secret of one exact version, after the inventory's pre-check and before any SSH [18],
[44]. The value is checked against the version's thumbprint and the deployment's fingerprint, used once and
zeroed; it is never stored. Every read that returned a value is audited, also when the value is then refused
[34]. A read that returns certificates without a key marks the certificate not exportable, so later requests are
refused before any read [45]; a read that finds the chain incomplete is remembered on the version, so every later
manual deployment of it needs an Administrator's confirmation [19]. A vault credential that cannot be unsealed ends
a deployment before any sign-in [47]. The leak suite plants canaries (client secret, service-principal key, every sampled access token, the vault's
PFX and PEM secrets, the PFX files Alice sent on import, canaries in 403 bodies and malformed listings) and
searches DEBUG logs, every API answer and every table in text, hex and both base64 alphabets.

### Automatic deployment decisions

The poll only records; one planner decides from the database [20]. A version is deployed without a person only
if Alice detected it after automatic deployment was switched on, it is the current version, it is not held, and
its chain is complete [19], [43]; a version whose chain is incomplete is held and never deployed automatically, also
after a release. A version that appeared around a time the license gate was closed is held for an
Administrator [41], [42]. Switching automatic deployment on, releasing a held version, deploying a held version and
adding websites to an automatic connection need an Administrator with a fresh step-up and no API token [11]. Three
failures stop a wave.

### Imports

An import sends a private key out of Alice. It needs an Administrator with step-up, is sent once and is never
re-sent [38]. An outcome that cannot be proven either way is "Not confirmed yet" until a poll sees a version
created after the request with the imported thumbprint, and ends as "Outcome unknown" otherwise [39], [40].
Importing into a name that exists needs an explicit confirmation.

### The fake and its fidelity

The fake was written from the public REST reference and from memory of Azure's answers. Its endpoint table
classifies each behaviour as documented (16 rows), inferred or proven by the SDK accepting it (12 rows) or guessed
(39 rows), as reported by its implementer after the fix round. A test that passes against the fake proves Alice's
behaviour against these guesses, not Azure's.

## Review checklist

- [ ] No request leaves for a host other than `login.microsoftonline.com`, the session's vault host and, for a
      managed identity only, `169.254.169.254:80` (`TestGuardedTransportRefusesOtherHosts`,
      `TestRedirectIsNeverFollowed`, `TestForeignNextLinkIsRefused`, `TestManagedIdentityTalksOnlyToIMDS`,
      `TestA14KeyVaultSSRF`).
- [ ] `TestAzureSDKSurface` and `TestSurfaceRulesCatchEvasions` pass; no ambient credential, token cache, log
      listener, `DisableChallengeResourceVerification` or `AdditionallyAllowedTenants` anywhere.
- [ ] The three environment variables of R40 item 37 refuse a session at open and at every token request.
- [ ] No Azure, Entra, MSAL or SDK error text is stored, logged, audited or returned (`TestMapErrorTable`,
      `assertNoLeak`).
- [ ] A vault secret value is in no table, log, job row, audit row, email or response
      (`TestSecretLeakSuiteWithAzureCanaries`); no Key Vault column can hold one
      (`TestNoKeyVaultColumnCanHoldSecretMaterial`).
- [ ] A deployment whose pre-check refuses makes zero vault and zero SSH calls; a failed vault step leaves the
      website unchanged (`TestKVDeploymentReadsTheSecretBeforeAnySSH`, `TestKVDeploymentSecretReadOverTheWire`).
- [ ] An import is sent at most once at every interruption point (`TestImportJobNeverResends`,
      `TestImportNeverResendsOverTheWire`, `TestImportFoundRunningIsNeverSent`).
- [ ] A held version is never released by a poll and never deployed automatically; a released version is never
      held again by the planner.
- [ ] `credentials.manage` and the three conditional cases refuse an Operator, an Administrator without a fresh
      step-up and every API token.
- [ ] The release binary lacks the e2e trust path, the fake and any dial symbol (`make release-symcheck`,
      `make image-check`, `TestAzureDialSeamIsIntegrationOnly`).
- [ ] A version whose chain a read found incomplete is refused for a manual deployment without an Administrator's
      confirmation (409 `ALC-CRT-0011`, nothing queued), held or released.
- [ ] A secret read without a key marks the certificate and the version not exportable, and a later poll that
      finds the key exportable clears the mark.
- [ ] The role commands of `docs/azure-setup.md` equal those the web shows
      (`TestAzureSetupGuideQuotesTheRoleGuideCommands`).

## Findings

Found by the per-task reviews, the final fix wave, the Playwright task and the final whole-branch review, with the
commits. None was rated Critical by its reviewer.

| ID | Area | Description | Decision |
|---|---|---|---|
| P5-01 | Outbound guard | The Azure SDK requests a `nextLink` that names another host and sends its bearer token there (found by the fake's SDK round trip). | By design from the first provider commit: two guarded transports, foreign links refused (c741331). |
| P5-02 | Outbound guard | With `AZURE_REGIONAL_AUTHORITY_NAME` or `MSAL_FORCE_REGION` set, MSAL called the instance metadata service through `http.DefaultTransport`, outside the guard; the variable was read again after open. | Fixed: 06d4142 (refused at open), 09a3d6a (re-checked at every token). |
| P5-03 | Outbound guard | `AZURE_SDK_GO_LOGGING=all` made the SDK print Azure error bodies to standard error (no token or secret was seen in them). | Fixed: 09a3d6a (variable refused; a subprocess test shows the leak exists without the refusal). |
| P5-04 | Provider | A `nextLink` cycle was unbounded, and so was a `nextLink`'s length. | Fixed: 06d4142 (repeats and 1000 pages), 09a3d6a (4 KiB). |
| P5-05 | Provider | A listing page without `value` was taken as complete and empty, which would mark every certificate missing. | Fixed: bd4dfc4; and an empty listing is believed only on the second poll (88f21da). |
| P5-06 | Provider | The provider decoded the import PFX to learn the leaf's thumbprint: one more copy of the private key that cannot be zeroed. | Fixed: fd47d6a (`ImportRequest.LeafThumbprint`). |
| P5-07 | Provider | The SDK may send an import's body a second time after a 401 challenge inside Alice's one attempt. | Accepted, documented and pinned by a test (bd4dfc4); see "Not verified against Azure", item 15. |
| P5-08 | Provider | "Nothing was sent" was judged by the declared body length; the evidence was not kept for the whole attempt. | Fixed: 4c0e013. |
| P5-09 | Provider | A 404 on a vault's listing was reported as "certificate no longer in the vault" (`ALC-AKV-0015`). | Fixed: 5b4f1ff (`azure.vault_not_found`). |
| P5-10 | Fakes | The scripted provider fake accepted reads and imports the real provider must refuse (engine tests would pass while reading "latest"); the fake service answered 403 for a non-exportable certificate's secret where the documentation says 200 without a key. | Fixed: cf69859, 9085573, da48340. |
| P5-11 | Schema | A connection could name a certificate of another vault; a finished import could be reopened and its send time changed; name uniqueness depended on the database's collation. | Fixed: 76d57a0 (composite foreign key, `Z1007`, `lower(name COLLATE "C")`, explicit down refusal `Z1008`). |
| P5-12 | Inventory | A refused credential replacement was not audited; the SSH record paths accepted a vault's ID; a foreign error or a panic of the pre-flight could be returned as it was. | Fixed: c43db90, 2f8bbf6. |
| P5-13 | Inventory (poll) | The reason of a failed list was ignored (always `degraded`); emails carried untranslated values; a renewal made during a lock was not held, and the first redesign lost the hold after an incomplete listing or kept it for good. | Fixed: 95ea6c5, b779c02 (with d4ce0c3 and 07faea0), f6b769c. |
| P5-14 | Inventory (deploy) | A queued deployment still received the key after its connection was removed, its website released or automatic deployment switched off; nothing was re-checked when the secret arrived; refused reads were not audited; removing a vault with connections could deadlock against a deployment request. | Fixed: e405fac, a548c07, 438bef2. |
| P5-15 | Engine | The engine read the secret before it asked the inventory whether the deployment was still wanted; an unmapped inventory error was retried three times with a key read each. | Fixed: 45b370a (pre-check first, sentinel table), 4864c17 (a database error after the read is retried, not final). |
| P5-16 | Planner and imports | The planner starved connections beyond the first 500; the stop email's advice did not work; an import into a connected name Alice had marked missing needed no confirmation and could be deployed automatically; a dropped confirmation gave a refusal loop; the requester was not re-checked at job time; a leaf not yet valid was imported. | Fixed: 8b300df, 0dd3904, 9a52e46. |
| P5-17 | Planner | The planner's reopening hold re-held a version an Administrator had released, on the next tick, and caught old versions already deployed to most websites. | Fixed: c2b44ed, e6ce73e, 665dc9f. |
| P5-18 | Planner | A renewal Alice detected after automatic deployment was switched on was neither deployed nor announced when Azure's clock was behind Alice's (found by the API suite, failing test 1a7d5f0). | Fixed: 4ccdae8 (the notice follows Alice's detection time; the eligibility rule is unchanged). |
| P5-19 | Jobs | An import stayed queued or running for good when its job ended without the handler, blocking the name; the access check's secret read was not audited; polls waiting for one of the two slots parked all eight workers; a renewal detected just before a lock was deployed after the license returned. | Fixed: 6adf84c, 99beaa4, 7304c3c, 170dfb0. |
| P5-20 | API | Three catalogue texts were false; the authorization matrix was wrong for the three conditional actions; the import reads skipped the vault check; an answer could contain a literal `{{role}}`; two OpenAPI properties were corrupted; a check-then-act gap on deploying a held version. | Fixed: 0012df1, 11f7303, 84a683e, b8ecb5d. |
| P5-21 | Web | The release dialog said releasing deploys nothing (false with automatic deployment on) and its first correction was false for chain holds and non-current versions; "still working" pointed to a server's page; "Last checked" and the degraded text were false; Turkish terminology. | Fixed: 665c0a1, 8241d7e. |
| P5-22 | e2e wiring | The rule that keeps the dial seam out of untagged builds was name-based; the e2e trust file was read without checks (a link to the system bundle was accepted). | Fixed: 94b5a91, 1c578c8. |
| P5-23 | Test evidence | In the API suite the PFX Alice sent was not a canary, only the last token was, "nothing sent to the foreign host" was vacuous for a non-vault host, and the proxy assertions proved nothing. | Fixed (tests only): 6869f13; the proxy case is proven by the provider's subprocess test only. |
| P5-24 | Provider | The per-vault rate limiter kept its schedule when the clock stepped backwards (found by the e2e reset, which moves Alice's clock back): the next vault request waited for the clock to catch up and failed as `azure.unreachable`; the first fix granted a whole new burst per backward step. | Fixed: 51fd1fc, then eea6f58 (the schedule moves back by the step). |
| P5-25 | Engine | A vault whose sealed credential cannot be decrypted failed a deployment with the generic `ALC-SYS-0003`. | Fixed on the deployment path: 663af93, caab34c, 715f900 (`ALC-AKV-0041`); the poll, the access check and an import still answer `ALC-SYS-0003` (known limitation). |
| P5-26 | Inventory | A policy switched to non-exportable without a new version was not noticed: every deployment read the secret and ended `ALC-AKV-0016`. The first detection of a key-less value recognised only the fake's Java trust-store shape. | Fixed: 3c2f3d1, fb02f24 (the read marks the certificate and the version not exportable), 20020c6 (any PFX that decrypts with the empty password and has certificates but no key), 5fa5042 (the 0016 text), 9051c02 (a later poll clears the mark). |
| P5-27 | API and web | A vault's `last_error` did not carry the poll's firewall address or permission model, so the firewall address was shown nowhere. | Fixed: c75dd75, 8405627, 7231878. |
| P5-28 | Jobs and web | Job items named neither their deployment nor their import (the held-jobs panel searched the server's deployments); the first fix made the Phase 4 held-jobs panel lose "already sent / not sent" (the Phase 4 journey failed). | Fixed: 0ee77a5, then ec0c88a. |
| P5-29 | API | Nothing kept production code from setting the request-secret zeroing observer; the first rule missed a range assignment and a `go:linkname` alias. | Fixed (tests only): 90c0790, 3f7e8f1. |
| P5-30 | Inventory and web | After an Administrator released a version held for its incomplete chain, **Deploy now** never offered the chain confirmation, so every manual deployment failed with `certificate.chain_unconfirmed` (found by the Playwright task). | Fixed: 18801d9 (migration `00009`, `chain_incomplete`, the server refuses up front with 409 `ALC-CRT-0011`, the dialog offers the confirmation), 6e26e42 (journey in EN and TR). |
| P5-31 | Web | Three serious axe violations, theme-wide: table scroll areas a keyboard could not reach, and two red-on-white contrasts of fields with an error; the first fix's focus ring was clipped and the scroll area had no name. | Fixed: 7da356e, c7d654a, 8add878, then b4e1c36. |
| P5-32 | Test evidence | Playwright: axe scans ran before a dialog was visible, the throttling cycles could pass on a stale screen, some counts were vacuous, the firewall address was not asserted, and the incomplete-chain release was not driven. | Fixed (tests only): 98800fc, 1dbb305. |
| P5-33 | Test evidence | A provider test drove the fake clock in real time and failed under CPU load. | Fixed (tests only): 24985d3 (`Fake.AdvanceToNextTimer`). |
| P5-34 | Inventory | Final review: an Administrator's chain confirmation was dropped when another vault object had delivered the same leaf with a complete chain, so such a version could never be deployed. | Fixed: 4c7235a (the version's own `chain_incomplete` wins over the shared certificate row). |
| P5-35 | Migration | Scoped re-review: rows held for their chain before migration `00009` got `chain_incomplete = false`, so after a release the first **Deploy now** failed closed at the read before the mark was set. | Fixed: 509e5b7 (`00009` amended in place to mark them; see the known limitation on databases that ran the first form). |
| P5-36 | Web and emails | Final review: the add dialog called a firewall refusal a missing permission; the import confirmation promised an automatic deployment that may not happen; three emails pointed to a page or a control that does not exist; every table's scroll area was a landmark with one shared name (axe `landmark-unique`, moderate). | Fixed: d4d25a0, 20ce34a, 447b6c6, 118af0f (the scroll area is a named group). |
| P5-37 | Inventory and audit | Final review B: a version first stored from a version list was not judged by the hold rule and got no new-version audit row when it became current; releasing a chain hold audited `confirm_incomplete_chain`, as if it approved automatic deployment; the access check's secret read was audited without the person who asked. | Fixed: 23d3e95, 1d55040 (`chain_incomplete_acknowledged`), 1dcc3a5 (`requested_by`, `requested_by_role`). |
| P5-38 | Imports and jobs | Final review B: an uncertain import could be settled by an earlier version with the same thumbprint (Azure's clock ahead of Alice's); a `kv.import` job ended `succeeded` for an import another path had failed, or `dead` with an email when the vault was removed during the send. | Fixed: 9a956f6 (only a version Alice stored after the send, not settled by another import), 1de998e (the job fails with the import's code, no retry, no email). |
| P5-39 | API and texts | Final review B: an API token in the race window of a hold or a switch-on was told to step up (`ALC-AUTH-0003`) where the documents promise `ALC-AUTH-0002`; `certificate.pfx_busy` told a Key Vault deployment to upload a file again; OpenAPI omitted routine refusals. | Fixed: abc60ef, 96f10b2, f4f7162. |
| P5-40 | Web | Final review C minors: the Deploy now dialog kept a chain request across versions and let an Operator resubmit into the same refusal; an Operator's row offered Deploy now for a known-incomplete chain; the release of a chain hold with automatic deployment off did not say that Deploy now asks again; one failing vault blanked the import history; the vault list had no loading state. | Fixed: 880e503, ba1fe88, dbcdcb0, 76222d4, 16ea1e9. |
| P5-41 | Certificates | Re-review and final review A: a PFX whose key sits in a bag go-pkcs12 does not read was not pinned; clearing a refused second PEM key block was not pinned (surviving mutant). | Pinned by tests, behaviour unchanged: 550fddb (the nested-bag case is a known limitation). |
| P5-42 | Build | `cmd/alice` `TestServeStartsOnAPhase3Database` expected schema version 8 since migration `00009` (red on the branch; the partial coverage runs did not include `cmd/alice`). | Fixed: f5ef240. |

## Not verified against Azure

Each item is a behaviour the product's logic depends on and that is proven only against the fake, by the SDK
accepting the fake's answer, or by reading documentation or SDK code. "Suite" means the opt-in real-Azure suite;
"by hand" means the owner walkthrough below or a look at the vault in the Azure portal.

How to run the suite: `make test-azure` runs `TestRealAzure` and `TestRealAzureReaderSufficiency` under the
`azure` build tag. It needs `ALICE_AZURE_TEST_VAULT_URL`, `ALICE_AZURE_TEST_TENANT_ID`,
`ALICE_AZURE_TEST_CLIENT_ID`, `ALICE_AZURE_TEST_CLIENT_SECRET` (or `ALICE_AZURE_TEST_CERT_FILE`, a PEM file with
the certificate and private key) and `ALICE_AZURE_TEST_CERT_NAME` (an exportable certificate of the vault with at
least one version); the Reader test also needs `ALICE_AZURE_TEST_READER_CLIENT_ID` and
`ALICE_AZURE_TEST_READER_CLIENT_SECRET`, an identity that holds only Key Vault Reader on the vault. Without the
variables the tests skip. `make record-azure` needs the same variables and rewrites
`test/testdata/kv-recordings/` from the vault's answers (shapes and placeholders only; review the diff before
committing). Neither target is part of `make ci`. The suite reads; it never imports and never changes the vault.
It covers items 1, 2, 12, 21, 24, 29, 30 and 33 below; the others need the walkthrough or a deliberate fault.

Roles and access:

1. **Key Vault Reader is enough to list certificates, keys and secrets and to read a certificate** (R22, AC6,
   SEC-083). If not: a monitor-only vault shows `degraded` with a role message that is wrong. Check: suite
   (`TestRealAzureReaderSufficiency`).
2. **Reader may call `GetKey` (public key) on an RBAC vault** [16]. If not: keys are listed without type and size.
   Check: suite (the Reader test prints the result).
3. **Which data actions each built-in role carries** (the fake's role presets are from memory; in the fake list
   and get can be revoked separately, which Azure cannot express). If wrong: the role named in a message is not
   the one that helps. Check: by hand, walkthrough steps 1, 5 and 7.

Error answers of a vault:

4. **The inner codes of a 403**: `ForbiddenByRbac` for RBAC; `ForbiddenByPolicy` or `AccessDenied` for access
   policies (both accepted). If different: the permission model in the message is missing or wrong; the status
   and the outer code (documented) still give `azure.forbidden`. Check: by hand (step 5; an access-policy vault).
5. **The firewall's 403**: inner code `ForbiddenByFirewall` and a `Client address: <ip>` line in the message. If
   different: a firewall refusal reads as a missing role (`ALC-AKV-0003` instead of `0004`) and no address is
   shown. Check: by hand (enable the vault firewall without Alice's address).
6. **A disabled version's secret read answers 403 with inner code `SecretDisabled`.** If different: it reads as a
   missing role. Check: by hand (disable a version, **Deploy now**).
7. **The 404 code names** `CertificateNotFound`, `SecretNotFound`, `KeyNotFound`; soft-deleted certificates are
   absent from listings; an import into a soft-deleted name answers 409. If different: a deleted certificate
   reads as an unexpected answer, or an import into a soft-deleted name ends uncertain. Check: by hand.
8. **An unknown vault name.** In the fake it is a 404 on the listing, mapped to `azure.vault_not_found`
   (`ALC-AKV-0005`). On Azure an unknown name is expected to fail in DNS; that mapping is tested only in the
   provider's unit tests with an injected dial failure and cannot be produced through the API suite. Whether
   Azure ever answers a 404 on the listing is unknown. Check: by hand (add a vault name that does not exist).
9. **Other error bodies**: the 401 texts and `AKV` codes, 405 and unknown-route bodies, the bodies of 429, 500
   and 503, and the form of `x-ms-request-id` (kept only if it is a GUID). If different: a request ID is dropped
   or a failure reads as `azure.unexpected_response`.
10. **`Retry-After` on 429 and 503 is seconds or an HTTP date.** If absent or different: Alice uses its own wait.

Sign-in, challenge and tokens:

11. **The AADSTS number arrives in `error_codes[0]`**, with 7000215 (wrong secret), 7000222 (expired secret),
    700016 (unknown application), 90002 (unknown tenant), 700027 (unregistered certificate) and 700024 (clock);
    their HTTP statuses and texts, and the codes 700021, 700023, 70011, 70003, 900144 and 7000216, are guesses.
    If different: "Credentials expired" and "clock" read as a plain sign-in failure. Check: by hand (wrong
    secret; expired secret if one is at hand).
12. **The vault's challenge** names `authorization="https://login.microsoftonline.com/<tenant>"` and
    `resource="https://vault.azure.net"` (or the matching `scope`). If Azure sends another resource form the
    pinned-scope check refuses every sign-in as `azure.unexpected_response`. Check: suite (any success proves it).
13. **Challenge caching and a 401 on a later page**: the SDK caches the challenge per process; on page 2 with an
    expired token the SDK's host check sees `:443` in the `nextLink`; Alice maps that to a retry and expects a
    refreshed token to succeed. If wrong: a long listing can fail once per poll. Unpinned at provider level.
14. **Token lifetime**: MSAL caches by real time; the fake expires tokens by the test clock.
15. **A vault does not carry out a request it answers 401.** The SDK may re-send an import's body once after a
    challenge; if Azure had carried out the first one, two versions would exist and the import would still read
    "refused". Check: cannot be provoked by hand; look for a second version after any import that reported a
    sign-in failure.
16. **Token and discovery answers**: the token endpoint's success fields, the OpenID configuration field set, an
    unknown tenant answering `invalid_request` or `invalid_tenant`, and that Entra accepts MSAL's PS256 client
    assertion with `x5t#S256` (Microsoft's code; the fake's verification is written from MSAL's source).
17. **Token claims**: `oid` and `tid` are present and GUIDs (shown as the object ID; not stored otherwise).
18. **The instance metadata service**: its success answer with numbers as strings, 400 "Identity not found" for
    an unknown identity, its other error bodies, and that an absent service fails at dial or by timeout; the
    `object_id` and `msi_res_id` selectors are not modelled. Check: by hand on an Azure virtual machine.

Listings:

19. **Order by name, the `$skiptoken`, page fill** (short or empty pages that still carry a `nextLink`), the
    default page size, `nextLink` with `:443`.
20. **A listing's `updated` and `x5t` are the current version's**; `managed` marks a certificate's own key and
    secret (absent means false); `attributes.enabled` absent means enabled; names are case-insensitive.
21. **An empty list carries `"value": []`**, never `{}` or `null`. If not: a vault without keys or secrets shows
    a failed list. Check: suite.
22. **The version list** and that Alice's newest-by-`created` choice matches Azure's current version.
23. **Whether an import or a policy change moves `updated`** (decides when details are read again, and so whether
    a later poll clears the not-exportable mark after the policy is switched back).
24. **Object IDs** use `https`, the vault's own host and port 443 or none. If a private endpoint answered with
    another host name in its IDs, every item would be dropped with a warning. Check: suite (public endpoint);
    by hand for a private endpoint.
25. **`created` has whole seconds, and its relation to Alice's clock.** Import settling [39], hold rule (b) [41]
    and planner eligibility [43] compare it with Alice's times. With a clock difference between Azure and Alice,
    rule (b) can hold or miss a version created near a license reopening, an import can fail to settle, and a
    real renewal stamped before automatic deployment was switched on is not deployed automatically (it is
    announced by email). Check: by hand, steps 4 and 8.
26. **A certificate deleted and created again under the same name** is the same row in Alice; what Azure does
    with its versions is not modelled.

Secrets:

27. **A non-exportable certificate's secret**: that the key is absent is documented; the container form of the
    key-less value is a guess. Alice recognises two forms as "no key": a PEM value with certificates and no key
    block, and a PFX that decrypts and authenticates with the empty password and holds certificates but no key bag
    (go-pkcs12's answer "pkcs12: private key missing"; pinned by tests on the Java trust-store and the openssl/.NET
    shapes). Those mark the certificate **Monitor only**. Any other form (for example a PFX without a MAC, which
    go-pkcs12 refuses as "only password-protected PFX is implemented") ends the deployment as `ALC-AKV-0016` without
    the mark. So a wrong guess changes the outcome, though never safety: nothing is sent to a server either way.
    Alice itself reads such a secret only when the policy changed after its last poll, so check by hand: read the
    non-exportable certificate's secret with `az keyvault secret show` and see which form it has.
28. **Whether switching a policy to non-exportable affects existing versions** (the fake changes the policy, not
    old versions).
29. **The content-type strings** are exactly `application/x-pkcs12` and `application/x-pem-file`. If Azure adds
    a parameter or another case, every deployment ends `kv.secret_unreadable`. Check: suite.
30. **The PFX secret's profile** (encryption, empty password), chain order and which certificates it includes,
    and the position of the key in a PEM secret. If go-pkcs12 cannot read the profile: every deployment ends
    `kv.secret_unreadable`. Check: suite.

Imports:

31. **Key Vault accepts a `LegacyDES` (3DES, SHA-1) PFX with an empty password** (tools differ in how they
    encode an empty password). If not: every import is refused (`kv.import_rejected`) with nothing created.
    Check: by hand, step 7.
32. **The import answer** carries `id` with the new version, `x5t` and `cer`, and `created` not earlier than the
    request. If not: a successful import reads "Not confirmed yet" until a poll settles it.
33. **The secret's and certificate's ID in an answer** name the requested name and version (Alice refuses an
    answer for another object). Check: suite (secret read).
34. **Import validation**: the 400 `BadParameter` bodies, that an import into an existing name adds a version
    that becomes current and replaces the policy when the request carries one, and what Azure does with a policy
    whose key type or size does not match the key (Alice sends them from the validated key).
35. **Key Vault Certificates Officer is the role an import needs.**

Proven by reading SDK code only (not Azure's behaviour, but equally unconfirmed outside the tests):

36. **`azcore` passes the call's context to the transport**, which is how "no body was handed on" is known.
37. **The pager resumes from a `nextLink` through `Pager.UnmarshalJSON`** and hands the seeded page back once
    (`azcore` v1.23.2). Two tests would fail on an SDK update that changes it.
38. **The pinned SDK sends API version `2025-07-01`** and real vaults accept it with instance discovery disabled.

## Known limitations

Azure and scope:

- **Nothing was run against Azure.** See the section above. Key Vault Reader sufficiency (R22) and every answer of
  the fake are unconfirmed until the owner runs `make test-azure`; the role guide says "Expected to be enough; not
  yet confirmed on a real vault." The inner code of a disabled version's secret read is assumed to be
  `SecretDisabled`; any other code reads as a missing role (item 6 above).
- **Public cloud only; no HTTPS proxy and no custom CA bundle for Azure before Phase 7** [5], [7]. Managed
  identity only on an Azure virtual machine [4]. No deployment windows [31]; wave limits are fixed [20]; expiry
  emails for client secrets and keys wait for Phase 7 [27].
- **Listing bounds**: 5000 certificates, 5000 keys, 10,000 secrets, details of 100 certificates and 100 keys per
  poll [15]. A version Alice never saw as current cannot be deployed [17].
- **The access check never probes import** [28]. A deployment needs the vault reachable when it runs (no cached
  key). An `auth_failed` vault keeps being polled, at most hourly [12]. One token request per job session [33].
- **The access check does not read a certificate's details** (it lists only). An identity with `list` but not
  `get` on certificates (an access-policy vault) passes the check, and then every poll discards the whole
  certificate listing: one certificate whose detail read keeps failing (other than not found or the poll's own
  deadline) fails the list of certificates, with a role message. Fail-safe; documented, not changed in this phase.
- **Each job session signs in afresh**: one token request to Entra per poll, access check, deployment read and
  import, for every vault [33]; with many vaults this counts against Entra's limits.
- **The per-vault rate limit counts attempts, not HTTP requests**: one attempt can be the SDK's challenge probe, a
  token request and the call, so for a short time (the first call of each client) up to about three times the
  limit of 5 per second reaches the wire.
- **Managed identity lends the machine's identity to every Administrator** who may add a vault: any vault name can
  be added with it, so the identity should hold only the roles Alice needs [4].
- **Connections cannot be prepared while the license is locked**: only switching automatic deployment off and
  deleting a connection work then [22].
- **The import PFX uses 3DES and SHA-1 with an empty password**; no confidentiality is claimed for it [25].

Memory and logs:

- **The SDK keeps a client secret, and a secret value it read, as Go strings** for the session's lifetime; they
  cannot be zeroed. The same holds for the base64 text and request body of an import and for key objects parsed
  by go-pkcs12 and `crypto/x509`. MSAL's managed-identity token cache is process-global.
- **A code chosen by the vault reaches DEBUG logs** (`azure_code`, strict shape `^[A-Za-z][A-Za-z0-9]{0,63}$`).
- **`pkg/browser` and MSAL are linked** into the binary and never called [1].
- **Superseded credential rows are kept**, sealed, because `credentials` is append-only [9].
- **`ALC-AKV-0041` is produced only by a deployment** [47]. **Check now**, the access check and an import show
  `ALC-SYS-0003` when the vault's credential cannot be opened, so the vault page does not name the fix.
- **The access check's secret read** can be asked for by an Operator or an operate-scope token
  (`inventory.operate`); the key is read into memory, never returned, and zeroed. The audit row `kv.secret_read`
  (purpose `access_check`) names who asked (`requested_by`, `requested_by_role`).

Network:

- **Loopback and shared (CGNAT) addresses are dialled for a vault name**, as `netaddr` allows them for every
  target (R39 item 8). TLS verifies the vault's name and no token leaves without it, so the exposure is a
  connection and a ClientHello to such an address; private endpoints need the private ranges.
- **At most two polls run at a time, for all vaults together** [44]. Two slow vaults can delay a third, which
  F-44 says should not happen. A poll whose process crashed keeps its slot until its 45-second lease runs out and
  the next recovery pass (every minute) puts it back, so two crashed polls can pause every vault's polls for up to
  about two minutes (read from the runner's defaults; not pinned by a test).
- **The e2e stack does not switch managed identity off.** Its Alice container has network egress, so on an Azure
  virtual machine the real metadata service could answer and a real identity token would go to the fake, which
  the e2e build trusts. Do not run the e2e stack on an Azure virtual machine. Only the e2e build trusts the fake's
  CA for Azure hosts [45]; the release binary has no such path (row 11 of the evidence).

Not covered, or not pinned by a test (proven only at unit level, by reading, or not at all):

- isolation between two vaults (F-44 "another vault is not delayed", F-50): the fake serves one vault;
- a vault name that resolves to the metadata or a link-local address is refused, and a private endpoint on a
  private address works: unit level only, not through the API suite's seam; the environment proxy is ignored: a
  subprocess test only;
- the one-minute budget of the secret read: run once by hand by the Task 18 implementer (the job ended after
  1 m 0.03 s with no SSH), no permanent test;
- a 401 on a later listing page: covered over the wire, but no provider mutant turns red (the retry is the SDK's);
- the email bounds of a mass renewal;
- the planner's own guard against a second deployment of a busy website (F-48; Phase 4's unique index also
  refuses it);
- the managed-identity error mapping, branch by branch.

License holds:

- **False holds after a renewal out of grace.** `grace` counts as a closed state for "reopening", so a version
  created within about one poll interval before a license upload out of grace is held although changes were
  allowed. Accepted as fail-safe [41].
- **Rule (c) can hold for good.** In a vault whose certificate listing never completes after a reopening, every
  new version without a creation time stays held [41]. Theoretical; an Administrator releases them.
- **Hold rule (b), planner eligibility and the settling of an uncertain import trust Azure's `created`** and its
  relation to Alice's clock (item 25 above). When Azure's clock is behind Alice's by a second or more, the version
  a lost import created never matches and the import ends "Outcome unknown" (`ALC-AKV-0026`). (An earlier version
  with the same thumbprint can no longer settle it: only a version Alice stored after the send counts.)
  The pointer to the current version moves to an already known version only when its `created` is strictly later,
  which relies on Azure sending `created` on every version.
- **A wave that began before a lock continues after it.** The planner's reopening hold applies only when the
  connection has no deployment of the version at all [42]; deployment jobs that were waiting at the lock wait for
  an Administrator as in Phase 4.
- **A version first stored from a version list** (seen in the list before it became current, a window of seconds
  between two reads of one poll) keeps that earlier detection time when it becomes current (the application role
  cannot change `detected_at`); the hold rule and the new-version audit row apply then.

Chains and keys:

- **An incomplete chain is known only after a read** [52]. The first manual deployment of a never-read version is
  accepted and then refused at the material step; a release never confirms the chain, so every manual deployment of
  such a version asks for the confirmation again. A released chain hold is held again by the next automatic attempt
  (an hour later at the earliest), with a new email, because automatic deployment never carries a confirmation.
- **An Administrator's operate-scope API token can confirm an incomplete chain** for a version that is not held, as
  on Phase 4's deploy route.
- **A value without a private key is recognised from the PFX decoder's error text** "pkcs12: private key missing"
  (pinned by tests, so an upgrade of go-pkcs12 that changes it fails them) [45]. If Azure's key-less form
  differs, a deployment ends `ALC-AKV-0016` and the certificate is not marked **Monitor only** (item 27 above). The
  first deployment that meets a key-less secret reads it (audited) and fails `ALC-AKV-0016`; only later requests
  answer `ALC-AKV-0013` up front.
- **A PFX whose private key sits in a bag go-pkcs12 does not read** (it reads only top-level `keyBag` and
  `pkcs8ShroudedKeyBag`; a key inside a nested SafeContentsBag, for example) is read as a value without a key: the
  certificate is marked **Monitor only** instead of the deployment failing as `ALC-AKV-0016` alone. Pinned by a
  test; go-pkcs12 gives no access to the bags, so a strict check would need Alice's own PKCS #12 decoder.

Imports:

- **A crash between marking an import sent and sending it** leaves a false "Not confirmed yet"; it ends as
  "Outcome unknown" after 24 hours with a complete listing, or after 72 hours [40].
- **An uncertain import blocks its name** in that vault until it is settled or ended. **An import whose retry job
  is held for the license blocks its name too**, also after the lock, until an Administrator runs or discards the
  held job (the held-jobs panel links the import's vault). The import sweep and the 72-hour end are read-only
  periodic work and do not run during a lock; they catch up afterwards.

Email and interface:

- **No bound on emails across vaults.** The bound is 20 per kind, per vault and per run, then one summary [43].
  Many vaults renewing at once send many emails. No email is sent for the firewall case [12].
- **`autocomplete=off` on the secret fields may be ignored by a browser.**
- **The "New version found" chip is a heuristic** computed in the browser: created in Azure after Alice first saw
  the certificate and within 7 days [46].
- **The held-jobs panel reads each held deployment by its ID**, one request per held deployment job [49].
- **Every table's scrolling part is a keyboard stop**, also when nothing scrolls, named as a group (not a landmark)
  with the generic name "Table, scrolls sideways" rather than the table's own [51].
- **The fake's client secret appears in Playwright traces of failed e2e runs**, which CI uploads as an artifact.
  The fake generates it per start and reset and it dies with the stack; never reuse this pattern against a real
  tenant.

Migration:

- **Migration `00009` was amended before release** (509e5b7): its Up also marks versions held for their chain.
  Goose records only version numbers, so a database that already ran the first form of `00009` (possible only for
  someone who ran the `phase-5` branch between 18801d9 and 509e5b7) lacks that mark. Run once by hand on such a
  database:
  `UPDATE kv_certificate_versions SET chain_incomplete = true WHERE held_reason = 'incomplete_chain';`
  Without it, the first **Deploy now** after releasing such a version fails at the read with nothing changed, and
  the next one asks for the confirmation.

Earlier phases:

- **`targets_endpoint_live`** (migration `00005`) still uses `lower()` under the database's collation. Vault host
  names are ASCII lower-case by a CHECK, so vaults are not affected; server host names under a Turkish collation
  are.

## Done in the final fix wave

The items the controller collected for a final fix wave while the tasks ran, with their commits:

- A vault whose sealed credential cannot be opened: `ALC-AKV-0041` on the deployment path (663af93, caab34c,
  715f900); the other paths are a known limitation above.
- A policy switched to non-exportable without a new version: the read marks the certificate and the version not
  exportable, a later poll clears the mark (3c2f3d1, fb02f24, 9051c02, 5fa5042, 20020c6).
- A vault's `last_error` carries the poll-time params (c75dd75, 8405627, 7231878).
- `deployment_id` and `import_id` on job items, which closes the Phase 4 carry "a deployment ID on deploy jobs"
  (0ee77a5, ec0c88a).
- A test that nothing outside tests sets the request-secret zeroing observer (90c0790, 3f7e8f1).

## Owner verification

Spec §26.7 "Owner verifies", extended by the actions this phase added. Steps 1 to 5 are the spec's. You need:

- An Azure subscription with a **test** vault (never a production vault) that uses Azure RBAC, in which you can
  create certificates and assign roles; an app registration with a client secret (and, for step 6, one with a
  certificate; a virtual machine with a managed identity if you have one).
- A development stack on the Alice machine, signed in as an administrator, with the evaluation started, and the
  disposable Nginx test server of the Phase 4 walkthrough with one website.
- In the test vault: a self-signed certificate `web-cert` with an exportable key, a short lifetime and a renewal
  policy of one day (so that Key Vault renews it by itself), and one certificate created with a non-exportable key.
  For step 11, a certificate whose PFX holds the leaf without its intermediate.
- [docs/azure-setup.md](../../azure-setup.md) for the app registration, the roles and the network (the role
  commands there are the ones Alice shows).

Without an Azure subscription, steps 1 to 5 and 7 to 10 can be walked on the e2e stack (`make e2e-up`), whose
vault is the fake; write "fake" in the result cell. That proves the screens, not Azure.

1. **Add the vault with only Key Vault Reader.** Give the app registration the role **Key Vault Reader** on the
   test vault. In Alice open **Key Vaults**, **Add Key Vault**, sign-in method **Client secret**.
   Expected: "Key Vault added."; the access check shows what works and a clear note for what was not checked
   (deployment access, import).
2. **Inventory.** Open the vault.
   Expected: certificates, keys and secrets with their expiry dates; the non-exportable certificate is marked
   **Monitor only**.
3. **Connect.** Give the app **Key Vault Secrets User** (preferably on `web-cert`'s secret only). On `web-cert`
   choose **Connect websites** and pick the test website.
   Expected: the connection lists the website; **Check deploy access** reports that the secret can be read.
4. **Renew with automatic deployment.** Switch **Automatic deployment** on (Alice asks for step-up). In Azure
   create a new version of `web-cert`. Choose **Check now**, or wait for the poll.
   Expected: within the poll interval plus about a minute the new version is deployed and appears in
   **Deployment history** as "From Key Vault: <name>" with the step **Read the certificate from Key Vault**; the
   website serves it.
5. **Missing role.** Remove **Key Vault Secrets User** in Azure and create another version.
   Expected: Alice says which role is missing (`ALC-AKV-0003`, Key Vault Secrets User); the deployment failed at
   the vault step; the website is unchanged.
6. **The other sign-in methods.** On the vault's page choose **Replace credentials** with sign-in method
   **Certificate (recommended)**; then try once with a wrong client secret. If Alice runs on an Azure virtual
   machine, add a second test vault with **Managed identity**.
   Expected: each valid method signs in; the wrong secret is refused and the vault keeps its credentials.
7. **Import.** Give the app **Key Vault Certificates Officer**. On a certificate with a key in Alice choose
   **Import into Key Vault**, pick the vault and a new name; then import again into the same name.
   Expected: the first import ends **Imported**; the second asks you to confirm that a new version is added and
   that it can switch off the vault's own renewal; without the role nothing is created (`ALC-AKV-0003`).
8. **Held version and release.** Let the license lock, create a new version of `web-cert` in Azure, then
   install a valid license and choose **Check now**.
   Expected: the version shows **Held** with the waiting-for-an-administrator text and is not deployed; **Deploy
   now** by an Operator is refused; **Release** (step-up) says what automatic deployment will do, and then it
   happens.
9. **License lock.** While locked: try **Add Key Vault**, **Check now**, **Connect websites**, **Deploy now**,
   **Import into Key Vault**; then switch **Automatic deployment** off and delete a connection.
   Expected: the first five are refused with the license message and nothing is sent to Azure; the last two
   work.
10. **Removal.** Choose **Remove Key Vault** on a vault with a connection.
    Expected: Alice asks to remove the connections with the vault (step-up); afterwards the website still serves
    its certificate and nothing was changed on the server.
11. **Incomplete chain** (optional). Connect the certificate whose PFX lacks the intermediate to the test website
    with automatic deployment on, then create a new version of it.
    Expected: the version is held for its chain and nothing is deployed; **Release** asks for the chain
    confirmation; **Deploy now** asks for it again and then deploys.

Then run the real-Azure suite (`make test-azure`, with the Reader variables) and record its output.

| Step | Result (pass, or what differed) | Date and tester |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |
| 10 | | |
| 11 | | |
| Real-Azure suite (`make test-azure`) | | |
| Reader sufficiency (R22) | | |
| Turkish tone review | | |
| Crypto sign-off | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
