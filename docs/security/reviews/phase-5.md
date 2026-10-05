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

A pre-flight scan compiled the plan's code for Tasks 1 to 8 in a scratch worktree before Task 1 and read the rest
against the code: 41 defects of the plan and 15 design findings (S1 to S15), ruled on before the first task.

## Evidence

All commands run from the repository root; `-tags integration` needs Docker (testcontainers). "Recorded" means the
result is taken from the run recorded while the phase was built (the task report and the commit are named in the
controller's ledger), not from a run made for this review. This review was written without Docker.

**TO UPDATE AT PHASE CLOSE:** the "Result" column and the coverage line below hold the values recorded per task.
Replace them with the results of the final `make coverage` and `make ci`, add the new coverage floors
(`internal/platform/azureid`, `internal/providers/azurekv`, `internal/jobs/kvjobs`), and fill row 12 (Playwright).

| # | Check | Command | Expected | Result (recorded) |
|---|---|---|---|---|
| 1 | Vault address, ID, name, version and thumbprint grammars; fuzz of the address parser | `go test ./internal/platform/azureid -count=1` | ok | ok, coverage 100 % (Tasks 1–3) |
| 2 | Guarded transports, sign-in wrapper, error mapping (no Azure text in any rendering), retry and budgets, listing bounds and cycles, managed identity only to the metadata address, refused environment variables, SDK surface rules, import outcomes, secret read | `go test -race -count=3 ./internal/providers/azurekv/` | ok | ok, coverage 98.4 % (Tasks 6–8, fix round 2) |
| 3 | Provider contract: import result rules, conformance of every session implementation, the scripted provider fake | `go test ./internal/providers/... -count=1` | ok | ok, `internal/providers` 100 % |
| 4 | Key Vault secret decoding, sign-in certificates, PFX export, buffers cleared; fuzz | `go test ./internal/certs -count=1`, `make fuzz-certs` | ok, no crasher | ok, coverage 98.1 %; `FuzzParseKVSecret` 30 s, no crash (Tasks 1–3) |
| 5 | The fake Azure service against the reference shapes and the real SDK clients (three sign-in methods, paging, import, challenge verification left on) | `go test -race -count=8 ./internal/testutil/fakekv` | ok | ok (Tasks 4–5) |
| 6 | Migration `00008`: grants listed exactly, triggers `Z1005`–`Z1008`, no column that can hold a secret, names under a Turkish collation, down refusal | `go test -tags integration ./migrations -count=1` | ok | ok (Task 9, fix round 1) |
| 7 | Inventory: vaults and sealed credentials, polling and failure transitions, hold rules, connections, planner, imports, pre-check and material step, zeroing, leak dumps | `go test -tags integration -count=1 -cover ./internal/inventory/...` | ok | ok, coverage 89.2 % (floor 88) |
| 8 | Jobs: access check, poll, import, periodic tasks, poll cap in the claim, deadlines, L-87 (`TestL87PollInFlightAtLock`); the vault step of the deployment engine, L-80 to L-82 with a vault deployment (`TestL80L82WithAKeyVaultDeployment`, `TestL81KVDeploymentHeldThenConfirmed`) | `go test -tags integration -count=1 -cover ./internal/jobs/...` | ok | ok: `kvjobs` 100 %, `deployjobs` 99.3 %, `jobs` 89.2 % (floor 89) |
| 9 | API over the wire with the real provider and the fake service: journeys, F-40 to F-52, A-14, S-01 to S-05 with Azure canaries, license lock, held versions, imports sent once, clock skew | `go test -tags integration -count=1 -cover ./internal/api/...` | ok | ok, coverage 94.9 % (floor 93), 37 s; run by the controller at 6869f13 |
| 10 | Authorization matrix incl. `credentials.manage` and the conditional rules; error catalogue `ALC-AKV-0001`..`0040` with EN and TR texts that render with partial params | `go test ./internal/api ./internal/rbac -count=1` and `make authz-doc && git diff --exit-code docs/authz-matrix.md` | ok, no diff | ok, no diff (Task 17, fix round 1) |
| 11 | Release binary holds no e2e trust path, no fake and no dial seam; the fake's image reuses the pinned base images | `make release-symcheck`, `make image-check`, `go test ./internal/archtest/... ./cmd/...` | ok | ok (Task 19) |
| 12 | Web: Vitest; Playwright journeys EN/TR with axe on the e2e stack with the `fakeazure` service | `make web-coverage`; `make e2e-up && make e2e-hardening-check && make e2e`, then `make e2e-down` | all passed | Vitest: 68 files, 877 tests (Tasks 20–22, fix round 2). Playwright: Task 23 was running while this review was written |
| 13 | The optional real-Azure suite | `make test-azure` | — | **never run** (no subscription) |

Coverage recorded per task: `internal/platform/azureid` 100 %, `internal/providers` 100 %, `internal/providers/azurekv`
98.4 %, `internal/certs` 98.1 %, `internal/inventory` 89.2 %, `internal/jobs/kvjobs` 100 %, `internal/jobs/deployjobs`
99.3 %, `internal/jobs` 89.2 %, `internal/api` 94.9 %. `internal/jobs` and `internal/inventory` are close to their
floors.

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
[34]. The leak suite plants canaries (client secret, service-principal key, every sampled access token, the vault's
PFX and PEM secrets, the PFX files Alice sent on import, canaries in 403 bodies and malformed listings) and
searches DEBUG logs, every API answer and every table in text, hex and both base64 alphabets.

### Automatic deployment decisions

The poll only records; one planner decides from the database [20]. A version is deployed without a person only
if Alice detected it after automatic deployment was switched on, it is the current version, it is not held, and
its chain is complete [19], [43]. A version that appeared around a time the license gate was closed is held for an
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

## Findings

Found by the per-task reviews and fixed before the phase closed, with the commits. None was rated Critical by
its reviewer.

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
23. **Whether an import or a policy change moves `updated`** (decides when details are read again).
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
    key-less value (a PFX without a key, PEM with certificates only) is a guess. Any undecodable or key-less
    value maps to one closed reason, so a wrong guess changes no outcome. Check: by hand (step 2, then try).
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

- **Nothing was run against Azure.** See the section above. Key Vault Reader sufficiency (R22) is stated as
  "expected" in the role guide until the owner runs `make test-azure`.
- **Public cloud only; no HTTPS proxy and no custom CA bundle for Azure before Phase 7** [5], [7]. Managed
  identity only on an Azure virtual machine [4]. No deployment windows [31]; wave limits are fixed [20]; expiry
  emails for client secrets and keys wait for Phase 7 [27].
- **Listing bounds**: 5000 certificates, 5000 keys, 10,000 secrets, details of 100 certificates and 100 keys per
  poll [15]. A version Alice never saw as current cannot be deployed [17].
- **The access check never probes import** [28]. A deployment needs the vault reachable when it runs (no cached
  key). An `auth_failed` vault keeps being polled, at most hourly [12].
- **The import PFX uses 3DES and SHA-1 with an empty password**; no confidentiality is claimed for it [25].

Memory and logs:

- **The SDK keeps a client secret, and a secret value it read, as Go strings** for the session's lifetime; they
  cannot be zeroed. The same holds for the base64 text and request body of an import and for key objects parsed
  by go-pkcs12 and `crypto/x509`. MSAL's managed-identity token cache is process-global.
- **A code chosen by the vault reaches DEBUG logs** (`azure_code`, strict shape `^[A-Za-z][A-Za-z0-9]{0,63}$`).
- **`pkg/browser` and MSAL are linked** into the binary and never called [1].
- **Superseded credential rows are kept**, sealed, because `credentials` is append-only [9].

Network:

- **Loopback and shared (CGNAT) addresses are dialled for a vault name**, as `netaddr` allows them for every
  target (R39 item 8). TLS verifies the vault's name and no token leaves without it, so the exposure is a
  connection and a ClientHello to such an address; private endpoints need the private ranges.
- **Proven at unit level only**, not through the API suite's seam: a vault name that resolves to the metadata or
  a link-local address is refused; a private endpoint on a private address works; the environment proxy is
  ignored (a subprocess test); isolation between two vaults (F-44 "another vault is not delayed", F-50); the
  one-minute budget of the secret read (run once by hand by the Task 18 implementer: the job ended after
  1 m 0.03 s with no SSH; no permanent test). A 401 on a later page is covered over the wire but no provider
  mutant turns red (the retry is the SDK's own).
- **At most two polls run at a time, for all vaults together** [44]. Two slow vaults can delay a third, which
  F-44 says should not happen. Two dead poll jobs can pause polling for up to about two minutes (stated by the
  controller in the brief for this review; the figure is in no task report and no test names it).
- **The e2e stack does not switch managed identity off.** Its Alice container has network egress, so on an Azure
  virtual machine the real metadata service could answer and a real identity token would go to the fake, which
  the e2e build trusts. Do not run the e2e stack on an Azure virtual machine.

License holds:

- **False holds after a renewal out of grace.** `grace` counts as a closed state for "reopening", so a version
  created within about one poll interval before a license upload out of grace is held although changes were
  allowed. Accepted as fail-safe [41].
- **Rule (c) can hold for good.** In a vault whose certificate listing never completes after a reopening, every
  new version without a creation time stays held [41]. Theoretical; an Administrator releases them.
- **Hold rule (b) and planner eligibility trust Azure's `created`** and its relation to Alice's clock (item 25
  above).

Imports:

- **A crash between marking an import sent and sending it** leaves a false "Not confirmed yet"; it ends as
  "Outcome unknown" after 24 hours with a complete listing, or after 72 hours [40].
- **An uncertain import blocks its name** in that vault until it is settled or ended.

Email and interface:

- **No bound on emails across vaults.** The bound is 20 per kind, per vault and per run, then one summary [43].
  Many vaults renewing at once send many emails. No email is sent for the firewall case [12].
- **`autocomplete=off` on the secret fields may be ignored by a browser.**
- **The "New version found" chip is a heuristic** computed in the browser: created in Azure after Alice first saw
  the certificate and within 7 days [46].
- **Job rows carry no deployment or import ID** (see the open items).

Earlier phases:

- **`targets_endpoint_live`** (migration `00005`) still uses `lower()` under the database's collation. Vault host
  names are ASCII lower-case by a CHECK, so vaults are not affected; server host names under a Turkish collation
  are.

## Open items for the final fix wave

**TO UPDATE AT PHASE CLOSE:** the items below were collected by the controller for a final fix wave and were
**not done** when this review was written. Record for each the commit that fixed it, or move it to "Known
limitations" with the reason.

- A vault whose sealed credential cannot be opened fails a deployment with the generic `ALC-SYS-0003`. Planned: a
  closed "replace the vault's credentials" reason with its catalogue text.
- A policy switched to non-exportable without a new version is not noticed by a poll; the deployment ends at the
  read with `ALC-AKV-0016` instead of `ALC-AKV-0013`. Planned: the material step marks the certificate
  non-exportable when the read has no key, so the next attempt answers `0013` and the page shows "Monitor only".
- A vault's `last_error` does not return the poll-time params (`client_address`, `model`); they are only on a
  deployment's error and in the access check.
- `deployment_id` and `import_id` on job items (the held-jobs panel searches the server's deployments; a held
  import job has no link to its import). This also closes the Phase 4 carry "a deployment id on deploy jobs".
- Optional: a test that nothing outside tests assigns the request-secret zeroing observer.

**TO UPDATE AT PHASE CLOSE:** add the findings of the whole-branch final review and of the Playwright task
(Task 23) to the findings table, with their commits.

## Owner verification

Spec §26.7 "Owner verifies", extended by the actions this phase added. Steps 1 to 5 are the spec's. You need:

- An Azure subscription with a **test** vault (never a production vault) that uses Azure RBAC, in which you can
  create certificates and assign roles; an app registration with a client secret (and, for step 6, one with a
  certificate; a virtual machine with a managed identity if you have one).
- A development stack on the Alice machine, signed in as an administrator, with the evaluation started, and the
  disposable Nginx test server of the Phase 4 walkthrough with one website.
- In the test vault: a self-signed certificate `web-cert` with an exportable key and a short lifetime, and one
  certificate created with a non-exportable key.

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
| Real-Azure suite (`make test-azure`) | | |
| Reader sufficiency (R22) | | |
| Turkish tone review | | |
| Crypto sign-off | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
