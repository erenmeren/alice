# Phase 5: Azure Key Vault — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An administrator adds an Azure Key Vault by its address with a service principal (certificate or client secret) or a managed identity; Alice checks at once that it can sign in and reach the vault (a wrong name or a refused sign-in creates nothing and uses no license slot), shows which of the three roles it holds (monitor, deploy, import) with copy-paste `az role assignment create` commands, and lists the vault's certificates (with their versions and expiry, "Monitor only" when the private key is not exportable), keys and secret metadata. Alice polls every vault (every 15 minutes by default), detects a new certificate version by its version ID and X.509 thumbprint, and — for a vault certificate an Operator connected ("bound") to Nginx websites with auto-deploy turned on by an Administrator — deploys the new version to every bound website through the Phase 4 deployment engine, reading the private key from the certificate's backing secret only inside the deployment job, in memory, never storing it. A failing server rolls back alone; others continue; three failures stop the wave. People can also import a certificate held in Alice into a vault. Every Azure failure (wrong secret, expired secret, missing role, firewall, unknown vault, throttling, an unreachable token endpoint, a malformed answer) becomes a plain-language message with an `ALC-AKV-*` code and never a crash loop; no client secret, token or private key ever reaches a log, an answer, the audit log or the database in clear.

**Architecture:** A new provider `internal/providers/azurekv` wraps the official Azure SDK for Go (`azcore`, `azidentity`, `azcertificates`, `azkeys`, `azsecrets`) behind a small internal `kvAPI` interface, with Alice's own HTTP transport underneath every SDK call: a per-session host allow-list (`login.microsoftonline.com` and the vault's own `<name>.vault.azure.net`, plus — for a managed identity only — the fixed instance metadata endpoint `169.254.169.254:80`), the connect-time address rule of `internal/platform/netaddr`, no redirects, no environment proxy, bounded response bodies; the SDK's own retry is off and Alice's single retry loop (clock-injected, `Retry-After` honoured, at most 5 attempts per call) and a per-vault limiter (5 requests/s, 4 at once) sit on top. A pure package `internal/platform/azureid` holds the identifiers both inventory and the provider check (vault address, tenant and client IDs, object names, versions, thumbprints). The provider framework gains the Azure identity source, the Key Vault half of discovery, `ReadCertificateSecret` and `ImportCertificate`. `internal/certs` decodes a vault secret (PFX or PEM), parses a service-principal certificate and builds the PFX of an import. Migration `00008` adds vault credentials bound to their vault, the vault inventory (`kv_certificates`, `kv_certificate_versions`, `kv_keys`, `kv_secrets`), `bindings`, the Key Vault source of a deployment and `kv_imports`. Inventory adds vaults (with a synchronous pre-flight check), the vault reconciliation, bindings, Key Vault deployments and their material, the auto-deploy planner and imports. A new job package `internal/jobs/kvjobs` runs `kv.test_connection`, `kv.poll` and `certificate.import_to_kv`; two periodic tasks schedule polls (`kv.schedule`) and plan auto-deploys (`kv.auto_deploy`); the Phase 4 `certificate.deploy` handler gains one step before any SSH: read and check the vault secret. The API adds vault, inventory, binding, import and cross-server location routes; the SPA adds **Key Vaults**, the vault and vault-certificate pages, the binding and import dialogs. Tests never need Azure: an in-process fake of the Key Vault data plane, the Entra ID token endpoint and the instance metadata service (`internal/testutil/fakekv`), whose answers follow the public REST reference shapes committed in `test/testdata/kv-recordings/`, drives the Go suites; the same fake runs as a container (`alice-fakeazure`) in the e2e stack; an optional real-Azure contract suite (`-tags azure`, environment variables) never runs in CI.

**Tech Stack:** Go 1.27.1; new runtime modules (pinned, `go mod verify`): `github.com/Azure/azure-sdk-for-go/sdk/azcore` v1.23.2, `.../sdk/azidentity` v1.14.1, `.../sdk/security/keyvault/azcertificates` v1.5.0, `.../azkeys` v1.5.0, `.../azsecrets` v1.5.0 (they bring `sdk/internal` v1.12.0, `sdk/security/keyvault/internal` v1.2.0, `github.com/AzureAD/microsoft-authentication-library-for-go` v1.8.0, `github.com/golang-jwt/jwt/v5` v5.3.1, `github.com/kylelemons/godebug` v1.1.0, `github.com/pkg/browser` v0.0.0-20240102092130-5ac0b6a4141c, `golang.org/x/net` v0.58.0, `golang.org/x/sync` v0.22.0; all resolved and built in a scratch module while writing this plan); `software.sslmate.com/src/go-pkcs12` v0.7.3 (already present); pgx v5, goose v3, testify, testcontainers-go v0.44; React 18 + TypeScript 6 + Vite 8, Mantine 8, React Router 7, TanStack Query 5, i18next, Vitest 5 + Testing Library + msw 2, Playwright 1.63 + axe-core. No new web dependency.

**Spec:** `docs/superpowers/specs/alice-v1/` — `00-decisions.md` ("Azure Key Vault only (v1)", Security, R9, R22, R23, R24, R29, R33, R36 item 6, R37, R38 (all of it: the deployment engine this phase reuses), R39 (all of it: the gate, refusal rows, connect-time addresses, supply chain)), `01-product.md` S2 AC1–AC2, S5 (all), S8 AC3/AC6, S10, §3.1, §3.2, `02-architecture.md` §5.2–§5.4 (dependency budget), §6 (provider interface, capabilities, registry, the checklist of §6.5), §7.2 (`credentials`), §7.3 (`targets`, `certificates`, `certificate_locations`, `bindings`, `certificate_versions`), §7.4 (`deployments`), §8 (job types `kv.poll`, `certificate.import_to_kv`, retries, concurrency, lock gating, crash recovery), §9 (conventions, errors, endpoint groups `keyvault`, `certificates`), `03-integrations.md` §11 (all of it), §12.5, §12.6 (Phase 4 note), §12.7, §12.9 ("Bound KV version rolled back"), `04-security.md` threat rows AZ-1..AZ-4, SEC-037, SEC-040..SEC-047, SEC-062, SEC-065, SEC-083, SEC-101, §17 (Phase 5 gate), `05-operations.md` §19 network table, §21 docs list (`docs/azure-setup.md`), `06-quality.md` §22.1, §22.5 (fake Key Vault, optional real Azure suite), §22.6, §23.4 (L-26, L-29), §23.8 (L-81, L-87), §24.3 (F-40..F-52), §25.2 (S-01..S-05), §25.4 (A-14), §25.6, §26.1, §26.7. `00-decisions.md` wins on conflict; this plan proposes **R40** (written in Task 24) for the conflicts listed under "Spec conflicts resolved by this plan". Carry sources: `docs/superpowers/rulings/phase-4.md` ("Parked / carried to Phase 5"), `docs/superpowers/rulings/audit-remediation.md` ("Parked / carried forward"), `docs/security/reviews/phase-4.md` and `docs/security/reviews/audit-remediation.md` ("Known limitations"). Style reference: `docs/superpowers/plans/2026-10-03-phase-4-nginx-certificates.md`.

**Plan verification:** written against branch `phase-5` at `8f15b80` (= `master`: Phases 0–4 and the audit remediation merged). Every existing path, symbol, route, Make target and command a task uses was checked with `grep`/`sed` in that tree, among them: `providers.{Session,UnsupportedSession,Provider,CredentialSource,Env,TargetRef,TargetConfig,Kind,KindAzureKV,KindForTargetType,Capability,CapDiscoverKVKeys,CapDiscoverKVSecrets,CapImportCertificate,knownCapabilities,DiscoverRequest,DiscoveryResult,ConnectionReport,Warning,StepLogger,Error,NewError,ErrUnsupported,ConnectionCache,DeployRequest.Format/LogValue}`, `providers/outcome.go` (`Validate`, `CheckDeployReturn`, `forbid`, `require`), `providertest.{CheckProvider,CheckUnsupported,SessionHarness,CheckSession,CheckNoSecrets,sessionOps}`, `fake.{Config,Provider,New,session}` (it does not embed `UnsupportedSession`), `secrets.{Plaintext,NewPlaintext,Keyring.Seal,Keyring.Open,Location,Envelope}`, `certs.{Upload,Validated,Parsed,KeyInfo,ValidateUpload,KeyInfoOf,KeyPEM,ParseChainPEM,ChainComplete,SystemRoots,Err*}`, `pki.{NewCA,CA.Issue,Opts,Leaf,KeyType,ECDSA256,RSA2048,PFX,Fingerprint,SelfSigned}`, `netaddr.{Allowed,Control,DialContext,ErrNotAllowed}`, `clock.{Clock,Real,Fake}`, `validate.{FieldError,Errors,Required,Pattern,TooLong,OneOf,OutOfRange,Duplicate}`, `audit.{Event,SystemActor,Success,Failure,Denied,Log.Append,sensitiveSegments}`, `license.{Class,ClassAlways,ClassReadOnly,ClassChange,ErrLocked,DenialReason}`, `inventory.{Service,Config,Actor,Target,Facts,NewTarget,TargetPatch,targetConfig,targetColumns,scanTarget,getTarget,CreateTarget,insertTarget,UpdateTarget,DeleteTarget,RequestTest,RequestDiscovery,requestJob,TargetRef,ScheduleDiscovery,markConnected,statusAfterSuccess,reasonRE,EnsurePlatformKey,Credentials,platformCredentials,credentialLocation,RequestDeployment,DeployRequestInput,RequestedDeployment,lockDeployTargets,checkDeployLocation,insertDeployment,deployCertificate,deployLocation,targetReady,DeploymentMaterial,Material,SendValues,certificateKeyPEM,Deployment,FinishDeployment,JobRequest,Enqueuer,WithClaim,Claim,ErrClaimLost,Notifier,Templates,detachedTimeout,auditLicenseDenial,refreshLicense,Status*,Type*,Job*}`, `jobs.{Register,Type,Types,Job,View,HandlerFunc,StepRecorder,Retry,Fail,Attention,FromProvider,MaxAttemptsFor,AlertsWhenExhausted,Task,Scheduler,NewScheduler,RunNow,Runner.Handle,Runner.Handles,Kind*,Status*}`, `targetjobs.{Register,Deps,Inventory,handlers.open,retestFailure}`, `deployjobs.{Register,Deps,Inventory,handlers.first,beforeSend,refuse,follow}`, `api.{route,server.apiRoutes,targetRoutes,certificateRoutes,locationRoutes,deploymentRoutes,ErrorCode,AllErrorCodes,codeForReason,errorMap,providerParamRules,providerParamKeys,writeErrorWith,fail,actor,ifMatch,etag}`, `rbac.{Permission,Policy,policies,TargetsManage,InventoryOperate,CertificatesOperate,JobsConfirm,Admin,Operator,Auditor,ScopeOperate,ScopeRead}`, `migrations/roles_integration_test.go` (`explicitGrants`, `explicitColumnGrants`), `internal/archtest/arch_test.go` (`rules`, `denied`, `TestAllowed` — it already names `alice/internal/providers/azurekv`), `cmd/alice/{providers.go:registerProviders,wiring.go:shippedProviders,periodicTypes,checkWiring,services.go:buildServices,buildRunner,buildScheduler,deployDeps,targetDeps,testapi_e2e.go:sweepEvery,startJobWorkers,testapi_release.go,compose_test.go:TestE2ETargetIsTestOnlyAndUnpublished}`, `deploy/docker-compose.e2e.yml`, `deploy/dev/check-hardening.sh`, `test/images/e2e-target/`, the web `AddServerModal`, `TargetsPage`, `TargetDetailPage`, `CertificateDetailPage`, `DeploymentsPage`, `AppLayout` (`nav.servers`), `api/endpoints.ts` (`listAllTargets`, `listCertificates`, `listDeployments`), `api/queryKeys.ts`, `api/jobs.ts` (`waitForJob`), `components/StepUpProvider.tsx`, the e2e helpers (`targetExec`, `drainJobs`, `drainUntil`, `runScheduled`, `served`, `newCert`, `expectAccessible`, `apiAs`, `COPY`), and the Make targets `test`, `test-integration`, `lint`, `vuln`, `build`, `release-symcheck`, `image-check`, `e2e-up`, `e2e`, `e2e-down`, `e2e-hardening-check`, `authz-doc`, `i18n-check`, `web-test`, `web-coverage`, `coverage`, `fuzz-certs`, `secrets-scan`, `ci`. The Azure SDK identifiers the sketches use were read from the module cache at the versions above: `azidentity.{NewClientSecretCredential,ClientSecretCredentialOptions,NewClientCertificateCredential,ClientCertificateCredentialOptions,NewManagedIdentityCredential,ManagedIdentityCredentialOptions,ClientID,AuthenticationFailedError}` (both SP options have `DisableInstanceDiscovery`; MSAL accepts only RSA certificate keys and signs PS256 with `x5t#S256`), `azcore.{ClientOptions,TokenCredential,AccessToken,ResponseError}`, `policy.{Transporter,RetryOptions,TelemetryOptions,TokenRequestOptions}` (`RetryOptions.MaxRetries < 0` = one try), `cloud.AzurePublic`, `azcertificates.{NewClient,ClientOptions (DisableChallengeResourceVerification),Client.NewListCertificatePropertiesPager,NewListCertificatePropertiesVersionsPager,GetCertificate,ImportCertificate,ImportCertificateParameters,Certificate,CertificateProperties,CertificateAttributes,CertificatePolicy,KeyProperties,SecretProperties,ID.Name,ID.Version}` (api-version `2025-07-01`, no page-size option), `azkeys.{Client.NewListKeyPropertiesPager,GetKey,KeyProperties,JSONWebKey}` (a listing carries no key type or size), `azsecrets.{Client.GetSecret,NewListSecretPropertiesPager,Secret,SecretProperties}`; `pkcs12.LegacyDES.Encode(key, leaf, chain, "")` round-trips with `pkcs12.DecodeChain(pfx, "")` (checked). Compiled while writing, in a scratch copy of `8f15b80` with the SDK modules added: Task 1's code and tests (pass, 100 % coverage); Task 2's provider types, `ImportResult` rules and the `Session` change (`go build ./...`, `go vet ./...` and `go vet -tags integration ./...` pass once `fake.session` has the two methods — no other `Session` implementation breaks); Task 3's `ParseKVSecret`; Task 6's `guardedTransport`, `newCredential` and `kvAPI`; the SDK calls of Tasks 5 and 8 (credential options, pagers, `GetCertificate` policy fields, `ImportCertificateParameters` with `to.Ptr`, `GetSecret`). The rest of the plan has **not** been compiled: before Task 1 the controller runs the pre-flight scan earlier phases used (apply each task's code in a scratch worktree and compile it); every task's red/green steps are the real check. Where a sketch says "mirror" or names a grep, the implementer reads the code named before writing.

## Global Constraints

- Go module path is `alice`; toolchain `go 1.27.1`. Every shell step assumes `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"` and the repository root as working directory.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `tr.json` files.
- **Commits:** Conventional Commits, made with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "<message>" -- <paths>` (`-m` before `--`: after it, `-m` is read as a path; several agents share one working tree and one git index: stage new files with `git add -- <paths>` and commit **only** your paths; never `git add -A`, `git add .`, `git commit -a` or a bare `git commit`), the message ending with a `Co-Authored-By:` line that names the model that wrote the commit (for this model: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Never squash, rebase or amend: `.gitleaksignore` is pinned to commit hashes, so the branch merges into `master` fast-forward only.
- **Never add** `docs/security/reviews/independent-audit-2026-10-04.md`, `docs/security/reviews/independent-audit-2026-10-04-poc/` or `.claude/`.
- **Docker safety:** the owner's live compose project `alice` (image `alice:dev`, volumes `alice_*`) is never touched: no `make up`, `make down`, `make reset`, `make logs`, `make setup-token`, `make unlock`, `make hardening-check`, no `docker compose` without `-p alice-e2e`, no `docker system/volume/image prune`, no `docker rm` of containers you did not create. Allowed: testcontainers (integration tests), `docker run --rm` throwaway containers, `docker create`/`docker cp`/`docker rm` of a container created from `alice:ci` in the same step, and the e2e project `alice-e2e` (`make e2e-up`, `make e2e`, `make e2e-down`, port 127.0.0.1:9443). **Never run Docker test containers (integration tests, `make test-ssh`) while Playwright runs**: Chromium aborts requests whenever a host network interface changes. Every step that runs Docker says so.
- **Secrets in the repository:** no private key, certificate, password, client secret or token is committed. Certificates, keys and PFX files come from `internal/testutil/pki` at test time; the fake Azure service generates its CA, its vault certificates and its application's client secret when it starts; fake client secrets in Go tests are generated (`fakekv.NewClientSecret()`: `"fake-" + 40 random hex characters`); access tokens are built at run time and never written as literals (a JWT literal matches gitleaks' `jwt` rule); strings that look like PEM private-key markers are built at run time (`"-----BEGIN " + "PRIVATE KEY-----"`), as Phases 3–4 did. The recorded response shapes in `test/testdata/kv-recordings/` hold placeholders (`"<cer>"`, `"<value>"`, `"<x5t>"`), never real or fake key material. If `make secrets-scan` still flags a file, add the finding to `.gitleaksignore` with the new commit hash in the same task.
- **Supply chain (R39 item 9):** every new build input is pinned: Go modules by exact version in `go.mod` with `go.sum` (`go mod verify` must pass), Docker images by `tag@sha256:` index digest (reuse the digests already in `deploy/Dockerfile` and `test/images/e2e-target/Dockerfile`; no new base image), no new GitHub Action. `go run ./tools/pincheck` must pass. The new Go modules are justified in `docs/dev/dependency-updates.md` (SEC-101) in the task that adds them.
- Code blocks are gofmt-clean except for column alignment of consecutive one-line declarations and struct fields: run `gofmt -w` (or `make lint`) on every changed Go file before committing.
- Tests: Go stdlib `testing` plus testify `require`/`assert` only; small hand fakes, no mock frameworks. Integration tests carry `//go:build integration`, call `pgtest.Main` from `TestMain` and get a fresh database per test from `pgtest.New(t)` (pools `Owner` and `App`; the application always uses `App`). A red step in a brand-new package may fail with "no non-test Go files"; that is the expected failure. The optional real-Azure suite carries `//go:build azure` and skips unless its environment variables are set; it never runs in `make test`, `make coverage` or `make ci`.
- Build tags: `integration`, `e2e`, `testlicense`, `releasecheck`, and the new `azure` (real-Azure suite only). Release images are built with no tag; the e2e image with `e2e testlicense`.
- Lint is golangci-lint v2 (`make lint`): gosec, errorlint, forbidigo, bodyclose, misspell, noctx, gofmt, goimports (`local-prefixes: alice`). Forbidden: `fmt.Print*`, `strings.ToUpper`/`ToLower`/`Title` (use ASCII folding), `time.Now` outside `internal/platform/clock` and tests (use the injected clock; the provider waits with `Env.Clock.After`), `ssh.InsecureIgnoreHostKey`. `InsecureSkipVerify` stays allowed only in `helperproto.ProbeTLSConfig` (the Phase 4 grep test keeps failing on any other use). No `//nolint` without a reason.
- **Module import rules** (`internal/archtest`): Phase 5 adds no rule key. `alice/internal/platform/azureid` is under `platform/...` (allowed everywhere, imports nothing of Alice). `internal/providers/azurekv` imports only `providers`, `platform/...` and third-party modules (the existing `providers/...` rule; it may **not** import `internal/certs` or `internal/secrets`: it gets `secrets.Plaintext` values only through `providers` types and `providers.NewSecret`). `internal/jobs/kvjobs` imports `jobs`, `inventory`, `providers`, `platform/...` (the `jobs/...` rule). `internal/testutil/fakekv` imports `platform/...` and `internal/testutil/pki` (the `testutil/...` rule; never `providers`). Only `cmd/*` imports `internal/providers/azurekv` in non-test code (integration tests of `inventory`, `jobs/...` and `api` register it in their harness, which archtest allows: it governs non-test imports); `cmd/alice-fakeazure` (test tool, e2e image only, listed in archtest's `testOnlyDirs`) imports `fakekv`. `TestAllowed` gets the new positive and negative cases in Task 6.
- **Outbound rule (security-critical, SEC-065, A-14):** every HTTP request the `azurekv` provider (and through it the SDK) sends goes through `guardedTransport` (Task 6): scheme `https`, host and port exactly `login.microsoftonline.com:443` or the session's own vault host `:443`; for a managed identity's token request only, `http://169.254.169.254:80` through a separate transport whose dialer accepts that one address; every other request, a redirect, a `nextLink` or challenge pointing elsewhere, and a connection to an address `netaddr.Allowed` refuses (except that one IMDS address) fail with a closed provider error before anything is sent. `http.Transport.Proxy` is `nil` (no environment proxy). No `DefaultAzureCredential`, no environment, CLI, device-code, interactive-browser, workload-identity or pipelines credential, no persistent token cache, no SDK log listener: `TestAzureSDKSurface` (Task 6) greps the repository and fails on any of them.
- **Secret rule (security-critical, SEC-040..SEC-047, SEC-083, §11.5 item 6):** client secrets, service-principal private keys and vault secret values live only in `secrets.Plaintext` holders (or the SDK credential object of one session) and are zeroed by their owner after use; they are sealed in `credentials` (AAD `credentials/<id>/ciphertext`, the Phase 3 envelope) and never returned by the API; a vault secret value is never stored at all; access tokens live only inside the SDK credential of one session (in memory) and are decoded only to read the `oid` claim for display. Provider errors carry closed codes and allowlisted params; the text of an SDK, MSAL or HTTP error is never logged, stored, audited or returned (only its Go type is logged, and an Azure `x-ms-request-id` and error code are kept when they match their strict shapes).
- No SQL string building (SEC-060). SQL time comes from the injected clock as a bind parameter. `alice_app` gets explicit grants for every new table and column; the grant guard (`migrations/roles_integration_test.go`) lists every non-default and column-level grant set.
- API JSON conventions from Phase 1 (snake_case, UTC RFC 3339, error body `code`, `reason`, `message_key`, `message`, `request_id`, `retryable`, `params`, `details`; lists `{items, next_cursor}`); every new code `ALC-<AREA>-<NNNN>` has `errors.<reason>.title|cause|action` in `locales/common/{en,tr}.json`, a section in `docs/troubleshooting.md` and an entry wherever its neighbours are listed (enforced by `internal/api/errors_test.go` and `errors_catalogue_test.go`). Every new route is in the route table with a permission and (for non-GET methods) a license class, in `api/openapi.yaml` with the same `x-permission`, in `docs/authz-matrix.md` (`make authz-doc`) and in the authz tests. Long operations answer `202` with job ids.
- Audit detail keys pass the denylist of `internal/audit/audit.go` (`sensitiveSegments`: `password`, `passphrase`, `secret`, `private`, `token`, `code`, `totp`, `otp`, `key`, `dek`, `credential`, `cookie`, `session` segments are refused unless the key ends in `id`, `prefix` or `count`): this plan uses `vault_url`, `auth`, `tenant_id`, `client_id`, `kv_certificate_id`, `certificate_name`, `version`, `thumbprint`, `fingerprint`, `deployment_id`, `binding_id`, `import_id`, `purpose`, `reason`, `location_count`, `failed_count`, `held`; never `secret_*`, `key_*` or `credential_*`.
- i18n: every user-visible string is a key in English and Turkish (`make i18n-check`); placeholders `{{name}}` without spaces; no sentence assembly; no suffix attached to a placeholder (rephrase as "Label: {{value}}"); formal-polite Turkish ("siz"); plural forms `_one`/`_other`. Terminology (fixed for EN and TR, used by every task): **Key Vault** (product name, unchanged in Turkish: "Key Vault"), **vault** / "kasa", **Key Vaults** (navigation) / "Key Vault kasaları", **Check now** / "Şimdi denetle" (a manual poll), **Access check** / "Erişim denetimi", **Monitor only** / "Yalnızca izleme", **Connect websites** / "Web sitelerine bağla", **Connected websites** / "Bağlı web siteleri" (a binding), **Automatic deployment** / "Otomatik dağıtım", **Deploy now** / "Şimdi dağıt", **Import into Key Vault** / "Key Vault'a aktar", **New version found** / "Yeni sürüm bulundu", **Sign-in method** / "Oturum açma yöntemi", **Client secret** / "İstemci gizli anahtarı", **Certificate (recommended)** / "Sertifika (önerilir)", **Managed identity** / "Yönetilen kimlik". Azure role names (`Key Vault Reader`, `Key Vault Secrets User`, `Key Vault Certificates Officer`) are never translated and are rendered in `<Code>`. The "UI copy" table of the contract is exact and is what the Vitest and Playwright tests match.
- Accessibility: new screens and dialogs have no serious or critical axe violation at 640, 1280 and 1920 px (`expectAccessible`) and at 375 px for the Key Vaults list and the vault pages (tables scroll inside their own container), in English and Turkish, keyboard usable, no horizontal page scroll.
- Frontend: no `dangerouslySetInnerHTML`, no `toUpperCase`/`toLowerCase`; vault addresses, IDs, version IDs, thumbprints, fingerprints, role names, `az` commands and paths are rendered with `<Code>`/monospace, never translated or case-transformed, always as text (A-11).
- Coverage floors in `coverage-floors.json` are **never lowered**; new packages get floors (Task 24): `internal/platform/azureid` 100 (pure), `internal/providers/azurekv` and `internal/jobs/kvjobs` at their measured values rounded down; `internal/providers` stays at 100 and `internal/jobs/deployjobs` at 99, so every new branch there needs a test. Test tools (`internal/testutil/fakekv`, `cmd/alice-fakeazure`) get no floor, as `pki` and `pgtest` have none.

## Review Focus

1. **Where Alice's HTTP requests go** — a vault address typed as `http://contoso.vault.azure.net`, `https://contoso.vault.azure.net:8443`, `https://contoso.vault.azure.net.evil.test`, `https://contoso.vault.azure.net/secrets`, `contoso.vault.usgovcloudapi.net`; a vault (or a DNS answer) that sends a `nextLink` or a challenge `authorization` to another host, a `302` to `169.254.169.254`, a vault name resolving to `169.254.169.254` or `fe80::1`; a private endpoint resolving to `10.1.2.3`; a container with `IDENTITY_ENDPOINT` set; an `HTTPS_PROXY` in the environment. Expected: the first five are refused when typed (`validation.pattern` on `vault_url`); no request ever leaves for a host other than `login.microsoftonline.com` and the vault's own host (`azure.address_not_allowed` / `azure.unexpected_response`, nothing sent to the other host — the fake's request log proves it); the private endpoint works; the managed identity talks only to `169.254.169.254:80` and fails closed with `azure.managed_identity_unavailable` when the SDK picks another source; the proxy variable is ignored. Tests: Task 1 (`TestParseVaultTable`), Task 6 (`TestGuardedTransportRefusesOtherHosts`, `TestRedirectIsNeverFollowed`, `TestForeignNextLinkIsRefused`, `TestManagedIdentityTalksOnlyToIMDS`, `TestProxyEnvironmentIsIgnored`, `TestDialRefusesMetadataAddress`), Task 18 (`TestA14KeyVaultSSRF`).
2. **Secrets that must never leak** — a client secret, a service-principal private key, an access token, a vault secret (PFX and PEM), a 403 body that echoes a canary, a malformed answer containing a canary, an import's PFX. Expected: none of them in logs (DEBUG), API answers, job results and errors, audit details, deployment steps or the database (credentials only as AES-GCM envelopes, vault secrets nowhere), whatever the error path. Tests: Task 2 (`TestAzureIdentityNeverPrints`), Task 6 (`TestMapErrorTable`: no Azure text in any rendering), Task 8 (`TestConformanceAgainstTheFake` with secrets), Task 18 (`TestSecretLeakSuiteWithAzureCanaries` S-01..S-05).
3. **Renewal to deployment under failure** — Key Vault renews `web-cert`; three websites on two servers are bound; one server's reload fails; the role `Key Vault Secrets User` is removed; a second renewal arrives while the first deployment runs; the version is disabled, expired, not yet valid, older than the deployed one; the license locks during a poll. Expected: one deployment per website, the failing one rolled back alone, the others succeed; F-41 ends "Alice needs the Key Vault Secrets User role" before any SSH with the website unchanged; the second renewal coalesces to the newest version without parallel deployments; a location is retried at most three times, one hour apart, and three failures of a version stop the wave with one email; skipped versions email once and never deploy; a version detected in lock is held for an Administrator. Tests: Task 13 (`TestAutoDeployPlanTable`), Task 16 (`TestKVDeploymentReadsTheSecretBeforeAnySSH`, `TestF41MissingSecretsRoleChangesNothing`), Task 18 (`TestKeyVaultFailureCatalogue` rows F-46..F-48), Task 15 (`TestL87PollInFlightAtLock`).
4. **Azure errors as Azure sends them** — `AADSTS7000215` (wrong secret), `AADSTS700016` (unknown application), `AADSTS90002` (unknown tenant), `AADSTS7000222` (expired secret), `AADSTS700027` (unregistered certificate), `AADSTS700024` (clock), 403 `ForbiddenByRbac`, 403 `ForbiddenByPolicy`, 403 `ForbiddenByFirewall` with "Client address: 203.0.113.7", 404 `CertificateNotFound`, DNS `NXDOMAIN` for the vault, a dead token endpoint, 429 with `Retry-After: 7`, 429 without it, 503, malformed JSON, a truncated body. Expected: each maps to exactly one closed reason with the right params; throttling is retried within the cycle and degrades the vault only after three cycles; nothing crash-loops (the next poll is delayed, interval × 2 capped at an hour); the vault's status and the plain-language text match spec §11.9. Tests: Task 6 (`TestMapErrorTable`, `TestRetryLoop`), Task 11 (`TestKVFailureTransitions`), Task 18 (`TestKeyVaultFailureCatalogue` F-40..F-52).
5. **Imports** — a new name, an existing name without confirmation, an existing name with confirmation, an import whose answer is lost after it reached the vault, a vault without `Key Vault Certificates Officer`. Expected: the new name creates version 1; the existing name is refused until confirmed and then adds a version (auto-deploy may follow); a lost answer is never re-sent: the import stays **Not confirmed yet** until a poll sees its thumbprint (then **Imported**) or 24 hours pass (**Outcome unknown**, `ALC-AKV-0026`); the missing role is `ALC-AKV-0003` with role `Key Vault Certificates Officer`, nothing created. Tests: Task 14 (`TestImportStateMachine`), Task 15 (`TestImportJobNeverResends`), Task 18 (`TestImportJourney`).

---
## Spec conflicts resolved by this plan (proposed R40, written in Task 24)

Each row: the conflict, the decision, why, and the cost if the decision is wrong. Task 24 writes them, corrected to the built code, as **R40** in `00-decisions.md`.

| # | Conflict | Decision | Why | Cost if wrong |
|---|---|---|---|---|
| 1 | §11.2 mandates the official Azure SDK; the repository's supply-chain policy (SEC-101, R39 item 9) and the request to keep outbound traffic under Alice's control favour a small hand-written REST client | The official SDK: `azcore` v1.23.2, `azidentity` v1.14.1, `azcertificates`/`azkeys`/`azsecrets` v1.5.0, wrapped behind the internal `kvAPI` interface; Alice supplies the transport (`policy.Transporter`), turns the SDK's retry and telemetry off, disables Entra instance discovery and never sets a log listener | No Azure subscription is available to anyone building or reviewing this phase: with the SDK, the protocol details that only real Azure can confirm (token audience, client-assertion claims, the Key Vault challenge, paging, JSON models) are Microsoft's tested code, and the fake only has to satisfy that client; a hand-written client would be verified only against a fake written from the same reading of the documentation. The transport keeps every request under Alice's rules (row 8) | Thirteen modules more to watch (`govulncheck`, Dependabot), including MSAL, `golang-jwt` and `pkg/browser` (linked by `azidentity`, never called: `TestAzureSDKSurface`); SDK updates can change behaviour under the fake |
| 2 | §22.5 fake on `api-version=7.5` | The fake answers the API version the pinned SDK sends (`2025-07-01`) and refuses any other with the real error shape | The SDK fixes the version in its generated code; a fake on another version would test nothing the product sends | A future SDK update changes the version; the fake's version check fails loudly (intended) |
| 3 | §11.2 "SDK default retry stays enabled, Alice adds its own backoff for 429", §11.6 "max 6 attempts", F-44 "max 5 attempts per cycle" | One retry loop, Alice's: `RetryOptions.MaxRetries = -1` in the SDK; per call at most **5 attempts**; a `Retry-After` (seconds or HTTP date) is honoured up to 5 minutes (a longer one ends the cycle); otherwise 5, 10, 20, 40 s with full jitter; each try bounded by 30 s; retried: 408, 429, 500, 502, 503, 504, connection failures, timeouts, malformed or truncated bodies (F-52); waits use the injected clock | Two stacked retry policies multiply attempts (4 × 6) and wait with the SDK's real-time sleeps, which a fake clock cannot drive; F-44 is the stricter, testable statement | A long Azure throttling episode degrades a vault one cycle earlier than a doubled policy would |
| 4 | §11.3 and §26.7 deliver Managed Identity; SEC-065 and R39 item 8 refuse link-local addresses (169.254.169.254) "unless explicitly allowed"; `azidentity` picks its managed-identity source from environment variables | Managed Identity is supported for the Azure VM case only: its token request goes to the fixed instance metadata endpoint `http://169.254.169.254:80` through a separate transport whose dialer accepts exactly that address; this is the explicit, code-fixed allowance of SEC-065 (no setting); vault requests still refuse link-local; if `azidentity` picks another source (App Service, Arc, Cloud Shell variables in the environment) the transport refuses its host and the vault reads `azure.managed_identity_unavailable` | The spec delivers the feature and names the risk; a constant endpoint chosen by Alice is not an admin- or attacker-supplied address, which is what SEC-065 guards | Alice on App Service or Arc cannot use a managed identity (documented); a future SDK that changes the IMDS address breaks managed identity until the constant is updated |
| 5 | §11.1 "vaults added by URL" with no grammar; §25.4 A-14 "KV URL must match `*.vault.azure.net`" | `azureid.ParseVault`: accepts `name`, `name.vault.azure.net` or `https://name.vault.azure.net` (optional final `/`, any ASCII letter case) and nothing else; the name follows Azure's rule (3–24 characters, starts with a letter, letters, digits and single hyphens, no final hyphen); stored lower-case as `https://<name>.vault.azure.net` with `host` and `port: 443` in `targets.config`, so the Phase 3 unique index keeps one live target per vault; sovereign clouds and Managed HSM are refused | Public cloud only (§11.1, §11.10); a strict grammar is the SSRF boundary; reusing `host`/`port` reuses the duplicate check | A customer on a sovereign cloud cannot add a vault (spec-deferred) |
| 6 | §11.3 stores "tenant ID, client ID" without a format | Tenant and client IDs are GUIDs only (stored lower-case); a tenant domain such as `contoso.onmicrosoft.com` is refused with a hint to paste the Directory (tenant) ID | The tenant becomes a path segment of the authority URL; a GUID cannot carry `/`, `?` or `..` | An administrator must look up the GUID (the guide says where) |
| 7 | §11.2 "the container passes `HTTPS_PROXY` through if the admin sets it in `settings`"; SEC-037 "optional admin-provided CA bundle" for Azure | Not in Phase 5: Azure connections are direct, `Proxy: nil`, system roots only; both arrive with the Settings page (Phase 7) | `settings` has no admin UI before Phase 7; an environment proxy would bypass the connect-time address rule silently | Networks that force all HTTPS through an inspecting proxy cannot use Key Vault until Phase 7 (documented limitation; private endpoints work) |
| 8 | §11.2 lists no outbound restrictions; SEC-065 and R39 item 8 apply to managed servers | Per-session host allow-list (`login.microsoftonline.com:443`, the vault host `:443`, IMDS for a managed identity only), `netaddr.DialContext` on every connection, redirects never followed (`http.ErrUseLastResponse`, the 3xx is an error), `nextLink`s and challenges to other hosts refused, response bodies capped at 4 MiB, header bytes at 64 KiB | A-14; the SDK follows `nextLink` URLs from the response, so the server decides where the next request goes unless the transport refuses | None known; a vault answer bigger than 4 MiB (a page of 25 items is a few kilobytes) would read as malformed |
| 9 | §7.2 `credentials.target_id` "unique per target purpose"; R37 item 11 "append-only for `alice_app`"; replacing an expired secret (F-49 "points to the credentials screen") | Purpose `azure_vault`; `credentials.target_id` (a deferrable foreign key, set in the transaction that creates the vault); a replacement is a new credential row plus `targets.credential_id` moved to it (new column grant), so credentials stay append-only; the source refuses a credential whose `target_id` is not the vault being opened; envelope and AAD as the platform key (`credentials/<id>/ciphertext`) | Keeps R37's append-only property and gives "unique per target" without UPDATE on credentials | Replaced credentials stay sealed in the table (as cancelled signing-request keys do) |
| 10 | F-43 "target is not created and does not count towards the license" vs the Phase 3 pattern (create, then test in a job) | Adding a vault runs a **synchronous pre-flight check** (token, then page 1 of the certificate list; at most 45 s) before anything is stored: `azure.vault_not_found`, `azure.auth_failed`, `azure.credentials_expired`, `azure.unreachable`, `azure.tls_untrusted`, `azure.address_not_allowed`, `azure.clock_skew` and `azure.managed_identity_unavailable` refuse the add (nothing stored, audited `vault.add_refused`); a 403 (role missing, firewall) still creates the vault, status `degraded`, with the access checklist; a replacement of the credentials runs the same check | F-43 forbids creating the target; a vault that answers 403 must be addable, because the role is usually assigned after the vault is added (owner step 1) | An add request can take up to 45 s; the UI shows progress |
| 11 | Permissions: R3 "credentials Admin only", §25.1 "credential edit requires step-up"; `targets.manage` allows operate tokens | New permission `credentials.manage` = Administrator in a browser session with step-up (no API token): adding a vault (it carries a credential) and replacing its credentials; deleting a vault, the poll interval and auto-deploy stay `targets.manage`; test, **Check now** `inventory.operate`; bindings, **Deploy now**, imports `certificates.operate`; reads `read` | The spec's step-up list names credential edit | Automation cannot add vaults (accepted: credentials should be typed by a person) |
| 12 | Target statuses (`targets.status`) have no vault states; §11.6 `degraded`; §11.9 "`auth_failed`, retry every poll, alert after 3 failures" vs F-34 (an `auth_failed` SSH target is never retried) and F-49 "no retry storm" | Vaults use `ok`, `degraded` (new: the last poll was refused in part — a role, the firewall — or throttled for three cycles, or a list failed), `auth_failed`, `unreachable` and `disabled`; `pending_host_key`, `checking` and `host_key_changed` never apply; an `auth_failed` vault is still polled (spec §11.9) with the failure backoff of row 13; one email to Administrators after **3 consecutive** failed sign-ins (`kv.auth_failed`), once per episode | Sign-in failures of a vault are often fixed in Azure (a role or a new secret elsewhere), unlike a refused SSH key; one token request per hour is no storm | One token request per hour against a dead secret until someone fixes it |
| 13 | §11.6 setting `azurekv.poll_interval` (5 min–24 h), 0–60 s jitter, "next poll delayed (interval × 2, cap 1 h)" | A per-vault poll interval in minutes (5–1440, default 15; `PATCH /targets/{id}` `poll_interval_minutes`, Administrator) stored in `discovery_interval_seconds` (a vault's range is 300–86400 s); the per-minute `kv.schedule` tick spreads polls (no extra jitter); after a failed poll the next one waits `min(interval × 2^min(failures, 2), max(interval, 1 h))`, and the next success resets the count (`targets.poll_failures`) | `settings` has no page before Phase 7; vaults on different hosts do not compete, so jitter buys nothing | Many vaults added in the same minute poll in the same minute |
| 14 | §7.3 puts Key Vault certificates into `certificate_locations` (kind `kv_certificate`) and `certificates.kv_current_version`, `kv_updated_at`, `thumbprint` | Separate tables: `kv_certificates` (one row per vault certificate name: current version, thumbprint, enabled, expiry, policy summary, missing), `kv_certificate_versions` (spec `certificate_versions`, one per version, linked to the `certificates` row of its leaf once its details were read), `kv_keys`, `kv_secrets` (metadata), `bindings`, `kv_imports`; `certificate_locations.binding_id`; `deployments.binding_id` and `kv_version_id` | One certificate can sit in several vaults (one `certificates` row by fingerprint), and every `certificate_locations` column and query is Nginx-specific (paths, servers, hashes, the deploy dialog) | Two places hold "where a certificate is": the certificate pages join both |
| 15 | §11.2 "page size 25 requested" | Service default page size (the SDK has no `maxresults` option); bounds per poll: 5000 certificates, 5000 keys, 10,000 secrets listed (more: `list_truncated`, nothing marked missing), details of at most 100 changed certificates and 100 new key versions (the rest on the next poll), 100 versions per certificate, 10 minutes per poll | A hostile or huge vault must not hold a worker or a transaction (R39's discovery bounds) | A vault with more than 5000 certificates is shown incomplete |
| 16 | §11.1 key inventory "type, size/curve" from a listing; §11.4 "Key Vault Reader … cannot read key material" | A key listing has no type or size: Alice reads `GetKey` (the public key only) once per key version, at most 100 per poll; the key-listing role is still Key Vault Reader | The REST listing carries only id, attributes, tags, managed | If Reader cannot `GetKey` on RBAC vaults, keys show without type (the call answers 403, recorded per key, monitoring continues); the real-Azure suite checks it (owner) |
| 17 | §11.6 change detection details | As R23: the change key is (current version ID, x5t thumbprint); `Updated` only decides whether attributes are refreshed; details (`GetCertificate`: leaf, policy, secret content type) are read only when the pair changed; the versions list is read when the current version changes; older versions Alice never saw as current are listed but have no leaf and cannot be deployed (`kv.version_not_deployable`) | "Large vaults cost pages, not per-object calls" | "Deploy now" of a version Alice never saw as current needs the next renewal or an import |
| 18 | §12.6 deploy input from a vault; §11.5 items 2–6; R38's engine (journal, fence, recovery) is an SSH-helper design | A Key Vault deployment **is** a Phase 4 deployment to an Nginx location (same states, journal, fence, recovery, emails); only its material differs: before any SSH, the `certificate.deploy` job reads the backing secret of the exact version (`ReadCertificateSecret`, never "latest"), checks it (content type PFX or PEM; key matches the leaf; leaf SHA-1 = the version's x5t and SHA-256 = the deployment's `new_fingerprint`; not expired) and builds the PEM chain (leaf, intermediates in issuing order, a self-signed root dropped); the key exists only in memory, is zeroed after the send, and is never sealed ("keep a copy" not built); recovery never needs it; `include_root` is not built | The engine already gives the guarantees F-47 needs (one server rolls back alone); the vault is only the source | A vault whose consumers rely on the root in the bundle get no root on Nginx (correct TLS practice) |
| 19 | F-17 (an incomplete chain needs an Administrator's confirmation) vs §11.5 item 5 (chain incomplete = warning, not blocking) for vault certificates | Key Vault deployments need no confirmation: an incomplete chain is the step param `chain=incomplete` and a warning on the deployment | Auto-deploy has nobody to confirm; §11.10 "chains deployed as delivered by KV" | A vault that delivers no intermediates deploys a chain browsers may reject (visible on the deployment) |
| 20 | §11.6 item 3 "enqueue one deploy job per bound host" on detection; §12.5 "staggered (5 at once)", "stop the wave after N failures (3)"; F-47 "3 attempts, 1 h apart"; F-48 "coalesced to the newest version"; §11.6 items 6–7 | The poll only records; a per-minute periodic task `kv.auto_deploy` (ClassChange) plans: for each live binding with auto-deploy on, the vault certificate's **current** version V is eligible when detected after `auto_since`, not held, enabled, exportable, leaf known, `not_before ≤ now < expires`, and `expires ≥` the expiry of what the website serves now; per location: nothing while a deployment of the location is unfinished (coalescing), nothing when V is already served, a new attempt at most 1 h after the last failed one; at most **5 unfinished** auto deployments per binding; **3 failed deployments of V in the binding stop the wave** (`bindings.stopped_version`, one email); skipped versions (disabled, expired, not yet valid, older) email once per version and never deploy | One planner decides from the database, so a renewal during a running deployment needs no queue of its own and every rule is one SQL-backed test table | A planner bug can stall deployments for a minute per tick; the wave limit is fixed until Settings (Phase 7) |
| 21 | L-87 "no auto-deploy is triggered from" a poll in flight at lock; S5 AC5 / R29 "deploys pending during lock wait for Admin confirmation" | A version detected while the license gate refuses changes (`Allow(ClassChange)` fails at reconcile time: locked, lock due or unverified) is stored **held**: never auto-deployed, shown as "New version found while the license was expired" with **Deploy now** for an Administrator only (`kv.held_needs_admin` otherwise); polls do not run in lock (ClassReadOnly), so a renewal during lock is first detected after renewal and follows the normal rules | L-87 and AC5 together; "held" is what the poll actually observed | A renewal that happens in Azure during a lock deploys automatically after the renewal of the license (Alice only learns of it then) |
| 22 | §11.7 "in license lock, creating a binding (a database-only change) remains possible" vs R36 item 6 (`/keyvault` routes are ClassChange) and R38 item 9 ("Phase 5 revisits bindings") | Every binding route is ClassChange (refused in lock) | One rule for every inventory change; R36 item 6 is the later decision | An administrator cannot prepare bindings during a lock |
| 23 | §11.7 "binding creation requires … vault capability at least Deploy" | A binding requires the vault certificate to be known, not removed, enabled, **exportable** (F-45) and of the location's key type; Deploy access is not a precondition (it is known only after a secret read): the binding shows "Deploy access not checked" until a deployment or an **Access check** with "also test deployment access" reads a secret | Requiring a verified Deploy level would force a secret read before the first binding with nothing to read yet | A binding can exist without the role; its first deployment fails F-41-style with nothing changed |
| 24 | §11.7 binding model (a binding per KV certificate name and a list of locations; deleting a vault "requires removing bindings first (or confirming their removal)") | One live binding per vault certificate (`bindings_one_live`), a location in at most one live binding (`certificate_locations.binding_id`), 1–200 locations per binding; deleting a binding is a soft delete that clears the locations' `binding_id` and never touches servers; deleting a vault with live bindings is refused (`kv.vault_has_bindings`) unless `remove_bindings=true` | Simple, unique ownership; history kept for deployments | Two policies for one vault certificate need two vault certificates |
| 25 | §11.8 import; §12.6 states for deployments | An import is **not** a deployment: no journal, fence or rollback (vault versions are immutable; undoing is disabling the version in Azure, which Alice never does). `certificate.import_to_kv` (ClassChange, target = the vault) builds a PFX (`pkcs12.LegacyDES`, empty password: the widest acceptance by Key Vault and its consumers; the encryption is no protection with an empty password, TLS protects transit) with policy exportable, key type and size from the key, content type `application/x-pkcs12`, no lifetime actions; the request `POST …/import` is not idempotent, so after it was sent it is **never re-sent**: an uncertain outcome stays `uncertain` until a poll sees a version with the imported thumbprint (then `succeeded`) or 24 hours pass (`failed`, `kv.import_outcome_unknown`); an existing name needs `confirm_new_version` | A duplicate import creates a confusing second version; the poll is the only safe read-back | An import whose answer is lost waits up to one poll interval for confirmation |
| 26 | §11.9 "raw Azure errors (with `x-ms-request-id`) are stored in the job log after redaction" | Only the `x-ms-request-id` (a GUID) and the Azure error code (`^[A-Za-z][A-Za-z0-9]{0,63}$`, e.g. `ForbiddenByRbac`, `AADSTS7000215` as `aadsts=7000215`) are kept, as job and deployment params; never the message text | Redaction of free text cannot be proven; codes and request IDs are what Microsoft support asks for | Less detail for support (the request ID lets Microsoft find the rest) |
| 27 | §11.3 "alerts 30 days before" a client secret expires; §11.1 key expiry alerts | Phase 5 stores and shows the expiry date an administrator typed and marks it in the UI from 30 days before; the emails come with the Phase 7 alert engine, as certificate expiry emails do | No alert engine before Phase 7 | A secret can expire unnoticed by email until Phase 7 (the vault then reads **Credentials expired** and emails after 3 failed sign-ins, row 12) |
| 28 | §11.3 "Test connection … checklist Monitor / Deploy / Import derived from which calls returned 403" | **Access check** = sign-in, page 1 of the certificate, key and secret lists (Monitor), and only when asked, `GetSecret` of one chosen exportable certificate's current version (Deploy; the value is read into memory, discarded, zeroed and the read audited `kv.secret_read` with `purpose=access_check`); Import is never probed ("Checked when you import") because the only probe is an import | A probe that changes the vault would violate "Alice only ever calls import" for the person's request | Import permission problems appear only at the first import (nothing created, `ALC-AKV-0003`) |
| 29 | §8.2 job types; §8.4 retries | Queue types `kv.test_connection` (ClassReadOnly, 1 attempt), `kv.poll` (ClassReadOnly, 1 attempt; a failure ends `failed` without the `job.dead` email: the vault's status and its own email carry it), `certificate.import_to_kv` (ClassChange, 3 attempts, retried only before the send); periodic `kv.schedule` (ClassReadOnly, every minute) and `kv.auto_deploy` (ClassChange, every minute; never ticks in the e2e build) | Poll failures are paced by row 13, not by queue backoff | — |
| 30 | §22.5 fake "copied from recorded real responses … refreshed by the optional real-Azure suite"; R22 / AC6 / SEC-083 "Key Vault Reader sufficiency … confirmed by the real-Azure test suite in Phase 5" | Without a subscription nothing can be recorded: `test/testdata/kv-recordings/` holds **reference shapes** transcribed from the public REST API reference (api-version 2025-07-01; each file names its source page) with placeholders; the fake's answers are checked against them key by key and decoded by the real SDK clients in tests; the `-tags azure` contract suite runs the same assertions against a real vault when `ALICE_AZURE_TEST_*` is set and can rewrite the shapes (`ALICE_AZURE_RECORD=1`); it never runs in CI. Reader sufficiency stays **unconfirmed** in the docs and the UI ("expected; not yet confirmed on a real vault") until the owner runs the suite | The honest state of evidence | The fake may differ from Azure in a detail neither the SDK nor the reference shows; the owner walkthrough on real Azure is the first real evidence |
| 31 | §12.7 deployment windows (optional setting) | Not built (Phase 7 Settings) | No settings page | Auto-deploys run at any hour |
| 32 | `05-operations.md` §20 wizard "first target (Nginx server, Linux host, or Azure Key Vault)" | The wizard's first-target step keeps offering servers only; vaults are added on **Key Vaults** | The add-vault dialog needs step-up and a role guide that do not fit the wizard | A Key Vault-only customer skips the step |
| 33 | §11.2 "one client per vault, created lazily and cached per target" | One set of clients and one SDK credential per **job session** (opened, used, dropped); tokens are cached only inside that session | A long-lived credential keeps the decrypted secret in process memory for days (Go strings cannot be zeroed) | One token request per job (every poll interval per vault) |
| 34 | AZ-2 "secret contents only fetched for cert-backing secrets bound to a deploy" | Every secret read (deploy or access check) writes an audit row `kv.secret_read` (`kv_certificate_id`, `certificate_name`, `version`, `purpose`, `deployment_id` when a deployment) | Makes the residual of AZ-2 visible | One audit row per deployment from a vault |
| 35 | §22.5 / §26.7 e2e "with the fake" | A compose service `fakeazure` in `deploy/docker-compose.e2e.yml` only, on the internal network with the aliases `login.microsoftonline.com` and `alice-e2e.vault.azure.net` (Docker's DNS answers them for the e2e Alice), its CA written to a volume that the e2e Alice trusts through a build-tagged hook (`-tags e2e` only; `release-symcheck` and `image-check` prove the release binary lacks the path) | Follows the e2e SSH target: test-only services and trust never reach a release build or the base compose file | The e2e stack needs one more image build |

## Carries and deferred items

Sources: `docs/superpowers/rulings/phase-4.md` ("Parked / carried to Phase 5"), `docs/superpowers/rulings/audit-remediation.md` ("Parked / carried forward"), `docs/security/reviews/phase-4.md` and `docs/security/reviews/audit-remediation.md` ("Known limitations"), R37 item 18.

| # | Carry | Decision | Where |
|---|---|---|---|
| 1 | L-87 (Key Vault poll in flight at lock) | **Included** with the real `kv.poll` job: the request finishes, metadata is stored, the version is held, no deployment is created | Task 15 |
| 2 | L-29 real-job cases for vaults; L-26 "Import (certificate or Key Vault) is refused the same way" | **Included**: in lock no request reaches the fake Azure service (its request log stays empty) for add, check, poll, binding, **Deploy now** and import, every refusal audited, nothing deleted or added | Task 18 |
| 3 | L-81 with Key Vault deployments (queued before the lock, held, confirmed after renewal) and L-80/L-82 with a Key Vault-sourced deployment | **Included** (the engine is Phase 4's; one case each proves the vault material step does not change it) | Task 16 |
| 4 | L-83..L-86, L-88 (rotation runner) | **Re-deferred to Phase 6** (their jobs do not exist); `internal/jobs/stubjobs_test.go` keeps their gate parts | — |
| 5 | API: a deployment id on deploy jobs (the blocked-jobs panel searches the server's latest 200 deployments) | **Included**: `GET /api/v1/jobs` and `/jobs/{id}` items carry `deployment_id` (deploy and recovery jobs) and `import_id` (import jobs) read from the payload; the web's held-jobs panel links them directly | Task 17, Task 22 |
| 6 | API: a cross-server locations list (the certificate page cannot offer websites that do not use the certificate yet) | **Included**: `GET /api/v1/certificate-locations` (deployable, unbound, by key type, searchable, paged); the binding dialog uses it; the Phase 4 deploy dialog keeps its own list | Tasks 12, 17, 21 |
| 7 | API: `facts.nginx.scanned_at` | **Re-deferred** (no Phase 5 screen needs it; R38 item 43 stays) | — |
| 8 | Helper: dropped-certificate warning without the file, TLS block without `ssl` listen, host-name listens, unreadable journal blocking 30 days | **Re-deferred** (Phase 5 changes no helper; no protocol bump) | — |
| 9 | Recovery codes lost when the completing answer is lost; a certificate re-issued for a completed signing request's key | **Re-deferred** (unrelated to Key Vault) | — |
| 10 | Inventory's own refusal rows not coalesced (`deployment.denied`, …) | **Re-deferred**; the new `binding.denied` and `kv.import.denied` rows follow the same uncoalesced pattern (bounded by the session rate limit) | — |
| 11 | e2e hooks for the route error page, `unverified` banner, locale fallback | **Re-deferred** (Vitest only, as recorded) | — |
| 12 | Lockfile secret scanning, `osv-scanner`, real-systemd job, nightly pipeline, mutation testing | **Re-deferred to Phase 8** | — |
| 13 | Owner items: remote and first CI run, production license key, walkthroughs of Phases 1–4 and the remediation, Turkish tone review, crypto sign-off, a clean-machine `make ci`, the decisions on lockfile scanning and refusable loopback | Owner only; Phase 5 adds its own walkthrough table and the real-Azure suite run (R22 confirmation) | Task 24 |

---

## File Structure

```
internal/platform/azureid/                 vault address, GUIDs, object names, versions, thumbprints (Task 1)
internal/providers/                        azure.go (identity, Key Vault discovery, secret, import types), provider.go,
                                           unsupported.go, capability.go, import_outcome.go; providertest; fake (Task 2)
internal/certs/                            kvsecret.go (ParseKVSecret, WithoutRoot), clientcert.go (ParseClientCertificate),
                                           pfx.go (ExportPFX), FuzzParseKVSecret (Task 3)
internal/testutil/fakekv/                  vault data plane, state, recordings check (Task 4); identity, IMDS, challenge,
                                           faults, request log, SDK round trip (Task 5)
test/testdata/kv-recordings/               reference shapes of the REST answers (Task 4)
internal/providers/azurekv/                provider.go, transport.go, identity.go, errors.go, retry.go, limiter.go,
                                           kvapi.go (Task 6); connection.go, discover.go (Task 7); secret.go, import.go,
                                           conformance and real-Azure contract tests (Task 8)
migrations/00008_key_vault.sql             credentials, targets, kv_*, bindings, deployments, kv_imports, grants (Task 9)
internal/inventory/                        vaults.go, vault_credentials.go (Task 10); kv_reconcile.go, kv_schedule.go,
                                           kv_queries.go (Task 11); bindings.go, kv_deploy.go, kv_material.go,
                                           locations_list.go (Task 12); kv_autodeploy.go (Task 13); kv_imports.go (Task 14);
                                           jobs.go, notify.go, errors.go, types.go, targets.go, schedule.go (several)
internal/jobs/types.go, internal/jobs/kvjobs/   job types and handlers (Task 15)
internal/jobs/deployjobs/                  kv.go, deploy.go (the vault material step) (Task 16)
internal/rbac/rbac.go                      credentials.manage (Task 17)
internal/api/                              vaults_handlers.go, bindings_handlers.go, kv_dto.go, imports_handlers.go,
                                           errors.go, jobs_handlers.go, targets_handlers.go (Task 17); integration suites (Task 18)
api/openapi.yaml, docs/authz-matrix.md     new operations (Task 17)
locales/common/{en,tr}.json                error texts (Task 17), email templates (Tasks 11, 13, 14)
cmd/alice/                                 providers.go, wiring.go, services.go, testapi_e2e.go, testapi_release.go,
                                           compose_test.go (Task 19)
cmd/alice-fakeazure/, test/images/fakeazure/Dockerfile, deploy/docker-compose.e2e.yml, deploy/dev/check-hardening.sh,
Makefile                                   e2e fake Azure service (Task 19)
web/src/                                   API, Key Vaults page, add-vault dialog, access check, credentials (Task 20); vault
                                           detail, vault certificate page, binding dialogs (Task 21); import dialog, history,
                                           Servers without vaults (Task 22)
web/e2e/phase5.spec.ts                     EN/TR journeys (Task 23)
docs/                                      azure-setup.md, operator/admin guides, troubleshooting, dev/dependency-updates.md,
                                           security/reviews/phase-5.md, CHANGELOG, R40, coverage floors (Task 24)
```

Task order is bottom-up: pure identifiers (1), framework (2), certificates (3), the fake (4–5), the provider (6–8), schema (9), inventory (10–14), jobs and engine (15–16), HTTP (17–18), wiring and the e2e service (19), web (20–22), end-to-end (23), documentation and verification (24). Each task leaves the repository green (`make lint`, `make test`, the integration packages it touches, `make web-test` and `make i18n-check` where it touches the web). No task changes `alice-helper`.

### Task index

1. `internal/platform/azureid`: vault address, tenant and client IDs, object names, versions, thumbprints
2. Provider framework: Azure identity source, Key Vault discovery types, `ReadCertificateSecret` and `ImportCertificate`, capability, import outcome rules, conformance suite, fake provider
3. Certificates: Key Vault secret decoding, service-principal certificate credentials, PFX export for import; `FuzzParseKVSecret`
4. Fake Azure part 1 (`internal/testutil/fakekv`): the Key Vault data plane and the reference shapes
5. Fake Azure part 2: Entra ID token endpoint, managed identity, the Key Vault challenge, fault injection, request log; SDK round trip
6. `azurekv` provider part 1: SDK modules, guarded transport, Azure identities, error catalogue, retry loop, per-vault limiter
7. `azurekv` provider part 2: access check (`TestConnection`) and the vault inventory (`Discover`) with bounds
8. `azurekv` provider part 3: `ReadCertificateSecret`, `ImportCertificate`, conformance, the optional real-Azure contract suite
9. Migration `00008_key_vault.sql`
10. Inventory: vault targets — add with the pre-flight check, sealed credentials and their replacement, the per-vault credential source, poll interval, deletion; vaults out of the SSH scheduler
11. Inventory: vault reconciliation, poll state and failures, poll scheduling, Key Vault emails
12. Inventory: bindings, the cross-server location list, Key Vault deployments (**Deploy now**) and their material
13. Inventory: the auto-deploy planner (F-46..F-48, stagger, stop after three failures, version rules)
14. Inventory: imports into a vault
15. Jobs: `kvjobs` (`kv.test_connection`, `kv.poll`, `certificate.import_to_kv`), job types, periodic tasks; L-87
16. Deploy engine: the vault material step in `certificate.deploy` (F-41, F-45 at run time); L-80..L-82 with a Key Vault deployment
17. API: routes, DTOs, `credentials.manage`, `ALC-AKV-*` codes, job ids on deploy jobs, OpenAPI, authz matrix
18. API integration: Key Vault journeys with the fake (F-40..F-52), lock (L-26, L-29, L-81), SSRF (A-14), secret-leak suite (S-01..S-05)
19. Wiring and the e2e fake Azure service: registration, scheduler, e2e trust hook, `alice-fakeazure`, compose overlay, Makefile, release checks
20. Web: API layer, **Key Vaults** page, **Add Key Vault** dialog with the role guide, **Access check**, credentials replacement, navigation, audit labels
21. Web: vault page (certificates, keys, secrets), vault certificate page (versions, **Connected websites**, **Automatic deployment**, **Deploy now**), deployment source
22. Web: **Import into Key Vault**, import history, held jobs with their deployment, **Servers** without vaults
23. End-to-end: Phase 5 journeys in EN and TR against the fake Azure service, accessibility
24. Coverage floors, documentation (Azure setup guide with the role assignments, guides, troubleshooting), R40, security review, CHANGELOG, `make ci`

Recommended execution: subagent-driven, one reviewer per task, an additional security reviewer on Tasks 3, 6, 8, 10, 12, 16 and 18. Tasks 4–5 are one fake and may go to one implementer; Tasks 6–8 build one provider and should keep one implementer.

---
## Cross-task contract

Every task's **Interfaces** block repeats the parts of this contract it consumes or produces. When a task and this section disagree, this section wins and the task is a plan defect to fix at execution time (record it in the task's report).

### Facts about the Key Vault REST API this plan builds on (api-version 2025-07-01, public reference)

- Listing certificates (`GET /certificates`) returns per item `id` **without a version** (`https://<vault>/certificates/<name>`), `x5t` (base64url SHA-1 of the current version's DER), `attributes` (`enabled`, `nbf`, `exp`, `created`, `updated` as Unix seconds, `recoveryLevel`) and `tags`, plus `nextLink`. The SDK decodes `x5t` into `X509Thumbprint []byte`. The current version ID comes only from `GET /certificates/<name>/` (empty version = latest), whose answer also carries `cer` (the leaf DER), `kid`, `sid`, `policy` (`key_props.exportable`, `kty`, `key_size`, `crv`, `secret_props.contentType`, `issuer.name`, `lifetime_actions`) and the versioned `id`. So the change detection is: list → when (`x5t`, `updated`) differ from what Alice stored for that name, get the latest → compare (version ID, x5t) (R23).
- Listing versions (`GET /certificates/<name>/versions`) returns versioned `id`s with `x5t` and attributes.
- Listing keys (`GET /keys`) returns `kid` without version, `attributes`, `managed`, `tags`; type and size need `GET /keys/<name>/` (public JWK: `kty`, `n`, `crv`).
- Listing secrets (`GET /secrets`) returns `id` without version, `attributes`, `contentType`, `managed`; never values.
- `GET /secrets/<name>/<version>` returns `value` (for a certificate: base64 PFX with an empty password when `contentType` is `application/x-pkcs12`; PEM text with a `PRIVATE KEY` block when `application/x-pem-file`), `contentType`, `kid`, `managed: true`.
- `POST /certificates/<name>/import` with `{"value": <base64 PFX>, "pwd": "", "policy": {…}}` creates a new version (version 1 for a new name) and answers the certificate bundle.
- Errors: `{"error":{"code":"Forbidden","message":"…","innererror":{"code":"ForbiddenByRbac"|"ForbiddenByPolicy"|"ForbiddenByFirewall"|…}}}`; 404 `CertificateNotFound`/`SecretNotFound`/`KeyNotFound`; 429 with `Retry-After`; an unauthenticated request answers 401 with `WWW-Authenticate: Bearer authorization="https://login.microsoftonline.com/<tenant>", resource="https://vault.azure.net"` (the challenge the SDK answers). A vault name that does not exist does not resolve in DNS.
- Entra ID: `POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` (client credentials; secret, or `client_assertion` = a PS256 JWT with header `x5t#S256`), preceded by MSAL's tenant discovery `GET /<tenant>/v2.0/.well-known/openid-configuration` (instance discovery is disabled by Alice); errors `{"error":"invalid_client","error_codes":[7000215],…}`. Managed identity on a VM: `GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=…&resource=https://vault.azure.net[&client_id=…]` with header `Metadata: true`.

### Database (migration `00008_key_vault.sql`, Task 9)

```sql
-- +goose Up
-- Phase 5: Azure Key Vault targets and their sign-in credentials, the vault inventory, bindings of
-- vault certificates to Nginx websites, Key Vault deployments and imports (spec §7.2-§7.4, §11; R40).
-- Same conventions as 00006: closed lists for values Alice owns, format checks for names Azure
-- owns, no clock defaults.

-- A vault's credential belongs to its vault (R37 item 11, R40 row 9): target_id is set in the
-- transaction that inserts the vault, so the foreign key is checked at commit. Credentials stay
-- append-only: a replacement is a new row that targets.credential_id moves to.
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh', 'azure_vault'));
ALTER TABLE credentials ADD COLUMN target_id uuid REFERENCES targets (id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE credentials ADD CONSTRAINT credentials_target_purpose CHECK ((purpose = 'azure_vault') = (target_id IS NOT NULL));
ALTER TABLE credentials ADD CONSTRAINT credentials_kind_purpose CHECK (
    (purpose = 'platform_ssh' AND kind = 'ssh_private_key')
    OR (purpose = 'azure_vault' AND kind IN ('azure_sp_secret', 'azure_sp_cert', 'azure_managed_identity')));
CREATE INDEX credentials_target ON credentials (target_id) WHERE target_id IS NOT NULL;

-- Vault targets: status degraded (R40 row 12), a poll interval of 5 minutes to 24 hours (row 13),
-- the failure count that delays the next poll, and the vault address (row 5; host and port keep the
-- Phase 3 endpoint index: one live target per vault).
ALTER TABLE targets DROP CONSTRAINT targets_status_check;
ALTER TABLE targets ADD CONSTRAINT targets_status_check CHECK (status IN ('pending_host_key', 'checking', 'ok', 'unreachable',
    'host_key_changed', 'auth_failed', 'disabled', 'degraded'));
ALTER TABLE targets DROP CONSTRAINT targets_discovery_interval_seconds_check;
ALTER TABLE targets ADD CONSTRAINT targets_discovery_interval_seconds_check CHECK (CASE WHEN type = 'azure_key_vault'
    THEN discovery_interval_seconds BETWEEN 300 AND 86400 ELSE discovery_interval_seconds BETWEEN 3600 AND 2592000 END);
ALTER TABLE targets ADD COLUMN poll_failures integer NOT NULL DEFAULT 0 CHECK (poll_failures BETWEEN 0 AND 1000000);
ALTER TABLE targets ADD CONSTRAINT targets_vault_config CHECK (type <> 'azure_key_vault' OR coalesce(
    jsonb_typeof(config->'host') = 'string'
    AND config->>'host' ~ '^[a-z](-?[a-z0-9])+\.vault\.azure\.net$'
    AND char_length(config->>'host') BETWEEN 19 AND 40
    AND config->'port' = '443'::jsonb
    AND config->>'vault_url' = 'https://' || (config->>'host'), false));

-- One row per certificate name of a vault (spec §11.1; R40 row 14). current_version, current_thumbprint
-- and kv_updated_at change together, when Alice read the latest version's details (R40 row 17);
-- enabled, not_before and expires follow every listing.
CREATE TABLE kv_certificates (
    id                  uuid PRIMARY KEY,
    target_id           uuid NOT NULL REFERENCES targets (id),
    name                text NOT NULL CHECK (name ~ '^[0-9A-Za-z-]{1,127}$'),
    current_version     text NOT NULL DEFAULT '' CHECK (current_version ~ '^([0-9a-f]{32})?$'),
    current_thumbprint  text NOT NULL DEFAULT '' CHECK (current_thumbprint ~ '^([0-9a-f]{40})?$'),
    kv_updated_at       timestamptz,                  -- attributes.updated of the version whose details Alice read
    listed_thumbprint   text NOT NULL CHECK (listed_thumbprint ~ '^[0-9a-f]{40}$'), -- the last listing's x5t
    listed_updated_at   timestamptz,                  -- the last listing's attributes.updated
    enabled             boolean NOT NULL,
    not_before          timestamptz,
    expires             timestamptz,
    kv_created_at       timestamptz,
    exportable          boolean,                      -- NULL until the policy was read
    key_type            text NOT NULL DEFAULT '' CHECK (key_type IN ('', 'rsa', 'ecdsa', 'other')),
    key_size            integer NOT NULL DEFAULT 0 CHECK (key_size BETWEEN 0 AND 16384),
    content_type        text NOT NULL DEFAULT '' CHECK (content_type IN ('', 'pkcs12', 'pem', 'other')),
    issuer_name         text NOT NULL DEFAULT '' CHECK (char_length(issuer_name) <= 127),
    auto_renew          boolean NOT NULL DEFAULT false,
    details_pending     boolean NOT NULL DEFAULT false, -- the listing changed and the details wait for the next poll
    first_seen_at       timestamptz NOT NULL,
    last_seen_at        timestamptz NOT NULL,
    missing_since       timestamptz,
    removed_notified_at timestamptz,
    UNIQUE (target_id, name)
);

-- One row per version Alice listed (spec certificate_versions). certificate_id is the leaf's row once
-- Alice read the version's details (only versions Alice saw as current have one; R40 row 17).
CREATE TABLE kv_certificate_versions (
    id                uuid PRIMARY KEY,
    kv_certificate_id uuid NOT NULL REFERENCES kv_certificates (id),
    version           text NOT NULL CHECK (version ~ '^[0-9a-f]{32}$'),
    thumbprint        text NOT NULL CHECK (thumbprint ~ '^[0-9a-f]{40}$'),
    certificate_id    uuid REFERENCES certificates (id),
    enabled           boolean NOT NULL,
    not_before        timestamptz,
    expires           timestamptz,
    kv_created_at     timestamptz,
    exportable        boolean,
    key_type          text NOT NULL DEFAULT '' CHECK (key_type IN ('', 'rsa', 'ecdsa', 'other')),
    content_type      text NOT NULL DEFAULT '' CHECK (content_type IN ('', 'pkcs12', 'pem', 'other')),
    detected_at       timestamptz NOT NULL,
    held              boolean NOT NULL DEFAULT false, -- detected while the license refused changes (R40 row 21)
    notified_at       timestamptz,                    -- its new-version or skipped-version email went out
    UNIQUE (kv_certificate_id, version)
);
CREATE INDEX kv_certificate_versions_certificate ON kv_certificate_versions (certificate_id) WHERE certificate_id IS NOT NULL;
CREATE INDEX kv_certificate_versions_thumbprint ON kv_certificate_versions (thumbprint);

-- Key and secret metadata (spec §11.1); never key material, never secret values.
CREATE TABLE kv_keys (
    id                 uuid PRIMARY KEY,
    target_id          uuid NOT NULL REFERENCES targets (id),
    name               text NOT NULL CHECK (name ~ '^[0-9A-Za-z-]{1,127}$'),
    version            text NOT NULL DEFAULT '' CHECK (version ~ '^([0-9a-f]{32})?$'),
    key_type           text NOT NULL DEFAULT '' CHECK (key_type IN ('', 'rsa', 'ec', 'oct', 'other')),
    hsm                boolean NOT NULL DEFAULT false,
    key_size           integer NOT NULL DEFAULT 0 CHECK (key_size BETWEEN 0 AND 16384),
    curve              text NOT NULL DEFAULT '' CHECK (curve IN ('', 'P-256', 'P-256K', 'P-384', 'P-521', 'other')),
    details_updated_at timestamptz,   -- attributes.updated when the details were read
    details_problem    text NOT NULL DEFAULT '' CHECK (details_problem IN ('', 'forbidden', 'failed')),
    enabled            boolean NOT NULL,
    managed            boolean NOT NULL DEFAULT false,
    not_before         timestamptz,
    expires            timestamptz,
    kv_created_at      timestamptz,
    kv_updated_at      timestamptz,
    first_seen_at      timestamptz NOT NULL,
    last_seen_at       timestamptz NOT NULL,
    missing_since      timestamptz,
    UNIQUE (target_id, name)
);
CREATE TABLE kv_secrets (
    id            uuid PRIMARY KEY,
    target_id     uuid NOT NULL REFERENCES targets (id),
    name          text NOT NULL CHECK (name ~ '^[0-9A-Za-z-]{1,127}$'),
    content_type  text NOT NULL DEFAULT '' CHECK (char_length(content_type) <= 255),
    enabled       boolean NOT NULL,
    managed       boolean NOT NULL DEFAULT false,
    not_before    timestamptz,
    expires       timestamptz,
    kv_created_at timestamptz,
    kv_updated_at timestamptz,
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    missing_since timestamptz,
    UNIQUE (target_id, name)
);
CREATE INDEX kv_certificates_expires ON kv_certificates (expires) WHERE missing_since IS NULL;
CREATE INDEX kv_keys_expires ON kv_keys (expires) WHERE missing_since IS NULL;

-- A binding connects one vault certificate to Nginx locations (spec §11.7; R40 rows 22-24).
CREATE TABLE bindings (
    id                uuid PRIMARY KEY,
    kv_certificate_id uuid NOT NULL REFERENCES kv_certificates (id),
    kv_target_id      uuid NOT NULL REFERENCES targets (id),
    auto_deploy       boolean NOT NULL DEFAULT false,
    auto_since        timestamptz,           -- when automatic deployment was last turned on
    stopped_version   text NOT NULL DEFAULT '' CHECK (stopped_version ~ '^([0-9a-f]{32})?$'), -- the wave of this version stopped (R40 row 20)
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    deleted_at        timestamptz,
    version           integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CHECK (auto_deploy = (auto_since IS NOT NULL))
);
CREATE UNIQUE INDEX bindings_one_live ON bindings (kv_certificate_id) WHERE deleted_at IS NULL;
CREATE INDEX bindings_auto ON bindings (id) WHERE deleted_at IS NULL AND auto_deploy;

ALTER TABLE certificate_locations ADD COLUMN binding_id uuid REFERENCES bindings (id);
CREATE INDEX certificate_locations_binding ON certificate_locations (binding_id) WHERE binding_id IS NOT NULL;

-- A Key Vault deployment names its binding and the vault version it deploys (R38 item 7's
-- "binding_id arrives in Phase 5"; R40 row 18). Both are written by the INSERT only.
ALTER TABLE deployments ADD COLUMN binding_id uuid REFERENCES bindings (id);
ALTER TABLE deployments ADD COLUMN kv_version_id uuid REFERENCES kv_certificate_versions (id);
ALTER TABLE deployments ADD CONSTRAINT deployments_kv_source CHECK ((binding_id IS NULL) = (kv_version_id IS NULL));
CREATE INDEX deployments_kv_version ON deployments (kv_version_id, location_id, created_at DESC) WHERE kv_version_id IS NOT NULL;
CREATE INDEX deployments_binding ON deployments (binding_id, created_at DESC) WHERE binding_id IS NOT NULL;

-- Imports of a certificate held in Alice into a vault (spec §11.8; R40 row 25).
CREATE TABLE kv_imports (
    id             uuid PRIMARY KEY,
    certificate_id uuid NOT NULL REFERENCES certificates (id),
    target_id      uuid NOT NULL REFERENCES targets (id),
    name           text NOT NULL CHECK (name ~ '^[0-9A-Za-z-]{1,127}$'),
    new_version    boolean NOT NULL,     -- the name existed: the person confirmed a new version
    state          text NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'uncertain')),
    thumbprint     text NOT NULL CHECK (thumbprint ~ '^[0-9a-f]{40}$'), -- SHA-1 of the imported leaf: how a poll recognises it
    version        text NOT NULL DEFAULT '' CHECK (version ~ '^([0-9a-f]{32})?$'),
    error_code     text NOT NULL DEFAULT '' CHECK (error_code ~ '^[A-Za-z0-9._-]{0,100}$'),
    error_params   jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(error_params) = 'object' AND octet_length(error_params::text) <= 4096),
    job_id         uuid REFERENCES jobs (id) ON DELETE SET NULL,
    requested_by   uuid REFERENCES users (id),
    created_at     timestamptz NOT NULL,
    sent_at        timestamptz,
    finished_at    timestamptz,
    CHECK ((state IN ('succeeded', 'failed')) = (finished_at IS NOT NULL)),
    CHECK (state <> 'succeeded' OR version <> '')
);
CREATE UNIQUE INDEX kv_imports_one_active ON kv_imports (target_id, name) WHERE state IN ('queued', 'running', 'uncertain');
CREATE INDEX kv_imports_certificate ON kv_imports (certificate_id, created_at DESC);

-- History is never deleted; vault inventory rows are marked missing, bindings soft-deleted.
GRANT SELECT, INSERT ON kv_certificates, kv_certificate_versions, kv_keys, kv_secrets, bindings, kv_imports TO alice_app;
GRANT UPDATE (credential_id, poll_failures) ON targets TO alice_app;
GRANT UPDATE (current_version, current_thumbprint, kv_updated_at, listed_thumbprint, listed_updated_at, enabled, not_before,
    expires, kv_created_at, exportable, key_type, key_size, content_type, issuer_name, auto_renew, details_pending, last_seen_at,
    missing_since, removed_notified_at) ON kv_certificates TO alice_app;
GRANT UPDATE (certificate_id, enabled, not_before, expires, exportable, key_type, content_type, held, notified_at)
    ON kv_certificate_versions TO alice_app;
GRANT UPDATE (version, key_type, hsm, key_size, curve, details_updated_at, details_problem, enabled, managed, not_before, expires,
    kv_created_at, kv_updated_at, last_seen_at, missing_since) ON kv_keys TO alice_app;
GRANT UPDATE (content_type, enabled, managed, not_before, expires, kv_created_at, kv_updated_at, last_seen_at, missing_since)
    ON kv_secrets TO alice_app;
GRANT UPDATE (auto_deploy, auto_since, stopped_version, deleted_at, version) ON bindings TO alice_app;
GRANT UPDATE (binding_id) ON certificate_locations TO alice_app;
GRANT UPDATE (state, version, error_code, error_params, job_id, sent_at, finished_at) ON kv_imports TO alice_app;

-- +goose Down
REVOKE UPDATE (binding_id) ON certificate_locations FROM alice_app;
REVOKE UPDATE (credential_id, poll_failures) ON targets FROM alice_app;
DROP TABLE kv_imports;
ALTER TABLE deployments DROP CONSTRAINT deployments_kv_source;
ALTER TABLE deployments DROP COLUMN kv_version_id;
ALTER TABLE deployments DROP COLUMN binding_id;
ALTER TABLE certificate_locations DROP COLUMN binding_id;
DROP TABLE bindings;
DROP TABLE kv_secrets;
DROP TABLE kv_keys;
DROP TABLE kv_certificate_versions;
DROP TABLE kv_certificates;
ALTER TABLE targets DROP CONSTRAINT targets_vault_config;
ALTER TABLE targets DROP COLUMN poll_failures;
ALTER TABLE targets DROP CONSTRAINT targets_discovery_interval_seconds_check;
ALTER TABLE targets ADD CONSTRAINT targets_discovery_interval_seconds_check CHECK (discovery_interval_seconds BETWEEN 3600 AND 2592000);
ALTER TABLE targets DROP CONSTRAINT targets_status_check;
ALTER TABLE targets ADD CONSTRAINT targets_status_check CHECK (status IN ('pending_host_key', 'checking', 'ok', 'unreachable',
    'host_key_changed', 'auth_failed', 'disabled'));
DROP INDEX credentials_target;
ALTER TABLE credentials DROP CONSTRAINT credentials_kind_purpose;
ALTER TABLE credentials DROP CONSTRAINT credentials_target_purpose;
ALTER TABLE credentials DROP COLUMN target_id;
ALTER TABLE credentials DROP CONSTRAINT credentials_purpose_check;
ALTER TABLE credentials ADD CONSTRAINT credentials_purpose_check CHECK (purpose IN ('platform_ssh'));
```

The Down migration is only correct on a database without vault rows (as 00006's); `migrations/down_integration_test.go` runs Up/Down/Up on an empty database. The constraint names `credentials_purpose_check`, `targets_status_check` and `targets_discovery_interval_seconds_check` are PostgreSQL's default names for the column CHECKs of 00005; Task 9's first test asserts them from `pg_constraint` before the migration relies on them.

Grant guard additions (`migrations/roles_integration_test.go`): `explicitGrants` gains `"public.kv_certificates"`, `"public.kv_certificate_versions"`, `"public.kv_keys"`, `"public.kv_secrets"`, `"public.bindings"`, `"public.kv_imports"`: `{"INSERT", "SELECT"}`; `explicitColumnGrants` gains each `UPDATE` list above, adds `"credential_id", "poll_failures"` to `public.targets` and `"binding_id"` to `public.certificate_locations` (sorted, as the existing lists are).

### `internal/platform/azureid` (Task 1)

```go
// Package azureid holds the Azure identifiers Alice accepts (spec §11.1, SEC-062, §25.4 A-14):
// one rule for what an administrator types (inventory) and what the azurekv provider connects to.
// Public cloud only (R40 rows 5-6).
package azureid

const (
	AuthorityHost = "login.microsoftonline.com"        // the only Entra ID host Alice signs in at
	AuthorityURL  = "https://" + AuthorityHost + "/"   // cloud.Configuration.ActiveDirectoryAuthorityHost
	VaultSuffix   = ".vault.azure.net"                 // every vault Alice accepts
	VaultScope    = "https://vault.azure.net/.default" // the data-plane token scope
	IMDSAddr      = "169.254.169.254:80"               // the managed-identity endpoint of an Azure VM (R40 row 4)
)

var ErrVault = errors.New("azureid: not a Key Vault address of the Azure public cloud")

// Vault is a normalised vault address.
type Vault struct {
	Name string // "contoso-prod"
	Host string // "contoso-prod.vault.azure.net"
	URL  string // "https://contoso-prod.vault.azure.net"
}

func ParseVault(raw string) (Vault, error)             // R40 row 5
func NormalizeGUID(raw string) (string, bool)          // trims, folds ASCII to lower case, ^[0-9a-f]{8}-…-[0-9a-f]{12}$
func ValidObjectName(s string) bool                    // ^[0-9A-Za-z-]{1,127}$ (certificate, key and secret names)
func ValidVersion(s string) bool                       // ^[0-9a-f]{32}$
func ValidThumbprint(s string) bool                    // ^[0-9a-f]{40}$
func Thumbprint(x5t []byte) (string, bool)             // hex of a 20-byte SHA-1; false for any other length
func ThumbprintOf(der []byte) string                   // hex SHA-1 of a DER certificate (x5t as hex)
func ValidRequestID(s string) bool                     // an x-ms-request-id: a GUID in any letter case
func ValidAzureCode(s string) bool                     // ^[A-Za-z][A-Za-z0-9]{0,63}$ (an error or inner error code)
```

### Provider framework additions (`internal/providers`, Task 2)

```go
// capability.go
	// CapReadCertificateSecret: read the secret that backs a vault certificate version (the private
	// key, for a deployment to Nginx; spec §11.5; R40 row 18).
	CapReadCertificateSecret Capability = "read_certificate_secret" //nolint:gosec // G101 false positive: a capability name, not a credential
// knownCapabilities gains it.

// provider.go: Session gains (after FenceDeployment)
	// ReadCertificateSecret (CapReadCertificateSecret) reads the secret that backs one version of a
	// vault certificate: its content type and value (a PFX or PEM with the private key). The caller
	// zeroes the value. It never reads "latest": Version is required.
	ReadCertificateSecret(ctx context.Context, req SecretRequest) (CertificateSecret, error)
	// ImportCertificate (CapImportCertificate) adds a version to a vault certificate (creating it
	// when the name is new). The outcome rules are ImportResult.Validate and CheckImportReturn: a
	// request that may have reached the vault is never answered "refused".
	ImportCertificate(ctx context.Context, req ImportRequest, log StepLogger) (ImportResult, error)
```

```go
// azure.go (new file)
package providers

// Sign-in methods of a vault's credential (R40 rows 4, 9).
const (
	AzureAuthClientSecret    = "client_secret"
	AzureAuthCertificate     = "certificate"
	AzureAuthManagedIdentity = "managed_identity"
)

// AzureIdentity is the identity Alice signs in to Azure with for one vault. It carries secrets:
// Format and LogValue print the method and the IDs only, and the secret fields are Plaintext.
type AzureIdentity struct {
	Auth           string            // AzureAuth*
	TenantID       string            // a GUID; "" for a managed identity
	ClientID       string            // the application (client) ID; for a managed identity the optional user-assigned client ID
	ClientSecret   secrets.Plaintext // AzureAuthClientSecret
	CertificateDER []byte            // AzureAuthCertificate: the registered certificate (public)
	PrivateKeyDER  secrets.Plaintext // AzureAuthCertificate: its RSA key, PKCS #8
}

// AzureCredentialSource is implemented by the credential source of a vault. release zeroes what was
// decrypted; the caller calls it as soon as the SDK credential is built.
type AzureCredentialSource interface {
	AzureIdentity(ctx context.Context) (AzureIdentity, func(), error)
}

// NewSecret wraps bytes a provider received (a vault secret value) in a Plaintext holder; the
// azurekv provider may not import internal/secrets (archtest), so it builds holders through here.
func NewSecret(b []byte) secrets.Plaintext { return secrets.NewPlaintext(b) }

// SecretRequest names one version of a vault certificate.
type SecretRequest struct{ Name, Version string }

// CertificateSecret is the backing secret of a vault certificate version. Value is base64 PFX or
// PEM text exactly as the vault returned it; Format and LogValue print the content type only.
type CertificateSecret struct {
	ContentType string // "application/x-pkcs12" | "application/x-pem-file" | anything the vault says
	Value       secrets.Plaintext
}

// ImportRequest asks the vault to add a version to certificate Name from a PFX (empty password).
type ImportRequest struct {
	OperationID uuid.UUID         // = kv_imports.id (logs and steps only; the vault has no idempotency key)
	Name        string
	PFX         secrets.Plaintext // the caller zeroes it
	KeyType     string            // "rsa" | "ecdsa"
	KeySize     int               // RSA bits, or 256/384 for ECDSA
}

// Import outcomes.
const (
	ImportCreated   = "created"   // the vault answered with the new version
	ImportRefused   = "refused"   // nothing was created: refused before the send, or a well-formed refusal from the vault
	ImportUncertain = "uncertain" // the request may have reached the vault; read the truth from a later listing
)

// ImportResult is the result of ImportCertificate (rules: Validate, CheckImportReturn).
type ImportResult struct {
	Outcome    string
	Version    string // created: the new version ID
	Thumbprint string // created: hex SHA-1 of the new version's leaf
	CER        []byte // created: the leaf DER
}

// Validate: created needs a valid Version, Thumbprint and a non-empty CER; refused and uncertain
// carry none of them; any other Outcome is invalid.
func (r ImportResult) Validate() error
// CheckImportReturn: Validate, then created comes with a nil error, refused with a *Error,
// uncertain with a non-nil error; ErrUnsupported is none of these.
func CheckImportReturn(r ImportResult, err error) error

// The Key Vault half of discovery (spec §6.2, §11.6; R40 rows 15-17).
type KVKnown struct {
	Version    string    // the current version whose details Alice read
	Thumbprint string    // its x5t (hex)
	Updated    time.Time // its attributes.updated
}

// DiscoverRequest gains (the struct keeps SSHKeys and Certificates):
//	KVKeys, KVSecrets bool                // also list keys / secrets (every fourth poll, §11.6 item 4)
//	KVKnown     map[string]KVKnown        // certificate name -> what Alice stored; details are fetched when the listing differs
//	KVKnownKeys map[string]time.Time      // key name -> attributes.updated whose details Alice read

// DiscoveryResult gains:
//	KV *KVInventory // the Key Vault half; nil for other providers

type KVInventory struct {
	Certificates   []KVCertificate
	Keys           []KVKey    // when KVKeys was asked
	Secrets        []KVSecret // when KVSecrets was asked
	KeysListed     bool       // the key list was read completely
	SecretsListed  bool
	Truncated      []string   // "certificates" | "keys" | "secrets" | "versions": cut at a bound; nothing of that kind is marked missing
	DetailsPending int        // certificates whose details wait for the next poll (MaxKVDetails)
	Failures       []KVListFailure
}

type KVListFailure struct {
	Object string // "certificates" | "keys" | "secrets"
	Err    *Error // azure.forbidden (F-40), azure.firewall, azure.throttled, …
}

type KVCertificate struct {
	Name       string
	Thumbprint string // the listing's x5t (hex)
	Enabled    bool
	NotBefore, Expires, Created, Updated *time.Time
	Details    *KVCertificateDetails // set when read in this call
	Versions   []KVCertificateVersion // set with Details when the current version differs from KVKnown (newest first, at most MaxKVVersions)
}

type KVCertificateDetails struct {
	Version     string // the latest version's ID
	Thumbprint  string // its x5t (hex)
	Updated     *time.Time
	CER         []byte // the leaf DER (public)
	Exportable  *bool  // nil when the policy was not returned
	KeyType     string // "rsa" | "ecdsa" | "other" | ""
	KeySize     int
	ContentType string // "pkcs12" | "pem" | "other" | ""
	IssuerName  string
	AutoRenew   bool
}

type KVCertificateVersion struct {
	Version, Thumbprint string
	Enabled             bool
	NotBefore, Expires, Created *time.Time
}

type KVKey struct {
	Name      string
	Enabled   bool
	Managed   bool
	NotBefore, Expires, Created, Updated *time.Time
	Details   *KVKeyDetails // set when read in this call
	DetailsProblem string   // "forbidden" | "failed" | "" (GetKey refused or failed; R40 row 16)
}
type KVKeyDetails struct {
	Version string
	KeyType string // "rsa" | "ec" | "oct" | "other"
	HSM     bool
	Size    int    // RSA modulus bits
	Curve   string // "P-256" | "P-256K" | "P-384" | "P-521" | "other" | ""
}

type KVSecret struct {
	Name        string
	ContentType string
	Enabled     bool
	Managed     bool
	NotBefore, Expires, Created, Updated *time.Time
}

// ConnectionReport gains:
//	Azure *AzureFacts // the vault's access check; nil for other providers

type AzureFacts struct {
	ObjectID        string       `json:"object_id"`        // the oid of Alice's token (display only, never trusted)
	TenantID        string       `json:"tenant_id"`        // the tid of the token
	PermissionModel string       `json:"permission_model"` // "rbac" | "access_policy" | "unknown"
	Checks          []AzureCheck `json:"checks"`
	CheckedAt       time.Time    `json:"checked_at"`
}
type AzureCheck struct {
	Name   string `json:"name"`   // AzureCheck*
	Result string `json:"result"` // AzureResult*
	Reason string `json:"reason,omitempty"`
	Role   string `json:"role,omitempty"` // the role that would allow it (forbidden)
}
const (
	AzureCheckSignIn           = "sign_in"
	AzureCheckListCertificates = "list_certificates"
	AzureCheckListKeys         = "list_keys"
	AzureCheckListSecrets      = "list_secrets"
	AzureCheckReadSecret       = "read_secret"
	AzureCheckImport           = "import"

	AzureResultOK         = "ok"
	AzureResultForbidden  = "forbidden"
	AzureResultFailed     = "failed"
	AzureResultNotChecked = "not_checked"
)

// Roles named in messages and the access check (spec §11.4; never translated).
const (
	RoleKeyVaultReader             = "Key Vault Reader"
	RoleKeyVaultSecretsUser        = "Key Vault Secrets User"
	RoleKeyVaultCertificatesOfficer = "Key Vault Certificates Officer"
)
```

`AzureIdentity`, `CertificateSecret` and `ImportRequest` get `Format(fmt.State, rune)` and `LogValue() slog.Value` that print only non-secret fields (as `DeployRequest` does), and a `Zero()` that zeroes their Plaintext fields. `UnsupportedSession` answers `ErrUnsupported` for both new methods. `providertest.CheckUnsupported` checks them when the capability is absent (`CapReadCertificateSecret`, `CapImportCertificate`); `CheckSession` adds the read-only op `ReadCertificateSecret` (an empty request: it must answer a `*providers.Error`, never `ErrUnsupported`) and `CheckImportResult(t, r, err)` mirrors `CheckDeployOutcome`.

### `internal/certs` additions (Task 3)

```go
const (
	ContentTypePKCS12 = "application/x-pkcs12" // a vault secret holding base64 PFX (empty password)
	ContentTypePEM    = "application/x-pem-file"
	MaxKVSecretSize   = 256 << 10 // a vault secret value Alice decodes (base64 PFX or PEM text)
)

var (
	ErrKVContentType  = errors.New("certs: the vault secret is neither a PFX nor a PEM file")
	ErrClientCertKey  = errors.New("certs: the sign-in certificate needs an RSA key of 2048 bits or more")
)

// ParseKVSecret decodes the backing secret of a vault certificate version (spec §11.5 items 3-5):
// PFX (base64, empty password) or PEM (CERTIFICATE and PRIVATE KEY blocks split by type), validated
// as an upload (ValidateUpload: key matches the leaf, not expired, key and signature rules, size and
// iteration bounds), then WithoutRoot. Errors never contain input.
func ParseKVSecret(contentType string, value []byte, now time.Time, roots *x509.CertPool) (Validated, error)

// WithoutRoot drops a self-signed last certificate from p's chain and re-encodes PEMChain
// (spec §11.5 item 4; include_root is not built, R40 row 18).
func WithoutRoot(p Parsed) Parsed

// ClientCertificate is a service principal's sign-in certificate (spec §11.3).
type ClientCertificate struct {
	CertificateDER []byte            // the leaf
	PrivateKeyDER  secrets.Plaintext // PKCS #8 RSA
	Thumbprint     string            // hex SHA-1 (what Azure shows as the certificate's thumbprint)
	NotAfter       time.Time
}

// ParseClientCertificate validates an upload as a sign-in certificate: ValidateUpload, then an RSA
// key (MSAL signs PS256; ErrClientCertKey otherwise).
func ParseClientCertificate(u Upload, now time.Time, roots *x509.CertPool) (ClientCertificate, error)

// ExportPFX builds the PFX of an import (R40 row 25): pkcs12.LegacyDES, empty password, the leaf
// and p.Chain (without a self-signed root).
func ExportPFX(keyDER secrets.Plaintext, p Parsed) (secrets.Plaintext, error)
```

### `internal/providers/azurekv` (Tasks 6–8)

```go
// Options configures the provider (cmd/alice; tests).
type Options struct {
	// RootCAs returns the roots Azure's TLS certificates are verified with; nil function or a nil
	// pool = the system roots. The e2e build returns the fake service's CA (R40 row 35).
	RootCAs func() (*x509.CertPool, error)
	// DialAddr rewrites "host:port" before dialing (tests only: the in-process fake). nil in cmd/alice.
	DialAddr func(addr string) string
}

func New(o Options) *Provider

// Limits (R40 rows 3, 8, 15, 16).
const (
	MaxAttempts        = 5
	TryTimeout         = 30 * time.Second
	MaxRetryAfter      = 5 * time.Minute
	PollBudget         = 10 * time.Minute    // a Discover call
	PreflightBudget    = 45 * time.Second    // inventory's add check uses it as its context bound
	MaxBody            = 4 << 20
	MaxHeaderBytes     = 64 << 10
	MaxKVCertificates  = 5000
	MaxKVKeys          = 5000
	MaxKVSecrets       = 10000
	MaxKVDetails       = 100
	MaxKVKeyDetails    = 100
	MaxKVVersions      = 100
	VaultRate          = 5   // requests per second per vault
	VaultConcurrency   = 4
)
```

`Provider` implements `providers.Provider` (kind `azurekv`, display key `provider.azurekv.name`, capabilities `test_connection`, `discover_certificates`, `discover_kv_keys`, `discover_kv_secret_metadata`, `read_certificate_secret`, `import_certificate`; config schema: `vault_url` (string, required, pattern of `ParseVault`'s output form `^https://[a-z](-?[a-z0-9])+\.vault\.azure\.net$`); credential schema: `auth` (enum), `tenant_id`, `client_id`, `client_secret`, `certificate`; `ValidateConfig` runs `azureid.ParseVault`) and `providers.ConnectionCache` (forgets the vault's limiter). `Open` needs `cred` to implement `providers.AzureCredentialSource` (else `azure.auth_failed` with no cause text) and `t.Config["vault_url"]`.

### `internal/testutil/fakekv` (Tasks 4–5)

```go
type Options struct {
	Now       func() time.Time // default time.Now
	TenantID  string           // default a generated GUID
	ClientID  string           // the registered application; default a generated GUID
	Secret    string           // its client secret; default NewClientSecret()
	ClientCert *x509.Certificate // a registered certificate credential (PS256 assertions are verified with it)
	VaultName string           // default "alice-test"
	ManagedIdentity bool       // IMDS answers for the VM's identity
	MIClientID string          // a user-assigned identity's client ID ("" = system-assigned)
	Model     string           // "rbac" (default) | "access_policy": the inner code of a 403
}
type Server struct{ /* … */ }
func NewServer(o Options) (*Server, error)           // TLS on 127.0.0.1:0 with a CA from internal/testutil/pki
func Start(t testing.TB, o Options) *Server         // NewServer + t.Cleanup(Close); fails the test on error
func NewClientSecret() string                       // "fake-" + 40 random hex characters
func (s *Server) Close()
func (s *Server) CAPool() *x509.CertPool
func (s *Server) CAPEM() []byte
func (s *Server) DialAddr(addr string) string        // login host, vault host, IMDS → the listener; anything else unchanged
func (s *Server) Handler() http.Handler              // for cmd/alice-fakeazure (its own listener)
func (s *Server) TLSConfig() *tls.Config
func (s *Server) VaultURL() string                   // "https://<name>.vault.azure.net"
func (s *Server) TenantID() string
func (s *Server) ClientID() string
func (s *Server) Secret() string
func (s *Server) ObjectID() string                    // the oid of the tokens it issues
func (s *Server) TestClient() *TestClient            // HTTPClient() *http.Client (DialAddr, CA, no proxy); GetJSON(t, path) with a valid token
func (s *Server) SecretValue(name, version string) []byte // the secret value it serves (leak-test needles)
func (s *Server) LastAccessToken() string            // the last token it issued (leak-test needle)
// State.
func (s *Server) AddCertificate(name string, o CertOptions) string // returns the version ID
func (s *Server) Renew(name string) string                         // a new version signed by the fake CA (KV auto-renewal)
func (s *Server) SetExportable(name string, exportable bool)
func (s *Server) DisableVersion(name, version string)
func (s *Server) DeleteCertificate(name string)
func (s *Server) AddKey(name string, o KeyOptions)
func (s *Server) AddSecret(name, contentType string)
func (s *Server) Leaf(name, version string) *x509.Certificate
// Faults (spec §22.5).
func (s *Server) RevokeRole(action string) // "certificates/list", "certificates/get", "keys/list", "keys/get", "secrets/list", "secrets/get", "certificates/import"
func (s *Server) GrantRole(action string)
func (s *Server) Firewall(clientAddress string) // "" = off; else every vault call answers 403 ForbiddenByFirewall naming the address
func (s *Server) FailNext(path string, f Fault) // the next request whose path starts with path answers f
func (s *Server) SetLatency(d time.Duration)
func (s *Server) Hold(path string) (release func())   // the next request on path waits until release (L-87)
func (s *Server) ExpireSecret()                        // token requests answer AADSTS7000222
func (s *Server) Requests() []Request                  // method, host, path, query keys; never bodies or headers
type Fault struct {
	Status     int
	Body       string // raw body ("" = the real shape for Status)
	RetryAfter string
	Truncate   bool   // cut the body in half (F-52)
	Location   string // a redirect target
	NextLink   string // replace the nextLink of a listing (A-14)
	Apply      bool   // process the request first, then answer the fault (an import that happened although the answer failed)
}
type CertOptions struct {
	CommonName string; SANs []string
	KeyType    pki.KeyType   // default ECDSA256
	Exportable bool          // default false unless set; the e2e and most tests set true
	ContentType string       // "application/x-pkcs12" (default) | "application/x-pem-file"
	IncludeRoot bool         // the secret's bundle carries the fake root
	NotBefore, NotAfter time.Time
}
type KeyOptions struct { KeyType string; Size int; Curve string; Enabled bool; Expires *time.Time }
type Request struct { Method, Host, Path string; Query []string }
```

### Inventory additions (Tasks 10–14)

```go
// Types and statuses.
const TypeAzureKeyVault = "azure_key_vault"
const StatusDegraded = "degraded"

// Job types (jobs.go).
const (
	JobKVTest   = "kv.test_connection"     // payload: {} or {"read_secret_of": <kv_certificate id>}; dedupe "kv.test_connection:<vault>"
	JobKVPoll   = "kv.poll"                // payload: {}; dedupe "kv.poll:<vault>"
	JobKVImport = "certificate.import_to_kv" // payload: {"import_id": <id>}; dedupe "certificate.import_to_kv:<id>"
)

// Target gains: Vault *VaultInfo (nil for servers).
type VaultInfo struct {
	URL             string
	Name            string
	Auth            string     // providers.AzureAuth*
	TenantID        string
	ClientID        string
	SecretExpiresOn *time.Time // what the administrator typed (client secret only)
	CertThumbprint  string     // certificate sign-in: hex SHA-1 (what Azure shows)
	CertNotAfter    *time.Time
	PollInterval    time.Duration
	Access          *providers.AzureFacts // Facts.Azure
}
// Facts gains: Azure *providers.AzureFacts `json:"azure,omitempty"`; KVMetadataAt *time.Time `json:"kv_metadata_at,omitempty"`;
// KVAuthFailures int `json:"kv_auth_failures,omitempty"`; KVThrottledCycles int `json:"kv_throttled_cycles,omitempty"`.

// Vaults (Task 10).
type NewVault struct {
	Name, VaultURL, Auth, TenantID, ClientID string
	ClientSecret    secrets.Plaintext // client_secret; zeroed by CreateVault
	SecretExpiresOn *time.Time
	Certificate     certs.Upload      // certificate (PEM fields or PFX + password)
	PollIntervalMinutes int           // 0 = 15
}
type VaultCredentialsInput struct { Auth, TenantID, ClientID string; ClientSecret secrets.Plaintext; SecretExpiresOn *time.Time; Certificate certs.Upload }
type Preflight interface { Check(ctx context.Context, url string, src providers.AzureCredentialSource) (providers.ConnectionReport, error) }
func (s *Service) CreateVault(ctx context.Context, a Actor, in NewVault) (Target, providers.ConnectionReport, uuid.UUID, error)
func (s *Service) ReplaceVaultCredentials(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, in VaultCredentialsInput) (Target, providers.ConnectionReport, error)
func (s *Service) VaultCredentials(id uuid.UUID) providers.CredentialSource // implements providers.AzureCredentialSource too
func (s *Service) RecordKVConnection(ctx context.Context, id uuid.UUID, rep providers.ConnectionReport) error
// TargetPatch gains PollIntervalMinutes *int (vaults only; 5..1440); DeleteTarget gains a variant
// DeleteVault(ctx, a, id, removeBindings bool); RequestTest(ctx, a, id) and RequestDiscovery queue kv jobs for vaults;
// RequestAccessCheck(ctx, a, id, readSecretOf uuid.UUID) queues kv.test_connection with read_secret_of.

// Reconcile and polls (Task 11).
type KVSummary struct { Certificates, NewVersions, Removed, Keys, Secrets int; Held bool }
func (s *Service) KVPollRequest(ctx context.Context, id uuid.UUID) (providers.DiscoverRequest, error)
func (s *Service) ReconcileKV(ctx context.Context, id uuid.UUID, res providers.DiscoveryResult) (KVSummary, error) // fenced (WithClaim)
func (s *Service) RecordKVFailure(ctx context.Context, id uuid.UUID, err *providers.Error) error
func (s *Service) ScheduleKVPolls(ctx context.Context) (int, error)
func (s *Service) ListKVCertificates(ctx context.Context, f KVFilter) (KVCertificatePage, error)
func (s *Service) KVCertificate(ctx context.Context, id uuid.UUID) (KVCertificateDetail, error) // with versions and binding
func (s *Service) ListKVKeys(ctx context.Context, f KVFilter) (KVKeyPage, error)
func (s *Service) ListKVSecrets(ctx context.Context, f KVFilter) (KVSecretPage, error)

// Bindings and Key Vault deployments (Task 12).
const MaxBindingLocations = 200
type BindingInput struct { KVCertificateID uuid.UUID; LocationIDs []uuid.UUID }
func (s *Service) CreateBinding(ctx context.Context, a Actor, in BindingInput) (Binding, error)
func (s *Service) UpdateBindingLocations(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, locations []uuid.UUID) (Binding, error)
func (s *Service) SetAutoDeploy(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, enabled bool) (Binding, error)
func (s *Service) DeleteBinding(ctx context.Context, a Actor, id uuid.UUID) error
func (s *Service) Binding(ctx context.Context, id uuid.UUID) (Binding, error)
func (s *Service) ListDeployableLocations(ctx context.Context, f LocationFilter) (LocationPage, error) // carry 6
type KVDeployInput struct { BindingID, VersionID uuid.UUID; LocationIDs []uuid.UUID } // LocationIDs empty = every location of the binding
func (s *Service) RequestKVDeployment(ctx context.Context, a Actor, in KVDeployInput) ([]RequestedDeployment, error)
// Material gains: KV *KVSource; Warnings []string. KVSource{VaultID uuid.UUID; KVCertificateID uuid.UUID; Name, Version, Thumbprint string}.
func (s *Service) KVDeployMaterial(ctx context.Context, id uuid.UUID, secret providers.CertificateSecret) (Material, error) // zeroes secret.Value

// Auto-deploy (Task 13).
const (
	AutoDeployWave       = 5         // unfinished automatic deployments per binding
	AutoDeployMaxFailed  = 3         // failed deployments of one version in a binding stop the wave
	AutoDeployRetryAfter = time.Hour // between attempts at one location
	autoDeployBatch      = 50        // deployments created per planner run
)
func (s *Service) PlanKVAutoDeploy(ctx context.Context) (int, error)

// Imports (Task 14).
type ImportInput struct { CertificateID, VaultID uuid.UUID; Name string; ConfirmNewVersion bool }
type KVImport struct { ID, CertificateID, VaultID uuid.UUID; VaultName, Name string; NewVersion bool; State, Version, Thumbprint, ErrorCode string; ErrorParams map[string]string; JobID *uuid.UUID; RequestedByName string; CreatedAt time.Time; SentAt, FinishedAt *time.Time }
func (s *Service) RequestImport(ctx context.Context, a Actor, in ImportInput) (KVImport, error)
type ImportMaterial struct { Import KVImport; Request providers.ImportRequest } // Request.PFX: the caller zeroes it
func (s *Service) ImportMaterial(ctx context.Context, id uuid.UUID) (ImportMaterial, error) // fenced; state queued only
func (s *Service) MarkImportSent(ctx context.Context, id uuid.UUID) error                      // fenced; queued -> running, sent_at
func (s *Service) FinishImport(ctx context.Context, id uuid.UUID, r providers.ImportResult, perr *providers.Error) error
func (s *Service) KVImport(ctx context.Context, id uuid.UUID) (KVImport, error)
func (s *Service) ListKVImports(ctx context.Context, f ImportFilter) (ImportPage, error)
// ReconcileKV resolves uncertain imports (thumbprint seen -> succeeded; older than 24 h -> failed kv.import_outcome_unknown).
const ImportUnknownAfter = 24 * time.Hour
```

Inventory errors (`errors.go`), each with an API code in Task 17: `ErrVaultHasBindings`, `ErrLocationBound` (a `*LocationRefusalError` names the location), `ErrBindingExists`, `ErrNotExportable`, `ErrVersionDisabled`, `ErrKVCertificateMissing`, `ErrVersionNotDeployable`, `ErrHeldNeedsAdmin`, `ErrImportConfirmNeeded`, `ErrImportInProgress`, `ErrImportState` (an import job meets a record that is not queued: internal), `ErrSecretUnreadable`, `ErrSecretMismatch`, `ErrClientCertificateInvalid`, `ErrNotAVault`; and the provider-coded refusal of a pre-flight check is returned as the `*providers.Error` itself.

### Job types, payloads and periodic tasks (Task 15)

| Type | Class | Attempts | Kind | Target | Payload | Dedupe | Dead email |
|---|---|---|---|---|---|---|---|
| `kv.test_connection` | ReadOnly | 1 | user | vault | `{}` or `{"read_secret_of": id}` | `kv.test_connection:<vault>` | yes (a person asked) |
| `kv.poll` | ReadOnly | 1 | scheduled / user / system | vault | `{}` | `kv.poll:<vault>` | **no** (the vault carries it) |
| `certificate.import_to_kv` | Change | 3 | user | vault | `{"import_id": id}` | `certificate.import_to_kv:<id>` | yes |
| `kv.schedule` (periodic, 1 min) | ReadOnly | — | — | — | — | — | — |
| `kv.auto_deploy` (periodic, 1 min; e2e: never ticks) | Change | — | — | — | — | — | — |

Deployments created by **Deploy now** have trigger `manual`; by the planner `kv_renewal`, job kind `system`, actor `system:jobs`.

### Error codes (Task 17; reasons are produced by the tasks named)

| Code | Reason | HTTP | Retryable | Params | English title (exact) | Producer |
|---|---|---|---|---|---|---|
| ALC-AKV-0001 | `azure.auth_failed` | 502 | no | `aadsts` | Azure sign-in refused | Task 6 |
| ALC-AKV-0002 | `azure.credentials_expired` | 502 | no | `aadsts` | Azure sign-in secret expired | Task 6 |
| ALC-AKV-0003 | `azure.forbidden` | 502 | no | `role`, `model` | Missing permission in the vault | Task 6 |
| ALC-AKV-0004 | `azure.firewall` | 502 | no | `client_address` | Vault firewall blocks Alice | Task 6 |
| ALC-AKV-0005 | `azure.vault_not_found` | 502 | no | — | Vault not found | Task 6 |
| ALC-AKV-0006 | `azure.unreachable` | 502 | yes | — | Cannot reach Azure | Task 6 |
| ALC-AKV-0007 | `azure.throttled` | 503 | yes | — | Azure asked Alice to slow down | Task 6 |
| ALC-AKV-0008 | `azure.unexpected_response` | 502 | yes | — | Unexpected answer from Azure | Task 6 |
| ALC-AKV-0009 | `azure.clock_skew` | 502 | no | `aadsts` | Server clock rejected by Azure | Task 6 |
| ALC-AKV-0010 | `azure.managed_identity_unavailable` | 502 | no | — | Managed identity not available | Task 6 |
| ALC-AKV-0011 | `azure.address_not_allowed` | 502 | no | — | Azure address not allowed | Task 6 |
| ALC-AKV-0012 | `azure.tls_untrusted` | 502 | no | — | Azure's certificate is not trusted | Task 6 |
| ALC-AKV-0013 | `kv.not_exportable` | 422 | no | — | Private key not exportable | Tasks 12, 16 |
| ALC-AKV-0014 | `kv.version_disabled` | 409 | no | — | Version disabled in Key Vault | Tasks 6, 12, 16 |
| ALC-AKV-0015 | `kv.certificate_not_found` | 409 | no | — | Certificate no longer in the vault | Tasks 6, 12, 16 |
| ALC-AKV-0016 | `kv.secret_unreadable` | 502 | no | — | Certificate data could not be read | Tasks 12, 16 |
| ALC-AKV-0017 | `kv.secret_mismatch` | 502 | no | — | Vault data does not match the version | Tasks 12, 16 |
| ALC-AKV-0018 | `kv.location_bound` | 409 | no | `location_id` | Website already connected | Task 12 |
| ALC-AKV-0019 | `kv.binding_exists` | 409 | no | — | Certificate already connected | Task 12 |
| ALC-AKV-0020 | `kv.vault_has_bindings` | 409 | no | — | Vault still has connected websites | Task 10 |
| ALC-AKV-0021 | `kv.version_not_deployable` | 409 | no | — | Version cannot be deployed | Task 12 |
| ALC-AKV-0022 | `kv.held_needs_admin` | 403 | no | — | An administrator must deploy this version | Task 12 |
| ALC-AKV-0023 | `kv.import_confirm_needed` | 409 | no | `certificate_name` | Name already used in the vault | Task 14 |
| ALC-AKV-0024 | `kv.import_in_progress` | 409 | yes | — | Import already running | Task 14 |
| ALC-AKV-0025 | `kv.import_rejected` | 502 | no | `azure_code` | Key Vault refused the import | Task 8 |
| ALC-AKV-0026 | `kv.import_outcome_unknown` | 502 | no | — | Import outcome unknown | Task 14 |
| ALC-AKV-0027 | `kv.client_certificate_invalid` | 422 | no | — | Sign-in certificate not usable | Task 10 |

Message texts (`errors.<reason>.title|cause|action`) follow spec §11.9 and §11.5; the English `cause`+`action` of the codes the spec words are (Task 17 writes all three parts, Turkish formal): `azure.auth_failed` "Alice could not sign in to Azure with these details." / "Check the tenant ID, application ID and secret or certificate."; `azure.credentials_expired` "The secret or certificate Alice uses to sign in to Azure has expired." / "Create a new one in Azure and replace it on the vault's page in Alice."; `azure.forbidden` "Alice is signed in to Azure, but the vault does not allow what Alice tried." / "Ask your Azure administrator to give Alice's identity the role {{role}} on this vault (or the matching access policy)."; `azure.firewall` "The vault's firewall does not allow connections from this Alice server." / "Add Alice's address to the vault's allowed networks, or use a private endpoint."; `azure.vault_not_found` "The vault address cannot be found." / "Check the name and network access (private endpoints need internal DNS)."; `azure.throttled` "Azure is asking Alice to slow down." / "Alice retries automatically; nothing to do unless this continues for an hour."; `azure.clock_skew` "The clock on the Alice server appears to be wrong, so Azure rejected the sign-in." / "Correct the server's time (NTP)."; `kv.not_exportable` "This certificate's private key is marked non-exportable in Azure Key Vault, so Alice cannot copy it to a server." / "Create a new version of the certificate with 'Exportable private key' turned on, or upload a different certificate."; `kv.secret_unreadable` "The certificate data from Azure could not be read. Nothing was changed on your servers." / "Check the certificate's content type in Key Vault (PFX or PEM)."; `kv.version_disabled` "This version is disabled (or expired) in Key Vault, so it was not deployed." / "Enable it in Key Vault or deploy another version."; `kv.certificate_not_found` "This certificate no longer exists in the vault." / "Restore it in Key Vault, or remove its connection to websites.". The Turkish titles (exact): Azure oturum açma reddedildi; Azure oturum açma gizli anahtarının süresi doldu; Kasada eksik izin; Kasa güvenlik duvarı Alice'i engelliyor; Kasa bulunamadı; Azure'a ulaşılamıyor; Azure, Alice'ten yavaşlamasını istedi; Azure'dan beklenmeyen yanıt; Sunucu saati Azure tarafından reddedildi; Yönetilen kimlik kullanılamıyor; Azure adresine izin verilmiyor; Azure sertifikasına güvenilmiyor; Özel anahtar dışa aktarılamıyor; Sürüm Key Vault'ta devre dışı; Sertifika artık kasada yok; Sertifika verileri okunamadı; Kasa verileri sürümle eşleşmiyor; Web sitesi zaten bağlı; Sertifika zaten bağlı; Kasada hâlâ bağlı web siteleri var; Sürüm dağıtılamaz; Bu sürümü bir yönetici dağıtmalı; Ad kasada zaten kullanılıyor; Aktarma zaten sürüyor; Key Vault aktarmayı reddetti; Aktarmanın sonucu bilinmiyor; Oturum açma sertifikası kullanılamıyor.

Reused codes: `certificate.expired` (ALC-CRT-0003), `certificate.not_yet_valid` (ALC-CRT-0014), `certificate.key_type_mismatch` (ALC-CRT-0010), `certificate.no_private_key` (ALC-CRT-0009, import of a certificate without its key), `certificate.pfx_busy` (ALC-CRT-0015, the two PFX decode slots), `deployment.in_progress` (ALC-DEP-0001), `license.locked`/`license.unverified`. `providerParamRules` gains `role` (one of the three role constants), `model` (`rbac|access_policy|unknown`), `client_address` (`netip.ParseAddr` succeeds), `aadsts` (`^[0-9]{1,8}$`), `azure_code` (`azureid.ValidAzureCode`), `azure_request_id` (`azureid.ValidRequestID`), `certificate_name` (`azureid.ValidObjectName`), `location_id` (UUID; it already exists for Phase 4 refusals — reuse).

### Audit actions

`target.created` (vaults: `name`, `type`, `vault_url`, `auth`, `tenant_id`, `client_id`), `vault.add_refused` (result failure; `vault_url`, `auth`, `reason`), `vault.credentials_replaced` (`auth`, `client_id`), `target.updated` (`fields` gains `poll_interval`), `target.deleted` (vaults: `binding_count` when removed with it), `target.status_changed` (reasons `kv_poll_ok`, `kv_check_ok` besides Phase 3's), `kv.certificate.new_version` (object `kv_certificate`; `certificate_name`, `version`, `thumbprint`, `fingerprint`, `held`), `kv.certificate.removed`, `kv.secret_read` (object `kv_certificate`; `certificate_name`, `version`, `purpose` = `deploy`|`access_check`, `deployment_id`), `binding.created` (`kv_certificate_id`, `location_count`), `binding.updated` (`location_count`), `binding.auto_deploy_changed` (`enabled`), `binding.deleted`, `binding.denied` (result denied; `reason`, `location_id`), `kv.auto_deploy.stopped` (object `binding`; `version`, `failed_count`), `kv.import.requested`, `kv.import.denied`, `kv.import.succeeded` (`version`, `thumbprint`), `kv.import.failed` (`reason`), `kv.import.uncertain`. `deployment.requested` rows of Key Vault deployments add `binding_id` and `version`.

### Emails (Tasks 11, 13, 14; `locales/common/{en,tr}.json` `email.<template>.subject|body`, to every Administrator with an email address)

| Template | When | Params |
|---|---|---|
| `kv.auth_failed` | third consecutive failed sign-in of a vault (once per episode) | `vault_name`, `reason` |
| `kv.certificate_removed` | a known vault certificate disappeared from a complete listing (F-42), once | `vault_name`, `certificate_name`, `binding` (`yes`/`no`) |
| `kv.new_version_available` | a new version of a bound certificate whose binding has automatic deployment off, or a held version (once per version) | `vault_name`, `certificate_name`, `version`, `held` |
| `kv.version_skipped` | an automatic deployment did not start because the version is disabled, expired, not yet valid or older than the deployed one (once per version) | `vault_name`, `certificate_name`, `version`, `why` (`disabled`/`expired`/`not_yet_valid`/`older`) |
| `kv.auto_deploy_stopped` | the third failed deployment of a version in a binding (once per binding and version) | `vault_name`, `certificate_name`, `version`, `failed_count` |
| `kv.import_failed` | an import ended failed or outcome unknown | `vault_name`, `certificate_name`, `reason` |

Deployment emails stay Phase 4's (`deployment.failed`, …): a Key Vault deployment that fails or rolls back sends them.

### API routes (Task 17)

| Method and path | Permission | Class | Answer |
|---|---|---|---|
| `POST /api/v1/key-vaults` | `credentials.manage` | Change | 201 `{target, access, job_id}`; refusals as above |
| `PUT /api/v1/targets/{id}/vault-credentials` (`If-Match`) | `credentials.manage` | Change | 200 `{target, access}` |
| `GET /api/v1/targets?type=` | `read` | — | the target list filtered by type (`linux`, `nginx`, `azure_key_vault`); a vault item carries `vault` |
| `PATCH /api/v1/targets/{id}` | `targets.manage` | Change | vaults accept `name`, `poll_interval_minutes` |
| `DELETE /api/v1/targets/{id}?remove_bindings=true` | `targets.manage` | Change | 204; a vault with bindings and no flag: 409 ALC-AKV-0020 |
| `POST /api/v1/targets/{id}/actions/test` | `inventory.operate` | ReadOnly | vaults: body `{"read_secret_of": <kv_certificate id>}` optional; 202 job |
| `POST /api/v1/targets/{id}/actions/discover` | `inventory.operate` | ReadOnly | vaults: **Check now** (`kv.poll`); 202 job |
| `GET /api/v1/targets/{id}/kv/certificates`, `/kv/keys`, `/kv/secrets` | `read` | — | paged `{items, next_cursor}` (`?q=&expires_before=&cursor=&limit=`) |
| `GET /api/v1/kv-certificates/{id}` | `read` | — | detail with versions, binding, deploy access |
| `GET /api/v1/certificate-locations` | `read` | — | cross-server deployable locations (`?key_type=&unbound=true&q=&cursor=&limit=`) |
| `POST /api/v1/bindings` | `certificates.operate` | Change | 201 binding |
| `GET /api/v1/bindings/{id}` | `read` | — | binding with per-location state |
| `PATCH /api/v1/bindings/{id}` (`If-Match`) | `certificates.operate` | Change | `{"location_ids": […]}` |
| `PUT /api/v1/bindings/{id}/auto-deploy` (`If-Match`) | `targets.manage` | Change | `{"enabled": bool}` |
| `DELETE /api/v1/bindings/{id}` | `certificates.operate` | Change | 204 |
| `POST /api/v1/bindings/{id}/actions/deploy` | `certificates.operate` | Change | `{"version_id", "location_ids"?}` → 202 `{deployments: [{id, job_id, location_id, warnings}]}` |
| `POST /api/v1/certificates/{id}/actions/import-to-key-vault` | `certificates.operate` | Change | `{"target_id", "name", "confirm_new_version"}` → 202 `{import, job_id}` |
| `GET /api/v1/kv-imports?certificate_id=&target_id=`, `GET /api/v1/kv-imports/{id}` | `read` | — | imports |

`GET /api/v1/jobs` and `/jobs/{id}` items gain `deployment_id` and `import_id` (carry 5). `GET /api/v1/deployments` items gain `source` (`upload`|`key_vault`), `binding_id`, `kv_version` and `vault_name`. Bodies take their keys exactly once, in lower case (R38 item 18's rule); size caps: add-vault 768 KiB (a PFX), credentials 768 KiB, bindings 16 KiB, deploy 8 KiB, import 4 KiB.

### UI copy (exact; EN / TR)

| Key | English | Turkish |
|---|---|---|
| `nav.keyVaults` | Key Vaults | Key Vault kasaları |
| `vaults.title` | Key Vaults | Key Vault kasaları |
| `vaults.add` | Add Key Vault | Key Vault ekle |
| `vaults.empty` | No Key Vault yet. Add one to see its certificates and keys. | Henüz Key Vault yok. Sertifikalarını ve anahtarlarını görmek için bir tane ekleyin. |
| `vaults.fields.vault_url` | Vault address | Kasa adresi |
| `vaults.fields.auth` | Sign-in method | Oturum açma yöntemi |
| `vaults.auth.certificate` | Certificate (recommended) | Sertifika (önerilir) |
| `vaults.auth.client_secret` | Client secret | İstemci gizli anahtarı |
| `vaults.auth.managed_identity` | Managed identity | Yönetilen kimlik |
| `vaults.fields.tenant_id` | Directory (tenant) ID | Dizin (kiracı) kimliği |
| `vaults.fields.client_id` | Application (client) ID | Uygulama (istemci) kimliği |
| `vaults.fields.secret_expires` | The secret expires on (optional) | Gizli anahtarın bitiş tarihi (isteğe bağlı) |
| `vaults.checking` | Checking that Alice can sign in and reach the vault… | Alice'in oturum açıp kasaya ulaşabildiği denetleniyor… |
| `vaults.added` | Key Vault added. | Key Vault eklendi. |
| `vaults.signsInAs` | Alice signs in to Azure as {{objectId}} | Alice, Azure'da {{objectId}} olarak oturum açar |
| `vaults.roles.title` | Roles Alice needs | Alice'in ihtiyaç duyduğu roller |
| `vaults.roles.monitor` | Monitor certificates, keys and secrets | Sertifikaları, anahtarları ve gizli anahtarları izleme |
| `vaults.roles.deploy` | Deploy certificates to Nginx | Sertifikaları Nginx'e dağıtma |
| `vaults.roles.import` | Import certificates into the vault | Sertifikaları kasaya aktarma |
| `vaults.roles.readerUnconfirmed` | Expected to be enough; not yet confirmed on a real vault. | Yeterli olması bekleniyor; henüz gerçek bir kasada doğrulanmadı. |
| `vaults.access.title` | Access check | Erişim denetimi |
| `vaults.access.run` | Check again | Yeniden denetle |
| `vaults.access.deployToo` | Also test deployment access | Dağıtım erişimini de sına |
| `vaults.access.ok` | Allowed | İzin var |
| `vaults.access.forbidden` | Not allowed: needs {{role}} | İzin yok: {{role}} gerekiyor |
| `vaults.access.notChecked` | Not checked | Denetlenmedi |
| `vaults.access.importNote` | Checked when you import | Aktarma sırasında denetlenir |
| `vaults.checkNow` | Check now | Şimdi denetle |
| `vaults.status.degraded` | Partly working | Kısmen çalışıyor |
| `vaults.status.auth_failed` | Credentials refused | Kimlik bilgileri reddedildi |
| `vaults.status.unreachable` | Cannot reach Azure | Azure'a ulaşılamıyor |
| `vaults.status.noCertPermission` | No permission to read certificates | Sertifikaları okuma izni yok |
| `vaults.status.credentialsExpired` | Credentials expired | Kimlik bilgilerinin süresi doldu |
| `vaults.tabs.certificates` | Certificates | Sertifikalar |
| `vaults.tabs.keys` | Keys | Anahtarlar |
| `vaults.tabs.secrets` | Secrets | Gizli anahtarlar |
| `vaults.monitorOnly` | Monitor only | Yalnızca izleme |
| `vaults.removed` | Removed from Key Vault | Key Vault'tan kaldırıldı |
| `vaults.newVersion` | New version found | Yeni sürüm bulundu |
| `vaults.heldVersion` | New version found while the license was expired. An administrator can deploy it. | Lisansın süresi dolmuşken yeni sürüm bulundu. Bir yönetici dağıtabilir. |
| `vaults.replaceCredentials` | Replace credentials | Kimlik bilgilerini değiştir |
| `bindings.title` | Connected websites | Bağlı web siteleri |
| `bindings.connect` | Connect websites | Web sitelerine bağla |
| `bindings.autoDeploy` | Automatic deployment | Otomatik dağıtım |
| `bindings.autoDeployHelp` | When Key Vault renews this certificate, Alice deploys the new version to these websites. | Key Vault bu sertifikayı yenilediğinde Alice yeni sürümü bu web sitelerine dağıtır. |
| `bindings.deployNow` | Deploy now | Şimdi dağıt |
| `bindings.state.deployed` | Deployed: version {{version}} | Dağıtıldı: sürüm {{version}} |
| `bindings.state.pending` | Waiting to deploy | Dağıtım bekliyor |
| `bindings.state.failed` | Failed | Başarısız |
| `bindings.state.stopped` | Stopped after 3 failures | 3 başarısızlıktan sonra durduruldu |
| `bindings.deployAccessUnchecked` | Deploy access not checked | Dağıtım erişimi denetlenmedi |
| `imports.action` | Import into Key Vault | Key Vault'a aktar |
| `imports.newVersionWarning` | This will add a new version to the existing certificate {{name}}. | Bu, mevcut {{name}} sertifikasına yeni bir sürüm ekler. |
| `imports.noAutoRenew` | An imported certificate does not renew itself in Key Vault. | Aktarılan sertifika Key Vault'ta kendini yenilemez. |
| `imports.state.succeeded` | Imported | Aktarıldı |
| `imports.state.uncertain` | Not confirmed yet | Henüz doğrulanmadı |
| `imports.state.failed` | Failed | Başarısız |
| `deployments.source.key_vault` | From Key Vault | Key Vault'tan |

---
### Task 1: `internal/platform/azureid`: vault address, tenant and client IDs, object names, versions, thumbprints

The one rule for every Azure identifier Alice accepts or connects to (R40 rows 5, 6; A-14). Pure, no Alice imports, coverage 100.

**Files:**
- Create: `internal/platform/azureid/azureid.go`, `internal/platform/azureid/azureid_test.go`

**Interfaces:**
- Produces: the `azureid` API of the contract.

- [ ] **Step 1: Write the failing tests**

```go
package azureid_test

import (
	"crypto/sha1" //nolint:gosec // G505: x5t is SHA-1 by Azure's definition (test reference)
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/azureid"
)

func TestParseVaultTable(t *testing.T) {
	ok := map[string]string{
		"contoso-prod":                          "https://contoso-prod.vault.azure.net",
		"Contoso-Prod":                          "https://contoso-prod.vault.azure.net",
		"contoso-prod.vault.azure.net":          "https://contoso-prod.vault.azure.net",
		"https://contoso-prod.vault.azure.net":  "https://contoso-prod.vault.azure.net",
		"https://contoso-prod.vault.azure.net/": "https://contoso-prod.vault.azure.net",
		" HTTPS://KV1.VAULT.AZURE.NET ":         "https://kv1.vault.azure.net",
		"abc":                                   "https://abc.vault.azure.net",
		"a23456789012345678901234":              "https://a23456789012345678901234.vault.azure.net",
	}
	for in, want := range ok {
		v, err := azureid.ParseVault(in)
		if assert.NoError(t, err, in) {
			assert.Equal(t, want, v.URL, in)
			assert.Equal(t, strings.TrimPrefix(want, "https://"), v.Host, in)
			assert.Equal(t, strings.TrimSuffix(strings.TrimPrefix(want, "https://"), ".vault.azure.net"), v.Name, in)
		}
	}
	bad := []string{
		"", "ab", "a234567890123456789012345", "1abc", "-abc", "abc-", "ab--c", "ab_c", "ab.c",
		"http://contoso.vault.azure.net", "https://contoso.vault.azure.net:443", "https://contoso.vault.azure.net:8443",
		"https://contoso.vault.azure.net.evil.test", "https://contoso.vault.azure.net/secrets", "https://contoso.vault.azure.net//",
		"https://contoso.vault.azure.net?x=1", "https://user@contoso.vault.azure.net", "contoso.vault.usgovcloudapi.net",
		"contoso.vault.azure.cn", "contoso.managedhsm.azure.net", "https://contoso", "con toso", "kontosö",
		"contoso.privatelink.vaultcore.azure.net", "169.254.169.254", "https://169.254.169.254",
	}
	for _, in := range bad {
		_, err := azureid.ParseVault(in)
		assert.ErrorIs(t, err, azureid.ErrVault, in)
	}
}

func TestNormalizeGUID(t *testing.T) {
	g, ok := azureid.NormalizeGUID(" 6B8E2C1A-0F3D-4C2B-9A7E-1D2C3B4A5F60 ")
	assert.True(t, ok)
	assert.Equal(t, "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60", g)
	for _, in := range []string{"", "contoso.onmicrosoft.com", "6b8e2c1a0f3d4c2b9a7e1d2c3b4a5f60", "{6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60}",
		"6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f6", "6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f6g", "../6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f"} {
		_, ok := azureid.NormalizeGUID(in)
		assert.False(t, ok, in)
	}
	assert.True(t, azureid.ValidRequestID("6B8E2C1A-0F3D-4C2B-9A7E-1D2C3B4A5F60"))
	assert.False(t, azureid.ValidRequestID("not-a-guid"))
}

func TestObjectNamesVersionsThumbprintsCodes(t *testing.T) {
	assert.True(t, azureid.ValidObjectName("web-cert-2026"))
	assert.True(t, azureid.ValidObjectName(strings.Repeat("a", 127)))
	for _, n := range []string{"", strings.Repeat("a", 128), "web_cert", "web.cert", "web cert", "web/cert", "ü"} {
		assert.False(t, azureid.ValidObjectName(n), n)
	}
	assert.True(t, azureid.ValidVersion("0123456789abcdef0123456789abcdef"))
	assert.False(t, azureid.ValidVersion("0123456789ABCDEF0123456789abcdef"))
	assert.False(t, azureid.ValidVersion("0123"))
	der := []byte("leaf")
	sum := sha1.Sum(der) //nolint:gosec // G401: reference value
	assert.Equal(t, hex.EncodeToString(sum[:]), azureid.ThumbprintOf(der))
	tp, ok := azureid.Thumbprint(sum[:])
	assert.True(t, ok)
	assert.True(t, azureid.ValidThumbprint(tp))
	_, ok = azureid.Thumbprint(sum[:19])
	assert.False(t, ok)
	assert.True(t, azureid.ValidAzureCode("ForbiddenByRbac"))
	assert.False(t, azureid.ValidAzureCode("Forbidden By Rbac"))
	assert.False(t, azureid.ValidAzureCode("7000215"))
}
```

Run: `go test ./internal/platform/azureid -count=1`
Expected: FAIL (no non-test Go files).

- [ ] **Step 2: Implement**

```go
// Package azureid holds the Azure identifiers Alice accepts (spec §11.1, SEC-062, §25.4 A-14):
// one rule for what an administrator types (inventory) and what the azurekv provider connects to.
// Public cloud only (R40 rows 5-6).
package azureid

import (
	"crypto/sha1" //nolint:gosec // G505: x5t is SHA-1 by Azure's definition; Alice compares it, never trusts it
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// Fixed endpoints of the Azure public cloud (R40 rows 4, 5, 8).
const (
	AuthorityHost = "login.microsoftonline.com"
	AuthorityURL  = "https://" + AuthorityHost + "/"
	VaultSuffix   = ".vault.azure.net"
	VaultScope    = "https://vault.azure.net/.default"
	IMDSAddr      = "169.254.169.254:80"
)

// ErrVault: the text is not a vault address of the public cloud.
var ErrVault = errors.New("azureid: not a Key Vault address of the Azure public cloud")

var (
	vaultNameRE = regexp.MustCompile(`^[a-z](-?[a-z0-9])+$`)
	guidRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	objectRE    = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
	versionRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	thumbRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	codeRE      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
)

// Vault is a normalised vault address.
type Vault struct {
	Name string
	Host string
	URL  string
}

// foldASCII lowercases ASCII letters only (strings.ToLower is banned: Turkish İ/ı).
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// ParseVault accepts "name", "name.vault.azure.net" or "https://name.vault.azure.net", with one
// optional final "/" and any ASCII letter case, and nothing else: no other scheme, port, path,
// query, user, fragment or DNS suffix. The name follows Azure's rule: 3-24 characters, a letter
// first, letters, digits and single hyphens, a letter or digit last.
func ParseVault(raw string) (Vault, error) {
	s := foldASCII(strings.TrimSpace(raw))
	scheme := strings.HasPrefix(s, "https://")
	s = strings.TrimSuffix(strings.TrimPrefix(s, "https://"), "/")
	name, suffixed := strings.CutSuffix(s, VaultSuffix)
	if (scheme && !suffixed) || len(name) < 3 || len(name) > 24 || !vaultNameRE.MatchString(name) {
		return Vault{}, ErrVault
	}
	host := name + VaultSuffix
	return Vault{Name: name, Host: host, URL: "https://" + host}, nil
}

// NormalizeGUID returns a GUID in lower case without surrounding space.
func NormalizeGUID(raw string) (string, bool) {
	s := foldASCII(strings.TrimSpace(raw))
	return s, guidRE.MatchString(s)
}

// ValidObjectName reports a certificate, key or secret name Key Vault allows.
func ValidObjectName(s string) bool { return objectRE.MatchString(s) }

// ValidVersion reports a Key Vault version ID (32 lower-case hex digits).
func ValidVersion(s string) bool { return versionRE.MatchString(s) }

// ValidThumbprint reports an x5t as Alice stores it (40 lower-case hex digits).
func ValidThumbprint(s string) bool { return thumbRE.MatchString(s) }

// Thumbprint encodes a decoded x5t (SHA-1, 20 bytes) as hex.
func Thumbprint(x5t []byte) (string, bool) {
	if len(x5t) != sha1.Size {
		return "", false
	}
	return hex.EncodeToString(x5t), true
}

// ThumbprintOf is the x5t of a DER certificate, as hex.
func ThumbprintOf(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // G401: x5t is SHA-1 by definition; compared with Azure's value only
	return hex.EncodeToString(sum[:])
}

// ValidRequestID reports an x-ms-request-id (a GUID in any letter case).
func ValidRequestID(s string) bool {
	_, ok := NormalizeGUID(s)
	return ok && strings.TrimSpace(s) == s
}

// ValidAzureCode reports an Azure error or inner error code Alice may keep (R40 row 26).
func ValidAzureCode(s string) bool { return codeRE.MatchString(s) }
```

Run the Step 1 command, then `go test -cover ./internal/platform/azureid -count=1`
Expected: PASS, `coverage: 100.0% of statements`.

- [ ] **Step 3: Commit**

```bash
git add -- internal/platform/azureid
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(azureid): Azure vault addresses, IDs, names and thumbprints Alice accepts

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/platform/azureid
```

### Task 2: Provider framework: Azure identity source, Key Vault discovery types, `ReadCertificateSecret` and `ImportCertificate`, capability, import outcome rules, conformance suite, fake provider

The framework half of the provider contract (spec §6.1–§6.3, §6.5): the types of the contract's "Provider framework additions", the two new session methods with `UnsupportedSession`, the import outcome rules (like `outcome.go`), the conformance suite's new checks and the fake provider's support. `internal/providers` keeps its 100 % floor.

**Files:**
- Create: `internal/providers/azure.go`, `internal/providers/import_outcome.go`, `internal/providers/azure_test.go`, `internal/providers/import_outcome_test.go`
- Modify: `internal/providers/capability.go`, `internal/providers/provider.go` (Session), `internal/providers/types.go` (`DiscoverRequest`, `DiscoveryResult`, `ConnectionReport`), `internal/providers/unsupported.go`, `internal/providers/providers_test.go`, `internal/providers/providertest/providertest.go`, `internal/providers/providertest/providertest_test.go`, `internal/providers/fake/fake.go`, `internal/providers/fake/fake_test.go`

**Interfaces:**
- Consumes: `azureid.ValidVersion`, `azureid.ValidThumbprint`; `secrets.NewPlaintext`.
- Produces: the provider framework additions of the contract.

- [ ] **Step 1: Write the failing tests**

`internal/providers/azure_test.go`:

```go
func TestAzureIdentityNeverPrints(t *testing.T) {
	secret := "fake-" + strings.Repeat("ab", 20)
	key := []byte("-----BEGIN " + "PRIVATE KEY-----canary")
	id := providers.AzureIdentity{Auth: providers.AzureAuthClientSecret, TenantID: "t", ClientID: "c",
		ClientSecret: providers.NewSecret([]byte(secret)), PrivateKeyDER: providers.NewSecret(key)}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "id", id)
	raw, err := json.Marshal(id)
	require.NoError(t, err)
	for _, s := range []string{fmt.Sprintf("%v", id), fmt.Sprintf("%+v", id), fmt.Sprintf("%#v", id), fmt.Sprintf("%s", id),
		fmt.Sprintf("%v", &id), buf.String(), string(raw)} {
		assert.NotContains(t, s, secret)
		assert.NotContains(t, s, "canary")
	}
	assert.Contains(t, fmt.Sprintf("%v", id), "auth:client_secret")
	id.Zero()
	assert.Equal(t, make([]byte, len(secret)), id.ClientSecret.Bytes(), "Zero clears the secret in place")
	// CertificateSecret and ImportRequest redact the same way (value, PFX).
}

func TestNewSecretHoldsTheBytes(t *testing.T) {
	b := []byte("x")
	s := providers.NewSecret(b)
	s.Zero()
	assert.Equal(t, []byte{0}, b, "the holder shares the caller's bytes")
}

func TestReadAndImportAreUnsupportedByDefault(t *testing.T) {
	var s providers.Session = providers.UnsupportedSession{}
	_, err := s.ReadCertificateSecret(context.Background(), providers.SecretRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.ImportCertificate(context.Background(), providers.ImportRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
}

func TestReadCertificateSecretIsAKnownCapability(t *testing.T) {
	// A registry accepts a provider advertising read_certificate_secret (knownCapabilities).
}
```

(Write the comment-only tests out, and extend `TestAzureIdentityNeverPrints` with the `CertificateSecret` and `ImportRequest` cases.)

`internal/providers/import_outcome_test.go` — a table over `ImportResult.Validate` and `CheckImportReturn`:

```go
func TestImportResultRules(t *testing.T) {
	v, tp := strings.Repeat("a", 32), strings.Repeat("b", 40)
	created := providers.ImportResult{Outcome: providers.ImportCreated, Version: v, Thumbprint: tp, CER: []byte{1}}
	refusal := providers.NewError("azure.forbidden", false, nil, nil)
	cases := []struct {
		name string
		r    providers.ImportResult
		err  error
		ok   bool
	}{
		{"created", created, nil, true},
		{"created with an error", created, refusal, false},
		{"created without a version", providers.ImportResult{Outcome: providers.ImportCreated, Thumbprint: tp, CER: []byte{1}}, nil, false},
		{"created with a bad thumbprint", providers.ImportResult{Outcome: providers.ImportCreated, Version: v, Thumbprint: "x", CER: []byte{1}}, nil, false},
		{"created without the leaf", providers.ImportResult{Outcome: providers.ImportCreated, Version: v, Thumbprint: tp}, nil, false},
		{"refused", providers.ImportResult{Outcome: providers.ImportRefused}, refusal, true},
		{"refused without a provider error", providers.ImportResult{Outcome: providers.ImportRefused}, errors.New("x"), false},
		{"refused with a nil error", providers.ImportResult{Outcome: providers.ImportRefused}, nil, false},
		{"refused with a version", providers.ImportResult{Outcome: providers.ImportRefused, Version: v}, refusal, false},
		{"uncertain", providers.ImportResult{Outcome: providers.ImportUncertain}, errors.New("timeout"), true},
		{"uncertain without an error", providers.ImportResult{Outcome: providers.ImportUncertain}, nil, false},
		{"uncertain with a leaf", providers.ImportResult{Outcome: providers.ImportUncertain, CER: []byte{1}}, errors.New("x"), false},
		{"blank", providers.ImportResult{}, nil, false},
		{"unknown", providers.ImportResult{Outcome: "maybe"}, nil, false},
		{"unsupported", providers.ImportResult{}, providers.ErrUnsupported, false},
	}
	for _, tc := range cases {
		err := providers.CheckImportReturn(tc.r, tc.err)
		if tc.ok {
			assert.NoError(t, err, tc.name)
		} else {
			assert.Error(t, err, tc.name)
		}
	}
}
```

`providertest_test.go`: a session advertising `read_certificate_secret` but answering `ErrUnsupported` fails `CheckSession` (use the existing failing-session fixture pattern of the file), and one without the capability that does not answer `ErrUnsupported` fails `CheckUnsupported`; `CheckImportResult` reports a broken result.

`fake_test.go`: `fake.New(providers.KindAzureKV, providers.CapReadCertificateSecret, providers.CapImportCertificate)` returns `Config.Secret`/`Config.SecretErr` and `Config.Import(req)` (default: created with a generated version, thumbprint and leaf), records `ReadCertificateSecret` and `ImportCertificate` calls with the PFX and the value cleared (as `DeployCertificate` clears the key), answers `ErrUnsupported` without the capabilities, and `Open` with a credential source that implements `providers.AzureCredentialSource` calls `AzureIdentity` (and its release) instead of `SSHSigner` when the kind is `azurekv`.

Run: `go test ./internal/providers/... -count=1`
Expected: FAIL (undefined: providers.AzureIdentity, …).

- [ ] **Step 2: Implement**

`azure.go`: the types and constants of the contract, with

```go
func (a AzureIdentity) redacted() string {
	return fmt.Sprintf("providers.AzureIdentity{auth:%s, tenant:%s, client:%s, secret:[redacted]}", a.Auth, a.TenantID, a.ClientID)
}

// Format prints the method and the IDs only, for every verb and flag (pointers too).
func (a AzureIdentity) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, a.redacted()) }

// LogValue keeps the secrets out of slog output.
func (a AzureIdentity) LogValue() slog.Value { return slog.StringValue(a.redacted()) }

// Zero clears the client secret and the private key in place.
func (a AzureIdentity) Zero() {
	a.ClientSecret.Zero()
	a.PrivateKeyDER.Zero()
}
```

and the same three methods for `CertificateSecret` (prints `providers.CertificateSecret{content_type:<ct>, value:[redacted]}`) and `ImportRequest` (prints the operation and the name). `import_outcome.go`:

```go
package providers

import (
	"errors"
	"fmt"

	"alice/internal/platform/azureid"
)

// Validate checks ImportResult's invariants: created carries a valid version, a valid thumbprint
// and the leaf; refused and uncertain carry none of them; any other outcome is invalid.
func (r ImportResult) Validate() error {
	switch r.Outcome {
	case ImportCreated:
		if !azureid.ValidVersion(r.Version) || !azureid.ValidThumbprint(r.Thumbprint) || len(r.CER) == 0 {
			return errors.New("providers: import result: created needs a version, a thumbprint and the leaf")
		}
	case ImportRefused, ImportUncertain:
		if r.Version != "" || r.Thumbprint != "" || len(r.CER) > 0 {
			return fmt.Errorf("providers: import result: %s carries no version, thumbprint or leaf", r.Outcome)
		}
	default:
		return fmt.Errorf("providers: import result: blank or unknown outcome %q", orBlank(r.Outcome))
	}
	return nil
}

// CheckImportReturn checks what ImportCertificate returned: Validate, then created with a nil
// error, refused with a *Error (nothing was created), uncertain with a non-nil error. A caller
// treats any violation as uncertain: the request may have reached the vault (R40 row 25).
func CheckImportReturn(r ImportResult, err error) error {
	if errors.Is(err, ErrUnsupported) {
		return errors.New("providers: import: ErrUnsupported is not an outcome")
	}
	if verr := r.Validate(); verr != nil {
		return verr
	}
	switch {
	case r.Outcome == ImportCreated && err != nil:
		return errors.New("providers: import: created with an error")
	case r.Outcome == ImportRefused && !isProviderError(err):
		return errors.New("providers: import: refused needs a *providers.Error")
	case r.Outcome == ImportUncertain && err == nil:
		return errors.New("providers: import: uncertain without an error")
	}
	return nil
}
```

`types.go`: `DiscoverRequest` becomes

```go
// DiscoverRequest selects what Discover reads. SSHKeys and Certificates are Phase 3/4's; for a
// Key Vault, Certificates lists the vault's certificates and the KV fields select the rest
// (spec §11.6; R40 rows 15-17).
type DiscoverRequest struct {
	SSHKeys, Certificates bool
	KVKeys, KVSecrets     bool
	KVKnown               map[string]KVKnown
	KVKnownKeys           map[string]time.Time
}
```

and `DiscoveryResult` and `ConnectionReport` gain `KV *KVInventory` and `Azure *AzureFacts`. `capability.go` adds `CapReadCertificateSecret` to the constants and `knownCapabilities`; `provider.go` adds the two methods to `Session` (the doc of the contract) and replaces "Phase 5 adds import." with a pointer to them; `unsupported.go` answers `ErrUnsupported` for both. `providertest`: `CheckUnsupported` checks both methods when their capability is absent; `sessionOps` gains `{"ReadCertificateSecret", providers.CapReadCertificateSecret, func(ctx, s) { return s.ReadCertificateSecret(ctx, providers.SecretRequest{}) }}` (an empty request is refused with a `*providers.Error`, never sent); `CheckImportResult(t testing.TB, r providers.ImportResult, err error)` reports `providers.CheckImportReturn`. `fake`: `Config` gains `Secret providers.CertificateSecret`, `SecretErr error`, `Import func(req providers.ImportRequest) (providers.ImportResult, error)`; `Call` gains `Secret providers.SecretRequest` and `Import providers.ImportRequest` (recorded with `PFX` cleared); `session` implements both methods (capability check first, `mustHonour("ImportCertificate", providers.CheckImportReturn(out, err))`); `Open` uses `AzureIdentity` for kind `azurekv` when the source implements it.

Run: `go build ./... && go vet ./... && go vet -tags integration ./...` (every `Session` implementation compiles: `nginx` and `linuxssh` sessions embed a `providers.Session`/`UnsupportedSession`; test doubles that embed `providers.Session` keep compiling), then `go test ./internal/providers/... -count=1` and `go test -cover ./internal/providers -count=1`
Expected: PASS; `internal/providers` at 100.0 %.

- [ ] **Step 3: Commit**

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(providers): Azure identity source, Key Vault discovery, secret read and import contract

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/providers
```

(`git add -- internal/providers/azure.go internal/providers/import_outcome.go internal/providers/azure_test.go internal/providers/import_outcome_test.go` first.)

### Task 3: Certificates: Key Vault secret decoding, service-principal certificate credentials, PFX export for import; `FuzzParseKVSecret`

The pure certificate work of Phase 5 (spec §11.3, §11.5 items 3–5, §11.8 step 2): decode a vault secret into a validated leaf, chain and key; validate a service principal's sign-in certificate; build the PFX of an import. Everything reuses `ValidateUpload`'s rules (key match, expiry, key and signature strength, the 16384-bit and iteration bounds, certificate time ranges).

**Files:**
- Create: `internal/certs/kvsecret.go`, `internal/certs/clientcert.go`, `internal/certs/pfx.go`, `internal/certs/kvsecret_test.go`, `internal/certs/clientcert_test.go`, `internal/certs/pfx_test.go`
- Modify: `internal/certs/certs.go` (errors), `Makefile` (`fuzz-certs` also runs `FuzzParseKVSecret` for 60 s)

**Interfaces:**
- Consumes: `ValidateUpload`, `Upload`, `Validated`, `Parsed`, `ParseChainPEM`, `MaxInputSize`; `pki.{NewCA,CA.Issue,Opts,PFX,SelfSigned,RSA2048,ECDSA256}`; `software.sslmate.com/src/go-pkcs12` (`LegacyDES`).
- Produces: the `internal/certs` additions of the contract.

- [ ] **Step 1: Write the failing tests**

`kvsecret_test.go`:

```go
func TestParseKVSecretPFXAndPEM(t *testing.T) {
	now := time.Now().UTC()
	ca := pki.NewCA("KV Test CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	pfx := base64.StdEncoding.EncodeToString(pki.PFX(leaf, ca, ""))
	for name, tc := range map[string]struct{ ct, value string }{
		"pkcs12":             {certs.ContentTypePKCS12, pfx},
		"pkcs12 with spaces": {certs.ContentTypePKCS12, "\n" + pfx + "\n"},
		"pem key first":      {certs.ContentTypePEM, string(leaf.KeyPEM) + string(leaf.FullchainPEM)},
		"pem key last":       {certs.ContentTypePEM, string(leaf.FullchainPEM) + string(leaf.KeyPEM)},
		"pem with root":      {certs.ContentTypePEM, string(leaf.FullchainPEM) + string(ca.RootPEM) + string(leaf.KeyPEM)},
	} {
		v, err := certs.ParseKVSecret(tc.ct, []byte(tc.value), now, nil)
		require.NoError(t, err, name)
		assert.Equal(t, pki.Fingerprint(leaf.Cert), v.Fingerprint, name)
		assert.Len(t, v.Chain, 1, "%s: the intermediate only; a self-signed root is dropped", name)
		assert.Equal(t, 2, strings.Count(v.PEMChain, "BEGIN CERTIFICATE"), name)
		v.PrivateKeyDER.Zero()
	}
}

func TestParseKVSecretRefusals(t *testing.T) {
	// Table: unknown content type ("text/plain", "") → ErrKVContentType; PFX that is not base64 →
	// ErrInvalid; a PFX with a password → ErrPFXPassword; PEM without a key → ErrNoKey; PEM whose key
	// belongs to another certificate → ErrKeyMismatch; an expired leaf → ErrExpired; an RSA 1024 leaf
	// → ErrWeak; a value above MaxKVSecretSize → ErrTooLarge; an encrypted PEM key → ErrKeyEncrypted.
	// Every error's text contains no byte of the input (assert on a canary in the PEM).
}

func TestWithoutRootKeepsAChainWithoutRoot(t *testing.T) {
	// Parsed with Chain [intermediate] → unchanged; [intermediate, root] → [intermediate] and PEMChain
	// re-encoded; [] → unchanged; a self-signed leaf alone → unchanged (the leaf is never dropped).
}

func FuzzParseKVSecret(f *testing.F) {
	now := time.Now().UTC()
	ca := pki.NewCA("Fuzz CA", pki.ECDSA256, now)
	leaf := ca.Issue(pki.Opts{CommonName: "f.example.test"}, now)
	f.Add(certs.ContentTypePKCS12, []byte(base64.StdEncoding.EncodeToString(pki.PFX(leaf, ca, ""))))
	f.Add(certs.ContentTypePEM, append(append([]byte{}, leaf.FullchainPEM...), leaf.KeyPEM...))
	f.Add(certs.ContentTypePEM, []byte("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, ct string, value []byte) {
		v, err := certs.ParseKVSecret(ct, value, now, nil)
		if err == nil {
			require.NotNil(t, v.Leaf)
			v.PrivateKeyDER.Zero()
		}
	})
}
```

`clientcert_test.go`: an RSA 2048 PEM pair and an RSA PFX with a password are accepted (thumbprint = `azureid.ThumbprintOf(leaf DER)`, `NotAfter`, key PKCS #8); an ECDSA pair is `ErrClientCertKey`; an expired certificate `ErrExpired`; a key that does not match `ErrKeyMismatch`.

`pfx_test.go`: `ExportPFX` of an ECDSA and an RSA leaf with an intermediate decodes with `pkcs12.DecodeChain(pfx, "")` to the same key, leaf and chain; a key that is not PKCS #8 is `ErrInvalid`; the returned holder is a `secrets.Plaintext` and the key DER argument is not modified.

Run: `go test ./internal/certs -count=1`
Expected: FAIL (undefined: certs.ParseKVSecret, …).

- [ ] **Step 2: Implement**

`kvsecret.go`:

```go
// ParseKVSecret decodes the backing secret of a vault certificate version (spec §11.5 items 3-5).
// application/x-pkcs12: base64 of a PFX with an empty password; application/x-pem-file: PEM text
// with CERTIFICATE and PRIVATE KEY blocks in any order. The result is validated as an upload and
// the chain loses a self-signed last certificate. Errors never contain input.
func ParseKVSecret(contentType string, value []byte, now time.Time, roots *x509.CertPool) (Validated, error) {
	if len(value) > MaxKVSecretSize {
		return Validated{}, ErrTooLarge
	}
	var u Upload
	switch contentType {
	case ContentTypePKCS12:
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(value)))
		if err != nil {
			return Validated{}, invalid("the vault secret is not base64")
		}
		u = Upload{PFX: raw}
	case ContentTypePEM:
		certPEM, keyPEM := splitPEM(value)
		u = Upload{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
	default:
		return Validated{}, ErrKVContentType
	}
	v, err := ValidateUpload(u, now, roots)
	if err != nil {
		return Validated{}, err
	}
	v.Parsed = WithoutRoot(v.Parsed)
	return v, nil
}
```

`splitPEM` walks `pem.Decode` and appends each block, re-encoded, to the certificate or the key buffer by its type (`CERTIFICATE`; `PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` to the key, so `ValidateUpload` gives its usual errors); the key buffer is zeroed by the caller path (`ValidateUpload` copies what it keeps into `PrivateKeyDER`; clear the buffer with `clear` after the call). `WithoutRoot` drops a final chain certificate whose subject equals its issuer and whose signature verifies with its own key (`CheckSignatureFrom` on itself), then rebuilds `PEMChain` from `Leaf` and the remaining `Chain` (`pem.EncodeToMemory` of each `Raw`). `clientcert.go`: `ValidateUpload`, then `Algorithm == "rsa"` (else zero the key and `ErrClientCertKey`), thumbprint `azureid.ThumbprintOf(v.Leaf.Raw)` (certs may import `platform/...`). `pfx.go`: `x509.ParsePKCS8PrivateKey(keyDER.Bytes())`, then `pkcs12.LegacyDES.Encode(key, p.Leaf, WithoutRoot(p).Chain, "")`, wrapped in `secrets.NewPlaintext`; any error is `invalid("…")`.

`Makefile` `fuzz-certs`: add the line `go test -count=1 -run '^$$' -fuzz FuzzParseKVSecret -fuzztime 60s ./internal/certs/`.

Run: `go test ./internal/certs -count=1`, `go test -count=1 -run '^$' -fuzz FuzzParseKVSecret -fuzztime 20s ./internal/certs/`, `go test -cover ./internal/certs -count=1`
Expected: PASS; no crash in 20 s; coverage at or above the floor (97).

- [ ] **Step 3: Commit**

```bash
git add -- internal/certs/kvsecret.go internal/certs/clientcert.go internal/certs/pfx.go internal/certs/kvsecret_test.go internal/certs/clientcert_test.go internal/certs/pfx_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(certs): decode Key Vault secrets, sign-in certificates and import PFX files

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/certs Makefile
```

### Task 4: Fake Azure part 1 (`internal/testutil/fakekv`): the Key Vault data plane and the reference shapes

An in-process fake of what Alice's SDK clients call on a vault (spec §22.5; R40 rows 2, 30), on api-version `2025-07-01`, answering with the shapes of the public REST reference. Part 1 serves the vault with a fixed bearer token check; Task 5 adds the token endpoint, managed identity, the challenge and the faults. The fake is test code: it may use `time.Now` (it is under `internal/testutil`, a test helper the forbidigo exception for tests covers through `_test.go` only — so take the time from `Options.Now`, defaulting to `clock.Real{}.Now`, and keep `time.Now` out of the package).

**Files:**
- Create: `internal/testutil/fakekv/fakekv.go` (Server, Options, lifecycle, TLS with a `pki` CA, `DialAddr`), `internal/testutil/fakekv/vault.go` (state: certificates with versions, keys, secrets; handlers), `internal/testutil/fakekv/shapes.go` (JSON encoders of each answer), `internal/testutil/fakekv/fakekv_test.go`, `internal/testutil/fakekv/shapes_test.go`
- Create: `test/testdata/kv-recordings/README.md` (the source page of each file, the rule "placeholders only, never real values", how `ALICE_AZURE_RECORD=1` rewrites them) and the JSON files `list_certificates.json`, `get_certificate.json`, `list_certificate_versions.json`, `get_secret_pkcs12.json`, `get_secret_pem.json`, `list_keys.json`, `get_key_rsa.json`, `get_key_ec.json`, `list_secrets.json`, `import_certificate.json`, `error_forbidden_rbac.json`, `error_forbidden_policy.json`, `error_forbidden_firewall.json`, `error_not_found.json`, `error_throttled.json`, `error_unauthorized.json`

**Interfaces:**
- Consumes: `pki`; `azureid`; `clock.Real`.
- Produces: the `fakekv` API of the contract (state methods; faults arrive in Task 5).

- [ ] **Step 1: Write the reference shapes and the failing tests**

Each JSON file is the REST reference's example answer for its operation (Key Vault REST API reference, api-version 2025-07-01: "Get Certificates", "Get Certificate", "Get Certificate Versions", "Get Secret", "Get Keys", "Get Key", "Get Secrets", "Import Certificate"; the error shapes from "Azure Key Vault REST API error codes" and "Azure Key Vault throttling guidance"), with every value that is key material, a thumbprint, a DER or a GUID replaced by a placeholder string (`"<cer>"`, `"<value>"`, `"<x5t>"`, `"<n>"`, `"<guid>"`), timestamps kept as numbers. For example `list_certificates.json`:

```json
{
  "value": [
    {
      "id": "https://<vault>.vault.azure.net/certificates/<name>",
      "x5t": "<x5t>",
      "attributes": {"enabled": true, "nbf": 1700000000, "exp": 1731536000, "created": 1700000600, "updated": 1700000600, "recoveryLevel": "Recoverable+Purgeable", "recoverableDays": 90},
      "tags": {}
    }
  ],
  "nextLink": "https://<vault>.vault.azure.net/certificates?api-version=2025-07-01&$skiptoken=<token>&maxresults=25"
}
```

`shapes_test.go`:

```go
// TestAnswersMatchTheReferenceShapes compares the key structure (object keys recursively, array
// elements by their first item, JSON types) of every fake answer with its reference file: the fake
// may add nothing and omit nothing the reference shows, except keys listed in optionalKeys (the
// reference marks them optional).
func TestAnswersMatchTheReferenceShapes(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	s.AddSecret("db-password", "text/plain")
	c := s.TestClient() // http.Client trusting the fake's CA and dialing through DialAddr, with the fake's bearer token
	for file, path := range map[string]string{
		"list_certificates.json":         "/certificates",
		"get_certificate.json":           "/certificates/web-cert/",
		"list_certificate_versions.json": "/certificates/web-cert/versions",
		"list_keys.json":                 "/keys",
		"get_key_rsa.json":               "/keys/signing/",
		"list_secrets.json":              "/secrets",
	} {
		got := c.GetJSON(t, path)
		want := readShape(t, file)
		assert.Equal(t, keyPaths(want), keyPaths(got), file)
	}
}
```

(`readShape` reads `../../../test/testdata/kv-recordings/<file>`; `keyPaths` returns the sorted set of `path:type` strings. Add the secret, import and error cases with their state set up first; the error cases use `RevokeRole` in Task 5, so only the data-plane cases are in this task's list and Task 5 adds the rest.)

`fakekv_test.go`:

```go
func TestListingsArePagedAndUnversioned(t *testing.T) {
	// 60 certificates → three pages of 25, 25, 10 linked by nextLink on the vault host;
	// every id is https://<vault>/certificates/<name> without a version; x5t is base64url of the
	// SHA-1 of the current version's DER; Renew changes x5t and updated.
}

func TestGetLatestAndVersions(t *testing.T) {
	// GET /certificates/web-cert/ answers the latest version: versioned id, kid, sid, x5t, cer
	// (base64 std of the DER), policy.key_props {exportable, kty "EC", key_size 256, crv "P-256"},
	// secret_props.contentType, issuer.name "Self", lifetime_actions with AutoRenew; after Renew the
	// versions list has both (newest first) and GET of the old version still answers it.
}

func TestSecretOfAVersion(t *testing.T) {
	// GET /secrets/web-cert/<version> answers value (base64 PFX, empty password, leaf + fake
	// intermediate [+ root with IncludeRoot]) and contentType application/x-pkcs12; with
	// ContentType PEM the value is PEM text with a PRIVATE KEY block; a non-exportable certificate
	// answers 403 Forbidden with the inner code of the vault's model; GET /secrets/<name>/ without a
	// version is refused 400 (Alice never asks for "latest"; the fake makes the test fail loudly).
}

func TestImportCreatesAVersion(t *testing.T) {
	// POST /certificates/new-cert/import {value: base64 PFX, pwd: "", policy} → 200 bundle with a
	// new version; for an existing name a new version that becomes current; a PFX that does not
	// decode → 400 BadParameter with the reference shape.
}

func TestOtherAPIVersionsAreRefused(t *testing.T) {
	// ?api-version=7.5 → 400 with code "BadParameter" (R40 row 2).
}
```

Run: `go test ./internal/testutil/fakekv -count=1`
Expected: FAIL (no non-test Go files).

- [ ] **Step 2: Implement**

`fakekv.go`: `NewServer` creates a CA with `pki.NewCA("Alice fake Azure", pki.ECDSA256, now)`, a server certificate for `login.microsoftonline.com`, `<vault>.vault.azure.net` and `127.0.0.1` issued by it, and a TLS `httptest.Server` (`httptest.NewUnstartedServer(handler)`, `TLS = &tls.Config{Certificates: …, MinVersion: tls.VersionTLS12}`, `StartTLS()`). `DialAddr` maps `login.microsoftonline.com:443`, `<vault>.vault.azure.net:443` and `169.254.169.254:80` to the listener's address (the IMDS route is served on the same TLS listener in Task 5 through a second plain listener — keep a plain `http.Server` on another `127.0.0.1:0` port for `169.254.169.254:80`) and returns other addresses unchanged. `Start(t, o)` wraps `NewServer` with `t.Cleanup(s.Close)`. `TestClient()` (exported for tests of other packages too) returns a client whose transport dials through `DialAddr` with the CA pool, and a `GetJSON(t, path)` helper that adds `api-version=2025-07-01` and the fake's test bearer token.

`vault.go`: a `sync.Mutex`-guarded state: `certs map[string]*fakeCert` (name → versions in creation order, each with DER, key, thumbprint, attributes, policy, content type), `keys`, `secrets`; routes on the vault host only (any other `Host` answers 404 with no body: the fake never answers a name it does not own): `GET /certificates`, `GET /certificates/{name}/`, `GET /certificates/{name}/{version}`, `GET /certificates/{name}/versions`, `POST /certificates/{name}/import`, `GET /keys`, `GET /keys/{name}/`, `GET /secrets`, `GET /secrets/{name}/{version}`; paging with `$skiptoken` (an opaque index) and 25 items per page; `api-version` must be `2025-07-01`. `Renew` issues a new leaf with the same names and key type from the fake CA (KV auto-renewal); new version IDs are 32 random hex digits. `shapes.go` encodes each answer as the reference does (Unix seconds for times; `x5t` base64url without padding; `cer` and PFX `value` base64 standard).

Run the Step 1 command and `go vet ./internal/testutil/...`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- internal/testutil/fakekv test/testdata/kv-recordings
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "test(fakekv): in-process Key Vault data plane with reference answer shapes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/testutil/fakekv test/testdata/kv-recordings
```

### Task 5: Fake Azure part 2: Entra ID token endpoint, managed identity, the Key Vault challenge, fault injection, request log; SDK round trip

The identity half of the fake and its fault controls (spec §22.5: "the Entra ID token endpoint for client secret and client certificate assertions (the fake validates the JWT client assertion structure and signature), and the managed-identity endpoint"), plus the proof that the real SDK clients work against it (R40 row 1: the fake must satisfy Microsoft's client).

**Files:**
- Create: `internal/testutil/fakekv/identity.go` (openid configuration, token endpoint, IMDS, token issuing and checking), `internal/testutil/fakekv/faults.go`, `internal/testutil/fakekv/identity_test.go`, `internal/testutil/fakekv/sdk_test.go`
- Create: `test/testdata/kv-recordings/token_ok.json`, `token_error_7000215.json`, `token_error_7000222.json`, `openid_configuration.json`, `imds_token.json`, `challenge.txt` (the `WWW-Authenticate` value with placeholders)
- Modify: `internal/testutil/fakekv/vault.go` (challenge on unauthenticated requests, role checks, firewall, faults, log), `internal/testutil/fakekv/shapes_test.go` (identity and error shapes)
- Modify: `go.mod`, `go.sum` (the Azure SDK modules of the Tech Stack, needed by `sdk_test.go`; the provider imports them in Task 6)

**Interfaces:**
- Consumes: Task 4's server.
- Produces: the fault, identity and log methods of the `fakekv` contract.

- [ ] **Step 1: Write the failing tests**

`identity_test.go`:

```go
func TestTokenEndpoint(t *testing.T) {
	// GET /<tenant>/v2.0/.well-known/openid-configuration answers token_endpoint
	// https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token, authorization_endpoint, issuer.
	// POST …/token grant_type=client_credentials, scope=https://vault.azure.net/.default:
	//   client_secret right → 200 {token_type, expires_in, ext_expires_in, access_token}
	//   wrong secret → 401 invalid_client, error_codes [7000215]
	//   unknown client → 400 unauthorized_client, error_codes [700016]
	//   unknown tenant (path) → 400 invalid_request, error_codes [90002]
	//   after ExpireSecret → 401 invalid_client, error_codes [7000222]
	//   client_assertion (urn:ietf:params:oauth:client-assertion-type:jwt-bearer): verified as a PS256
	//   JWT whose header x5t#S256 is the registered certificate's SHA-256 and whose aud is the token
	//   endpoint, iss = sub = client_id, nbf <= now < exp (60 s skew); a wrong signature or an
	//   unregistered certificate → 401 invalid_client [700027]; an exp in the past → [700024].
	// The access token is a JWT-shaped string the fake issued (claims aud, iss, oid, tid, appid,
	// nbf, exp), built at run time; the vault accepts only tokens it issued and not expired.
}

func TestManagedIdentityEndpoint(t *testing.T) {
	// With Options.ManagedIdentity: GET http://169.254.169.254/metadata/identity/oauth2/token
	// ?api-version=2018-02-01&resource=https://vault.azure.net with Metadata: true → 200 {access_token,
	// client_id, expires_in, expires_on, ext_expires_in, not_before, resource, token_type}; without the
	// header → 400; with client_id other than MIClientID → 400 "Identity not found"; without
	// ManagedIdentity → 400 "Identity not found".
}

func TestVaultChallengeAndRoles(t *testing.T) {
	// An unauthenticated vault request → 401 with WWW-Authenticate Bearer
	// authorization="https://login.microsoftonline.com/<tenant>", resource="https://vault.azure.net".
	// RevokeRole("secrets/get") → GET /secrets/… 403 {"error":{"code":"Forbidden",…,"innererror":
	// {"code":"ForbiddenByRbac"}}} (Model access_policy: "ForbiddenByPolicy"); GrantRole restores it.
	// Firewall("203.0.113.7") → every vault call 403 ForbiddenByFirewall with "Client address:
	// 203.0.113.7" in the message.
}

func TestFaults(t *testing.T) {
	// FailNext("/certificates", Fault{Status: 429, RetryAfter: "7"}) → one 429 with Retry-After 7, then
	// normal; Fault{Status: 503}; Fault{Truncate: true} → half the body; Fault{Status: 302, Location:
	// "https://169.254.169.254/"}; Fault{NextLink: "https://evil.test/certificates"}; SetLatency;
	// Hold("/certificates") blocks the next listing until release; DeleteCertificate → 404
	// CertificateNotFound and absent from the listing; DisableVersion → version attributes enabled
	// false and its secret 403 with inner code "SecretDisabled".
}

func TestRequestLogHoldsNoSecrets(t *testing.T) {
	// After token requests (secret and assertion) and vault calls, Requests() lists method, host,
	// path and query keys; no entry contains the client secret, an assertion, a token or a PFX.
}
```

`sdk_test.go` — the real SDK clients against the fake (this is the fidelity proof of R40 row 30):

```go
func TestSDKClientsRoundTrip(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	ver := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	transport := s.TestClient().HTTPClient() // *http.Client: DialAddr, the fake's CA, no proxy
	opts := azcore.ClientOptions{Cloud: cloud.AzurePublic, Transport: transport, Retry: policy.RetryOptions{MaxRetries: -1},
		Telemetry: policy.TelemetryOptions{Disabled: true}}
	cred, err := azidentity.NewClientSecretCredential(s.TenantID(), s.ClientID(), s.Secret(),
		&azidentity.ClientSecretCredentialOptions{ClientOptions: opts, DisableInstanceDiscovery: true})
	require.NoError(t, err)
	certsClient, err := azcertificates.NewClient(s.VaultURL(), cred, &azcertificates.ClientOptions{ClientOptions: opts})
	require.NoError(t, err)
	pager := certsClient.NewListCertificatePropertiesPager(nil)
	var names []string
	for pager.More() {
		page, err := pager.NextPage(context.Background())
		require.NoError(t, err)
		for _, p := range page.Value {
			names = append(names, p.ID.Name())
			assert.Equal(t, "", p.ID.Version(), "a listing carries no version")
		}
	}
	assert.Equal(t, []string{"web-cert"}, names)
	got, err := certsClient.GetCertificate(context.Background(), "web-cert", "", nil)
	require.NoError(t, err)
	assert.Equal(t, ver, got.ID.Version())
	assert.True(t, *got.Policy.KeyProperties.Exportable)
	secretsClient, err := azsecrets.NewClient(s.VaultURL(), cred, &azsecrets.ClientOptions{ClientOptions: opts})
	require.NoError(t, err)
	sec, err := secretsClient.GetSecret(context.Background(), "web-cert", ver, nil)
	require.NoError(t, err)
	assert.Equal(t, "application/x-pkcs12", *sec.ContentType)
	// The same with NewClientCertificateCredential (an RSA pki leaf registered as Options.ClientCert)
	// and with NewManagedIdentityCredential (Options.ManagedIdentity; the transport maps
	// 169.254.169.254:80); azkeys.NewListKeyPropertiesPager and GetKey; ImportCertificate of a
	// certs.ExportPFX-shaped PFX built with pkcs12.LegacyDES (the test builds it directly).
}
```

Run: `go get github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.23.2 github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.14.1 github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates@v1.5.0 github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys@v1.5.0 github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets@v1.5.0 && go mod tidy && go mod verify`, then `go test ./internal/testutil/fakekv -count=1`
Expected: `all modules verified`; the tests FAIL (the identity routes do not exist).

- [ ] **Step 2: Implement**

`identity.go`: the routes on the `login.microsoftonline.com` host (`/{tenant}/v2.0/.well-known/openid-configuration`, `/{tenant}/oauth2/v2.0/token`) and the IMDS route on the plain listener (`/metadata/identity/oauth2/token`). Client assertions are verified by hand with the standard library: split on `.`, decode the base64url header and claims, check `alg == "PS256"` and `x5t#S256 == base64url(sha256(cert.Raw))`, verify with `rsa.VerifyPSS(pub, crypto.SHA256, sha256(header + "." + claims), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})`, then the claims. Access tokens: `base64url({"alg":"RS256","typ":"JWT"}) + "." + base64url(claims) + "." + base64url(32 random bytes)`, recorded in a set with their expiry. Every error body follows its reference file. `faults.go`: `FailNext`, `SetLatency`, `Hold`, `ExpireSecret`, `RevokeRole`, `GrantRole`, `Firewall`; the vault handler consults them in this order: log, latency, hold, fault, authentication (challenge), firewall, role, route. The request log keeps `Method`, `Host`, `Path` and the sorted query keys (never values: `$skiptoken` values and `client_id` stay out).

Run: `go test ./internal/testutil/fakekv -count=1 -race`
Expected: PASS (all five credential paths of the SDK round trip and every shape).

- [ ] **Step 3: Record the dependency justification**

`docs/dev/dependency-updates.md`: a section "Azure SDK for Go (Phase 5)" naming the five direct modules, their versions, why (R40 row 1, SEC-101 justification), the transitive modules, that `pkg/browser` and the interactive credentials are linked but never called (`TestAzureSDKSurface`, Task 6), and the update procedure (`go get …@vX`, `go mod tidy`, `go mod verify`, `make test test-integration`, re-run the fake round trip; a new SDK API version needs the fake's version check and the reference shapes updated).

- [ ] **Step 4: Commit**

```bash
git add -- internal/testutil/fakekv test/testdata/kv-recordings
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "test(fakekv): Entra ID, managed identity, Key Vault challenge and faults; SDK round trip

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/testutil/fakekv test/testdata/kv-recordings go.mod go.sum docs/dev/dependency-updates.md
```

### Task 6: `azurekv` provider part 1: SDK modules, guarded transport, Azure identities, error catalogue, retry loop, per-vault limiter

The plumbing every vault call goes through (R40 rows 1, 3, 4, 7, 8, 26): the transport that decides where requests may go, the SDK credential of a session, the mapping of every Azure failure to one closed reason, Alice's single retry loop and the per-vault limiter. Tasks 7 and 8 add the operations.

**Files:**
- Create: `internal/providers/azurekv/provider.go` (Provider, Options, New, schemas, `ValidateConfig`, `Open`, `ForgetTarget`, session struct), `transport.go`, `identity.go`, `kvapi.go` (the `kvAPI` interface and its SDK implementation), `errors.go`, `retry.go`, `limiter.go`, and tests `transport_test.go`, `identity_test.go`, `errors_test.go`, `retry_test.go`, `limiter_test.go`, `provider_test.go`, `surface_test.go`
- Modify: `internal/archtest/arch_test.go` (`TestAllowed` cases: `azurekv` → `platform/azureid` allowed, → `internal/certs` denied, → `internal/secrets` denied, → `providers/nginx` denied; `fakekv` → `providers` denied)

**Interfaces:**
- Consumes: `providers.{Provider,Session,UnsupportedSession,AzureCredentialSource,AzureIdentity,Env,TargetRef,Error,NewError,ConnectionCache,KindAzureKV,Cap*}`, `azureid`, `netaddr.DialContext`, `clock.Clock`; the SDK identifiers listed in "Plan verification".
- Produces: `azurekv.{Provider,Options,New}` and the constants of the contract; the internal `kvAPI`, `guardedTransport`, `mapError`, `call` (retry loop), `vaultLimiter`, used by Tasks 7–8.

- [ ] **Step 1: Write the failing tests**

`transport_test.go` (the fake from Tasks 4–5; `DialAddr` = `s.DialAddr`, roots = `s.CAPool()`):

```go
func TestGuardedTransportRefusesOtherHosts(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	g := newGuardedTransport([]string{azureid.AuthorityHost, "alice-test.vault.azure.net"}, s.CAPool(), s.DialAddr)
	for _, raw := range []string{
		"http://alice-test.vault.azure.net/certificates", "https://alice-test.vault.azure.net:8443/certificates",
		"https://other.vault.azure.net/certificates", "https://evil.test/", "https://169.254.169.254/",
		"https://user@alice-test.vault.azure.net/certificates", "https://management.azure.com/",
	} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
		require.NoError(t, err)
		_, err = g.Do(req)
		assert.ErrorIs(t, err, errHostNotAllowed, raw)
	}
	assert.Empty(t, s.Requests(), "nothing was sent")
}

func TestRedirectIsNeverFollowed(t *testing.T) {
	// FailNext("/certificates", Fault{Status: 302, Location: "https://169.254.169.254/"}): Do answers
	// errRedirect, the fake's log has one request, nothing reached another host.
}

func TestForeignNextLinkIsRefused(t *testing.T) {
	// A listing whose nextLink names https://evil.test/certificates: the second page fails with
	// errHostNotAllowed through the real SDK pager (azcertificates over guardedTransport).
}

func TestDialRefusesMetadataAddress(t *testing.T) {
	// DialAddr maps the vault host to 169.254.169.254:443: Do fails with an error matching
	// netaddr.ErrNotAllowed; mapped to 10.1.2.3 (a private endpoint) the dial is attempted (connection
	// refused in the test, not an address refusal).
}

func TestProxyEnvironmentIsIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	// A request through the transport reaches the fake (the proxy would have failed it).
}

func TestBodiesAreCapped(t *testing.T) {
	// A fault body of MaxBody+1 bytes: reading it fails with errBodyTooLarge; MaxBody bytes read fine.
}

func TestManagedIdentityTalksOnlyToIMDS(t *testing.T) {
	// imdsTransport accepts http://169.254.169.254:80 only: https, another host or port, and a vault
	// URL are errHostNotAllowed; with IDENTITY_ENDPOINT=https://evil.test/msi and IDENTITY_HEADER set
	// in the environment (t.Setenv), a session with a managed identity fails with
	// azure.managed_identity_unavailable and the fake saw no request to evil.test.
}
```

`identity_test.go`: a session opens with each sign-in method against the fake (`Options.ClientCert` for the certificate case; `Options.ManagedIdentity`), the token request carries the configured tenant and client, the credential source's `release` is called before `Open` returns, a source that does not implement `providers.AzureCredentialSource` answers `azure.auth_failed`, an identity with an ECDSA key answers `azure.auth_failed` (MSAL refuses it; the error text is not kept), and `AzureIdentity` errors (the database) are `internal.unexpected` with no cause text.

`errors_test.go` — `TestMapErrorTable`: build each failure with the fake (or by hand with `azcore.ResponseError`/`azidentity.AuthenticationFailedError` values whose `RawResponse` carries the reference body) and assert `(code, retryable, params)`:

| Failure | Code | Retryable | Params |
|---|---|---|---|
| token 401 `[7000215]` | `azure.auth_failed` | no | `aadsts=7000215` |
| token 400 `[700016]` | `azure.auth_failed` | no | `aadsts=700016` |
| token 400 `[90002]` | `azure.auth_failed` | no | `aadsts=90002` |
| token 401 `[7000222]` | `azure.credentials_expired` | no | `aadsts=7000222` |
| token 401 `[700027]` | `azure.auth_failed` | no | `aadsts=700027` |
| token 400 `[700024]` | `azure.clock_skew` | no | `aadsts=700024` |
| IMDS 400 "Identity not found", or no IMDS | `azure.managed_identity_unavailable` | no | — |
| vault 401 after a token | `azure.auth_failed` | no | — |
| 403 `ForbiddenByRbac` (action certificates/list) | `azure.forbidden` | no | `role=Key Vault Reader`, `model=rbac` |
| 403 `ForbiddenByPolicy` (secrets/get) | `azure.forbidden` | no | `role=Key Vault Secrets User`, `model=access_policy` |
| 403 `Forbidden` without inner code (import) | `azure.forbidden` | no | `role=Key Vault Certificates Officer`, `model=unknown` |
| 403 `ForbiddenByFirewall`, "Client address: 203.0.113.7" | `azure.firewall` | no | `client_address=203.0.113.7` |
| 403 `ForbiddenByFirewall` without a readable address | `azure.firewall` | no | — |
| 403 inner `SecretDisabled` | `kv.version_disabled` | no | — |
| 404 `CertificateNotFound` / `SecretNotFound` | `kv.certificate_not_found` | no | — |
| DNS NXDOMAIN for the vault host | `azure.vault_not_found` | no | — |
| DNS failure or refused connection for `login.microsoftonline.com` | `azure.unreachable` | yes | — |
| dial refused by `netaddr` | `azure.address_not_allowed` | no | — |
| TLS unknown authority | `azure.tls_untrusted` | no | — |
| 429 (after the retries) | `azure.throttled` | yes | — |
| 500/502/503/504, timeout | `azure.unreachable` | yes | — |
| malformed JSON, truncated body, `errBodyTooLarge`, `errRedirect`, `errHostNotAllowed` (a server-chosen URL) | `azure.unexpected_response` | yes | — |
| `context.Canceled` | `azure.unreachable` | yes | — (and `errors.Is(err, context.Canceled)`) |

Every row also asserts: the error is a `*providers.Error`, its `Error()` is `"providers: <code>"`, and neither `Error()`, `%+v`, the JSON nor a slog line of it contains the reference body's message text or a canary placed in it; `azure_request_id` (from the response's `x-ms-request-id`) and `azure_code` (the inner or top-level code) are params only when they pass `azureid.ValidRequestID` / `ValidAzureCode`.

`retry_test.go` — `TestRetryLoop` with `clock.Fake` (advance the clock from the test while `call` waits on `Env.Clock.After`): 429 with `Retry-After: 7` waits exactly 7 s then succeeds; 429 with an HTTP-date `Retry-After` waits until that date; `Retry-After: 600` (above 5 minutes) gives up at once with `azure.throttled`; 429 without the header waits a jittered delay in [0, 5 s], then [0, 10 s], [0, 20 s], [0, 40 s] (jitter injected as a function for the test: `full`), and the fifth failure ends with `azure.throttled` after exactly 5 attempts; 503 and a truncated body are retried; 403 and 404 are not; a cancelled context during a wait returns at once wrapping `context.Canceled`; each try gets its own 30 s deadline (a hanging fault ends that try with `azure.unreachable`, retried).

`limiter_test.go` — `TestPerVaultLimiter` (F-44: "other vaults' polling are not delayed"): with a fake clock, 20 calls on vault A take 4 s of clock time at 5 per second and at most 4 run at once; calls on vault B in the same instant do not wait for A; `ForgetTarget` drops A's limiter.

`provider_test.go`: `providertest.CheckProvider(t, azurekv.New(azurekv.Options{}))`; `ValidateConfig` refuses a missing or invalid `vault_url` (`validation.required`, `validation.pattern`); `Open` with a cancelled context returns an error wrapping `context.Canceled` without a request.

`surface_test.go` — `TestAzureSDKSurface`: walks the repository's `.go` files (outside `vendor` and the module cache) and fails on any of `NewDefaultAzureCredential`, `NewEnvironmentCredential`, `NewAzureCLICredential`, `NewAzureDeveloperCLICredential`, `NewDeviceCodeCredential`, `NewInteractiveBrowserCredential`, `NewWorkloadIdentityCredential`, `NewAzurePipelinesCredential`, `NewChainedTokenCredential`, `NewUsernamePasswordCredential`, `azidentity/cache`, `log.SetListener`, `Cache:` inside an `azidentity` options literal, `DisableChallengeResourceVerification: true`, `InsecureAllowCredentialWithHTTP`; and asserts that `azidentity.NewClientSecretCredential`, `NewClientCertificateCredential` and `NewManagedIdentityCredential` appear only in `internal/providers/azurekv/identity.go` (and tests).

Run: `go test ./internal/providers/azurekv ./internal/archtest -count=1`
Expected: FAIL (no non-test Go files in azurekv).

- [ ] **Step 2: Implement**

`transport.go`:

```go
package azurekv

// guardedTransport is the only HTTP transport of the provider and of the SDK clients it builds
// (R40 row 8, SEC-065, A-14): https to an allowed host and port, the connect-time address rule,
// no redirect, no environment proxy, bounded bodies.
type guardedTransport struct {
	allowed map[string]bool // "host:443"
	client  *http.Client
}

var (
	errHostNotAllowed = errors.New("azurekv: request to a host this session may not reach")
	errRedirect       = errors.New("azurekv: Azure answered with a redirect")
	errBodyTooLarge   = errors.New("azurekv: Azure's answer is larger than Alice reads")
)

func newGuardedTransport(hosts []string, roots *x509.CertPool, dialAddr func(string) string) *guardedTransport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // never the environment's proxy (R40 row 7)
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dialAddr != nil {
				addr = dialAddr(addr)
			}
			return netaddr.DialContext(ctx, dialer, network, addr)
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  TryTimeout,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		ForceAttemptHTTP2:      true,
		MaxIdleConnsPerHost:    VaultConcurrency,
		IdleConnTimeout:        90 * time.Second,
	}
	allowed := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		allowed[h+":443"] = true
	}
	return &guardedTransport{allowed: allowed, client: &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Do implements policy.Transporter.
func (g *guardedTransport) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.User != nil || !g.allowed[hostPort(req.URL, "443")] {
		return nil, errHostNotAllowed
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		_ = resp.Body.Close()
		return nil, errRedirect
	}
	resp.Body = &cappedBody{rc: resp.Body, left: MaxBody}
	return resp, nil
}

// hostPort is the URL's lower-case host and port (def when the URL names none).
func hostPort(u *url.URL, def string) string {
	port := u.Port()
	if port == "" {
		port = def
	}
	return foldASCII(u.Hostname()) + ":" + port
}

type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.rc.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return 0, errBodyTooLarge
	}
	return n, err
}

func (c *cappedBody) Close() error { return c.rc.Close() }
```

and `imdsTransport` (same shape; `Do` accepts only `http` to `azureid.IMDSAddr` with the default port `80`; its dialer refuses any other address before `dialAddr` mapping and dials with `(&net.Dialer{Timeout: 5 * time.Second}).DialContext`, not through `netaddr`: this is R40 row 4's single exception). `foldASCII` is a local copy (as `inventory` has one).

`identity.go`: `clientOptions(t policy.Transporter) azcore.ClientOptions` = `{Cloud: cloud.AzurePublic, Transport: t, Retry: policy.RetryOptions{MaxRetries: -1}, Telemetry: policy.TelemetryOptions{Disabled: true}}`; `newCredential(id providers.AzureIdentity, vaultOpts, imdsOpts azcore.ClientOptions) (azcore.TokenCredential, error)`:

```go
func newCredential(id providers.AzureIdentity, opts, imds azcore.ClientOptions) (azcore.TokenCredential, error) {
	switch id.Auth {
	case providers.AzureAuthClientSecret:
		// The SDK keeps the secret as a Go string for this session's lifetime (R40 row 33).
		return azidentity.NewClientSecretCredential(id.TenantID, id.ClientID, string(id.ClientSecret.Bytes()),
			&azidentity.ClientSecretCredentialOptions{ClientOptions: opts, DisableInstanceDiscovery: true})
	case providers.AzureAuthCertificate:
		cert, err := x509.ParseCertificate(id.CertificateDER)
		if err != nil {
			return nil, errBadIdentity
		}
		key, err := x509.ParsePKCS8PrivateKey(id.PrivateKeyDER.Bytes())
		rsaKey, ok := key.(*rsa.PrivateKey)
		if err != nil || !ok {
			return nil, errBadIdentity
		}
		return azidentity.NewClientCertificateCredential(id.TenantID, id.ClientID, []*x509.Certificate{cert}, rsaKey,
			&azidentity.ClientCertificateCredentialOptions{ClientOptions: opts, DisableInstanceDiscovery: true})
	case providers.AzureAuthManagedIdentity:
		o := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: imds}
		if id.ClientID != "" {
			o.ID = azidentity.ClientID(id.ClientID)
		}
		return azidentity.NewManagedIdentityCredential(o)
	default:
		return nil, errBadIdentity
	}
}
```

`kvapi.go`: the internal interface (the provider's operations depend only on it, so Tasks 7–8 unit-test with a hand fake as well as with `fakekv`):

```go
// kvAPI is what the provider asks of one vault (spec §11.2): sdkAPI over the SDK clients in
// production; a hand fake in unit tests. page callbacks see one page at a time; returning an error
// stops the listing.
type kvAPI interface {
	Token(ctx context.Context) (azcore.AccessToken, error)
	ListCertificates(ctx context.Context, page func([]*azcertificates.CertificateProperties) error) error
	GetCertificate(ctx context.Context, name, version string) (azcertificates.Certificate, error)
	ListCertificateVersions(ctx context.Context, name string, page func([]*azcertificates.CertificateProperties) error) error
	ListKeys(ctx context.Context, page func([]*azkeys.KeyProperties) error) error
	GetKey(ctx context.Context, name string) (azkeys.KeyBundle, error)
	ListSecrets(ctx context.Context, page func([]*azsecrets.SecretProperties) error) error
	GetSecret(ctx context.Context, name, version string) (azsecrets.Secret, error)
	ImportCertificate(ctx context.Context, name string, p azcertificates.ImportCertificateParameters) (azcertificates.Certificate, error)
}
```

`sdkAPI` holds the credential and the three clients (`azcertificates.NewClient(vaultURL, cred, &azcertificates.ClientOptions{ClientOptions: opts})`, likewise `azkeys` and `azsecrets`), built in `Open`; `Token` calls `cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureid.VaultScope}})`; each listing runs the pager and hands `page.Value` to the callback. Every `kvAPI` call by an operation goes through `s.call(ctx, op, fn)` (`retry.go`), which takes the vault's limiter slot, bounds the try with `TryTimeout`, classifies the error with `retryable(err)` and waits with `s.clock.After`.

`errors.go`: `mapError(err error, action string) *providers.Error` implementing the table (the `action` names the operation — `list_certificates`, `get_certificate`, `list_keys`, `get_key`, `list_secrets`, `read_secret`, `import_certificate`, `sign_in` — and decides the `role` param: Reader for the first five, Secrets User for `read_secret`, Certificates Officer for `import_certificate`). Response bodies are read only from the already-buffered `RawResponse` (the SDK buffers it), at most 64 KiB, decoded into `struct{ Error struct{ Code string; InnerError *struct{ Code string } `json:"innererror"` } }` or the Entra form `struct{ ErrorCodes []int `json:"error_codes"` }`; the firewall address is taken with `regexp.MustCompile(`Client address: ([0-9A-Fa-f.:]{2,45})`)` and kept only when `netip.ParseAddr` accepts it. The cause kept on the `*providers.Error` is a sentinel of this package (`errAzureResponse`, `errAzureSignIn`, …) joined with `context.Canceled`/`context.DeadlineExceeded` when they apply — never the SDK error itself (its `Error()` contains the response text). A log line, when the provider logs one, carries only fixed labels (`operation`, `code`, `status`, `azure_code`, `azure_request_id`) and is at Warn for `azure.throttled` (F-44 "a log line records throttling").

`limiter.go`: a provider-wide `map[string]*vaultLimiter` keyed by vault host, each a token bucket (rate `VaultRate`, burst `VaultRate`, refilled from `Env.Clock`) and a semaphore of `VaultConcurrency`; `ForgetTarget(id)` drops the entry of that target's host (the session remembers it).

`provider.go`: `New(o Options) *Provider`; `Kind() = providers.KindAzureKV`; `DisplayNameKey() = "provider.azurekv.name"`; capabilities as the contract; `Open(ctx, t, cred, env)`: `ctx.Err()` first; `azureid.ParseVault(t.Config["vault_url"].(string))`; `src, ok := cred.(providers.AzureCredentialSource)` (else `azure.auth_failed`); `id, release, err := src.AzureIdentity(ctx)` (an error → `internal.unexpected`, retryable); build the transports (`roots` from `o.RootCAs` when set), the credential and the clients, then `release()` (always, also on errors); the session embeds `providers.UnsupportedSession` and keeps the vault, the `kvAPI`, the limiter, `env.Clock` and `env.Log`.

Run: `go test ./internal/providers/azurekv ./internal/archtest -count=1 -race`, `go vet ./...`, `make lint`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- internal/providers/azurekv
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(azurekv): guarded transport, Azure sign-in, error catalogue, retries and per-vault limiter

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/providers/azurekv internal/archtest/arch_test.go go.mod go.sum
```

### Task 7: `azurekv` provider part 2: access check (`TestConnection`) and the vault inventory (`Discover`) with bounds

`TestConnection` is spec §11.3's access check without the optional secret read (the job adds that, Task 15); `Discover` is one poll's server side (spec §11.6 items 1–5; R40 rows 15–17).

**Files:**
- Create: `internal/providers/azurekv/connection.go`, `internal/providers/azurekv/discover.go`, `connection_test.go`, `discover_test.go`

**Interfaces:**
- Consumes: Task 6; `providers.{ConnectionReport,AzureFacts,AzureCheck,AzureCheck*,AzureResult*,Role*,DiscoverRequest,DiscoveryResult,KVInventory,KVCertificate,KVCertificateDetails,KVCertificateVersion,KVKey,KVKeyDetails,KVSecret,KVListFailure,KVKnown,Warning}`; `azureid.{Thumbprint,ValidObjectName,ValidVersion}`.
- Produces: `session.TestConnection`, `session.Discover`.

- [ ] **Step 1: Write the failing tests**

`connection_test.go`:

```go
func TestAccessCheckWithEveryRole(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	rep, err := openSession(t, s).TestConnection(context.Background())
	require.NoError(t, err)
	require.NotNil(t, rep.Azure)
	assert.Equal(t, s.ObjectID(), rep.Azure.ObjectID, "the oid of the token, shown as 'Alice signs in to Azure as'")
	assert.Equal(t, s.TenantID(), rep.Azure.TenantID)
	assert.Equal(t, []providers.AzureCheck{
		{Name: providers.AzureCheckSignIn, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListCertificates, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListKeys, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckListSecrets, Result: providers.AzureResultOK},
		{Name: providers.AzureCheckReadSecret, Result: providers.AzureResultNotChecked},
		{Name: providers.AzureCheckImport, Result: providers.AzureResultNotChecked},
	}, rep.Azure.Checks)
}

func TestAccessCheckReportsMissingRolesAndTheModel(t *testing.T) {
	// RevokeRole("keys/list") on an RBAC vault: list_keys forbidden with Role "Key Vault Reader",
	// PermissionModel "rbac", TestConnection returns the report and a nil error (monitoring
	// continues); Model access_policy → "access_policy"; all three lists forbidden → still nil error.
	// A sign-in failure (wrong secret) → error azure.auth_failed and no report; the firewall → every
	// list "forbidden" with Reason azure.firewall and the error is nil (the vault is reachable).
}
```

`discover_test.go` (fake clock; the fake's state):

```go
func TestDiscoverFetchesDetailsOnlyForChanges(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	v1 := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	s.AddCertificate("monitor-only", fakekv.CertOptions{CommonName: "m.example.test"})
	sess := openSession(t, s)
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	require.NotNil(t, res.KV)
	byName := map[string]providers.KVCertificate{}
	for _, c := range res.KV.Certificates {
		byName[c.Name] = c
	}
	require.NotNil(t, byName["web-cert"].Details)
	assert.Equal(t, v1, byName["web-cert"].Details.Version)
	assert.True(t, *byName["web-cert"].Details.Exportable)
	assert.False(t, *byName["monitor-only"].Details.Exportable)
	assert.Len(t, byName["web-cert"].Versions, 1)

	known := map[string]providers.KVKnown{}
	for _, c := range res.KV.Certificates {
		known[c.Name] = providers.KVKnown{Version: c.Details.Version, Thumbprint: c.Details.Thumbprint, Updated: *c.Details.Updated}
	}
	before := len(s.Requests())
	res, err = sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKnown: known})
	require.NoError(t, err)
	for _, c := range res.KV.Certificates {
		assert.Nil(t, c.Details, "unchanged (x5t, updated): no details read")
	}
	assert.Equal(t, 1, len(s.Requests())-before, "one listing page, no per-certificate call (§11.6: large vaults cost pages)")

	v2 := s.Renew("web-cert")
	res, err = sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKnown: known})
	require.NoError(t, err)
	// web-cert has Details with Version v2 and Versions [v2, v1] (newest first); monitor-only has none.
	_ = v2
}

func TestDiscoverBounds(t *testing.T) {
	// With the bounds lowered through package variables (maxKVCertificates = 30, maxKVDetails = 10,
	// maxKVVersions = 3, set in the test): 40 certificates → 30 listed, Truncated ["certificates"],
	// at most 10 with Details and DetailsPending 20; a certificate with 5 versions → 3 Versions and
	// Truncated contains "versions"; keys and secrets the same with their bounds; a listing that
	// passes PollBudget ends with what was read and Truncated (the remaining lists are not read).
}

func TestDiscoverKeysAndSecretsOnlyWhenAsked(t *testing.T) {
	// KVKeys false: no /keys request; KVKeys true: Keys with Details (GetKey) for keys not in
	// KVKnownKeys or whose updated changed, at most maxKVKeyDetails; GetKey 403 → DetailsProblem
	// "forbidden" and the key still listed; KeysListed true. Secrets: metadata only, never a
	// GET /secrets/<name>/… request (assert on the fake's log).
}

func TestDiscoverReportsListFailuresAndKeepsTheRest(t *testing.T) {
	// F-40: RevokeRole("certificates/list") with KVKeys: Failures [{certificates, azure.forbidden
	// role Key Vault Reader}], Keys listed, nil error. A sign-in failure → the error (no result).
	// F-52: a truncated certificate page → that list in Failures with azure.unexpected_response
	// after the retries, never a partial certificate list presented as complete.
}

func TestDiscoverSkipsUnusableItems(t *testing.T) {
	// A listed id with a name outside azureid.ValidObjectName, a version that is not 32 hex, an x5t
	// that is not 20 bytes, a pending certificate without x5t: skipped with the warning
	// kv_item_unreadable (one per kind), never stored.
}
```

Run: `go test ./internal/providers/azurekv -run 'Access|Discover' -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement**

`connection.go`: `TestConnection(ctx)`: `call(Token)` (a failure is the returned error); decode the token's claims (`strings.Split(token, ".")[1]`, base64url, JSON `{oid, tid}`; a token that does not decode leaves both empty — never an error, never logged); then the three list calls, each for its first page only (the callback returns a stop sentinel after one page), each turned into an `AzureCheck` (`ok`; `forbidden` with `Role` and `Reason` from `mapError`; `failed` with the reason); `PermissionModel` from the first 403's `model` param (`unknown` when none); `read_secret` and `import` are `not_checked`; `CheckedAt` from `env.Clock`. Returns a nil error whenever sign-in worked (F-40: the vault is reachable; the checklist says what is missing).

`discover.go`: `Discover(ctx, req)` under `context.WithTimeout(ctx, PollBudget)`. A Key Vault has no SSH keys: a request without `Certificates`, `KVKeys` or `KVSecrets` returns an empty result with `KV` nil and no request (the conformance suite's SSH `Discover` op is keyed on `CapDiscoverSSHKeys`, which this provider does not advertise). Certificates: page through `ListCertificates` up to `maxKVCertificates`; for each item take `ID.Name()` (refuse with the warning per the test), `azureid.Thumbprint(X509Thumbprint)`, attributes; when `req.KVKnown[name]` differs in thumbprint or `Updated` (or is absent) and fewer than `maxKVDetails` details were read, `GetCertificate(name, "")` → `KVCertificateDetails` (version from `ID.Version()`, `CER`, policy: `KeyProperties.Exportable`, `KeyType` mapped `EC`/`EC-HSM` → `ecdsa`, `RSA`/`RSA-HSM` → `rsa`, others → `other`; `KeySize`; `SecretProperties.ContentType` mapped to `pkcs12`/`pem`/`other`; `IssuerParameters.Name`; `AutoRenew` when a lifetime action's `Action.ActionType` is `CertificatePolicyActionAutoRenew`); when the details' version differs from the known version, list the versions (newest first by `Created`, at most `maxKVVersions`); otherwise count `DetailsPending`. Keys (when asked): list, then `GetKey(name)` for new or updated keys up to `maxKVKeyDetails` (`kty` mapped, `HSM` for the `-HSM` types, RSA size from `len(N)*8`, `crv`); a 403 or failure of one `GetKey` sets `DetailsProblem` and continues. Secrets (when asked): list only. A failed listing becomes a `KVListFailure` (the others are still read) unless it is a sign-in failure, which ends `Discover` with that error. The bounds are package variables initialised from the exported constants so tests can lower them.

Run: `go test ./internal/providers/azurekv -count=1 -race`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- internal/providers/azurekv/connection.go internal/providers/azurekv/discover.go internal/providers/azurekv/connection_test.go internal/providers/azurekv/discover_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(azurekv): access check and bounded vault inventory with change-only details

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/providers/azurekv
```

### Task 8: `azurekv` provider part 3: `ReadCertificateSecret`, `ImportCertificate`, conformance, the optional real-Azure contract suite

The two operations that touch secrets and change a vault, the conformance suite of spec §6.5 item 5 against the fake, and the contract suite that runs the same assertions against a real vault when an owner provides one (R40 row 30).

**Files:**
- Create: `internal/providers/azurekv/secret.go`, `internal/providers/azurekv/import.go`, `secret_test.go`, `import_test.go`, `conformance_test.go`, `contract_test.go` (shared assertions, no build tag), `real_azure_test.go` (`//go:build azure`), `record_test.go` (`//go:build azure`)
- Modify: `Makefile` (target `test-azure`: `go test -count=1 -v -tags azure -run '^TestRealAzure' ./internal/providers/azurekv/`, documented as "optional; needs ALICE_AZURE_TEST_*; never part of ci")

**Interfaces:**
- Consumes: Tasks 6–7; `providers.{SecretRequest,CertificateSecret,ImportRequest,ImportResult,Import*,NewSecret,CheckImportReturn}`; `providertest.{SessionHarness,CheckSession,CheckImportResult,CheckNoSecrets}`.
- Produces: `session.ReadCertificateSecret`, `session.ImportCertificate`.

- [ ] **Step 1: Write the failing tests**

`secret_test.go`:

```go
func TestReadCertificateSecretOfAVersion(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	ver := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	sec, err := openSession(t, s).ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
	require.NoError(t, err)
	defer sec.Value.Zero()
	assert.Equal(t, "application/x-pkcs12", sec.ContentType)
	assert.NotEmpty(t, sec.Value.Bytes())
	last := s.Requests()[len(s.Requests())-1]
	assert.Equal(t, "/secrets/web-cert/"+ver, last.Path, "the exact version, never latest (§11.5 item 2)")
}

func TestReadCertificateSecretRefusals(t *testing.T) {
	// An empty or invalid name or version → *providers.Error kv.version_not_deployable, refused
	// before sending (the fake's log stays unchanged).
	// RevokeRole("secrets/get") → azure.forbidden role "Key Vault Secrets User" (F-41); a disabled
	// version → kv.version_disabled; a deleted certificate → kv.certificate_not_found; a non-exportable
	// certificate → azure.forbidden (the vault refuses; Alice never asks for a non-exportable one,
	// R40 row 18); a value above certs.MaxKVSecretSize (256 KiB) → kv.secret_unreadable (provider-side
	// bound: maxSecretValue, a variable equal to 256 KiB) and the oversized value is zeroed.
}
```

`import_test.go`:

```go
func TestImportCreatesAVersion(t *testing.T) {
	// A PFX built with pkcs12.LegacyDES (empty password): Outcome created, Version, Thumbprint = the
	// leaf's x5t, CER = the leaf; the fake's state has the new version with policy exportable true,
	// key type and size from the request, contentType application/x-pkcs12, no lifetime actions, and
	// the import body carried "pwd": "" (or no pwd); providertest.CheckImportResult passes; steps
	// "sign_in" ok, "import" started/ok were reported to the StepLogger.
}

func TestImportOutcomes(t *testing.T) {
	// RevokeRole("certificates/import") → refused, azure.forbidden role "Key Vault Certificates
	// Officer"; 400 BadParameter → refused, kv.import_rejected with azure_code BadParameter; a token
	// failure → refused (nothing was sent); FailNext 503 on the import → uncertain (the request
	// reached the vault) and the import is NOT retried (one request in the fake's log); a timeout
	// after the request was written → uncertain; 429 on the import → retried (a 429 means "not
	// processed", spec §11.6), then created; every outcome passes CheckImportReturn.
}
```

`conformance_test.go`:

```go
func TestConformanceAgainstTheFake(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	ver := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	_ = ver
	p := azurekv.New(azurekv.Options{RootCAs: func() (*x509.CertPool, error) { return s.CAPool(), nil }, DialAddr: s.DialAddr})
	providertest.CheckProvider(t, p)
	providertest.CheckSession(t, providertest.SessionHarness{
		Capabilities: p.Capabilities(),
		Open: func(ctx context.Context) (providers.Session, error) {
			return p.Open(ctx, vaultRef(s), secretSource(s), providers.Env{Clock: clock.Real{}, Log: slog.New(slog.DiscardHandler)})
		},
		Secrets: []string{s.Secret(), string(s.SecretValue("web-cert", ver)), s.LastAccessToken()},
	})
}
```

(`secretSource(s)` is a test `providers.AzureCredentialSource` returning the fake's tenant, client and secret; `s.SecretValue` and `s.LastAccessToken` are fakekv test accessors — add them in this task if Task 5 did not.)

`contract_test.go` — the shared contract (R40 row 30), no build tag:

```go
// contractEnv is a vault the contract runs against: the fake (always) or a real vault (tags azure).
type contractEnv struct {
	open        func(t *testing.T) providers.Session
	certName    string // an exportable certificate with at least one version
	renew       func(t *testing.T) // creates a new version (fake: Renew; real: skipped unless the policy renews daily)
}

func runContract(t *testing.T, env contractEnv) {
	// 1. TestConnection: sign_in ok; the three lists ok or forbidden with a role.
	// 2. Discover: env.certName listed; its details have a 32-hex version, a 40-hex thumbprint that
	//    equals azureid.ThumbprintOf(CER), exportable true, a content type pkcs12 or pem.
	// 3. ReadCertificateSecret of that version decodes with certs.ParseKVSecret (in the test) to a
	//    leaf whose SHA-1 equals the thumbprint.
	// 4. A second Discover with KVKnown from the first reads no details.
}

func TestContractAgainstTheFake(t *testing.T) { runContract(t, fakeContractEnv(t)) }
```

`real_azure_test.go` (`//go:build azure`): `TestRealAzure` reads `ALICE_AZURE_TEST_VAULT_URL`, `ALICE_AZURE_TEST_TENANT_ID`, `ALICE_AZURE_TEST_CLIENT_ID` and either `ALICE_AZURE_TEST_CLIENT_SECRET` or `ALICE_AZURE_TEST_CERT_FILE` (PEM with key), `ALICE_AZURE_TEST_CERT_NAME`; `t.Skip` with a message naming the variables when any is missing; runs `runContract` with `azurekv.New(azurekv.Options{})` (system roots, real DNS); and `TestRealAzureReaderSufficiency` (R22): with a second identity holding only Key Vault Reader (`ALICE_AZURE_TEST_READER_CLIENT_ID`/`_SECRET`), asserts the three lists and `GetCertificate` succeed and `GetSecret` is 403, and prints the result for the owner's record. `record_test.go` (`//go:build azure`): with `ALICE_AZURE_RECORD=1`, writes each answer's shape (keys and JSON types, every string value replaced by its placeholder) over `test/testdata/kv-recordings/*.json` for the owner to review and commit.

Run: `go test ./internal/providers/azurekv -count=1 -race` and `go vet -tags azure ./internal/providers/azurekv/` and `go test -tags azure -run '^TestRealAzure' ./internal/providers/azurekv/ -count=1 -v`
Expected: PASS; the last command prints `--- SKIP: TestRealAzure` (no variables set).

- [ ] **Step 2: Implement**

`secret.go`: refuse an invalid name or version before sending (`kv.version_not_deployable`); `call(GetSecret(name, version))`; `ContentType` from the secret (empty → `""`); the value copied into a fresh byte slice wrapped in `providers.NewSecret` (the SDK's string cannot be zeroed: accepted residual, R40 row 33) and refused above `maxSecretValue`. `import.go`: a pre-send phase (validate the name, the PFX non-empty, `Token` with retries: any failure is `refused`), then **one** send of `ImportCertificate(name, ImportCertificateParameters{Base64EncodedCertificate: &b64, Password: to.Ptr(""), CertificatePolicy: &azcertificates.CertificatePolicy{KeyProperties: &azcertificates.KeyProperties{Exportable: to.Ptr(true), KeyType: kty, KeySize: size (RSA), Curve: crv (ECDSA), ReuseKey: to.Ptr(false)}, SecretProperties: &azcertificates.SecretProperties{ContentType: to.Ptr("application/x-pkcs12")}, IssuerParameters: &azcertificates.IssuerParameters{Name: to.Ptr("Unknown")}}})` (`to` is `github.com/Azure/azure-sdk-for-go/sdk/azcore/to`); the send is outside `call`'s retry except for an answer with status 429 (retried with the loop's waits; the request was not processed); after the send: an `azcore.ResponseError` with a 4xx status other than 408/429 is `refused` with the mapped error; anything else that failed (5xx, 408, timeout, connection lost, malformed answer) is `uncertain`; success is `created` with the version, `azureid.Thumbprint(X509Thumbprint)` and `CER`. The base64 copy of the PFX is cleared (`clear` on its bytes) after the call.

Run the Step 1 commands.
Expected: PASS and SKIP as stated.

- [ ] **Step 3: Commit**

```bash
git add -- internal/providers/azurekv
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(azurekv): read certificate secrets, import certificates, conformance and contract suites

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/providers/azurekv Makefile
```

### Task 9: Migration `00008_key_vault.sql`

The schema of the contract's "Database" section, the grant guard and the migration tests.

**Files:**
- Create: `migrations/00008_key_vault.sql` (the contract's SQL verbatim), `migrations/keyvault_integration_test.go`
- Modify: `migrations/roles_integration_test.go` (`explicitGrants`, `explicitColumnGrants`), `migrations/down_integration_test.go` (if it lists the latest version)

**Interfaces:**
- Produces: the database of the contract.

- [ ] **Step 1: Write the failing tests**

`migrations/keyvault_integration_test.go` (`//go:build integration`; it uses the package's existing `pgtest` helpers and inserts as the owner role where the app role cannot):

```go
func TestPhase3ConstraintNamesAreTheDefaults(t *testing.T) {
	// SELECT conname FROM pg_constraint WHERE conrelid IN ('credentials'::regclass, 'targets'::regclass)
	// contains credentials_purpose_check, targets_status_check and
	// targets_discovery_interval_seconds_check (00008 drops and re-adds them by these names).
}

func TestVaultTargetAndItsCredentialCommitTogether(t *testing.T) {
	// As alice_app, in one transaction: INSERT a credentials row (purpose azure_vault, kind
	// azure_sp_secret, target_id = a new uuid T) and then the targets row T (type azure_key_vault,
	// config {"vault_url": "https://kv1.vault.azure.net", "host": "kv1.vault.azure.net", "port": 443},
	// credential_id = that credential, discovery_interval_seconds 900, status ok): commits.
	// The credential alone (no target T) fails at COMMIT (deferred foreign key).
	// A platform_ssh credential with a target_id, an azure_vault credential without one, a
	// kind/purpose mismatch: each refused (credentials_target_purpose, credentials_kind_purpose).
}

func TestVaultConfigAndIntervalChecks(t *testing.T) {
	// Refused: host "kv1.vault.azure.net.evil.test", port 8443, vault_url not https://<host>,
	// a missing host; interval 299 and 86401 for a vault; 1800 for a linux target. Accepted: 300 and
	// 86400 for a vault, 3600 for a linux target; status degraded for both kinds.
	// A second live vault with the same host is refused by targets_endpoint_live (duplicate vault).
}

func TestKeyVaultInventoryChecks(t *testing.T) {
	// kv_certificates: a name with "_" refused; current_version "" accepted, "ABC" refused;
	// (target_id, name) unique. kv_certificate_versions: (kv_certificate_id, version) unique;
	// thumbprint must be 40 lower-case hex. kv_keys/kv_secrets: unique per vault and name.
	// bindings: two live bindings of one vault certificate refused (bindings_one_live), a second one
	// after deleted_at is set accepted; auto_deploy true without auto_since refused.
	// deployments: binding_id without kv_version_id refused (deployments_kv_source).
	// kv_imports: two queued imports of one vault and name refused; state succeeded without a version
	// refused; succeeded without finished_at refused.
}

func TestAppRoleCannotRewriteKeyVaultHistory(t *testing.T) {
	// As alice_app: UPDATE kv_certificates SET name, UPDATE kv_certificate_versions SET thumbprint,
	// UPDATE bindings SET kv_certificate_id, UPDATE deployments SET binding_id, kv_version_id,
	// UPDATE credentials SET target_id, DELETE FROM bindings / kv_imports: each permission denied.
}
```

Extend `roles_integration_test.go`'s two maps with the contract's lists.

Run: `go test -tags integration ./migrations -count=1` (Docker: testcontainers PostgreSQL)
Expected: FAIL (relations do not exist; grant guard lists unknown relations).

- [ ] **Step 2: Implement**

Write `migrations/00008_key_vault.sql` exactly as the contract. If `TestPhase3ConstraintNamesAreTheDefaults` shows other names, use the names it shows in the migration and correct the contract (record it in the task report).

Run: `go test -tags integration ./migrations -count=1` and `go test -tags integration ./internal/inventory ./internal/jobs/... -count=1` (Docker)
Expected: PASS (the existing suites are unaffected by the new columns).

- [ ] **Step 3: Commit**

```bash
git add -- migrations/00008_key_vault.sql migrations/keyvault_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(migrations): Key Vault targets, credentials, inventory, bindings and imports

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- migrations
```

### Task 10: Inventory: vault targets — add with the pre-flight check, sealed credentials and their replacement, the per-vault credential source, poll interval, deletion; vaults out of the SSH scheduler

Vaults as targets (spec §7.2, §7.3, §11.1, §11.3; R40 rows 5, 6, 9–13; F-43). The license limit is checked in the insert transaction as for servers (L-74, L-79).

**Files:**
- Create: `internal/inventory/vaults.go` (`NewVault`, `CreateVault`, `ReplaceVaultCredentials`, `RecordKVConnection`, `RequestAccessCheck`, validation), `internal/inventory/vault_credentials.go` (sealing, the per-vault source, the in-memory source of a pre-flight), `internal/inventory/vaults_integration_test.go`, `internal/inventory/vaults_test.go`
- Modify: `internal/inventory/types.go` (`TypeAzureKeyVault`, `StatusDegraded`, `Target.Vault`, `VaultInfo`, `Facts.Azure`, `Facts.KVMetadataAt`, `Facts.KVAuthFailures`, `Facts.KVThrottledCycles`, `targetConfig.VaultURL`, `TargetPatch.PollIntervalMinutes`), `internal/inventory/targets.go` (`targetColumns` with the vault's credential public info, `scanTarget`, `insertTarget` takes a `targetRow`, `UpdateTarget` (poll interval), `DeleteVault`, `RequestTest`/`RequestDiscovery` dispatch), `internal/inventory/status.go` (`TargetRef` config for vaults), `internal/inventory/schedule.go` (vaults excluded), `internal/inventory/jobs.go` (Phase 5 job types), `internal/inventory/errors.go` (`ErrVaultHasBindings`, `ErrNotAVault`, `ErrClientCertificateInvalid`), `internal/inventory/validate.go` (`typeValues`)

**Interfaces:**
- Consumes: Task 9 schema; `azureid`; `certs.ParseClientCertificate`; `providers.{AzureIdentity,AzureCredentialSource,ConnectionReport,AzureFacts,Error}`; the registry's `azurekv` provider (the integration harness registers `azurekv.New(azurekv.Options{RootCAs: …, DialAddr: kv.DialAddr})` with a `fakekv` server: archtest governs non-test imports only, so a `_test.go` file may import the provider implementation).
- Produces: the vault part of the inventory contract; `Service.VaultCredentials`.

- [ ] **Step 1: Write the failing tests**

`vaults_test.go` (pure): `validateNewVault` table — name rules as servers (`validName`); `vault_url` through `azureid.ParseVault` (`validation.pattern`); `auth` one of three (`validation.one_of`); `tenant_id` and `client_id` GUIDs (`validation.pattern`; a domain such as `contoso.onmicrosoft.com` is a pattern error), `client_id` optional for a managed identity; `client_secret` required for `client_secret` (1..1024 bytes, `validation.required`/`validation.too_long`), refused for the other methods; the certificate required for `certificate`; `poll_interval_minutes` 0 (= 15) or 5..1440 (`validation.out_of_range`); `secret_expires_on` only with a client secret.

`vaults_integration_test.go` (harness: the existing inventory harness plus `fakekv.Start` and the real `azurekv` provider in the registry):

```go
func TestCreateVaultRunsThePreflightAndStoresTheCredentialSealed(t *testing.T) {
	h := newHarness(t, withAzure())
	secret := fakekv.NewClientSecret()
	tgt, rep, jobID, err := h.svc.CreateVault(h.ctx, h.admin, inventory.NewVault{Name: "Prod vault", VaultURL: h.kv.VaultURL(),
		Auth: providers.AzureAuthClientSecret, TenantID: h.kv.TenantID(), ClientID: h.kv.ClientID(),
		ClientSecret: secrets.NewPlaintext([]byte(secret))})
	require.NoError(t, err)
	assert.Equal(t, inventory.TypeAzureKeyVault, tgt.Type)
	assert.Equal(t, inventory.StatusOK, tgt.Status)
	require.NotNil(t, tgt.Vault)
	assert.Equal(t, h.kv.VaultURL(), tgt.Vault.URL)
	assert.Equal(t, 15*time.Minute, tgt.Vault.PollInterval)
	assert.Equal(t, providers.AzureResultOK, rep.Azure.Checks[1].Result)
	assert.Equal(t, inventory.JobKVPoll, h.jobs.requests()[0].Type, "the first poll is queued at once")
	assert.NotEqual(t, uuid.Nil, jobID)
	// The credential row: purpose azure_vault, kind azure_sp_secret, target_id = the vault, public_info
	// without the secret; the ciphertext does not contain the secret and opens with the AAD of its row.
	raw := h.ownerScalarBytes(t, "SELECT ciphertext FROM credentials WHERE target_id = $1", tgt.ID)
	assert.NotContains(t, string(raw), secret)
	assert.Equal(t, 1, h.audits("target.created"))
}

func TestCreateVaultRefusalsCreateNothing(t *testing.T) {
	// F-43: a vault name the fake does not serve (DNS: the harness's DialAddr returns an address that
	// fails like NXDOMAIN for unknown vault hosts) → *providers.Error azure.vault_not_found; a wrong
	// secret → azure.auth_failed; ExpireSecret → azure.credentials_expired; the fake stopped →
	// azure.unreachable. Each: no targets row, no credentials row, no job, license count unchanged,
	// one audit vault.add_refused with reason. A duplicate of a live vault → ErrDuplicateTarget.
	// The license limit reached → *license.TargetLimitError and target.add.denied_license (L-74).
}

func TestCreateVaultWithMissingRolesIsDegraded(t *testing.T) {
	// RevokeRole("certificates/list"): the vault is created, status degraded, last_error_code
	// azure.forbidden, facts.azure has the checklist; a firewall → degraded with azure.firewall.
}

func TestCreateVaultWithCertificateAndManagedIdentity(t *testing.T) {
	// A PEM pair (RSA 2048) registered as the fake's ClientCert: created; public_info carries the
	// certificate's thumbprint and not_after, the sealed payload is the PKCS #8 key; an ECDSA pair →
	// ErrClientCertificateInvalid (field certificate), nothing sent to Azure. Managed identity
	// (fake ManagedIdentity, the IMDS mapping): created with an empty sealed payload.
}

func TestVaultCredentialSource(t *testing.T) {
	// VaultCredentials(id).AzureIdentity returns the stored method, IDs and secret; release zeroes it.
	// A credential whose target_id names another vault (moved by the owner role) is refused
	// (errForeignCredential), never used. SSHSigner of a vault source answers an error.
}

func TestReplaceVaultCredentials(t *testing.T) {
	// With If-Match: a new credentials row, targets.credential_id moved, version+1, status and
	// poll_failures reset, audit vault.credentials_replaced, a poll queued; the old row remains
	// (append-only). A wrong secret is refused by the pre-flight and nothing changes; a stale
	// version is ErrVersionMismatch.
}

func TestVaultPollIntervalAndDeletion(t *testing.T) {
	// UpdateTarget PollIntervalMinutes 5 and 1440 accepted, 4 and 1441 out of range; on a server
	// the field is refused (validation.pattern on poll_interval_minutes) and DiscoveryIntervalHours
	// on a vault likewise. DeleteVault of a vault with a live binding → ErrVaultHasBindings; with
	// removeBindings: the binding soft-deleted, its locations' binding_id cleared, both audited, the
	// vault deleted, the license slot free.
}

func TestVaultJobsAndScheduling(t *testing.T) {
	// RequestTest on a vault queues kv.test_connection; RequestDiscovery queues kv.poll (dedupe
	// kv.poll:<id>); RequestAccessCheck(readSecretOf) needs an exportable certificate of that vault
	// with a known current version (else ErrNotExportable / ErrVersionNotDeployable / ErrNotFound) and
	// queues kv.test_connection with read_secret_of. ScheduleDiscovery never queues target.discover
	// or target.test_connection for a vault.
}
```

Run: `go test ./internal/inventory -run 'Vault' -count=1` and `go test -tags integration ./internal/inventory -run 'Vault' -count=1` (Docker)
Expected: FAIL (undefined: inventory.NewVault, …).

- [ ] **Step 2: Implement**

`types.go`/`targets.go`: `targetColumns` gains, as its last column, `coalesce((SELECT c.public_info FROM credentials c WHERE c.id = targets.credential_id AND c.purpose = 'azure_vault'), 'null'::jsonb)` (check with `grep -n "targetColumns" internal/inventory/*.go` that every use reads `FROM targets` without an alias; `scanTarget` gains the destination); `scanTarget` fills `Target.Vault` for `azure_key_vault` rows from the config (`vault_url`, host) and that public info (`auth`, `tenant_id`, `client_id`, `secret_expires_on`, `cert_thumbprint`, `cert_not_after`), `PollInterval` from `discovery_interval_seconds`, `Access` from `Facts.Azure`. `insertTarget(ctx, tx, r targetRow)` keeps the `CheckCanAddTarget` call and the single `INSERT INTO targets` (the L-79 static test), with `targetRow{ID, Name, Type, Config any, CredentialID, Status, Capabilities, IntervalSeconds, Facts, By}`; `CreateTarget` builds its row as before.

`vault_credentials.go`:

```go
const purposeAzureVault = "azure_vault"

// vaultInfo is credentials.public_info of a vault credential (never a secret).
type vaultInfo struct {
	Auth            string     `json:"auth"`
	TenantID        string     `json:"tenant_id,omitempty"`
	ClientID        string     `json:"client_id,omitempty"`
	SecretExpiresOn *time.Time `json:"secret_expires_on,omitempty"`
	CertificateDER  []byte     `json:"certificate_der,omitempty"` // public
	CertThumbprint  string     `json:"cert_thumbprint,omitempty"`
	CertNotAfter    *time.Time `json:"cert_not_after,omitempty"`
}

// kindOf maps a sign-in method to credentials.kind.
func kindOf(auth string) string {
	switch auth {
	case providers.AzureAuthCertificate:
		return "azure_sp_cert"
	case providers.AzureAuthManagedIdentity:
		return "azure_managed_identity"
	default:
		return "azure_sp_secret"
	}
}
```

The sealed payload is the client secret's bytes, the PKCS #8 key, or nothing (managed identity), sealed with `s.keyring.Seal(credentialLocation(id), payload)` (the platform key's AAD shape). `VaultCredentials(id)` returns `vaultSource{s, id}` whose `AzureIdentity(ctx)` reads `SELECT c.id, c.kind, c.public_info, c.ciphertext, c.nonce, c.wrapped_dek, c.key_version, c.target_id FROM targets t JOIN credentials c ON c.id = t.credential_id WHERE t.id = $1 AND t.deleted_at IS NULL AND c.purpose = 'azure_vault'`, refuses `c.target_id <> t.id` (`errForeignCredential`), opens the envelope and builds the identity; `release` zeroes the payload. `SSHSigner` answers `errNotAnSSHTarget`. `memorySource` (the pre-flight's) holds the identity built from the request and implements the same two methods.

`vaults.go`: `CreateVault` — `validateNewVault`; `s.license.Allow(license.ClassChange)` (refusal audited through `auditLicenseDenial`); build the identity (`certs.ParseClientCertificate(in.Certificate, now, s.roots)` for a certificate: `certs.ErrClientCertKey` → `ErrClientCertificateInvalid`, other `certs` errors keep their sentinels (`ErrCertKeyMismatch`… already mapped by the API)); the pre-flight: `p, ok := s.registry.Get(providers.KindAzureKV)`, `ctx2, cancel := context.WithTimeout(ctx, vaultPreflightBudget)` (45 s), `sess, err := p.Open(ctx2, providers.TargetRef{Name: name, Kind: providers.KindAzureKV, Config: providers.TargetConfig{"vault_url": v.URL}}, memorySource{…}, providers.Env{Clock: s.clock, Log: s.log})`, `rep, err := sess.TestConnection(ctx2)`, `sess.Close()`; a `*providers.Error` with a code in `preflightRefusals` (`azure.vault_not_found`, `azure.auth_failed`, `azure.credentials_expired`, `azure.unreachable`, `azure.tls_untrusted`, `azure.address_not_allowed`, `azure.clock_skew`, `azure.managed_identity_unavailable`, `azure.unexpected_response`, `azure.throttled`) is returned as it is after a detached audit `vault.add_refused` (`vault_url`, `auth`, `reason`); then one transaction: insert the credential (id C, `target_id` = new id T) and the target row (`Status` ok or degraded from the checklist, `LastErrorCode` the first failed check's reason, `Facts{Azure: rep.Azure}`, interval in seconds), audit `target.created`, enqueue `kv.poll` (`Kind a.jobKind()`, dedupe `kv.poll:<T>`); `refreshLicense` after commit. `ReplaceVaultCredentials` is the same pre-flight, then `UPDATE targets SET credential_id = $2, status = $3, last_error_code = $4, facts = jsonb_set(facts, '{azure}', $5), poll_failures = 0, version = version + 1, updated_at = $6 WHERE id = $1 AND version = $7`. `RecordKVConnection` stores `facts.azure` and the status of the checklist (audited `target.status_changed`, reason `kv_check_ok` or the failure's reason). `RequestTest`/`RequestDiscovery` choose `JobKVTest`/`JobKVPoll` for vaults (a vault has no host key: no status check other than `disabled`). `schedule.go`: `AND type <> 'azure_key_vault'` in `ScheduleDiscovery`'s query. `status.go` `TargetRef`: for a vault `Config = providers.TargetConfig{"vault_url": t.Vault.URL}`.

Run the Step 1 commands, then `go test -tags integration ./internal/inventory -count=1` and `go test -tags integration ./internal/archtest -count=1` (Docker)
Expected: PASS (the whole inventory suite, the L-79 static test included).

- [ ] **Step 3: Commit**

```bash
git add -- internal/inventory/vaults.go internal/inventory/vault_credentials.go internal/inventory/vaults_integration_test.go internal/inventory/vaults_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(inventory): Key Vault targets with a pre-flight check and sealed sign-in credentials

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/inventory
```

### Task 11: Inventory: vault reconciliation, poll state and failures, poll scheduling, Key Vault emails

What a poll stores and how a vault's status follows its polls (spec §11.6, §11.9; F-40, F-42, F-44, F-49..F-52 at inventory level; R40 rows 12–17, 21, 25 (import resolution hook)).

**Files:**
- Create: `internal/inventory/kv_reconcile.go` (`KVPollRequest`, `ReconcileKV`, `RecordKVFailure`), `internal/inventory/kv_schedule.go` (`ScheduleKVPolls`), `internal/inventory/kv_queries.go` (lists and detail), `internal/inventory/kv_reconcile_integration_test.go`, `internal/inventory/kv_queries_integration_test.go`
- Modify: `internal/inventory/notify.go` (`kv.auth_failed`, `kv.certificate_removed`; `Templates()`), `locales/common/{en,tr}.json` (`email.kv.auth_failed|certificate_removed.subject|body`), `internal/inventory/certificates.go` (insert of a vault leaf as source `azure_kv`)

**Interfaces:**
- Consumes: Task 9 schema; Task 10 targets; `providers.{DiscoverRequest,DiscoveryResult,KVInventory,…,Error}`; `certs.ParseChainPEM`; `license.ClassChange`; `checkClaim`; `Notifier`.
- Produces: the reconcile part of the inventory contract; `KVSummary`; `KVCertificateDetail{KVCertificate fields, Versions []KVVersion, Binding *BindingSummary, DeployAccess string ("ok"|"forbidden"|"not_checked")}`.

- [ ] **Step 1: Write the failing tests**

`kv_reconcile_integration_test.go` (results are built by hand as `providers.DiscoveryResult` values; leaves from `pki`):

```go
func TestFirstPollImportsInventoryOnly(t *testing.T) {
	// A result with two certificates with Details and Versions, two keys, three secrets: kv rows
	// created, a certificates row (source azure_kv, pem_chain = the leaf only, chain_complete as
	// ChainComplete decides) per current version, kv_certificate_versions with certificate_id for
	// the current versions only; no kv.certificate.new_version audit (first sight, §11.6 item 7);
	// target status ok, last_success_at and last_discovery_at set, poll_failures 0.
}

func TestNewVersionIsDetectedByVersionAndThumbprint(t *testing.T) {
	// F-46/R23: the same (x5t, updated) without Details → nothing changes; Details with the same
	// version and a new updated (attributes edited) → attributes refreshed, no new version;
	// Details with a new version → current_version/thumbprint moved, a versions row with
	// detected_at = now and certificate_id, audit kv.certificate.new_version (held false), the old
	// version kept (history).
}

func TestNewVersionInLockIsHeld(t *testing.T) {
	// L-87 (inventory half): with the harness license gate refusing ClassChange, ReconcileKV stores
	// the metadata and the new version with held = true and the audit row says held=true; nothing is
	// queued.
}

func TestMissingMarkingNeedsACompleteListing(t *testing.T) {
	// F-42: a known certificate absent from a complete listing → missing_since, audit
	// kv.certificate.removed, one email kv.certificate_removed (binding "yes" when bound), and its
	// bound locations untouched; absent again on the next poll → no second email; it returns →
	// missing cleared. Absent from a listing with Truncated ["certificates"] or a certificates
	// Failure → not marked. Keys and secrets alike with KeysListed/SecretsListed.
}

func TestPartialListingsAndThrottling(t *testing.T) {
	// F-40: Failures [certificates forbidden] → status degraded, last_error_code azure.forbidden,
	// keys stored, certificates untouched. F-44: a throttled list failure → kv_throttled_cycles 1,
	// status unchanged (ok); the third consecutive throttled cycle → degraded; a clean poll resets it.
}

func TestKVFailureTransitions(t *testing.T) {
	// RecordKVFailure: azure.auth_failed three times → status auth_failed from the first, poll_failures
	// 3, exactly one kv.auth_failed email (at the third), one target.status_changed row per transition;
	// azure.credentials_expired → auth_failed with that code (UI "Credentials expired");
	// azure.unreachable → unreachable (F-50); azure.unexpected_response → status unchanged, failure
	// counted (F-52); a successful ReconcileKV afterwards → ok, poll_failures 0, kv_auth_failures 0.
}

func TestReconcileIsFencedAndBounded(t *testing.T) {
	// With a claim whose job was taken back → ErrClaimLost, nothing written. A result above the
	// provider bounds (5001 certificates) is refused as internal.unexpected (inventory re-checks the
	// bounds it stores).
}

func TestScheduleKVPolls(t *testing.T) {
	// A vault with interval 15 min: due at once (never scheduled), then not before 15 min; after
	// one failure 30 min, after two or more 60 min (cap max(interval, 1 h)); a vault with interval
	// 2 h after failures: 2 h; disabled vaults never; servers never; the dedupe key kv.poll:<id>;
	// last_scheduled_at stamped in the same transaction. KVPollRequest asks for keys and secrets
	// when facts.kv_metadata_at is unset or older than 4 intervals, with KVKnown from the stored
	// current versions and KVKnownKeys from details_updated_at.
}
```

`kv_queries_integration_test.go`: `ListKVCertificates` of a vault (filters `q`, `expires_before`, `missing`; cursor by name; limit 1..200), `KVCertificate` with versions newest first and `DeployAccess` (`ok` after a recorded successful Key Vault deployment from this vault or an access check whose `read_secret` is ok; `forbidden` from the checklist; else `not_checked`), `ListKVKeys`, `ListKVSecrets`; an unknown id is `ErrNotFound`; a vault id that is a server is `ErrNotAVault`.

Run: `go test -tags integration ./internal/inventory -run 'KV|Poll|Missing|Partial|Reconcile|Schedule' -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`kv_reconcile.go`: `ReconcileKV(ctx, id, res)`: `held := s.license.Allow(license.ClassChange) != nil` (before the transaction); parse every `Details.CER` outside the transaction (`certs.ParseChainPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cer}))`; a leaf that does not parse leaves that certificate's details out and adds the server warning `kv_item_unreadable`); bounds re-checked (`len(Certificates) <= 5000`, …); one transaction: `checkClaim`, lock the target `FOR NO KEY UPDATE`, upsert in name order (`INSERT … ON CONFLICT (target_id, name) DO UPDATE`), certificates rows with `INSERT … ON CONFLICT (fingerprint_sha256) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at` (source `azure_kv` only for a new row: an existing row keeps its source and chain, R38 item 19), version rows with `ON CONFLICT (kv_certificate_id, version) DO UPDATE SET enabled, not_before, expires, certificate_id = coalesce(kv_certificate_versions.certificate_id, EXCLUDED.certificate_id)`; new-version detection exactly as the test table; `held` set on the newly current version only; missing marking per kind when complete; status, counters and facts as the tests; the uncertain-import resolution (Task 14 adds its body: a call `s.resolveImports(ctx, tx, id, now)` that is a no-op until then); emails through `s.notifier` in the transaction. `RecordKVFailure(ctx, id, perr)`: one transaction, the transitions of the test table; `reasonRE` guards the stored code. `kv_schedule.go`:

```sql
SELECT id FROM targets
WHERE deleted_at IS NULL AND type = 'azure_key_vault' AND status <> 'disabled'
  AND (last_scheduled_at IS NULL OR last_scheduled_at + make_interval(secs => LEAST(
        discovery_interval_seconds * (1 << LEAST(poll_failures, 2)), GREATEST(discovery_interval_seconds, 3600))) <= $1)
ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED
```

then per vault `EnqueueTx` (`JobKVPoll`, `Kind "scheduled"`, dedupe `kv.poll:<id>`) and `UPDATE targets SET last_scheduled_at = $2`. `notify.go`: the two templates (params of the contract's email table); `locales/common/{en,tr}.json` texts (subject and body, formal Turkish; the body of `kv.auth_failed` names the vault and the reason's title and says Alice keeps trying every hour).

Run the Step 1 command and `go test ./internal/notify -count=1` (every template renders in EN and TR with all params)
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- internal/inventory/kv_reconcile.go internal/inventory/kv_schedule.go internal/inventory/kv_queries.go internal/inventory/kv_reconcile_integration_test.go internal/inventory/kv_queries_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(inventory): Key Vault reconciliation, poll scheduling and vault status

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/inventory locales/common
```

### Task 12: Inventory: bindings, the cross-server location list, Key Vault deployments (**Deploy now**) and their material

Bindings (spec §11.7; R40 rows 22–24), the location list the binding dialog needs (carry 6), manual deployments of a vault version through the Phase 4 request path, and the material step the engine calls (R40 rows 18, 19, 34).

**Files:**
- Create: `internal/inventory/bindings.go`, `internal/inventory/locations_list.go`, `internal/inventory/kv_deploy.go` (`RequestKVDeployment`), `internal/inventory/kv_material.go` (`KVDeployMaterial`), `internal/inventory/bindings_integration_test.go`, `internal/inventory/kv_deploy_integration_test.go`
- Modify: `internal/inventory/deployments.go` (`insertDeployment` takes a `deploySource`; `Deployment` gains `BindingID`, `KVVersion`, `VaultName`, `Source`), `internal/inventory/deployment_records.go` (`Material.KV`, `Material.Warnings`; `DeploymentMaterial` does not require a sealed key for a Key Vault deployment), `internal/inventory/errors.go`

**Interfaces:**
- Consumes: Tasks 9–11; Phase 4's `lockDeployTargets`, `checkDeployLocation`, `deployCertificate`, `deployLocation`, `LocationRefusalError`, `KeyTypeMismatchError`, `acquirePFXSlot`, `ErrPFXBusy`, `checkClaim`, `chainLength`, `sha256Hex`; `certs.{ParseKVSecret,KeyPEM}`; `azureid.ThumbprintOf`.
- Produces: the binding and Key Vault deployment parts of the inventory contract.

- [ ] **Step 1: Write the failing tests**

`bindings_integration_test.go` (fixture: a vault with an exportable ECDSA certificate `web-cert` reconciled with details, a non-exportable `monitor-only`, an RSA `rsa-cert`; two Nginx targets with ECDSA locations `loc1`, `loc2` and an RSA location `loc3`, an unsupported `locU`):

```go
func TestCreateBindingRules(t *testing.T) {
	// web-cert → [loc1, loc2]: binding, both locations' binding_id set, audit binding.created
	// location_count 2. Refusals, each audited binding.denied with its reason and nothing changed:
	// monitor-only → ErrNotExportable (F-45); rsa-cert → loc1: *KeyTypeMismatchError (ecdsa, rsa);
	// locU → ErrLocationUnsupported; a second binding of web-cert → ErrBindingExists; loc1 in another
	// binding → ErrLocationBound naming loc1; a missing kv certificate → ErrKVCertificateMissing; 0 or
	// 201 locations, a duplicate id → validate.Errors; in lock → license.ErrLocked (R40 row 22).
}

func TestUpdateDeleteAndAutoDeploy(t *testing.T) {
	// UpdateBindingLocations with If-Match: [loc2] → loc1 released; stale version → ErrVersionMismatch.
	// SetAutoDeploy(true) → auto_deploy, auto_since = now, stopped_version cleared, audit
	// binding.auto_deploy_changed enabled=true; SetAutoDeploy(false) → auto_since NULL.
	// DeleteBinding → deleted_at, locations released, an unfinished deployment of it untouched.
	// Binding(id) carries per-location state: not_deployed, then pending (an unfinished Key Vault
	// deployment), deployed <version> (a succeeded one, or the location's served leaf equals a version's
	// leaf), failed (the last one failed), stopped (stopped_version = current version, not deployed).
}

func TestListDeployableLocations(t *testing.T) {
	// Across both servers: supported, present, deployable paths only (locU excluded); key_type
	// filter; unbound=true excludes bound ones; q matches the server name, the path or a server
	// name of the location (a "%" or "_" in q matches literally); cursor paging; limit bounds.
}
```

`kv_deploy_integration_test.go`:

```go
func TestRequestKVDeployment(t *testing.T) {
	// Deploy now of web-cert's current version to its binding: one deployment per location, trigger
	// manual, binding_id and kv_version_id set, new_fingerprint = the version's leaf, a
	// certificate.deploy job each, audit deployment.requested with binding_id and version. Refusals:
	// a version without details → ErrVersionNotDeployable; disabled → ErrVersionDisabled; expired →
	// ErrCertificateExpired; not yet valid → ErrCertificateNotYetValid; a held version by an Operator →
	// ErrHeldNeedsAdmin, by an Administrator accepted; a location outside the binding →
	// *LocationRefusalError(ErrNotFound); an unfinished deployment of the location →
	// ErrDeploymentInProgress (F-15); an incomplete chain needs no confirmation (R40 row 19).
}

func TestKVDeployMaterial(t *testing.T) {
	// With the vault secret of the version (built with pki: PFX base64 of leaf + intermediate +
	// root): the material has CertificatePEM = leaf + intermediate (root dropped), PrivateKeyPEM of the
	// key, NewChainLength 2, NewCertSHA256 of that PEM, KV set; the certificates row's pem_chain and
	// chain_complete updated (source azure_kv only; an uploaded row with the same leaf is never
	// changed); audit kv.secret_read purpose=deploy deployment_id; the secret's value zeroed.
	// Refusals: another leaf → ErrSecretMismatch (kv.secret_mismatch); a key that does not match →
	// ErrSecretUnreadable (kv.secret_unreadable); text/plain → ErrSecretUnreadable; both PFX slots taken → ErrPFXBusy (retryable); a claim lost →
	// ErrClaimLost and nothing written. DeploymentMaterial(id, true) of a Key Vault deployment
	// returns KV set and no key (no ErrNoPrivateKey).
}
```

Run: `go test -tags integration ./internal/inventory -run 'Binding|Deployable|KVDeploy' -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`deployments.go`: `type deploySource struct{ Trigger string; BindingID, KVVersionID *uuid.UUID; Confirmed bool; Version string }`; `insertDeployment(ctx, tx, a, c, l, src, now)` writes `trigger`, `binding_id`, `kv_version_id` and `confirm_incomplete_chain = src.Confirmed`, and the audit row adds `binding_id` and `version` when set; `RequestDeployment` passes `deploySource{Trigger: "manual", Confirmed: …}`. `Deployment`/`ListDeployments` select `d.binding_id`, the version string and the vault's name (`LEFT JOIN kv_certificate_versions v ON v.id = d.kv_version_id LEFT JOIN kv_certificates kc ON kc.id = v.kv_certificate_id LEFT JOIN targets vt ON vt.id = kc.target_id`), `Source` = `key_vault` when `binding_id` is set, else `upload`. `deployment_records.go`: `Material.KV *KVSource`, `Material.Warnings []string`; `DeploymentMaterial` reads `d.kv_version_id`'s vault, name, version and thumbprint, sets `KV`, and with `withKey` returns without a key for a Key Vault deployment (the engine reads the vault, Task 16).

`bindings.go`: the functions of the contract; lock order vault target → kv certificate → (via `lockDeployTargets`) Nginx targets → locations, all in id order; refusals audited `binding.denied` in a detached transaction (as `auditDeployDenial`). `locations_list.go`: one parameterised query (`ILIKE '%' || $q || '%' ESCAPE '\'` with `%`, `_` and `\` escaped in Go), cursor `(target name, cert_path, id)` base64-encoded like the Phase 4 cursors.

`kv_deploy.go`: `RequestKVDeployment` as the test table, reusing `lockDeployTargets`, `checkDeployLocation` (with a `deployCertificate` built from the version's `certificates` row: `keyID` irrelevant here, `chainComplete` ignored) and `insertDeployment` with `deploySource{Trigger: "manual", BindingID, KVVersionID, Version}`.

`kv_material.go`:

```go
// KVDeployMaterial checks the backing secret of a Key Vault deployment's version and returns the
// material of its first send (R40 row 18): the chain as the vault delivered it without a
// self-signed root, and the key as PEM, only in memory. secret.Value is zeroed on every path.
func (s *Service) KVDeployMaterial(ctx context.Context, id uuid.UUID, secret providers.CertificateSecret) (Material, error) {
	defer secret.Value.Zero()
	m, err := s.DeploymentMaterial(ctx, id, false)
	if err != nil {
		return Material{}, err
	}
	if m.KV == nil || m.Recorded {
		return Material{}, ErrDeploymentState
	}
	release, ok := acquirePFXSlot()
	if !ok {
		return Material{}, ErrPFXBusy
	}
	v, err := certs.ParseKVSecret(secret.ContentType, secret.Value.Bytes(), s.clock.Now().UTC(), s.roots)
	release()
	if err != nil {
		return Material{}, ErrSecretUnreadable
	}
	defer v.PrivateKeyDER.Zero()
	if v.Fingerprint != m.Fingerprint || azureid.ThumbprintOf(v.Leaf.Raw) != m.KV.Thumbprint || v.Algorithm != m.KeyType {
		return Material{}, ErrSecretMismatch
	}
	key, err := certs.KeyPEM(v.PrivateKeyDER)
	if err != nil {
		return Material{}, ErrSecretUnreadable
	}
	m.CertificatePEM = []byte(v.PEMChain)
	m.NewChainLength = chainLength(m.CertificatePEM)
	m.NewCertSHA256 = sha256Hex(m.CertificatePEM)
	m.PrivateKeyPEM = key
	if !v.ChainComplete {
		m.Warnings = append(m.Warnings, "chain_incomplete")
	}
	if err := s.recordSecretRead(ctx, m, v); err != nil { // fenced: pem_chain (azure_kv rows only) and kv.secret_read
		m.PrivateKeyPEM.Zero()
		return Material{}, err
	}
	return m, nil
}
```

(`ErrSecretUnreadable` and `ErrSecretMismatch` are new inventory sentinels mapped to `kv.secret_unreadable`/`kv.secret_mismatch` in Task 17 and by the engine in Task 16.)

Run the Step 1 command and the whole `go test -tags integration ./internal/inventory -count=1` (Docker)
Expected: PASS (Phase 4's deployment tests unchanged).

- [ ] **Step 3: Commit**

```bash
git add -- internal/inventory/bindings.go internal/inventory/locations_list.go internal/inventory/kv_deploy.go internal/inventory/kv_material.go internal/inventory/bindings_integration_test.go internal/inventory/kv_deploy_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(inventory): bindings, deployable locations, Key Vault deployments and their material

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/inventory
```

### Task 13: Inventory: the auto-deploy planner (F-46..F-48, stagger, stop after three failures, version rules)

`PlanKVAutoDeploy` (R40 row 20, row 21): one decision function over the database, run every minute by `kv.auto_deploy` (ClassChange, so it never runs in lock).

**Files:**
- Create: `internal/inventory/kv_autodeploy.go`, `internal/inventory/kv_autodeploy_integration_test.go`
- Modify: `internal/inventory/notify.go` (`kv.new_version_available`, `kv.version_skipped`, `kv.auto_deploy_stopped`), `locales/common/{en,tr}.json`

**Interfaces:**
- Consumes: Tasks 11–12 (`insertDeployment` with `deploySource{Trigger: "kv_renewal", …}`, `checkDeployLocation`).
- Produces: `PlanKVAutoDeploy`, `AutoDeployWave`, `AutoDeployMaxFailed`, `AutoDeployRetryAfter`.

- [ ] **Step 1: Write the failing tests**

`kv_autodeploy_integration_test.go` — `TestAutoDeployPlanTable`, each row its own subtest on a fresh fixture (a vault certificate bound to N locations, auto-deploy on at T0, versions inserted by `ReconcileKV`, deployments finished by the Phase 4 `FinishDeployment` as the row needs; clock from the harness):

| # | Situation | Expected after one `PlanKVAutoDeploy` |
|---|---|---|
| 1 | version V2 detected after `auto_since`, 3 locations | 3 deployments (trigger `kv_renewal`, job kind `system`), returns 3 |
| 2 | V2 detected **before** `auto_since` (the binding was created after it) | none (§11.6 item 7) |
| 3 | auto-deploy off; V2 detected after the binding was created | none; one `kv.new_version_available` email; a second run sends none |
| 4 | V2 held (detected in lock) | none; one `kv.new_version_available` email with `held=true` |
| 5 | V2 disabled / expired / `not_before` in the future / `expires` earlier than the served certificate's | none; one `kv.version_skipped` email each with `why` |
| 6 | V2 not exportable, or its leaf unknown | none |
| 7 | 8 locations | 5 deployments (`AutoDeployWave`); after 2 finish, the next run adds 2 |
| 8 | a location already serves V2's leaf, or a V2 deployment of it succeeded | nothing for that location |
| 9 | an unfinished deployment (any version) of a location | nothing for that location (F-48); after it finishes and V3 is current, V3 only (coalesced) |
| 10 | V2's deployment of a location failed 30 minutes ago | nothing for it; 61 minutes after → one new attempt (F-47) |
| 11 | 3 V2 deployments of the binding failed (any locations) | none; `stopped_version = V2`; audit `kv.auto_deploy.stopped`, one `kv.auto_deploy_stopped` email; later runs add nothing and send nothing |
| 12 | V3 becomes current after a stop of V2 | V3 is planned (the stop names V2 only) |
| 13 | the vault certificate is missing (removed from Key Vault) | none (F-42: bound websites untouched) |
| 14 | a location became unsupported or its server is not ready | that location skipped silently; the others planned |
| 15 | 120 eligible locations over many bindings | at most `autoDeployBatch` (50) deployments per run |

Run: `go test -tags integration ./internal/inventory -run AutoDeploy -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`kv_autodeploy.go`: select live bindings with `auto_deploy` or with a current version that needs an email (at most 100 bindings per run, `FOR UPDATE OF b SKIP LOCKED`), and per binding in one transaction: the current version row; the eligibility rules of the table in its order; the counts in SQL (`count(*) FILTER (WHERE d.state <> 'done')` of `kv_renewal` deployments of the binding; failed (`status IN ('failed','rolled_back','rollback_failed')`) deployments of the binding and version; per location the latest deployment of that version and any unfinished deployment of the location); then `lockDeployTargets` of the candidate locations, `checkDeployLocation` (a refusal skips the location without an audit row: no person asked), `insertDeployment(… deploySource{Trigger: "kv_renewal", BindingID, KVVersionID, Version})` with `Actor{Audit: jobsActor}` (job kind `system`); `notified_at` and `stopped_version` updates make every email once. The comparison "older than what is served" uses the served certificate of each location (`certificate_locations.certificate_id` → `not_after`) and skips only those locations, emailing once per version.

Run the Step 1 command and `go test ./internal/notify -count=1`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- internal/inventory/kv_autodeploy.go internal/inventory/kv_autodeploy_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(inventory): plan automatic deployments of renewed Key Vault certificates

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/inventory locales/common
```

### Task 14: Inventory: imports into a vault

`kv_imports` and its state machine (spec §11.8; R40 row 25; L-26 import refusal).

**Files:**
- Create: `internal/inventory/kv_imports.go`, `internal/inventory/kv_imports_integration_test.go`
- Modify: `internal/inventory/kv_reconcile.go` (`resolveImports`), `internal/inventory/notify.go` (`kv.import_failed`), `locales/common/{en,tr}.json`, `internal/inventory/errors.go`

**Interfaces:**
- Consumes: Tasks 9–11; `loadKey`; `certs.ExportPFX`; `providers.{ImportRequest,ImportResult,Import*}`; `checkClaim`.
- Produces: the import part of the inventory contract.

- [ ] **Step 1: Write the failing tests**

`kv_imports_integration_test.go` — `TestImportStateMachine`:

```go
func TestImportStateMachine(t *testing.T) {
	// RequestImport of an uploaded certificate (with its key) into the vault under a new name →
	// KVImport queued, new_version false, thumbprint = the leaf's x5t, a certificate.import_to_kv job
	// (target the vault, payload import_id, dedupe), audit kv.import.requested.
	// Refusals, each audited kv.import.denied and nothing stored: a certificate without its key →
	// ErrNoPrivateKey; expired → ErrCertificateExpired; an invalid name → validate.Errors on name; a
	// name that exists in the vault without confirm → ErrImportConfirmNeeded (param certificate_name);
	// with confirm → accepted with new_version true; a second request for the same vault and name
	// while one is queued or uncertain → ErrImportInProgress; a server target → ErrNotAVault; in lock →
	// license.ErrLocked (L-26).
	// ImportMaterial(id): the PFX decodes (pkcs12.DecodeChain, empty password) to the stored key and
	// leaf; KeyType and KeySize from the key; only in state queued (else ErrImportState); fenced by
	// the claim.
	// MarkImportSent: queued → running, sent_at. FinishImport(created) → succeeded with the version,
	// the vault rows updated at once (kv_certificates current version = the new one, detected_at now)
	// and audit kv.import.succeeded; FinishImport(refused, *providers.Error) → failed with the code
	// and params, audit kv.import.failed, email kv.import_failed; FinishImport(uncertain) → uncertain,
	// audit kv.import.uncertain, no email yet.
	// resolveImports (through ReconcileKV): an uncertain import whose thumbprint appears in the
	// vault's versions → succeeded with that version; one older than 24 h without it → failed
	// kv.import_outcome_unknown with the email; a finished import is never changed again.
}
```

Run: `go test -tags integration ./internal/inventory -run Import -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`kv_imports.go` as the test; the PFX is built in `ImportMaterial` with `loadKey` → `certs.ExportPFX(keyDER, parsed)` (the stored `pem_chain` parsed with `certs.ParseChainPEM`), wrapped in the `providers.ImportRequest` (`OperationID` = import id, `KeyType`/`KeySize` from `certs.KeyInfoOf`); `FinishImport(created)` also upserts the vault certificate and version rows from the result (the same helper `ReconcileKV` uses, with the leaf from `r.CER`). `resolveImports(ctx, tx, vault, now)` as the test.

Run the Step 1 command and the whole inventory integration suite (Docker)
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- internal/inventory/kv_imports.go internal/inventory/kv_imports_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(inventory): import certificates into a Key Vault with a never-resent send

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/inventory locales/common
```

### Task 15: Jobs: `kvjobs` (`kv.test_connection`, `kv.poll`, `certificate.import_to_kv`), job types, periodic tasks; L-87

The handlers that connect the vault records to the `azurekv` provider (spec §8.2, §11.3, §11.6, §11.8; R40 rows 25, 28, 29) and the L-87 case with the real poll job.

**Files:**
- Create: `internal/jobs/kvjobs/kvjobs.go` (Inventory, Deps, Register, open, test connection), `internal/jobs/kvjobs/poll.go`, `internal/jobs/kvjobs/import.go`, `internal/jobs/kvjobs/kvjobs_test.go` (hand fakes), `internal/jobs/kvjobs/kvjobs_integration_test.go` (real inventory, `fakekv`, the real `azurekv` provider)
- Modify: `internal/jobs/types.go` (the Phase 5 types, `MaxAttemptsFor`, `AlertsWhenExhausted`), `internal/jobs/types_test.go` (or the registry test file), `internal/inventory/vaults.go` (`RecordAccessCheckRead`)

**Interfaces:**
- Consumes: the inventory contract (Tasks 10–14); `providers.{Session,AzureFacts,AzureCheck*,SecretRequest,ImportRequest,CheckImportReturn}`; `jobs.{Register,Job,StepRecorder,Retry,Fail,FromProvider,Runner.Handle}`; `inventory.{WithClaim,Claim,ErrClaimLost,ErrNotFound}`.
- Produces: `kvjobs.{Inventory,Deps,Register}`; `jobs.{KVTestConnection,KVPoll,KVImport,KVSchedule,KVAutoDeploy}`.

- [ ] **Step 1: Write the failing tests**

`internal/jobs/types_test.go` (extend):

```go
func TestPhase5JobTypes(t *testing.T) {
	assert.Equal(t, license.ClassReadOnly, jobs.KVTestConnection.Class)
	assert.Equal(t, license.ClassReadOnly, jobs.KVPoll.Class)
	assert.Equal(t, license.ClassChange, jobs.KVImport.Class)
	assert.Equal(t, license.ClassReadOnly, jobs.KVSchedule.Class)
	assert.Equal(t, license.ClassChange, jobs.KVAutoDeploy.Class)
	assert.Equal(t, 1, jobs.MaxAttemptsFor(jobs.KVTestConnection))
	assert.Equal(t, 1, jobs.MaxAttemptsFor(jobs.KVPoll))
	assert.Equal(t, 3, jobs.MaxAttemptsFor(jobs.KVImport))
	assert.False(t, jobs.AlertsWhenExhausted(jobs.KVPoll), "the vault's status and its own email carry a failed poll")
	assert.True(t, jobs.AlertsWhenExhausted(jobs.KVImport))
}
```

`kvjobs_test.go` (a `fakeInv` implementing `kvjobs.Inventory` and `fake.New(providers.KindAzureKV, …)`): the decision table of each handler —

| Handler | Situation | Recorded | Job returns |
|---|---|---|---|
| test | vault deleted | nothing | `Fail system.not_found` |
| test | vault disabled | nothing | `Fail target.disabled` |
| test | not a vault (a server's id) | nothing | `Fail internal.unexpected` |
| test | `Open` fails `azure.auth_failed` | `RecordKVFailure` | `Fail azure.auth_failed` (one attempt) |
| test | report ok | `RecordKVConnection` with the report | result `{object_id, permission_model, checks}` |
| test | `read_secret_of` set, secret read ok | report's `read_secret` ok, value zeroed, `RecordAccessCheckRead` | result |
| test | `read_secret_of` set, 403 | `read_secret` forbidden with role Key Vault Secrets User | result (not an error: the check ran) |
| poll | `Discover` fails `azure.unreachable` | `RecordKVFailure` | `Fail azure.unreachable` (no dead email) |
| poll | `Discover` ok | `ReconcileKV` with the claim on the context | result `{certificates, new_versions, removed, keys, secrets}` |
| poll | `ReconcileKV` `ErrClaimLost` | nothing more | `Retry job.lease_expired` |
| poll | `ReconcileKV` `ErrNotFound` (deleted meanwhile) | nothing | `Fail system.not_found` |
| import | import already succeeded / failed / uncertain | nothing | result of the record; **no send** |
| import | state running (a run after a send or a crash after `MarkImportSent`) | `FinishImport(uncertain)` | `Fail azure.unexpected_response` with params `{state: uncertain}`; **no send** |
| import | `ImportMaterial` fails (no key) | `FinishImport(refused, certificate.no_private_key)` | `Fail` |
| import | `Open` fails retryably, attempts left | nothing | `Retry` (the next attempt starts over; nothing was sent) |
| import | `CheckClaim` lost before the send | nothing; no send | `Retry job.lease_expired` |
| import | outcome created | `FinishImport(created)` | result `{state: succeeded, version}` |
| import | outcome refused | `FinishImport(refused, err)` | `Fail` with the code |
| import | outcome uncertain or a contract violation (`CheckImportReturn`) | `FinishImport(uncertain)` | `Fail` with the cause's code, `{state: uncertain}` |
| import | the PFX of the material | zeroed after the call on every path | — |

`kvjobs_integration_test.go` (Docker):

```go
func TestPollJobEndToEnd(t *testing.T) {
	// A vault created through inventory.CreateVault against fakekv; run the queued kv.poll through a
	// runner with kvjobs registered: kv rows stored; Renew; RequestDiscovery + run again: a new
	// version recorded; RevokeRole("certificates/list") + run: vault degraded, keys still stored.
}

func TestL87PollInFlightAtLock(t *testing.T) {
	// fakekv Hold("/certificates/web-cert/"): start the poll (a renewal is pending); while the request
	// is held, the license moves to LOCK (the license test harness used by internal/jobs'
	// license_gate_integration_test.go); release: the job finishes, the new version is stored with
	// held = true, no deployment exists, and PlanKVAutoDeploy (called directly; its periodic task is
	// refused in lock anyway) creates none; after a renewal of the license the held version is still
	// not deployed automatically (R40 row 21).
}

func TestImportJobNeverResends(t *testing.T) {
	// FailNext("/certificates/new-cert/import", Fault{Status: 503}): the job ends with the import
	// uncertain and exactly one import request in the fake's log; running the job again (a retry or a
	// lost lease) sends nothing more; the next poll that lists the imported thumbprint marks it
	// succeeded (no fake fault the second time: the fake created the version although it answered 503 —
	// Fault gains Apply bool: "process the request, then answer the fault").
}
```

Run: `go test ./internal/jobs/... -count=1` and `go test -tags integration ./internal/jobs/kvjobs -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`internal/jobs/types.go`:

```go
// Phase 5 job types (spec §8.2, §8.6, §11; R40 row 29): reading a vault is read-only work (paused
// in lock); importing into a vault changes it (refused and held in lock). The periodic poll
// scheduler is read-only work; the auto-deploy planner queues changes, so it pauses in lock.
var (
	KVTestConnection = Register(inventory.JobKVTest, license.ClassReadOnly)
	KVPoll           = Register(inventory.JobKVPoll, license.ClassReadOnly)
	KVImport         = Register(inventory.JobKVImport, license.ClassChange)
	KVSchedule       = Register("kv.schedule", license.ClassReadOnly)
	KVAutoDeploy     = Register("kv.auto_deploy", license.ClassChange)
)
```

`MaxAttemptsFor`: `inventory.JobKVTest`, `inventory.JobKVPoll` → 1 (added to the existing `case` with `JobTestConnection`); `inventory.JobKVImport` falls to the default 3. `AlertsWhenExhausted`: `return t.Name != inventory.JobDeployRecover && t.Name != inventory.JobKVPoll`.

`kvjobs.go`:

```go
// Package kvjobs holds the job handlers of Azure Key Vault targets (spec §8.2, §11):
// kv.test_connection (the access check), kv.poll (one poll) and certificate.import_to_kv.
package kvjobs

// Inventory is the part of *inventory.Service the handlers use.
type Inventory interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	VaultCredentials(id uuid.UUID) providers.CredentialSource
	RecordKVConnection(ctx context.Context, id uuid.UUID, rep providers.ConnectionReport) error
	RecordAccessCheckRead(ctx context.Context, vault, kvCertificate uuid.UUID, version string) error
	RecordKVFailure(ctx context.Context, id uuid.UUID, err *providers.Error) error
	KVPollRequest(ctx context.Context, id uuid.UUID) (providers.DiscoverRequest, error)
	ReconcileKV(ctx context.Context, id uuid.UUID, res providers.DiscoveryResult) (inventory.KVSummary, error)
	KVCertificate(ctx context.Context, id uuid.UUID) (inventory.KVCertificateDetail, error)
	KVImport(ctx context.Context, id uuid.UUID) (inventory.KVImport, error)
	ImportMaterial(ctx context.Context, id uuid.UUID) (inventory.ImportMaterial, error)
	MarkImportSent(ctx context.Context, id uuid.UUID) error
	FinishImport(ctx context.Context, id uuid.UUID, r providers.ImportResult, perr *providers.Error) error
	CheckClaim(ctx context.Context) error
}

var _ Inventory = (*inventory.Service)(nil)

// Deps are the handlers' dependencies.
type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry
	Clock     clock.Clock
	Log       *slog.Logger
}

// Register registers the three handlers; it panics on a missing dependency.
func Register(r *jobs.Runner, d Deps) {
	if r == nil || d.Inventory == nil || d.Registry == nil || d.Clock == nil {
		panic("kvjobs: Register needs a runner, Deps.Inventory, Deps.Registry and Deps.Clock")
	}
	h := &handlers{d: d}
	if h.d.Log == nil {
		h.d.Log = slog.New(slog.DiscardHandler)
	}
	r.Handle(jobs.KVTestConnection, h.testConnection)
	r.Handle(jobs.KVPoll, h.poll)
	r.Handle(jobs.KVImport, h.importToKV)
}
```

`open(ctx, id)` mirrors `targetjobs.handlers.open` without the host-key statuses (a vault refuses only `disabled`; a non-vault target is `internal.unexpected`) and records a provider failure with `RecordKVFailure`. `poll.go` runs `Discover` under `pollTimeout` (`azurekvPollBudget + time.Minute`, a package constant of 11 minutes: kvjobs may not import the provider implementation) and stores through `ReconcileKV(inventory.WithClaim(ctx, inventory.Claim{JobID: j.ID, Attempt: j.Attempt}), …)`. `import.go` follows the table: the PFX of `ImportMaterial` is zeroed with `defer m.Request.PFX.Zero()`, `CheckClaim` and `MarkImportSent` right before the one send, the outcome recorded on a context detached from the job's (`context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)`) so a lease lost during the send still records it.

Run the Step 1 commands
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- internal/jobs/kvjobs
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(jobs): Key Vault access check, poll and import jobs; L-87 with the real poll

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/jobs internal/inventory/vaults.go
```

### Task 16: Deploy engine: the vault material step in `certificate.deploy` (F-41, F-45 at run time); L-80..L-82 with a Key Vault deployment

One new step before any SSH (R40 row 18): a Key Vault deployment reads and checks its version's secret, then the Phase 4 run continues unchanged. Recovery never needs the key, so `certificate.deploy_recover` does not change.

**Files:**
- Create: `internal/jobs/deployjobs/kv.go`, `internal/jobs/deployjobs/kv_test.go`, `internal/jobs/deployjobs/kv_integration_test.go`
- Modify: `internal/jobs/deployjobs/deploy.go` (`first`: the step after `DeploymentMaterial`; the decision table in `deploy`'s doc comment), `internal/jobs/deployjobs/deployjobs.go` (`Inventory` gains `VaultCredentials` and `KVDeployMaterial`), `internal/jobs/deployjobs/deployjobs_test.go` (`fakeInv` implements them), `internal/inventory/deployment_records.go` (`stepParamKeys` unchanged: the step uses `reason`)

**Interfaces:**
- Consumes: Task 12 (`Material.KV`, `KVDeployMaterial`, `ErrSecretMismatch`, `ErrSecretUnreadable`, `ErrPFXBusy`); Task 10 (`VaultCredentials`); `providers.{KindAzureKV,SecretRequest}`.
- Produces: the deploy table rows below.

- [ ] **Step 1: Write the failing tests**

`kv_test.go` (unit, `fakeInv` and two fake providers: `nginx` and `azurekv`):

```go
func TestKVDeploymentReadsTheSecretBeforeAnySSH(t *testing.T) {
	// A Key Vault deployment: the calls are, in order, azurekv Open, ReadCertificateSecret (the
	// deployment's vault certificate name and exact version), Close, KVDeployMaterial, then the
	// nginx Open, VerifyDeployment (pre-check), StartDeployment, DeployCertificate with the
	// material's chain and key; the step kv_secret is recorded ok (with reason chain_incomplete when
	// the material warns); the key is zeroed after the send.
}
```

and the table `TestKVMaterialFailures` — each row: the failure, what is recorded, what the job returns, and **no nginx call**:

| Failure | Recorded | Job returns |
|---|---|---|
| `ReadCertificateSecret` `azure.forbidden` role Key Vault Secrets User (F-41) | finish failed `azure.forbidden` with `role`, step `kv_secret` failed | `Fail azure.forbidden` |
| `kv.version_disabled` / `kv.certificate_not_found` | finish failed with it | `Fail` |
| `azure.unreachable` / `azure.throttled`, attempts left | nothing (precheck) | `Retry` |
| the same on the last attempt | finish failed with it | `Fail` (I-3) |
| `KVDeployMaterial` `ErrSecretMismatch` / `ErrSecretUnreadable` | finish failed `kv.secret_mismatch` / `kv.secret_unreadable` | `Fail` |
| `ErrPFXBusy` | nothing | `Retry certificate.pfx_busy` |
| the vault target deleted | finish failed `kv.certificate_not_found` | `Fail` |
| the vault disabled | finish failed `target.disabled` | `Fail` |
| no `azurekv` provider registered | finish failed `internal.unexpected` | `Fail` |
| context ended during the read | nothing | `Retry deployment.interrupted` (released) |

`kv_integration_test.go` (Docker; the deployjobs integration harness with the real inventory, the fake SSH Nginx world and `fakekv` + `azurekv`):

```go
func TestKVDeploymentEndToEnd(t *testing.T) {
	// A vault certificate bound to two locations of two servers; RequestKVDeployment; run the jobs:
	// both succeed, the websites serve the vault's leaf with its intermediate, an audit kv.secret_read
	// per deployment, no managed_private_keys row was added (the key was never sealed).
}

func TestF41MissingSecretsRoleChangesNothing(t *testing.T) {
	// RevokeRole("secrets/get"): the deployment ends failed ALC-AKV-0003 role "Key Vault Secrets
	// User"; the fake SSH server saw no command; the website serves the old certificate.
}

func TestF45NonExportableAtRunTime(t *testing.T) {
	// The certificate made non-exportable after the request: the vault refuses the secret →
	// azure.forbidden, nothing changed on the server (the request-time refusal is Task 12's).
}

func TestL80L82WithAKeyVaultDeployment(t *testing.T) {
	// L-80: a Key Vault deployment blocked inside the send while the license locks: it completes and
	// is recorded. L-82: its reload fails as the lock enters: the rollback runs (deployment.failed then
	// deployment.rolled_back), recovery (ClassAlways) needs no vault access (the fake's log shows no
	// secret read after the send).
}

func TestL81KVDeploymentHeldThenConfirmed(t *testing.T) {
	// A Key Vault deployment queued before the lock: its job becomes blocked_license; after a renewal
	// it does not run until an Administrator confirms; then it reads the secret and deploys.
}
```

Run: `go test ./internal/jobs/deployjobs -count=1` and `go test -tags integration ./internal/jobs/deployjobs -run 'KV|F41|F45|L8' -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`deployjobs.go`: add to `Inventory`:

```go
	// VaultCredentials and KVDeployMaterial serve Key Vault deployments (R40 row 18): the vault's
	// sign-in, and the check of its version's secret that yields the first send's material.
	VaultCredentials(id uuid.UUID) providers.CredentialSource
	KVDeployMaterial(ctx context.Context, id uuid.UUID, secret providers.CertificateSecret) (inventory.Material, error)
```

`kv.go`:

```go
// stepKVSecret is the deployment step that reads and checks the vault secret.
const stepKVSecret = "kv_secret"

// kvMaterial reads the backing secret of a Key Vault deployment's version before anything is sent
// to the Nginx server and returns the material of the first send (R40 row 18). The vault session
// is opened, used once and closed; the secret is zeroed by KVDeployMaterial on every path.
func (h *handlers) kvMaterial(ctx context.Context, d inventory.Deployment, m inventory.Material) (inventory.Material, error) {
	ref, t, err := h.d.Inventory.TargetRef(ctx, m.KV.VaultID)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return m, jobs.Fail("kv.certificate_not_found", nil, err)
	case err != nil:
		return m, jobs.Retry(reasonUnexpected, nil, err)
	case t.Status == inventory.StatusDisabled:
		return m, jobs.Fail("target.disabled", nil, nil)
	}
	p, ok := h.d.Registry.Get(providers.KindAzureKV)
	if !ok {
		return m, jobs.Fail(reasonUnexpected, nil, errors.New("deployjobs: no Key Vault provider in this build"))
	}
	sess, err := p.Open(ctx, ref, h.d.Inventory.VaultCredentials(m.KV.VaultID), providers.Env{Clock: h.d.Clock, Log: h.d.Log})
	if err != nil {
		return m, jobs.FromProvider(err)
	}
	sec, err := sess.ReadCertificateSecret(ctx, providers.SecretRequest{Name: m.KV.Name, Version: m.KV.Version})
	h.close(sess)
	if err != nil {
		return m, jobs.FromProvider(err)
	}
	out, err := h.d.Inventory.KVDeployMaterial(ctx, d.ID, sec)
	switch {
	case errors.Is(err, inventory.ErrPFXBusy):
		return m, jobs.Retry("certificate.pfx_busy", nil, err)
	case errors.Is(err, inventory.ErrSecretMismatch):
		return m, jobs.Fail("kv.secret_mismatch", nil, err)
	case errors.Is(err, inventory.ErrSecretUnreadable):
		return m, jobs.Fail("kv.secret_unreadable", nil, err)
	case err != nil:
		return m, err // ErrClaimLost and database errors: handled by the caller like DeploymentMaterial's
	}
	return out, nil
}
```

`deploy.go` `first`: right after a successful `DeploymentMaterial(ctx, d.ID, true)`, when `m.KV != nil`: record step `kv_secret` started; `m, err = h.kvMaterial(ctx, d, m)`; on error record the step failed (params `reason`) and route it exactly like a pre-send failure of `DeploymentMaterial` (a `jobs.Failure` that is permanent, or retryable on the last attempt, finishes the deployment failed with its reason through `h.beforeSendAt(ctx, j, d, err, stepKVSecret)`; `ErrClaimLost` is a stale run; a context that ended returns it for the runner to release); on success record the step ok (`{"reason": "chain_incomplete"}` when `m.Warnings` holds it) and continue with the Phase 4 run-time checks. Add the rows to the decision table in `deploy`'s doc comment and to the package doc's property 3 ("a Key Vault deployment fails before the send when its secret cannot be read or checked: nothing was written").

Run the Step 1 commands and `go test -cover ./internal/jobs/deployjobs -count=1` and `go test -tags integration ./internal/jobs/deployjobs -count=1` (Docker)
Expected: PASS; coverage at or above 99.

- [ ] **Step 3: Commit**

```bash
git add -- internal/jobs/deployjobs/kv.go internal/jobs/deployjobs/kv_test.go internal/jobs/deployjobs/kv_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(deployjobs): read and check the Key Vault secret before any SSH

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/jobs/deployjobs
```

### Task 17: API: routes, DTOs, `credentials.manage`, `ALC-AKV-*` codes, job ids on deploy jobs, OpenAPI, authz matrix

The HTTP surface of the contract's route table (spec §9; R40 rows 11, 22, 26; carries 5 and 6).

**Files:**
- Create: `internal/api/vaults_handlers.go`, `internal/api/bindings_handlers.go`, `internal/api/imports_handlers.go`, `internal/api/kv_dto.go`, and tests `vaults_handlers_test.go`, `bindings_handlers_test.go`, `imports_handlers_test.go`
- Modify: `internal/rbac/rbac.go` (`CredentialsManage`), `internal/rbac/rbac_test.go`, `internal/api/server.go` (`apiRoutes` adds `vaultRoutes`, `bindingRoutes`, `importRoutes`), `internal/api/targets_handlers.go` (type filter, vault DTO fields, PATCH `poll_interval_minutes`, DELETE `remove_bindings`, test body `read_secret_of`, discover on vaults), `internal/api/certificates_handlers.go` (import action, location list route), `internal/api/deployments_handlers.go` and `certs_dto.go` (deployment `source`, `binding_id`, `kv_version`, `vault_name`), `internal/api/jobs_handlers.go` and `internal/jobs/queue.go` (`View.DeploymentID`, `View.ImportID` from the payload), `internal/api/errors.go` (codes, `AllErrorCodes`, `errorMap` entries for the new inventory sentinels, `providerParamRules`/`providerParamKeys`), `internal/api/errors_catalogue_test.go` (Phase 5 texts render with their params), `internal/api/authz_test.go` (`expectedMatrix` rows), `api/openapi.yaml`, `docs/authz-matrix.md` (`make authz-doc`), `locales/common/{en,tr}.json` (`errors.<reason>.title|cause|action` for every new code), `docs/troubleshooting.md` (a section per new code with the exact title)

**Interfaces:**
- Consumes: the inventory contract; `rbac`; Phase 4's handler helpers (`decodeExact`, `actor`, `ifMatch`, `etag`, `fail`, `pathUUID`, `pageLimit`).
- Produces: the routes, codes and DTOs of the contract.

- [ ] **Step 1: Write the failing tests**

`rbac_test.go`: `CredentialsManage` = Administrator, step-up, no API token.

`vaults_handlers_test.go` (fake inventory, as the Phase 4 handler tests do):

```go
func TestCreateVaultHandler(t *testing.T) {
	// POST /api/v1/key-vaults with a client secret: 201 {target, access, job_id}; the target DTO has
	// type azure_key_vault and vault {url, name, auth, tenant_id, client_id, poll_interval_minutes,
	// secret_expires_on, access}; the body never echoes client_secret, private_key_pem, pfx_base64
	// or pfx_password (S-02); a key given twice, an upper-case key, an unknown key → 400; 769 KiB →
	// 413; a refusal *providers.Error azure.vault_not_found → 502 ALC-AKV-0005 with message_key; a
	// TargetLimitError → 409 license.target_limit_reached; an Operator → 403; an Administrator without
	// step-up → 403 auth.stepup_required; an API token → 403 (session only).
}

func TestVaultReadRoutes(t *testing.T) {
	// GET /api/v1/targets?type=azure_key_vault lists vaults only; ?type=nginx servers only;
	// ?type=bogus → 422; GET /targets/{id}/kv/certificates|keys|secrets with q, cursor, limit (1..200);
	// GET /kv-certificates/{id} with versions and binding; a server's id on a kv route → 404.
}
```

`bindings_handlers_test.go`: create (201, refusals 409 ALC-AKV-0018/0019, 422 ALC-AKV-0013, key type 409 ALC-CRT-0010 naming the location in `params.location_id`), PATCH with `If-Match` (412 on a stale version), PUT auto-deploy (Administrator only; an Operator 403), DELETE 204, deploy now (202 with deployments; ALC-AKV-0021/0022/0014; an Operator's held version 403 ALC-AKV-0022), `GET /api/v1/certificate-locations` (filters, cursor).

`imports_handlers_test.go`: 202 with `{import, job_id}`; 409 ALC-AKV-0023 with `params.certificate_name`; 409 ALC-AKV-0024; `GET /kv-imports` filters.

`jobs_handlers_test.go` (extend): a `certificate.deploy` job item carries `deployment_id`, an import job `import_id`, other jobs neither.

`errors_catalogue_test.go`: `TestPhase5TextsRenderWithTheirParams` renders every `ALC-AKV-*` text in EN and TR with its params (`role`, `model`, `client_address`, `aadsts`, `azure_code`, `certificate_name`, `location_id`) and finds no `{{`; `TestPhase5CodesHaveTroubleshootingSections`.

`authz_test.go`: the matrix rows for every new route (permission, license class, step-up).

Run: `go test ./internal/rbac ./internal/api ./internal/jobs -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement**

`rbac.go`: `CredentialsManage Permission = "credentials.manage" // add a Key Vault, replace its credentials: Admin with step-up, never a token (§25.1, R40 row 11)` and `CredentialsManage: {Roles: []Role{Admin}, StepUp: true}`. The handlers decode their bodies with `decodeExact` under the contract's size caps, turn `client_secret`, `private_key_pem` and `pfx_base64` into `secrets.Plaintext` at once (`pfx_base64` decoded with `base64.StdEncoding`), and pass inventory types; the add handler answers 201 with the target DTO, the access DTO (`object_id`, `permission_model`, `checks`, `checked_at`) and the job id. `errors.go`: the 27 codes of the contract in `AllErrorCodes` and in the order of the table; `errorMap` entries for `ErrVaultHasBindings` (0020), `ErrLocationBound` (0018), `ErrBindingExists` (0019), `ErrNotExportable` (0013), `ErrVersionDisabled` (0014), `ErrKVCertificateMissing` (0015), `ErrVersionNotDeployable` (0021), `ErrHeldNeedsAdmin` (0022), `ErrImportConfirmNeeded` (0023), `ErrImportInProgress` (0024), `ErrClientCertificateInvalid` (0027), `ErrSecretUnreadable` (0016), `ErrSecretMismatch` (0017), `ErrNotAVault` (`ErrNotFound`); `providerParamRules`: `role` (`^Key Vault (Reader|Secrets User|Certificates Officer)$`), `model` (`^(rbac|access_policy|unknown)$`), `client_address` (a validator function `netip.ParseAddr`: express it as a regexp `^[0-9A-Fa-f.:]{2,45}$` plus a `netip` check in `providerParams`), `aadsts` (`^[0-9]{1,8}$`), `azure_code` (`^[A-Za-z][A-Za-z0-9]{0,63}$`), `azure_request_id` (GUID), `certificate_name` (`^[0-9A-Za-z-]{1,127}$`), each added to `providerParamKeys`. `queue.go`: the job view query reads `payload->>'deployment_id'` and `payload->>'import_id'` (valid UUIDs only). `api/openapi.yaml`: every operation with `x-permission`, request bodies (`additionalProperties: false`), responses with the shared `Error` schema; the secret fields appear only in request schemas (S-08). `make authz-doc` regenerates `docs/authz-matrix.md`. Locale texts: the contract's titles and causes/actions, Turkish formal; `docs/troubleshooting.md`: a "Key Vault" section group with one `## ALC-AKV-NNNN: <title>` section per code (meaning, likely cause, what to do — for `ALC-AKV-0003` the exact `az role assignment create` commands of `docs/azure-setup.md`, Task 24 cross-links them).

Run: `go test ./internal/rbac ./internal/api ./internal/jobs -count=1`, `make authz-doc`, `make i18n-check`, `go test ./internal/api -run 'OpenAPI|Authz|Error' -count=1`
Expected: PASS; `docs/authz-matrix.md` updated.

- [ ] **Step 3: Commit**

```bash
git add -- internal/api/vaults_handlers.go internal/api/bindings_handlers.go internal/api/imports_handlers.go internal/api/kv_dto.go internal/api/vaults_handlers_test.go internal/api/bindings_handlers_test.go internal/api/imports_handlers_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(api): Key Vault, binding and import routes with ALC-AKV codes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/api internal/rbac internal/jobs/queue.go api/openapi.yaml docs/authz-matrix.md docs/troubleshooting.md locales/common
```

### Task 18: API integration: Key Vault journeys with the fake (F-40..F-52), lock (L-26, L-29, L-81), SSRF (A-14), secret-leak suite (S-01..S-05)

The phase's behavioural proof through the real HTTP stack, real services and jobs, the fake Azure service and the fake SSH Nginx world (spec §24.3, §23.4, §25.2, §25.4).

**Files:**
- Create: `internal/api/keyvault_integration_test.go`, `internal/api/keyvault_failures_integration_test.go`, `internal/api/keyvault_lock_integration_test.go`, `internal/api/keyvault_leak_integration_test.go`
- Modify: `internal/api/stack_integration_test.go` (the stack registers `azurekv.New(azurekv.Options{RootCAs: …, DialAddr: kv.DialAddr})`, starts `fakekv`, registers `kvjobs` and runs `kv.schedule`/`kv.auto_deploy` on demand)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the tests (they should pass on the code of Tasks 1–17; a failure is a defect of the task that owns the behaviour)**

`keyvault_integration_test.go` — `TestKeyVaultJourney`: an Administrator (step-up) adds a vault; the access check is green; the first poll lists `web-cert` (exportable ECDSA for `www.example.test`), `monitor-only` (marked monitor only), a key and secrets; an Operator binds `web-cert` to two websites on two Nginx servers; the Administrator turns automatic deployment on; `kv.Renew("web-cert")`; **Check now**; the planner (`PlanKVAutoDeploy` through the stack's scheduler run) creates two deployments; the jobs run; both websites serve the new leaf; the deployment history shows source Key Vault and version; F-46's "old version retained in the history". `TestImportJourney`: import an uploaded certificate under a new name (version 1), under the same name without and with confirmation (version 2, which a binding with auto-deploy then deploys), with `RevokeRole("certificates/import")` (ALC-AKV-0003 role Certificates Officer, nothing created), and with a lost answer (uncertain, then succeeded after a poll).

`keyvault_failures_integration_test.go` — `TestKeyVaultFailureCatalogue`, one subtest per row of spec §24.3, each asserting the vault's status and `last_error_code` through `GET /targets/{id}`, the job's code, the deployment's code where one exists, the audit rows and emails, and **no crash loop** (the next scheduled poll is delayed per R40 row 13):

| ID | Injection (fakekv) | Expected |
|---|---|---|
| F-40 | `RevokeRole("certificates/list")` | status degraded, label "No permission to read certificates", ALC-AKV-0003 role Key Vault Reader, model rbac and (second subtest) access_policy; keys still listed; next poll at the normal interval (a 403 list failure is not a poll failure) |
| F-41 | `RevokeRole("secrets/get")`, then a renewal | monitoring works; the auto deployment fails ALC-AKV-0003 role Key Vault Secrets User before any SSH command; website unchanged |
| F-42 | `DeleteCertificate("web-cert")` | "Removed from Key Vault", one email, bound websites untouched, no deployment |
| F-43 | add a vault named `nope-vault` (not served) | 502 ALC-AKV-0005, no target, license count unchanged |
| F-44 | `FailNext("/certificates", 429 Retry-After 7)` ×2 | the poll succeeds after waiting; a second vault's poll in the same minute is not delayed; a log line `azure throttled` with fixed labels; three cycles of persistent 429 → degraded ALC-AKV-0007, no email before |
| F-45 | `monitor-only` | binding refused 422 ALC-AKV-0013; **Deploy now** refused 422 before any request to the fake's secrets |
| F-46 | renewal, success | covered by the journey (assert the coverage pointer) |
| F-47 | renewal; one server's reload fails | that website rolled back (Phase 4 statuses), the other succeeds, `deployment.failed` email; the planner retries that website after one hour and at most three times; the third failure stops the wave with `kv.auto_deploy_stopped` |
| F-48 | renewal while a deployment of the version before runs | no second deployment of the location until the first ends; then only the newest version |
| F-49 | `ExpireSecret()` | status auth_failed, ALC-AKV-0002 ("Credentials expired"), the email after the third failed poll only, polls hourly (no storm) |
| F-50 | the fake's identity listener stopped | status unreachable ALC-AKV-0006 within the dial timeout; another vault and the Nginx servers unaffected |
| F-51 | `Firewall("203.0.113.7")` | ALC-AKV-0004 with `client_address` 203.0.113.7, distinct from F-40 |
| F-52 | `FailNext` truncated body and malformed JSON on the certificate list | treated as transient, nothing stored from that list, no panic, status unchanged until it persists |

`keyvault_lock_integration_test.go` — `TestKeyVaultInLock` (L-26, L-29): with the license locked: add vault, replace credentials, test, **Check now**, create/update/delete a binding, toggle auto-deploy, **Deploy now**, import → each 403 `license.locked` and audited; reads work; the fake's request log is unchanged (no request reached Azure) and the fake SSH server saw no command; `kv.schedule` and `kv.auto_deploy` runs are refused by the gate; no row added or deleted. `TestL81KeyVaultDeploymentHeld` (API half of Task 16's case: the held job appears in the blocked jobs list with its `deployment_id`).

`keyvault_leak_integration_test.go` — `TestSecretLeakSuiteWithAzureCanaries` (S-01..S-05): canaries in the client secret (`fake-CANARY…`), the service principal's private key (a fresh RSA key whose base64 body lines are the needles), the fake's access tokens (the fake exposes the tokens it issued), the vault secret values (PFX base64 and PEM key lines), a 403 body echoing a canary (`FailNext` with a body containing it) and a malformed answer containing it; run the journey, the failure catalogue's F-40/F-49/F-51/F-52 and an import with DEBUG logging captured; assert no canary in the logs, any HTTP answer (bodies, headers, cookies), job results and errors (`GET /jobs/{id}`), deployment steps, audit details (`audit_log.details` raw), `targets.facts`, `kv_*` rows; credentials rows hold ciphertext only (no canary, no PEM marker; two vaults with the same secret have different ciphertexts, S-04); `managed_private_keys` gained no row from a Key Vault deployment.

`TestA14KeyVaultSSRF` (in `keyvault_failures_integration_test.go`): the add-vault refusals of Review Focus 1 (422 on `vault_url`); a vault whose listing's `nextLink` points to another host and one that redirects to `169.254.169.254`: the poll fails `azure.unexpected_response`, and the fake (which also serves the other host name) logs no request to it.

Run: `go test -tags integration ./internal/api -run 'KeyVault|Import|A14' -count=1 -v` (Docker)
Expected: PASS.

- [ ] **Step 2: Fix what fails in the task that owns the behaviour** (record each fix in the report), then run `go test -tags integration ./internal/api -count=1` (Docker)
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- internal/api/keyvault_integration_test.go internal/api/keyvault_failures_integration_test.go internal/api/keyvault_lock_integration_test.go internal/api/keyvault_leak_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "test(api): Key Vault journeys, F-40..F-52, lock, SSRF and secret-leak suites

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/api
```

### Task 19: Wiring and the e2e fake Azure service: registration, scheduler, e2e trust hook, `alice-fakeazure`, compose overlay, Makefile, release checks

Everything that makes the binary and the e2e stack run Phase 5 (spec §6.4, §8.3; R40 row 35).

**Files:**
- Modify: `cmd/alice/providers.go` (`reg.Register(azurekv.New(azurekv.Options{RootCAs: azureRoots}))`), `cmd/alice/wiring.go` (`shippedProviders` adds `providers.KindAzureKV`; `periodicTypes` adds `jobs.KVSchedule`, `jobs.KVAutoDeploy`), `cmd/alice/services.go` (`kvjobs.Register(runner, kvDeps(svc, clk, log))`; `buildScheduler` tasks `kv.schedule` every `kvScheduleEvery` → `svc.inventory.ScheduleKVPolls`, `kv.auto_deploy` every `kvAutoDeployEvery` → `svc.inventory.PlanKVAutoDeploy`), `cmd/alice/testapi_e2e.go` (`kvScheduleEvery`, `kvAutoDeployEvery` = 100 years; `azureRoots` reads `/run/alice-e2e-azure/ca.pem`), `cmd/alice/testapi_release.go` (`kvScheduleEvery = time.Minute`, `kvAutoDeployEvery = time.Minute`, `azureRoots` returns `nil, nil`), `cmd/alice/wiring_test.go`, `cmd/alice/providers_test.go`, `cmd/alice/services_test.go` (`TestJobDepsCarryEveryDependency` for `kvDeps`), `cmd/alice/compose_test.go`, `deploy/docker-compose.e2e.yml`, `deploy/dev/check-hardening.sh`, `deploy/dev/check-image.sh`, `Makefile` (`E2E_AZURE_MARKER := /run/alice-e2e-azure`, used by `release-symcheck` and passed to `image-check`), `internal/archtest/buildtags_test.go` (`testOnlyDirs` gains `cmd/alice-fakeazure`: a test tool that imports `internal/testutil/fakekv` and never ships — `TestReleaseFilesImportNoTestCode` would refuse it otherwise; `TestReleaseBinariesLinkNoTestPackages` keeps checking `cmd/alice`, `cmd/alice-helper` and `cmd/licensectl`; and `TestAzureMarkerIsE2EOnly`: the only non-test file that contains `E2E_AZURE_MARKER` requires the `e2e` tag)
- Create: `cmd/alice-fakeazure/main.go`, `cmd/alice-fakeazure/main_test.go`, `test/images/fakeazure/Dockerfile`

**Interfaces:**
- Consumes: Tasks 6–17.
- Produces: the e2e service `fakeazure` (aliases `login.microsoftonline.com`, `alice-e2e.vault.azure.net`), its `ctl` commands, the trust hook.

- [ ] **Step 1: Write the failing tests**

`wiring_test.go`: `checkWiring` refuses a registry without `azurekv` and a scheduler without `kv.schedule` or `kv.auto_deploy`; `providers_test.go`: `registerProviders` registers `linuxssh`, `nginx`, `azurekv`. `compose_test.go` (extend `TestE2ETargetIsTestOnlyAndUnpublished`; teach the test's compose struct to read `networks` as a list or a map with `aliases`):

```go
	// The overlay adds the SSH target and the fake Azure service, nothing else; the release file has neither.
	assert.ElementsMatch(t, []string{"alice", "sshtarget", "fakeazure"}, names)
	fake := overlay.Services["fakeazure"]
	assert.Empty(t, fake.Ports, "the fake Azure service publishes nothing")
	assert.Equal(t, []string{"login.microsoftonline.com", "alice-e2e.vault.azure.net"}, fake.Networks["backend"].Aliases)
	assert.True(t, fake.ReadOnly)
	assert.Equal(t, []string{"ALL"}, fake.CapDrop)
	assert.Equal(t, "test/images/fakeazure/Dockerfile", fake.Build.Dockerfile)
	assert.Contains(t, overlay.Services["alice"].Volumes, "fakeazure-ca:/run/alice-e2e-azure:ro")
	raw, err := os.ReadFile("../../deploy/docker-compose.yml")
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "alice-e2e-azure", "the release compose file never trusts the fake")
```

`cmd/alice-fakeazure/main_test.go`: `serve` with `--listen 127.0.0.1:0 --admin 127.0.0.1:0 --ca-out <tmp>/ca.pem` writes the CA (0644), seeds `web-cert` (ECDSA, `www.example.test`, exportable), `monitor-only` (not exportable), key `signing-key` (RSA 2048) and secret `db-password`; `ctl credentials` prints `{"tenant_id","client_id","client_secret","vault_url"}`; `ctl renew web-cert` prints the new version; `ctl revoke-role secrets/get` / `grant-role`; `ctl ping` exits 0; `ctl` refuses an admin address that is not loopback.

Run: `go test ./cmd/alice ./cmd/alice-fakeazure -count=1` and `go test -tags "e2e testlicense" ./cmd/alice -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement**

`cmd/alice-fakeazure/main.go`: a small CLI around `fakekv.NewServer` (`fakekv.Options{VaultName: "alice-e2e", Model: "rbac"}`): `serve` listens on `--listen` (default `:443`) with `TLSConfig()`, writes `CAPEM()` to `--ca-out` (`os.WriteFile`, 0644, the directory created 0755), and serves the admin API on `--admin` (default `127.0.0.1:9090`, plain HTTP, loopback only) for `ctl`; the generated client secret never goes to its logs. `test/images/fakeazure/Dockerfile`: the pinned `golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414` builder (`CGO_ENABLED=0 go build -trimpath -o /out/alice-fakeazure ./cmd/alice-fakeazure`) and the pinned `gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2` runtime (both digests already in `deploy/Dockerfile`), `ENTRYPOINT ["/alice-fakeazure", "serve"]`. `deploy/docker-compose.e2e.yml`:

```yaml
  # Test-only fake of Microsoft Entra ID and Azure Key Vault for the Phase 5 journeys
  # (web/e2e/phase5.spec.ts): the in-process fake of internal/testutil/fakekv as a container. Docker's
  # DNS answers login.microsoftonline.com and alice-e2e.vault.azure.net with it on the internal
  # network, and only the e2e build of Alice trusts its CA (the fakeazure-ca volume; R40 row 35).
  # Playwright drives it with "docker compose exec fakeazure /alice-fakeazure ctl …". It publishes nothing.
  fakeazure:
    image: alice-e2e-fakeazure
    build:
      context: ..
      dockerfile: test/images/fakeazure/Dockerfile
    user: "0:0"
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - fakeazure-ca:/run/alice-e2e-azure
    networks:
      backend:
        aliases: [login.microsoftonline.com, alice-e2e.vault.azure.net]
    healthcheck:
      test: ["CMD", "/alice-fakeazure", "ctl", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10
```

and, on the `alice` service of the overlay, `volumes: - fakeazure-ca:/run/alice-e2e-azure:ro` and `depends_on: {fakeazure: {condition: service_healthy}}`, plus `volumes: fakeazure-ca: {}` at the end. `testapi_e2e.go`: `azureRoots()` reads `/run/alice-e2e-azure/ca.pem` at each session open (the file may appear after Alice starts), appends it to a copy of the system pool, and returns an error when it cannot (the session then fails `azure.tls_untrusted`, visible in the journey). `Makefile` `release-symcheck`: the two greps of `$(E2E_AZURE_MARKER)` in the e2e and release builds (present / absent), as for `TEST_ROUTE_MARKER`; `image-check` passes `E2E_AZURE_MARKER` and `check-image.sh` refuses it in the image's binary. `check-hardening.sh` (e2e mode): `fakeazure` is read-only, drops all capabilities, publishes no port.

Run: `go test ./cmd/alice ./cmd/alice-fakeazure ./internal/archtest -count=1`, `go test -tags "e2e testlicense" ./cmd/alice -count=1`, `make release-symcheck`, `go run ./tools/pincheck`, `make build`
Expected: PASS; `release-symcheck: ok`.

- [ ] **Step 3: Bring up the e2e stack once and check the fake (Docker; no Playwright running)**

Run: `make e2e-up && docker compose -p alice-e2e -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml --env-file deploy/.env exec -T fakeazure /alice-fakeazure ctl credentials && make e2e-hardening-check && make e2e-down`
Expected: the stack is healthy; `ctl credentials` prints the JSON; the hardening check passes; the stack is removed. Never `make up`/`down` (the owner's project).

- [ ] **Step 4: Commit**

```bash
git add -- cmd/alice-fakeazure test/images/fakeazure
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(alice): register the Key Vault provider and jobs; e2e fake Azure service

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- cmd/alice cmd/alice-fakeazure test/images/fakeazure deploy/docker-compose.e2e.yml deploy/dev/check-hardening.sh deploy/dev/check-image.sh Makefile internal/archtest/buildtags_test.go
```

### Task 20: Web: API layer, **Key Vaults** page, **Add Key Vault** dialog with the role guide, **Access check**, credentials replacement, navigation, audit labels

The vault list and everything about a vault's sign-in (spec §11.3, §11.4, SEC-083, S5 AC4, §26.7 owner step 1).

**Files:**
- Create: `web/src/api/keyvault.ts` (types and calls of the contract's routes), `web/src/pages/KeyVaultsPage.tsx`, `web/src/pages/KeyVaultsPage.test.tsx`, `web/src/components/AddKeyVaultDialog.tsx`, `web/src/components/AddKeyVaultDialog.test.tsx`, `web/src/components/RoleGuide.tsx`, `web/src/components/RoleGuide.test.tsx`, `web/src/components/AccessCheckPanel.tsx`, `web/src/components/AccessCheckPanel.test.tsx`, `web/src/components/ReplaceCredentialsDialog.tsx`, `web/src/components/ReplaceCredentialsDialog.test.tsx`, `web/src/components/VaultStatusBadge.tsx`
- Modify: `web/src/api/types.ts` (`Target.vault`, `TargetType` adds `azure_key_vault`), `web/src/api/endpoints.ts` (`listAllTargets(type?)`, `testTarget(id, body?)`), `web/src/api/queryKeys.ts` (`VAULTS_KEY`, `KV_CERTIFICATES_KEY`, …), `web/src/router.tsx` (`key-vaults`), `web/src/layout/AppLayout.tsx` (`{ to: '/key-vaults', labelKey: 'nav.keyVaults', roles: ALL }` after Servers), `web/src/locales/{en,tr}.json` (the contract's UI copy and the audit action labels of every new action), `web/src/test/screens.ts` (the new screens in the EN/TR render test), `web/src/test/fixtures.ts`

**Interfaces:**
- Consumes: the API of Task 17; `StepUpProvider` (the add and replace calls need step-up: the existing step-up retry wrapper); `waitForJob`; `ErrorAlert`; `Expiry`.
- Produces: the pages and components above; the UI copy keys of the contract.

- [ ] **Step 1: Write the failing tests**

`AddKeyVaultDialog.test.tsx` (msw):

```tsx
it('adds a vault with a client secret and shows the access check', async () => {
  server.use(http.post('/api/v1/key-vaults', async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    expect(body).toEqual({ name: 'Prod vault', vault_url: 'contoso-prod', auth: 'client_secret',
      tenant_id: '6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60', client_id: '0f1e2d3c-4b5a-4968-8776-655443322110',
      client_secret: 'fake-secret-value', poll_interval_minutes: 15 });
    return HttpResponse.json({ target: vaultFixture, access: accessFixture, job_id: 'j1' }, { status: 201 });
  }));
  renderRoute(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
  await user.type(screen.getByLabelText('Name'), 'Prod vault');
  await user.type(screen.getByLabelText('Vault address'), 'contoso-prod');
  await user.click(screen.getByRole('radio', { name: 'Client secret' }));
  await user.type(screen.getByLabelText('Directory (tenant) ID'), '6b8e2c1a-0f3d-4c2b-9a7e-1d2c3b4a5f60');
  await user.type(screen.getByLabelText('Application (client) ID'), '0f1e2d3c-4b5a-4968-8776-655443322110');
  await user.type(screen.getByLabelText('Client secret'), 'fake-secret-value');
  await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
  expect(await screen.findByText('Key Vault added.')).toBeVisible();
  expect(screen.getByText('Alice signs in to Azure as 11111111-2222-4333-8444-555555555555')).toBeVisible();
  expect(screen.getByRole('row', { name: /Monitor certificates/ })).toHaveTextContent('Allowed');
});
```

and: "Certificate (recommended)" is preselected; its file input accepts PEM (two text areas) or PFX with a password; "Managed identity" hides tenant and secret and shows the optional client ID; a 502 ALC-AKV-0005 shows the error title "Vault not found" and keeps the form; field errors (`vault_url` pattern) show under their fields; the secret field is `type="password"`, `autocomplete="off"`, and is cleared after any answer; while the request runs, "Checking that Alice can sign in and reach the vault…" is shown and the submit button is disabled.

`RoleGuide.test.tsx`: three rows (monitor, deploy, import) with the role names in `<code>` (`Key Vault Reader`, `+ Key Vault Secrets User`, `+ Key Vault Certificates Officer`), the Reader row's note `vaults.roles.readerUnconfirmed`, each row's `az role assignment create` command with the typed client ID and vault name filled in (placeholders `<client-id>`, `<vault-name>`, `<certificate-name>` otherwise), a copy button per command, and the collapsible "Vault uses access policies" section with the `az keyvault set-policy` commands of `docs/azure-setup.md` (Task 24 writes the guide from these exact commands):

```
az role assignment create --role "Key Vault Reader" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)"
az role assignment create --role "Key Vault Secrets User" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)/secrets/<certificate-name>"
az role assignment create --role "Key Vault Certificates Officer" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)"
az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list --key-permissions list --secret-permissions list
az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list --key-permissions list --secret-permissions get list
az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list import --key-permissions list --secret-permissions get list
```

`AccessCheckPanel.test.tsx`: the checklist renders `ok` as "Allowed", `forbidden` as "Not allowed: needs Key Vault Reader", `not_checked` as "Not checked", import as "Checked when you import"; **Check again** (Administrator and Operator) posts `actions/test` and waits for the job; the "Also test deployment access" checkbox needs a certificate choice (exportable certificates of the vault) and posts `read_secret_of`; an Auditor sees no buttons.

`KeyVaultsPage.test.tsx`: lists vaults only (`?type=azure_key_vault`), columns name, address, status, sign-in method, last checked; the status label "No permission to read certificates" for `degraded` with `azure.forbidden` and the list check forbidden, "Credentials expired" for `auth_failed` with `azure.credentials_expired`, "Cannot reach Azure" for `unreachable`; the empty state; **Add Key Vault** only for an Administrator; at 375 px the table scrolls in its own container.

`ReplaceCredentialsDialog.test.tsx`: same fields as the add dialog without name and address, `If-Match` sent, a secret expiry within 30 days shown with a warning badge on the vault page (R40 row 27).

Run: `cd web && npx vitest run src/components/AddKeyVaultDialog.test.tsx src/components/RoleGuide.test.tsx src/components/AccessCheckPanel.test.tsx src/pages/KeyVaultsPage.test.tsx src/components/ReplaceCredentialsDialog.test.tsx`
Expected: FAIL.

- [ ] **Step 2: Implement** the components and pages; render IDs, addresses, role names and commands with `<Code>` and `CopyButton`; every text from the locale keys of the contract (add the keys to both `en.json` and `tr.json`); audit labels for `vault.add_refused`, `vault.credentials_replaced`, `kv.certificate.new_version`, `kv.certificate.removed`, `kv.secret_read`, `binding.*`, `kv.auto_deploy.stopped`, `kv.import.*`.

Run: `make web-test web-lint i18n-check`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- web/src/api/keyvault.ts web/src/pages/KeyVaultsPage.tsx web/src/pages/KeyVaultsPage.test.tsx web/src/components/AddKeyVaultDialog.tsx web/src/components/AddKeyVaultDialog.test.tsx web/src/components/RoleGuide.tsx web/src/components/RoleGuide.test.tsx web/src/components/AccessCheckPanel.tsx web/src/components/AccessCheckPanel.test.tsx web/src/components/ReplaceCredentialsDialog.tsx web/src/components/ReplaceCredentialsDialog.test.tsx web/src/components/VaultStatusBadge.tsx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(web): Key Vaults page, add-vault dialog with the role guide and access check

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src
```

### Task 21: Web: vault page (certificates, keys, secrets), vault certificate page (versions, **Connected websites**, **Automatic deployment**, **Deploy now**), deployment source

What an Operator works with every day (spec §11.1, §11.6, §11.7; S5 AC1–AC3; owner steps 2–4).

**Files:**
- Create: `web/src/pages/KeyVaultDetailPage.tsx` (+ test), `web/src/pages/KVCertificatePage.tsx` (+ test), `web/src/components/ConnectWebsitesDialog.tsx` (+ test), `web/src/components/AutoDeploySwitch.tsx` (+ test), `web/src/components/KVDeployDialog.tsx` (+ test), `web/src/components/BindingPanel.tsx` (+ test)
- Modify: `web/src/router.tsx` (`key-vaults/:id`, `key-vaults/:vaultId/certificates/:id`), `web/src/pages/DeploymentsPage.tsx`, `web/src/pages/DeploymentDetailPage.tsx`, `web/src/components/DeploymentSteps.tsx` (step `kv_secret`: "Read the certificate from Key Vault" / "Sertifikayı Key Vault'tan oku"), `web/src/locales/{en,tr}.json`, `web/src/test/screens.ts`

**Interfaces:**
- Consumes: Task 17's routes; Task 20's API module and components.

- [ ] **Step 1: Write the failing tests**

`KeyVaultDetailPage.test.tsx`: the header (status badge, "Alice signs in to Azure as …", last checked, poll interval with an Administrator's edit (5–1440 minutes, `If-Match`), **Check now** for Administrator and Operator posting `actions/discover` and waiting for the job, **Replace credentials** and **Delete** for an Administrator; deleting a vault with connected websites asks to remove them and sends `remove_bindings=true`); the tabs **Certificates** (name, current version as its first 8 hex digits in `<Code>`, expiry with `Expiry`, chips "Monitor only", "Removed from Key Vault", "New version found", "Connected websites: {{count}}"), **Keys** (name, type, size or curve, expiry, enabled, managed), **Secrets** (name, content type, expiry, enabled, managed); cursor paging ("Show more"); EN and TR.

`KVCertificatePage.test.tsx`: the policy (exportable, key type and size, issuer, renews itself), the versions table newest first (version, thumbprint, valid from/to, enabled, found on, "Held" badge with `vaults.heldVersion`), a **Deploy now** action per version that has a leaf (disabled with the reason otherwise: no details, disabled, expired, not exportable; held versions only for an Administrator), and `BindingPanel`.

`BindingPanel.test.tsx`: no binding → **Connect websites** (Operator and Administrator); with a binding: the locations with their state (`bindings.state.*`), `AutoDeploySwitch` (Administrator: confirm dialog quoting `bindings.autoDeployHelp`; others: read-only state), "Deploy access not checked" with a button that runs the access check with this certificate, **Deploy now** opening `KVDeployDialog` (version picker defaulting to the current version, locations of the binding preselected), remove a website, delete the connection (confirm).

`ConnectWebsitesDialog.test.tsx`: loads `GET /api/v1/certificate-locations?key_type=<the certificate's>&unbound=true`, search box (`q`), paging, multi-select (1–200), server name and path in `<Code>`, submits `POST /bindings`; refusals render with their location named (`params.location_id` → the row is highlighted).

`DeploymentsPage.test.tsx` (extend): a Key Vault deployment shows "From Key Vault", the vault name and the version; the detail page shows the `kv_secret` step.

Run: `cd web && npx vitest run src/pages/KeyVaultDetailPage.test.tsx src/pages/KVCertificatePage.test.tsx src/components/BindingPanel.test.tsx src/components/ConnectWebsitesDialog.test.tsx src/components/AutoDeploySwitch.test.tsx src/components/KVDeployDialog.test.tsx src/pages/DeploymentsPage.test.tsx`
Expected: FAIL.

- [ ] **Step 2: Implement**, then run `make web-test web-lint i18n-check`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add -- web/src/pages/KeyVaultDetailPage.tsx web/src/pages/KeyVaultDetailPage.test.tsx web/src/pages/KVCertificatePage.tsx web/src/pages/KVCertificatePage.test.tsx web/src/components/ConnectWebsitesDialog.tsx web/src/components/ConnectWebsitesDialog.test.tsx web/src/components/AutoDeploySwitch.tsx web/src/components/AutoDeploySwitch.test.tsx web/src/components/KVDeployDialog.tsx web/src/components/KVDeployDialog.test.tsx web/src/components/BindingPanel.tsx web/src/components/BindingPanel.test.tsx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(web): vault page, vault certificate versions and connected websites

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src
```

### Task 22: Web: **Import into Key Vault**, import history, held jobs with their deployment, **Servers** without vaults

**Files:**
- Create: `web/src/components/ImportToKeyVaultDialog.tsx` (+ test), `web/src/components/ImportHistory.tsx` (+ test)
- Modify: `web/src/pages/CertificateDetailPage.tsx` (the action when Alice holds the key and the person may operate; the history panel), `web/src/pages/TargetsPage.tsx` and its test (Servers lists `linux` and `nginx` only), `web/src/components/BlockedJobsPanel.tsx` and its test (link a held deploy job to its deployment through `deployment_id`, carry 5), `web/src/locales/{en,tr}.json`

- [ ] **Step 1: Write the failing tests**

`ImportToKeyVaultDialog.test.tsx`: vault select (vaults only), name prefilled from the certificate's common name with dots and other characters outside `[0-9A-Za-z-]` replaced by `-` and trimmed to 127 characters, validated as typed; the note `imports.noAutoRenew`; a 409 ALC-AKV-0023 shows `imports.newVersionWarning` with the name in `<Code>` and a required confirmation checkbox, then resends with `confirm_new_version: true`; after 202 the dialog waits for the job and shows "Imported" (succeeded), "Not confirmed yet" (uncertain, with the explanation that the next check of the vault confirms it) or the error.

`ImportHistory.test.tsx`: the certificate's imports newest first with vault, name, state, version and the error title for failures.

`TargetsPage.test.tsx` (extend): a vault returned by the API is not listed under Servers.

`BlockedJobsPanel.test.tsx` (extend): a held `certificate.deploy` job links to `/deployments/<deployment_id>` without searching the server's deployments.

Run: `cd web && npx vitest run src/components/ImportToKeyVaultDialog.test.tsx src/components/ImportHistory.test.tsx src/pages/TargetsPage.test.tsx src/components/BlockedJobsPanel.test.tsx`
Expected: FAIL.

- [ ] **Step 2: Implement**, then `make web-test web-lint web-coverage i18n-check`
Expected: PASS; the Vitest thresholds of `web/vite.config.ts` hold (raise them if they rose; never lower).

- [ ] **Step 3: Commit**

```bash
git add -- web/src/components/ImportToKeyVaultDialog.tsx web/src/components/ImportToKeyVaultDialog.test.tsx web/src/components/ImportHistory.tsx web/src/components/ImportHistory.test.tsx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "feat(web): import certificates into a Key Vault; held jobs link their deployment

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src web/vite.config.ts
```

### Task 23: End-to-end: Phase 5 journeys in EN and TR against the fake Azure service, accessibility

The spec §26.7 e2e ("add vault, see certificates and keys, 'renew' in the fake, and observe the automatic deployment on the Nginx container") and the owner steps that the fake can play, in English and Turkish.

**Files:**
- Create: `web/e2e/phase5.spec.ts`
- Modify: `web/e2e/helpers.ts` (`azureExec(args)`: like `targetExec`, service `fakeazure`, the same `alice-e2e*` project guard; `azureCredentials()`, `azureRenew(name)`, `azureLeafFingerprint(name)`, `azureRole('revoke' | 'grant', action)`, `azureReset()`; `COPY` gains the Phase 5 texts in both languages)
- Modify: `cmd/alice-fakeazure/main.go` (`ctl leaf <name>` prints the current leaf's SHA-256 fingerprint; `ctl reset` reseeds and generates a new client secret), its test

**Interfaces:**
- Consumes: the e2e stack of Task 19; `runWizard`, `signIn`, `drainJobs`, `runScheduled`, `served`, `newCert`, `expectAccessible`, `expectWide`, `targetExec` (the Phase 4 server preparation steps reused from `phase4.spec.ts`).

- [ ] **Step 1: Write the journeys**

```ts
for (const lang of ['en', 'tr'] as const) {
  test.describe(`Phase 5 Key Vault (${lang})`, () => {
    test('add a vault, see its inventory, renew in Key Vault and watch the automatic deployment', async ({ page, request }) => {
      // Wizard + an Nginx server prepared and discovered (as phase4.spec.ts does), azureReset().
      // Key Vaults → Add Key Vault: name, vault address from azureCredentials().vault_url, Client secret,
      // tenant, client, secret → step-up → "Key Vault added." and the access check: three "Allowed".
      // drainJobs (first poll) → Certificates tab: web-cert and monitor-only with "Monitor only";
      // Keys tab: signing-key, RSA, 2048; Secrets tab: db-password.
      // web-cert → Connect websites → www.example.test on the e2e server → saved; Automatic deployment on
      // (confirm). azureRenew('web-cert'); Check now; drainJobs → "New version found";
      // runScheduled(request, 'kv.auto_deploy'); drainJobs → the website's state "Deployed: version …";
      // served('www.example.test') equals azureLeafFingerprint('web-cert'); Deployment history: "From Key Vault".
    });

    test('a missing Key Vault Secrets User role is reported and the website is unchanged', async ({ page, request }) => {
      // From the state above: azureRole('revoke', 'secrets/get'); azureRenew; Check now; drainJobs;
      // runScheduled('kv.auto_deploy'); drainJobs → the deployment "Failed", title "Missing permission in
      // the vault", the role "Key Vault Secrets User" in <code>; served() unchanged; azureRole('grant', …).
    });

    test('import an uploaded certificate into the vault', async ({ page, request }) => {
      // Upload newCert('import.example.test') → Import into Key Vault → name import-example-test → drainJobs
      // → "Imported"; the vault's Certificates tab lists it after Check now.
    });

    test('Key Vault screens are accessible', async ({ page }) => {
      // expectAccessible on: Key Vaults (list), Add Key Vault (each sign-in method), the vault page (each tab),
      // the vault certificate page, Connect websites, Deploy now, Import into Key Vault; expectWide at 375 px
      // for the list and the vault page.
    });
  });
}
```

Run (Docker; nothing else using Docker meanwhile): `make e2e-up && make e2e; status=$?; make e2e-down; exit $status`
Expected: every Phase 1–5 journey passes in EN and TR.

- [ ] **Step 2: Fix what fails in the task that owns the behaviour** (record each fix), re-run the same command.

- [ ] **Step 3: Commit**

```bash
git add -- web/e2e/phase5.spec.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "test(e2e): Phase 5 Key Vault journeys in English and Turkish

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/e2e cmd/alice-fakeazure
```

### Task 24: Coverage floors, documentation (Azure setup guide with the role assignments, guides, troubleshooting), R40, security review, CHANGELOG, `make ci`

**Files:**
- Modify: `coverage-floors.json`, `docs/operator-guide.md`, `docs/admin-guide.md`, `docs/troubleshooting.md`, `docs/licensing.md` (vaults count as targets), `CHANGELOG.md`, `docs/superpowers/specs/alice-v1/00-decisions.md` (R40), `docs/superpowers/specs/alice-v1/06-quality.md` (a pointer under §26.7: R40 rows 30 and 2), `docs/superpowers/specs/alice-v1/01-product.md` (AC6: "(R40 row 30: unconfirmed until the owner's real-Azure run)")
- Create: `docs/azure-setup.md`, `docs/security/reviews/phase-5.md`, `internal/api/docs_azure_test.go` (the guide and the UI agree)

- [ ] **Step 1: Coverage floors**

Run: `make coverage` (Docker)
Expected: PASS. Add `alice/internal/platform/azureid: 100`, `alice/internal/providers/azurekv` and `alice/internal/jobs/kvjobs` at their measured values rounded down; raise every floor whose package rose; never lower one (if a package fell below its floor, add tests in the task that lowered it).

- [ ] **Step 2: Documentation**

`docs/azure-setup.md` (spec §21's `docs/azure-setup.md`, for Azure administrators): create the app registration; add a certificate (recommended: `openssl req -x509 -newkey rsa:3072 …` and upload of the public part) or a client secret (note its expiry date for Alice); the role table per feature (monitor-only = Key Vault Reader — "expected; not yet confirmed on a real vault"; deploy to Nginx = + Key Vault Secrets User, preferably on each certificate's secret; import = + Key Vault Certificates Officer) with the **exact** `az role assignment create` commands of Task 20's `RoleGuide` (a test, `internal/api/docs_azure_test.go`, reads `web/src/components/RoleGuide.tsx` and the guide and fails if the commands differ); the access-policy alternative with the `az keyvault set-policy` commands; managed identity on an Azure VM (assign the roles to the VM's identity; only the VM's instance metadata endpoint is supported; App Service and Arc are not); network: outbound TCP 443 to `login.microsoftonline.com` and `<vault>.vault.azure.net`, the vault firewall (add Alice's public address, or a private endpoint with internal DNS for `privatelink.vaultcore.azure.net`), no HTTP proxy until Settings (Phase 7); adding the vault in Alice and reading the access check; common errors with their codes (`ALC-AKV-0001`, `-0002`, `-0003`, `-0004`, `-0005`, `-0006`, `-0010`). `docs/operator-guide.md`: a "Key Vaults" chapter (statuses, **Check now**, the inventory, connecting websites, automatic deployment and its rules — newest version only, five at a time, one hour between attempts, three failures stop — **Deploy now** of an older version, held versions after a lock, imports and "Not confirmed yet"). `docs/admin-guide.md`: credentials (replace before expiry; Phase 7 sends the reminder email), permissions of the new routes, what is stored (sealed credentials; never vault secret values), the poll interval. `docs/troubleshooting.md`: review the Task 17 sections against the built behaviour and link `docs/azure-setup.md`. `docs/licensing.md`: a vault is one target. `CHANGELOG.md`: the Phase 5 entry.

- [ ] **Step 3: R40**

Append **R40** to `00-decisions.md` after R39, in the style of R38/R39: "(Phase 5, approved with the Phase 5 plan; corrected to the built code at the end of Phase 5) Accepted Phase 5 decisions: (1) …" — one item per row of this plan's "Spec conflicts resolved by this plan", each corrected to what was built (names, numbers, codes), plus an addendum for the rulings made while the tasks ran.

- [ ] **Step 4: Security review**

`docs/security/reviews/phase-5.md`, in the structure of `phase-4.md`: Evidence (the suites and commands of this phase with their results), Threat notes (outbound requests and SSRF; credentials and tokens; vault secrets in deployments; auto-deploy decisions; imports; the fake and its fidelity), Review checklist, Findings, **Known limitations** — at least: the SDK keeps a client secret and the secret value as Go strings for a session's lifetime (cannot be zeroed); Key Vault Reader sufficiency (R22) and every fake answer are unconfirmed against real Azure until the owner runs `make test-azure`; the inner error code of a disabled secret is assumed (`SecretDisabled`) and otherwise reads as a missing role; no HTTPS proxy or custom CA for Azure before Phase 7; public cloud only; managed identity only on Azure VMs; vault listing bounds (5000/5000/10,000, 100 details per poll); older versions Alice never saw as current cannot be deployed; the import PFX uses 3DES/SHA-1 (empty password: no confidentiality claimed); client-secret expiry and key expiry emails wait for Phase 7; no deployment windows; wave limits fixed; bindings cannot be prepared in lock; a renewal made in Azure during a lock deploys automatically after the license is renewed; the access check never probes import; one token request per job; a Key Vault deployment needs the vault reachable when it runs (no cached key); `auth_failed` vaults keep polling hourly; `pkg/browser` and MSAL are linked; the e2e fake trusts a CA only in the e2e build. **Owner verification**: spec §26.7's five steps written for a real test vault (create the vault and a self-signed certificate with a 1-day renewal policy, the app registration with only Key Vault Reader, add the vault, …, remove Key Vault Secrets User and renew) and the real-Azure suite run (`ALICE_AZURE_TEST_*`, `make test-azure`, including `TestRealAzureReaderSufficiency`), with an empty result table:

| Step | Result (pass, or what differed) | Date and tester |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| Real-Azure suite (`make test-azure`) | | |
| Reader sufficiency (R22) | | |

and Sign-off (empty).

- [ ] **Step 5: `make ci`**

Run (Docker; no other Docker user meanwhile — Playwright runs inside it): `make ci`
Expected: PASS (lint, test, coverage, test-ssh, build, release-symcheck, i18n-check, web-lint, web-coverage, vuln, secrets-scan, fs-scan, the e2e stack with hardening and Playwright, image-check, image-scan). Fix failures in the task that owns them.

- [ ] **Step 6: Commit**

```bash
git add -- docs/azure-setup.md docs/security/reviews/phase-5.md internal/api/docs_azure_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "docs: Phase 5 Azure setup guide, R40, security review and coverage floors

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- coverage-floors.json docs/azure-setup.md docs/operator-guide.md docs/admin-guide.md docs/troubleshooting.md docs/licensing.md CHANGELOG.md docs/superpowers/specs/alice-v1/00-decisions.md docs/superpowers/specs/alice-v1/06-quality.md docs/superpowers/specs/alice-v1/01-product.md docs/security/reviews/phase-5.md internal/api/docs_azure_test.go
```
