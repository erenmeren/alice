# Dependency pins and how to update them

Every input that feeds a build is named by an immutable identifier, so one commit builds from
the same inputs tomorrow (audit AUD-09, SEC-089, SEC-103):

| Input | Pinned by | Where |
| --- | --- | --- |
| GitHub Actions (`uses:`) | full 40-character commit SHA plus `# v1.2.3` comment | `.github/workflows/*.yml` |
| Docker base images and the `# syntax=` frontend | `image:tag@sha256:<index digest>` | `deploy/Dockerfile`, `test/images/**` |
| PostgreSQL | `postgres:16-alpine@sha256:...` | `deploy/docker-compose.yml`, `internal/testutil/pgtest/pgtest.go`, `internal/platform/db/db_integration_test.go` |
| Tool images (gitleaks, trivy, ShellCheck) | `GITLEAKS_IMAGE`, `TRIVY_IMAGE`, `SHELLCHECK_IMAGE` with tag and digest; every `*_IMAGE` variable of the Makefile must be pinned that way | `Makefile` |

The tag stays in the reference for readability; Docker verifies the digest, not the tag. Digests are
of the multi-architecture index, so amd64 and arm64 both keep working.

`make lint` runs `go run ./tools/pincheck`, which needs no network. It fails when a `uses:`, a
workflow job's `container:` or `services.<name>.image:`, a `FROM`, a `COPY --from=`, a Compose
`image:` (of a service without `build:`), the image operand of a `docker run` / `docker create` /
`docker pull` in the Makefile, a script or a workflow `run:` step, a `docker://` reference, or a Go
test image names something not pinned, or when the PostgreSQL reference in a Go test differs from
the one in the Compose file. Only the image operand counts (a digest in a trailing comment or in
an option value does not), and the locally built `alice:` image is accepted only as that operand.
Dockerfile names are matched in any letter case (`Dockerfile`, `app.dockerfile`). `docker compose
run` names a service, not an image; that service's `image:` is checked in its Compose file. Each
message names the file and line. Fix it by pinning as below; do not add exceptions without a
decision recorded here.

What the check does not see: an image named only inside a shell variable or a Makefile variable that is not
named `<NAME>_IMAGE` (it fails closed: such an operand is reported; a `$(<NAME>_IMAGE)` operand must name a
variable that the Makefile defines, pinned), images pulled by
programs (the testcontainers Ryuk image, Playwright's browsers), and commands other than the ones
listed above that fetch images without a `docker://` reference (`docker buildx build` of a remote context, `crane`).

## Updating a pin by hand

Do not move to a new version while only pinning. To update on purpose, change the tag and the
digest together and run `make lint` and `make ci`.

Docker image (index digest; the `Docker-Content-Digest` header of the manifest list):

    docker buildx imagetools inspect postgres:16-alpine | awk '/^Digest:/ {print $2; exit}'
    # without buildx, ask the registry for the index directly (Docker Hub shown):
    tok=$(curl -s 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/postgres:pull' | jq -r .token)
    curl -sI -H "Authorization: Bearer $tok" \
      -H 'Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json' \
      https://registry-1.docker.io/v2/library/postgres/manifests/16-alpine | grep -i docker-content-digest
    # GitHub Container Registry (gitleaks) and Google Container Registry (distroless): the same
    # manifest request, with the token from the registry's own endpoint.
    tok=$(curl -s 'https://ghcr.io/token?service=ghcr.io&scope=repository:gitleaks/gitleaks:pull' | jq -r .token)
    #   then https://ghcr.io/v2/gitleaks/gitleaks/manifests/v8.30.1
    tok=$(curl -s 'https://gcr.io/v2/token?service=gcr.io&scope=repository:distroless/static-debian12:pull' | jq -r .token)
    #   then https://gcr.io/v2/distroless/static-debian12/manifests/latest

Write `postgres:16-alpine@sha256:<digest>`. The PostgreSQL reference appears three times (Compose,
`pgtest.go`, `internal/platform/db/db_integration_test.go`); Dependabot edits only the Compose file,
so a Dependabot PostgreSQL update fails `make lint` until the two Go files are edited to match.
The distroless base is `gcr.io/distroless/static-debian12:latest@sha256:...`. The `# syntax=` line
of a Dockerfile uses `docker/dockerfile:1@sha256:...` (resolve it the same way).

GitHub Action:

    git ls-remote https://github.com/actions/checkout 'refs/tags/v7*'

Take the newest `v7.x.y` tag. If the tag is annotated, the list also shows `refs/tags/v7.x.y^{}`;
use that peeled commit. Write `uses: actions/checkout@<sha> # v7.x.y`.

## Azure SDK for Go (Phase 5)

Phase 5 (Azure Key Vault) adds five direct modules, pinned by `go.mod` and `go.sum` (R40 row 1,
SEC-101): `github.com/Azure/azure-sdk-for-go/sdk/azcore` v1.23.2, `.../sdk/azidentity` v1.14.1,
`.../sdk/security/keyvault/azcertificates` v1.5.0, `.../azkeys` v1.5.0 and `.../azsecrets` v1.5.0
(all MIT). Why: they are Microsoft's own clients for Entra ID sign-in and the Key Vault data plane;
writing the protocol by hand would carry more risk than depending on them. The first user is the fake
Azure service's round-trip test (`internal/testutil/fakekv/sdk_test.go`); the provider imports them
from Task 6 on.

Seven indirect modules come with them: `sdk/internal` v1.12.0 (MIT), `sdk/security/keyvault/internal`
v1.2.0 (MIT), `github.com/AzureAD/microsoft-authentication-library-for-go` v1.9.0 (MIT; the plan said
v1.8.0, v1.9.0 is what resolves), `github.com/golang-jwt/jwt/v5` v5.3.1 (MIT),
`github.com/kylelemons/godebug` v1.1.0 (Apache-2.0), `github.com/pkg/browser` (BSD-2-Clause) and
`golang.org/x/net` v0.58.0 (BSD-3-Clause). `pkg/browser` and the interactive credentials of `azidentity`
are linked but never called: `TestAzureSDKSurface` (Task 6) fails on any use of a credential type other
than the three Alice needs (client secret, client certificate, managed identity).

Update procedure: `go get <module>@vX.Y.Z` for the five modules, `go mod tidy`, `go mod verify`,
`go run ./tools/pincheck`, `make test test-integration`, then run the fake's round trip
(`go test ./internal/testutil/fakekv -run SDK`) again. A new Key Vault api-version in the SDK needs the
fake's version check (`fakekv.APIVersion`) and the reference answers in `test/testdata/kv-recordings`
updated first; MSAL's changes to the assertion header or the token request need the fake's token
endpoint checked.

## go-ldap (directory sign-in)

Directory sign-in (plan 2026-10-15, LDAP and Active Directory) adds two direct modules, pinned by `go.mod` and
`go.sum`: `github.com/go-ldap/ldap/v3` v3.4.15 (MIT; the newest tag when it was added) and
`github.com/go-asn1-ber/asn1-ber` v1.5.8 (MIT; direct because a test reads the compiled filter packets). Why:
go-ldap is the established pure-Go LDAP v3 client (no cgo, so `CGO_ENABLED=0` builds keep working); writing the
protocol, the BER encoding and the filter compiler by hand would carry more risk. The first user is the filter and
DN property tests of `internal/auth/ldap/ldapx` (`ldap.CompileFilter`, `ldap.ParseDN`); the production helpers in
that package import neither module. The network client in `internal/auth/ldap` imports go-ldap from Task 3 on.

One new indirect module is compiled in: `github.com/Azure/go-ntlmssp` v0.1.1 (MIT; NTLM bind, linked by go-ldap but
never called: Alice binds with a simple bind over `ldaps://` only). `github.com/google/uuid` v1.6.0 (BSD-3-Clause)
and `golang.org/x/crypto` v0.57.0 (BSD-3-Clause, `md4` for NTLM) were already in the graph at these or newer
versions; go-ldap asks for x/crypto v0.54.0, so nothing moved. The module graph (and `go.sum`) also gains modules of
go-ldap's GSSAPI and Windows SSPI packages, which Alice does not import and does not compile:
`github.com/jcmturner/gokrb5/v8` v8.4.4, `aescts/v2` v2.0.0, `dnsutils/v2` v2.0.0, `goidentity/v6` v6.0.1 and
`rpc/v2` v2.0.3 (Apache-2.0), `github.com/jcmturner/gofork` v1.7.6 and `github.com/alexbrainman/sspi`
(BSD-3-Clause), and `github.com/hashicorp/go-uuid` v1.0.3 (MPL-2.0). If a later change imports
`github.com/go-ldap/ldap/v3/gssapi`, the MPL-2.0 module becomes part of the binary: decide that on purpose.

Update procedure: `go list -m -versions github.com/go-ldap/ldap/v3` (take the newest tag without a pre-release
suffix), `go get github.com/go-ldap/ldap/v3@vX.Y.Z`, `go mod tidy`, `go mod verify`, check with
`go list -m all` that no other module moved backwards, read the LICENSE of every new module in the module cache,
`CGO_ENABLED=0 go build ./cmd/...`, `go run ./tools/pincheck`, `make lockcheck`, then
`go test ./internal/auth/ldap/...`, `make fuzz-ldap` and `make test-integration` (the real OpenLDAP suite). Read the
release notes for changes to `CompileFilter`, `ParseDN`, `EscapeFilter` or the TLS dial: the property tests of
`ldapx` compare Alice's escaping with go-ldap's parser and fail when go-ldap reads a filter differently.

## Dependabot

`.github/dependabot.yml` proposes weekly updates for Actions, the Dockerfile and Compose images,
Go modules and `web/` npm packages, with a limit of five open pull requests per ecosystem. It does
nothing until the repository has a GitHub remote. Dependabot's Docker updater may not read
`test/images/sshd/*.Dockerfile` (they are not named `Dockerfile`); update those three by hand.

Updated by hand, always (Dependabot does not read them): the Makefile tool images
`GITLEAKS_IMAGE` and `TRIVY_IMAGE`, and the `# syntax=docker/dockerfile:1@sha256:...` frontend
line of every Dockerfile.

Reviewing a Dependabot pull request: read the release notes; for an image, compare
`docker buildx imagetools inspect <tag>` with the digest in the diff; run `make ci`.

## Not pinned, on purpose

- Go tools (`golangci-lint`, `govulncheck`) are `go install ...@vX.Y.Z`: a version, verified by the
  Go module checksum database. `go.sum` pins the module graph.
- npm packages are pinned by `web/package-lock.json` (`npm ci --ignore-scripts`: no package runs
  code at install time). Go modules are pinned by `go.sum`; `make vuln` and the workflow run
  `go mod verify` first.
- The testcontainers Ryuk reaper image is chosen by the library version, not named in this
  repository.
- Playwright downloads its browsers (`npx playwright install`); the version follows
  `@playwright/test` in the lockfile, the download itself is not content-pinned.
- `actions/setup-node` and `actions/setup-go` download the Node and Go toolchains by the version
  given to them (`go-version-file: go.mod`, `node-version: 24`).

## The other static gates of `make lint` and `make vuln`

| Target | Checks | Tool |
| --- | --- | --- |
| `make shellcheck` | every shell script (`SHELL_SCRIPTS` in the Makefile) with `-x -P SCRIPTDIR`, so `# shellcheck source=` lines resolve next to the script | `SHELLCHECK_IMAGE` (pinned) |
| `make lockcheck` | `web/package-lock.json` and `go.sum` hold package data only: no extra field, only registry.npmjs.org downloads, only `sha512-` integrity values (a secret-scan substitute for files too large to review) | `tools/lockcheck` |
| `make docs-check` | commands, flags and `make` targets named in the guides exist; relative links and heading anchors resolve; the sentences of `tools/docscheck/required.txt` are still in their files | `tools/docscheck` |
| `make actionlint` | the GitHub workflows | `actionlint` (`ACTIONLINT_VERSION`, installed by `make tools`) |
| `make osv` (in `make vuln`) | `go.mod` and `web/package-lock.json` against the OSV database; any finding fails | `osv-scanner` (`OSV_SCANNER_VERSION`) |

An `osv-scanner` finding is fixed (for npm, `npm update <package> --package-lock-only` in `web/` when the
range allows the fixed version). If it cannot be fixed, `osv-scanner.toml` takes an `[[IgnoredVulns]]` entry with
`id`, `reason` and `ignoreUntil` at most 90 days ahead. ShellCheck findings are fixed in the script; a
`# shellcheck disable=` line needs a reason on the same line.
