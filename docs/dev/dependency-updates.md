# Dependency pins and how to update them

Every input that feeds a build is named by an immutable identifier, so one commit builds from
the same inputs tomorrow (audit AUD-09, SEC-089, SEC-103):

| Input | Pinned by | Where |
| --- | --- | --- |
| GitHub Actions (`uses:`) | full 40-character commit SHA plus `# v1.2.3` comment | `.github/workflows/*.yml` |
| Docker base images and the `# syntax=` frontend | `image:tag@sha256:<index digest>` | `deploy/Dockerfile`, `test/images/**` |
| PostgreSQL | `postgres:16-alpine@sha256:...` | `deploy/docker-compose.yml`, `internal/testutil/pgtest/pgtest.go`, `internal/platform/db/db_integration_test.go` |
| Tool images (gitleaks, trivy) | `GITLEAKS_IMAGE`, `TRIVY_IMAGE` with tag and digest | `Makefile` |

The tag stays in the reference for readability; Docker verifies the digest, not the tag. Digests are
of the multi-architecture index, so amd64 and arm64 both keep working.

`make lint` runs `go run ./tools/pincheck`, which needs no network. It fails when a `uses:`, a
workflow job's `container:` or `services.<name>.image:`, a `FROM`, a `COPY --from=`, a Compose
`image:` (of a service without `build:`), the image operand of a `docker run` / `docker create` in
the Makefile, a script or a workflow `run:` step, a `docker://` reference, or a Go test image names
something not pinned, or when the PostgreSQL reference in a Go test differs from the one in the
Compose file. Only the image operand of a `docker run` counts (a digest in a trailing comment or in
an option value does not), and the locally built `alice:` image is accepted only as that operand. Each message names the file and
line. Fix it by pinning as below; do not add exceptions without a decision recorded here.

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
