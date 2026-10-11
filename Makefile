SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w -X alice/internal/version.Version=$(VERSION) -X alice/internal/version.Commit=$(COMMIT) -X alice/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

.PHONY: test
test: ## Run Go unit tests with the race detector (release build, plus the e2e and test-license builds of cmd/alice)
	go test -race -count=1 ./...
	go test -race -count=1 -tags "e2e testlicense" ./cmd/alice/
	go test -race -count=1 -tags testlicense ./cmd/alice/
	go test -race -count=1 -tags testlicense ./internal/license/...

.PHONY: test-integration
test-integration: ## Run integration tests (needs Docker)
	go test -race -count=1 -tags integration ./...

# The real-Nginx matrix installs the release-built helper (make helper) through the nginx profile's
# setup script, which checks it against the checksums linked into the test binary exactly as make
# build links them into alice. It runs only here (ALICE_REAL_MATRIX=1; make coverage skips it). Each
# matrix line runs verbose and fails unless its test PASSED: a -run pattern that matches no test
# ("[no tests to run]", which go test calls ok) or a skipped test fails the line. RUN, PAUSE, CONT
# and passing subtest lines are not printed.
SSH_MATRIX_PASSED = 2>&1 | awk -v t=$(1) '!/^=== |^ +--- PASS/ { print } /no tests to run/ || $$0 ~ "^--- SKIP: " t { bad = 1 } $$0 ~ "^--- PASS: " t " " { ok = 1 } END { exit bad || !ok }'

.PHONY: test-ssh
test-ssh: helper ## Run the real OpenSSH and Nginx matrices (Ubuntu 22.04, Debian 12, Rocky 9; needs Docker). ALICE_SSH_IMAGES=ubuntu22 limits them
	@for sum in '$(call HELPER_SUM,amd64)' '$(call HELPER_SUM,arm64)'; do \
	  echo "$$sum" | grep -Eqx '[0-9a-f]{64}' || { echo "bin/alice-helper.sha256 lacks a helper checksum; run make helper"; exit 1; }; \
	done
	set -o pipefail; go test -count=1 -v -tags integration -run '^TestRealOpenSSH$$' ./internal/providers/linuxssh/ $(call SSH_MATRIX_PASSED,TestRealOpenSSH)
	set -o pipefail; ALICE_REAL_MATRIX=1 go test -count=1 -v -timeout 30m -tags integration -ldflags "$(HELPER_LDFLAGS)" -run '^TestRealNginx' ./internal/providers/nginx/ $(call SSH_MATRIX_PASSED,TestRealNginx)

.PHONY: test-release
test-release: ## Release harness: install, backup/restore drill, update and rollback in Ubuntu 22.04, Debian 12, Rocky 9 containers (Docker; no Playwright meanwhile; ~30 min)
	@mkdir -p bin
	set -o pipefail; go test -count=1 -timeout 90m -tags release -v ./test/release/ 2>&1 | tee bin/test-release.log

.PHONY: test-azure
test-azure: ## Optional real Azure Key Vault suite; needs ALICE_AZURE_TEST_* (see internal/providers/azurekv/real_azure_test.go); never part of ci
	go test -count=1 -v -tags azure -run '^TestRealAzure' ./internal/providers/azurekv/

.PHONY: record-azure
record-azure: ## Optional: rewrite test/testdata/kv-recordings from a real vault's answers (shapes and placeholders only); needs ALICE_AZURE_TEST_*; never part of ci
	ALICE_AZURE_RECORD=1 go test -count=1 -v -tags azure -run '^TestRecordShapes$$' ./internal/providers/azurekv/

.PHONY: i18n-check
i18n-check: ## Verify EN/TR translation catalogs have identical keys and placeholders
	go run ./tools/i18n-check locales/common web/src/locales

.PHONY: authz-doc
authz-doc: ## Regenerate docs/authz-matrix.md from the route table
	go test ./internal/api -run TestAuthzMatrixDocIsCurrent -count=1 -update

# --ignore-scripts (SEC-103, AUD-23): no package runs code at install time. Only fsevents (macOS)
# and msw (copies its worker only when package.json sets msw.workerDirectory) declare install
# scripts; native tools (rolldown, lightningcss, esbuild) come as optional platform packages.
# Playwright's browsers are a separate step (make e2e).
.PHONY: web-install
web-install: ## Install web dependencies from the lockfile, without install scripts
	cd web && npm ci --ignore-scripts

.PHONY: web
web: ## Build the web UI into internal/webui/dist/app
	cd web && npm run build

.PHONY: web-test
web-test: ## Run web unit tests
	cd web && npm test

.PHONY: web-coverage
web-coverage: ## Run web unit tests under coverage and enforce the thresholds of web/vite.config.ts (AUD-23)
	cd web && npm run coverage

.PHONY: web-lint
web-lint: ## Lint the web UI
	cd web && npm run lint

# The setup script checks alice-helper against these checksums (R37 item 2). Expanded when the
# build recipe runs, after the helper prerequisite wrote bin/alice-helper.sha256.
HELPER_SUM = $(shell awk '$$2 == "alice-helper-linux-$(1)" { print $$1 }' bin/alice-helper.sha256 2>/dev/null)
HELPER_LDFLAGS = -X alice/internal/providers/linuxssh.helperSHA256LinuxAMD64=$(call HELPER_SUM,amd64) -X alice/internal/providers/linuxssh.helperSHA256LinuxARM64=$(call HELPER_SUM,arm64)

.PHONY: build
build: web helper ## Build the alice binary with the embedded UI (and the helper checksums) into bin/
	@for sum in '$(call HELPER_SUM,amd64)' '$(call HELPER_SUM,arm64)'; do \
	  echo "$$sum" | grep -Eqx '[0-9a-f]{64}' || { echo "bin/alice-helper.sha256 lacks a helper checksum; run make helper"; exit 1; }; \
	done
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS) $(HELPER_LDFLAGS)" -o bin/alice ./cmd/alice
	@! go version -m bin/alice | grep -q stretchr/testify || { echo "testify is linked into bin/alice"; exit 1; }

# Release symbol guard: the release build (no tags) links no e2e-only code. The e2e build is the
# positive control: release-symcheck checks EACH name (present in the e2e build, absent from the
# release build), so a renamed or inlined symbol fails instead of hiding behind another one. The
# release build also imports no alice/internal/testutil/ package: go list -deps checks the package graph (a
# constant or an inlined helper leaves no symbol), nm the linked symbols; the e2e build is the positive control.
E2E_SYMBOLS := main\.(damageLicenseFile|tamperNewestLicenseFile|resetInstall|e2eClock|e2eMailbox|drainJobs|runWithinBudget|drainMu|errDrainBudget|runScheduledTask|scheduled|serveRotationOverlap|setPolicyOverlap|serveSeedDashboard)$$

# Test-only data a release binary must not hold (AUD-23): the label the test license signing key is
# derived from (testKeyLabel in internal/license/keys_testlicense.go) and a route only the e2e build
# serves (cmd/alice/testapi_e2e.go). release-symcheck proves an e2e build holds both, so their
# absence from the release build and from the image (image-check) means something.
# internal/archtest/buildtags_test.go checks that both values still match the source.
TEST_LICENSE_LABEL := alice test license signing key v1
TEST_ROUTE_MARKER := /test/clock

# The directory the e2e build reads the fake Azure service's CA from (cmd/alice/testapi_e2e.go; the fake
# writes its CA there, compose shares the volume read-only with alice). Only the e2e build holds this
# string: release-symcheck proves the e2e build does and the release build does not, and image-check
# refuses it in the image's binary. internal/archtest checks it appears only in e2e-tagged source.
E2E_AZURE_MARKER := /run/alice-e2e-azure

.PHONY: release-symcheck
release-symcheck: ## Fail if the release build of alice links e2e-only test code, has build tags or trusts the test license key
	CGO_ENABLED=0 go build -trimpath -o bin/.symcheck-release ./cmd/alice
	CGO_ENABLED=0 go build -trimpath -tags "e2e testlicense" -o bin/.symcheck-e2e ./cmd/alice
	@go tool nm bin/.symcheck-e2e > bin/.symcheck-e2e.nm && go tool nm bin/.symcheck-release > bin/.symcheck-release.nm
	@for s in $$(echo '$(E2E_SYMBOLS)' | sed -E 's/^[^(]*\((.*)\).*/\1/' | tr '|' ' '); do \
	  grep -Eq " main\.$$s$$" bin/.symcheck-e2e.nm || { echo "release-symcheck: the e2e build lacks main.$$s (renamed or inlined?); update E2E_SYMBOLS"; exit 1; }; \
	  ! grep -Eq " main\.$$s$$" bin/.symcheck-release.nm || { echo "release-symcheck: the release build links e2e-only main.$$s"; exit 1; }; \
	done
	@! grep -E ' $(E2E_SYMBOLS)' bin/.symcheck-release.nm || { echo "release-symcheck: the release build links e2e-only code"; exit 1; }
	@go list -deps -tags "e2e testlicense" ./cmd/alice > bin/.symcheck-e2e.deps && go list -deps ./cmd/alice > bin/.symcheck-release.deps
	@grep -q '^alice/internal/testutil/seed$$' bin/.symcheck-e2e.deps || { echo "release-symcheck: cannot see the seed package in the e2e build's dependencies"; exit 1; }
	@! grep -E '^alice/internal/testutil/' bin/.symcheck-release.deps || { echo "release-symcheck: the release build imports test-data code"; exit 1; }
	@grep -Eq ' alice/internal/testutil/seed\.' bin/.symcheck-e2e.nm || { echo "release-symcheck: cannot see the seed package in the e2e build"; exit 1; }
	@! grep -E ' alice/internal/testutil/' bin/.symcheck-release.nm || { echo "release-symcheck: the release build links test-data code"; exit 1; }
	@go version -m bin/.symcheck-e2e | grep -Eq '^\s+build\s+-tags=.*testlicense' || { echo "release-symcheck: cannot see build tags in the build info"; exit 1; }
	@! go version -m bin/.symcheck-release | grep -Eq '^\s+build\s+-tags=' || { echo "release-symcheck: the release build has build tags"; exit 1; }
	@grep -aqF '$(TEST_LICENSE_LABEL)' bin/.symcheck-e2e || { echo "release-symcheck: cannot see the test key label in the e2e build; update TEST_LICENSE_LABEL"; exit 1; }
	@! grep -aqF '$(TEST_LICENSE_LABEL)' bin/.symcheck-release || { echo "release-symcheck: the release build trusts the test license key"; exit 1; }
	@grep -aqF '$(TEST_ROUTE_MARKER)' bin/.symcheck-e2e || { echo "release-symcheck: cannot see $(TEST_ROUTE_MARKER) in the e2e build; update TEST_ROUTE_MARKER"; exit 1; }
	@! grep -aqF '$(TEST_ROUTE_MARKER)' bin/.symcheck-release || { echo "release-symcheck: the release build serves the e2e /test routes"; exit 1; }
	@grep -aqF '$(E2E_AZURE_MARKER)' bin/.symcheck-e2e || { echo "release-symcheck: cannot see $(E2E_AZURE_MARKER) in the e2e build; update E2E_AZURE_MARKER"; exit 1; }
	@! grep -aqF '$(E2E_AZURE_MARKER)' bin/.symcheck-release || { echo "release-symcheck: the release build knows where the fake Azure CA lives"; exit 1; }
	@rm -f bin/.symcheck-release bin/.symcheck-e2e bin/.symcheck-release.nm bin/.symcheck-e2e.nm bin/.symcheck-release.deps bin/.symcheck-e2e.deps
	@echo "release-symcheck: ok"

.PHONY: licensectl
licensectl: ## Build the vendor's offline license tool into bin/ (never shipped to customers)
	CGO_ENABLED=0 go build -trimpath -o bin/licensectl ./cmd/licensectl

.PHONY: helper
helper: ## Build the static alice-helper for Linux amd64 and arm64 into bin/ with SHA-256 checksums (reproducible: no VCS stamp)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-helper-linux-amd64 ./cmd/alice-helper
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-helper-linux-arm64 ./cmd/alice-helper
	cd bin && sha256sum alice-helper-linux-amd64 alice-helper-linux-arm64 > alice-helper.sha256

# The make up stack also reads deploy/docker-compose.override.yml when it exists, as docker compose
# does by itself in deploy/ (AUD-24): docs/operator-guide.md mounts the SMTP password and CA file
# with it. The file is the operator's and ignored by git. COMPOSE_E2E never reads it: the e2e
# project names its files explicitly.
COMPOSE := docker compose -f deploy/docker-compose.yml $(if $(wildcard deploy/docker-compose.override.yml),-f deploy/docker-compose.override.yml) --env-file deploy/.env

# make image builds alice:$(IMAGE_TAG) only. It never writes alice:dev, the tag the make up stack
# runs (image: alice:$${ALICE_VERSION:-dev}), so a CI build cannot replace the image of a running
# installation on the next "docker compose up". Pass IMAGE_TAG=<version> to tag a release build.
IMAGE_TAG ?= ci

.PHONY: image
image: ## Build the alice container image as alice:$(IMAGE_TAG) (default alice:ci; never alice:dev)
	@[ "$(IMAGE_TAG)" != dev ] || { echo "make image never writes alice:dev (the make up stack's tag); use make up"; exit 1; }
	docker build -f deploy/Dockerfile --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t alice:$(IMAGE_TAG) .

# make image-check inspects the image make image just built (alice:$(IMAGE_TAG), never alice:dev):
# deploy/dev/check-image.sh lists what it checks. It needs Docker and Go, no database, no network.
# The helper build is reproducible, so the image must hold the checksums make helper writes.
.PHONY: image-check
image-check: image helper ## Check the release image: non-root, no shell or test artefacts, a release binary without build tags, test key or /test routes (AUD-23)
	TEST_LICENSE_LABEL='$(TEST_LICENSE_LABEL)' TEST_ROUTE_MARKER='$(TEST_ROUTE_MARKER)' E2E_AZURE_MARKER='$(E2E_AZURE_MARKER)' \
	  HELPER_SHA256_AMD64='$(call HELPER_SUM,amd64)' HELPER_SHA256_ARM64='$(call HELPER_SUM,arm64)' \
	  ./deploy/dev/check-image.sh $(IMAGE_TAG)

.PHONY: up
up: ## Build and start Alice with PostgreSQL (https://localhost)
	./deploy/dev/init-env.sh
	ALICE_BUILD_TIME=$(BUILD_TIME) $(COMPOSE) up -d --build --wait

.PHONY: down
down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) down

.PHONY: reset
reset: ## DELETE local data (database, key and state volumes) and start a fresh stack
	$(COMPOSE) down -v
	$(MAKE) up

.PHONY: logs
logs: ## Follow the alice container logs
	$(COMPOSE) logs -f alice

.PHONY: hardening-check
hardening-check: ## Verify container hardening of the running stack
	./deploy/dev/check-hardening.sh

# The e2e stack is its own compose project: its database, volumes and networks never touch the
# make up stack (project "alice"), because every Playwright run empties the database.
E2E_PROJECT := alice-e2e
E2E_FILES   := docker-compose.yml docker-compose.e2e.yml
COMPOSE_E2E := docker compose -p $(E2E_PROJECT) -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml --env-file deploy/.env

.PHONY: e2e-up
e2e-up: ## Build and start the e2e variant as project alice-e2e (adds test-only /test endpoints; never shipped)
	./deploy/dev/init-env.sh
	ALICE_BUILD_TIME=$(BUILD_TIME) $(COMPOSE_E2E) up -d --build --wait

.PHONY: e2e-down
e2e-down: ## Stop the e2e stack and DELETE its volumes (never touches the make up stack)
	$(COMPOSE_E2E) down -v --remove-orphans

.PHONY: e2e-hardening-check
e2e-hardening-check: ## Verify container hardening of the running e2e stack, including the SSH test target and the fake Azure service
	ALICE_PROJECT=$(E2E_PROJECT) ALICE_COMPOSE_FILES="$(E2E_FILES)" ./deploy/dev/check-hardening.sh

.PHONY: setup-token
setup-token: ## Print a new one-time setup code for the /setup wizard (only before the first administrator exists)
	$(COMPOSE) exec -T alice /usr/local/bin/alice setup-token --reset

.PHONY: unlock
unlock: ## End a sign-in delay or lockout: make unlock ACCOUNT=<username> (audited as cli)
	@test -n "$(ACCOUNT)" || { echo "usage: make unlock ACCOUNT=<username>"; exit 2; }
	$(COMPOSE) exec -T alice /usr/local/bin/alice admin unlock "$(ACCOUNT)"

.PHONY: e2e
e2e: ## Run Playwright tests against the e2e stack (make e2e-up first)
	cd web && npx playwright install chromium && port="$${ALICE_E2E_PORT:-}" && set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a && { [ -z "$$port" ] || ALICE_E2E_PORT="$$port"; } && export ALICE_E2E_PORT && ALICE_E2E_PROJECT=$(E2E_PROJECT) npx playwright test

GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION   ?= v1.8.0
OSV_SCANNER_VERSION   ?= v2.6.0
GREMLINS_VERSION      ?= v0.6.0
ACTIONLINT_VERSION    ?= v1.7.12
# Tool images are pinned by tag and by index digest (AUD-09; docs/dev/dependency-updates.md).
GITLEAKS_IMAGE        ?= ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
TRIVY_IMAGE           ?= aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969
SHELLCHECK_IMAGE      ?= koalaman/shellcheck:v0.11.0@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d
# Every shell script of the repository that is not named *.sh as well (tracked files only).
SHELL_SCRIPTS         := $(shell git ls-files -- '*.sh' deploy/release/alicectl 'deploy/release/testdata/stubs/*' deploy/release/testdata/swap-openssl/openssl test/images/e2e-target/systemctl test/images/e2e-target/nginx-wrapper)
# How long each fuzz target runs; fuzz-nightly and fuzz-release raise it.
FUZZTIME              ?= 60s
# Extra flags of matrix-check ("-strict" in release-gates and the last step of Phase 8).
MATRIXCHECK_FLAGS     ?=

.PHONY: tools
tools: ## Install pinned Go developer tools into $(HOME)/go/bin
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/google/osv-scanner/v2/cmd/osv-scanner@$(OSV_SCANNER_VERSION)
	go install github.com/go-gremlins/gremlins/cmd/gremlins@$(GREMLINS_VERSION)
	go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

.PHONY: lint
lint: ## Run golangci-lint (gosec, forbidigo, ...) on the release and the e2e build
	go run ./tools/pincheck
	$(MAKE) shellcheck lockcheck docs-check actionlint
	golangci-lint run ./...
	golangci-lint run --build-tags e2e,testlicense ./cmd/...
	golangci-lint run --build-tags integration,testlicense ./cmd/...
	golangci-lint run --build-tags integration,e2e,testlicense ./cmd/...
	golangci-lint run --build-tags integration,testlicense ./internal/license/...
	golangci-lint run --build-tags integration ./internal/providers/azurekv/...
	golangci-lint run --build-tags release ./test/release/...

.PHONY: vuln
vuln: ## Verify the Go module cache against go.sum, then check Go and npm dependencies for known vulnerabilities
	go mod verify
	govulncheck ./...
	cd web && npm audit --omit=dev --audit-level=high
	$(MAKE) osv

.PHONY: shellcheck lockcheck matrix-check docs-check actionlint osv test-backup-cycle fuzz-backup fuzz-api fuzz-nightly fuzz-release
shellcheck: ## ShellCheck every shell script (pinned image; -P SCRIPTDIR resolves the "# shellcheck source=" lines)
	docker run --rm -v "$(CURDIR):/src:ro" -w /src $(SHELLCHECK_IMAGE) -x -P SCRIPTDIR $(SHELL_SCRIPTS)
lockcheck: ## Refuse anything but package data in web/package-lock.json and go.sum (secret-scan substitute, R43 row 38)
	go run ./tools/lockcheck web/package-lock.json go.sum
matrix-check: ## Every ID of the sections 23-25 matrices maps to existing tests, an owner step or a ruling (-strict: release-gates)
	go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md $(MATRIXCHECK_FLAGS)
docs-check: ## Commands named in the guides exist; relative links resolve; required sentences are present
	go run ./tools/docscheck
actionlint: ## Lint the GitHub workflows
	actionlint .github/workflows/*.yml
osv: ## osv-scanner over go.mod and the npm lockfile (any finding fails; ignores need id, reason and ignoreUntil)
	osv-scanner scan source --config osv-scanner.toml -L go.mod -L web/package-lock.json
test-backup-cycle: ## F-85 full cycle with a test license (integration, testlicense; needs Docker)
	out=$$(mktemp); trap 'rm -f "$$out"' EXIT; set -o pipefail; \
	go test -race -count=1 -tags 'integration testlicense' -run '^TestF85' -v ./internal/backup/ | tee "$$out"; \
	grep -q -- '^--- PASS: TestF85' "$$out" || { echo 'test-backup-cycle: no TestF85 test passed (does it exist?)' >&2; exit 1; }

.PHONY: secrets-scan
secrets-scan: ## Scan git history for committed secrets
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$(CURDIR):/repo" $(GITLEAKS_IMAGE) git /repo --config /repo/.gitleaks.toml --gitleaks-ignore-path /repo/.gitleaksignore --redact

.PHONY: fs-scan
fs-scan: ## Scan the source tree for HIGH/CRITICAL vulnerabilities and secrets (trivy fs)
	docker run --rm -v "$(CURDIR):/src:ro" -w /src $(TRIVY_IMAGE) fs --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 --skip-dirs '**/node_modules',.superpowers,.claude,.git,web/playwright-report,web/test-results,bin .

.PHONY: image-scan
image-scan: image ## Scan the container image for HIGH/CRITICAL vulnerabilities
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $(TRIVY_IMAGE) image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed alice:$(IMAGE_TAG)

# The e2e stack is always removed at the end, also when a stage of it fails. It publishes
# ALICE_E2E_PORT (default 9443), so it runs beside the make up stack, which ci never touches.
.PHONY: ci
ci: ## Run the full CI pipeline locally
	$(MAKE) lint test coverage perf test-backup-cycle test-ssh build release-symcheck i18n-check web-lint web-coverage vuln secrets-scan fs-scan
	@status=0; $(MAKE) e2e-up e2e-hardening-check e2e || status=$$?; $(MAKE) e2e-down; exit $$status
	$(MAKE) image-check image-scan

.PHONY: fuzz-license
fuzz-license: ## Fuzz the license parser ($(FUZZTIME); spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseLicense -fuzztime $(FUZZTIME) ./internal/license/

.PHONY: fuzz-ssh
fuzz-ssh: ## Fuzz the authorized_keys and sshd configuration parsers ($(FUZZTIME) each; spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseAuthorizedKeys -fuzztime $(FUZZTIME) ./internal/providers/linuxssh/
	go test -count=1 -run '^$$' -fuzz FuzzParseSSHDConfig -fuzztime $(FUZZTIME) ./internal/providers/linuxssh/sshdconf/
	go test -count=1 -run '^$$' -fuzz FuzzAuthorizedLine -fuzztime $(FUZZTIME) ./internal/sshkeys/keymat/

.PHONY: fuzz-oidc
fuzz-oidc: ## Fuzz the ID token claim parser ($(FUZZTIME); spec §25.6, Phase 7)
	go test -count=1 -run '^$$' -fuzz FuzzParse -fuzztime $(FUZZTIME) ./internal/auth/oidc/claims/

.PHONY: fuzz-nginx
fuzz-nginx: ## Fuzz the nginx -T parser ($(FUZZTIME); spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseNginxConfig -fuzztime $(FUZZTIME) ./internal/providers/nginx/nginxconf/

.PHONY: fuzz-certs
fuzz-certs: ## Fuzz the certificate upload and Key Vault secret parsers ($(FUZZTIME) each; spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseCertificateUpload -fuzztime $(FUZZTIME) ./internal/certs/
	go test -count=1 -run '^$$' -fuzz FuzzParseKVSecret -fuzztime $(FUZZTIME) ./internal/certs/

.PHONY: fuzz-backup
fuzz-backup: ## Fuzz the backup header, stream and payload decoder ($(FUZZTIME) each)
	go test -count=1 -run '^$$' -fuzz FuzzBackupHeader -fuzztime $(FUZZTIME) ./internal/backup/format/
	go test -count=1 -run '^$$' -fuzz FuzzBackupStream -fuzztime $(FUZZTIME) ./internal/backup/format/
	go test -count=1 -run '^$$' -fuzz FuzzDecoder -fuzztime $(FUZZTIME) ./internal/backup/dump/

.PHONY: fuzz-api
fuzz-api: ## Fuzz every create/update body of the API (needs Docker; $(FUZZTIME))
	go test -count=1 -tags integration -run '^$$' -fuzz FuzzOpenAPIInputs -fuzztime $(FUZZTIME) ./internal/api/

.PHONY: fuzz-nightly
fuzz-nightly: ## Every fuzz target for 10 minutes (spec §25.6 nightly)
	$(MAKE) fuzz-license fuzz-ssh fuzz-oidc fuzz-nginx fuzz-certs fuzz-backup fuzz-api FUZZTIME=10m

.PHONY: fuzz-release
fuzz-release: ## Every fuzz target for 30 minutes (spec §25.6 release; about 7 hours)
	$(MAKE) fuzz-license fuzz-ssh fuzz-oidc fuzz-nginx fuzz-certs fuzz-backup fuzz-api FUZZTIME=30m

# Release packages (C5; Task 12). make release stages an unsigned package in $(RELEASE_DIR)/alice-$(VERSION)/alice;
# the vendor signs its SHA256SUMS offline (licensectl release-sign), make release-pack packs it and the
# vendor signs the outer .sha256. make release-test does all of it with a throw-away test key
# (release candidates only, TEST_SIGNED=1). make release refuses when outputs of the same VERSION
# exist (it never replaces a signed package); only make release-test removes them, and only those
# of a test package (Task 12 review I-2). make release needs Docker: it builds alice:$(VERSION),
# inspects it with make image-check (build tags, test key, /test routes, user, shell, and the
# embedded helper checksums against bin/alice-helper.sha256, which the stage checks the bundled
# helper against; I-6), and saves both images.
RELEASE_DIR      ?= bin/release
RELEASE_KEYS     ?= deploy/release/keys
RELEASE_TEST_KEY ?= bin/release-test-key
RELEASE_COMMIT   ?= $(shell git rev-parse HEAD 2>/dev/null)
RELEASE_STAGE_FLAGS ?=
# Every 1.0.x release accepts an update from the first release candidate on; raise it when a release needs an intermediate one
# (the first release signed by a new release key: the overlap release that carried both keys; licensing-vendor.md, Rotation).
MIN_UPGRADE_FROM ?= 1.0.0-rc.1
POSTGRES_RELEASE_IMAGE := postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea

RELEASE_OUTPUTS = "$(abspath $(RELEASE_DIR))/alice-$(VERSION)" "$(abspath $(RELEASE_DIR))/sbom-$(VERSION)" "$(abspath $(RELEASE_DIR))/alice-$(VERSION).tar.gz" "$(abspath $(RELEASE_DIR))/alice-$(VERSION).tar.gz.sha256" "$(abspath $(RELEASE_DIR))/alice-$(VERSION).tar.gz.sha256.sig"

.PHONY: release-preflight
release-preflight: # make release's first prerequisite: refuse before anything is built
	@echo "$(VERSION)" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?' || { echo "make release needs VERSION=x.y.z or x.y.z-rc.N"; exit 2; }
	@test -n "$(RELEASE_COMMIT)" || { echo "make release needs RELEASE_COMMIT (no .git here)"; exit 2; }
	@for f in $(RELEASE_OUTPUTS); do if [ -e "$$f" ]; then echo "make release: outputs of $(VERSION) already exist in $(abspath $(RELEASE_DIR)); it never replaces them (make release-test removes those of a test package)"; exit 2; fi; done

.PHONY: release
# One build time for the image and RELEASE (BUILD_TIME is a recursive ?= and would be re-evaluated per use).
release: BUILD_TIME := $(BUILD_TIME)
release: release-preflight helper notices ## Stage an unsigned release in $(RELEASE_DIR)/alice-$(VERSION) (VERSION=x.y.z; needs Docker; sign SHA256SUMS offline, then make release-pack)
	$(MAKE) image-check IMAGE_TAG=$(VERSION) VERSION=$(VERSION) BUILD_TIME=$(BUILD_TIME)
	docker image inspect $(POSTGRES_RELEASE_IMAGE) >/dev/null 2>&1 || docker pull postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
	docker tag $(POSTGRES_RELEASE_IMAGE) alice-postgres:$(VERSION)
	$(MAKE) sbom VERSION=$(VERSION)
	go run ./tools/releasebuild stage $(RELEASE_STAGE_FLAGS) -version $(VERSION) -out $(abspath $(RELEASE_DIR))/alice-$(VERSION) -keys $(RELEASE_KEYS) \
	  -alice-image alice:$(VERSION) -postgres-image alice-postgres:$(VERSION) -sbom $(abspath $(RELEASE_DIR))/sbom-$(VERSION) \
	  -notices bin/THIRD_PARTY_NOTICES.md -helper bin -commit $(RELEASE_COMMIT) -build-time $(BUILD_TIME) \
	  -gates-log bin/release-gates.log -license deploy/release/LICENSE.txt -min-upgrade-from $(MIN_UPGRADE_FROM)

.PHONY: release-pack
release-pack: ## Pack a signed stage into alice-$(VERSION).tar.gz with its checksum (sign the .sha256 offline afterwards)
	go run ./tools/releasebuild pack -stage $(abspath $(RELEASE_DIR))/alice-$(VERSION) -out $(abspath $(RELEASE_DIR))

.PHONY: release-test
release-test: ## Build, sign with a test key and pack a release (VERSION=x.y.z-rc.N only); never for customers
	@echo "$(VERSION)" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+' || { echo "make release-test needs VERSION=x.y.z-rc.N (a test-signed package is never a customer version)"; exit 2; }
	@stage="$(abspath $(RELEASE_DIR))/alice-$(VERSION)"; if [ -e "$$stage" ] && ! grep -qx 'TEST_SIGNED=1' "$$stage/alice/RELEASE" 2>/dev/null; then \
	  echo "make release-test: $$stage is not a test package (no TEST_SIGNED=1); remove it by hand if it is not needed"; exit 2; fi
	rm -rf $(RELEASE_OUTPUTS)
	@test -f $(RELEASE_TEST_KEY)/test-release.key || go run ./tools/releasesign generate $(RELEASE_TEST_KEY)
	$(MAKE) release VERSION=$(VERSION) RELEASE_KEYS=$(RELEASE_TEST_KEY) RELEASE_STAGE_FLAGS="-test -allow-draft"
	go run ./tools/releasesign sign $(RELEASE_TEST_KEY)/test-release.key $(abspath $(RELEASE_DIR))/alice-$(VERSION)/alice/SHA256SUMS
	$(MAKE) release-pack VERSION=$(VERSION)
	go run ./tools/releasesign sign $(RELEASE_TEST_KEY)/test-release.key $(abspath $(RELEASE_DIR))/alice-$(VERSION).tar.gz.sha256

.PHONY: release-broken
release-broken: ## A package whose image carries a failing (BROKEN=fail) or sleeping (BROKEN=sleep) extra migration, for the update rollback test (SIGN=test: test-signed, rc versions; SIGN=offline: unsigned stage for the ceremony)
	./deploy/dev/build-broken-release.sh "$(VERSION)" "$(BROKEN)" "$(SIGN)" "$(abspath $(RELEASE_DIR))" "$(abspath $(RELEASE_TEST_KEY))"

.PHONY: sbom
sbom: ## CycloneDX SBOMs of the alice and postgres images and the source tree (pinned Trivy)
	mkdir -p $(abspath $(RELEASE_DIR))/sbom-$(VERSION)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" $(TRIVY_IMAGE) image --format cyclonedx --output /out/alice-$(VERSION).cdx.json alice:$(VERSION)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" $(TRIVY_IMAGE) image --format cyclonedx --output /out/postgres-$(VERSION).cdx.json alice-postgres:$(VERSION)
	docker run --rm -v "$(CURDIR):/src:ro" -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" -w /src $(TRIVY_IMAGE) fs --scanners vuln --format cyclonedx --output /out/source-$(VERSION).cdx.json --skip-dirs '**/node_modules',.claude,.superpowers,.git,bin .

.PHONY: notices
notices: build ## Third-party notices of the Go modules in bin/alice and the helper, and the bundled npm packages
	go run ./tools/notices -binaries bin/alice,bin/alice-helper-linux-amd64 -lockfile web/package-lock.json -node-modules web/node_modules -out bin/THIRD_PARTY_NOTICES.md

.PHONY: reproducible-check
reproducible-check: ## Build alice and the helpers twice from clean copies of HEAD in different paths and compare the bytes
	./deploy/dev/reproducible-check.sh

.PHONY: release-keycheck
release-keycheck: ## Release gate: fails until the vendor's production release and license keys are committed and are separate keys (R36, S-12)
	@ls $(RELEASE_KEYS)/rk-*.pem >/dev/null 2>&1 || { echo "release-keycheck: no production release public key in $(RELEASE_KEYS) (docs/vendor/licensing-vendor.md, 'Release key')"; exit 1; }
	go run ./tools/releasebuild keycheck -release $(RELEASE_KEYS) -license internal/license/keys/production.json
	go test -count=1 -tags releasecheck -run TestProductionKeySetIsReadyForRelease ./internal/license/

.PHONY: coverage
coverage: ## Run all Go tests (with integration) under coverage and enforce coverage-floors.json (R36)
	go test -race -count=1 -tags integration -coverprofile=coverage.out ./...
	go run ./tools/covercheck -profile coverage.out -floors coverage-floors.json

.PHONY: perf
perf: ## Run the R32 performance test (5,000 certificates, 500 targets; needs Docker, nothing else using it)
	go vet -tags 'integration perf' ./internal/api/
	go test -count=1 -timeout 30m -tags 'integration perf' -run '^TestR32' -v ./internal/api/
