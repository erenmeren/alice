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
# ALICE_REQUIRE_FLEET=1: the network discovery fleet journey fails instead of skipping when this machine has no
# container bridge address to run its fake TLS fleet on (internal/api/discovery_integration_test.go).
test-integration: ## Run integration tests (needs Docker)
	ALICE_REQUIRE_FLEET=1 go test -race -count=1 -timeout 45m -tags integration ./...

# The real-Nginx, real-Apache and real-HAProxy matrices install the release-built helper (make
# helper) through the nginx, apache or haproxy profile's setup script, which checks it against the
# checksums linked into the test binary exactly as make build links them into alice. They run only
# here (ALICE_REAL_MATRIX=1; make coverage skips them). Apache and HAProxy are installed in the
# images but never started (discovery only). Each
# matrix line runs verbose and fails unless its test PASSED: a -run pattern that matches no test
# ("[no tests to run]", which go test calls ok) or a skipped test fails the line. RUN, PAUSE, CONT
# and passing subtest lines are not printed.
SSH_MATRIX_PASSED = 2>&1 | awk -v t=$(1) '!/^=== |^ +--- PASS/ { print } /no tests to run/ || $$0 ~ "^--- SKIP: " t { bad = 1 } $$0 ~ "^--- PASS: " t " " { ok = 1 } END { exit bad || !ok }'

.PHONY: test-ssh
test-ssh: helper ## Run the real OpenSSH, Nginx, Apache and HAProxy matrices (Ubuntu 22.04, Debian 12, Rocky 9; needs Docker). ALICE_SSH_IMAGES=ubuntu22 limits them
	@for sum in '$(call HELPER_SUM,amd64)' '$(call HELPER_SUM,arm64)'; do \
	  echo "$$sum" | grep -Eqx '[0-9a-f]{64}' || { echo "bin/alice-helper.sha256 lacks a helper checksum; run make helper"; exit 1; }; \
	done
	set -o pipefail; go test -count=1 -v -timeout 30m -tags integration -run '^TestRealOpenSSH$$' ./internal/providers/linuxssh/ $(call SSH_MATRIX_PASSED,TestRealOpenSSH)
	set -o pipefail; ALICE_REAL_MATRIX=1 go test -count=1 -v -timeout 30m -tags integration -ldflags "$(HELPER_LDFLAGS)" -run '^TestRealNginx' ./internal/providers/nginx/ $(call SSH_MATRIX_PASSED,TestRealNginx)
	set -o pipefail; ALICE_REAL_MATRIX=1 go test -count=1 -v -timeout 30m -tags integration -ldflags "$(HELPER_LDFLAGS)" -run '^TestRealApache' ./internal/providers/apache/ $(call SSH_MATRIX_PASSED,TestRealApache)
	set -o pipefail; ALICE_REAL_MATRIX=1 go test -count=1 -v -timeout 30m -tags integration -ldflags "$(HELPER_LDFLAGS)" -run '^TestRealHAProxy' ./internal/providers/haproxy/ $(call SSH_MATRIX_PASSED,TestRealHAProxy)

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

# The Let's Encrypt staging acceptance harness (test/lestaging, docs/dev/le-staging-acceptance.md): Alice's real ACME
# code against the real staging service, for a domain the owner controls. It is a test binary built with the lestaging
# tag (built separately so it can be run with sudo for port 80); without the ALICE_LE_* variables it skips. Never part
# of ci. It refuses the production Let's Encrypt service unless ALICE_LE_ALLOW_PRODUCTION=yes.
.PHONY: le-staging-build
le-staging-build: ## Build the Let's Encrypt staging acceptance harness into bin/le-staging.test
	@mkdir -p bin
	go test -c -tags lestaging -o bin/le-staging.test ./test/lestaging/

.PHONY: le-staging
le-staging: le-staging-build ## Run the Let's Encrypt staging acceptance harness (needs ALICE_LE_*, skips without them; never part of ci)
	ALICE_LE_STATE_DIR="$${ALICE_LE_STATE_DIR:-$(CURDIR)/bin/le-staging}" ./bin/le-staging.test -test.v -test.count=1 -test.timeout 2h -test.run '^TestLetsEncryptStaging$$'

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

# The Windows setup script checks alice-helper.exe against these (R60 Ruling 16), from
# bin/alice-winhelper.sha256 that make winhelper writes.
WINHELPER_SUM = $(shell awk '$$2 == "alice-winhelper-windows-$(1).exe" { print $$1 }' bin/alice-winhelper.sha256 2>/dev/null)
WINHELPER_LDFLAGS = -X alice/internal/providers/windows.helperSHA256WindowsAMD64=$(call WINHELPER_SUM,amd64) -X alice/internal/providers/windows.helperSHA256WindowsARM64=$(call WINHELPER_SUM,arm64)

.PHONY: build
build: web helper winhelper ## Build the alice binary with the embedded UI (and the helper checksums) into bin/
	@for sum in '$(call HELPER_SUM,amd64)' '$(call HELPER_SUM,arm64)'; do \
	  echo "$$sum" | grep -Eqx '[0-9a-f]{64}' || { echo "bin/alice-helper.sha256 lacks a helper checksum; run make helper"; exit 1; }; \
	done
	@for sum in '$(call WINHELPER_SUM,amd64)' '$(call WINHELPER_SUM,arm64)'; do \
	  echo "$$sum" | grep -Eqx '[0-9a-f]{64}' || { echo "bin/alice-winhelper.sha256 lacks a helper checksum; run make winhelper"; exit 1; }; \
	done
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS) $(HELPER_LDFLAGS) $(WINHELPER_LDFLAGS)" -o bin/alice ./cmd/alice
	@! go version -m bin/alice | grep -q stretchr/testify || { echo "testify is linked into bin/alice"; exit 1; }

# Release symbol guard: the release build (no tags) links no e2e-only code. The e2e build is the
# positive control: release-symcheck checks EACH name (present in the e2e build, absent from the
# release build), so a renamed or inlined symbol fails instead of hiding behind another one. The
# release build also imports no alice/internal/testutil/ package: go list -deps checks the package graph (a
# constant or an inlined helper leaves no symbol), nm the linked symbols; the e2e build is the positive control.
E2E_SYMBOLS := main\.(damageLicenseFile|tamperNewestLicenseFile|resetInstall|e2eClock|e2eMailbox|drainJobs|runWithinBudget|drainMu|errDrainBudget|runScheduledTask|scheduled|serveRotationOverlap|setPolicyOverlap|serveSeedDashboard|resetTemporaryCertificate|removeBackupFiles)$$

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

# The same for the fake ACME CA (cmd/alice-fakeacme, compose service fakeacme): the directory its TLS CA is
# written to and the e2e build reads it from (cmd/alice/testapi_e2e.go). Only the e2e build holds this string.
E2E_ACME_MARKER := /run/alice-e2e-acme

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
	@grep -aqF '$(E2E_ACME_MARKER)' bin/.symcheck-e2e || { echo "release-symcheck: cannot see $(E2E_ACME_MARKER) in the e2e build; update E2E_ACME_MARKER"; exit 1; }
	@! grep -aqF '$(E2E_ACME_MARKER)' bin/.symcheck-release || { echo "release-symcheck: the release build knows where the fake ACME CA lives"; exit 1; }
	@rm -f bin/.symcheck-release bin/.symcheck-e2e bin/.symcheck-release.nm bin/.symcheck-e2e.nm bin/.symcheck-release.deps bin/.symcheck-e2e.deps
	@echo "release-symcheck: ok"

.PHONY: licensectl
licensectl: ## Build the vendor's offline license tool into bin/ (never shipped to customers)
	CGO_ENABLED=0 go build -trimpath -o bin/licensectl ./cmd/licensectl

.PHONY: vendor-console
vendor-console: ## Build the vendor console into bin/ (no YubiKey support, no cgo; never shipped to customers)
	CGO_ENABLED=0 go build -trimpath -o bin/vendor-console ./cmd/vendor-console

# The YubiKey build links the PC/SC library through cgo on Linux (libpcsclite-dev, pcscd) and macOS:
# run vendor-console-yubikey natively there. On Windows the PC/SC library loads the system's
# winscard.dll without cgo, so the Windows build is a plain cross build (vendor-console-yubikey-windows,
# or `go build -trimpath -tags yubikey -o bin\vendor-console-yubikey.exe ./cmd/vendor-console` on Windows).
.PHONY: vendor-console-yubikey
vendor-console-yubikey: ## Build the vendor console with YubiKey signing for this Linux or macOS machine (needs cgo and PC/SC)
	CGO_ENABLED=1 go build -trimpath -tags yubikey -o bin/vendor-console-yubikey ./cmd/vendor-console

.PHONY: vendor-console-yubikey-windows
vendor-console-yubikey-windows: ## Build the vendor console with YubiKey signing for Windows amd64 (no cgo) into bin/vendor-console-yubikey.exe
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -tags yubikey -o bin/vendor-console-yubikey.exe ./cmd/vendor-console

.PHONY: helper
helper: ## Build the static alice-helper for Linux amd64 and arm64 into bin/ with SHA-256 checksums (reproducible: no VCS stamp)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-helper-linux-amd64 ./cmd/alice-helper
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-helper-linux-arm64 ./cmd/alice-helper
	cd bin && sha256sum alice-helper-linux-amd64 alice-helper-linux-arm64 > alice-helper.sha256

.PHONY: winhelper
winhelper: ## Build alice-helper.exe for Windows amd64 and arm64 into bin/ with SHA-256 checksums (reproducible: no VCS stamp)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-winhelper-windows-amd64.exe ./cmd/alice-winhelper
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-winhelper-windows-arm64.exe ./cmd/alice-winhelper
	cd bin && sha256sum alice-winhelper-windows-amd64.exe alice-winhelper-windows-arm64.exe > alice-winhelper.sha256

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
image-check: image helper winhelper ## Check the release image: non-root, no shell or test artefacts, a release binary without build tags, test key or /test routes (AUD-23)
	TEST_LICENSE_LABEL='$(TEST_LICENSE_LABEL)' TEST_ROUTE_MARKER='$(TEST_ROUTE_MARKER)' E2E_AZURE_MARKER='$(E2E_AZURE_MARKER)' E2E_ACME_MARKER='$(E2E_ACME_MARKER)' \
	  HELPER_SHA256_AMD64='$(call HELPER_SUM,amd64)' HELPER_SHA256_ARM64='$(call HELPER_SUM,arm64)' \
	  WINHELPER_SHA256_AMD64='$(call WINHELPER_SUM,amd64)' WINHELPER_SHA256_ARM64='$(call WINHELPER_SUM,arm64)' \
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
e2e: ## Run Playwright tests on Chromium against the e2e stack (make e2e-up first; make e2e-browsers adds Firefox and WebKit)
	cd web && npx playwright install chromium && port="$${ALICE_E2E_PORT:-}" && set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a && { [ -z "$$port" ] || ALICE_E2E_PORT="$$port"; } && export ALICE_E2E_PORT && ALICE_E2E_PROJECT=$(E2E_PROJECT) npx playwright test --project=chromium

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
SHELL_SCRIPTS         := $(shell git ls-files -- '*.sh' deploy/release/alicectl 'deploy/release/testdata/stubs/*' deploy/release/testdata/swap-openssl/openssl test/images/e2e-target/systemctl test/images/e2e-target/nginx-wrapper test/images/openldap/alice-fakeldap-start test/images/openldap/alice-fakeldap-ctl)
# How long each fuzz target runs; fuzz-nightly and fuzz-release raise it.
FUZZTIME              ?= 60s
# Extra flags of matrix-check ("-strict" in lint and release-gates: a gap, a missing named test or a partial row without a ruling fails).
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
	$(MAKE) shellcheck lockcheck docs-check matrix-check actionlint MATRIXCHECK_FLAGS=-strict
	golangci-lint run ./...
	GOOS=windows golangci-lint run ./cmd/alice-winhelper/... ./internal/providers/windows/...
	golangci-lint run --build-tags e2e,testlicense ./cmd/...
	golangci-lint run --build-tags integration,testlicense ./cmd/...
	golangci-lint run --build-tags integration,e2e,testlicense ./cmd/...
	golangci-lint run --build-tags integration,testlicense ./internal/license/...
	golangci-lint run --build-tags integration ./internal/providers/azurekv/...
	golangci-lint run --build-tags systemd ./internal/providers/nginx/...
	golangci-lint run --build-tags release ./test/release/...
	golangci-lint run --build-tags lestaging ./test/lestaging/...

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
matrix-check: ## Every ID of the sections 23-25 matrices maps to existing tests, an owner step or a ruling (lint and release-gates run it with -strict)
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

.PHONY: fuzz-ldap
fuzz-ldap: ## Fuzz the directory sign-in filter and DN escaping, the filter template expansion, the user name and sign-in name rules ($(FUZZTIME) each)
	go test -count=1 -run '^$$' -fuzz FuzzEscapeFilter -fuzztime $(FUZZTIME) ./internal/auth/ldap/ldapx/
	go test -count=1 -run '^$$' -fuzz FuzzEscapeDN -fuzztime $(FUZZTIME) ./internal/auth/ldap/ldapx/
	go test -count=1 -run '^$$' -fuzz FuzzUsername -fuzztime $(FUZZTIME) ./internal/auth/ldap/ldapx/
	go test -count=1 -run '^$$' -fuzz FuzzExpandFilter -fuzztime $(FUZZTIME) ./internal/auth/ldap/ldapx/
	go test -count=1 -run '^$$' -fuzz FuzzValidLoginName -fuzztime $(FUZZTIME) ./internal/auth/ldap/ldapx/

.PHONY: fuzz-nginx
fuzz-nginx: ## Fuzz the nginx -T parser ($(FUZZTIME); spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseNginxConfig -fuzztime $(FUZZTIME) ./internal/providers/nginx/nginxconf/

.PHONY: fuzz-apache
fuzz-apache: ## Fuzz the Apache DUMP_INCLUDES and configuration parsers ($(FUZZTIME) each; spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseApacheIncludes -fuzztime $(FUZZTIME) ./internal/providers/apacheconf/
	go test -count=1 -run '^$$' -fuzz FuzzParseApacheConfig -fuzztime $(FUZZTIME) ./internal/providers/apacheconf/

.PHONY: fuzz-haproxy
fuzz-haproxy: ## Fuzz the HAProxy lexer, crt-list and configuration parsers ($(FUZZTIME) each; spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzLex -fuzztime $(FUZZTIME) ./internal/providers/haproxyconf/
	go test -count=1 -run '^$$' -fuzz FuzzParseCrtList -fuzztime $(FUZZTIME) ./internal/providers/haproxyconf/
	go test -count=1 -run '^$$' -fuzz FuzzParseHAProxyConfig -fuzztime $(FUZZTIME) ./internal/providers/haproxyconf/

.PHONY: fuzz-netaddr
fuzz-netaddr: ## Fuzz the scan address rule and the route table parsers ($(FUZZTIME) each; network discovery)
	go test -count=1 -run '^$$' -fuzz FuzzAllowedForScan -fuzztime $(FUZZTIME) ./internal/platform/netaddr/
	go test -count=1 -run '^$$' -fuzz FuzzParseRoutes -fuzztime $(FUZZTIME) ./internal/platform/netaddr/

.PHONY: fuzz-discovery
fuzz-discovery: ## Fuzz the discovery scope entry and exclusion parsers, the host and SNI name rule and the expansion ($(FUZZTIME) each; network discovery)
	go test -count=1 -run '^$$' -fuzz FuzzParseEntry -fuzztime $(FUZZTIME) ./internal/discovery/
	go test -count=1 -run '^$$' -fuzz FuzzCanonicalHostname -fuzztime $(FUZZTIME) ./internal/discovery/
	go test -count=1 -run '^$$' -fuzz FuzzExpand -fuzztime $(FUZZTIME) ./internal/discovery/

.PHONY: fuzz-tlsprobe
fuzz-tlsprobe: ## Fuzz the presented certificate chain parser of the discovery probe ($(FUZZTIME); network discovery)
	go test -count=1 -run '^$$' -fuzz FuzzParsePresentedChain -fuzztime $(FUZZTIME) ./internal/discovery/tlsprobe/

.PHONY: fuzz-certs
fuzz-certs: ## Fuzz the certificate upload and Key Vault secret parsers ($(FUZZTIME) each; spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseCertificateUpload -fuzztime $(FUZZTIME) ./internal/certs/
	go test -count=1 -run '^$$' -fuzz FuzzParseKVSecret -fuzztime $(FUZZTIME) ./internal/certs/

.PHONY: fuzz-backup
fuzz-backup: ## Fuzz the backup header, stream and payload decoder ($(FUZZTIME) each)
	go test -count=1 -run '^$$' -fuzz FuzzBackupHeader -fuzztime $(FUZZTIME) ./internal/backup/format/
	go test -count=1 -run '^$$' -fuzz FuzzBackupStream -fuzztime $(FUZZTIME) ./internal/backup/format/
	go test -count=1 -run '^$$' -fuzz FuzzDecoder -fuzztime $(FUZZTIME) ./internal/backup/dump/

.PHONY: fuzz-acme fuzz-acme-docs fuzz-acme-order
fuzz-acme: fuzz-acme-docs fuzz-acme-order ## Every ACME fuzz target (both groups below; local use)
fuzz-acme-docs: ## Fuzz the ACME problem, renewal information and directory parsers ($(FUZZTIME) each)
	go test -count=1 -run '^$$' -fuzz FuzzParseProblem -fuzztime $(FUZZTIME) ./internal/acme/
	go test -count=1 -run '^$$' -fuzz FuzzParseARI -fuzztime $(FUZZTIME) ./internal/acme/
	go test -count=1 -run '^$$' -fuzz FuzzParseDirectory -fuzztime $(FUZZTIME) ./internal/acme/
fuzz-acme-order: ## Fuzz the ACME issued chain check, the order names and the DNS hook reply parser ($(FUZZTIME) each)
	go test -count=1 -run '^$$' -fuzz FuzzCheckChain -fuzztime $(FUZZTIME) ./internal/acme/
	go test -count=1 -run '^$$' -fuzz FuzzNormalizeNames -fuzztime $(FUZZTIME) ./internal/acme/
	go test -count=1 -run '^$$' -fuzz FuzzParseHookReply -fuzztime $(FUZZTIME) ./internal/acme/solver/dns01/

.PHONY: fuzz-api
fuzz-api: ## Fuzz every create/update body of the API (needs Docker; $(FUZZTIME))
	go test -count=1 -tags integration -run '^$$' -fuzz FuzzOpenAPIInputs -fuzztime $(FUZZTIME) ./internal/api/

.PHONY: fuzz-nightly
fuzz-nightly: ## Every fuzz target for 10 minutes (spec §25.6 nightly; 34 targets, 340 minutes)
	$(MAKE) fuzz-license fuzz-ssh fuzz-oidc fuzz-ldap fuzz-nginx fuzz-apache fuzz-haproxy fuzz-certs fuzz-backup fuzz-acme-docs fuzz-acme-order fuzz-netaddr fuzz-discovery fuzz-tlsprobe fuzz-api FUZZTIME=10m

.PHONY: fuzz-release
fuzz-release: ## Every fuzz target for 30 minutes (spec §25.6 release; 34 targets, about 17 hours)
	$(MAKE) fuzz-license fuzz-ssh fuzz-oidc fuzz-ldap fuzz-nginx fuzz-apache fuzz-haproxy fuzz-certs fuzz-backup fuzz-acme-docs fuzz-acme-order fuzz-netaddr fuzz-discovery fuzz-tlsprobe fuzz-api FUZZTIME=30m

# Dynamic gates (Task 15; spec §22.7 stages 5 and 6, §25.7). zap-baseline, zap-full and testssl scan
# the release image (alice:ci of make image) as compose project alice-zap on 127.0.0.1:9445
# (deploy/dev/zap-stack.sh; the stack is always removed afterwards). The scanner images are pinned by
# tag and digest here and exported to the script, which never takes them from arguments (M-21).
ZAP_IMAGE     ?= ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2
TESTSSL_IMAGE ?= ghcr.io/testssl/testssl.sh:3.2@sha256:51918b1e954df0acee8c08d3ad5ce306710e4fefe49ed0e0f92728ecf9e7ff34
ZAP_OUT       := bin/zap
TESTSSL_TARGET ?=
TESTSSL_CA     ?=
export ZAP_IMAGE TESTSSL_IMAGE

.PHONY: zap-baseline zap-full testssl test-systemd e2e-browsers mutation nightly release-gates
zap-baseline: image ## ZAP passive baseline and API scan of the release image, unauthenticated and as Admin, Operator, Auditor (Docker)
	go run ./tools/zaprules .zap/rules.tsv
	./deploy/dev/zap-stack.sh run baseline $(ZAP_OUT)
zap-full: image ## ZAP full active scan against a disposable stack (hours; release gate; owner/CI)
	go run ./tools/zaprules .zap/rules.tsv
	./deploy/dev/zap-stack.sh run full $(ZAP_OUT)
testssl: ## testssl.sh, grade A or A+ required: the release image on the zap stack, or TESTSSL_TARGET=host:port (TESTSSL_CA=file) without a stack (Docker)
	@if [ -n "$(TESTSSL_TARGET)" ]; then ./deploy/dev/zap-stack.sh testssl-target "$(TESTSSL_TARGET)" "$(TESTSSL_CA)" $(ZAP_OUT); \
	else $(MAKE) image && ./deploy/dev/zap-stack.sh run testssl $(ZAP_OUT); fi
test-systemd: helper ## Real-systemd Nginx job (R38 item 16): privileged Ubuntu 22.04 container with systemd as PID 1 (Docker)
	go test -count=1 -v -timeout 20m -tags systemd -ldflags "$(HELPER_LDFLAGS)" -run '^TestRealSystemdNginx$$' ./internal/providers/nginx/
e2e-browsers: ## Every Playwright spec on Chromium, Firefox and WebKit in EN and TR (make e2e-up first; nightly and release)
	cd web && npx playwright install chromium firefox webkit && port="$${ALICE_E2E_PORT:-}" && set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a && { [ -z "$$port" ] || ALICE_E2E_PORT="$$port"; } && export ALICE_E2E_PORT && ALICE_E2E_PROJECT=$(E2E_PROJECT) npx playwright test --project=chromium --project=firefox --project=webkit
.PHONY: e2e-design-evidence
e2e-design-evidence: ## Screenshots of every primary route and wizard screen (light/dark, EN/TR, 1440/1024/768/390 px) into bin/design-evidence for review; never committed (make e2e-up first)
	cd web && npx playwright install chromium && port="$${ALICE_E2E_PORT:-}" && set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a && { [ -z "$$port" ] || ALICE_E2E_PORT="$$port"; } && export ALICE_E2E_PORT && ALICE_DESIGN_EVIDENCE=1 ALICE_E2E_PROJECT=$(E2E_PROJECT) npx playwright test e2e/design-evidence.spec.ts --project=chromium
mutation: ## Mutation testing of the security-critical pure packages (advisory; nightly)
	gremlins unleash --tags '' ./internal/backup/format
	gremlins unleash --tags '' ./internal/license
	gremlins unleash --tags '' ./internal/rbac
nightly: ## The nightly set (§22.7 stage 5) on this machine; hours; Docker alone
	$(MAKE) fuzz-nightly test-release test-systemd zap-baseline testssl mutation
	@status=0; $(MAKE) e2e-up e2e-browsers || status=$$?; $(MAKE) e2e-down; exit $$status
# release-gates runs every gate of deploy/dev/release-gates.sh in order. The list is defined once,
# in tools/releasebuild (releaseGates; go run ./tools/releasebuild gates prints it): ci, matrix-check
# -strict, reproducible-check, test-release, test-systemd, zap-baseline, testssl, test-backup-cycle,
# the three browsers, release-keycheck last. Every gate runs also after a failure and is recorded in
# bin/release-gates.log (first line commit<TAB><HEAD>, then <gate><TAB><exit status><TAB><tool
# version>), which make release turns into RELEASE-CHECKLIST-SIGNED.txt; the production stage
# requires every gate exactly once with exit 0. RELEASE_GATES_SKIP="gate ..." leaves gates out of a
# local partial run: each gets the line <gate><TAB>skipped<TAB>-, which the production stage refuses.
# zap-full and fuzz-release are not in it: they run for hours on the owner's or CI's machine
# (release.yml) and the release checklist lists them.
RELEASE_GATES_SKIP ?=
release-gates: ## Every release gate that runs on one machine (§22.7 stage 6, §17.7), logged to bin/release-gates.log; hours; Docker alone
	RELEASE_GATES_SKIP="$(RELEASE_GATES_SKIP)" GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION) MAKE="$(MAKE)" ./deploy/dev/release-gates.sh

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
	@if [ -z "$(RELEASE_ALLOW_DIRTY)" ] && [ -n "$$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then echo "make release: the working tree has uncommitted changes; the package must be built from the release commit (RELEASE_ALLOW_DIRTY=1 only for make release-test)"; exit 2; fi

.PHONY: release
# One build time for the image and RELEASE (BUILD_TIME is a recursive ?= and would be re-evaluated per use).
release: BUILD_TIME := $(BUILD_TIME)
release: release-preflight helper notices ## Stage an unsigned release in $(RELEASE_DIR)/alice-$(VERSION) (VERSION=x.y.z; needs Docker; sign SHA256SUMS offline, then make release-pack)
	$(MAKE) image-check IMAGE_TAG=$(VERSION) VERSION=$(VERSION) BUILD_TIME=$(BUILD_TIME)
	docker image inspect $(POSTGRES_RELEASE_IMAGE) >/dev/null 2>&1 || docker pull postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
	docker tag $(POSTGRES_RELEASE_IMAGE) alice-postgres:$(VERSION)
	$(MAKE) sbom VERSION=$(VERSION)
	$(MAKE) image-notices VERSION=$(VERSION)
	go run ./tools/releasebuild stage $(RELEASE_STAGE_FLAGS) -version $(VERSION) -out $(abspath $(RELEASE_DIR))/alice-$(VERSION) -keys $(RELEASE_KEYS) \
	  -alice-image alice:$(VERSION) -postgres-image alice-postgres:$(VERSION) -sbom $(abspath $(RELEASE_DIR))/sbom-$(VERSION) \
	  -notices bin/THIRD_PARTY_NOTICES.md -image-notices bin/IMAGE_NOTICES.md -helper bin -commit $(RELEASE_COMMIT) -build-time $(BUILD_TIME) \
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
release-broken: ## A package whose image carries a failing (BROKEN=fail), sleeping (BROKEN=sleep) or chain-breaking but successful (BROKEN=unhealthy) extra migration, for the update rollback tests (SIGN=test: test-signed, rc versions; SIGN=offline: unsigned stage for the ceremony)
	./deploy/dev/build-broken-release.sh "$(VERSION)" "$(BROKEN)" "$(SIGN)" "$(abspath $(RELEASE_DIR))" "$(abspath $(RELEASE_TEST_KEY))"

.PHONY: sbom
sbom: ## CycloneDX SBOMs of the alice and postgres images and the source tree (pinned Trivy)
	mkdir -p $(abspath $(RELEASE_DIR))/sbom-$(VERSION)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" $(TRIVY_IMAGE) image --format cyclonedx --output /out/alice-$(VERSION).cdx.json alice:$(VERSION)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" $(TRIVY_IMAGE) image --format cyclonedx --output /out/postgres-$(VERSION).cdx.json alice-postgres:$(VERSION)
	docker run --rm -v "$(CURDIR):/src:ro" -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" -w /src $(TRIVY_IMAGE) fs --scanners vuln --format cyclonedx --output /out/source-$(VERSION).cdx.json --skip-dirs '**/node_modules',.claude,.superpowers,.git,bin .

# The notices of the two images the package ships (final review B I-1): from each image's SBOM (make sbom) and an
# export of its files (a container created and removed here; alice-postgres:$(VERSION) is a tag of
# POSTGRES_RELEASE_IMAGE), after make notices, whose Go modules it does not repeat.
IMAGE_ROOTFS = bin/image-rootfs-$(VERSION)
.PHONY: image-notices
image-notices: ## Third-party notices and the written source offer of the alice and postgres images (after make sbom and make notices)
	rm -rf $(IMAGE_ROOTFS) && mkdir -p $(IMAGE_ROOTFS)
	cid=$$(docker create alice:$(VERSION)) && { docker export -o $(IMAGE_ROOTFS)/alice.tar "$$cid"; rc=$$?; docker rm "$$cid" >/dev/null; exit $$rc; }
	cid=$$(docker create $(POSTGRES_RELEASE_IMAGE)) && { docker export -o $(IMAGE_ROOTFS)/postgres.tar "$$cid"; rc=$$?; docker rm "$$cid" >/dev/null; exit $$rc; }
	go run ./tools/notices images -go-notices bin/THIRD_PARTY_NOTICES.md -out bin/IMAGE_NOTICES.md \
	  -image alice:$(VERSION)=$(abspath $(RELEASE_DIR))/sbom-$(VERSION)/alice-$(VERSION).cdx.json,$(IMAGE_ROOTFS)/alice.tar \
	  -image alice-postgres:$(VERSION)=$(abspath $(RELEASE_DIR))/sbom-$(VERSION)/postgres-$(VERSION).cdx.json,$(IMAGE_ROOTFS)/postgres.tar
	rm -rf $(IMAGE_ROOTFS)

.PHONY: notices
notices: build ## Third-party notices of the Go modules in bin/alice and the helper, and the bundled npm packages
	go run ./tools/notices -binaries bin/alice,bin/alice-helper-linux-amd64 -lockfile web/package-lock.json -node-modules web/node_modules -out bin/THIRD_PARTY_NOTICES.md -vendored web/src/design/THIRD_PARTY.json

.PHONY: reproducible-check
reproducible-check: ## Build alice and the helpers twice from clean copies of HEAD in different paths and compare the bytes
	./deploy/dev/reproducible-check.sh

.PHONY: release-keycheck
release-keycheck: ## Release gate: fails until the vendor's production release and license keys are committed and are separate keys (R36, S-12)
	@ls $(RELEASE_KEYS)/rk-*.pem >/dev/null 2>&1 || { echo "release-keycheck: no production release public key in $(RELEASE_KEYS) (docs/vendor/licensing-vendor.md, 'Release key')"; exit 1; }
	go run ./tools/releasebuild keycheck -release $(RELEASE_KEYS) -license internal/license/keys/production.json
	go test -count=1 -tags releasecheck -run TestProductionKeySetIsReadyForRelease ./internal/license/

.PHONY: coverage
# -timeout: under race+coverage+integration on a CI runner internal/api took over 600 s, past go test's
# 10-minute default per package (run 38921544223); the job itself is bounded by its 75 minutes.
coverage: ## Run all Go tests (with integration) under coverage and enforce coverage-floors.json (R36)
	ALICE_REQUIRE_FLEET=1 go test -race -count=1 -timeout 45m -tags integration -coverprofile=coverage.out ./...
	go run ./tools/covercheck -profile coverage.out -floors coverage-floors.json

.PHONY: perf
perf: ## Run the R32 and network discovery performance tests (5,000 certificates, 500 targets; 5,000 endpoints; needs Docker, nothing else using it)
	go vet -tags 'integration perf' ./internal/api/
	go test -count=1 -timeout 30m -tags 'integration perf' -run '^(TestR32|TestPerfNetdiscoScan)' -v ./internal/api/
