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
# positive control: if it lacks the symbols, the names here are stale and the guard proves nothing.
E2E_SYMBOLS := main\.(damageLicenseFile|tamperNewestLicenseFile|resetInstall|e2eClock|e2eMailbox|drainJobs|runWithinBudget|drainMu|errDrainBudget|runScheduledTask|scheduled)$$

# Test-only data a release binary must not hold (AUD-23): the label the test license signing key is
# derived from (testKeyLabel in internal/license/keys_testlicense.go) and a route only the e2e build
# serves (cmd/alice/testapi_e2e.go). release-symcheck proves an e2e build holds both, so their
# absence from the release build and from the image (image-check) means something.
# internal/archtest/buildtags_test.go checks that both values still match the source.
TEST_LICENSE_LABEL := alice test license signing key v1
TEST_ROUTE_MARKER := /test/clock

.PHONY: release-symcheck
release-symcheck: ## Fail if the release build of alice links e2e-only test code, has build tags or trusts the test license key
	CGO_ENABLED=0 go build -trimpath -o bin/.symcheck-release ./cmd/alice
	CGO_ENABLED=0 go build -trimpath -tags "e2e testlicense" -o bin/.symcheck-e2e ./cmd/alice
	@go tool nm bin/.symcheck-e2e | grep -E ' $(E2E_SYMBOLS)' >/dev/null || { echo "release-symcheck: the e2e build lacks the guarded symbols; update E2E_SYMBOLS"; exit 1; }
	@! go tool nm bin/.symcheck-release | grep -E ' $(E2E_SYMBOLS)' || { echo "release-symcheck: the release build links e2e-only code"; exit 1; }
	@go version -m bin/.symcheck-e2e | grep -Eq '^\s+build\s+-tags=.*testlicense' || { echo "release-symcheck: cannot see build tags in the build info"; exit 1; }
	@! go version -m bin/.symcheck-release | grep -Eq '^\s+build\s+-tags=' || { echo "release-symcheck: the release build has build tags"; exit 1; }
	@grep -aqF '$(TEST_LICENSE_LABEL)' bin/.symcheck-e2e || { echo "release-symcheck: cannot see the test key label in the e2e build; update TEST_LICENSE_LABEL"; exit 1; }
	@! grep -aqF '$(TEST_LICENSE_LABEL)' bin/.symcheck-release || { echo "release-symcheck: the release build trusts the test license key"; exit 1; }
	@grep -aqF '$(TEST_ROUTE_MARKER)' bin/.symcheck-e2e || { echo "release-symcheck: cannot see $(TEST_ROUTE_MARKER) in the e2e build; update TEST_ROUTE_MARKER"; exit 1; }
	@! grep -aqF '$(TEST_ROUTE_MARKER)' bin/.symcheck-release || { echo "release-symcheck: the release build serves the e2e /test routes"; exit 1; }
	@rm -f bin/.symcheck-release bin/.symcheck-e2e
	@echo "release-symcheck: ok"

.PHONY: licensectl
licensectl: ## Build the vendor's offline license tool into bin/ (never shipped to customers)
	CGO_ENABLED=0 go build -trimpath -o bin/licensectl ./cmd/licensectl

.PHONY: helper
helper: ## Build the static alice-helper for Linux amd64 and arm64 into bin/ with SHA-256 checksums (reproducible: no VCS stamp)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-helper-linux-amd64 ./cmd/alice-helper
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-helper-linux-arm64 ./cmd/alice-helper
	cd bin && sha256sum alice-helper-linux-amd64 alice-helper-linux-arm64 > alice-helper.sha256

COMPOSE := docker compose -f deploy/docker-compose.yml --env-file deploy/.env

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
	TEST_LICENSE_LABEL='$(TEST_LICENSE_LABEL)' TEST_ROUTE_MARKER='$(TEST_ROUTE_MARKER)' \
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
e2e-hardening-check: ## Verify container hardening of the running e2e stack, including the SSH test target
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
# Tool images are pinned by tag and by index digest (AUD-09; docs/dev/dependency-updates.md).
GITLEAKS_IMAGE        ?= ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
TRIVY_IMAGE           ?= aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969

.PHONY: tools
tools: ## Install pinned Go developer tools into $(HOME)/go/bin
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: lint
lint: ## Run golangci-lint (gosec, forbidigo, ...) on the release and the e2e build
	go run ./tools/pincheck
	golangci-lint run ./...
	golangci-lint run --build-tags e2e,testlicense ./cmd/...
	golangci-lint run --build-tags integration,testlicense ./cmd/...
	golangci-lint run --build-tags integration,testlicense ./internal/license/...

.PHONY: vuln
vuln: ## Verify the Go module cache against go.sum, then check Go and npm dependencies for known vulnerabilities
	go mod verify
	govulncheck ./...
	cd web && npm audit --omit=dev --audit-level=high

.PHONY: secrets-scan
secrets-scan: ## Scan git history for committed secrets
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$(CURDIR):/repo" $(GITLEAKS_IMAGE) git /repo --config /repo/.gitleaks.toml --gitleaks-ignore-path /repo/.gitleaksignore --redact

.PHONY: fs-scan
fs-scan: ## Scan the source tree for HIGH/CRITICAL vulnerabilities and secrets (trivy fs)
	docker run --rm -v "$(CURDIR):/src:ro" -w /src $(TRIVY_IMAGE) fs --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 --skip-dirs '**/node_modules',.superpowers,.git,web/playwright-report,web/test-results,bin .

.PHONY: image-scan
image-scan: image ## Scan the container image for HIGH/CRITICAL vulnerabilities
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $(TRIVY_IMAGE) image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed alice:$(IMAGE_TAG)

# The e2e stack is always removed at the end, also when a stage of it fails. It publishes
# ALICE_E2E_PORT (default 9443), so it runs beside the make up stack, which ci never touches.
.PHONY: ci
ci: ## Run the full CI pipeline locally
	$(MAKE) lint test coverage test-ssh build release-symcheck i18n-check web-lint web-coverage vuln secrets-scan fs-scan
	@status=0; $(MAKE) e2e-up e2e-hardening-check e2e || status=$$?; $(MAKE) e2e-down; exit $$status
	$(MAKE) image-check image-scan

.PHONY: fuzz-license
fuzz-license: ## Fuzz the license parser for 60 s (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseLicense -fuzztime 60s ./internal/license/

.PHONY: fuzz-ssh
fuzz-ssh: ## Fuzz the authorized_keys and sshd configuration parsers for 60 s each (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseAuthorizedKeys -fuzztime 60s ./internal/providers/linuxssh/
	go test -count=1 -run '^$$' -fuzz FuzzParseSSHDConfig -fuzztime 60s ./internal/providers/linuxssh/sshdconf/

.PHONY: fuzz-nginx
fuzz-nginx: ## Fuzz the nginx -T parser for 60 s (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseNginxConfig -fuzztime 60s ./internal/providers/nginx/nginxconf/

.PHONY: fuzz-certs
fuzz-certs: ## Fuzz the certificate upload parser for 60 s (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseCertificateUpload -fuzztime 60s ./internal/certs/

.PHONY: release-keycheck
release-keycheck: ## Release gate: fails until the vendor's production license key is committed (R36)
	go test -count=1 -tags releasecheck -run TestProductionKeySetIsReadyForRelease ./internal/license/

.PHONY: coverage
coverage: ## Run all Go tests (with integration) under coverage and enforce coverage-floors.json (R36)
	go test -race -count=1 -tags integration -coverprofile=coverage.out ./...
	go run ./tools/covercheck -profile coverage.out -floors coverage-floors.json
