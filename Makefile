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

.PHONY: test-ssh
test-ssh: ## Run the real OpenSSH matrix (Ubuntu 22.04, Debian 12, Rocky 9; needs Docker). ALICE_SSH_IMAGES=ubuntu22 limits it
	go test -count=1 -tags integration -run TestRealOpenSSH ./internal/providers/linuxssh/

.PHONY: i18n-check
i18n-check: ## Verify EN/TR translation catalogs have identical keys and placeholders
	go run ./tools/i18n-check locales/common web/src/locales

.PHONY: authz-doc
authz-doc: ## Regenerate docs/authz-matrix.md from the route table
	go test ./internal/api -run TestAuthzMatrixDocIsCurrent -count=1 -update

.PHONY: web-install
web-install: ## Install web dependencies from the lockfile
	cd web && npm ci

.PHONY: web
web: ## Build the web UI into internal/webui/dist/app
	cd web && npm run build

.PHONY: web-test
web-test: ## Run web unit tests
	cd web && npm test

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
E2E_SYMBOLS := main\.(damageLicenseFile|tamperNewestLicenseFile|resetInstall|e2eClock|e2eMailbox)$$

.PHONY: release-symcheck
release-symcheck: ## Fail if the release build of alice links e2e-only test code
	CGO_ENABLED=0 go build -trimpath -o bin/.symcheck-release ./cmd/alice
	CGO_ENABLED=0 go build -trimpath -tags "e2e testlicense" -o bin/.symcheck-e2e ./cmd/alice
	@go tool nm bin/.symcheck-e2e | grep -E ' $(E2E_SYMBOLS)' >/dev/null || { echo "release-symcheck: the e2e build lacks the guarded symbols; update E2E_SYMBOLS"; exit 1; }
	@! go tool nm bin/.symcheck-release | grep -E ' $(E2E_SYMBOLS)' || { echo "release-symcheck: the release build links e2e-only code"; exit 1; }
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

.PHONY: image
image: ## Build the alice container image
	docker build -f deploy/Dockerfile --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t alice:$(VERSION) -t alice:dev .

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
	cd web && npx playwright install chromium && set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a && ALICE_E2E_PROJECT=$(E2E_PROJECT) npx playwright test

GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION   ?= v1.8.0
GITLEAKS_VERSION      ?= 8.30.1
TRIVY_VERSION         ?= 0.74.0

.PHONY: tools
tools: ## Install pinned Go developer tools into $(HOME)/go/bin
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: lint
lint: ## Run golangci-lint (gosec, forbidigo, ...) on the release and the e2e build
	golangci-lint run ./...
	golangci-lint run --build-tags e2e,testlicense ./cmd/...
	golangci-lint run --build-tags integration,testlicense ./cmd/...
	golangci-lint run --build-tags integration,testlicense ./internal/license/...

.PHONY: vuln
vuln: ## Check Go dependencies and code for known vulnerabilities
	govulncheck ./...
	cd web && npm audit --omit=dev --audit-level=high

.PHONY: secrets-scan
secrets-scan: ## Scan git history for committed secrets
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$(CURDIR):/repo" ghcr.io/gitleaks/gitleaks:v$(GITLEAKS_VERSION) git /repo --config /repo/.gitleaks.toml --redact

.PHONY: fs-scan
fs-scan: ## Scan the source tree for HIGH/CRITICAL vulnerabilities and secrets (trivy fs)
	docker run --rm -v "$(CURDIR):/src:ro" -w /src aquasec/trivy:$(TRIVY_VERSION) fs --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 --skip-dirs '**/node_modules',.superpowers,.git,web/playwright-report,web/test-results,bin .

.PHONY: image-scan
image-scan: image ## Scan the container image for HIGH/CRITICAL vulnerabilities
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:$(TRIVY_VERSION) image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed alice:dev

.PHONY: ci
ci: lint test coverage build release-symcheck i18n-check web-lint web-test vuln secrets-scan fs-scan e2e-up e2e-hardening-check e2e image-scan ## Run the full CI pipeline locally

.PHONY: fuzz-license
fuzz-license: ## Fuzz the license parser for 60 s (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseLicense -fuzztime 60s ./internal/license/

.PHONY: fuzz-ssh
fuzz-ssh: ## Fuzz the authorized_keys and sshd configuration parsers for 60 s each (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseAuthorizedKeys -fuzztime 60s ./internal/providers/linuxssh/
	go test -count=1 -run '^$$' -fuzz FuzzParseSSHDConfig -fuzztime 60s ./internal/providers/linuxssh/sshdconf/

.PHONY: release-keycheck
release-keycheck: ## Release gate: fails until the vendor's production license key is committed (R36)
	go test -count=1 -tags releasecheck -run TestProductionKeySetIsReadyForRelease ./internal/license/

.PHONY: coverage
coverage: ## Run all Go tests (with integration) under coverage and enforce coverage-floors.json (R36)
	go test -race -count=1 -tags integration -coverprofile=coverage.out ./...
	go run ./tools/covercheck -profile coverage.out -floors coverage-floors.json
