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
test: ## Run Go unit tests with the race detector
	go test -race -count=1 ./...

.PHONY: test-integration
test-integration: ## Run integration tests (needs Docker)
	go test -race -count=1 -tags integration ./...

.PHONY: i18n-check
i18n-check: ## Verify EN/TR translation catalogs have identical keys and placeholders
	go run ./tools/i18n-check locales/common web/src/locales

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

.PHONY: build
build: web ## Build the alice binary with the embedded UI into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/alice ./cmd/alice

COMPOSE := docker compose -f deploy/docker-compose.yml --env-file deploy/.env

.PHONY: image
image: ## Build the alice container image
	docker build -f deploy/Dockerfile --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t alice:$(VERSION) -t alice:dev .

.PHONY: up
up: ## Build and start Alice with PostgreSQL (https://localhost)
	./deploy/dev/init-env.sh
	$(COMPOSE) up -d --build --wait

.PHONY: down
down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) down

.PHONY: logs
logs: ## Follow the alice container logs
	$(COMPOSE) logs -f alice

.PHONY: hardening-check
hardening-check: ## Verify container hardening of the running stack
	./deploy/dev/check-hardening.sh

.PHONY: e2e
e2e: ## Run Playwright tests against the running stack (make up first)
	cd web && npx playwright install chromium && npx playwright test
