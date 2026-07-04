GO      ?= go
COMPOSE ?= docker compose -f docker/compose.yaml

GOLANGCI_LINT_VERSION ?= v2.12.2
GOLANGCI_LINT ?= $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: test
test: ## Unit tests (no Docker required)
	$(GO) vet ./...
	$(GO) test -race -count=1 ./...

.PHONY: fuzz
fuzz: ## Short fuzzing pass over the response parser
	$(GO) test -run='^$$' -fuzz=FuzzParseScanResponse -fuzztime=30s ./internal/proto/

.PHONY: integration-up
integration-up: ## Start the clamd test container
	mkdir -p docker/run
	chmod 777 docker/run
	$(COMPOSE) up -d --wait

.PHONY: test-integration
test-integration: ## Run integration tests against the running container
	CLAMAV_TCP_ADDR=tcp://127.0.0.1:3310 \
	CLAMAV_UNIX_ADDR=unix://$(CURDIR)/docker/run/clamd.sock \
	$(GO) test -race -count=1 -tags=integration ./...

.PHONY: integration
integration: integration-up test-integration ## Start clamd and run integration tests

.PHONY: integration-down
integration-down: ## Tear down the clamd test container
	$(COMPOSE) down -v

.PHONY: integration-logs
integration-logs:
	$(COMPOSE) logs --no-color

.PHONY: verify
verify: ## Full local verification (build + lint + test); records success for the harness
	$(GO) build ./...
	$(GO) build -tags=integration ./...
	$(MAKE) lint
	$(MAKE) test
	./scripts/record-verified.sh

.PHONY: setup
setup: ## One-time developer setup: enable git hooks, check tooling
	git config core.hooksPath githooks
	chmod +x githooks/* scripts/*.sh .claude/hooks/*.sh
	@command -v jq >/dev/null 2>&1 || echo "WARNING: jq not found; Claude Code guard hooks are inert without it."

.PHONY: lint
lint: ## Static analysis (golangci-lint + govulncheck)
	$(GOLANGCI_LINT) run
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: format
format: ## Format code with gofumpt + gci (via golangci-lint fmt)
	$(GOLANGCI_LINT) fmt

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'
