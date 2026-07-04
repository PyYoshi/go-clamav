GO      ?= go
COMPOSE ?= docker compose -f docker/compose.yaml

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

.PHONY: lint
lint: ## Static analysis (requires staticcheck and govulncheck)
	$(GO) vet ./...
	staticcheck ./...
	govulncheck ./...

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'
