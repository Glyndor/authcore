.PHONY: build test test-hostile test-repeat api-compat lint clean coverage help

# Default target
all: lint test build

## build: Build all packages
build:
	go build ./...

## test: Run tests with race detector
test:
	go test -v -race ./...

## test-hostile: Run the hostile suites twice, shuffled, under the race detector
test-hostile:
	go test -race -count=2 -shuffle=on ./tests/hostile/...

## test-repeat: Run the unit tests three times, shuffled, under the race detector (the weekly flake hunt)
test-repeat:
	@pkgs="$$(go list ./... | grep -v '/tests/hostile')" && go test -race -count=3 -shuffle=on $$pkgs

## api-compat: Compare the public API with BASE (default origin/develop); set LABELS=breaking to acknowledge a break
BASE ?= origin/develop
LABELS ?=
api-compat:
	@command -v apidiff > /dev/null || { \
		echo "apidiff is required; install the version pinned in .github/workflows/api-compat.yml" >&2; \
		echo "  go install golang.org/x/exp/cmd/apidiff@<APIDIFF_VERSION>" >&2; \
		exit 1; \
	}
	@base="$$(mktemp -d)" && git archive "$(BASE)" | tar -x -C "$$base" && \
		PR_LABELS="$(LABELS)" bash scripts/api-compat/api-compat.sh "$$base" . ; \
		rc=$$?; rm -rf "$$base"; exit $$rc

## lint: Run golangci-lint
lint:
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint 2.15.0 is required (the version CI pins); install it from https://github.com/golangci/golangci-lint/releases/tag/v2.15.0" >&2; \
		exit 1; \
	fi

## coverage: Run tests and generate coverage report
coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

## clean: Remove build artifacts and coverage files
clean:
	go clean
	rm -f coverage.out

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' Makefile | column -t -s ':' | sed -e 's/^/ /'
