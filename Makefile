.PHONY: build test lint clean coverage help

# Default target
all: lint test build

## build: Build all packages
build:
	go build ./...

## test: Run tests with race detector
test:
	go test -v -race ./...

## lint: Run golangci-lint
lint:
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint 2.14.0 is required (the version CI pins); install it from https://github.com/golangci/golangci-lint/releases/tag/v2.14.0" >&2; \
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
