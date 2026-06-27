# Contributing to authcore

Thank you for taking the time to contribute! Security-focused libraries need careful,
thoughtful contributions — the guidelines below keep the bar high for everyone's benefit.

## Code of Conduct

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security First

If you find a security vulnerability, **do not open a public issue**.
Follow the process in our [Security Policy](SECURITY.md) instead.

## Ways to Contribute

### Reporting Bugs

1. Search [existing issues](https://github.com/Glyndor/authcore/issues) first.
2. If none matches, [open a new issue](https://github.com/Glyndor/authcore/issues/new/choose) using the **Bug Report** template.
3. Include: Go version, OS, steps to reproduce, and any relevant logs.

### Suggesting Enhancements

1. Search [existing issues](https://github.com/Glyndor/authcore/issues) to avoid duplicates.
2. Open an issue using the **Feature Request** template.
3. Explain the use case — why would most users benefit?

### Pull Requests

> **Branch model.** `main` only ever contains released code — what you see on
> [pkg.go.dev](https://pkg.go.dev/github.com/Glyndor/authcore). All work lands on
> `develop` first and is promoted to `main` together with a release tag. Always
> branch from `develop` and target `develop` in your PR. Pull requests against
> `main` will be redirected.

1. **Fork** the repository and branch from `develop` (not `main`).
2. **Run `go mod download`** to fetch dependencies.
3. **Write tests.** Every change must include tests. Security-critical paths need
   table-driven tests that cover both the happy path and all error cases.
4. **Follow Go standards:**
   - `go fmt ./...`
   - `go vet ./...`
   - `golangci-lint run` (if installed)
   - Export everything with [godoc-style comments](https://go.dev/doc/effective_go#commentary).
5. **Keep PRs small.** Smaller, focused PRs are reviewed faster.
6. **Update docs.** If a public API changes, update `README.md` and affected examples.
7. **Sign commits** for auditability (preferred, not required).

## Development Setup

Requires **Go 1.26+**.

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/authcore.git
cd authcore

# Fetch dependencies
go mod download

# Run all tests with the race detector
go test -v -race ./...

# Run linting (requires golangci-lint)
golangci-lint run
```

## Pull Request Process

1. Ensure all CI checks pass (tests + lint).
2. A maintainer will review within a few days.
3. Once approved it will be squash-merged into `develop`. The maintainer
   later promotes `develop` to `main` together with a release tag.

Thank you for your contribution!
