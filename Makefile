# findingspec developer tasks.
#
# Local-first: run these checks locally before pushing. CI (see
# .github/workflows) is reserved for what local runs can't cover — cross-OS
# build/test — plus a scheduled govulncheck (the vulnerability database changes
# under unchanged code, so a periodic CI scan catches newly-disclosed vulns a
# local-on-last-commit run would miss). Security scanners (gosec, semgrep) and
# golangci-lint run here, not on every push, to conserve runner minutes.

GO ?= go
GOSEC_VERSION ?= latest
GOVULNCHECK_VERSION ?= latest

.PHONY: all check fmt vet lint sast gosec govulncheck semgrep test tidy help

all: check

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'

## check: full local gate — fmt, vet, lint, sast, test
check: fmt vet lint sast test

## fmt: verify gofmt formatting
fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needs: $$out"; exit 1; fi

## vet: go vet
vet:
	$(GO) vet ./...

## lint: golangci-lint (install from https://golangci-lint.run)
lint:
	golangci-lint run

## sast: all security scanners (gosec, govulncheck, semgrep)
sast: gosec govulncheck semgrep

## gosec: static security analysis (no install needed; via go run)
gosec:
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet ./...

## govulncheck: known-vulnerability scan with call-graph reachability
govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

## semgrep: run semgrep if installed (pip install semgrep)
semgrep:
	@if command -v semgrep >/dev/null 2>&1; then \
		semgrep scan --config auto --metrics=off --error .; \
	else \
		echo "semgrep not installed; skipping (pip install semgrep)"; \
	fi

## test: unit tests with coverage
test:
	$(GO) test -covermode=count ./...

## tidy: go mod tidy
tidy:
	$(GO) mod tidy
