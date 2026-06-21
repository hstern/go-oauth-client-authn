# Developer convenience targets. CI does not depend on this Makefile — it
# invokes the same `go` commands directly (see .github/workflows/ci.yml) — so
# these targets exist purely to make the local edit/check loop one word long.

GO ?= go

.PHONY: all check fmt fmt-check vet build test lint tidy tidy-check

all: check

## check: the full local gate, matching CI (fmt, vet, build, test, lint)
check: fmt-check vet build test lint

## fmt: rewrite all Go sources with gofmt
fmt:
	gofmt -w .

## fmt-check: fail if any Go source is not gofmt-clean
fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

## vet: run go vet
vet:
	$(GO) vet ./...

## build: compile all packages
build:
	$(GO) build ./...

## test: run the race-enabled, shuffled test suite
test:
	$(GO) test -race -shuffle=on ./...

## lint: run golangci-lint (install: https://golangci-lint.run)
lint:
	golangci-lint run ./...

## tidy: tidy go.mod / go.sum
tidy:
	$(GO) mod tidy

## tidy-check: fail if go.mod / go.sum would change
tidy-check:
	$(GO) mod tidy -diff
